use anyhow::{Context, Result};
use tempfile::TempDir;

use csd::chain::index::{get_hidx, header_hash, index_header};
use csd::chain::reorg::maybe_reorg_to;
use csd::state::app_state::{epoch_of, get_topk};
use csd::state::db::{k_block, set_tip, Stores};
use csd::state::utxo::validate_and_apply_block;
use csd::types::{AppPayload, Block, Hash20, Hash32, OutPoint, Transaction, TxIn, TxOut};

mod testutil_chain;
use testutil_chain::{
    assert_tip_eq, build_base_chain_with_miner, flush_all_state_trees, make_test_header, open_db,
    replay_canonical_from_tip,
};

fn h20(n: u8) -> Hash20 {
    [n; 20]
}

fn signer_addr(sk32: [u8; 32]) -> Hash20 {
    let dummy = Transaction {
        version: 1,
        inputs: vec![TxIn {
            prevout: OutPoint {
                txid: [0u8; 32],
                vout: 0,
            },
            script_sig: vec![],
        }],
        outputs: vec![TxOut {
            value: 1,
            script_pubkey: [0u8; 20],
        }],
        locktime: 0,
        app: AppPayload::None,
    };

    let (_sig64, pub33) = csd::crypto::sign_tx_compact_secp256k1(&dummy, sk32);
    csd::crypto::hash160(&pub33)
}

fn load_block(db: &Stores, bh: &Hash32) -> Result<Block> {
    let Some(v) = db.blocks.get(k_block(bh))? else {
        anyhow::bail!("missing block bytes for 0x{}", hex::encode(bh));
    };
    Ok(csd::codec::consensus_bincode().deserialize::<Block>(&v)?)
}

fn make_spend_tx(
    prev: OutPoint,
    prev_value: u64,
    to: Hash20,
    send_value: u64,
    fee: u64,
    sk32: [u8; 32],
    app: AppPayload,
) -> Transaction {
    assert_eq!(prev_value, send_value + fee);

    let mut tx = Transaction {
        version: 1,
        inputs: vec![TxIn {
            prevout: prev,
            script_sig: vec![0u8; 99],
        }],
        outputs: vec![TxOut {
            value: send_value,
            script_pubkey: to,
        }],
        locktime: 0,
        app,
    };

    let (sig64, pub33) = csd::crypto::sign_tx_compact_secp256k1(&tx, sk32);

    let mut ss = Vec::with_capacity(99);
    ss.push(64u8);
    ss.extend_from_slice(&sig64);
    ss.push(33u8);
    ss.extend_from_slice(&pub33);
    tx.inputs[0].script_sig = ss;

    tx
}

fn persist_index_apply_block(db: &Stores, blk: &Block, height: u64) -> Result<Hash32> {
    let bh = header_hash(&blk.header);

    let bytes = csd::codec::consensus_bincode().serialize(blk)?;
    db.blocks.insert(k_block(&bh), bytes)?;

    let parent_hi = if blk.header.prev == [0u8; 32] {
        None
    } else {
        get_hidx(db, &blk.header.prev)?
    };

    index_header(db, &blk.header, parent_hi.as_ref())?;
    validate_and_apply_block(db, blk, epoch_of(height), height)
        .with_context(|| format!("validate_and_apply_block h={height}"))?;
    set_tip(db, &bh)?;

    Ok(bh)
}

fn persist_index_only_block(db: &Stores, blk: &Block) -> Result<Hash32> {
    let bh = header_hash(&blk.header);

    let bytes = csd::codec::consensus_bincode().serialize(blk)?;
    db.blocks.insert(k_block(&bh), bytes)?;

    let parent_hi = if blk.header.prev == [0u8; 32] {
        None
    } else {
        get_hidx(db, &blk.header.prev)?
    };

    index_header(db, &blk.header, parent_hi.as_ref())?;
    Ok(bh)
}

fn snapshot_topk(
    db: &Stores,
    epochs: &[u64],
) -> Result<Vec<(u64, String, Vec<(Hash32, u128)>)>> {
    let mut out = Vec::new();
    for &epoch in epochs {
        for domain in ["science", "ai"] {
            let v = get_topk(db, epoch, domain)
                .with_context(|| format!("get_topk epoch={epoch} domain={domain}"))?;
            out.push((epoch, domain.to_string(), v));
        }
    }
    Ok(out)
}

#[test]
fn reorg_to_same_tip_is_idempotent_and_replay_equivalent() -> Result<()> {
    let tmp = TempDir::new()?;
    let db = open_db(&tmp)?;

    let sk = [11u8; 32];
    let signer = signer_addr(sk);
    let miner_a = h20(0xA1);
    let miner_b = h20(0xB2);
    let user_addr = signer;

    let shared_len = 140u64;
    let fork_parent_height = 100u64;
    let start_time = 1_700_400_000u64;

    let shared = build_base_chain_with_miner(&db, shared_len, start_time, signer)?;
    let shared_tip = shared[fork_parent_height as usize];
    set_tip(&db, &shared_tip)?;
    assert_tip_eq(&db, shared_tip)?;

    let mut funds = Vec::new();
    for bh in shared.iter().take(shared_len as usize).skip(2) {
        let b = load_block(&db, bh)?;
        let cb = &b.txs[0];
        let cbid = csd::crypto::txid(cb);
        funds.push((OutPoint { txid: cbid, vout: 0 }, cb.outputs[0].value));
    }
    assert!(funds.len() >= 80, "not enough funds: {}", funds.len());

    let mut fund_i = 0usize;

    // Branch A applied (shorter)
    let mut prev_a = shared_tip;
    for step in 0..6u64 {
        let height = fork_parent_height + 1 + step;
        let epoch = epoch_of(height);
        let mut txs = Vec::new();
        let mut fees = 0u64;

        for j in 0..2u8 {
            let (op, v) = funds[fund_i];
            fund_i += 1;

            let fee = csd::params::MIN_FEE_PROPOSE;
            fees += fee;

            let mut payload_hash = [0u8; 32];
            payload_hash[0] = 0x51;
            payload_hash[1] = step as u8;
            payload_hash[2] = j;

            txs.push(make_spend_tx(
                op,
                v,
                user_addr,
                v - fee,
                fee,
                sk,
                AppPayload::Propose {
                    domain: if j % 2 == 0 { "science".into() } else { "ai".into() },
                    payload_hash,
                    uri: format!("ipfs://idem/a/{epoch}/{step}/{j}"),
                    expires_epoch: epoch + 3,
                },
            ));
        }

        let mut all_txs = Vec::new();
        all_txs.push(csd::chain::mine::coinbase(
            miner_a,
            csd::params::block_reward(height) + fees,
            height,
            None,
        ));
        all_txs.extend(txs);

        let hdr = make_test_header(&db, prev_a, &all_txs, height)?;
        let blk = Block { header: hdr, txs: all_txs };
        prev_a = persist_index_apply_block(&db, &blk, height)?;
    }

    let tip_a = prev_a;
    assert_tip_eq(&db, tip_a)?;

    // Branch B indexed only (longer)
    let mut prev_b = shared_tip;
    for step in 0..8u64 {
        let height = fork_parent_height + 1 + step;
        let epoch = epoch_of(height);
        let mut txs = Vec::new();
        let mut fees = 0u64;
        let mut proposal_ids = Vec::<Hash32>::new();

        for j in 0..3u8 {
            let (op, v) = funds[fund_i];
            fund_i += 1;

            let fee = csd::params::MIN_FEE_PROPOSE;
            fees += fee;

            let mut payload_hash = [0u8; 32];
            payload_hash[0] = 0x61;
            payload_hash[1] = step as u8;
            payload_hash[2] = j;

            let tx = make_spend_tx(
                op,
                v,
                user_addr,
                v - fee,
                fee,
                sk,
                AppPayload::Propose {
                    domain: if j == 0 { "science".into() } else { "ai".into() },
                    payload_hash,
                    uri: format!("ipfs://idem/b/{epoch}/{step}/{j}"),
                    expires_epoch: epoch + 5,
                },
            );
            proposal_ids.push(csd::crypto::txid(&tx));
            txs.push(tx);
        }

        for k in 0..2usize {
            let (op, v) = funds[fund_i];
            fund_i += 1;

            let fee = csd::params::MIN_FEE_ATTEST + k as u64 * 50;
            fees += fee;

            txs.push(make_spend_tx(
                op,
                v,
                user_addr,
                v - fee,
                fee,
                sk,
                AppPayload::Attest {
                    proposal_id: proposal_ids[k % proposal_ids.len()],
                    score: 1000 + step as u32 * 17 + k as u32,
                    confidence: 100 + k as u32,
                },
            ));
        }

        let mut all_txs = Vec::new();
        all_txs.push(csd::chain::mine::coinbase(
            miner_b,
            csd::params::block_reward(height) + fees,
            height,
            None,
        ));
        all_txs.extend(txs);

        let hdr = make_test_header(&db, prev_b, &all_txs, height)?;
        let blk = Block { header: hdr, txs: all_txs };
        prev_b = persist_index_only_block(&db, &blk)?;
    }

    let tip_b = prev_b;
    let hi_a = get_hidx(&db, &tip_a)?.expect("missing hidx A");
    let hi_b = get_hidx(&db, &tip_b)?.expect("missing hidx B");
    assert!(hi_b.height > hi_a.height);

    flush_all_state_trees(&db)?;
    maybe_reorg_to(&db, &tip_b, None)?;
    assert_tip_eq(&db, tip_b)?;

    let epochs = [
        epoch_of(fork_parent_height - 1),
        epoch_of(fork_parent_height),
        epoch_of(fork_parent_height + 1),
        epoch_of(fork_parent_height + 8),
    ];

    let before = snapshot_topk(&db, &epochs)?;

    // Idempotence check: reorg to same tip again
    flush_all_state_trees(&db)?;
    maybe_reorg_to(&db, &tip_b, None)?;
    assert_tip_eq(&db, tip_b)?;

    let after = snapshot_topk(&db, &epochs)?;
    assert_eq!(before, after, "state changed on idempotent reorg");

    let replay_tmp = TempDir::new()?;
    let replay_db = open_db(&replay_tmp)?;
    replay_canonical_from_tip(&replay_db, &db, tip_b)?;
    assert_tip_eq(&replay_db, tip_b)?;

    for epoch in epochs {
        for domain in ["science", "ai"] {
            let live = get_topk(&db, epoch, domain)?;
            let replay = get_topk(&replay_db, epoch, domain)?;
            assert_eq!(live, replay, "replay mismatch epoch={epoch} domain={domain}");
        }
    }

    Ok(())
}
