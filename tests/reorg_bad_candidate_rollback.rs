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

fn make_signed_tx_with_custom_inputs(
    inputs: Vec<OutPoint>,
    outputs: Vec<TxOut>,
    app: AppPayload,
    sk32: [u8; 32],
) -> Transaction {
    let mut tx = Transaction {
        version: 1,
        inputs: inputs
            .into_iter()
            .map(|prevout| TxIn {
                prevout,
                script_sig: vec![0u8; 99],
            })
            .collect(),
        outputs,
        locktime: 0,
        app,
    };

    let (sig64, pub33) = csd::crypto::sign_tx_compact_secp256k1(&tx, sk32);
    let mut ss = Vec::with_capacity(99);
    ss.push(64u8);
    ss.extend_from_slice(&sig64);
    ss.push(33u8);
    ss.extend_from_slice(&pub33);

    for input in &mut tx.inputs {
        input.script_sig = ss.clone();
    }

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
    validate_and_apply_block(db, blk, epoch_of(height), height)?;
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

#[test]
fn bad_candidate_reorg_rolls_back_cleanly_and_preserves_tip() -> Result<()> {
    let tmp = TempDir::new()?;
    let db = open_db(&tmp)?;

    let sk = [13u8; 32];
    let signer = signer_addr(sk);
    let miner_good = h20(0xA1);
    let miner_bad = h20(0xB2);

    let shared_len = 130u64;
    let fork_parent_height = 100u64;
    let start_time = 1_700_500_000u64;

    let shared = build_base_chain_with_miner(&db, shared_len, start_time, signer)?;
    let shared_tip = shared[fork_parent_height as usize];
    set_tip(&db, &shared_tip)?;
    assert_tip_eq(&db, shared_tip)?;

    let mut funds = Vec::new();
    for bh in shared.iter().take(shared_len as usize).skip(2) {
        let b = load_block(&db, bh)?;
        let cb = &b.txs[0];
        funds.push((
            OutPoint {
                txid: csd::crypto::txid(cb),
                vout: 0,
            },
            cb.outputs[0].value,
        ));
    }

    // Good canonical branch: 6 blocks
    let mut good_prev = shared_tip;
    let mut fund_i = 0usize;
    for step in 0..6u64 {
        let height = fork_parent_height + 1 + step;
        let (op, v) = funds[fund_i];
        fund_i += 1;

        let fee = csd::params::MIN_FEE_PROPOSE;
        let tx = make_signed_tx_with_custom_inputs(
            vec![op],
            vec![TxOut {
                value: v - fee,
                script_pubkey: signer,
            }],
            AppPayload::Propose {
                domain: "science".into(),
                payload_hash: [0x71, step as u8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
                uri: format!("ipfs://good/{step}"),
                expires_epoch: epoch_of(height) + 2,
            },
            sk,
        );

        let all_txs = vec![
            csd::chain::mine::coinbase(
                miner_good,
                csd::params::block_reward(height) + fee,
                height,
                None,
            ),
            tx,
        ];

        let hdr = make_test_header(&db, good_prev, &all_txs, height)?;
        let blk = Block { header: hdr, txs: all_txs };
        good_prev = persist_index_apply_block(&db, &blk, height)?;
    }

    let good_tip = good_prev;
    assert_tip_eq(&db, good_tip)?;

    let epochs = [
        epoch_of(fork_parent_height - 1),
        epoch_of(fork_parent_height),
        epoch_of(fork_parent_height + 1),
    ];

    let mut before = Vec::new();
    for epoch in epochs {
        for domain in ["science", "ai"] {
            before.push((epoch, domain.to_string(), get_topk(&db, epoch, domain)?));
        }
    }

    // Bad heavier branch: first 7 blocks valid-ish, last block invalid
    let mut bad_prev = shared_tip;
    let mut bad_fund_i = 20usize;

    for step in 0..7u64 {
        let height = fork_parent_height + 1 + step;
        let (op, v) = funds[bad_fund_i];
        bad_fund_i += 1;

        let fee = csd::params::MIN_FEE_PROPOSE;
        let tx = make_signed_tx_with_custom_inputs(
            vec![op],
            vec![TxOut {
                value: v - fee,
                script_pubkey: signer,
            }],
            AppPayload::Propose {
                domain: "ai".into(),
                payload_hash: [0x81, step as u8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
                uri: format!("ipfs://bad/{step}"),
                expires_epoch: epoch_of(height) + 2,
            },
            sk,
        );

        let all_txs = vec![
            csd::chain::mine::coinbase(
                miner_bad,
                csd::params::block_reward(height) + fee,
                height,
                None,
            ),
            tx,
        ];

        let hdr = make_test_header(&db, bad_prev, &all_txs, height)?;
        let blk = Block { header: hdr, txs: all_txs };
        bad_prev = persist_index_only_block(&db, &blk)?;
    }

    // Final heavier block is invalid: double-spends same prevout inside one tx
    let bad_height = fork_parent_height + 1 + 7;
    let (op, v) = funds[bad_fund_i];
    let fee = csd::params::MIN_FEE_PROPOSE * 2;

    let invalid_tx = make_signed_tx_with_custom_inputs(
        vec![op, op],
        vec![TxOut {
            value: v * 2 - fee,
            script_pubkey: signer,
        }],
        AppPayload::None,
        sk,
    );

    let invalid_txs = vec![
        csd::chain::mine::coinbase(
            miner_bad,
            csd::params::block_reward(bad_height) + fee,
            bad_height,
            None,
        ),
        invalid_tx,
    ];

    let invalid_hdr = make_test_header(&db, bad_prev, &invalid_txs, bad_height)?;
    let invalid_blk = Block {
        header: invalid_hdr,
        txs: invalid_txs,
    };
    let bad_tip = persist_index_only_block(&db, &invalid_blk)?;

    let hi_good = get_hidx(&db, &good_tip)?.expect("missing good tip");
    let hi_bad = get_hidx(&db, &bad_tip)?.expect("missing bad tip");
    assert!(hi_bad.height > hi_good.height);

    flush_all_state_trees(&db)?;
    let err = maybe_reorg_to(&db, &bad_tip, None).expect_err("bad reorg should fail");
    let msg = format!("{:#}", err);
    assert!(
        msg.contains("missing utxo")
            || msg.contains("double")
            || msg.contains("apply")
            || msg.contains("validate"),
        "unexpected error: {msg}"
    );

    assert_tip_eq(&db, good_tip)?;

    let mut after = Vec::new();
    for epoch in epochs {
        for domain in ["science", "ai"] {
            after.push((epoch, domain.to_string(), get_topk(&db, epoch, domain)?));
        }
    }

    assert_eq!(before, after, "state changed after failed reorg");
    Ok(())
}
