use anyhow::{Context, Result};
use rand::{Rng, SeedableRng};
use rand::rngs::StdRng;
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
    fee: u64,
    sk32: [u8; 32],
    app: AppPayload,
) -> Transaction {
    let send_value = prev_value - fee;

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
fn random_fuzz_reorg_app_state_matches_replay() -> Result<()> {
    for seed in 0u64..10u64 {
        let tmp = TempDir::new().context("tmp")?;
        let db = open_db(&tmp).context("open db")?;

        let mut rng = StdRng::seed_from_u64(seed);
        let sk = [17u8; 32];
        let signer = signer_addr(sk);
        let user_addr = signer;

        let shared_len = 220u64;
        let fork_parent_height = 100u64;
        let start_time = 1_700_700_000 + seed * 1000;

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

        let mut fund_i = 0usize;

        // Applied branch A
        let mut prev_a = shared_tip;
        let blocks_a = rng.gen_range(5u64..8u64);
        for step in 0..blocks_a {
            let height = fork_parent_height + 1 + step;
            let epoch = epoch_of(height);

            let prop_n = rng.gen_range(1usize..=3usize);
            let att_n = rng.gen_range(0usize..=3usize);

            let mut txs = Vec::new();
            let mut fees = 0u64;
            let mut pids = Vec::<Hash32>::new();

            for j in 0..prop_n {
                let (op, v) = funds[fund_i];
                fund_i += 1;
                let fee = csd::params::MIN_FEE_PROPOSE;
                fees += fee;

                let mut payload_hash = [0u8; 32];
                payload_hash[0] = 0x91;
                payload_hash[1] = seed as u8;
                payload_hash[2] = step as u8;
                payload_hash[3] = j as u8;

                let tx = make_spend_tx(
                    op,
                    v,
                    user_addr,
                    fee,
                    sk,
                    AppPayload::Propose {
                        domain: if rng.gen_bool(0.5) { "science".into() } else { "ai".into() },
                        payload_hash,
                        uri: format!("ipfs://fuzz/a/{seed}/{step}/{j}"),
                        expires_epoch: epoch + 3,
                    },
                );
                pids.push(csd::crypto::txid(&tx));
                txs.push(tx);
            }

            for k in 0..att_n {
                if pids.is_empty() {
                    break;
                }
                let (op, v) = funds[fund_i];
                fund_i += 1;
                let fee = csd::params::MIN_FEE_ATTEST + rng.gen_range(0u64..50u64);
                fees += fee;

                txs.push(make_spend_tx(
                    op,
                    v,
                    user_addr,
                    fee,
                    sk,
                    AppPayload::Attest {
                        proposal_id: pids[k % pids.len()],
                        score: rng.gen_range(0u32..5000u32),
                        confidence: rng.gen_range(1u32..1000u32),
                    },
                ));
            }

            let mut all_txs = vec![csd::chain::mine::coinbase(
                h20(0xA1),
                csd::params::block_reward(height) + fees,
                height,
                None,
            )];
            all_txs.extend(txs);

            let hdr = make_test_header(&db, prev_a, &all_txs, height)?;
            let blk = Block { header: hdr, txs: all_txs };
            prev_a = persist_index_apply_block(&db, &blk, height)?;
        }

        let tip_a = prev_a;

        // Indexed-only heavier branch B
        let mut prev_b = shared_tip;
        let blocks_b = blocks_a + rng.gen_range(1u64..=3u64);
        for step in 0..blocks_b {
            let height = fork_parent_height + 1 + step;
            let epoch = epoch_of(height);

            let prop_n = rng.gen_range(1usize..=4usize);
            let att_n = rng.gen_range(0usize..=4usize);

            let mut txs = Vec::new();
            let mut fees = 0u64;
            let mut pids = Vec::<Hash32>::new();

            for j in 0..prop_n {
                let (op, v) = funds[fund_i];
                fund_i += 1;
                let fee = csd::params::MIN_FEE_PROPOSE;
                fees += fee;

                let mut payload_hash = [0u8; 32];
                payload_hash[0] = 0xA1;
                payload_hash[1] = seed as u8;
                payload_hash[2] = step as u8;
                payload_hash[3] = j as u8;

                let tx = make_spend_tx(
                    op,
                    v,
                    user_addr,
                    fee,
                    sk,
                    AppPayload::Propose {
                        domain: if rng.gen_bool(0.35) { "science".into() } else { "ai".into() },
                        payload_hash,
                        uri: format!("ipfs://fuzz/b/{seed}/{step}/{j}"),
                        expires_epoch: epoch + 5,
                    },
                );
                pids.push(csd::crypto::txid(&tx));
                txs.push(tx);
            }

            for k in 0..att_n {
                if pids.is_empty() {
                    break;
                }
                let (op, v) = funds[fund_i];
                fund_i += 1;
                let fee = csd::params::MIN_FEE_ATTEST + rng.gen_range(0u64..75u64);
                fees += fee;

                txs.push(make_spend_tx(
                    op,
                    v,
                    user_addr,
                    fee,
                    sk,
                    AppPayload::Attest {
                        proposal_id: pids[k % pids.len()],
                        score: rng.gen_range(0u32..7000u32),
                        confidence: rng.gen_range(1u32..1000u32),
                    },
                ));
            }

            let mut all_txs = vec![csd::chain::mine::coinbase(
                h20(0xB2),
                csd::params::block_reward(height) + fees,
                height,
                None,
            )];
            all_txs.extend(txs);

            let hdr = make_test_header(&db, prev_b, &all_txs, height)?;
            let blk = Block { header: hdr, txs: all_txs };
            prev_b = persist_index_only_block(&db, &blk)?;
        }

        let tip_b = prev_b;
        let hi_a = get_hidx(&db, &tip_a)?.expect("missing A");
        let hi_b = get_hidx(&db, &tip_b)?.expect("missing B");
        assert!(hi_b.height > hi_a.height, "seed={seed}: B must beat A");

        flush_all_state_trees(&db)?;
        maybe_reorg_to(&db, &tip_b, None).with_context(|| format!("seed={seed}: reorg to B"))?;
        assert_tip_eq(&db, tip_b)?;

        let replay_tmp = TempDir::new()?;
        let replay_db = open_db(&replay_tmp)?;
        replay_canonical_from_tip(&replay_db, &db, tip_b)
            .with_context(|| format!("seed={seed}: replay"))?;
        assert_tip_eq(&replay_db, tip_b)?;

        let epochs = [
            epoch_of(fork_parent_height - 1),
            epoch_of(fork_parent_height),
            epoch_of(fork_parent_height + 1),
            epoch_of(fork_parent_height + blocks_b),
        ];

        for epoch in epochs {
            for domain in ["science", "ai"] {
                let live = get_topk(&db, epoch, domain)
                    .with_context(|| format!("seed={seed} epoch={epoch} domain={domain} live"))?;
                let replay = get_topk(&replay_db, epoch, domain)
                    .with_context(|| format!("seed={seed} epoch={epoch} domain={domain} replay"))?;
                assert_eq!(
                    live, replay,
                    "seed={seed}: replay mismatch epoch={epoch} domain={domain}"
                );
            }
        }
    }

    Ok(())
}
