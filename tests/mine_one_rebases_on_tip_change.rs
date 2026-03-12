// tests/mine_one_rebases_on_tip_change.rs
use anyhow::{Context, Result};
use std::sync::Arc;
use std::thread;
use std::time::Duration;
use tempfile::TempDir;

use csd::chain::index::{get_hidx, header_hash, index_header};
use csd::chain::mine::mine_one;
use csd::chain::reorg::maybe_reorg_to;
use csd::crypto::txid;
use csd::net::mempool::Mempool;
use csd::state::app_state::epoch_of;
use csd::state::db::{get_tip, k_block, set_tip, Stores};
use csd::state::utxo::validate_and_apply_block;
use csd::types::{AppPayload, Block, Hash20, Hash32, OutPoint, Transaction, TxIn, TxOut};

mod testutil_chain;
use testutil_chain::{assert_tip_eq, build_base_chain_with_miner, make_test_header, open_db};

const SK: [u8; 32] = [21u8; 32];

fn h20(n: u8) -> Hash20 {
    [n; 20]
}

fn signer_addr(sk32: [u8; 32]) -> [u8; 20] {
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

fn make_signed_tx(prevout: OutPoint, input_value: u64, fee: u64, to: [u8; 20]) -> Transaction {
    let send = input_value - fee;

    let mut tx = Transaction {
        version: 1,
        inputs: vec![TxIn {
            prevout,
            script_sig: vec![0u8; 99],
        }],
        outputs: vec![TxOut {
            value: send,
            script_pubkey: to,
        }],
        locktime: 0,
        app: AppPayload::None,
    };

    let (sig64, pub33) = csd::crypto::sign_tx_compact_secp256k1(&tx, SK);

    let mut ss = Vec::with_capacity(99);
    ss.push(64);
    ss.extend_from_slice(&sig64);
    ss.push(33);
    ss.extend_from_slice(&pub33);
    tx.inputs[0].script_sig = ss;

    tx
}

fn persist_index_apply_block(db: &Stores, blk: &Block, height: u64) -> Result<Hash32> {
    let bh = header_hash(&blk.header);

    let bytes = csd::codec::consensus_bincode()
        .serialize(blk)
        .context("serialize block")?;
    db.blocks
        .insert(k_block(&bh), bytes)
        .context("db.blocks.insert")?;

    let parent_hi = if blk.header.prev == [0u8; 32] {
        None
    } else {
        get_hidx(db, &blk.header.prev).context("get_hidx(parent)")?
    };

    index_header(db, &blk.header, parent_hi.as_ref()).context("index_header")?;
    validate_and_apply_block(db, blk, epoch_of(height), height)
        .with_context(|| format!("validate_and_apply_block h={height}"))?;
    set_tip(db, &bh).context("set_tip")?;

    Ok(bh)
}

fn persist_index_block_only(db: &Stores, blk: &Block) -> Result<Hash32> {
    let bh = header_hash(&blk.header);

    let bytes = csd::codec::consensus_bincode()
        .serialize(blk)
        .context("serialize block")?;
    db.blocks
        .insert(k_block(&bh), bytes)
        .context("db.blocks.insert")?;

    let parent_hi = if blk.header.prev == [0u8; 32] {
        None
    } else {
        get_hidx(db, &blk.header.prev).context("get_hidx(parent)")?
    };

    index_header(db, &blk.header, parent_hi.as_ref()).context("index_header")?;
    Ok(bh)
}

fn load_block(db: &Stores, bh: &Hash32) -> Result<Block> {
    let Some(v) = db.blocks.get(k_block(bh))? else {
        anyhow::bail!("missing block bytes for 0x{}", hex::encode(bh));
    };
    Ok(csd::codec::consensus_bincode().deserialize::<Block>(&v)?)
}

#[test]
fn mine_one_rebases_on_tip_change_and_rebuilds_template() -> Result<()> {
    let tmp = TempDir::new().context("tmp")?;
    let db = Arc::new(open_db(&tmp).context("open db")?);
    let mp = Arc::new(Mempool::new());

    let miner_shared = h20(0x11);
    let miner_a = signer_addr(SK); // old tip creates a spendable output for our mempool tx
    let miner_b = h20(0x77);
    let miner_final = h20(0x99);

    let shared_len = 7u64; // heights 0..6
    let start_time = 1_700_900_000u64;

    // Shared canonical prefix.
    let shared = build_base_chain_with_miner(&db, shared_len, start_time, miner_shared)
        .context("build shared")?;
    let common_tip = shared[(shared_len - 1) as usize];
    assert_tip_eq(&db, common_tip)?;

    // Build old canonical tip A1 from the shared ancestor.
    let height_a1 = shared_len;
    let a1_cb = csd::chain::mine::coinbase(miner_a, csd::params::block_reward(height_a1), height_a1, None);
    let a1_txs = vec![a1_cb.clone()];
    let a1_hdr = make_test_header(&db, common_tip, &a1_txs, height_a1)
        .context("make_test_header a1")?;
    let a1_blk = Block {
        header: a1_hdr,
        txs: a1_txs,
    };
    let tip_a1 = persist_index_apply_block(&db, &a1_blk, height_a1).context("apply a1")?;
    assert_tip_eq(&db, tip_a1)?;

    // Mempool tx spends the old-tip coinbase output.
    // If mine_one rebases to branch B, this tx becomes invalid and must be dropped from template.
    let old_coinbase_prevout = OutPoint {
        txid: txid(&a1_blk.txs[0]),
        vout: 0,
    };
    let old_coinbase_value = a1_blk.txs[0].outputs[0].value;

    let spend_old_tip_tx = make_signed_tx(old_coinbase_prevout, old_coinbase_value, 5_000, h20(0x42));
    let spend_old_tip_txid = txid(&spend_old_tip_tx);

    let added = mp.insert_checked(&db, spend_old_tip_tx.clone())
        .context("insert_checked spend_old_tip_tx")?;
    assert!(added, "expected mempool tx to be accepted on old tip");
    assert!(mp.contains(&spend_old_tip_txid), "mempool should contain old-tip spend");

    // Pre-build side-branch blocks B1/B2 from the shared ancestor, but do not apply yet.
    let height_b1 = shared_len;
    let b1_cb = csd::chain::mine::coinbase(miner_b, csd::params::block_reward(height_b1), height_b1, None);
    let b1_txs = vec![b1_cb];
    let b1_hdr = make_test_header(&db, common_tip, &b1_txs, height_b1)
        .context("make_test_header b1")?;
    let b1_blk = Block {
        header: b1_hdr,
        txs: b1_txs,
    };
    let tip_b1 = persist_index_block_only(&db, &b1_blk).context("persist b1")?;

    let height_b2 = shared_len + 1;
    let b2_cb = csd::chain::mine::coinbase(miner_b, csd::params::block_reward(height_b2), height_b2, None);
    let b2_txs = vec![b2_cb];
    let b2_hdr = make_test_header(&db, tip_b1, &b2_txs, height_b2)
        .context("make_test_header b2")?;
    let b2_blk = Block {
        header: b2_hdr,
        txs: b2_txs,
    };
    let tip_b2 = persist_index_block_only(&db, &b2_blk).context("persist b2")?;

    let db_miner = db.clone();
    let mp_miner = mp.clone();

    let miner_thread = thread::spawn(move || -> Result<Hash32> {
        let chain_lock = csd::chain::lock::new_chain_lock();
        mine_one(&db_miner, &mp_miner, miner_final, 100, &chain_lock)
            .context("mine_one")
    });

    // Give miner a brief chance to enter its loop on A1, then externally switch tip to B2.
    // Even if the thread starts slightly later, the key invariant still holds:
    // it must not mine on stale A1, and the invalidated tx must not be included.
    thread::sleep(Duration::from_millis(10));

    maybe_reorg_to(&db, &tip_b2, Some(&mp)).context("maybe_reorg_to b2")?;
    assert_tip_eq(&db, tip_b2)?;

    let mined_hash = miner_thread
        .join()
        .expect("miner thread panicked")?;


    let mined_block = load_block(&db, &mined_hash).context("load mined block")?;
    let final_tip = get_tip(&db)?.expect("missing final tip");

    // The mined block must extend the externally selected branch, not stale A1.
    assert_eq!(
        mined_block.header.prev,
        tip_b2,
        "mined block must build on rebased tip B2, not stale A1"
    );
    assert_eq!(
        final_tip,
        mined_hash,
        "mined block should become the selected final tip"
    );

    // The old-tip spend must not survive template rebuild after rebase.
    assert_eq!(
        mined_block.txs.len(),
        1,
        "rebased block should contain only coinbase after invalid old-tip tx is dropped"
    );
    assert_ne!(
        txid(&mined_block.txs[0]),
        spend_old_tip_txid,
        "coinbase must not equal old-tip spend txid"
    );

    // The mempool tx should be gone after the reorg + post-mine prune path.
    assert!(
        !mp.contains(&spend_old_tip_txid),
        "invalidated old-tip mempool tx should be pruned"
    );
    assert_eq!(mp.len(), 0, "mempool should be empty after prune");

    let hi_final = get_hidx(&db, &final_tip)?.expect("missing final hidx");
    let hi_b2 = get_hidx(&db, &tip_b2)?.expect("missing b2 hidx");
    assert_eq!(
        hi_final.height,
        hi_b2.height + 1,
        "mined block should sit exactly one height above rebased tip"
    );

    Ok(())
}
