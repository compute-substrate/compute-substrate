// tests/reorg_restores_mempool_transactions.rs
use anyhow::{Context, Result};
use std::sync::Arc;
use tempfile::TempDir;

use csd::chain::index::{get_hidx, header_hash, index_header};
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

#[test]
fn reorg_restores_transactions_from_old_branch_to_mempool() -> Result<()> {
    let tmp = TempDir::new().context("tmp")?;
    let db = Arc::new(open_db(&tmp).context("open db")?);
    let mp = Arc::new(Mempool::new());

    let miner_shared = signer_addr(SK); // so shared coinbase is spendable by our signed tx
    let miner_a = h20(0xA1);
    let miner_b = h20(0xB2);

    let shared_len = 7u64; // heights 0..6
    let start_time = 1_701_000_000u64;

    // Build shared prefix and leave tip at common_tip.
    let shared = build_base_chain_with_miner(&db, shared_len, start_time, miner_shared)
        .context("build shared")?;
    let common_tip = shared[(shared_len - 1) as usize];
    assert_tip_eq(&db, common_tip)?;

    // Build a tx that spends the shared-tip coinbase, so it remains valid on either branch.
    let common_tip_block_bytes = db
        .blocks
        .get(k_block(&common_tip))?
        .context("missing common tip block bytes")?;
    let common_tip_block: Block = csd::codec::consensus_bincode()
        .deserialize(&common_tip_block_bytes)
        .context("deserialize common tip block")?;

    let spend_prevout = OutPoint {
        txid: txid(&common_tip_block.txs[0]),
        vout: 0,
    };
    let spend_value = common_tip_block.txs[0].outputs[0].value;

    let resurrectable_tx = make_signed_tx(spend_prevout, spend_value, 5_000, h20(0x44));
    let resurrectable_txid = txid(&resurrectable_tx);

    let added = mp
        .insert_checked(&db, resurrectable_tx.clone())
        .context("insert_checked resurrectable tx")?;
    assert!(added, "expected tx to enter mempool");
    assert!(mp.contains(&resurrectable_txid), "mempool should contain tx before mining");

    // Branch A: include the tx in A1, then extend to A2 so A is initially canonical.
    let height_a1 = shared_len;
    let a1_cb = csd::chain::mine::coinbase(
        miner_a,
        csd::params::block_reward(height_a1) + 5_000,
        height_a1,
        None,
    );
    let a1_txs = vec![a1_cb, resurrectable_tx.clone()];
    let a1_hdr = make_test_header(&db, common_tip, &a1_txs, height_a1)
        .context("make_test_header a1")?;
    let a1_blk = Block {
        header: a1_hdr,
        txs: a1_txs,
    };
    let tip_a1 = persist_index_block_only(&db, &a1_blk).context("persist a1")?;
    maybe_reorg_to(&db, &tip_a1, Some(&mp)).context("maybe_reorg_to a1")?;

    assert!(!mp.contains(&resurrectable_txid), "tx should be removed from mempool once mined");
    assert_eq!(mp.len(), 0, "mempool should be empty after A1 mines tx");

    let height_a2 = shared_len + 1;
    let a2_cb = csd::chain::mine::coinbase(
        miner_a,
        csd::params::block_reward(height_a2),
        height_a2,
        None,
    );
    let a2_txs = vec![a2_cb];
    let a2_hdr = make_test_header(&db, tip_a1, &a2_txs, height_a2)
        .context("make_test_header a2")?;
    let a2_blk = Block {
        header: a2_hdr,
        txs: a2_txs,
    };
    let tip_a2 = persist_index_block_only(&db, &a2_blk).context("persist a2")?;
    maybe_reorg_to(&db, &tip_a2, Some(&mp)).context("maybe_reorg_to a2")?;
    assert_tip_eq(&db, tip_a2)?;

    // Branch B: heavier competing branch from common_tip, WITHOUT the tx.
    let height_b1 = shared_len;
    let b1_cb = csd::chain::mine::coinbase(
        miner_b,
        csd::params::block_reward(height_b1),
        height_b1,
        None,
    );
    let b1_txs = vec![b1_cb];
    let b1_hdr = make_test_header(&db, common_tip, &b1_txs, height_b1)
        .context("make_test_header b1")?;
    let b1_blk = Block {
        header: b1_hdr,
        txs: b1_txs,
    };
    let tip_b1 = persist_index_block_only(&db, &b1_blk).context("persist b1")?;

    let height_b2 = shared_len + 1;
    let b2_cb = csd::chain::mine::coinbase(
        miner_b,
        csd::params::block_reward(height_b2),
        height_b2,
        None,
    );
    let b2_txs = vec![b2_cb];
    let b2_hdr = make_test_header(&db, tip_b1, &b2_txs, height_b2)
        .context("make_test_header b2")?;
    let b2_blk = Block {
        header: b2_hdr,
        txs: b2_txs,
    };
    let tip_b2 = persist_index_block_only(&db, &b2_blk).context("persist b2")?;

    let height_b3 = shared_len + 2;
    let b3_cb = csd::chain::mine::coinbase(
        miner_b,
        csd::params::block_reward(height_b3),
        height_b3,
        None,
    );
    let b3_txs = vec![b3_cb];
    let b3_hdr = make_test_header(&db, tip_b2, &b3_txs, height_b3)
        .context("make_test_header b3")?;
    let b3_blk = Block {
        header: b3_hdr,
        txs: b3_txs,
    };
    let tip_b3 = persist_index_block_only(&db, &b3_blk).context("persist b3")?;

    // Reorg to heavier branch B.
    maybe_reorg_to(&db, &tip_b3, Some(&mp)).context("maybe_reorg_to b3")?;

    let final_tip = get_tip(&db)?.expect("missing final tip");
    assert_eq!(final_tip, tip_b3, "tip should move to heavier B branch");

    // The tx from orphaned A1 should be restored to mempool.
    assert!(
        mp.contains(&resurrectable_txid),
        "tx from orphaned old branch should return to mempool"
    );
    assert_eq!(mp.len(), 1, "exactly one tx should be restored to mempool");

    let hi_final = get_hidx(&db, &final_tip)?.expect("missing final hidx");
    assert_eq!(hi_final.height, height_b3, "final tip height should be B3");

    Ok(())
}
