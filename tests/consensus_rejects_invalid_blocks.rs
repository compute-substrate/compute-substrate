// tests/consensus_rejects_invalid_blocks.rs
use anyhow::{Context, Result};
use tempfile::TempDir;

use csd::chain::index::{get_hidx, header_hash, index_header};
use csd::chain::pow::expected_bits;
use csd::crypto::txid;
use csd::state::app_state::epoch_of;
use csd::state::utxo::validate_and_apply_block;
use csd::types::{Block, Hash20, Hash32};

mod testutil_chain;
use testutil_chain::{build_base_chain_with_miner, make_test_header, open_db};

fn h20(n: u8) -> Hash20 {
    [n; 20]
}

fn make_valid_next_block(
    db: &csd::state::db::Stores,
    parent: Hash32,
    height: u64,
    miner: Hash20,
) -> Result<Block> {
    let cb = csd::chain::mine::coinbase(
        miner,
        csd::params::block_reward(height),
        height,
        None,
    );
    let txs = vec![cb];
    let hdr = make_test_header(db, parent, &txs, height)
        .with_context(|| format!("make_test_header h={height}"))?;
    Ok(Block { header: hdr, txs })
}

#[test]
fn rejects_block_with_bad_merkle_root() -> Result<()> {
    let tmp = TempDir::new()?;
    let db = open_db(&tmp)?;

    let miner = h20(0x11);
    let shared = build_base_chain_with_miner(&db, 7, 1_701_100_000, miner)?;
    let parent = shared[6];
    let height = 7u64;

    let mut blk = make_valid_next_block(&db, parent, height, miner)?;
    blk.header.merkle = [0xAA; 32]; // corrupt it

    let parent_hi = get_hidx(&db, &parent)?.expect("missing parent hidx");
    index_header(&db, &blk.header, Some(&parent_hi)).context("index_header bad merkle")?;

    let err = validate_and_apply_block(&db, &blk, epoch_of(height), height)
        .expect_err("block with bad merkle root must be rejected");

    let msg = format!("{err:#}");
    assert!(
        msg.to_lowercase().contains("merkle"),
        "expected merkle-related rejection, got: {msg}"
    );

    Ok(())
}

#[test]
fn rejects_block_with_missing_parent() -> Result<()> {
    let tmp = TempDir::new()?;
    let db = open_db(&tmp)?;

    let miner = h20(0x22);
    let height = 1u64;

    let fake_parent = [0x55; 32];
    let cb = csd::chain::mine::coinbase(
        miner,
        csd::params::block_reward(height),
        height,
        None,
    );
    let txs = vec![cb];

    let hdr = csd::types::BlockHeader {
        version: 1,
        prev: fake_parent,
        merkle: {
            let ids = vec![txid(&txs[0])];
            csd::chain::mine::merkle_root_txids(&ids)
        },
        time: 1_701_200_000,
        bits: 0x1e00ffff,
        nonce: 0,
    };

    let blk = Block { header: hdr, txs };

    let err = index_header(&db, &blk.header, None)
        .expect_err("index_header should reject block whose parent is unknown");

    let msg = format!("{err:#}");
    assert!(
        msg.to_lowercase().contains("parent")
            || msg.to_lowercase().contains("prev")
            || msg.to_lowercase().contains("missing"),
        "expected missing-parent rejection, got: {msg}"
    );

    Ok(())
}

#[test]
fn rejects_block_with_bad_coinbase_value() -> Result<()> {
    let tmp = TempDir::new()?;
    let db = open_db(&tmp)?;

    let miner = h20(0x33);
    let shared = build_base_chain_with_miner(&db, 7, 1_701_300_000, miner)?;
    let parent = shared[6];
    let height = 7u64;

    let mut blk = make_valid_next_block(&db, parent, height, miner)?;
    blk.txs[0].outputs[0].value += 1; // overpay coinbase

    // recompute merkle so the failure is really coinbase-value, not merkle
    let ids = blk.txs.iter().map(txid).collect::<Vec<_>>();
    blk.header.merkle = csd::chain::mine::merkle_root_txids(&ids);

    let parent_hi = get_hidx(&db, &parent)?.expect("missing parent hidx");
    index_header(&db, &blk.header, Some(&parent_hi)).context("index_header bad coinbase")?;

    let err = validate_and_apply_block(&db, &blk, epoch_of(height), height)
        .expect_err("block with overpaying coinbase must be rejected");

    let msg = format!("{err:#}");
    assert!(
        msg.to_lowercase().contains("coinbase")
            || msg.to_lowercase().contains("reward")
            || msg.to_lowercase().contains("fee"),
        "expected coinbase-value rejection, got: {msg}"
    );

    Ok(())
}

#[test]
fn rejects_block_with_bad_pow_when_pow_checks_enabled() -> Result<()> {
    // This test only makes sense if PoW checks are active in the environment.
    // If your test runs with CSD_BYPASS_POW=1, skip quietly.
    let bypass_pow = std::env::var("CSD_BYPASS_POW").ok().as_deref() == Some("1");
    if bypass_pow {
        return Ok(());
    }

    let tmp = TempDir::new()?;
    let db = open_db(&tmp)?;

    let miner = h20(0x44);
    let shared = build_base_chain_with_miner(&db, 7, 1_701_400_000, miner)?;
    let parent = shared[6];
    let height = 7u64;

    let parent_hi = get_hidx(&db, &parent)?.expect("missing parent hidx");

    let cb = csd::chain::mine::coinbase(
        miner,
        csd::params::block_reward(height),
        height,
        None,
    );
    let txs = vec![cb];

    let mut hdr = make_test_header(&db, parent, &txs, height)?;
    hdr.bits = expected_bits(&db, height, Some(&parent_hi))?;
    hdr.nonce = 0; // almost certainly invalid under real PoW

    let blk = Block { header: hdr, txs };

    let err = index_header(&db, &blk.header, Some(&parent_hi))
        .expect_err("index_header should reject bad PoW when PoW checks are enabled");

    let msg = format!("{err:#}");
    assert!(
        msg.to_lowercase().contains("pow")
            || msg.to_lowercase().contains("target")
            || msg.to_lowercase().contains("hash"),
        "expected PoW rejection, got: {msg}"
    );

    Ok(())
}
