// tests/consensus_rejects_coinbase_wrong_locktime_height.rs
#![cfg(feature = "test-bypass")]

use anyhow::{Context, Result};
use tempfile::TempDir;

use csd::chain::index::{get_hidx, header_hash, index_header};
use csd::state::app_state::epoch_of;
use csd::state::db::k_block;
use csd::state::utxo::validate_and_apply_block;
use csd::types::{Block, Hash20};

mod testutil_chain;
use testutil_chain::{assert_tip_eq, build_base_chain_with_miner, make_test_header, open_db};

fn h20(n: u8) -> Hash20 {
    [n; 20]
}

#[test]
fn rejects_block_with_coinbase_wrong_locktime_height() -> Result<()> {
    let tmp = TempDir::new().context("tmp")?;
    let db = open_db(&tmp).context("open db")?;

    let miner_shared = h20(0x11);
    let miner_block = h20(0xA1);

    let shared_len = 7u64; // heights 0..6
    let start_time = 1_701_500_000u64;

    let shared = build_base_chain_with_miner(&db, shared_len, start_time, miner_shared)
        .context("build shared chain")?;
    let common_tip = shared[(shared_len - 1) as usize];
    assert_tip_eq(&db, common_tip)?;

    let height = shared_len; // next block should be height 7

    // Start from a normal coinbase, then corrupt locktime so it no longer matches height.
    let mut bad_coinbase = csd::chain::mine::coinbase(
        miner_block,
        csd::params::block_reward(height),
        height,
        None,
    );
    bad_coinbase.locktime = (height as u32).saturating_add(1);

    let txs = vec![bad_coinbase];
    let hdr = make_test_header(&db, common_tip, &txs, height)
        .context("make_test_header wrong-locktime-height")?;
    let blk = Block { header: hdr, txs };

    let bh = header_hash(&blk.header);

    let bytes = csd::codec::consensus_bincode()
        .serialize(&blk)
        .context("serialize wrong-locktime-height block")?;
    db.blocks
        .insert(k_block(&bh), bytes)
        .context("db.blocks.insert wrong-locktime-height block")?;

    let parent_hi = get_hidx(&db, &common_tip)
        .context("get_hidx(common_tip)")?
        .context("missing parent hidx")?;
    index_header(&db, &blk.header, Some(&parent_hi))
        .context("index_header wrong-locktime-height block")?;

    let err = validate_and_apply_block(&db, &blk, epoch_of(height), height)
        .expect_err("block with wrong coinbase locktime/height commitment must be rejected");

    let msg = format!("{err:#}").to_lowercase();
    assert!(
        msg.contains("coinbase")
            || msg.contains("locktime")
            || msg.contains("height"),
        "unexpected error: {}",
        err
    );

    Ok(())
}
