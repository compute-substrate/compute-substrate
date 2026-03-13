// tests/consensus_rejects_multiple_coinbases.rs
use anyhow::{Context, Result};

use csd::chain::index::{get_hidx, header_hash, index_header};
use csd::state::app_state::epoch_of;
use csd::state::utxo::validate_and_apply_block;
use csd::types::{Block, Hash20};

mod testutil_chain;
use testutil_chain::{assert_tip_eq, build_base_chain_with_miner, make_test_header, open_db};

fn h20(n: u8) -> Hash20 {
    [n; 20]
}

#[test]
fn rejects_block_with_multiple_coinbases() -> Result<()> {
    let tmp = tempfile::TempDir::new().context("tmp")?;
    let db = open_db(&tmp).context("open db")?;

    let miner = h20(0x11);
    let start_time = 1_701_100_000u64;

    // Build a valid genesis block so we have a real parent/header index.
    let shared = build_base_chain_with_miner(&db, 1, start_time, miner)
        .context("build base chain")?;
    let genesis_tip = shared[0];

    assert_tip_eq(&db, genesis_tip)?;

    let height = 1u64;

    // Invalid block body: two coinbases.
    let cb1 = csd::chain::mine::coinbase(
        h20(0xA1),
        csd::params::block_reward(height),
        height,
        None,
    );
    let cb2 = csd::chain::mine::coinbase(
        h20(0xB2),
        csd::params::block_reward(height),
        height,
        None,
    );

    let txs = vec![cb1, cb2];

    let hdr = make_test_header(&db, genesis_tip, &txs, height)
        .context("make_test_header")?;

    let blk = Block { header: hdr, txs };

    let parent_hi = get_hidx(&db, &genesis_tip)
        .context("get_hidx(parent)")?
        .context("missing parent hidx")?;

    index_header(&db, &blk.header, Some(&parent_hi))
        .context("index_header should succeed; body validation should fail later")?;

    let err = validate_and_apply_block(&db, &blk, epoch_of(height), height)
        .expect_err("block with multiple coinbases must be rejected");

    let msg = format!("{err:#}");
    assert!(
        msg.to_lowercase().contains("coinbase"),
        "expected multiple-coinbase rejection, got: {msg}"
    );

    // Tip must remain unchanged.
    assert_tip_eq(&db, genesis_tip)?;

    // And the invalid block must not become canonical.
    let bad_hash = header_hash(&blk.header);
    assert_ne!(bad_hash, genesis_tip, "sanity: bad block hash should differ");

    Ok(())
}
