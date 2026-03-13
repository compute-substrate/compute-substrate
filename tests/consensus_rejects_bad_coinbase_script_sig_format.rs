// tests/consensus_rejects_bad_coinbase_script_sig_format.rs
use anyhow::{Context, Result};
use tempfile::TempDir;

use csd::chain::index::{get_hidx, header_hash, index_header};
use csd::chain::mine::coinbase;
use csd::state::app_state::epoch_of;
use csd::state::db::{k_block, set_tip, Stores};
use csd::state::utxo::validate_and_apply_block;
use csd::types::{Block, Hash20};

mod testutil_chain;
use testutil_chain::{build_base_chain_with_miner, make_test_header, open_db};

fn h20(n: u8) -> Hash20 {
    [n; 20]
}

fn persist_index_apply_block(db: &Stores, blk: &Block, height: u64) -> Result<[u8; 32]> {
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
        .with_context(|| format!("apply h={height}"))?;
    set_tip(db, &bh).context("set_tip")?;

    Ok(bh)
}

#[test]
fn rejects_block_with_bad_coinbase_script_sig_format() -> Result<()> {
    let tmp = TempDir::new().context("tmp")?;
    let db = open_db(&tmp).context("open db")?;

    let miner = h20(0x11);
    let shared_len = 7u64; // heights 0..6
    let start_time = 1_701_500_000u64;

    let shared = build_base_chain_with_miner(&db, shared_len, start_time, miner)
        .context("build shared chain")?;
    let parent = shared[(shared_len - 1) as usize];

    let height = shared_len;

    // Start from a normal coinbase, then corrupt the script_sig format.
    // Current consensus expects the first 8 bytes of coinbase script_sig
    // to be exactly `height.to_le_bytes()`.
    let mut bad_cb = coinbase(
        miner,
        csd::params::block_reward(height),
        height,
        None,
    );

    // Bad format: too short / missing required 8-byte height commitment.
    bad_cb.inputs[0].script_sig = vec![0xAA, 0xBB, 0xCC];

    let txs = vec![bad_cb];
    let hdr = make_test_header(&db, parent, &txs, height)
        .with_context(|| format!("make_test_header h={height}"))?;
    let blk = Block { header: hdr, txs };

    // Header/indexing should be fine; block validation should reject coinbase format.
    let bh = header_hash(&blk.header);
    let bytes = csd::codec::consensus_bincode()
        .serialize(&blk)
        .context("serialize invalid block")?;
    db.blocks
        .insert(k_block(&bh), bytes)
        .context("store invalid block bytes")?;

    let parent_hi = get_hidx(&db, &parent).context("get_hidx(parent)")?;
    index_header(&db, &blk.header, parent_hi.as_ref()).context("index_header invalid block")?;

    let err = validate_and_apply_block(&db, &blk, epoch_of(height), height)
        .expect_err("block with malformed coinbase script_sig must be rejected");

    let msg = format!("{err:#}");
    assert!(
        msg.contains("coinbase")
            && (msg.contains("script_sig")
                || msg.contains("height")
                || msg.contains("format")
                || msg.contains("short")),
        "unexpected error: {msg}"
    );

    Ok(())
}
