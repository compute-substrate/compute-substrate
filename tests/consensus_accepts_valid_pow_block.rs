// tests/consensus_accepts_valid_pow_block.rs
use anyhow::{Context, Result};
use tempfile::TempDir;

use csd::chain::genesis::make_genesis_block;
use csd::chain::index::{get_hidx, header_hash, index_header};
use csd::chain::pow::{expected_bits, pow_ok};
use csd::chain::time::median_time_past;
use csd::params::{MAX_FUTURE_DRIFT_SECS, MIN_BLOCK_SPACING_SECS};
use csd::state::app_state::current_epoch;
use csd::state::db::{get_tip, k_block, set_tip};
use csd::state::utxo::validate_and_apply_block;
use csd::types::{Block, BlockHeader, Hash20, Hash32};

mod testutil_chain;
use testutil_chain::open_db;

fn h20(n: u8) -> Hash20 {
    [n; 20]
}

fn mine_valid_header(mut hdr: BlockHeader) -> BlockHeader {
    loop {
        let hh = header_hash(&hdr);
        if pow_ok(&hh, hdr.bits) {
            return hdr;
        }
        hdr.nonce = hdr.nonce.wrapping_add(1);
    }
}

#[test]
fn accepts_valid_pow_block_without_bypass() -> Result<()> {
    let tmp = TempDir::new().context("tmp")?;
    let db = open_db(&tmp).context("open db")?;

    // IMPORTANT:
    // Replace this with the exact same burn address your production startup uses.
    let burn_addr = h20(0x00);

    // Build the real canonical genesis and persist/apply it.
    let genesis = make_genesis_block(burn_addr).context("make_genesis_block")?;
    let genesis_hash = header_hash(&genesis.header);

    let genesis_bytes = csd::codec::consensus_bincode()
        .serialize(&genesis)
        .context("serialize genesis")?;
    db.blocks
        .insert(k_block(&genesis_hash), genesis_bytes)
        .context("insert genesis bytes")?;

    let genesis_hi = index_header(&db, &genesis.header, None)
        .context("index genesis")?;
    assert_eq!(genesis_hi.height, 0, "genesis must be height 0");

    validate_and_apply_block(&db, &genesis, current_epoch(0), 0)
        .context("apply genesis")?;
    set_tip(&db, &genesis_hash).context("set genesis tip")?;

    let parent_hi = get_hidx(&db, &genesis_hash)?
        .context("missing genesis hidx")?;

    let height = 1u64;
    let miner = h20(0x11);

    let cb = csd::chain::mine::coinbase(
        miner,
        csd::params::block_reward(height),
        height,
        None,
    );
    let txs = vec![cb];

    let merkle = {
        let ids: Vec<Hash32> = txs.iter().map(csd::crypto::txid).collect();
        csd::chain::mine::merkle_root_txids(&ids)
    };

    let mtp = median_time_past(&db, &parent_hi.hash).unwrap_or(parent_hi.time);
    let min_time = parent_hi.time.saturating_add(MIN_BLOCK_SPACING_SECS);
    let mut time = min_time.max(mtp.saturating_add(1));
    let max_allowed = mtp.saturating_add(MAX_FUTURE_DRIFT_SECS);
    if time > max_allowed {
        time = max_allowed;
    }

    let hdr = BlockHeader {
        version: 1,
        prev: genesis_hash,
        merkle,
        time,
        bits: expected_bits(&db, height, Some(&parent_hi))
            .context("expected_bits")?,
        nonce: 0,
    };

    let hdr = mine_valid_header(hdr);
    let bh = header_hash(&hdr);

    let blk = Block {
        header: hdr.clone(),
        txs,
    };

    let bytes = csd::codec::consensus_bincode()
        .serialize(&blk)
        .context("serialize block")?;
    db.blocks
        .insert(k_block(&bh), bytes)
        .context("insert block bytes")?;

    let hi = index_header(&db, &hdr, Some(&parent_hi))
        .context("index valid pow block")?;
    assert_eq!(hi.height, 1, "new block must be height 1");

    validate_and_apply_block(&db, &blk, current_epoch(1), 1)
        .context("apply valid pow block")?;
    set_tip(&db, &bh).context("set final tip")?;

    let final_tip = get_tip(&db)?.context("missing final tip")?;
    assert_eq!(final_tip, bh, "tip should equal mined valid block");

    Ok(())
}
