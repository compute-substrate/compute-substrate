// tests/consensus_accepts_valid_pow_block.rs
use anyhow::{Context, Result};
use tempfile::TempDir;

use csd::chain::index::{get_hidx, header_hash, index_header};
use csd::chain::pow::pow_ok;
use csd::state::app_state::epoch_of;
use csd::state::db::{get_tip, k_block, set_tip};
use csd::state::utxo::validate_and_apply_block;
use csd::types::{Block, BlockHeader, Hash20, Hash32};

mod testutil_chain;
use testutil_chain::{assert_tip_eq, build_base_chain_with_miner, open_db};

fn h20(n: u8) -> Hash20 {
    [n; 20]
}

fn mine_valid_header(mut hdr: BlockHeader) -> Result<BlockHeader> {
    loop {
        let hh = header_hash(&hdr);
        if pow_ok(&hh, hdr.bits) {
            return Ok(hdr);
        }
        hdr.nonce = hdr.nonce.wrapping_add(1);
    }
}

#[test]
fn accepts_valid_pow_block_without_bypass() -> Result<()> {
    let tmp = TempDir::new().context("tmp")?;
    let db = open_db(&tmp).context("open db")?;

    let miner = h20(0x11);
    let shared_len = 7u64;
    let start_time = 1_701_100_000u64;

    let shared = build_base_chain_with_miner(&db, shared_len, start_time, miner)
        .context("build shared chain")?;
    let parent_tip = shared[(shared_len - 1) as usize];
    assert_tip_eq(&db, parent_tip)?;

    let parent_hi = get_hidx(&db, &parent_tip)?
        .context("missing parent hidx")?;

    let height = parent_hi.height + 1;
    let reward = csd::params::block_reward(height);

    let cb = csd::chain::mine::coinbase(miner, reward, height, None);
    let txs = vec![cb];

    let merkle = {
        let ids: Vec<Hash32> = txs.iter().map(csd::crypto::txid).collect();
        csd::chain::mine::merkle_root_txids(&ids)
    };

    let mut hdr = BlockHeader {
        version: 1,
        prev: parent_tip,
        merkle,
        time: parent_hi.time.saturating_add(csd::params::MIN_BLOCK_SPACING_SECS),
        bits: csd::chain::pow::expected_bits(&db, height, Some(&parent_hi))
            .context("expected_bits")?,
        nonce: 0,
    };

    hdr = mine_valid_header(hdr).context("mine valid header")?;

    let blk = Block {
        header: hdr.clone(),
        txs,
    };

    let bh = header_hash(&hdr);
    let bytes = csd::codec::consensus_bincode()
        .serialize(&blk)
        .context("serialize block")?;
    db.blocks
        .insert(k_block(&bh), bytes)
        .context("db.blocks.insert")?;

    let hi = index_header(&db, &hdr, Some(&parent_hi))
        .context("index_header should accept valid PoW block")?;
    assert_eq!(hi.height, height, "indexed height mismatch");

    validate_and_apply_block(&db, &blk, epoch_of(height), height)
        .context("validate_and_apply_block should accept valid block")?;

    set_tip(&db, &bh).context("set_tip")?;

    let tip = get_tip(&db)?.context("missing tip after apply")?;
    assert_eq!(tip, bh, "final tip should be the mined block");

    Ok(())
}
