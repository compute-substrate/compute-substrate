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
    // These two lines must come from your REAL chain genesis implementation,
    // not from testutil_chain.
    let genesis = csd::chain::genesis::genesis_block();
    let genesis_hash = header_hash(&genesis.header);

    // Persist + index + apply the REAL genesis
    let genesis_bytes = csd::codec::consensus_bincode()
        .serialize(&genesis)
        .context("serialize genesis")?;
    db.blocks
        .insert(k_block(&genesis_hash), genesis_bytes)
        .context("insert genesis bytes")?;

    let genesis_hi = index_header(&db, &genesis.header, None)
        .context("index real genesis")?;
    assert_eq!(genesis_hi.height, 0, "genesis must be height 0");

    validate_and_apply_block(&db, &genesis, epoch_of(0), 0)
        .context("apply real genesis")?;
    set_tip(&db, &genesis_hash).context("set genesis tip")?;

    // Build a valid block on top of the real genesis
    let miner = h20(0x11);
    let height = 1u64;
    let reward = csd::params::block_reward(height);

    let cb = csd::chain::mine::coinbase(miner, reward, height, None);
    let txs = vec![cb];

    let merkle = {
        let ids: Vec<Hash32> = txs.iter().map(csd::crypto::txid).collect();
        csd::chain::mine::merkle_root_txids(&ids)
    };

    let parent_hi = get_hidx(&db, &genesis_hash)?
        .context("missing genesis hidx")?;

    let hdr = BlockHeader {
        version: 1,
        prev: genesis_hash,
        merkle,
        time: parent_hi.time.saturating_add(csd::params::MIN_BLOCK_SPACING_SECS),
        bits: csd::chain::pow::expected_bits(&db, height, Some(&parent_hi))
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
        .context("index_header should accept valid PoW block")?;
    assert_eq!(hi.height, 1, "height should be 1");

    validate_and_apply_block(&db, &blk, epoch_of(1), 1)
        .context("validate_and_apply_block should accept valid block")?;

    set_tip(&db, &bh).context("set tip to mined block")?;

    let tip = get_tip(&db)?.context("missing final tip")?;
    assert_eq!(tip, bh, "tip should be the valid mined block");

    Ok(())
}
