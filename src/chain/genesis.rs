use anyhow::Result;
use crate::types::{Block, BlockHeader};
use crate::chain::mine::coinbase;
use crate::chain::index::{header_hash, index_header};
use crate::state::db::{Stores, get_tip, set_tip, k_block};
use crate::state::utxo::validate_and_apply_block;
use crate::state::app::current_epoch;
use std::sync::Arc;

fn merkle_root(txs: &[crate::types::Transaction]) -> crate::types::Hash32 {
    let mut bytes = vec![];
    for tx in txs {
        bytes.extend_from_slice(&crate::crypto::txid(tx));
    }
    crate::crypto::sha256d(&bytes)
}

fn target_ok(hash: &crate::types::Hash32, _bits: u32) -> bool {
    // must match miner’s target_ok for consistency
    hash[0] == 0
}

pub fn make_genesis_block(burn_addr20: [u8;20]) -> Result<Block> {
    let cb = coinbase(burn_addr20, crate::params::BLOCK_REWARD);
    let txs = vec![cb];

    let merkle = merkle_root(&txs);

    let mut hdr = BlockHeader {
        version: 1,
        prev: [0u8;32],
        merkle,
        time: 1700000000, // fixed timestamp
        bits: crate::params::INITIAL_BITS,
        nonce: 0,
    };

    loop {
        let h = header_hash(&hdr);
        if target_ok(&h, hdr.bits) {
            return Ok(Block { header: hdr, txs });
        }
        hdr.nonce = hdr.nonce.wrapping_add(1);
    }
}

/// Ensure genesis is stored + applied exactly once.
pub fn ensure_genesis(db: Arc<Stores>, genesis: Block) -> Result<()> {
    if get_tip(&db)?.is_some() {
        return Ok(());
    }

    let gh = header_hash(&genesis.header);

    // store raw block
    db.blocks.insert(k_block(&gh), bincode::serialize(&genesis)?)?;

    // index header
    let _ = index_header(&db, &genesis.header, None)?;

    // apply state
    let epoch = current_epoch(0);
    validate_and_apply_block(&db, &genesis, epoch)?;
    set_tip(&db, &gh)?;
    Ok(())
}
