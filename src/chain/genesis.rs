// src/chain/genesis.rs
use anyhow::Result;
use std::sync::Arc;

use crate::chain::index::{header_hash, index_header};
use crate::chain::mine::coinbase;
use crate::chain::pow::pow_ok;
use crate::params::{GENESIS_HASH, INITIAL_BITS, INITIAL_REWARD, GENESIS_EPIGRAPH};
use crate::state::app::current_epoch;
use crate::state::db::{get_tip, k_block, set_tip, Stores};
use crate::state::utxo::validate_and_apply_block;
use crate::types::{Block, BlockHeader, Hash20, Transaction};

/// CONSENSUS: fixed genesis timestamp (deterministic).
/// Pick any constant you want, but DO NOT derive from wallclock.
pub const GENESIS_TIME: u64 = 1700000000;

/// Bitcoin-ish merkle root from txids.
/// - leaves are txid bytes
/// - internal nodes are sha256d(left || right), duplicating last if odd
fn merkle_root_txids(txids: &[[u8; 32]]) -> [u8; 32] {
    if txids.is_empty() {
        return [0u8; 32];
    }
    let mut layer: Vec<[u8; 32]> = txids.to_vec();
    while layer.len() > 1 {
        let mut next: Vec<[u8; 32]> = Vec::with_capacity((layer.len() + 1) / 2);
        let mut i = 0usize;
        while i < layer.len() {
            let left = layer[i];
            let right = if i + 1 < layer.len() { layer[i + 1] } else { layer[i] };
            let mut buf = [0u8; 64];
            buf[..32].copy_from_slice(&left);
            buf[32..].copy_from_slice(&right);
            next.push(crate::crypto::sha256d(&buf));
            i += 2;
        }
        layer = next;
    }
    layer[0]
}

fn merkle_root(txs: &[Transaction]) -> crate::types::Hash32 {
    let mut ids: Vec<[u8; 32]> = Vec::with_capacity(txs.len());
    for tx in txs {
        ids.push(crate::crypto::txid(tx));
    }
    merkle_root_txids(&ids)
}

pub fn make_genesis_block(burn_addr20: Hash20) -> Result<Block> {
    // height=0 for genesis coinbase
    let cb = coinbase(burn_addr20, INITIAL_REWARD, 0, Some(GENESIS_EPIGRAPH.as_bytes()));
    let txs = vec![cb];

    let merkle = merkle_root(&txs);

    let mut hdr = BlockHeader {
        version: 1,
        prev: [0u8; 32],
        merkle,
        time: GENESIS_TIME, // ✅ FIXED
        bits: INITIAL_BITS,
        nonce: 0,
    };

    // Deterministic nonce search: always starts at 0 and increments.
    loop {
        let h = header_hash(&hdr);
        if pow_ok(&h, hdr.bits) {
            return Ok(Block { header: hdr, txs });
        }
        hdr.nonce = hdr.nonce.wrapping_add(1);
    }
}

/// Ensure genesis is stored + applied exactly once.
pub fn ensure_genesis(db: Arc<Stores>, genesis: Block) -> Result<()> {
    // Already bootstrapped
    if get_tip(&db)?.is_some() {
        return Ok(());
    }

    let gh = header_hash(&genesis.header);

    // IMPORTANT: enforce that the genesis we are about to apply matches params::GENESIS_HASH
    if gh != GENESIS_HASH {
        anyhow::bail!(
            "foreign genesis header (got=0x{}, want=0x{})",
            hex::encode(gh),
            hex::encode(GENESIS_HASH),
        );
    }

    // store raw block
    db.blocks.insert(
        k_block(&gh),
        crate::codec::consensus_bincode().serialize(&genesis)?,
    )?;

    // index header (also enforces bits/PoW rules)
    let _ = index_header(&db, &genesis.header, None)?;

    // apply state
    let epoch = current_epoch(0);
    validate_and_apply_block(&db, &genesis, epoch, 0)?;

    set_tip(&db, &gh)?;
    Ok(())
}
