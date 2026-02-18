// src/state/tx_index.rs
use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};

use crate::crypto::txid;
use crate::state::db::{k_block, Stores};
use crate::types::{Block, Hash32};

fn c() -> crate::codec::ConsensusBincode {
    crate::codec::consensus_bincode()
}

// --------------------
// idx tree key helpers
// --------------------
// These are explorer-only, not consensus-adjacent. Keep stable anyway.

pub fn k_hh(height: u64) -> Vec<u8> {
    // height->hash
    let mut k = Vec::with_capacity(3 + 8);
    k.extend_from_slice(b"hh/");
    k.extend_from_slice(&height.to_be_bytes());
    k
}

pub fn k_btx(block_hash: &Hash32) -> Vec<u8> {
    // block_hash->txids (so we can delete tx index on rollback)
    let mut k = Vec::with_capacity(4 + 32);
    k.extend_from_slice(b"btx/");
    k.extend_from_slice(block_hash);
    k
}

pub fn k_tx(txid: &Hash32) -> Vec<u8> {
    // txid->locator
    let mut k = Vec::with_capacity(3 + 32);
    k.extend_from_slice(b"tx/");
    k.extend_from_slice(txid);
    k
}

#[derive(Clone, Copy, Debug, Serialize, Deserialize)]
pub struct TxLocator {
    pub block_hash: Hash32,
    pub height: u64,
    pub index_in_block: u32,
}

// --------------------
// reads
// --------------------

pub fn get_block_hash_by_height(db: &Stores, height: u64) -> Result<Option<Hash32>> {
    let Some(v) = db.idx.get(k_hh(height))? else {
        return Ok(None);
    };
    if v.len() != 32 {
        return Ok(None);
    }
    let mut out = [0u8; 32];
    out.copy_from_slice(&v);
    Ok(Some(out))
}

pub fn get_tx_locator(db: &Stores, id: &Hash32) -> Result<Option<TxLocator>> {
    let Some(v) = db.idx.get(k_tx(id))? else {
        return Ok(None);
    };
    let loc: TxLocator = c().deserialize(&v).context("decode TxLocator")?;
    Ok(Some(loc))
}

// --------------------
// writes (explorer-only)
// --------------------

pub fn index_canonical_block(db: &Stores, block_hash: &Hash32, height: u64) -> Result<()> {
    // Need block bytes to index txs.
    let Some(v) = db.blocks.get(k_block(block_hash))? else {
        // header may exist before body during sync
        return Ok(());
    };
    let blk: Block = c().deserialize(&v).context("decode Block for indexing")?;

    let mut txids: Vec<Hash32> = Vec::with_capacity(blk.txs.len());

    for (i, tx) in blk.txs.iter().enumerate() {
        let id = txid(tx);
        txids.push(id);

        let loc = TxLocator {
            block_hash: *block_hash,
            height,
            index_in_block: i as u32,
        };

        db.idx
            .insert(k_tx(&id), c().serialize(&loc)?)
            .context("idx.insert(tx locator)")?;
    }

    db.idx
        .insert(k_btx(block_hash), c().serialize(&txids)?)
        .context("idx.insert(btx)")?;

    db.idx
        .insert(k_hh(height), block_hash.as_slice())
        .context("idx.insert(hh)")?;

    Ok(())
}

pub fn unindex_canonical_block(db: &Stores, block_hash: &Hash32, height: u64) -> Result<()> {
    if let Some(v) = db.idx.get(k_btx(block_hash))? {
        let txids: Vec<Hash32> = c().deserialize(&v).unwrap_or_default();
        for id in txids {
            let _ = db.idx.remove(k_tx(&id))?;
        }
        let _ = db.idx.remove(k_btx(block_hash))?;
    }
    let _ = db.idx.remove(k_hh(height))?;
    Ok(())
}

// --------------------
// full rebuild (recommended)
// --------------------
// This is the safe, deterministic way to ensure idx matches the canonical chain,
// and it avoids any tip-transition edge cases.
//
// Call this from non-consensus code only (startup after recovery, background task, etc).

pub fn rebuild_canonical_index_from_tip(db: &Stores) -> Result<()> {
    // Wipe explorer index
    db.idx.clear().context("idx.clear")?;

    // Get tip
    let Some(tip) = crate::state::db::get_tip(db)? else {
        db.idx.flush().ok();
        return Ok(());
    };

    // Walk back to genesis using header index, collecting (height, hash)
    let mut chain: Vec<(u64, Hash32)> = Vec::new();
    let mut cur = crate::chain::index::get_hidx(db, &tip)?
        .ok_or_else(|| anyhow::anyhow!("missing header index for tip during idx rebuild"))?;

    loop {
        chain.push((cur.height, cur.hash));
        if cur.height == 0 {
            break;
        }
        cur = crate::chain::index::get_hidx(db, &cur.parent)?
            .ok_or_else(|| anyhow::anyhow!("missing header index while walking parents for idx rebuild"))?;
    }

    chain.reverse();

    for (height, hash) in chain {
        // best-effort: if block bytes missing, skip (common during header-first sync)
        let _ = index_canonical_block(db, &hash, height);
    }

    db.idx.flush().context("idx.flush after rebuild")?;
    Ok(())
}
