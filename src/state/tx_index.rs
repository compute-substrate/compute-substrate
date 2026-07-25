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

/// Value stored under `k_tx(id)` when the SAME txid has been seen in more than one canonical
/// block. A `TxLocator` serialises to a fixed 44 bytes under the consensus codec, so a one-byte
/// value can never be mistaken for one.
///
/// Coinbase txids are not consensus-unique while `COINBASE_HEIGHT_PREFIX_ACTIVATION_HEIGHT` is
/// `u64::MAX` (src/state/utxo.rs): a miner can reuse an earlier coinbase byte-for-byte. A single
/// locator cannot describe two blocks, and unindexing either one would delete an entry the other
/// still owns, turning a later miss into a PROVED absence for a transaction that exists.
///
/// Marking the ONE txid ambiguous is the proportionate answer. That txid falls back to the
/// honest scan forever; every other txid keeps its O(1) locator and the index still converges, so
/// the marker still means what it says. The alternative considered and rejected was failing the
/// whole tick: that would let one adversarial block permanently disable the tx-lookup subsystem
/// on every node in the network, with no operator recourse, which trades a narrow correctness bug
/// for a cheap and permanent availability attack.
pub const TX_AMBIGUOUS: &[u8] = &[0xFF];

/// What the index knows about a txid.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TxIndexEntry {
    /// Exactly one canonical block carries it, here.
    Locator(TxLocator),
    /// More than one block has claimed it. The index cannot answer for this txid; callers must
    /// fall back to the chain scan. NEVER treat this as an absence.
    Ambiguous,
}

impl PartialEq for TxLocator {
    fn eq(&self, other: &Self) -> bool {
        self.block_hash == other.block_hash
            && self.height == other.height
            && self.index_in_block == other.index_in_block
    }
}
impl Eq for TxLocator {}

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

/// The full index answer, including the ambiguous case. Use this on any path where "not in the
/// index" would be reported to a caller as a proved absence.
pub fn get_tx_entry(db: &Stores, id: &Hash32) -> Result<Option<TxIndexEntry>> {
    let Some(v) = db.idx.get(k_tx(id))? else {
        return Ok(None);
    };
    if v.as_ref() == TX_AMBIGUOUS {
        return Ok(Some(TxIndexEntry::Ambiguous));
    }
    let loc: TxLocator = c().deserialize(&v).context("decode TxLocator")?;
    Ok(Some(TxIndexEntry::Locator(loc)))
}

/// Convenience: the locator, or None for both "not indexed" and "ambiguous". Callers that must
/// distinguish those two MUST use `get_tx_entry`.
pub fn get_tx_locator(db: &Stores, id: &Hash32) -> Result<Option<TxLocator>> {
    match get_tx_entry(db, id)? {
        Some(TxIndexEntry::Locator(loc)) => Ok(Some(loc)),
        _ => Ok(None),
    }
}

// --------------------
// writes (explorer-only)
// --------------------

/// Index one canonical block and, in the SAME sled batch, advance the completeness marker to it.
///
/// The marker lives in this tree so that `Tree::apply_batch` (atomic per tree) covers
/// the locator writes and the marker together. Before that the marker lived in the `meta` tree
/// and could in principle become durable ahead of the data it describes, which would let a miss
/// for a transaction in that block be reported as a proved absence.
/// Returns Ok(false) when the block body is not present yet (header-first sync). The caller MUST
/// treat that as "stop here", never as "done": advancing the completeness marker past a block
/// that was not indexed is a marker claiming coverage it does not have.
pub fn index_canonical_block(db: &Stores, block_hash: &Hash32, height: u64) -> Result<bool> {
    // Need block bytes to index txs.
    let Some(v) = db.blocks.get(k_block(block_hash))? else {
        // header may exist before body during sync
        return Ok(false);
    };
    let blk: Block = c().deserialize(&v).context("decode Block for indexing")?;

    let mut batch = sled::Batch::default();
    let mut txids: Vec<Hash32> = Vec::with_capacity(blk.txs.len());

    for (i, tx) in blk.txs.iter().enumerate() {
        let id = txid(tx);
        txids.push(id);

        // A txid already indexed under a DIFFERENT block means two canonical blocks carry the
        // same transaction. Overwriting the locator would be silently destructive: the later
        // `unindex_canonical_block` of either block removes the single `tx/<id>` entry, and the
        // txid then reads as absent while a canonical block still contains it. Under a fresh
        // completeness marker that absence is reported as PROVED, which is the confident lie the
        // whole scan-outcome contract exists to remove.
        //
        // This is not hypothetical: coinbase txids are not consensus-unique on this chain yet.
        // The coinbase script_sig is committed in the txid and
        // `validate_coinbase_scriptsig_height` is gated off at
        // COINBASE_HEIGHT_PREFIX_ACTIVATION_HEIGHT = u64::MAX (see src/state/utxo.rs), so a miner
        // can deliberately reuse an earlier coinbase's txid.
        //
        // DO NOT "fail the tick" here. That was tried and rejected: it lets one adversarial block
        // permanently disable the tx-lookup subsystem on every node in the network, with no
        // operator recourse and no self-heal, which is a worse trade than the bug it fixes. Mark
        // the single txid ambiguous instead (below) and keep converging. The durable fix is
        // upstream's: activate the height-prefix rule at a coordinated height, a no-op for honest
        // blocks.
        match get_tx_entry(db, &id)? {
            Some(TxIndexEntry::Ambiguous) => {
                // Already known ambiguous: leave the marker, keep indexing everything else.
                continue;
            }
            Some(TxIndexEntry::Locator(prev)) if prev.block_hash != *block_hash => {
                println!(
                    "[txidx] duplicate txid 0x{} in canonical blocks 0x{} (height {}) and 0x{} (height {}): \
                     marking it ambiguous, lookups for THIS txid fall back to the chain scan",
                    hex::encode(id),
                    hex::encode(prev.block_hash),
                    prev.height,
                    hex::encode(block_hash),
                    height
                );
                batch.insert(k_tx(&id), TX_AMBIGUOUS);
                continue;
            }
            _ => {}
        }

        let loc = TxLocator {
            block_hash: *block_hash,
            height,
            index_in_block: i as u32,
        };

        batch.insert(k_tx(&id), c().serialize(&loc)?);
    }

    batch.insert(k_btx(block_hash), c().serialize(&txids)?);
    batch.insert(k_hh(height), block_hash.as_slice());
    batch.insert(
        crate::state::tx_scan::k_idx_tip(),
        block_hash.as_slice(),
    );

    db.idx
        .apply_batch(batch)
        .context("idx.apply_batch(index block)")?;

    Ok(true)
}

/// Remove one block from the index and, in the same batch, step the completeness marker to
/// `marker_to` (the disconnected block's parent) when the caller is walking a reorg.
pub fn unindex_canonical_block(
    db: &Stores,
    block_hash: &Hash32,
    height: u64,
    marker_to: Option<&Hash32>,
) -> Result<()> {
    let mut batch = sled::Batch::default();

    if let Some(v) = db.idx.get(k_btx(block_hash))? {
        let txids: Vec<Hash32> = c().deserialize(&v).unwrap_or_default();
        for id in txids {
            // An ambiguity marker is NEVER removed. It records that more than one block claimed
            // this txid; disconnecting one of them does not prove the other is gone, and deleting
            // the marker would let a later miss be reported as a proved absence. The cost is a
            // permanent scan fallback for that single txid.
            if matches!(get_tx_entry(db, &id), Ok(Some(TxIndexEntry::Ambiguous))) {
                continue;
            }
            batch.remove(k_tx(&id));
        }
        batch.remove(k_btx(block_hash));
    }
    batch.remove(k_hh(height));

    if let Some(parent) = marker_to {
        batch.insert(crate::state::tx_scan::k_idx_tip(), parent.as_slice());
    }

    db.idx
        .apply_batch(batch)
        .context("idx.apply_batch(unindex block)")?;
    Ok(())
}
