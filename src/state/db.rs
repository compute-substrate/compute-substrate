// src/state/db.rs
use crate::types::{Hash32, OutPoint, TxOut};
use anyhow::{bail, Result};
use serde::{Deserialize, Serialize};
use sled::{Db, Tree};

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct UtxoMeta {
    pub height: u64,
    pub coinbase: bool,
}

/// Sled trees (physical separation) + key prefixes (logical separation).
///

pub struct Stores {
    pub db: Db,

    // raw blocks by hash
    pub blocks: Tree, // key: k_block(hash)  => consensus_bincode(Block)

    // header index by hash -> HeaderIndex
    pub hdr: Tree, // key: k_hdr(hash) => consensus_bincode(HeaderIndex)

    // raw header bytes by hash (consensus_bincode(BlockHeader)) (optional, for explorers/debug)
    pub hdr_raw: Tree, // key: k_hdr_raw(hash) => bytes

    // meta keys (tip, bad-block markers, reorg journal, etc.)
    pub meta: Tree, // keys: k_meta_tip(), k_bad(hash), ...

    // utxo set
    pub utxo: Tree, // key: k_utxo(outpoint) => consensus_bincode(TxOut)

    // utxo metadata
    pub utxo_meta: Tree, // key: k_utxo_meta(outpoint) => consensus_bincode(UtxoMeta)

    // undo logs per block
    pub undo: Tree, // key: k_undo(hash) => consensus_bincode(UndoLog)

    // app state
    pub app: Tree, // keyspace described in app_state.rs

    // explorer index (height->hash, txid->locator, block->txids)
    // Not consensus-adjacent; safe to evolve, but keep stable once public.
    pub idx: Tree,
}

impl Stores {
    pub fn open(path: &str) -> Result<Self> {
        let db = sled::open(path)?;
        Ok(Self {
            blocks: db.open_tree("blocks")?,
            hdr: db.open_tree("hdr")?,
            hdr_raw: db.open_tree("hdr_raw")?,
            meta: db.open_tree("meta")?,
            utxo: db.open_tree("utxo")?,
            utxo_meta: db.open_tree("utxo_meta")?,
            undo: db.open_tree("undo")?,
            app: db.open_tree("app")?,
            idx: db.open_tree("idx")?,
            db,
        })
    }

    /// Explicit flush boundary. Avoid calling flush on every tip write.
    ///
    /// IMPORTANT:
    /// - Tree::flush() is not a cross-tree durability fence.
    /// - Db::flush() is the single durability barrier for all trees.
    pub fn flush_all(&self) -> Result<()> {
        self.db.flush()?;
        Ok(())
    }

    pub fn flush_meta(&self) -> Result<()> {
        self.meta.flush()?;
        Ok(())
    }

    pub fn flush_idx(&self) -> Result<()> {
        self.idx.flush()?;
        Ok(())
    }
}

// -----------------------------------------------------------------------------
// Key builders (CONSENSUS-ADJACENT: keep stable)
// -----------------------------------------------------------------------------

pub fn k_block(hash: &Hash32) -> Vec<u8> {
    let mut k = Vec::with_capacity(1 + 32);
    k.push(b'B');
    k.extend_from_slice(hash);
    k
}

pub fn k_hdr(hash: &Hash32) -> Vec<u8> {
    let mut k = Vec::with_capacity(1 + 32);
    k.push(b'H');
    k.extend_from_slice(hash);
    k
}

pub fn k_hdr_raw(hash: &Hash32) -> Vec<u8> {
    let mut k = Vec::with_capacity(1 + 32);
    k.push(b'R');
    k.extend_from_slice(hash);
    k
}

pub fn k_undo(hash: &Hash32) -> Vec<u8> {
    let mut k = Vec::with_capacity(1 + 32);
    k.push(b'X');
    k.extend_from_slice(hash);
    k
}

pub fn k_utxo(op: &OutPoint) -> Vec<u8> {
    let mut k = Vec::with_capacity(1 + 36);
    k.push(b'U');
    k.extend_from_slice(&op.txid);
    k.extend_from_slice(&op.vout.to_le_bytes());
    k
}

pub fn k_utxo_meta(op: &OutPoint) -> Vec<u8> {
    let mut k = Vec::with_capacity(1 + 36);
    k.push(b'M');
    k.extend_from_slice(&op.txid);
    k.extend_from_slice(&op.vout.to_le_bytes());
    k
}

// -----------------------------------------------------------------------------
// Meta keys
// -----------------------------------------------------------------------------

pub fn k_meta_tip() -> &'static [u8] {
    b"meta:tip"
}

pub fn k_bad(hash: &Hash32) -> Vec<u8> {
    let mut k = Vec::with_capacity(4 + 32);
    k.extend_from_slice(b"bad:");
    k.extend_from_slice(hash);
    k
}

// Legacy key (kept for compatibility / not used by your new double-buffer journal)
pub fn k_reorg_in_progress() -> &'static [u8] {
    b"reorg:in_progress"
}

// -----------------------------------------------------------------------------
// Meta helpers
// -----------------------------------------------------------------------------

pub fn meta_put_bytes(db: &Stores, key: &[u8], val: &[u8]) -> Result<()> {
    db.meta.insert(key, val)?;
    Ok(())
}

pub fn meta_get_bytes(db: &Stores, key: &[u8]) -> Result<Option<Vec<u8>>> {
    Ok(db.meta.get(key)?.map(|v| v.to_vec()))
}

pub fn meta_del(db: &Stores, key: &[u8]) -> Result<()> {
    db.meta.remove(key)?;
    Ok(())
}

// -----------------------------------------------------------------------------
// Tip helpers (CONSENSUS-ADJACENT)
// -----------------------------------------------------------------------------

pub fn get_tip(db: &Stores) -> Result<Option<Hash32>> {
    if let Some(v) = db.meta.get(k_meta_tip())? {
        if v.len() != 32 {
            bail!("meta:tip value wrong length: {}", v.len());
        }
        let mut h = [0u8; 32];
        h.copy_from_slice(&v);
        Ok(Some(h))
    } else {
        Ok(None)
    }
}

/// CONSENSUS-ONLY tip write.
/// No explorer indexing, no extra tree mutations.
pub fn set_tip(db: &Stores, tip: &Hash32) -> Result<()> {
    let old = get_tip(db)?.unwrap_or([0u8; 32]);

    println!(
        "[tip] set_tip: old=0x{} -> new=0x{}",
        hex::encode(old),
        hex::encode(tip)
    );

    db.meta.insert(k_meta_tip(), tip)?;
    Ok(())
}

// -----------------------------------------------------------------------------
// Explorer indexing helpers (NOT CONSENSUS)
// -----------------------------------------------------------------------------
//
// Keep your existing behavior, but call it ONLY from non-consensus paths
// (explorer sync, background maintenance, RPC handlers), not from reorg/apply/undo.
//
// If you call this during crash-fuzz, you re-introduce the same nondeterminism.

pub fn update_explorer_index_for_tip_transition(db: &Stores, old: &Hash32, new: &Hash32) {
    // Determine old/new heights (best-effort)
    let old_hi = crate::chain::index::get_hidx(db, old).ok().flatten();
    let new_hi = crate::chain::index::get_hidx(db, new).ok().flatten();

    // If moving backwards: unindex blocks from old down to new height+1.
    if let (Some(ohi), Some(nhi)) = (old_hi.clone(), new_hi.clone()) {
        if nhi.height < ohi.height {
            let mut cur_hash = *old;
            let mut cur_hi = ohi;

            while cur_hi.height > nhi.height {
                let _ = crate::state::tx_index::unindex_canonical_block(db, &cur_hash, cur_hi.height);

                // step to parent
                cur_hash = cur_hi.parent;
                cur_hi = crate::chain::index::get_hidx(db, &cur_hash)
                    .ok()
                    .flatten()
                    .unwrap_or(crate::chain::index::HeaderIndex {
                        hash: cur_hash,
                        parent: [0u8; 32],
                        height: 0,
                        chainwork: 0,
                        bits: 0,
                        time: 0,
                    });
            }
        }
    }

    // If we know new height, index the canonical tip block.
    if let Some(nhi) = new_hi {
        let _ = crate::state::tx_index::index_canonical_block(db, new, nhi.height);
    }
}

// -----------------------------------------------------------------------------
// UTXO helpers
// -----------------------------------------------------------------------------

pub fn put_utxo(db: &Stores, op: &OutPoint, out: &TxOut) -> Result<()> {
    db.utxo.insert(k_utxo(op), crate::codec::consensus_bincode().serialize(out)?)?;
    Ok(())
}

pub fn del_utxo(db: &Stores, op: &OutPoint) -> Result<()> {
    db.utxo.remove(k_utxo(op))?;
    Ok(())
}

pub fn get_utxo(db: &Stores, op: &OutPoint) -> Result<Option<TxOut>> {
    if let Some(v) = db.utxo.get(k_utxo(op))? {
        Ok(Some(crate::codec::consensus_bincode().deserialize::<TxOut>(&v)?))
    } else {
        Ok(None)
    }
}

pub fn put_utxo_meta(db: &Stores, op: &OutPoint, meta: &UtxoMeta) -> Result<()> {
    db.utxo_meta.insert(k_utxo_meta(op), crate::codec::consensus_bincode().serialize(meta)?)?;
    Ok(())
}

pub fn del_utxo_meta(db: &Stores, op: &OutPoint) -> Result<()> {
    db.utxo_meta.remove(k_utxo_meta(op))?;
    Ok(())
}

pub fn get_utxo_meta(db: &Stores, op: &OutPoint) -> Result<Option<UtxoMeta>> {
    if let Some(v) = db.utxo_meta.get(k_utxo_meta(op))? {
        Ok(Some(crate::codec::consensus_bincode().deserialize::<UtxoMeta>(&v)?))
    } else {
        Ok(None)
    }
}

// -----------------------------------------------------------------------------
// Raw header helpers (optional tree)
// -----------------------------------------------------------------------------

pub fn put_hdr_raw(db: &Stores, hash: &Hash32, header_bytes: &[u8]) -> Result<()> {
    db.hdr_raw.insert(k_hdr_raw(hash), header_bytes)?;
    Ok(())
}

pub fn get_hdr_raw(db: &Stores, hash: &Hash32) -> Result<Option<Vec<u8>>> {
    Ok(db.hdr_raw.get(k_hdr_raw(hash))?.map(|v| v.to_vec()))
}

pub fn del_hdr_raw(db: &Stores, hash: &Hash32) -> Result<()> {
    db.hdr_raw.remove(k_hdr_raw(hash))?;
    Ok(())
}
