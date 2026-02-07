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
/// MAINNET FREEZE RULE:
/// - Tree names and key prefixes below are consensus-adjacent and must not change
///   without a coordinated migration plan.
pub struct Stores {
    pub db: Db,

    // raw blocks by hash
    pub blocks: Tree, // key: k_block(hash)  => consensus_bincode(Block)

    // header index by hash -> HeaderIndex
    pub hdr: Tree, // key: k_hdr(hash) => consensus_bincode(HeaderIndex)

    // raw header bytes by hash (consensus_bincode(BlockHeader)) (optional, for explorers/debug)
    pub hdr_raw: Tree, // key: k_hdr_raw(hash) => bytes

    // meta keys (tip, bad-block markers, reorg journal, etc.)
    pub meta: Tree, // keys: k_meta_tip(), k_bad(hash), k_reorg_in_progress(), ...

    // utxo set
    pub utxo: Tree, // key: k_utxo(outpoint) => consensus_bincode(TxOut)

    // utxo metadata
    pub utxo_meta: Tree, // key: k_utxo_meta(outpoint) => consensus_bincode(UtxoMeta)

    // undo logs per block
    pub undo: Tree, // key: k_undo(hash) => consensus_bincode(UndoLog)

    // app state
    pub app: Tree, // keyspace described in app_state.rs
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
            db,
        })
    }

    /// Explicit flush boundary. Avoid calling flush on every tip write.
    /// Call this:
    /// - on clean shutdown
    /// - after applying a batch of blocks
    /// - after a successful reorg completion (optional)
    pub fn flush_all(&self) -> Result<()> {
        self.blocks.flush()?;
        self.hdr.flush()?;
        self.hdr_raw.flush()?;
        self.meta.flush()?;
        self.utxo.flush()?;
        self.utxo_meta.flush()?;
        self.undo.flush()?;
        self.app.flush()?;
        Ok(())
    }

    /// Flush only meta (tip/bad markers/journal). Useful if you want fast persistence.
    pub fn flush_meta(&self) -> Result<()> {
        self.meta.flush()?;
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
// Meta keys (centralized here so other modules don’t invent ad-hoc strings)
// -----------------------------------------------------------------------------

/// Canonical tip hash (32 bytes).
pub fn k_meta_tip() -> &'static [u8] {
    b"meta:tip"
}

/// Bad-block marker for hash (used by reorg.rs).
pub fn k_bad(hash: &Hash32) -> Vec<u8> {
    let mut k = Vec::with_capacity(4 + 32);
    k.extend_from_slice(b"bad:");
    k.extend_from_slice(hash);
    k
}

/// Crash-atomic reorg journal key (used by chain/reorg_journal.rs).
pub fn k_reorg_in_progress() -> &'static [u8] {
    b"reorg:in_progress"
}

// -----------------------------------------------------------------------------
// Meta helpers (typed convenience wrappers)
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
// Tip helpers
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

/// Write tip WITHOUT flushing.
///
/// Mainnet note:
/// - flushing on every call is too expensive (reorg applies call set_tip many times).
/// - call `db.flush_meta()` or `db.flush_all()` at explicit boundaries.
pub fn set_tip(db: &Stores, tip: &Hash32) -> Result<()> {
    // Debug visibility: prove set_tip is executed and what it writes.
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
// UTXO helpers
// -----------------------------------------------------------------------------

pub fn put_utxo(db: &Stores, op: &OutPoint, out: &TxOut) -> Result<()> {
    db.utxo.insert(
        k_utxo(op),
        crate::codec::consensus_bincode().serialize(out)?,
    )?;
    Ok(())
}

pub fn del_utxo(db: &Stores, op: &OutPoint) -> Result<()> {
    db.utxo.remove(k_utxo(op))?;
    Ok(())
}

pub fn get_utxo(db: &Stores, op: &OutPoint) -> Result<Option<TxOut>> {
    if let Some(v) = db.utxo.get(k_utxo(op))? {
        Ok(Some(
            crate::codec::consensus_bincode().deserialize::<TxOut>(&v)?,
        ))
    } else {
        Ok(None)
    }
}

pub fn put_utxo_meta(db: &Stores, op: &OutPoint, meta: &UtxoMeta) -> Result<()> {
    db.utxo_meta.insert(
        k_utxo_meta(op),
        crate::codec::consensus_bincode().serialize(meta)?,
    )?;
    Ok(())
}

pub fn del_utxo_meta(db: &Stores, op: &OutPoint) -> Result<()> {
    db.utxo_meta.remove(k_utxo_meta(op))?;
    Ok(())
}

pub fn get_utxo_meta(db: &Stores, op: &OutPoint) -> Result<Option<UtxoMeta>> {
    if let Some(v) = db.utxo_meta.get(k_utxo_meta(op))? {
        Ok(Some(
            crate::codec::consensus_bincode().deserialize::<UtxoMeta>(&v)?,
        ))
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
