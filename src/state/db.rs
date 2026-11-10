// src/state/db.rs
use crate::types::{Hash32, OutPoint, TxOut};
use anyhow::{bail, Result};
use std::sync::atomic::{AtomicU64, Ordering};
use serde::{Deserialize, Serialize};
use sled::{Db, Tree};

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct UtxoMeta {
    pub height: u64,
    pub coinbase: bool,
}

/// Sled trees (physical separation) + key prefixes (logical separation).

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
    /// Upstream's comment here said `Tree::flush()` is not a cross-tree durability fence while
    /// `Db::flush()` is. In sled 0.34 that distinction does not exist: `Db` derefs to its default
    /// `Tree` (sled-0.34.7 src/db.rs), and `Tree::flush()` calls `pagecache.flush()` on the one
    /// shared write-ahead log, so `db.meta.flush()`, `db.idx.flush()` and `db.db.flush()` are the
    /// same operation.
    ///
    /// What is missing is atomicity, not a fence: writes to different trees are separate
    /// operations, so an unclean kill can persist some and not others. `apply_batch` is atomic
    /// per tree, which is why the txid index writes each block's data and its completeness marker
    /// in one batch on one tree. Block apply still spans utxo, utxo_meta, app, undo and meta
    /// without a batch; the reorg journal plus the shutdown handler cover that, and a cross-tree
    /// transaction there would change the consensus-governing apply code.
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
// Key builders (keep stable)
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

pub fn k_bad_prefix() -> &'static [u8] {
    b"bad:"
}

pub fn k_bad(hash: &Hash32) -> Vec<u8> {
    let mut k = Vec::with_capacity(4 + 32);
    k.extend_from_slice(k_bad_prefix());
    k.extend_from_slice(hash);
    k
}

/// Number of `bad:` marks (`/node/info` `bad_block_marks`, `csd fingerprint --long`).
pub fn bad_mark_count(db: &Stores) -> Result<usize> {
    let mut n = 0;
    for k in db.meta.scan_prefix(k_bad_prefix()).keys() {
        k?;
        n += 1;
    }
    Ok(n)
}

/// The block a `bad:` key marks (the inverse of `k_bad`).
pub fn bad_mark_hash(key: &[u8]) -> Option<Hash32> {
    Hash32::try_from(key.strip_prefix(k_bad_prefix())?).ok()
}

/// Stored block bodies removed since process start because they failed validation on bytes their
/// header does not commit to (`/node/info` `dropped_block_bodies`).
pub static DROPPED_BLOCK_BODIES: AtomicU64 = AtomicU64::new(0);

/// Removes a stored block body so it is neither applied nor served again and can be fetched anew.
pub fn drop_block_body(db: &Stores, hash: &Hash32) -> Result<()> {
    if db.blocks.remove(k_block(hash))?.is_some() {
        DROPPED_BLOCK_BODIES.fetch_add(1, Ordering::Relaxed);
    }
    Ok(())
}

// Legacy key (kept for compatibility)
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

/// Test-only error seam: while `CSD_TEST_FAIL_SET_TIP` holds a hash in hex, `set_tip` to that hash
/// fails before writing, with an untyped error like `get_tip`'s own. Compiled only under `test` or
/// the `test-bypass` feature, so a release binary does not contain it.
#[cfg(any(test, feature = "test-bypass"))]
fn test_seam_fail_set_tip(tip: &Hash32) -> Result<()> {
    if std::env::var("CSD_TEST_FAIL_SET_TIP").is_ok_and(|want| want == hex::encode(tip)) {
        bail!("CSD_TEST_FAIL_SET_TIP: injected set_tip failure");
    }
    Ok(())
}

/// CONSENSUS-ONLY tip write.
/// No explorer indexing, no extra tree mutations.
pub fn set_tip(db: &Stores, tip: &Hash32) -> Result<()> {
    #[cfg(any(test, feature = "test-bypass"))]
    test_seam_fail_set_tip(tip)?;

    let old = get_tip(db)?.unwrap_or([0u8; 32]);

    println!(
        "[tip] set_tip: old=0x{} -> new=0x{}",
        hex::encode(old),
        hex::encode(tip)
    );

    db.meta.insert(k_meta_tip(), tip)?;

    // Wake the txid-index reconciler. This is the single chokepoint every tip change goes
    // through (sync apply, miner apply, reorg, recovery), so one call here covers all of them and
    // cannot be forgotten by a new apply path.
    //
    // Why it matters: almost every node runs at the tip, and a polled reconciler is stale for up
    // to one idle period after every block (measured with polling alone: about 1.45 s per block),
    // during which /tx/:id falls back to the bounded chain scan, which is exactly the moment a
    // wallet polls for the transaction that just confirmed.
    //
    // notify_one is non-blocking, stores a permit if nobody is waiting, and is safe to call from
    // any thread including the blocking pool, so this cannot stall an apply.
    crate::state::tx_scan::notify_tip_changed();

    Ok(())
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
