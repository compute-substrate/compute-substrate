// src/net/mempool.rs
use std::collections::{BTreeSet, HashMap, HashSet};
use std::sync::RwLock;

use anyhow::{bail, Result};

use crate::crypto::txid;
use crate::params::{MAX_TX_BYTES, MAX_TX_INPUTS, MAX_TX_OUTPUTS};
use crate::state::db::get_utxo;
use crate::state::utxo::validate_tx_for_mempool;
use crate::types::{Block, Hash32, OutPoint, Transaction};

/// -------------------------
/// Mainnet hardening limits
/// -------------------------
///
/// Non-consensus policy limits. Safe to change later.
/// These are conservative defaults for mainnet stability.
///
/// Notes:
/// - Mempool is "strictly mineable": it only accepts txs whose inputs exist
///   in the current canonical UTXO set (no mempool chains / no package relay).
/// - That property dramatically reduces complexity and DoS surface.
///
/// IMPORTANT:
/// - Per-tx caps must NOT exceed consensus caps (or you'll accept txs you can't mine).
const MAX_MEMPOOL_TXS: usize = 50_000;
const MAX_MEMPOOL_BYTES: usize = 64 * 1024 * 1024; // 64 MiB total tx bytes (serialized)
const MAX_MEMPOOL_SPENT: usize = 200_000; // cap spent-outpoint index growth (DoS guard)

/// Minimum fee-rate to be accepted into mempool.
///
/// Unit: "ppm-per-byte" = fee * 1_000_000 / tx_bytes.
/// - MIN_FEERATE_PPM = 1 means: fee >= tx_bytes / 1_000_000 (very low)
/// - You can raise later if you want a stronger spam floor.
///
/// If you prefer simpler, you can enforce `fee > 0` instead.
/// This is the same idea but more granular and future-proof.
const MIN_FEERATE_PPM: u64 = 1;

pub struct Mempool {
    inner: RwLock<Inner>,
    max_txs: usize,
    max_bytes: usize,
    max_spent: usize,
}

#[derive(Default)]
struct Inner {
    // txid -> tx
    txs: HashMap<Hash32, Transaction>,
    // outpoint -> txid (who is spending it in mempool)
    spent: HashMap<OutPoint, Hash32>,

    // total serialized bytes of all txs currently in mempool (consensus codec)
    total_bytes: usize,

    // fee info
    // txid -> (fee, bytes, feerate_ppm)
    feeinfo: HashMap<Hash32, FeeInfo>,

    // eviction order: lowest feerate first, tie-break by txid (deterministic)
    // item: (feerate_ppm, txid)
    eviction: BTreeSet<(u64, Hash32)>,
}

#[derive(Clone, Copy, Debug)]
struct FeeInfo {
    fee: u64,
    bytes: u32,
    feerate_ppm: u64, // fee * 1_000_000 / bytes
}

impl Mempool {
    pub fn new() -> Self {
        Self {
            inner: RwLock::new(Inner::default()),
            max_txs: MAX_MEMPOOL_TXS,
            max_bytes: MAX_MEMPOOL_BYTES,
            max_spent: MAX_MEMPOOL_SPENT,
        }
    }

    pub fn new_with_limits(max_txs: usize, max_bytes: usize, max_spent: usize) -> Self {
        Self {
            inner: RwLock::new(Inner::default()),
            max_txs,
            max_bytes,
            max_spent,
        }
    }

    pub fn contains(&self, id: &Hash32) -> bool {
        self.inner.read().unwrap().txs.contains_key(id)
    }

    pub fn len(&self) -> usize {
        self.inner.read().unwrap().txs.len()
    }

    /// Total serialized bytes currently held in mempool.
    pub fn total_bytes(&self) -> usize {
        self.inner.read().unwrap().total_bytes
    }

    /// Cheaper than spent_outpoints().len() (no cloning).
    pub fn spent_len(&self) -> usize {
        self.inner.read().unwrap().spent.len()
    }

    /// Snapshot of spent outpoints (cloned).
    pub fn spent_outpoints(&self) -> HashSet<OutPoint> {
        let r = self.inner.read().unwrap();
        r.spent.keys().cloned().collect()
    }

    /// Cheaper snapshot than HashSet (still clones, but less overhead).
    pub fn spent_outpoints_vec(&self) -> Vec<OutPoint> {
        let r = self.inner.read().unwrap();
        r.spent.keys().cloned().collect()
    }

    /// Minimum feerate in mempool (lowest-fee tx).
    pub fn min_feerate_ppm(&self) -> Option<u64> {
        self.inner
            .read()
            .unwrap()
            .eviction
            .iter()
            .next()
            .map(|x| x.0)
    }

    /// Maximum feerate in mempool (highest-fee tx).
    pub fn max_feerate_ppm(&self) -> Option<u64> {
        self.inner
            .read()
            .unwrap()
            .eviction
            .iter()
            .next_back()
            .map(|x| x.0)
    }

    /// Insert WITH consensus-mempool validation against the current UTXO set.
    ///
    /// This should be the ONLY entrypoint for:
    /// - /tx/submit
    /// - gossipsub tx messages
    /// - any "received from peer" path
    ///
    /// Returns:
    /// - Ok(true)  => added
    /// - Ok(false) => already present OR conflicts with an existing mempool spend
    /// - Err(_)    => tx is invalid or not connectable to current UTXO set OR rejected by policy
    pub fn insert_checked(&self, db: &crate::state::db::Stores, tx: Transaction) -> Result<bool> {
        let c = crate::codec::consensus_bincode();

        // Cheap DoS guards: serialized size + shape caps (use consensus limits).
        let tx_bytes_u64 = c.serialized_size(&tx)?;
        if tx_bytes_u64 > (usize::MAX as u64) {
            bail!("tx too large for this platform (serialized_size overflow usize)");
        }
        if tx_bytes_u64 > (u32::MAX as u64) {
            bail!("tx too large (serialized_size overflow u32)");
        }
        let tx_bytes: usize = tx_bytes_u64 as usize;

        if tx_bytes > MAX_TX_BYTES {
            bail!(
                "tx too large ({} > MAX_TX_BYTES={})",
                tx_bytes,
                MAX_TX_BYTES
            );
        }
        if tx.inputs.len() > MAX_TX_INPUTS {
            bail!(
                "too many inputs ({} > MAX_TX_INPUTS={})",
                tx.inputs.len(),
                MAX_TX_INPUTS
            );
        }
        if tx.outputs.len() > MAX_TX_OUTPUTS {
            bail!(
                "too many outputs ({} > MAX_TX_OUTPUTS={})",
                tx.outputs.len(),
                MAX_TX_OUTPUTS
            );
        }
        if tx.inputs.is_empty() {
            // coinbase-like txs never belong in mempool
            bail!("tx has no inputs (coinbase-like); not allowed in mempool");
        }

        let id = txid(&tx);
        if self.contains(&id) {
            return Ok(false);
        }

        // Strong checks (structure, sigs, app sanity, and connectable NOW to current UTXO set).
        validate_tx_for_mempool(db, &tx)?;

        // Compute fee deterministically from current UTXO set (inputs must exist by now).
        let (fee, feerate_ppm) = compute_fee_and_feerate_ppm(db, &tx, tx_bytes_u64)?;

        // Anti-spam floor.
        if feerate_ppm < MIN_FEERATE_PPM {
            bail!(
                "feerate too low ({} < MIN_FEERATE_PPM={})",
                feerate_ppm,
                MIN_FEERATE_PPM
            );
        }

        // Now attempt insertion under lock with global caps + conflicts.
        let mut w = self.inner.write().unwrap();

        if w.txs.contains_key(&id) {
            return Ok(false);
        }

        // Reject if any input already spent in mempool (conflict).
        for inp in &tx.inputs {
            if w.spent.contains_key(&inp.prevout) {
                // no RBF/replace: keep it simple and safe for v0.1
                return Ok(false);
            }
        }

        // spent index growth DoS guard

        if w.spent.len().saturating_add(tx.inputs.len()) > self.max_spent {
            bail!(
                "mempool spent index full (spent_len={} + new_inputs={} > max_spent={})",
                w.spent.len(),
                tx.inputs.len(),
                self.max_spent
            );
        }

        // If we're full (by count or bytes), require incoming tx to be competitive.
        // This prevents churn attacks where low-fee txs cause repeated evictions.
        let would_exceed_count = w.txs.len() >= self.max_txs;
        let would_exceed_bytes = w.total_bytes.saturating_add(tx_bytes) > self.max_bytes;

        if would_exceed_count || would_exceed_bytes {
            if let Some(min_fr) = w.eviction.iter().next().map(|x| x.0) {
                if feerate_ppm <= min_fr {
                    bail!(
                        "mempool full; feerate {} not competitive (min={})",
                        feerate_ppm,
                        min_fr
                    );
                }
            } else {
                bail!("mempool state inconsistent: full but eviction set empty");
            }
        }

        // Ensure global caps by evicting lowest-fee-rate txs deterministically.

        while w.txs.len() >= self.max_txs {

            if !evict_one_lowest_feerate(&mut w) {
                bail!("mempool full (cannot evict)");
            }
        }

        while w.total_bytes.saturating_add(tx_bytes) > self.max_bytes {

            if !evict_one_lowest_feerate(&mut w) {
                bail!("mempool bytes full (cannot evict)");
            }
        }

        // Insert spent marks first.
        for inp in &tx.inputs {
            w.spent.insert(inp.prevout, id);
        }

        // Insert tx.
        w.txs.insert(id, tx);

        // Update total bytes (single source of truth).
        w.total_bytes = w.total_bytes.saturating_add(tx_bytes);

        // Fee info + eviction key.
        let fi = FeeInfo {
            fee,
            bytes: tx_bytes_u64 as u32,
            feerate_ppm,
        };
        w.feeinfo.insert(id, fi);
        w.eviction.insert((fi.feerate_ppm, id));

        Ok(true)
    }

    /// Remove tx by id, and free its spent outpoints. Returns true if removed.
    pub fn remove(&self, id: &Hash32) -> bool {
        let mut w = self.inner.write().unwrap();
        remove_locked(&mut w, id)
    }

    /// Return up to `max_txs` transactions (cloned) without removing them.
    ///
    /// Deterministic order: highest feerate first, tie-break by txid.
    ///
    /// PRODUCTION UPGRADE:
    /// - Use eviction index directly (reverse iteration) so we avoid O(n log n) sorting every call.
    pub fn sample(&self, max_txs: usize) -> Vec<Transaction> {
    let r = self.inner.read().unwrap();

    // Collect first so we can fix tie-break ordering
    let mut entries: Vec<(u64, Hash32)> =
        r.eviction.iter().cloned().collect();

    // Sort by:
    // 1) feerate DESC
    // 2) txid ASC
    entries.sort_by(|a, b| {
        match b.0.cmp(&a.0) {
            std::cmp::Ordering::Equal => a.1.cmp(&b.1),
            other => other,
        }
    });

    let mut out = Vec::with_capacity(max_txs.min(entries.len()));
    for (_fr, id) in entries.into_iter().take(max_txs) {
        if let Some(tx) = r.txs.get(&id) {
            out.push(tx.clone());
        }
    }

    out
}

    /// Revalidate mempool txs against *current* canonical UTXO set and policy caps.
    ///
    /// Returns number removed.
    pub fn prune(&self, db: &crate::state::db::Stores) -> usize {
        let c = crate::codec::consensus_bincode();

        // snapshot outside lock
        let snapshot: Vec<(Hash32, Transaction)> = {
            let r = self.inner.read().unwrap();
            r.txs.iter().map(|(id, tx)| (*id, tx.clone())).collect()
        };

        let mut removed = 0usize;

        for (id, tx) in snapshot {
            // Enforce shape/size caps and strict-connectability.
            let oversized = tx.inputs.is_empty()
                || tx.inputs.len() > MAX_TX_INPUTS
                || tx.outputs.len() > MAX_TX_OUTPUTS
                || c.serialized_size(&tx)
                    .map(|n| (n as usize) > MAX_TX_BYTES)
                    .unwrap_or(true);

            // Also enforce min feerate on prune (in case policy changes).
            let too_low_feerate = match c.serialized_size(&tx) {
                Ok(n) if n > 0 => compute_fee_and_feerate_ppm(db, &tx, n)
                    .map(|(_fee, fr)| fr < MIN_FEERATE_PPM)
                    .unwrap_or(true),
                _ => true,
            };

            // Most important: if inputs no longer exist / not valid for current tip, drop it.
            if oversized || too_low_feerate || validate_tx_for_mempool(db, &tx).is_err() {
                if self.remove(&id) {
                    removed += 1;
                }
            }
        }

        removed
    }

    pub fn remove_conflicts(&self, spent: &HashSet<OutPoint>) -> usize {
        let mut w = self.inner.write().unwrap();

        let mut victims: Vec<Hash32> = Vec::new();
        for op in spent {
            if let Some(txid) = w.spent.get(op) {
                victims.push(*txid);
            }
        }
        victims.sort();

        let mut removed = 0usize;
        for id in victims {
            if remove_locked(&mut w, &id) {
                removed += 1;
            }
        }
        removed
    }

    pub fn remove_mined_block(&self, block: &Block) -> usize {
        let mut spent = HashSet::<OutPoint>::new();
        let mut mined_ids = Vec::<Hash32>::new();

        for (i, tx) in block.txs.iter().enumerate() {
            // skip coinbase for spent collection; it's fine if we still "remove" it by txid (no-op).
            if i != 0 {
                for inp in &tx.inputs {
                    spent.insert(inp.prevout);
                }
            }
            mined_ids.push(txid(tx));
        }

        let mut removed = 0usize;

        for id in mined_ids {
            if self.remove(&id) {
                removed += 1;
            }
        }

        removed += self.remove_conflicts(&spent);
        removed
    }
}

// ------------------------- fee computation -------------------------

fn compute_fee_and_feerate_ppm(
    db: &crate::state::db::Stores,
    tx: &Transaction,
    tx_bytes: u64,
) -> Result<(u64, u64)> {
    if tx_bytes == 0 {
        bail!("tx_bytes=0");
    }
    if tx.inputs.is_empty() {
        bail!("no inputs; cannot compute fee");
    }

    // Sum input values from UTXO set.
    let mut in_sum: u64 = 0;
    for inp in &tx.inputs {
        let Some(u) = get_utxo(db, &inp.prevout)? else {
            bail!("missing utxo during fee computation (prevout not found)");
        };
        in_sum = in_sum
            .checked_add(u.value)
            .ok_or_else(|| anyhow::anyhow!("u64 overflow in input sum"))?;
    }

    let mut out_sum: u64 = 0;
    for o in &tx.outputs {
        out_sum = out_sum
            .checked_add(o.value)
            .ok_or_else(|| anyhow::anyhow!("u64 overflow in output sum"))?;
    }

    if in_sum < out_sum {
        bail!("negative fee (in_sum < out_sum)");
    }
    let fee = in_sum - out_sum;

    // fee-rate in “ppm per byte” for integer ordering: fee * 1_000_000 / bytes
    let fr = (fee as u128)
        .saturating_mul(1_000_000u128)
        .checked_div(tx_bytes as u128)
        .unwrap_or(0) as u64;

    Ok((fee, fr))
}

// ------------------------- eviction helpers -------------------------

fn evict_one_lowest_feerate(w: &mut Inner) -> bool {
    let victim = w.eviction.iter().next().cloned();
    let Some((_fr, id)) = victim else {
        return false;
    };
    remove_locked(w, &id)
}

fn remove_locked(w: &mut Inner, id: &Hash32) -> bool {
    let Some(tx) = w.txs.remove(id) else {
        return false;
    };

    // Remove feeinfo + eviction key deterministically.
    if let Some(fi) = w.feeinfo.remove(id) {
        w.eviction.remove(&(fi.feerate_ppm, *id));

        // total_bytes is accounted via fi.bytes (derived from consensus serialized_size at insert).
        // This is our single source of truth for byte accounting on removal.
        w.total_bytes = w.total_bytes.saturating_sub(fi.bytes as usize);
    } else {
        // Defensive fallback: recompute bytes.
        let c = crate::codec::consensus_bincode();
        if let Ok(n) = c.serialized_size(&tx) {
            w.total_bytes = w.total_bytes.saturating_sub(n as usize);
        }
        // Also best-effort remove from eviction if it exists (scan).
        let mut rm: Option<(u64, Hash32)> = None;
        for item in w.eviction.iter() {
            if item.1 == *id {
                rm = Some(*item);
                break;
            }
        }
        if let Some(x) = rm {
            w.eviction.remove(&x);
        }
    }

    // Free spent outpoints owned by this tx.
    for inp in &tx.inputs {
        if let Some(spender) = w.spent.get(&inp.prevout) {
            if spender == id {
                w.spent.remove(&inp.prevout);
            }
        }
    }

    true
}
