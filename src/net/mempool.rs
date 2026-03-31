//mempool.rs

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

    // txid -> fee info
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

#[derive(Clone, Copy, Debug, Default)]
pub struct MempoolStats {
    pub txs: usize,
    pub total_bytes: usize,
    pub spent_len: usize,
    pub min_feerate_ppm: Option<u64>,
    pub max_feerate_ppm: Option<u64>,
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

    pub fn total_bytes(&self) -> usize {
        self.inner.read().unwrap().total_bytes
    }

    pub fn spent_len(&self) -> usize {
        self.inner.read().unwrap().spent.len()
    }

    pub fn has_spent_outpoint(&self, op: &OutPoint) -> bool {
        self.inner.read().unwrap().spent.contains_key(op)
    }

    pub fn has_spent_outpoint_hex(&self, txid_hex: &str, vout: u32) -> bool {
        let s = txid_hex.strip_prefix("0x").unwrap_or(txid_hex);
        let bytes = match hex::decode(s) {
            Ok(b) => b,
            Err(_) => return false,
        };

        if bytes.len() != 32 {
            return false;
        }

        let mut txid = [0u8; 32];
        txid.copy_from_slice(&bytes);

        let op = OutPoint { txid, vout };
        self.has_spent_outpoint(&op)
    }

    pub fn spent_outpoints(&self) -> HashSet<OutPoint> {
        let r = self.inner.read().unwrap();
        r.spent.keys().cloned().collect()
    }

    pub fn spent_outpoints_vec(&self) -> Vec<OutPoint> {
        let r = self.inner.read().unwrap();
        r.spent.keys().cloned().collect()
    }

    pub fn min_feerate_ppm(&self) -> Option<u64> {
        self.inner
            .read()
            .unwrap()
            .eviction
            .iter()
            .next()
            .map(|x| x.0)
    }

    pub fn max_feerate_ppm(&self) -> Option<u64> {
        self.inner
            .read()
            .unwrap()
            .eviction
            .iter()
            .next_back()
            .map(|x| x.0)
    }

    pub fn stats(&self) -> MempoolStats {
        let r = self.inner.read().unwrap();
        MempoolStats {
            txs: r.txs.len(),
            total_bytes: r.total_bytes,
            spent_len: r.spent.len(),
            min_feerate_ppm: r.eviction.iter().next().map(|x| x.0),
            max_feerate_ppm: r.eviction.iter().next_back().map(|x| x.0),
        }
    }

    /// For operational/testing use only.
    pub fn clear(&self) {
        let mut w = self.inner.write().unwrap();
        *w = Inner::default();
    }

    /// Insert WITH consensus-mempool validation against the current UTXO set.
    ///
    /// Returns:
    /// - Ok(true)  => added
    /// - Ok(false) => already present OR conflicts with an existing mempool spend
    /// - Err(_)    => tx is invalid / not connectable / rejected by policy
    pub fn insert_checked(&self, db: &crate::state::db::Stores, tx: Transaction) -> Result<bool> {
        let c = crate::codec::consensus_bincode();

        // Cheap DoS guards
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
            bail!("tx has no inputs (coinbase-like); not allowed in mempool");
        }

        let id = txid(&tx);
        if self.contains(&id) {
            return Ok(false);
        }

        // Strong checks against current canonical UTXO set.
        validate_tx_for_mempool(db, &tx)?;

        let (fee, feerate_ppm) = compute_fee_and_feerate_ppm(db, &tx, tx_bytes_u64)?;

        if feerate_ppm < MIN_FEERATE_PPM {
            bail!(
                "feerate too low ({} < MIN_FEERATE_PPM={})",
                feerate_ppm,
                MIN_FEERATE_PPM
            );
        }

        let mut w = self.inner.write().unwrap();

        if w.txs.contains_key(&id) {
            return Ok(false);
        }

        // Reject if any input already spent in mempool.
        for inp in &tx.inputs {
            if w.spent.contains_key(&inp.prevout) {
                return Ok(false);
            }
        }

        if w.spent.len().saturating_add(tx.inputs.len()) > self.max_spent {
            bail!(
                "mempool spent index full (spent_len={} + new_inputs={} > max_spent={})",
                w.spent.len(),
                tx.inputs.len(),
                self.max_spent
            );
        }

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

        for inp in &tx.inputs {
            w.spent.insert(inp.prevout, id);
        }

        w.txs.insert(id, tx);
        w.total_bytes = w.total_bytes.saturating_add(tx_bytes);

        let fi = FeeInfo {
            fee,
            bytes: tx_bytes_u64 as u32,
            feerate_ppm,
        };
        w.feeinfo.insert(id, fi);
        w.eviction.insert((fi.feerate_ppm, id));

        Ok(true)
    }

    pub fn remove(&self, id: &Hash32) -> bool {
        let mut w = self.inner.write().unwrap();
        remove_locked(&mut w, id)
    }

    /// Deterministic order:
    /// 1) feerate DESC
    /// 2) txid ASC
    ///
    /// This walks the eviction index from high -> low, grouping equal-feerate txs
    /// and sorting only inside each feerate bucket.
    pub fn sample(&self, max_txs: usize) -> Vec<Transaction> {
        let r = self.inner.read().unwrap();
        let mut out = Vec::with_capacity(max_txs.min(r.txs.len()));

        let mut current_fr: Option<u64> = None;
        let mut bucket: Vec<Hash32> = Vec::new();

        let flush_bucket =
            |bucket: &mut Vec<Hash32>, out: &mut Vec<Transaction>, r: &Inner, max_txs: usize| {
                if bucket.is_empty() || out.len() >= max_txs {
                    bucket.clear();
                    return;
                }
                bucket.sort(); // txid ASC inside equal-feerate bucket
                for id in bucket.iter() {
                    if out.len() >= max_txs {
                        break;
                    }
                    if let Some(tx) = r.txs.get(id) {
                        out.push(tx.clone());
                    }
                }
                bucket.clear();
            };

        for (fr, id) in r.eviction.iter().rev() {
            match current_fr {
                None => {
                    current_fr = Some(*fr);
                    bucket.push(*id);
                }
                Some(cur) if cur == *fr => {
                    bucket.push(*id);
                }
                Some(_) => {
                    flush_bucket(&mut bucket, &mut out, &r, max_txs);
                    if out.len() >= max_txs {
                        break;
                    }
                    current_fr = Some(*fr);
                    bucket.push(*id);
                }
            }
        }

        flush_bucket(&mut bucket, &mut out, &r, max_txs);
        out
    }

    pub fn prune(&self, db: &crate::state::db::Stores) -> usize {
        let c = crate::codec::consensus_bincode();

        let snapshot: Vec<(Hash32, Transaction)> = {
            let r = self.inner.read().unwrap();
            r.txs.iter().map(|(id, tx)| (*id, tx.clone())).collect()
        };

        let mut removed = 0usize;

        for (id, tx) in snapshot {
            let oversized = tx.inputs.is_empty()
                || tx.inputs.len() > MAX_TX_INPUTS
                || tx.outputs.len() > MAX_TX_OUTPUTS
                || c.serialized_size(&tx)
                    .map(|n| (n as usize) > MAX_TX_BYTES)
                    .unwrap_or(true);

            let too_low_feerate = match c.serialized_size(&tx) {
                Ok(n) if n > 0 => compute_fee_and_feerate_ppm(db, &tx, n)
                    .map(|(_fee, fr)| fr < MIN_FEERATE_PPM)
                    .unwrap_or(true),
                _ => true,
            };

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

        let mut victims: BTreeSet<Hash32> = BTreeSet::new();
        for op in spent {
            if let Some(txid) = w.spent.get(op) {
                victims.insert(*txid);
            }
        }

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

    if let Some(fi) = w.feeinfo.remove(id) {
        let _ = fi.fee; // retained because useful for future RPC/stats
        w.eviction.remove(&(fi.feerate_ppm, *id));
        w.total_bytes = w.total_bytes.saturating_sub(fi.bytes as usize);
    } else {
        let c = crate::codec::consensus_bincode();
        if let Ok(n) = c.serialized_size(&tx) {
            w.total_bytes = w.total_bytes.saturating_sub(n as usize);
        }

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

    for inp in &tx.inputs {
        if let Some(spender) = w.spent.get(&inp.prevout) {
            if spender == id {
                w.spent.remove(&inp.prevout);
            }
        }
    }

    true
}
