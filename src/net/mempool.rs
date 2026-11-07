//mempool.rs

use std::collections::{BTreeSet, HashMap, HashSet};
use std::sync::RwLock;

use anyhow::{bail, Result};

use crate::crypto::txid;
use crate::params::{MAX_TX_BYTES, MAX_TX_INPUTS, MAX_TX_OUTPUTS};
use crate::state::db::get_utxo;
use crate::state::utxo::{validate_app_state_mempool, validate_tx_for_mempool};
use crate::types::{Block, Hash32, OutPoint, Transaction};


/// Notes:
/// - Mempool is "strictly mineable": it only accepts txs whose inputs exist
///   in the current canonical UTXO set (no mempool chains / no package relay).
/// - That property dramatically reduces complexity and DoS surface.

/// IMPORTANT:
/// - Per-tx caps must NOT exceed consensus caps (or unminable txes will be accepted).
const MAX_MEMPOOL_TXS: usize = 50_000;
const MAX_MEMPOOL_BYTES: usize = 64 * 1024 * 1024; // 64 MiB total tx bytes (serialized)
const MAX_MEMPOOL_SPENT: usize = 200_000; // cap spent-outpoint index growth (DoS guard)

/// Minimum fee-rate to be accepted into mempool.
/// Unit: "ppm-per-byte" = fee * 1_000_000 / tx_bytes.
const MIN_FEERATE_PPM: u64 = 1;

pub struct Mempool {
    inner: RwLock<Inner>,
    max_txs: usize,
    max_bytes: usize,
    max_spent: usize,
}

// Unmined-tx time-to-live (in-memory policy only; never touches consensus bytes). The mempool has
// no RBF ("input already spent in mempool" rejects replacements) and, without this, no expiry; a
// valid tx that missed its single gossip window would sit here FOREVER holding its inputs hostage in
// this node's available-utxo view (a user-visible fund freeze until a process restart). 36h is
// orders of magnitude above any honest inclusion delay on a 120s-block chain, so expiry can only
// ever free a genuinely stuck tx; a wallet then simply resubmits. Swept in prune() (runs on
// every block connect + reorg).
const MEMPOOL_TX_TTL_SECS: u64 = 36 * 3600;

fn unix_now_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
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

    // txid -> unix seconds first accepted (for the TTL sweep; a reorg re-add restarts the clock,
    // which only ever EXTENDS a stuck tx's life; acceptable, and it keeps reorg.rs untouched)
    seen_at: HashMap<Hash32, u64>,
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

    pub fn get(&self, id: &Hash32) -> Option<Transaction> {
        self.inner.read().unwrap().txs.get(id).cloned()
    }

    /// True when the pool holds the tx `id` and its consensus encoding is `tx_bytes`, script_sigs
    /// included. `contains` matches any tx with that txid, and a txid leaves the script_sigs out
    /// (`crypto::txid`).
    pub fn holds_encoding(&self, id: &Hash32, tx_bytes: &[u8]) -> bool {
        let r = self.inner.read().unwrap();
        r.txs.get(id).is_some_and(|held| {
            crate::codec::consensus_bincode()
                .serialize(held)
                .is_ok_and(|b| b == tx_bytes)
        })
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

    /// (txid, age_secs) for up to `cap` mempool txs, oldest first: the stranded-tx monitor's source,
    /// with the pool's tx count read under the same lock. Age derives from the TTL `seen_at`
    /// stamp; `now` is unix seconds (0 age if a stamp is somehow missing). Read-only; the API
    /// route that exposes it is loopback-gated.
    pub fn txids_with_age(&self, now: u64, cap: usize) -> (Vec<(Hash32, u64)>, usize) {
        let r = self.inner.read().unwrap();
        let mut out: Vec<(Hash32, u64)> = r
            .txs
            .keys()
            .map(|id| (*id, now.saturating_sub(r.seen_at.get(id).copied().unwrap_or(now))))
            .collect();
        out.sort_by(|a, b| b.1.cmp(&a.1)); // oldest (largest age) first
        out.truncate(cap);
        (out, r.txs.len())
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

        // Room is planned against all three caps before anything is removed, so a tx that cannot
        // be admitted leaves the pool as it was.
        let victims = match plan_admission(
            &w,
            Caps { txs: self.max_txs, bytes: self.max_bytes, spent: self.max_spent },
            tx_bytes,
            tx.inputs.len(),
            feerate_ppm,
        ) {
            Ok(victims) => victims,
            Err(short) => {
                let min_fr = w.eviction.iter().next().map(|x| x.0);
                match (short, min_fr) {
                    (Shortfall::Spent, _) => bail!(
                        "mempool spent index full (spent_len={} + new_inputs={} > max_spent={})",
                        w.spent.len(),
                        tx.inputs.len(),
                        self.max_spent
                    ),
                    (_, None) => bail!("mempool state inconsistent: full but eviction set empty"),
                    (_, Some(min_fr)) if feerate_ppm <= min_fr => bail!(
                        "mempool full; feerate {} not competitive (min={})",
                        feerate_ppm,
                        min_fr
                    ),
                    (Shortfall::Count, _) => bail!(
                        "mempool full; no lower-feerate tx available to evict (new_feerate={})",
                        feerate_ppm
                    ),
                    (Shortfall::Bytes, _) => bail!(
                        "mempool bytes full; no lower-feerate tx available to evict (new_feerate={})",
                        feerate_ppm
                    ),
                }
            }
        };
        for vid in &victims {
            remove_locked(&mut w, vid);
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
        w.seen_at.insert(id, unix_now_secs());

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
    /// TEST-ONLY seam: plant a tx WITHOUT the admission gate (insert_checked). The template
    /// test uses this to simulate a poison that predates the gate (a tx held from before the gate
    /// existed, or a refeed path), proving the TEMPLATE builder re-validates and excludes it.
    #[cfg(test)]
    pub(crate) fn force_insert_for_test(&self, tx: Transaction, feerate_ppm: u64) -> Hash32 {
        let id = txid(&tx);
        let bytes = crate::codec::consensus_bincode()
            .serialized_size(&tx)
            .unwrap() as usize;
        let mut w = self.inner.write().unwrap();
        for inp in &tx.inputs {
            w.spent.insert(inp.prevout, id);
        }
        w.txs.insert(id, tx);
        w.total_bytes += bytes;
        w.feeinfo.insert(id, FeeInfo { fee: 1, bytes: bytes as u32, feerate_ppm });
        w.eviction.insert((feerate_ppm, id));
        id
    }

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
        let now = unix_now_secs();

        let snapshot: Vec<(Hash32, Transaction, Option<u64>)> = {
            let r = self.inner.read().unwrap();
            r.txs
                .iter()
                .map(|(id, tx)| (*id, tx.clone(), r.seen_at.get(id).copied()))
                .collect()
        };

        let mut removed = 0usize;

        for (id, tx, seen) in snapshot {
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

            // TTL: an unmined tx past MEMPOOL_TX_TTL_SECS is expired; with no RBF it would hold
            // its inputs hostage in this node's view forever otherwise (see the const's comment).
            // The mempool is RAM-only, so every entry in THIS process was stamped by insert_checked;
            // a None stamp cannot occur, and if it somehow did we must not expire blind.
            let expired = match seen {
                Some(t) => now.saturating_sub(t) > MEMPOOL_TX_TTL_SECS,
                None => false,
            };

            if oversized || too_low_feerate || expired || still_admissible(db, &tx).is_err() {
                if self.remove(&id) {
                    removed += 1;
                    // log only after the removal actually happened (a racing remove could win)
                    if expired {
                        println!(
                            "[mempool] TTL-expired unmined tx 0x{} after {}h; inputs released",
                            hex::encode(id),
                            now.saturating_sub(seen.unwrap_or(now)) / 3600
                        );
                    }
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

/// What a block or a reorg can change for a held tx: whether the outputs it
/// spends are still unspent, and the app state its payload is checked against (a proposal an
/// Attest names, the epoch a Propose or an Attest expires by). Every other check of
/// `validate_tx_for_mempool` reads only the tx's own bytes and the outputs it spends, which the
/// txids in its inputs fix, and passed at admission (`insert_checked`; the pool's other writer,
/// `force_insert_for_test`, is compiled in tests only), so prune does not repeat it: its signature
/// checks were most of the prune's cost, at every block and before every template.
fn still_admissible(db: &crate::state::db::Stores, tx: &Transaction) -> Result<()> {
    // `prune` drops a tx with a spent or missing input first, through its feerate check
    // (`compute_fee_and_feerate_ppm` fails on it); this loop keeps the rule here as well.
    for inp in &tx.inputs {
        if get_utxo(db, &inp.prevout)?.is_none() {
            bail!("missing utxo");
        }
    }
    validate_app_state_mempool(db, tx)
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

#[derive(Clone, Copy)]
struct Caps {
    txs: usize,
    bytes: usize,
    spent: usize,
}

/// The cap a tx still overflows once every lower-feerate entry is counted out.
#[derive(Clone, Copy)]
enum Shortfall {
    Spent,
    Count,
    Bytes,
}

/// The entries to evict to admit a tx of `bytes` bytes spending `inputs` outpoints at
/// `feerate_ppm`: the shortest prefix of the eviction order (lowest feerate first, all below
/// `feerate_ppm`) after which the count, byte and spent-input caps all hold. It only decides;
/// `insert_checked` removes the victims once the tx is sure to go in.
fn plan_admission(
    w: &Inner,
    caps: Caps,
    bytes: usize,
    inputs: usize,
    feerate_ppm: u64,
) -> std::result::Result<Vec<Hash32>, Shortfall> {
    let (mut n, mut total, mut spent) = (w.txs.len(), w.total_bytes, w.spent.len());
    let short = |n: usize, total: usize, spent: usize| {
        if spent.saturating_add(inputs) > caps.spent {
            Some(Shortfall::Spent)
        } else if n >= caps.txs {
            Some(Shortfall::Count)
        } else if total.saturating_add(bytes) > caps.bytes {
            Some(Shortfall::Bytes)
        } else {
            None
        }
    };
    let mut victims = Vec::new();
    for &(fr, vid) in w.eviction.iter() {
        if short(n, total, spent).is_none() || fr >= feerate_ppm {
            break;
        }
        n -= 1;
        total = total.saturating_sub(w.feeinfo.get(&vid).map_or(0, |f| f.bytes as usize));
        spent = spent.saturating_sub(w.txs.get(&vid).map_or(0, |t| t.inputs.len()));
        victims.push(vid);
    }
    match short(n, total, spent) {
        None => Ok(victims),
        Some(s) => Err(s),
    }
}

fn remove_locked(w: &mut Inner, id: &Hash32) -> bool {
    let Some(tx) = w.txs.remove(id) else {
        return false;
    };
    w.seen_at.remove(id); // single removal chokepoint: every exit path clears the TTL stamp

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

#[cfg(test)]
mod tests {
    use super::*;
use crate::types::{AppPayload, BlockHeader, TxIn, TxOut};

fn test_header() -> BlockHeader {
    BlockHeader {
        version: 1,
        prev: [0u8; 32],
        merkle: [0u8; 32],
        time: 0,
        bits: 0,
        nonce: 0,
    }
}

    fn op(n: u8) -> OutPoint {
        OutPoint {
            txid: [n; 32],
            vout: 0,
        }
    }

    fn tx_spending(prevout: OutPoint, value: u64) -> Transaction {
        Transaction {
            version: 1,
            inputs: vec![TxIn {
                prevout,
                script_sig: vec![1, 2, 3],
            }],
            outputs: vec![TxOut {
                value,
                script_pubkey: [9u8; 20],
            }],
            locktime: 0,
            app: AppPayload::None,
        }
    }

    fn coinbase() -> Transaction {
        Transaction {
            version: 1,
            inputs: vec![TxIn {
                prevout: OutPoint {
                    txid: [0u8; 32],
                    vout: u32::MAX,
                },
                script_sig: vec![0],
            }],
            outputs: vec![TxOut {
                value: 50,
                script_pubkey: [7u8; 20],
            }],
            locktime: 0,
            app: AppPayload::None,
        }
    }

    fn force_insert_for_test(mp: &Mempool, tx: Transaction, feerate_ppm: u64) -> Hash32 {
        let id = txid(&tx);
        let bytes = crate::codec::consensus_bincode()
            .serialized_size(&tx)
            .unwrap() as usize;

        let mut w = mp.inner.write().unwrap();

        for inp in &tx.inputs {
            w.spent.insert(inp.prevout, id);
        }

        w.txs.insert(id, tx);
        w.total_bytes += bytes;

        let fi = FeeInfo {
            fee: 1,
            bytes: bytes as u32,
            feerate_ppm,
        };

        w.feeinfo.insert(id, fi);
        w.eviction.insert((feerate_ppm, id));

        id
    }

    #[test]
    fn mined_block_removes_conflicting_mempool_tx() {
        let mp = Mempool::new();

        let shared_input = op(1);

        let mempool_tx = tx_spending(shared_input, 10);
        let mined_competing_tx = tx_spending(shared_input, 9);

        let mempool_id = force_insert_for_test(&mp, mempool_tx, 100);

        assert!(mp.contains(&mempool_id));
        assert!(mp.has_spent_outpoint(&shared_input));

        let block = Block {
header: test_header(),
            txs: vec![coinbase(), mined_competing_tx],
        };

        let removed = mp.remove_mined_block(&block);

        assert_eq!(removed, 1);
        assert!(!mp.contains(&mempool_id));
        assert!(!mp.has_spent_outpoint(&shared_input));
        assert_eq!(mp.len(), 0);
        assert_eq!(mp.spent_len(), 0);
    }

    #[test]
    fn mined_block_removes_exact_mempool_tx() {
        let mp = Mempool::new();

        let input = op(2);
        let tx = tx_spending(input, 10);
        let id = force_insert_for_test(&mp, tx.clone(), 100);

        assert!(mp.contains(&id));
        assert!(mp.has_spent_outpoint(&input));

        let block = Block {
header: test_header(),
            txs: vec![coinbase(), tx],
        };

        let removed = mp.remove_mined_block(&block);

        assert_eq!(removed, 1);
        assert!(!mp.contains(&id));
        assert!(!mp.has_spent_outpoint(&input));
        assert_eq!(mp.len(), 0);
        assert_eq!(mp.spent_len(), 0);
    }
}
