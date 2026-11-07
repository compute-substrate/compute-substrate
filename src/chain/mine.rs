// src/chain/mine.rs
use anyhow::{anyhow, Result};

use crate::chain::index::{get_hidx, header_hash, index_header, HeaderIndex};
use crate::chain::lock::ChainLock;
use crate::chain::pow::{expected_bits, PowTarget};
use crate::chain::reorg::maybe_reorg_to;
use crate::chain::time::{median_time_past, now_secs};
use crate::crypto::{sha256d, txid};
use crate::net::mempool::Mempool;
use crate::params::{
    block_reward, MAX_BLOCK_BYTES, MAX_FUTURE_DRIFT_SECS, MIN_BLOCK_SPACING_SECS,
};
use crate::state::app_state::epoch_of;
use crate::state::db::{get_tip, get_utxo, k_block, Stores};
use crate::state::utxo::validate_tx_for_mempool;
use crate::types::{
    AppPayload, Block, BlockHeader, Hash20, Hash32, OutPoint, Transaction, TxIn, TxOut,
};
use std::sync::{
atomic::{AtomicBool, AtomicU64, Ordering},
    mpsc,
    Arc,
};
use std::thread;
use std::collections::HashSet;
use std::time::Instant;

const MINER_BLOCK_SIZE_SAFETY_BYTES: usize = 16 * 1024;

// The template belt: every node refuses a request-response message of 1 MiB or more
// (net/node.rs MAX_RR_MSG_BYTES, upstream's bound too), though consensus admits a block up to
// MAX_BLOCK_BYTES. A block we templated above it could be fetched by no peer, and a mempool flood
// would make one. The cap stays while consensus admits blocks the transport refuses
// (docs/behaviour.md "Transport cap and blocks above 1 MiB").
const MINER_TEMPLATE_TRANSPORT_SAFE_BYTES: usize = 1024 * 1024 - 32 * 1024;

/// The effective template byte cap: the consensus cap minus the safety margin, belted below the
/// 1 MiB transport cap.
pub(crate) fn template_byte_cap() -> usize {
    MAX_BLOCK_BYTES
        .saturating_sub(MINER_BLOCK_SIZE_SAFETY_BYTES)
        .min(MINER_TEMPLATE_TRANSPORT_SAFE_BYTES)
}



/// Bitcoin-ish merkle root from txids.
/// - leaves are txid bytes
/// - internal nodes are sha256d(left || right), duplicating last if odd
pub fn merkle_root_txids(txids: &[[u8; 32]]) -> [u8; 32] {
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
            next.push(sha256d(&buf));
            i += 2;
        }
        layer = next;
    }
    layer[0]
}

fn merkle_root(txs: &[Transaction]) -> Hash32 {
    let mut ids: Vec<Hash32> = Vec::with_capacity(txs.len());
    for tx in txs {
        ids.push(txid(tx));
    }
    merkle_root_txids(&ids)
}

fn miner_entropy() -> Vec<u8> {
    let host = std::env::var("HOSTNAME").unwrap_or_else(|_| "unknown-host".to_string());
    let pid = std::process::id();
    let instance = std::env::var("CSD_MINER_ID").unwrap_or_else(|_| "default".to_string());

    format!("{host}:{pid}:{instance}").into_bytes()
}

fn mine_log_event(event: &str, height: u64, hash: Option<&Hash32>, msg: &str) {
    match hash {
        Some(h) => println!(
            "[mine-event] event={} height={} hash=0x{} {}",
            event,
            height,
            hex::encode(h),
            msg
        ),
        None => println!(
            "[mine-event] event={} height={} {}",
            event,
            height,
            msg
        ),
    }
}


/// Coinbase with guaranteed uniqueness:
/// - script_sig commits height (consensus rule enforced in utxo.rs)
/// - locktime commits height (also makes txid unique even if txid strips scriptsig)
pub fn coinbase(miner_h160: Hash20, value: u64, height: u64, memo: Option<&[u8]>) -> Transaction {
    let mut script_sig = height.to_le_bytes().to_vec();
    let locktime = height as u32;
    if let Some(m) = memo {
    script_sig.push(0x00);
    script_sig.extend_from_slice(m);
}
    Transaction {
        version: 1,
        inputs: vec![TxIn {
            prevout: OutPoint {
                txid: [0u8; 32],
                vout: u32::MAX,
            },
            script_sig,
        }],
        outputs: vec![TxOut {
            value,
            script_pubkey: miner_h160,
        }],
        locktime,
        app: AppPayload::None,
    }
}



/// Return (all_inputs_exist, in_sum)
fn sum_inputs_if_present(db: &Stores, tx: &Transaction) -> Result<(bool, u64)> {
    if tx.inputs.is_empty() {
        return Ok((false, 0));
    }

    let mut in_sum: u64 = 0;
    for inp in &tx.inputs {
        let prev = match get_utxo(db, &inp.prevout)? {
            Some(p) => p,
            None => return Ok((false, 0)),
        };

        in_sum = in_sum
            .checked_add(prev.value)
            .ok_or_else(|| anyhow!("overflow in_sum"))?;
    }

    Ok((true, in_sum))
}

fn sum_outputs(tx: &Transaction) -> Result<u64> {
    let mut out_sum: u64 = 0;
    for out in &tx.outputs {
        out_sum = out_sum
            .checked_add(out.value)
            .ok_or_else(|| anyhow!("overflow out_sum"))?;
    }
    Ok(out_sum)
}

/// Compute fee for a tx using the current UTXO set.
fn compute_fee_from_utxos(db: &Stores, tx: &Transaction) -> Result<u64> {
    let (ok, in_sum) = sum_inputs_if_present(db, tx)?;
    if !ok {
        return Err(anyhow!("missing utxo"));
    }

    let out_sum = sum_outputs(tx)?;
    if out_sum > in_sum {
        return Err(anyhow!("outputs exceed inputs"));
    }

    Ok(in_sum - out_sum)
}

/// How far our stamps stay inside the consensus future bound: a peer refuses
/// a header stamped past its own now + MAX_FUTURE_DRIFT_SECS (index.rs), and the time between our
/// stamp and its check only advances its clock, so a peer whose clock is up to this far behind ours
/// accepts every header we stamp. It also bounds the wait on a parent stamped at the drift limit
/// to this plus MIN_BLOCK_SPACING_SECS.
pub const MINER_CLOCK_SKEW_MARGIN_SECS: u64 = 600;

/// The miner's stamp for a block whose earliest valid time is `min_ok`, at wall clock `now`:
/// `Ok(max(now, min_ok))` whenever min_ok is at most now + MAX_FUTURE_DRIFT_SECS -
/// MINER_CLOCK_SKEW_MARGIN_SECS, else `Err(seconds until it is)`. Upstream's miner waits until the
/// wall clock passes min_ok, so one tip stamped near the 2 h drift limit idles it for up to 2 h
/// while consensus accepts a child at once. The consensus rules are unchanged; this is only the
/// miner's choice inside them.
pub fn miner_block_time(now: u64, min_ok: u64) -> std::result::Result<u64, u64> {
    let latest = now
        .saturating_add(MAX_FUTURE_DRIFT_SECS)
        .saturating_sub(MINER_CLOCK_SKEW_MARGIN_SECS);
    if min_ok <= latest {
        Ok(now.max(min_ok))
    } else {
        Err(min_ok - latest)
    }
}

/// Choose a block time that matches the consensus rules in index_header:
/// - time >= parent.time + MIN_BLOCK_SPACING_SECS
/// - time > MTP(parent)
/// - time <= now + MAX_FUTURE_DRIFT_SECS
///
/// This MUST track wall-clock time (clamped), or LWMA will drift the wrong way. It does
/// except while the parent is stamped ahead of the clock, when it is the earliest valid time; the
/// LWMA effect of that is measured in docs/behaviour.md "Block time on a parent stamped ahead".
/// The stamp is `miner_block_time`'s; a wait for a parent stamped beyond its bound ends with `None`
/// as soon as `stale` is set (the tip moved: `mine_one`'s watcher runs during the wait).
fn choose_block_time(
    db: &Stores,
    parent_tip: &Hash32,
    parent_hi: Option<&HeaderIndex>,
    stale: &AtomicBool,
) -> Option<u64> {
    if *parent_tip == [0u8; 32] || parent_hi.is_none() {
        return Some(0);
    }

    let p = parent_hi.unwrap();

    let mtp = median_time_past(db, &p.hash).unwrap_or(p.time);

    let min_ok = p.time
        .saturating_add(MIN_BLOCK_SPACING_SECS)
        .max(mtp.saturating_add(1));

    let mut logged = false;
    loop {
        let now = now_secs();
        let wait = match miner_block_time(now, min_ok) {
            Ok(t) => return Some(t),
            Err(wait) => wait,
        };
        if stale.load(Ordering::Relaxed) {
            return None;
        }
        if !logged {
            println!(
                "[mine] parent stamped {}s ahead of the wall clock: waiting {}s for next_valid_time={} to come within {}s of now",
                p.time.saturating_sub(now),
                wait,
                min_ok,
                MAX_FUTURE_DRIFT_SECS - MINER_CLOCK_SKEW_MARGIN_SECS,
            );
            logged = true;
        }
        std::thread::sleep(std::time::Duration::from_millis(200));
    }
}

/// Test-only record of the parent of every solution `mine_one` received, before it takes the chain
/// lock to commit it (`tests/mine_one_rebases_on_tip_change.rs` holds the lock across a solve).
#[cfg(feature = "test-bypass")]
pub static TEST_SOLVED_PARENTS: std::sync::Mutex<Vec<Hash32>> = std::sync::Mutex::new(Vec::new());

/// Build a fresh block template from the current tip + current UTXO set.
///
/// Key behavior:
/// - Only includes txs that are valid AND connectable *right now*
/// - Skips anything that fails validate_tx_for_mempool or has missing inputs
/// - Sorts by fee (desc) so miners converge under load
/// - also respects MAX_BLOCK_BYTES (consensus) so we never build an unmineable block

fn build_template(
    db: &Stores,
    mempool: &Mempool,
    miner_h160: Hash20,
    height: u64,
    max_mempool_txs: usize,
) -> Result<(Vec<Transaction>, Vec<Hash32>, u64)> {
    build_template_with_byte_cap(
        db,
        mempool,
        miner_h160,
        height,
        max_mempool_txs,
        template_byte_cap(),
    )
}

fn build_template_with_byte_cap(
    db: &Stores,
    mempool: &Mempool,
    miner_h160: Hash20,
    height: u64,
    max_mempool_txs: usize,
    byte_cap: usize,
) -> Result<(Vec<Transaction>, Vec<Hash32>, u64)> {
    let c = crate::codec::consensus_bincode();
    let reward = block_reward(height);

    const CANDIDATE_MULT: usize = 8;
    let want_candidates = max_mempool_txs
        .saturating_mul(CANDIDATE_MULT)
        .max(max_mempool_txs);

    let sampled = mempool.sample(want_candidates);

    // (feerate_ppm, txid, tx, fee, tx_bytes)
    let mut candidates: Vec<(u64, Hash32, Transaction, u64, u64)> = Vec::new();

    for tx in sampled {
        let id = txid(&tx);

        if validate_tx_for_mempool(db, &tx).is_err() {
            continue;
        }

        let fee = match compute_fee_from_utxos(db, &tx) {
            Ok(f) => f,
            Err(_) => continue,
        };

        let tx_bytes = match c.serialized_size(&tx) {
            Ok(n) if n > 0 => n,
            _ => continue,
        };

        let feerate_ppm = ((fee as u128)
            .saturating_mul(1_000_000u128)
            / (tx_bytes as u128)) as u64;

        candidates.push((feerate_ppm, id, tx, fee, tx_bytes));
    }

    // feerate desc; tie-break by txid ASC
candidates.sort_by(|a, b| {
    use std::cmp::Ordering;

    let prio = |tx: &Transaction| match &tx.app {
        AppPayload::Propose { .. } => 0u8,
        AppPayload::Attest { .. } => 1u8,
        _ => 2u8,
    };

    match prio(&a.2).cmp(&prio(&b.2)) {
        Ordering::Equal => match b.0.cmp(&a.0) {
            Ordering::Equal => a.1.cmp(&b.1),
            o => o,
        },
        o => o,
    }
});

let entropy = miner_entropy();
let cb_placeholder = coinbase(miner_h160, reward, height, Some(&entropy));

    let cb_bytes = c.serialized_size(&cb_placeholder)? as usize;

    let mut remaining = byte_cap.saturating_sub(cb_bytes);

    let mut total_fees: u64 = 0;
    let mut included: Vec<Transaction> = Vec::with_capacity(max_mempool_txs);
    let mut included_ids: Vec<Hash32> = Vec::with_capacity(max_mempool_txs);
    let mut included_bytes: usize = 0;

let mut spent_in_template: HashSet<OutPoint> = HashSet::new();

    for (_feerate_ppm, id, tx, fee, tx_bytes_u64) in candidates.into_iter() {
        if included.len() >= max_mempool_txs {
            break;
        }

        let tx_bytes = tx_bytes_u64 as usize;



        if tx_bytes > remaining {
            continue;
        }

let conflicts_with_template = tx
    .inputs
    .iter()
    .any(|inp| spent_in_template.contains(&inp.prevout));

if conflicts_with_template {
    continue;
}

        total_fees = total_fees
            .checked_add(fee)
            .ok_or_else(|| anyhow!("fee overflow"))?;

for inp in &tx.inputs {
    spent_in_template.insert(inp.prevout.clone());
}

included_ids.push(id);
included.push(tx);



        remaining = remaining.saturating_sub(tx_bytes);
        included_bytes = included_bytes.saturating_add(tx_bytes);
    }

    println!(
        "[mine] template: height={} mempool_len={} sampled={} included={} total_fees={} block_bytes≈{} (cb_bytes={}, tx_bytes={})",
        height,
        mempool.len(),
        want_candidates.min(mempool.len()),
        included.len(),
        total_fees,
        cb_bytes.saturating_add(included_bytes),
        cb_bytes,
        included_bytes
    );

    let cb_value = reward
        .checked_add(total_fees)
        .ok_or_else(|| anyhow!("coinbase overflow"))?;
let cb = coinbase(miner_h160, cb_value, height, Some(&entropy));

    let mut final_txs: Vec<Transaction> = Vec::with_capacity(1 + included.len());
    final_txs.push(cb);
    final_txs.extend(included);

    Ok((final_txs, included_ids, total_fees))
}

/// Test-only template builder entry point. Gated on `test` (unit tests) OR the
/// `test-bypass` cargo feature (integration tests in tests/, which link the lib
/// without cfg(test)). Never compiled into production release builds.
#[cfg(any(test, feature = "test-bypass"))]
pub fn build_template_for_tests(
    db: &Stores,
    mempool: &Mempool,
    miner_h160: Hash20,
    height: u64,
    max_mempool_txs: usize,
    byte_cap: usize,
) -> Result<(Vec<Transaction>, Vec<Hash32>, u64)> {
    build_template_with_byte_cap(
        db,
        mempool,
        miner_h160,
        height,
        max_mempool_txs,
        byte_cap,
    )
}

fn miner_thread_count() -> usize {
    if let Ok(v) = std::env::var("CSD_MINER_THREADS") {
        if let Ok(n) = v.parse::<usize>() {
            return n.max(1);
        }
    }

    let cores = std::thread::available_parallelism()
        .map(|n| n.get())
        .unwrap_or(1);

    let reserve = std::env::var("CSD_MINER_RESERVED_THREADS")
        .ok()
        .and_then(|v| v.parse::<usize>().ok())
        .unwrap_or(1);

    cores.saturating_sub(reserve).max(1)
}

/// Mine exactly one block.
///
/// CRITICAL: Do NOT apply blocks here.
/// Only persist + index, then call maybe_reorg_to() (single source of truth for apply/undo/tip).

pub fn mine_one(
    db: &Stores,
    mempool: &Mempool,
    miner_h160: Hash20,
    max_mempool_txs: usize,
    chain_lock: &ChainLock,
) -> Result<Hash32> {

const HASH_COUNTER_FLUSH_EVERY_NONCES: u64 = 4_194_304;

    
    let parent_tip: Hash32 = get_tip(db)?.unwrap_or([0u8; 32]);
    let parent_hi_opt = if parent_tip != [0u8; 32] {
        get_hidx(db, &parent_tip)?
    } else {
        None
    };

    let height = parent_hi_opt.as_ref().map(|h| h.height + 1).unwrap_or(0);

    let _epoch = epoch_of(height);

    let (mut txs, mut included_ids, _fees) =
        build_template(db, mempool, miner_h160, height, max_mempool_txs)?;

mine_log_event(
    "candidate_created",
    height,
    None,
    &format!(
        "prev=0x{} txs={} included_mempool_txs={} mempool_len={}",
        hex::encode(parent_tip),
        txs.len(),
        included_ids.len(),
        mempool.len()
    ),
);

    // `time` is chosen below, once the stale-tip watcher runs.
    let mut hdr = BlockHeader {
        version: 1,
        prev: parent_tip,
        merkle: merkle_root(&txs),
        time: 0,
        bits: expected_bits(db, height, parent_hi_opt.as_ref())?,
        nonce: 0u32,
    };

let pow_target = PowTarget::from_bits(hdr.bits)
    .ok_or_else(|| anyhow!("invalid mining bits"))?;

#[derive(Clone)]
enum MineMsg {
    Found(Hash32, Block),
    Stale,
}

let workers = miner_thread_count().min(u32::MAX as usize).max(1);
println!("[mine] workers={}", workers);

let stop = Arc::new(AtomicBool::new(false));
let stale = Arc::new(AtomicBool::new(false));
let hash_counter = Arc::new(AtomicU64::new(0));
let (tx_found, rx_found) = mpsc::channel::<MineMsg>();

thread::scope(|scope| {
    {
        let stop = stop.clone();
        let stale = stale.clone();
        let tx_found = tx_found.clone();

        scope.spawn(move || {
            while !stop.load(Ordering::Relaxed) {
                std::thread::sleep(std::time::Duration::from_millis(200));

                let cur_tip = get_tip(db).ok().flatten().unwrap_or([0u8; 32]);

if cur_tip != parent_tip {
    mine_log_event(
        "candidate_stale_before_solution",
        height,
        None,
        &format!(
            "old_prev=0x{} new_tip=0x{}",
            hex::encode(parent_tip),
            hex::encode(cur_tip)
        ),
    );

    stale.store(true, Ordering::Relaxed);
    stop.store(true, Ordering::Relaxed);

    if tx_found.send(MineMsg::Stale).is_err() {
        return;
    }
    return;
}

            }
        });
    }

    // The time is chosen with the watcher running, so a wait on a parent stamped beyond
    // `miner_block_time`'s bound ends when the tip moves.
    let Some(time) = choose_block_time(db, &parent_tip, parent_hi_opt.as_ref(), &stale) else {
        stop.store(true, Ordering::Relaxed);
        return Err(anyhow!("stale template"));
    };
    hdr.time = time;

println!(
    "[mine] enter: height={} prev=0x{} bits=0x{:08x} time={}",
    height,
    hex::encode(hdr.prev),
    hdr.bits,
    hdr.time
);

mine_log_event(
    "pow_search_started",
    height,
    None,
    &format!(
        "prev=0x{} bits=0x{:08x} time={} workers={}",
        hex::encode(hdr.prev),
        hdr.bits,
        hdr.time,
        miner_thread_count()
    ),
);

    for worker_id in 0..workers {

        let stop = stop.clone();
        let tx_found = tx_found.clone();

let stale = stale.clone();
let hash_counter = hash_counter.clone();

let parent_hi_for_worker = parent_hi_opt.clone();
let mut whdr = hdr.clone();

let mut wtxs = txs.clone();

// Give each worker a unique coinbase script_sig.
// This changes coinbase txid -> merkle -> header search space.
wtxs[0].inputs[0].script_sig.push(0x00);
wtxs[0]
    .inputs[0]
    .script_sig
    .extend_from_slice(format!("worker:{worker_id}").as_bytes());

whdr.merkle = merkle_root(&wtxs);

let base_script_sig = wtxs[0].inputs[0].script_sig.clone();


        // Split nonce space across workers.
        whdr.nonce = worker_id as u32;
        let step = workers as u32;
let pow_target = pow_target;

scope.spawn(move || {
    // Deprioritize PoW grind threads (SCHED_IDLE) so networking/apply threads (normal priority) always
    // preempt them -- mine on every core without starving block-apply. Best-effort; ignored on failure.
    #[cfg(target_os = "linux")]
    unsafe {
        let p = libc::sched_param { sched_priority: 0 };
        let _ = libc::sched_setscheduler(0, libc::SCHED_IDLE, &p);
    }
    #[allow(unused_assignments)]
    let mut checks: u64 = 0;
    let mut extra_nonce: u64 = 0;

    loop {
if stop.load(Ordering::Relaxed) || stale.load(Ordering::Relaxed) {
    if checks > 0 {
        hash_counter.fetch_add(checks, Ordering::Relaxed);
    }
    return;
}

        let h = header_hash(&whdr);

if pow_target.check(&h) {

    if checks > 0 {
        hash_counter.fetch_add(checks, Ordering::Relaxed);
    }

    stop.store(true, Ordering::Relaxed);

mine_log_event(
    "pow_solution_found",
    height,
    Some(&h),
    &format!(
        "prev=0x{} bits=0x{:08x} time={} nonce={} worker_id={}",
        hex::encode(whdr.prev),
        whdr.bits,
        whdr.time,
        whdr.nonce,
        worker_id
    ),
);

    let block = Block {
                header: whdr.clone(),
                txs: wtxs.clone(),
            };

if tx_found.send(MineMsg::Found(h, block)).is_err() {
    return;
}
            return;
        }

        let old_nonce = whdr.nonce;
        whdr.nonce = whdr.nonce.wrapping_add(step);

if whdr.nonce < old_nonce {
    extra_nonce = extra_nonce.wrapping_add(1);

    whdr.time = match choose_block_time(db, &parent_tip, parent_hi_for_worker.as_ref(), &stale) {
        Some(t) => t,
        None => return,
    };

    let marker = extra_nonce.to_le_bytes();

    wtxs[0].inputs[0].script_sig = base_script_sig.clone();
    wtxs[0].inputs[0].script_sig.push(0x00);
    wtxs[0]
        .inputs[0]
        .script_sig
        .extend_from_slice(&marker);

    whdr.merkle = merkle_root(&wtxs);
    whdr.nonce = worker_id as u32;
}

        checks = checks.wrapping_add(1);

if checks >= HASH_COUNTER_FLUSH_EVERY_NONCES {
    hash_counter.fetch_add(checks, Ordering::Relaxed);
    checks = 0;
}

    }
});
}

// -------------------------------------------------------------------------
// Optional GPU worker. Compiled in when --features cuda and enabled when
// CSD_GPU env var is set (1/true/yes/on). It runs alongside the CPU workers
// inside the same thread::scope and uses the same MineMsg channel.
// -------------------------------------------------------------------------
#[cfg(feature = "cuda")]
{
    if crate::gpu::enabled_via_env() && crate::gpu::ensure_initialized().is_ok() {
        let stop          = stop.clone();
        let stale         = stale.clone();
        let hash_counter  = hash_counter.clone();
        let tx_found      = tx_found.clone();
        let parent_hi_for_worker = parent_hi_opt.clone();
        let parent_tip_for_worker = parent_tip;
        let pow_target_for_worker = pow_target;

        let mut whdr_gpu = hdr.clone();
        let mut wtxs_gpu = txs.clone();

        // Give the GPU worker its own coinbase script_sig so its merkle is
        // unique from CPU workers (mirrors the CPU worker pattern above).
        wtxs_gpu[0].inputs[0].script_sig.push(0x00);
        wtxs_gpu[0]
            .inputs[0]
            .script_sig
            .extend_from_slice(b"worker:gpu");
        whdr_gpu.merkle = merkle_root(&wtxs_gpu);
        let base_script_sig_gpu = wtxs_gpu[0].inputs[0].script_sig.clone();

        let target_be = crate::chain::pow::bits_to_target_bytes(whdr_gpu.bits);

        scope.spawn(move || {
            // ~96M hashes per batch on a 2080 (~43 ms). Short enough that
            // stop/stale signals get checked promptly.
            const NONCES_PER_THREAD: u32 = 256;

            let (n_threads, hashes_per_batch) =
                match crate::gpu::with_global(|m| (m.n_threads(), m.hashes_per_batch(NONCES_PER_THREAD))) {
                    Some(v) => v,
                    None => {
                        eprintln!("[gpu] worker: global miner not available, exiting");
                        return;
                    }
                };
            let batch_nonce_span: u32 = n_threads.saturating_mul(NONCES_PER_THREAD);

            let (mut midstate, mut block2_pre) =
                crate::gpu::header_to_gpu_params(&whdr_gpu);
            let mut nonce_base: u32 = 0;
            let mut extra_nonce: u64 = 0;

            println!(
                "[gpu] worker started: {} threads, {} nonces/thread => {} hashes/batch (~{} batches per nonce-space wrap)",
                n_threads,
                NONCES_PER_THREAD,
                hashes_per_batch,
                (u64::from(u32::MAX) / u64::from(batch_nonce_span).max(1)).max(1),
            );

            loop {
                if stop.load(Ordering::Relaxed) || stale.load(Ordering::Relaxed) {
                    return;
                }

                let result = crate::gpu::with_global(|m| {
                    m.search_batch(
                        &midstate,
                        &block2_pre,
                        &target_be,
                        nonce_base,
                        NONCES_PER_THREAD,
                    )
                });

                let hit = match result {
                    Some(Ok(r)) => r,
                    Some(Err(e)) => {
                        eprintln!("[gpu] search_batch failed: {e}");
                        return;
                    }
                    None => {
                        eprintln!("[gpu] global miner disappeared mid-run");
                        return;
                    }
                };

                hash_counter.fetch_add(hashes_per_batch, Ordering::Relaxed);

                if let Some((winning_nonce, _gpu_hash_be)) = hit {
                    whdr_gpu.nonce = winning_nonce;
                    let h = header_hash(&whdr_gpu);
                    if !pow_target_for_worker.check(&h) {
                        // GPU claimed a hit that the host doesn't agree with.
                        // This should never happen with a correct kernel but
                        // we defensively skip and keep searching.
                        eprintln!(
                            "[gpu] WARN: GPU hit failed host PoW check (nonce={}, extra_nonce={}); skipping batch",
                            winning_nonce, extra_nonce,
                        );
                        match nonce_base.checked_add(batch_nonce_span) {
                            Some(b) => nonce_base = b,
                            None => nonce_base = 0,
                        }
                        continue;
                    }

                    stop.store(true, Ordering::Relaxed);

                    mine_log_event(
                        "pow_solution_found",
                        height,
                        Some(&h),
                        &format!(
                            "prev=0x{} bits=0x{:08x} time={} nonce={} worker_id=gpu",
                            hex::encode(whdr_gpu.prev),
                            whdr_gpu.bits,
                            whdr_gpu.time,
                            whdr_gpu.nonce,
                        ),
                    );

                    let block = Block {
                        header: whdr_gpu.clone(),
                        txs: wtxs_gpu.clone(),
                    };
                    let _ = tx_found.send(MineMsg::Found(h, block));
                    return;
                }

                // Advance nonce. On u32 wrap, rotate the extra_nonce and
                // refresh midstate/merkle exactly like the CPU workers do.
                match nonce_base.checked_add(batch_nonce_span) {
                    Some(b) => nonce_base = b,
                    None => {
                        extra_nonce = extra_nonce.wrapping_add(1);
                        whdr_gpu.time = match choose_block_time(
                            db,
                            &parent_tip_for_worker,
                            parent_hi_for_worker.as_ref(),
                            &stale,
                        ) {
                            Some(t) => t,
                            None => return,
                        };
                        let marker = extra_nonce.to_le_bytes();
                        wtxs_gpu[0].inputs[0].script_sig = base_script_sig_gpu.clone();
                        wtxs_gpu[0].inputs[0].script_sig.push(0x00);
                        wtxs_gpu[0]
                            .inputs[0]
                            .script_sig
                            .extend_from_slice(&marker);
                        whdr_gpu.merkle = merkle_root(&wtxs_gpu);
                        let (m, p) = crate::gpu::header_to_gpu_params(&whdr_gpu);
                        midstate = m;
                        block2_pre = p;
                        nonce_base = 0;
                    }
                }
            }
        });
    } else if crate::gpu::enabled_via_env() {
        eprintln!("[gpu] CSD_GPU=1 set but GPU init failed; mining CPU-only this block");
    }
}

    drop(tx_found);

    match rx_found.recv() {
        Ok(MineMsg::Stale) => Err(anyhow!("stale template")),

Ok(MineMsg::Found(h, block)) => {
    let solved_hdr = block.header.clone();
    #[cfg(feature = "test-bypass")]
    TEST_SOLVED_PARENTS.lock().unwrap().push(solved_hdr.prev);

let solved_at = Instant::now();

mine_log_event(
    "solution_received",
    height,
    Some(&h),
    &format!(
        "prev=0x{} txs={}",
        hex::encode(block.header.prev),
        block.txs.len()
    ),
);

if header_hash(&solved_hdr) != h {
    return Err(anyhow!("solved block hash/header mismatch"));
}

if solved_hdr.merkle != merkle_root(&block.txs) {
    return Err(anyhow!("solved block merkle mismatch"));
}

if !pow_target.check(&h) {
    return Err(anyhow!("solved block failed local pow check"));
}

            let _g = chain_lock.lock();

            let cur_tip = get_tip(db)?.unwrap_or([0u8; 32]);
            if cur_tip != solved_hdr.prev {
                println!(
                    "[mine] solved stale block: solved_prev=0x{} current_tip=0x{}",
                    hex::encode(solved_hdr.prev),
                    hex::encode(cur_tip),
                );
                return Err(anyhow!("solved stale block"));
            }

            let block_bytes = crate::codec::consensus_bincode().serialize(&block)?;

            if block_bytes.len() > MAX_BLOCK_BYTES {
                println!(
                    "[mine] refusing to store oversized block ({} > MAX_BLOCK_BYTES={})",
                    block_bytes.len(),
                    MAX_BLOCK_BYTES
                );
                return Err(anyhow!("oversized block template"));
            }

            db.blocks.insert(k_block(&h), block_bytes)?;

mine_log_event(
    "block_stored",
    height,
    Some(&h),
    &format!(
        "elapsed_ms={}",
        solved_at.elapsed().as_millis()
    ),
);

            let _hi = index_header(db, &solved_hdr, parent_hi_opt.as_ref())?;

mine_log_event(
    "block_indexed",
    height,
    Some(&h),
    &format!(
        "chainwork={} elapsed_ms={}",
        _hi.chainwork,
        solved_at.elapsed().as_millis()
    ),
);

            db.db.flush()?;

            if let Err(e) = maybe_reorg_to(db, &h, Some(mempool)) {
                println!("[mine] maybe_reorg_to failed for {}: {}", hex::encode(h), e);
                return Err(e);
            }

            let tip_after = get_tip(db)?.unwrap_or([0u8; 32]);
            let accepted_as_tip = tip_after == h;

if accepted_as_tip {
    mine_log_event(
        "block_accepted_canonical",
        height,
        Some(&h),
        &format!(
            "tip_after=0x{} elapsed_ms={}",
            hex::encode(tip_after),
            solved_at.elapsed().as_millis()
        ),
    );

                let removed = mempool.remove_mined_block(&block);

                if removed > 0 {
                    println!(
                        "[mempool] removed {} mined/conflicting txs after accepted block (mempool_len={}, spent_outpoints={})",
                        removed,
                        mempool.len(),
                        mempool.spent_len()
                    );
                }
            } else {

    mine_log_event(
        "block_orphaned",
        height,
        Some(&h),
        &format!(
            "tip_after=0x{} elapsed_ms={} included_mempool_txs={}",
            hex::encode(tip_after),
            solved_at.elapsed().as_millis(),
            included_ids.len()
        ),
    );

                println!(
                    "[mine] orphaned local win: 0x{} (tip_after=0x{})",
                    hex::encode(h),
                    hex::encode(tip_after),
                );
                println!(
                    "[mine] block {} was not selected as tip (tip_after={}); keeping {} txs in mempool",
                    hex::encode(h),
                    hex::encode(tip_after),
                    included_ids.len()
                );
            }

            let pruned = mempool.prune(db);
            if pruned > 0 {
                println!(
                    "[mempool] pruned {} txs after mining (mempool_len={}, spent_outpoints={})",
                    pruned,
                    mempool.len(),
                    mempool.spent_outpoints().len()
                );
            }

            Ok(h)
        }
        Err(_) => Err(anyhow!("miner workers exited without result")),
    }
})
}

// The miner's stamp on a parent stamped ahead of the wall clock.
#[cfg(test)]
mod block_time_tests {
    use super::*;

    const NOW: u64 = 1_800_000_000;
    const BOUND: u64 = MAX_FUTURE_DRIFT_SECS - MINER_CLOCK_SKEW_MARGIN_SECS;

    // Honest path: a parent in the past, or the earliest valid time already reached, stamps the
    // wall clock, as upstream's miner does.
    #[test]
    fn a_parent_in_the_past_stamps_the_wall_clock() {
        assert_eq!(miner_block_time(NOW, NOW - 300), Ok(NOW));
        assert_eq!(miner_block_time(NOW, NOW), Ok(NOW));
    }

    // The earliest valid time ahead of the clock but within the bound is stamped at once, with no
    // wait: 30 s ahead (a parent found 30 s ago) and 6,560 s ahead (a parent stamped 6,500 s ahead).
    // Upstream's miner waits until the clock reaches it.
    #[test]
    fn an_earliest_time_within_the_bound_is_stamped_at_once() {
        assert_eq!(miner_block_time(NOW, NOW + 30), Ok(NOW + 30));
        assert_eq!(miner_block_time(NOW, NOW + 6_560), Ok(NOW + 6_560));
        assert_eq!(miner_block_time(NOW, NOW + BOUND), Ok(NOW + BOUND));
    }

    // A parent at the consensus limit (now + MAX_FUTURE_DRIFT_SECS) waits the margin plus the
    // spacing, 660 s, not the two hours until the clock passes it.
    #[test]
    fn a_parent_at_the_drift_limit_waits_the_margin_plus_the_spacing() {
        let min_ok = NOW + MAX_FUTURE_DRIFT_SECS + MIN_BLOCK_SPACING_SECS;
        let wait = MINER_CLOCK_SKEW_MARGIN_SECS + MIN_BLOCK_SPACING_SECS;
        assert_eq!(miner_block_time(NOW, min_ok), Err(wait));
        assert_eq!(miner_block_time(NOW + wait, min_ok), Ok(min_ok));
    }

    // Every stamp is accepted by a receiver whose clock is MINER_CLOCK_SKEW_MARGIN_SECS behind ours
    // (index_header refuses only a stamp past its own now + MAX_FUTURE_DRIFT_SECS) and is at least
    // the earliest valid time.
    #[test]
    fn every_stamp_is_valid_for_a_receiver_whose_clock_is_the_margin_behind() {
        let receiver_now = NOW - MINER_CLOCK_SKEW_MARGIN_SECS;
        for min_ok in [NOW - 1, NOW, NOW + 1, NOW + 3_600, NOW + BOUND] {
            let stamp = miner_block_time(NOW, min_ok).unwrap();
            assert!(stamp >= min_ok && stamp <= receiver_now + MAX_FUTURE_DRIFT_SECS, "min_ok {min_ok}");
        }
    }
}

// ── tests: template path ──
// A poison that bypassed admission (a mempool carried over from a build without the app-state
// gate, or a refeed) must be excluded at template build, because the selection re-runs
// validate_tx_for_mempool (app-state-aware) on every candidate. These tests plant a poison
// directly in the mempool (test-only seam) and prove the template excludes it, and pin the
// template byte cap below the transport cap.
#[cfg(test)]
mod template_tests {
    use super::*;
    use crate::chain::index::{put_hidx, HeaderIndex};
    use crate::crypto::{hash160, sign_tx_compact_secp256k1, txid};
    use crate::params::{COIN, MIN_FEE_PROPOSE};
    use crate::state::db::{put_utxo, put_utxo_meta, set_tip, UtxoMeta};
    use crate::types::{AppPayload, OutPoint, Transaction, TxIn, TxOut};
    use tempfile::TempDir;

    const SK: [u8; 32] = [7u8; 32];
    const START_TIME: u64 = 1_702_000_000;

    fn signer_addr() -> [u8; 20] {
        let dummy = Transaction {
            version: 1,
            inputs: vec![TxIn { prevout: OutPoint { txid: [0u8; 32], vout: 0 }, script_sig: vec![] }],
            outputs: vec![TxOut { value: 1, script_pubkey: [0u8; 20] }],
            locktime: 0,
            app: AppPayload::None,
        };
        let (_sig, pub33) = sign_tx_compact_secp256k1(&dummy, SK);
        hash160(&pub33)
    }

    fn sign(mut tx: Transaction) -> Transaction {
        let (sig64, pub33) = sign_tx_compact_secp256k1(&tx, SK);
        let mut ss = Vec::with_capacity(99);
        ss.push(64);
        ss.extend_from_slice(&sig64);
        ss.push(33);
        ss.extend_from_slice(&pub33);
        for inp in &mut tx.inputs {
            inp.script_sig = ss.clone();
        }
        tx
    }

    fn open_db() -> (TempDir, Stores) {
        let tmp = TempDir::new().unwrap();
        let db = Stores::open(tmp.path().to_str().unwrap()).unwrap();
        (tmp, db)
    }

    fn insert_utxo(db: &Stores, op: OutPoint, value: u64, owner: [u8; 20]) {
        put_utxo(db, &op, &TxOut { value, script_pubkey: owner }).unwrap();
        put_utxo_meta(db, &op, &UtxoMeta { height: 1, coinbase: false }).unwrap();
    }

    // Fabricate a canonical tip at `height` so the app-state gate reads the intended epoch.
    fn set_tip_at_height(db: &Stores, height: u64) {
        let mut hash = [0u8; 32];
        hash[0..8].copy_from_slice(&height.to_le_bytes());
        hash[31] = 0xFF;
        let hi = HeaderIndex { hash, parent: [0u8; 32], height, chainwork: 0, bits: 0, time: START_TIME };
        put_hidx(db, &hi).unwrap();
        set_tip(db, &hash).unwrap();
    }

    fn propose_tx(op: OutPoint, owner: [u8; 20], expires_epoch: u64) -> Transaction {
        sign(Transaction {
            version: 1,
            inputs: vec![TxIn { prevout: op, script_sig: vec![0u8; 99] }],
            outputs: vec![TxOut { value: COIN - MIN_FEE_PROPOSE, script_pubkey: owner }],
            locktime: 0,
            app: AppPayload::Propose {
                domain: "test-domain".to_string(),
                payload_hash: [0x66; 32],
                uri: "https://example.com/x".to_string(),
                expires_epoch,
            },
        })
    }

    #[test]
    fn template_excludes_app_state_poison() {
        // Tip at height 60 → the next block is in epoch 2 (30 blocks/epoch).
        let (_tmp, db) = open_db();
        set_tip_at_height(&db, 60);
        let owner = signer_addr();
        let good_op = OutPoint { txid: [0xA1; 32], vout: 0 };
        let poison_op = OutPoint { txid: [0xA2; 32], vout: 0 };
        insert_utxo(&db, good_op, COIN, owner);
        insert_utxo(&db, poison_op, COIN, owner);
        let good = propose_tx(good_op, owner, 10); // expires epoch 10 ≥ current 2: valid
        let poison = propose_tx(poison_op, owner, 1); // expires epoch 1 < current 2: poison

        // Plant both directly in the mempool, bypassing admission (admission would have refused
        // the poison): this simulates a mempool carried over from a build without the gate, or a
        // refeed, the "poisoned mempool -> template" state.
        let mp = Mempool::new();
        let poison_id = mp.force_insert_for_test(poison.clone(), 1000);
        let good_id = mp.force_insert_for_test(good.clone(), 500);

        let (_txs, ids, _fees) = build_template_for_tests(&db, &mp, [0x99; 20], 61, 100, 1_000_000)
            .expect("template builds");
        assert!(ids.contains(&good_id), "the valid tx is templated");
        assert!(
            !ids.contains(&poison_id),
            "RT-N1: an app-state poison in the mempool is EXCLUDED at template build"
        );
    }

    #[test]
    fn template_byte_cap_is_belted_below_the_transport_cap() {
        // Every block we template must stay fetchable by every node (the 1 MiB request-response
        // cap, upstream's too): the cap sits below it with envelope room, and strictly below the
        // consensus cap (otherwise the belt is decorative). The full Block answer is pinned in
        // net::node::sync_transport_cap_tests.
        assert!(template_byte_cap() <= 1024 * 1024);
        assert!(template_byte_cap() < MAX_BLOCK_BYTES);
    }
}
