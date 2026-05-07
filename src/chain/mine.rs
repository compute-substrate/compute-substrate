// src/chain/mine.rs
use anyhow::{anyhow, Result};

use crate::chain::index::{get_hidx, header_hash, index_header, HeaderIndex};
use crate::chain::lock::ChainLock;
use crate::chain::pow::{expected_bits, pow_ok};
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

/// Choose a block time that matches the consensus rules in index_header:
/// - time >= parent.time + MIN_BLOCK_SPACING_SECS
/// - time > MTP(parent)
/// - time <= now + MAX_FUTURE_DRIFT_SECS
///
/// This MUST track wall-clock time (clamped), or LWMA will drift the wrong way.
fn choose_block_time(db: &Stores, parent_tip: &Hash32, parent_hi: Option<&HeaderIndex>) -> u64 {
    // Genesis mining case (should basically never happen here).
    if *parent_tip == [0u8; 32] || parent_hi.is_none() {
        return 0;
    }

    let p = parent_hi.unwrap();

    let mtp = median_time_past(db, &p.hash).unwrap_or(p.time);

    // Lower bound: must satisfy spacing and be > MTP
    let min_ok = p.time
        .saturating_add(MIN_BLOCK_SPACING_SECS)
        .max(mtp.saturating_add(1));

    // Upper bound: must not be too far in the future vs wall clock
    let max_ok = now_secs().saturating_add(MAX_FUTURE_DRIFT_SECS);

    // Track reality but stay within consensus bounds
    now_secs().clamp(min_ok, max_ok)
}

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
        MAX_BLOCK_BYTES,
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
    candidates.sort_by(|a, b| match b.0.cmp(&a.0) {
        std::cmp::Ordering::Equal => a.1.cmp(&b.1),
        o => o,
    });

    // Ensure proposals are always included before attests.
    // Without this, attests can reference proposals not yet applied in the same block.
    candidates.sort_by(|a, b| {
        use std::cmp::Ordering;

        let prio = |tx: &Transaction| match &tx.app {
            AppPayload::Propose { .. } => 0u8,
            AppPayload::Attest { .. } => 1u8,
            _ => 2u8,
        };

        match prio(&a.2).cmp(&prio(&b.2)) {
            Ordering::Equal => Ordering::Equal, // keep fee ordering within same class
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

    for (_feerate_ppm, id, tx, fee, tx_bytes_u64) in candidates.into_iter() {
        if included.len() >= max_mempool_txs {
            break;
        }

        let tx_bytes = tx_bytes_u64 as usize;

        if tx_bytes > remaining {
            continue;
        }

        total_fees = total_fees
            .checked_add(fee)
            .ok_or_else(|| anyhow!("fee overflow"))?;

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

#[doc(hidden)]
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

    std::thread::available_parallelism()
        .map(|n| n.get())
        .unwrap_or(1)
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
const TIP_CHECK_EVERY_NONCES: u64 = 4_194_304;

    
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

    let mut hdr = BlockHeader {
        version: 1,
        prev: parent_tip,
        merkle: merkle_root(&txs),
        time: choose_block_time(db, &parent_tip, parent_hi_opt.as_ref()),
        bits: expected_bits(db, height, parent_hi_opt.as_ref())?,
        nonce: 0u32,
    };

println!(
    "[mine] enter: height={} prev=0x{} bits=0x{:08x} time={}",
    height,
    hex::encode(hdr.prev),
    hdr.bits,
    hdr.time
);

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
                std::thread::sleep(std::time::Duration::from_millis(250));

                let cur_tip = get_tip(db).ok().flatten().unwrap_or([0u8; 32]);
                if cur_tip != parent_tip {
                    stale.store(true, Ordering::Relaxed);
                    stop.store(true, Ordering::Relaxed);
                    let _ = tx_found.send(MineMsg::Stale);
                    return;
                }
            }
        });
    }

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

        // Split nonce space across workers.
        whdr.nonce = worker_id as u32;
        let step = workers as u32;

scope.spawn(move || {
    let mut checks: u64 = 0;
    let mut extra_nonce: u64 = 0;

    loop {
        if stop.load(Ordering::Relaxed) || stale.load(Ordering::Relaxed) {
            return;
        }

        let h = header_hash(&whdr);

        if pow_ok(&h, whdr.bits) {
            stop.store(true, Ordering::Relaxed);

            let block = Block {
                header: whdr.clone(),
                txs: wtxs.clone(),
            };

            let _ = tx_found.send(MineMsg::Found(h, block));
            return;
        }

        let old_nonce = whdr.nonce;
        whdr.nonce = whdr.nonce.wrapping_add(step);

        if whdr.nonce < old_nonce {
            extra_nonce = extra_nonce.wrapping_add(1);

            whdr.time = choose_block_time(db, &parent_tip, parent_hi_for_worker.as_ref());

            wtxs[0].inputs[0].script_sig.push(0x00);
            wtxs[0]
                .inputs[0]
                .script_sig
                .extend_from_slice(format!("extra:{extra_nonce}").as_bytes());

            whdr.merkle = merkle_root(&wtxs);
            whdr.nonce = worker_id as u32;
        }

        checks = checks.wrapping_add(1);

        if checks >= TIP_CHECK_EVERY_NONCES {
            checks = 0;
            hash_counter.fetch_add(TIP_CHECK_EVERY_NONCES, Ordering::Relaxed);
        }
    }
});
}
    drop(tx_found);

    match rx_found.recv() {
        Ok(MineMsg::Stale) => Err(anyhow!("stale template")),

Ok(MineMsg::Found(h, block)) => {
    let solved_hdr = block.header.clone();

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

            let _hi = index_header(db, &solved_hdr, parent_hi_opt.as_ref())?;

            db.db.flush()?;

            if let Err(e) = maybe_reorg_to(db, &h, Some(mempool)) {
                println!("[mine] maybe_reorg_to failed for {}: {}", hex::encode(h), e);
                return Err(e);
            }

            let tip_after = get_tip(db)?.unwrap_or([0u8; 32]);
            let accepted_as_tip = tip_after == h;

            if accepted_as_tip {
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
