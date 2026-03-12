// src/chain/mine.rs
use anyhow::{anyhow, Result};

use crate::chain::index::{get_hidx, header_hash, index_header, HeaderIndex};
use crate::chain::lock::ChainLock;
use crate::chain::pow::{expected_bits, pow_ok};
use crate::chain::reorg::maybe_reorg_to;
use crate::chain::time::median_time_past;
use crate::crypto::{sha256d, txid};
use crate::net::mempool::Mempool;
use crate::params::{
    block_reward, MAX_BLOCK_BYTES, MAX_FUTURE_DRIFT_SECS, MIN_BLOCK_SPACING_SECS,
};
use crate::state::app::current_epoch;
use crate::state::db::{get_tip, get_utxo, k_block, Stores};
use crate::state::utxo::validate_tx_for_mempool;
use crate::types::{
    AppPayload, Block, BlockHeader, Hash20, Hash32, OutPoint, Transaction, TxIn, TxOut,
};

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

/// Choose a block time that *matches the objective consensus rules* in index_header:
/// - time >= parent.time + MIN_BLOCK_SPACING_SECS
/// - time > MTP(parent)
/// - time <= MTP(parent) + MAX_FUTURE_DRIFT_SECS
///
/// IMPORTANT: do not use wall-clock time here, or you'll diverge from objective rules.
fn choose_block_time(db: &Stores, parent_tip: &Hash32, parent_hi: Option<&HeaderIndex>) -> u64 {
    // Genesis mining case (should basically never happen here).
    if *parent_tip == [0u8; 32] || parent_hi.is_none() {
        return 0;
    }

    let p = parent_hi.unwrap();

    let min_spacing = p.time.saturating_add(MIN_BLOCK_SPACING_SECS);

    let mtp = median_time_past(db, &p.hash).unwrap_or(p.time);
    let mtp_time = mtp.saturating_add(1);

    let max_allowed = mtp.saturating_add(MAX_FUTURE_DRIFT_SECS);

    // pick the earliest valid time; keep deterministic
    let t = min_spacing.max(mtp_time);

    // Clamp into allowed window. If clamping would violate >MTP, just use mtp+1.
    let t = t.min(max_allowed);
    if t <= mtp {
        mtp_time
    } else {
        t
    }
}

/// Build a fresh block template from the current tip + current UTXO set.
///
/// Key behavior:
/// - Only includes txs that are valid AND connectable *right now*
/// - Skips anything that fails validate_tx_for_mempool or has missing inputs
/// - Sorts by fee (desc) so miners converge under load
/// - NEW: also respects MAX_BLOCK_BYTES (consensus) so we never build an unmineable block

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

    let cb_placeholder = coinbase(miner_h160, reward, height, None);
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
    let cb = coinbase(miner_h160, cb_value, height, None);

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
    const TIP_CHECK_EVERY_NONCES: u64 = 4096;

    let mut parent_tip: Hash32 = get_tip(db)?.unwrap_or([0u8; 32]);
    let mut parent_hi_opt = if parent_tip != [0u8; 32] {
        get_hidx(db, &parent_tip)?
    } else {
        None
    };

    let mut height = parent_hi_opt.as_ref().map(|h| h.height + 1).unwrap_or(0);
    let mut _epoch = current_epoch(height);

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

    let mut n_since_check: u64 = 0;

    println!(
        "[mine] enter: height={} prev=0x{} bits=0x{:08x} time={}",
        height,
        hex::encode(hdr.prev),
        hdr.bits,
        hdr.time
    );

    loop {
        n_since_check = n_since_check.wrapping_add(1);

        if n_since_check % TIP_CHECK_EVERY_NONCES == 0 {
            std::thread::yield_now();
        }

        if n_since_check >= TIP_CHECK_EVERY_NONCES {
            n_since_check = 0;

            let cur_tip = get_tip(db)?.unwrap_or([0u8; 32]);
            if cur_tip != [0u8; 32] && cur_tip != hdr.prev {
                parent_tip = cur_tip;
                parent_hi_opt = if parent_tip != [0u8; 32] {
                    get_hidx(db, &parent_tip)?
                } else {
                    None
                };

                height = parent_hi_opt.as_ref().map(|h| h.height + 1).unwrap_or(0);
                _epoch = current_epoch(height);

                let built = build_template(db, mempool, miner_h160, height, max_mempool_txs)?;
                txs = built.0;
                included_ids = built.1;

                hdr = BlockHeader {
                    version: 1,
                    prev: parent_tip,
                    merkle: merkle_root(&txs),
                    time: choose_block_time(db, &parent_tip, parent_hi_opt.as_ref()),
                    bits: expected_bits(db, height, parent_hi_opt.as_ref())?,
                    nonce: 0u32,
                };

                println!(
                    "[mine] rebase: height={} prev=0x{} bits=0x{:08x} time={}",
                    height,
                    hex::encode(hdr.prev),
                    hdr.bits,
                    hdr.time
                );
            }
        }

        let h = header_hash(&hdr);

        if pow_ok(&h, hdr.bits) {
            let _g = chain_lock.lock();

            let cur_tip = get_tip(db)?.unwrap_or([0u8; 32]);
            if cur_tip != hdr.prev {
                continue;
            }

            let block = Block {
                header: hdr.clone(),
                txs: txs.clone(),
            };

            let block_bytes = crate::codec::consensus_bincode().serialize(&block)?;
            if block_bytes.len() > MAX_BLOCK_BYTES {
                // This *should* be rare now that template packing respects MAX_BLOCK_BYTES,
                // but keep the guard in case encoding overhead changes.
                println!(
                    "[mine] refusing to store oversized block ({} > MAX_BLOCK_BYTES={})",
                    block_bytes.len(),
                    MAX_BLOCK_BYTES
                );
                // Force template rebuild on next loop iteration.
                parent_tip = get_tip(db)?.unwrap_or([0u8; 32]);
                parent_hi_opt = if parent_tip != [0u8; 32] { get_hidx(db, &parent_tip)? } else { None };
                height = parent_hi_opt.as_ref().map(|h| h.height + 1).unwrap_or(0);
                let built = build_template(db, mempool, miner_h160, height, max_mempool_txs)?;
                txs = built.0;
                included_ids = built.1;
                hdr = BlockHeader {
                    version: 1,
                    prev: parent_tip,
                    merkle: merkle_root(&txs),
                    time: choose_block_time(db, &parent_tip, parent_hi_opt.as_ref()),
                    bits: expected_bits(db, height, parent_hi_opt.as_ref())?,
                    nonce: 0u32,
                };
                continue;
            }

            db.blocks.insert(k_block(&h), block_bytes)?;

            let _hi = index_header(db, &hdr, parent_hi_opt.as_ref())?;

            db.db.flush()?;
            
            if let Err(e) = maybe_reorg_to(db, &h, Some(mempool)) {
                println!("[mine] maybe_reorg_to failed for {}: {}", hex::encode(h), e);
                continue;
            }

            let tip_after = get_tip(db)?.unwrap_or([0u8; 32]);
            let accepted_as_tip = tip_after == h;

            if accepted_as_tip {
                for id in &included_ids {
                    mempool.remove(id);
                }
            } else {
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

            return Ok(h);
        }

        hdr.nonce = hdr.nonce.wrapping_add(1);

        // If nonce wrapped, bump time *within objective bounds* (no wall-clock).
        if hdr.nonce == 0 {
            if let Some(p) = parent_hi_opt.as_ref() {
                let mtp = median_time_past(db, &p.hash).unwrap_or(p.time);
                let max_allowed = mtp.saturating_add(MAX_FUTURE_DRIFT_SECS);

                hdr.time = hdr.time.saturating_add(1);
                if hdr.time > max_allowed {
                    hdr.time = max_allowed;
                }
                if hdr.time <= mtp {
                    hdr.time = mtp.saturating_add(1);
                }
            } else {
                hdr.time = hdr.time.saturating_add(1);
            }
        }
    }
}
