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
    block_reward, MAX_BLOCK_BYTES, MAX_FUTURE_DRIFT_SECS, MAX_TX_BYTES, MIN_BLOCK_SPACING_SECS,
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
fn merkle_root_txids(txids: &[[u8; 32]]) -> [u8; 32] {
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
pub fn coinbase(miner_h160: Hash20, value: u64, height: u64) -> Transaction {
    let script_sig = height.to_le_bytes().to_vec();
    let locktime = height as u32;

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

/// Build a fresh block template from the current tip + current UTXO set.
///
/// Key behavior:
/// - Candidates come from mempool.sample() (highest feerate first, deterministic).
/// - Each tx must still validate against *current* UTXO set (reorg-safe).
/// - Enforces MAX_BLOCK_BYTES by tracking serialized bytes.
/// - Defense-in-depth: refuses any tx > MAX_TX_BYTES even if it somehow got into mempool.
/// - Avoids intra-block input conflicts defensively.
fn build_template(
    db: &Stores,
    mempool: &Mempool,
    miner_h160: Hash20,
    height: u64,
    max_mempool_txs: usize,
) -> Result<(Vec<Transaction>, Vec<Hash32>, u64, usize)> {
    let c = crate::codec::consensus_bincode();

    let reward = block_reward(height);

    // Pull more than we need so we can skip invalid/non-connectable/oversize/conflicting txs.
    const CANDIDATE_MULT: usize = 8;
    let want_candidates = max_mempool_txs
        .saturating_mul(CANDIDATE_MULT)
        .max(max_mempool_txs);

    let sampled = mempool.sample(want_candidates);

    // We enforce block bytes budget. Start with coinbase (added later) as unknown size.
    // We'll compute coinbase size once we know total fees.
    let mut included: Vec<Transaction> = Vec::with_capacity(max_mempool_txs);
    let mut included_ids: Vec<Hash32> = Vec::with_capacity(max_mempool_txs);

    // Defensive anti-conflict set (mempool policy should already prevent conflicts).
    let mut spent_in_block: std::collections::HashSet<OutPoint> = std::collections::HashSet::new();

    let mut total_fees: u64 = 0;
    let mut tx_bytes_total: usize = 0;

    let mut skipped_invalid: usize = 0;
    let mut skipped_oversize: usize = 0;
    let mut skipped_conflict: usize = 0;
    let mut skipped_budget: usize = 0;

    for tx in sampled {
        if included.len() >= max_mempool_txs {
            break;
        }

        // Must remain valid/connectable right now.
        if validate_tx_for_mempool(db, &tx).is_err() {
            skipped_invalid += 1;
            continue;
        }

        // Defense-in-depth on tx size.
        let tx_sz_u64 = match c.serialized_size(&tx) {
            Ok(n) => n,
            Err(_) => {
                skipped_invalid += 1;
                continue;
            }
        };
        if tx_sz_u64 > (MAX_TX_BYTES as u64) {
            skipped_oversize += 1;
            continue;
        }
        let tx_sz = tx_sz_u64 as usize;

        // Defensive intra-block conflict check.
        let mut conflict = false;
        for inp in &tx.inputs {
            if spent_in_block.contains(&inp.prevout) {
                conflict = true;
                break;
            }
        }
        if conflict {
            skipped_conflict += 1;
            continue;
        }

        // Compute fee from current UTXO set (deterministic).
        let fee = match compute_fee_from_utxos(db, &tx) {
            Ok(f) => f,
            Err(_) => {
                skipped_invalid += 1;
                continue;
            }
        };

        // Tentatively include; enforce block byte budget later after coinbase is known.
        // But we can still do a conservative pre-check: if tx alone already exceeds MAX_BLOCK_BYTES, skip.
        if tx_sz > MAX_BLOCK_BYTES {
            skipped_oversize += 1;
            continue;
        }

        // Track in-block spends.
        for inp in &tx.inputs {
            spent_in_block.insert(inp.prevout);
        }

        // Track totals (coinbase added later).
        total_fees = total_fees
            .checked_add(fee)
            .ok_or_else(|| anyhow!("fee overflow"))?;
        tx_bytes_total = tx_bytes_total.saturating_add(tx_sz);

        included_ids.push(txid(&tx));
        included.push(tx);
    }

    // Now construct coinbase with reward+fees.
    let cb_value = reward
        .checked_add(total_fees)
        .ok_or_else(|| anyhow!("coinbase overflow"))?;
    let cb = coinbase(miner_h160, cb_value, height);

    let cb_sz_u64 = c.serialized_size(&cb)?;
    let cb_sz = cb_sz_u64 as usize;

    // Enforce full block budget (coinbase + included txs).
    // If we're over budget, drop txs from the tail (lowest priority due to sampling order).
    let mut block_bytes = cb_sz.saturating_add(tx_bytes_total);

    while block_bytes > MAX_BLOCK_BYTES && !included.is_empty() {
        // Drop last tx.
        let dropped = included.pop().unwrap();
        let dropped_id = included_ids.pop().unwrap_or_else(|| txid(&dropped));

        // Recompute size and fee impact for the dropped tx.
        let d_sz = c.serialized_size(&dropped).unwrap_or(0) as usize;
        let d_fee = compute_fee_from_utxos(db, &dropped).unwrap_or(0);

        // Adjust totals.
        tx_bytes_total = tx_bytes_total.saturating_sub(d_sz);
        total_fees = total_fees.saturating_sub(d_fee);

        // Rebuild coinbase value (reward+fees) and size since fees changed.
        let cb_value2 = reward
            .checked_add(total_fees)
            .ok_or_else(|| anyhow!("coinbase overflow (rebuild)"))?;
        let cb2 = coinbase(miner_h160, cb_value2, height);
        let cb2_sz = c.serialized_size(&cb2).unwrap_or(cb_sz_u64) as usize;

        block_bytes = cb2_sz.saturating_add(tx_bytes_total);

        // Track why we dropped.
        let _ = dropped_id;
        skipped_budget += 1;
    }

    // Final coinbase after any tail drops.
    let cb_value_final = reward
        .checked_add(total_fees)
        .ok_or_else(|| anyhow!("coinbase overflow (final)"))?;
    let cb_final = coinbase(miner_h160, cb_value_final, height);

    let cb_final_sz = c.serialized_size(&cb_final)? as usize;
    let final_block_bytes = cb_final_sz.saturating_add(tx_bytes_total);

    println!(
        "[mine] template: height={} mempool_len={} sampled={} included={} fees={} block_bytes={} (max={}) skipped_invalid={} skipped_oversize={} skipped_conflict={} dropped_for_budget={}",
        height,
        mempool.len(),
        want_candidates.min(mempool.len()),
        included.len(),
        total_fees,
        final_block_bytes,
        MAX_BLOCK_BYTES,
        skipped_invalid,
        skipped_oversize,
        skipped_conflict,
        skipped_budget,
    );

    let mut final_txs: Vec<Transaction> = Vec::with_capacity(1 + included.len());
    final_txs.push(cb_final);
    final_txs.extend(included);

    Ok((final_txs, included_ids, total_fees, final_block_bytes))
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

    let (mut txs, _included_ids, _fees, _blk_bytes) =
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

            // Final defense: ensure stored bytes do not exceed MAX_BLOCK_BYTES.
            let bytes = crate::codec::consensus_bincode().serialize(&block)?;
            if bytes.len() > MAX_BLOCK_BYTES {
                // Should never happen because template enforces budget,
                // but keep this guard to avoid DB poisoning.
                println!(
                    "[mine] refusing to store oversized mined block ({} bytes > MAX_BLOCK_BYTES={})",
                    bytes.len(),
                    MAX_BLOCK_BYTES
                );
                // Rebuild template and keep mining.
                let built = build_template(db, mempool, miner_h160, height, max_mempool_txs)?;
                txs = built.0;
                hdr.merkle = merkle_root(&txs);
                hdr.nonce = 0;
                continue;
            }

            db.blocks.insert(k_block(&h), bytes)?;

            let _hi = index_header(db, &hdr, parent_hi_opt.as_ref())?;

            // This is where apply/undo/tip happens (and mined txs are removed from mempool).
            if let Err(e) = maybe_reorg_to(db, &h, Some(mempool)) {
                println!("[mine] maybe_reorg_to failed for {}: {}", hex::encode(h), e);
                continue;
            }

            let tip_after = get_tip(db)?.unwrap_or([0u8; 32]);
            let accepted_as_tip = tip_after == h;

            // No manual mempool removals here.
            // maybe_reorg_to(..., Some(mempool)) is the canonical place for mined removal,
            // and it also handles reorg outcomes correctly.

            let pruned = mempool.prune(db);
            if pruned > 0 {
                println!(
                    "[mempool] pruned {} txs after mining (mempool_len={}, spent_outpoints={})",
                    pruned,
                    mempool.len(),
                    mempool.spent_len()
                );
            }

            println!(
                "[mine] new block 0x{} (accepted_as_tip={}, txs_in_block={}, mempool_len={}, spent_outpoints={})",
                hex::encode(h),
                accepted_as_tip,
                block.txs.len(),
                mempool.len(),
                mempool.spent_len(),
            );

            return Ok(h);
        }

        hdr.nonce = hdr.nonce.wrapping_add(1);

        // If nonce wrapped, bump time *within objective bounds* (no wall-clock).
        if hdr.nonce == 0 {
            if let Some(p) = parent_hi_opt.as_ref() {
                let mtp = median_time_past(db, &p.hash).unwrap_or(p.time);
                let max_allowed = mtp.saturating_add(MAX_FUTURE_DRIFT_SECS);

                // increment by 1, but clamp
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
