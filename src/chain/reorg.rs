// src/chain/reorg.rs
use anyhow::{bail, Context, Result};

use crate::chain::failpoints;
use crate::chain::index::{get_hidx, HeaderIndex};
use crate::chain::reorg_journal::{journal_clear, journal_read, journal_write, Phase, ReorgJournal};
use crate::crypto::txid;
use crate::net::mempool::Mempool;
use crate::state::app_state::epoch_of;
use crate::state::db::{get_tip, k_bad, k_block, k_undo, set_tip, Stores};
use crate::state::utxo::{undo_block, validate_and_apply_block};
use crate::types::{Block, Hash32};
use std::collections::HashMap;

fn hex32(h: &Hash32) -> String {
    format!("0x{}", hex::encode(h))
}

fn fmt_opt32(x: Option<Hash32>) -> String {
    match x {
        Some(h) => hex32(&h),
        None => "None".to_string(),
    }
}

fn load_block(db: &Stores, hash: &Hash32) -> Result<Block> {
    let Some(v) = db
        .blocks
        .get(k_block(hash))
        .with_context(|| format!("db.blocks.get({})", hex32(hash)))?
    else {
        bail!("missing block bytes for {}", hex32(hash));
    };


    crate::codec::consensus_bincode()
        .deserialize::<Block>(&v)
        .context("consensus_bincode::deserialize(Block)")
}

fn header_hash_matches_key(bh: &Hash32, blk: &Block) -> bool {
    let hh = crate::chain::index::header_hash(&blk.header);
    &hh == bh
}

fn header_min_valid(bh: &Hash32, blk: &Block) -> bool {
    if !header_hash_matches_key(bh, blk) {
        return false;
    }
    if !crate::chain::pow::bits_within_pow_limit(blk.header.bits) {
        return false;
    }
    // pow_ok honors CSD_BYPASS_POW=1 in tests; otherwise strict.
    if !crate::chain::pow::pow_ok(bh, blk.header.bits) {
        return false;
    }
    true
}

fn is_missing_block_bytes_err(e: &anyhow::Error) -> bool {
    let s = format!("{e:#}");
    s.contains("missing block bytes for 0x")
}

fn is_missing_undo_err(e: &anyhow::Error) -> bool {
    let s = format!("{e:#}");
    s.contains("missing undo")
}

fn hash_from_block_key(k: &[u8]) -> Option<Hash32> {
    // k_block = b'B' + 32 bytes
    if k.len() == 33 && k[0] == b'B' {
        let mut h = [0u8; 32];
        h.copy_from_slice(&k[1..33]);
        Some(h)
    } else {
        None
    }
}

// ----------------------
// Best tip selection WITHOUT hdr (blocks-only)
// ----------------------
//
// Journal-less crash recovery must not depend on hdr durability.
// We derive (height, chainwork) by walking Block.header.prev using block bytes,
// and compute work via canonical pow::work_from_bits(bits).
//
// Any block whose ancestry cannot be resolved from bytes is ignored.

fn best_tip_from_blocks_only(db: &Stores) -> Result<Option<(Hash32, u64, u128)>> {
    // memo[hash] = Some((height, chainwork_to_here)) OR None while visiting (cycle guard)
    let mut memo: HashMap<Hash32, Option<(u64, u128)>> = HashMap::new();

    fn calc(
        db: &Stores,
        h: Hash32,
        memo: &mut HashMap<Hash32, Option<(u64, u128)>>,
    ) -> Result<Option<(u64, u128)>> {
        if let Some(v) = memo.get(&h) {
            return Ok(*v);
        }

        // mark visiting (cycle guard)
        memo.insert(h, None);


let blk = match load_block(db, &h) {
    Ok(b) => b,
    Err(_) => {
        memo.remove(&h);
        return Ok(None);
    }
};

if !header_min_valid(&h, &blk) {
    memo.remove(&h);
    return Ok(None);
}

        let parent = blk.header.prev;

        // canonical work increment (same as HeaderIndex)
        let my_work = match crate::chain::pow::work_from_bits(blk.header.bits) {
            Ok(w) => w,
            Err(_) => {
                memo.remove(&h);
                return Ok(None);
            }
        };

        // genesis terminator convention: prev == 0
        if parent == [0u8; 32] {
            let out = Some((0u64, my_work));
            memo.insert(h, out);
            return Ok(out);
        }

        // parent must exist (as bytes) to be rebuildable
        let p = calc(db, parent, memo)?;
        let out = match p {
            Some((ph, pw)) => Some((ph + 1, pw.saturating_add(my_work))),
            None => None,
        };

        memo.insert(h, out);
        Ok(out)
    }

    let mut best: Option<(Hash32, u64, u128)> = None;

    for kv in db.blocks.iter() {
        let (k, _v) = kv.context("blocks.iter()")?;
        let Some(h) = hash_from_block_key(&k) else { continue };

        let Some((height, cw)) = calc(db, h, &mut memo)? else { continue };

        best = match best {
            None => Some((h, height, cw)),
            Some((bh, bhgt, bcw)) => {
                if cw > bcw || (cw == bcw && height > bhgt) {
                    Some((h, height, cw))
                } else {
                    Some((bh, bhgt, bcw))
                }
            }
        };
    }

    Ok(best)
}


fn best_tip_with_block_bytes(db: &Stores) -> Result<Option<HeaderIndex>> {
    let mut best: Option<HeaderIndex> = None;

    for kv in db.blocks.iter() {
        let (k, _v) = kv.context("blocks.iter()")?;
        let Some(h) = hash_from_block_key(&k) else { continue };

        let Some(hi) = get_hidx(db, &h).ok().flatten() else { continue };

        best = match best {
            None => Some(hi),
            Some(cur) => {
                if hi.chainwork > cur.chainwork
                    || (hi.chainwork == cur.chainwork && hi.height > cur.height)
                {
                    Some(hi)
                } else {
                    Some(cur)
                }
            }
        };
    }

    Ok(best)
}

fn must_hidx(db: &Stores, hash: &Hash32) -> Result<HeaderIndex> {
    get_hidx(db, hash)?.ok_or_else(|| anyhow::anyhow!("missing header index for {}", hex32(hash)))
}

#[allow(dead_code)]
fn best_header_tip(db: &Stores) -> Result<Option<HeaderIndex>> {
    let mut best: Option<HeaderIndex> = None;

    for kv in db.hdr.iter() {
        let (_k, v) = kv.context("hdr.iter()")?;
        let hi: HeaderIndex = crate::codec::consensus_bincode()
            .deserialize::<HeaderIndex>(&v)
            .context("decode HeaderIndex in best_header_tip")?;

        best = match best {
            None => Some(hi),
            Some(cur) => {
                if hi.chainwork > cur.chainwork
                    || (hi.chainwork == cur.chainwork && hi.height > cur.height)
                {
                    Some(hi)
                } else {
                    Some(cur)
                }
            }
        };
    }

    Ok(best)
}

fn find_ancestor(db: &Stores, mut a: HeaderIndex, mut b: HeaderIndex) -> Result<HeaderIndex> {
    while a.height > b.height {
        a = must_hidx(db, &a.parent)?;
    }
    while b.height > a.height {
        b = must_hidx(db, &b.parent)?;
    }
    while a.hash != b.hash {
        a = must_hidx(db, &a.parent)?;
        b = must_hidx(db, &b.parent)?;
    }
    Ok(a)
}

// IMPORTANT: sled Tree::flush() is not a cross-tree durability fence.
// Use Db::flush() as the single all-trees barrier.
fn flush_state_step(db: &Stores) -> Result<()> {
    db.db.flush().context("db.flush (all trees)")?;
    failpoints::hit("flush_state_step:post");
    Ok(())
}

/// ✅ NEW: Pre-tip durability fence.
/// Ensures the block bytes for `bh` are present and durable *before* meta:tip is advanced to `bh`.
///
/// This addresses the crash-fuzz mismatch where clean/replay reaches a tip whose block bytes
/// were not yet durable in the crashed DB, preventing journal-less recovery from rebuilding there.
fn pre_tip_fence(db: &Stores, bh: &Hash32) -> Result<()> {
    if db.blocks.get(k_block(bh))?.is_none() {
        bail!("pre_tip_fence: missing block bytes for {}", hex32(bh));
    }
    // Cross-tree durability fence: blocks/hdr/utxo/meta/undo/app all at once.
    flush_state_step(db).context("pre_tip_fence: flush_state_step")?;
    Ok(())
}

fn set_tip_durable(db: &Stores, h: &Hash32, ctx: &'static str) -> Result<()> {
    // (Optional but recommended) ensure block bytes durable before tip can point to it.
    // If you call this in contexts where block bytes might not exist (e.g. drive_tip_down_to),
    // remove this line there.
    // pre_tip_fence(db, h).with_context(|| format!("{ctx}: pre_tip_fence"))?;

    set_tip(db, h).with_context(|| format!("{ctx}: set_tip {}", hex32(h)))?;
    flush_state_step(db).with_context(|| format!("{ctx}: flush_state_step"))?;
    Ok(())
}

// Tip helpers
fn tip_is(db: &Stores, h: &Hash32) -> Result<bool> {
    Ok(get_tip(db)?.map(|t| t == *h).unwrap_or(false))
}

fn current_tip(db: &Stores) -> Result<Option<Hash32>> {
    get_tip(db).context("get_tip")
}

// Journal helper
fn jw(db: &Stores, j: &mut ReorgJournal, ctx: &'static str) -> Result<()> {
    journal_write(db, j).context(ctx)?;
    flush_state_step(db).context("jw flush_state_step")?;
    Ok(())
}

// Bad-block persistence
fn is_bad(db: &Stores, h: &Hash32) -> Result<bool> {
    Ok(db.meta.get(k_bad(h))?.is_some())
}

fn mark_bad(db: &Stores, h: &Hash32, why: &str) -> Result<()> {
    db.meta.insert(k_bad(h), b"1")?;
    println!("[reorg] marked bad {} ({})", hex32(h), why);
    Ok(())
}

// Mempool helpers
fn mempool_remove_mined(mempool: Option<&Mempool>, blk: &Block) {
    let Some(mp) = mempool else { return };

    let mut removed = 0usize;
    for tx in &blk.txs {
        let id = txid(tx);
        if mp.remove(&id) {
            removed += 1;
        }
    }

    if removed > 0 {
        println!(
            "[mempool] removed {} mined txs after block apply (mempool_len={}, spent_outpoints={})",
            removed,
            mp.len(),
            mp.spent_len()
        );
    }
}

fn mempool_prune_if_present(db: &Stores, mempool: Option<&Mempool>) {
    if let Some(mp) = mempool {
        let removed = mp.prune(db);
        if removed > 0 {
            println!(
                "[mempool] pruned {} txs after tip update (mempool_len={}, spent_outpoints={})",
                removed,
                mp.len(),
                mp.spent_len()
            );
        }
    }
}

fn ensure_apply_blocks_present(db: &Stores, apply_hashes: &[Hash32], new_tip: &Hash32) -> Result<bool> {
    for bh in apply_hashes {
        if db.blocks.get(k_block(bh))?.is_none() {
            println!(
                "[reorg] deferring reorg to {}: missing block bytes for apply-path block {}",
                hex32(new_tip),
                hex32(bh)
            );
            return Ok(false);
        }
    }
    Ok(true)
}

fn vec_contains(v: &[Hash32], x: &Hash32) -> bool {
    v.iter().any(|h| h == x)
}

fn journal_structurally_plausible(j: &ReorgJournal) -> bool {
    // undo_path should start at old_tip (if any)
    if !j.undo_path.is_empty() && j.undo_path[0] != j.old_tip {
        return false;
    }
    // apply_path should end at new_tip (if any)
    if !j.apply_path.is_empty() {
        if let Some(last) = j.apply_path.last() {
            if *last != j.new_tip {
                return false;
            }
        }
    }
    // cursor must be in-range for its phase
    match j.phase {
        Phase::Undo => j.cursor <= j.undo_path.len() as u64,
        Phase::Apply => j.cursor <= j.apply_path.len() as u64,
    }
}

fn journal_matches_current_tip_state(cur_tip: &Option<Hash32>, j: &ReorgJournal) -> bool {
    let Some(t) = cur_tip else {
        // cold start / crash timing
        return true;
    };

    if *t == j.old_tip || *t == j.ancestor || *t == j.new_tip {
        return true;
    }
    if j.undo_path.iter().any(|h| h == t) { return true; }
    if j.apply_path.iter().any(|h| h == t) { return true; }

    false
}


// ----------------------
// Parent resolution (hdr-or-block)
// ----------------------
//
// Crash-fuzz can leave hdr tree missing while block bytes exist.
// Recovery must be able to move using Block.header.prev.

fn parent_of(db: &Stores, h: &Hash32) -> Result<Hash32> {
    if let Ok(Some(hi)) = get_hidx(db, h) {
        return Ok(hi.parent);
    }
    let blk = load_block(db, h).with_context(|| format!("parent_of load_block {}", hex32(h)))?;
    Ok(blk.header.prev)
}

// Undo idempotence wrapper
fn undo_block_idempotent(db: &Stores, block_hash: &Hash32) -> Result<()> {
    let Some(undo_bytes) = db.undo.get(k_undo(block_hash))? else {
        bail!("missing undo");
    };

    undo_block(db, block_hash).with_context(|| format!("undo_block {}", hex32(block_hash)))?;

    db.undo
        .insert(k_undo(block_hash), undo_bytes)
        .with_context(|| format!("reinsert undo {}", hex32(block_hash)))?;

    Ok(())
}

fn drive_tip_down_to(db: &Stores, target: &Hash32) -> Result<()> {
    loop {
        let tip = match current_tip(db).context("drive_tip_down_to get_tip")? {
            Some(t) => t,
            None => {
                set_tip(db, target).context("drive_tip_down_to set_tip(from None)")?;
                flush_state_step(db).context("drive_tip_down_to flush(set_tip from None)")?;
                return Ok(());
            }
        };

        if tip == *target {
            return Ok(());
        }

        undo_block_idempotent(db, &tip)
            .with_context(|| format!("drive_tip_down_to undo_block_idempotent {}", hex32(&tip)))?;

        let p = parent_of(db, &tip)
            .with_context(|| format!("drive_tip_down_to parent_of(cur_tip {})", hex32(&tip)))?;

        set_tip(db, &p).with_context(|| format!("drive_tip_down_to set_tip(parent of {})", hex32(&tip)))?;
        flush_state_step(db).context("drive_tip_down_to flush(undo)")?;
    }
}

// -------- rebuild helpers --------
//
// Prefer hdr-based chain if available; fall back to block-bytes chain.
// Height during rebuild is computed from position in chain (deterministic).

fn chain_to_tip_from_hdr(db: &Stores, tip: &Hash32) -> Result<Vec<Hash32>> {
    let mut chain: Vec<Hash32> = Vec::new();
    let mut cur = must_hidx(db, tip).context("chain_to_tip_from_hdr must_hidx(tip)")?;
    loop {
        chain.push(cur.hash);
        if cur.height == 0 {
            break;
        }
        cur = must_hidx(db, &cur.parent)
            .with_context(|| format!("chain_to_tip_from_hdr must_hidx(parent of {})", hex32(&cur.hash)))?;
    }
    chain.reverse();
    Ok(chain)
}

fn chain_to_tip_from_blocks(db: &Stores, tip: &Hash32) -> Result<Vec<Hash32>> {
    let mut chain: Vec<Hash32> = Vec::new();
    let mut cur = *tip;

    loop {
        chain.push(cur);

        let blk = load_block(db, &cur).with_context(|| format!("chain_to_tip_from_blocks load {}", hex32(&cur)))?;
        let p = blk.header.prev;

        // Stop at genesis (prev==0) or if this block is height 0 in hdr (optional fast stop)
        if p == [0u8; 32] {
            break;
        }
        cur = p;
    }

    chain.reverse();
    Ok(chain)
}

fn can_rebuild_to_tip(db: &Stores, tip: &Hash32) -> Result<bool> {
    // 1) Try hdr chain first, but do NOT treat failure as "not rebuildable".
    // Crash fuzz can leave hdr incomplete while block bytes are complete.
    if let Ok(chain) = chain_to_tip_from_hdr(db, tip) {
        for bh in &chain {
            if db.blocks.get(k_block(bh))?.is_none() {
                return Ok(false);
            }
        }
        return Ok(true);
    }

    // 2) Fall back to block-bytes parent chain.
    let chain = chain_to_tip_from_blocks(db, tip)?;
    for bh in &chain {
        if db.blocks.get(k_block(bh))?.is_none() {
            return Ok(false);
        }
    }
    Ok(true)
}

fn rebuild_state_to_tip(db: &Stores, target_tip: &Hash32, mempool: Option<&Mempool>) -> Result<()> {
    println!(
        "[reorg] recovery fallback: rebuilding state to tip {}",
        hex32(target_tip)
    );

    // Prefer hdr-based chain if possible, but FALL BACK to block chain if hdr chain is incomplete.
    let chain = match chain_to_tip_from_hdr(db, target_tip) {
        Ok(c) => c,
        Err(e) => {
            println!(
                "[reorg] rebuild: hdr chain walk failed for {} ({}). Falling back to block-parent chain.",
                hex32(target_tip),
                e
            );
            chain_to_tip_from_blocks(db, target_tip).context("rebuild chain_to_tip_from_blocks")?
        }
    };

    db.utxo.clear().context("rebuild utxo.clear")?;
    db.utxo_meta.clear().context("rebuild utxo_meta.clear")?;
    db.undo.clear().context("rebuild undo.clear")?;
    db.app.clear().context("rebuild app.clear")?;
    flush_state_step(db).context("rebuild flush after clears")?;

    for (i, bh) in chain.iter().enumerate() {
        let blk = load_block(db, bh).with_context(|| format!("rebuild load_block {}", hex32(bh)))?;

        // Height during rebuild: deterministic position in the rebuilt chain.
        let height = i as u64;

        validate_and_apply_block(db, &blk, epoch_of(height), height)
            .with_context(|| format!("rebuild validate_and_apply_block {}", hex32(bh)))?;

        mempool_remove_mined(mempool, &blk);

set_tip_durable(db, bh, "rebuild")?;

    }

    Ok(())
}

// ----------------------
// Crash recovery
// ----------------------


pub fn recover_if_needed(db: &Stores, mempool: Option<&Mempool>) -> Result<()> {

let Some(mut j) = journal_read(db).context("journal_read")? else {
    // ------------------------------
    // JOURNAL-LESS RECOVERY
    // ------------------------------
    //
    // Must not depend on hdr durability.
    // Select canonical tip using block bytes only (prev pointers) and work_from_bits(bits).

    println!("[reorg] recovery(journal-less): selecting canonical tip from blocks-only chainwork");

let meta_tip = get_tip(db).ok().flatten();
println!("[reorg] journal-less: meta_tip={}", fmt_opt32(meta_tip));

let hdr_best = best_header_tip(db).ok().flatten();
println!(
    "[reorg] journal-less: hdr_best={}",
    match &hdr_best {
        Some(hi) => format!("{} (h={}, w={})", hex32(&hi.hash), hi.height, hi.chainwork),
        None => "None".to_string(),
    }
);

    let best = best_tip_from_blocks_only(db)
        .context("journal-less best_tip_from_blocks_only")?;

    match best {
        Some((best_hash, h, w)) => {
            println!(
                "[reorg] recovery(journal-less): rebuilding to best tip {} (h={}, w={})",
                hex32(&best_hash),
                h,
                w
            );

println!(
    "[reorg] journal-less: blocks_only_best={}",
    match &best {
        Some((h, ht, cw)) => format!("{} (h={}, w={})", hex32(h), ht, cw),
        None => "None".to_string(),
    }
);

// If meta tip exists, see if we can rebuild to it
if let Some(t) = meta_tip {
    let ok = can_rebuild_to_tip(db, &t).unwrap_or(false);
    println!("[reorg] journal-less: can_rebuild_to_meta_tip={} tip={}", ok, hex32(&t));
}

            rebuild_state_to_tip(db, &best_hash, mempool)
                .context("journal-less rebuild_state_to_tip(best blocks-only)")?;

            flush_state_step(db).ok();
        }
        None => {
            println!("[reorg] recovery(journal-less): no rebuildable blocks found");
        }
    }

    mempool_prune_if_present(db, mempool);
    return Ok(());
};


    println!(
        "[reorg] recovery: found in-progress reorg old_tip={} new_tip={} ancestor={} phase={:?} cursor={} seq={}",
        hex32(&j.old_tip),
        hex32(&j.new_tip),
        hex32(&j.ancestor),
        j.phase,
        j.cursor,
        j.seq
    );

let cur_tip = get_tip(db).context("get_tip(recover pre-guard)")?;






// after reading j and cur_tip...

// after reading j and cur_tip...
let plausible = journal_structurally_plausible(&j);

let matches = journal_matches_current_tip_state(&cur_tip, &j);

if !plausible {
    // Truly corrupted -> clear + fall back to journal-less handling.
    println!("[reorg] recovery: journal corrupted; clearing and falling back");
    journal_clear(db).ok();
    flush_state_step(db).ok();
    mempool_prune_if_present(db, mempool);
    return Ok(());
}


if !matches {
    println!(
        "[reorg] recovery: cur_tip not on journal path; continuing journal-driven recovery anyway (cur_tip={:?})",
        cur_tip.as_ref().map(|h| hex32(h))
    );
    // Do NOT clear. Continue.
}





    // Stale journal: already at new_tip.
    if tip_is(db, &j.new_tip).context("recover tip_is(new_tip)")? {
        println!(
            "[reorg] recovery: tip already at new_tip {}; clearing stale journal",
            hex32(&j.new_tip)
        );
        journal_clear(db).context("recover journal_clear(stale)")?;
        flush_state_step(db).context("recover flush after journal_clear(stale)")?;
        mempool_prune_if_present(db, mempool);
        return Ok(());
    }

    // ✅ Deterministic recovery order, but now rebuild does NOT require hdr.
    if can_rebuild_to_tip(db, &j.new_tip).context("recover can_rebuild_to_tip(new_tip)")? {
        rebuild_state_to_tip(db, &j.new_tip, mempool)
            .context("recover rebuild_state_to_tip(rebuild->new_tip)")?;
        journal_clear(db).ok();
        flush_state_step(db).ok();
        mempool_prune_if_present(db, mempool);
        return Ok(());
    }

    if can_rebuild_to_tip(db, &j.ancestor).context("recover can_rebuild_to_tip(ancestor)")? {
        rebuild_state_to_tip(db, &j.ancestor, mempool)
            .context("recover rebuild_state_to_tip(rebuild->ancestor)")?;

        let apply_path = j.apply_path.clone();
        if ensure_apply_blocks_present(db, &apply_path, &j.new_tip)? {
            // Apply forward using ONLY block bytes for parent alignment.
            for (i, bh) in apply_path.iter().enumerate() {
                let blk = load_block(db, bh).with_context(|| format!("recover load_block {}", hex32(bh)))?;

                let height = if let Ok(Some(hi)) = get_hidx(db, bh) {
                    hi.height
                } else {
                    let chain = chain_to_tip_from_blocks(db, bh)?;
                    (chain.len().saturating_sub(1)) as u64
                };

                validate_and_apply_block(db, &blk, epoch_of(height), height)
                    .with_context(|| format!("recover validate_and_apply_block {}", hex32(bh)))?;

                mempool_remove_mined(mempool, &blk);

                // ✅ NEW: ensure body durable before advancing tip

pre_tip_fence(db, bh)
    .with_context(|| format!("recover pre_tip_fence {}", i))?;
set_tip_durable(db, bh, "recover apply")?;

            }

            // ✅ NEW: fence final new_tip too
            pre_tip_fence(db, &j.new_tip).ok();

set_tip_durable(db, &j.new_tip, "recover final new_tip")?;

        } else {
            println!(
                "[reorg] recovery: missing block bytes on apply path; leaving tip at ancestor {}",
                hex32(&j.ancestor)
            );
        }

        journal_clear(db).ok();
        flush_state_step(db).ok();
        mempool_prune_if_present(db, mempool);
        return Ok(());
    }

    // ----- journal-driven fallback -----
    let undo_path = j.undo_path.clone();
    let apply_path = j.apply_path.clone();

    j.phase = Phase::Undo;

    for (i, bh) in undo_path.iter().enumerate() {
        let expected_tip_after_undo = parent_of(db, bh)
            .with_context(|| format!("recover expected_tip_after_undo parent_of {}", hex32(bh)))?;

        if tip_is(db, &expected_tip_after_undo)? {
            j.cursor = (i as u64) + 1;
            jw(db, &mut j, "recover journal_write(skip_undo)")?;
            continue;
        }

        failpoints::hit(&format!("recover:undo:{}:pre", i));

        if tip_is(db, bh)? {
            let r = undo_block_idempotent(db, bh);
            if let Err(e) = r {
                if is_missing_undo_err(&e) {
                    println!(
                        "[reorg] recovery: missing undo while undoing {}; falling back to rebuild",
                        hex32(bh)
                    );
                    rebuild_state_to_tip(db, &j.new_tip, mempool)
                        .context("recover rebuild_state_to_tip(missing undo during undo)")?;
                    journal_clear(db).ok();
                    flush_state_step(db).ok();
                    mempool_prune_if_present(db, mempool);
                    return Ok(());
                }
                return Err(e).context("recover undo_block_idempotent")?;
            }

            set_tip(db, &expected_tip_after_undo)
                .with_context(|| format!("recover set_tip(parent of {})", hex32(bh)))?;
            flush_state_step(db).context("recover flush_state_step(undo)")?;
        } else {
            break;
        }

        j.cursor = (i as u64) + 1;
        failpoints::hit(&format!("recover:undo:{}:pre_journal", i));
        jw(db, &mut j, "recover journal_write(progress_undo)")?;
        failpoints::hit(&format!("recover:undo:{}:post_journal", i));
    }

    if !tip_is(db, &j.ancestor)? {
        let r = drive_tip_down_to(db, &j.ancestor);
        if let Err(e) = r {
            if is_missing_undo_err(&e) {
                println!(
                    "[reorg] recovery: missing undo while driving down; falling back to rebuild"
                );
                rebuild_state_to_tip(db, &j.new_tip, mempool)
                    .context("recover rebuild_state_to_tip(missing undo drive_down)")?;
                journal_clear(db).ok();
                flush_state_step(db).ok();
                mempool_prune_if_present(db, mempool);
                return Ok(());
            }
            return Err(e).context("recover drive_tip_down_to(ancestor)")?;
        }
    }

    mempool_prune_if_present(db, mempool);

    if !ensure_apply_blocks_present(db, &apply_path, &j.new_tip)? {
        println!(
            "[reorg] recovery: missing block bytes for apply path; leaving tip at ancestor {}",
            hex32(&j.ancestor)
        );
        return Ok(());
    }

    println!(
        "[reorg] recovery: applying new branch toward {}",
        hex32(&j.new_tip)
    );

    j.phase = Phase::Apply;
    j.cursor = 0;
    jw(db, &mut j, "recover journal_write(start_apply)")?;

    for (i, bh) in apply_path.iter().enumerate() {
        if tip_is(db, bh)? {
            j.cursor = (i as u64) + 1;
            jw(db, &mut j, "recover journal_write(skip_apply)")?;
            continue;
        }

        let blk = load_block(db, bh).with_context(|| format!("recover load_block {}", hex32(bh)))?;

        let height = if let Ok(Some(hi)) = get_hidx(db, bh) {
            hi.height
        } else {
            let chain = chain_to_tip_from_blocks(db, bh)?;
            (chain.len().saturating_sub(1)) as u64
        };

        failpoints::hit(&format!("recover:apply:{}:pre", i));

        let r = validate_and_apply_block(db, &blk, epoch_of(height), height)
            .with_context(|| format!("recover validate_and_apply_block {}", hex32(bh)));

        if let Err(e) = r {
            println!("[reorg] recovery: apply failed at {}: {e:#}", hex32(bh));

            if !is_missing_block_bytes_err(&e) {
                let _ = mark_bad(db, bh, "recovery apply failed");
                let _ = mark_bad(db, &j.new_tip, "recovery apply path contains invalid block");
            } else {
                println!("[reorg] recovery: missing bytes; not marking bad");
            }

            rebuild_state_to_tip(db, &j.new_tip, mempool)
                .context("recover rebuild_state_to_tip(apply failed)")?;
            journal_clear(db).ok();
            flush_state_step(db).ok();
            mempool_prune_if_present(db, mempool);
            return Ok(());
        }

        mempool_remove_mined(mempool, &blk);

        // ✅ NEW: ensure body durable before advancing tip

pre_tip_fence(db, bh)
    .with_context(|| format!("recover pre_tip_fence {}", i))?;
set_tip_durable(db, bh, "recover apply")?;

        j.cursor = (i as u64) + 1;
        failpoints::hit(&format!("recover:apply:{}:pre_journal", i));
        jw(db, &mut j, "recover journal_write(progress_apply)")?;
        failpoints::hit(&format!("recover:apply:{}:post_journal", i));
    }

    // ✅ NEW: fence final new_tip too
    pre_tip_fence(db, &j.new_tip).ok();

set_tip_durable(db, &j.new_tip, "recover final new_tip")?;

    failpoints::hit("recover:pre_journal_clear");
    journal_clear(db).context("recover journal_clear")?;
    flush_state_step(db).context("recover flush after journal_clear")?;

    mempool_prune_if_present(db, mempool);
    println!("[reorg] recovery success: now tip={}", hex32(&j.new_tip));
    Ok(())
}

// ----------------------
// Main reorg
// ----------------------
pub fn maybe_reorg_to(db: &Stores, new_tip: &Hash32, mempool: Option<&Mempool>) -> Result<()> {
    if is_bad(db, new_tip).context("is_bad(new_tip)")? {
        return Ok(());
    }

    // ---------------- Cold-start fix ----------------
    let old_tip = match get_tip(db).context("get_tip")? {
        Some(t) => t,
        None => {
            let new_hi = must_hidx(db, new_tip).context("missing new tip idx (cold-start)")?;

            if new_hi.height != 0 {
                println!(
                    "[reorg] cold-start deferring: new_tip {} is height {}, not 0",
                    hex32(new_tip),
                    new_hi.height
                );
                return Ok(());
            }

            if db.blocks.get(k_block(new_tip))?.is_none() {
                println!(
                    "[reorg] cold-start deferring: missing block bytes for {}",
                    hex32(new_tip)
                );
                return Ok(());
            }

            let blk = load_block(db, new_tip).context("cold-start load genesis block")?;

            validate_and_apply_block(db, &blk, epoch_of(new_hi.height), new_hi.height)
                .context("cold-start validate_and_apply_block")?;

            mempool_remove_mined(mempool, &blk);

            // ✅ NEW: ensure genesis body durable before setting tip
            pre_tip_fence(db, new_tip).context("cold-start pre_tip_fence(genesis)")?;

            set_tip(db, new_tip).context("cold-start set_tip(genesis)")?;
            flush_state_step(db).context("cold-start flush_state_step")?;

            mempool_prune_if_present(db, mempool);
            println!("[reorg] cold-start success: tip={}", hex32(new_tip));
            return Ok(());
        }
    };

    if old_tip == *new_tip {
        return Ok(());
    }

    let old_hi = must_hidx(db, &old_tip).context("missing old tip idx")?;
    let new_hi = must_hidx(db, new_tip).context("missing new tip idx")?;

    if new_hi.chainwork <= old_hi.chainwork {
        return Ok(());
    }

    let anc = find_ancestor(db, old_hi.clone(), new_hi.clone()).context("find_ancestor")?;

    let mut undo_path: Vec<Hash32> = vec![];
    let mut cur = old_hi.clone();
    while cur.hash != anc.hash {
        undo_path.push(cur.hash);
        cur = must_hidx(db, &cur.parent)?;
    }

    let mut apply_path: Vec<Hash32> = vec![];
    let mut cur2 = new_hi.clone();
    while cur2.hash != anc.hash {
        apply_path.push(cur2.hash);
        cur2 = must_hidx(db, &cur2.parent)?;
    }
    apply_path.reverse();

    for bh in &apply_path {
        if is_bad(db, bh).with_context(|| format!("is_bad(apply {})", hex32(bh)))? {
            return Ok(());
        }
    }

    if !ensure_apply_blocks_present(db, &apply_path, new_tip)? {
        return Ok(());
    }

    println!(
        "[reorg] candidate: old_tip={} (h={}, w={}) -> new_tip={} (h={}, w={}), anc={} (h={}, w={}), undo={}, apply={}",
        hex32(&old_tip),
        old_hi.height,
        old_hi.chainwork,
        hex32(new_tip),
        new_hi.height,
        new_hi.chainwork,
        hex32(&anc.hash),
        anc.height,
        anc.chainwork,
        undo_path.len(),
        apply_path.len(),
    );

    flush_state_step(db).context("pre-journal flush_state_step")?;

    let mut j = ReorgJournal {
        seq: 0,
        old_tip,
        new_tip: *new_tip,
        ancestor: anc.hash,
        phase: Phase::Undo,
        cursor: 0,
        undo_path: undo_path.clone(),
        apply_path: apply_path.clone(),
    };
    jw(db, &mut j, "journal_write(start)")?;
    failpoints::hit("reorg:after_journal_start");

    for (i, bh) in undo_path.iter().enumerate() {
        failpoints::hit(&format!("undo:{}:pre", i));

        let hi = must_hidx(db, bh).with_context(|| format!("must_hidx(undo {})", hex32(bh)))?;

        undo_block_idempotent(db, bh).with_context(|| format!("[reorg] undo_block {}", hex32(bh)))?;

        set_tip(db, &hi.parent)
            .with_context(|| format!("[reorg] set_tip(parent of {})", hex32(bh)))?;

        flush_state_step(db).context("flush_state_step(undo)")?;

        j.cursor = (i as u64) + 1;
        jw(db, &mut j, "journal_write(progress_undo)")?;
        failpoints::hit(&format!("undo:{}:post_journal", i));
    }

    set_tip(db, &anc.hash).context("[reorg] set_tip(ancestor)")?;
    flush_state_step(db).context("flush_state_step(set ancestor)")?;
    failpoints::hit("reorg:at_ancestor_post_flush");

    j.phase = Phase::Apply;
    j.cursor = 0;
    jw(db, &mut j, "journal_write(start_apply)")?;
    failpoints::hit("reorg:after_apply_start");

    let mut applied_new: Vec<Hash32> = Vec::with_capacity(apply_path.len());
    let mut last_applying: Option<Hash32> = None;

    let apply_result: Result<()> = (|| {
        for (i, bh) in apply_path.iter().enumerate() {
            failpoints::hit(&format!("apply:{}:pre", i));
            last_applying = Some(*bh);

            let blk = load_block(db, bh).with_context(|| format!("[reorg] load_block {}", hex32(bh)))?;
            let hi = must_hidx(db, bh).with_context(|| format!("[reorg] must_hidx {}", hex32(bh)))?;

            validate_and_apply_block(db, &blk, epoch_of(hi.height), hi.height)
                .with_context(|| format!("[reorg] validate_and_apply_block {}", hex32(bh)))?;

            mempool_remove_mined(mempool, &blk);

            // ✅ NEW: ensure applied head body durable before setting tip

pre_tip_fence(db, bh)
    .with_context(|| format!("apply pre_tip_fence {}", i))?;

set_tip_durable(db, bh, "apply")?;

            applied_new.push(*bh);

            j.cursor = (i as u64) + 1;
            jw(db, &mut j, "journal_write(progress_apply)")?;
            failpoints::hit(&format!("apply:{}:post_journal", i));
        }
        Ok(())
    })();

    if let Err(e) = apply_result {
        println!(
            "[reorg] apply failed at {:?}: {e:#}. Rolling back…",
            last_applying.map(|h| hex32(&h))
        );

        if !is_missing_block_bytes_err(&e) {
            if let Some(bad_bh) = last_applying {
                let _ = mark_bad(db, &bad_bh, "apply failed");
                let _ = mark_bad(db, new_tip, "apply path contains invalid block");
            }
        } else {
            println!("[reorg] apply failed due to missing local block bytes; not marking branch bad.");
        }

        for bh in applied_new.iter().rev() {
            let p = parent_of(db, bh).with_context(|| format!("[reorg] rollback parent_of(applied_new {})", hex32(bh)))?;
            undo_block_idempotent(db, bh).with_context(|| format!("[reorg] rollback undo_block(applied_new {})", hex32(bh)))?;
            set_tip(db, &p).with_context(|| format!("[reorg] rollback set_tip(parent of {})", hex32(bh)))?;
            flush_state_step(db).context("rollback flush_state_step(undo applied_new)")?;
        }

        set_tip(db, &anc.hash).context("[reorg] rollback set_tip(ancestor)")?;
        flush_state_step(db).context("rollback flush_state_step(set ancestor)")?;

        let mut reapply_old = undo_path.clone();
        reapply_old.reverse();

        for (i, bh) in reapply_old.iter().enumerate() {
            let blk = load_block(db, bh).with_context(|| format!("[reorg] rollback load_block(old {})", hex32(bh)))?;
            let hi = must_hidx(db, bh).with_context(|| format!("[reorg] rollback must_hidx(old {})", hex32(bh)))?;

            validate_and_apply_block(db, &blk, epoch_of(hi.height), hi.height)
                .with_context(|| format!("[reorg] rollback validate_and_apply_block(old {})", hex32(bh)))?;

            mempool_remove_mined(mempool, &blk);

            // ✅ NEW: fence before advancing tip in rollback replay too

pre_tip_fence(db, bh)
    .with_context(|| format!("rollback reapply_old pre_tip_fence {}", i))?;
set_tip_durable(db, bh, "rollback reapply_old")?;

        }

        set_tip(db, &old_tip).context("[reorg] rollback final set_tip(old_tip)")?;
        flush_state_step(db).context("rollback flush_state_step(final set old_tip)")?;

        mempool_prune_if_present(db, mempool);

        let _ = journal_clear(db);
        let _ = flush_state_step(db);

        return Err(e);
    }

    // ✅ NEW: fence final new_tip before setting tip to it (paranoia)

pre_tip_fence(db, new_tip).ok();
set_tip_durable(db, new_tip, "final new_tip")?;

    let final_tip = get_tip(db).context("get_tip(final)")?.unwrap_or([0u8; 32]);
    if final_tip != *new_tip {
        bail!(
            "[reorg] success but tip mismatch: expected {}, got {}",
            hex32(new_tip),
            hex32(&final_tip)
        );
    }

    failpoints::hit("reorg:pre_journal_clear");
    journal_clear(db).context("journal_clear(success)")?;
    flush_state_step(db).context("flush after journal_clear(success)")?;

    println!(
        "[reorg] success: now tip={} (h={}, w={})",
        hex32(new_tip),
        new_hi.height,
        new_hi.chainwork
    );

    mempool_prune_if_present(db, mempool);
    Ok(())
}
