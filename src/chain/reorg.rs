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

fn hex32(h: &Hash32) -> String {
    format!("0x{}", hex::encode(h))
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

fn is_missing_block_bytes_err(e: &anyhow::Error) -> bool {
    let s = format!("{e:#}");
    s.contains("missing block bytes for 0x")
}

fn is_missing_undo_err(e: &anyhow::Error) -> bool {
    let s = format!("{e:#}");
    s.contains("missing undo")
}

fn must_hidx(db: &Stores, hash: &Hash32) -> Result<HeaderIndex> {
    get_hidx(db, hash)?.ok_or_else(|| anyhow::anyhow!("missing header index for {}", hex32(hash)))
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

// ----------------------
// Durability barrier (CRASH DETERMINISM FIX)
// ----------------------
//
// IMPORTANT: Tree::flush() is NOT a cross-tree atomic durability fence in sled.
// Use Db::flush() as the single "all trees" durability barrier.
fn flush_state_step(db: &Stores) -> Result<()> {
    db.db.flush().context("db.flush (all trees)")?;
    failpoints::hit("flush_state_step:post");
    Ok(())
}

// ----------------------
// Tip helpers
// ----------------------
fn tip_is(db: &Stores, h: &Hash32) -> Result<bool> {
    Ok(get_tip(db)?.map(|t| t == *h).unwrap_or(false))
}

fn current_tip(db: &Stores) -> Result<Option<Hash32>> {
    get_tip(db).context("get_tip")
}

// ----------------------
// Journal helper (seq monotonicity for double-buffer journal)
// ----------------------
fn jw(db: &Stores, j: &mut ReorgJournal, ctx: &'static str) -> Result<()> {
    journal_write(db, j).context(ctx)?;
    // journal_write() assigns monotonic seq itself; just fence.
    flush_state_step(db).context("jw flush_state_step")?;
    Ok(())
}

// ----------------------
// Bad-block persistence
// ----------------------
fn is_bad(db: &Stores, h: &Hash32) -> Result<bool> {
    Ok(db.meta.get(k_bad(h))?.is_some())
}

fn mark_bad(db: &Stores, h: &Hash32, why: &str) -> Result<()> {
    db.meta.insert(k_bad(h), b"1")?;
    println!("[reorg] marked bad {} ({})", hex32(h), why);
    Ok(())
}

// ----------------------
// Mempool helpers
// ----------------------
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

// ----------------------
// Undo idempotence wrapper
// ----------------------
//
// Your undo_block() currently removes the undo log key.
// That creates a fatal crash window:
// - undo applied
// - undo entry removed
// - tip/journal not advanced yet
// After restart, recovery cannot undo again => divergence.
//
// Fix here without touching utxo.rs:
// - snapshot undo bytes BEFORE undo_block()
// - call undo_block() (it removes key)
// - reinsert the same undo bytes so undo is retryable until we "commit"
fn undo_block_idempotent(db: &Stores, block_hash: &Hash32) -> Result<()> {
    let Some(undo_bytes) = db.undo.get(k_undo(block_hash))? else {
        bail!("missing undo");
    };

    undo_block(db, block_hash).with_context(|| format!("undo_block {}", hex32(block_hash)))?;

    // Reinsert so a crash before commit can retry the undo deterministically.
    db.undo
        .insert(k_undo(block_hash), undo_bytes)
        .with_context(|| format!("reinsert undo {}", hex32(block_hash)))?;

    Ok(())
}

// Drive durable tip DOWN to a target by undoing the current tip until tip==target.
// Used in recovery to force a deterministic base.
// Uses undo_block_idempotent() so it's safe across crash boundaries.
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

        let hi = must_hidx(db, &tip)
            .with_context(|| format!("drive_tip_down_to must_hidx(cur_tip {})", hex32(&tip)))?;

        undo_block_idempotent(db, &tip)
            .with_context(|| format!("drive_tip_down_to undo_block_idempotent {}", hex32(&tip)))?;

        set_tip(db, &hi.parent)
            .with_context(|| format!("drive_tip_down_to set_tip(parent of {})", hex32(&tip)))?;

        flush_state_step(db).context("drive_tip_down_to flush(undo)")?;
    }
}

// ----------------------
// Recovery fallback: full rebuild to a tip
// ----------------------
//
// If we cannot safely undo (missing undo) or apply (state is inconsistent),
// we rebuild UTXO+APP from scratch by replaying block bytes in canonical order.
//
// This is slower but makes crash fuzz deterministic even with non-persistent undo logs.
fn rebuild_state_to_tip(db: &Stores, target_tip: &Hash32, mempool: Option<&Mempool>) -> Result<()> {
    println!(
        "[reorg] recovery fallback: rebuilding state to tip {}",
        hex32(target_tip)
    );

    // Build canonical chain from genesis -> target_tip using header index parent pointers.
    let mut chain: Vec<Hash32> = Vec::new();
    let mut cur = must_hidx(db, target_tip).context("rebuild must_hidx(target_tip)")?;
    loop {
        chain.push(cur.hash);
        if cur.height == 0 {
            break;
        }
        cur = must_hidx(db, &cur.parent)
            .with_context(|| format!("rebuild must_hidx(parent of {})", hex32(&cur.hash)))?;
    }
    chain.reverse();

    // Clear consensus state trees that are derived from blocks.
    // (We intentionally do NOT clear blocks/hdr/hdr_raw/meta(bad) etc.)
    db.utxo.clear().context("rebuild utxo.clear")?;
    db.utxo_meta.clear().context("rebuild utxo_meta.clear")?;
    db.undo.clear().context("rebuild undo.clear")?;
    db.app.clear().context("rebuild app.clear")?;
    flush_state_step(db).context("rebuild flush after clears")?;

    // Replay forward.
    for (i, bh) in chain.iter().enumerate() {
        let blk = load_block(db, bh).with_context(|| format!("rebuild load_block {}", hex32(bh)))?;
        let hi = must_hidx(db, bh).with_context(|| format!("rebuild must_hidx {}", hex32(bh)))?;

        validate_and_apply_block(db, &blk, epoch_of(hi.height), hi.height)
            .with_context(|| format!("rebuild validate_and_apply_block {}", hex32(bh)))?;

        mempool_remove_mined(mempool, &blk);

        set_tip(db, bh).with_context(|| format!("rebuild set_tip {}", hex32(bh)))?;

        // Fence each step so rebuild is itself crash-safe.
        flush_state_step(db).with_context(|| format!("rebuild flush step {}", i))?;
    }

    Ok(())
}

// ----------------------
// Crash recovery
// ----------------------
pub fn recover_if_needed(db: &Stores, mempool: Option<&Mempool>) -> Result<()> {
    let Some(mut j) = journal_read(db).context("journal_read")? else {
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

    // ---- STALE JOURNAL GUARD ----
    if tip_is(db, &j.new_tip).context("recover tip_is(new_tip)")? {
        println!(
            "[reorg] recovery: tip already at new_tip {}; clearing stale journal",
            hex32(&j.new_tip)
        );
        journal_clear(db).context("recover journal_clear(stale)")?;
        flush_state_step(db).context("recover flush after journal_clear(stale)")?;
        return Ok(());
    }

    // Clone paths so we can mutate `j` while iterating.
    let undo_path = j.undo_path.clone();
    let apply_path = j.apply_path.clone();

    // ---------------------------------------------
    // Step 1: drive state back to ancestor
    // ---------------------------------------------
    j.phase = Phase::Undo;

    // Best-effort replay of recorded undo path (skips if already undone),
    // then deterministically drive down to ancestor.
    for (i, bh) in undo_path.iter().enumerate() {
        let hi =
            must_hidx(db, bh).with_context(|| format!("recover must_hidx(undo {})", hex32(bh)))?;
        let expected_tip_after_undo = hi.parent;

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
                    // Cannot safely continue this path; fall back.
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

    // Deterministic base.
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

    // ---------------------------------------------
    // Step 2: apply new branch
    // ---------------------------------------------
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

    // Ensure correct base.
    if !tip_is(db, &j.ancestor)? {
        let r = drive_tip_down_to(db, &j.ancestor);
        if let Err(e) = r {
            if is_missing_undo_err(&e) {
                println!(
                    "[reorg] recovery: missing undo before apply; falling back to rebuild"
                );
                rebuild_state_to_tip(db, &j.new_tip, mempool)
                    .context("recover rebuild_state_to_tip(missing undo pre-apply)")?;
                journal_clear(db).ok();
                flush_state_step(db).ok();
                mempool_prune_if_present(db, mempool);
                return Ok(());
            }
            return Err(e).context("recover drive_tip_down_to(ancestor pre-apply)")?;
        }
    }

    for (i, bh) in apply_path.iter().enumerate() {
        if tip_is(db, bh)? {
            j.cursor = (i as u64) + 1;
            jw(db, &mut j, "recover journal_write(skip_apply)")?;
            continue;
        }

        // Enforce correct parent (drive DOWN only).
        let hi = must_hidx(db, bh).with_context(|| format!("recover must_hidx {}", hex32(bh)))?;
        let parent = hi.parent;

        if !tip_is(db, &parent)? {
            let r = drive_tip_down_to(db, &parent);
            if let Err(e) = r {
                if is_missing_undo_err(&e) {
                    println!(
                        "[reorg] recovery: missing undo while aligning parent; falling back to rebuild"
                    );
                    rebuild_state_to_tip(db, &j.new_tip, mempool)
                        .context("recover rebuild_state_to_tip(missing undo align parent)")?;
                    journal_clear(db).ok();
                    flush_state_step(db).ok();
                    mempool_prune_if_present(db, mempool);
                    return Ok(());
                }
                return Err(e).context("recover drive_tip_down_to(parent)")?;
            }
        }

        failpoints::hit(&format!("recover:apply:{}:pre", i));

        let blk = load_block(db, bh).with_context(|| format!("recover load_block {}", hex32(bh)))?;

        let r = validate_and_apply_block(db, &blk, epoch_of(hi.height), hi.height)
            .with_context(|| format!("recover validate_and_apply_block {}", hex32(bh)));

        if let Err(e) = r {
            println!("[reorg] recovery: apply failed at {}: {e:#}", hex32(bh));

            if !is_missing_block_bytes_err(&e) {
                let _ = mark_bad(db, bh, "recovery apply failed");
                let _ = mark_bad(db, &j.new_tip, "recovery apply path contains invalid block");
            } else {
                println!("[reorg] recovery: missing bytes; not marking bad");
            }

            // Apply failure can leave state inconsistent vs replay; safest is rebuild.
            rebuild_state_to_tip(db, &j.new_tip, mempool)
                .context("recover rebuild_state_to_tip(apply failed)")?;
            journal_clear(db).ok();
            flush_state_step(db).ok();
            mempool_prune_if_present(db, mempool);
            return Ok(());
        }

        mempool_remove_mined(mempool, &blk);
        set_tip(db, bh).with_context(|| format!("recover set_tip {}", hex32(bh)))?;
        flush_state_step(db).context("recover flush_state_step(apply)")?;

        j.cursor = (i as u64) + 1;
        failpoints::hit(&format!("recover:apply:{}:pre_journal", i));
        jw(db, &mut j, "recover journal_write(progress_apply)")?;
        failpoints::hit(&format!("recover:apply:{}:post_journal", i));
    }

    set_tip(db, &j.new_tip).context("recover final set_tip(new_tip)")?;
    flush_state_step(db).context("recover flush_state_step(final set new_tip)")?;

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

    // Build undo path: old_tip -> ancestor (exclusive)
    let mut undo_path: Vec<Hash32> = vec![];
    let mut cur = old_hi.clone();
    while cur.hash != anc.hash {
        undo_path.push(cur.hash);
        cur = must_hidx(db, &cur.parent)?;
    }

    // Build apply path: ancestor -> new_tip (exclusive)
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
        hex32(&old_tip), old_hi.height, old_hi.chainwork,
        hex32(new_tip), new_hi.height, new_hi.chainwork,
        hex32(&anc.hash), anc.height, anc.chainwork,
        undo_path.len(), apply_path.len(),
    );

    // PRE-JOURNAL: global fence so journal can't reference data that's not durable.
    flush_state_step(db).context("pre-journal flush_state_step")?;

    // ---------------- Crash-atomic journal start ----------------
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
    // -----------------------------------------------------------

    // Phase A: undo old branch
    for (i, bh) in undo_path.iter().enumerate() {
        failpoints::hit(&format!("undo:{}:pre", i));

        let hi = must_hidx(db, bh).with_context(|| format!("must_hidx(undo {})", hex32(bh)))?;

        // Use idempotent wrapper.
        undo_block_idempotent(db, bh).with_context(|| format!("[reorg] undo_block {}", hex32(bh)))?;

        set_tip(db, &hi.parent)
            .with_context(|| format!("[reorg] set_tip(parent of {})", hex32(bh)))?;

        flush_state_step(db).context("flush_state_step(undo)")?;

        failpoints::hit(&format!("undo:{}:post_tip_pre_flush", i));
        failpoints::hit(&format!("undo:{}:post_flush_pre_journal", i));

        j.cursor = (i as u64) + 1;
        jw(db, &mut j, "journal_write(progress_undo)")?;

        failpoints::hit(&format!("undo:{}:post_journal", i));
    }

    set_tip(db, &anc.hash).context("[reorg] set_tip(ancestor)")?;
    flush_state_step(db).context("flush_state_step(set ancestor)")?;
    failpoints::hit("reorg:at_ancestor_post_flush");

    j.phase = Phase::Apply;
    j.cursor = 0;
    jw(db, &mut j, "journal_write(at_ancestor)")?;

    // Phase B: apply new branch
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

            let blk =
                load_block(db, bh).with_context(|| format!("[reorg] load_block {}", hex32(bh)))?;
            let hi =
                must_hidx(db, bh).with_context(|| format!("[reorg] must_hidx {}", hex32(bh)))?;

            validate_and_apply_block(db, &blk, epoch_of(hi.height), hi.height)
                .with_context(|| format!("[reorg] validate_and_apply_block {}", hex32(bh)))?;

            mempool_remove_mined(mempool, &blk);

            set_tip(db, bh).with_context(|| format!("[reorg] set_tip {}", hex32(bh)))?;
            flush_state_step(db).context("flush_state_step(apply)")?;

            failpoints::hit(&format!("apply:{}:post_tip_pre_flush", i));
            failpoints::hit(&format!("apply:{}:post_flush_pre_journal", i));

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

        // Roll back: undo applied_new (reverse), then re-apply old branch (forward).
        let mut reapply_old = undo_path.clone();
        reapply_old.reverse();

        // Undo applied_new back to ancestor.
        for bh in applied_new.iter().rev() {
            let hi = must_hidx(db, bh).with_context(|| {
                format!("[reorg] rollback must_hidx(applied_new {})", hex32(bh))
            })?;
            undo_block_idempotent(db, bh).with_context(|| {
                format!("[reorg] rollback undo_block(applied_new {})", hex32(bh))
            })?;
            set_tip(db, &hi.parent)
                .with_context(|| format!("[reorg] rollback set_tip(parent of {})", hex32(bh)))?;
            flush_state_step(db).context("rollback flush_state_step(undo applied_new)")?;
        }

        set_tip(db, &anc.hash).context("[reorg] rollback set_tip(ancestor)")?;
        flush_state_step(db).context("rollback flush_state_step(set ancestor)")?;

        // Re-apply the old branch.
        for bh in &reapply_old {
            let blk = load_block(db, bh)
                .with_context(|| format!("[reorg] rollback load_block(old {})", hex32(bh)))?;
            let hi = must_hidx(db, bh)
                .with_context(|| format!("[reorg] rollback must_hidx(old {})", hex32(bh)))?;

            validate_and_apply_block(db, &blk, epoch_of(hi.height), hi.height).with_context(|| {
                format!(
                    "[reorg] rollback validate_and_apply_block(old {})",
                    hex32(bh)
                )
            })?;

            mempool_remove_mined(mempool, &blk);

            set_tip(db, bh)
                .with_context(|| format!("[reorg] rollback set_tip(old {})", hex32(bh)))?;

            flush_state_step(db).context("rollback flush_state_step(reapply old)")?;
        }

        set_tip(db, &old_tip).context("[reorg] rollback final set_tip(old_tip)")?;
        flush_state_step(db).context("rollback flush_state_step(final set old_tip)")?;

        mempool_prune_if_present(db, mempool);

        let _ = journal_clear(db);
        let _ = flush_state_step(db);

        return Err(e);
    }

    set_tip(db, new_tip).context("[reorg] final set_tip(new_tip)")?;
    flush_state_step(db).context("flush_state_step(final set new_tip)")?;

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
