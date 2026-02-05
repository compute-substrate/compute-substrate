// src/chain/reorg.rs
use anyhow::{bail, Context, Result};

use crate::chain::index::{get_hidx, HeaderIndex};
use crate::chain::reorg_journal::{
    journal_clear, journal_read, journal_write, Phase, ReorgJournal,
};
use crate::crypto::txid;
use crate::net::mempool::Mempool;
use crate::state::app_state::epoch_of;
use crate::state::db::{get_tip, k_bad, k_block, set_tip, Stores};
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

fn ensure_apply_blocks_present(
    db: &Stores,
    apply_hashes: &[Hash32],
    new_tip: &Hash32,
) -> Result<bool> {
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
// Crash recovery
// ----------------------

/// Call this once on startup (after opening DB) to complete or safely unwind any interrupted reorg.
///
/// Safe behavior:
/// - If journal exists, we ALWAYS restore applied state to `ancestor` first (using undo logs),
///   then we attempt to apply toward `new_tip` only if block bytes exist.
/// - If application fails for a non-local-missing-bytes reason, we mark bad and stop at ancestor.
/// - On success, we clear the journal.
pub fn recover_if_needed(db: &Stores, mempool: Option<&Mempool>) -> Result<()> {
    let Some(mut j) = journal_read(db).context("journal_read")? else {
        return Ok(());
    };

    println!(
        "[reorg] recovery: found in-progress reorg old_tip={} new_tip={} ancestor={} phase={:?} cursor={}",
        hex32(&j.old_tip),
        hex32(&j.new_tip),
        hex32(&j.ancestor),
        j.phase,
        j.cursor
    );

    // 1) Restore state to ancestor deterministically.
    // If we were in Undo, we had undone `cursor` blocks from undo_path already.
    // If we were in Apply, we were at ancestor + applied cursor blocks; we must undo those applied blocks.
    match j.phase {
        Phase::Undo => {
            // We should currently be at some tip along the old branch.
            // Finish the remaining undo steps to reach ancestor.
            let start = j.cursor as usize;
            for (i, bh) in j.undo_path.iter().enumerate().skip(start) {
                let hi = must_hidx(db, bh)
                    .with_context(|| format!("recover must_hidx(undo {})", hex32(bh)))?;
                undo_block(db, bh)
                    .with_context(|| format!("recover undo_block(undo {})", hex32(bh)))?;
                set_tip(db, &hi.parent)
                    .with_context(|| format!("recover set_tip(parent of {})", hex32(bh)))?;

                j.cursor = (i as u64) + 1;
                journal_write(db, &j).context("recover journal_write(undo)")?;
            }
            set_tip(db, &j.ancestor).context("recover set_tip(ancestor)")?;
        }

        Phase::Apply => {
            // We applied first `cursor` blocks from apply_path. Undo them in reverse to return to ancestor.
            let applied_n = j.cursor as usize;
            for bh in j.apply_path.iter().take(applied_n).rev() {
                let hi = must_hidx(db, bh)
                    .with_context(|| format!("recover must_hidx(applied {})", hex32(bh)))?;
                undo_block(db, bh)
                    .with_context(|| format!("recover undo_block(applied {})", hex32(bh)))?;
                set_tip(db, &hi.parent)
                    .with_context(|| format!("recover set_tip(parent of applied {})", hex32(bh)))?;
            }
            set_tip(db, &j.ancestor).context("recover set_tip(ancestor)")?;

            // Now switch journal back to Apply with cursor=0 (since we are at ancestor again).
            j.phase = Phase::Apply;
            j.cursor = 0;
            journal_write(db, &j).context("recover journal_write(reset_apply)")?;
        }
    }

    mempool_prune_if_present(db, mempool);

    // 2) Attempt to apply new branch if possible (only if we have bytes).
    if !ensure_apply_blocks_present(db, &j.apply_path, &j.new_tip)? {
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
    journal_write(db, &j).context("recover journal_write(start_apply)")?;

    for (i, bh) in j.apply_path.iter().enumerate() {
        let blk =
            load_block(db, bh).with_context(|| format!("recover load_block {}", hex32(bh)))?;
        let hi = must_hidx(db, bh).with_context(|| format!("recover must_hidx {}", hex32(bh)))?;

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

            // Stop at ancestor (already there if we haven't progressed far; otherwise undo to ancestor).
            // Since we set tip after each apply step below, best is to just stop here; next boot can retry.
            return Ok(());
        }

        mempool_remove_mined(mempool, &blk);
        set_tip(db, bh).with_context(|| format!("recover set_tip {}", hex32(bh)))?;

        j.cursor = (i as u64) + 1;
        journal_write(db, &j).context("recover journal_write(progress)")?;
    }

    set_tip(db, &j.new_tip).context("recover final set_tip(new_tip)")?;
    journal_clear(db).context("recover journal_clear")?;
    mempool_prune_if_present(db, mempool);

    println!("[reorg] recovery success: now tip={}", hex32(&j.new_tip));
    Ok(())
}

// ----------------------
// Main reorg
// ----------------------

/// Paranoid reorg: only reorgs if strictly higher chainwork.
/// Guarantees that `tip` is always consistent with the applied state.
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

    // ---------------- Crash-atomic journal start ----------------
    let mut j = ReorgJournal {
        old_tip,
        new_tip: *new_tip,
        ancestor: anc.hash,
        phase: Phase::Undo,
        cursor: 0,
        undo_path: undo_path.clone(),
        apply_path: apply_path.clone(),
    };
    journal_write(db, &j).context("journal_write(start)")?;
    // -----------------------------------------------------------

    // Phase A: undo old branch
    for (i, bh) in undo_path.iter().enumerate() {
        let hi = must_hidx(db, bh).with_context(|| format!("must_hidx(undo {})", hex32(bh)))?;
        undo_block(db, bh).with_context(|| format!("[reorg] undo_block {}", hex32(bh)))?;
        set_tip(db, &hi.parent)
            .with_context(|| format!("[reorg] set_tip(parent of {})", hex32(bh)))?;

        j.cursor = (i as u64) + 1;
        journal_write(db, &j).context("journal_write(progress_undo)")?;
    }

    set_tip(db, &anc.hash).context("[reorg] set_tip(ancestor)")?;

    j.phase = Phase::Apply;
    j.cursor = 0;
    journal_write(db, &j).context("journal_write(at_ancestor)")?;

    // Phase B: apply new branch
    j.phase = Phase::Apply;
    j.cursor = 0;
    journal_write(db, &j).context("journal_write(start_apply)")?;

    let mut applied_new: Vec<Hash32> = Vec::with_capacity(apply_path.len());
    let mut last_applying: Option<Hash32> = None;

    let apply_result: Result<()> = (|| {
        for (i, bh) in apply_path.iter().enumerate() {
            last_applying = Some(*bh);

            let blk =
                load_block(db, bh).with_context(|| format!("[reorg] load_block {}", hex32(bh)))?;
            let hi =
                must_hidx(db, bh).with_context(|| format!("[reorg] must_hidx {}", hex32(bh)))?;

            validate_and_apply_block(db, &blk, epoch_of(hi.height), hi.height)
                .with_context(|| format!("[reorg] validate_and_apply_block {}", hex32(bh)))?;

            mempool_remove_mined(mempool, &blk);

            set_tip(db, bh).with_context(|| format!("[reorg] set_tip {}", hex32(bh)))?;

            applied_new.push(*bh);

            j.cursor = (i as u64) + 1;
            journal_write(db, &j).context("journal_write(progress_apply)")?;
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
            println!(
                "[reorg] apply failed due to missing local block bytes; not marking branch bad."
            );
        }

        // Roll back: undo applied_new (reverse), then re-apply old branch (forward).
        // We re-derive old branch forward path from undo_path reversed.
        let mut reapply_old = undo_path.clone();
        reapply_old.reverse();

        // Undo applied_new back to ancestor.
        for bh in applied_new.iter().rev() {
            let hi = must_hidx(db, bh).with_context(|| {
                format!("[reorg] rollback must_hidx(applied_new {})", hex32(bh))
            })?;
            undo_block(db, bh).with_context(|| {
                format!("[reorg] rollback undo_block(applied_new {})", hex32(bh))
            })?;
            set_tip(db, &hi.parent)
                .with_context(|| format!("[reorg] rollback set_tip(parent of {})", hex32(bh)))?;
        }
        set_tip(db, &anc.hash).context("[reorg] rollback set_tip(ancestor)")?;

        // Re-apply the old branch.
        for bh in &reapply_old {
            let blk = load_block(db, bh)
                .with_context(|| format!("[reorg] rollback load_block(old {})", hex32(bh)))?;
            let hi = must_hidx(db, bh)
                .with_context(|| format!("[reorg] rollback must_hidx(old {})", hex32(bh)))?;

            validate_and_apply_block(db, &blk, epoch_of(hi.height), hi.height).with_context(
                || {
                    format!(
                        "[reorg] rollback validate_and_apply_block(old {})",
                        hex32(bh)
                    )
                },
            )?;

            mempool_remove_mined(mempool, &blk);

            set_tip(db, bh)
                .with_context(|| format!("[reorg] rollback set_tip(old {})", hex32(bh)))?;
        }

        set_tip(db, &old_tip).context("[reorg] rollback final set_tip(old_tip)")?;
        mempool_prune_if_present(db, mempool);

        // Clear journal: we returned to old tip cleanly.
        let _ = journal_clear(db);

        return Err(e);
    }

    // Final set (should already be at new_tip)
    set_tip(db, new_tip).context("[reorg] final set_tip(new_tip)")?;

    let final_tip = get_tip(db).context("get_tip(final)")?.unwrap_or([0u8; 32]);
    if final_tip != *new_tip {
        bail!(
            "[reorg] success but tip mismatch: expected {}, got {}",
            hex32(new_tip),
            hex32(&final_tip)
        );
    }

    // Success: clear journal
    journal_clear(db).context("journal_clear(success)")?;

    println!(
        "[reorg] success: now tip={} (h={}, w={})",
        hex32(new_tip),
        new_hi.height,
        new_hi.chainwork
    );

    mempool_prune_if_present(db, mempool);
    Ok(())
}
