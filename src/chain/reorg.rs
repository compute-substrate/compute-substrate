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


fn hash_lt(a: &Hash32, b: &Hash32) -> bool {
    // Lexicographic byte compare
    a.as_slice() < b.as_slice()
}

fn better_candidate(cw_a: u128, h_a: u64, hash_a: &Hash32, cw_b: u128, h_b: u64, hash_b: &Hash32) -> bool {
    // true if A is strictly better than B
    if cw_a != cw_b {
        return cw_a > cw_b;
    }
    if h_a != h_b {
        return h_a > h_b;
    }
    // deterministic tie-break: smallest hash wins
    hash_lt(hash_a, hash_b)
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

fn tip_on_journal_path(t: &Hash32, j: &ReorgJournal) -> bool {
    *t == j.old_tip
        || *t == j.ancestor
        || *t == j.new_tip
        || j.undo_path.iter().any(|h| h == t)
        || j.apply_path.iter().any(|h| h == t)
}

/// Cursor semantics: number of steps already completed (next index).
fn expected_tip_from_journal(db: &Stores, j: &ReorgJournal) -> Result<Hash32> {
    match j.phase {
        Phase::Undo => {
            if j.cursor == 0 {
                Ok(j.old_tip)
            } else {
                let idx = (j.cursor - 1) as usize;
                if idx >= j.undo_path.len() {
                    bail!(
                        "expected_tip_from_journal: undo cursor out of range cursor={} len={}",
                        j.cursor,
                        j.undo_path.len()
                    );
                }
                let bh = j.undo_path[idx];
                let p = parent_of(db, &bh)
                    .with_context(|| format!("expected_tip_from_journal parent_of(undo[{}])", idx))?;
                Ok(p) // when idx==last, this should be ancestor
            }
        }
        Phase::Apply => {
            if j.cursor == 0 {
                Ok(j.ancestor)
            } else {
                let idx = (j.cursor - 1) as usize;
                if idx >= j.apply_path.len() {
                    bail!(
                        "expected_tip_from_journal: apply cursor out of range cursor={} len={}",
                        j.cursor,
                        j.apply_path.len()
                    );
                }
                Ok(j.apply_path[idx])
            }
        }
    }
}

/// Given a durable tip, infer what (phase,cursor) that tip corresponds to within this journal.
/// Returns None if tip is not on the journal path.
fn infer_phase_cursor_from_tip(
    db: &Stores,
    j: &ReorgJournal,
    tip: &Hash32,
) -> Result<Option<(Phase, u64)>> {
    if *tip == j.old_tip {
        return Ok(Some((Phase::Undo, 0)));
    }
    if *tip == j.ancestor {
        return Ok(Some((Phase::Apply, 0)));
    }

    // Undo: after i+1 undos, tip == parent(undo_path[i])
    for (i, bh) in j.undo_path.iter().enumerate() {
        let p = parent_of(db, bh)
            .with_context(|| format!("infer_phase_cursor_from_tip parent_of(undo[{}])", i))?;
        if &p == tip {
            return Ok(Some((Phase::Undo, (i as u64) + 1)));
        }
    }

    // Apply: after i+1 applies, tip == apply_path[i]
    for (i, bh) in j.apply_path.iter().enumerate() {
        if bh == tip {
            return Ok(Some((Phase::Apply, (i as u64) + 1)));
        }
    }

    Ok(None)
}

/// Resume tip choice:
/// Always trust the journal's (phase,cursor) semantics.
/// meta_tip can be ahead/behind due to crash timing; journal is the intent log.
fn choose_resume_tip(db: &Stores, j: &ReorgJournal) -> Result<Hash32> {
    expected_tip_from_journal(db, j)
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

fn chain_to_tip_safe(db: &Stores, tip: &Hash32) -> Result<Vec<Hash32>> {
    // Try hdr chain first, but only accept it if ALL block bytes exist.
    if let Ok(chain) = chain_to_tip_from_hdr(db, tip) {
        let mut missing = false;
        for bh in &chain {
            if db.blocks.get(k_block(bh))?.is_none() {
                missing = true;
                break;
            }
        }
        if !missing {
            return Ok(chain);
        }
    }

    // Fallback: block-prev chain
    chain_to_tip_from_blocks(db, tip)
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

        // parent must exist to be rebuildable
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
                if better_candidate(cw, height, &h, bcw, bhgt, &bh) {
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
                if better_candidate(hi.chainwork, hi.height, &hi.hash, cur.chainwork, cur.height, &cur.hash) {
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
                if better_candidate(hi.chainwork, hi.height, &hi.hash, cur.chainwork, cur.height, &cur.hash) {
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

/// Pre-tip check (NOT a flush):
/// Ensures the block bytes for `bh` exist before allowing meta:tip to point to it.
///
/// NOTE: Durability is provided by the caller's subsequent single flush barrier
/// which now commits: (state + tip + journal) together.
fn pre_tip_fence(db: &Stores, bh: &Hash32) -> Result<()> {
    if db.blocks.get(k_block(bh))?.is_none() {
        bail!("pre_tip_fence: missing block bytes for {}", hex32(bh));
    }
    Ok(())
}

/// Set tip with a presence check, but do NOT flush.
/// Callers decide the correct commit point (often: after journal_write()).
fn set_tip_checked(db: &Stores, h: &Hash32, ctx: &'static str) -> Result<()> {
    pre_tip_fence(db, h).with_context(|| format!("{ctx}: pre_tip_fence"))?;
    set_tip(db, h).with_context(|| format!("{ctx}: set_tip {}", hex32(h)))?;
    Ok(())
}

// Tip helpers
fn tip_is(db: &Stores, h: &Hash32) -> Result<bool> {
    Ok(get_tip(db)?.map(|t| t == *h).unwrap_or(false))
}

fn current_tip(db: &Stores) -> Result<Option<Hash32>> {
    get_tip(db).context("get_tip")
}

// Journal helper (NO FLUSH here anymore)
fn jw(db: &Stores, j: &mut ReorgJournal, ctx: &'static str) -> Result<()> {
    journal_write(db, j).context(ctx)?;
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
    if j.undo_path.iter().any(|h| h == t) {
        return true;
    }
    if j.apply_path.iter().any(|h| h == t) {
        return true;
    }

    false
}

// ----------------------
// Parent resolution (hdr-or-block)
// ----------------------

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

        set_tip(db, &p)
            .with_context(|| format!("drive_tip_down_to set_tip(parent of {})", hex32(&tip)))?;
        flush_state_step(db)
            .with_context(|| format!("drive_tip_down_to flush_state_step(set parent of {})", hex32(&tip)))?;
    }
}

// -------- rebuild helpers --------

fn chain_to_tip_from_hdr(db: &Stores, tip: &Hash32) -> Result<Vec<Hash32>> {
    let mut chain: Vec<Hash32> = Vec::new();
    let mut cur = must_hidx(db, tip).context("chain_to_tip_from_hdr must_hidx(tip)")?;
    loop {
        chain.push(cur.hash);
        if cur.height == 0 {
            break;
        }
        cur = must_hidx(db, &cur.parent).with_context(|| {
            format!(
                "chain_to_tip_from_hdr must_hidx(parent of {})",
                hex32(&cur.hash)
            )
        })?;
    }
    chain.reverse();
    Ok(chain)
}

fn chain_to_tip_from_blocks(db: &Stores, tip: &Hash32) -> Result<Vec<Hash32>> {
    let mut chain: Vec<Hash32> = Vec::new();
    let mut cur = *tip;

    loop {
        chain.push(cur);

        let blk =
            load_block(db, &cur).with_context(|| format!("chain_to_tip_from_blocks load {}", hex32(&cur)))?;
        let p = blk.header.prev;

        if p == [0u8; 32] {
            break;
        }
        cur = p;
    }

    chain.reverse();
    Ok(chain)
}

fn can_rebuild_to_tip(db: &Stores, tip: &Hash32) -> Result<bool> {
    if let Ok(chain) = chain_to_tip_from_hdr(db, tip) {
        let mut missing = false;
        for bh in &chain {
            if db.blocks.get(k_block(bh))?.is_none() {
                missing = true;
                break;
            }
        }
        if !missing {
            return Ok(true);
        }
    }

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

    let chain = chain_to_tip_safe(db, target_tip)
        .with_context(|| format!("rebuild chain_to_tip_safe {}", hex32(target_tip)))?;

    db.utxo.clear().context("rebuild utxo.clear")?;
    db.utxo_meta.clear().context("rebuild utxo_meta.clear")?;
    db.undo.clear().context("rebuild undo.clear")?;
    db.app.clear().context("rebuild app.clear")?;
    flush_state_step(db).context("rebuild flush after clears")?;

    for (i, bh) in chain.iter().enumerate() {
        let blk = load_block(db, bh).with_context(|| format!("rebuild load_block {}", hex32(bh)))?;

        let height = i as u64;

        validate_and_apply_block(db, &blk, epoch_of(height), height)
            .with_context(|| format!("rebuild validate_and_apply_block {}", hex32(bh)))?;

        mempool_remove_mined(mempool, &blk);

        // No journal during rebuild: commit each step with a flush.
        set_tip_checked(db, bh, "rebuild")?;
        flush_state_step(db).context("rebuild flush_state_step")?;
    }

    Ok(())
}

fn pick_best_rebuildable_tip(db: &Stores) -> Result<Option<(Hash32, u64, u128, &'static str)>> {
    let meta_tip = get_tip(db).ok().flatten();
    let hdr_best = best_header_tip(db).ok().flatten();
    let blocks_best = best_tip_from_blocks_only(db).context("pick_best best_tip_from_blocks_only")?;

    let mut best: Option<(Hash32, u64, u128, &'static str)> = None;

    // helper closure to consider a candidate
    let mut consider = |h: Hash32, height: u64, cw: u128, tag: &'static str| {
        best = match best {
            None => Some((h, height, cw, tag)),
            Some((bh, bhgt, bcw, btag)) => {
                if better_candidate(cw, height, &h, bcw, bhgt, &bh) {
                    Some((h, height, cw, tag))
                } else {
                    Some((bh, bhgt, bcw, btag))
                }
            }
        };
    };

    // 1) meta_tip (only if it has a header index we can score, AND is rebuildable)
    if let Some(t) = meta_tip {
        if can_rebuild_to_tip(db, &t).unwrap_or(false) {
            if let Ok(Some(hi)) = get_hidx(db, &t) {
                consider(hi.hash, hi.height, hi.chainwork, "meta_tip");
            }
        }
    }

    // 2) hdr_best
    if let Some(hi) = hdr_best {
        if can_rebuild_to_tip(db, &hi.hash).unwrap_or(false) {
            consider(hi.hash, hi.height, hi.chainwork, "hdr_best");
        }
    }

    // 3) blocks-only best
    if let Some((h, height, cw)) = blocks_best {
        if can_rebuild_to_tip(db, &h).unwrap_or(false) {
            consider(h, height, cw, "blocks_only_best");
        }
    }

    Ok(best)
}



// ----------------------
// Crash recovery
// ----------------------

pub fn recover_if_needed(db: &Stores, mempool: Option<&Mempool>) -> Result<()> {
    eprintln!("[reorg] ENTER recover_if_needed");

    let j_opt = journal_read(db).context("journal_read")?;

// ------------------------------
// JOURNAL-PRESENT RECOVERY
// ------------------------------
if let Some(mut j) = j_opt {
    eprintln!("[reorg] ENTER journal-present recovery branch");

    // 0) Structural sanity. If corrupt, clear and fall through to journal-less.
    if !journal_structurally_plausible(&j) {
        println!("[reorg] recovery: journal corrupted; clearing and falling back");
        journal_clear(db).ok();
        flush_state_step(db).ok();
        mempool_prune_if_present(db, mempool);
    } else {
        // 1) ALIGNMENT CHECK (the "new logic"):
        // The durable meta_tip must correspond to the journal's (phase,cursor) semantics.
        // If not, the journal is unsafe to replay -> clear and fall through to journal-less.
        let meta_tip_opt = get_tip(db).context("recover get_tip(meta_tip)")?;

        let mut aligned = true;

        if let Some(mt) = meta_tip_opt {
            if let Some((ph, cur)) = infer_phase_cursor_from_tip(db, &j, &mt)? {
                if ph != j.phase || cur != j.cursor {
                    aligned = false;
                    println!(
                        "[reorg] recovery: journal disagrees with durable tip {}; clearing journal (journal phase={:?} cursor={}, inferred phase={:?} cursor={})",
                        hex32(&mt),
                        j.phase,
                        j.cursor,
                        ph,
                        cur
                    );
                }
            } else {
                aligned = false;
                println!(
                    "[reorg] recovery: durable tip {} not on journal path; clearing journal",
                    hex32(&mt)
                );
            }
        } else {
            aligned = false;
            println!("[reorg] recovery: meta_tip=None with journal present; clearing journal");
        }

        if !aligned {
            journal_clear(db).ok();
            flush_state_step(db).ok();
            mempool_prune_if_present(db, mempool);
            // fall through to journal-less recovery
        } else {
            // ------------------------------
            // ALIGNED: continue with your existing journal replay logic
            // ------------------------------

            // 2) If already at new_tip, clear stale journal
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

            // 3) Rebuild to expected tip implied by (phase,cursor)
            let resume_tip = expected_tip_from_journal(db, &j).context("expected_tip_from_journal")?;
            println!(
                "[reorg] recovery(journal): resume_tip={} (phase={:?} cursor={})",
                hex32(&resume_tip),
                j.phase,
                j.cursor
            );

            if can_rebuild_to_tip(db, &resume_tip).context("recover can_rebuild_to_tip(resume_tip)")? {
                rebuild_state_to_tip(db, &resume_tip, mempool)
                    .context("recover rebuild_state_to_tip(resume_tip)")?;
            } else if can_rebuild_to_tip(db, &j.ancestor).unwrap_or(false) {
                rebuild_state_to_tip(db, &j.ancestor, mempool)
                    .context("recover rebuild_state_to_tip(ancestor fallback)")?;
                j.phase = Phase::Apply;
                j.cursor = 0;
                jw(db, &mut j, "recover journal_write(force_apply_at_ancestor)")?;
                flush_state_step(db).context("recover flush(force_apply_at_ancestor)")?;
            } else if can_rebuild_to_tip(db, &j.old_tip).unwrap_or(false) {
                rebuild_state_to_tip(db, &j.old_tip, mempool)
                    .context("recover rebuild_state_to_tip(old_tip fallback)")?;
                j.phase = Phase::Undo;
                j.cursor = 0;
                jw(db, &mut j, "recover journal_write(force_undo_at_old_tip)")?;
                flush_state_step(db).context("recover flush(force_undo_at_old_tip)")?;
            } else {
                println!(
                    "[reorg] recovery(journal): cannot rebuild to resume/ancestor/old_tip; clearing journal and falling back"
                );
                journal_clear(db).ok();
                flush_state_step(db).ok();
                mempool_prune_if_present(db, mempool);
                // fall through to journal-less recovery
            }



            // If we got here with j still present, continue with your existing replay code:
            // --- UNDO remainder ---
            if matches!(j.phase, Phase::Undo) {
                for i in (j.cursor as usize)..j.undo_path.len() {
                    let bh = j.undo_path[i];

                    if !tip_is(db, &bh)? {
                        if can_rebuild_to_tip(db, &bh).unwrap_or(false) {
                            rebuild_state_to_tip(db, &bh, mempool)
                                .with_context(|| format!("recover rebuild to undo bh {}", hex32(&bh)))?;
                        } else {
                            bail!("recover undo: cannot rebuild to undo bh {}", hex32(&bh));
                        }
                    }

                    undo_block_idempotent(db, &bh)
                        .with_context(|| format!("recover undo_block_idempotent {}", hex32(&bh)))?;

                    let p = parent_of(db, &bh)
                        .with_context(|| format!("recover undo parent_of {}", hex32(&bh)))?;

                    set_tip(db, &p).with_context(|| format!("recover set_tip(parent of {})", hex32(&bh)))?;

                    j.cursor = (i as u64) + 1;
                    jw(db, &mut j, "recover journal_write(progress_undo)")?;

                    flush_state_step(db).context("recover flush_state_step(undo + journal)")?;
                }

                if !tip_is(db, &j.ancestor)? {
                    set_tip(db, &j.ancestor).context("recover set_tip(ancestor after undo)")?;
                    flush_state_step(db).context("recover flush_state_step(set ancestor)")?;
                }

                j.phase = Phase::Apply;
                j.cursor = 0;
                jw(db, &mut j, "recover journal_write(start_apply)")?;
                flush_state_step(db).context("recover flush(start_apply)")?;
            }

            // --- APPLY remainder ---
            if !ensure_apply_blocks_present(db, &j.apply_path, &j.new_tip)? {
                println!(
                    "[reorg] recovery: missing block bytes for apply path; leaving journal in-place (tip={})",
                    fmt_opt32(get_tip(db).ok().flatten())
                );
                mempool_prune_if_present(db, mempool);
                return Ok(());
            }

            for i in (j.cursor as usize)..j.apply_path.len() {
                let bh = j.apply_path[i];

                if tip_is(db, &bh)? {
                    j.cursor = (i as u64) + 1;
                    jw(db, &mut j, "recover journal_write(skip_apply)")?;
                    flush_state_step(db).context("recover flush(skip_apply)")?;
                    continue;
                }

                let blk = load_block(db, &bh).with_context(|| format!("recover load_block {}", hex32(&bh)))?;
                let height = if let Ok(Some(hi)) = get_hidx(db, &bh) {
                    hi.height
                } else {
                    (chain_to_tip_from_blocks(db, &bh)?.len().saturating_sub(1)) as u64
                };

                validate_and_apply_block(db, &blk, epoch_of(height), height)
                    .with_context(|| format!("recover validate_and_apply_block {}", hex32(&bh)))?;

                mempool_remove_mined(mempool, &blk);

                set_tip_checked(db, &bh, "recover apply")?;

                j.cursor = (i as u64) + 1;
                jw(db, &mut j, "recover journal_write(progress_apply)")?;

                flush_state_step(db).context("recover flush_state_step(apply + journal)")?;
            }

            if !tip_is(db, &j.new_tip)? {
                set_tip_checked(db, &j.new_tip, "recover final new_tip")?;
                flush_state_step(db).context("recover flush(final new_tip)")?;
            }

            journal_clear(db).context("recover journal_clear")?;
            flush_state_step(db).context("recover flush after journal_clear")?;
            mempool_prune_if_present(db, mempool);

            println!("[reorg] recovery success: now tip={}", hex32(&j.new_tip));
            return Ok(());
        }
    }
}

// ------------------------------
// JOURNAL-LESS RECOVERY
// ------------------------------
eprintln!("[reorg] ENTER journal-less recovery branch");
println!("[reorg] recovery(journal-less): selecting canonical tip");

let meta_tip = get_tip(db).ok().flatten();
println!("[reorg] journal-less: meta_tip={}", fmt_opt32(meta_tip));

match pick_best_rebuildable_tip(db).context("journal-less pick_best_rebuildable_tip")? {
    Some((h, height, cw, tag)) => {
        println!(
            "[reorg] journal-less: selected {} tip={} (h={}, w={})",
            tag,
            hex32(&h),
            height,
            cw
        );

        rebuild_state_to_tip(db, &h, mempool)
            .with_context(|| format!("journal-less rebuild_state_to_tip({})", tag))?;
        flush_state_step(db).ok();
    }
    None => {
        println!("[reorg] journal-less: no rebuildable candidate tip found");
    }
}

mempool_prune_if_present(db, mempool);
Ok(())

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

    // Journal start is committed with a flush
    jw(db, &mut j, "journal_write(start)")?;
    flush_state_step(db).context("flush(journal start)")?;
    failpoints::hit("reorg:after_journal_start");

    // ----------------------
    // UNDO: state+tip, then journal, then ONE flush
    // ----------------------
    for (i, bh) in undo_path.iter().enumerate() {
        failpoints::hit(&format!("undo:{}:pre", i));

        let hi = must_hidx(db, bh).with_context(|| format!("must_hidx(undo {})", hex32(bh)))?;

        undo_block_idempotent(db, bh).with_context(|| format!("[reorg] undo_block {}", hex32(bh)))?;

        // set tip (no flush yet)
        set_tip(db, &hi.parent)
            .with_context(|| format!("[reorg] set_tip(parent of {})", hex32(bh)))?;

        // journal progress (no flush yet)
        j.cursor = (i as u64) + 1;
        jw(db, &mut j, "journal_write(progress_undo)")?;

        // single durability barrier commits both state+tip+journal
        flush_state_step(db).context("flush_state_step(undo + journal)")?;

        failpoints::hit(&format!("undo:{}:post_journal", i));
    }

    // land at ancestor (commit)
    set_tip(db, &anc.hash).context("[reorg] set_tip(ancestor)")?;
    flush_state_step(db).context("flush_state_step(set ancestor)")?;
    failpoints::hit("reorg:at_ancestor_post_flush");

    // transition to apply (journal + flush)
    j.phase = Phase::Apply;
    j.cursor = 0;
    jw(db, &mut j, "journal_write(start_apply)")?;
    flush_state_step(db).context("flush(start_apply)")?;
    failpoints::hit("reorg:after_apply_start");

    let mut applied_new: Vec<Hash32> = Vec::with_capacity(apply_path.len());
    let mut last_applying: Option<Hash32> = None;

    // ----------------------
    // APPLY: state, tip, journal, ONE flush
    // ----------------------
    let apply_result: Result<()> = (|| {
        for (i, bh) in apply_path.iter().enumerate() {
            failpoints::hit(&format!("apply:{}:pre", i));
            last_applying = Some(*bh);

            let blk =
                load_block(db, bh).with_context(|| format!("[reorg] load_block {}", hex32(bh)))?;
            let hi = must_hidx(db, bh).with_context(|| format!("[reorg] must_hidx {}", hex32(bh)))?;

            validate_and_apply_block(db, &blk, epoch_of(hi.height), hi.height)
                .with_context(|| format!("[reorg] validate_and_apply_block {}", hex32(bh)))?;

            mempool_remove_mined(mempool, &blk);

            // allow tip to point here (presence check)
            set_tip_checked(db, bh, "apply")?;

            applied_new.push(*bh);

            // journal progress
            j.cursor = (i as u64) + 1;
            jw(db, &mut j, "journal_write(progress_apply)")?;

            // single durability barrier commits both
            flush_state_step(db).context("flush_state_step(apply + journal)")?;

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

        // Roll back applied_new (each undo commits with a flush; journal is still "apply" in progress)
        for bh in applied_new.iter().rev() {
            let p = parent_of(db, bh)
                .with_context(|| format!("[reorg] rollback parent_of(applied_new {})", hex32(bh)))?;
            undo_block_idempotent(db, bh)
                .with_context(|| format!("[reorg] rollback undo_block(applied_new {})", hex32(bh)))?;
            set_tip(db, &p)
                .with_context(|| format!("[reorg] rollback set_tip(parent of {})", hex32(bh)))?;
            flush_state_step(db).context("rollback flush_state_step(undo applied_new)")?;
        }

        set_tip(db, &anc.hash).context("[reorg] rollback set_tip(ancestor)")?;
        flush_state_step(db).context("rollback flush_state_step(set ancestor)")?;

        let mut reapply_old = undo_path.clone();
        reapply_old.reverse();

        // Reapply old chain (commit each block)
        for (i, bh) in reapply_old.iter().enumerate() {
            let blk =
                load_block(db, bh).with_context(|| format!("[reorg] rollback load_block(old {})", hex32(bh)))?;
            let hi = must_hidx(db, bh).with_context(|| format!("[reorg] rollback must_hidx(old {})", hex32(bh)))?;

            validate_and_apply_block(db, &blk, epoch_of(hi.height), hi.height)
                .with_context(|| format!("[reorg] rollback validate_and_apply_block(old {})", hex32(bh)))?;

            mempool_remove_mined(mempool, &blk);

            set_tip_checked(db, bh, "rollback reapply_old")?;
            flush_state_step(db).with_context(|| format!("rollback flush_state_step(reapply_old {})", i))?;
        }

        set_tip(db, &old_tip).context("[reorg] rollback final set_tip(old_tip)")?;
        flush_state_step(db).context("rollback flush_state_step(final set old_tip)")?;

        mempool_prune_if_present(db, mempool);

        let _ = journal_clear(db);
        let _ = flush_state_step(db);

        return Err(e);
    }

    // Finalize: tip to new_tip, then clear journal, committing both
    set_tip_checked(db, new_tip, "final new_tip")?;
    journal_clear(db).context("journal_clear(success)")?;
    flush_state_step(db).context("flush(final tip + journal_clear)")?;

    let final_tip = get_tip(db).context("get_tip(final)")?.unwrap_or([0u8; 32]);
    if final_tip != *new_tip {
        bail!(
            "[reorg] success but tip mismatch: expected {}, got {}",
            hex32(new_tip),
            hex32(&final_tip)
        );
    }

    println!(
        "[reorg] success: now tip={} (h={}, w={})",
        hex32(new_tip),
        new_hi.height,
        new_hi.chainwork
    );

    mempool_prune_if_present(db, mempool);
    Ok(())
}
}
