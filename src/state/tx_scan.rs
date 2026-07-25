// src/state/tx_scan.rs
//
// Transaction lookup: an honest scan, and a background index that makes it cheap.
//
// Two halves.
//
// The scan. `find_tx_in_chain` is the tip-to-genesis back-walk that used to live inline in the
// API's `tx_get` and `tx_proof_get`, extracted into a pure function with `max_back` as a
// parameter and a four-way `ScanOutcome`. The walk can terminate four ways: it reached genesis
// without finding the transaction, it ran out of budget, a block body was missing, or a body
// failed to decode. Only the first proves the transaction is not on the chain. All four used to
// collapse into `{ok:false, err:"not found"}`, so for three of them the node was reporting "no"
// when the truth was "I do not know", and every client built on the API inherited that.
//
// The index. `locate_tx` consults the txid index first, when its completeness marker says the
// index describes the current tip, and falls back to the scan otherwise. `reconcile_tick` and
// `run_reconciler` are the bounded background task that keeps the index converged with the
// canonical chain without hooking the consensus apply path: every index write happens here.
//
// Three rules hold this together. They are worth stating because breaking any one of them turns
// a performance feature into a correctness bug.
//
//   1. No index writes in the apply path. The reconciler observes `meta:tip` after the fact and
//      does every index write itself. A non-blocking wake from the apply path is allowed and is
//      what `set_tip` does, because polling for the tip left the index stale for about 1.45 s
//      after every block, which is exactly when a client polls for the transaction that just
//      confirmed. Do not turn that wake into a write.
//   2. Always unindex-then-index on a reorg. The other order deletes a txid that is present in
//      both the disconnected and the reconnected block.
//   3. An index miss is never authoritative unless the marker equals the current tip and the
//      format version matches. On a stale marker, fall back to the scan and report its honest
//      Horizon or Incomplete outcome rather than a confident absence.

use anyhow::{bail, Context, Result};
use std::collections::HashSet;
use std::sync::Arc;

use crate::chain::index::get_hidx;
use crate::crypto::txid;
use crate::state::db::{get_tip, k_block, meta_del, Stores};
use crate::state::tx_index::{
    get_tx_locator, index_canonical_block, unindex_canonical_block, TxLocator,
};
use crate::types::{Block, Hash32};

fn c() -> crate::codec::ConsensusBincode {
    crate::codec::consensus_bincode()
}

// -----------------------------------------------------------------------------
// The pure scan
// -----------------------------------------------------------------------------

/// Outcome of a bounded canonical-chain back-walk for a txid.
/// Only `Absent` proves absence; everything else is an honest "cannot say".
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ScanOutcome {
    /// The tx was located in a canonical block within the scan budget.
    Found {
        block_hash: Hash32,
        height: u64,
        index_in_block: usize,
    },
    /// The walk reached genesis without a hit: absence is PROVED over the whole chain.
    Absent { scanned: u64 },
    /// The scan budget ran out before genesis: absence is NOT proved.
    /// `stopped_at_height` is the height of the first block the walk did NOT examine.
    Horizon { scanned: u64, stopped_at_height: u64 },
    /// The walk could not continue (missing block body, undecodable body, or a traversal
    /// defect) at block `at`. Absence is NOT proved.
    Incomplete { at: Hash32, why: &'static str },
}

/// `why` values used by `Incomplete` (the API maps these to wire codes).
pub const WHY_MISSING_BODY: &str = "missing-block-body";
pub const WHY_DECODE: &str = "decode-failed";
pub const WHY_LOOP: &str = "traversal-loop";
pub const WHY_HEIGHT_UNDERFLOW: &str = "height-underflow";
pub const WHY_NO_TIP: &str = "no-chain-tip";

/// Walk the canonical chain backwards from the tip looking for `want`, examining at most
/// `max_back` blocks. Pure with respect to the db: read-only, no index consultation.
///
/// Termination mapping, which is the whole point of this type:
/// - hit                                      -> Found
/// - genesis reached (header.prev == 0x00*32) -> Absent   (proved over the whole chain)
/// - budget exhausted                         -> Horizon  (NOT proved)
/// - body missing / undecodable / defect      -> Incomplete (NOT proved)
pub fn find_tx_in_chain(db: &Stores, want: &Hash32, max_back: u64) -> ScanOutcome {
    let Ok(Some(tip)) = get_tip(db) else {
        // No tip at all: nothing is provable. The pre-0.1.6 code walked a zero hash into a
        // missing-body break and answered "not found"; that was one of the confident lies.
        return ScanOutcome::Incomplete {
            at: [0u8; 32],
            why: WHY_NO_TIP,
        };
    };

    let tip_height = match get_hidx(db, &tip) {
        Ok(Some(hi)) => hi.height,
        _ => 0, // matches the historical zero_hidx fallback; the walk still terminates honestly
    };

    let mut cur_hash = tip;
    let mut cur_height = tip_height;
    let mut scanned: u64 = 0;
    let mut seen = HashSet::<Hash32>::new();

    while scanned < max_back {
        if !seen.insert(cur_hash) {
            return ScanOutcome::Incomplete {
                at: cur_hash,
                why: WHY_LOOP,
            };
        }

        let body = match db.blocks.get(k_block(&cur_hash)) {
            Ok(Some(v)) => v,
            _ => {
                return ScanOutcome::Incomplete {
                    at: cur_hash,
                    why: WHY_MISSING_BODY,
                }
            }
        };

        let blk: Block = match c().deserialize(&body) {
            Ok(b) => b,
            Err(_) => {
                return ScanOutcome::Incomplete {
                    at: cur_hash,
                    why: WHY_DECODE,
                }
            }
        };

        for (i, tx) in blk.txs.iter().enumerate() {
            if txid(tx) == *want {
                return ScanOutcome::Found {
                    block_hash: cur_hash,
                    height: cur_height,
                    index_in_block: i,
                };
            }
        }

        scanned += 1;

        if blk.header.prev == [0u8; 32] {
            // True genesis: every canonical block has been examined.
            return ScanOutcome::Absent { scanned };
        }
        if cur_height == 0 {
            // Height bookkeeping says genesis but the block disagrees: an inconsistent
            // header index, not a proved absence.
            return ScanOutcome::Incomplete {
                at: cur_hash,
                why: WHY_HEIGHT_UNDERFLOW,
            };
        }

        cur_hash = blk.header.prev;
        cur_height -= 1;
    }

    ScanOutcome::Horizon {
        scanned,
        stopped_at_height: cur_height,
    }
}

// -----------------------------------------------------------------------------
// Completeness marker
// -----------------------------------------------------------------------------

/// Bump this when the idx tree layout changes; a mismatch wipes and rebuilds in the background.
///
/// Version 2 moves both markers out of the `meta` tree and into the `idx` tree.
/// `Stores` documents that `Tree::flush()` is not a cross-tree durability fence, so with the
/// marker in `meta` and the data in `idx` there was no guarantee that an unclean shutdown could
/// not leave a marker claiming coverage of a block whose txids never reached disk. A fresh-marker
/// miss for a transaction in that block would then be reported as a PROVED absence, which is the
/// exact confident-lie class the ScanOutcome contract exists to remove. Same-tree markers are
/// written in the same `sled::Batch` as the data they describe, and `Tree::apply_batch` is
/// atomic, so the marker can never be ahead of its data.
pub const IDX_VERSION: &[u8] = b"2";

pub fn k_idx_version() -> &'static [u8] {
    b"idx:version"
}

pub fn k_idx_tip() -> &'static [u8] {
    b"idx:tip_hash"
}

fn idx_version_ok(db: &Stores) -> bool {
    matches!(db.idx.get(k_idx_version()), Ok(Some(v)) if v.as_ref() == IDX_VERSION)
}

/// The last block hash up to which the index is contiguously complete from genesis,
/// or None if the index has never converged (or the version marker is missing/wrong).
pub fn idx_tip(db: &Stores) -> Option<Hash32> {
    if !idx_version_ok(db) {
        return None;
    }
    let v = db.idx.get(k_idx_tip()).ok().flatten()?;
    if v.len() != 32 {
        return None;
    }
    let mut h = [0u8; 32];
    h.copy_from_slice(&v);
    Some(h)
}

/// The tip iff the index marker is fresh at it (`idx:tip_hash == meta:tip`, HARD RULE 3).
/// Returning the validated tip (not just a bool) lets a caller thread ONE atomic tip read
/// through both the freshness decision and any absence-bound derived from it, closing the
/// TOCTOU where a second `get_tip` could observe a newer tip than the one that was validated.
pub fn fresh_tip(db: &Stores) -> Option<Hash32> {
    match (idx_tip(db), get_tip(db)) {
        (Some(i), Ok(Some(t))) if i == t => Some(t),
        _ => None,
    }
}

/// HARD RULE 3: the index speaks with authority only while `idx:tip_hash == meta:tip`.
pub fn idx_fresh(db: &Stores) -> bool {
    fresh_tip(db).is_some()
}

// -----------------------------------------------------------------------------
// Index-first lookup with scan fallback
// -----------------------------------------------------------------------------

/// Resolve `want` via the txid index when the completeness marker is fresh, falling back to
/// the bounded scan otherwise (HARD RULE 3). An index HIT is cross-checked against the block
/// body before it is trusted; any inconsistency degrades to the scan.
pub fn locate_tx(db: &Stores, want: &Hash32, max_back: u64) -> ScanOutcome {
    // Capture the tip that gates the whole index-first decision ONCE. The absence-bound and
    // the post-miss freshness re-check are both derived from THIS binding, never from a fresh
    // `get_tip`, so a tip that advances mid-call cannot produce a false `Absent`.
    if let Some(at_tip) = fresh_tip(db) {
        if let Some(outcome) = resolve_via_index(db, want, at_tip) {
            return outcome;
        }
    }
    find_tx_in_chain(db, want, max_back)
}

/// Index-first resolution pinned to a SPECIFIC tip (`at_tip`, the value `fresh_tip` validated).
/// Returns:
/// - `Some(Found)`  on a locator hit that cross-checks against the block body,
/// - `Some(Absent)` on a miss that is STILL provable at `at_tip` (see the re-check below),
/// - `None`         when the caller must fall back to the scan (index no longer authoritative
///   at `at_tip`, a hit that did not verify, or a read error).
///
/// The re-check is the G14 pre-gate LOW fix: a fresh-index miss is a proved absence over the
/// whole chain ONLY while the marker still points at the exact tip that gated entry AND the
/// tip has not moved (`idx_tip == at_tip && meta:tip == at_tip`). If a new tip block carrying
/// `want` was applied after `fresh_tip` returned, `get_tip` now differs from `at_tip`, so we
/// return `None` and the caller scans the current chain, which correctly returns `Found` for
/// the just-applied tx instead of a confident-lie `Absent`.
pub fn resolve_via_index(db: &Stores, want: &Hash32, at_tip: Hash32) -> Option<ScanOutcome> {
    match crate::state::tx_index::get_tx_entry(db, want) {
        Ok(Some(crate::state::tx_index::TxIndexEntry::Locator(loc))) => {
            verify_locator(db, want, &loc) // Some(Found) or None -> scan
        }
        // More than one block claimed this txid, so the index cannot answer for it. This is a
        // "cannot say", NOT an absence: falling through to the scan is the whole point.
        Ok(Some(crate::state::tx_index::TxIndexEntry::Ambiguous)) => None,
        Ok(None) => {
            if idx_tip(db) == Some(at_tip) && get_tip(db).ok().flatten() == Some(at_tip) {
                let hi = get_hidx(db, &at_tip).ok().flatten()?;
                Some(ScanOutcome::Absent {
                    scanned: hi.height + 1,
                })
            } else {
                None
            }
        }
        Err(_) => None,
    }
}

/// Cross-check an index locator against the actual block body AND against canonicity. Returns
/// Some(Found) only when the height-to-hash entry still names this block, the block exists,
/// decodes, and carries `want` at exactly `index_in_block`.
///
/// The canonicity check is not redundant with the body check. Block bodies are never deleted, so
/// a locator left over from a disconnected block verifies against its body perfectly well; what
/// makes it wrong is that its block is no longer on the chain. Without this, a stale locator
/// would be answered as `Found` with an orphan's block hash, and `/proof/tx/:txid` would build a
/// merkle proof against a header that is not in the canonical chain.
fn verify_locator(db: &Stores, want: &Hash32, loc: &TxLocator) -> Option<ScanOutcome> {
    if crate::state::tx_index::get_block_hash_by_height(db, loc.height)
        .ok()
        .flatten()
        != Some(loc.block_hash)
    {
        return None; // stale locator: its block is not the canonical block at that height
    }
    let v = db.blocks.get(k_block(&loc.block_hash)).ok().flatten()?;
    let blk: Block = c().deserialize(&v).ok()?;
    let tx = blk.txs.get(loc.index_in_block as usize)?;
    if txid(tx) != *want {
        return None;
    }
    Some(ScanOutcome::Found {
        block_hash: loc.block_hash,
        height: loc.height,
        index_in_block: loc.index_in_block as usize,
    })
}

/// Height -> canonical block hash via the index, only when the marker is fresh.
/// Callers keep their own fallback path (the API keeps its uncapped walk: the wallet's
/// documented emergency fallback depends on /block/height/:h answering regardless of index state).
pub fn canonical_hash_at_height(db: &Stores, height: u64) -> Option<Hash32> {
    if !idx_fresh(db) {
        return None;
    }
    crate::state::tx_index::get_block_hash_by_height(db, height)
        .ok()
        .flatten()
}

// -----------------------------------------------------------------------------
// The bounded background reconciler
// -----------------------------------------------------------------------------

/// The work the reconciler has to do to move the index from its current marker to a specific
/// canonical tip, computed ONCE and then consumed a budget at a time.
///
/// The plan used to be recomputed on every tick. Because planning walks the header
/// index from the canonical tip down to the last indexed block, and a tick only applies
/// `RECONCILE_BUDGET_PER_TICK` blocks, building the index from cold cost about `T^2 / (2*budget)`
/// header reads for a chain of height `T`: measured 4.5 minutes at T = 60,450, and growing with
/// the square of the chain. Planning once per tip and consuming the plan makes a cold build
/// linear. A plan is only valid for the tip it was built against (`anchor_tip`); when the tip
/// moves, the plan is discarded and rebuilt, which during a long cold build happens once every
/// ~120s rather than four times a second.
#[derive(Clone, Debug)]
pub struct ReconcilePlan {
    anchor_tip: Hash32,
    /// (height, hash, parent), highest first: applied in this order.
    disconnects: Vec<(u64, Hash32, Hash32)>,
    /// (height, hash), highest first: applied from the BACK, i.e. ascending.
    connects: Vec<(u64, Hash32)>,
    d_done: usize,
    c_done: usize,
    /// Where the completeness marker must be for the NEXT step of this plan to be the right one.
    /// Set to the marker the plan was planned from, then advanced with every applied step.
    ///
    /// This is the safety interlock for reusing a plan across ticks. Consuming a plan against a
    /// marker it did not start from would skip blocks, and a skipped block under a marker that
    /// claims to cover it is exactly the confident-lie class the scan-outcome contract exists to
    /// remove. Tracking the expected position exactly beats inferring it from the vectors.
    expect_marker: Option<Hash32>,
}

impl ReconcilePlan {
    /// The canonical tip this plan was built for. A plan is invalid once the tip moves.
    pub fn anchor_tip(&self) -> Hash32 {
        self.anchor_tip
    }

    /// Blocks still to unindex or index.
    pub fn remaining(&self) -> usize {
        (self.disconnects.len() - self.d_done) + (self.connects.len() - self.c_done)
    }
}

/// Build the disconnect/connect plan that moves `indexed` to `tip`.
///
/// Errors here mean the header index cannot support the walk (a missing ancestor, or two
/// branches that never meet). `run_reconciler` treats that as a corrupt index and resets, rather
/// than retrying the same impossible walk forever.
/// Tag carried by every error `plan_reconcile` can produce, so `run_reconciler` can tell "the
/// index describes a chain we cannot explain" (curable by a rebuild) from "applying the plan
/// failed" (not curable by a rebuild, and made worse by one).
pub const PLANNING_ERROR_TAG: &str = "[idx-plan]";

fn is_planning_error(e: &anyhow::Error) -> bool {
    format!("{e:#}").contains(PLANNING_ERROR_TAG)
}

fn plan_reconcile(db: &Stores, tip: Hash32, indexed: Option<Hash32>) -> Result<ReconcilePlan> {
    let tip_hi = match get_hidx(db, &tip)? {
        Some(hi) => hi,
        None => bail!("{PLANNING_ERROR_TAG} tip header index missing during idx reconcile"),
    };

    let mut disconnects: Vec<(u64, Hash32, Hash32)> = Vec::new();
    let mut connects: Vec<(u64, Hash32)> = Vec::new();

    let parent_of = |h: &Hash32| -> Result<(u64, Hash32)> {
        let hi = get_hidx(db, h)?
            .ok_or_else(|| anyhow::anyhow!("{PLANNING_ERROR_TAG} header index missing for 0x{}", hex::encode(h)))?;
        Ok((hi.height, hi.parent))
    };

    match indexed {
        None => {
            // Cold build: connect everything from genesis to tip.
            let (mut h, mut hash) = (tip_hi.height, tip);
            loop {
                connects.push((h, hash));
                if h == 0 {
                    break;
                }
                let (_, parent) = parent_of(&hash)?;
                hash = parent;
                h -= 1;
            }
        }
        Some(itip) => {
            let (mut ah, mut a) = parent_of(&itip).map(|(h, _)| (h, itip))?;
            let (mut bh, mut b) = (tip_hi.height, tip);
            while bh > ah {
                connects.push((bh, b));
                let (_, p) = parent_of(&b)?;
                b = p;
                bh -= 1;
            }
            while ah > bh {
                let (_, p) = parent_of(&a)?;
                disconnects.push((ah, a, p));
                a = p;
                ah -= 1;
            }
            while a != b {
                let (_, pa) = parent_of(&a)?;
                let (_, pb) = parent_of(&b)?;
                disconnects.push((ah, a, pa));
                connects.push((bh, b));
                a = pa;
                b = pb;
                if ah == 0 || bh == 0 {
                    // Diverged all the way past genesis: inconsistent header index.
                    bail!("{PLANNING_ERROR_TAG} idx reconcile found no common ancestor");
                }
                ah -= 1;
                bh -= 1;
            }
        }
    }

    Ok(ReconcilePlan {
        anchor_tip: tip,
        disconnects,
        connects,
        d_done: 0,
        c_done: 0,
        expect_marker: indexed,
    })
}

/// One bounded reconciliation step: converge the index toward the current `meta:tip`,
/// touching at most `budget` blocks. Returns Ok(true) when the index is converged
/// (`idx:tip_hash == meta:tip`) at the time of the check, Ok(false) when more work remains.
///
/// Reorg handling walks last-indexed hash -> common ancestor and applies ALL unindexes
/// (descending) BEFORE any indexes (ascending): HARD RULE 2, unindex-then-index, so a txid
/// present in both branches survives with its new locator.
///
/// `plan` carries the walk across ticks (see `ReconcilePlan`). Pass a `&mut None` for a
/// one-shot call; `run_reconciler` keeps one across the whole catch-up.
pub fn reconcile_tick_planned(
    db: &Stores,
    budget: usize,
    plan: &mut Option<ReconcilePlan>,
) -> Result<bool> {
    // Version gate: wipe a foreign-format index in the background, never in the boot path.
    if !idx_version_ok(db) {
        reset_index(db)?;
        *plan = None;
    }

    let Some(tip) = get_tip(db)? else {
        *plan = None;
        return Ok(true); // nothing to index yet
    };

    let indexed = idx_tip(db);
    if indexed == Some(tip) {
        *plan = None;
        return Ok(true);
    }

    // A plan is only usable while it targets the current tip AND still starts where the marker
    // actually is. The second check is belt and braces: any other writer of the marker (there is
    // none today) would invalidate the plan rather than silently skip blocks.
    let reusable = match plan.as_ref() {
        Some(p) => p.anchor_tip == tip && p.remaining() > 0 && plan_head_matches(p, indexed),
        None => false,
    };
    if !reusable {
        *plan = Some(plan_reconcile(db, tip, indexed)?);
    }
    let p = plan.as_mut().expect("plan set above");

    let mut left = budget;

    // HARD RULE 2: all unindexes first (descending height order, as planned).
    while p.d_done < p.disconnects.len() {
        if left == 0 {
            db.flush_idx().ok();
            return Ok(false);
        }
        let (h, hash, parent) = p.disconnects[p.d_done];
        // Data write and marker step land in ONE batch, so a partial tick always
        // describes a contiguous, genesis-anchored prefix even across an unclean shutdown.
        unindex_canonical_block(db, &hash, h, Some(&parent))?;
        p.d_done += 1;
        p.expect_marker = Some(parent);
        left -= 1;
    }

    // Then indexes, ascending from the ancestor toward the tip.
    while p.c_done < p.connects.len() {
        if left == 0 {
            db.flush_idx().ok();
            return Ok(false);
        }
        let (h, hash) = p.connects[p.connects.len() - 1 - p.c_done];
        // A body can legitimately be absent during header-first sync. Do NOT advance the
        // marker past it (index_canonical_block would silently skip and a later fresh-marker
        // miss would be a confident lie, the exact class the ScanOutcome contract removed). Stall and retry
        // next tick; the plan is kept so the retry is free.
        // `index_canonical_block` reports whether it actually indexed the block. A body can
        // legitimately be absent during header-first sync; do NOT advance the marker past it,
        // because a marker covering an unindexed block turns a later miss into a false PROVED
        // absence. Stall and retry next tick; the plan is kept so the retry is free.
        if !index_canonical_block(db, &hash, h)? {
            db.flush_idx().ok();
            return Ok(false);
        }
        p.c_done += 1;
        p.expect_marker = Some(hash);
        left -= 1;
    }

    db.flush_idx().ok();
    let done = idx_fresh(db);
    if done {
        *plan = None;
    }
    Ok(done)
}

/// True when the marker is exactly where this plan's next step expects it to be. Anything else
/// means something moved the marker behind the plan's back, so the plan is discarded and rebuilt.
fn plan_head_matches(p: &ReconcilePlan, indexed: Option<Hash32>) -> bool {
    indexed == p.expect_marker
}

/// Convenience wrapper: one reconcile step with a throwaway plan. Same behaviour as the
/// pre-0.1.7 `reconcile_tick`, kept for tests and any one-shot caller.
pub fn reconcile_tick(db: &Stores, budget: usize) -> Result<bool> {
    let mut plan = None;
    reconcile_tick_planned(db, budget, &mut plan)
}

/// Drop the whole index and its markers, so the next tick rebuilds from genesis. Used on a
/// version mismatch and as the self-heal for an index the header store can no longer explain.
pub fn reset_index(db: &Stores) -> Result<()> {
    // ORDER IS LOAD-BEARING. `Tree::clear` in sled 0.34 is a per-key remove loop in key order,
    // so an interrupted clear persists a PREFIX of the removals. Since "idx:" sorts after "btx/"
    // and "hh/" but before "tx/", a naive clear-then-reinsert could be interrupted with the
    // markers still present and intact while the block-to-txids and height-to-hash entries are
    // already gone. On restart the index would read as FRESH while structurally broken, and the
    // next reorg's unindex would find no btx entry and leave stale locators behind.
    //
    // So: invalidate the VERSION marker first and make it durable. Any interruption after that
    // point leaves the index version-invalid, which sends the next tick straight back here.
    db.idx
        .remove(k_idx_version())
        .context("idx version marker remove")?;
    db.idx.remove(k_idx_tip()).context("idx tip marker remove")?;
    // Load-bearing: the whole point of this ordering is that the invalidation is DURABLE before
    // the destructive clear starts. Swallowing a failure here would silently void the guarantee.
    db.flush_idx()
        .context("flush after invalidating the index version marker")?;

    db.idx.clear().context("idx.clear")?;

    // Pre-0.1.7 kept the markers in the meta tree; clear those too so an old node's leftovers
    // can never be mistaken for a marker.
    meta_del(db, k_idx_tip()).ok();
    meta_del(db, k_idx_version()).ok();

    db.idx
        .insert(k_idx_version(), IDX_VERSION)
        .context("idx version marker")?;
    db.flush_idx().ok();
    db.flush_meta().ok();
    Ok(())
}

/// Blocks indexed (or unindexed) per reconciler tick. Bounded so a cold build or deep reorg
/// never monopolizes the sled trees or a runtime worker.
///
/// Raised from 64 to 128 together with the shorter catch-up sleep below. With the walk now
/// planned once per tip, a tick is just `budget` block-body reads plus one batched write
/// each, which is well under the sleep that follows it; before the plan was reused a tick also carried an
/// O(tip - indexed) header walk, which is why it had to stay small.
pub const RECONCILE_BUDGET_PER_TICK: usize = 128;

/// Sleep between ticks while there is still work to do. The old 250 ms was chosen when a tick
/// was expensive; with a planned walk it just made a cold build sleep-bound (about 4 minutes at
/// tip 60,000 even after the quadratic term was removed). 50 ms keeps the reconciler well under
/// a third of one worker while cutting a cold build at that height to roughly half a minute,
/// which is the difference between a recovering node being useful immediately or not.
const RECONCILE_SLEEP_CATCHUP_MS: u64 = 50;

/// Sleep between ticks once converged, used only as a SAFETY NET now that the apply path wakes
/// the reconciler directly (see `notify_tip_changed`).
const RECONCILE_SLEEP_IDLE_MS: u64 = 2_000;

/// Woken by the apply path when the tip moves.
///
/// This matters because almost every node runs AT THE TIP, and a polled reconciler is stale for
/// up to one idle period after every single block. Measured on the standby before this change:
/// about 1.45 s of staleness after each block. During that window `idx_fresh` is false, so
/// `/tx/:id` and `/proof/tx/:txid` fall back to the bounded chain scan, which is exactly when a
/// wallet is polling for the transaction that just confirmed. Cold-sync speed is a nice-to-have;
/// this is the common case.
///
/// `notify_one` stores a permit when nobody is waiting, so a wake that lands between ticks is not
/// lost. The idle sleep stays as a backstop for any apply path that forgets to call this.
static TIP_CHANGED: tokio::sync::Notify = tokio::sync::Notify::const_new();

/// Call after the canonical tip has moved. Cheap, non-blocking, safe from any thread.
pub fn notify_tip_changed() {
    TIP_CHANGED.notify_one();
}

/// Sleep after an error, before retrying (and eventually resetting, see below). Doubles per
/// consecutive error up to the ceiling, so a condition that needs a human does not spin.
const RECONCILE_SLEEP_ERROR_MS: u64 = 5_000;
const RECONCILE_SLEEP_ERROR_MAX_MS: u64 = 80_000;

/// Consecutive planning failures tolerated before the index is treated as unexplainable by the
/// header store and reset. A couple of retries first, because one failure can be a
/// transient read error rather than a structurally broken index.
const RECONCILE_ERRORS_BEFORE_RESET: u32 = 3;

/// The background reconciler loop, spawned once from node startup. Never panics: on error it
/// logs and retries; every read path degrades to the scan while the index is stale
/// (HARD RULE 3), so a broken reconciler costs performance, never correctness.
///
/// It keeps ONE `ReconcilePlan` across ticks, which makes catch-up linear instead of quadratic,
/// and self-heals a marker the header store can no longer explain. Before that, an
/// unresolvable `idx:tip_hash` produced the same error every 5 seconds forever, with every lookup
/// permanently degraded to the scan and no path back.
pub async fn run_reconciler(db: Arc<Stores>) {
    let mut announced_complete = false;
    let mut plan: Option<ReconcilePlan> = None;
    let mut consecutive_errors: u32 = 0;

    loop {
        // The tick is fully synchronous sled work (up to `budget` block reads plus a batched
        // write each) and this task shares the runtime with the axum RPC. Run it on the blocking
        // pool so a rebuild cannot add tail latency to reads the app layer is making at the same
        // time, which matters most right after an upgrade, when the IDX_VERSION bump forces a
        // full rebuild while every RPC consumer is still polling.
        let tick_db = db.clone();
        let mut owned_plan = plan.take();
        let step = match tokio::task::spawn_blocking(move || {
            let r = reconcile_tick_planned(tick_db.as_ref(), RECONCILE_BUDGET_PER_TICK, &mut owned_plan);
            (r, owned_plan)
        })
        .await
        {
            Ok((r, returned)) => {
                plan = returned;
                r
            }
            Err(e) => {
                plan = None;
                Err(anyhow::anyhow!("reconcile task failed: {e}"))
            }
        };
        let sleep_ms = match step {
            Ok(true) => {
                consecutive_errors = 0;
                if !announced_complete {
                    println!("[txidx] index converged with meta:tip; serving index-first lookups");
                    announced_complete = true;
                }
                RECONCILE_SLEEP_IDLE_MS
            }
            Ok(false) => {
                consecutive_errors = 0;
                announced_complete = false;
                RECONCILE_SLEEP_CATCHUP_MS
            }
            Err(e) => {
                announced_complete = false;
                plan = None;
                consecutive_errors = consecutive_errors.saturating_add(1);
                let planning_failed = is_planning_error(&e);

                // Log the first few, then back off: a condition that needs a human (a duplicate
                // txid on the chain, a bad block body) must not turn into a line every 5 seconds
                // forever.
                if consecutive_errors <= RECONCILE_ERRORS_BEFORE_RESET || consecutive_errors % 12 == 0
                {
                    println!(
                        "[txidx] reconcile error #{consecutive_errors} (tx lookups degrade to the scan fallback, which is honest but slower): {e:#}"
                    );
                }

                // Reset ONLY for the condition the reset actually cures: a marker the header
                // store cannot resolve, which means the index describes a chain this node does
                // not have. Counting every error would be wrong. An undecodable block body or a
                // duplicate-txid refusal errors on every tick too, and wiping and rebuilding a
                // 60k-block index every 15 seconds would make that permanently worse instead of
                // leaving it degraded, honest and loud.
                // Reset for the condition a reset actually cures: the index describes a chain
                // this node cannot explain. That is exactly "planning failed", and planning fails
                // in three ways (see plan_reconcile): the tip header is missing, an ancestor
                // header is missing, or the two branches never meet. An earlier version probed
                // only get_hidx(idx_tip), which covers the first of the three and silently left
                // the other two permanently degraded.
                //
                // Errors from APPLYING the plan (an undecodable block body, a failed batch) are
                // deliberately NOT reset conditions: rebuilding would make a bad body worse
                // rather than curing it.
                if consecutive_errors >= RECONCILE_ERRORS_BEFORE_RESET && planning_failed {
                    // Clearing a converged index is a per-key remove loop over hundreds of
                    // thousands of keys plus flushes. Keep it off the runtime workers for the
                    // same reason the tick itself is.
                    let reset_db = db.clone();
                    let reset =
                        tokio::task::spawn_blocking(move || reset_index(reset_db.as_ref())).await;
                    match reset {
                        Ok(Ok(())) => println!(
                            "[txidx] index cannot be explained by the header store after {consecutive_errors} planning failures; index reset, rebuilding from genesis"
                        ),
                        Ok(Err(e)) => println!("[txidx] index reset FAILED: {e:#}"),
                        Err(e) => println!("[txidx] index reset task failed: {e}"),
                    }
                    consecutive_errors = 0;
                }

                // Exponential backoff to a ceiling, so a stuck condition costs almost nothing.
                let shift = consecutive_errors.saturating_sub(1).min(4);
                (RECONCILE_SLEEP_ERROR_MS << shift).min(RECONCILE_SLEEP_ERROR_MAX_MS)
            }
        };
        // Converged: wait for the tip to move rather than polling for it. Still bounded by the
        // idle sleep so a missed notification cannot wedge the index.
        if sleep_ms == RECONCILE_SLEEP_IDLE_MS {
            tokio::select! {
                _ = TIP_CHANGED.notified() => {}
                _ = tokio::time::sleep(std::time::Duration::from_millis(sleep_ms)) => {}
            }
        } else {
            tokio::time::sleep(std::time::Duration::from_millis(sleep_ms)).await;
        }
    }
}
