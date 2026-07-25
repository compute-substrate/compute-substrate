// Regression tests for transaction lookup: the four-way scan outcome and the txid index.
//
// The /tx/:id walk on main collapses four different terminations (budget exhausted, missing
// block body, decode failure, genesis reached) into one identical `{ok:false, err:"not found"}`:
// a confident lie for every termination except the genesis walk-out. These tests pin the
// four-way `ScanOutcome` split and the txid index with its bounded reconciler.
//
// HARNESS NOTE (same as reorg_ghost_utxo_all_or_nothing.rs): the repo's generic testutil_chain
// is documented-rotted, it stamps wrong difficulty bits and `index_header`'s foreign-genesis
// allowance is `#[cfg(test)]`-gated, which is NOT active when the lib is linked by an
// integration test. So these tests drive the functions DIRECTLY and hand-build blocks into the
// sled trees: bodies via `db.blocks.insert(k_block(..))`, header index via `put_hidx`, tip via
// `set_tip`. The scan and the index never validate PoW/merkle, so toy headers are sufficient.

use anyhow::Result;
use tempfile::TempDir;

use csd::chain::index::{header_hash, put_hidx, HeaderIndex};
use csd::codec::consensus_bincode;
use csd::crypto::txid;
use csd::state::db::{k_block, set_tip, Stores};
use csd::state::tx_index::{
    get_tx_entry, get_tx_locator, index_canonical_block, unindex_canonical_block, TxIndexEntry,
};
use csd::state::tx_scan::{
    find_tx_in_chain, fresh_tip, idx_fresh, locate_tx, reconcile_tick, resolve_via_index,
    ScanOutcome, WHY_MISSING_BODY,
};
use csd::types::{AppPayload, Block, BlockHeader, Hash32, OutPoint, Transaction, TxIn, TxOut};

fn open_db(tmp: &TempDir) -> Stores {
    Stores::open(tmp.path().to_str().unwrap()).expect("open db")
}

/// A structurally-valid unique tx (the scan/index compute txids; they never validate).
fn dummy_tx(tag: u8) -> Transaction {
    Transaction {
        version: 1,
        inputs: vec![TxIn {
            prevout: OutPoint {
                txid: [tag; 32],
                vout: 0,
            },
            script_sig: vec![],
        }],
        outputs: vec![TxOut {
            value: 1,
            script_pubkey: [tag; 20],
        }],
        locktime: 0,
        app: AppPayload::None,
    }
}

/// Insert one block (body + header index) at `height` on top of `prev`. `salt` makes
/// same-height sibling headers distinct across branches.
fn append_block(db: &Stores, prev: Hash32, height: u64, salt: u32, txs: Vec<Transaction>) -> Hash32 {
    let blk = Block {
        header: BlockHeader {
            version: 1,
            prev,
            merkle: [0u8; 32],
            time: height,
            bits: 0,
            nonce: salt,
        },
        txs,
    };
    let hash = header_hash(&blk.header);
    db.blocks
        .insert(k_block(&hash), consensus_bincode().serialize(&blk).unwrap())
        .unwrap();
    put_hidx(
        db,
        &HeaderIndex {
            hash,
            parent: prev,
            height,
            chainwork: (height + 1) as u128,
            bits: 0,
            time: height,
        },
    )
    .unwrap();
    hash
}

/// Build an n-block chain (heights 0..n-1), one unique tx per block, and set the tip.
/// Returns the block hashes by height.
fn build_chain(db: &Stores, n: u64, salt: u32) -> Vec<Hash32> {
    let mut hashes = Vec::with_capacity(n as usize);
    let mut prev = [0u8; 32];
    for h in 0..n {
        let hash = append_block(db, prev, h, salt, vec![dummy_tx(h as u8)]);
        hashes.push(hash);
        prev = hash;
    }
    set_tip(db, hashes.last().unwrap()).unwrap();
    hashes
}

fn tx_in_block(h: u64) -> Hash32 {
    txid(&dummy_tx(h as u8))
}

/// Run the reconciler to convergence (bounded so a bug cannot hang the suite).
fn reconcile_until_fresh(db: &Stores, budget: usize) {
    for _ in 0..2_000 {
        if reconcile_tick(db, budget).expect("reconcile_tick") {
            return;
        }
    }
    panic!("reconciler did not converge");
}

// -----------------------------------------------------------------------------
// (1) the scan/index subsystem: an in-horizon tx is Found.
// -----------------------------------------------------------------------------
#[test]
fn scan_finds_tx_at_depth_3_within_max_back_8() -> Result<()> {
    let tmp = TempDir::new()?;
    let db = open_db(&tmp);
    let hashes = build_chain(&db, 16, 0); // tip = height 15

    let want = tx_in_block(12); // depth 3 from tip
    assert_eq!(
        find_tx_in_chain(&db, &want, 8),
        ScanOutcome::Found {
            block_hash: hashes[12],
            height: 12,
            index_in_block: 0
        }
    );
    Ok(())
}

// -----------------------------------------------------------------------------
// (2) THE W9 PIN: beyond-horizon must be Horizon, NOT Absent. The pre-fix code
// mapped budget exhaustion to the same "not found" as a proved absence; mapping
// Horizon back to Absent (the pre-fix semantics) turns this test red.
// -----------------------------------------------------------------------------
#[test]
fn scan_beyond_horizon_is_horizon_not_absent() -> Result<()> {
    let tmp = TempDir::new()?;
    let db = open_db(&tmp);
    build_chain(&db, 16, 0); // tip = height 15

    let want = tx_in_block(5); // depth 10 from tip, beyond max_back = 8
    let out = find_tx_in_chain(&db, &want, 8);
    assert!(
        !matches!(out, ScanOutcome::Absent { .. }),
        "W9: budget exhaustion answered as a PROVED absence (the pre-0.1.6 lie): {out:?}"
    );
    assert_eq!(
        out,
        ScanOutcome::Horizon {
            scanned: 8,
            stopped_at_height: 7
        }
    );
    Ok(())
}

// -----------------------------------------------------------------------------
// (3) the scan/index subsystem: a walk that reaches genesis is a PROVED absence with an honest count.
// -----------------------------------------------------------------------------
#[test]
fn scan_to_genesis_proves_absence() -> Result<()> {
    let tmp = TempDir::new()?;
    let db = open_db(&tmp);
    build_chain(&db, 12, 0);

    let want: Hash32 = [0xEE; 32]; // never in any block
    assert_eq!(
        find_tx_in_chain(&db, &want, 1000),
        ScanOutcome::Absent { scanned: 12 }
    );
    Ok(())
}

// -----------------------------------------------------------------------------
// (4) the scan/index subsystem: a missing mid-chain block body is Incomplete, never Absent (the walk
// examined only part of the chain, so absence is NOT proved).
// -----------------------------------------------------------------------------
#[test]
fn missing_block_body_is_incomplete_not_absent() -> Result<()> {
    let tmp = TempDir::new()?;
    let db = open_db(&tmp);
    let hashes = build_chain(&db, 12, 0);

    db.blocks.remove(k_block(&hashes[6])).unwrap(); // hole at height 6

    let want: Hash32 = [0xEE; 32];
    let out = find_tx_in_chain(&db, &want, 1000);
    assert!(
        !matches!(out, ScanOutcome::Absent { .. }),
        "a partial walk answered as a PROVED absence: {out:?}"
    );
    assert_eq!(
        out,
        ScanOutcome::Incomplete {
            at: hashes[6],
            why: WHY_MISSING_BODY
        }
    );
    Ok(())
}

// -----------------------------------------------------------------------------
// (5) the scan/index subsystem: with the index warm (marker fresh), a deep tx resolves with max_back=0,
// i.e. WITHOUT scanning; and a fresh-index miss is a proved Absent over the chain.
// -----------------------------------------------------------------------------
#[test]
fn warm_index_resolves_deep_tx_with_zero_scan_budget() -> Result<()> {
    let tmp = TempDir::new()?;
    let db = open_db(&tmp);
    let hashes = build_chain(&db, 16, 0);

    reconcile_until_fresh(&db, 1000);
    assert!(idx_fresh(&db), "index must be converged");

    let want = tx_in_block(5); // depth 10
    // Control: the raw scan with a zero budget cannot answer.
    assert_eq!(
        find_tx_in_chain(&db, &want, 0),
        ScanOutcome::Horizon {
            scanned: 0,
            stopped_at_height: 15
        }
    );
    // The index-first lookup can.
    assert_eq!(
        locate_tx(&db, &want, 0),
        ScanOutcome::Found {
            block_hash: hashes[5],
            height: 5,
            index_in_block: 0
        }
    );
    // And a fresh-index miss is a PROVED absence covering the whole chain.
    assert_eq!(
        locate_tx(&db, &[0xEE; 32], 0),
        ScanOutcome::Absent { scanned: 16 }
    );
    Ok(())
}

// -----------------------------------------------------------------------------
// (6) Reorg rule 2: across a reorg, a txid present in BOTH branches must keep a
// locator (pointing into the new branch). The reverse order (index-then-unindex) is
// proven destructive by the negative control below: the same class of defect as the
// same-block create-then-spend undo bug in src/state/utxo.rs.
// -----------------------------------------------------------------------------
#[test]
fn reorg_unindex_then_index_preserves_txid_present_in_both_branches() -> Result<()> {
    let tmp = TempDir::new()?;
    let db = open_db(&tmp);

    let shared = dummy_tx(0x77); // T: mined in BOTH branches
    let t = txid(&shared);

    // Branch A: g <- a1(T, uA) <- a2
    let g = append_block(&db, [0u8; 32], 0, 0, vec![dummy_tx(0x01)]);
    let a1 = append_block(&db, g, 1, 0xA, vec![shared.clone(), dummy_tx(0xA1)]);
    let a2 = append_block(&db, a1, 2, 0xA, vec![dummy_tx(0xA2)]);
    set_tip(&db, &a2).unwrap();
    reconcile_until_fresh(&db, 1000);
    assert_eq!(
        get_tx_locator(&db, &t)?.expect("T indexed on branch A").block_hash,
        a1
    );

    // Reorg to branch B: g <- b1(T, uB) <- b2 <- b3
    let b1 = append_block(&db, g, 1, 0xB, vec![shared.clone(), dummy_tx(0xB1)]);
    let b2 = append_block(&db, b1, 2, 0xB, vec![dummy_tx(0xB2)]);
    let b3 = append_block(&db, b2, 3, 0xB, vec![dummy_tx(0xB3)]);
    set_tip(&db, &b3).unwrap();

    // Small budget on purpose: the reorg must survive partial ticks too.
    reconcile_until_fresh(&db, 2);
    assert!(idx_fresh(&db));

    let loc = get_tx_locator(&db, &t)?.expect(
        "HARD RULE 2 violated: txid present in both branches lost its locator across the reorg",
    );
    assert_eq!(loc.block_hash, b1, "T must relocate to the new branch");
    assert_eq!(loc.height, 1);
    assert!(get_tx_locator(&db, &txid(&dummy_tx(0xA1)))?.is_none(), "uA must be unindexed");
    assert!(get_tx_locator(&db, &txid(&dummy_tx(0xB1)))?.is_some(), "uB must be indexed");
    // The lookup path agrees end-to-end.
    assert_eq!(
        locate_tx(&db, &t, 0),
        ScanOutcome::Found {
            block_hash: b1,
            height: 1,
            index_in_block: 0
        }
    );

    // NEGATIVE CONTROL, fresh db: the REVERSE order (index-then-unindex) is what HARD RULE 2
    // exists to forbid. Historically it silently deleted T, leaving a txid a canonical block
    // still contains absent from a "complete" index. It can no longer get that far:
    // indexing a txid that is already indexed under a DIFFERENT block is refused outright, so
    // the index simply stops converging and every lookup stays on the honest scan.
    let tmp2 = TempDir::new()?;
    let db2 = open_db(&tmp2);
    let g2 = append_block(&db2, [0u8; 32], 0, 0, vec![dummy_tx(0x01)]);
    let a1_2 = append_block(&db2, g2, 1, 0xA, vec![shared.clone(), dummy_tx(0xA1)]);
    let b1_2 = append_block(&db2, g2, 1, 0xB, vec![shared.clone(), dummy_tx(0xB1)]);
    assert!(index_canonical_block(&db2, &a1_2, 1)?, "branch A indexed (pre-reorg state)");

    // Wrong order: connect B while A still holds T. The index does not silently
    // overwrite (which would let the later unindex of EITHER block delete a locator the other
    // still owns) and does not fail the whole tick either. It marks that ONE txid ambiguous.
    assert!(index_canonical_block(&db2, &b1_2, 1)?, "indexing still succeeds");
    assert_eq!(
        get_tx_entry(&db2, &t)?,
        Some(TxIndexEntry::Ambiguous),
        "a txid claimed by two blocks must be marked ambiguous, not overwritten"
    );

    // Ambiguous is a "cannot say", never an absence: the caller must fall back to the scan.
    assert!(
        get_tx_locator(&db2, &t)?.is_none(),
        "no single locator can describe two blocks"
    );

    // Everything else in both blocks keeps its O(1) locator, so one bad txid does not cost the
    // index. This is the whole point of marking instead of failing.
    assert!(get_tx_locator(&db2, &txid(&dummy_tx(0xA1)))?.is_some());
    assert!(get_tx_locator(&db2, &txid(&dummy_tx(0xB1)))?.is_some());

    // And unindexing one of the two blocks must NOT delete the marker: disconnecting B does not
    // prove A no longer carries T, and removing it would let a later miss read as PROVED absent.
    unindex_canonical_block(&db2, &b1_2, 1, None)?;
    assert_eq!(
        get_tx_entry(&db2, &t)?,
        Some(TxIndexEntry::Ambiguous),
        "the ambiguity marker must survive an unindex"
    );
    Ok(())
}

// -----------------------------------------------------------------------------
// (7) the scan/index subsystem HARD RULE 3: a stale idx:tip_hash must fall back to the scan. A new block
// arrives (tip moves) before the reconciler runs: trusting the stale index would
// answer a false Absent for a tx in that block.
// -----------------------------------------------------------------------------
#[test]
fn stale_index_marker_falls_back_to_scan() -> Result<()> {
    let tmp = TempDir::new()?;
    let db = open_db(&tmp);
    let hashes = build_chain(&db, 16, 0);
    reconcile_until_fresh(&db, 1000);
    assert!(idx_fresh(&db));

    // A new block with a new tx lands; the reconciler has NOT run yet.
    let fresh_tx = dummy_tx(0xF7);
    let want = txid(&fresh_tx);
    let h16 = append_block(&db, hashes[15], 16, 0, vec![fresh_tx]);
    set_tip(&db, &h16).unwrap();

    assert!(!idx_fresh(&db), "marker must be stale after the tip moved");
    assert!(
        get_tx_locator(&db, &want)?.is_none(),
        "precondition: the stale index really would miss this tx"
    );

    // The lookup must NOT trust the stale index: the scan finds the tx.
    assert_eq!(
        locate_tx(&db, &want, 1000),
        ScanOutcome::Found {
            block_hash: h16,
            height: 16,
            index_in_block: 0
        }
    );

    // After the reconciler catches up, the index serves it with no scan budget at all.
    reconcile_until_fresh(&db, 1000);
    assert_eq!(
        locate_tx(&db, &want, 0),
        ScanOutcome::Found {
            block_hash: h16,
            height: 16,
            index_in_block: 0
        }
    );
    Ok(())
}

// -----------------------------------------------------------------------------
// (8) G14 pre-gate LOW fix: the intra-call TOCTOU. `fresh_tip()` validates the index at tip
// T1; a new tip block Y containing `want` is applied BEFORE the absence-bound is derived.
// The pre-fix code read `get_tip` a second time and returned Absent{Y.height+1} for a tx that
// IS in Y (the exact confident-lie class the scan/index subsystem exists to remove). `resolve_via_index` is the
// production decomposition that pins the decision to the captured `at_tip`; calling it with
// at_tip=T1 while the live tip is already Y (reconciler not yet run) is a FAITHFUL, fully
// deterministic reproduction of the covered-read step of that race, with no test-only seam:
// at_tip is a real parameter locate_tx passes in production.
// -----------------------------------------------------------------------------
#[test]
fn fresh_index_miss_does_not_lie_when_tip_advances_midcall() -> Result<()> {
    let tmp = TempDir::new()?;
    let db = open_db(&tmp);
    let hashes = build_chain(&db, 16, 0); // tip T1 = height 15
    reconcile_until_fresh(&db, 1000);
    let t1 = fresh_tip(&db).expect("index must be fresh at T1");
    assert_eq!(t1, hashes[15]);

    // The tip advances to Y = height 16, carrying `want`. The reconciler has NOT run, so the
    // marker still points at T1: this is precisely the mid-race db state at the instant the
    // pre-fix code performed its second get_tip read.
    let y_tx = dummy_tx(0xF8);
    let want = txid(&y_tx);
    let y = append_block(&db, hashes[15], 16, 0, vec![y_tx]);
    set_tip(&db, &y).unwrap();

    // The captured-tip decision MUST NOT emit Absent for a tx that exists in Y. It returns
    // None (index no longer authoritative at t1), so locate_tx falls through to the scan.
    assert_eq!(
        resolve_via_index(&db, &want, t1),
        None,
        "G14: a fresh-index miss pinned to T1 emitted a proved-absence for a tx applied at a \
         newer tip (the intra-call TOCTOU confident lie)"
    );

    // End to end, the public entry point returns the honest Found (via the scan fallback),
    // never a false Absent.
    assert_eq!(
        locate_tx(&db, &want, 1000),
        ScanOutcome::Found {
            block_hash: y,
            height: 16,
            index_in_block: 0
        }
    );

    // Control: with the tip genuinely STILL at T1, a real miss of an absent txid is a correct
    // proved Absent bounded by T1's height (the guard blocks lies, not true absences).
    let db2 = {
        let tmp2 = TempDir::new()?;
        let db2 = open_db(&tmp2);
        let h2 = build_chain(&db2, 16, 0);
        reconcile_until_fresh(&db2, 1000);
        let t1b = fresh_tip(&db2).expect("fresh");
        assert_eq!(t1b, h2[15]);
        assert_eq!(
            resolve_via_index(&db2, &[0xEE; 32], t1b),
            Some(ScanOutcome::Absent { scanned: 16 })
        );
        db2
    };
    drop(db2);
    Ok(())
}

// -----------------------------------------------------------------------------
// (9) EVERY non-decisive termination must be reported as non-decisive.
//
// the scan/index subsystem exists because four different terminations of the back-walk used to collapse into one
// `{ok:false, err:"not found"}`. The suite only ever pinned ONE of them (a missing block body).
// A mutation turning WHY_DECODE, WHY_NO_TIP, WHY_LOOP or WHY_HEIGHT_UNDERFLOW into `Absent`
// passed the whole suite, which is three quarters of the exact bug class this subsystem was
// built to remove, unguarded. Each case below fails if its outcome ever becomes Absent.
// -----------------------------------------------------------------------------
#[test]
fn every_incomplete_reason_is_reported_as_not_proved() -> Result<()> {
    // (a) no chain tip at all
    let tmp = TempDir::new()?;
    let db = open_db(&tmp);
    assert!(
        matches!(
            find_tx_in_chain(&db, &[0x01; 32], 100),
            ScanOutcome::Incomplete { .. }
        ),
        "a db with no tip must be Incomplete, never a proved absence"
    );

    // (b) an undecodable block body
    let tmp = TempDir::new()?;
    let db = open_db(&tmp);
    let chain = build_chain(&db, 4, 0);
    db.blocks
        .insert(k_block(&chain[2]), b"not a block".as_slice())?;
    match find_tx_in_chain(&db, &[0x01; 32], 100) {
        ScanOutcome::Incomplete { at, why } => {
            assert_eq!(at, chain[2]);
            assert_eq!(why, "decode-failed", "wrong reason reported");
        }
        other => panic!("an undecodable body must be Incomplete, got {other:?}"),
    }

    // (c) a traversal loop: a block whose parent is itself
    let tmp = TempDir::new()?;
    let db = open_db(&tmp);
    let g = append_block(&db, [0u8; 32], 0, 0, vec![dummy_tx(0)]);
    let looped = append_block(&db, g, 1, 0, vec![dummy_tx(1)]);
    // Rewrite block 1's header index so its parent is itself.
    put_hidx(
        &db,
        &HeaderIndex {
            hash: looped,
            parent: looped,
            height: 1,
            chainwork: 2,
            bits: 0,
            time: 1,
        },
    )?;
    // And make the body point at itself too, so the walk revisits the same hash.
    let selfblk = Block {
        header: BlockHeader {
            version: 1,
            prev: looped,
            merkle: [0u8; 32],
            time: 1,
            bits: 0,
            nonce: 0,
        },
        txs: vec![dummy_tx(1)],
    };
    db.blocks
        .insert(k_block(&looped), consensus_bincode().serialize(&selfblk)?)?;
    set_tip(&db, &looped)?;
    match find_tx_in_chain(&db, &[0xEE; 32], 100) {
        ScanOutcome::Incomplete { why, .. } => {
            assert_eq!(why, "traversal-loop", "wrong reason reported")
        }
        other => panic!("a self-referencing parent must be Incomplete, got {other:?}"),
    }

    // (d) height bookkeeping says genesis but the block disagrees
    let tmp = TempDir::new()?;
    let db = open_db(&tmp);
    let only = append_block(&db, [0x77; 32], 0, 0, vec![dummy_tx(5)]); // non-zero prev at height 0
    set_tip(&db, &only)?;
    match find_tx_in_chain(&db, &[0xEE; 32], 100) {
        ScanOutcome::Incomplete { why, .. } => {
            assert_eq!(why, "height-underflow", "wrong reason reported")
        }
        other => panic!("an inconsistent height index must be Incomplete, got {other:?}"),
    }
    Ok(())
}
