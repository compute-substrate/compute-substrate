// Regression tests for the txid-index reconciler.
//
// Plan reuse: the reconcile walk is planned ONCE per canonical tip and consumed across ticks. Before
//      this, every tick re-walked the header index from the tip down to the last indexed block
//      while applying only `budget` blocks, so building the index from cold cost about
//      T^2 / (2*budget) header reads. Measured 4.5 minutes at tip 60,450, and it grows with the
//      square of the chain.
// Marker atomicity: the completeness markers live in the SAME sled tree as the data they describe and are
//      written in the same batch, so a marker can never be durable ahead of its data. The old
//      layout kept them in `meta` while the data was in `idx`, and `Tree::flush` is documented
//      as not being a cross-tree durability fence.
// Self-heal: an `idx:tip_hash` the header store cannot explain is reset and rebuilt instead of
//      producing the same error forever with every lookup permanently degraded to the scan.
//
// HARNESS NOTE (same as tx_scan_horizon.rs): testutil_chain is rotted for integration tests, so
// these drive the functions directly and hand-build blocks into the sled trees.

use anyhow::Result;
use tempfile::TempDir;

use csd::chain::index::{header_hash, put_hidx, HeaderIndex};
use csd::codec::consensus_bincode;
use csd::crypto::txid;
use csd::state::db::{k_block, k_hdr, meta_get_bytes, meta_put_bytes, set_tip, Stores};
use csd::state::tx_index::{
    get_block_hash_by_height, get_tx_entry, get_tx_locator, index_canonical_block,
    unindex_canonical_block, TxIndexEntry,
};
use csd::state::tx_scan::{
    fresh_tip, idx_fresh, idx_tip, k_idx_tip, k_idx_version, locate_tx, reconcile_tick,
    reconcile_tick_planned, reset_index, resolve_via_index, ReconcilePlan, ScanOutcome,
};
use csd::types::{AppPayload, Block, BlockHeader, Hash32, OutPoint, Transaction, TxIn, TxOut};

fn open_db(tmp: &TempDir) -> Stores {
    Stores::open(tmp.path().to_str().unwrap()).expect("open db")
}

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

/// n blocks at heights 0..n-1, one unique tx each, tip set to the last.
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

// -----------------------------------------------------------------------------
// (1) the plan is built once per tip and then consumed.
//
// The discriminating step is deleting a mid-chain HEADER INDEX entry after the plan exists.
// Planning is the only thing that reads the header index, so:
//   - a reconciler that re-plans every tick cannot get past the hole and fails,
//   - a reconciler that consumes the plan it already built converges normally.
// Block bodies are untouched, so indexing itself has everything it needs either way.
// -----------------------------------------------------------------------------
#[test]
fn plan_is_reused_across_ticks_and_survives_a_header_hole() -> Result<()> {
    let tmp = TempDir::new()?;
    let db = open_db(&tmp);
    let chain = build_chain(&db, 40, 0);
    let tip = *chain.last().unwrap();

    let mut plan: Option<ReconcilePlan> = None;

    // First tick builds the plan and applies `budget` blocks.
    assert!(!reconcile_tick_planned(&db, 8, &mut plan)?, "not converged yet");
    let p = plan.as_ref().expect("a plan must be retained between ticks");
    assert_eq!(p.anchor_tip(), tip, "plan must be anchored to the canonical tip");
    assert_eq!(p.remaining(), 32, "40 blocks planned, 8 applied");

    // Punch a hole in the header index at a height the plan has already recorded but not yet
    // applied. Only re-planning would need it.
    db.hdr.remove(k_hdr(&chain[20]))?;

    let mut calls = 1; // the tick above
    loop {
        let done = reconcile_tick_planned(&db, 8, &mut plan)?;
        calls += 1;
        assert!(calls < 100, "reconciler did not converge");
        if done {
            break;
        }
        let p = plan.as_ref().expect("plan must persist while work remains");
        assert_eq!(p.anchor_tip(), tip, "plan re-anchored, so it was rebuilt");
    }

    assert_eq!(calls, 5, "40 blocks at 8 per tick should be exactly 5 ticks");
    assert!(idx_fresh(&db), "index must be converged");
    assert!(plan.is_none(), "a converged reconciler must drop its plan");

    // Every block really is indexed, including the one whose header we removed.
    for (h, hash) in chain.iter().enumerate() {
        assert_eq!(
            get_block_hash_by_height(&db, h as u64)?,
            Some(*hash),
            "height {h} missing from the index"
        );
        let loc = get_tx_locator(&db, &txid(&dummy_tx(h as u8)))?
            .unwrap_or_else(|| panic!("tx of block {h} not indexed"));
        assert_eq!(loc.height, h as u64);
    }
    Ok(())
}

// -----------------------------------------------------------------------------
// (2) a tip that advances mid-catch-up invalidates the plan, and the reconciler still
// converges on the new tip rather than silently finishing against the old one.
// -----------------------------------------------------------------------------
#[test]
fn plan_is_rebuilt_when_the_tip_moves_midway() -> Result<()> {
    let tmp = TempDir::new()?;
    let db = open_db(&tmp);
    let chain = build_chain(&db, 30, 0);
    let old_tip = *chain.last().unwrap();

    let mut plan: Option<ReconcilePlan> = None;
    assert!(!reconcile_tick_planned(&db, 8, &mut plan)?);
    assert_eq!(plan.as_ref().unwrap().anchor_tip(), old_tip);

    // A new block arrives before the index caught up.
    let new_tip = append_block(&db, old_tip, 30, 0, vec![dummy_tx(30)]);
    set_tip(&db, &new_tip)?;

    for _ in 0..100 {
        if reconcile_tick_planned(&db, 8, &mut plan)? {
            break;
        }
    }

    assert!(idx_fresh(&db), "index must converge on the NEW tip");
    assert_eq!(idx_tip(&db), Some(new_tip));
    assert_eq!(get_block_hash_by_height(&db, 30)?, Some(new_tip));
    assert!(
        get_tx_locator(&db, &txid(&dummy_tx(30)))?.is_some(),
        "the block that arrived mid-catch-up was never indexed"
    );
    Ok(())
}

// -----------------------------------------------------------------------------
// (3) the markers live in the idx tree, and each block's marker step is written with that
// block's data. The meta tree must hold no index markers at all.
// -----------------------------------------------------------------------------
#[test]
fn markers_live_in_the_index_tree_next_to_their_data() -> Result<()> {
    let tmp = TempDir::new()?;
    let db = open_db(&tmp);
    let chain = build_chain(&db, 6, 0);

    for _ in 0..50 {
        if reconcile_tick(&db, 2)? {
            break;
        }
    }
    assert!(idx_fresh(&db));

    assert!(
        db.idx.get(k_idx_tip())?.is_some() && db.idx.get(k_idx_version())?.is_some(),
        "both markers must be in the idx tree"
    );
    assert!(
        meta_get_bytes(&db, k_idx_tip())?.is_none() && meta_get_bytes(&db, k_idx_version())?.is_none(),
        "the meta tree must not carry index markers any more"
    );

    // Indexing a block advances the marker to it in the same write.
    let next = append_block(&db, *chain.last().unwrap(), 6, 0, vec![dummy_tx(6)]);
    index_canonical_block(&db, &next, 6)?;
    assert_eq!(idx_tip(&db), Some(next), "index write did not carry its marker");

    // Unindexing steps the marker back to the parent in the same write.
    unindex_canonical_block(&db, &next, 6, Some(chain.last().unwrap()))?;
    assert_eq!(idx_tip(&db), Some(*chain.last().unwrap()));
    assert_eq!(get_block_hash_by_height(&db, 6)?, None);
    Ok(())
}

// -----------------------------------------------------------------------------
// (4) a datadir written by an older node carries version 1 markers in the meta tree.
// They must be ignored (never read as a completeness claim) and the index rebuilt.
// -----------------------------------------------------------------------------
#[test]
fn a_pre_v017_marker_in_meta_is_ignored_and_rebuilt() -> Result<()> {
    let tmp = TempDir::new()?;
    let db = open_db(&tmp);
    let chain = build_chain(&db, 5, 0);
    let tip = *chain.last().unwrap();

    // Simulate the old layout: version 1 marker and a tip marker, both in meta, no idx data.
    meta_put_bytes(&db, k_idx_version(), b"1")?;
    meta_put_bytes(&db, k_idx_tip(), &tip)?;

    assert!(
        !idx_fresh(&db),
        "an old meta marker must never be read as a fresh index"
    );
    assert_eq!(idx_tip(&db), None);

    for _ in 0..50 {
        if reconcile_tick(&db, 2)? {
            break;
        }
    }
    assert!(idx_fresh(&db), "index must rebuild after the version change");
    assert_eq!(idx_tip(&db), Some(tip));
    assert!(
        meta_get_bytes(&db, k_idx_version())?.is_none(),
        "the stale meta markers must be cleaned up, not left to confuse a later reader"
    );
    Ok(())
}

// -----------------------------------------------------------------------------
// (5) a marker the header store cannot explain is an error the loop can count, and
// reset_index recovers from it. Before this, the same error repeated every 5 seconds forever.
// -----------------------------------------------------------------------------
#[test]
fn an_unexplainable_marker_errors_then_resets_clean() -> Result<()> {
    let tmp = TempDir::new()?;
    let db = open_db(&tmp);
    let chain = build_chain(&db, 10, 0);
    let tip = *chain.last().unwrap();

    for _ in 0..50 {
        if reconcile_tick(&db, 4)? {
            break;
        }
    }
    assert!(idx_fresh(&db));

    // Point the marker at a block this node has never heard of, and move the tip so the
    // reconciler has to plan a walk from it.
    db.idx.insert(k_idx_tip(), &[0xEE; 32])?;
    let new_tip = append_block(&db, tip, 10, 0, vec![dummy_tx(10)]);
    set_tip(&db, &new_tip)?;

    let mut plan: Option<ReconcilePlan> = None;
    for attempt in 1..=3 {
        let err = reconcile_tick_planned(&db, 4, &mut plan)
            .expect_err("planning from an unknown marker must fail loudly");
        assert!(
            format!("{err:#}").contains("header index missing"),
            "attempt {attempt}: unexpected error: {err:#}"
        );
    }

    // What run_reconciler does after RECONCILE_ERRORS_BEFORE_RESET failures.
    reset_index(&db)?;
    assert_eq!(idx_tip(&db), None, "reset must clear the bad marker");

    let mut plan: Option<ReconcilePlan> = None;
    for _ in 0..50 {
        if reconcile_tick_planned(&db, 4, &mut plan)? {
            break;
        }
    }
    assert!(idx_fresh(&db), "index must rebuild itself after the reset");
    assert_eq!(idx_tip(&db), Some(new_tip));
    assert!(
        get_tx_locator(&db, &txid(&dummy_tx(10)))?.is_some(),
        "rebuild did not cover the whole chain"
    );
    Ok(())
}

// -----------------------------------------------------------------------------
// (6) The reconciler stalls (does not advance the marker) at a block whose body is missing,
// rather than skipping it, so a later fresh-marker miss can never be a confident lie. This
// must keep holding now that the plan persists across ticks.
// -----------------------------------------------------------------------------
#[test]
fn a_missing_body_stalls_the_marker_instead_of_skipping_the_block() -> Result<()> {
    let tmp = TempDir::new()?;
    let db = open_db(&tmp);
    let chain = build_chain(&db, 10, 0);

    // Header-first sync: block 5's body has not arrived yet.
    db.blocks.remove(k_block(&chain[5]))?;

    let mut plan: Option<ReconcilePlan> = None;
    for _ in 0..50 {
        if reconcile_tick_planned(&db, 4, &mut plan)? {
            panic!("must not report convergence while a body is missing");
        }
    }

    assert!(!idx_fresh(&db), "marker must not claim coverage past the hole");
    assert_eq!(
        idx_tip(&db),
        Some(chain[4]),
        "marker must stop at the last block that was fully indexed"
    );
    assert!(
        get_tx_locator(&db, &txid(&dummy_tx(6)))?.is_none(),
        "a block past the hole was indexed, so the marker prefix is not contiguous"
    );

    // The body arrives; the reconciler picks up where it stopped.
    let blk = Block {
        header: BlockHeader {
            version: 1,
            prev: chain[4],
            merkle: [0u8; 32],
            time: 5,
            bits: 0,
            nonce: 0,
        },
        txs: vec![dummy_tx(5)],
    };
    db.blocks
        .insert(k_block(&chain[5]), consensus_bincode().serialize(&blk)?)?;

    for _ in 0..50 {
        if reconcile_tick_planned(&db, 4, &mut plan)? {
            break;
        }
    }
    assert!(idx_fresh(&db), "index must converge once the body lands");
    assert!(get_tx_locator(&db, &txid(&dummy_tx(5)))?.is_some());
    assert!(get_tx_locator(&db, &txid(&dummy_tx(9)))?.is_some());
    Ok(())
}

// -----------------------------------------------------------------------------
// (7) The plan-reuse interlock. A plan may only be consumed while the marker is exactly where
// that plan's next step expects it. If anything moves the marker behind the plan's back, the
// plan MUST be discarded and rebuilt.
//
// The reachable version of "anything" is a reset: run_reconciler's self-heal clears the index
// while a plan may exist. Blindly continuing would index the remaining blocks and leave the
// already-consumed prefix unindexed under a marker that claims to cover it, which is a
// completeness marker lying about its own coverage: the confident-absence class this whole
// subsystem exists to prevent.
// -----------------------------------------------------------------------------
#[test]
fn a_plan_is_discarded_when_the_marker_moves_behind_its_back() -> Result<()> {
    let tmp = TempDir::new()?;
    let db = open_db(&tmp);
    let chain = build_chain(&db, 30, 0);

    let mut plan: Option<ReconcilePlan> = None;
    assert!(!reconcile_tick_planned(&db, 8, &mut plan)?);
    assert_eq!(idx_tip(&db), Some(chain[7]), "first tick indexed heights 0..7");
    assert!(plan.is_some());

    // Something else wipes the index while the plan still thinks it is at height 7.
    reset_index(&db)?;
    assert_eq!(idx_tip(&db), None);

    // Keep feeding the SAME plan variable.
    for _ in 0..100 {
        if reconcile_tick_planned(&db, 8, &mut plan)? {
            break;
        }
    }

    assert!(idx_fresh(&db), "index must converge");
    // The whole chain must be indexed, especially the prefix the stale plan had already consumed.
    for (h, hash) in chain.iter().enumerate() {
        assert_eq!(
            get_block_hash_by_height(&db, h as u64)?,
            Some(*hash),
            "height {h} missing after the reset: the stale plan was consumed instead of rebuilt"
        );
        assert!(
            get_tx_locator(&db, &txid(&dummy_tx(h as u8)))?.is_some(),
            "tx of block {h} missing after the reset"
        );
    }
    Ok(())
}

// -----------------------------------------------------------------------------
// (8) A duplicate txid across two canonical blocks degrades exactly that ONE txid, and the
// index still converges for everything else.
//
// Coinbase txids are not consensus-unique while COINBASE_HEIGHT_PREFIX_ACTIVATION_HEIGHT is
// u64::MAX, so a miner can reuse an earlier coinbase byte-for-byte. Overwriting the locator would
// be silently destructive (unindexing either block deletes an entry the other still owns, so a
// later miss reads as a PROVED absence). Failing the tick instead would be worse in the other
// direction: one adversarial block would permanently disable the whole tx-lookup subsystem on
// every node, with no operator recourse. Marking the single txid ambiguous is the proportionate
// answer, and this test pins that it is genuinely proportionate.
// -----------------------------------------------------------------------------
#[test]
fn a_duplicate_txid_degrades_only_itself() -> Result<()> {
    let tmp = TempDir::new()?;
    let db = open_db(&tmp);

    // Heights 0..4, with the SAME transaction in blocks 1 and 3.
    let dup = dummy_tx(0x77);
    let dup_id = txid(&dup);
    let mut chain = Vec::new();
    let mut prev = [0u8; 32];
    for h in 0..5u64 {
        let txs = if h == 1 || h == 3 {
            vec![dup.clone()]
        } else {
            vec![dummy_tx(h as u8)]
        };
        let hash = append_block(&db, prev, h, 0, txs);
        chain.push(hash);
        prev = hash;
    }
    set_tip(&db, chain.last().unwrap())?;

    let mut plan: Option<ReconcilePlan> = None;
    let mut converged = false;
    for _ in 0..50 {
        converged = reconcile_tick_planned(&db, 8, &mut plan)?;
        if converged {
            break;
        }
    }

    // The index MUST still converge. One duplicate txid is not a reason to disable tx lookup for
    // the whole chain.
    assert!(converged, "a duplicate txid must not stop the index converging");
    assert!(idx_fresh(&db), "marker must reach the tip");

    // The duplicated txid is ambiguous: a "cannot say", never an absence.
    assert_eq!(get_tx_entry(&db, &dup_id)?, Some(TxIndexEntry::Ambiguous));
    assert!(get_tx_locator(&db, &dup_id)?.is_none());

    // resolve_via_index must hand it to the scan rather than answer Absent, even though the
    // marker is fresh. This is the assertion that matters: a fresh marker plus a missing locator
    // is normally a PROVED absence.
    let at_tip = fresh_tip(&db).expect("index is fresh");
    assert_eq!(
        resolve_via_index(&db, &dup_id, at_tip),
        None,
        "an ambiguous txid must fall through to the scan, never be reported absent"
    );
    // End to end, the scan finds it.
    assert!(matches!(
        locate_tx(&db, &dup_id, 100),
        ScanOutcome::Found { .. }
    ));

    // Every other txid keeps its O(1) locator, and an unrelated miss is still a proved absence.
    for h in [0u64, 2, 4] {
        assert!(
            get_tx_locator(&db, &txid(&dummy_tx(h as u8)))?.is_some(),
            "block {h} lost its locator over an unrelated duplicate"
        );
    }
    assert!(matches!(
        locate_tx(&db, &[0xEE; 32], 100),
        ScanOutcome::Absent { .. }
    ));
    Ok(())
}
