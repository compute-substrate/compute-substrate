// The address index answers /utxos exactly as the scan does: for every address
// at every tip of a generated chain with many addresses, spends, coinbases (two repeating an
// earlier coinbase's txid) and reorgs of several depths, applied through the production apply and
// reorg path. Same outputs in the same order, the same height and coinbase flag for each, the same
// tip height and lifetime totals: every field and total /utxos serves is a function of these
// (`api::utxos_resp`). docs/behaviour.md "The address index".
#![cfg(feature = "test-bypass")] // toy-chain fixture: needs the PoW/genesis bypass (cargo test --features test-bypass)

mod testutil_addr_chain;

use anyhow::Result;
use tempfile::TempDir;

use csd::chain::reorg::recover_if_needed;
use csd::state::addr_index::{check_against_scan, read, read_via_index_at, read_via_scan};
use csd::state::db::{get_tip, get_utxo, get_utxo_meta, put_utxo, set_tip, Stores};
use csd::state::tx_scan::{fresh_tip, idx_fresh, idx_tip};
use csd::state::utxo::undo_block;
use csd::types::{OutPoint, TxOut};
use testutil_addr_chain::{answer, assert_index_equals_scan, reconcile, ChainGen, Coinbase};

fn phantom() -> OutPoint {
    OutPoint { txid: [0xab; 32], vout: 7 }
}

fn open(dir: &TempDir) -> Stores {
    Stores::open(dir.path().to_str().unwrap()).unwrap()
}

/// Checks one tip: before the reconciler runs the read is the scan's; once it has run, the index
/// answers for every address, equal to the scan, and holds exactly the UTXO tree's outputs.
fn check_tip(db: &Stores, gen: &ChainGen, ctx: &str) -> Result<usize> {
    let universe = gen.universe();
    for a in &universe {
        let r = read(db, a, true)?;
        assert!(!r.via_index, "{ctx}: the index answered before it covered the tip");
        assert_eq!(answer(r), answer(read_via_scan(db, a, true)?), "{ctx}");
    }
    reconcile(db, 3)?;
    let n = assert_index_equals_scan(db, &universe, ctx)?;
    let check = check_against_scan(db)?;
    assert!(check.mismatches.is_empty(), "{ctx}: {:?}", check.mismatches);
    assert_eq!(check.index_entries, check.utxo_rows, "{ctx}");
    Ok(n)
}

#[test]
fn the_index_answers_as_the_scan_for_every_address_at_every_tip() -> Result<()> {
    let dir = TempDir::new()?;
    let db = open(&dir);
    let mut gen = ChainGen::new(90, 10, 6);
    let (mut tips, mut reads) = (0usize, 0usize);
    let mut step = |db: &Stores, gen: &mut ChainGen, what: &str| -> Result<()> {
        tips += 1;
        reads += check_tip(db, gen, &format!("tip move {tips} ({what})"))?;
        Ok(())
    };

    gen.extend(&db, false, false)?;
    step(&db, &mut gen, "genesis")?;
    let (mut repeated, mut restored) = (Vec::new(), 0);
    for depth in [1u64, 2, 4, 8, 16] {
        for i in 0..20 {
            // The last two blocks before the depth-2 reorg repeat an earlier coinbase whose coin
            // is still unspent (`ChainGen::build` says which): one overwrites the coin, one spends
            // it in a transaction of its own and then recreates it, so the index writes nothing for
            // the coin and records its owner to undo the block.
            let want = match (depth, i) {
                (2, 18) => Coinbase::Overwrites,
                (2, 19) => Coinbase::SpendsThenRecreates,
                _ => Coinbase::New,
            };
            let (block, got) = gen.extend(&db, want != Coinbase::New, want == Coinbase::SpendsThenRecreates)?;
            assert_eq!(got, want, "block {i} before the depth-{depth} reorg");
            if got != Coinbase::New {
                let op = gen.coinbase_outpoint(&block);
                repeated.push((op, get_utxo_meta(&db, &op)?.expect("the repeated coin").height));
            }
            step(&db, &mut gen, "extend")?;
        }
        gen.reorg(&db, depth)?;
        // The reorg takes both blocks out and keeps the coin's own block (the coin is back at a
        // lower height), so taking them out of the index has to restore the coin's owner from
        // their undo records.
        for (op, repeated_at) in repeated.drain(..) {
            let back = get_utxo_meta(&db, &op)?.map(|m| m.height);
            assert!(back.is_some_and(|h| h < repeated_at), "depth-{depth} reorg: coin height {back:?}, repeated at {repeated_at}");
            restored += 1;
        }
        step(&db, &mut gen, &format!("reorg depth {depth}"))?;
    }
    assert_eq!(restored, 2);
    eprintln!("[replay] {tips} tips, {reads} address reads compared with the scan, reorg depths 1, 2, 4, 8, 16");
    Ok(())
}

// A restart rebuilds the state from genesis (`rebuild_state_to_tip`, which clears the UTXO trees
// and replays) and leaves the idx tree as it was: the index is current again as soon as the
// rebuild ends, with no reconciler work, and still equal to the scan.
#[test]
fn a_restart_rebuilds_the_state_and_the_index_is_current_without_rework() -> Result<()> {
    let dir = TempDir::new()?;
    let mut gen = ChainGen::new(91, 6, 3);
    {
        let db = open(&dir);
        for i in 0..40 {
            gen.extend(&db, false, false)?;
            if i == 30 {
                gen.reorg(&db, 3)?;
            }
        }
        reconcile(&db, 1_000)?;
        // A coin no block made: the rebuild from genesis must not carry it over.
        put_utxo(&db, &phantom(), &TxOut { value: 5, script_pubkey: gen.universe()[0] })?;
        db.flush_all()?;
    }
    let db = open(&dir);
    recover_if_needed(&db, None)?;
    assert!(get_utxo(&db, &phantom())?.is_none(), "the restart did not rebuild the state from genesis");
    assert!(idx_fresh(&db), "the index must be current right after the state rebuild");
    assert_index_equals_scan(&db, &gen.universe(), "after the restart")?;
    let check = check_against_scan(&db)?;
    assert!(check.mismatches.is_empty(), "{:?}", check.mismatches);
    Ok(())
}

// A read is the index's only if the marker and the tip are still the tip it started at when it ends:
// one that a new block overtook falls back to the scan, which sees the new block's coins.
#[test]
fn a_read_that_a_new_block_overtakes_falls_back_to_the_scan() -> Result<()> {
    let dir = TempDir::new()?;
    let db = open(&dir);
    let mut gen = ChainGen::new(92, 6, 3);
    for _ in 0..12 {
        gen.extend(&db, false, false)?;
    }
    reconcile(&db, 1_000)?;
    let started_at = fresh_tip(&db).expect("current");
    gen.extend(&db, false, false)?;
    reconcile(&db, 1_000)?;
    for a in gen.universe() {
        assert!(read_via_index_at(&db, &a, true, started_at).is_none(), "0x{}", hex::encode(a));
        let now = read(&db, &a, true)?;
        assert!(now.via_index && now.tip != Some(started_at));
        assert_eq!(answer(now), answer(read_via_scan(&db, &a, true)?));
    }
    Ok(())
}

// A block's index batch outlived its state: the state is back at the parent (undone, as a lost
// apply leaves it) while the marker names the block. Every read is the scan's until the reconciler
// takes the block back out, and then the index equals the scan again.
#[test]
fn a_marker_past_the_state_answers_through_the_scan_until_reconciled() -> Result<()> {
    let dir = TempDir::new()?;
    let db = open(&dir);
    let mut gen = ChainGen::new(93, 6, 3);
    for _ in 0..15 {
        gen.extend(&db, false, false)?;
    }
    let older = get_tip(&db)?.expect("tip");
    let (newer, _) = gen.extend(&db, false, false)?;
    reconcile(&db, 1_000)?;
    undo_block(&db, &newer)?;
    set_tip(&db, &older)?;
    assert_eq!(idx_tip(&db), Some(newer), "the marker is past the state");
    for a in gen.universe() {
        let r = read(&db, &a, true)?;
        assert!(!r.via_index);
        assert_eq!(answer(r), answer(read_via_scan(&db, &a, true)?));
    }
    reconcile(&db, 1_000)?;
    assert_eq!(idx_tip(&db), Some(older));
    assert_index_equals_scan(&db, &gen.universe(), "after the reconciler took the block back out")?;
    let check = check_against_scan(&db)?;
    assert!(check.mismatches.is_empty(), "{:?}", check.mismatches);
    Ok(())
}

// The UTXO tree decides membership: an index entry for an output the UTXO tree does not hold adds
// nothing to the read, and the offline check names it.
#[test]
fn a_stray_index_entry_adds_no_output_and_the_check_names_it() -> Result<()> {
    let dir = TempDir::new()?;
    let db = open(&dir);
    let mut gen = ChainGen::new(94, 4, 2);
    for _ in 0..10 {
        gen.extend(&db, false, false)?;
    }
    reconcile(&db, 1_000)?;
    let addr = gen.universe()[0];
    let before = read(&db, &addr, true)?;
    let stray = phantom();
    let outpoint = [&stray.txid[..], &stray.vout.to_le_bytes()].concat();
    db.idx.insert([&b"a/"[..], &addr, &outpoint].concat(), &[][..])?;
    db.idx.insert([&b"ao/"[..], &outpoint].concat(), &addr[..])?;
    let after = read(&db, &addr, true)?;
    assert!(after.via_index);
    assert_eq!(answer(after), answer(before));
    let check = check_against_scan(&db)?;
    assert!(check.mismatches.iter().any(|m| m.contains("the UTXO tree does not")), "{:?}", check.mismatches);
    Ok(())
}
