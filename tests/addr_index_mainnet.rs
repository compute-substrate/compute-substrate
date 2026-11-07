// Mainnet figures for the address index (docs/behaviour.md "The address index"). Replays a mainnet
// block file into a fresh datadir through the production checks (header index with PoW, full block
// validation, `set_tip`), times a restart's state rebuild (`recover_if_needed`) and the index's cold
// build by the reconciler, compares the index with the scan for every address, and prints the
// index's size and the read costs of the heaviest addresses.
//
//   CSD_MAINNET_BLOCKS=<file> cargo test --release --locked --test addr_index_mainnet -- --ignored --nocapture
//
// The file holds, per block in height order from genesis, the 32-byte block hash, a u32 LE length
// and the block's consensus bytes. CSD_MAINNET_DATADIR=<dir> (an empty or absent directory) keeps
// the datadir for `csd utxo-index-check`.
#![cfg(not(feature = "test-bypass"))] // real PoW and the mainnet genesis

use std::collections::BTreeMap;
use std::time::{Duration, Instant};

use anyhow::{bail, Context, Result};

use csd::chain::index::{header_hash, index_header, HeaderIndex};
use csd::codec::consensus_bincode;
use csd::state::addr_index::{check_against_scan, read_via_index, read_via_scan, scan_utxos};
use csd::state::app_state::epoch_of;
use csd::state::db::{k_block, set_tip, Stores};
use csd::state::tx_scan::{idx_fresh, reconcile_tick_planned, RECONCILE_BUDGET_PER_TICK};
use csd::state::utxo::validate_and_apply_block;
use csd::testutil::fastest;
use csd::types::{Block, Hash20, Hash32};

fn import(db: &Stores, raw: &[u8]) -> Result<u64> {
    let (mut off, mut parent, mut n) = (0usize, None::<HeaderIndex>, 0u64);
    while off < raw.len() {
        let hash: Hash32 = raw[off..off + 32].try_into()?;
        let len = u32::from_le_bytes(raw[off + 32..off + 36].try_into()?) as usize;
        let bytes = &raw[off + 36..off + 36 + len];
        let blk: Block = consensus_bincode().deserialize(bytes)?;
        if header_hash(&blk.header) != hash {
            bail!("block {n}: the header does not hash to its recorded hash");
        }
        db.blocks.insert(k_block(&hash), bytes)?;
        let hi = index_header(db, &blk.header, parent.as_ref()).with_context(|| format!("index_header {n}"))?;
        validate_and_apply_block(db, &blk, epoch_of(hi.height), hi.height).with_context(|| format!("apply {n}"))?;
        set_tip(db, &hash)?;
        parent = Some(hi);
        n += 1;
        off += 36 + len;
    }
    db.flush_all()?;
    Ok(n)
}

fn prefix_size(db: &Stores, prefix: &[u8]) -> (usize, usize) {
    db.idx
        .scan_prefix(prefix)
        .flatten()
        .fold((0, 0), |(n, b), (k, v)| (n + 1, b + k.len() + v.len()))
}

#[test]
#[ignore = "a measurement: needs CSD_MAINNET_BLOCKS, a mainnet block file in the format above"]
fn mainnet_replay_index_equals_scan_with_costs_and_size() -> Result<()> {
    let raw = std::fs::read(std::env::var("CSD_MAINNET_BLOCKS").context("CSD_MAINNET_BLOCKS")?)?;
    let tmp = tempfile::TempDir::new()?;
    let dir = std::env::var("CSD_MAINNET_DATADIR").map(std::path::PathBuf::from).unwrap_or_else(|_| tmp.path().into());
    let db = Stores::open(dir.to_str().context("datadir path")?)?;

    let t = Instant::now();
    let blocks = import(&db, &raw)?;
    println!("[mainnet] imported {blocks} blocks (header index, PoW, full validation) in {:?}", t.elapsed());

    let t = Instant::now();
    csd::chain::reorg::recover_if_needed(&db, None)?;
    println!("[mainnet] a restart's state rebuild from genesis (recover_if_needed): {:?}", t.elapsed());

    // One plan across the ticks, as `run_reconciler` keeps it: a fresh plan per tick would walk the
    // remaining headers again every tick, which production never does.
    let (t, mut ticks, mut plan) = (Instant::now(), 0u32, None);
    while !reconcile_tick_planned(&db, RECONCILE_BUDGET_PER_TICK, &mut plan)? {
        ticks += 1;
    }
    db.flush_all()?;
    let build = t.elapsed();
    println!(
        "[mainnet] cold build of the idx tree (txid and address index), {ticks} ticks of {RECONCILE_BUDGET_PER_TICK} blocks: {build:?} of work; the reconciler sleeps 50 ms between catch-up ticks, about {:?} more",
        Duration::from_millis(50) * ticks
    );

    let t = Instant::now();
    csd::chain::reorg::recover_if_needed(&db, None)?;
    println!(
        "[mainnet] a second restart: state rebuild {:?}, index current right after it: {}",
        t.elapsed(),
        idx_fresh(&db)
    );
    assert!(idx_fresh(&db));

    let t = Instant::now();
    let check = check_against_scan(&db)?;
    println!(
        "[mainnet] check at height {}: {} addresses, {} UTXO rows, {} index entries, {} lifetime entries, {} mismatches ({:?})",
        check.height,
        check.addresses,
        check.utxo_rows,
        check.index_entries,
        check.lifetime_addresses,
        check.mismatches.len(),
        t.elapsed()
    );
    assert!(check.mismatches.is_empty(), "{:?}", &check.mismatches[..check.mismatches.len().min(20)]);

    for (name, prefix) in [("a/", &b"a/"[..]), ("ao/", b"ao/"), ("au/", b"au/"), ("al/", b"al/"), ("whole idx", b"")] {
        let (n, bytes) = prefix_size(&db, prefix);
        println!("[mainnet] idx {name}: {n} entries, {bytes} bytes of keys and values");
    }

    // The heaviest holders by unspent count, the heaviest coinbase receivers, and an absent address.
    let mut holders: BTreeMap<Hash20, usize> = BTreeMap::new();
    for (_, v) in db.utxo.iter().flatten() {
        if let Ok(o) = consensus_bincode().deserialize::<csd::types::TxOut>(&v) {
            *holders.entry(o.script_pubkey).or_default() += 1;
        }
    }
    let mut by_count: Vec<(usize, Hash20)> = holders.iter().map(|(a, n)| (*n, *a)).collect();
    by_count.sort_unstable_by(|x, y| y.cmp(x));
    let median = by_count[by_count.len() / 2].1;
    let mut probes: Vec<(String, Hash20)> = by_count.iter().take(2).map(|(n, a)| (format!("{n} UTXOs"), *a)).collect();
    probes.push((format!("median holder, {} UTXOs", holders[&median]), median));
    let mut miners: Vec<(u64, u64, Hash20)> = Vec::new();
    for kv in db.idx.scan_prefix(b"al/").flatten() {
        let a: Hash20 = kv.0[3..].try_into()?;
        let (mined, outputs) = read_via_index(&db, &a, true).and_then(|r| r.lifetime).context("lifetime read")?;
        miners.push((outputs, mined, a));
    }
    miners.sort_unstable_by(|x, y| y.cmp(x));
    for (n, mined, a) in miners.iter().take(2) {
        let unspent = holders.get(a).copied().unwrap_or(0);
        probes.push((format!("{n} coinbase outputs, {mined} base units mined, {unspent} unspent"), *a));
    }
    probes.push(("absent".into(), [0x01; 20]));
    for (what, a) in probes {
        let index = fastest(5, || {
            read_via_index(&db, &a, false).expect("index read");
        });
        let index_life = fastest(5, || {
            read_via_index(&db, &a, true).expect("index read");
        });
        let scan = fastest(3, || {
            scan_utxos(&db, &a);
        });
        let scan_life = fastest(1, || {
            read_via_scan(&db, &a, true).unwrap();
        });
        println!(
            "[mainnet] 0x{} ({what}): index {index:?}, with lifetime {index_life:?}; scan {scan:?}, with the lifetime walk {scan_life:?}",
            hex::encode(a)
        );
    }
    Ok(())
}
