// tests/reorg_crash_recovery.rs
use anyhow::{Context, Result};
use tempfile::TempDir;

use csd::codec;
use csd::params::{INITIAL_BITS, INITIAL_REWARD, POW_LIMIT_BITS};
use csd::state::db::{k_block, set_tip, Stores};
use csd::state::fingerprint::{fingerprint, fmt_fp};
use csd::state::app_state::epoch_of;
use csd::state::utxo::validate_and_apply_block;

use csd::chain::index::{get_hidx, header_hash, index_header};
use csd::chain::reorg::{maybe_reorg_to, recover_if_needed};
use csd::types::{Block, BlockHeader, Hash32, Transaction};

fn open_db(tmp: &TempDir) -> Result<Stores> {
    Stores::open(tmp.path().to_str().unwrap()).context("Stores::open")
}

// Optional crashpoint helper: NEVER errors if env var missing.
fn crashpoint(name: &str) -> bool {
    std::env::var("CSD_CRASHPOINT").ok().as_deref() == Some(name)
}

fn make_coinbase(height: u64) -> Transaction {
    let miner: [u8; 20] = [0x11u8; 20];
    csd::chain::mine::coinbase(miner, INITIAL_REWARD, height)
}

fn merkle_root(txs: &[Transaction]) -> Hash32 {
    use csd::crypto::txid;
    use sha2::{Digest, Sha256};

    fn h2(a: &Hash32, b: &Hash32) -> Hash32 {
        let mut hasher = Sha256::new();
        hasher.update(a);
        hasher.update(b);
        let x = hasher.finalize();
        let mut out = [0u8; 32];
        out.copy_from_slice(&x);
        out
    }

    let mut layer: Vec<Hash32> = txs.iter().map(txid).collect();
    if layer.is_empty() {
        return [0u8; 32];
    }
    while layer.len() > 1 {
        let mut next = Vec::with_capacity((layer.len() + 1) / 2);
        let mut i = 0usize;
        while i < layer.len() {
            let a = layer[i];
            let b = if i + 1 < layer.len() { layer[i + 1] } else { layer[i] };
            next.push(h2(&a, &b));
            i += 2;
        }
        layer = next;
    }
    layer[0]
}

// For tests we do NOT want real mining. Use POW_LIMIT_BITS and your pow.rs test-bypass.
// (If you keep pow bypass under cfg(test), this will still work in integration tests
// because integration tests compile the crate as a dependency without cfg(test).
// So: you should keep the bypass behind a crate feature, not cfg(test).)
fn test_bits() -> u32 {
    POW_LIMIT_BITS
}

fn build_block(prev: Hash32, height: u64, time: u64) -> Block {
    let cb = make_coinbase(height);
    let txs = vec![cb];
    let hdr = BlockHeader {
        version: 1,
        prev,
        merkle: merkle_root(&txs),
        time,
        bits: test_bits(),
        nonce: 0,
    };
    Block { header: hdr, txs }
}

fn persist_index_apply(db: &Stores, blk: &Block, height: u64) -> Result<Hash32> {
    let bh = header_hash(&blk.header);

    // persist bytes
    let bytes = codec::consensus_bincode().serialize(blk).context("serialize Block")?;
    db.blocks.insert(k_block(&bh), bytes).context("db.blocks.insert")?;

    // index header (parent must exist unless genesis)
    let parent_hi = if blk.header.prev == [0u8; 32] {
        None
    } else {
        get_hidx(db, &blk.header.prev).context("get_hidx(parent)")?
    };
    index_header(db, &blk.header, parent_hi.as_ref()).context("index_header")?;

    // apply
    validate_and_apply_block(db, blk, epoch_of(height), height).context("apply")?;
    set_tip(db, &bh).context("set_tip")?;
    Ok(bh)
}

fn build_chain(db: &Stores, n: u64, start_time: u64) -> Result<Vec<Hash32>> {
    let mut hashes = Vec::with_capacity(n as usize);
    let mut prev = [0u8; 32];

    for h in 0..n {
        let t = start_time + h * 60;
        let blk = build_block(prev, h, t);
        let bh = persist_index_apply(db, &blk, h).with_context(|| format!("apply h={h}"))?;
        hashes.push(bh);
        prev = bh;
    }
    Ok(hashes)
}

fn build_fork(
    db: &Stores,
    base: &[Hash32],
    fork_height: u64,
    fork_len: u64,
    start_time: u64,
) -> Result<Vec<Hash32>> {
    anyhow::ensure!(fork_height > 0);
    let mut out = Vec::with_capacity(fork_len as usize);
    let mut prev = base[(fork_height - 1) as usize];

    for i in 0..fork_len {
        let h = fork_height + i;
        let t = start_time + h * 60 + 17;
        let blk = build_block(prev, h, t);
        let bh = persist_index_apply(db, &blk, h).with_context(|| format!("fork apply h={h}"))?;
        out.push(bh);
        prev = bh;
    }
    Ok(out)
}

fn replay_chain(dst: &Stores, src: &Stores, canon: &[Hash32]) -> Result<()> {
    for (height, bh) in canon.iter().enumerate() {
        let Some(v) = src.blocks.get(k_block(bh)).context("src.blocks.get")? else {
            anyhow::bail!("missing block bytes for {}", hex::encode(bh));
        };
        let blk: Block = codec::consensus_bincode().deserialize(&v).context("deserialize Block")?;
        persist_index_apply(dst, &blk, height as u64).context("replay apply")?;
    }
    Ok(())
}

#[test]
fn crash_fuzz_reorg_then_recover_matches_clean_replay() -> Result<()> {
    // 1) Build a DB with a fork, then force tip back and start reorg.
    let tmp = TempDir::new().context("TempDir")?;
    let db = open_db(&tmp).context("open db")?;

    let a = build_chain(&db, 40, 1_700_000_000).context("build base")?;
    let tip_a = *a.last().unwrap();

    let fork_height = 20u64;
    let fork_len = 35u64;
    let b_tail = build_fork(&db, &a, fork_height, fork_len, 1_700_000_000).context("build fork")?;
    let tip_b = *b_tail.last().unwrap();

    // force canonical tip back to A, so reorg actually does work
    set_tip(&db, &tip_a).context("force tip A")?;

    // Optional crashpoint: if set, we simulate a crash by returning early AFTER the journal exists.
    // You can run the test multiple times with different CSD_CRASHPOINT values.
    if crashpoint("pre_reorg") {
        // journal doesn't exist yet; just exit cleanly
        return Ok(());
    }

    // Run reorg (this writes journal internally). If you want a "crash" mid-way,
    // use the crashpoints you already added inside reorg.rs/reorg_journal.rs.
    let r = maybe_reorg_to(&db, &tip_b, None).context("baseline reorg failed");

    if crashpoint("after_reorg_call") {
        // simulate process death after calling reorg: drop db without cleanup
        drop(db);
        // reopen and recover
        let db2 = open_db(&tmp).context("reopen db after crash")?;
        recover_if_needed(&db2, None).context("recover_if_needed")?;
        // continue below with comparisons
        let fp_rec = fingerprint(&db2)?;
        println!("[test] recovered fp: {}", fmt_fp(&fp_rec));
    } else {
        r?;
    }

    // 2) Open DB again (fresh handle) and run recovery to ensure idempotent safety.
    let db_rec = open_db(&tmp).context("reopen db")?;
    recover_if_needed(&db_rec, None).context("recover_if_needed(idempotent)")?;
    let fp1 = fingerprint(&db_rec).context("fingerprint(recovered)")?;
    println!("[test] recovered fp: {}", fmt_fp(&fp1));

    // 3) Clean replay DB from genesis using canonical chain (A[0..fork_height) + b_tail).
    let tmp_clean = TempDir::new().context("TempDir clean")?;
    let db_clean = open_db(&tmp_clean).context("open clean db")?;

    let mut canon: Vec<Hash32> = Vec::new();
    canon.extend_from_slice(&a[0..(fork_height as usize)]);
    canon.extend_from_slice(&b_tail);

    replay_chain(&db_clean, &db_rec, &canon).context("replay canonical")?;
    let fp2 = fingerprint(&db_clean).context("fingerprint(clean)")?;
    println!("[test] clean fp: {}", fmt_fp(&fp2));

    anyhow::ensure!(fp1 == fp2, "fingerprint mismatch recovered vs clean");

    Ok(())
}
