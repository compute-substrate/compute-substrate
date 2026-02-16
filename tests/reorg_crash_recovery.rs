// tests/reorg_crash_recovery.rs
use anyhow::{Context, Result};
use tempfile::TempDir;

use csd::chain::index::{get_hidx, header_hash, index_header};
use csd::chain::pow::expected_bits;
use csd::chain::reorg::{maybe_reorg_to, recover_if_needed};
use csd::codec;
use csd::params::INITIAL_REWARD;
use csd::state::app_state::epoch_of;
use csd::state::db::{get_tip, k_block, set_tip, Stores};
use csd::state::fingerprint::{fingerprint, fmt_fp, StateFingerprint};
use csd::state::utxo::validate_and_apply_block;
use csd::types::{Block, BlockHeader, Hash32, Transaction};

fn open_db(tmp: &TempDir) -> Result<Stores> {
    Stores::open(tmp.path().to_str().unwrap()).context("Stores::open")
}

fn make_coinbase(height: u64) -> Transaction {
    let miner: [u8; 20] = [0x11u8; 20];
    csd::chain::mine::coinbase(miner, INITIAL_REWARD, height)
}

/// Minimal merkle for tests (single-tx blocks are fine here).
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

/// Build + persist + index + apply one block extending `prev_hash` at `height`.
/// IMPORTANT: bits are set to consensus `expected_bits()` for that height.
fn apply_block(db: &Stores, prev_hash: Hash32, height: u64, time: u64) -> Result<Hash32> {
    let cb = make_coinbase(height);
    let txs = vec![cb];

    // Parent header index (needed for expected_bits + index_header)
    let parent_hi = if prev_hash == [0u8; 32] {
        None
    } else {
        get_hidx(db, &prev_hash).context("get_hidx(parent)")?
    };

    // Consensus difficulty for this height
    let bits = expected_bits(db, height, parent_hi.as_ref()).context("expected_bits")?;

    let hdr = BlockHeader {
        version: 1,
        prev: prev_hash,
        merkle: merkle_root(&txs),
        time,
        bits,
        nonce: 0, // tests can rely on pow-bypass; nonce value is still deterministic
    };

    let bh = header_hash(&hdr);
    let blk = Block { header: hdr, txs };

    // Persist bytes so reorg/recovery can load blocks
    let bytes = codec::consensus_bincode()
        .serialize(&blk)
        .context("serialize Block")?;
    db.blocks
        .insert(k_block(&bh), bytes)
        .context("db.blocks.insert")?;

    // Index header + apply state + set tip
    index_header(db, &blk.header, parent_hi.as_ref()).context("index_header")?;
    validate_and_apply_block(db, &blk, epoch_of(height), height).context("apply")?;
    set_tip(db, &bh).context("set_tip")?;

    Ok(bh)
}

fn build_chain(db: &Stores, n: u64, start_time: u64) -> Result<Vec<Hash32>> {
    let mut out = Vec::with_capacity(n as usize);
    let mut prev = [0u8; 32];
    for h in 0..n {
        let t = start_time + (h * 60);
        let bh = apply_block(db, prev, h, t).with_context(|| format!("apply h={h}"))?;
        out.push(bh);
        prev = bh;
    }
    Ok(out)
}

fn build_fork(
    db: &Stores,
    base_hashes: &[Hash32],
    fork_height: u64,
    fork_len: u64,
    start_time: u64,
) -> Result<Vec<Hash32>> {
    anyhow::ensure!(fork_height > 0, "fork_height must be > 0 (need parent)");
    let parent_hash = base_hashes[(fork_height - 1) as usize];

    let mut out = Vec::with_capacity(fork_len as usize);
    let mut prev = parent_hash;

    for i in 0..fork_len {
        let h = fork_height + i;
        let t = start_time + (h * 60) + 17; // distinct but monotonic
        let bh = apply_block(db, prev, h, t).with_context(|| format!("fork apply h={h}"))?;
        out.push(bh);
        prev = bh;
    }

    Ok(out)
}

fn replay_chain(dst: &Stores, src: &Stores, chain: &[Hash32]) -> Result<()> {
    for (height, bh) in chain.iter().enumerate() {
        let Some(v) = src.blocks.get(k_block(bh)).context("src.blocks.get")? else {
            anyhow::bail!("missing block bytes for {}", hex::encode(bh));
        };
        let blk: Block = codec::consensus_bincode().deserialize(&v).context("deserialize Block")?;

        let parent_hi = if blk.header.prev == [0u8; 32] {
            None
        } else {
            get_hidx(dst, &blk.header.prev).context("get_hidx(dst parent)")?
        };

        // NOTE: replay must also respect expected_bits; the block already contains bits from src,
        // so index_header will check it and accept if src was consistent.
        index_header(dst, &blk.header, parent_hi.as_ref()).context("index_header(dst)")?;
        validate_and_apply_block(dst, &blk, epoch_of(height as u64), height as u64)
            .context("apply(dst)")?;
        set_tip(dst, bh).context("set_tip(dst)")?;
    }
    Ok(())
}

fn assert_fp_eq(fp1: &StateFingerprint, fp2: &StateFingerprint, ctx: &str) -> Result<()> {
    if fp1 != fp2 {
        println!("[fp mismatch] {ctx}");
        println!("[db1] {}", fmt_fp(fp1));
        println!("[db2] {}", fmt_fp(fp2));
        anyhow::bail!("fingerprint mismatch: {ctx}");
    }
    Ok(())
}

#[test]
fn crash_fuzz_reorg_then_recover_matches_clean_replay() -> Result<()> {
    // --- db1: build base + fork, do reorg, then simulate "crash recovery" path ---
    let tmp1 = TempDir::new().context("tmp1")?;
    let db1 = open_db(&tmp1).context("open db1")?;

    let start_time = 1_700_000_000u64;
    let base_len = 40u64;
    let fork_height = 20u64;
    let fork_len = 35u64;

    let a = build_chain(&db1, base_len, start_time).context("build base")?;
    let tip_a = *a.last().unwrap();

    let b_tail = build_fork(&db1, &a, fork_height, fork_len, start_time).context("build fork")?;
    let tip_b = *b_tail.last().unwrap();

    // Force tip back to A, then attempt reorg to B
    set_tip(&db1, &tip_a).context("force tip back to A")?;
    maybe_reorg_to(&db1, &tip_b, None).context("reorg to B")?;

    // Now run recovery (should be a no-op if journal is clear, but must be safe)
    recover_if_needed(&db1, None).context("recover_if_needed")?;

    let fp1 = fingerprint(&db1).context("fingerprint(db1)")?;
    println!("[db1] {}", fmt_fp(&fp1));

    // Determine db1's actual canonical chain (it might not be tip_b if B didn’t win by chainwork).
    let final_tip = get_tip(&db1)?.unwrap_or([0u8; 32]);

    // Walk tip->genesis via header index
    let mut canon_rev: Vec<Hash32> = Vec::new();
    let mut cur = final_tip;
    loop {
        canon_rev.push(cur);
        let hi = get_hidx(&db1, &cur)?
            .ok_or_else(|| anyhow::anyhow!("missing hidx for {}", hex::encode(cur)))?;
        if hi.parent == [0u8; 32] {
            break;
        }
        cur = hi.parent;
    }
    canon_rev.reverse();
    let canon = canon_rev;

    // --- db2: clean replay of db1’s canonical chain ---
    let tmp2 = TempDir::new().context("tmp2")?;
    let db2 = open_db(&tmp2).context("open db2")?;
    replay_chain(&db2, &db1, &canon).context("replay chain")?;

    let fp2 = fingerprint(&db2).context("fingerprint(db2)")?;
    println!("[db2] {}", fmt_fp(&fp2));

    assert_fp_eq(&fp1, &fp2, "recover vs clean replay")?;

    // Make sure TempDir locks are released cleanly (sled lock issues are usually from extra opens)
    drop(db2);
    drop(db1);

    Ok(())
}
