// tests/reorg_crash_recovery.rs
use anyhow::{Context, Result};
use tempfile::TempDir;

use csd::codec;
use csd::params::{INITIAL_BITS, INITIAL_REWARD};
use csd::state::app_state::epoch_of;
use csd::state::db::{k_block, set_tip, Stores};
use csd::state::fingerprint::{fingerprint, fmt_fp};
use csd::state::utxo::validate_and_apply_block;

use csd::chain::index::{get_hidx, header_hash, index_header, HeaderIndex};
use csd::chain::pow::expected_bits;
use csd::chain::reorg::{maybe_reorg_to, recover_if_needed};
use csd::types::{Block, BlockHeader, Hash32, Transaction};

fn open_db_path(path: &str) -> Result<Stores> {
    Stores::open(path).context("Stores::open")
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

/// Consensus-correct bits for the next block we are about to build.
fn bits_for_next_block(db: &Stores, height: u64, parent_hi: Option<&HeaderIndex>) -> Result<u32> {
    if height == 0 {
        Ok(INITIAL_BITS)
    } else {
        expected_bits(db, height, parent_hi).context("expected_bits(test)")
    }
}

fn build_block(prev: Hash32, height: u64, time: u64, bits: u32) -> Block {
    let cb = make_coinbase(height);
    let txs = vec![cb];

    let hdr = BlockHeader {
        version: 1,
        prev,
        merkle: merkle_root(&txs),
        time,
        bits,
        nonce: 0,
    };

    Block { header: hdr, txs }
}

fn persist_index_apply(db: &Stores, blk: &Block, height: u64) -> Result<Hash32> {
    let bh = header_hash(&blk.header);

    // persist bytes
    let bytes = codec::consensus_bincode().serialize(blk).context("serialize Block")?;
    db.blocks.insert(k_block(&bh), bytes).context("db.blocks.insert")?;

    // parent index (unless genesis)
    let parent_hi = if blk.header.prev == [0u8; 32] {
        None
    } else {
        get_hidx(db, &blk.header.prev).context("get_hidx(parent)")?
    };

    // index header (enforces bits/time/pow rules)
    index_header(db, &blk.header, parent_hi.as_ref()).context("index_header")?;

    // apply state
    validate_and_apply_block(db, blk, epoch_of(height), height).context("apply")?;
    set_tip(db, &bh).context("set_tip")?;

    Ok(bh)
}

fn build_chain(db: &Stores, n: u64, start_time: u64) -> Result<Vec<Hash32>> {
    let mut hashes = Vec::with_capacity(n as usize);
    let mut prev = [0u8; 32];

    for h in 0..n {
        let t = start_time + h * 60;

        let parent_hi = if h == 0 {
            None
        } else {
            get_hidx(db, &prev).context("get_hidx(parent in build_chain)")?
        };
        let bits = bits_for_next_block(db, h, parent_hi.as_ref())?;

        let blk = build_block(prev, h, t, bits);
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

        let parent_hi = get_hidx(db, &prev).context("get_hidx(parent in build_fork)")?;
        let bits = bits_for_next_block(db, h, parent_hi.as_ref())?;

        let blk = build_block(prev, h, t, bits);
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
    // One TempDir for the “crashy” DB
    let tmp = TempDir::new().context("TempDir")?;
    let db_path = tmp.path().to_str().unwrap().to_string();

    // We also need to keep these hashes across opens
    let (a, tip_a, b_tail, tip_b, fork_height) = {
        // IMPORTANT: only one Stores open at a time
        let db = open_db_path(&db_path).context("open db")?;

        // base chain
        let a = build_chain(&db, 40, 1_700_000_000).context("build base")?;
        let tip_a = *a.last().unwrap();

        // fork that overtakes
        let fork_height = 20u64;
        let fork_len = 35u64;
        let b_tail =
            build_fork(&db, &a, fork_height, fork_len, 1_700_000_000).context("build fork")?;
        let tip_b = *b_tail.last().unwrap();

        // ensure canonical tip is A before invoking reorg
        set_tip(&db, &tip_a).context("force tip A")?;

        // optional crashpoint
        if crashpoint("pre_reorg") {
    return Ok(());
}

        // run reorg
        maybe_reorg_to(&db, &tip_b, None).context("baseline reorg failed")?;

        // drop happens at end of scope
        (a, tip_a, b_tail, tip_b, fork_height)
    };

    // ---- Recovery pass (reopen only after previous Stores is dropped) ----
    {
        let db = open_db_path(&db_path).context("reopen db for recovery")?;
        recover_if_needed(&db, None).context("recover_if_needed")?;
        let fp = fingerprint(&db).context("fingerprint(recovered)")?;
        println!("[test] recovered fp: {}", fmt_fp(&fp));
        // drop db before opening again anywhere
    }

    // ---- Clean replay into a separate DB ----
    let tmp_clean = TempDir::new().context("TempDir clean")?;
    let clean_path = tmp_clean.path().to_str().unwrap().to_string();

    // reopen the recovered db ONE more time to read block bytes for replay
    let fp_recovered = {
        let db = open_db_path(&db_path).context("reopen db to read blocks")?;
        let fp = fingerprint(&db).context("fingerprint(recovered again)")?;
        println!("[test] recovered fp (again): {}", fmt_fp(&fp));
        fp
    };

    // Now open both DBs sequentially (never at the same time)
    // 1) open recovered for reading bytes, but we can't keep it open while opening clean.
    // So: read bytes indirectly by replaying from a fresh open in the replay loop.
    {
        let db_clean = open_db_path(&clean_path).context("open clean db")?;

        // canonical chain is: A[0..fork_height-1] + fork blocks
        let mut canon: Vec<Hash32> = Vec::new();
        canon.extend_from_slice(&a[0..(fork_height as usize)]);
        canon.extend_from_slice(&b_tail);

        // For replay, open recovered DB inside this block-by-block loop in a minimal way:
        // simplest: reopen recovered once, replay, drop, and keep clean open.
        // But sled won't allow two opens simultaneously. Therefore we do the replay
        // as: close clean? No. So we do the replay in two phases:
        // - extract block bytes from recovered into memory
        // - then apply to clean
        drop(db_clean);
    }

    // Phase 1: extract canonical block bytes from recovered (one open)
    let canon_bytes: Vec<Vec<u8>> = {
        let db = open_db_path(&db_path).context("reopen db to extract canon bytes")?;

        let mut canon: Vec<Hash32> = Vec::new();
        canon.extend_from_slice(&a[0..(fork_height as usize)]);
        canon.extend_from_slice(&b_tail);

        let mut out = Vec::with_capacity(canon.len());
        for bh in &canon {
            let Some(v) = db.blocks.get(k_block(bh)).context("blocks.get")? else {
                anyhow::bail!("missing block bytes for {}", hex::encode(bh));
            };
            out.push(v.to_vec());
        }
        out
    };

    // Phase 2: apply bytes to clean (one open)
    let fp_clean = {
        let db_clean = open_db_path(&clean_path).context("open clean db (apply)")?;

        // reconstruct hashes list again
        let mut canon: Vec<Hash32> = Vec::new();
        canon.extend_from_slice(&a[0..(fork_height as usize)]);
        canon.extend_from_slice(&b_tail);

        for (height, (bh, bytes)) in canon.iter().zip(canon_bytes.iter()).enumerate() {
            let blk: Block = codec::consensus_bincode()
                .deserialize(bytes)
                .context("deserialize Block (canon_bytes)")?;

            // sanity: hash matches expected
            let got = header_hash(&blk.header);
            anyhow::ensure!(got == *bh, "canon_bytes hash mismatch at height={}", height);

            persist_index_apply(&db_clean, &blk, height as u64)
                .with_context(|| format!("clean apply height={height}"))?;
        }

        let fp = fingerprint(&db_clean).context("fingerprint(clean)")?;
        println!("[test] clean fp: {}", fmt_fp(&fp));
        fp
    };

    anyhow::ensure!(
        fp_recovered == fp_clean,
        "fingerprint mismatch recovered vs clean"
    );

    Ok(())
}
