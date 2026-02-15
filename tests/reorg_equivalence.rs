// tests/reorg_equivalence.rs
use anyhow::{Context, Result};
use std::path::Path;
use tempfile::TempDir;

use csd::chain::index::{header_hash, index_header};
use csd::chain::pow::pow_ok;
use csd::chain::reorg::maybe_reorg_to;
use csd::codec;
use csd::params::{INITIAL_BITS, INITIAL_REWARD};
use csd::state::db::{k_block, set_tip, Stores};
use csd::state::fingerprint::{fingerprint, fmt_fp};
use csd::state::app_state::epoch_of;
use csd::state::utxo::validate_and_apply_block;
use csd::types::{Block, BlockHeader, Hash32, Transaction};

fn open_db(tmp: &TempDir) -> Result<Stores> {
    Stores::open(tmp.path().to_str().unwrap()).context("Stores::open")
}

/// You likely already have this helper. If your coinbase signature differs,
/// adjust ONLY this function.
fn make_coinbase(height: u64) -> Transaction {
    // deterministic test miner address (20 bytes)
    let miner: [u8; 20] = [0x11u8; 20];
    csd::chain::mine::coinbase(miner, INITIAL_REWARD, height)
}

/// Minimal merkle for our test: if 1 tx, merkle = txid(tx).
/// If multiple, we do a simple Bitcoin-ish merkle (pair-hash, duplicate last).
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

/// Mines a header by scanning nonce until pow_ok(header_hash, bits).
/// If your pow_ok signature differs, adjust this function ONLY.
fn mine_header(mut hdr: BlockHeader) -> Result<BlockHeader> {
    // If your pow_ok expects (hash, bits) or (hash32, bits), adapt here.
    for _ in 0..5_000_000u64 {
        let h = header_hash(&hdr);
        if pow_ok(&h, hdr.bits) {
            return Ok(hdr);
        }
        hdr.nonce = hdr.nonce.wrapping_add(1);
    }
    anyhow::bail!("failed to mine header within nonce budget")
}

/// Build + persist + index + apply one block extending `prev_hash` at `height`.
/// Returns block hash.
fn apply_mined_block(db: &Stores, prev_hash: Hash32, height: u64, time: u64) -> Result<Hash32> {
    let cb = make_coinbase(height);
    let txs = vec![cb];

    let hdr = BlockHeader {
        version: 1,
        prev: prev_hash,
        merkle: merkle_root(&txs),
        time,
        bits: INITIAL_BITS,
        nonce: 0,
    };

    let hdr = mine_header(hdr).context("mine_header")?;
    let bh = header_hash(&hdr);

    let blk = Block { header: hdr, txs };

    // Persist block bytes (so reorg/apply-path can load it)
    let bytes = codec::consensus_bincode()
        .serialize(&blk)
        .context("serialize Block")?;
    db.blocks
        .insert(k_block(&bh), bytes)
        .context("db.blocks.insert")?;

    // Index header (so get_hidx works and chainwork/height exists)
let parent_hi = if blk.header.prev == [0u8; 32] {
    None
} else {
    // parent must already be indexed
    get_hidx(db, &blk.header.prev).context("get_hidx(parent)")?
};
index_header(db, &blk.header, parent_hi.as_ref()).context("index_header")?;

    // Apply (UTXO + APP), then set tip.
    validate_and_apply_block(db, &blk, epoch_of(height), height).context("validate_and_apply_block")?;
    set_tip(db, &bh).context("set_tip")?;

    Ok(bh)
}

/// Builds a linear chain of `n` blocks starting from genesis_prev (all-zero prev).
/// Returns Vec of block hashes by height (0..n-1).
fn build_chain(db: &Stores, n: u64, start_time: u64) -> Result<Vec<Hash32>> {
    let mut out = Vec::with_capacity(n as usize);
    let mut prev = [0u8; 32];
    for h in 0..n {
        let t = start_time + (h * 60); // deterministic time spacing
        let bh = apply_mined_block(db, prev, h, t).with_context(|| format!("apply block height={h}"))?;
        out.push(bh);
        prev = bh;
    }
    Ok(out)
}

/// Builds a fork off an ancestor height `fork_height` (inclusive parent is fork_height-1).
/// Returns Vec of hashes for the fork blocks (heights fork_height..fork_height+fork_len-1).
fn build_fork(
    db: &Stores,
    base_hashes: &[Hash32],
    fork_height: u64,
    fork_len: u64,
    start_time: u64,
) -> Result<Vec<Hash32>> {
    anyhow::ensure!(fork_height > 0, "fork_height must be > 0 (need a parent)");
    let parent_hash = base_hashes[(fork_height - 1) as usize];

    let mut out = Vec::with_capacity(fork_len as usize);
    let mut prev = parent_hash;

    for i in 0..fork_len {
        let h = fork_height + i;
        // Make fork times distinct but still monotonic
        let t = start_time + (h * 60) + 17;
        let bh = apply_mined_block(db, prev, h, t).with_context(|| format!("apply fork block height={h}"))?;
        out.push(bh);
        prev = bh;
    }

    Ok(out)
}

/// Rebuild chain B from scratch into a fresh DB, using the stored blocks in `src_db`.
/// (We’re not “syncing”; we just replay the canonical chain deterministically.)
fn replay_chain_from_blocks(dst: &Stores, src_db: &Stores, chain: &[Hash32]) -> Result<()> {
    for (height, bh) in chain.iter().enumerate() {
        let Some(v) = src_db.blocks.get(k_block(bh)).context("src_db.blocks.get")? else {
            anyhow::bail!("missing block bytes in src_db for {}", hex::encode(bh));
        };
        let blk: Block = codec::consensus_bincode()
            .deserialize(&v)
            .context("deserialize Block")?;

        // Index header + apply + set tip (same as normal import pipeline)
let parent_hi = if blk.header.prev == [0u8; 32] {
    None
} else {
    // parent must already be indexed
    get_hidx(db, &blk.header.prev).context("get_hidx(parent)")?
};
index_header(db, &blk.header, parent_hi.as_ref()).context("index_header")?;
        validate_and_apply_block(dst, &blk, epoch_of(height as u64), height as u64)
            .context("validate_and_apply_block(dst)")?;
        set_tip(dst, bh).context("set_tip(dst)")?;
    }
    Ok(())
}

#[test]
fn reorg_produces_same_state_as_direct_apply() -> Result<()> {
    // DB #1: apply base chain A, then fork B exists and we reorg to it.
    let tmp1 = TempDir::new().context("TempDir 1")?;
    let db1 = open_db(&tmp1).context("open db1")?;

    // Build base chain A of 40 blocks.
    let a = build_chain(&db1, 40, 1_700_000_000).context("build chain A")?;
    let tip_a = *a.last().unwrap();

    // Build fork B off height 20 and make it longer than A.
    // fork heights: 20..(20+35-1)=54, so it overtakes A’s chainwork by length.
    let fork_height = 20u64;
    let fork_len = 35u64;
    let b_tail = build_fork(&db1, &a, fork_height, fork_len, 1_700_000_000).context("build fork B")?;
    let tip_b = *b_tail.last().unwrap();

    // At this point db1 tip is tip_b because we “applied” fork blocks as we mined them.
    // That’s fine: we want a realistic environment where both branches exist in blocks/hdr,
    // but canonical tip can move. To test reorg properly, we force tip back to A then call maybe_reorg_to(B).
    set_tip(&db1, &tip_a).context("force tip back to A")?;

    // Now reorg to B using the real reorg engine.
    maybe_reorg_to(&db1, &tip_b, None).context("maybe_reorg_to(B)")?;

    let fp1 = fingerprint(&db1).context("fingerprint(db1)")?;
    println!("[test] db1 fp: {}", fmt_fp(&fp1));

    // DB #2: fresh DB, direct-apply the canonical chain B from genesis.
    // Canonical chain is: A[0..fork_height-1] + fork blocks (fork_height..).
    let tmp2 = TempDir::new().context("TempDir 2")?;
    let db2 = open_db(&tmp2).context("open db2")?;

    let mut canon: Vec<Hash32> = Vec::new();
    canon.extend_from_slice(&a[0..(fork_height as usize)]);
    canon.extend_from_slice(&b_tail);

    // Replay those blocks into db2 using bytes from db1.
    replay_chain_from_blocks(&db2, &db1, &canon).context("replay canonical chain into db2")?;

    let fp2 = fingerprint(&db2).context("fingerprint(db2)")?;
    println!("[test] db2 fp: {}", fmt_fp(&fp2));

    // Must match exactly.
    anyhow::ensure!(fp1.tip == fp2.tip, "tip mismatch: {} vs {}", hex::encode(fp1.tip), hex::encode(fp2.tip));
    anyhow::ensure!(fp1.utxo_root == fp2.utxo_root, "utxo_root mismatch");
    anyhow::ensure!(fp1.utxo_meta_root == fp2.utxo_meta_root, "utxo_meta_root mismatch");
    anyhow::ensure!(fp1.app_root == fp2.app_root, "app_root mismatch");

    Ok(())
}
