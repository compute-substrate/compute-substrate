// tests/reorg_equivalence.rs
use anyhow::{Context, Result};
use tempfile::TempDir;

use csd::chain::genesis::{make_genesis_block, GENESIS_TIME};
use csd::chain::index::get_hidx;
use csd::chain::index::{header_hash, index_header, HeaderIndex};
use csd::chain::pow::pow_ok;
use csd::chain::reorg::maybe_reorg_to;
use csd::codec;
use csd::params::{INITIAL_BITS, INITIAL_REWARD};
use csd::state::app_state::epoch_of;
use csd::state::db::{k_block, k_hdr, set_tip, Stores};
use csd::state::fingerprint::{fingerprint, fmt_fp};
use csd::state::utxo::validate_and_apply_block;
use csd::types::{Block, BlockHeader, Hash20, Hash32, Transaction};

fn open_db(tmp: &TempDir) -> Result<Stores> {
    Stores::open(tmp.path().to_str().unwrap()).context("Stores::open")
}

/// Deterministic test address (20 bytes).
fn test_addr20() -> Hash20 {
    [0x11u8; 20]
}

/// Coinbase helper (matches mine::coinbase(miner_h160, value, height))
fn make_coinbase(height: u64) -> Transaction {
    csd::chain::mine::coinbase(test_addr20(), INITIAL_REWARD, height)
}

/// Minimal merkle for test blocks.
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
fn mine_header(mut hdr: BlockHeader) -> Result<BlockHeader> {
    for _ in 0..5_000_000u64 {
        let h = header_hash(&hdr);
        if pow_ok(&h, hdr.bits) {
            return Ok(hdr);
        }
        hdr.nonce = hdr.nonce.wrapping_add(1);
    }
    anyhow::bail!("failed to mine header within nonce budget")
}

/// Bootstraps DB with a deterministic genesis WITHOUT calling index_header(genesis),
/// because index_header enforces params::GENESIS_HASH for prev=0.
/// Instead we manually insert a HeaderIndex entry for genesis into db.hdr.
fn bootstrap_genesis(db: &Stores) -> Result<Hash32> {
    let genesis: Block = make_genesis_block(test_addr20()).context("make_genesis_block")?;
    let gh = header_hash(&genesis.header);

    // Persist genesis block bytes
    let bytes = codec::consensus_bincode()
        .serialize(&genesis)
        .context("serialize genesis")?;
    db.blocks
        .insert(k_block(&gh), bytes)
        .context("db.blocks.insert(genesis)")?;

    // ✅ Manual header index insert (avoid index_header(genesis) foreign-genesis check)
    let hi = HeaderIndex {
        hash: gh,
        parent: [0u8; 32],
        height: 0,
        chainwork: 0, // baseline; chainwork comparisons still work for this test
        bits: genesis.header.bits,
        time: genesis.header.time,
    };
    let hi_bytes = codec::consensus_bincode()
        .serialize(&hi)
        .context("serialize HeaderIndex(genesis)")?;
    db.hdr
        .insert(k_hdr(&gh), hi_bytes)
        .context("db.hdr.insert(genesis HeaderIndex)")?;

    // Apply state at height=0
    validate_and_apply_block(db, &genesis, epoch_of(0), 0).context("apply genesis")?;

    // Set tip
    set_tip(db, &gh).context("set_tip(genesis)")?;

    Ok(gh)
}

fn parent_hi_for(db: &Stores, prev: &Hash32) -> Result<Option<HeaderIndex>> {
    if *prev == [0u8; 32] {
        Ok(None)
    } else {
        Ok(get_hidx(db, prev).context("get_hidx(parent)")?)
    }
}

/// Build + persist + index + apply one block extending `prev_hash` at `height`.
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

    // Persist block bytes
    let bytes = codec::consensus_bincode()
        .serialize(&blk)
        .context("serialize Block")?;
    db.blocks
        .insert(k_block(&bh), bytes)
        .context("db.blocks.insert")?;

    // Index header (safe for non-genesis blocks)
    let parent_hi = parent_hi_for(db, &blk.header.prev)?;
    index_header(db, &blk.header, parent_hi.as_ref()).context("index_header")?;

    // Apply + set tip
    validate_and_apply_block(db, &blk, epoch_of(height), height).context("validate_and_apply_block")?;
    set_tip(db, &bh).context("set_tip")?;

    Ok(bh)
}

/// Builds a linear chain of `n_after_genesis` blocks after genesis.
/// Returns hashes by height including genesis at [0].
fn build_chain(db: &Stores, n_after_genesis: u64, start_time: u64) -> Result<Vec<Hash32>> {
    let gh = bootstrap_genesis(db).context("bootstrap_genesis")?;

    let mut out = Vec::with_capacity((n_after_genesis + 1) as usize);
    out.push(gh); // height 0

    let mut prev = gh;
    for h in 1..=n_after_genesis {
        let t = start_time + (h * 60);
        let bh = apply_mined_block(db, prev, h, t)
            .with_context(|| format!("apply block height={h}"))?;
        out.push(bh);
        prev = bh;
    }
    Ok(out)
}

/// Builds a fork off an ancestor height `fork_height`.
fn build_fork(
    db: &Stores,
    base_hashes: &[Hash32],
    fork_height: u64,
    fork_len: u64,
    start_time: u64,
) -> Result<Vec<Hash32>> {
    anyhow::ensure!(fork_height > 0, "fork_height must be > 0 (need a parent)");
    anyhow::ensure!(
        (fork_height as usize) < base_hashes.len(),
        "fork_height beyond base chain"
    );

    let parent_hash = base_hashes[(fork_height - 1) as usize];

    let mut out = Vec::with_capacity(fork_len as usize);
    let mut prev = parent_hash;

    for i in 0..fork_len {
        let h = fork_height + i;
        let t = start_time + (h * 60) + 17;
        let bh = apply_mined_block(db, prev, h, t)
            .with_context(|| format!("apply fork block height={h}"))?;
        out.push(bh);
        prev = bh;
    }

    Ok(out)
}

/// Replay blocks from src_db into dst deterministically.
fn replay_chain_from_blocks(dst: &Stores, src_db: &Stores, chain: &[Hash32]) -> Result<()> {
    for (height, bh) in chain.iter().enumerate() {
        let Some(v) = src_db
            .blocks
            .get(k_block(bh))
            .context("src_db.blocks.get")?
        else {
            anyhow::bail!("missing block bytes in src_db for 0x{}", hex::encode(bh));
        };

        let blk: Block = codec::consensus_bincode()
            .deserialize(&v)
            .context("deserialize Block")?;

        // For genesis in dst, we must also avoid index_header(genesis).
        if blk.header.prev == [0u8; 32] {
            let gh = header_hash(&blk.header);

            dst.blocks
                .insert(k_block(&gh), v)
                .context("dst.blocks.insert(genesis bytes)")?;

            let hi = HeaderIndex {
                hash: gh,
                parent: [0u8; 32],
                height: 0,
                chainwork: 0,
                bits: blk.header.bits,
                time: blk.header.time,
            };
            let hi_bytes = codec::consensus_bincode()
                .serialize(&hi)
                .context("serialize HeaderIndex(dst genesis)")?;
            dst.hdr
                .insert(k_hdr(&gh), hi_bytes)
                .context("dst.hdr.insert(genesis HeaderIndex)")?;

            validate_and_apply_block(dst, &blk, epoch_of(0), 0).context("apply genesis(dst)")?;
            set_tip(dst, &gh).context("set_tip(genesis dst)")?;
            continue;
        }

        let parent_hi = parent_hi_for(dst, &blk.header.prev)?;
        index_header(dst, &blk.header, parent_hi.as_ref()).context("index_header(dst)")?;

        let h = height as u64;
        validate_and_apply_block(dst, &blk, epoch_of(h), h)
            .context("validate_and_apply_block(dst)")?;

        set_tip(dst, bh).context("set_tip(dst)")?;
    }
    Ok(())
}

#[test]
fn reorg_produces_same_state_as_direct_apply() -> Result<()> {
    let tmp1 = TempDir::new().context("TempDir 1")?;
    let db1 = open_db(&tmp1).context("open db1")?;

    let start_time = GENESIS_TIME;

    // Base chain A: genesis + 40 blocks (heights 0..40)
    let a = build_chain(&db1, 40, start_time).context("build chain A")?;
    let tip_a = *a.last().unwrap();

    // Fork B off height 20, length 35 (heights 20..54)
    let fork_height = 20u64;
    let fork_len = 35u64;
    let b_tail = build_fork(&db1, &a, fork_height, fork_len, start_time).context("build fork B")?;
    let tip_b = *b_tail.last().unwrap();

    // Force tip back to A, then reorg to B
    set_tip(&db1, &tip_a).context("force tip back to A")?;
    maybe_reorg_to(&db1, &tip_b, None).context("maybe_reorg_to(B)")?;

    let fp1 = fingerprint(&db1).context("fingerprint(db1)")?;
    println!("[test] db1 fp: {}", fmt_fp(&fp1));

    // DB #2: replay canonical chain from db1 bytes
    let tmp2 = TempDir::new().context("TempDir 2")?;
    let db2 = open_db(&tmp2).context("open db2")?;

    let mut canon: Vec<Hash32> = Vec::new();
    canon.extend_from_slice(&a[0..(fork_height as usize)]); // includes genesis
    canon.extend_from_slice(&b_tail);

    replay_chain_from_blocks(&db2, &db1, &canon).context("replay canonical chain into db2")?;

    let fp2 = fingerprint(&db2).context("fingerprint(db2)")?;
    println!("[test] db2 fp: {}", fmt_fp(&fp2));

    anyhow::ensure!(
        fp1.tip == fp2.tip,
        "tip mismatch: 0x{} vs 0x{}",
        hex::encode(fp1.tip),
        hex::encode(fp2.tip)
    );
    anyhow::ensure!(fp1.utxo_root == fp2.utxo_root, "utxo_root mismatch");
    anyhow::ensure!(fp1.utxo_meta_root == fp2.utxo_meta_root, "utxo_meta_root mismatch");
    anyhow::ensure!(fp1.app_root == fp2.app_root, "app_root mismatch");

    Ok(())
}
