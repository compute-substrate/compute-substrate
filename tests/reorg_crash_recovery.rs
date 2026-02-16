// tests/reorg_randomized.rs
use anyhow::{Context, Result};
use rand::{Rng, SeedableRng};
use rand::rngs::StdRng;
use tempfile::TempDir;

use csd::chain::index::{get_hidx, header_hash, index_header};
use csd::chain::reorg::maybe_reorg_to;
use csd::codec;
use csd::params::{INITIAL_BITS, INITIAL_REWARD, POW_LIMIT_BITS};
use csd::state::app_state::epoch_of;
use csd::state::db::{get_tip, k_block, set_tip, Stores};
use csd::state::fingerprint::{fingerprint, fmt_fp};
use csd::state::utxo::validate_and_apply_block;
use csd::types::{Block, BlockHeader, Hash32, Transaction};

fn open_db(tmp: &TempDir) -> Result<Stores> {
    Stores::open(tmp.path().to_str().unwrap()).context("Stores::open")
}

// deterministic miner addr for tests
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

/// TEST MODE: don’t mine; we just set a nonce and (optionally) an easy bits.
/// Your index/pow layer already has a test bypass — this keeps it fast.
fn build_header(prev: Hash32, time: u64, bits: u32) -> BlockHeader {
    BlockHeader {
        version: 1,
        prev,
        merkle: [0u8; 32], // filled after txs chosen
        time,
        bits,
        nonce: 0,
    }
}

fn apply_block(db: &Stores, prev: Hash32, height: u64, time: u64, bits: u32) -> Result<Hash32> {
    let cb = make_coinbase(height);
    let txs = vec![cb];

    let mut hdr = build_header(prev, time, bits);
    hdr.merkle = merkle_root(&txs);

    let bh = header_hash(&hdr);
    let blk = Block { header: hdr, txs };

    // persist bytes so reorg can load it
    let bytes = codec::consensus_bincode().serialize(&blk).context("serialize Block")?;
    db.blocks.insert(k_block(&bh), bytes).context("db.blocks.insert")?;

    // index header
    let parent_hi = if blk.header.prev == [0u8; 32] {
        None
    } else {
        get_hidx(db, &blk.header.prev).context("get_hidx(parent)")?
    };
    index_header(db, &blk.header, parent_hi.as_ref()).context("index_header")?;

    // apply and set tip
    validate_and_apply_block(db, &blk, epoch_of(height), height).context("validate_and_apply_block")?;
    set_tip(db, &bh).context("set_tip")?;

    Ok(bh)
}

fn build_linear(db: &Stores, n: u64, start_time: u64, bits: u32) -> Result<Vec<Hash32>> {
    let mut out = Vec::with_capacity(n as usize);
    let mut prev = [0u8; 32];
    for h in 0..n {
        let t = start_time + (h * 60);
        let bh = apply_block(db, prev, h, t, bits).with_context(|| format!("apply h={h}"))?;
        out.push(bh);
        prev = bh;
    }
    Ok(out)
}

fn build_fork(
    db: &Stores,
    base: &[Hash32],
    fork_height: u64,
    fork_len: u64,
    start_time: u64,
    bits: u32,
) -> Result<Vec<Hash32>> {
    anyhow::ensure!(fork_height > 0, "fork_height must be > 0");
    let parent = base[(fork_height - 1) as usize];

    let mut out = Vec::with_capacity(fork_len as usize);
    let mut prev = parent;

    for i in 0..fork_len {
        let h = fork_height + i;
        let t = start_time + (h * 60) + 17;
        let bh = apply_block(db, prev, h, t, bits).with_context(|| format!("fork apply h={h}"))?;
        out.push(bh);
        prev = bh;
    }
    Ok(out)
}

/// Walk the canonical chain from `tip` back to genesis using header index,
/// return hashes in forward order (genesis..tip).
fn canonical_chain_from_tip(db: &Stores, tip: Hash32) -> Result<Vec<Hash32>> {
    let mut chain_rev: Vec<Hash32> = Vec::new();
    let mut cur = tip;

    loop {
        chain_rev.push(cur);
        let hi = get_hidx(db, &cur)?.ok_or_else(|| anyhow::anyhow!("missing hidx for {}", hex::encode(cur)))?;
        if hi.parent == [0u8; 32] {
            break;
        }
        cur = hi.parent;
    }

    chain_rev.reverse();
    Ok(chain_rev)
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
        index_header(dst, &blk.header, parent_hi.as_ref()).context("index_header(dst)")?;
        validate_and_apply_block(dst, &blk, epoch_of(height as u64), height as u64)
            .context("validate_and_apply_block(dst)")?;
        set_tip(dst, bh).context("set_tip(dst)")?;
    }
    Ok(())
}

#[test]
fn reorg_equivalence_randomized_many_shapes() -> Result<()> {
    // keep it fast but meaningful
    let mut rng = StdRng::seed_from_u64(1337);

    for case in 0..50u64 {
        let base_len = rng.gen_range(10..80) as u64;
        let fork_height = rng.gen_range(1..(base_len.saturating_sub(1).max(2))) as u64;
        let fork_len = rng.gen_range(1..60) as u64;

        // Use an easy bits in tests so we don't ever get stuck on expected_bits drift.
        // (Your production bits rules still exist; this is purely test speed.)
        let bits = POW_LIMIT_BITS;

        let tmp1 = TempDir::new().context("tmp1")?;
        let db1 = open_db(&tmp1).context("open db1")?;

        let a = build_linear(&db1, base_len, 1_700_000_000 + case * 10_000, bits)
            .context("build base")?;
        let tip_a = *a.last().unwrap();

        let b_tail = build_fork(
            &db1,
            &a,
            fork_height,
            fork_len,
            1_700_000_000 + case * 10_000,
            bits,
        )
        .context("build fork")?;
        let tip_b = *b_tail.last().unwrap();

        println!("case={case} base_len={base_len} fork_height={fork_height} fork_len={fork_len}");

        // Force tip back to A, then try to reorg to B (may or may not win).
        set_tip(&db1, &tip_a).context("force tip back to A")?;
        maybe_reorg_to(&db1, &tip_b, None).context("maybe_reorg_to")?;

        // THIS is the canonical chain we must replay: whatever db1 ended up choosing.
        let final_tip = get_tip(&db1)?.unwrap_or([0u8; 32]);
        let canon = canonical_chain_from_tip(&db1, final_tip).context("canon walk")?;

        let fp1 = fingerprint(&db1).context("fp db1")?;
        println!("[db1] {}", fmt_fp(&fp1));

        let tmp2 = TempDir::new().context("tmp2")?;
        let db2 = open_db(&tmp2).context("open db2")?;
        replay_chain(&db2, &db1, &canon).context("replay canon to db2")?;

        let fp2 = fingerprint(&db2).context("fp db2")?;
        println!("[db2] {}", fmt_fp(&fp2));

        if fp1 != fp2 {
            anyhow::bail!("fingerprint mismatch in randomized case {}", case);
        }
    }

    Ok(())
}
