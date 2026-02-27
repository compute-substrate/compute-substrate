// tests/reorg_randomized.rs
use anyhow::{Context, Result};
use rand::{rngs::StdRng, Rng, SeedableRng};
use tempfile::TempDir;

use csd::chain::index::{get_hidx, header_hash, index_header};
use csd::chain::pow::expected_bits;
use csd::chain::reorg::maybe_reorg_to;
use csd::codec;
use csd::params::INITIAL_REWARD;
use csd::state::app_state::epoch_of;
use csd::state::db::{get_tip, k_block, set_tip, Stores};
use csd::state::fingerprint::{fingerprint, fmt_fp};
use csd::state::utxo::validate_and_apply_block;
use csd::types::{Block, BlockHeader, Hash32, Transaction};

fn open_db(tmp: &TempDir) -> Result<Stores> {
    Stores::open(tmp.path().to_str().unwrap()).context("Stores::open")
}

fn make_coinbase(height: u64) -> Transaction {
    let miner: [u8; 20] = [0x11u8; 20];
    csd::chain::mine::coinbase(miner, INITIAL_REWARD, height, None)
}

/// Minimal merkle for tests.
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

/// Build + persist + index + apply one canonical block.
/// Uses consensus expected_bits().
fn apply_canonical_block(db: &Stores, prev: Hash32, height: u64, time: u64) -> Result<Hash32> {
    let cb = make_coinbase(height);
    let txs = vec![cb];

    let parent_hi = if prev == [0u8; 32] {
        None
    } else {
        get_hidx(db, &prev).context("get_hidx(parent)")?
    };

    let bits = expected_bits(db, height, parent_hi.as_ref()).context("expected_bits")?;

    let hdr = BlockHeader {
        version: 1,
        prev,
        merkle: merkle_root(&txs),
        time,
        bits,
        nonce: 0, // tests can rely on pow bypass
    };

    let bh = header_hash(&hdr);
    let blk = Block { header: hdr, txs };

    let bytes = codec::consensus_bincode()
        .serialize(&blk)
        .context("serialize Block")?;
    db.blocks.insert(k_block(&bh), bytes).context("db.blocks.insert")?;

    index_header(db, &blk.header, parent_hi.as_ref()).context("index_header")?;
    validate_and_apply_block(db, &blk, epoch_of(height), height).context("apply")?;
    set_tip(db, &bh).context("set_tip")?;

    Ok(bh)
}

/// Build + persist + index a NON-canonical fork block (do NOT apply, do NOT move tip).
/// Uses consensus expected_bits() based on fork-parent header history.
fn store_index_fork_block(db: &Stores, prev: Hash32, height: u64, time: u64) -> Result<Hash32> {
    let cb = make_coinbase(height);
    let txs = vec![cb];

    let parent_hi = if prev == [0u8; 32] {
        None
    } else {
        get_hidx(db, &prev).context("get_hidx(fork parent)")?
    };

    let bits = expected_bits(db, height, parent_hi.as_ref()).context("expected_bits(fork)")?;

    let hdr = BlockHeader {
        version: 1,
        prev,
        merkle: merkle_root(&txs),
        time,
        bits,
        nonce: 0,
    };

    let bh = header_hash(&hdr);
    let blk = Block { header: hdr, txs };

    let bytes = codec::consensus_bincode()
        .serialize(&blk)
        .context("serialize fork Block")?;
    db.blocks.insert(k_block(&bh), bytes).context("db.blocks.insert(fork)")?;

    // Index the fork header (this is required for reorg path discovery + chainwork compare)
    index_header(db, &blk.header, parent_hi.as_ref()).context("index_header(fork)")?;

    Ok(bh)
}

/// Replay the ACTUAL canonical chain from db1 tip into db2.
fn replay_canonical_from_tip(dst: &Stores, src: &Stores, tip: Hash32) -> Result<()> {
    // Walk tip -> genesis using header index
    let mut rev: Vec<Hash32> = Vec::new();
    let mut cur = tip;

    loop {
        rev.push(cur);
        let hi = get_hidx(src, &cur)?
            .ok_or_else(|| anyhow::anyhow!("missing hidx for {}", hex::encode(cur)))?;
        if hi.parent == [0u8; 32] {
            break;
        }
        cur = hi.parent;
    }

    rev.reverse();

    // Replay into dst by bytes (index+apply+set_tip)
    for (height, bh) in rev.iter().enumerate() {
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
            .context("apply(dst)")?;
        set_tip(dst, bh).context("set_tip(dst)")?;
    }

    Ok(())
}

fn assert_fp_fields_match(case: usize, fp1: &csd::state::fingerprint::StateFingerprint, fp2: &csd::state::fingerprint::StateFingerprint) -> Result<()> {
    if fp1.tip != fp2.tip
        || fp1.utxo_root != fp2.utxo_root
        || fp1.utxo_meta_root != fp2.utxo_meta_root
        || fp1.app_root != fp2.app_root
    {
        println!("case={case} fingerprint mismatch");
        println!("[db1] {}", fmt_fp(fp1));
        println!("[db2] {}", fmt_fp(fp2));
        anyhow::bail!("fingerprint mismatch in randomized case {case}");
    }
    Ok(())
}

#[test]
fn reorg_equivalence_randomized_many_shapes() -> Result<()> {
    // Deterministic randomness
    let mut rng = StdRng::seed_from_u64(1337);

    // Keep this modest; CI-friendly.
    let cases = 25usize;

    for case in 0..cases {
        let tmp1 = TempDir::new().context("tmp1")?;
        let db1 = open_db(&tmp1).context("open db1")?;

        // Randomized shape
        let base_len: u64 = rng.gen_range(10..=60);
        let fork_height: u64 = rng.gen_range(1..base_len); // must have parent
        let fork_len: u64 = rng.gen_range(1..=40);

        let start_time = 1_700_000_000u64 + (case as u64) * 10_000;

        // 1) Build canonical base chain (applied)
        let mut base_hashes: Vec<Hash32> = Vec::with_capacity(base_len as usize);
        let mut prev = [0u8; 32];
        for h in 0..base_len {
            let t = start_time + h * 60;
            let bh = apply_canonical_block(&db1, prev, h, t).with_context(|| format!("apply base h={h}"))?;
            base_hashes.push(bh);
            prev = bh;
        }
        let tip_a = *base_hashes.last().unwrap();

        // 2) Build a competing fork branch (store+index only, NOT applied)
        let mut fork_prev = base_hashes[(fork_height - 1) as usize];
        let mut fork_tail: Vec<Hash32> = Vec::with_capacity(fork_len as usize);

        for i in 0..fork_len {
            let h = fork_height + i;
            let t = start_time + h * 60 + 17; // distinct but monotonic
            let bh = store_index_fork_block(&db1, fork_prev, h, t)
                .with_context(|| format!("store fork h={h}"))?;
            fork_tail.push(bh);
            fork_prev = bh;
        }
        let tip_b = *fork_tail.last().unwrap();

        println!("case={case} base_len={base_len} fork_height={fork_height} fork_len={fork_len}");

        // Ensure db1 tip is still tip_a (fork construction must not move tip)
        let cur_tip = get_tip(&db1)?.unwrap_or([0u8; 32]);
        if cur_tip != tip_a {
            anyhow::bail!(
                "test bug: tip moved during fork construction (got={}, want={})",
                hex::encode(cur_tip),
                hex::encode(tip_a)
            );
        }

        // 3) Attempt reorg to fork tip (may or may not happen depending on chainwork)
        maybe_reorg_to(&db1, &tip_b, None).context("maybe_reorg_to")?;

        let final_tip = get_tip(&db1)?.unwrap_or([0u8; 32]);
        let fp1 = fingerprint(&db1).context("fingerprint(db1)")?;
        println!("[db1] {}", fmt_fp(&fp1));

        // 4) Replay db1's ACTUAL canonical chain into db2 and compare fingerprints
        let tmp2 = TempDir::new().context("tmp2")?;
        let db2 = open_db(&tmp2).context("open db2")?;

        replay_canonical_from_tip(&db2, &db1, final_tip).context("replay canonical")?;

        let fp2 = fingerprint(&db2).context("fingerprint(db2)")?;
        println!("[db2] {}", fmt_fp(&fp2));

        assert_fp_fields_match(case, &fp1, &fp2)?;

        drop(db2);
        drop(db1);
    }

    Ok(())
}
