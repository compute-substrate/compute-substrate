// tests/testutil_chain.rs
use anyhow::{Context, Result};
use tempfile::TempDir;

use csd::chain::index::{get_hidx, header_hash, index_header};
use csd::chain::pow::expected_bits;
use csd::codec;
use csd::params::INITIAL_REWARD;
use csd::state::app_state::epoch_of;
use csd::state::db::{get_tip, k_block, set_tip, Stores};
use csd::state::utxo::validate_and_apply_block;
use csd::types::{Block, BlockHeader, Hash32, Transaction};

pub fn open_db(tmp: &TempDir) -> Result<Stores> {
    Stores::open(tmp.path().to_str().unwrap()).context("Stores::open")
}

pub fn make_coinbase(height: u64) -> Transaction {
    let miner: [u8; 20] = [0x11u8; 20];
    csd::chain::mine::coinbase(miner, INITIAL_REWARD, height)
}

/// Minimal merkle for tests.
pub fn merkle_root(txs: &[Transaction]) -> Hash32 {
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

/// Persist block bytes into db.blocks.
fn persist_block(db: &Stores, blk: &Block) -> Result<Hash32> {
    let bh = header_hash(&blk.header);
    let bytes = codec::consensus_bincode()
        .serialize(blk)
        .context("serialize Block")?;
    db.blocks.insert(k_block(&bh), bytes).context("db.blocks.insert")?;
    Ok(bh)
}

/// Apply a canonical block (persist + index + validate/apply + set_tip).
pub fn apply_canonical_block(db: &Stores, prev: Hash32, height: u64, time: u64) -> Result<Hash32> {
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
        nonce: 0, // tests rely on PoW bypass mode
    };

    let blk = Block { header: hdr, txs };
    let bh = persist_block(db, &blk)?;
    index_header(db, &blk.header, parent_hi.as_ref()).context("index_header")?;
    validate_and_apply_block(db, &blk, epoch_of(height), height).context("apply")?;
    set_tip(db, &bh).context("set_tip")?;
    Ok(bh)
}

/// Store + index a fork block (persist + index ONLY; no apply, no tip change).
pub fn store_index_fork_block(db: &Stores, prev: Hash32, height: u64, time: u64) -> Result<Hash32> {
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

    let blk = Block { header: hdr, txs };
    let bh = persist_block(db, &blk)?;
    index_header(db, &blk.header, parent_hi.as_ref()).context("index_header(fork)")?;
    Ok(bh)
}

/// Build canonical base chain of length `n` (applied).
pub fn build_base_chain(db: &Stores, n: u64, start_time: u64) -> Result<Vec<Hash32>> {
    let mut out = Vec::with_capacity(n as usize);
    let mut prev = [0u8; 32];
    for h in 0..n {
        let t = start_time + h * 60;
        let bh = apply_canonical_block(db, prev, h, t).with_context(|| format!("apply h={h}"))?;
        out.push(bh);
        prev = bh;
    }
    Ok(out)
}

/// Build a fork off base at `fork_height` (fork starts at that height; parent is fork_height-1).
/// Fork blocks are stored+indexed ONLY (not applied).
pub fn build_fork_index_only(
    db: &Stores,
    base_hashes: &[Hash32],
    fork_height: u64,
    fork_len: u64,
    start_time: u64,
) -> Result<Vec<Hash32>> {
    anyhow::ensure!(fork_height > 0, "fork_height must be > 0");
    let mut out = Vec::with_capacity(fork_len as usize);
    let mut prev = base_hashes[(fork_height - 1) as usize];

    for i in 0..fork_len {
        let h = fork_height + i;
        let t = start_time + h * 60 + 17;
        let bh = store_index_fork_block(db, prev, h, t).with_context(|| format!("fork h={h}"))?;
        out.push(bh);
        prev = bh;
    }
    Ok(out)
}

/// Walk tip->genesis via header index (in `src`), then replay bytes into `dst`.
pub fn replay_canonical_from_tip(dst: &Stores, src: &Stores, tip: Hash32) -> Result<()> {
    let mut rev = Vec::<Hash32>::new();
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

/// Flush all trees that reorg touches (matches your reorg durability barrier intent).
pub fn flush_all_state_trees(db: &Stores) -> anyhow::Result<()> {
    db.db.flush().context("db.flush (all trees)")?;
    Ok(())
}

/// Assert tip hasn’t moved unexpectedly.
pub fn assert_tip_eq(db: &Stores, want: Hash32) -> Result<()> {
    let got = get_tip(db)?.unwrap_or([0u8; 32]);
    anyhow::ensure!(
        got == want,
        "tip mismatch: got=0x{} want=0x{}",
        hex::encode(got),
        hex::encode(want)
    );
    Ok(())
}
