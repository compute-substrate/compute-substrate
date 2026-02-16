// tests/testutil_chain.rs
use anyhow::{Context, Result};
use tempfile::TempDir;

use csd::chain::index::{get_hidx, header_hash, index_header, HeaderIndex};
use csd::codec;
use csd::params::{INITIAL_BITS, INITIAL_REWARD};
use csd::state::app_state::epoch_of;
use csd::state::db::{k_block, set_tip, Stores};
use csd::state::utxo::validate_and_apply_block;
use csd::types::{Block, BlockHeader, Hash32, Transaction};

pub fn open_db(tmp: &TempDir) -> Result<Stores> {
    Stores::open(tmp.path().to_str().unwrap()).context("Stores::open")
}

pub fn set_test_env() {
    // You said you want to bypass PoW validation in tests.
    // Your pow/index should read this env (feature-gated).
    std::env::set_var("CSD_TEST_BYPASS_POW", "1");
    std::env::set_var("CSD_TEST_BYPASS_GENESIS", "1");
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

pub fn apply_block(
    db: &Stores,
    prev: Hash32,
    height: u64,
    time: u64,
    bits: u32,
) -> Result<Hash32> {
    let txs = vec![make_coinbase(height)];
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
        .context("serialize Block")?;
    db.blocks.insert(k_block(&bh), bytes).context("db.blocks.insert")?;

    let parent_hi: Option<HeaderIndex> = if blk.header.prev == [0u8; 32] {
        None
    } else {
        get_hidx(db, &blk.header.prev)
            .context("get_hidx(parent)")?
    };

    index_header(db, &blk.header, parent_hi.as_ref()).context("index_header")?;
    validate_and_apply_block(db, &blk, epoch_of(height), height).context("apply")?;
    set_tip(db, &bh).context("set_tip")?;
    Ok(bh)
}

pub fn build_chain(db: &Stores, n: u64, start_time: u64, bits: u32) -> Result<Vec<Hash32>> {
    let mut out = Vec::with_capacity(n as usize);
    let mut prev = [0u8; 32];
    for h in 0..n {
        let t = start_time + h * 60;
        let bh = apply_block(db, prev, h, t, bits).with_context(|| format!("apply h={h}"))?;
        out.push(bh);
        prev = bh;
    }
    Ok(out)
}

pub fn build_fork(
    db: &Stores,
    base: &[Hash32],
    fork_height: u64,
    fork_len: u64,
    start_time: u64,
    bits: u32,
) -> Result<Vec<Hash32>> {
    anyhow::ensure!(fork_height > 0);
    let parent = base[(fork_height - 1) as usize];

    let mut out = Vec::with_capacity(fork_len as usize);
    let mut prev = parent;

    for i in 0..fork_len {
        let h = fork_height + i;
        let t = start_time + h * 60 + 17;
        let bh = apply_block(db, prev, h, t, bits).with_context(|| format!("fork h={h}"))?;
        out.push(bh);
        prev = bh;
    }
    Ok(out)
}

pub fn replay_chain(dst: &Stores, src: &Stores, chain: &[Hash32]) -> Result<()> {
    for (height, bh) in chain.iter().enumerate() {
        let Some(v) = src.blocks.get(k_block(bh)).context("src.get block")? else {
            anyhow::bail!("missing block bytes {}", hex::encode(bh));
        };
        let blk: Block = codec::consensus_bincode().deserialize(&v).context("decode")?;

        let parent_hi: Option<HeaderIndex> = if blk.header.prev == [0u8; 32] {
            None
        } else {
            get_hidx(dst, &blk.header.prev).context("dst get parent")?
        };

        index_header(dst, &blk.header, parent_hi.as_ref()).context("dst index")?;
        validate_and_apply_block(dst, &blk, epoch_of(height as u64), height as u64)
            .context("dst apply")?;
        set_tip(dst, bh).context("dst set_tip")?;
    }
    Ok(())
}
