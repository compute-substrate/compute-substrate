// src/testutil.rs
//
// Helpers for integration tests + reorg crash driver.
// Not consensus-critical. Keep deterministic.

use anyhow::{Context, Result};

use crate::chain::index::{get_hidx, header_hash, index_header};
use crate::chain::mine::coinbase;
use crate::chain::pow::pow_ok;
use crate::codec;
use crate::params::INITIAL_REWARD;
use crate::state::app_state::epoch_of;
use crate::state::db::{k_block, set_tip, Stores};
use crate::state::utxo::validate_and_apply_block;
use crate::types::{Block, BlockHeader, Hash32, Transaction};

/// Set by `set_test_env`: the header miner below skips the nonce search. A process-wide flag
/// rather than an environment variable, so no thread ever writes the environment.
static BYPASS_POW: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);

/// Enable the test bypass used by the crash driver (`src/bin/reorg_crash_driver.rs`).
/// Not cfg(test): the crash driver is a normal binary.
pub fn set_test_env() {
    BYPASS_POW.store(true, std::sync::atomic::Ordering::Relaxed);
}

/// Deterministic test miner (20 bytes).
fn test_miner() -> [u8; 20] {
    [0x11u8; 20]
}

/// Coinbase used by tests. Must match consensus coinbase format (height-unique).
pub fn make_coinbase(height: u64) -> Transaction {
    coinbase(test_miner(), INITIAL_REWARD, height, None)
}

/// Minimal merkle for tests (pair-hash, duplicate last).
pub fn merkle_root(txs: &[Transaction]) -> Hash32 {
    use crate::crypto::txid;
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

/// Mine a header by scanning nonce until pow_ok(hash, bits).
/// If test bypass is enabled, skip mining and keep nonce=0.
fn mine_header(mut hdr: BlockHeader) -> Result<BlockHeader> {
    if BYPASS_POW.load(std::sync::atomic::Ordering::Relaxed) {
        return Ok(hdr);
    }

    for _ in 0..50_000_000u64 {
        let h = header_hash(&hdr);
        if pow_ok(&h, hdr.bits) {
            return Ok(hdr);
        }
        hdr.nonce = hdr.nonce.wrapping_add(1);
    }
    anyhow::bail!("failed to mine header within nonce budget")
}

/// Build + persist + index + apply one block extending `prev_hash` at `height`.
fn apply_mined_block(
    db: &Stores,
    prev_hash: Hash32,
    height: u64,
    time: u64,
    bits: u32,
) -> Result<Hash32> {
    let cb = make_coinbase(height);
    let txs = vec![cb];

    let hdr = BlockHeader {
        version: 1,
        prev: prev_hash,
        merkle: merkle_root(&txs),
        time,
        bits,
        nonce: 0,
    };

    let hdr = mine_header(hdr).context("mine_header")?;
    let bh = header_hash(&hdr);
    let blk = Block { header: hdr, txs };

    // Persist bytes (reorg/apply path loads from db.blocks)
    let bytes = codec::consensus_bincode()
        .serialize(&blk)
        .context("serialize Block")?;
    db.blocks
        .insert(k_block(&bh), bytes)
        .context("db.blocks.insert")?;

    // Index header (parent optional for height 0)
    let parent_hi = if blk.header.prev == [0u8; 32] {
        None
    } else {
        get_hidx(db, &blk.header.prev).context("get_hidx(parent)")?
    };
    index_header(db, &blk.header, parent_hi.as_ref()).context("index_header")?;

    // Apply UTXO+APP and advance tip
    validate_and_apply_block(db, &blk, epoch_of(height), height)
        .context("validate_and_apply_block")?;
    set_tip(db, &bh).context("set_tip")?;

    Ok(bh)
}

/// Builds a linear chain of `n` blocks starting from prev=[0;32].
/// Returns block hashes by height.
///
/// `bits` is injected by the caller (driver/tests) and may be the easy pow limit
/// when `set_test_env` has enabled the bypass.
pub fn build_chain(db: &Stores, n: u64, start_time: u64, bits: u32) -> Result<Vec<Hash32>> {
    let mut out = Vec::with_capacity(n as usize);
    let mut prev = [0u8; 32];

    for h in 0..n {
        let t = start_time + (h * 60);
        let bh = apply_mined_block(db, prev, h, t, bits).with_context(|| format!("apply h={h}"))?;
        out.push(bh);
        prev = bh;
    }

    Ok(out)
}

/// Builds a fork off ancestor height `fork_height` (parent is fork_height-1).
/// Returns fork block hashes.
///
/// `bits` is injected by caller for determinism/testing.
pub fn build_fork(
    db: &Stores,
    base_hashes: &[Hash32],
    fork_height: u64,
    fork_len: u64,
    start_time: u64,
    bits: u32,
) -> Result<Vec<Hash32>> {
    anyhow::ensure!(fork_height > 0, "fork_height must be > 0");
    let parent_hash = base_hashes[(fork_height - 1) as usize];

    let mut out = Vec::with_capacity(fork_len as usize);
    let mut prev = parent_hash;

    for i in 0..fork_len {
        let h = fork_height + i;
        let t = start_time + (h * 60) + 17;
        let bh =
            apply_mined_block(db, prev, h, t, bits).with_context(|| format!("apply fork h={h}"))?;
        out.push(bh);
        prev = bh;
    }

    Ok(out)
}

/// CPU time of the calling thread. The cost tests measure work that runs on the test thread, and
/// unlike wall time this does not grow while the thread waits for a core on a loaded host.
pub fn thread_cpu() -> std::time::Duration {
    let mut ts = libc::timespec { tv_sec: 0, tv_nsec: 0 };
    assert_eq!(unsafe { libc::clock_gettime(libc::CLOCK_THREAD_CPUTIME_ID, &mut ts) }, 0);
    std::time::Duration::new(ts.tv_sec as u64, ts.tv_nsec as u32)
}

/// The least thread CPU time `f` took over `runs` runs.
pub fn fastest<F: FnMut()>(runs: usize, mut f: F) -> std::time::Duration {
    (0..runs)
        .map(|_| {
            let t = thread_cpu();
            f();
            thread_cpu() - t
        })
        .min()
        .unwrap()
}

/// Applies, with no header checks, a block whose coinbase pays a funding key and then one whose
/// transactions pay one coin to each of `others` addresses and `mine` coins to `target`, each
/// with its header index, and moves the tip to it. The index reconciler is left to the caller.
pub fn chain_paying(db: &Stores, others: usize, target: crate::types::Hash20, mine: usize) -> Result<()> {
    use crate::chain::index::{put_hidx, HeaderIndex};
    use crate::chain::mine::merkle_root_txids;
    use crate::crypto::{hash160, sign_tx_compact_secp256k1, txid};
    use crate::params::block_reward;
    use crate::types::{AppPayload, OutPoint, TxIn, TxOut};
    const SK: [u8; 32] = [23u8; 32];
    let funder = hash160(&sign_tx_compact_secp256k1(&coinbase([0u8; 20], 1, 0, None), SK).1);
    let mut prev = [0u8; 32];
    let mut apply = |height: u64, txs: Vec<Transaction>| -> Result<()> {
        let ids: Vec<Hash32> = txs.iter().map(txid).collect();
        let header = BlockHeader { version: 1, prev, merkle: merkle_root_txids(&ids), time: height, bits: 0, nonce: 0 };
        let hash = header_hash(&header);
        let block = Block { header, txs };
        db.blocks.insert(k_block(&hash), codec::consensus_bincode().serialize(&block)?)?;
        put_hidx(db, &HeaderIndex { hash, parent: prev, height, chainwork: 0, bits: 0, time: height })?;
        validate_and_apply_block(db, &block, epoch_of(height), height)?;
        set_tip(db, &hash)?;
        prev = hash;
        Ok(())
    };
    let cb0 = coinbase(funder, block_reward(0), 0, None);
    let mut coin = (OutPoint { txid: txid(&cb0), vout: 0 }, block_reward(0));
    apply(0, vec![cb0])?;
    let mut payees: Vec<crate::types::Hash20> = (0..others as u32)
        .map(|i| {
            let mut a = [0x5au8; 20];
            a[..4].copy_from_slice(&i.to_be_bytes());
            a
        })
        .collect();
    payees.extend(std::iter::repeat_n(target, mine));
    let mut txs = vec![coinbase(funder, block_reward(1), 1, None)];
    for chunk in payees.chunks(511) {
        let change = coin.1 - chunk.len() as u64;
        let mut outputs: Vec<TxOut> = chunk.iter().map(|a| TxOut { value: 1, script_pubkey: *a }).collect();
        outputs.push(TxOut { value: change, script_pubkey: funder });
        let mut tx = Transaction {
            version: 1,
            inputs: vec![TxIn { prevout: coin.0, script_sig: vec![] }],
            outputs,
            locktime: 0,
            app: AppPayload::None,
        };
        let (sig, pubkey) = sign_tx_compact_secp256k1(&tx, SK);
        tx.inputs[0].script_sig = [&[64u8][..], &sig, &[33u8], &pubkey].concat();
        coin = (OutPoint { txid: txid(&tx), vout: chunk.len() as u32 }, change);
        txs.push(tx);
    }
    apply(1, txs)
}
