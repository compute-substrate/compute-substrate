// tests/mine_one_rebases_on_tip_change.rs
#![cfg(feature = "test-bypass")] // toy-chain fixture: needs the PoW/genesis bypass (cargo test --features test-bypass)
use anyhow::{Context, Result};
use std::sync::{mpsc, Arc};
use std::thread;
use std::time::{Duration, Instant};
use tempfile::TempDir;

use csd::chain::index::{get_hidx, header_hash, index_header};
use csd::chain::mine::{mine_one, MINER_CLOCK_SKEW_MARGIN_SECS, TEST_SOLVED_PARENTS};
use csd::chain::time::now_secs;
use csd::params::{MAX_FUTURE_DRIFT_SECS, MIN_BLOCK_SPACING_SECS};
use csd::chain::reorg::maybe_reorg_to;
use csd::crypto::txid;
use csd::net::mempool::Mempool;
use csd::state::app_state::epoch_of;
use csd::state::db::{get_tip, k_block, set_tip, Stores};
use csd::state::utxo::validate_and_apply_block;
use csd::types::{AppPayload, Block, Hash20, Hash32, OutPoint, Transaction, TxIn, TxOut};
use csd::chain::lock::new_chain_lock;

mod testutil_chain;
use testutil_chain::{assert_tip_eq, build_base_chain_with_miner, make_test_header, open_db};

const SK: [u8; 32] = [21u8; 32];

fn h20(n: u8) -> Hash20 {
    [n; 20]
}

fn signer_addr(sk32: [u8; 32]) -> [u8; 20] {
    let dummy = Transaction {
        version: 1,
        inputs: vec![TxIn {
            prevout: OutPoint {
                txid: [0u8; 32],
                vout: 0,
            },
            script_sig: vec![],
        }],
        outputs: vec![TxOut {
            value: 1,
            script_pubkey: [0u8; 20],
        }],
        locktime: 0,
        app: AppPayload::None,
    };

    let (_sig64, pub33) = csd::crypto::sign_tx_compact_secp256k1(&dummy, sk32);
    csd::crypto::hash160(&pub33)
}

fn make_signed_tx(prevout: OutPoint, input_value: u64, fee: u64, to: [u8; 20]) -> Transaction {
    let send = input_value - fee;

    let mut tx = Transaction {
        version: 1,
        inputs: vec![TxIn {
            prevout,
            script_sig: vec![0u8; 99],
        }],
        outputs: vec![TxOut {
            value: send,
            script_pubkey: to,
        }],
        locktime: 0,
        app: AppPayload::None,
    };

    let (sig64, pub33) = csd::crypto::sign_tx_compact_secp256k1(&tx, SK);

    let mut ss = Vec::with_capacity(99);
    ss.push(64);
    ss.extend_from_slice(&sig64);
    ss.push(33);
    ss.extend_from_slice(&pub33);
    tx.inputs[0].script_sig = ss;

    tx
}

fn persist_index_apply_block(db: &Stores, blk: &Block, height: u64) -> Result<Hash32> {
    let bh = header_hash(&blk.header);

    let bytes = csd::codec::consensus_bincode()
        .serialize(blk)
        .context("serialize block")?;
    db.blocks
        .insert(k_block(&bh), bytes)
        .context("db.blocks.insert")?;

    let parent_hi = if blk.header.prev == [0u8; 32] {
        None
    } else {
        get_hidx(db, &blk.header.prev).context("get_hidx(parent)")?
    };

    index_header(db, &blk.header, parent_hi.as_ref()).context("index_header")?;
    validate_and_apply_block(db, blk, epoch_of(height), height)
        .with_context(|| format!("validate_and_apply_block h={height}"))?;
    set_tip(db, &bh).context("set_tip")?;

    Ok(bh)
}

fn persist_index_block_only(db: &Stores, blk: &Block) -> Result<Hash32> {
    let bh = header_hash(&blk.header);

    let bytes = csd::codec::consensus_bincode()
        .serialize(blk)
        .context("serialize block")?;
    db.blocks
        .insert(k_block(&bh), bytes)
        .context("db.blocks.insert")?;

    let parent_hi = if blk.header.prev == [0u8; 32] {
        None
    } else {
        get_hidx(db, &blk.header.prev).context("get_hidx(parent)")?
    };

    index_header(db, &blk.header, parent_hi.as_ref()).context("index_header")?;
    Ok(bh)
}

fn load_block(db: &Stores, bh: &Hash32) -> Result<Block> {
    let Some(v) = db.blocks.get(k_block(bh))? else {
        anyhow::bail!("missing block bytes for 0x{}", hex::encode(bh));
    };
    Ok(csd::codec::consensus_bincode().deserialize::<Block>(&v)?)
}

/// Runs `mine_one` on its own thread; its result arrives on the returned channel.
fn spawn_mine_one(
    db: &Arc<Stores>,
    mp: &Arc<Mempool>,
    miner: Hash20,
    chain_lock: &csd::chain::lock::ChainLock,
) -> mpsc::Receiver<Result<Hash32>> {
    let (tx, rx) = mpsc::channel();
    let (db, mp, chain_lock) = (db.clone(), mp.clone(), chain_lock.clone());
    thread::spawn(move || {
        let _ = tx.send(mine_one(&db, &mp, miner, 100, &chain_lock).context("mine_one"));
    });
    rx
}

/// A block on `parent` stamped at `time` (index_header admits up to now + MAX_FUTURE_DRIFT_SECS).
fn block_stamped_at(db: &Stores, parent: Hash32, height: u64, miner: Hash20, time: u64) -> Result<Block> {
    let txs = vec![csd::chain::mine::coinbase(miner, csd::params::block_reward(height), height, None)];
    let mut header = make_test_header(db, parent, &txs, height)?;
    header.time = time;
    Ok(Block { header, txs })
}

// The stale-template watcher (mine.rs, the thread that polls the tip) runs from before the block
// time is chosen. Old tip A1 is stamped 7,000 s ahead, so the miner waits for its stamp to come
// within MAX_FUTURE_DRIFT_SECS - MINER_CLOCK_SKEW_MARGIN_SECS of the clock (460 s) and grinds
// nothing meanwhile; the reorg to B2 during that wait must end it with "stale template". The
// refusal does not race a solve (with the watcher off it waits the 460 s).
#[test]
fn mine_one_rebases_on_tip_change_and_rebuilds_template() -> Result<()> {
    let tmp = TempDir::new().context("tmp")?;
    let db = Arc::new(open_db(&tmp).context("open db")?);
    let mp = Arc::new(Mempool::new());

    let miner_shared = h20(0x11);
    let miner_a = signer_addr(SK); // old tip creates a spendable output for our mempool tx
    let miner_b = h20(0x77);
    let miner_final = h20(0x99);

    let shared_len = 7u64; // heights 0..6
    let start_time = 1_700_900_000u64;

    // Shared canonical prefix.
    let shared = build_base_chain_with_miner(&db, shared_len, start_time, miner_shared)
        .context("build shared")?;
    let common_tip = shared[(shared_len - 1) as usize];
    assert_tip_eq(&db, common_tip)?;

    // Build old canonical tip A1 from the shared ancestor, stamped 7,000 s ahead of the clock.
    let height_a1 = shared_len;
    let a1_blk = block_stamped_at(&db, common_tip, height_a1, miner_a, now_secs() + 7_000)?;
    let tip_a1 = persist_index_apply_block(&db, &a1_blk, height_a1).context("apply a1")?;
    assert_tip_eq(&db, tip_a1)?;

    // Mempool tx spends the old-tip coinbase output.
    // If mine_one rebases to branch B, this tx becomes invalid and must be dropped from template.
    let old_coinbase_prevout = OutPoint {
        txid: txid(&a1_blk.txs[0]),
        vout: 0,
    };
    let old_coinbase_value = a1_blk.txs[0].outputs[0].value;

    let spend_old_tip_tx = make_signed_tx(old_coinbase_prevout, old_coinbase_value, 5_000, h20(0x42));
    let spend_old_tip_txid = txid(&spend_old_tip_tx);

    let added = mp.insert_checked(&db, spend_old_tip_tx.clone())
        .context("insert_checked spend_old_tip_tx")?;
    assert!(added, "expected mempool tx to be accepted on old tip");
    assert!(mp.contains(&spend_old_tip_txid), "mempool should contain old-tip spend");

    // Pre-build side-branch blocks B1/B2 from the shared ancestor, but do not apply yet.
    let height_b1 = shared_len;
    let b1_cb = csd::chain::mine::coinbase(miner_b, csd::params::block_reward(height_b1), height_b1, None);
    let b1_txs = vec![b1_cb];
    let b1_hdr = make_test_header(&db, common_tip, &b1_txs, height_b1)
        .context("make_test_header b1")?;
    let b1_blk = Block {
        header: b1_hdr,
        txs: b1_txs,
    };
    let tip_b1 = persist_index_block_only(&db, &b1_blk).context("persist b1")?;

    let height_b2 = shared_len + 1;
    let b2_cb = csd::chain::mine::coinbase(miner_b, csd::params::block_reward(height_b2), height_b2, None);
    let b2_txs = vec![b2_cb];
    let b2_hdr = make_test_header(&db, tip_b1, &b2_txs, height_b2)
        .context("make_test_header b2")?;
    let b2_blk = Block {
        header: b2_hdr,
        txs: b2_txs,
    };
    let tip_b2 = persist_index_block_only(&db, &b2_blk).context("persist b2")?;

let chain_lock = new_chain_lock();
let first = spawn_mine_one(&db, &mp, miner_final, &chain_lock);

// The miner has read A1 and waits for its stamp; it cannot have solved anything.
thread::sleep(Duration::from_secs(2));
assert!(first.try_recv().is_err(), "mine_one returned during its wait on a parent stamped ahead");

// Switch the canonical tip while the miner waits.
maybe_reorg_to(&db, &tip_b2, Some(&mp)).context("maybe_reorg_to b2")?;
assert_tip_eq(&db, tip_b2)?;

// CURRENT CONTRACT (src/chain/mine.rs): mine_one does NOT rebase internally. Its watcher
// flags the template stale the moment the tip moves and returns Err("stale template");
// the mining loop (src/cli/main.rs) treats that as a normal retry signal, rebuilds the
// template on the new tip, and calls mine_one again. Pin both halves of that contract:
let err = first
    .recv_timeout(Duration::from_secs(60))
    .expect("the watcher must end the wait once the tip moved")
    .expect_err("mine_one must refuse to finalize a block on a stale template");
assert!(
    format!("{err:#}").contains("stale template"),
    "expected the stale-template refusal, got: {err:#}"
);

// The loop-level retry: fresh template on the rebased tip mines successfully, and the
// old-tip spend (invalid on branch B) is gone: pruned by the reorg and excluded from
// any template built on B2.
let mined_hash = mine_one(&db, &mp, miner_final, 100, &chain_lock)
    .context("mine_one retry on rebased tip")?;


    let mined_block = load_block(&db, &mined_hash).context("load mined block")?;
    let final_tip = get_tip(&db)?.expect("missing final tip");

    // The mined block must extend the externally selected branch, not stale A1.
    assert_eq!(
        mined_block.header.prev,
        tip_b2,
        "mined block must build on rebased tip B2, not stale A1"
    );
    assert_eq!(
        final_tip,
        mined_hash,
        "mined block should become the selected final tip"
    );

    // The old-tip spend must not survive template rebuild after rebase.
    assert_eq!(
        mined_block.txs.len(),
        1,
        "rebased block should contain only coinbase after invalid old-tip tx is dropped"
    );
    assert_ne!(
        txid(&mined_block.txs[0]),
        spend_old_tip_txid,
        "coinbase must not equal old-tip spend txid"
    );

    // The mempool tx should be gone after the reorg + post-mine prune path.
    assert!(
        !mp.contains(&spend_old_tip_txid),
        "invalidated old-tip mempool tx should be pruned"
    );
    assert_eq!(mp.len(), 0, "mempool should be empty after prune");

    let hi_final = get_hidx(&db, &final_tip)?.expect("missing final hidx");
    let hi_b2 = get_hidx(&db, &tip_b2)?.expect("missing b2 hidx");
    assert_eq!(
        hi_final.height,
        hi_b2.height + 1,
        "mined block should sit exactly one height above rebased tip"
    );

    Ok(())
}

// The chain lock (mine.rs, taken before the tip check that commits a solved block) keeps a solved
// block from being committed while a reorg holds it. The test holds the lock, waits until mine_one
// has received a solution on tip X (TEST_SOLVED_PARENTS), checks that nothing was stored, moves the
// tip, and releases the lock: the solved block is refused as stale. Without
// the lock the solved block is stored and becomes the tip while the test holds it.
#[test]
fn a_block_solved_while_the_chain_lock_is_held_is_not_committed_until_release() -> Result<()> {
    let tmp = TempDir::new().context("tmp")?;
    let db = Arc::new(open_db(&tmp).context("open db")?);
    let mp = Arc::new(Mempool::new());
    let shared = build_base_chain_with_miner(&db, 7, 1_700_950_000, h20(0x12)).context("build shared")?;
    let tip_x = shared[6];
    // A heavier side branch Y1, Y2 off shared[5], stored and indexed only.
    let y1 = block_stamped_at(&db, shared[5], 6, h20(0x78), 1_700_950_000 + 6 * 60 + 7)?;
    let tip_y1 = persist_index_block_only(&db, &y1)?;
    let y2 = block_stamped_at(&db, tip_y1, 7, h20(0x78), 1_700_950_000 + 7 * 60 + 7)?;
    let tip_y2 = persist_index_block_only(&db, &y2)?;
    let y3 = block_stamped_at(&db, tip_y2, 8, h20(0x78), 1_700_950_000 + 8 * 60 + 7)?;
    let tip_y3 = persist_index_block_only(&db, &y3)?;

    let blocks = db.blocks.len();
    let chain_lock = new_chain_lock();
    let held = chain_lock.lock();
    let result = spawn_mine_one(&db, &mp, h20(0x99), &chain_lock);

    let deadline = Instant::now() + Duration::from_secs(600);
    while !TEST_SOLVED_PARENTS.lock().unwrap().contains(&tip_x) {
        assert!(Instant::now() < deadline, "mine_one found no solution on X in 600 s");
        thread::sleep(Duration::from_millis(50));
    }
    thread::sleep(Duration::from_millis(500));
    assert_eq!(db.blocks.len(), blocks, "a block was stored while the chain lock was held");
    assert_tip_eq(&db, tip_x)?;

    maybe_reorg_to(&db, &tip_y3, Some(&mp)).context("maybe_reorg_to y3")?;
    drop(held);
    let err = result
        .recv_timeout(Duration::from_secs(60))
        .expect("mine_one returns once the lock is free")
        .expect_err("a block solved on X must not be committed over Y3");
    assert!(format!("{err:#}").contains("solved stale block"), "got: {err:#}");
    assert_tip_eq(&db, tip_y3)?;
    assert_eq!(db.blocks.len(), blocks, "the stale solution was stored");
    Ok(())
}

// At the mine_one level: on a parent stamped 6,500 s ahead the child is
// valid at once (index_header admits a stamp up to now + 7,200 s), and mine_one builds it at once,
// stamped parent.time + 60. Upstream's miner waits until the wall clock passes that
// stamp: about 6,560 s. The paired honest path: on a parent stamped in the past it stamps the clock.
#[test]
fn mine_one_builds_at_once_on_a_parent_stamped_hours_ahead() -> Result<()> {
    let tmp = TempDir::new().context("tmp")?;
    let db = Arc::new(open_db(&tmp).context("open db")?);
    let mp = Arc::new(Mempool::new());
    let shared = build_base_chain_with_miner(&db, 7, 1_700_960_000, h20(0x13)).context("build shared")?;
    let chain_lock = new_chain_lock();

    // Honest path first: a normal parent (stamped in 2023) gives a block stamped at the clock.
    let before = now_secs();
    let honest = spawn_mine_one(&db, &mp, h20(0x99), &chain_lock)
        .recv_timeout(Duration::from_secs(600))
        .expect("mine_one on a normal parent")?;
    let honest_blk = load_block(&db, &honest)?;
    assert_eq!(honest_blk.header.prev, shared[6]);
    assert!(honest_blk.header.time >= before && honest_blk.header.time <= now_secs(), "stamped at the clock");

    let ahead = now_secs() + 6_500;
    let parent = block_stamped_at(&db, honest, 8, h20(0x14), ahead)?;
    let parent_hash = persist_index_apply_block(&db, &parent, 8)?;
    let mined = spawn_mine_one(&db, &mp, h20(0x99), &chain_lock)
        .recv_timeout(Duration::from_secs(600))
        .expect("mine_one must build at once on a parent stamped 6,500 s ahead, not wait for the clock")?;
    let blk = load_block(&db, &mined)?;
    assert_eq!(blk.header.prev, parent_hash);
    assert_eq!(blk.header.time, ahead + MIN_BLOCK_SPACING_SECS, "stamped at the earliest valid time");
    assert!(
        blk.header.time <= now_secs() + MAX_FUTURE_DRIFT_SECS - MINER_CLOCK_SKEW_MARGIN_SECS,
        "within the bound a receiver whose clock is the margin behind still accepts"
    );
    assert_tip_eq(&db, mined)?;
    Ok(())
}
