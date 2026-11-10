#![cfg(feature = "test-bypass")] // live p2p lane: toy chains and the fault seam need the bypass (cargo test --features test-bypass)
use anyhow::{Context, Result};
use std::sync::atomic::Ordering;
use std::sync::Arc;
use std::time::Duration;
use tempfile::TempDir;
use tokio::sync::mpsc;

use libp2p::Multiaddr;

use csd::chain::index::{get_hidx, header_hash, index_header};
use csd::net::mempool::Mempool;
use csd::net::node::{spawn_p2p, NetConfig, TestPeerMode, TEST_STALLED_BLOCK_REQUESTS};
use csd::state::app_state::epoch_of;
use csd::state::db::{get_tip, k_block, set_tip, Stores};
use csd::state::utxo::validate_and_apply_block;
use csd::types::{Block, Hash20, Hash32};

mod testutil_chain;
use testutil_chain::{assert_tip_eq, build_base_chain_with_miner, make_test_header, open_db};

fn h20(n: u8) -> Hash20 {
    [n; 20]
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

fn load_block(db: &Stores, bh: &Hash32) -> Result<Block> {
    let Some(v) = db.blocks.get(k_block(bh))? else {
        anyhow::bail!("missing block bytes for 0x{}", hex::encode(bh));
    };
    Ok(csd::codec::consensus_bincode().deserialize::<Block>(&v)?)
}

// The stall peer serves the heavier chain's headers and accepts every body request without
// answering. Waits end on their event; the bounds only stop a run that never gets there. The
// convergence bound is far above the 60 s plain request timeout so host load cannot decide it.
const PHASE1_SECS: u64 = 30;
const CONVERGE_SECS: u64 = 180;

// TEST_STALLED_BLOCK_REQUESTS is process-wide: the tests of this file run one at a time.
static SERIAL: std::sync::Mutex<()> = std::sync::Mutex::new(());

async fn spawn(db: &Arc<Stores>, dir: &TempDir, bootnodes: Vec<Multiaddr>, genesis_hash: Hash32, test_mode: TestPeerMode) -> Result<csd::net::node::NetHandle> {
    let (mined_tx, mined_rx) = mpsc::unbounded_channel();
    let (gossip_tx, gossip_rx) = mpsc::unbounded_channel();
    drop(mined_tx);
    drop(gossip_tx);
    let cfg = NetConfig {
        datadir: dir.path().to_string_lossy().to_string(),
        listen: "/ip4/127.0.0.1/tcp/0".parse::<Multiaddr>()?,
        bootnodes,
        genesis_hash,
        is_bootnode: true,
        test_mode,
    };
    spawn_p2p(db.clone(), Arc::new(Mempool::new()), cfg, mined_rx, gossip_rx, csd::chain::lock::new_chain_lock())
        .await
        .context("spawn_p2p")
}

async fn dial_addr(handle: &csd::net::node::NetHandle) -> Result<Multiaddr> {
    for _ in 0..60 {
        if let Some(addr) = handle.listen_addr().await {
            return Ok(format!("{}/p2p/{}", addr, handle.peer_id).parse()?);
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    anyhow::bail!("no listen_addr in time");
}

async fn wait_until(secs: u64, mut done: impl FnMut() -> Result<bool>) -> Result<bool> {
    let deadline = tokio::time::Instant::now() + Duration::from_secs(secs);
    loop {
        if done()? {
            return Ok(true);
        }
        if tokio::time::Instant::now() >= deadline {
            return Ok(false);
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn live_timeout_stall_peer_falls_back_to_good_peer() -> Result<()> {
    let _serial = SERIAL.lock().unwrap_or_else(|e| e.into_inner());
    let tmp_good = TempDir::new().context("tmp_good")?;
    let tmp_stall = TempDir::new().context("tmp_stall")?;
    let tmp_sync = TempDir::new().context("tmp_sync")?;

    let db_good = Arc::new(open_db(&tmp_good).context("open db_good")?);
    let db_stall = Arc::new(open_db(&tmp_stall).context("open db_stall")?);
    let db_sync = Arc::new(open_db(&tmp_sync).context("open db_sync")?);


    let miner = h20(0xA1);
    let shared_len = 7u64; // heights 0..6
    let extra_len = 4u64;  // heavy branch to height 10
    let start_time = 1_700_800_000u64;

    // All nodes share the same prefix.
    let shared_good = build_base_chain_with_miner(&db_good, shared_len, start_time, miner)
        .context("build shared_good")?;
    let shared_stall = build_base_chain_with_miner(&db_stall, shared_len, start_time, miner)
        .context("build shared_stall")?;
    let shared_sync = build_base_chain_with_miner(&db_sync, shared_len, start_time, miner)
        .context("build shared_sync")?;

    let common_tip_good = shared_good[(shared_len - 1) as usize];
    let common_tip_stall = shared_stall[(shared_len - 1) as usize];
    let common_tip_sync = shared_sync[(shared_len - 1) as usize];

    assert_eq!(common_tip_good, common_tip_stall, "shared prefix mismatch");
    assert_eq!(common_tip_good, common_tip_sync, "shared prefix mismatch");

    assert_tip_eq(&db_good, common_tip_good)?;
    assert_tip_eq(&db_stall, common_tip_stall)?;
    assert_tip_eq(&db_sync, common_tip_sync)?;

    let genesis_hash = shared_good[0];

    // GOOD peer: full heavier branch with full blocks.
    let mut prev_good = common_tip_good;
    let mut heavy_hashes = Vec::<Hash32>::new();

    for height in shared_len..(shared_len + extra_len) {
        let cb = csd::chain::mine::coinbase(miner, csd::params::block_reward(height), height, None);
        let txs = vec![cb];
        let hdr = make_test_header(&db_good, prev_good, &txs, height)
            .with_context(|| format!("make_test_header good h={height}"))?;
        let blk = Block { header: hdr, txs };
        prev_good = persist_index_apply_block(&db_good, &blk, height)?;
        heavy_hashes.push(prev_good);
    }

    let tip_good = prev_good;
    let hi_good = get_hidx(&db_good, &tip_good)?.expect("missing hidx good tip");
    assert_eq!(hi_good.height, shared_len + extra_len - 1);

    // STALL peer: the same heavier chain with its bodies, so it serves the headers (the header
    // serve path reads the bodies); its test mode leaves every block request unanswered.
    for (i, bh) in heavy_hashes.iter().enumerate() {
        let blk = load_block(&db_good, bh)?;
        persist_index_apply_block(&db_stall, &blk, shared_len + i as u64)?;
    }

    let hi_stall = get_hidx(&db_stall, &tip_good)?.expect("missing hidx stall tip");
    assert_eq!(hi_stall.height, hi_good.height, "stall peer must advertise same height as good peer");

    // Phase 1: the stall peer is the sync node's only peer, so it gets the body requests and
    // answers none of them.
    let stall = spawn(&db_stall, &tmp_stall, vec![], genesis_hash, TestPeerMode::StallBlockResponses).await?;
    let sync = spawn(&db_sync, &tmp_sync, vec![dial_addr(&stall).await?], genesis_hash, TestPeerMode::Normal).await?;
    let asked = wait_until(PHASE1_SECS, || Ok(TEST_STALLED_BLOCK_REQUESTS.load(Ordering::Relaxed) >= 1)).await?;
    assert!(asked, "the sync node did not ask the stall peer for a body within {PHASE1_SECS}s");
    assert_eq!(get_tip(&db_sync)?, Some(common_tip_sync), "no body can have arrived yet");

    // Phase 2: a good peer dials in. The bodies can only come from it, after the requests to the
    // stall peer fail: the request-response timeout (15 s) ends each held one (at most two are held,
    // MAX_BLOCK_REQUESTS_PER_PEER), and the failure requeues the block and, with the good peer
    // connected, stamps the stall peer for it. The 60 s in-flight sweep is the later net.
    let _good = spawn(&db_good, &tmp_good, vec![dial_addr(&sync).await?], genesis_hash, TestPeerMode::Normal).await?;
    let synced = wait_until(CONVERGE_SECS, || Ok(get_tip(&db_sync)? == Some(tip_good))).await?;
    let last_tip_sync = get_tip(&db_sync)?.unwrap_or([0u8; 32]);
    let hi_sync = get_hidx(&db_sync, &last_tip_sync)?;
    assert!(
        synced,
        "sync node should converge to the good peer's heavy tip after the block-request timeout fallback \
         within {CONVERGE_SECS}s (sync_tip=0x{}, good_tip=0x{}, sync_h={:?}, good_h={})",
        hex::encode(last_tip_sync),
        hex::encode(tip_good),
        hi_sync.as_ref().map(|x| x.height),
        hi_good.height,
    );

    let hi_sync = hi_sync.expect("missing hidx sync tip");
    assert_eq!(hi_sync.height, hi_good.height, "sync node height should match good peer");
    let blk_good = load_block(&db_good, &tip_good)?;
    let blk_sync = load_block(&db_sync, &last_tip_sync)?;
    assert_eq!(
        header_hash(&blk_good.header),
        header_hash(&blk_sync.header),
        "winning synced tip block must match good peer exactly"
    );
    Ok(())
}

// The sole block server answers its first block request too late (the request-response
// timeout ends it) and serves the rest. That timeout must not stamp the only server, which would
// leave the block unrequested for BAD_PROVIDER_RETRY_SECS (120 s): the sync node converges well
// inside SOLE_SERVER_SECS, below that wait plus the 15 s timeout.
const SOLE_SERVER_SECS: u64 = 100;

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_slow_then_honest_sole_server_is_asked_again_without_the_bad_provider_wait() -> Result<()> {
    let _serial = SERIAL.lock().unwrap_or_else(|e| e.into_inner());
    let tmp_slow = TempDir::new()?;
    let tmp_sync = TempDir::new()?;
    let db_slow = Arc::new(open_db(&tmp_slow)?);
    let db_sync = Arc::new(open_db(&tmp_sync)?);
    let miner = h20(0xA2);
    let shared = build_base_chain_with_miner(&db_slow, 7, 1_700_810_000, miner)?;
    assert_eq!(build_base_chain_with_miner(&db_sync, 7, 1_700_810_000, miner)?, shared);
    let mut prev = shared[6];
    for height in 7..11u64 {
        let txs = vec![csd::chain::mine::coinbase(miner, csd::params::block_reward(height), height, None)];
        let header = make_test_header(&db_slow, prev, &txs, height)?;
        prev = persist_index_apply_block(&db_slow, &Block { header, txs }, height)?;
    }
    let tip = prev;

    let stalled0 = TEST_STALLED_BLOCK_REQUESTS.load(Ordering::Relaxed);
    let started = std::time::Instant::now();
    let slow = spawn(&db_slow, &tmp_slow, vec![], shared[0], TestPeerMode::StallFirstBlockRequest).await?;
    let _sync = spawn(&db_sync, &tmp_sync, vec![dial_addr(&slow).await?], shared[0], TestPeerMode::Normal).await?;
    let synced = wait_until(SOLE_SERVER_SECS, || Ok(get_tip(&db_sync)? == Some(tip))).await?;
    let h = get_tip(&db_sync)?.and_then(|t| get_hidx(&db_sync, &t).ok().flatten()).map(|hi| hi.height);
    assert_eq!(TEST_STALLED_BLOCK_REQUESTS.load(Ordering::Relaxed) - stalled0, 1, "one request was held");
    assert!(synced, "the sync node did not reach the tip within {SOLE_SERVER_SECS}s (height {h:?})");
    println!("sole slow server: converged in {:.1} s", started.elapsed().as_secs_f64());
    Ok(())
}
