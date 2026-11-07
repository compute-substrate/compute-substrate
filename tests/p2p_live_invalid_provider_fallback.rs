#![cfg(feature = "test-bypass")] // live p2p lane: toy chains and the fault seam need the bypass (cargo test --features test-bypass)
use anyhow::{Context, Result};
use std::sync::Arc;
use std::time::Duration;
use tempfile::TempDir;
use tokio::sync::mpsc;

use libp2p::Multiaddr;

use csd::chain::index::{get_hidx, header_hash, index_header};
use csd::net::mempool::Mempool;
use csd::net::node::{spawn_p2p, NetConfig, TestPeerMode, TEST_ACKED_BLOCK_REQUESTS, TEST_PEER_SCORES};
use std::sync::atomic::Ordering;
use csd::state::app_state::epoch_of;
use csd::state::db::{get_tip, k_block, set_tip, Stores};
use csd::state::utxo::validate_and_apply_block;
use csd::types::{Block, Hash20, Hash32};

mod testutil_chain;
use testutil_chain::{assert_tip_eq, build_base_chain_with_miner, make_test_header, open_db};

// Each wait ends on its event; the bounds only stop a run that never gets there. Locally the
// sync node reaches the good tip 0.1 s or 5.1 s after the good peer starts. CONVERGE_SECS stays
// below BLOCK_REQ_TIMEOUT_SECS (60 s, src/net/node.rs), so a refused body that is only re-asked
// after that timeout fails the test.
const PHASE1_SECS: u64 = 30;
const CONVERGE_SECS: u64 = 45;
const EXTRA_LEN: u64 = 4;

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

fn extend_chain(
    db: &Stores,
    start_tip: Hash32,
    start_height: u64,
    extra_len: u64,
    miner: Hash20,
) -> Result<(Hash32, Vec<Hash32>)> {
    let mut prev = start_tip;
    let mut made = Vec::new();

    for height in start_height..(start_height + extra_len) {
        let cb = csd::chain::mine::coinbase(
            miner,
            csd::params::block_reward(height),
            height,
            None,
        );
        let txs = vec![cb];
        let hdr = make_test_header(db, prev, &txs, height)
            .with_context(|| format!("make_test_header h={height}"))?;
        let blk = Block { header: hdr, txs };
        prev = persist_index_apply_block(db, &blk, height)?;
        made.push(prev);
    }

    Ok((prev, made))
}

async fn wait_for_listen_addr(
    handle: &csd::net::node::NetHandle,
    label: &str,
) -> Result<Multiaddr> {
    for _ in 0..60 {
        if let Some(addr) = handle.listen_addr().await {
            return Ok(addr);
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    anyhow::bail!("{label} did not expose listen_addr in time");
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

fn tip_and_height(db: &Stores) -> Result<(Hash32, u64)> {
    let tip = get_tip(db)?.unwrap_or([0u8; 32]);
    let height = get_hidx(db, &tip)?.map(|x| x.height).unwrap_or(0);
    Ok((tip, height))
}

#[tokio::test(flavor = "multi_thread", worker_threads = 6)]
async fn live_invalid_provider_falls_back_to_good_peer() -> Result<()> {
    bad_provider_falls_back_to_good_peer(TestPeerMode::UnknownBlockResponses).await
}

// A provider that answers every GetBlock with Ack (a well-formed answer of the wrong kind) never
// times out, so only the answer itself can move the request to another server. Each block may be
// asked of it once per BAD_PROVIDER_RETRY_SECS (120 s); the run is shorter than that.
#[tokio::test(flavor = "multi_thread", worker_threads = 6)]
async fn live_wrong_kind_provider_falls_back_to_good_peer() -> Result<()> {
    let acked0 = TEST_ACKED_BLOCK_REQUESTS.load(Ordering::Relaxed);
    bad_provider_falls_back_to_good_peer(TestPeerMode::AckBlockRequests).await?;
    let acked = TEST_ACKED_BLOCK_REQUESTS.load(Ordering::Relaxed) - acked0;
    assert!(
        acked <= EXTRA_LEN,
        "the wrong-kind provider was asked {acked} times for {EXTRA_LEN} blocks; each block must move to another server after one wrong answer"
    );
    Ok(())
}

fn score(scorer: &libp2p::PeerId, peer: &libp2p::PeerId) -> i32 {
    TEST_PEER_SCORES.lock().unwrap().get(scorer).and_then(|m| m.get(peer).copied()).unwrap_or(0)
}

// The provider announced the chain and holds no body, the shape of an honest peer that served a
// body it had not validated and dropped it after its own apply blamed it (chain::body_fault). Its
// answers move each block to another server and cost it no score: an honest peer can be in that state.
async fn bad_provider_falls_back_to_good_peer(bad_mode: TestPeerMode) -> Result<()> {
    let tmp_good = TempDir::new().context("tmp_good")?;
    let tmp_bad = TempDir::new().context("tmp_bad")?;
    let tmp_sync = TempDir::new().context("tmp_sync")?;

    let db_good = Arc::new(open_db(&tmp_good).context("open db_good")?);
    let db_bad = Arc::new(open_db(&tmp_bad).context("open db_bad")?);
    let db_sync = Arc::new(open_db(&tmp_sync).context("open db_sync")?);

    let mp_good = Arc::new(Mempool::new());
    let mp_bad = Arc::new(Mempool::new());
    let mp_sync = Arc::new(Mempool::new());

    let miner_shared = h20(0x11);
    let miner_ext = h20(0x77);

    let shared_len = 7u64;   // heights 0..6
    let extra_len = EXTRA_LEN; // winner ends at height 10
    let start_time = 1_700_600_000u64;

    // identical shared prefix on all three
    let shared_good = build_base_chain_with_miner(&db_good, shared_len, start_time, miner_shared)
        .context("build shared_good")?;
    let shared_bad = build_base_chain_with_miner(&db_bad, shared_len, start_time, miner_shared)
        .context("build shared_bad")?;
    let shared_sync = build_base_chain_with_miner(&db_sync, shared_len, start_time, miner_shared)
        .context("build shared_sync")?;

    let common_tip_good = shared_good[(shared_len - 1) as usize];
    let common_tip_bad = shared_bad[(shared_len - 1) as usize];
    let common_tip_sync = shared_sync[(shared_len - 1) as usize];

    assert_eq!(common_tip_good, common_tip_bad, "shared good/bad tip mismatch");
    assert_eq!(common_tip_good, common_tip_sync, "shared good/sync tip mismatch");

    assert_tip_eq(&db_good, common_tip_good)?;
    assert_tip_eq(&db_bad, common_tip_bad)?;
    assert_tip_eq(&db_sync, common_tip_sync)?;

    let genesis_hash = shared_good[0];
    let branch_start_height = shared_len;

    // good peer gets the full heavier extension
    let (tip_good, good_blocks) = extend_chain(
        &db_good,
        common_tip_good,
        branch_start_height,
        extra_len,
        miner_ext,
    )
    .context("extend good")?;

    // bad peer gets the same chain; its test mode makes it refuse every body
    let (tip_bad, bad_blocks) = extend_chain(
        &db_bad,
        common_tip_bad,
        branch_start_height,
        extra_len,
        miner_ext,
    )
    .context("extend bad")?;

    assert_eq!(tip_good, tip_bad, "good and bad peer should advertise same tip");
    assert_eq!(good_blocks.len(), bad_blocks.len(), "extension block count mismatch");

    let hi_good = get_hidx(&db_good, &tip_good)?.expect("missing hidx good");
    assert_eq!(hi_good.height, shared_len + extra_len - 1);

    let (mined_tx_good, mined_rx_good) = mpsc::unbounded_channel();
    let (gossip_tx_good, gossip_rx_good) = mpsc::unbounded_channel();
    let (mined_tx_bad, mined_rx_bad) = mpsc::unbounded_channel();
    let (gossip_tx_bad, gossip_rx_bad) = mpsc::unbounded_channel();
    let (mined_tx_sync, mined_rx_sync) = mpsc::unbounded_channel();
    let (gossip_tx_sync, gossip_rx_sync) = mpsc::unbounded_channel();

    drop(mined_tx_good);
    drop(gossip_tx_good);
    drop(mined_tx_bad);
    drop(gossip_tx_bad);
    drop(mined_tx_sync);
    drop(gossip_tx_sync);

    // Phase 1: the bad provider serves the heavier chain's headers and refuses every block
    // request (`bad_mode`). It is the sync node's only peer, so the sync node asks it, and only
    // it, for the bodies.
    let cfg_bad = NetConfig {
        datadir: tmp_bad.path().to_string_lossy().to_string(),
        listen: "/ip4/127.0.0.1/tcp/0".parse::<Multiaddr>()?,
        bootnodes: vec![],
        genesis_hash,
        is_bootnode: true,
        test_mode: bad_mode,
    };

    let handle_bad = spawn_p2p(
        db_bad.clone(),
        mp_bad.clone(),
        cfg_bad,
        mined_rx_bad,
        gossip_rx_bad,
        csd::chain::lock::new_chain_lock(),
    )
    .await
    .context("spawn_p2p bad")?;

    let listen_bad = wait_for_listen_addr(&handle_bad, "bad peer").await?;
    let bootnode_bad: Multiaddr = format!("{}/p2p/{}", listen_bad, handle_bad.peer_id)
        .parse()
        .context("parse bootnode_bad")?;

    let cfg_sync = NetConfig {
        datadir: tmp_sync.path().to_string_lossy().to_string(),
        listen: "/ip4/127.0.0.1/tcp/0".parse::<Multiaddr>()?,
        bootnodes: vec![bootnode_bad],
        genesis_hash,
        is_bootnode: false,
        test_mode: TestPeerMode::Normal,
    };

    let handle_sync = spawn_p2p(
        db_sync.clone(),
        mp_sync.clone(),
        cfg_sync,
        mined_rx_sync,
        gossip_rx_sync,
        csd::chain::lock::new_chain_lock(),
    )
    .await
    .context("spawn_p2p sync")?;

    let listen_sync = wait_for_listen_addr(&handle_sync, "sync node").await?;

    let (sync_id, bad_id) = (handle_sync.peer_id, handle_bad.peer_id);
    let mut lowest = 0;
    let learned = wait_until(PHASE1_SECS, || {
        lowest = lowest.min(score(&sync_id, &bad_id));
        Ok(get_hidx(&db_sync, &tip_good)?.is_some())
    })
    .await?;
    assert!(learned, "sync node did not learn the heavier chain's headers within {PHASE1_SECS}s");
    let (p1_tip, p1_height) = tip_and_height(&db_sync)?;
    assert_eq!(
        p1_tip, common_tip_sync,
        "the bad provider served a block body (sync_h={p1_height})"
    );

    // Phase 2: an honest peer dials in. The bodies can only come from it.
    let cfg_good = NetConfig {
        datadir: tmp_good.path().to_string_lossy().to_string(),
        listen: "/ip4/127.0.0.1/tcp/0".parse::<Multiaddr>()?,
        bootnodes: vec![format!("{}/p2p/{}", listen_sync, handle_sync.peer_id)
            .parse()
            .context("parse bootnode_sync")?],
        genesis_hash,
        is_bootnode: false,
        test_mode: TestPeerMode::Normal,
    };

    let _handle_good = spawn_p2p(
        db_good.clone(),
        mp_good.clone(),
        cfg_good,
        mined_rx_good,
        gossip_rx_good,
        csd::chain::lock::new_chain_lock(),
    )
    .await
    .context("spawn_p2p good")?;

    wait_until(CONVERGE_SECS, || {
        lowest = lowest.min(score(&sync_id, &bad_id));
        Ok(get_tip(&db_sync)? == Some(tip_good))
    })
    .await?;
    // Scores are copied at the poll tick (5 s); sample past the next one.
    let _ = wait_until(6, || {
        lowest = lowest.min(score(&sync_id, &bad_id));
        Ok(false)
    })
    .await?;
    assert!(lowest >= 0, "the provider without the bodies was scored: {lowest}");
    let (last_tip, last_height) = tip_and_height(&db_sync)?;

    let hi_sync = get_hidx(&db_sync, &last_tip)?.expect("missing hidx sync");
    let hi_good = get_hidx(&db_good, &tip_good)?.expect("missing hidx good");

    assert_eq!(
        last_tip,
        tip_good,
        "sync node must fall back from the invalid provider to the good peer's tip within \
         {CONVERGE_SECS}s (sync_tip=0x{}, good_tip=0x{}, sync_h={}, good_h={})",
        hex::encode(last_tip),
        hex::encode(tip_good),
        last_height,
        hi_good.height,
    );

    assert_eq!(hi_sync.height, hi_good.height, "sync height should match good peer");
    assert_eq!(hi_sync.chainwork, hi_good.chainwork, "sync chainwork should match good peer");

    let blk_sync = load_block(&db_sync, &last_tip)?;
    let blk_good = load_block(&db_good, &tip_good)?;
    assert_eq!(
        header_hash(&blk_sync.header),
        header_hash(&blk_good.header),
        "final synced tip block must match good peer exactly"
    );
    Ok(())
}
