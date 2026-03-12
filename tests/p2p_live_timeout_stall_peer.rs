use anyhow::{Context, Result};
use std::sync::Arc;
use std::time::Duration;
use tempfile::TempDir;
use tokio::sync::mpsc;

use libp2p::Multiaddr;

use csd::chain::index::{get_hidx, header_hash, index_header};
use csd::net::mempool::Mempool;
use csd::net::node::{spawn_p2p, NetConfig, TestPeerMode};
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

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn live_timeout_stall_peer_falls_back_to_good_peer() -> Result<()> {
    let tmp_good = TempDir::new().context("tmp_good")?;
    let tmp_stall = TempDir::new().context("tmp_stall")?;
    let tmp_sync = TempDir::new().context("tmp_sync")?;

    let db_good = Arc::new(open_db(&tmp_good).context("open db_good")?);
    let db_stall = Arc::new(open_db(&tmp_stall).context("open db_stall")?);
    let db_sync = Arc::new(open_db(&tmp_sync).context("open db_sync")?);

    let mp_good = Arc::new(Mempool::new());
    let mp_stall = Arc::new(Mempool::new());
    let mp_sync = Arc::new(Mempool::new());

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

    // STALL peer: same heavier header chain indexed locally, and same tip/chainwork,
    // but we do NOT store the heavier block bytes.
    let mut prev_hdr = common_tip_stall;
    for bh in &heavy_hashes {
        let blk = load_block(&db_good, bh)?;
        let parent_hi = if blk.header.prev == [0u8; 32] {
            None
        } else {
            get_hidx(&db_stall, &blk.header.prev).context("get_hidx stall parent")?
        };

        index_header(&db_stall, &blk.header, parent_hi.as_ref())
            .with_context(|| format!("index_header stall 0x{}", hex::encode(bh)))?;

        prev_hdr = *bh;
    }

    // Move stall peer's logical tip to the heavy tip, but without block bodies.
    set_tip(&db_stall, &tip_good).context("set_tip stall heavy tip")?;

    let hi_stall = get_hidx(&db_stall, &tip_good)?.expect("missing hidx stall tip");
    assert_eq!(hi_stall.height, hi_good.height, "stall peer must advertise same height as good peer");

    let (mined_tx_good, mined_rx_good) = mpsc::unbounded_channel();
    let (gossip_tx_good, gossip_rx_good) = mpsc::unbounded_channel();

    let (mined_tx_stall, mined_rx_stall) = mpsc::unbounded_channel();
    let (gossip_tx_stall, gossip_rx_stall) = mpsc::unbounded_channel();

    let (mined_tx_sync, mined_rx_sync) = mpsc::unbounded_channel();
    let (gossip_tx_sync, gossip_rx_sync) = mpsc::unbounded_channel();

    drop(mined_tx_good);
    drop(gossip_tx_good);
    drop(mined_tx_stall);
    drop(gossip_tx_stall);
    drop(mined_tx_sync);
    drop(gossip_tx_sync);

    // Start STALL peer first.
    let cfg_stall = NetConfig {
        datadir: tmp_stall.path().to_string_lossy().to_string(),
        listen: "/ip4/127.0.0.1/tcp/0".parse::<Multiaddr>()?,
        bootnodes: vec![],
        genesis_hash,
        is_bootnode: true,
        test_mode: TestPeerMode::StallBlockResponses,
    };

    let handle_stall = spawn_p2p(
        db_stall.clone(),
        mp_stall.clone(),
        cfg_stall,
        mined_rx_stall,
        gossip_rx_stall,
        csd::chain::lock::new_chain_lock(),
    )
    .await
    .context("spawn_p2p stall")?;

    // Start GOOD peer second.
    let cfg_good = NetConfig {
        datadir: tmp_good.path().to_string_lossy().to_string(),
        listen: "/ip4/127.0.0.1/tcp/0".parse::<Multiaddr>()?,
        bootnodes: vec![],
        genesis_hash,
        is_bootnode: true,
        test_mode: TestPeerMode::Normal,
    };

    let handle_good = spawn_p2p(
        db_good.clone(),
        mp_good.clone(),
        cfg_good,
        mined_rx_good,
        gossip_rx_good,
        csd::chain::lock::new_chain_lock(),
    )
    .await
    .context("spawn_p2p good")?;

    tokio::time::sleep(Duration::from_millis(700)).await;

    let listen_stall = {
        let mut got: Option<Multiaddr> = None;
        for _ in 0..40 {
            if let Some(addr) = handle_stall.listen_addr().await {
                got = Some(addr);
                break;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
        got.context("stall peer did not expose listen_addr in time")?
    };

    let listen_good = {
        let mut got: Option<Multiaddr> = None;
        for _ in 0..40 {
            if let Some(addr) = handle_good.listen_addr().await {
                got = Some(addr);
                break;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
        got.context("good peer did not expose listen_addr in time")?
    };

    let bootnode_stall: Multiaddr =
        format!("{}/p2p/{}", listen_stall, handle_stall.peer_id)
            .parse()
            .context("parse bootnode_stall")?;

    let bootnode_good: Multiaddr =
        format!("{}/p2p/{}", listen_good, handle_good.peer_id)
            .parse()
            .context("parse bootnode_good")?;

    // Sync node dials both; stall peer first.
    let cfg_sync = NetConfig {
        datadir: tmp_sync.path().to_string_lossy().to_string(),
        listen: "/ip4/127.0.0.1/tcp/0".parse::<Multiaddr>()?,
        bootnodes: vec![bootnode_stall, bootnode_good],
        genesis_hash,
        is_bootnode: false,
        test_mode: TestPeerMode::Normal,
    };

    let _handle_sync = spawn_p2p(
        db_sync.clone(),
        mp_sync.clone(),
        cfg_sync,
        mined_rx_sync,
        gossip_rx_sync,
        csd::chain::lock::new_chain_lock(),
    )
    .await
    .context("spawn_p2p sync")?;

    // Poll instead of sleeping a fixed amount.
    let deadline = tokio::time::Instant::now() + Duration::from_secs(20);
    let mut last_tip_sync = get_tip(&db_sync)?.unwrap_or([0u8; 32]);

    loop {
        last_tip_sync = get_tip(&db_sync)?.unwrap_or([0u8; 32]);

        if last_tip_sync == tip_good {
            break;
        }

        if tokio::time::Instant::now() >= deadline {
            break;
        }

        tokio::time::sleep(Duration::from_millis(200)).await;
    }

    let hi_sync = get_hidx(&db_sync, &last_tip_sync)?;
    assert_eq!(
        last_tip_sync,
        tip_good,
        "sync node should converge to the good peer's heavy tip after actual block-request timeout fallback (sync_tip=0x{}, good_tip=0x{}, sync_h={:?}, good_h={})",
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
