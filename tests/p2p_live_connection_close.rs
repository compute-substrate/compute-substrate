#![cfg(feature = "test-bypass")] // live p2p lane: toy chains and the fault seam need the bypass (cargo test --features test-bypass)
// A peer that goes away is counted out, and the ConnectionClosed arm logs the
// close with its cause ("[p2p] closed connection to ..."). No other live test closes a connection.

use anyhow::{Context, Result};
use std::sync::atomic::Ordering;
use std::sync::Arc;
use std::time::Duration;
use tempfile::TempDir;
use tokio::sync::mpsc;

use libp2p::Multiaddr;

use csd::net::mempool::Mempool;
use csd::net::node::{spawn_p2p, NetConfig, NetHandle, TestPeerMode};
use csd::state::db::Stores;
use csd::types::Hash32;

mod testutil_chain;
use testutil_chain::{build_base_chain, open_db};

const START: u64 = 1_700_950_000;

async fn spawn(db: &Arc<Stores>, dir: &TempDir, bootnodes: Vec<Multiaddr>, genesis: Hash32) -> Result<NetHandle> {
    let (mined_tx, mined_rx) = mpsc::unbounded_channel();
    let (gossip_tx, gossip_rx) = mpsc::unbounded_channel();
    drop(mined_tx);
    drop(gossip_tx);
    let cfg = NetConfig {
        datadir: dir.path().to_string_lossy().to_string(),
        listen: "/ip4/127.0.0.1/tcp/0".parse::<Multiaddr>()?,
        bootnodes,
        genesis_hash: genesis,
        is_bootnode: true,
        test_mode: TestPeerMode::Normal,
    };
    spawn_p2p(db.clone(), Arc::new(Mempool::new()), cfg, mined_rx, gossip_rx, csd::chain::lock::new_chain_lock())
        .await
        .context("spawn_p2p")
}

async fn dial_addr(handle: &NetHandle) -> Result<Multiaddr> {
    for _ in 0..60 {
        if let Some(addr) = handle.listen_addr().await {
            return Ok(format!("{}/p2p/{}", addr, handle.peer_id).parse()?);
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    anyhow::bail!("no listen_addr in time");
}

async fn wait_until(secs: u64, mut done: impl FnMut() -> bool) -> bool {
    let deadline = tokio::time::Instant::now() + Duration::from_secs(secs);
    while !done() {
        if tokio::time::Instant::now() >= deadline {
            return false;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    true
}

// B runs on its own runtime, so shutting that runtime down drops B's swarm and closes its sockets.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_peer_that_goes_away_is_counted_out() -> Result<()> {
    let (tmp_a, tmp_b) = (TempDir::new()?, TempDir::new()?);
    let db_a = Arc::new(open_db(&tmp_a)?);
    let db_b = Arc::new(open_db(&tmp_b)?);
    let base = build_base_chain(&db_a, 3, START)?;
    assert_eq!(build_base_chain(&db_b, 3, START)?, base);

    let a = spawn(&db_a, &tmp_a, vec![], base[0]).await?;
    let addr_a = dial_addr(&a).await?;
    let (up_tx, up_rx) = std::sync::mpsc::channel::<()>();
    let (stop_tx, stop_rx) = std::sync::mpsc::channel::<()>();
    let genesis = base[0];
    let b_thread = std::thread::spawn(move || -> Result<()> {
        let rt = tokio::runtime::Builder::new_multi_thread().worker_threads(2).enable_all().build()?;
        rt.block_on(async {
            spawn(&db_b, &tmp_b, vec![addr_a], genesis).await?;
            up_tx.send(()).context("signal up")
        })?;
        stop_rx.recv().context("stop signal")?;
        rt.shutdown_timeout(Duration::from_secs(5));
        Ok(())
    });

    up_rx.recv().context("B did not start")?;
    let connected = wait_until(20, || a.connected_peers.load(Ordering::Relaxed) == 1).await;
    assert!(connected, "B never connected to A");
    stop_tx.send(()).context("stop B")?;
    b_thread.join().map_err(|_| anyhow::anyhow!("B's thread panicked"))??;
    let gone = wait_until(20, || a.connected_peers.load(Ordering::Relaxed) == 0).await;
    assert!(gone, "A still counts B 20 s after B went away");
    Ok(())
}
