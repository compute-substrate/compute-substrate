#![cfg(feature = "test-bypass")] // live p2p lane: toy chains and the fault seam need the bypass (cargo test --features test-bypass)
use anyhow::{Context, Result};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tempfile::TempDir;
use tokio::sync::mpsc;

use libp2p::Multiaddr;

use csd::chain::index::get_hidx;
use csd::net::mempool::Mempool;
use csd::net::node::{spawn_p2p, NetConfig, NetHandle, TestPeerMode, TEST_PEERS_REQUESTS_SERVED};
use csd::state::db::{get_tip, Stores};
use csd::types::Hash32;

mod testutil_chain;
use testutil_chain::{build_base_chain_with_miner, open_db};

const START: u64 = 1_700_800_000;
/// More than one headers answer (MAX_HEADERS_PER_SYNC, 1,024), so sync takes two headers rounds.
const LEN: u64 = 1_100;

async fn spawn(db: &Arc<Stores>, tmp: &TempDir, genesis: Hash32, bootnodes: Vec<Multiaddr>) -> Result<NetHandle> {
    let (mined_tx, mined_rx) = mpsc::unbounded_channel();
    let (gossip_tx, gossip_rx) = mpsc::unbounded_channel();
    drop(mined_tx);
    drop(gossip_tx);
    let cfg = NetConfig {
        datadir: tmp.path().to_string_lossy().to_string(),
        listen: "/ip4/127.0.0.1/tcp/0".parse::<Multiaddr>()?,
        is_bootnode: bootnodes.is_empty(),
        bootnodes,
        genesis_hash: genesis,
        test_mode: TestPeerMode::Normal,
    };
    spawn_p2p(db.clone(), Arc::new(Mempool::new()), cfg, mined_rx, gossip_rx, csd::chain::lock::new_chain_lock()).await
}

async fn boot_addr(handle: &NetHandle) -> Result<Multiaddr> {
    for _ in 0..60 {
        if let Some(addr) = handle.listen_addr().await {
            return Ok(format!("{}/p2p/{}", addr, handle.peer_id).parse()?);
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    anyhow::bail!("no listen address")
}

/// The happy path of the background requests (`src/net/background.rs`): one honest peer, a fresh
/// node holding only genesis. The node bootstraps (its first GetTip and a peers request, one at a
/// time, the peers request delivered), is owed headers on the heavier tip, and follows the peer's
/// 1,100-block chain through two headers rounds to its tip.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_fresh_node_syncs_a_long_chain_from_one_honest_peer() -> Result<()> {
    let (tmp_a, tmp_b) = (TempDir::new()?, TempDir::new()?);
    let (db_a, db_b) = (Arc::new(open_db(&tmp_a)?), Arc::new(open_db(&tmp_b)?));
    let chain = build_base_chain_with_miner(&db_a, LEN, START, [0x11; 20])?;
    assert_eq!(build_base_chain_with_miner(&db_b, 1, START, [0x11; 20])?, chain[..1]);
    let (genesis, tip) = (chain[0], chain[LEN as usize - 1]);

    let a = spawn(&db_a, &tmp_a, genesis, vec![]).await?;
    let started = Instant::now();
    let b = spawn(&db_b, &tmp_b, genesis, vec![boot_addr(&a).await?]).await?;
    let deadline = tokio::time::Instant::now() + Duration::from_secs(300);
    while get_tip(&db_b)? != Some(tip) && tokio::time::Instant::now() < deadline {
        tokio::time::sleep(Duration::from_millis(500)).await;
    }
    let height = get_tip(&db_b)?.and_then(|t| get_hidx(&db_b, &t).ok().flatten()).map(|hi| hi.height);
    assert_eq!(get_tip(&db_b)?, Some(tip), "the fresh node stopped at height {height:?}");
    eprintln!("[measure] synced {LEN} blocks from one peer in {:?}", started.elapsed());
    get_hidx(&db_b, &tip)?.context("tip indexed")?;
    let served = TEST_PEERS_REQUESTS_SERVED.lock().unwrap().get(&(a.peer_id, b.peer_id)).copied().unwrap_or(0);
    assert!(served >= 1, "the fresh node's owed peers request never reached its peer");
    Ok(())
}
