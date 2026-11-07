#![cfg(feature = "test-bypass")] // live p2p lane: toy chains and the fault seam need the bypass (cargo test --features test-bypass)
use anyhow::{Context, Result};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tempfile::TempDir;
use tokio::sync::mpsc;

use libp2p::{Multiaddr, PeerId};

use csd::chain::index::{get_hidx, header_hash};
use csd::chain::lock::{new_chain_lock, ChainLock};
use csd::net::mempool::Mempool;
use csd::net::node::{spawn_p2p, NetConfig, NetHandle, TestPeerMode, TEST_PEER_SCORES, TEST_RATE_DROPPED_HEADERS};
use csd::net::{GossipTxEvent, MinedHeaderEvent};
use csd::state::db::{get_tip, k_block, Stores};
use csd::types::{Block, BlockHeader, Hash32};

mod testutil_chain;
use testutil_chain::{apply_canonical_block_to, build_base_chain_with_miner, make_coinbase_to, make_test_header, open_db};

const START: u64 = 1_700_700_000;
/// RL_MAX_GOSSIP_MSGS_PER_WINDOW and RL_WINDOW in src/net/node.rs.
const BUDGET: usize = 1024;
const WINDOW: Duration = Duration::from_secs(10);

struct Node {
    db: Arc<Stores>,
    lock: ChainLock,
    handle: NetHandle,
    announce: mpsc::UnboundedSender<MinedHeaderEvent>,
    _gossip: mpsc::UnboundedSender<GossipTxEvent>,
    _dir: TempDir,
}

async fn spawn(chain: impl Fn(&Stores) -> Result<()>, bootnodes: Vec<Multiaddr>, mode: TestPeerMode, genesis: Hash32) -> Result<Node> {
    let dir = TempDir::new()?;
    let db = open_db(&dir)?;
    chain(&db)?;
    let db = Arc::new(db);
    let (announce, mined_rx) = mpsc::unbounded_channel();
    let (gossip, gossip_rx) = mpsc::unbounded_channel();
    let cfg = NetConfig {
        datadir: dir.path().to_string_lossy().to_string(),
        listen: "/ip4/127.0.0.1/tcp/0".parse::<Multiaddr>()?,
        is_bootnode: bootnodes.is_empty(),
        bootnodes,
        genesis_hash: genesis,
        test_mode: mode,
    };
    let lock = new_chain_lock();
    let handle = spawn_p2p(db.clone(), Arc::new(Mempool::new()), cfg, mined_rx, gossip_rx, lock.clone()).await?;
    Ok(Node { db, lock, handle, announce, _gossip: gossip, _dir: dir })
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

fn score(scorer: &PeerId, peer: &PeerId) -> i32 {
    TEST_PEER_SCORES.lock().unwrap().get(scorer).and_then(|m| m.get(peer).copied()).unwrap_or(0)
}

/// Polls every 100 ms until `done` or `secs`; `watch` runs on every poll and fails the wait.
async fn wait_until(secs: u64, mut watch: impl FnMut() -> Result<()>, mut done: impl FnMut() -> Result<bool>) -> Result<bool> {
    let deadline = tokio::time::Instant::now() + Duration::from_secs(secs);
    while tokio::time::Instant::now() < deadline {
        watch()?;
        if done()? {
            return Ok(true);
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    done()
}

fn indexed(db: &Stores, hashes: &[Hash32]) -> Result<usize> {
    let mut n = 0;
    for h in hashes {
        n += usize::from(get_hidx(db, h)?.is_some());
    }
    Ok(n)
}

/// Applies a block on B's tip under B's chain lock and announces it from B.
fn mine_at_b(b: &Node, prev: Hash32, height: u64, miner: [u8; 20]) -> Result<Hash32> {
    let hash = {
        let _held = b.lock.lock();
        apply_canonical_block_to(&b.db, prev, height, START + height * 60 + 7, miner)?
    };
    let raw = b.db.blocks.get(k_block(&hash))?.context("block stored at B")?;
    let blk: Block = csd::codec::consensus_bincode().deserialize(&raw)?;
    b.announce.send(MinedHeaderEvent { hash, header: blk.header })?;
    Ok(hash)
}

/// A caught-up node keeps the forwarder of message 1,025 within a rate window, whatever the
/// messages were: the forwarder may be an honest relay. B is an honest relay for R1 and R2, which
/// each send it 550 valid side-branch headers (under B's budget for each); B forwards all 1,100 to caught-up A. A
/// takes the budget's worth, drops the rest, keeps B and B's credit; after the window B's own
/// gossip is taken again and A syncs a block from B. Then R1 and R2 send 1,000 a window each (B
/// forwards twice A's budget); B's announcement of its next block is dropped for B's budget and A
/// applies the block while the flood runs. The figures are printed (`--nocapture`). R1 and R2
/// publish unsigned (`AnonymousGossip`), and B forwards their messages as they are.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn an_honest_relay_over_the_gossip_budget_stays_connected_and_synced() -> Result<()> {
    let miner = [0x11; 20];
    let scratch = TempDir::new()?;
    let base = open_db(&scratch)?;
    let shared = build_base_chain_with_miner(&base, 5, START, miner)?;
    let (genesis, tip) = (shared[0], shared[4]);
    let chain = |db: &Stores| -> Result<()> {
        anyhow::ensure!(build_base_chain_with_miner(db, 5, START, miner)? == shared);
        Ok(())
    };

    // Valid headers on a side branch below the tip's work: siblings at height 3, one per nonce.
    let side = make_test_header(&base, shared[2], &[make_coinbase_to(3, [0x44; 20])], 3)?;
    let sibling = |nonce: u32| BlockHeader { nonce, ..side.clone() };
    let send = |node: &Node, from: u32, n: u32| -> Result<Vec<Hash32>> {
        (from..from + n)
            .map(|nonce| {
                let header = sibling(nonce);
                let hash = header_hash(&header);
                node.announce.send(MinedHeaderEvent { hash, header })?;
                Ok(hash)
            })
            .collect()
    };

    let a = spawn(chain, vec![], TestPeerMode::Normal, genesis).await?;
    let b = spawn(chain, vec![boot_addr(&a.handle).await?], TestPeerMode::Normal, genesis).await?;
    let boot_b = boot_addr(&b.handle).await?;
    let r1 = spawn(chain, vec![boot_b.clone()], TestPeerMode::AnonymousGossip, genesis).await?;
    let r2 = spawn(chain, vec![boot_b], TestPeerMode::AnonymousGossip, genesis).await?;
    let (pa, pb) = (a.handle.peer_id, b.handle.peer_id);
    let ready = wait_until(30, || Ok(()), || {
        Ok(a.handle.connected_peers() == 1 && b.handle.connected_peers() == 3 && a.handle.best_peer_height() == 4)
    })
    .await?;
    assert!(ready, "setup: A caught up with B, and R1 and R2 connected only to B");
    tokio::time::sleep(Duration::from_secs(3)).await;
    assert_eq!(get_tip(&a.db)?, Some(tip));

    let peer_change = a.handle.last_peer_change_unix();
    let kept = || -> Result<()> {
        anyhow::ensure!(a.handle.connected_peers() == 1, "A dropped B");
        anyhow::ensure!(a.handle.last_peer_change_unix() == peer_change, "A's connection to B changed");
        Ok(())
    };

    // The burst: one window's budget is indexed, the rest dropped.
    let burst_at = Instant::now();
    let mut burst = send(&r1, 0, 550)?;
    burst.extend(send(&r2, 550, 550)?);
    let mut last = (0, Instant::now());
    let settled = wait_until(30, &kept, || {
        let n = indexed(&a.db, &burst)?;
        if n != last.0 {
            last = (n, Instant::now());
        }
        Ok(n > 0 && last.1.elapsed() >= Duration::from_secs(2))
    })
    .await?;
    kept()?;
    assert!(settled, "A's index of the burst did not settle");
    let at_b = indexed(&b.db, &burst)?;
    let took = last.1.duration_since(burst_at);
    eprintln!("[measure] burst: 1100 sent through B (B indexed {at_b}), A indexed {} in {took:?}", last.0);
    assert_eq!(at_b, burst.len(), "setup: B takes every header, each origin being under its budget");
    assert!(took < WINDOW, "setup: A took {took:?} for the burst, past one rate window");
    assert_eq!(last.0, BUDGET, "A indexes the budget's worth of one window and drops the rest");
    let credit = wait_until(6, &kept, || Ok(score(&pa, &pb) > 0)).await?;
    assert!(credit, "B lost its credit for the headers A indexed");

    // After the window: B's own gossip is taken again, and A syncs B's next block.
    tokio::time::sleep_until((burst_at + WINDOW + Duration::from_secs(1)).into()).await;
    let after = send(&b, 1_100, 1)?;
    let taken = wait_until(10, &kept, || Ok(indexed(&a.db, &after)? == 1)).await?;
    assert!(taken, "A refused B's gossip after the window");
    let x_at = Instant::now();
    let x = mine_at_b(&b, tip, 5, miner)?;
    let synced = wait_until(30, &kept, || Ok(get_tip(&a.db)? == Some(x))).await?;
    assert!(synced, "A did not sync B's block after the burst");
    eprintln!("[measure] no flood: A applied B's block {:?} after its announce", x_at.elapsed());

    // Sustained: R1 and R2 send 100 a second each, twice A's budget through B. Once A starts
    // dropping B's gossip in a window, B announces its next block Y, whose header A drops too; A
    // must apply Y while the flood still runs.
    let rate_dropped = || TEST_RATE_DROPPED_HEADERS.lock().unwrap().get(&(pa, pb)).cloned().unwrap_or_default();
    let mut flood: Vec<Hash32> = Vec::new();
    let mut nonce = 2_000;
    let flood_at = Instant::now();
    let (mut y, mut y_at, mut y_took, mut y_dropped) = (None, None, None, false);
    let (mut seen_drops, mut quiet_ticks) = (rate_dropped().len(), 0);
    while y_took.is_none() && flood_at.elapsed() < 9 * WINDOW {
        for r in [&r1, &r2] {
            flood.extend(send(r, nonce, 10)?);
            nonce += 10;
        }
        let dropped = rate_dropped();
        let growing = dropped.len() > seen_drops;
        seen_drops = dropped.len();
        if y.is_none() && growing && quiet_ticks >= 5 {
            // The budget ran out in this window moments ago: most of the window is left.
            y_at = Some(Instant::now());
            y = Some(mine_at_b(&b, x, 6, miner)?);
        }
        quiet_ticks = if growing { 0 } else { quiet_ticks + 1 };
        if let Some(hash) = y {
            y_dropped |= dropped.contains(&hash);
            if get_tip(&a.db)? == Some(hash) {
                y_took = y_at.map(|t| t.elapsed());
            }
        }
        kept()?;
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    let sent_for = flood_at.elapsed();
    let y_took = y_took.context("A did not apply B's block Y while the flood ran")?;
    assert!(y_dropped, "B's announcement of Y was not dropped for B's budget: the case is not exercised");
    let _ = wait_until(3, &kept, || Ok(false)).await?;
    let (at_b, n) = (indexed(&b.db, &flood)?, indexed(&a.db, &flood)?);
    let secs = sent_for.as_secs_f64();
    eprintln!(
        "[measure] sustained: {} sent over {secs:.1} s, B indexed {at_b}, A indexed {n} ({:.0}/s); Y's announcement dropped, A applied Y {y_took:?} after it, during the flood",
        flood.len(),
        n as f64 / secs,
    );
    let windows = sent_for.as_secs().div_ceil(WINDOW.as_secs()) as usize + 1;
    assert!(n <= windows * BUDGET, "A took {n} of the flood, past the budget of the {windows} windows it spans");
    assert!(n >= BUDGET, "A took only {n} of the flood");
    assert!(score(&pa, &pb) > 0, "B lost its credit during the flood");
    kept()?;
    Ok(())
}
