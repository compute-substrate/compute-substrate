#![cfg(feature = "test-bypass")] // live p2p lane: toy chains and the fault seam need the bypass (cargo test --features test-bypass)
use anyhow::{Context, Result};
use std::cell::Cell;
use std::sync::atomic::Ordering;
use std::sync::Arc;
use std::time::Duration;
use tempfile::TempDir;
use tokio::sync::mpsc;

use libp2p::{Multiaddr, PeerId};

use csd::chain::index::{get_hidx, header_hash, index_header};
use csd::net::mempool::Mempool;
use csd::net::node::{
    spawn_p2p, NetConfig, NetHandle, TestPeerMode, TEST_EMPTY_HEADERS_ANSWERS, TEST_PEER_SCORES, TEST_REPLAYED_HEADERS,
    TEST_TIPS_FOR_HEADERS,
};
use csd::net::MinedHeaderEvent;
use csd::state::db::{get_tip, Stores};
use csd::types::Hash32;

mod testutil_chain;
use testutil_chain::{
    apply_canonical_block_to, build_base_chain_with_miner, make_coinbase_to, make_test_header, open_db,
    store_index_fork_block_to,
};

const START: u64 = 1_700_600_000;

fn score(scorer: &PeerId, peer: &PeerId) -> i32 {
    TEST_PEER_SCORES.lock().unwrap().get(scorer).and_then(|m| m.get(peer).copied()).unwrap_or(0)
}

async fn spawn(db: &Arc<Stores>, tmp: &TempDir, genesis: Hash32, bootnodes: Vec<Multiaddr>, mode: TestPeerMode) -> Result<NetHandle> {
    Ok(spawn_announcing(db, tmp, genesis, bootnodes, mode).await?.0)
}

/// As `spawn`, keeping the sender through which the node publishes a header as its own.
async fn spawn_announcing(
    db: &Arc<Stores>,
    tmp: &TempDir,
    genesis: Hash32,
    bootnodes: Vec<Multiaddr>,
    mode: TestPeerMode,
) -> Result<(NetHandle, mpsc::UnboundedSender<MinedHeaderEvent>)> {
    let (mined_tx, mined_rx) = mpsc::unbounded_channel();
    let (gossip_tx, gossip_rx) = mpsc::unbounded_channel();
    drop(gossip_tx);
    let cfg = NetConfig {
        datadir: tmp.path().to_string_lossy().to_string(),
        listen: "/ip4/127.0.0.1/tcp/0".parse::<Multiaddr>()?,
        is_bootnode: bootnodes.is_empty(),
        bootnodes,
        genesis_hash: genesis,
        test_mode: mode,
    };
    let handle = spawn_p2p(db.clone(), Arc::new(Mempool::new()), cfg, mined_rx, gossip_rx, csd::chain::lock::new_chain_lock()).await?;
    Ok((handle, mined_tx))
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

async fn wait_until(secs: u64, mut done: impl FnMut() -> Result<bool>) -> Result<bool> {
    let deadline = tokio::time::Instant::now() + Duration::from_secs(secs);
    while tokio::time::Instant::now() < deadline {
        if done()? {
            return Ok(true);
        }
        tokio::time::sleep(Duration::from_millis(200)).await;
    }
    done()
}

/// Without these checks, any non-empty Headers answer earned +2 score and its length in
/// peer quality before a header was checked, and a Headers answer to a GetTip was taken like one to
/// our headers request, so 1,024 copies of a known header every 10 s farmed both. B does that: it
/// answers GetTip with copies of its own tip's header (new to A) and every other time with a claim
/// that makes A ask it for headers, which it answers with copies of a header A holds. C is honest
/// and serves a heavier chain. A earns B nothing, indexes nothing from the GetTip answers, and
/// follows C, whose score never drops; both stay connected.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn replayed_headers_earn_nothing_and_an_honest_headers_answer_is_taken() -> Result<()> {
    let (tmp_a, tmp_b, tmp_c) = (TempDir::new()?, TempDir::new()?, TempDir::new()?);
    let (db_a, db_b, db_c) = (Arc::new(open_db(&tmp_a)?), Arc::new(open_db(&tmp_b)?), Arc::new(open_db(&tmp_c)?));
    let miner = [0x11; 20];

    let shared = build_base_chain_with_miner(&db_a, 5, START, miner)?;
    assert_eq!(build_base_chain_with_miner(&db_b, 5, START, miner)?, shared);
    assert_eq!(build_base_chain_with_miner(&db_c, 5, START, miner)?, shared);
    let (genesis, tip_a) = (shared[0], shared[4]);

    // B's tip: one block on A's tip that A has not seen.
    let tip_b = apply_canonical_block_to(&db_b, tip_a, 5, START + 5 * 60 + 7, [0x22; 20])?;
    // C: three more blocks on A's tip.
    let mut tip_c = tip_a;
    for h in 5..8 {
        tip_c = apply_canonical_block_to(&db_c, tip_c, h, START + h * 60, [0x33; 20])?;
    }

    let replayed0 = [0, 1].map(|i| TEST_REPLAYED_HEADERS[i].load(Ordering::Relaxed));
    let handle_a = spawn(&db_a, &tmp_a, genesis, vec![], TestPeerMode::Normal).await?;
    let boot_a = boot_addr(&handle_a).await?;
    let handle_b = spawn(&db_b, &tmp_b, genesis, vec![boot_a.clone()], TestPeerMode::ReplayHeaders).await?;
    let handle_c = spawn(&db_c, &tmp_c, genesis, vec![boot_a], TestPeerMode::Normal).await?;
    let (a, b, c) = (handle_a.peer_id, handle_b.peer_id, handle_c.peer_id);

    // Until B has answered both kinds of request, and a poll tick (5 s) after, so
    // the score A held for B after the last answer is copied out.
    let (highest_b, lowest_c) = (Cell::new(0), Cell::new(0));
    let sample = || {
        highest_b.set(highest_b.get().max(score(&a, &b)));
        lowest_c.set(lowest_c.get().min(score(&a, &c)));
    };
    let replayed = wait_until(60, || {
        sample();
        let sent = [0, 1].map(|i| TEST_REPLAYED_HEADERS[i].load(Ordering::Relaxed));
        Ok(sent[0] > replayed0[0] && sent[1] > replayed0[1])
    })
    .await?;
    assert!(replayed, "B did not answer both kinds of request");
    let _ = wait_until(6, || {
        sample();
        Ok(false)
    })
    .await?;

    assert!(get_hidx(&db_a, &tip_b)?.is_none(), "A indexed the header B sent in answer to a GetTip");
    assert!(highest_b.get() <= 0, "A credited B for replayed headers: {}", highest_b.get());

    // The honest path: C's headers were indexed and its blocks applied, at no cost to C.
    let followed = wait_until(30, || {
        sample();
        Ok(get_tip(&db_a)? == Some(tip_c))
    })
    .await?;
    assert!(followed, "A did not follow C's chain");
    assert!(lowest_c.get() >= 0, "C was struck: {}", lowest_c.get());
    // A block C served became canonical: +3 for serving it, +12 for its becoming canonical.
    let credited = wait_until(6, || Ok(score(&a, &c) >= 15)).await?;
    assert!(credited, "C's served blocks earned it nothing: {}", score(&a, &c));
    assert_eq!(handle_a.connected_peers(), 2, "B and C are still connected");
    Ok(())
}

/// An empty Headers answer from the sync peer costs it no score: an honest peer answers empty
/// whenever its chain has nothing above our locator's anchor.
/// A and its sync peer B share tip H. B holds a side branch whose parent P is below H's work, and
/// relays P's child C. A lacks P, asks B for headers from H, and B answers empty; B's score at A
/// does not move.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn an_empty_headers_answer_from_the_sync_peer_costs_it_nothing() -> Result<()> {
    let (tmp_a, tmp_b) = (TempDir::new()?, TempDir::new()?);
    let (db_a, db_b) = (Arc::new(open_db(&tmp_a)?), Arc::new(open_db(&tmp_b)?));
    let miner = [0x11; 20];

    let shared = build_base_chain_with_miner(&db_a, 5, START, miner)?;
    assert_eq!(build_base_chain_with_miner(&db_b, 5, START, miner)?, shared);
    let (genesis, tip) = (shared[0], shared[4]);

    let side = [0x44; 20];
    let p = store_index_fork_block_to(&db_b, shared[2], 3, START + 3 * 60 + 17, side)?;
    let p_hi = get_hidx(&db_b, &p)?.context("P indexed at B")?;
    assert!(p_hi.chainwork < get_hidx(&db_b, &tip)?.context("tip index")?.chainwork, "setup: P is below H's work");
    let c = make_test_header(&db_b, p, &[make_coinbase_to(4, side)], 4)?;
    index_header(&db_b, &c, Some(&p_hi))?;
    let c_hash = header_hash(&c);

    let handle_a = spawn(&db_a, &tmp_a, genesis, vec![], TestPeerMode::Normal).await?;
    let (handle_b, announce_b) =
        spawn_announcing(&db_b, &tmp_b, genesis, vec![boot_addr(&handle_a).await?], TestPeerMode::Normal).await?;
    let (a, b) = (handle_a.peer_id, handle_b.peer_id);

    // A has indexed B's Tip answer, so B, its only peer, is its sync peer and A is caught up.
    let synced = wait_until(30, || Ok(handle_a.connected_peers() == 1 && handle_a.best_peer_height() == 4)).await?;
    assert!(synced, "A did not take B's tip");
    // Subscriptions and mesh grafting (1 s heartbeats) settle before the publish.
    tokio::time::sleep(Duration::from_secs(3)).await;
    assert_eq!(get_tip(&db_a)?, Some(tip));
    assert_eq!(get_tip(&db_b)?, Some(tip));

    let empty = || TEST_EMPTY_HEADERS_ANSWERS.lock().unwrap().get(&b).copied().unwrap_or(0);
    let empty0 = empty();
    let (lowest, highest) = (Cell::new(score(&a, &b)), Cell::new(score(&a, &b)));
    assert_eq!(lowest.get(), 0, "setup: B starts at 0");
    let sample = || {
        let s = score(&a, &b);
        lowest.set(lowest.get().min(s));
        highest.set(highest.get().max(s));
    };

    announce_b.send(MinedHeaderEvent { hash: c_hash, header: c })?;
    let answered = wait_until(30, || {
        sample();
        Ok(empty() > empty0)
    })
    .await?;
    assert!(answered, "A did not get B's empty answer to the headers request C caused");
    // A poll tick (5 s) after the answer copies out the score A held for B.
    let _ = wait_until(6, || {
        sample();
        Ok(false)
    })
    .await?;

    assert!(get_hidx(&db_a, &c_hash)?.is_none(), "A indexed C without its parent");
    assert_eq!((lowest.get(), highest.get()), (0, 0), "B's score moved for an honest empty answer");
    assert_eq!(handle_a.connected_peers(), 1, "B is still connected");
    Ok(())
}

/// Without the check, the forwarder of a gossip header earned +1 whether or not the header
/// was new here, so re-gossiping headers we hold, or ones `index_header` refuses, farmed score up
/// to the ceiling. B gossips 20 headers A holds and one A refuses (its time is its parent's), then
/// one new header; A credits B 1, for the new one only.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_gossip_header_earns_its_forwarder_credit_only_when_it_is_new_here() -> Result<()> {
    let (tmp_a, tmp_b) = (TempDir::new()?, TempDir::new()?);
    let (db_a, db_b) = (Arc::new(open_db(&tmp_a)?), Arc::new(open_db(&tmp_b)?));
    let miner = [0x11; 20];
    let shared = build_base_chain_with_miner(&db_a, 5, START, miner)?;
    assert_eq!(build_base_chain_with_miner(&db_b, 5, START, miner)?, shared);
    let genesis = shared[0];

    // Side-branch siblings at height 3, below the tip's work: 20 that both hold, one only B sends.
    let side = make_test_header(&db_b, shared[2], &[make_coinbase_to(3, [0x44; 20])], 3)?;
    let parent = get_hidx(&db_a, &shared[2])?.context("parent index")?;
    let sibling = |nonce: u32| csd::types::BlockHeader { nonce, ..side.clone() };
    let mut known = Vec::new();
    for nonce in 0..20 {
        let hdr = sibling(nonce);
        index_header(&db_a, &hdr, Some(&parent))?;
        index_header(&db_b, &hdr, Some(&parent))?;
        known.push(hdr);
    }
    let refused = csd::types::BlockHeader { time: parent.time, ..sibling(100) };
    assert!(index_header(&db_b, &refused, Some(&parent)).is_err(), "setup: the refused header is refused");
    let new = sibling(200);
    let new_hash = header_hash(&new);

    let handle_a = spawn(&db_a, &tmp_a, genesis, vec![], TestPeerMode::Normal).await?;
    let (handle_b, announce_b) =
        spawn_announcing(&db_b, &tmp_b, genesis, vec![boot_addr(&handle_a).await?], TestPeerMode::Normal).await?;
    let (a, b) = (handle_a.peer_id, handle_b.peer_id);
    let ready = wait_until(30, || Ok(handle_a.connected_peers() == 1 && handle_a.best_peer_height() == 4)).await?;
    assert!(ready, "A did not take B's tip");
    tokio::time::sleep(Duration::from_secs(3)).await;
    assert_eq!(score(&a, &b), 0, "setup: B starts at 0");

    for header in known.into_iter().chain([refused]) {
        announce_b.send(MinedHeaderEvent { hash: header_hash(&header), header })?;
    }
    // One connection carries the messages in order, so the new header is judged after the others.
    announce_b.send(MinedHeaderEvent { hash: new_hash, header: new })?;
    let highest = Cell::new(0);
    let indexed = wait_until(20, || {
        highest.set(highest.get().max(score(&a, &b)));
        Ok(get_hidx(&db_a, &new_hash)?.is_some())
    })
    .await?;
    assert!(indexed, "A did not index the new header B forwarded");
    // A poll tick (5 s) after copies out the score A held for B.
    let _ = wait_until(6, || {
        highest.set(highest.get().max(score(&a, &b)));
        Ok(false)
    })
    .await?;
    assert_eq!(highest.get(), 1, "B's credit for 20 known headers, one refused and one new");
    assert_eq!(handle_a.connected_peers(), 1, "B is still connected");
    Ok(())
}

/// Without the check, a Tip sent in answer to our headers request ran the
/// Tip arm, so it set the peer's height and work and could start a new headers request, which let
/// eight such peers hold every background slot. B answers our headers request (caused, as in the
/// empty-answer test, by a side-branch header whose parent A lacks) with a Tip naming Z, a header
/// both hold one block above the tip. A takes B's GetTip answers (height 4) and never Z's height.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_tip_sent_to_our_headers_request_moves_nothing() -> Result<()> {
    let (tmp_a, tmp_b) = (TempDir::new()?, TempDir::new()?);
    let (db_a, db_b) = (Arc::new(open_db(&tmp_a)?), Arc::new(open_db(&tmp_b)?));
    let miner = [0x11; 20];
    let shared = build_base_chain_with_miner(&db_a, 5, START, miner)?;
    assert_eq!(build_base_chain_with_miner(&db_b, 5, START, miner)?, shared);
    let (genesis, tip) = (shared[0], shared[4]);

    let z = make_test_header(&db_b, tip, &[make_coinbase_to(5, [0x55; 20])], 5)?;
    let tip_hi = get_hidx(&db_a, &tip)?.context("tip index")?;
    index_header(&db_a, &z, Some(&tip_hi))?;
    index_header(&db_b, &z, Some(&tip_hi))?;
    let side = [0x44; 20];
    let p = store_index_fork_block_to(&db_b, shared[2], 3, START + 3 * 60 + 17, side)?;
    let p_hi = get_hidx(&db_b, &p)?.context("P indexed at B")?;
    let c = make_test_header(&db_b, p, &[make_coinbase_to(4, side)], 4)?;
    index_header(&db_b, &c, Some(&p_hi))?;

    let handle_a = spawn(&db_a, &tmp_a, genesis, vec![], TestPeerMode::Normal).await?;
    let (_handle_b, announce_b) = spawn_announcing(
        &db_b,
        &tmp_b,
        genesis,
        vec![boot_addr(&handle_a).await?],
        TestPeerMode::TipForHeaders(header_hash(&z)),
    )
    .await?;
    // The happy path: B's answers to A's GetTip set its height.
    let synced = wait_until(30, || Ok(handle_a.connected_peers() == 1 && handle_a.best_peer_height() == 4)).await?;
    assert!(synced, "A did not take B's tip");
    tokio::time::sleep(Duration::from_secs(3)).await;

    let sent0 = TEST_TIPS_FOR_HEADERS.load(Ordering::Relaxed);
    let highest = Cell::new(handle_a.best_peer_height());
    announce_b.send(MinedHeaderEvent { hash: header_hash(&c), header: c })?;
    let answered = wait_until(30, || {
        highest.set(highest.get().max(handle_a.best_peer_height()));
        Ok(TEST_TIPS_FOR_HEADERS.load(Ordering::Relaxed) > sent0)
    })
    .await?;
    assert!(answered, "B did not answer a headers request with a Tip");
    let _ = wait_until(3, || {
        highest.set(highest.get().max(handle_a.best_peer_height()));
        Ok(false)
    })
    .await?;
    assert_eq!(highest.get(), 4, "a Tip sent to our headers request set B's height");
    assert_eq!(handle_a.connected_peers(), 1, "B is still connected");
    Ok(())
}
