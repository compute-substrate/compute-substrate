#![cfg(feature = "test-bypass")] // live p2p lane: toy chains and the fault seam need the bypass (cargo test --features test-bypass)
// The inbound cap counts connections (the peer cap
// plus 64) and the peer-cap evictor counts peers, so on a default bootnode (cap 64, 128 inbound
// places) 64 identities holding two inbound connections each fill every place at the peer cap's
// count, where nothing is evicted, and an honest connection was refused for as long as they stayed.
// Here 64 identities from 16 loopback addresses (4 each, 8 connections, the per-address cap) hold two
// connections each and keep both busy with GetPeers (not a sync request, so the bootnode evictor's
// sync protection does not cover them). An honest peer H is refused while they are younger than the
// evictor's 60 s protection; after it, the node sheds second inbound connections down to its reserve,
// every flooder keeps one, and H's next connection is admitted and served.

use anyhow::Result;
use futures::StreamExt;
use std::net::Ipv4Addr;
use std::sync::atomic::{AtomicBool, AtomicI64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use tempfile::TempDir;

use libp2p::{identity, request_response, swarm::ConnectionId, swarm::SwarmEvent, Multiaddr, PeerId, Swarm};

use csd::chain::index::get_hidx;
use csd::net::node::{TEST_BAD_PROVIDERS, TEST_HOLD_SWARM_AFTER_SHED, TEST_PEER_SCORES};
use csd::net::proto::{SyncRequest, SyncResponse};
use csd::state::db::{k_block, Stores};
use csd::types::{Block, Hash32};

mod testutil_chain;
use testutil_chain::{build_base_chain_with_miner, open_db};
mod testutil_p2p;
use testutil_p2p::{spawn_node, spawn_node_on, swarm_config, sync_rr, transport, transport_from, wait_until};

/// Identities that fill a default bootnode's 128 inbound places, two connections each.
const FLOODERS: usize = 64;
/// Identities per source address: 8 connections, the per-address cap.
const PER_ADDRESS: usize = 4;
/// The evictor's protection of a new peer (`PROTECT_NEW_PEER_SECS`) and one poll tick (5 s), with room.
const PROTECTED_AND_A_TICK: Duration = Duration::from_secs(68);

/// Dials `a` twice from `local` and keeps both connections busy until `until`, a GetPeers a second
/// (the request-response layer takes connections in turn), answering A's requests with an Err;
/// `open` follows its open connections.
async fn hold_two(a: Multiaddr, a_peer: PeerId, local: Ipv4Addr, open: Arc<AtomicI64>, until: Instant) {
    let key = identity::Keypair::generate_ed25519();
    let mut swarm = Swarm::new(transport_from(&key, local), sync_rr(), key.public().to_peer_id(), swarm_config());
    swarm.dial(a.clone()).unwrap();
    swarm.dial(a).unwrap();
    let mut tick = tokio::time::interval(Duration::from_millis(500));
    while Instant::now() < until {
        tokio::select! {
            _ = tick.tick() => {
                if open.load(Ordering::Relaxed) > 0 {
                    swarm.behaviour_mut().send_request(&a_peer, SyncRequest::GetPeers { max: 1 });
                }
            }
            ev = swarm.select_next_some() => match ev {
                SwarmEvent::ConnectionEstablished { .. } => { open.fetch_add(1, Ordering::Relaxed); }
                SwarmEvent::ConnectionClosed { .. } => { open.fetch_sub(1, Ordering::Relaxed); }
                SwarmEvent::Behaviour(request_response::Event::Message {
                    message: request_response::Message::Request { channel, .. }, ..
                }) => {
                    let _ = swarm.behaviour_mut().send_response(channel, SyncResponse::Err { msg: "not served".into() });
                }
                _ => {}
            }
        }
    }
}

/// H dials A from 127.0.0.1, holds what it is given for `secs` and asks for A's tip once connected;
/// returns (its open connections at the end, whether the tip came).
async fn honest_peer(a: Multiaddr, a_peer: PeerId, secs: u64) -> (i64, bool) {
    let key = identity::Keypair::generate_ed25519();
    let mut h = Swarm::new(transport(&key), sync_rr(), key.public().to_peer_id(), swarm_config());
    h.dial(a).unwrap();
    let (mut open, mut tip) = (0i64, false);
    let until = tokio::time::Instant::now() + Duration::from_secs(secs);
    while let Ok(ev) = tokio::time::timeout_at(until, h.select_next_some()).await {
        match ev {
            SwarmEvent::ConnectionEstablished { .. } => {
                open += 1;
                h.behaviour_mut().send_request(&a_peer, SyncRequest::GetTip);
            }
            SwarmEvent::ConnectionClosed { .. } => open -= 1,
            SwarmEvent::Behaviour(request_response::Event::Message {
                message: request_response::Message::Response { response, .. }, ..
            }) => tip |= matches!(response, SyncResponse::Tip { .. }),
            SwarmEvent::Behaviour(request_response::Event::Message {
                message: request_response::Message::Request { channel, .. }, ..
            }) => {
                let _ = h.behaviour_mut().send_response(channel, SyncResponse::Err { msg: "not served".into() });
            }
            _ => {}
        }
    }
    (open, tip)
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn second_inbound_connections_are_shed_and_an_honest_connection_admitted() -> Result<()> {
    let a = spawn_node(vec![]).await?;
    let (addr, a_peer) = (a.dial_addr(), a.handle.peer_id);
    let until = Instant::now() + Duration::from_secs(120);
    let opens: Vec<Arc<AtomicI64>> = (0..FLOODERS).map(|_| Arc::new(AtomicI64::new(0))).collect();
    let mut flood = Vec::new();
    for (i, open) in opens.iter().enumerate() {
        let local = Ipv4Addr::new(127, 0, 0, 2 + (i / PER_ADDRESS) as u8);
        flood.push(tokio::spawn(hold_two(addr.clone(), a_peer, local, open.clone(), until)));
    }
    let total = || opens.iter().map(|o| o.load(Ordering::Relaxed)).sum::<i64>();
    assert!(wait_until(30, || total() == 2 * FLOODERS as i64).await, "the flood holds {} connections", total());
    let full_at = Instant::now();

    // The honest connection is refused while the flood is protected: the scenario holds.
    let (refused_open, _) = honest_peer(addr.clone(), a_peer, 3).await;
    assert_eq!(refused_open, 0, "H was admitted while all 128 inbound places were taken");

    tokio::time::sleep_until((full_at + PROTECTED_AND_A_TICK).into()).await;
    let (held, fewest) = (total(), opens.iter().map(|o| o.load(Ordering::Relaxed)).min().unwrap_or(0));
    let (h_open, h_tip) = honest_peer(addr, a_peer, 8).await;
    eprintln!("[measure] flood connections at {} s: {held} (fewest of one identity {fewest}); H open {h_open}, tip {h_tip}", PROTECTED_AND_A_TICK.as_secs());
    for f in flood {
        f.abort();
    }
    assert_eq!(h_open, 1, "an honest connection is refused while the flood holds {held} inbound connections");
    assert!(h_tip, "H was admitted and not served");
    // The node keeps its reserve by second connections only: 128 - 96 = 32 shed, each identity keeps one.
    assert_eq!(held, 96, "the flood holds {held} connections after the protection");
    assert!(fewest >= 1, "an identity lost both its connections to the shedding");
    Ok(())
}

/// What the honest holder P saw: its connections in the order they were established, the GetBlocks
/// A sent it (connection, block), and, once A closed P's second connection, when it saw that and
/// the blocks asked on it; `read` is set by the test once it has read A's state.
#[derive(Default)]
struct Held {
    conns: Vec<ConnectionId>,
    open: i64,
    blocks: Vec<(ConnectionId, Hash32)>,
    lost: Option<(Instant, Vec<Hash32>)>,
    read: bool,
}

fn load_block(db: &Stores, h: &Hash32) -> Block {
    let bytes = db.blocks.get(k_block(h)).unwrap().expect("P holds the block");
    csd::codec::consensus_bincode().deserialize(&bytes).unwrap()
}

/// P: an honest peer on `chain`, which holds two connections to A, the second dialed once the first
/// is up so that A records it as the newer. Until `reveal` it answers as if its tip were
/// `chain[shown - 1]` (A's own); after, with its own tip and the headers above A's locator. It holds
/// every GetBlock unanswered, keeping its response channel, until A sheds its second connection;
/// then it answers those it holds, and every later GetBlock, at once with an Err, which A takes as a
/// refusal of that block (a stamp for it, no score), so that none of its requests reaches A's 15 s
/// request timeout however long A takes to handle the shed. A block whose request was lost with the
/// shed connection is the exception: when A asks for it again, P holds that request until the test
/// has read A's state, then serves the block. Refusing it would stamp the block just as the blame
/// under test does, and serving it before the read would raise P's score. A asks again only once
/// the close's failures reached its loop, and the test reads within 8 s of the close (with `hold`,
/// of the release), inside that request's 15 s. A GetPeers every 500 ms keeps both connections in
/// use (libp2p closes a connection idle for 10 s).
async fn honest_holder(
    key: identity::Keypair,
    a: Multiaddr,
    a_peer: PeerId,
    db: Arc<Stores>,
    chain: Vec<Hash32>,
    shown: usize,
    reveal: Arc<AtomicBool>,
    held: Arc<Mutex<Held>>,
    until: Instant,
) {
    let mut swarm = Swarm::new(transport(&key), sync_rr(), key.public().to_peer_id(), swarm_config());
    swarm.dial(a.clone()).unwrap();
    // `channels`: GetBlocks held until the shed; `retries`: requests for a lost block, held until `read`.
    let (mut channels, mut retries) = (Vec::new(), Vec::new());
    let tip_of = |h: &Hash32| {
        let hi = get_hidx(&db, h).unwrap().expect("P indexed its chain");
        SyncResponse::Tip { hash: *h, height: hi.height, chainwork: hi.chainwork }
    };
    let mut tick = tokio::time::interval(Duration::from_millis(500));
    while Instant::now() < until {
        let ev = tokio::select! {
            _ = tick.tick() => {
                let held = held.lock().unwrap();
                if held.read {
                    for (hash, channel) in retries.drain(..) {
                        let _ = swarm.behaviour_mut().send_response(channel, SyncResponse::Block { block: load_block(&db, &hash) });
                    }
                }
                if held.open > 0 {
                    swarm.behaviour_mut().send_request(&a_peer, SyncRequest::GetPeers { max: 1 });
                }
                continue;
            }
            ev = swarm.select_next_some() => ev,
        };
        let revealed = reveal.load(Ordering::SeqCst);
        match ev {
            SwarmEvent::ConnectionEstablished { connection_id, .. } => {
                let mut held = held.lock().unwrap();
                held.conns.push(connection_id);
                held.open += 1;
                if held.conns.len() == 1 {
                    swarm.dial(a.clone()).unwrap();
                }
            }
            SwarmEvent::ConnectionClosed { connection_id, .. } => {
                let mut held = held.lock().unwrap();
                held.open -= 1;
                if held.conns.get(1) == Some(&connection_id) {
                    let lost: Vec<Hash32> = held.blocks.iter().filter(|(c, _)| *c == connection_id).map(|(_, h)| *h).collect();
                    // A request for a lost block that reached P on the other connection before this
                    // close is a retry; the lost requests themselves went with the connection, and
                    // answering them later does nothing.
                    for (hash, channel) in channels.drain(..) {
                        if lost.contains(&hash) {
                            retries.push((hash, channel));
                        } else {
                            let _ = swarm.behaviour_mut().send_response(channel, SyncResponse::Err { msg: "not served".into() });
                        }
                    }
                    held.lost = Some((Instant::now(), lost));
                }
            }
            SwarmEvent::Behaviour(request_response::Event::Message {
                connection_id,
                message: request_response::Message::Request { request, channel, .. },
                ..
            }) => {
                let answer = match request {
                    SyncRequest::GetTip => tip_of(&chain[if revealed { chain.len() - 1 } else { shown - 1 }]),
                    SyncRequest::GetHeadersByLocator { locator, max } => {
                        let top = if revealed { chain.len() } else { shown };
                        let from = chain[..top].iter().rposition(|h| locator.contains(h)).map_or(0, |i| i + 1);
                        let headers = chain[from..top].iter().take(max as usize).map(|h| load_block(&db, h).header).collect();
                        SyncResponse::Headers { headers }
                    }
                    SyncRequest::GetBlock { hash } => {
                        let mut held = held.lock().unwrap();
                        held.blocks.push((connection_id, hash));
                        if held.lost.is_none() {
                            channels.push((hash, channel));
                            continue;
                        }
                        if held.lost.as_ref().is_some_and(|(_, lost)| lost.contains(&hash)) {
                            retries.push((hash, channel));
                            continue;
                        }
                        SyncResponse::Err { msg: "not served".into() }
                    }
                    SyncRequest::GetPeers { .. } => SyncResponse::Peers { peers: vec![] },
                    _ => SyncResponse::Err { msg: "not served".into() },
                };
                let _ = swarm.behaviour_mut().send_response(channel, answer);
            }
            _ => {}
        }
    }
}

// The poll tick sheds a peer's second inbound connection, and our own
// requests to that peer are spread over its connections by request id (request-response 0.30.0
// lib.rs:575), so the shed connection can carry our GetBlock. Its OutboundFailure::ConnectionClosed
// reached the arm as the peer's failure: -1 to its score, a 120 s bad-provider stamp for the block
// and a sync-peer switch, for a close that was ours. P, an honest peer on a longer chain, holds two
// connections to A from before the evictor's 60 s protection ends; 47 young flood identities (which the
// protection keeps out of the shedding order) bring A's inbound connections to the cap less its
// reserve (96 on a default bootnode), where nothing is shed; P announces its chain and A asks it for
// two blocks, an immediate request and the pump's next, consecutive request ids and so one on each
// of P's connections; P holds them; one more flood identity takes A past the reserve, and the tick
// sheds P's second connection, the only one it may shed. With `hold`, A's loop then polls no swarm
// event until a poll tick at least 6 s later (`TEST_HOLD_SWARM_AFTER_SHED`), so the failures stay
// queued across that tick, and A's state is read at a tick after it let them through.
struct ShedOutcome {
    score: i32,
    stamped: usize,
    open: i64,
    asked_again: bool,
    stored_lost: bool,
}

async fn shed_with_our_block_request_on_it(hold: bool) -> Result<ShedOutcome> {
    const BASE: u64 = 8;
    const EXTRA: u64 = 20;
    const START: u64 = 1_700_950_000;
    const MINER: [u8; 20] = [0x5E; 20];
    /// Flood identities that bring A's inbound connections, with P's two, to 96: the cap less the reserve.
    const AT_THE_RESERVE: usize = 47;

    let tmp_p = TempDir::new()?;
    let db_p = Arc::new(open_db(&tmp_p)?);
    let chain = build_base_chain_with_miner(&db_p, BASE + EXTRA, START, MINER)?;
    let tmp_a = TempDir::new()?;
    let db_a = Arc::new(open_db(&tmp_a)?);
    let base = build_base_chain_with_miner(&db_a, BASE, START, MINER)?;
    assert_eq!(base[..], chain[..BASE as usize], "A's chain is P's first {BASE} blocks");
    let a = spawn_node_on(db_a.clone(), tmp_a, chain[0], vec![]).await?;
    let (addr, a_peer) = (a.dial_addr(), a.handle.peer_id);
    if hold {
        TEST_HOLD_SWARM_AFTER_SHED.lock().unwrap().insert(a_peer, None);
    }

    let until = Instant::now() + Duration::from_secs(240);
    let (reveal, held) = (Arc::new(AtomicBool::new(false)), Arc::new(Mutex::new(Held::default())));
    let p_key = identity::Keypair::generate_ed25519();
    let p_peer = p_key.public().to_peer_id();
    let p = tokio::spawn(honest_holder(p_key, addr.clone(), a_peer, db_p, chain, BASE as usize, reveal.clone(), held.clone(), until));
    assert!(wait_until(20, || held.lock().unwrap().open == 2).await, "P holds {} connections to A", held.lock().unwrap().open);
    // P past the evictor's 60 s protection (PROTECT_NEW_PEER_SECS) before anything else happens.
    tokio::time::sleep(Duration::from_secs(62)).await;

    let opens: Vec<Arc<AtomicI64>> = (0..=AT_THE_RESERVE).map(|_| Arc::new(AtomicI64::new(0))).collect();
    let mut flood = Vec::new();
    for (i, open) in opens[..AT_THE_RESERVE].iter().enumerate() {
        let local = Ipv4Addr::new(127, 0, 0, 2 + (i / PER_ADDRESS) as u8);
        flood.push(tokio::spawn(hold_two(addr.clone(), a_peer, local, open.clone(), until)));
    }
    let total = || opens.iter().map(|o| o.load(Ordering::Relaxed)).sum::<i64>();
    assert!(wait_until(30, || total() == 2 * AT_THE_RESERVE as i64).await, "the flood holds {} connections", total());

    reveal.store(true, Ordering::SeqCst);
    let on_each = || {
        let held = held.lock().unwrap();
        held.conns.len() == 2 && held.conns.iter().all(|c| held.blocks.iter().any(|(on, _)| on == c))
    };
    if !wait_until(40, on_each).await {
        let held = held.lock().unwrap();
        panic!("A's block requests to P: {:?}, P's connections {:?}", held.blocks, held.conns);
    }
    let asked_before = held.lock().unwrap().blocks.len();

    let last = Ipv4Addr::new(127, 0, 0, 30);
    flood.push(tokio::spawn(hold_two(addr, a_peer, last, opens[AT_THE_RESERVE].clone(), until)));
    assert!(wait_until(12, || held.lock().unwrap().lost.is_some()).await, "A did not shed P's second connection");
    let (closed_at, lost) = held.lock().unwrap().lost.clone().unwrap();
    assert!(!lost.is_empty(), "the scenario did not hold: no block request of A's on P's shed connection");

    // A's state at its first poll tick after the close, or after it let the swarm go (each tick
    // copies it).
    let since = if hold {
        let released = || TEST_HOLD_SWARM_AFTER_SHED.lock().unwrap().get(&a_peer).copied().flatten();
        assert!(wait_until(16, || released().is_some()).await, "A held its swarm past two poll ticks");
        let released = released().unwrap();
        assert!(released >= closed_at + Duration::from_secs(5), "A let its swarm go {:?} after the close", released - closed_at);
        released
    } else {
        closed_at
    };
    let copied_after = || TEST_BAD_PROVIDERS.lock().unwrap().get(&a_peer).is_some_and(|(at, _)| *at > since);
    assert!(wait_until(8, copied_after).await, "no poll tick of A after the close");
    let stamps = TEST_BAD_PROVIDERS.lock().unwrap().get(&a_peer).unwrap().1.clone();
    let score = TEST_PEER_SCORES.lock().unwrap().get(&a_peer).and_then(|m| m.get(&p_peer).copied()).unwrap_or(0);
    let stamped = lost.iter().filter(|h| stamps.contains(&(**h, p_peer))).count();
    held.lock().unwrap().read = true;
    let asked_again = wait_until(6, || held.lock().unwrap().blocks.len() > asked_before).await;
    let stored_lost = wait_until(8, || lost.iter().all(|h| db_a.blocks.get(k_block(h)).unwrap().is_some())).await;
    let open = held.lock().unwrap().open;
    eprintln!(
        "[measure] hold {hold}: lost {} block request(s) on the shed connection; P score {score}, stamped for {stamped} of them; P open {open}, asked again {asked_again}, lost stored {stored_lost}",
        lost.len()
    );
    p.abort();
    for f in flood {
        f.abort();
    }
    Ok(ShedOutcome { score, stamped, open, asked_again, stored_lost })
}

fn assert_nobody_blamed(o: &ShedOutcome) {
    assert_eq!(o.stamped, 0, "P was stamped a bad provider for a block whose request we cut");
    assert_eq!(o.score, 0, "P's score moved for a connection we shed");
    // The paired honest path: P keeps its first connection, is asked for blocks again, and A stores
    // the lost block once P serves it.
    assert_eq!(o.open, 1, "P lost its first connection");
    assert!(o.asked_again, "A asked P for no block after the shed");
    assert!(o.stored_lost, "A did not store the lost block P served");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_shed_connection_carrying_our_block_request_blames_nobody() -> Result<()> {
    assert_nobody_blamed(&shed_with_our_block_request_on_it(false).await?);
    Ok(())
}

// A span of wall clock is the wrong bound for remembering a shed connection: what holds its
// failures back is event order. Remembered for 5 s and pruned at the poll tick, if other arms
// held the loop past 5 s between the close and the failures (a slow store read in the tick), the
// tick would forget the connection and the failures would blame P. A's loop here polls no swarm event
// from the close until a tick at least 6 s later; the failures reach the arm after that tick.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_shed_connection_is_remembered_until_its_failures_are_handled_however_late() -> Result<()> {
    assert_nobody_blamed(&shed_with_our_block_request_on_it(true).await?);
    Ok(())
}
