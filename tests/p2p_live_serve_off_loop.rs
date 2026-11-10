#![cfg(feature = "test-bypass")] // live p2p lane: toy chains and the fault seam need the bypass (cargo test --features test-bypass)
// When the p2p loop awaited every inbound request's answer in turn (the serve ran on
// the blocking pool, but the loop's select! arm awaited it), so peers asking for headers held the
// loop that also handles gossip, sync answers, block apply and the poll tick, and the one-permit
// serving semaphore never refused. Requests are now served off the loop and answered through a
// result channel back to it. A is a node on a 1,100-block chain; F1..Fk are bare peers that keep
// three GetHeaders(from 0, 1,024) in flight each (the fourth stream is the node's own request to
// them, which they answer at once), within the request budget; P asks A for its peers, which A
// answers on its loop, every 25 ms. The loop's latency is the assertion; the paired honest path:
// the pipelined requests of the flood are answered with their headers, none refused (an Err answer)
// as "server busy". A request that fails on the flooder's side is reported, not asserted.

use anyhow::Result;
use futures::StreamExt;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tempfile::TempDir;

use libp2p::{identity, request_response, swarm::SwarmEvent, Multiaddr, PeerId, Swarm};

use csd::net::node::{TestPeerMode, TEST_SERVES_PENDING};
use csd::net::proto::{SyncRequest, SyncResponse};

mod testutil_chain;
use testutil_chain::{build_base_chain_with_miner, open_db};
mod testutil_p2p;
use testutil_p2p::{spawn_node_on, spawn_node_with, swarm_config, sync_rr, transport, wait_until};

const START: u64 = 1_700_900_000;
const LEN: u64 = 1_100;
const FLOODERS: usize = 6;
/// Requests a flooder keeps in flight: three of the connection's four streams, the fourth left to
/// the node's own background request to it (the requester's stream cap counts both directions).
const STREAMS: usize = 3;
/// Requests a flooder sends per second at most: 110 in 10 s, under the request throttle (1,200 in a
/// window).
const FLOOD_PER_SEC: u64 = 11;

#[derive(Default)]
struct Tally {
    headers: AtomicU64,
    refused: AtomicU64,
    failed: AtomicU64,
}

/// Keeps STREAMS GetHeaders in flight to A, at most FLOOD_PER_SEC a second, until `until`, and
/// answers A's own requests at once.
async fn flooder(a: Multiaddr, a_peer: PeerId, until: Instant, tally: Arc<Tally>) {
    let key = identity::Keypair::generate_ed25519();
    let mut swarm = Swarm::new(transport(&key), sync_rr(), key.public().to_peer_id(), swarm_config());
    swarm.dial(a).unwrap();
    let (mut connected, mut in_flight, mut sent) = (false, 0usize, 0u64);
    let started = Instant::now();
    let mut tick = tokio::time::interval(Duration::from_millis(10));
    while Instant::now() < until {
        tokio::select! {
            _ = tick.tick() => {
                while connected
                    && in_flight < STREAMS
                    && sent < 1 + started.elapsed().as_millis() as u64 * FLOOD_PER_SEC / 1000
                {
                    swarm.behaviour_mut().send_request(&a_peer, SyncRequest::GetHeaders { from_height: 0, max: 1_024 });
                    in_flight += 1;
                    sent += 1;
                }
            }
            ev = swarm.select_next_some() => match ev {
                SwarmEvent::ConnectionEstablished { .. } => connected = true,
                SwarmEvent::Behaviour(request_response::Event::Message {
                    message: request_response::Message::Response { response, .. }, ..
                }) => {
                    in_flight -= 1;
                    match response {
                        SyncResponse::Headers { .. } => tally.headers.fetch_add(1, Ordering::Relaxed),
                        SyncResponse::Err { .. } => tally.refused.fetch_add(1, Ordering::Relaxed),
                        _ => 0,
                    };
                }
                SwarmEvent::Behaviour(request_response::Event::Message {
                    message: request_response::Message::Request { channel, .. }, ..
                }) => {
                    let _ = swarm.behaviour_mut().send_response(channel, SyncResponse::Err { msg: "not served".into() });
                }
                SwarmEvent::Behaviour(request_response::Event::OutboundFailure { .. }) => {
                    in_flight -= 1;
                    tally.failed.fetch_add(1, Ordering::Relaxed);
                }
                _ => {}
            }
        }
    }
}

/// P: a GetPeers to A every 25 ms on its own connection, one at a time, from `from` until `until`;
/// the latency of each answer in ms (None for a failed one).
async fn probe(a: Multiaddr, a_peer: PeerId, from: Instant, until: Instant) -> Vec<Option<f64>> {
    let key = identity::Keypair::generate_ed25519();
    let mut swarm = Swarm::new(transport(&key), sync_rr(), key.public().to_peer_id(), swarm_config());
    swarm.dial(a).unwrap();
    let (mut connected, mut pending, mut out) = (false, None::<(request_response::OutboundRequestId, Instant)>, Vec::new());
    let mut tick = tokio::time::interval(Duration::from_millis(25));
    while Instant::now() < until {
        tokio::select! {
            _ = tick.tick() => {
                if connected && pending.is_none() && Instant::now() >= from {
                    let id = swarm.behaviour_mut().send_request(&a_peer, SyncRequest::GetPeers { max: 64 });
                    pending = Some((id, Instant::now()));
                }
            }
            ev = swarm.select_next_some() => match ev {
                SwarmEvent::ConnectionEstablished { .. } => connected = true,
                SwarmEvent::Behaviour(request_response::Event::Message {
                    message: request_response::Message::Response { request_id, response }, ..
                }) => {
                    if let Some((id, t0)) = pending {
                        if id == request_id {
                            let ok = matches!(response, SyncResponse::Peers { .. });
                            out.push(ok.then(|| t0.elapsed().as_secs_f64() * 1000.0));
                            pending = None;
                        }
                    }
                }
                SwarmEvent::Behaviour(request_response::Event::OutboundFailure { request_id, .. }) => {
                    if pending.is_some_and(|(id, _)| id == request_id) {
                        out.push(None);
                        pending = None;
                    }
                }
                SwarmEvent::Behaviour(request_response::Event::Message {
                    message: request_response::Message::Request { channel, .. }, ..
                }) => {
                    let _ = swarm.behaviour_mut().send_response(channel, SyncResponse::Err { msg: "not served".into() });
                }
                _ => {}
            }
        }
    }
    // A request still out at the end counts as unanswered once it is older than the slowest answer
    // the assertions allow.
    if let Some((_, t0)) = pending.filter(|(_, t0)| t0.elapsed() > Duration::from_millis(250)) {
        eprintln!("[measure] a GetPeers still unanswered after {:.0} ms", t0.elapsed().as_secs_f64() * 1000.0);
        out.push(None);
    }
    out
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn header_requests_do_not_hold_the_p2p_loop_and_none_is_refused() -> Result<()> {
    let tmp = TempDir::new()?;
    let db = Arc::new(open_db(&tmp)?);
    let chain = build_base_chain_with_miner(&db, LEN, START, [0x11; 20])?;
    let a = spawn_node_on(db, tmp, chain[0], vec![]).await?;
    let (addr, a_peer) = (a.dial_addr(), a.handle.peer_id);

    let start = Instant::now();
    let (flood_until, probe_from, probe_until) =
        (start + Duration::from_secs(9), start + Duration::from_secs(3), start + Duration::from_secs(8));
    let tally = Arc::new(Tally::default());
    let flood: Vec<_> = (0..FLOODERS).map(|_| tokio::spawn(flooder(addr.clone(), a_peer, flood_until, tally.clone()))).collect();
    let latencies = tokio::spawn(probe(addr.clone(), a_peer, probe_from, probe_until)).await?;
    for f in flood {
        f.await?;
    }

    let answered: Vec<f64> = latencies.iter().flatten().copied().collect();
    let mut sorted = answered.clone();
    sorted.sort_by(|x, y| x.total_cmp(y));
    let pct = |q: f64| sorted.get(((sorted.len() as f64 - 1.0) * q).round() as usize).copied().unwrap_or(f64::NAN);
    let (headers, refused, failed) =
        (tally.headers.load(Ordering::Relaxed), tally.refused.load(Ordering::Relaxed), tally.failed.load(Ordering::Relaxed));
    eprintln!(
        "[measure] load {}; flood: {headers} headers answers, {refused} refused, {failed} failed; GetPeers on A's loop: {} of {} answered, p50 {:.2} ms, p90 {:.2} ms, max {:.2} ms",
        std::fs::read_to_string("/proc/loadavg").unwrap_or_default().split(' ').next().unwrap_or("?"),
        answered.len(),
        latencies.len(),
        pct(0.5),
        pct(0.9),
        pct(1.0)
    );
    // The loop's latency first: what the fix is for.
    assert!(answered.len() >= 100 && answered.len() == latencies.len(), "GetPeers answers: {} of {}", answered.len(), latencies.len());
    assert!(pct(0.9) < 25.0, "A's loop waited on the serves: GetPeers p90 {:.2} ms", pct(0.9));
    // The paired honest path: pipelined requests are served, at least as many as one pipelined round
    // holds (every flooder's every stream), and none refused as busy.
    let round = (FLOODERS * STREAMS) as u64;
    assert!(headers >= round, "the flood was served {headers} headers answers, fewer than one round ({round})");
    assert_eq!(refused, 0, "pipelined header requests were refused");
    Ok(())
}

/// How long A holds a headers serve in the test below: past two request timeouts (15 s).
const HELD: Duration = Duration::from_secs(40);

/// Dials A and keeps STREAMS GetTip in flight, sending again as each fails, from `from` until
/// `until`; returns (the GetTip answers received at or after `answered_from`, requests sent).
async fn keep_asking(a: Multiaddr, a_peer: PeerId, from: Instant, answered_from: Instant, until: Instant) -> (u64, u64) {
    let key = identity::Keypair::generate_ed25519();
    let mut swarm = Swarm::new(transport(&key), sync_rr(), key.public().to_peer_id(), swarm_config());
    swarm.dial(a).unwrap();
    let (mut connected, mut in_flight, mut sent, mut answered) = (false, 0usize, 0u64, 0u64);
    let mut tick = tokio::time::interval(Duration::from_millis(50));
    while Instant::now() < until {
        tokio::select! {
            _ = tick.tick() => {
                while connected && in_flight < STREAMS && Instant::now() >= from {
                    swarm.behaviour_mut().send_request(&a_peer, SyncRequest::GetTip);
                    in_flight += 1;
                    sent += 1;
                }
            }
            ev = swarm.select_next_some() => match ev {
                SwarmEvent::ConnectionEstablished { .. } => connected = true,
                SwarmEvent::Behaviour(request_response::Event::Message {
                    message: request_response::Message::Response { response, .. }, ..
                }) => {
                    in_flight -= 1;
                    if matches!(response, SyncResponse::Tip { .. }) && Instant::now() >= answered_from {
                        answered += 1;
                    }
                }
                SwarmEvent::Behaviour(request_response::Event::Message {
                    message: request_response::Message::Request { channel, .. }, ..
                }) => {
                    let _ = swarm.behaviour_mut().send_response(channel, SyncResponse::Err { msg: "not served".into() });
                }
                SwarmEvent::Behaviour(request_response::Event::OutboundFailure { .. }) => in_flight -= 1,
                _ => {}
            }
        }
    }
    (answered, sent)
}

// Without the fix, a serve waited for the permit before it checked
// its channel, and a request's timeout neither ended its serve task nor took it out of the
// semaphore's queue, so behind one stalled serve every expired request stayed queued, and each
// stream its timeout freed let another request in. Here A holds one headers serve for HELD while a
// requester keeps three GetTip in flight, each timing out at 15 s and sent again. At HELD - 3 s the
// serves pending at A are the held one and the live requests, at most one more per stream whose
// request ended within the last check; before the fix every request sent so far was still queued.
// The paired honest path: once the held serve returns, the live requests are served.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn expired_requests_leave_the_serve_queue_behind_a_stalled_serve() -> Result<()> {
    let a = spawn_node_with(TestPeerMode::SlowHeaderServes(HELD)).await?;
    let (addr, a_peer) = (a.dial_addr(), a.handle.peer_id);

    // H asks for headers first, and A holds that serve, with its one permit, for HELD.
    let key = identity::Keypair::generate_ed25519();
    let mut h = Swarm::new(transport(&key), sync_rr(), key.public().to_peer_id(), swarm_config());
    h.dial(addr.clone())?;
    loop {
        if let SwarmEvent::ConnectionEstablished { .. } = h.select_next_some().await {
            break;
        }
    }
    h.behaviour_mut().send_request(&a_peer, SyncRequest::GetHeaders { from_height: 0, max: 1 });
    let held_from = Instant::now();
    let h_task = tokio::spawn(async move {
        let until = tokio::time::Instant::now() + HELD + Duration::from_secs(5);
        while tokio::time::timeout_at(until, h.select_next_some()).await.is_ok() {}
    });

    let asker = tokio::spawn(keep_asking(
        addr,
        a_peer,
        held_from + Duration::from_secs(1),
        held_from + HELD,
        held_from + HELD + Duration::from_secs(3),
    ));
    tokio::time::sleep_until((held_from + HELD - Duration::from_secs(3)).into()).await;
    let pending = TEST_SERVES_PENDING.lock().unwrap().get(&a_peer).copied().unwrap_or(0);
    let (answered, sent) = asker.await?;
    h_task.abort();
    eprintln!("[measure] serves pending at A {pending} at {} s; GetTip sent {sent}, answered after the held serve {answered}", (HELD - Duration::from_secs(3)).as_secs());
    assert!(pending <= 1 + 2 * STREAMS, "{pending} serves pending at A behind the held one, {sent} GetTip sent");
    assert!(answered >= 1, "no live request was served after the held serve returned");
    Ok(())
}

/// How long A holds the headers serve in the test below: inside one request timeout, so a request
/// queued behind it is still live when it returns.
const SHORT_HOLD: Duration = Duration::from_secs(10);

/// Dials A, sends `n` GetTip once connected and drives the connection until `until`, or until the
/// task is dropped, which closes it; returns the Tip answers received.
async fn ask_tips(a: Multiaddr, a_peer: PeerId, n: usize, until: Instant) -> u64 {
    let key = identity::Keypair::generate_ed25519();
    let mut swarm = Swarm::new(transport(&key), sync_rr(), key.public().to_peer_id(), swarm_config());
    swarm.dial(a).unwrap();
    let mut tips = 0;
    while let Ok(ev) = tokio::time::timeout_at(until.into(), swarm.select_next_some()).await {
        match ev {
            SwarmEvent::ConnectionEstablished { .. } => {
                for _ in 0..n {
                    swarm.behaviour_mut().send_request(&a_peer, SyncRequest::GetTip);
                }
            }
            SwarmEvent::Behaviour(request_response::Event::Message {
                message: request_response::Message::Response { response, .. }, ..
            }) => tips += u64::from(matches!(response, SyncResponse::Tip { .. })),
            SwarmEvent::Behaviour(request_response::Event::Message {
                message: request_response::Message::Request { channel, .. }, ..
            }) => {
                let _ = swarm.behaviour_mut().send_response(channel, SyncResponse::Err { msg: "not served".into() });
            }
            _ => {}
        }
    }
    tips
}

// The 500 ms stream check in `wait_for_turn` needs its own test: with it removed the deadline
// alone keeps the test above green. Its own case is a requester whose
// connection closes while its requests wait for their turn: they leave the queue within a check,
// where the deadline would keep them up to 15 s after the read. A holds one headers serve for
// SHORT_HOLD; K queues one GetTip behind it and R three; R's connection closes. The serves pending
// at A fall to the held one and K's before the held serve returns. The paired honest path: K's
// request, whose connection stays open, waits and is answered once the held serve returns.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn queued_requests_leave_once_their_connection_closes_not_at_their_deadline() -> Result<()> {
    let a = spawn_node_with(TestPeerMode::SlowHeaderServes(SHORT_HOLD)).await?;
    let (addr, a_peer) = (a.dial_addr(), a.handle.peer_id);
    let pending = || TEST_SERVES_PENDING.lock().unwrap().get(&a_peer).copied().unwrap_or(0);

    let key = identity::Keypair::generate_ed25519();
    let mut h = Swarm::new(transport(&key), sync_rr(), key.public().to_peer_id(), swarm_config());
    h.dial(addr.clone())?;
    loop {
        if let SwarmEvent::ConnectionEstablished { .. } = h.select_next_some().await {
            break;
        }
    }
    h.behaviour_mut().send_request(&a_peer, SyncRequest::GetHeaders { from_height: 0, max: 1 });
    let held_from = Instant::now();
    let h_task = tokio::spawn(async move {
        let until = tokio::time::Instant::now() + SHORT_HOLD + Duration::from_secs(5);
        while tokio::time::timeout_at(until, h.select_next_some()).await.is_ok() {}
    });
    assert!(wait_until(5, || pending() == 1).await, "A is not serving H's headers request");

    let k = tokio::spawn(ask_tips(addr.clone(), a_peer, 1, held_from + SHORT_HOLD + Duration::from_secs(4)));
    assert!(wait_until(5, || pending() == 2).await, "K's request is not queued at A: {} pending", pending());
    let r = tokio::spawn(ask_tips(addr, a_peer, STREAMS, held_from + 2 * SHORT_HOLD));
    assert!(wait_until(5, || pending() == 2 + STREAMS).await, "R's requests are not queued at A: {} pending", pending());
    r.abort();
    let closed_at = Instant::now();
    let left = wait_until(3, || pending() == 2).await;
    let (after, left_at, pending_then) = (closed_at.elapsed(), Instant::now(), pending());
    let k_tips = k.await?;
    h_task.abort();
    eprintln!(
        "[measure] R's requests left A's queue {after:?} after its connection closed (left {left}), {:?} before the held serve returned; K answered {k_tips}",
        (held_from + SHORT_HOLD).saturating_duration_since(left_at)
    );
    assert!(left, "R's requests stayed queued at A {after:?} after its connection closed ({pending_then} pending)");
    assert!(left_at < held_from + SHORT_HOLD, "they left only when the held serve returned");
    assert_eq!(k_tips, 1, "K's queued request was not answered after the held serve returned");
    Ok(())
}
