#![cfg(feature = "test-bypass")] // live p2p lane: toy chains and the fault seam need the bypass (cargo test --features test-bypass)
// Connection admission, on loopback. Without it, one PeerId could hold any number of connections,
// counted as one peer; a TCP connection that never sent a byte was held until the remote closed it,
// and a dial to an address that accepted TCP and never answered never failed; and a banned peer that
// reconnected kept a connection the node neither closed nor counted, and was served over it once the
// ban ran out (the ban's closes are pinned in peer_state_tests: a request flood is throttled, not
// banned, and quarantine holds an invalid flood before its ban). Each test pairs the refusal with
// the honest path it must keep: two connections from one peer (a dial race, or an upstream node dialing the same address as a bootnode and from its book), a
// handshake from another address while one address is at its cap, a connection after the idle ones
// are cut, and an honest peer served beside the throttled one.

use anyhow::Result;
use futures::StreamExt;
use std::io::{ErrorKind, Read};
use std::net::{TcpListener, TcpStream};
use std::time::{Duration, Instant};

use libp2p::{identity, request_response, swarm::SwarmEvent, Multiaddr, PeerId, Swarm};

use csd::net::proto::{SyncRequest, SyncResponse};

mod testutil_p2p;
use testutil_p2p::{spawn_node, swarm_config, sync_rr, transport, transport_from, wait_until};

/// Seconds a connection's handshake may take at the node (`admission::HANDSHAKE_TIMEOUT`).
const HANDSHAKE_SECS: u64 = 20;
/// Inbound handshakes one address may hold at the node (`admission::MAX_PENDING_INBOUND_PER_IP`).
const PENDING_PER_ADDRESS: usize = 16;

type BarePeer = Swarm<request_response::Behaviour<csd::net::node::SyncCodec>>;

fn bare_peer() -> BarePeer {
    bare_peer_with(&identity::Keypair::generate_ed25519())
}

fn bare_peer_with(key: &identity::Keypair) -> BarePeer {
    Swarm::new(transport(key), sync_rr(), key.public().to_peer_id(), swarm_config())
}

/// Drives `peer` for `secs`, answering the node's requests with an Err and sending the node a GetTip
/// every 3 s; returns (open connections at the end, requests received from the node).
async fn drive(peer: &mut BarePeer, node: PeerId, secs: u64) -> (i64, u32) {
    let (mut open, mut received) = (0i64, 0u32);
    let until = tokio::time::Instant::now() + Duration::from_secs(secs);
    let mut tick = tokio::time::interval(Duration::from_secs(3));
    loop {
        tokio::select! {
            _ = tokio::time::sleep_until(until) => break,
            _ = tick.tick() => {
                if open > 0 {
                    peer.behaviour_mut().send_request(&node, SyncRequest::GetTip);
                }
            }
            ev = peer.select_next_some() => match ev {
                SwarmEvent::ConnectionEstablished { .. } => open += 1,
                SwarmEvent::ConnectionClosed { .. } => open -= 1,
                SwarmEvent::Behaviour(request_response::Event::Message {
                    message: request_response::Message::Request { channel, .. }, ..
                }) => {
                    received += 1;
                    let _ = peer.behaviour_mut().send_response(channel, SyncResponse::Err { msg: "not served".into() });
                }
                _ => {}
            }
        }
    }
    (open, received)
}

/// K opens three connections to a fresh node, which holds two and refuses the third; then K goes
/// away. Returns the node and K's key.
async fn refused_third_then_gone() -> Result<(testutil_p2p::Node, identity::Keypair)> {
    let a = spawn_node(vec![]).await?;
    let key = identity::Keypair::generate_ed25519();
    let mut k = bare_peer_with(&key);
    for _ in 0..3 {
        k.dial(a.dial_addr())?;
    }
    let (open, _) = drive(&mut k, a.handle.peer_id, 4).await;
    assert_eq!(open, 2, "K holds {open} connections");
    assert_eq!(a.handle.connected_peers(), 1);
    drop(k);
    Ok((a, key))
}

/// Drives `peer` for `secs` and returns its open connections to anyone at the end.
async fn open_connections_after<B: libp2p::swarm::NetworkBehaviour>(peer: &mut Swarm<B>, secs: u64) -> i64 {
    let mut open = 0i64;
    let until = tokio::time::Instant::now() + Duration::from_secs(secs);
    while let Ok(ev) = tokio::time::timeout_at(until, peer.select_next_some()).await {
        match ev {
            SwarmEvent::ConnectionEstablished { .. } => open += 1,
            SwarmEvent::ConnectionClosed { .. } => open -= 1,
            _ => {}
        }
    }
    open
}

/// When the remote closes `s` (EOF or reset), in seconds from `since`; None if it is still open at
/// `deadline`. Anything the remote sends first is read and ignored.
fn closed_by_remote(mut s: TcpStream, since: Instant, deadline: Instant) -> Option<f64> {
    let mut buf = [0u8; 256];
    loop {
        let left = deadline.saturating_duration_since(Instant::now());
        if left.is_zero() {
            return None;
        }
        s.set_read_timeout(Some(left)).unwrap();
        match s.read(&mut buf) {
            Ok(0) => return Some(since.elapsed().as_secs_f64()),
            Ok(_) => continue,
            Err(e) if matches!(e.kind(), ErrorKind::WouldBlock | ErrorKind::TimedOut) => return None,
            Err(_) => return Some(since.elapsed().as_secs_f64()),
        }
    }
}

// With the admission behaviours after gossipsub and request-response in the composed Behaviour,
// whose derive calls each field's handle_established_* in order and stops at the first refusal
// (libp2p-swarm-derive 0.36.0 lib.rs:290-310), request-response had recorded the
// refused third connection already (libp2p-request-response 0.30.0 lib.rs:757) and handles no
// ListenFailure (:836-847), so it kept a connection that never existed: when K's two real connections
// closed, its debug assertion (lib.rs:678) ended the node's p2p task, and in a release build half of
// the node's requests to a reconnected K went to that connection (lib.rs:575) and were never sent.
// Both cases were red on that order.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_refused_third_connection_leaves_no_record_in_the_behaviours() -> Result<()> {
    let (a, _) = refused_third_then_gone().await?;
    assert!(
        wait_until(10, || a.handle.connected_peers() == 0).await,
        "the node still counts K after its connections closed (its p2p task ended?)"
    );
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_reconnecting_identity_gets_every_request_after_a_refused_connection() -> Result<()> {
    let (a, key) = refused_third_then_gone().await?;
    let _ = wait_until(10, || a.handle.connected_peers() == 0).await;
    let mut k = bare_peer_with(&key);
    k.dial(a.dial_addr())?;
    let (open, received) = drive(&mut k, a.handle.peer_id, 25).await;
    assert_eq!(open, 1, "K's reconnect holds {open} connections");
    // A GetTip at first sight, a GetPeers, then a GetTip every 10 s, one at a time: a request routed
    // to a connection that does not exist holds that slot for 60 s.
    assert!(received >= 3, "the node sent K {received} requests in 25 s");
    Ok(())
}

/// Established inbound connections one address may hold at the node
/// (`admission::MAX_ESTABLISHED_INBOUND_PER_IP`); 127.0.0.1 and ::1 are exempt.
const ESTABLISHED_PER_ADDRESS: usize = 8;

// Eclipse class: without a per-address cap, one address held as many inbound connections as
// identities it could make, up to the node's whole connection budget. Now at most
// ESTABLISHED_PER_ADDRESS from one address, 127.0.0.1 exempt (nodes on one host connect to each
// other there).
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn one_address_holds_at_most_eight_inbound_connections_and_loopback_is_exempt() -> Result<()> {
    let a = spawn_node(vec![]).await?;
    let second = std::net::Ipv4Addr::new(127, 0, 0, 2);
    let mut peers = Vec::new();
    for _ in 0..ESTABLISHED_PER_ADDRESS + 1 {
        let key = identity::Keypair::generate_ed25519();
        let mut p = Swarm::new(transport_from(&key, second), sync_rr(), key.public().to_peer_id(), swarm_config());
        p.dial(a.dial_addr())?;
        peers.push(p);
    }
    let mut held = 0;
    for p in peers.iter_mut() {
        held += open_connections_after(p, 1).await;
    }
    assert_eq!(held, ESTABLISHED_PER_ADDRESS as i64, "identities from one address hold {held} connections");

    // The paired honest path: twelve identities from 127.0.0.1, the address nodes on one host use, are all held.
    let mut local = Vec::new();
    for _ in 0..12 {
        let mut p = bare_peer();
        p.dial(a.dial_addr())?;
        local.push(p);
    }
    let mut held = 0;
    for p in local.iter_mut() {
        held += open_connections_after(p, 1).await;
    }
    assert_eq!(held, 12, "identities from 127.0.0.1 hold {held} connections");
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn one_identity_holds_at_most_two_connections() -> Result<()> {
    let a = spawn_node(vec![]).await?;
    let mut k = bare_peer();
    for _ in 0..3 {
        k.dial(a.dial_addr())?;
    }
    let open = open_connections_after(&mut k, 3).await;
    assert_eq!(open, 2, "one identity holds {open} connections to the node");
    assert_eq!(a.handle.connected_peers(), 1, "counted as one peer");
    Ok(())
}

/// An idle TCP connection to `target` from 127.0.0.2, a loopback address of its own: it never sends
/// a byte.
async fn idle_from_second_address(target: std::net::SocketAddr) -> std::io::Result<TcpStream> {
    let socket = tokio::net::TcpSocket::new_v4()?;
    socket.bind("127.0.0.2:0".parse().unwrap())?;
    let stream = socket.connect(target).await?.into_std()?;
    stream.set_nonblocking(false)?;
    Ok(stream)
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn idle_tcp_connections_are_capped_per_address_and_cut_at_the_handshake_deadline() -> Result<()> {
    let a = spawn_node(vec![]).await?;
    let port = a.addr.iter().find_map(|p| match p {
        libp2p::multiaddr::Protocol::Tcp(port) => Some(port),
        _ => None,
    });
    let target: std::net::SocketAddr = format!("127.0.0.1:{}", port.expect("a tcp listen port")).parse()?;
    let start = Instant::now();
    let mut idle = Vec::new();
    for _ in 0..PENDING_PER_ADDRESS {
        idle.push(idle_from_second_address(target).await?);
    }
    tokio::time::sleep(Duration::from_millis(500)).await;

    // One past the address's cap is closed at once.
    let over = idle_from_second_address(target).await?;
    let t = Instant::now();
    let over_closed = tokio::task::spawn_blocking(move || closed_by_remote(over, t, t + Duration::from_secs(3))).await?;
    assert!(over_closed.is_some(), "a 17th idle connection from one address was held");

    // The paired honest path: a peer from another address (127.0.0.1) completes its handshake meanwhile.
    let mut honest = bare_peer();
    honest.dial(a.dial_addr())?;
    assert_eq!(open_connections_after(&mut honest, 3).await, 1, "a handshake from another address was refused");

    // The idle connections are cut at the deadline, none much later.
    let deadline = start + Duration::from_secs(HANDSHAKE_SECS + 10);
    let cut = tokio::task::spawn_blocking(move || {
        idle.into_iter().map(|s| closed_by_remote(s, start, deadline)).collect::<Vec<_>>()
    })
    .await?;
    let held = cut.iter().filter(|c| c.is_none()).count();
    assert_eq!(held, 0, "{held} of {PENDING_PER_ADDRESS} idle connections held past {} s", HANDSHAKE_SECS + 10);
    let first = cut.iter().flatten().copied().fold(f64::INFINITY, f64::min);
    assert!(first >= (HANDSHAKE_SECS - 1) as f64, "an idle connection was cut after {first:.1} s, before the deadline");

    // And the address is admitted to a handshake again once they are gone.
    let again = idle_from_second_address(target).await?;
    let t = Instant::now();
    let refused = tokio::task::spawn_blocking(move || closed_by_remote(again, t, t + Duration::from_secs(2))).await?;
    assert!(refused.is_none(), "the address stayed refused after its handshakes ended");
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_dial_to_an_address_that_never_answers_fails_at_the_handshake_deadline() -> Result<()> {
    // The tarpit accepts TCP and never answers; the node dials it as its only bootnode.
    let tarpit = TcpListener::bind("127.0.0.1:0")?;
    let bootnode: Multiaddr = format!("/ip4/127.0.0.1/tcp/{}/p2p/{}", tarpit.local_addr()?.port(), PeerId::random()).parse()?;
    let start = Instant::now();
    let _a = spawn_node(vec![bootnode]).await?;
    let first_close = tokio::task::spawn_blocking(move || {
        let (s, _) = tarpit.accept().ok()?;
        closed_by_remote(s, start, start + Duration::from_secs(HANDSHAKE_SECS + 10))
    })
    .await?;
    let closed_at = first_close.expect("the node's dial to the tarpit never failed");
    assert!(
        closed_at >= (HANDSHAKE_SECS - 1) as f64 && closed_at <= (HANDSHAKE_SECS + 5) as f64,
        "the dial ended after {closed_at:.1} s"
    );
    Ok(())
}

/// A bare peer that requests and gossips: the sync protocol and gossipsub on the tx topic.
#[derive(libp2p::swarm::NetworkBehaviour)]
struct RequestAndGossip {
    rr: request_response::Behaviour<csd::net::node::SyncCodec>,
    gs: libp2p::gossipsub::Behaviour,
}

// Requests past the window's figure (1,200 in every mode) are answered "rate limited" for the rest
// of the window, and the requester is kept: not banned, not closed, its gossip still taken, served
// again in its next window. An honest upstream node's thread_local pacer does not bound what it
// sends one peer, so an honest node can go past the figure; banning it would cut off an honest
// peer.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_request_flood_is_throttled_for_its_window_and_the_peer_kept() -> Result<()> {
    use csd::net::proto::{GossipTx, TOPIC_TX};
    use libp2p::gossipsub::{self, IdentTopic, MessageAuthenticity};

    let a = spawn_node(vec![]).await?;
    let a_peer = a.handle.peer_id;

    // H, an honest peer, stays connected and is served throughout.
    let mut h = bare_peer();
    h.dial(a.dial_addr())?;
    let h_task = tokio::spawn(async move {
        let (mut answered, mut open) = (0u32, 0i64);
        let mut tick = tokio::time::interval(Duration::from_secs(2));
        let until = tokio::time::Instant::now() + Duration::from_secs(25);
        loop {
            tokio::select! {
                _ = tokio::time::sleep_until(until) => break,
                _ = tick.tick() => {
                    if open > 0 {
                        h.behaviour_mut().send_request(&a_peer, SyncRequest::GetTip);
                    }
                }
                ev = h.select_next_some() => match ev {
                    SwarmEvent::ConnectionEstablished { .. } => open += 1,
                    SwarmEvent::ConnectionClosed { .. } => open -= 1,
                    SwarmEvent::Behaviour(request_response::Event::Message {
                        message: request_response::Message::Response { response: SyncResponse::Tip { .. }, .. }, ..
                    }) => answered += 1,
                    SwarmEvent::Behaviour(request_response::Event::Message {
                        message: request_response::Message::Request { channel, .. }, ..
                    }) => {
                        let _ = h.behaviour_mut().send_response(channel, SyncResponse::Err { msg: "not served".into() });
                    }
                    _ => {}
                }
            }
        }
        (open, answered)
    });

    // X requests past its window's figure; it answers the node's own requests at once.
    let key = identity::Keypair::generate_ed25519();
    let gs_cfg = gossipsub::ConfigBuilder::default().max_transmit_size(256 * 1024).build()?;
    let gs = gossipsub::Behaviour::new(MessageAuthenticity::Signed(key.clone()), gs_cfg).map_err(anyhow::Error::msg)?;
    let mut x = Swarm::new(transport(&key), RequestAndGossip { rr: sync_rr(), gs }, key.public().to_peer_id(), swarm_config());
    let x_peer = key.public().to_peer_id();
    let topic = IdentTopic::new(TOPIC_TX);
    x.behaviour_mut().gs.subscribe(&topic)?;
    x.dial(a.dial_addr())?;
    let window_start = Instant::now();
    let (mut in_flight, mut open, mut answered, mut throttled_at, mut a_subscribed) = (0u32, 0i64, 0u32, None, false);
    let (mut closed, mut published, mut served_after) = (false, false, false);
    let deadline = tokio::time::Instant::now() + Duration::from_secs(24);
    while let Ok(ev) = tokio::time::timeout_at(deadline, x.select_next_some()).await {
        match ev {
            SwarmEvent::ConnectionEstablished { .. } => open += 1,
            SwarmEvent::ConnectionClosed { .. } => {
                open -= 1;
                closed |= throttled_at.is_some();
            }
            SwarmEvent::Behaviour(RequestAndGossipEvent::Gs(gossipsub::Event::Subscribed { peer_id, .. })) if peer_id == a_peer => {
                a_subscribed = true;
            }
            SwarmEvent::Behaviour(RequestAndGossipEvent::Rr(request_response::Event::Message {
                message: request_response::Message::Response { response, .. },
                ..
            })) => {
                in_flight -= 1;
                match response {
                    SyncResponse::Tip { .. } if throttled_at.is_none() => answered += 1,
                    SyncResponse::Tip { .. } => served_after = true,
                    SyncResponse::Err { msg } if msg == "rate limited" && throttled_at.is_none() => throttled_at = Some(Instant::now()),
                    _ => {}
                }
            }
            SwarmEvent::Behaviour(RequestAndGossipEvent::Rr(request_response::Event::Message {
                message: request_response::Message::Request { channel, .. },
                ..
            })) => {
                let _ = x.behaviour_mut().rr.send_response(channel, SyncResponse::Err { msg: "not served".into() });
            }
            SwarmEvent::Behaviour(RequestAndGossipEvent::Rr(request_response::Event::OutboundFailure { .. })) => in_flight -= 1,
            _ => {}
        }
        // The flood, two requests in flight, until the first "rate limited".
        while open > 0 && throttled_at.is_none() && in_flight < 2 {
            x.behaviour_mut().rr.send_request(&a_peer, SyncRequest::GetTip);
            in_flight += 1;
        }
        // Throttled: its gossip still reaches the node's checks (a tx spending a coin the node lacks).
        if let (Some(_), true, false) = (throttled_at, a_subscribed, published) {
            let tx = csd::types::Transaction {
                version: 1,
                inputs: vec![csd::types::TxIn { prevout: csd::types::OutPoint { txid: [0xAA; 32], vout: 0 }, script_sig: vec![0; 98] }],
                outputs: vec![csd::types::TxOut { value: 1, script_pubkey: [0x11; 20] }],
                locktime: 0,
                app: csd::types::AppPayload::None,
            };
            let bytes = csd::codec::consensus_bincode().serialize(&GossipTx { tx })?;
            x.behaviour_mut().gs.publish(topic.clone(), bytes)?;
            published = true;
        }
        // In the next window (the bucket opened at X's first request), one GetTip more.
        if throttled_at.is_some() && !served_after && in_flight == 0 && window_start.elapsed() > Duration::from_secs(12) {
            x.behaviour_mut().rr.send_request(&a_peer, SyncRequest::GetTip);
            in_flight += 1;
        }
        if served_after && window_start.elapsed() > Duration::from_secs(16) {
            break;
        }
    }
    let throttled_at = throttled_at.expect("the flood was never answered \"rate limited\"");
    assert!(answered >= 1_190, "{answered} requests served before the window's figure");
    assert!(!closed && open == 1, "the throttled peer's connection was closed (open {open})");
    assert!(throttled_at.elapsed() > Duration::from_secs(6), "the throttled peer was watched past a poll tick");
    assert!(served_after, "the throttled peer was not served in its next window");
    let checks = csd::net::node::TEST_GOSSIP_TX_CHECKS.lock().unwrap().get(&x_peer).copied().unwrap_or(0);
    assert!(checks >= 1, "the throttled peer's gossip was not taken");
    assert_eq!(a.handle.connected_peers(), 2, "the node counts {} peers", a.handle.connected_peers());

    let (h_open, h_answered) = h_task.await?;
    assert_eq!(h_open, 1, "the honest peer lost its connection");
    assert!(h_answered >= 10, "the honest peer was answered {h_answered} times");
    Ok(())
}

/// A bare peer that claims a heavier tip to the node's GetTip, answers the node's headers request with
/// `n` headers that fail its PoW gate (bits 0, past the PoW limit) in one Headers answer, and holds its
/// connection `secs` past that answer, asking for the node's tip every 2 s so that it is not idle;
/// returns (whether it sent the answer, its open connections then).
async fn answer_with_invalid_headers(a: Multiaddr, a_peer: PeerId, n: u32, secs: u64) -> (bool, i64) {
    use csd::types::BlockHeader;
    let mut p = bare_peer();
    p.dial(a).unwrap();
    let (mut open, mut answered) = (0i64, false);
    let mut until = tokio::time::Instant::now() + Duration::from_secs(30);
    let mut tick = tokio::time::interval(Duration::from_secs(2));
    loop {
        let ev = tokio::select! {
            _ = tokio::time::sleep_until(until) => break,
            _ = tick.tick() => {
                if answered && open > 0 {
                    p.behaviour_mut().send_request(&a_peer, SyncRequest::GetTip);
                }
                continue;
            }
            ev = p.select_next_some() => ev,
        };
        match ev {
            SwarmEvent::ConnectionEstablished { .. } => open += 1,
            SwarmEvent::ConnectionClosed { .. } => open -= 1,
            SwarmEvent::Behaviour(request_response::Event::Message {
                message: request_response::Message::Request { request, channel, .. }, ..
            }) => {
                let response = match request {
                    SyncRequest::GetTip => SyncResponse::Tip { hash: [0xAB; 32], height: 1_000, chainwork: u128::MAX / 2 },
                    SyncRequest::GetHeadersByLocator { .. } if !answered => {
                        answered = true;
                        until = tokio::time::Instant::now() + Duration::from_secs(secs);
                        let invalid = |nonce| BlockHeader { version: 1, prev: [0xCD; 32], merkle: [0; 32], time: 1_700_000_000, bits: 0, nonce };
                        SyncResponse::Headers { headers: (0..n).map(invalid).collect() }
                    }
                    _ => SyncResponse::Err { msg: "not served".into() },
                };
                let _ = p.behaviour_mut().send_response(channel, response);
            }
            _ => {}
        }
    }
    (answered, open)
}

// Quarantine is checked once per message (the
// request-response arm drops a banned or quarantined peer's messages before it handles them), and the
// Headers arm runs through its whole answer, striking the peer for each invalid header without
// checking again. So one answer of 32 invalid headers to our own headers request bans a peer from
// score 0, its 5th strike quarantining it on the way, and the next poll tick closes its connection:
// the early quarantine holds between messages, not within one. Paired: 31 in one answer quarantine the
// peer without banning it, and its connection stays.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn one_answer_of_32_invalid_headers_bans_a_peer_from_score_zero_and_31_do_not() -> Result<()> {
    let a = spawn_node(vec![]).await?;
    // Two poll ticks (5 s) after the answer.
    let (banned, kept) = tokio::join!(
        answer_with_invalid_headers(a.dial_addr(), a.handle.peer_id, 32, 11),
        answer_with_invalid_headers(a.dial_addr(), a.handle.peer_id, 31, 11)
    );
    eprintln!("[measure] 32 invalid headers: {banned:?}; 31: {kept:?}");
    assert!(banned.0 && kept.0, "the node did not ask both peers for headers");
    assert_eq!(banned.1, 0, "one answer of 32 invalid headers left the peer connected");
    assert_eq!(kept.1, 1, "one answer of 31 invalid headers closed the peer's connection");
    Ok(())
}
