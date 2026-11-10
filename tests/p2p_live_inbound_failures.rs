#![cfg(feature = "test-bypass")] // live p2p lane: toy chains and the fault seam need the bypass (cargo test --features test-bypass)
// Upstream counts every InboundFailure::Io toward the noisy disconnect (20 in 60 s), but
// libp2p-request-response 0.30.0 reports an Io only for a request it registered
// (lib.rs:1001-1018), after the request was read: our own write or close of the answer failing. A request the codec cannot read is only traced and never reaches the node.
// Each requester here goes past 20 a minute: one whose answers our codec refuses to write (an
// answer at or above the 1 MiB wire cap, as a stored block between 1 and 2 MiB would be; upstream
// disconnects it as noisy at its 20th), one that gives up on each request before our answer comes (a
// late write), and one whose requests the codec cannot read (an unknown kind, or past its kind's
// size). Each must stay connected; the paired honest path: its next request on that connection is
// answered. The late answers and the unreadable requests reached no counter before the fix either:
// a requester's yamux drops a request stream after its FIN without a reset and ignores data for it
// (yamux 0.14.1 connection.rs:541-550, :680-695), so our late write succeeds, and an unreadable
// request is never reported. Here no inbound failure is counted at all
// (the noisy disconnect is removed); all three stay pinned so that a change that reports or counts
// one cannot disconnect the requester.

use anyhow::Result;
use futures::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, StreamExt};
use std::time::Duration;

use libp2p::request_response::{self, ProtocolSupport};
use libp2p::{identity, swarm::SwarmEvent, Multiaddr, PeerId, Swarm};

use csd::net::node::{SyncCodec, TestPeerMode, TEST_SERVES_ANSWERED};
use csd::net::proto::{SyncRequest, SyncResponse, SYNC_PROTO};

mod testutil_p2p;
use testutil_p2p::{spawn_node_with, swarm_config, transport};

/// Requests each requester sends: past upstream's noisy disconnect, 20 in 60 s.
const REQUESTS: usize = 25;

/// A requester's view at the end: its open connections to the node, the requests that failed on its
/// side, and whether its last request, sent after the others, was answered.
#[derive(Debug)]
struct Outcome {
    open: i64,
    failed: usize,
    last_answered: bool,
}

/// Dials `node` with `rr`, sends `requests` one every `every`, waits `settle` after the last has
/// failed or been answered, then sends `last` and waits up to 10 s for an answer `is_answer` accepts.
async fn ask<C>(
    node: Multiaddr,
    node_peer: PeerId,
    rr: request_response::Behaviour<C>,
    requests: Vec<C::Request>,
    every: Duration,
    settle: Duration,
    last: C::Request,
    is_answer: impl Fn(&C::Response) -> bool,
) -> Outcome
where
    C: request_response::Codec + Clone + Send + 'static,
    C::Request: Clone,
{
    let key = identity::Keypair::generate_ed25519();
    let mut swarm = Swarm::new(transport(&key), rr, key.public().to_peer_id(), swarm_config());
    swarm.dial(node).unwrap();
    let (mut open, mut sent, mut settled, mut failed) = (0i64, 0usize, 0usize, 0usize);
    let mut last_id = None;
    let mut last_answered = false;
    let mut settled_at = None::<tokio::time::Instant>;
    let deadline = tokio::time::Instant::now() + Duration::from_secs(60);
    let mut tick = tokio::time::interval(every);
    loop {
        tokio::select! {
            _ = tokio::time::sleep_until(deadline) => break,
            _ = tick.tick() => {
                if open > 0 && sent < requests.len() {
                    swarm.behaviour_mut().send_request(&node_peer, requests[sent].clone());
                    sent += 1;
                }
                if last_id.is_none() && settled_at.is_some_and(|t| t.elapsed() >= settle) {
                    last_id = Some(swarm.behaviour_mut().send_request(&node_peer, last.clone()));
                }
            }
            ev = swarm.select_next_some() => match ev {
                SwarmEvent::ConnectionEstablished { .. } => open += 1,
                SwarmEvent::ConnectionClosed { .. } => {
                    open -= 1;
                    if open == 0 {
                        break;
                    }
                }
                SwarmEvent::Behaviour(request_response::Event::Message {
                    message: request_response::Message::Response { request_id, response }, ..
                }) => {
                    if Some(request_id) == last_id {
                        last_answered = is_answer(&response);
                        break;
                    }
                    settled += 1;
                }
                SwarmEvent::Behaviour(request_response::Event::OutboundFailure { request_id, .. }) => {
                    if Some(request_id) == last_id {
                        break;
                    }
                    settled += 1;
                    failed += 1;
                }
                _ => {}
            }
        }
        if settled == requests.len() && settled_at.is_none() {
            settled_at = Some(tokio::time::Instant::now());
        }
    }
    Outcome { open, failed, last_answered }
}

fn sync_rr_timing_out_after(timeout: Duration) -> request_response::Behaviour<SyncCodec> {
    request_response::Behaviour::<SyncCodec>::new(
        std::iter::once((SYNC_PROTO, ProtocolSupport::Full)),
        request_response::Config::default().with_request_timeout(timeout).with_max_concurrent_streams(4),
    )
}

fn is_peers(r: &SyncResponse) -> bool {
    matches!(r, SyncResponse::Peers { .. })
}

/// A requester's codec that writes its request bytes as given and reads the answer's bytes whole.
#[derive(Clone, Default)]
struct RawCodec;

impl request_response::Codec for RawCodec {
    type Protocol = &'static str;
    type Request = Vec<u8>;
    type Response = Vec<u8>;

    async fn read_request<T: AsyncRead + Unpin + Send>(&mut self, _: &Self::Protocol, io: &mut T) -> std::io::Result<Vec<u8>> {
        let mut buf = Vec::new();
        io.take(1 << 20).read_to_end(&mut buf).await?;
        Ok(buf)
    }

    /// An empty answer is the node closing the stream unanswered: a failure, as the sync codec reads it.
    async fn read_response<T: AsyncRead + Unpin + Send>(&mut self, p: &Self::Protocol, io: &mut T) -> std::io::Result<Vec<u8>> {
        let buf = self.read_request(p, io).await?;
        if buf.is_empty() {
            return Err(std::io::ErrorKind::UnexpectedEof.into());
        }
        Ok(buf)
    }

    async fn write_request<T: AsyncWrite + Unpin + Send>(&mut self, _: &Self::Protocol, io: &mut T, req: Vec<u8>) -> std::io::Result<()> {
        io.write_all(&req).await?;
        io.close().await
    }

    async fn write_response<T: AsyncWrite + Unpin + Send>(&mut self, p: &Self::Protocol, io: &mut T, res: Vec<u8>) -> std::io::Result<()> {
        self.write_request(p, io, res).await
    }
}

// Red before the fix: the node disconnected the requester as noisy at its 20th refused answer.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn an_answer_our_codec_refuses_to_write_never_disconnects_the_requester() -> Result<()> {
    let a = spawn_node_with(TestPeerMode::OversizedAnswers).await?;
    let out = ask(
        a.dial_addr(),
        a.handle.peer_id,
        sync_rr_timing_out_after(Duration::from_secs(15)),
        vec![SyncRequest::GetTip; REQUESTS],
        Duration::from_millis(100),
        Duration::from_secs(1),
        // Answered on the p2p loop, not by the serve that answers oversized.
        SyncRequest::GetPeers { max: 8 },
        is_peers,
    )
    .await;
    eprintln!("[measure] refused answers: {out:?}");
    assert_eq!(out.open, 1, "the requester was disconnected for our failed writes");
    assert_eq!(out.failed, REQUESTS, "each answer our codec refused fails on the requester's side");
    assert!(out.last_answered, "the requester's next request was not answered");
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_late_answer_or_an_unreadable_request_never_disconnects_the_requester() -> Result<()> {
    // Each headers serve takes 250 ms; the late requester gives up after 100 ms and asks every
    // 400 ms, so the serves do not queue and each answer is written after its requester has gone.
    let a = spawn_node_with(TestPeerMode::SlowHeaderServes(Duration::from_millis(250))).await?;
    let late = ask(
        a.dial_addr(),
        a.handle.peer_id,
        sync_rr_timing_out_after(Duration::from_millis(100)),
        vec![SyncRequest::GetHeaders { from_height: 0, max: 1 }; REQUESTS],
        Duration::from_millis(400),
        Duration::from_secs(1),
        SyncRequest::GetPeers { max: 8 },
        is_peers,
    );
    // An unknown kind (9), and a GetBlock (kind 3) past its 36 bytes.
    let mut unreadable = Vec::new();
    for i in 0..REQUESTS {
        unreadable.push(if i % 2 == 0 { vec![9, 0, 0, 0] } else { [vec![3, 0, 0, 0], vec![0xAB; 40]].concat() });
    }
    let raw_rr = request_response::Behaviour::<RawCodec>::new(
        std::iter::once((SYNC_PROTO, ProtocolSupport::Full)),
        request_response::Config::default().with_request_timeout(Duration::from_secs(15)).with_max_concurrent_streams(4),
    );
    let malformed = ask(
        a.dial_addr(),
        a.handle.peer_id,
        raw_rr,
        unreadable,
        Duration::from_millis(100),
        Duration::from_secs(1),
        // GetPeers { max: 8 }; the answer's first four bytes are SyncResponse::Peers's tag, 5.
        vec![5, 0, 0, 0, 8, 0],
        |r: &Vec<u8>| r.starts_with(&[5, 0, 0, 0]),
    );
    let (late, malformed) = tokio::join!(late, malformed);
    let answered = TEST_SERVES_ANSWERED.lock().unwrap().get(&a.handle.peer_id).copied().unwrap_or(0);
    eprintln!("[measure] late: {late:?}, serves answered {answered}; unreadable: {malformed:?}");
    assert_eq!(late.failed, REQUESTS, "every request of the late requester timed out on its side");
    assert_eq!(answered, REQUESTS as u64, "the node answered each, after its requester had gone");
    assert_eq!((late.open, late.last_answered), (1, true), "a requester we answered late was disconnected");
    assert_eq!(malformed.failed, REQUESTS, "an unreadable request was answered");
    assert_eq!((malformed.open, malformed.last_answered), (1, true), "a requester of unreadable requests was disconnected");
    Ok(())
}
