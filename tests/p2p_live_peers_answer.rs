#![cfg(feature = "test-bypass")] // live p2p lane: toy chains and the fault seam need the bypass (cargo test --features test-bypass)
// If a Peers answer were taken in reply to any of our requests, a connected peer
// could answer each GetTip (one every 10 s), headers request or GetBlock with an address list and
// push book entries, a peers.txt rewrite and dials with every answer, where we ask for peers at most
// every 30 s. A Peers answer is taken only as the answer to our GetPeers, as a Tip answer only to
// our GetTip and a Headers answer only to our headers request. P is a bare peer that answers the
// node's GetTip with one address list and its GetPeers with another; only the second may enter the
// book (the paired honest path).

use anyhow::Result;
use futures::StreamExt;
use std::time::Duration;

use libp2p::{identity, request_response, swarm::SwarmEvent, PeerId, Swarm};

use csd::net::proto::{SyncRequest, SyncResponse};

mod testutil_p2p;
use testutil_p2p::{spawn_node, swarm_config, sync_rr, transport, wait_until};

/// `n` addresses of distinct new peers that the book stores (routable, with a port). The node never
/// dials them: CSD_MAX_PEERS=1 keeps it at its cap while P is connected.
fn address_list(first_octet: u8, n: u8) -> Vec<String> {
    (0..n)
        .map(|i| format!("/ip4/{first_octet}.0.0.{}/tcp/17999/p2p/{}", i + 1, PeerId::random()))
        .collect()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_peers_answer_enters_the_book_only_as_the_answer_to_our_get_peers() -> Result<()> {
    // Read once per process (OnceLock), before the node starts; every test in this binary wants it.
    std::env::set_var("CSD_MAX_PEERS", "1");
    let a = spawn_node(vec![]).await?;

    let to_get_tip = address_list(11, 10);
    let to_get_peers = address_list(12, 5);
    let key = identity::Keypair::generate_ed25519();
    let mut p = Swarm::new(transport(&key), sync_rr(), key.public().to_peer_id(), swarm_config());
    p.dial(a.dial_addr())?;

    let (mut answered_tip, mut answered_peers) = (0u32, 0u32);
    let deadline = tokio::time::Instant::now() + Duration::from_secs(30);
    while answered_tip == 0 || answered_peers == 0 {
        let ev = tokio::time::timeout_at(deadline, p.select_next_some()).await?;
        if let SwarmEvent::Behaviour(request_response::Event::Message {
            message: request_response::Message::Request { request, channel, .. },
            ..
        }) = ev
        {
            let answer = match request {
                SyncRequest::GetTip => {
                    answered_tip += 1;
                    SyncResponse::Peers { peers: to_get_tip.clone() }
                }
                SyncRequest::GetPeers { .. } => {
                    answered_peers += 1;
                    SyncResponse::Peers { peers: to_get_peers.clone() }
                }
                _ => SyncResponse::Err { msg: "not served here".into() },
            };
            let _ = p.behaviour_mut().send_response(channel, answer);
        }
    }
    // Keep P's connection serviced while the node handles both answers.
    let settle = tokio::spawn(async move {
        loop {
            p.select_next_some().await;
        }
    });

    let took_the_get_peers_answer = wait_until(10, || a.handle.known_peers() >= to_get_peers.len()).await;
    // A Peers answer to the GetTip would show within the same wait; give it one more second.
    tokio::time::sleep(Duration::from_secs(1)).await;
    let known = a.handle.known_peers();
    settle.abort();

    assert!(took_the_get_peers_answer, "the answer to our GetPeers never reached the book (known {known})");
    assert_eq!(
        known,
        to_get_peers.len(),
        "the book holds {known} peers: a Peers answer to our GetTip ({} peers) was taken",
        to_get_tip.len()
    );
    Ok(())
}
