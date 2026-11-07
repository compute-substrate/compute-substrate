#![cfg(feature = "test-bypass")] // live p2p lane: toy chains and the fault seam need the bypass (cargo test --features test-bypass)
// Eclipse class: when the established-connection cap counted both directions, connections a
// remote opened to us could fill it and refuse our own dials. The cap now counts inbound connections only (the peer cap plus its burst). Here the
// cap is 1 + 64 (CSD_MAX_PEERS=1, set before the node starts; read once per process): the node
// dials its bootnode B through a proxy that holds the connection for a few seconds, while 33
// identities open two connections each to the node and fill its 65 inbound places. The node's own
// dial must still be admitted (it was refused under the shared cap).

use anyhow::{Context, Result};
use futures::StreamExt;
use std::io::{Read, Write};
use std::net::{Shutdown, TcpListener, TcpStream};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;

use libp2p::{identity, request_response, swarm::SwarmEvent, Multiaddr, Swarm};

use csd::net::proto::SyncResponse;

mod testutil_p2p;
use testutil_p2p::{spawn_node, swarm_config, sync_rr, transport};

const INBOUND_PLACES: usize = 1 + 64;
const FLOOD_IDENTITIES: usize = 33;
const PROXY_HOLD: Duration = Duration::from_secs(6);

/// Copies `from` to `to` until either end closes.
fn pipe(mut from: TcpStream, mut to: TcpStream) {
    let mut buf = [0u8; 16 * 1024];
    while let Ok(n) = from.read(&mut buf) {
        if n == 0 || to.write_all(&buf[..n]).is_err() {
            break;
        }
    }
    let _ = to.shutdown(Shutdown::Write);
}

/// A loopback proxy to `target` that holds each connection PROXY_HOLD before it forwards it.
fn delaying_proxy(target: std::net::SocketAddr) -> Result<u16> {
    let listener = TcpListener::bind("127.0.0.1:0")?;
    let port = listener.local_addr()?.port();
    std::thread::spawn(move || {
        for inbound in listener.incoming().flatten() {
            std::thread::spawn(move || {
                std::thread::sleep(PROXY_HOLD);
                let Ok(outbound) = TcpStream::connect(target) else { return };
                let (Ok(i2), Ok(o2)) = (inbound.try_clone(), outbound.try_clone()) else { return };
                std::thread::spawn(move || pipe(i2, o2));
                pipe(outbound, inbound);
            });
        }
    });
    Ok(port)
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn an_inbound_flood_does_not_refuse_our_own_dial() -> Result<()> {
    std::env::set_var("CSD_MAX_PEERS", "1");

    // B: the node's bootnode, a bare peer listening on 127.0.0.1.
    let b_key = identity::Keypair::generate_ed25519();
    let b_peer = b_key.public().to_peer_id();
    let mut b = Swarm::new(transport(&b_key), sync_rr(), b_peer, swarm_config());
    b.listen_on("/ip4/127.0.0.1/tcp/0".parse::<Multiaddr>()?)?;
    let b_addr = loop {
        if let SwarmEvent::NewListenAddr { address, .. } = b.select_next_some().await {
            break address;
        }
    };
    let b_port = b_addr.iter().find_map(|p| match p {
        libp2p::multiaddr::Protocol::Tcp(port) => Some(port),
        _ => None,
    });
    let proxy = delaying_proxy(format!("127.0.0.1:{}", b_port.context("B's port")?).parse()?)?;
    let bootnode: Multiaddr = format!("/ip4/127.0.0.1/tcp/{proxy}/p2p/{b_peer}").parse()?;
    let b_held = Arc::new(AtomicUsize::new(0));
    let b_task = {
        let held = b_held.clone();
        tokio::spawn(async move {
            loop {
                match b.select_next_some().await {
                    SwarmEvent::ConnectionEstablished { .. } => {
                        held.fetch_add(1, Ordering::Relaxed);
                    }
                    SwarmEvent::ConnectionClosed { .. } => {
                        held.fetch_sub(1, Ordering::Relaxed);
                    }
                    SwarmEvent::Behaviour(request_response::Event::Message {
                        message: request_response::Message::Request { channel, .. }, ..
                    }) => {
                        let _ = b.behaviour_mut().send_response(channel, SyncResponse::Err { msg: "not served".into() });
                    }
                    _ => {}
                }
            }
        })
    };

    // The node dials B at its start; the proxy holds that dial while the flood fills the node.
    let a = spawn_node(vec![bootnode]).await?;
    let flood_open = Arc::new(AtomicUsize::new(0));
    let mut flood = Vec::new();
    for batch in 0..FLOOD_IDENTITIES.div_ceil(8) {
        for _ in 0..8.min(FLOOD_IDENTITIES - batch * 8) {
            let key = identity::Keypair::generate_ed25519();
            let mut f = Swarm::new(transport(&key), sync_rr(), key.public().to_peer_id(), swarm_config());
            f.dial(a.dial_addr())?;
            f.dial(a.dial_addr())?;
            let open = flood_open.clone();
            flood.push(tokio::spawn(async move {
                loop {
                    match f.select_next_some().await {
                        SwarmEvent::ConnectionEstablished { .. } => {
                            open.fetch_add(1, Ordering::Relaxed);
                        }
                        SwarmEvent::ConnectionClosed { .. } => {
                            open.fetch_sub(1, Ordering::Relaxed);
                        }
                        SwarmEvent::Behaviour(request_response::Event::Message {
                            message: request_response::Message::Request { channel, .. }, ..
                        }) => {
                            let _ = f.behaviour_mut().send_response(channel, SyncResponse::Err { msg: "not served".into() });
                        }
                        _ => {}
                    }
                }
            }));
        }
        tokio::time::sleep(Duration::from_millis(300)).await;
    }
    let filled = flood_open.load(Ordering::Relaxed);
    assert_eq!(filled, INBOUND_PLACES, "the flood holds {filled} connections");

    // B's connection from the node arrives after the proxy's hold and must be kept.
    tokio::time::sleep(PROXY_HOLD + Duration::from_secs(3)).await;
    let held = b_held.load(Ordering::Relaxed);
    b_task.abort();
    for f in flood {
        f.abort();
    }
    assert_eq!(held, 1, "the node's own dial to its bootnode holds {held} connections under an inbound flood");
    Ok(())
}
