// csd-gateway: browsers reach a Compute Substrate node directly, over WebRTC, by IP address and
// the hash of this program's certificate, with no web server, domain name or certificate authority
// in between. A page asks it what it would otherwise ask the node's HTTP RPC: one request per
// stream on `/csd/rpc/1`, JSON in, JSON out, which this passes to the node's RPC on this machine.
//
//   csd-gateway --rpc http://127.0.0.1:8789 --listen /ip4/0.0.0.0/udp/18001/webrtc-direct
//
// It runs beside the node, as its own program: the node itself is unchanged, and browser
// connections never touch the node's peer-to-peer network. Only the public read routes and
// `POST /tx/submit` are passed on; operator routes (`/node/info`, `/peers`, `/metrics`, ...) are not.
// A page checks what it is told against the proof-of-work (`/headers`, `/proof/tx`), so it
// needn't trust a node it reaches this way any more than one it reaches over HTTPS.

use anyhow::{Context, Result};
use clap::Parser;
use futures::StreamExt;
use libp2p::{
    connection_limits::{self, ConnectionLimits},
    core::{muxing::StreamMuxerBox, Transport as _},
    identity,
    request_response::{self, ProtocolSupport},
    swarm::{NetworkBehaviour, SwarmEvent},
    Multiaddr, PeerId, StreamProtocol, Swarm,
};
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use std::time::Duration;

pub const RPC_PROTOCOL: StreamProtocol = StreamProtocol::new("/csd/rpc/1");

/// At most this many browsers connected at once, and requests being answered at once.
const MAX_BROWSERS: u32 = 512;
const MAX_IN_FLIGHT: usize = 64;
/// A response larger than this is refused (the codec's own limit is 10 MiB).
const MAX_RESPONSE_BYTES: usize = 8 * 1024 * 1024;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RpcRequest {
    pub method: String,
    pub path: String,
    #[serde(default)]
    pub body: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RpcResponse {
    pub status: u16,
    pub body: String,
}

#[derive(NetworkBehaviour)]
struct Behaviour {
    limits: connection_limits::Behaviour,
    rpc: request_response::json::Behaviour<RpcRequest, RpcResponse>,
}

/// The routes a browser may use: what a public node already serves to anyone over HTTP.
fn public_route(method: &str, path: &str) -> bool {
    let p = path.split('?').next().unwrap_or("");
    if path.len() > 2048 || p.contains("..") {
        return false;
    }
    match method {
        "POST" => p == "/tx/submit",
        "GET" => {
            const EXACT: &[&str] = &["/health", "/tip", "/domains", "/oracle"];
            const PREFIX: &[&str] = &[
                "/headers/", "/proof/tx/", "/tx/", "/block/", "/utxos/", "/address/", "/recent/",
                "/proposals/", "/proposal/", "/attestations/", "/window/", "/top/", "/topk/",
            ];
            EXACT.contains(&p) || PREFIX.iter().any(|x| p.starts_with(x) && !p.starts_with("/tx/template"))
        }
        _ => false,
    }
}

fn load_or_create(datadir: &str) -> Result<(identity::Keypair, libp2p_webrtc::tokio::Certificate)> {
    let dir = std::path::Path::new(datadir);
    std::fs::create_dir_all(dir).context("create datadir")?;
    // its own key, so a browser connection can never be mistaken for the node's p2p identity
    let kp_path = dir.join("browser-key.ed25519");
    let kp = if kp_path.exists() {
        identity::Keypair::from_protobuf_encoding(&std::fs::read(&kp_path)?)
            .map_err(|e| anyhow::anyhow!("bad {}: {e}", kp_path.display()))?
    } else {
        let kp = identity::Keypair::generate_ed25519();
        let tmp = kp_path.with_extension("tmp");
        std::fs::write(&tmp, kp.to_protobuf_encoding().map_err(|e| anyhow::anyhow!("{e}"))?)?;
        std::fs::rename(&tmp, &kp_path)?;
        kp
    };
    // the certificate's hash is part of the address browsers dial, so it is kept: a new one on
    // every start would change the address
    let cert_path = dir.join("browser-cert.pem");
    let cert = if cert_path.exists() {
        libp2p_webrtc::tokio::Certificate::from_pem(&std::fs::read_to_string(&cert_path)?)
            .map_err(|e| anyhow::anyhow!("bad {}: {e}", cert_path.display()))?
    } else {
        let cert = libp2p_webrtc::tokio::Certificate::generate(&mut rand::rng())
            .map_err(|e| anyhow::anyhow!("certificate: {e}"))?;
        let tmp = cert_path.with_extension("tmp");
        std::fs::write(&tmp, cert.serialize_pem())?;
        std::fs::rename(&tmp, &cert_path)?;
        cert
    };
    Ok((kp, cert))
}

/// Answer one request by passing it to the node's RPC.
async fn answer(rpc: Arc<String>, req: RpcRequest) -> RpcResponse {
    let refuse = |status: u16, msg: &str| RpcResponse { status, body: serde_json::json!({ "ok": false, "err": msg }).to_string() };
    if !public_route(&req.method, &req.path) {
        return refuse(404, "not served to browsers");
    }
    let url = format!("{}{}", rpc.trim_end_matches('/'), req.path);
    let res = tokio::task::spawn_blocking(move || {
        let agent = ureq::AgentBuilder::new().timeout(Duration::from_secs(60)).build();
        let r = if req.method == "POST" {
            agent.post(&url).set("content-type", "application/json").send_string(&req.body.unwrap_or_default())
        } else {
            agent.get(&url).call()
        };
        let resp = match r {
            Ok(resp) => resp,
            Err(ureq::Error::Status(_, resp)) => resp,
            Err(e) => return Err(e.to_string()),
        };
        let status = resp.status();
        let mut body = String::new();
        use std::io::Read;
        resp.into_reader().take(MAX_RESPONSE_BYTES as u64 + 1).read_to_string(&mut body).map_err(|e| e.to_string())?;
        Ok::<_, String>((status, body))
    })
    .await;
    match res {
        Ok(Ok((_, body))) if body.len() > MAX_RESPONSE_BYTES => refuse(507, "response too large"),
        Ok(Ok((status, body))) => RpcResponse { status, body },
        _ => refuse(502, "the node didn't answer"),
    }
}

/// Listen for browsers on `listen` (a `/udp/<port>/webrtc-direct` address) and answer them with
/// the node's RPC at `rpc`. Runs until the process ends.
async fn serve(datadir: String, listen: Multiaddr, rpc: String) -> Result<()> {
    let rpc = Arc::new(rpc);
    let (kp, cert) = load_or_create(&datadir)?;
    let peer_id = PeerId::from(kp.public());
    let transport = libp2p_webrtc::tokio::Transport::new(kp.clone(), cert)
        .map(|(peer, conn), _| (peer, StreamMuxerBox::new(conn)))
        .boxed();
    let behaviour = Behaviour {
        limits: connection_limits::Behaviour::new(
            ConnectionLimits::default()
                .with_max_established_incoming(Some(MAX_BROWSERS))
                .with_max_pending_incoming(Some(MAX_BROWSERS))
                .with_max_established_per_peer(Some(2)),
        ),
        rpc: request_response::json::Behaviour::new(
            [(RPC_PROTOCOL, ProtocolSupport::Inbound)],
            request_response::Config::default()
                .with_request_timeout(Duration::from_secs(60))
                .with_max_concurrent_streams(16),
        ),
    };
    let mut swarm = Swarm::new(
        transport,
        behaviour,
        peer_id,
        libp2p::swarm::Config::with_tokio_executor().with_idle_connection_timeout(Duration::from_secs(120)),
    );
    swarm.listen_on(listen.clone()).with_context(|| format!("listen for browsers on {listen}"))?;
    println!("[browser] peer id {peer_id}, listening on {listen}");

    let gate = Arc::new(tokio::sync::Semaphore::new(MAX_IN_FLIGHT));
    let (done_tx, mut done_rx) = tokio::sync::mpsc::unbounded_channel::<(request_response::ResponseChannel<RpcResponse>, RpcResponse)>();
    loop {
        tokio::select! {
            ev = swarm.select_next_some() => match ev {
                SwarmEvent::NewListenAddr { address, .. } => {
                    println!("[browser] reachable at {address}/p2p/{peer_id}");
                }
                SwarmEvent::Behaviour(BehaviourEvent::Rpc(request_response::Event::Message {
                    message: request_response::Message::Request { request, channel, .. }, ..
                })) => {
                    let Ok(permit) = gate.clone().try_acquire_owned() else {
                        let _ = swarm.behaviour_mut().rpc.send_response(channel, RpcResponse {
                            status: 503,
                            body: serde_json::json!({ "ok": false, "err": "busy", "retry_after_secs": 2 }).to_string(),
                        });
                        continue;
                    };
                    let (rpc, done) = (rpc.clone(), done_tx.clone());
                    tokio::spawn(async move {
                        let _p = permit;
                        let res = answer(rpc, request).await;
                        let _ = done.send((channel, res));
                    });
                }
                _ => {}
            },
            Some((channel, res)) = done_rx.recv() => {
                // the browser may have gone in the meantime; nothing to do then
                let _ = swarm.behaviour_mut().rpc.send_response(channel, res);
            }
        }
    }
}

#[derive(Parser)]
#[command(about = "Lets browsers reach a Compute Substrate node directly, over WebRTC")]
struct Args {
    /// The node's RPC on this machine
    #[arg(long, default_value = "http://127.0.0.1:8789")]
    rpc: String,
    /// Where browsers connect: a UDP port, opened in the firewall
    #[arg(long, default_value = "/ip4/0.0.0.0/udp/18001/webrtc-direct")]
    listen: String,
    /// Where this program keeps its key and certificate (they make up its address, so keep them)
    #[arg(long, default_value = "csd-gateway-data")]
    datadir: String,
}

#[tokio::main]
async fn main() -> Result<()> {
    let a = Args::parse();
    let listen: Multiaddr = a.listen.parse().with_context(|| format!("--listen {}", a.listen))?;
    tokio::select! {
        r = serve(a.datadir, listen, a.rpc) => r,
        _ = tokio::signal::ctrl_c() => Ok(()),
    }
}

#[cfg(test)]
mod tests {
    use super::public_route;
    #[test]
    fn only_public_routes_are_served_to_browsers() {
        for ok in ["/tip", "/headers/0/2000", "/proof/tx/ab", "/proposals/500", "/utxos/aa?available=true", "/domains"] {
            assert!(public_route("GET", ok), "{ok}");
        }
        assert!(public_route("POST", "/tx/submit"));
        for no in ["/node/info", "/peers", "/metrics", "/p2p/info", "/mempool", "/tx/template/propose", "/proposals/../node/info"] {
            assert!(!public_route("GET", no), "{no}");
        }
        assert!(!public_route("POST", "/tx/template/propose"));
        assert!(!public_route("DELETE", "/tip"));
    }
}
