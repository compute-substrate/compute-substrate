#![cfg(feature = "test-bypass")] // live p2p lane: toy chains and the fault seam need the bypass (cargo test --features test-bypass)
#![allow(dead_code)]
//! Shared by the live p2p tests: a node under test on a fresh store, and bare libp2p peers that
//! speak its transport and sync protocol (the shape an upstream node or a crafted peer has).

use anyhow::Result;
use std::sync::Arc;
use std::time::Duration;
use tempfile::TempDir;
use tokio::sync::mpsc;

use libp2p::{
    core::upgrade,
    identity, noise,
    request_response::{self, ProtocolSupport},
    tcp, yamux, Multiaddr, PeerId, Transport,
};

use csd::chain::lock::new_chain_lock;
use csd::net::mempool::Mempool;
use csd::net::node::{spawn_p2p, NetConfig, NetHandle, SyncCodec, TestPeerMode};
use csd::net::proto::SYNC_PROTO;
use csd::state::db::Stores;

pub type Boxed = libp2p::core::transport::Boxed<(PeerId, libp2p::core::muxing::StreamMuxerBox)>;

/// tcp + noise + yamux with no upgrade timeout: upstream's transport (v1.1.2 and main d168f70
/// `src/net/node.rs`, the `tcp::tokio::Transport` chain in `run_p2p`).
pub fn transport(key: &identity::Keypair) -> Boxed {
    tcp::tokio::Transport::new(tcp::Config::default().nodelay(true))
        .upgrade(upgrade::Version::V1)
        .authenticate(noise::Config::new(key).unwrap())
        .multiplex(yamux::Config::default())
        .boxed()
}

pub fn swarm_config() -> libp2p::swarm::Config {
    libp2p::swarm::Config::with_tokio_executor().with_idle_connection_timeout(Duration::from_secs(120))
}

/// The sync protocol as a requester and server, upstream's request-response config (15 s timeout,
/// four streams per connection).
pub fn sync_rr() -> request_response::Behaviour<SyncCodec> {
    request_response::Behaviour::<SyncCodec>::new(
        std::iter::once((SYNC_PROTO, ProtocolSupport::Full)),
        request_response::Config::default()
            .with_request_timeout(Duration::from_secs(15))
            .with_max_concurrent_streams(4),
    )
}

/// A node under test with its store and channels kept alive.
pub struct Node {
    pub handle: NetHandle,
    pub addr: Multiaddr,
    pub db: Arc<Stores>,
    pub dir: TempDir,
    _chans: (mpsc::UnboundedSender<csd::net::MinedHeaderEvent>, mpsc::UnboundedSender<csd::net::GossipTxEvent>),
}

impl Node {
    /// Its listen address with its /p2p suffix, as a peer dials it.
    pub fn dial_addr(&self) -> Multiaddr {
        format!("{}/p2p/{}", self.addr, self.handle.peer_id).parse().unwrap()
    }
}

/// A node on a fresh store listening on 127.0.0.1, a bootnode by config when `bootnodes` is empty.
pub async fn spawn_node(bootnodes: Vec<Multiaddr>) -> Result<Node> {
    let dir = TempDir::new()?;
    let db = Arc::new(Stores::open(dir.path().to_str().unwrap())?);
    spawn_node_on(db, dir, [0x77; 32], bootnodes).await
}

pub async fn wait_until(secs: u64, mut done: impl FnMut() -> bool) -> bool {
    let deadline = tokio::time::Instant::now() + Duration::from_secs(secs);
    while !done() {
        if tokio::time::Instant::now() >= deadline {
            return false;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    true
}

/// A node serving `db` (a chain whose first block is `genesis`), listening on 127.0.0.1.
pub async fn spawn_node_on(db: Arc<Stores>, dir: TempDir, genesis: csd::types::Hash32, bootnodes: Vec<Multiaddr>) -> Result<Node> {
    spawn_node_in(db, dir, genesis, bootnodes, TestPeerMode::Normal).await
}

/// A fresh node, a bootnode by config, in `mode`.
pub async fn spawn_node_with(mode: TestPeerMode) -> Result<Node> {
    let dir = TempDir::new()?;
    let db = Arc::new(Stores::open(dir.path().to_str().unwrap())?);
    spawn_node_in(db, dir, [0x77; 32], vec![], mode).await
}

/// `spawn_node_on` in `mode`.
pub async fn spawn_node_in(
    db: Arc<Stores>,
    dir: TempDir,
    genesis: csd::types::Hash32,
    bootnodes: Vec<Multiaddr>,
    mode: TestPeerMode,
) -> Result<Node> {
    let (mined, mined_rx) = mpsc::unbounded_channel();
    let (gossip, gossip_rx) = mpsc::unbounded_channel();
    let cfg = NetConfig {
        datadir: dir.path().to_string_lossy().to_string(),
        listen: "/ip4/127.0.0.1/tcp/0".parse()?,
        is_bootnode: bootnodes.is_empty(),
        bootnodes,
        genesis_hash: genesis,
        test_mode: mode,
    };
    let handle = spawn_p2p(db.clone(), Arc::new(Mempool::new()), cfg, mined_rx, gossip_rx, new_chain_lock()).await?;
    for _ in 0..100 {
        if let Some(addr) = handle.listen_addr().await {
            return Ok(Node { handle, addr, db, dir, _chans: (mined, gossip) });
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    anyhow::bail!("the node has no listen address")
}

/// A dial-only TCP transport whose sockets are bound to `local` before they connect, so a test can
/// connect from a loopback address other than 127.0.0.1 (libp2p's own TCP transport binds a dial to
/// the unspecified address or its listen port, and the kernel then picks 127.0.0.1).
pub struct BoundTcp(pub std::net::Ipv4Addr);

impl Transport for BoundTcp {
    type Output = libp2p::tcp::tokio::TcpStream;
    type Error = std::io::Error;
    type ListenerUpgrade = futures::future::Pending<Result<Self::Output, Self::Error>>;
    type Dial = std::pin::Pin<Box<dyn std::future::Future<Output = Result<Self::Output, Self::Error>> + Send>>;

    fn listen_on(
        &mut self,
        _id: libp2p::core::transport::ListenerId,
        addr: Multiaddr,
    ) -> Result<(), libp2p::core::transport::TransportError<Self::Error>> {
        Err(libp2p::core::transport::TransportError::MultiaddrNotSupported(addr))
    }

    fn remove_listener(&mut self, _id: libp2p::core::transport::ListenerId) -> bool {
        false
    }

    fn dial(
        &mut self,
        addr: Multiaddr,
        _opts: libp2p::core::transport::DialOpts,
    ) -> Result<Self::Dial, libp2p::core::transport::TransportError<Self::Error>> {
        use libp2p::multiaddr::Protocol;
        let (mut ip, mut port) = (None, None);
        for p in addr.iter() {
            match p {
                Protocol::Ip4(a) => ip = Some(a),
                Protocol::Tcp(t) => port = Some(t),
                _ => {}
            }
        }
        let (Some(ip), Some(port)) = (ip, port) else {
            return Err(libp2p::core::transport::TransportError::MultiaddrNotSupported(addr));
        };
        let local = self.0;
        Ok(Box::pin(async move {
            let socket = tokio::net::TcpSocket::new_v4()?;
            socket.bind(std::net::SocketAddr::from((local, 0)))?;
            let stream = socket.connect(std::net::SocketAddr::from((ip, port))).await?;
            stream.set_nodelay(true)?;
            Ok(libp2p::tcp::tokio::TcpStream(stream))
        }))
    }

    fn poll(
        self: std::pin::Pin<&mut Self>,
        _cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<libp2p::core::transport::TransportEvent<Self::ListenerUpgrade, Self::Error>> {
        std::task::Poll::Pending
    }
}

/// `transport`'s stack over `BoundTcp(local)`.
pub fn transport_from(key: &identity::Keypair, local: std::net::Ipv4Addr) -> Boxed {
    BoundTcp(local)
        .upgrade(upgrade::Version::V1)
        .authenticate(noise::Config::new(key).unwrap())
        .multiplex(yamux::Config::default())
        .boxed()
}
