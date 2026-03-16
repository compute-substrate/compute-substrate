// src/net/node.rs
//
// Mainnet-hardening notes (what I changed vs your pasted file):
// 1) Removed the local MAX_BLOCK_BYTES constant and instead use consensus params:
//      - crate::params::MAX_BLOCK_BYTES
//      - crate::params::MAX_TX_BYTES
//    This ensures P2P byte caps match consensus limits.
//
// 2) Added TX-size enforcement on inbound TX gossip *after decode* (defense-in-depth):
//      - if consensus_bincode().serialize(&gt.tx).len() > MAX_TX_BYTES => reject + count invalid
//
// 3) Added outbound TX gossip check: if tx serializes > MAX_TX_BYTES, we refuse to publish it.
//
// 4) Tightened RR codec write_request/write_response to refuse sending oversized bodies
//    (protects our own node from accidentally emitting > MAX_RR_MSG_BYTES).
//
// 5) Added Option A plumbing (miner gating support):
//      - Track connected peer count
//      - Track "last remote tip observed" time
//      - Track "last peer change" time (peer stability latch)
//      - Expose these via NetHandle so miner can refuse to mine unless:
//           connected_peers >= 1 AND tip_fresh <= N seconds AND peers stable >= M seconds
//
// 6) FIXED: run_p2p() previously never returned NetHandle because it entered an infinite loop.
//    Now:
//      - spawn_p2p() returns NetHandle immediately and spawns the P2P loop
//      - run_p2p() is an alias for spawn_p2p() for compatibility
//
// 7) Bootnode auto-redial:
//      - If we have 0 connected peers, periodically attempt to dial bootnodes again.
//
// 8) NEW (this patch): connection refcount + dial backoff (fixes “connected spam” + tip spam).
//
// 9) NEW (production upgrades):
//      - peer scoring (prefer good peers; deprioritize bad)
//      - misbehavior quarantine (soft-ban for N seconds when score too low)

use crate::chain::pow::{bits_within_pow_limit, pow_ok};
use anyhow::{bail, Context, Result};
use futures::StreamExt;
use futures::{AsyncReadExt, AsyncWriteExt};
use libp2p::{
    core::upgrade,
    gossipsub::{self, IdentTopic, MessageAuthenticity, ValidationMode},
    identity, noise,
    request_response::{self, ProtocolSupport},
    swarm::{NetworkBehaviour, Swarm, SwarmEvent},
    tcp, yamux, Multiaddr, PeerId, Transport,
};
use std::{
    collections::{HashMap, HashSet, VecDeque},
    sync::{
        atomic::{AtomicU64, AtomicUsize, Ordering},
        Arc,
    },
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};
use tokio::time::interval;
use tokio::sync::RwLock;

use crate::{
    chain::index::{get_hidx, header_hash, index_header},
    chain::lock::ChainLock,
    net::mempool::Mempool,
    params::{MAX_BLOCK_BYTES, MAX_TX_BYTES},
    state::db::{get_tip, k_block, Stores},
    types::{Block, BlockHeader, Hash32},
};

use super::proto::*;
use super::{GossipTxEvent, MinedHeaderEvent};

const SYNC_PROTOCOL: &str = SYNC_PROTO;

// ----------------- hardening constants -----------------

const MAX_RR_SLACK_BYTES: u64 = 64 * 1024; // 64 KiB
const MAX_RR_MSG_BYTES: u64 = (MAX_BLOCK_BYTES as u64) + MAX_RR_SLACK_BYTES;

const MAX_GOSSIP_MSG_BYTES: usize = 256 * 1024; // 256 KiB

const RL_WINDOW: Duration = Duration::from_secs(10);
const RL_MAX_RR_REQS_PER_WINDOW: u32 = 200;
const RL_MAX_GOSSIP_MSGS_PER_WINDOW: u32 = 500;
const RL_MAX_INVALID_PER_WINDOW: u32 = 50;

const BAN_SECS: u64 = 60;

// ----------------- production upgrades -----------------

// score tuning (simple + stable)
const SCORE_GOOD_TIP: i32 = 1;
const SCORE_GOOD_HEADERS: i32 = 2;
const SCORE_GOOD_BLOCK: i32 = 3;
const SCORE_BAD_INVALID: i32 = -4;
const SCORE_BAD_TIMEOUT: i32 = -2;
const SCORE_BAD_UNKNOWN_BLOCK: i32 = -2;

// quarantine: soft-ban for a while when score too low
const QUAR_SECS: u64 = 60;
const QUAR_SCORE_THRESHOLD: i32 = -20;

// ----------------- dial backoff tuning -----------------

const REDIAL_EVERY_SECS: u64 = 10;
const DIAL_BACKOFF_SECS: u64 = 10;

// ----------------- time helpers -----------------

fn unix_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_else(|_| Duration::from_secs(0))
        .as_secs()
}

// ----------------- node key persistence -----------------

fn nodekey_path(datadir: &str) -> std::path::PathBuf {
    std::path::PathBuf::from(datadir).join("nodekey.ed25519")
}

fn load_or_create_node_key(datadir: &str) -> anyhow::Result<identity::Keypair> {
    std::fs::create_dir_all(datadir).context("create datadir")?;
    let p = nodekey_path(datadir);

    if p.exists() {
        let bytes = std::fs::read(&p).context("read nodekey.ed25519")?;
        let kp = identity::Keypair::from_protobuf_encoding(&bytes)
            .map_err(|e| anyhow::anyhow!("bad nodekey {}: {e}", p.display()))?;
        return Ok(kp);
    }

    let kp = identity::Keypair::generate_ed25519();
    let bytes = kp
        .to_protobuf_encoding()
        .map_err(|e| anyhow::anyhow!("cannot encode nodekey: {e}"))?;

    let tmp = p.with_extension("tmp");
    std::fs::write(&tmp, &bytes).context("write nodekey tmp")?;
    std::fs::rename(&tmp, &p).context("rename nodekey tmp -> nodekey.ed25519")?;
    Ok(kp)
}

// ----------------- misc helpers -----------------

fn is_genesis_header(h: &BlockHeader) -> bool {
    h.prev == [0u8; 32]
}

fn hex32(h: &Hash32) -> String {
    format!("0x{}", hex::encode(h))
}

fn peer_id_from_multiaddr(a: &Multiaddr) -> Option<PeerId> {
    use libp2p::multiaddr::Protocol;
    a.iter().find_map(|p| {
        if let Protocol::P2p(pid) = p {
            Some(pid)
        } else {
            None
        }
    })
}


// Locator builder (Bitcoin-style): tip, parent, parent^2, parent^4, ... capped.
fn build_locator(db: &Stores, tip: &Hash32) -> Vec<Hash32> {
    let mut loc = Vec::<Hash32>::new();
    if *tip == [0u8; 32] {
        loc.push([0u8; 32]);
        return loc;
    }

    let mut cur = *tip;
    let mut step: u64 = 1;
    let mut n: u64 = 0;

    while cur != [0u8; 32] && loc.len() < 64 {
        loc.push(cur);

        // walk back `step` parents
        let mut i = 0;
        while i < step {
            let Some(hi) = get_hidx(db, &cur).ok().flatten() else {
                break;
            };
            cur = hi.parent;
            if cur == [0u8; 32] {
                break;
            }
            i += 1;
        }

        n += 1;
        if n > 10 {
            step = step.saturating_mul(2);
        }
    }

    loc.push([0u8; 32]);
    loc
}

// ----------------- simple peer rate limiting / bans -----------------

#[derive(Clone)]
struct RateBucket {
    window_start: Instant,
    rr_reqs: u32,
    gossip_msgs: u32,
    invalid: u32,
}

impl RateBucket {
    fn new() -> Self {
        Self {
            window_start: Instant::now(),
            rr_reqs: 0,
            gossip_msgs: 0,
            invalid: 0,
        }
    }

    fn reset_if_needed(&mut self, window: Duration) {
        if self.window_start.elapsed() >= window {
            self.window_start = Instant::now();
            self.rr_reqs = 0;
            self.gossip_msgs = 0;
            self.invalid = 0;
        }
    }
}

impl Default for RateBucket {
    fn default() -> Self {
        Self::new()
    }
}

fn is_banned(bans: &HashMap<PeerId, Instant>, p: &PeerId) -> bool {
    bans.get(p)
        .map(|t| t.elapsed().as_secs() < BAN_SECS)
        .unwrap_or(false)
}

fn ban_peer(bans: &mut HashMap<PeerId, Instant>, p: PeerId, why: &str) {
    println!("[p2p] banning peer {p}: {why}");
    bans.insert(p, Instant::now());
}

fn note_invalid(
    buckets: &mut HashMap<PeerId, RateBucket>,
    bans: &mut HashMap<PeerId, Instant>,
    p: PeerId,
    why: &str,
) {
    let b = buckets.entry(p).or_insert_with(RateBucket::new);
    b.reset_if_needed(RL_WINDOW);
    b.invalid = b.invalid.saturating_add(1);
    println!(
        "[p2p] invalid from {p}: {why} (invalid_in_window={})",
        b.invalid
    );
    if b.invalid >= RL_MAX_INVALID_PER_WINDOW {
        ban_peer(bans, p, "too many invalid messages");
    }
}

fn allow_rr_req(
    buckets: &mut HashMap<PeerId, RateBucket>,
    bans: &mut HashMap<PeerId, Instant>,
    p: PeerId,
) -> bool {
    if is_banned(bans, &p) {
        return false;
    }
    let b = buckets.entry(p).or_insert_with(RateBucket::new);
    b.reset_if_needed(RL_WINDOW);
    b.rr_reqs = b.rr_reqs.saturating_add(1);
    if b.rr_reqs > RL_MAX_RR_REQS_PER_WINDOW {
        ban_peer(bans, p, "rr request rate limit exceeded");
        return false;
    }
    true
}

fn allow_gossip(
    buckets: &mut HashMap<PeerId, RateBucket>,
    bans: &mut HashMap<PeerId, Instant>,
    p: PeerId,
) -> bool {
    if is_banned(bans, &p) {
        return false;
    }
    let b = buckets.entry(p).or_insert_with(RateBucket::new);
    b.reset_if_needed(RL_WINDOW);
    b.gossip_msgs = b.gossip_msgs.saturating_add(1);
    if b.gossip_msgs > RL_MAX_GOSSIP_MSGS_PER_WINDOW {
        ban_peer(bans, p, "gossip rate limit exceeded");
        return false;
    }
    true
}

// ----------------- libp2p behaviour -----------------

#[derive(Clone, Debug)]
pub enum TestPeerMode {
    Normal,
    StallBlockResponses,
    UnknownBlockResponses,
}


#[derive(Clone)]
pub struct NetConfig {
    pub datadir: String,
    pub listen: Multiaddr,
    pub bootnodes: Vec<Multiaddr>,
    pub genesis_hash: Hash32,
    pub is_bootnode: bool,
    pub test_mode: TestPeerMode,
}

#[derive(Clone)]
pub struct NetHandle {
    pub peer_id: PeerId,
    connected_peers: Arc<AtomicUsize>,
    last_tip_seen_unix: Arc<AtomicU64>,
    last_peer_change_unix: Arc<AtomicU64>,
    listen_addr: Arc<RwLock<Option<Multiaddr>>>,
}

impl NetHandle {
    pub fn connected_peers(&self) -> usize {
        self.connected_peers.load(Ordering::Relaxed)
    }

    pub async fn listen_addr(&self) -> Option<Multiaddr> {
        self.listen_addr.read().await.clone()
    }

    pub fn last_tip_seen_unix(&self) -> u64 {
        self.last_tip_seen_unix.load(Ordering::Relaxed)
    }

    pub fn is_tip_fresh(&self, max_age_secs: u64) -> bool {
        let now = unix_now();
        let last = self.last_tip_seen_unix();
        now.saturating_sub(last) <= max_age_secs
    }

    pub fn last_peer_change_unix(&self) -> u64 {
        self.last_peer_change_unix.load(Ordering::Relaxed)
    }

    pub fn is_peer_stable(&self, min_stable_secs: u64) -> bool {
        let now = unix_now();
        let last = self.last_peer_change_unix();
        now.saturating_sub(last) >= min_stable_secs
    }
}

#[derive(Debug)]
pub enum OutEvent {
    Gossipsub(gossipsub::Event),
    Rr(request_response::Event<SyncRequest, SyncResponse>),
}

impl From<gossipsub::Event> for OutEvent {
    fn from(e: gossipsub::Event) -> Self {
        OutEvent::Gossipsub(e)
    }
}
impl From<request_response::Event<SyncRequest, SyncResponse>> for OutEvent {
    fn from(e: request_response::Event<SyncRequest, SyncResponse>) -> Self {
        OutEvent::Rr(e)
    }
}

#[derive(NetworkBehaviour)]
#[behaviour(to_swarm = "OutEvent")]
pub struct Behaviour {
    pub gossipsub: gossipsub::Behaviour,
    pub rr: request_response::Behaviour<SyncCodec>,
}

#[derive(Clone, Default)]
pub struct SyncCodec;

#[async_trait::async_trait]
impl request_response::Codec for SyncCodec {
    type Protocol = &'static str;
    type Request = SyncRequest;
    type Response = SyncResponse;

    async fn read_request<T>(
        &mut self,
        _: &Self::Protocol,
        io: &mut T,
    ) -> std::io::Result<Self::Request>
    where
        T: futures::prelude::AsyncRead + Unpin + Send,
    {
        let mut buf = Vec::new();
        let mut limited = io.take(MAX_RR_MSG_BYTES);
        limited.read_to_end(&mut buf).await?;
        if buf.len() as u64 >= MAX_RR_MSG_BYTES {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "request too large",
            ));
        }

        let req: SyncRequest = crate::codec::consensus_bincode()
            .deserialize::<SyncRequest>(&buf)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;

        Ok(req)
    }

    async fn read_response<T>(
        &mut self,
        _: &Self::Protocol,
        io: &mut T,
    ) -> std::io::Result<Self::Response>
    where
        T: futures::prelude::AsyncRead + Unpin + Send,
    {
        let mut buf = Vec::new();
        let mut limited = io.take(MAX_RR_MSG_BYTES);
        limited.read_to_end(&mut buf).await?;
        if buf.len() as u64 >= MAX_RR_MSG_BYTES {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "response too large",
            ));
        }

        let resp: SyncResponse = crate::codec::consensus_bincode()
            .deserialize::<SyncResponse>(&buf)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;

        Ok(resp)
    }

    async fn write_request<T>(
        &mut self,
        _: &Self::Protocol,
        io: &mut T,
        req: Self::Request,
    ) -> std::io::Result<()>
    where
        T: futures::prelude::AsyncWrite + Unpin + Send,
    {
        let bytes = crate::codec::consensus_bincode()
            .serialize(&req)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;

        if (bytes.len() as u64) >= MAX_RR_MSG_BYTES {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "request too large to send",
            ));
        }
        io.write_all(&bytes).await?;
        io.close().await?;
        Ok(())
    }

    async fn write_response<T>(
        &mut self,
        _: &Self::Protocol,
        io: &mut T,
        resp: Self::Response,
    ) -> std::io::Result<()>
    where
        T: futures::prelude::AsyncWrite + Unpin + Send,
    {
        let bytes = crate::codec::consensus_bincode()
            .serialize(&resp)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;

        if (bytes.len() as u64) >= MAX_RR_MSG_BYTES {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "response too large to send",
            ));
        }
        io.write_all(&bytes).await?;
        io.close().await?;
        Ok(())
    }
}

// ----------------- sync hardening helpers -----------------

fn accept_header_universe_pow(cfg: &NetConfig, hdr: &BlockHeader, h: &Hash32) -> bool {
    if is_genesis_header(hdr) && *h != cfg.genesis_hash {
        println!("[p2p] ignoring foreign genesis header {}", hex32(h));
        return false;
    }
    if !bits_within_pow_limit(hdr.bits) {
        println!("[p2p] ignoring header bits beyond pow limit");
        return false;
    }
    if !pow_ok(h, hdr.bits) {
        println!("[p2p] ignoring header failing PoW {}", hex32(h));
        return false;
    }
    true
}

fn local_tip_and_work(db: &Stores) -> (Hash32, u64, u128) {
    let tip = match get_tip(db) {
        Ok(Some(t)) => t,
        _ => [0u8; 32],
    };
    if tip == [0u8; 32] {
        return ([0u8; 32], 0, 0);
    }
    match get_hidx(db, &tip) {
        Ok(Some(hi)) => (tip, hi.height, hi.chainwork),
        _ => (tip, 0, 0),
    }
}

fn block_parent_ready(
    db: &Stores,
    pending_apply: &HashMap<Hash32, Block>,
    hdr: &BlockHeader,
) -> bool {
    if hdr.prev == [0u8; 32] {
        return true;
    }

    if db.blocks.get(k_block(&hdr.prev)).ok().flatten().is_some() {
        return true;
    }

    pending_apply.contains_key(&hdr.prev)
}


fn try_apply_pending(
    db: &Stores,
    mempool: &Mempool,
    pending_apply: &mut HashMap<Hash32, Block>,
    chain_lock: &crate::chain::lock::ChainLock,
) {
    loop {
        let (tip, _h, _w) = local_tip_and_work(db);

        let next_hash = pending_apply.iter().find_map(|(h, blk)| {
            if blk.header.prev == tip {
                Some(*h)
            } else {
                None
            }
        });

        let Some(h) = next_hash else { break };
        let blk = pending_apply.remove(&h).unwrap();

        {
            let _g = chain_lock.lock();

            if db.blocks.get(k_block(&h)).ok().flatten().is_none() {
                if let Ok(bytes) = crate::codec::consensus_bincode().serialize(&blk) {
                    if bytes.len() <= MAX_BLOCK_BYTES {
                        let _ = db.blocks.insert(k_block(&h), bytes);
                    }
                }
            }

            let _ = get_hidx(db, &h).ok().flatten().or_else(|| {
                if is_genesis_header(&blk.header) {
                    index_header(db, &blk.header, None).ok()?;
                    get_hidx(db, &h).ok().flatten()
                } else {
                    let parent = get_hidx(db, &blk.header.prev).ok().flatten()?;
                    index_header(db, &blk.header, Some(&parent)).ok()?;
                    get_hidx(db, &h).ok().flatten()
                }
            });
        }

        if let Err(e) = crate::chain::reorg::maybe_reorg_to(db, &h, Some(mempool)) {
            println!("[sync] maybe_reorg_to {} failed: {}", hex32(&h), e);
        }
    }
}

fn handle_gossipsub_event(event: &OutEvent) -> Option<(Option<PeerId>, Vec<u8>, String)> {
    match event {
        OutEvent::Gossipsub(gossipsub::Event::Message {
            propagation_source,
            message,
            ..
        }) => {
            let topic = message.topic.as_str().to_string();
            Some((Some(*propagation_source), message.data.clone(), topic))
        }
        _ => None,
    }
}

fn as_rr_event(event: OutEvent) -> Option<request_response::Event<SyncRequest, SyncResponse>> {
    match event {
        OutEvent::Rr(ev) => Some(ev),
        _ => None,
    }
}

// ----------------- PUBLIC API -----------------

pub async fn spawn_p2p(
    db: Arc<Stores>,
    mempool: Arc<Mempool>,
    cfg: NetConfig,
    mined_rx: tokio::sync::mpsc::UnboundedReceiver<MinedHeaderEvent>,
    tx_gossip_rx: tokio::sync::mpsc::UnboundedReceiver<GossipTxEvent>,
    chain_lock: ChainLock,
) -> Result<NetHandle> {
    let local_key = load_or_create_node_key(&cfg.datadir)?;
    let peer_id = PeerId::from(local_key.public());

    let connected_peers = Arc::new(AtomicUsize::new(0));
    let last_tip_seen_unix = Arc::new(AtomicU64::new(0));
    let last_peer_change_unix = Arc::new(AtomicU64::new(unix_now()));

let listen_addr = Arc::new(RwLock::new(None));


let handle = NetHandle {
    peer_id,
    connected_peers: connected_peers.clone(),
    last_tip_seen_unix: last_tip_seen_unix.clone(),
    last_peer_change_unix: last_peer_change_unix.clone(),
    listen_addr: listen_addr.clone(),
};

    tokio::spawn(async move {
        if let Err(e) = run_p2p_loop(
    db,
    mempool,
    cfg,
    local_key,
    peer_id,
    connected_peers,
    last_tip_seen_unix,
    last_peer_change_unix,
    listen_addr,
    mined_rx,
    tx_gossip_rx,
    chain_lock,
)
        .await
        {
            eprintln!("[p2p] fatal: {e}");
        }
    });

    Ok(handle)
}

pub async fn run_p2p(
    db: Arc<Stores>,
    mempool: Arc<Mempool>,
    cfg: NetConfig,
    mined_rx: tokio::sync::mpsc::UnboundedReceiver<MinedHeaderEvent>,
    tx_gossip_rx: tokio::sync::mpsc::UnboundedReceiver<GossipTxEvent>,
    chain_lock: ChainLock,
) -> Result<NetHandle> {
    spawn_p2p(db, mempool, cfg, mined_rx, tx_gossip_rx, chain_lock).await
}

// ----------------- main p2p loop (PRIVATE) -----------------

async fn run_p2p_loop(
    db: Arc<Stores>,
    mempool: Arc<Mempool>,
    cfg: NetConfig,
    local_key: identity::Keypair,
    peer_id: PeerId,
    connected_peers: Arc<AtomicUsize>,
    last_tip_seen_unix: Arc<AtomicU64>,
    last_peer_change_unix: Arc<AtomicU64>,
    listen_addr: Arc<RwLock<Option<Multiaddr>>>,

    mut mined_rx: tokio::sync::mpsc::UnboundedReceiver<MinedHeaderEvent>,
    mut tx_gossip_rx: tokio::sync::mpsc::UnboundedReceiver<GossipTxEvent>,
    chain_lock: ChainLock,
) -> Result<()> {
    println!("[p2p] peer_id: {peer_id}");

    let transport = tcp::tokio::Transport::new(tcp::Config::default().nodelay(true))
        .upgrade(upgrade::Version::V1)
        .authenticate(noise::Config::new(&local_key).unwrap())
        .multiplex(yamux::Config::default())
        .boxed();

    let gs_cfg = gossipsub::ConfigBuilder::default()
        .validation_mode(ValidationMode::Permissive)
        .heartbeat_interval(Duration::from_secs(1))
        .max_transmit_size(MAX_GOSSIP_MSG_BYTES)
        .message_id_fn(|m: &gossipsub::Message| {
            use blake3::Hasher;
            let mut h = Hasher::new();
            h.update(&m.data);
            gossipsub::MessageId::from(h.finalize().to_hex().to_string())
        })
        .build()
        .unwrap();

    let mut gossipsub =
        gossipsub::Behaviour::new(MessageAuthenticity::Signed(local_key.clone()), gs_cfg)
            .map_err(|e| anyhow::anyhow!(e))?;

    gossipsub.subscribe(&IdentTopic::new(TOPIC_HDR))?;
    gossipsub.subscribe(&IdentTopic::new(TOPIC_TX))?;

    let rr_cfg = request_response::Config::default();
    let protocols = std::iter::once((SYNC_PROTOCOL, ProtocolSupport::Full));
    let rr = request_response::Behaviour::<SyncCodec>::new(protocols, rr_cfg);

    let behaviour = Behaviour { gossipsub, rr };

    let mut swarm = Swarm::new(
        transport,
        behaviour,
        peer_id,
        libp2p::swarm::Config::with_tokio_executor(),
    );

    swarm.listen_on(cfg.listen.clone())?;
    println!("[p2p] listening on {}", cfg.listen);

    for a in &cfg.bootnodes {
        println!("[p2p] dialing bootnode {a}");
        let _ = swarm.dial(a.clone());
    }

    const MAX_HEADERS_PER_SYNC: u64 = 1024;
    const MAX_INFLIGHT_BLOCKS: usize = 128;
    const MAX_WANT_QUEUE: usize = 20_000;
    const BLOCK_REQ_TIMEOUT_SECS: u64 = 10;

    let mut connected: HashSet<PeerId> = HashSet::new();

    // NEW: connection refcount to avoid duplicate “connected” spam
    let mut conn_refcnt: HashMap<PeerId, usize> = HashMap::new();

    let mut peer_heights: HashMap<PeerId, u64> = HashMap::new();
    let mut peer_work: HashMap<PeerId, u128> = HashMap::new();
    let mut sync_peer: Option<PeerId> = None;

    // NEW: peer scoring + quarantine
    let mut peer_score: HashMap<PeerId, i32> = HashMap::new();
    let mut quarantine: HashMap<PeerId, Instant> = HashMap::new();

    let mut providers: HashMap<Hash32, PeerId> = HashMap::new();
    let mut bad_providers: HashMap<Hash32, HashSet<PeerId>> = HashMap::new();

    let mut seen_blocks: HashSet<Hash32> = HashSet::new();

    let mut inflight: HashMap<Hash32, (request_response::OutboundRequestId, Instant, PeerId)> =
        HashMap::new();
    let mut rid_to_hash: HashMap<request_response::OutboundRequestId, Hash32> = HashMap::new();

    let mut pending_apply: HashMap<Hash32, Block> = HashMap::new();
    let mut want_blocks: VecDeque<Hash32> = VecDeque::new();

    let mut best_hdr_tip: Hash32 = [0u8; 32];
    let mut best_hdr_height: u64 = 0;
    let mut best_hdr_work: u128 = 0;

    let mut buckets: HashMap<PeerId, RateBucket> = HashMap::new();
    let mut bans: HashMap<PeerId, Instant> = HashMap::new();

    let mut poll = interval(Duration::from_secs(5));

    let mut last_redial = Instant::now() - Duration::from_secs(60);
    let mut last_dial_by_addr: HashMap<Multiaddr, Instant> = HashMap::new();

    let is_bad = |bad: &HashMap<Hash32, HashSet<PeerId>>, h: &Hash32, p: &PeerId| -> bool {
        bad.get(h).map(|s| s.contains(p)).unwrap_or(false)
    };

    let is_quarantined = |quar: &HashMap<PeerId, Instant>, p: &PeerId| -> bool {
        quar.get(p)
            .map(|t| t.elapsed().as_secs() < QUAR_SECS)
            .unwrap_or(false)
    };

    let bump_score = |scores: &mut HashMap<PeerId, i32>, quar: &mut HashMap<PeerId, Instant>, p: PeerId, delta: i32| {
        let s = scores.entry(p).or_insert(0);
        *s = s.saturating_add(delta);
        if *s <= QUAR_SCORE_THRESHOLD {
            quar.insert(p, Instant::now());
        }
    };

    let choose_best_sync_peer = |connected: &HashSet<PeerId>,
                                 peer_work: &HashMap<PeerId, u128>,
                                 peer_score: &HashMap<PeerId, i32>,
                                 bans: &HashMap<PeerId, Instant>,
                                 quarantine: &HashMap<PeerId, Instant>|
     -> Option<PeerId> {
        let mut best: Option<(PeerId, u128, i32)> = None;
        for p in connected.iter() {
            if is_banned(bans, p) { continue; }
            if is_quarantined(quarantine, p) { continue; }

            let w = *peer_work.get(p).unwrap_or(&0);
            let s = *peer_score.get(p).unwrap_or(&0);

            match best {
                None => best = Some((*p, w, s)),
                Some((_bp, bw, bs)) => {
                    // Primary: chainwork
                    if w > bw {
                        best = Some((*p, w, s));
                    } else if w == bw {
                        // Tie-break: score
                        if s > bs {
                            best = Some((*p, w, s));
                        }
                    }
                }
            }
        }
        best.map(|(p, _w, _s)| p)
    };

    let mark_tip_seen = |last_tip_seen_unix: &Arc<AtomicU64>| {
        last_tip_seen_unix.store(unix_now(), Ordering::Relaxed);
    };

    let mark_peer_change = |last_peer_change_unix: &Arc<AtomicU64>| {
        last_peer_change_unix.store(unix_now(), Ordering::Relaxed);
    };

let pump_blocks =
    |swarm: &mut Swarm<Behaviour>,
     sync_peer: Option<PeerId>,
     connected: &HashSet<PeerId>,
     providers: &HashMap<Hash32, PeerId>,
     bad_providers: &mut HashMap<Hash32, HashSet<PeerId>>,
     bans: &HashMap<PeerId, Instant>,
     peer_score: &mut HashMap<PeerId, i32>,
     quarantine: &mut HashMap<PeerId, Instant>,
     rid_to_hash: &mut HashMap<request_response::OutboundRequestId, Hash32>,
     db: &Stores,
     pending_apply: &HashMap<Hash32, Block>,
     want_blocks: &mut VecDeque<Hash32>,
     inflight: &mut HashMap<Hash32, (request_response::OutboundRequestId, Instant, PeerId)>|
     -> Result<()> {

            let now = Instant::now();
            let mut timed_out: Vec<(Hash32, PeerId)> = vec![];

            for (h, (_rid, t0, peer)) in inflight.iter() {
                if now.duration_since(*t0).as_secs() >= BLOCK_REQ_TIMEOUT_SECS {
                    timed_out.push((*h, *peer));
                }
            }

            for (h, peer) in timed_out {
                if let Some((rid, _t0, _peer2)) = inflight.remove(&h) {
                    rid_to_hash.remove(&rid);
                }

                bump_score(peer_score, quarantine, peer, SCORE_BAD_TIMEOUT); 
bad_providers.entry(h).or_default().insert(peer);

                if providers.get(&h) == Some(&peer) {
                    // leave provider stale in map if you want, but do not trust it for this hash anymore
                }

                if want_blocks.len() < MAX_WANT_QUEUE {
                    want_blocks.push_back(h);
                }
                println!("[sync] requeue timed-out block {} from {}", hex32(&h), peer);
            }

            while inflight.len() < MAX_INFLIGHT_BLOCKS {
                let Some(h) = want_blocks.pop_front() else { break };
                if db.blocks.get(k_block(&h))?.is_some() {
                    continue;
                }
                if inflight.contains_key(&h) {
                    continue;
                }

let Some(hi) = get_hidx(db, &h)? else {
    if want_blocks.len() < MAX_WANT_QUEUE {
        want_blocks.push_back(h);
    }
    continue;
};

if hi.parent != [0u8; 32]
    && db.blocks.get(k_block(&hi.parent))?.is_none()
    && !pending_apply.contains_key(&hi.parent)
{
    if want_blocks.len() < MAX_WANT_QUEUE {
        want_blocks.push_back(h);
    }
    continue;
}



                let mut target: Option<PeerId> = None;

                // 1) Prefer the recorded provider for this hash, but only if still eligible.
                if let Some(p) = providers.get(&h) {
                    if connected.contains(p)
                        && !is_banned(bans, p)
                        && !is_quarantined(quarantine, p)
                        && !is_bad(bad_providers, &h, p)
                    {
                        target = Some(*p);
                    }
                }

                // 2) Fall back to sync_peer if eligible.
                if target.is_none() {
                    if let Some(sp) = sync_peer {
                        if connected.contains(&sp)
                            && !is_banned(bans, &sp)
                            && !is_quarantined(quarantine, &sp)
                            && !is_bad(bad_providers, &h, &sp)
                        {
                            target = Some(sp);
                        }
                    }
                }

                // 3) Fall back to any connected eligible peer.
                if target.is_none() {
                    target = connected
                        .iter()
                        .find(|p| {
                            !is_banned(bans, p)
                                && !is_quarantined(quarantine, p)
                                && !is_bad(bad_providers, &h, p)
                        })
                        .cloned();
                }

                // 4) Nobody eligible yet: requeue and wait.
                if target.is_none() {
                    if want_blocks.len() < MAX_WANT_QUEUE {
                        want_blocks.push_back(h);
                    }
                    continue;
                }




                let Some(peer) = target else { break };

                let rid = swarm
                    .behaviour_mut()
                    .rr
                    .send_request(&peer, SyncRequest::GetBlock { hash: h });
                // println!("[sync] request block {} from {}", hex32(&h), peer);

                rid_to_hash.insert(rid, h);
                inflight.insert(h, (rid, Instant::now(), peer));
            }

            Ok(())
        };

    loop {
        tokio::select! {
            _ = poll.tick() => {
                // bootnode auto-redial (with backoff + connected-skip)
                if connected.is_empty() && last_redial.elapsed() >= Duration::from_secs(REDIAL_EVERY_SECS) {
                    for a in &cfg.bootnodes {
                        // if multiaddr includes peer id, skip if already connected
                        if let Some(pid) = peer_id_from_multiaddr(a) {
                            if connected.contains(&pid) {
                                continue;
                            }
                        }

                        // per-address backoff
                        if let Some(t0) = last_dial_by_addr.get(a) {
                            if t0.elapsed() < Duration::from_secs(DIAL_BACKOFF_SECS) {
                                continue;
                            }
                        }

                        println!("[p2p] redial bootnode {a}");
                        let _ = swarm.dial(a.clone());
                        last_dial_by_addr.insert(a.clone(), Instant::now());
                    }
                    last_redial = Instant::now();
                }

                // periodic tip requests (skip banned/quarantined)
                for p in connected.iter() {
                    if is_banned(&bans, p) { continue; }
                    if is_quarantined(&quarantine, p) { continue; }
                    let _ = swarm.behaviour_mut().rr.send_request(p, SyncRequest::GetTip);
                }

                if sync_peer.is_none() {
                    sync_peer = choose_best_sync_peer(&connected, &peer_work, &peer_score, &bans, &quarantine)
                        .or_else(|| connected.iter().find(|p| !is_banned(&bans, p) && !is_quarantined(&quarantine, p)).cloned());
                }

let _ = pump_blocks(
    &mut swarm,
    sync_peer,
    &connected,
    &providers,
    &mut bad_providers,
    &bans,
&mut peer_score,
    &mut quarantine,
    &mut rid_to_hash,
    &db,
    &pending_apply,
    &mut want_blocks,
    &mut inflight,
);

                try_apply_pending(&db, mempool.as_ref(), &mut pending_apply, &chain_lock);
            }

            Some(ev) = mined_rx.recv() => {
                let gh = GossipHeader { header: ev.header };
                let bytes = crate::codec::consensus_bincode().serialize(&gh)?;
                if bytes.len() <= MAX_GOSSIP_MSG_BYTES {
                    let _ = swarm.behaviour_mut().gossipsub.publish(IdentTopic::new(TOPIC_HDR), bytes);
                }
            }

            Some(ev) = tx_gossip_rx.recv() => {
                if let Ok(tx_bytes) = crate::codec::consensus_bincode().serialize(&ev.tx) {
                    if tx_bytes.len() > MAX_TX_BYTES {
                        println!("[p2p] refusing to gossip oversized tx ({} bytes)", tx_bytes.len());
                        continue;
                    }
                }

                let gt = GossipTx { tx: ev.tx.clone() };
                let bytes = crate::codec::consensus_bincode().serialize(&gt)?;
                if bytes.len() <= MAX_GOSSIP_MSG_BYTES {
                    let _ = swarm.behaviour_mut().gossipsub.publish(IdentTopic::new(TOPIC_TX), bytes);
                }
            }

            swarm_ev = swarm.select_next_some() => {
                match swarm_ev {

SwarmEvent::NewListenAddr { address, .. } => {
    println!("[p2p] NewListenAddr: {}", address);

    // store first usable listen addr
    let mut g = listen_addr.write().await;
    if g.is_none() {
        *g = Some(address.clone());
    }
}

                    SwarmEvent::ConnectionEstablished { peer_id, .. } => {
                        if is_banned(&bans, &peer_id) {
                            println!("[p2p] ignoring connect from banned peer: {peer_id}");
                            continue;
                        }

                        // NEW: refcount; only treat 0->1 as “connected”
                        let e = conn_refcnt.entry(peer_id).or_insert(0);
                        *e += 1;
                        if *e > 1 {
                            // duplicate connection, do not spam logs / do not re-add / do not re-request tip
                            continue;
                        }

println!("[p2p] connected: {peer_id}");
connected.insert(peer_id);
connected_peers.store(connected.len(), Ordering::Relaxed);
mark_peer_change(&last_peer_change_unix);
mark_tip_seen(&last_tip_seen_unix);

                        // only request tip on first connection
                        if sync_peer.is_none() && !is_quarantined(&quarantine, &peer_id) {
                            sync_peer = Some(peer_id);
                        }
                        if !is_quarantined(&quarantine, &peer_id) {
                            let rid = swarm.behaviour_mut().rr.send_request(&peer_id, SyncRequest::GetTip);
                            println!("[sync] requested tip ({rid:?})");
                        }
                    }

                    SwarmEvent::ConnectionClosed { peer_id, .. } => {
                        // NEW: refcount; only treat 1->0 as “disconnected”
                        if let Some(e) = conn_refcnt.get_mut(&peer_id) {
                            if *e > 0 { *e -= 1; }
                            if *e > 0 {
                                continue;
                            }
                        }
                        conn_refcnt.remove(&peer_id);

                        if connected.remove(&peer_id) {
                            connected_peers.store(connected.len(), Ordering::Relaxed);
                        }

                        mark_peer_change(&last_peer_change_unix);

                        peer_heights.remove(&peer_id);
                        peer_work.remove(&peer_id);

                        let mut dead_hashes = vec![];
                        for (h, (_rid, _t0, asked_peer)) in inflight.iter() {
                            if *asked_peer == peer_id {
                                dead_hashes.push(*h);
                            }
                        }
                        for h in dead_hashes {
                            if let Some((rid, _t0, _p)) = inflight.remove(&h) {
                                rid_to_hash.remove(&rid);
                            }
                            if want_blocks.len() < MAX_WANT_QUEUE {
                                want_blocks.push_back(h);
                            }
                        }

                        if sync_peer == Some(peer_id) {
                            sync_peer = None;
                        }
                    }

                    SwarmEvent::Behaviour(event) => {
                        if let Some((src, data, topic)) = handle_gossipsub_event(&event) {
                            if data.len() > MAX_GOSSIP_MSG_BYTES {
                                if let Some(p) = src {
                                    note_invalid(&mut buckets, &mut bans, p, "oversized gossip msg");
                                    bump_score(&mut peer_score, &mut quarantine, p, SCORE_BAD_INVALID);
                                }
                                continue;
                            }

                            if let Some(p) = src {
                                if !allow_gossip(&mut buckets, &mut bans, p) {
                                    continue;
                                }
                                if is_quarantined(&quarantine, &p) {
                                    // silently ignore gossip from quarantined peers
                                    continue;
                                }
                            }

                            if topic == TOPIC_HDR {
                                let gh: GossipHeader = match crate::codec::consensus_bincode().deserialize::<GossipHeader>(&data) {
                                    Ok(x) => x,
                                    Err(_) => {
                                        if let Some(p) = src {
                                            note_invalid(&mut buckets, &mut bans, p, "bad gossip header decode");
                                            bump_score(&mut peer_score, &mut quarantine, p, SCORE_BAD_INVALID);
                                        }
                                        continue;
                                    }
                                };

                                let h = header_hash(&gh.header);

                                if !accept_header_universe_pow(&cfg, &gh.header, &h) {
                                    if let Some(p) = src {
                                        note_invalid(&mut buckets, &mut bans, p, "gossip header failed pow/limit/universe");
                                        bump_score(&mut peer_score, &mut quarantine, p, SCORE_BAD_INVALID);
                                    }
                                    continue;
                                }

                                mark_tip_seen(&last_tip_seen_unix);

                                if let Some(p) = src {
                                    // Gossip source is only a relay hint, not a guaranteed block provider.
                                    bump_score(&mut peer_score, &mut quarantine, p, 1);
                                }

if seen_blocks.insert(h) {
    if db.blocks.get(k_block(&h))?.is_none()
        && !inflight.contains_key(&h)
        && want_blocks.len() < MAX_WANT_QUEUE
    {
        want_blocks.push_back(h);
    }
    if sync_peer.is_none() {
        sync_peer = src;
    }
}

let _ = pump_blocks(
    &mut swarm,
    sync_peer,
    &connected,
    &providers,
    &mut bad_providers,
    &bans,
&mut peer_score,
    &mut quarantine,
    &mut rid_to_hash,
    &db,
    &pending_apply,
    &mut want_blocks,
    &mut inflight,
);

                            } else if topic == TOPIC_TX {
                                let gt: GossipTx = match crate::codec::consensus_bincode().deserialize::<GossipTx>(&data) {
                                    Ok(x) => x,
                                    Err(_) => {
                                        if let Some(p) = src {
                                            note_invalid(&mut buckets, &mut bans, p, "bad gossip tx decode");
                                            bump_score(&mut peer_score, &mut quarantine, p, SCORE_BAD_INVALID);
                                        }
                                        continue;
                                    }
                                };

                                if let Ok(tx_bytes) = crate::codec::consensus_bincode().serialize(&gt.tx) {
                                    if tx_bytes.len() > MAX_TX_BYTES {
                                        if let Some(p) = src {
                                            note_invalid(&mut buckets, &mut bans, p, "gossip tx oversized");
                                            bump_score(&mut peer_score, &mut quarantine, p, SCORE_BAD_INVALID);
                                        }
                                        continue;
                                    }
                                }

                                match mempool.insert_checked(db.as_ref(), gt.tx) {
                                    Ok(_added) => {}
                                    Err(_) => {
                                        if let Some(p) = src {
                                            note_invalid(&mut buckets, &mut bans, p, "gossip tx failed mempool validation");
                                            bump_score(&mut peer_score, &mut quarantine, p, SCORE_BAD_INVALID);
                                        }
                                    }
                                }
                            }
                        }

                        if let Some(rr_ev) = as_rr_event(event) {
                            use request_response::{Event, Message};

                            match rr_ev {
                                Event::Message { peer, message } => {
                                    if is_banned(&bans, &peer) {
                                        continue;
                                    }
                                    if is_quarantined(&quarantine, &peer) {
                                        // ignore rr from quarantined peers
                                        continue;
                                    }

                                    match message {

Message::Request { request, channel, .. } => {
    if !allow_rr_req(&mut buckets, &mut bans, peer) {
        continue;
    }

    mark_tip_seen(&last_tip_seen_unix);

{
if matches!(request, SyncRequest::GetBlock { .. }) {
    if matches!(cfg.test_mode, TestPeerMode::StallBlockResponses) {
        println!("[p2p-test] intentionally stalling GetBlock response from {peer}");
        continue;
    }

    if matches!(cfg.test_mode, TestPeerMode::UnknownBlockResponses) {
        println!("[p2p-test] intentionally returning unknown block to {peer}");
        let _ = swarm.behaviour_mut().rr.send_response(
            channel,
            SyncResponse::Err { msg: "unknown block".into() },
        );
        continue;
    }
}
}

let db2 = db.clone();
let req2 = request;

let resp = tokio::task::spawn_blocking(move || {
    handle_request_blocking(&db2, req2)
})
.await
.map_err(|e| anyhow::anyhow!("spawn_blocking join error: {e}"))?;

let mut resp = resp.unwrap_or_else(|e| SyncResponse::Err { msg: e.to_string() });

                                            if let SyncResponse::Block { block } = &resp {
                                                let bh = header_hash(&block.header);
                                                if !accept_header_universe_pow(&cfg, &block.header, &bh) {
                                                    resp = SyncResponse::Err{ msg: "refusing to serve foreign/invalid pow block".into() };
                                                } else if let Ok(bytes) = crate::codec::consensus_bincode().serialize(block) {
                                                    if bytes.len() > MAX_BLOCK_BYTES {
                                                        resp = SyncResponse::Err{ msg: "block too large".into() };
                                                    }
                                                }
                                            }

                                            let _ = swarm.behaviour_mut().rr.send_response(channel, resp);
                                        }

                                        Message::Response { request_id: rid, response } => {
                                            match response {
                                                SyncResponse::Tip { hash: _hash, height, chainwork } => {
                                                    mark_tip_seen(&last_tip_seen_unix);
                                                    bump_score(&mut peer_score, &mut quarantine, peer, SCORE_GOOD_TIP);

                                                    peer_heights.insert(peer, height);
                                                    peer_work.insert(peer, chainwork);

                                                    let best = choose_best_sync_peer(&connected, &peer_work, &peer_score, &bans, &quarantine);
                                                    if best.is_some() && sync_peer != best {
                                                        sync_peer = best;
                                                    } else if sync_peer.is_none() {
                                                        sync_peer = Some(peer);
                                                    }

                                                    let (applied_tip, _applied_h, applied_w) = local_tip_and_work(&db);
                                                    let local_w = if best_hdr_work > 0 { best_hdr_work } else { applied_w };
                                                    let locator_tip = if best_hdr_tip != [0u8; 32] { best_hdr_tip } else { applied_tip };

                                                    if chainwork > local_w && sync_peer == Some(peer) {
                                                        let locator = build_locator(&db, &locator_tip);
                                                        let _ = swarm.behaviour_mut().rr.send_request(
                                                            &peer,
                                                            SyncRequest::GetHeadersByLocator { locator, max: MAX_HEADERS_PER_SYNC }
                                                        );
                                                    }
                                                }

                                                SyncResponse::Headers { headers } => {
                                                    if !headers.is_empty() {
                                                        mark_tip_seen(&last_tip_seen_unix);
                                                        bump_score(&mut peer_score, &mut quarantine, peer, SCORE_GOOD_HEADERS);
                                                    }

                                                    if sync_peer.is_some() && sync_peer != Some(peer) {
                                                        // ignore racing peers
                                                    } else {
                                                        if sync_peer.is_none() {
                                                            sync_peer = Some(peer);
                                                        }

                                                        for hdr in headers {
                                                            let h = header_hash(&hdr);

                                                            if !accept_header_universe_pow(&cfg, &hdr, &h) {
                                                                note_invalid(&mut buckets, &mut bans, peer, "headers: invalid pow/limit/universe");
                                                                bump_score(&mut peer_score, &mut quarantine, peer, SCORE_BAD_INVALID);
                                                                continue;
                                                            }

                                                          

                                                            let idx_res = {
                                                                let _g = chain_lock.lock();
                                                                if hdr.prev == [0u8;32] {
                                                                    index_header(&db, &hdr, None)
                                                                } else {
                                                                    let parent = get_hidx(&db, &hdr.prev)?;
                                                                    let Some(p) = parent else { continue; };
                                                                    index_header(&db, &hdr, Some(&p))
                                                                }
                                                            };

                                                            if idx_res.is_err() {
                                                                note_invalid(&mut buckets, &mut bans, peer, "headers: index_header failed");
                                                                bump_score(&mut peer_score, &mut quarantine, peer, SCORE_BAD_INVALID);
                                                                continue;
                                                            }

                                                            if let Ok(Some(hi2)) = get_hidx(&db, &h) {
                                                                if hi2.chainwork > best_hdr_work {
                                                                    best_hdr_tip = h;
                                                                    best_hdr_height = hi2.height;
                                                                    best_hdr_work = hi2.chainwork;
                                                                }
                                                            }

                                                            if db.blocks.get(k_block(&h))?.is_none()
    && !inflight.contains_key(&h)
    && block_parent_ready(&db, &pending_apply, &hdr)
    && want_blocks.len() < MAX_WANT_QUEUE
{
    want_blocks.push_back(h);
}
                                                        }

let _ = pump_blocks(
    &mut swarm,
    sync_peer,
    &connected,
    &providers,
    &mut bad_providers,
    &bans,
&mut peer_score,
    &mut quarantine,
    &mut rid_to_hash,
    &db,
    &pending_apply,
    &mut want_blocks,
    &mut inflight,
);

                                                    }
                                                }

                                                SyncResponse::Block { block } => {
                                                    mark_tip_seen(&last_tip_seen_unix);
                                                    bump_score(&mut peer_score, &mut quarantine, peer, SCORE_GOOD_BLOCK);

                                                    if let Ok(bytes) = crate::codec::consensus_bincode().serialize(&block) {
                                                        if bytes.len() > MAX_BLOCK_BYTES {
                                                            note_invalid(&mut buckets, &mut bans, peer, "block: oversized");
                                                            bump_score(&mut peer_score, &mut quarantine, peer, SCORE_BAD_INVALID);
                                                            continue;
                                                        }
                                                    }

let bh = header_hash(&block.header);
providers.insert(bh, peer);

if let Some((rid2, t0, asked_peer)) = inflight.remove(&bh) {
    rid_to_hash.remove(&rid2);
    if asked_peer == peer {
        let _elapsed = t0.elapsed().as_millis();
    }
}

                                                    if !accept_header_universe_pow(&cfg, &block.header, &bh) {
                                                        note_invalid(&mut buckets, &mut bans, peer, "block: failed pow/limit/universe");
                                                        bump_score(&mut peer_score, &mut quarantine, peer, SCORE_BAD_INVALID);
                                                        continue;
                                                    }

                                                    {
                                                        let _g = chain_lock.lock();

                                                        if db.blocks.get(k_block(&bh))?.is_none() {
                                                            let bytes = crate::codec::consensus_bincode().serialize(&block)?;
                                                            if bytes.len() > MAX_BLOCK_BYTES {
                                                                note_invalid(&mut buckets, &mut bans, peer, "block: oversized (store)");
                                                                bump_score(&mut peer_score, &mut quarantine, peer, SCORE_BAD_INVALID);
                                                                continue;
                                                            }
                                                            db.blocks.insert(k_block(&bh), bytes)?;
                                                        }

                                                        let idx_res = if block.header.prev == [0u8; 32] {
                                                            index_header(&db, &block.header, None)
                                                        } else if let Some(p) = get_hidx(&db, &block.header.prev)? {
                                                            index_header(&db, &block.header, Some(&p))
                                                        } else {
                                                            pending_apply.insert(bh, block);
                                                            continue;
                                                        };

                                                        if idx_res.is_err() {
                                                            note_invalid(&mut buckets, &mut bans, peer, "block: index_header failed");
                                                            bump_score(&mut peer_score, &mut quarantine, peer, SCORE_BAD_INVALID);
                                                            continue;
                                                        }

                                                        if let Ok(Some(hi2)) = get_hidx(&db, &bh) {
                                                            if hi2.chainwork > best_hdr_work {
                                                                best_hdr_tip = bh;
                                                                best_hdr_height = hi2.height;
                                                                best_hdr_work = hi2.chainwork;
                                                            }
                                                        }
                                                    }

pending_apply.insert(bh, block);
                                                    try_apply_pending(&db, mempool.as_ref(), &mut pending_apply, &chain_lock);

let _ = pump_blocks(
    &mut swarm,
    sync_peer,
    &connected,
    &providers,
    &mut bad_providers,
    &bans,
&mut peer_score,
    &mut quarantine,
    &mut rid_to_hash,
    &db,
    &pending_apply,
    &mut want_blocks,
    &mut inflight,
);

                                                }

                                                SyncResponse::Ack => {}

SyncResponse::Err { msg } => {
    println!("[sync] error response from {peer}: {msg}");

    if msg.contains("unknown block") {
        bump_score(&mut peer_score, &mut quarantine, peer, SCORE_BAD_UNKNOWN_BLOCK);

        if let Some(h) = rid_to_hash.remove(&rid) {
            inflight.remove(&h);
            bad_providers.entry(h).or_default().insert(peer);

            if providers.get(&h) == Some(&peer) {
                providers.remove(&h);
            }

            if want_blocks.len() < MAX_WANT_QUEUE {
                want_blocks.push_back(h);
            }
        } else {
            println!("[sync] unknown block from {peer}, but rid had no tracked hash");
        }

        if sync_peer == Some(peer) {
            sync_peer = choose_best_sync_peer(
                &connected,
                &peer_work,
                &peer_score,
                &bans,
                &quarantine,
            )
            .filter(|p| *p != peer)
            .or_else(|| {
                connected
                    .iter()
                    .find(|p| {
                        **p != peer
                            && !is_banned(&bans, p)
                            && !is_quarantined(&quarantine, p)
                    })
                    .cloned()
            });
        }
    }
}

                                            }
                                        }
                                    }
                                }
                                _ => {}
                            }
                        }

                        // Penalize timeouts (production upgrade)
                        // Scan inflight and mark peers that keep timing out.
                        // (Lightweight: done here since we are already in event loop.)
                  
                    }

                    _ => {}
                }
            }
        }
    }
}

// ----------------- server side request handler (BLOCKING) -----------------

fn handle_request_blocking(db: &Stores, req: SyncRequest) -> Result<SyncResponse> {
    match req {
        SyncRequest::GetTip => {
            let tip = get_tip(db)?.unwrap_or([0u8; 32]);

            let (height, chainwork) = if tip == [0u8; 32] {
                (0u64, 0u128)
            } else if let Some(hi) = get_hidx(db, &tip)? {
                (hi.height, hi.chainwork)
            } else {
                (0u64, 0u128)
            };

            Ok(SyncResponse::Tip {
                hash: tip,
                height,
                chainwork,
            })
        }

        SyncRequest::GetHeaders { from_height, max } => {
            let tip = get_tip(db)?.unwrap_or([0u8; 32]);
            if tip == [0u8; 32] {
                return Ok(SyncResponse::Headers { headers: vec![] });
            }

            let mut out: Vec<BlockHeader> = vec![];
            let mut cur = tip;

            while cur != [0u8; 32] {
                let hi = get_hidx(db, &cur)?
                    .ok_or_else(|| anyhow::anyhow!("missing idx for {}", hex32(&cur)))?;

                if hi.height < from_height {
                    break;
                }

                let Some(bv) = db.blocks.get(k_block(&cur))? else {
                    break;
                };

                if bv.len() > MAX_BLOCK_BYTES {
                    bail!("db corruption: stored block exceeds MAX_BLOCK_BYTES");
                }

                let blk: Block = crate::codec::consensus_bincode().deserialize::<Block>(&bv)?;

                let computed = header_hash(&blk.header);
                if computed != cur {
                    bail!("db corruption: header hash mismatch for {}", hex32(&cur));
                }

                out.push(blk.header.clone());

                if out.len() as u64 >= max {
                    break;
                }

                cur = hi.parent;
            }

            out.reverse();
            Ok(SyncResponse::Headers { headers: out })
        }

        SyncRequest::GetHeadersByLocator { locator, max } => {
            let tip = get_tip(db)?.unwrap_or([0u8; 32]);
            if tip == [0u8; 32] {
                return Ok(SyncResponse::Headers { headers: vec![] });
            }

            let mut anchor_height: Option<u64> = None;
            for h in locator {
                if h == [0u8; 32] {
                    break;
                }
                if let Ok(Some(hi)) = get_hidx(db, &h) {
                    anchor_height = Some(hi.height);
                    break;
                }
            }

            let Some(anchor_h) = anchor_height else {
                return Ok(SyncResponse::Headers { headers: vec![] });
            };

            let mut out: Vec<BlockHeader> = vec![];
            let mut cur = tip;

            while cur != [0u8; 32] {
                let hi = get_hidx(db, &cur)?
                    .ok_or_else(|| anyhow::anyhow!("missing idx for {}", hex32(&cur)))?;

                if hi.height <= anchor_h {
                    break;
                }

                let Some(bv) = db.blocks.get(k_block(&cur))? else {
                    break;
                };

                if bv.len() > MAX_BLOCK_BYTES {
                    bail!("db corruption: stored block exceeds MAX_BLOCK_BYTES");
                }

                let blk: Block = crate::codec::consensus_bincode().deserialize::<Block>(&bv)?;

                let computed = header_hash(&blk.header);
                if computed != cur {
                    bail!("db corruption: header hash mismatch for {}", hex32(&cur));
                }

                out.push(blk.header.clone());

                if out.len() as u64 >= max {
                    break;
                }

                cur = hi.parent;
            }

            out.reverse();
            Ok(SyncResponse::Headers { headers: out })
        }

        SyncRequest::GetBlock { hash } => {
            let Some(v) = db.blocks.get(k_block(&hash))? else {
                // println!("[sync-serve] GetBlock MISS {}", hex32(&hash));
                bail!("unknown block");
            };

            // println!("[sync-serve] GetBlock HIT {} bytes={}", hex32(&hash), v.len());

            if v.len() > MAX_BLOCK_BYTES {
                bail!("db corruption: stored block exceeds MAX_BLOCK_BYTES");
            }

            let blk: Block = crate::codec::consensus_bincode().deserialize::<Block>(&v)?;
            Ok(SyncResponse::Block { block: blk })
        }

        SyncRequest::SubmitTx { tx: _tx } => Ok(SyncResponse::Ack),
    }
}
