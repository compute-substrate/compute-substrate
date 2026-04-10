// src/net/node.rs

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
use tokio::time::{interval, MissedTickBehavior};
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
const RL_MAX_RR_REQS_PER_WINDOW: u32 = 4096;
const RL_MAX_GOSSIP_MSGS_PER_WINDOW: u32 = 128;
const RL_MAX_INVALID_PER_WINDOW: u32 = 12;

const BAN_SECS: u64 = 10 * 60;

// ----------------- production upgrades -----------------

const SCORE_GOOD_TIP: i32 = 1;
const SCORE_GOOD_HEADERS: i32 = 2;
const SCORE_GOOD_BLOCK: i32 = 3;

const SCORE_BAD_INVALID: i32 = -6;
const SCORE_BAD_TIMEOUT: i32 = -3;
const SCORE_BAD_UNKNOWN_BLOCK: i32 = -3;
const SCORE_BAD_EMPTY_HEADERS: i32 = -1;
const SCORE_BAD_UNREQUESTED_BLOCK: i32 = -8;
const SCORE_BAD_OVERSIZED_HEADERS: i32 = -6;

const TIP_POLL_SECS: u64 = 120;
const REGULAR_TIP_POLL_SECS: u64 = 10;
const GETTIP_LOG_EVERY_SECS: u64 = 60;

// quarantine: soft-ban for a while when score too low
const QUAR_SECS: u64 = 5 * 60;
const QUAR_SCORE_THRESHOLD: i32 = -12;

// ----------------- dial backoff tuning -----------------

const REDIAL_EVERY_SECS: u64 = 10;
const DIAL_BACKOFF_SECS: u64 = 10;

// ----------------- sync bounds -----------------

const MAX_HEADERS_PER_SYNC: u64 = 1024;
const MAX_LOCATOR_LEN: usize = 128;
const MAX_INFLIGHT_BLOCKS: usize = 64;
const MAX_WANT_QUEUE: usize = 20_000;
const BLOCK_REQ_TIMEOUT_SECS: u64 = 12;

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

fn prune_peer_state(
    buckets: &mut HashMap<PeerId, RateBucket>,
    bans: &mut HashMap<PeerId, Instant>,
    quarantine: &mut HashMap<PeerId, Instant>,
    connected: &HashSet<PeerId>,
) {
    bans.retain(|p, t| connected.contains(p) || t.elapsed().as_secs() < BAN_SECS);
    quarantine.retain(|p, t| connected.contains(p) || t.elapsed().as_secs() < QUAR_SECS);
    buckets.retain(|p, b| connected.contains(p) || b.window_start.elapsed() < RL_WINDOW);
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
    pub connected_peers: Arc<AtomicUsize>,
    last_tip_seen_unix: Arc<AtomicU64>,
    last_peer_change_unix: Arc<AtomicU64>,
    best_peer_height: Arc<AtomicU64>,
    best_peer_work_lo: Arc<AtomicU64>,
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

    pub fn best_peer_height(&self) -> u64 {
        self.best_peer_height.load(Ordering::Relaxed)
    }

    pub fn best_peer_work_lo(&self) -> u64 {
        self.best_peer_work_lo.load(Ordering::Relaxed)
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

fn peer_is_eligible(
    p: &PeerId,
    connected: &HashSet<PeerId>,
    bans: &HashMap<PeerId, Instant>,
    quarantine: &HashMap<PeerId, Instant>,
) -> bool {
    connected.contains(p)
        && !is_banned(bans, p)
        && !quarantine
            .get(p)
            .map(|t| t.elapsed().as_secs() < QUAR_SECS)
            .unwrap_or(false)
}

fn recompute_best_peer_metrics(
    connected: &HashSet<PeerId>,
    peer_heights: &HashMap<PeerId, u64>,
    peer_work: &HashMap<PeerId, u128>,
    bans: &HashMap<PeerId, Instant>,
    quarantine: &HashMap<PeerId, Instant>,
) -> (u64, u64) {
    let mut best_h: u64 = 0;
    let mut best_w_lo: u64 = 0;

    for p in connected.iter() {
        if !peer_is_eligible(p, connected, bans, quarantine) {
            continue;
        }

        let h = *peer_heights.get(p).unwrap_or(&0);
        let w_lo = (*peer_work.get(p).unwrap_or(&0) & (u64::MAX as u128)) as u64;

        if h > best_h {
            best_h = h;
            best_w_lo = w_lo;
        } else if h == best_h && w_lo > best_w_lo {
            best_w_lo = w_lo;
        }
    }

    (best_h, best_w_lo)
}

fn maybe_switch_sync_peer(
    current: Option<PeerId>,
    candidate: Option<PeerId>,
    connected: &HashSet<PeerId>,
    peer_work: &HashMap<PeerId, u128>,
    peer_score: &HashMap<PeerId, i32>,
    bans: &HashMap<PeerId, Instant>,
    quarantine: &HashMap<PeerId, Instant>,
) -> Option<PeerId> {
    match (current, candidate) {
        (Some(cur), Some(cand)) => {
            let cur_ok = peer_is_eligible(&cur, connected, bans, quarantine);
            if !cur_ok {
                return Some(cand);
            }

            if cur == cand {
                return Some(cur);
            }

            let cur_w = *peer_work.get(&cur).unwrap_or(&0);
            let cur_s = *peer_score.get(&cur).unwrap_or(&0);

            let cand_w = *peer_work.get(&cand).unwrap_or(&0);
            let cand_s = *peer_score.get(&cand).unwrap_or(&0);

            let cand_strictly_better =
                (cand_w > cur_w) || (cand_w == cur_w && cand_s > cur_s);

            if cand_strictly_better {
                Some(cand)
            } else {
                Some(cur)
            }
        }
        (None, Some(cand)) => Some(cand),
        (Some(cur), None) => {
            if peer_is_eligible(&cur, connected, bans, quarantine) {
                Some(cur)
            } else {
                None
            }
        }
        (None, None) => None,
    }
}




fn should_log_tip_update(
    last_logged: Option<(u64, u128, u128)>,
    new_height: u64,
    new_work: u128,
    local_work: u128,
) -> bool {
    last_logged != Some((new_height, new_work, local_work))
}

fn has_raw_or_pending(
    db: &Stores,
    pending_apply: &HashMap<Hash32, Block>,
    h: &Hash32,
) -> bool {
    db.blocks.get(k_block(h)).ok().flatten().is_some() || pending_apply.contains_key(h)
}

fn is_requestable_missing_block(
    db: &Stores,
    pending_apply: &HashMap<Hash32, Block>,
    inflight: &HashMap<Hash32, (request_response::OutboundRequestId, Instant, PeerId)>,
    h: &Hash32,
) -> Result<bool> {
    if has_raw_or_pending(db, pending_apply, h) {
        return Ok(false);
    }
    if inflight.contains_key(h) {
        return Ok(false);
    }

    let Some(hi) = get_hidx(db, h)? else {
        return Ok(false);
    };

    Ok(
        hi.parent == [0u8; 32]
            || has_raw_or_pending(db, pending_apply, &hi.parent)
    )
}

fn earliest_requestable_missing_ancestor(
    db: &Stores,
    pending_apply: &HashMap<Hash32, Block>,
    inflight: &HashMap<Hash32, (request_response::OutboundRequestId, Instant, PeerId)>,
    h: Hash32,
) -> Result<Option<Hash32>> {
    let mut cur = h;
    let mut path: Vec<Hash32> = Vec::new();

    loop {
        let Some(hi) = get_hidx(db, &cur)? else {
            return Ok(None);
        };

        path.push(cur);

        if hi.parent == [0u8; 32] {
            break;
        }

        cur = hi.parent;
    }

    path.reverse();

    for x in path {
        if has_raw_or_pending(db, pending_apply, &x) {
            continue;
        }

        if inflight.contains_key(&x) {
            return Ok(None);
        }

        let Some(hi) = get_hidx(db, &x)? else {
            return Ok(None);
        };

        let parent_grounded =
            hi.parent == [0u8; 32] || has_raw_or_pending(db, pending_apply, &hi.parent);

        if parent_grounded {
            return Ok(Some(x));
        } else {
            return Ok(None);
        }
    }

    Ok(None)
}


fn scrub_stale_inflight(
    inflight: &mut HashMap<Hash32, (request_response::OutboundRequestId, Instant, PeerId)>,
    rid_to_hash: &mut HashMap<request_response::OutboundRequestId, Hash32>,
    want_blocks: &mut VecDeque<Hash32>,
) {
    let mut stale: Vec<(Hash32, request_response::OutboundRequestId)> = Vec::new();

    for (h, (rid, _t0, _peer)) in inflight.iter() {
        match rid_to_hash.get(rid) {
            Some(mapped_h) if *mapped_h == *h => {}
            _ => stale.push((*h, *rid)),
        }
    }

    for (h, rid) in stale {
        inflight.remove(&h);
        rid_to_hash.remove(&rid);

        if !want_blocks.iter().any(|x| *x == h) && want_blocks.len() < MAX_WANT_QUEUE {
            want_blocks.push_back(h);
        }

        println!("[sync] scrubbed stale inflight {}", hex32(&h));
    }
}

fn short_peer(p: &PeerId) -> String {
    let s = p.to_string();
    if s.len() <= 12 { s } else { format!("{}..{}", &s[..6], &s[s.len()-4..]) }
}

fn short_hash(h: &Hash32) -> String {
    let s = hex32(h);
    if s.len() <= 18 { s } else { format!("{}..{}", &s[..10], &s[s.len()-6..]) }
}

fn try_apply_pending(
    db: &Stores,
    mempool: &Mempool,
    pending_apply: &mut HashMap<Hash32, Block>,
    chain_lock: &crate::chain::lock::ChainLock,
) {
    loop {
        let mut progressed = false;

        // Snapshot current canonical tip/work once per pass.
        let (cur_tip, _cur_h, cur_work) = local_tip_and_work(db);

        // Collect candidate hashes so we can mutate pending_apply safely.
        let candidate_hashes: Vec<Hash32> = pending_apply.keys().copied().collect();

        for h in candidate_hashes {
            let Some(blk) = pending_apply.get(&h) else { continue };

            // Only consider blocks whose parent is already present/indexed.
            let parent_ready = blk.header.prev == [0u8; 32]
                || db.blocks.get(k_block(&blk.header.prev)).ok().flatten().is_some()
                || pending_apply.contains_key(&blk.header.prev);

            if !parent_ready {
                continue;
            }

            {
                let _g = chain_lock.lock();

                // Ensure raw block exists.
                if db.blocks.get(k_block(&h)).ok().flatten().is_none() {
                    if let Ok(bytes) = crate::codec::consensus_bincode().serialize(blk) {
                        if bytes.len() <= MAX_BLOCK_BYTES {
                            let _ = db.blocks.insert(k_block(&h), bytes);
                        }
                    }
                }

                // Ensure header index exists.
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

            let Some(new_hi) = get_hidx(db, &h).ok().flatten() else {
                continue;
            };

            // Case 1: direct extension of current canonical tip.
            if blk.header.prev == cur_tip {
                let blk = pending_apply.remove(&h).unwrap();
                drop(blk);

                eprintln!(
                    "[sync] applying direct-tip pending block {} h={} w={}",
                    hex32(&h),
                    new_hi.height,
                    new_hi.chainwork
                );

                if let Err(e) = crate::chain::reorg::maybe_reorg_to(db, &h, Some(mempool)) {
                    println!("[sync] maybe_reorg_to {} failed: {}", hex32(&h), e);
                }

                progressed = true;
                break;
            }

            // Case 2: stronger competing fork head was downloaded.
            if new_hi.chainwork > cur_work {
                let blk = pending_apply.remove(&h).unwrap();
                drop(blk);

                eprintln!(
                    "[sync] stronger downloaded fork detected -> maybe_reorg_to({}) h={} w={} cur_w={}",
                    hex32(&h),
                    new_hi.height,
                    new_hi.chainwork,
                    cur_work
                );

                if let Err(e) = crate::chain::reorg::maybe_reorg_to(db, &h, Some(mempool)) {
                    println!("[sync] maybe_reorg_to {} failed: {}", hex32(&h), e);
                }

                progressed = true;
                break;
            }
        }

        if !progressed {
            break;
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
let best_peer_height = Arc::new(AtomicU64::new(0));
let best_peer_work_lo = Arc::new(AtomicU64::new(0));

let listen_addr = Arc::new(RwLock::new(None));

let handle = NetHandle {
    peer_id,
    connected_peers: connected_peers.clone(),
    last_tip_seen_unix: last_tip_seen_unix.clone(),
    last_peer_change_unix: last_peer_change_unix.clone(),
    best_peer_height: best_peer_height.clone(),
    best_peer_work_lo: best_peer_work_lo.clone(),
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
    best_peer_height,
    best_peer_work_lo,
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
    best_peer_height_atomic: Arc<AtomicU64>,
    best_peer_work_lo_atomic: Arc<AtomicU64>,
    listen_addr: Arc<RwLock<Option<Multiaddr>>>,

    mut mined_rx: tokio::sync::mpsc::UnboundedReceiver<MinedHeaderEvent>,
    mut tx_gossip_rx: tokio::sync::mpsc::UnboundedReceiver<GossipTxEvent>,
    chain_lock: ChainLock,
) -> Result<()> {

    if let Ok(v) = std::env::var("CSD_CRASH_AT") {
        eprintln!("[failpoint] CSD_CRASH_AT={}", v);
    }

    println!("[p2p] peer_id: {peer_id}");

    let (boot_tip, boot_height, boot_work) = local_tip_and_work(&db);
    let boot_tip_block_present = if boot_tip != [0u8; 32] {
        db.blocks.get(k_block(&boot_tip))?.is_some()
    } else {
        false
    };
    let boot_tip_hidx_present = if boot_tip != [0u8; 32] {
        get_hidx(&db, &boot_tip)?.is_some()
    } else {
        false
    };

    println!(
        "[boot-check] tip={} height={} work={}",
        hex32(&boot_tip),
        boot_height,
        boot_work
    );
    println!(
        "[boot-check] tip_block_present={} tip_hidx_present={}",
        boot_tip_block_present,
        boot_tip_hidx_present
    );

    if boot_height == 0 && boot_tip != [0u8; 32] && !boot_tip_block_present {
        println!(
            "[boot-check] WARNING: tip is set but raw tip block is missing; fresh sync may stall"
        );
    }
    

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

let rr_cfg = request_response::Config::default()
    .with_request_timeout(Duration::from_secs(10))
    .with_max_concurrent_streams(128);

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

    let mut connected: HashSet<PeerId> = HashSet::new();

    // NEW: connection refcount to avoid duplicate “connected” spam
    let mut conn_refcnt: HashMap<PeerId, usize> = HashMap::new();

    let mut peer_heights: HashMap<PeerId, u64> = HashMap::new();
    let mut peer_work: HashMap<PeerId, u128> = HashMap::new();
    let mut sync_peer: Option<PeerId> = None;

let mut last_logged_tip: HashMap<PeerId, (u64, u128, u128)> = HashMap::new();


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
poll.set_missed_tick_behavior(MissedTickBehavior::Skip);

    let mut last_redial = Instant::now() - Duration::from_secs(60);
    let mut last_dial_by_addr: HashMap<Multiaddr, Instant> = HashMap::new();

    let mut last_tip_req_at: HashMap<PeerId, Instant> = HashMap::new();

let mut last_gettip_log_at: HashMap<PeerId, Instant> = HashMap::new();

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
    let mut best: Option<(PeerId, u128, i32, String)> = None;

    for p in connected.iter() {
        if !peer_is_eligible(p, connected, bans, quarantine) {
            continue;
        }

        let w = *peer_work.get(p).unwrap_or(&0);
        let s = *peer_score.get(p).unwrap_or(&0);
        let pid = p.to_string();

        match &best {
            None => best = Some((*p, w, s, pid)),
            Some((_bp, bw, bs, bpid)) => {
                let better =
                    (w > *bw)
                    || (w == *bw && s > *bs)
                    || (w == *bw && s == *bs && pid < *bpid);

                if better {
                    best = Some((*p, w, s, pid));
                }
            }
        }
    }

    best.map(|(p, _, _, _)| p)
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
                }

                if want_blocks.len() < MAX_WANT_QUEUE {
                    want_blocks.push_back(h);
                }
                println!("[sync] requeue timed-out block {} from {}", hex32(&h), peer);

if sync_peer == Some(peer) {
    // handled by outer sync-peer chooser on next poll/event
}

            }



want_blocks.retain(|h| {
    if inflight.contains_key(h) || pending_apply.contains_key(h) {
        return true;
    }

    if db.blocks.get(k_block(h)).ok().flatten().is_some() {
        return false;
    }

    if get_hidx(db, h).ok().flatten().is_none() {
        return false;
    }

    true
});



while inflight.len() < MAX_INFLIGHT_BLOCKS {
    let snapshot: Vec<Hash32> = want_blocks.iter().copied().collect();

    let mut best_hash: Option<Hash32> = None;
    let mut best_peer: Option<PeerId> = None;
    let mut best_height: u64 = u64::MAX;

    let mut skip_no_requestable = 0usize;
    let mut skip_no_hidx = 0usize;
    let mut skip_no_peer = 0usize;

    let mut sample_reasons: Vec<String> = Vec::new();

    for queued_h in snapshot {
        let Some(target_h) = earliest_requestable_missing_ancestor(
            db,
            pending_apply,
            inflight,
            queued_h,
        )? else {
            skip_no_requestable += 1;

            if sample_reasons.len() < 8 {
                let have_raw = db.blocks.get(k_block(&queued_h)).ok().flatten().is_some();
                let in_pending = pending_apply.contains_key(&queued_h);
                let in_flight = inflight.contains_key(&queued_h);
                let hidx = get_hidx(db, &queued_h)?.is_some();

                sample_reasons.push(format!(
                    "queued={} no_requestable (have_raw={} pending={} inflight={} hidx={})",
                    short_hash(&queued_h),
                    have_raw,
                    in_pending,
                    in_flight,
                    hidx
                ));
            }

            continue;
        };

        let Some(hi) = get_hidx(db, &target_h)? else {
            skip_no_hidx += 1;

            if sample_reasons.len() < 8 {
                sample_reasons.push(format!(
                    "queued={} target={} missing_hidx",
                    short_hash(&queued_h),
                    short_hash(&target_h),
                ));
            }

            continue;
        };

        let mut target_peer: Option<PeerId> = None;
        let mut peer_reason = String::new();

        // 1) Prefer recorded provider for target hash
        if let Some(p) = providers.get(&target_h) {
            let connected_ok = connected.contains(p);
            let banned = is_banned(bans, p);
            let quarantined = is_quarantined(quarantine, p);
            let bad = is_bad(bad_providers, &target_h, p);

            if connected_ok && !banned && !quarantined && !bad {
                target_peer = Some(*p);
            } else {
                peer_reason = format!(
                    "provider={} connected={} banned={} quarantined={} bad={}",
                    short_peer(p),
                    connected_ok,
                    banned,
                    quarantined,
                    bad
                );
            }
        } else {
            peer_reason = "no_provider".to_string();
        }

        // 2) Fallback to sync_peer
        if target_peer.is_none() {
            if let Some(sp) = sync_peer {
                let connected_ok = connected.contains(&sp);
                let banned = is_banned(bans, &sp);
                let quarantined = is_quarantined(quarantine, &sp);
                let bad = is_bad(bad_providers, &target_h, &sp);

                if connected_ok && !banned && !quarantined && !bad {
                    target_peer = Some(sp);
                } else if peer_reason.is_empty() {
                    peer_reason = format!(
                        "sync_peer={} connected={} banned={} quarantined={} bad={}",
                        short_peer(&sp),
                        connected_ok,
                        banned,
                        quarantined,
                        bad
                    );
                }
            } else if peer_reason.is_empty() {
                peer_reason = "no_sync_peer".to_string();
            }
        }

        // 3) Fallback to any eligible connected peer
        if target_peer.is_none() {
            target_peer = connected
                .iter()
                .find(|p| {
                    !is_banned(bans, p)
                        && !is_quarantined(quarantine, p)
                        && !is_bad(bad_providers, &target_h, p)
                })
                .cloned();

            if target_peer.is_none() && peer_reason.is_empty() {
                peer_reason = "no_fallback_peer".to_string();
            }
        }

        let Some(peer) = target_peer else {
            skip_no_peer += 1;

            if sample_reasons.len() < 8 {
                sample_reasons.push(format!(
                    "queued={} target={} no_peer ({})",
                    short_hash(&queued_h),
                    short_hash(&target_h),
                    peer_reason
                ));
            }

            continue;
        };

        if hi.height < best_height {
            best_height = hi.height;
            best_hash = Some(target_h);
            best_peer = Some(peer);
        }
    }

    let Some(h) = best_hash else {
        if !want_blocks.is_empty() {
            println!(
                "[sync-debug] pump_blocks stalled: want={} inflight={} pending={} connected={} no_requestable={} no_hidx={} no_peer={}",
                want_blocks.len(),
                inflight.len(),
                pending_apply.len(),
                connected.len(),
                skip_no_requestable,
                skip_no_hidx,
                skip_no_peer,
            );

            for line in &sample_reasons {
                println!("[sync-debug] {}", line);
            }
        }
        break;
    };

    let Some(peer) = best_peer else {
        println!(
            "[sync-debug] pump_blocks internal inconsistency: best_hash but no best_peer for {}",
            short_hash(&h)
        );
        break;
    };

    want_blocks.retain(|x| *x != h);

    let rid = swarm
        .behaviour_mut()
        .rr
        .send_request(&peer, SyncRequest::GetBlock { hash: h });

    println!(
        "[sync] request block {} from {} (height={})",
        hex32(&h),
        peer,
        best_height
    );

    rid_to_hash.insert(rid, h);
    inflight.insert(h, (rid, Instant::now(), peer));
}

            Ok(())
        };

    loop {
        tokio::select! {

_ = poll.tick() => {

prune_peer_state(&mut buckets, &mut bans, &mut quarantine, &connected);

scrub_stale_inflight(
    &mut inflight,
    &mut rid_to_hash,
    &mut want_blocks,
);

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

// regular tip polling + stale fallback
let tip_age = unix_now().saturating_sub(last_tip_seen_unix.load(Ordering::Relaxed));

// Poll ALL connected eligible peers, not just sync_peer.
// Otherwise one stale bootnode can trap us on old peer_work.
for p in connected.iter().cloned() {
    if is_banned(&bans, &p) || is_quarantined(&quarantine, &p) {
        continue;
    }

    let regular_due = last_tip_req_at
        .get(&p)
        .map(|t| t.elapsed() >= Duration::from_secs(REGULAR_TIP_POLL_SECS))
        .unwrap_or(true);

    let stale_due = tip_age >= TIP_POLL_SECS;

    if regular_due || stale_due {
        let _ = swarm.behaviour_mut().rr.send_request(&p, SyncRequest::GetTip);
        last_tip_req_at.insert(p, Instant::now());

        if stale_due {
            println!("[sync] stale-tip poll to {} (tip_age={}s)", p, tip_age);
        }
    }
}

// Recompute live best-peer metrics from current eligible peers.
let (best_h, best_w_lo) = recompute_best_peer_metrics(
    &connected,
    &peer_heights,
    &peer_work,
    &bans,
    &quarantine,
);
best_peer_height_atomic.store(best_h, Ordering::Relaxed);
best_peer_work_lo_atomic.store(best_w_lo, Ordering::Relaxed);

// Pick best candidate, but keep current sync_peer unless the candidate is strictly better.
let candidate_sync_peer = choose_best_sync_peer(
    &connected,
    &peer_work,
    &peer_score,
    &bans,
    &quarantine,
)
.or_else(|| {
    connected
        .iter()
        .find(|p| peer_is_eligible(p, &connected, &bans, &quarantine))
        .cloned()
});

let next_sync_peer = maybe_switch_sync_peer(
    sync_peer,
    candidate_sync_peer,
    &connected,
    &peer_work,
    &peer_score,
    &bans,
    &quarantine,
);

if next_sync_peer != sync_peer {
    if let Some(p) = next_sync_peer {
        println!("[sync] switching sync_peer -> {}", p);
    }
}
sync_peer = next_sync_peer;

if !want_blocks.is_empty() || !inflight.is_empty() {
    println!(
        "[sync] queue status: want_blocks={} inflight={} pending_apply={}",
        want_blocks.len(),
        inflight.len(),
        pending_apply.len(),
    );
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

// Track refcount, but use `connected` as the authoritative "first connect" gate.
let e = conn_refcnt.entry(peer_id).or_insert(0);
*e += 1;

let is_first_logical_connection = connected.insert(peer_id);
if !is_first_logical_connection {
    // Already logically connected to this peer; ignore duplicate established events.
    continue;
}

println!("[p2p] connected: {peer_id}");
connected_peers.store(connected.len(), Ordering::Relaxed);
mark_peer_change(&last_peer_change_unix);

                        // only request tip on first connection
                        if sync_peer.is_none() && !is_quarantined(&quarantine, &peer_id) {
                            sync_peer = Some(peer_id);
                        }

if !is_quarantined(&quarantine, &peer_id) {
    let rid = swarm.behaviour_mut().rr.send_request(&peer_id, SyncRequest::GetTip);
    last_tip_req_at.insert(peer_id, Instant::now());
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
                        last_tip_req_at.remove(&peer_id);

let (best_h, best_w_lo) = recompute_best_peer_metrics(
    &connected,
    &peer_heights,
    &peer_work,
    &bans,
    &quarantine,
);
best_peer_height_atomic.store(best_h, Ordering::Relaxed);
best_peer_work_lo_atomic.store(best_w_lo, Ordering::Relaxed);

last_gettip_log_at.remove(&peer_id);


last_logged_tip.remove(&peer_id);


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
    let _ = swarm.behaviour_mut().rr.send_response(
        channel,
        SyncResponse::Err { msg: "rate limited".into() },
    );
    continue;
}

match &request {
    SyncRequest::GetHeadersByLocator { locator, max } => {
        if locator.len() > MAX_LOCATOR_LEN || *max > MAX_HEADERS_PER_SYNC {
            note_invalid(&mut buckets, &mut bans, peer, "oversized locator or max headers request");
            bump_score(&mut peer_score, &mut quarantine, peer, SCORE_BAD_INVALID);
            let _ = swarm.behaviour_mut().rr.send_response(
                channel,
                SyncResponse::Err { msg: "invalid headers request".into() },
            );
            continue;
        }
    }
    SyncRequest::GetHeaders { max, .. } => {
        if *max > MAX_HEADERS_PER_SYNC {
            note_invalid(&mut buckets, &mut bans, peer, "oversized GetHeaders request");
            bump_score(&mut peer_score, &mut quarantine, peer, SCORE_BAD_INVALID);
            let _ = swarm.behaviour_mut().rr.send_response(
                channel,
                SyncResponse::Err { msg: "invalid headers request".into() },
            );
            continue;
        }
    }
    _ => {}
}



match &request {

SyncRequest::GetTip => {
        let should_log = last_gettip_log_at
            .get(&peer)
            .map(|t| t.elapsed() >= Duration::from_secs(GETTIP_LOG_EVERY_SECS))
            .unwrap_or(true);

        if should_log {
            println!("[sync-serve] recv GetTip from {peer}");
            last_gettip_log_at.insert(peer, Instant::now());
        }
    }
    SyncRequest::GetHeadersByLocator { locator, max } => {
        println!(
            "[sync-serve] recv GetHeadersByLocator from {peer} locator_len={} max={}",
            locator.len(),
            max
        );
    }

    SyncRequest::GetHeaders { from_height, max } => {
        println!(
            "[sync-serve] recv GetHeaders from {peer} from_height={} max={}",
            from_height,
            max
        );
    }
    SyncRequest::GetBlock { hash } => {
        println!("[sync-serve] recv GetBlock from {peer} hash={}", hex32(hash));
    }
    SyncRequest::SubmitTx { .. } => {
        println!("[sync-serve] recv SubmitTx from {peer}");
    }
}

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

// Recompute live best-peer metrics from current eligible peers.
let (best_h, best_w_lo) = recompute_best_peer_metrics(
    &connected,
    &peer_heights,
    &peer_work,
    &bans,
    &quarantine,
);
best_peer_height_atomic.store(best_h, Ordering::Relaxed);
best_peer_work_lo_atomic.store(best_w_lo, Ordering::Relaxed);

let (_dbg_tip, _dbg_h, _dbg_w) = local_tip_and_work(&db);
let last_logged = last_logged_tip.get(&peer).copied();

if should_log_tip_update(last_logged, height, chainwork, _dbg_w) {
    println!(
        "[sync] tip from {}: remote_height={} remote_work={} local_work={}",
        peer, height, chainwork, _dbg_w
    );
    last_logged_tip.insert(peer, (height, chainwork, _dbg_w));
}

let candidate_sync_peer = choose_best_sync_peer(
    &connected,
    &peer_work,
    &peer_score,
    &bans,
    &quarantine,
).or_else(|| Some(peer));

let next_sync_peer = maybe_switch_sync_peer(
    sync_peer,
    candidate_sync_peer,
    &connected,
    &peer_work,
    &peer_score,
    &bans,
    &quarantine,
);

if next_sync_peer != sync_peer {
    if let Some(p) = next_sync_peer {
        println!("[sync] switching sync_peer -> {}", p);
    }
}
sync_peer = next_sync_peer;

    let (applied_tip, _applied_h, applied_w) = local_tip_and_work(&db);

    let local_w = applied_w;
    let locator_tip = applied_tip;

    if chainwork > local_w && sync_peer == Some(peer) {
        let locator = build_locator(&db, &locator_tip);
        let locator_len = locator.len();

        let _ = swarm.behaviour_mut().rr.send_request(
            &peer,
            SyncRequest::GetHeadersByLocator {
                locator,
                max: MAX_HEADERS_PER_SYNC,
            },
        );

        println!(
            "[sync] requesting headers-by-locator from {} (locator_len={})",
            peer,
            locator_len
        );
    }
}

                                                SyncResponse::Headers { headers } => {
    if headers.len() as u64 > MAX_HEADERS_PER_SYNC {
        note_invalid(&mut buckets, &mut bans, peer, "oversized headers response");
        bump_score(&mut peer_score, &mut quarantine, peer, SCORE_BAD_OVERSIZED_HEADERS);
        continue;
    }

    if headers.is_empty() && sync_peer == Some(peer) {
        bump_score(&mut peer_score, &mut quarantine, peer, SCORE_BAD_EMPTY_HEADERS);
    }

    println!(
        "[sync] got headers from {} count={}",
        peer,
        headers.len()
    );

    if !headers.is_empty() {
        mark_tip_seen(&last_tip_seen_unix);
        bump_score(&mut peer_score, &mut quarantine, peer, SCORE_GOOD_HEADERS);
    }

    if sync_peer.is_none() {
        sync_peer = Some(peer);
    }

    // Store headers from this batch in order, keeping parent linkage visible.
    let mut indexed_batch: Vec<(Hash32, BlockHeader)> = Vec::new();

    for hdr in headers.into_iter() {
        let h = header_hash(&hdr);

        if !accept_header_universe_pow(&cfg, &hdr, &h) {
            note_invalid(&mut buckets, &mut bans, peer, "headers: invalid pow/limit/universe");
            bump_score(&mut peer_score, &mut quarantine, peer, SCORE_BAD_INVALID);
            continue;
        }

        // Remember who advertised this hash.
        providers.entry(h).or_insert(peer);

        let idx_res = {
            let _g = chain_lock.lock();

            if hdr.prev == [0u8; 32] {
                index_header(&db, &hdr, None)
            } else {
                let parent = get_hidx(&db, &hdr.prev)?;
                let Some(p) = parent else {
                    // Can't index this header yet because its parent header is unknown locally.
                    continue;
                };
                index_header(&db, &hdr, Some(&p))
            }
        };

        if idx_res.is_err() {
            note_invalid(&mut buckets, &mut bans, peer, "headers: index_header failed");
            bump_score(&mut peer_score, &mut quarantine, peer, SCORE_BAD_INVALID);
            continue;
        }

        indexed_batch.push((h, hdr.clone()));

        if let Ok(Some(hi2)) = get_hidx(&db, &h) {
            if hi2.chainwork > best_hdr_work {
                best_hdr_tip = h;
                best_hdr_height = hi2.height;
                best_hdr_work = hi2.chainwork;
            }
        }

        let already_have_block = db.blocks.get(k_block(&h))?.is_some();
        let already_inflight = inflight.contains_key(&h);
        let already_pending = pending_apply.contains_key(&h);
        let already_queued = want_blocks.iter().any(|x| x == &h);

        if !already_have_block && !already_inflight && !already_pending && !already_queued {
            if want_blocks.len() < MAX_WANT_QUEUE {
                want_blocks.push_back(h);
            }
        }
    }

    // Recompute best-peer metrics.
    let (best_h, best_w_lo) = recompute_best_peer_metrics(
        &connected,
        &peer_heights,
        &peer_work,
        &bans,
        &quarantine,
    );
    best_peer_height_atomic.store(best_h, Ordering::Relaxed);
    best_peer_work_lo_atomic.store(best_w_lo, Ordering::Relaxed);

    let candidate_sync_peer = choose_best_sync_peer(
        &connected,
        &peer_work,
        &peer_score,
        &bans,
        &quarantine,
    ).or_else(|| Some(peer));

    let next_sync_peer = maybe_switch_sync_peer(
        sync_peer,
        candidate_sync_peer,
        &connected,
        &peer_work,
        &peer_score,
        &bans,
        &quarantine,
    );

    if next_sync_peer != sync_peer {
        if let Some(p) = next_sync_peer {
            println!("[sync] switching sync_peer -> {}", p);
        }
    }
    sync_peer = next_sync_peer;

    // Immediate request rule:
    // pick the FIRST missing block in this batch whose parent block is already grounded
    // locally (raw db) or already downloaded into pending_apply.
    let mut immediate_req: Option<Hash32> = None;

    for (h, hdr) in &indexed_batch {
        let already_have_block = db.blocks.get(k_block(h))?.is_some();
        let already_inflight = inflight.contains_key(h);
        let already_pending = pending_apply.contains_key(h);

        if already_have_block || already_inflight || already_pending {
            continue;
        }

        let parent_grounded = if hdr.prev == [0u8; 32] {
            true
        } else {
            db.blocks.get(k_block(&hdr.prev))?.is_some() || pending_apply.contains_key(&hdr.prev)
        };

        if parent_grounded {
            immediate_req = Some(*h);
            break;
        }
    }

    if let Some(h) = immediate_req {
        if !has_raw_or_pending(&db, &pending_apply, &h) && !inflight.contains_key(&h) {
            let request_peer = if let Some(p) = providers.get(&h) {
                if connected.contains(p)
                    && !is_banned(&bans, p)
                    && !is_quarantined(&quarantine, p)
                    && !bad_providers.get(&h).map(|s| s.contains(p)).unwrap_or(false)
                {
                    Some(*p)
                } else {
                    None
                }
            } else {
                None
            }
            .or_else(|| {
                if connected.contains(&peer)
                    && !is_banned(&bans, &peer)
                    && !is_quarantined(&quarantine, &peer)
                    && !bad_providers.get(&h).map(|s| s.contains(&peer)).unwrap_or(false)
                {
                    Some(peer)
                } else {
                    None
                }
            })
            .or_else(|| {
                sync_peer.filter(|sp| {
                    connected.contains(sp)
                        && !is_banned(&bans, sp)
                        && !is_quarantined(&quarantine, sp)
                        && !bad_providers.get(&h).map(|s| s.contains(sp)).unwrap_or(false)
                })
            });

            if let Some(req_peer) = request_peer {
                let rid = swarm
                    .behaviour_mut()
                    .rr
                    .send_request(&req_peer, SyncRequest::GetBlock { hash: h });

                println!(
                    "[sync] immediate request block {} from {}",
                    hex32(&h),
                    req_peer
                );

                rid_to_hash.insert(rid, h);
                inflight.insert(h, (rid, Instant::now(), req_peer));
            }
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
SyncResponse::Block { block } => {
    let bh = header_hash(&block.header);
    println!("[sync] got block {} from {}", hex32(&bh), peer);

    // Validate that this response matches an in-flight request
    let Some(expected_h) = rid_to_hash.remove(&rid) else {
        note_invalid(&mut buckets, &mut bans, peer, "unrequested block response");
        bump_score(&mut peer_score, &mut quarantine, peer, SCORE_BAD_UNREQUESTED_BLOCK);
        continue;
    };

    // Ensure the block hash matches what we requested
    if expected_h != bh {
        inflight.remove(&expected_h);

        note_invalid(&mut buckets, &mut bans, peer, "block response hash mismatch");
        bump_score(&mut peer_score, &mut quarantine, peer, SCORE_BAD_UNREQUESTED_BLOCK);

        bad_providers.entry(expected_h).or_default().insert(peer);

        if want_blocks.len() < MAX_WANT_QUEUE {
            want_blocks.push_back(expected_h);
        }

        continue;
    }

    mark_tip_seen(&last_tip_seen_unix);
    bump_score(&mut peer_score, &mut quarantine, peer, SCORE_GOOD_BLOCK);

                                                    if let Ok(bytes) = crate::codec::consensus_bincode().serialize(&block) {
                                                        if bytes.len() > MAX_BLOCK_BYTES {
                                                            note_invalid(&mut buckets, &mut bans, peer, "block: oversized");
                                                            bump_score(&mut peer_score, &mut quarantine, peer, SCORE_BAD_INVALID);
                                                            continue;
                                                        }
                                                    }

providers.insert(bh, peer);
want_blocks.retain(|x| *x != bh);

if let Some((_rid2, t0, asked_peer)) = inflight.remove(&expected_h) {
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

    if msg.contains("unknown block") {
        bump_score(&mut peer_score, &mut quarantine, peer, SCORE_BAD_UNKNOWN_BLOCK);

        if let Some(h) = rid_to_hash.remove(&rid) {
            println!(
                "[sync] unknown block from {} for hash={} provider={:?} sync_peer={:?}",
                peer,
                hex32(&h),
                providers.get(&h),
                sync_peer
            );

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
    } else {
        println!("[sync] error response from {peer}: {msg}");
    }

}

                                            }
                                        }



                                    }
                                }


Event::OutboundFailure { peer, request_id, error } => {
    println!("[sync] outbound failure to {}: {:?}", peer, error);

    if let Some(h) = rid_to_hash.remove(&request_id) {
        inflight.remove(&h);

        bump_score(&mut peer_score, &mut quarantine, peer, SCORE_BAD_TIMEOUT);
        bad_providers.entry(h).or_default().insert(peer);

        if providers.get(&h) == Some(&peer) {
            providers.remove(&h);
        }

        if want_blocks.len() < MAX_WANT_QUEUE {
            want_blocks.push_back(h);
        }

        println!("[sync] requeued {} after outbound failure", hex32(&h));
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

Event::InboundFailure { peer, error, .. } => {
            println!("[sync] inbound failure from {}: {:?}", peer, error);
            bump_score(&mut peer_score, &mut quarantine, peer, SCORE_BAD_INVALID);
        }

        _ => {}
    }
}

                        // Penalize timeouts
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
            let max = max.min(MAX_HEADERS_PER_SYNC);

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
            let max = max.min(MAX_HEADERS_PER_SYNC);

            let locator = if locator.len() > MAX_LOCATOR_LEN {
                locator.into_iter().take(MAX_LOCATOR_LEN).collect::<Vec<_>>()
            } else {
                locator
            };

            let tip = get_tip(db)?.unwrap_or([0u8; 32]);
            if tip == [0u8; 32] {
                return Ok(SyncResponse::Headers { headers: vec![] });
            }

            // Find the first locator hash we actually know.
            let mut anchor_hash: Option<Hash32> = None;
            let mut anchor_height: Option<u64> = None;

            for h in locator {
                if h == [0u8; 32] {
                    anchor_hash = Some([0u8; 32]);
                    anchor_height = Some(0);
                    break;
                }
                if let Ok(Some(hi)) = get_hidx(db, &h) {
                    anchor_hash = Some(h);
                    anchor_height = Some(hi.height);
                    break;
                }
            }

            let Some(anchor_h) = anchor_height else {
                return Ok(SyncResponse::Headers { headers: vec![] });
            };

            // Build canonical path from tip back to anchor, then reverse it so we can
            // return the NEXT contiguous chunk after the anchor.
            let mut rev_path: Vec<(Hash32, BlockHeader, u64)> = Vec::new();
            let mut cur = tip;

            while cur != [0u8; 32] {
                let hi = get_hidx(db, &cur)?
                    .ok_or_else(|| anyhow::anyhow!("missing idx for {}", hex32(&cur)))?;

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

                rev_path.push((cur, blk.header.clone(), hi.height));

                if hi.height <= anchor_h {
                    break;
                }

                cur = hi.parent;
            }

            rev_path.reverse();

            let mut out: Vec<BlockHeader> = Vec::new();
            for (_h, hdr, hgt) in rev_path {
                if hgt <= anchor_h {
                    continue;
                }
                out.push(hdr);
                if out.len() as u64 >= max {
                    break;
                }
            }

            println!(
                "[sync-serve] GetHeadersByLocator: anchor_h={} returning={} tip={}",
                anchor_h,
                out.len(),
                hex32(&tip),
            );

            Ok(SyncResponse::Headers { headers: out })
        }

SyncRequest::GetBlock { hash } => {
    println!("[sync-serve] GetBlock lookup {}", hex32(&hash));

    let Some(v) = db.blocks.get(k_block(&hash))? else {
        println!("[sync-serve] GetBlock MISS {}", hex32(&hash));
        bail!("unknown block");
    };

    println!(
        "[sync-serve] GetBlock HIT {} bytes={}",
        hex32(&hash),
        v.len()
    );

    if v.len() > MAX_BLOCK_BYTES {
        bail!("db corruption: stored block exceeds MAX_BLOCK_BYTES");
    }

    let blk: Block = crate::codec::consensus_bincode().deserialize::<Block>(&v)?;
    Ok(SyncResponse::Block { block: blk })
}


        SyncRequest::SubmitTx { tx: _tx } => Ok(SyncResponse::Ack),
    }
}
