// src/net/node.rs

use crate::chain::pow::{bits_within_pow_limit, pow_ok};
use anyhow::{bail, Context, Result};
use futures::StreamExt;
use futures::{AsyncReadExt, AsyncWriteExt};
use libp2p::{
    core::upgrade,
    gossipsub::{self, IdentTopic, MessageAuthenticity, ValidationMode},
    identify,
    identity, noise,
    request_response::{self, ProtocolSupport},
    swarm::{ConnectionError, ConnectionId, NetworkBehaviour, Swarm, SwarmEvent},
    tcp, yamux, Multiaddr, PeerId, Transport,
};

use std::{
    collections::{HashMap, HashSet, VecDeque},
    net::{Ipv4Addr, Ipv6Addr},
    sync::{
        atomic::{AtomicU64, AtomicUsize, Ordering},
        Arc,
    },
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

use tokio::time::{interval, MissedTickBehavior};
use tokio::sync::RwLock;

use bincode::Options;

use crate::{
    chain::index::{get_hidx, header_hash, index_header, HeaderIndex},
    chain::lock::ChainLock,
    net::mempool::Mempool,
    params::{MAX_BLOCK_BYTES, MAX_TX_BYTES},
    state::db::{get_tip, k_block, Stores},
    types::{Block, BlockHeader, Hash32, OutPoint, Transaction},
};

use super::proto::*;
use super::background::{Asked, Background, CEILING as BACKGROUND_CEILING};
use super::serve_log::{peer_gone, peer_line, peer_lines_tick, Line};
use super::unreported::Unreported;
use super::{GossipTxEvent, MinedHeaderEvent};

const SYNC_PROTOCOL: &str = SYNC_PROTO;

// ----------------- hardening constants -----------------

// Upstream's request-response cap (v1.1.2 node.rs:48, unchanged at main d168f70): no message of
// this node or upstream's comes near it (a full headers answer is 86,028 bytes, a full peers answer
// 512 addresses, a tx at most MAX_TX_BYTES, a block from this miner below `template_byte_cap`)
// except a block above 1 MiB, which consensus admits up to MAX_BLOCK_BYTES and no upstream node can
// fetch or serve. A larger cap here would let this node serve such a block while upstream nodes
// cannot, which puts it on the other side of the split such a block makes; with the same cap no
// node reads or writes one. Such a block on the network holds the tip at its parent; the remaining
// split is upstream's own 2 MiB consensus cap against its 1 MiB transport (docs/behaviour.md
// "Transport cap and blocks above 1 MiB").
const MAX_RR_MSG_BYTES: u64 = 1024 * 1024;
/// `read_response`'s refusal of a response at or above MAX_RR_MSG_BYTES (upstream's text).
const RESPONSE_TOO_LARGE: &str = "response too large";

const MAX_GOSSIP_MSG_BYTES: usize = 256 * 1024; // 256 KiB

const RL_WINDOW: Duration = Duration::from_secs(10);
// Requests one peer may send this node in one RL_WINDOW before the rest of its
// window is throttled (`allow_rr_req_at`; never banned), in every mode: upstream's own bootnode figure
// (d168f70 `src/net/node.rs:54`; its other nodes ban past 120, :53). A lower figure can refuse honest
// upstream nodes: their pacer map is a thread_local (:1054-1079) read from a loop spawned on a
// multi-thread runtime (:2529), so a loop polled on several worker threads paces each thread's sends
// apart and can pass 120, well past it with several threads, in one of our
// windows (docs/behaviour.md "Outbound pacing"). 1,200 is itself a threshold, not a ceiling: about 180
// per upstream worker thread fit in one of our windows, so a node of 7 or more cores catching up from
// us could pass it (derived, not measured). Past the figure the requester is answered "rate
// limited" for the rest of the window; its Err arm (:4541-4559) stamps us a bad provider of a
// requested block for 120 s (:84, :2036) and asks another peer for it. What the figure still bounds is
// one identity's answers in a window, the cheap ones (GetTip, GetPeers on the loop) included: past it
// a request costs a decode and an Err answer. The serving cost is bounded by the one serve permit
// (`Serves`) and the four streams a connection runs (two connections a peer), not by this figure.
const RL_MAX_RR_REQS_PER_WINDOW: u32 = 1_200;
/// The ban an upstream server applies (d168f70 `src/net/node.rs:53`), which our requester's pacing
/// stays under (`pace_saturated`); the pacing tests model an upstream server with it.
#[cfg(test)]
const UPSTREAM_RR_REQS_PER_WINDOW: u32 = 120;
const RL_MAX_GOSSIP_MSGS_PER_WINDOW: u32 = 1024;
// A forwarder's gossip txs that their check did not admit (a refusal, a conflict with a held tx, a
// byte-different copy of one) are charged their inputs, the unit of a check's cost (one spent-output
// read and one signature check each, the sighash once per tx). Once this many are charged in one
// RL_WINDOW, the forwarder's next txs are dropped unchecked and the forwarder kept, as past the
// message budget (the message budget alone lets 1,024 refusals of 512-input txs through a window).
// Admitted txs cost an honest relay nothing here. The budget is read when a tx arrives and charged
// when its check returns, so a forwarder gets about eight full-width refusals (4,096 /
// MAX_TX_INPUTS) checked plus whatever of its txs are queued or running when its charge lands, up
// to the queue's 16 full-width txs and the 2 running. The total cost stays capped by
// GOSSIP_TX_CHECKS_IN_FLIGHT and GOSSIP_TX_CHECK_QUEUE_INPUTS; under a flood from many forwarders
// the cost is honest gossip txs dropped at this node, not the p2p loop.
const RL_MAX_GOSSIP_TX_INPUTS_PER_WINDOW: u32 = 4_096;
// Gossip tx checks run on the blocking pool, at most this many at once, so the p2p loop does not
// wait on one; at most GOSSIP_TX_CHECK_QUEUE_INPUTS inputs wait for a turn, and a tx past that is
// dropped unchecked with no strike (the forwarder may be an honest relay).
const GOSSIP_TX_CHECKS_IN_FLIGHT: usize = 2;
const GOSSIP_TX_CHECK_QUEUE_INPUTS: usize = 8_192;
// csd-patches: a catching-up node must not ban its OWN sync peers for normal
// catch-up noise (unvalidatable mempool txs, oversized header requests). Stock 3
// collapses peers to 0. Steady state stays far under this.
const RL_MAX_INVALID_PER_WINDOW: u32 = 32;

const BAN_SECS: u64 = 10 * 60;

// ----------------- production upgrades -----------------

const SCORE_GOOD_BLOCK: i32 = 3;

const SCORE_GOOD_CANONICAL_BLOCK: i32 = 12;

const OUTBOUND_MAX_RR_PER_PEER_PER_WINDOW: u32 = 90;

const SCORE_BAD_INVALID: i32 = -6;
const SCORE_BAD_TIMEOUT: i32 = -1;
const SCORE_BAD_UNREQUESTED_BLOCK: i32 = -8;
const SCORE_BAD_OVERSIZED_HEADERS: i32 = -6;

const TIP_POLL_SECS: u64 = 120;
const REGULAR_TIP_POLL_SECS: u64 = 10;

const BAD_PROVIDER_RETRY_SECS: u64 = 120;

// quarantine: soft-ban for a while when score too low
const QUAR_SECS: u64 = 5 * 60;
const QUAR_SCORE_THRESHOLD: i32 = -30;
/// A score stays within [SCORE_MIN, SCORE_MAX] and moves toward zero every SCORE_DECAY_EVERY_SECS
/// (`decay_scores`). The ceiling is twice the threshold's size, so a peer at the ceiling is
/// quarantined on its fifteenth SCORE_BAD_INVALID in a row; without it a peer that forwarded
/// headers or served a long sync gathered tens of thousands of points and could never be
/// quarantined, and outranked every honest peer in the cap evictor.
const SCORE_MAX: i32 = 60;
const SCORE_MIN: i32 = -90;
const SCORE_DECAY_EVERY_SECS: u64 = 60;

const SCORE_BAD_STALE_PEER: i32 = -2;
const STALE_PEER_LAG_BLOCKS: u64 = 12;
const STALE_PEER_PENALTY_COOLDOWN_SECS: u64 = 60;

// ----------------- dial backoff tuning -----------------

const REDIAL_EVERY_SECS: u64 = 30;
const DIAL_BACKOFF_SECS: u64 = 20;

// ----------------- sync bounds -----------------

const MAX_HEADERS_PER_SYNC: u64 = 1024;
const MAX_LOCATOR_LEN: usize = 128;
const MAX_INFLIGHT_BLOCKS: usize = 8;
// Block requests in flight to one peer. The request-response handler runs at most
// `with_max_concurrent_streams` (4) streams on a connection, inbound and outbound together, and
// refuses an outbound request past that on our side (libp2p-request-response 0.30.0
// handler.rs:200-209); the other two are left for tip, header and peer requests and for the
// peer's own requests.
const MAX_BLOCK_REQUESTS_PER_PEER: usize = 2;
// How long a peer whose connection refused one of our requests for lack of streams is passed over
// for block requests (`note_streams_full`).
const STREAMS_FULL_MS: u64 = 1_000;
const MAX_WANT_QUEUE: usize = 5_000;
// A block request the request-response layer has not reported on within this is dropped from
// `inflight` and requeued, blaming nobody. The layer fails every request on a live connection
// within about 25 s (a 10 s stream upgrade, libp2p-swarm 0.48.0 handler.rs:542, then the 15 s
// request timeout), and its OutboundFailure is where a slow peer is scored and stamped; this only
// frees a slot whose report never came.
const BLOCK_REQ_TIMEOUT_SECS: u64 = 60;
// csd-patches: after a peer replies "historical block serving disabled" it serves
// headers only, not old blocks; skip it for block requests for this long so the
// scheduler converges onto the few archive peers instead of wasting inflight slots.
const HEADER_ONLY_COOLDOWN_SECS: u64 = 300;

const MAX_DIALS_PER_POLL: usize = 8;
// csd-patches: hard cap on concurrent pending (SYN-SENT) outbound dials. Peers
// advertise many unreachable/NAT'd addrs; each stuck dial lingers ~127s (kernel
// TCP timeout), so without a total cap they pile into the hundreds (measured 365)
// and saturate the single-threaded swarm loop, starving block-sync response
// processing. But too LOW a cap starves peer discovery: we then hold too few
// peers and stall whenever our lone archive peer drops. 128 acquires ~24 peers in
// a few minutes (enough to hold 2-4 archive peers for resilience), then dialing
// subsides as connected reaches MAX_CONNECTED_PEERS and CPU frees for block work.
const MAX_PENDING_OUTGOING_DIALS: usize = 128;
const MAX_DIALS_FROM_PEERS_RESPONSE: usize = 8;
const MAX_STARTUP_DIALS: usize = 16;

const MAX_KNOWN_PEERS: usize = 128;
/// Consecutive dial timeouts after which an address leaves the address book.
const ADDR_TIMEOUTS_TO_EVICT: u8 = 3;
/// Timeouts never shrink the book below this many peers.
const MIN_KNOWN_PEERS_KEPT: usize = 32;
/// New peers one Peers response may add to the book; the rest of the response is discarded.
const MAX_NEW_PEERS_PER_RESPONSE: usize = 16;

const MAX_PENDING_APPLY: usize = 512;
const MAX_PROVIDERS: usize = 50_000;
const MAX_SEEN_BLOCKS: usize = 50_000;

const HEADERS_REQ_COOLDOWN_SECS: u64 = 20;

const MAX_PEERS_IN_EXCHANGE: usize = 64;
const PEER_REQ_ON_CONNECT: u16 = 64;
const PEER_REDIAL_EVERY_SECS: u64 = 15;
const MAX_ADDRS_PER_PEER: usize = 8;
const BOOTSTRAP_REQ_COOLDOWN_SECS: u64 = 30;
const PEER_DISCONNECT_COOLDOWN_SECS: u64 = 20;

const COLD_START_SECS: u64 = 180;
const COLD_START_MIN_PEERS: usize = 12;

const MIN_OUTBOUND_PEERS: usize = 8;

/// Publish the `outbound` set size for /node/info. Called at every change
/// to the set. A peer stays in the set until its LAST connection closes, so a lingering dialer
/// connection keeps it counted and the gauge can over-count.
fn store_outbound_gauge(gauge: &AtomicUsize, outbound: &HashSet<PeerId>) {
    gauge.store(outbound.len(), Ordering::Relaxed);
}
const PEERS_FILE: &str = "peers.txt";
const SAVE_PEERS_EVERY_SECS: u64 = 30;

const PEER_SCORES_FILE: &str = "peer_scores.txt";

const STARTUP_PREFERRED_PEERS: usize = 16;

const MAX_CONNECTED_PEERS: usize = 32;
const TARGET_CONNECTED_PEERS: usize = 24;
const PROTECT_NEW_PEER_SECS: u64 = 60;
const PEER_CAP_BURST: usize = 64;
/// Inbound places the poll tick keeps free under the inbound cap (`inbound_cap`), for the connections
/// that arrive before the next tick: past `inbound_cap - INBOUND_RESERVE` established inbound
/// connections it sheds second inbound connections (`maybe_shed_second_inbound`).
const INBOUND_RESERVE: usize = PEER_CAP_BURST / 2;

const BOOTNODE_MAX_CONNECTED: usize = 64;
const BOOTNODE_TARGET_CONNECTED: usize = 48;
const BOOTNODE_PROTECT_NEW_SECS: u64 = 60;
const BOOTNODE_IDLE_EVICT_SECS: u64 = 120;
const BOOTNODE_SYNC_ACTIVE_SECS: u64 = 60;

const IDLE_PEER_MIN_AGE_SECS: u64 = 5 * 60;
const IDLE_PEER_EVICT_SECS: u64 = 10 * 60;
const IDLE_PEER_NEAR_BEST_WORK_DIVISOR: u128 = 1000;

// Optional runtime override of the connected-peer cap via CSD_MAX_PEERS, so ONE binary serves
// both roles: a high cap on a well-connected node, a low cap on a miner or fallback node. Read once
// and cached. Safe to raise only because gossipsub (0.48 and later) bounds the per-peer send queue
// (0.50.1 queue.rs:36-84). Unset => identical to the compile-time defaults above (no behavior
// change).
fn peer_cap_override() -> Option<usize> {
    use std::sync::OnceLock;
    static V: OnceLock<Option<usize>> = OnceLock::new();
    *V.get_or_init(|| {
        std::env::var("CSD_MAX_PEERS")
            .ok()
            .and_then(|s| s.trim().parse::<usize>().ok())
            .filter(|&n| n > 0)
    })
}

fn effective_max_connected(is_bootnode: bool) -> usize {
    peer_cap_override().unwrap_or(if is_bootnode {
        BOOTNODE_MAX_CONNECTED
    } else {
        MAX_CONNECTED_PEERS
    })
}

/// Established inbound connections admitted (`admission::ConnectionCaps`): the peer cap plus its
/// burst, the count at which the connect arm drops a new peer, as upstream's arm does (d168f70
/// node.rs:3212-3229); our own dials are not counted.
fn inbound_cap(is_bootnode: bool) -> usize {
    effective_max_connected(is_bootnode).saturating_add(PEER_CAP_BURST)
}

fn effective_target_connected(is_bootnode: bool) -> usize {
    // Hold ~7/8 of the cap before the evictor trims, so the node sustains near its cap instead of
    // oscillating down to a fixed low target.
    if let Some(c) = peer_cap_override() {
        return c.saturating_sub(c / 8).max(1);
    }
    if is_bootnode {
        BOOTNODE_TARGET_CONNECTED
    } else {
        TARGET_CONNECTED_PEERS
    }
}

// Runtime kill-switches for the two behavioural sync changes, so they can be
// A/B-benchmarked within one binary and disabled without a rebuild. Both default ON. Read once, cached.
fn env_flag_on(key: &str) -> bool {
    std::env::var(key).map(|s| s.trim() != "0").unwrap_or(true)
}
fn gossip_fetch_enabled() -> bool {
    use std::sync::OnceLock;
    static V: OnceLock<bool> = OnceLock::new();
    // Default OFF. In a sparse mesh of 2-4 peers the gossip announcer (propagation_source) is
    // frequently a FORWARDER that relayed the header before it holds the block, so eager-fetching from
    // it wastes a request and can 120s-bad-stamp one of the few peers that serve old blocks.
    // Present + A/B-benchmarkable; enable with CSD_GOSSIP_FETCH=1 where the mesh is denser (opt-in
    // tip-latency win).
    *V.get_or_init(|| std::env::var("CSD_GOSSIP_FETCH").map(|s| s.trim() == "1").unwrap_or(false))
}

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

fn peers_path(datadir: &str) -> std::path::PathBuf {
    std::path::PathBuf::from(datadir).join(PEERS_FILE)
}

fn load_known_addrs(datadir: &str, self_peer: PeerId) -> HashMap<PeerId, HashSet<Multiaddr>> {
    let mut out: HashMap<PeerId, HashSet<Multiaddr>> = HashMap::new();
    let p = peers_path(datadir);

    let Ok(s) = std::fs::read_to_string(&p) else {
        return out;
    };

    for line in s.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }

        let Ok(addr) = line.parse::<Multiaddr>() else {
            continue;
        };

        let Some(pid) = peer_id_from_multiaddr(&addr) else {
            continue;
        };

if should_store_discovered_addr(self_peer, pid, &addr) {
    insert_known_addr(&mut out, pid, addr);
}

    }

    out
}

fn save_known_addrs(datadir: &str, self_peer: PeerId, known_addrs: &HashMap<PeerId, HashSet<Multiaddr>>) {
    let p = peers_path(datadir);
    let tmp = p.with_extension("tmp");

    let mut lines: Vec<String> = Vec::new();

    let mut peers: Vec<PeerId> = known_addrs.keys().copied().collect();
    peers.sort_by(|a, b| a.to_string().cmp(&b.to_string()));

    for pid in peers {
        if pid == self_peer {
            continue;
        }

        let mut addrs: Vec<Multiaddr> = known_addrs
            .get(&pid)
            .map(|s| s.iter().cloned().collect())
            .unwrap_or_default();

        addrs.sort_by(|a, b| a.to_string().cmp(&b.to_string()));

        for addr in addrs {
            if should_store_discovered_addr(self_peer, pid, &addr) {
                lines.push(addr.to_string());
            }
        }
    }

    let body = lines.join("\n");
    if std::fs::write(&tmp, body).is_ok() {
        let _ = std::fs::rename(&tmp, &p);
    }
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
    scores: &mut HashMap<PeerId, i32>,
    connected: &HashSet<PeerId>,
    open: &HashSet<PeerId>,
) {
    // A ban is kept while its peer holds any connection, counted or not (`open`, the swarm's view):
    // the poll tick closes those (`banned_with_connections`), and the ban must not lapse first.
    bans.retain(|p, t| connected.contains(p) || open.contains(p) || t.elapsed().as_secs() < BAN_SECS);
    quarantine.retain(|p, t| connected.contains(p) || t.elapsed().as_secs() < QUAR_SECS);
    buckets.retain(|p, b| connected.contains(p) || b.window_start.elapsed() < RL_WINDOW);

    // peer_score is the one strike map with no expiry of its own, and
    // `bump_score` is its only writer, so without this retain the map keeps one entry per distinct
    // PeerId ever scored, for the life of the process. Connection churn on fresh keypairs is still
    // a live source of those entries, so this is the bound. Placed AFTER the three retains above so
    // it cannot resurrect a key that just expired.
    //
    // WHAT IT COSTS, plainly: this is NOT invisible to behaviour. `bump_score` accumulates through
    // `entry(p).or_insert(0)`, so dropping a key resets that peer's strike ladder. A peer that has
    // worked its way to -24 (four SCORE_BAD_INVALID, one strike short of the -30 quarantine
    // threshold), then disconnects and stays away until its ban, quarantine and rate-bucket entries
    // have all expired, reconnects at 0 rather than -24 and has to earn the ladder again. Live bans
    // and quarantines are unaffected: while either holds, the key is retained with its score.
    scores.retain(|p, _| {
        connected.contains(p)
            || bans.contains_key(p)
            || quarantine.contains_key(p)
            || buckets.contains_key(p)
    });
}

fn prune_bad_providers(
    bad_providers: &mut HashMap<Hash32, HashMap<PeerId, Instant>>,
) {
    bad_providers.retain(|_, peers| {
        peers.retain(|_, t| t.elapsed().as_secs() < BAD_PROVIDER_RETRY_SECS);
        !peers.is_empty()
    });
}

fn prune_ephemeral_sync_state(
    db: &Stores,
    pending_apply: &mut HashMap<Hash32, Block>,
    providers: &mut HashMap<Hash32, PeerId>,
    seen_blocks: &mut HashSet<Hash32>,
) {
    let (_tip, _height, local_work) = local_tip_and_work(db);

    pending_apply.retain(|h, _| {
        get_hidx(db, h)
            .ok()
            .flatten()
            .map(|hi| hi.chainwork > local_work)
            .unwrap_or(false)
    });

    if pending_apply.len() > MAX_PENDING_APPLY {
        let mut keep: Vec<(Hash32, u128)> = pending_apply
            .keys()
            .filter_map(|h| get_hidx(db, h).ok().flatten().map(|hi| (*h, hi.chainwork)))
            .collect();

        keep.sort_by(|a, b| b.1.cmp(&a.1));
        keep.truncate(MAX_PENDING_APPLY);

        let keep_set: HashSet<Hash32> = keep.into_iter().map(|x| x.0).collect();
        pending_apply.retain(|h, _| keep_set.contains(h));
    }

    providers.retain(|h, _| {
        get_hidx(db, h)
            .ok()
            .flatten()
            .map(|hi| hi.chainwork > local_work)
            .unwrap_or(false)
    });

    if providers.len() > MAX_PROVIDERS {
        providers.clear();
    }

    if seen_blocks.len() > MAX_SEEN_BLOCKS {
        seen_blocks.clear();
    }
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

fn maybe_evict_bootnode_peers(
    swarm: &mut Swarm<Behaviour>,
    closing: &mut HashMap<PeerId, &'static str>,
    cfg: &NetConfig,
    connected: &HashSet<PeerId>,
    connected_since: &HashMap<PeerId, Instant>,
    last_sync_request_from: &HashMap<PeerId, Instant>,
    peer_heights: &HashMap<PeerId, u64>,
    local_height: u64,
) {
    if !cfg.is_bootnode {
        return;
    }

    if connected.len() <= BOOTNODE_MAX_CONNECTED {
        return;
    }

    println!(
        "[bootnode] over capacity: connected={} max={} target={}",
        connected.len(),
        BOOTNODE_MAX_CONNECTED,
        BOOTNODE_TARGET_CONNECTED
    );

    let now = Instant::now();
    let over = connected.len().saturating_sub(BOOTNODE_TARGET_CONNECTED);

    let mut candidates: Vec<(PeerId, u8, u64)> = Vec::new();

    for p in connected.iter().copied() {
        let age = connected_since
            .get(&p)
            .map(|t| now.duration_since(*t).as_secs())
            .unwrap_or(u64::MAX);

        if age < BOOTNODE_PROTECT_NEW_SECS {
            continue;
        }

        let sync_recent = last_sync_request_from
            .get(&p)
            .map(|t| now.duration_since(*t).as_secs() < BOOTNODE_SYNC_ACTIVE_SECS)
            .unwrap_or(false);

        if sync_recent {
            continue;
        }

        let ph = *peer_heights.get(&p).unwrap_or(&0);
        let near_tip = local_height > 0 && ph.saturating_add(2) >= local_height;

        let idle_secs = last_sync_request_from
            .get(&p)
            .map(|t| now.duration_since(*t).as_secs())
            .unwrap_or(u64::MAX);

        if idle_secs < BOOTNODE_IDLE_EVICT_SECS && !near_tip {
            continue;
        }

        let class = if near_tip { 2 } else { 1 };
        candidates.push((p, class, age));
    }

candidates.sort_by(|a, b| {
    a.1.cmp(&b.1)
        .then_with(|| b.2.cmp(&a.2))
        .then_with(|| a.0.to_string().cmp(&b.0.to_string()))
});

    let selected: Vec<(PeerId, u8, u64)> = candidates.into_iter().take(over).collect();

    for (p, class, age) in selected.iter().copied() {
        if let Some(n) = peer_line(&p, Line::Evict) {
            println!("[bootnode] evicting peer {p} class={class} age={age}s to free bootstrap capacity since_last_line={n}");
        }
        disconnect_peer(swarm, closing, p, "bootnode capacity");
    }

    if selected.len() < over {
        let mut fallback: Vec<PeerId> = connected.iter().copied().collect();
        fallback.sort_by(|a, b| a.to_string().cmp(&b.to_string()));

        for p in fallback.into_iter().take(over - selected.len()) {
            if let Some(n) = peer_line(&p, Line::Evict) {
                println!("[bootnode] hard-cap evicting peer {p} since_last_line={n}");
            }
            disconnect_peer(swarm, closing, p, "bootnode hard cap");
        }
    }
}

/// The connected peers the cap evictors may shed, worst first: lower score, then lower work, then
/// older. Never a peer younger than PROTECT_NEW_PEER_SECS, and never one we dialed unless it is banned
/// or quarantined.
fn cap_eviction_order(
    connected: &HashSet<PeerId>,
    connected_since: &HashMap<PeerId, Instant>,
    peer_score: &HashMap<PeerId, i32>,
    peer_work: &HashMap<PeerId, u128>,
    outbound: &HashSet<PeerId>,
    bans: &HashMap<PeerId, Instant>,
    quarantine: &HashMap<PeerId, Instant>,
) -> Vec<(PeerId, i32, u128, u64)> {
    let now = Instant::now();
    let mut candidates: Vec<(PeerId, i32, u128, u64)> = connected
        .iter()
        .copied()
        .filter_map(|p| {
            // Never evict a peer WE dialed for being over-cap (anti-eclipse): an attacker floods
            // inbound to push our chosen peers out, and this makes them unshakeable, EXCEPT when that
            // dialed peer has itself misbehaved (banned or quarantined): then it loses its protection
            // and can be shed (a misbehaving peer must not be eviction-immune).
            if outbound.contains(&p) && !is_banned(bans, &p) && !is_quarantined(quarantine, &p) {
                return None;
            }

            let age = connected_since
                .get(&p)
                .map(|t| now.duration_since(*t).as_secs())
                .unwrap_or(u64::MAX);

            if age < PROTECT_NEW_PEER_SECS {
                return None;
            }

            let score = *peer_score.get(&p).unwrap_or(&0);
            let work = *peer_work.get(&p).unwrap_or(&0);

            Some((p, score, work, age))
        })
        .collect();

    // Evict worst first:
    // lower score first, then lower work, then oldest.
    candidates.sort_by(|a, b| {
        a.1.cmp(&b.1)
            .then_with(|| a.2.cmp(&b.2))
            .then_with(|| b.3.cmp(&a.3))
            .then_with(|| a.0.to_string().cmp(&b.0.to_string()))
    });
    candidates
}

fn maybe_evict_excess_peers(
    swarm: &mut Swarm<Behaviour>,
    closing: &mut HashMap<PeerId, &'static str>,
    cfg: &NetConfig,
    connected: &HashSet<PeerId>,
    connected_since: &HashMap<PeerId, Instant>,
    peer_score: &HashMap<PeerId, i32>,
    peer_work: &HashMap<PeerId, u128>,
    outbound: &HashSet<PeerId>,
    bans: &HashMap<PeerId, Instant>,
    quarantine: &HashMap<PeerId, Instant>,
) {
    let max_connected = effective_max_connected(cfg.is_bootnode);

    let target_connected = effective_target_connected(cfg.is_bootnode);

    if connected.len() <= max_connected {
        return;
    }

    println!(
        "[p2p] over peer cap: connected={} max={} target={}",
        connected.len(),
        max_connected,
        target_connected
    );

    let over = connected.len().saturating_sub(target_connected);
    let candidates = cap_eviction_order(connected, connected_since, peer_score, peer_work, outbound, bans, quarantine);

    for (p, score, work, age) in candidates.into_iter().take(over) {
        if let Some(n) = peer_line(&p, Line::Evict) {
            println!("[p2p] cap evicting peer {p} score={score} work={work} age={age}s since_last_line={n}");
        }
        disconnect_peer(swarm, closing, p, "over the peer cap");
    }
}

/// Sheds second inbound connections while the established inbound connections,
/// less those of peers being closed and those shed already, pass `inbound_cap - INBOUND_RESERVE`. The
/// inbound cap counts connections and `maybe_evict_excess_peers` counts peers, so peers holding two
/// inbound connections each could fill the cap at the peer cap's count, where nothing is evicted, and
/// refuse every new connection for as long as they stayed: on a default bootnode 64 identities from
/// 16 addresses fill its 128 places. A peer's second connection goes, and
/// the peer keeps its first; peers in the evictor's order (`cap_eviction_order`: never one younger
/// than PROTECT_NEW_PEER_SECS or one we dialed unless banned or quarantined), worst first. Whole peers
/// are not shed for connection pressure: past the second connections only peers holding one are left,
/// and the peer cap's evictor sheds those when there are more than the cap.
fn maybe_shed_second_inbound(
    swarm: &mut Swarm<Behaviour>,
    closing: &HashMap<PeerId, &'static str>,
    shed: &mut HashMap<ConnectionId, &'static str>,
    cfg: &NetConfig,
    connected: &HashSet<PeerId>,
    connected_since: &HashMap<PeerId, Instant>,
    peer_score: &HashMap<PeerId, i32>,
    peer_work: &HashMap<PeerId, u128>,
    outbound: &HashSet<PeerId>,
    bans: &HashMap<PeerId, Instant>,
    quarantine: &HashMap<PeerId, Instant>,
) {
    let caps = &swarm.behaviour().limits;
    let leaving: usize = closing.keys().map(|p| caps.inbound_of(p).len()).sum::<usize>() + shed.len();
    let open = caps.inbound().saturating_sub(leaving);
    let keep = inbound_cap(cfg.is_bootnode).saturating_sub(INBOUND_RESERVE);
    if open <= keep {
        return;
    }
    let second: Vec<(PeerId, ConnectionId)> = cap_eviction_order(connected, connected_since, peer_score, peer_work, outbound, bans, quarantine)
        .into_iter()
        .filter(|(p, ..)| !closing.contains_key(p))
        .filter_map(|(p, ..)| caps.second_inbound(&p).filter(|c| !shed.contains_key(c)).map(|c| (p, c)))
        .take(open - keep)
        .collect();
    if second.is_empty() {
        return;
    }
    println!(
        "[p2p] over the inbound reserve: inbound connections={open} keep={keep}, shedding {} second inbound connections",
        second.len()
    );
    for (p, c) in second {
        if swarm.close_connection(c) {
            if let Some(n) = peer_line(&p, Line::Evict) {
                println!("[p2p] shedding the second inbound connection of {p} since_last_line={n}");
            }
            shed.insert(c, "a second inbound connection, shed at the inbound reserve");
        }
    }
}

fn maybe_evict_idle_peers(
    swarm: &mut Swarm<Behaviour>,
    closing: &mut HashMap<PeerId, &'static str>,
    cfg: &NetConfig,
    connected: &HashSet<PeerId>,
    connected_since: &HashMap<PeerId, Instant>,
    last_useful_peer_at: &HashMap<PeerId, Instant>,
    peer_score: &HashMap<PeerId, i32>,
    peer_work: &HashMap<PeerId, u128>,
    best_work: u128,
) {
    let target_connected = effective_target_connected(cfg.is_bootnode);

    if connected.len() <= target_connected {
        return;
    }

    let now = Instant::now();
    let over = connected.len().saturating_sub(target_connected);

    let near_best_slack = if best_work > 0 {
        best_work / IDLE_PEER_NEAR_BEST_WORK_DIVISOR
    } else {
        0
    };

    let mut candidates: Vec<(PeerId, u64, i32, u128)> = Vec::new();

    for p in connected.iter().copied() {
        let age = connected_since
            .get(&p)
            .map(|t| now.duration_since(*t).as_secs())
            .unwrap_or(u64::MAX);

        if age < IDLE_PEER_MIN_AGE_SECS {
            continue;
        }

        let idle_secs = last_useful_peer_at
            .get(&p)
            .map(|t| now.duration_since(*t).as_secs())
            .unwrap_or(age);

        if idle_secs < IDLE_PEER_EVICT_SECS {
            continue;
        }

        let work = *peer_work.get(&p).unwrap_or(&0);
        let score = *peer_score.get(&p).unwrap_or(&0);

        let near_best =
            best_work > 0 && work > 0 && work.saturating_add(near_best_slack) >= best_work;

        if near_best && score >= 0 {
            continue;
        }

        candidates.push((p, idle_secs, score, work));
    }

    candidates.sort_by(|a, b| {
        a.2.cmp(&b.2)
            .then_with(|| a.3.cmp(&b.3))
            .then_with(|| b.1.cmp(&a.1))
            .then_with(|| a.0.to_string().cmp(&b.0.to_string()))
    });

    for (p, idle_secs, score, work) in candidates.into_iter().take(over) {
        if let Some(n) = peer_line(&p, Line::Evict) {
            println!("[p2p] idle evicting peer {p} idle={idle_secs}s score={score} work={work} target={target_connected} since_last_line={n}");
        }
        disconnect_peer(swarm, closing, p, "idle");
    }
}

fn with_p2p_suffix(mut addr: Multiaddr, peer: PeerId) -> Multiaddr {
    use libp2p::multiaddr::Protocol;
    let already_has_p2p = addr.iter().any(|p| matches!(p, Protocol::P2p(_)));
    if !already_has_p2p {
        addr.push(Protocol::P2p(peer.into()));
    }
    addr
}

fn strip_p2p_suffix(addr: &Multiaddr) -> Multiaddr {
    use libp2p::multiaddr::Protocol;
    let mut out = Multiaddr::empty();
    for p in addr.iter() {
        if matches!(p, Protocol::P2p(_)) {
            break;
        }
        out.push(p);
    }
    out
}

fn is_dialable_addr(addr: &Multiaddr) -> bool {
    use libp2p::multiaddr::Protocol;

    let mut has_ip_or_dns = false;
    let mut tcp_port: Option<u16> = None;

    for p in addr.iter() {
        match p {
            Protocol::Ip4(_)
            | Protocol::Ip6(_)
            | Protocol::Dns(_)
            | Protocol::Dns4(_)
            | Protocol::Dns6(_)
            | Protocol::Dnsaddr(_) => has_ip_or_dns = true,
            Protocol::Tcp(port) => tcp_port = Some(port),
            _ => {}
        }
    }

    has_ip_or_dns && tcp_port.map(|p| p > 0).unwrap_or(false)
}

fn is_routable_ipv4(ip: Ipv4Addr) -> bool {
    let o = ip.octets();

    let is_this_network = o[0] == 0;                                // 0.0.0.0/8
    let is_reserved = o[0] >= 240;                                  // 240.0.0.0/4, broadcast included
    let is_cgnat = o[0] == 100 && (64..=127).contains(&o[1]);       // 100.64.0.0/10
    let is_benchmark = o[0] == 198 && (18..=19).contains(&o[1]);    // 198.18.0.0/15
    let is_doc =
        (o[0] == 192 && o[1] == 0 && o[2] == 2)
        || (o[0] == 198 && o[1] == 51 && o[2] == 100)
        || (o[0] == 203 && o[1] == 0 && o[2] == 113);

    !(ip.is_loopback()
        || ip.is_private()
        || ip.is_link_local()
        || ip.is_unspecified()
        || ip.is_broadcast()
        || ip.is_multicast()
        || is_this_network
        || is_reserved
        || is_cgnat
        || is_benchmark
        || is_doc)
}

fn is_routable_ipv6(ip: Ipv6Addr) -> bool {
    // An IPv4 address in its mapped form (::ffff:0:0/96) is judged by the IPv4 rules, so
    // `/ip6/::ffff:127.0.0.1` is refused as `/ip4/127.0.0.1` is.
    if let Some(v4) = ip.to_ipv4_mapped() {
        return is_routable_ipv4(v4);
    }
    let seg0 = ip.segments()[0];

    let is_unique_local = (seg0 & 0xfe00) == 0xfc00; // fc00::/7
    let is_link_local = (seg0 & 0xffc0) == 0xfe80;   // fe80::/10

    !(ip.is_loopback()
        || ip.is_unspecified()
        || ip.is_multicast()
        || is_unique_local
        || is_link_local)
}

fn addr_is_public_or_dns(addr: &Multiaddr) -> bool {
    use libp2p::multiaddr::Protocol;

    for p in addr.iter() {
        match p {
            Protocol::Dns(_)
            | Protocol::Dns4(_)
            | Protocol::Dns6(_)
            | Protocol::Dnsaddr(_) => return true,
            Protocol::Ip4(ip) => return is_routable_ipv4(ip),
            Protocol::Ip6(ip) => return is_routable_ipv6(ip),
            _ => {}
        }
    }

    false
}

fn addr_peer_suffix_matches(addr: &Multiaddr, expected_peer: PeerId) -> bool {
    match peer_id_from_multiaddr(addr) {
        Some(pid) => pid == expected_peer,
        None => true,
    }
}

fn should_store_discovered_addr(self_peer: PeerId, peer: PeerId, addr: &Multiaddr) -> bool {
    if peer == self_peer {
        return false;
    }
    if !is_dialable_addr(addr) {
        return false;
    }
    if !addr_is_public_or_dns(addr) {
        return false;
    }
    if !addr_peer_suffix_matches(addr, peer) {
        return false;
    }
    true
}

fn should_dial_discovered_addr(self_peer: PeerId, peer: PeerId, addr: &Multiaddr) -> bool {
    if peer == self_peer {
        return false;
    }
    if !is_dialable_addr(addr) {
        return false;
    }
    if !addr_is_public_or_dns(addr) {
        return false;
    }
    if peer_id_from_multiaddr(addr) == Some(self_peer) {
        return false;
    }
    if !addr_peer_suffix_matches(addr, peer) {
        return false;
    }
    true
}


fn addr_backoff_secs(failures: u32) -> u64 {
    match failures {
        0 => 0,
        1 => 30,
        2 => 120,
        3 => 300,
        4 => 900,
        5 => 1800,
        _ => 3600,
    }
}

fn addr_is_backed_off(
    addr_backoff: &HashMap<Multiaddr, (u32, Instant)>,
    addr: &Multiaddr,
) -> bool {
    addr_backoff
        .get(addr)
        .map(|(_, until)| Instant::now() < *until)
        .unwrap_or(false)
}

fn note_addr_dial_failure(
    addr_backoff: &mut HashMap<Multiaddr, (u32, Instant)>,
    addr: &Multiaddr,
) {
    let failures = addr_backoff
        .get(addr)
        .map(|(n, _)| n.saturating_add(1))
        .unwrap_or(1);

    let secs = addr_backoff_secs(failures);
    addr_backoff.insert(addr.clone(), (failures, Instant::now() + Duration::from_secs(secs)));
}

fn note_addr_dial_success(
    addr_backoff: &mut HashMap<Multiaddr, (u32, Instant)>,
    addr: &Multiaddr,
) {
    addr_backoff.remove(addr);
}

/// How long a dial-failure count outlives its backoff. The count must survive the backoff it
/// started, or the next failure starts again at the first step and the backoff never grows: an
/// entry dropped the moment its backoff ended has a dead address dialed again every 30 s or so for
/// good. Twice the longest backoff.
const ADDR_BACKOFF_FORGET_SECS: u64 = 2 * 3600;

fn prune_addr_backoff(
    addr_backoff: &mut HashMap<Multiaddr, (u32, Instant)>,
) {
    let now = Instant::now();
    let forget = Duration::from_secs(ADDR_BACKOFF_FORGET_SECS);
    addr_backoff.retain(|_, (_fails, until)| now < *until + forget);
}

/// Bounds the dial bookkeeping. A disconnect time and a dial time are read only inside their
/// cooldowns (`PEER_DISCONNECT_COOLDOWN_SECS`, `DIAL_BACKOFF_SECS`, `PEER_REDIAL_EVERY_SECS`), so
/// older entries go; a quality record is read only to order the address book's peers, and a
/// timeout count only for an address in the book, so each is kept while that holds. Without
/// this, every fresh PeerId and address ever dialed or disconnected stayed in memory for the
/// life of the process.
fn prune_dial_state(
    last_disconnect_at: &mut HashMap<PeerId, Instant>,
    last_dial_by_addr: &mut HashMap<Multiaddr, Instant>,
    peer_quality: &mut HashMap<PeerId, PeerQuality>,
    addr_timeouts: &mut HashMap<Multiaddr, u8>,
    known_addrs: &HashMap<PeerId, HashSet<Multiaddr>>,
    connected: &HashSet<PeerId>,
) {
    let disconnect_window = Duration::from_secs(PEER_DISCONNECT_COOLDOWN_SECS);
    last_disconnect_at.retain(|_, t| t.elapsed() < disconnect_window);
    let dial_window = Duration::from_secs(DIAL_BACKOFF_SECS.max(PEER_REDIAL_EVERY_SECS));
    last_dial_by_addr.retain(|_, t| t.elapsed() < dial_window);
    peer_quality.retain(|p, _| known_addrs.contains_key(p) || connected.contains(p));
    if !addr_timeouts.is_empty() {
        let in_book: HashSet<Multiaddr> =
            known_addrs.values().flatten().map(strip_p2p_suffix).collect();
        addr_timeouts.retain(|a, _| in_book.contains(a));
    }
}

/// Whether the poll tick redials the bootnodes: during the cold start while fewer than
/// `COLD_START_MIN_PEERS` are connected, then while fewer than `MIN_OUTBOUND_PEERS` are
/// connected or fewer than `MIN_OUTBOUND_PEERS` of the connections are ones we dialed. Counting
/// all connections let peers that connect to us stop our own dials. The
/// outbound floor does not dial at the connection cap: a connection past the cap makes
/// `maybe_evict_excess_peers` shed down to its target, several inbound peers for one dial.
fn bootnode_redial_due(cold_start: bool, connected: usize, outbound: usize, max_connected: usize) -> bool {
    if cold_start {
        return connected < COLD_START_MIN_PEERS;
    }
    connected < MIN_OUTBOUND_PEERS || (outbound < MIN_OUTBOUND_PEERS && connected < max_connected)
}

fn note_pending_dial(
    pending_dials: &mut HashMap<PeerId, HashSet<Multiaddr>>,
    peer: PeerId,
    addr: Multiaddr,
) {
    pending_dials.entry(peer).or_default().insert(addr);
}

fn take_pending_dials(
    pending_dials: &mut HashMap<PeerId, HashSet<Multiaddr>>,
    peer: &PeerId,
) -> Vec<Multiaddr> {
    pending_dials
        .remove(peer)
        .map(|s| s.into_iter().collect())
        .unwrap_or_default()
}

fn addr_quality_rank(addr: &Multiaddr) -> u8 {
    use libp2p::multiaddr::Protocol;

    for p in addr.iter() {
        match p {
            Protocol::Dns(_)
            | Protocol::Dns4(_)
            | Protocol::Dns6(_)
            | Protocol::Dnsaddr(_) => return 0,
            Protocol::Ip4(ip) => {
                return if is_routable_ipv4(ip) { 1 } else { 10 };
            }
            Protocol::Ip6(ip) => {
                return if is_routable_ipv6(ip) { 2 } else { 11 };
            }
            _ => {}
        }
    }

    20
}

fn addr_base_key(addr: &Multiaddr) -> String {
    use libp2p::multiaddr::Protocol;

    let mut parts = Vec::<String>::new();
    for p in addr.iter() {
        match p {
            Protocol::P2p(_) => break,
            _ => parts.push(p.to_string()),
        }
    }
    parts.join("/")
}

fn dedup_addrs_by_base(addrs: Vec<Multiaddr>) -> Vec<Multiaddr> {
    let mut seen = HashSet::<String>::new();
    let mut out = Vec::<Multiaddr>::new();

    for addr in addrs {
        let k = addr_base_key(&addr);
        if seen.insert(k) {
            out.push(addr);
        }
    }

    out
}

fn sorted_peer_addrs_for_export(
    self_peer: PeerId,
    peer: PeerId,
    known_addrs: &HashMap<PeerId, HashSet<Multiaddr>>,
) -> Vec<Multiaddr> {
    let mut out: Vec<Multiaddr> = known_addrs
        .get(&peer)
        .map(|s| {
            s.iter()
                .filter(|addr| should_dial_discovered_addr(self_peer, peer, addr))
                .cloned()
                .collect()
        })
        .unwrap_or_default();

    out.sort_by(|a, b| {
        let ra = addr_quality_rank(a);
        let rb = addr_quality_rank(b);

        ra.cmp(&rb).then_with(|| a.to_string().cmp(&b.to_string()))
    });

    dedup_addrs_by_base(out)
}

fn insert_known_addr(
    known_addrs: &mut HashMap<PeerId, HashSet<Multiaddr>>,
    peer: PeerId,
    addr: Multiaddr,
) {
    if !known_addrs.contains_key(&peer) && known_addrs.len() >= MAX_KNOWN_PEERS {
        return;
    }

    let entry = known_addrs.entry(peer).or_default();

    if entry.len() >= MAX_ADDRS_PER_PEER && !entry.contains(&addr) {
        return;
    }

    entry.insert(addr);
}

/// Inserts like `insert_known_addr` and returns true only when `addr` was not already stored for
/// `peer` and is stored now, so callers log a learned address once instead of on every identify.
fn insert_known_addr_is_new(
    known_addrs: &mut HashMap<PeerId, HashSet<Multiaddr>>,
    peer: PeerId,
    addr: Multiaddr,
) -> bool {
    let was_known = known_addrs.get(&peer).is_some_and(|s| s.contains(&addr));
    insert_known_addr(known_addrs, peer, addr.clone());
    !was_known && known_addrs.get(&peer).is_some_and(|s| s.contains(&addr))
}

fn export_peer_strings(
    self_peer: PeerId,
    requester: PeerId,
    known_addrs: &HashMap<PeerId, HashSet<Multiaddr>>,
    peer_quality: &HashMap<PeerId, PeerQuality>,
    max: usize,
) -> Vec<String> {
    let mut peer_ids: Vec<PeerId> = known_addrs.keys().copied().collect();
    sort_peer_ids_by_quality(&mut peer_ids, peer_quality);

    let mut out = Vec::<String>::new();

    for pid in peer_ids {
        if pid == self_peer || pid == requester {
            continue;
        }

        let addrs = sorted_peer_addrs_for_export(self_peer, pid, known_addrs);

        for addr in addrs {
            if out.len() >= max {
                return out;
            }
            out.push(addr.to_string());
        }
    }

    out
}

/// Takes the addresses of one Peers response into the book. At most `MAX_NEW_PEERS_PER_RESPONSE`
/// peers new to the book are added per response, so one peer cannot fill the book with its own
/// list; the rest is discarded and nobody is penalised for it.
fn parse_peer_strings_into_known_addrs(
    known_addrs: &mut HashMap<PeerId, HashSet<Multiaddr>>,
    self_peer: PeerId,
    peers: Vec<String>,
) {
    let mut new_peers = 0usize;
    for s in peers {
        let Ok(addr) = s.parse::<Multiaddr>() else {
            continue;
        };
        let Some(pid) = peer_id_from_multiaddr(&addr) else {
            continue;
        };
        if !should_store_discovered_addr(self_peer, pid, &addr) {
            continue;
        }
        let is_new = !known_addrs.contains_key(&pid);
        if is_new && new_peers >= MAX_NEW_PEERS_PER_RESPONSE {
            continue;
        }
        insert_known_addr(known_addrs, pid, addr);
        if is_new && known_addrs.contains_key(&pid) {
            new_peers += 1;
        }
    }
}

/// The addresses a failed dial timed out on. The swarm reports each dialed address with its own
/// error (libp2p-swarm-0.48.0 `DialError::Transport`, `lib.rs:1553`); a timeout there is the
/// kernel's connect attempt to that address getting no answer (libp2p-tcp-0.45.0 `lib.rs:396-416`,
/// `provider/tokio.rs:94-98`; this transport has no timeout of its own), wrapped by the boxed
/// transport (libp2p-core-0.44.0 `transport/boxed.rs:173-175`). Live it prints as
/// `Os { code: 110, kind: TimedOut, .. }` inside that wrapper.
fn timed_out_dial_addrs(error: &libp2p::swarm::DialError) -> Vec<Multiaddr> {
    match error {
        libp2p::swarm::DialError::Transport(errors) => errors
            .iter()
            .filter(|(_, e)| dial_error_text_is_timeout(&format!("{e:?}")))
            .map(|(addr, _)| addr.clone())
            .collect(),
        _ => Vec::new(),
    }
}

/// A dial's per-address error text names a timeout: the kernel's connect timeout, or the
/// transport's handshake deadline (`admission::HANDSHAKE_TIMEOUT`), which ends a dial first and
/// reads as libp2p-core 0.44.0 `TransportTimeoutError::Timeout` inside `io::Error::other`
/// (`transport/timeout.rs:180-188`, boxed at `transport/boxed.rs:173-175`).
fn dial_error_text_is_timeout(debug: &str) -> bool {
    debug.contains("TimedOut") || debug.contains("error: Timeout }")
}

/// Whether our own connection limits refused a dial (`admission`): the peer already holds its
/// connections, or we are at the cap. Nobody is blamed for it.
fn dial_refused_by_us(e: &libp2p::swarm::DialError) -> bool {
    matches!(e, libp2p::swarm::DialError::Denied { .. })
}

/// A dial our own limits refused: its peer's pending dials are dropped from the bookkeeping, and no
/// address is backed off or forgotten (`dial_refused_by_us`). Returns the dropped addresses.
fn forget_refused_dial(pending_dials: &mut HashMap<PeerId, HashSet<Multiaddr>>, peer: Option<PeerId>) -> Vec<Multiaddr> {
    peer.map(|p| take_pending_dials(pending_dials, &p)).unwrap_or_default()
}

/// Banned peers that still hold a connection, the poll tick's to close, but for the ones we are
/// closing already.
fn banned_with_connections(
    open: &HashSet<PeerId>,
    bans: &HashMap<PeerId, Instant>,
    closing: &HashMap<PeerId, &'static str>,
) -> Vec<PeerId> {
    open.iter().filter(|p| is_banned(bans, p) && !closing.contains_key(p)).copied().collect()
}

/// Counts a dial timeout against `addr` and evicts the address from the book at the
/// `ADDR_TIMEOUTS_TO_EVICT`th in a row (a connection to it resets the count, `clear_addr_timeouts`).
/// Returns true when it evicted. Nothing is counted while this node holds no connection (a
/// timeout then says more about our own network than about the address), a configured bootnode
/// is never evicted, and an eviction that would remove a peer's last address leaves the book at
/// `MIN_KNOWN_PEERS_KEPT` peers or more. Only the address is removed: a planted address for an
/// honest peer's id goes, the peer's other addresses stay.
fn note_addr_timeout(
    known_addrs: &mut HashMap<PeerId, HashSet<Multiaddr>>,
    addr_timeouts: &mut HashMap<Multiaddr, u8>,
    peer: PeerId,
    addr: &Multiaddr,
    bootnode_peers: &HashSet<PeerId>,
    holding_connections: bool,
) -> bool {
    if !holding_connections || bootnode_peers.contains(&peer) {
        return false;
    }
    let base = strip_p2p_suffix(addr);
    let n = addr_timeouts.entry(base.clone()).or_insert(0);
    *n = n.saturating_add(1);
    if *n < ADDR_TIMEOUTS_TO_EVICT {
        return false;
    }
    let stored = stored_addrs_matching(known_addrs, &peer, addr);
    if stored.is_empty() {
        addr_timeouts.remove(&base);
        return false;
    }
    if known_addrs.get(&peer).is_some_and(|set| stored.len() == set.len())
        && known_addrs.len() <= MIN_KNOWN_PEERS_KEPT
    {
        return false;
    }
    for a in &stored {
        remove_known_addr(known_addrs, &peer, a);
    }
    addr_timeouts.remove(&base);
    true
}

/// `peer`'s stored addresses that are `dialed`, compared without the /p2p suffix (the swarm reports
/// a dialed address with it, and the book may hold it either way).
fn stored_addrs_matching(
    known_addrs: &HashMap<PeerId, HashSet<Multiaddr>>,
    peer: &PeerId,
    dialed: &Multiaddr,
) -> Vec<Multiaddr> {
    let base = strip_p2p_suffix(dialed);
    known_addrs
        .get(peer)
        .map(|set| set.iter().filter(|a| strip_p2p_suffix(a) == base).cloned().collect())
        .unwrap_or_default()
}

/// Forgets the addresses a failed dial to `peer` proved unusable and returns them with the reason,
/// for the log. Only the address the error names goes (`DialError::WrongPeerId` carries the dialed
/// address, `DialError::Transport` one error per address): anyone can advertise an address with an
/// honest peer's id, and its refusal or other identity must not cost that peer the addresses it
/// was reached at. A timeout is counted separately (`note_addr_timeout`).
fn forget_failed_dial_addrs(
    known_addrs: &mut HashMap<PeerId, HashSet<Multiaddr>>,
    peer: &PeerId,
    error: &libp2p::swarm::DialError,
) -> Vec<(Multiaddr, &'static str)> {
    use libp2p::swarm::DialError;
    let failed: Vec<(&Multiaddr, &'static str)> = match error {
        DialError::WrongPeerId { address, .. } => vec![(address, "wrong-peer-id")],
        DialError::Transport(errors) => errors
            .iter()
            .filter_map(|(addr, e)| {
                let text = format!("{e:?}");
                let why = if text.contains("ConnectionRefused") {
                    "refused"
                } else if text.contains("MultiaddrNotSupported") {
                    "unsupported"
                } else if text.contains("InvalidData") || text.contains("error: Input") {
                    "invalid-data"
                } else {
                    return None;
                };
                Some((addr, why))
            })
            .collect(),
        _ => Vec::new(),
    };
    let mut removed = Vec::new();
    for (dialed, why) in failed {
        for a in stored_addrs_matching(known_addrs, peer, dialed) {
            remove_known_addr(known_addrs, peer, &a);
            removed.push((a, why));
        }
    }
    removed
}

fn clear_addr_timeouts(addr_timeouts: &mut HashMap<Multiaddr, u8>, addr: &Multiaddr) {
    addr_timeouts.remove(&strip_p2p_suffix(addr));
}


fn remove_known_addr(
    known_addrs: &mut HashMap<PeerId, HashSet<Multiaddr>>,
    peer: &PeerId,
    addr: &Multiaddr,
) {
    if let Some(set) = known_addrs.get_mut(peer) {
        set.remove(addr);
        if set.is_empty() {
            known_addrs.remove(peer);
        }
    }
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
    gossip_tx_refused_inputs: u32,
    invalid: u32,
}

impl RateBucket {
    fn new() -> Self {
        Self::new_at(Instant::now())
    }

    fn new_at(now: Instant) -> Self {
        Self {
            window_start: now,
            rr_reqs: 0,
            gossip_msgs: 0,
            gossip_tx_refused_inputs: 0,
            invalid: 0,
        }
    }

    fn reset_if_needed(&mut self, window: Duration) {
        self.reset_if_needed_at(window, Instant::now());
    }

    fn reset_if_needed_at(&mut self, window: Duration, now: Instant) {
        if now.saturating_duration_since(self.window_start) >= window {
            self.window_start = now;
            self.rr_reqs = 0;
            self.gossip_msgs = 0;
            self.gossip_tx_refused_inputs = 0;
            self.invalid = 0;
        }
    }
}

impl Default for RateBucket {
    fn default() -> Self {
        Self::new()
    }
}

// Outbound request pacing, per peer: at most OUTBOUND_MAX_RR_PER_PEER_PER_WINDOW block requests (90,
// upstream's, d168f70 node.rs:71) in any RL_WINDOW, counted over the sends of the last RL_WINDOW, so
// every window starts on a send. An upstream server bans a requester past
// UPSTREAM_RR_REQS_PER_WINDOW (120) requests in its own window, which starts at its first request after
// the last window ended (`allow_rr_req`; ours throttles past RL_MAX_RR_REQS_PER_WINDOW, 1,200, and
// bans nobody). Any 10 s of ours then hold at most 90 block requests plus
// the unpaced background requests (`Background`, one in flight per peer: a GetTip at first sight and
// at each 5 s poll tick while our tip is stale, so at most 3, a headers request every 20 s and a
// peers request every 30 s, so at most 5), 95 in all, and a stall of the server can bunch only the
// requests we hold in flight on top (two block requests and one background request per request
// timeout). A tumbling window that a check from `pump_blocks` opens would not hold this: demand
// that comes late in it sends 90 at its end and 90 more when it resets, 180 in one window of the
// server, and an honest server bans us for ten minutes.
//
// This map must NOT be a thread_local, which is how upstream v1.1.2
// ships it. The swarm loop is a single task, but spawn_p2p starts it with `tokio::spawn` on the
// multi-threaded runtime, so the runtime is free to poll it on a different worker thread after
// any `.await`. With a thread_local map each worker keeps its own counters: the effective
// per-peer cap becomes (worker count) x OUTBOUND_MAX_RR_PER_PEER_PER_WINDOW, which is exactly the
// burst the pacing exists to prevent (a peer whose own RL_MAX_RR_REQS_PER_WINDOW is 120 then bans
// us mid-sync, and a node banned by its sync peers isolates itself). Process-wide instead:
// one p2p loop runs per process, the critical section is a couple of map operations, and
// correctness no longer depends on which worker happens to poll the task.
//
// A peer's sends older than RL_WINDOW are forgotten, and a peer with none left is dropped
// (`pace_prune_locked`), so the map cannot grow without bound over the lifetime of a long-running
// node that meets many peers.
static OUTBOUND_PACE: std::sync::Mutex<std::collections::BTreeMap<PeerId, VecDeque<Instant>>> =
    std::sync::Mutex::new(std::collections::BTreeMap::new());

/// Above this many tracked peers, drop the peers with no send in the last RL_WINDOW.
const PACE_PRUNE_AT: usize = 1024;

fn pace_forget_expired(sends: &mut VecDeque<Instant>, now: Instant) {
    while sends.front().is_some_and(|t| now.saturating_duration_since(*t) >= RL_WINDOW) {
        sends.pop_front();
    }
}

fn pace_prune_locked(m: &mut std::collections::BTreeMap<PeerId, VecDeque<Instant>>, now: Instant) {
    if m.len() > PACE_PRUNE_AT {
        m.retain(|_, sends| {
            pace_forget_expired(sends, now);
            !sends.is_empty()
        });
    }
}

/// Whether `p` already has OUTBOUND_MAX_RR_PER_PEER_PER_WINDOW block requests from us in the last
/// RL_WINDOW. A check starts nothing.
fn pace_saturated(p: &PeerId) -> bool {
    pace_saturated_at(p, Instant::now())
}

fn pace_saturated_at(p: &PeerId, now: Instant) -> bool {
    let mut m = OUTBOUND_PACE.lock().unwrap_or_else(|e| e.into_inner());
    pace_prune_locked(&mut m, now);
    let Some(sends) = m.get_mut(p) else { return false };
    pace_forget_expired(sends, now);
    sends.len() >= OUTBOUND_MAX_RR_PER_PEER_PER_WINDOW as usize
}

fn pace_note_sent(p: &PeerId) {
    pace_note_sent_at(p, Instant::now())
}

fn pace_note_sent_at(p: &PeerId, now: Instant) {
    let mut m = OUTBOUND_PACE.lock().unwrap_or_else(|e| e.into_inner());
    pace_prune_locked(&mut m, now);
    let sends = m.entry(*p).or_default();
    pace_forget_expired(sends, now);
    sends.push_back(now);
}


fn is_banned(bans: &HashMap<PeerId, Instant>, p: &PeerId) -> bool {
    bans.get(p)
        .map(|t| t.elapsed().as_secs() < BAN_SECS)
        .unwrap_or(false)
}

/// Bans `p` for BAN_SECS from now; logs (`peer_line`) and returns true only when `p` was not banned
/// already.
fn ban_peer(bans: &mut HashMap<PeerId, Instant>, p: PeerId, why: &str) -> bool {
    let entered = !is_banned(bans, &p);
    if entered && peer_line(&p, Line::Ban).is_some() {
        println!("[p2p] banning peer {p} for {BAN_SECS} s: {why}");
    }
    bans.insert(p, Instant::now());
    entered
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
    if let Some(n) = peer_line(&p, Line::Invalid) {
        println!("[p2p] invalid from {p}: {why} (invalid_in_window={}) since_last_line={n}", b.invalid);
    }
    if b.invalid >= RL_MAX_INVALID_PER_WINDOW {
        ban_peer(bans, p, "too many invalid messages");


    }
}

// NEW
/// What this node does with one inbound request (`allow_rr_req`).
#[derive(Debug, PartialEq, Eq)]
enum RrAdmission {
    Serve,
    /// Past the window's figure: answered "rate limited" for the rest of the window, the requester
    /// kept. `entered` on the first such request of a window, the one the log line reports.
    Throttled { entered: bool },
    /// From a banned peer (32 invalid messages in a window, `note_invalid`). Kept for the function's
    /// own contract, which the boundary test reads: the request arm never gets it, because the
    /// request-response message arm drops a banned or quarantined peer's messages before it calls
    /// `allow_rr_req`.
    Banned,
}

fn allow_rr_req(buckets: &mut HashMap<PeerId, RateBucket>, bans: &mut HashMap<PeerId, Instant>, p: PeerId) -> RrAdmission {
    allow_rr_req_at(buckets, bans, p, RL_MAX_RR_REQS_PER_WINDOW, Instant::now())
}

/// `allow_rr_req` at `now` against `limit` (the pacing tests model an upstream server with it,
/// whose figure is UPSTREAM_RR_REQS_PER_WINDOW). Past `limit` the rest of the window is throttled
/// and nobody is banned: an honest upstream node's pacer does not bound what it sends one peer (a
/// thread_local map, d168f70 node.rs:1053-1057, its loop a task on a multi-thread runtime, :2529),
/// and a ban, which closes its connections, would cost us the gossip of what may be the dominant
/// producer (an honest peer must not be treated as an attacker; the gossip budget drops on the same
/// ground). Upstream bans the peer for BAN_SECS.
fn allow_rr_req_at(
    buckets: &mut HashMap<PeerId, RateBucket>,
    bans: &mut HashMap<PeerId, Instant>,
    p: PeerId,
    limit: u32,
    now: Instant,
) -> RrAdmission {
    if is_banned(bans, &p) {
        return RrAdmission::Banned;
    }
    let b = buckets.entry(p).or_insert_with(|| RateBucket::new_at(now));
    b.reset_if_needed_at(RL_WINDOW, now);
    b.rr_reqs = b.rr_reqs.saturating_add(1);

    if b.rr_reqs > limit {
        return RrAdmission::Throttled { entered: b.rr_reqs == limit.saturating_add(1) };
    }
    RrAdmission::Serve
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

        return false;
    }
    true
}

/// Whether `p`'s refused gossip txs have reached `RL_MAX_GOSSIP_TX_INPUTS_PER_WINDOW` inputs in this
/// window; its next tx is then dropped unchecked. Reads only, and strikes nobody.
fn gossip_tx_refusals_spent(buckets: &mut HashMap<PeerId, RateBucket>, p: PeerId) -> bool {
    let b = buckets.entry(p).or_default();
    b.reset_if_needed(RL_WINDOW);
    b.gossip_tx_refused_inputs >= RL_MAX_GOSSIP_TX_INPUTS_PER_WINDOW
}

/// Charges `p` the inputs of a gossip tx its check did not admit. Strikes nobody.
fn charge_gossip_tx_refusal(buckets: &mut HashMap<PeerId, RateBucket>, p: PeerId, inputs: usize) {
    let b = buckets.entry(p).or_default();
    b.reset_if_needed(RL_WINDOW);
    let inputs = u32::try_from(inputs.max(1)).unwrap_or(u32::MAX);
    b.gossip_tx_refused_inputs = b.gossip_tx_refused_inputs.saturating_add(inputs);
}

/// A gossip tx waiting for, or under, its mempool check off the p2p loop.
struct GossipTxCheck {
    fwd: PeerId,
    msg_id: gossipsub::MessageId,
    /// The message's content hash, the orphan pool's key (what `message_id_fn` hashes).
    key: [u8; 32],
    tx: Transaction,
    tx_bytes: Vec<u8>,
}

/// A finished check, back on the loop: `Ok(forward)` when the mempool admitted or already holds
/// the tx (forward only when it holds these bytes), `Err(deps)` with what the node lacks when it
/// refused it.
struct GossipTxChecked {
    check: GossipTxCheck,
    outcome: std::result::Result<bool, crate::net::orphan_txs::Deps>,
}

/// Gossip tx checks (`Mempool::insert_checked`, every input's spent output and signature) on the
/// blocking pool, so the p2p loop does not wait on them (inline, each refusal of a wide tx would
/// hold the loop for its whole check). The loop reports each verdict when its check returns
/// (`run_p2p_loop`'s check arm); an unreported message stays in gossipsub's cache, unforwarded,
/// until the cache drops it, and a check that admits a tx after that has the node publish it.
#[derive(Default)]
struct GossipTxChecks {
    running: tokio::task::JoinSet<GossipTxChecked>,
    waiting: VecDeque<GossipTxCheck>,
    waiting_inputs: usize,
}

impl GossipTxChecks {
    /// Queues `check` and starts what fits; false, with `check` dropped, when the queue is full.
    fn push(&mut self, check: GossipTxCheck, db: &Arc<Stores>, mempool: &Arc<Mempool>) -> bool {
        let inputs = check.tx.inputs.len().max(1);
        if self.waiting_inputs.saturating_add(inputs) > GOSSIP_TX_CHECK_QUEUE_INPUTS {
            return false;
        }
        self.waiting_inputs += inputs;
        self.waiting.push_back(check);
        self.start_waiting(db, mempool);
        true
    }

    /// Starts waiting checks while fewer than GOSSIP_TX_CHECKS_IN_FLIGHT run.
    fn start_waiting(&mut self, db: &Arc<Stores>, mempool: &Arc<Mempool>) {
        while self.running.len() < GOSSIP_TX_CHECKS_IN_FLIGHT {
            let Some(check) = self.waiting.pop_front() else { return };
            self.waiting_inputs -= check.tx.inputs.len().max(1);
            let (db, mempool) = (db.clone(), mempool.clone());
            self.running.spawn_blocking(move || {
                #[cfg(feature = "test-bypass")]
                {
                    *TEST_GOSSIP_TX_CHECKS.lock().unwrap().entry(check.fwd).or_default() += 1;
                    let delay = TEST_GOSSIP_TX_CHECK_DELAY.lock().unwrap().get(&check.fwd).copied();
                    if let Some(d) = delay {
                        std::thread::sleep(d);
                    }
                }
                let outcome = match mempool.insert_checked(&db, check.tx.clone()) {
                    Ok(_) => Ok(mempool.holds_encoding(&crate::crypto::txid(&check.tx), &check.tx_bytes)),
                    Err(_) => Err(missing_deps(&db, &check.tx)),
                };
                GossipTxChecked { check, outcome }
            });
        }
    }

    fn is_running(&self) -> bool {
        !self.running.is_empty()
    }
}

/// Inbound requests served at once. One, as when the loop serves each request itself: the serves
/// run in turn, and the loop does not wait on them.
const SERVE_PERMITS: usize = 1;

/// The request-response timeout, both ways (upstream's 15 s, d168f70 node.rs:2652-2654). An inbound
/// request's stream lives at most this long from its start, which precedes its read: libp2p's timer
/// starts when the stream is pushed, before `read_request` (libp2p-request-response 0.30.0
/// handler.rs:113-116, :164-166; futures-bounded 0.3.0 futures_map.rs:62-69).
const RR_REQUEST_TIMEOUT: Duration = Duration::from_secs(15);

/// How often a serve waiting for its turn checks that its request's stream is still open (`Serves`).
const SERVE_WAIT_CHECK: Duration = Duration::from_millis(500);

/// Inbound requests (all but GetPeers, which reads the loop's address book)
/// served on the blocking pool, SERVE_PERMITS at a time, and answered from the loop when their serve
/// returns (`run_p2p_loop`'s serve arm): only the loop holds the swarm, and send_response needs it
/// (libp2p-request-response 0.30.0 lib.rs:484, the response channel's sender is private, :265-267).
/// A select! arm that awaited each serve would let peers asking for headers or blocks hold the loop
/// that also handles gossip, sync answers, block apply and the poll tick. A request waits for a
/// permit and is never refused for it: an honest node pipelines up to four requests on one
/// connection (upstream's `with_max_concurrent_streams(4)` and MAX_INFLIGHT_BLOCKS 8 with no
/// per-peer cap, d168f70 node.rs:2653-2654, :103), and a "server busy" answer to its GetBlock
/// stamps us a bad provider of that block for 120 s (its Err arm, :4484-4560). A waiting serve ends
/// unserved once its request's stream is gone (its channel closed: the request timed out, or its
/// connection closed; checked every SERVE_WAIT_CHECK) or RR_REQUEST_TIMEOUT after the request was
/// read, whichever is first, whether or not the permit has come (`wait_for_turn`), and leaves the
/// semaphore's queue then. So the waiting serves are at most the inbound request streams open (four
/// a connection, `with_max_concurrent_streams`, shared with our own requests) and those whose
/// stream ended within the last SERVE_WAIT_CHECK. A serve that waited for the permit before it
/// checked its channel would, behind one stalled serve, keep every expired request queued with its
/// decoded request, channel and store handle, and each stream freed by a timeout would let another
/// in. A serve already running on the blocking pool keeps its permit until it returns, its
/// requester gone or not.
struct Serves {
    running: tokio::task::JoinSet<Result<Served>>,
    permits: Arc<tokio::sync::Semaphore>,
    cfg: Arc<NetConfig>,
}

/// A finished serve, back on the loop: the response for `channel`, None when the requester had gone.
struct Served {
    channel: request_response::ResponseChannel<SyncResponse>,
    response: Option<SyncResponse>,
}

impl Serves {
    fn new(cfg: &NetConfig) -> Self {
        Self {
            running: tokio::task::JoinSet::new(),
            permits: Arc::new(tokio::sync::Semaphore::new(SERVE_PERMITS)),
            cfg: Arc::new(cfg.clone()),
        }
    }

    /// `logged`: whether the request's recv line was printed (`peer_line`), so the serve prints its own.
    fn start(
        &mut self,
        channel: request_response::ResponseChannel<SyncResponse>,
        request: SyncRequest,
        db: &Arc<Stores>,
        peer: PeerId,
        logged: bool,
    ) {
        let (permits, db, cfg) = (self.permits.clone(), db.clone(), self.cfg.clone());
        let expires = tokio::time::Instant::now() + RR_REQUEST_TIMEOUT;
        self.running.spawn(async move {
            let Some(permit) = wait_for_turn(permits, &channel, expires).await? else {
                return Ok(Served { channel, response: None });
            };
            if !channel.is_open() {
                return Ok(Served { channel, response: None });
            }
            let response = tokio::task::spawn_blocking(move || {
                let _permit = permit;
                serve_request(&db, &cfg, request, peer, logged)
            })
            .await
            .map_err(|e| anyhow::anyhow!("spawn_blocking join error: {e}"))?;
            Ok(Served { channel, response: Some(response) })
        });
    }
}

/// A serve permit, or None once `channel`'s stream is gone or `expires` has passed, whichever comes
/// first. Returning drops the semaphore's acquire future, which takes the waiter out of its queue.
/// `biased`: a permit that is ready wins over a check due at the same poll.
async fn wait_for_turn(
    permits: Arc<tokio::sync::Semaphore>,
    channel: &request_response::ResponseChannel<SyncResponse>,
    expires: tokio::time::Instant,
) -> Result<Option<tokio::sync::OwnedSemaphorePermit>> {
    let acquire = permits.acquire_owned();
    tokio::pin!(acquire);
    let deadline = tokio::time::sleep_until(expires);
    tokio::pin!(deadline);
    let mut check = interval(SERVE_WAIT_CHECK);
    loop {
        tokio::select! {
            biased;
            permit = &mut acquire => return Ok(Some(permit.context("the serve semaphore is never closed")?)),
            _ = &mut deadline => return Ok(None),
            _ = check.tick() => {
                if !channel.is_open() {
                    return Ok(None);
                }
            }
        }
    }
}

/// The answer to one inbound request from `peer`, read on the blocking pool. Its MISS and error-answer
/// lines are sampled on their own (`peer_line`); its lookup, HIT and anchor lines are printed only when
/// `logged`, with the request's recv line.
fn serve_request(db: &Stores, cfg: &NetConfig, request: SyncRequest, peer: PeerId, logged: bool) -> SyncResponse {
    #[cfg(feature = "test-bypass")]
    match cfg.test_mode {
        TestPeerMode::SlowHeaderServes(hold)
            if matches!(request, SyncRequest::GetHeaders { .. } | SyncRequest::GetHeadersByLocator { .. }) =>
        {
            std::thread::sleep(hold)
        }
        TestPeerMode::OversizedAnswers => {
            return SyncResponse::Peers { peers: vec!["0".repeat(MAX_RR_MSG_BYTES as usize)] };
        }
        _ => {}
    }
    let kind = Line::of(&request).name();
    let block_hash = match &request {
        SyncRequest::GetBlock { hash } => Some(*hash),
        _ => None,
    };
    let error = |msg: String| {
        if let Some(n) = peer_line(&peer, Line::ErrorAnswer) {
            let hash = block_hash.map(|h| format!(" {}", hex32(&h))).unwrap_or_default();
            println!("[sync-serve] error answer to {kind}{hash} from {peer}: {msg} since_last_line={n}");
        }
        SyncResponse::Err { msg }
    };
    let response = match handle_request_blocking(db, request, logged) {
        Ok(response) => response,
        Err(e) if e.to_string() == UNKNOWN_BLOCK => {
            if let (Some(n), Some(h)) = (peer_line(&peer, Line::Miss), block_hash) {
                println!("[sync-serve] GetBlock MISS {} from {peer} since_last_line={n}", hex32(&h));
            }
            return SyncResponse::Err { msg: UNKNOWN_BLOCK.into() };
        }
        Err(e) => return error(e.to_string()),
    };
    // The outbound bind. See outbound_block_refusal.
    if let SyncResponse::Block { block } = &response {
        if let Some(msg) = outbound_block_refusal(cfg, block, &header_hash(&block.header)) {
            return error(msg.into());
        }
    }
    response
}

/// The answer to a GetBlock for a block we do not store. Requesters read the text (our Err arm in
/// `run_p2p_loop`, upstream's at d168f70 `src/net/node.rs:4486`); its MISS line is printed by
/// `serve_request`.
const UNKNOWN_BLOCK: &str = "unknown block";

/// The transport gate's verdict on one gossip message, by its forwarder.
#[derive(Debug, PartialEq, Eq)]
enum GossipGate {
    Admit,
    Drop(&'static str),
    Disconnect(&'static str),
}

/// Over the gossip budget a message is dropped and the forwarder kept: an honest relay passes on
/// whatever its mesh sends it, so disconnecting it for that blames an honest peer for its mesh.
/// gossipsub 0.50.1's bounded send queue is the leak defence a disconnect would stand for. A banned
/// or quarantined forwarder is disconnected, only while we are caught up.
fn gossip_gate(
    buckets: &mut HashMap<PeerId, RateBucket>,
    bans: &mut HashMap<PeerId, Instant>,
    quarantine: &HashMap<PeerId, Instant>,
    p: PeerId,
    caught_up: bool,
) -> GossipGate {
    if is_banned(bans, &p) {
        return if caught_up { GossipGate::Disconnect("banned") } else { GossipGate::Drop("banned") };
    }
    if is_quarantined(quarantine, &p) {
        return if caught_up { GossipGate::Disconnect("quarantined") } else { GossipGate::Drop("quarantined") };
    }
    if !allow_gossip(buckets, bans, p) {
        return GossipGate::Drop("gossip rate limit");
    }
    GossipGate::Admit
}

// ----------------- libp2p behaviour -----------------

/// Test-only peer behavior switch for the live p2p integration lane (tests/p2p_live_*.rs).
/// Exists ONLY under the `test-bypass` cargo feature: production/release builds contain
/// neither this enum, the `NetConfig::test_mode` field, nor the request-handler branches
/// below; there is no runtime switch to abuse. The live p2p lane depends on it: do not remove it
/// without deleting the lane.
#[cfg(feature = "test-bypass")]
#[derive(Clone, Debug)]
pub enum TestPeerMode {
    Normal,
    /// Accept GetBlock requests but never respond (a connected-but-silent peer): the request ends
    /// at the request-response timeout, or at once when the requester already holds four on that
    /// connection (`with_max_concurrent_streams`), and the block is fetched from another peer.
    StallBlockResponses,
    /// Leave only the first GetBlock unanswered and serve the rest (a slow-then-honest peer).
    StallFirstBlockRequest,
    /// Answer GetBlock with "unknown block" errors (exercises invalid-provider fallback).
    UnknownBlockResponses,
    /// Serve blocks that carry a non-coinbase input with one signature byte flipped; the txids,
    /// and so the header, still match (exercises the dropped-body refetch).
    SubstituteSignatures,
    /// Serve a block with an odd number (above one) of txs with its last tx repeated; the merkle
    /// root repeats the last node of an odd layer, so the body still binds (exercises the store
    /// refusal).
    RepeatLastTxOfOddBlocks,
    /// Answer GetBlock for a block that carries a non-coinbase tx only at the next poll tick, so
    /// its descendants arrive first (exercises a deferred reorg).
    DelayBlocksWithSpends,
    /// As `SubstituteSignatures`, and once it has served an altered body, answer every GetTip with
    /// that body (exercises the refusal of a block response to another kind of request).
    PushSubstitutedOnTip,
    /// Answer every GetBlock with `Ack`, a well-formed answer of the wrong kind (exercises the
    /// fallback from a provider that answers but never serves).
    AckBlockRequests,
    /// Answer GetTip in turn with `MAX_HEADERS_PER_SYNC` copies of the local tip's header and with
    /// a Tip claiming an unknown hash and the most work, and answer GetHeadersByLocator with
    /// `MAX_HEADERS_PER_SYNC` copies of the tip's parent header (exercises the header credit).
    ReplayHeaders,
    /// Publish gossip unsigned. A debug build verifies an ed25519 signature in about 8 ms, so only
    /// unsigned messages reach a node's gossip budget within one rate window there.
    AnonymousGossip,
    /// Answer GetHeadersByLocator with a Tip naming this header (exercises the refusal of a Tip
    /// sent to another kind of request).
    TipForHeaders(crate::types::Hash32),
    /// Hold every headers request (GetHeaders, GetHeadersByLocator) served off the loop (`Serves`)
    /// this long on the blocking pool, with its serve permit, before serving it (a slow store read);
    /// the other kinds are served at once.
    SlowHeaderServes(std::time::Duration),
    /// Answer every request served off the loop with a response at or above MAX_RR_MSG_BYTES, which
    /// the codec refuses to write, as it would a stored block between 1 and 2 MiB: our write fails.
    OversizedAnswers,
}

/// Tips a `TipForHeaders` peer sent in answer to GetHeadersByLocator (live p2p lane).
#[cfg(feature = "test-bypass")]
pub static TEST_TIPS_FOR_HEADERS: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);

/// Headers answers a `ReplayHeaders` peer sent to GetTip and to GetHeadersByLocator (live p2p lane).
#[cfg(feature = "test-bypass")]
pub static TEST_REPLAYED_HEADERS: [std::sync::atomic::AtomicU64; 2] =
    [std::sync::atomic::AtomicU64::new(0), std::sync::atomic::AtomicU64::new(0)];

/// Gossip tx checks started, by forwarder (live p2p lane: the refusal budget's real bound).
#[cfg(feature = "test-bypass")]
pub static TEST_GOSSIP_TX_CHECKS: std::sync::Mutex<std::collections::BTreeMap<PeerId, u64>> =
    std::sync::Mutex::new(std::collections::BTreeMap::new());

/// A delay before each gossip tx check of a forwarder's txs, by forwarder (live p2p lane: a check
/// that returns after gossipsub dropped the message).
#[cfg(feature = "test-bypass")]
pub static TEST_GOSSIP_TX_CHECK_DELAY: std::sync::Mutex<std::collections::BTreeMap<PeerId, Duration>> =
    std::sync::Mutex::new(std::collections::BTreeMap::new());

/// Gossip headers dropped for the forwarder's budget, by (receiver, forwarder) (live p2p lane).
#[cfg(feature = "test-bypass")]
pub static TEST_RATE_DROPPED_HEADERS: std::sync::Mutex<
    std::collections::BTreeMap<(PeerId, PeerId), std::collections::HashSet<Hash32>>,
> = std::sync::Mutex::new(std::collections::BTreeMap::new());

/// GetPeers requests this node received, by (this node, the asking peer) (live p2p lane).
#[cfg(feature = "test-bypass")]
pub static TEST_PEERS_REQUESTS_SERVED: std::sync::Mutex<std::collections::BTreeMap<(PeerId, PeerId), u64>> =
    std::sync::Mutex::new(std::collections::BTreeMap::new());

/// Empty Headers answers to our headers request, by the answering peer (live p2p lane).
#[cfg(feature = "test-bypass")]
pub static TEST_EMPTY_HEADERS_ANSWERS: std::sync::Mutex<std::collections::BTreeMap<PeerId, u64>> =
    std::sync::Mutex::new(std::collections::BTreeMap::new());

/// GetBlock requests an `AckBlockRequests` peer answered with `Ack` (live p2p lane).
#[cfg(feature = "test-bypass")]
pub static TEST_ACKED_BLOCK_REQUESTS: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);

/// Block responses a `PushSubstitutedOnTip` peer sent in answer to GetTip (live p2p lane).
#[cfg(feature = "test-bypass")]
pub static TEST_PUSHED_BODIES: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);

/// GetBlock requests a `StallBlockResponses` peer left unanswered (live p2p lane).
#[cfg(feature = "test-bypass")]
pub static TEST_STALLED_BLOCK_REQUESTS: std::sync::atomic::AtomicU64 =
    std::sync::atomic::AtomicU64::new(0);

/// Each running node's peer scores, keyed by its own PeerId, copied at every poll tick (live p2p
/// lane). A peer without an entry has score 0.
#[cfg(feature = "test-bypass")]
pub static TEST_PEER_SCORES: std::sync::Mutex<std::collections::BTreeMap<PeerId, HashMap<PeerId, i32>>> =
    std::sync::Mutex::new(std::collections::BTreeMap::new());

/// Each running node's bad-provider stamps as (block, peer), keyed by its own PeerId, with when they
/// were copied, at every poll tick (live p2p lane).
#[cfg(feature = "test-bypass")]
pub static TEST_BAD_PROVIDERS: std::sync::Mutex<
    std::collections::BTreeMap<PeerId, (Instant, std::collections::HashSet<(Hash32, PeerId)>)>,
> = std::sync::Mutex::new(std::collections::BTreeMap::new());

/// Nodes whose p2p loop, once a connection it shed has closed, polls no swarm event until a poll
/// tick at least TEST_SWARM_HOLD later, as when other arms hold the loop that long: the failures of
/// our requests on that connection stay queued in the request-response layer across the tick. Keyed
/// by the node's own PeerId; the value is set to when it let the swarm go again (live p2p lane).
#[cfg(feature = "test-bypass")]
pub static TEST_HOLD_SWARM_AFTER_SHED: std::sync::Mutex<std::collections::BTreeMap<PeerId, Option<Instant>>> =
    std::sync::Mutex::new(std::collections::BTreeMap::new());

/// How long `TEST_HOLD_SWARM_AFTER_SHED` holds the swarm at least: past 5 s, so a node that
/// remembered a shed connection for only 5 s would fail.
#[cfg(feature = "test-bypass")]
const TEST_SWARM_HOLD: Duration = Duration::from_secs(6);

/// Answers of serves off the loop handed to the request-response layer, by the serving node (live
/// p2p lane).
#[cfg(feature = "test-bypass")]
pub static TEST_SERVES_ANSWERED: std::sync::Mutex<std::collections::BTreeMap<PeerId, u64>> =
    std::sync::Mutex::new(std::collections::BTreeMap::new());

/// Serves off the loop started and not yet returned (waiting for their turn or running), by the
/// serving node, as of its last serve start or return (live p2p lane).
#[cfg(feature = "test-bypass")]
pub static TEST_SERVES_PENDING: std::sync::Mutex<std::collections::BTreeMap<PeerId, usize>> =
    std::sync::Mutex::new(std::collections::BTreeMap::new());

/// Bodies served altered by a `SubstituteSignatures` or `RepeatLastTxOfOddBlocks` peer (live p2p lane).
#[cfg(feature = "test-bypass")]
pub static TEST_SUBSTITUTED_BODIES_SERVED: std::sync::atomic::AtomicU64 =
    std::sync::atomic::AtomicU64::new(0);


#[derive(Clone)]
pub struct NetConfig {
    pub datadir: String,
    pub listen: Multiaddr,
    pub bootnodes: Vec<Multiaddr>,
    pub genesis_hash: Hash32,
    pub is_bootnode: bool,
    /// Test-only behavior switch (live p2p lane). Present only under `test-bypass`.
    #[cfg(feature = "test-bypass")]
    pub test_mode: TestPeerMode,
}

#[derive(Clone)]
pub struct NetHandle {
    pub peer_id: PeerId,
    pub connected_peers: Arc<AtomicUsize>,
    /// Size of the p2p loop's `outbound` set (peers we dialed).
    pub outbound_peers: Arc<AtomicUsize>,
    pub known_peers: Arc<AtomicUsize>,
    last_tip_seen_unix: Arc<AtomicU64>,
    last_peer_change_unix: Arc<AtomicU64>,
    best_peer_height: Arc<AtomicU64>,
    best_peer_work: Arc< RwLock<u128> >,
    best_peer_tip: Arc<RwLock<Hash32>>,
    listen_addr: Arc<RwLock<Option<Multiaddr>>>,
}

impl NetHandle {

// Shared handles to the two p2p gauges the RPC reports on /health.
// Returned as Arc clones rather than making the fields pub, so NetHandle keeps its shape.
pub fn best_peer_height_gauge(&self) -> Arc<AtomicU64> {
    self.best_peer_height.clone()
}

pub fn tip_activity_gauge(&self) -> Arc<AtomicU64> {
    self.last_tip_seen_unix.clone()
}

pub fn known_peers(&self) -> usize {
    self.known_peers.load(Ordering::Relaxed)
}

    pub fn connected_peers(&self) -> usize {
        self.connected_peers.load(Ordering::Relaxed)
    }

    pub async fn listen_addr(&self) -> Option<Multiaddr> {
        self.listen_addr.read().await.clone()
    }

    pub fn last_tip_seen_unix(&self) -> u64 {
        self.last_tip_seen_unix.load(Ordering::Relaxed)
    }

pub async fn best_peer_tip(&self) -> Hash32 {
    *self.best_peer_tip.read().await
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

pub async fn best_peer_work(&self) -> u128 {
    *self.best_peer_work.read().await
}
}

#[derive(Debug)]
pub enum OutEvent {
    Gossipsub(gossipsub::Event),
    Rr(request_response::Event<SyncRequest, SyncResponse>),
    Identify(identify::Event),
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

impl From<identify::Event> for OutEvent {
    fn from(e: identify::Event) -> Self {
        OutEvent::Identify(e)
    }
}

/// The admission behaviours emit no events.
impl From<std::convert::Infallible> for OutEvent {
    fn from(e: std::convert::Infallible) -> Self {
        match e {}
    }
}

#[derive(NetworkBehaviour)]
#[behaviour(to_swarm = "OutEvent")]
pub struct Behaviour {
    /// Connection admission (`super::admission`): per peer, inbound, per address, and in their
    /// handshake. These
    /// come first: the derive calls each field's `handle_established_*` in order and stops at the
    /// first refusal (libp2p-swarm-derive 0.36.0 lib.rs:290-310), and a field before them records a
    /// connection they then refuse; request-response kept such a connection for good (0.30.0
    /// lib.rs:757, no ListenFailure handling at :836-847), routed requests to it, and asserted it away
    /// in a debug build when the peer's last connection closed (:678).
    limits: super::admission::ConnectionCaps,
    inbound_addresses: super::admission::InboundPerAddress,
    pub gossipsub: gossipsub::Behaviour,
    pub rr: request_response::Behaviour<SyncCodec>,
    pub identify: identify::Behaviour,
}

/// Decodes one wire message, a request-response frame or a gossip payload, with the consensus
/// codec settings under a size limit: bincode-1.3.3 `DefaultOptions` (`config/mod.rs:84-102`)
/// with fixint encoding, so little endian and trailing bytes refused. Every encoder of these
/// messages writes `consensus_bincode()` output and nothing after it (`write_request`,
/// `write_response`, `publish_header`, the tx gossip publish), so bytes past the value come only
/// from a crafted copy, and a padded copy of a gossip message would carry a new message id.
fn decode_wire<T: serde::de::DeserializeOwned>(data: &[u8], limit: u64) -> bincode::Result<T> {
    bincode::options()
        .with_fixint_encoding()
        .with_limit(limit)
        .deserialize::<T>(data)
}

/// A request's kind on the wire: bincode's u32 variant index of `SyncRequest` (fixint, little
/// endian), ahead of its fields.
const REQUEST_TAG_BYTES: u64 = 4;

/// The largest encoding of each request kind, by its variant index in `SyncRequest` (proto.rs,
/// frozen): no honest request of a kind is larger. Upstream (v1.0.0 to main d168f70) sends GetTip,
/// GetPeers, GetBlock and GetHeadersByLocator with at most 65 hashes (`build_locator`: 64 and the
/// zero hash), never GetHeaders or SubmitTx; our server refuses a locator above MAX_LOCATOR_LEN (128,
/// upstream's), and a tx above MAX_TX_BYTES is invalid. `sync_transport_cap_tests` pins each against
/// the codec.
fn request_limit(tag: u32) -> Option<u64> {
    const HASH: u64 = 32;
    Some(match tag {
        0 => REQUEST_TAG_BYTES,                                          // GetTip
        1 => REQUEST_TAG_BYTES + 8 + 8,                                  // GetHeaders { from_height, max }
        2 => REQUEST_TAG_BYTES + 8 + HASH * MAX_LOCATOR_LEN as u64 + 8,  // GetHeadersByLocator { locator, max }
        3 => REQUEST_TAG_BYTES + HASH,                                   // GetBlock { hash }
        4 => REQUEST_TAG_BYTES + MAX_TX_BYTES as u64,                    // SubmitTx { tx }
        5 => REQUEST_TAG_BYTES + 2,                                      // GetPeers { max: u16 }
        _ => return None,
    })
}

#[derive(Clone, Default)]
pub struct SyncCodec;

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
        // The kind first, then at most that kind's largest encoding, so a request is not read up to
        // the wire limit whatever its kind, four streams a connection.
        let mut tag = [0u8; REQUEST_TAG_BYTES as usize];
        io.read_exact(&mut tag).await?;
        let Some(limit) = request_limit(u32::from_le_bytes(tag)) else {
            return Err(std::io::Error::new(std::io::ErrorKind::InvalidData, "unknown request kind"));
        };
        let mut buf = tag.to_vec();
        let mut limited = io.take(limit - REQUEST_TAG_BYTES + 1);
        limited.read_to_end(&mut buf).await?;
        if buf.len() as u64 > limit {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "request too large",
            ));
        }

let req: SyncRequest = decode_wire(&buf, limit)
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
                RESPONSE_TOO_LARGE,
            ));
        }

let resp: SyncResponse = decode_wire(&buf, MAX_RR_MSG_BYTES)
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


#[derive(Clone, Debug, Default)]
struct PeerQuality {
    dial_success: u64,
    dial_failure: u64,
    good_tip: u64,
    good_block: u64,
	canonical_block: u64,
    timeout: u64,
    invalid: u64,
    last_seen_unix: u64,
    last_tip_height: u64,
    last_tip_work: u128,
}

/// Dial successes and Tip answers past these rank nothing more: reaching a peer and hearing its tip
/// are presence, at most 100 points each, so serving blocks (25 a served block, 100 a canonical one)
/// decides the order (uncapped, an identity that reconnected or stayed connected would outrank every
/// honest provider).
const DIAL_SUCCESSES_RANKED: u64 = 5;
const TIP_ANSWERS_RANKED: u64 = 20;

fn peer_quality_score(q: &PeerQuality) -> i128 {
    let mut s: i128 = 0;

    s += (q.dial_success.min(DIAL_SUCCESSES_RANKED) as i128) * 20;
    s -= (q.dial_failure as i128) * 25;

    s += (q.good_tip.min(TIP_ANSWERS_RANKED) as i128) * 5;
    s += (q.good_block as i128) * 25;

	s += (q.canonical_block as i128) * 100;

    s -= (q.timeout as i128) * 20;
    s -= (q.invalid as i128) * 50;

    s += (q.last_tip_height as i128) / 10;
    s += (q.last_tip_work.min(i128::MAX as u128) as i128) / 1_000_000_000_000i128;

    let age = unix_now().saturating_sub(q.last_seen_unix);
    if age < 3600 {
        s += 100;
    } else if age < 86400 {
        s += 25;
    } else {
        s -= 50;
    }

    s
}

/// Records a Tip answer in the peer's quality: the answer counts, and the claimed height and work
/// come only from our own index of the claimed header (`indexed`), so a claim we cannot check
/// leaves the last checked one in place. A Tip answer earns no score: naming a hash costs a peer
/// nothing.
/// Only an answer to our GetTip counts (`asked`), as for Headers: a Tip sent to another request
/// earns no quality.
fn note_tip_answer(q: &mut PeerQuality, asked: Option<Asked>, indexed: Option<&HeaderIndex>, now: u64) {
    if asked != Some(Asked::Tip) {
        return;
    }
    q.good_tip = q.good_tip.saturating_add(1);
    q.last_seen_unix = now;
    if let Some(hi) = indexed {
        q.last_tip_height = hi.height;
        q.last_tip_work = hi.chainwork;
    }
}

/// Records a peer's first connection in its quality: a dial success only when we dialed it. If every
/// connection counted, inbound included, an identity reconnecting to us would gain 20 points a
/// time.
fn note_connected(q: &mut PeerQuality, dialer: bool, now: u64) {
    if dialer {
        q.dial_success = q.dial_success.saturating_add(1);
    }
    q.last_seen_unix = now;
}

/// Whether a failed request of ours costs the peer a timeout in its quality record: only the
/// request-response timeout. A ConnectionClosed (the peer's restart, or our own disconnect with a
/// request in flight), an unsupported protocol, an IO error and our own stream refusal are not
/// charged. A failed dial is charged once, as `dial_failure`.
fn charges_quality_timeout(e: &request_response::OutboundFailure) -> bool {
    matches!(e, request_response::OutboundFailure::Timeout)
}

fn sort_peer_ids_by_quality(
    peer_ids: &mut Vec<PeerId>,
    peer_quality: &HashMap<PeerId, PeerQuality>,
) {
    peer_ids.sort_by(|a, b| {
        let qa = peer_quality.get(a).cloned().unwrap_or_default();
        let qb = peer_quality.get(b).cloned().unwrap_or_default();

        peer_quality_score(&qb)
            .cmp(&peer_quality_score(&qa))
            .then_with(|| a.to_string().cmp(&b.to_string()))
    });
}

fn peer_scores_path(datadir: &str) -> std::path::PathBuf {
    std::path::PathBuf::from(datadir).join(PEER_SCORES_FILE)
}

/// Format tag for peer_scores.txt (test-visible).
///
/// Every file written without this tag (upstream's format) was rotated by the column bug fixed in
/// `load_peer_quality`, and each save/load cycle rotated it further, so the values on disk are
/// not recoverable. Rather than migrate garbage, a file without this exact first line is
/// ignored: one session of slightly worse startup dial ordering, then correct data forever.
const PEER_QUALITY_FORMAT: &str = "csd-peer-quality v2";

/// Cap on persisted reputation records. `peers.txt` is bounded by MAX_KNOWN_PEERS, but this file
/// never was: a long-running mainnet miner held 1,443 records against a 128-peer cap.
const MAX_QUALITY_RECORDS: usize = 512;

/// Records older than this are dropped on save; a peer not seen in a month tells us nothing.
const QUALITY_RECORD_MAX_AGE_SECS: u64 = 30 * 24 * 3600;

fn load_peer_quality(datadir: &str) -> HashMap<PeerId, PeerQuality> {
    let mut out = HashMap::new();
    let p = peer_scores_path(datadir);

    let Ok(s) = std::fs::read_to_string(&p) else {
        return out;
    };

    let mut lines = s.lines();
    match lines.next() {
        Some(first) if first.trim() == PEER_QUALITY_FORMAT => {}
        _ => {
            println!(
                "[p2p] peer quality file is in the pre-v0.1.8 (column-rotated) format; ignoring it and starting fresh"
            );
            return out;
        }
    }

    for line in lines {
        let parts: Vec<&str> = line.split_whitespace().collect();
// v2 records are always 12 columns. The old 11-column form is only reachable through a
// hand-edited or truncated file, and accepting it here while indexing parts[11] below is a
// panic on the startup path, inside the supervised p2p task: RPC up, tip frozen, no restart.
if parts.len() != 12 {
    continue;
}

        let Ok(pid) = parts[0].parse::<PeerId>() else {
            continue;
        };

        let q = PeerQuality {
            dial_success: parts[1].parse().unwrap_or(0),
            dial_failure: parts[2].parse().unwrap_or(0),
            good_tip: parts[3].parse().unwrap_or(0),
            // parts[4] holds good_headers in upstream's layout (15 points per header in any answer);
            // it is written as 0 and not read, so a count farmed in an older file ranks nothing.
            good_block: parts[5].parse().unwrap_or(0),
            // Column order fixed. save_peer_quality writes
            //   pid ds df gt gh gb canonical timeout invalid last_seen lth ltw
            // i.e. canonical_block at index 6, but the loader read canonical_block from index 11
            // and everything from 6 onward shifted by one. Every save/load round trip rotated the
            // record by six fields, so a peer's canonical-block count came back as its TIMEOUT
            // count (-20 each in peer_quality_score) and last_seen_unix came back as 0, which
            // trips the "stale, older than a day" branch for another -50. The persisted
            // reputation file therefore demoted precisely the peers that had served best, on
            // every restart, and re-saved the rotated values so it compounded. Confirmed on a
            // running node's file: a unix timestamp had migrated into the canonical_block column.
            // Upstream v1.1.2 and main d168f70 have the same loader.
            canonical_block: parts[6].parse().unwrap_or(0),
            timeout: parts[7].parse().unwrap_or(0),
            invalid: parts[8].parse().unwrap_or(0),
            last_seen_unix: parts[9].parse().unwrap_or(0),
            last_tip_height: parts[10].parse().unwrap_or(0),
            last_tip_work: parts[11].parse().unwrap_or(0),
        };

        out.insert(pid, q);
    }

    out
}

fn save_peer_quality(datadir: &str, qmap: &HashMap<PeerId, PeerQuality>) {
    let p = peer_scores_path(datadir);
    let tmp = p.with_extension("tmp");

    let mut rows = vec![PEER_QUALITY_FORMAT.to_string()];

    // Bound the file: drop records we have not seen in a month, then keep the best
    // MAX_QUALITY_RECORDS by the same score the dial ordering uses.
    let now = unix_now();
    let mut peers: Vec<_> = qmap
        .iter()
        .filter(|(_, q)| {
            q.last_seen_unix == 0 || now.saturating_sub(q.last_seen_unix) < QUALITY_RECORD_MAX_AGE_SECS
        })
        .map(|(pid, q)| (*pid, peer_quality_score(q)))
        .collect();
    peers.sort_by(|a, b| b.1.cmp(&a.1));
    peers.truncate(MAX_QUALITY_RECORDS);
    // Stable on-disk ordering so a diff of two files is meaningful. Encode each PeerId ONCE:
    // sorting by `a.to_string().cmp(&b.to_string())` re-encodes both sides of every comparison,
    // which is thousands of base58 encodings and allocations per save, on the swarm loop.
    let mut peers: Vec<(String, PeerId)> =
        peers.into_iter().map(|(pid, _)| (pid.to_string(), pid)).collect();
    peers.sort_by(|a, b| a.0.cmp(&b.0));

    for (_, pid) in peers {
        let Some(q) = qmap.get(&pid) else { continue };

        rows.push(format!(
            "{} {} {} {} {} {} {} {} {} {} {} {}",
            pid,
            q.dial_success,
            q.dial_failure,
            q.good_tip,
            0,
            q.good_block,
			q.canonical_block,
            q.timeout,
            q.invalid,
            q.last_seen_unix,
            q.last_tip_height,
            q.last_tip_work,
        ));
    }

    if std::fs::write(&tmp, rows.join("\n")).is_ok() {
        let _ = std::fs::rename(&tmp, &p);
    }
}


// ── block body binding ──────────────────────────────────────────────────────────────────────────
//
// A peer can answer `SyncRequest::GetBlock` with a REAL header and a SUBSTITUTED body.
// `accept_header_universe_pow` below binds a header to the PoW universe and never touches
// `block.txs`; `store_block_bytes_checked` binds the body to the header's merkle root and refuses
// a body that repeats a txid (the root repeats the last node of an odd layer, so a repeated suffix
// binds) before the first-writer-wins store. The merkle root commits to txids, which leave out the
// script_sig of non-coinbase inputs (`crypto::txid`), so a body with altered signatures binds and
// is stored. Its apply then fails on a signature, and `chain::body_fault` drops that body instead
// of marking the hash, and the block is fetched again from another peer (`BodyRefetch`), so neither
// kind of body marks the honest block and tip bad.
//
// RULE: no path may persist block bytes that have not been bound to their header.
// `store_block_bytes_checked` is the ONLY writer of `db.blocks` on the network path; both store
// sites (the GetBlock response handler and the `pending_apply` drain) go through it.
//
// CONSENSUS-NEUTRAL BY CONSTRUCTION: it cannot reject a body consensus accepts, because consensus
// rejects that exact body at `state::utxo::validate_and_apply_block`, through the same
// `validate_block_merkle` call.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BlockStoreOutcome {
    Stored,
    AlreadyPresent,
    RejectedMerkle,
    RejectedOversize,
    /// The body binds to the header but repeats a txid: a merkle duplicate of the honest list
    /// (`chain::body_fault`) or an invalid block; no body that repeats a txid is valid.
    RejectedRepeatedTxid,
}

pub fn store_block_bytes_checked(
    db: &Stores,
    bh: &Hash32,
    block: &Block,
) -> Result<BlockStoreOutcome> {
    // The bind runs FIRST, ahead of any read or write: a body that does not belong to its header
    // must not reach `db.blocks`, the header index, or `pending_apply`.
    if crate::state::utxo::validate_block_merkle(block).is_err() {
        return Ok(BlockStoreOutcome::RejectedMerkle);
    }
    if crate::chain::body_fault::first_repeated_txid(block).is_some() {
        return Ok(BlockStoreOutcome::RejectedRepeatedTxid);
    }

    if db.blocks.get(k_block(bh))?.is_some() {
        return Ok(BlockStoreOutcome::AlreadyPresent);
    }

    let bytes = crate::codec::consensus_bincode().serialize(block)?;
    if bytes.len() > MAX_BLOCK_BYTES {
        return Ok(BlockStoreOutcome::RejectedOversize);
    }

    db.blocks.insert(k_block(bh), bytes)?;
    Ok(BlockStoreOutcome::Stored)
}

/// The serve leg of the body binding. A node that stored a poisoned body without the store-time
/// bind (a database written by a build without it) would RE-SERVE it to every peer that asked,
/// which is the difference between one node and a cascade. Re-running
/// `accept_header_universe_pow` alone does not catch it: that passes on a genuine header.
///
/// Returns `None` when the block may be sent as-is.
pub fn outbound_block_refusal(
    cfg: &NetConfig,
    block: &Block,
    bh: &Hash32,
) -> Option<&'static str> {
    if header_universe_pow_refusal(cfg, &block.header, bh).is_some() {
        return Some("refusing to serve foreign/invalid pow block");
    }
    if crate::state::utxo::validate_block_merkle(block).is_err() {
        return Some("refusing to serve block whose body does not bind to its header");
    }
    if crate::chain::body_fault::first_repeated_txid(block).is_some() {
        return Some("refusing to serve block whose body repeats a txid");
    }
    match crate::codec::consensus_bincode().serialize(block) {
        Ok(bytes) if bytes.len() > MAX_BLOCK_BYTES => Some("block too large"),
        _ => None,
    }
}

/// Why `hdr` is outside this chain's PoW universe (a foreign genesis, bits past the PoW limit, failing
/// PoW), or None.
fn header_universe_pow_refusal(cfg: &NetConfig, hdr: &BlockHeader, h: &Hash32) -> Option<&'static str> {
    if is_genesis_header(hdr) && *h != cfg.genesis_hash {
        return Some("foreign genesis header");
    }
    if !bits_within_pow_limit(hdr.bits) {
        return Some("header bits beyond pow limit");
    }
    if !pow_ok(h, hdr.bits) {
        return Some("header failing PoW");
    }
    None
}

/// Whether `hdr`, from `peer`, is within this chain's PoW universe; a refusal is logged (`peer_line`).
fn accept_header_universe_pow(cfg: &NetConfig, hdr: &BlockHeader, h: &Hash32, peer: &PeerId) -> bool {
    let Some(why) = header_universe_pow_refusal(cfg, hdr, h) else {
        return true;
    };
    if let Some(n) = peer_line(peer, Line::RefusedHeader) {
        println!("[p2p] ignoring {why} {} from {peer} since_last_line={n}", hex32(h));
    }
    false
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
) -> (u64, u128) {
    let mut best_h: u64 = 0;
    let mut best_w: u128 = 0;

    for p in connected.iter() {
        if !peer_is_eligible(p, connected, bans, quarantine) {
            continue;
        }

        let h = *peer_heights.get(p).unwrap_or(&0);
        let w = *peer_work.get(p).unwrap_or(&0);

        if w > best_w || (w == best_w && h > best_h) {
            best_h = h;
            best_w = w;
        }
    }

    (best_h, best_w)
}


fn recompute_best_peer_tip(
    connected: &HashSet<PeerId>,
    peer_tips: &HashMap<PeerId, Hash32>,
    peer_work: &HashMap<PeerId, u128>,
    peer_score: &HashMap<PeerId, i32>,
    bans: &HashMap<PeerId, Instant>,
    quarantine: &HashMap<PeerId, Instant>,
) -> Hash32 {
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

    best.and_then(|(p, _, _, _)| peer_tips.get(&p).copied())
        .unwrap_or([0u8; 32])
}

fn penalize_stale_peers(
    connected: &HashSet<PeerId>,
    peer_heights: &HashMap<PeerId, u64>,
    peer_work: &HashMap<PeerId, u128>,
    peer_score: &mut HashMap<PeerId, i32>,
    quarantine: &mut HashMap<PeerId, Instant>,
    last_stale_penalty_at: &mut HashMap<PeerId, Instant>,
    best_height: u64,
    best_work: u128,
) {
    if best_height < STALE_PEER_LAG_BLOCKS || best_work == 0 {
        return;
    }

    for p in connected.iter().copied() {
        let h = *peer_heights.get(&p).unwrap_or(&0);
        let w = *peer_work.get(&p).unwrap_or(&0);

        if w > 0
            && w < best_work
            && h.saturating_add(STALE_PEER_LAG_BLOCKS) < best_height
        {
let due = last_stale_penalty_at
    .get(&p)
    .map(|t| t.elapsed().as_secs() >= STALE_PEER_PENALTY_COOLDOWN_SECS)
    .unwrap_or(true);

if due {
    bump_score(peer_score, quarantine, p, SCORE_BAD_STALE_PEER);
    last_stale_penalty_at.insert(p, Instant::now());
}

        }
    }
}

/// On connect and on each identify exchange, at most every BOOTSTRAP_REQ_COOLDOWN_SECS: the peer is
/// owed a peers request (a new peer's GetTip is due at once). The caller then runs
/// `pump_background`.
fn owe_bootstrap(
    peer: PeerId,
    last_bootstrap_req_at: &mut HashMap<PeerId, Instant>,
    background: &mut Background<request_response::OutboundRequestId>,
) {
    let due = last_bootstrap_req_at
        .get(&peer)
        .map(|t| t.elapsed() >= Duration::from_secs(BOOTSTRAP_REQ_COOLDOWN_SECS))
        .unwrap_or(true);
    if due {
        background.want(peer, Asked::Peers, Instant::now());
        last_bootstrap_req_at.insert(peer, Instant::now());
    }
}

/// Connected peers that are neither banned nor quarantined.
fn eligible_peers(
    connected: &HashSet<PeerId>,
    bans: &HashMap<PeerId, Instant>,
    quarantine: &HashMap<PeerId, Instant>,
) -> Vec<PeerId> {
    connected.iter().copied().filter(|p| !is_banned(bans, p) && !is_quarantined(quarantine, p)).collect()
}

/// Sends `request` to `peer` and records it in `unreported` until the request-response layer reports
/// on it. Every request of ours goes out here.
fn send_our_request(
    swarm: &mut Swarm<Behaviour>,
    unreported: &mut Unreported<request_response::OutboundRequestId>,
    peer: &PeerId,
    request: SyncRequest,
) -> request_response::OutboundRequestId {
    let rid = swarm.behaviour_mut().rr.send_request(peer, request);
    unreported.sent(rid, *peer);
    rid
}

/// Sends what `Background::schedule` picks among `eligible`: each peer's earliest due request,
/// earliest first, under the ceiling.
fn pump_background(
    swarm: &mut Swarm<Behaviour>,
    background: &mut Background<request_response::OutboundRequestId>,
    unreported: &mut Unreported<request_response::OutboundRequestId>,
    db: &Stores,
    eligible: &[PeerId],
    stale_tip: bool,
) {
    let now = Instant::now();
    for (p, kind) in background.schedule(eligible, now, stale_tip) {
        let request = match kind {
            Asked::Tip => SyncRequest::GetTip,
            Asked::Peers => SyncRequest::GetPeers { max: PEER_REQ_ON_CONNECT },
            Asked::Headers => {
                let tip = get_tip(db).ok().flatten().unwrap_or([0u8; 32]);
                let locator = build_locator(db, &tip);
                SyncRequest::GetHeadersByLocator { locator, max: MAX_HEADERS_PER_SYNC }
            }
        };
        let logged = match kind {
            Asked::Tip if !stale_tip => None,
            _ => peer_line(&p, Line::Asked),
        };
        if let (Some(n), SyncRequest::GetHeadersByLocator { locator, .. }) = (logged, &request) {
            println!("[sync] requesting headers-by-locator from {} (locator_len={}) since_last_line={n}", p, locator.len());
        }
        let rid = send_our_request(swarm, unreported, &p, request);
        background.sent(rid, p, kind, now);
        match (kind, logged) {
            (Asked::Peers, Some(n)) => println!("[pex] requested peers from {p} since_last_line={n}"),
            (Asked::Tip, Some(n)) => println!("[sync] stale-tip poll to {p} since_last_line={n}"),
            _ => {}
        }
    }
}

fn choose_best_sync_peer(
    connected: &HashSet<PeerId>,
    peer_work: &HashMap<PeerId, u128>,
    peer_score: &HashMap<PeerId, i32>,
    bans: &HashMap<PeerId, Instant>,
    quarantine: &HashMap<PeerId, Instant>,
) -> Option<PeerId> {
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
}

fn mark_peer_change(last_peer_change_unix: &Arc<AtomicU64>) {
    last_peer_change_unix.store(unix_now(), Ordering::Relaxed);
}

fn mark_tip_seen(last_tip_seen_unix: &Arc<AtomicU64>) {
    last_tip_seen_unix.store(unix_now(), Ordering::Relaxed);
}

fn pump_blocks(
    swarm: &mut Swarm<Behaviour>,
    unreported: &mut Unreported<request_response::OutboundRequestId>,
    sync_peer: Option<PeerId>,
    connected: &HashSet<PeerId>,
    providers: &HashMap<Hash32, PeerId>,
    bad_providers: &mut HashMap<Hash32, HashMap<PeerId, Instant>>,
    bans: &HashMap<PeerId, Instant>,
    quarantine: &mut HashMap<PeerId, Instant>,
    rid_to_hash: &mut HashMap<request_response::OutboundRequestId, Hash32>,
    db: &Stores,
    pending_apply: &HashMap<Hash32, Block>,
    want_blocks: &mut VecDeque<Hash32>,
    inflight: &mut HashMap<Hash32, (request_response::OutboundRequestId, Instant, PeerId)>,
    body_refetch: &BodyRefetch,
    retired: &mut RetiredBlockRequests,
) -> Result<()> {

let (_local_tip, _local_height, local_work) = local_tip_and_work(db);

            let now = Instant::now();
            let expired: Vec<(Hash32, PeerId)> = inflight
                .iter()
                .filter(|(_, (_, t0, _))| now.duration_since(*t0).as_secs() >= BLOCK_REQ_TIMEOUT_SECS)
                .map(|(h, (_, _, peer))| (*h, *peer))
                .collect();
            for (h, peer) in expired {
                if let Some((rid, _t0, _)) = inflight.remove(&h) {
                    rid_to_hash.remove(&rid);
                    retired.retire(rid, h, peer);
                }
                if want_blocks.len() < MAX_WANT_QUEUE {
                    want_blocks.push_back(h);
                }
                println!(
                    "[sync] requeue block {} from {}: nothing reported in {BLOCK_REQ_TIMEOUT_SECS} s",
                    hex32(&h),
                    peer
                );
            }

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


let queued_strictly_better = worth_requesting(db, &queued_h, local_work, body_refetch)?;
  if !queued_strictly_better {
continue; }

        // Preference order: the recorded provider and the sync peer when they serve blocks, then
        // connected peers that serve blocks, then header-only ones.
        let mut candidates: Vec<PeerId> = Vec::new();
        candidates.extend(providers.get(&target_h).copied().filter(|p| !is_header_only(p)));
        candidates.extend(sync_peer.filter(|p| !is_header_only(p)));
        candidates.extend(connected.iter().filter(|p| !is_header_only(p)).copied());
        candidates.extend(connected.iter().filter(|p| is_header_only(p)).copied());
        let usable = |p: &PeerId| can_take_block_request(p, connected, bans, quarantine, inflight);
        let target_peer = pick_block_peer(&candidates, usable, &target_h, bad_providers, body_refetch);
        let peer_reason = format!("{} candidates, none usable or unstamped", candidates.len());

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

    let rid = send_our_request(swarm, unreported, &peer, SyncRequest::GetBlock { hash: h });
    note_block_request_sent(rid, peer, h, rid_to_hash, inflight);

    println!(
        "[sync] request block {} from {} (height={})",
        hex32(&h),
        peer,
        best_height
    );
}

            Ok(())
        }

fn is_bad(
    bad: &HashMap<Hash32, HashMap<PeerId, Instant>>,
    h: &Hash32,
    p: &PeerId,
) -> bool {
    bad.get(h)
        .and_then(|m| m.get(p))
        .map(|t| t.elapsed().as_secs() < BAD_PROVIDER_RETRY_SECS)
        .unwrap_or(false)
}

/// How long a retired GetBlock stays answerable as a late block response.
const RETIRED_REQUEST_SECS: u64 = 60;

/// GetBlock requests this node stopped waiting for (the timeout sweep, scrub_stale_inflight)
/// while the peer can still answer. Only an answer to one of these, for the block asked and from
/// the peer asked, is taken as a late block response; any other block response with an unknown
/// request id (one answering GetTip, say) is unsolicited.
#[derive(Default)]
struct RetiredBlockRequests(HashMap<request_response::OutboundRequestId, (Hash32, PeerId, Instant)>);

impl RetiredBlockRequests {
    fn retire(&mut self, rid: request_response::OutboundRequestId, h: Hash32, peer: PeerId) {
        self.0.insert(rid, (h, peer, Instant::now()));
    }

    /// The block and peer of a retired request, consumed.
    fn take(&mut self, rid: &request_response::OutboundRequestId) -> Option<(Hash32, PeerId)> {
        self.0.remove(rid).map(|(h, p, _)| (h, p))
    }

    fn prune(&mut self) {
        self.0.retain(|_, (_, _, t)| t.elapsed().as_secs() < RETIRED_REQUEST_SECS);
        if self.0.len() > MAX_PROVIDERS {
            self.0.clear();
        }
    }
}

#[derive(Debug, PartialEq, Eq)]
enum LateBlock {
    Accept,
    Ignore,
    Unsolicited,
}

/// The verdict on a block response whose request id is no longer awaited: taken only as the
/// answer to a retired GetBlock (`retired`) for this block from the peer asked, with its header
/// indexed; ignored when the body is already stored or the peer's body for it failed; otherwise
/// unsolicited.
fn late_block_verdict(
    retired: Option<(Hash32, PeerId)>,
    bh: &Hash32,
    peer: &PeerId,
    header_indexed: bool,
    already_stored: bool,
    faulted: bool,
) -> LateBlock {
    match retired {
        Some((h, asked)) if h == *bh && asked == *peer && header_indexed => {
            if already_stored || faulted {
                LateBlock::Ignore
            } else {
                LateBlock::Accept
            }
        }
        _ => LateBlock::Unsolicited,
    }
}

/// How long the peer whose body was stored stays known for blame if that body is dropped.
const BODY_SOURCE_SECS: u64 = 3600;

/// Reorg targets waiting on a missing body; past this the lightest is forgotten, and the stall
/// sweep finds its chain again (`BodyRefetch::sweep`). The targets on one chain hold one wait
/// between them (`BodyRefetch::note_unreached`), so the cap counts branches, not blocks.
const MAX_REORG_WAITS: usize = 256;

/// How long the tip must stand still before a stall sweep starts; each sweep that queues nothing,
/// or the same chain again at the same tip, doubles it up to STALL_SWEEP_MAX_SECS, and a new tip
/// resets it (`BodyRefetch::sweep`).
const STALL_SWEEP_SECS: u64 = 30;
const STALL_SWEEP_MAX_SECS: u64 = 480;

/// Header-index and body reads a sweep spends per poll tick (`stored_chain::AboveTip`); a sweep
/// that needs more goes on at the next tick, so the swarm loop pays at most this much per tick.
const STALL_SWEEP_READS: u64 = 4_096;

/// A body dropped by `chain::body_fault` (the hash is not refused) or refused at store for a
/// repeated txid is fetched again from another peer. `sources` names the peer whose body was
/// stored, which may not be `providers`' latest responder; `waits` maps a reorg target heavier
/// than the local tip to the body it waits on: a body dropped from its apply path, or the first
/// one missing when `maybe_reorg_to` deferred it, and the target is retried when that body is
/// stored (`note_stored`); `faulted` keeps the peers whose body for a hash failed ineligible for
/// that hash last for BODY_SOURCE_SECS (`pick_block_peer`), so identities that answer just inside
/// the request timeout get one try each before any of them is asked again. The stall sweep keeps
/// `armed`, `stall` (the tip, since when it stood still or was last swept, the interval),
/// `search` (one in progress, and whether its pause was logged) and `last_found` (the tip and the
/// chain it last queued).
#[derive(Default)]
struct BodyRefetch {
    sources: HashMap<Hash32, (PeerId, Instant)>,
    waits: HashMap<Hash32, Hash32>,
    faulted: HashMap<Hash32, HashMap<PeerId, Instant>>,
    armed: bool,
    stall: Option<(Hash32, Instant, u64)>,
    search: Option<(crate::chain::stored_chain::AboveTip, bool)>,
    last_found: Option<(Hash32, Hash32)>,
}

impl BodyRefetch {
    /// Records the peer whose body was stored and returns the reorg targets that waited on it,
    /// which the caller re-queues (`requeue_completable_tip`).
    fn note_stored(&mut self, h: Hash32, peer: PeerId) -> Vec<Hash32> {
        self.record_source(h, peer);
        self.arm_sweep();
        let targets: Vec<Hash32> = self.waits.iter().filter(|(_, b)| **b == h).map(|(t, _)| *t).collect();
        for t in &targets {
            self.waits.remove(t);
        }
        targets
    }

    /// `target` is retried when `body` is stored. One body per target, the latest.
    fn wait(&mut self, db: &Stores, target: Hash32, body: Hash32) {
        self.waits.insert(target, body);
        if self.waits.len() > MAX_REORG_WAITS {
            let work = |t: &Hash32| get_hidx(db, t).ok().flatten().map_or(0, |hi| hi.chainwork);
            let lightest = self.waits.keys().copied().min_by_key(work);
            if let Some(t) = lightest {
                self.waits.remove(&t);
            }
        }
    }

    /// After `maybe_reorg_to(target)` from `try_apply_pending` left the tip short of `target` (a
    /// deferral, a rejection, or a dropped body after `on_dropped`), by where its apply path stops
    /// (`apply_path_stop`): at a missing body `target` waits on it and it is queued; at a `bad:`
    /// block it waits on nothing. The waits of the blocks below `target` on the path are dropped:
    /// one above the stop cannot apply before the stop clears, which retries `target` too, and one
    /// below it is in the stored chain under the stop, which goes back into `pending_apply` here
    /// when it is heavier than the local tip. For the same reason `target` records no wait when a
    /// target already waiting on the same body descends from it, so the targets on one chain hold
    /// one wait whatever order they were tried in. A stored chain heavier than the tip is then
    /// tried while a target above it on its chain waits or is pending, and otherwise by the next
    /// stall sweep (`sweep`). The queued head lies below the stop, so retries within one
    /// `try_apply_pending` pass descend.
    fn note_unreached(
        &mut self,
        db: &Stores,
        target: Hash32,
        pending_apply: &mut HashMap<Hash32, Block>,
        want_blocks: &mut VecDeque<Hash32>,
    ) -> Result<()> {
        let Some(stop) = apply_path_stop(db, &target)? else { return Ok(()) };
        for h in std::iter::once(&target).chain(&stop.below_target) {
            self.waits.remove(h);
        }
        if stop.missing {
            if !self.has_waiting_descendant(db, &target, &stop.at)? {
                self.wait(db, target, stop.at);
            }
            if !want_blocks.contains(&stop.at) && want_blocks.len() < MAX_WANT_QUEUE {
                want_blocks.push_back(stop.at);
            }
        }
        if let Some(head) = stop.applicable_head {
            if requeue_completable_tip(db, pending_apply, head)? {
                println!(
                    "[sync] the reorg to {} stops at {}; queued the stored chain below it, to {}",
                    hex32(&target),
                    hex32(&stop.at),
                    hex32(&head)
                );
            }
        }
        Ok(())
    }

    /// Whether a target already waiting on `body` descends from `target`.
    fn has_waiting_descendant(&self, db: &Stores, target: &Hash32, body: &Hash32) -> Result<bool> {
        let Some(t) = get_hidx(db, target)? else { return Ok(false) };
        for (d, b) in &self.waits {
            if b != body || d == target {
                continue;
            }
            let mut cur = get_hidx(db, d)?;
            while let Some(hi) = &cur {
                if hi.height <= t.height {
                    break;
                }
                cur = get_hidx(db, &hi.parent)?;
            }
            if cur.is_some_and(|hi| hi.hash == *target) {
                return Ok(true);
            }
        }
        Ok(false)
    }

    /// The safety net under `waits`, run from the poll tick. When a header heavier than the local
    /// tip is known, the tip has stood still for the stall interval and the sweep is armed, a
    /// search (`stored_chain::AboveTip`, the selection journal-less recovery makes at boot, down to
    /// the local chain and past no `bad:` block) puts the heaviest complete stored chain heavier
    /// than the tip into `pending_apply`. A stored body or the process start arms the sweep; it
    /// stays armed after it queues a chain, which may still be rejected, and disarms only when a
    /// search finds none: a search ended early, by a new tip (our own mined block among them) or
    /// a return to the tip, re-arms it. So a complete chain heavier than a standing tip is tried within one
    /// interval, the search and a poll tick of its last body, whatever became of its wait. A search
    /// spends at most STALL_SWEEP_READS per tick and resumes on the next; at the tip and while the
    /// tip moves the sweep reads only the tip.
    fn sweep(
        &mut self,
        db: &Stores,
        best_hdr_work: u128,
        pending_apply: &mut HashMap<Hash32, Block>,
    ) -> Result<Option<Hash32>> {
        let (tip, _height, local_work) = local_tip_and_work(db);
        if best_hdr_work <= local_work {
            self.stall = None;
            self.drop_search();
            return Ok(None);
        }
        if self.search.as_ref().is_some_and(|(search, _)| search.tip() != tip) {
            self.drop_search();
        }
        let now = Instant::now();
        let Some((_, since, interval)) = self.stall.filter(|s| s.0 == tip) else {
            self.stall = Some((tip, now, STALL_SWEEP_SECS));
            self.drop_search();
            return Ok(None);
        };
        if self.search.is_none() {
            if !self.armed || since.elapsed().as_secs() < interval {
                return Ok(None);
            }
            let Some(search) = crate::chain::stored_chain::AboveTip::new(db)? else { return Ok(None) };
            self.armed = false;
            self.search = Some((search, false));
        }
        let (search, logged) = self.search.as_mut().expect("set above");
        let mut reads = STALL_SWEEP_READS;
        let found = match search.run(db, &mut reads)? {
            crate::chain::stored_chain::Step::Paused => {
                if !*logged {
                    *logged = true;
                    println!("[sync] stall sweep: one pass needs more than {STALL_SWEEP_READS} reads; it goes on each poll tick");
                }
                return Ok(None);
            }
            crate::chain::stored_chain::Step::Exhausted => None,
            crate::chain::stored_chain::Step::Found(hi) => Some(hi),
        };
        self.search = None;
        let mut queued = None;
        let mut next = (interval * 2).min(STALL_SWEEP_MAX_SECS);
        if let Some(hi) = found {
            self.armed = true;
            if self.last_found != Some((tip, hi.hash)) {
                next = STALL_SWEEP_SECS;
            }
            self.last_found = Some((tip, hi.hash));
            if requeue_completable_tip(db, pending_apply, hi.hash)? {
                println!(
                    "[sync] stall sweep: queued the complete stored chain to {} (h={})",
                    hex32(&hi.hash),
                    hi.height
                );
                queued = Some(hi.hash);
            }
        }
        self.stall = Some((tip, now, next));
        Ok(queued)
    }

    fn arm_sweep(&mut self) {
        self.armed = true;
    }

    /// A search ended before its answer (a new tip, or back at the tip) leaves the sweep armed: it
    /// disarmed the sweep when it started, and only a finished search may.
    fn drop_search(&mut self) {
        if self.search.take().is_some() {
            self.armed = true;
        }
    }

    fn record_source(&mut self, h: Hash32, peer: PeerId) {
        self.sources.insert(h, (peer, Instant::now()));
    }

    /// The source of the dropped body is not asked for it again while the stamp lasts (a
    /// per-hash stamp, no score: an honest peer can relay a body it has not validated yet), and
    /// the body is queued for another peer.
    fn on_dropped(
        &mut self,
        db: &Stores,
        dropped: Hash32,
        target: Hash32,
        bad_providers: &mut HashMap<Hash32, HashMap<PeerId, Instant>>,
        want_blocks: &mut VecDeque<Hash32>,
    ) {
        let source = self.sources.remove(&dropped).map(|(p, _)| p);
        if let Some(p) = source {
            self.note_fault(dropped, p, bad_providers);
        }
        self.wait(db, target, dropped);
        if !want_blocks.contains(&dropped) && want_blocks.len() < MAX_WANT_QUEUE {
            want_blocks.push_back(dropped);
        }
        println!(
            "[sync] dropped the body of {} (stored from {}); fetching it from another peer",
            hex32(&dropped),
            source.map(|p| p.to_string()).unwrap_or_else(|| "unknown".to_string())
        );
    }

    /// A body `peer` served for `h` was refused at store (a repeated txid): the same per-hash
    /// treatment as a dropped body, no score (an honest peer may have stored such a body before
    /// it refused them), and `h` is queued for another peer.
    fn note_refused(
        &mut self,
        h: Hash32,
        peer: PeerId,
        bad_providers: &mut HashMap<Hash32, HashMap<PeerId, Instant>>,
        want_blocks: &mut VecDeque<Hash32>,
    ) {
        self.note_fault(h, peer, bad_providers);
        if !want_blocks.contains(&h) && want_blocks.len() < MAX_WANT_QUEUE {
            want_blocks.push_back(h);
        }
        println!("[sync] refused a body for {} from {}: it repeats a txid", hex32(&h), peer);
    }

    fn note_fault(
        &mut self,
        h: Hash32,
        peer: PeerId,
        bad_providers: &mut HashMap<Hash32, HashMap<PeerId, Instant>>,
    ) {
        bad_providers.entry(h).or_default().insert(peer, Instant::now());
        self.faulted.entry(h).or_default().insert(peer, Instant::now());
    }

    fn is_faulted(&self, h: &Hash32, p: &PeerId) -> bool {
        self.faulted
            .get(h)
            .and_then(|m| m.get(p))
            .is_some_and(|t| t.elapsed().as_secs() < BODY_SOURCE_SECS)
    }

    /// A body a reorg waits on is requested even at or below the local chainwork while that reorg
    /// is still heavier than the local tip.
    fn wanted_below_tip(&self, db: &Stores, h: &Hash32, local_work: u128) -> bool {
        self.waits.iter().any(|(target, body)| {
            body == h && get_hidx(db, target).ok().flatten().is_some_and(|hi| hi.chainwork > local_work)
        })
    }

    fn prune(&mut self, db: &Stores) {
        let (_tip, _height, local_work) = local_tip_and_work(db);
        self.sources.retain(|_, (_, t)| t.elapsed().as_secs() < BODY_SOURCE_SECS);
        self.faulted.retain(|_, peers| {
            peers.retain(|_, t| t.elapsed().as_secs() < BODY_SOURCE_SECS);
            !peers.is_empty()
        });
        self.waits.retain(|target, _| {
            get_hidx(db, target).ok().flatten().is_some_and(|hi| hi.chainwork > local_work)
        });
        if self.sources.len() > MAX_PROVIDERS {
            self.sources.clear();
        }
        if self.faulted.len() > MAX_PROVIDERS {
            self.faulted.clear();
        }
    }
}

/// Where `maybe_reorg_to(target)` stops on its apply path, the blocks above the fork point with
/// the local tip (reorg.rs, from the same `find_ancestor`): the first block in apply order that
/// has no stored body, where it defers, or a `bad:` mark (`reorg::is_bad`), where it returns or,
/// for the block its apply loop rejected, fails.
struct ApplyPathStop {
    at: Hash32,
    /// `at` has no stored body; otherwise it is marked bad.
    missing: bool,
    /// The block under `at` on the path, the head of a stored chain with no mark; None when `at`
    /// is the first block above the fork point.
    applicable_head: Option<Hash32>,
    /// The blocks below `target` on the path.
    below_target: Vec<Hash32>,
}

/// None when the path is empty (`target` is the tip or below it) or nothing on it stops.
fn apply_path_stop(db: &Stores, target: &Hash32) -> Result<Option<ApplyPathStop>> {
    let Some(tip) = get_tip(db)? else { return Ok(None) };
    let (Some(tip_hi), Some(target_hi)) = (get_hidx(db, &tip)?, get_hidx(db, target)?) else {
        return Ok(None);
    };
    let fork = crate::chain::reorg::find_ancestor(db, tip_hi, target_hi.clone())?;
    let mut path = Vec::new();
    let mut cur = target_hi;
    while cur.hash != fork.hash {
        path.push(cur.hash);
        cur = get_hidx(db, &cur.parent)?.context("apply path header missing below the target")?;
    }
    for (i, h) in path.iter().enumerate().rev() {
        let missing = !db.blocks.contains_key(k_block(h))?;
        if missing || crate::chain::reorg::is_bad(db, h)? {
            return Ok(Some(ApplyPathStop {
                at: *h,
                missing,
                applicable_head: path.get(i + 1).copied(),
                below_target: path[1..].to_vec(),
            }));
        }
    }
    Ok(None)
}

/// Puts the stored block `tip` back into `pending_apply` when its header is heavier than the
/// local tip and it is not pending there: a reorg target whose awaited body was stored
/// (`BodyRefetch::note_stored`), or the stored chain below where a reorg stopped
/// (`BodyRefetch::note_unreached`). try_apply_pending takes a candidate out of `pending_apply`
/// before `maybe_reorg_to`, so a candidate that did not reach the tip is retried only from here.
/// Returns whether it queued `tip`.
fn requeue_completable_tip(
    db: &Stores,
    pending_apply: &mut HashMap<Hash32, Block>,
    tip: Hash32,
) -> Result<bool> {
    if pending_apply.contains_key(&tip) {
        return Ok(false);
    }
    let (_local_tip, _local_height, local_work) = local_tip_and_work(db);
    if !get_hidx(db, &tip)?.is_some_and(|hi| hi.chainwork > local_work) {
        return Ok(false);
    }
    let stored = db.blocks.get(k_block(&tip))?;
    let Some(b) = stored.and_then(|v| crate::codec::consensus_bincode().deserialize::<Block>(&v).ok()) else {
        return Ok(false);
    };
    pending_apply.insert(tip, b);
    Ok(true)
}

/// Connected peers that can serve a block now: not banned, quarantined or header-only (the
/// OutboundFailure handler's rule). pace_saturated is left out: a pace-limited peer is busy
/// for at most a window, not unable to serve.
fn block_server_count(
    connected: &HashSet<PeerId>,
    bans: &HashMap<PeerId, Instant>,
    quarantine: &HashMap<PeerId, Instant>,
) -> usize {
    connected
        .iter()
        .filter(|p| !is_banned(bans, p) && !is_quarantined(quarantine, p) && !is_header_only(p))
        .count()
}

/// A GetBlock for `h` to `peer` failed: the block is queued again. A failure of ours blames nobody:
/// a local stream refusal also passes the peer over briefly (`note_streams_full`), a connection we
/// shed does not (the peer keeps its other connection). The peer's failure (the request-response
/// timeout or a transport error) scores it down, and stamps it for `h` and drops it as provider
/// only when `block_servers` is above one: with nobody to switch to, the stamp would leave `h`
/// unrequested for BAD_PROVIDER_RETRY_SECS. Returns whether it stamped.
fn note_block_request_failure(
    h: Hash32,
    peer: PeerId,
    fault: OutboundFault,
    block_servers: usize,
    peer_score: &mut HashMap<PeerId, i32>,
    quarantine: &mut HashMap<PeerId, Instant>,
    bad_providers: &mut HashMap<Hash32, HashMap<PeerId, Instant>>,
    providers: &mut HashMap<Hash32, PeerId>,
    want_blocks: &mut VecDeque<Hash32>,
) -> bool {
    if want_blocks.len() < MAX_WANT_QUEUE {
        want_blocks.push_back(h);
    }
    match fault {
        OutboundFault::OurStreamLimit => {
            note_streams_full(&peer);
            return false;
        }
        OutboundFault::OurShed => return false,
        OutboundFault::Peer => {}
    }
    bump_score(peer_score, quarantine, peer, SCORE_BAD_TIMEOUT);
    let stamp = block_servers > 1;
    if stamp {
        bad_providers.entry(h).or_default().insert(peer, Instant::now());
        if providers.get(&h) == Some(&peer) {
            providers.remove(&h);
        }
    }
    stamp
}

/// A peer answered our GetBlock for `h` with "unknown block": the block is queued again and the peer
/// is stamped for it whatever the server count, because it answers at once and would be asked
/// again in a loop, and it stops being `h`'s recorded provider, so the next request goes to another
/// server. No score, also for the provider: a peer that served a body it had not validated drops
/// that body when its own apply blames it (`chain::body_fault`) and then honestly holds none.
fn note_unknown_block_answer(
    h: Hash32,
    peer: PeerId,
    bad_providers: &mut HashMap<Hash32, HashMap<PeerId, Instant>>,
    providers: &mut HashMap<Hash32, PeerId>,
    want_blocks: &mut VecDeque<Hash32>,
) {
    bad_providers.entry(h).or_default().insert(peer, Instant::now());
    if providers.get(&h) == Some(&peer) {
        providers.remove(&h);
    }
    if want_blocks.len() < MAX_WANT_QUEUE {
        want_blocks.push_back(h);
    }
}

/// A GetBlock whose answer this node does not handle (it came from a peer banned or quarantined
/// since we asked, or it is neither a block nor an error) frees its slot and goes back on the queue
/// at once, rather than holding `inflight` until the 60 s sweep. It blames nobody: a ban or
/// quarantine already did, and an answer of the wrong kind is handled by
/// `note_wrong_kind_block_answer`. Returns the block when `rid` was one of our GetBlock requests.
fn release_unanswered_block_request<R: Eq + std::hash::Hash>(
    rid: &R,
    rid_to_hash: &mut HashMap<R, Hash32>,
    inflight: &mut HashMap<Hash32, (R, Instant, PeerId)>,
    want_blocks: &mut VecDeque<Hash32>,
) -> Option<Hash32> {
    let h = rid_to_hash.remove(rid)?;
    if inflight.get(&h).is_some_and(|(r, _, _)| r == rid) {
        inflight.remove(&h);
    }
    if !want_blocks.contains(&h) && want_blocks.len() < MAX_WANT_QUEUE {
        want_blocks.push_back(h);
    }
    Some(h)
}

/// `peer` answered our GetBlock for `h` with another kind of response; this node's server answers
/// GetBlock only with the block or an error (`handle_request_blocking`). The answer arrives at
/// once, so no timeout moves the request: `peer` is stamped for `h` (`pick_block_peer` passes it
/// over for BAD_PROVIDER_RETRY_SECS) and stops being `h`'s recorded provider, so the next request
/// goes to another server. No score: the stamp is per block and expires.
fn note_wrong_kind_block_answer(
    h: Hash32,
    peer: PeerId,
    bad_providers: &mut HashMap<Hash32, HashMap<PeerId, Instant>>,
    providers: &mut HashMap<Hash32, PeerId>,
) {
    bad_providers.entry(h).or_default().insert(peer, Instant::now());
    if providers.get(&h) == Some(&peer) {
        providers.remove(&h);
    }
}

/// The first usable candidate, in preference order, to ask for block `h`. A peer with a 120 s
/// bad-provider stamp is skipped; a peer whose body for `h` failed within BODY_SOURCE_SECS is asked
/// only when no other usable candidate is left, so each identity gets one try before any repeats.
fn pick_block_peer(
    candidates: &[PeerId],
    usable: impl Fn(&PeerId) -> bool,
    h: &Hash32,
    bad_providers: &HashMap<Hash32, HashMap<PeerId, Instant>>,
    body_refetch: &BodyRefetch,
) -> Option<PeerId> {
    let eligible = |p: &&PeerId| usable(p) && !is_bad(bad_providers, h, p);
    candidates
        .iter()
        .filter(eligible)
        .find(|p| !body_refetch.is_faulted(h, p))
        .or_else(|| candidates.iter().find(eligible))
        .copied()
}

/// Whether a missing block is worth requesting: heavier than the local tip, or a dropped body
/// a heavier reorg waits on (`BodyRefetch::wanted_below_tip`).
fn worth_requesting(
    db: &Stores,
    h: &Hash32,
    local_work: u128,
    body_refetch: &BodyRefetch,
) -> Result<bool> {
    Ok(get_hidx(db, h)?.is_some_and(|hi| hi.chainwork > local_work)
        || body_refetch.wanted_below_tip(db, h, local_work))
}

/// A dropped body also leaves `pending_apply`, so its in-memory copy is not stored again.
fn note_reorg_failure(
    db: &Stores,
    e: &anyhow::Error,
    h: Hash32,
    pending_apply: &mut HashMap<Hash32, Block>,
    body_refetch: &mut BodyRefetch,
    bad_providers: &mut HashMap<Hash32, HashMap<PeerId, Instant>>,
    want_blocks: &mut VecDeque<Hash32>,
) {
    println!("[sync] maybe_reorg_to {} failed: {}", hex32(&h), e);
    if let Some(dropped) = e.downcast_ref::<crate::chain::body_fault::BodyDropped>() {
        pending_apply.remove(&dropped.0);
        body_refetch.on_dropped(db, dropped.0, h, bad_providers, want_blocks);
    }
}

// Peers that answer "historical block serving disabled" serve headers only. Track them so the
// block scheduler deprioritizes them.
//
// Process-wide for the same reason as OUTBOUND_PACE above: the mark is
// written when a response arrives and read when the next block request is scheduled, and those
// two points can be polled on different worker threads, so a thread_local map would lose the mark
// and keep scattering block requests at peers that only serve headers. It also feeds
// block_server_count (the stamp rule of `note_block_request_failure`), which is why a lost mark is
// worse than a missed optimization here. Stale entries are dropped on write.
static HEADER_ONLY_PEERS: std::sync::Mutex<std::collections::BTreeMap<PeerId, Instant>> =
    std::sync::Mutex::new(std::collections::BTreeMap::new());

fn note_header_only(p: &PeerId) {
    let mut m = HEADER_ONLY_PEERS.lock().unwrap_or_else(|e| e.into_inner());
    m.retain(|_, t| t.elapsed().as_secs() < HEADER_ONLY_COOLDOWN_SECS);
    m.insert(*p, Instant::now());
}

fn is_header_only(p: &PeerId) -> bool {
    let m = HEADER_ONLY_PEERS.lock().unwrap_or_else(|e| e.into_inner());
    m.get(p)
        .map(|t| t.elapsed().as_secs() < HEADER_ONLY_COOLDOWN_SECS)
        .unwrap_or(false)
}

// Peers whose connection refused one of our requests for lack of streams, for STREAMS_FULL_MS.
// Process-wide, as HEADER_ONLY_PEERS, so both block-request sites see the mark.
static STREAMS_FULL_PEERS: std::sync::Mutex<std::collections::BTreeMap<PeerId, Instant>> =
    std::sync::Mutex::new(std::collections::BTreeMap::new());

fn note_streams_full(p: &PeerId) {
    let mut m = STREAMS_FULL_PEERS.lock().unwrap_or_else(|e| e.into_inner());
    m.retain(|_, t| t.elapsed().as_millis() < STREAMS_FULL_MS as u128);
    m.insert(*p, Instant::now());
}

/// Whether `p` can take a block request now, for both senders, `pump_blocks` and the immediate
/// request on a new child header: connected, neither banned nor quarantined, a stream free
/// (`has_stream_room`) and under the outbound pace (`pace_saturated`). One check for both, so the
/// immediate request cannot bypass the pace.
fn can_take_block_request<R>(
    p: &PeerId,
    connected: &HashSet<PeerId>,
    bans: &HashMap<PeerId, Instant>,
    quarantine: &HashMap<PeerId, Instant>,
    inflight: &HashMap<Hash32, (R, Instant, PeerId)>,
) -> bool {
    connected.contains(p) && !is_banned(bans, p) && !is_quarantined(quarantine, p) && has_stream_room(inflight, p) && !pace_saturated(p)
}

/// Records the GetBlock for `h` just sent to `peer` as `rid`, for both senders: in flight, by its
/// request id, and in the outbound pace.
fn note_block_request_sent<R: Copy + Eq + std::hash::Hash>(
    rid: R,
    peer: PeerId,
    h: Hash32,
    rid_to_hash: &mut HashMap<R, Hash32>,
    inflight: &mut HashMap<Hash32, (R, Instant, PeerId)>,
) {
    pace_note_sent(&peer);
    rid_to_hash.insert(rid, h);
    inflight.insert(h, (rid, Instant::now(), peer));
}

/// Whether `p` can take another block request: fewer than MAX_BLOCK_REQUESTS_PER_PEER in flight
/// to it and no local stream refusal in the last STREAMS_FULL_MS.
fn has_stream_room<R>(inflight: &HashMap<Hash32, (R, Instant, PeerId)>, p: &PeerId) -> bool {
    let full = STREAMS_FULL_PEERS
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .get(p)
        .is_some_and(|t| t.elapsed().as_millis() < STREAMS_FULL_MS as u128);
    !full && inflight.values().filter(|(_, _, q)| q == p).count() < MAX_BLOCK_REQUESTS_PER_PEER
}

/// Whether a failed request never left this node: the connection already ran its maximum of
/// streams and our request-response handler refused to open another (libp2p-request-response
/// 0.30.0 handler.rs:200-209, `io::Error::other("max sub-streams reached")` at :208, reported as
/// `OutboundFailure::Io` at lib.rs:969-980). Our own limit, so it blames nobody. Any other failure
/// of a block request is the peer's (`note_block_request_failure`); of those only a timeout also
/// costs it quality (`charges_quality_timeout`).
fn is_local_stream_refusal(e: &request_response::OutboundFailure) -> bool {
    matches!(e, request_response::OutboundFailure::Io(io)
        if io.kind() == std::io::ErrorKind::Other && io.to_string() == "max sub-streams reached")
}

/// Whose doing a failed request of ours is, which decides its blame (`note_block_request_failure`)
/// and whether the sync peer moves.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum OutboundFault {
    /// The request-response timeout or a transport failure.
    Peer,
    /// Our handler refused to open another stream (`is_local_stream_refusal`).
    OurStreamLimit,
    /// The connection closed because we shed it (`maybe_shed_second_inbound`).
    OurShed,
}

/// `e`'s fault; `on_shed_connection` when the request's connection is one we shed
/// (`Unreported::reported`).
fn outbound_fault(e: &request_response::OutboundFailure, on_shed_connection: bool) -> OutboundFault {
    if is_local_stream_refusal(e) {
        OutboundFault::OurStreamLimit
    } else if on_shed_connection && matches!(e, request_response::OutboundFailure::ConnectionClosed) {
        OutboundFault::OurShed
    } else {
        OutboundFault::Peer
    }
}

fn is_quarantined(
    quar: &HashMap<PeerId, Instant>,
    p: &PeerId,
) -> bool {
    quar.get(p)
        .map(|t| t.elapsed().as_secs() < QUAR_SECS)
        .unwrap_or(false)
}

/// Adds `delta` to `p`'s score; at or below QUAR_SCORE_THRESHOLD `p` is quarantined for QUAR_SECS
/// from now. Logs (`peer_line`) and returns true only when `p` was not quarantined already.
fn bump_score(
    scores: &mut HashMap<PeerId, i32>,
    quar: &mut HashMap<PeerId, Instant>,
    p: PeerId,
    delta: i32,
) -> bool {
    let s = scores.entry(p).or_insert(0);
    *s = s.saturating_add(delta).clamp(SCORE_MIN, SCORE_MAX);
    let score = *s;
    if score > QUAR_SCORE_THRESHOLD {
        return false;
    }
    // The quarantine is the punishment, and the score starts again from zero: without the reset a
    // peer came out of quarantine near the threshold and its next single penalty sent it back.
    *s = 0;
    let entered = !is_quarantined(quar, &p);
    if entered && peer_line(&p, Line::Quarantine).is_some() {
        println!("[p2p] quarantining peer {p} for {QUAR_SECS} s: score {score} (threshold {QUAR_SCORE_THRESHOLD})");
    }
    quar.insert(p, Instant::now());
    entered
}

/// Moves every score one step toward zero, by max(1, |s| / 8) (from the ceiling, six steps of
/// SCORE_DECAY_EVERY_SECS to half), and drops the scores that reach zero. A step never crosses zero.
fn decay_scores(scores: &mut HashMap<PeerId, i32>) {
    for s in scores.values_mut() {
        let step = (s.abs() / 8).max(1);
        *s -= s.signum() * step;
    }
    scores.retain(|_, s| *s != 0);
}

fn note_canonical_provider(
    peer_quality: &mut HashMap<PeerId, PeerQuality>,
    peer_score: &mut HashMap<PeerId, i32>,
    quarantine: &mut HashMap<PeerId, Instant>,
    peer: PeerId,
    h: Hash32,
    why: &str,
) {
    {
        let q = peer_quality.entry(peer).or_default();
        q.canonical_block = q.canonical_block.saturating_add(1);
        q.last_seen_unix = unix_now();
    }

    bump_score(peer_score, quarantine, peer, SCORE_GOOD_CANONICAL_BLOCK);

    println!(
        "[p2p-score] canonical provider {} block={} reason={}",
        peer,
        hex32(&h),
        why
    );
}


fn better_fork_tip(cw_a: u128, hash_a: &Hash32, cw_b: u128, hash_b: &Hash32) -> bool {
let _ = (hash_a, hash_b);
      cw_a > cw_b
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
    if has_raw_or_pending(db, pending_apply, &h) {
        return Ok(None);
    }

    if inflight.contains_key(&h) {
        return Ok(None);
    }

    if get_hidx(db, &h)?.is_none() {
        return Ok(None);
    }

    Ok(Some(h))
}

fn scrub_stale_inflight(
    inflight: &mut HashMap<Hash32, (request_response::OutboundRequestId, Instant, PeerId)>,
    rid_to_hash: &mut HashMap<request_response::OutboundRequestId, Hash32>,
    want_blocks: &mut VecDeque<Hash32>,
    retired: &mut RetiredBlockRequests,
) {
    let mut stale: Vec<(Hash32, request_response::OutboundRequestId, PeerId)> = Vec::new();

    for (h, (rid, _t0, peer)) in inflight.iter() {
        match rid_to_hash.get(rid) {
            Some(mapped_h) if *mapped_h == *h => {}
            _ => stale.push((*h, *rid, *peer)),
        }
    }

    for (h, rid, peer) in stale {
        inflight.remove(&h);
        rid_to_hash.remove(&rid);
        retired.retire(rid, h, peer);

        if !want_blocks.iter().any(|x| *x == h) && want_blocks.len() < MAX_WANT_QUEUE {
            want_blocks.push_back(h);
        }

        println!("[sync] scrubbed stale inflight {}", hex32(&h));
    }
}

fn compact_want_queue(
    db: &Stores,
    pending_apply: &HashMap<Hash32, Block>,
    inflight: &HashMap<Hash32, (request_response::OutboundRequestId, Instant, PeerId)>,
    want_blocks: &mut VecDeque<Hash32>,
    body_refetch: &BodyRefetch,
) -> Result<()> {
    let old: Vec<Hash32> = want_blocks.drain(..).collect();
    let mut seen: HashSet<Hash32> = HashSet::new();

let (_local_tip, _local_height, local_work) = local_tip_and_work(db);

    for h in old {
        // Drop entries already satisfied locally.
        if has_raw_or_pending(db, pending_apply, &h) {
            continue;
        }

// Drop entries whose header index is gone / unknown,
// or whose chainwork cannot improve our current canonical work.
if get_hidx(db, &h)?.is_none() || !worth_requesting(db, &h, local_work, body_refetch)? {
    continue;
}

        // Keep descendants in the queue.
        // Do NOT collapse them onto the current frontier here.
        // pump_blocks() will map each queued descendant to the earliest
        // requestable missing ancestor at request time.
        if seen.insert(h) {
            want_blocks.push_back(h);
        }
    }

    Ok(())
}

fn compact_and_log_want_queue(
    db: &Stores,
    pending_apply: &HashMap<Hash32, Block>,
    inflight: &HashMap<Hash32, (request_response::OutboundRequestId, Instant, PeerId)>,
    want_blocks: &mut VecDeque<Hash32>,
    body_refetch: &BodyRefetch,
    label: &str,
) -> Result<()> {
    let before = want_blocks.len();
    compact_want_queue(db, pending_apply, inflight, want_blocks, body_refetch)?;
    let after = want_blocks.len();

    if before != after {
        println!(
            "[sync] compact_want_queue({}) {} -> {}",
            label, before, after
        );
    }

    Ok(())
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
    providers: &HashMap<Hash32, PeerId>,
    peer_quality: &mut HashMap<PeerId, PeerQuality>,
    peer_score: &mut HashMap<PeerId, i32>,
    quarantine: &mut HashMap<PeerId, Instant>,
    chain_lock: &crate::chain::lock::ChainLock,
    body_refetch: &mut BodyRefetch,
    bad_providers: &mut HashMap<Hash32, HashMap<PeerId, Instant>>,
    want_blocks: &mut VecDeque<Hash32>,
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

            // ONE guard for the whole iteration, over the store, the header index and both
            // `maybe_reorg_to` calls below. parking_lot::Mutex is not reentrant, and nothing in the
            // type system would keep a second guard in the same iteration apart from this one: one
            // guard costs one global-lock round-trip per candidate and cannot self-deadlock.
            let _apply_guard = chain_lock.lock();

            {
                // Body binding, store path 2 of 2: the pending_apply drain needs the same bind. A
                // body that does not bind to its header is dropped here rather than retried
                // forever, and the peer that provided it is scored down. Its source is the recorded
                // provider, the best attribution this path has.
                match store_block_bytes_checked(db, &h, blk) {
                    Ok(BlockStoreOutcome::RejectedMerkle) => {
                        println!(
                            "[sync] dropping pending block {}: body does not bind to header",
                            hex32(&h)
                        );
                        if let Some(p) = providers.get(&h).copied() {
                            bump_score(peer_score, quarantine, p, SCORE_BAD_INVALID);
                        }
                        pending_apply.remove(&h);
                        continue;
                    }
                    // The network store refuses such a body before it reaches pending_apply,
                    // so this copy came from db.blocks (stored by a build without that refusal):
                    // drop that body, blame nobody, fetch the block again.
                    Ok(BlockStoreOutcome::RejectedRepeatedTxid) => {
                        match crate::state::db::drop_block_body(db, &h) {
                            Ok(()) => println!("[sync] dropped the stored body of {}: it repeats a txid", hex32(&h)),
                            Err(e) => println!("[sync] could not drop the stored body of {}: {e:#}", hex32(&h)),
                        }
                        pending_apply.remove(&h);
                        if !want_blocks.contains(&h) && want_blocks.len() < MAX_WANT_QUEUE {
                            want_blocks.push_back(h);
                        }
                        continue;
                    }
                    Ok(BlockStoreOutcome::Stored) => {
                        body_refetch.arm_sweep();
                        if let Some(p) = providers.get(&h).copied() {
                            body_refetch.record_source(h, p);
                        }
                    }
                    _ => {}
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

            // The guard above covers this too: both `maybe_reorg_to` calls below are the actual
            // five-tree apply, not only the raw-block store and the header index. `maybe_reorg_to`
            // does not lock internally and `mine.rs` DOES hold the lock across its own call, so
            // outside the guard the sync path and the miner could apply concurrently, and
            // `seal_and_exit`'s guarantee would not hold on a node that applies via sync.
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

match crate::chain::reorg::maybe_reorg_to(db, &h, Some(mempool)) {
    // maybe_reorg_to also returns Ok when it applies nothing (a bad mark, a missing body).
    Ok(()) if get_tip(db).ok().flatten() == Some(h) => {
        if let Some(p) = providers.get(&h).copied() {
            note_canonical_provider(
                peer_quality,
                peer_score,
                quarantine,
                p,
                h,
                "direct-tip",
            );
        }
    }
    Ok(()) => {}
    Err(e) => note_reorg_failure(db, &e, h, pending_apply, body_refetch, bad_providers, want_blocks),
}
if let Err(e) = body_refetch.note_unreached(db, h, pending_apply, want_blocks) {
    println!("[sync] could not read where the reorg to {} stops: {e:#}", hex32(&h));
}

                progressed = true;
                break;
            }

            // Case 2: stronger competing fork head was downloaded.

if better_fork_tip(new_hi.chainwork, &h, cur_work, &cur_tip) {

                let blk = pending_apply.remove(&h).unwrap();
                drop(blk);

                eprintln!(
                    "[sync] stronger downloaded fork detected -> maybe_reorg_to({}) h={} w={} cur_w={}",
                    hex32(&h),
                    new_hi.height,
                    new_hi.chainwork,
                    cur_work
                );

match crate::chain::reorg::maybe_reorg_to(db, &h, Some(mempool)) {
    // maybe_reorg_to also returns Ok when it applies nothing (a bad mark, a missing body).
    Ok(()) if get_tip(db).ok().flatten() == Some(h) => {
        if let Some(p) = providers.get(&h).copied() {
            note_canonical_provider(
                peer_quality,
                peer_score,
                quarantine,
                p,
                h,
                "stronger-fork",
            );
        }
    }
    Ok(()) => {}
    Err(e) => note_reorg_failure(db, &e, h, pending_apply, body_refetch, bad_providers, want_blocks),
}
if let Err(e) = body_refetch.note_unreached(db, h, pending_apply, want_blocks) {
    println!("[sync] could not read where the reorg to {} stops: {e:#}", hex32(&h));
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
// THIS NODE DOES NOT READ `message.source` AT ALL.
//
// The gossip AUTHOR cannot be authenticated here, so there is no honest way to name one:
//
//   * gossipsub runs in `ValidationMode::Permissive` (`gossipsub_config`).
//   * libp2p-gossipsub-0.50.1/src/protocol.rs:409-419 sets `verify_signature` only when the
//     message actually carries a signature, so an UNSIGNED message is never signature-checked;
//     :527-555 then decodes `from` into a `PeerId` without binding it to a signature, a key, or
//     the connection it arrived on. `message.source` is therefore attacker-chosen on any unsigned
//     message.
//   * The application cannot even opt into "attribute only when signed": the app-facing
//     `gossipsub::Message` (libp2p-gossipsub-0.50.1/src/types.rs:209-220) carries no signature
//     field at all. Only the internal `RawMessage` (types.rs:131-152) has one, and
//     `Event::Message` (behaviour.rs:144-151) hands over the former.
//
// So the only peer identity this function returns is `propagation_source`, which the noise
// handshake authenticated and to which we hold a live connection.
//
// Why the FORWARDER is not the fallback either: striking the forwarder for a payload it did not
// write bans honest relays for what their mesh sent them. A content-level
// failure has no sound strike target, so it strikes nobody (see note_gossip_dropped).
//
// Returns `(forwarder, message id, payload, topic)`; the verdict is reported against the id.
fn handle_gossipsub_event(event: &OutEvent) -> Option<(PeerId, gossipsub::MessageId, Vec<u8>, String)> {
    match event {
        OutEvent::Gossipsub(gossipsub::Event::Message {
            propagation_source,
            message_id,
            message,
        }) => {
            let topic = message.topic.as_str().to_string();
            Some((*propagation_source, message_id.clone(), message.data.clone(), topic))
        }
        _ => None,
    }
}

/// Reports the gossip arm's verdict on one received message: `true` is Accept, `false` Ignore.
/// With `validate_messages` on, gossipsub forwards a message only on Accept
/// (libp2p-gossipsub-0.50.1 `behaviour.rs:949-985`), and one never reported stays in its cache
/// unforwarded until the cache drops it (`mcache.rs:192-210`, `history_length` 5 heartbeats of
/// 1 s); Ignore removes it at once (`behaviour.rs:986-991`). Reject is not used: it differs from
/// Ignore only in peer scoring, which this node does not enable, and the validity of a payload
/// says nothing about the peer that relayed it (note_gossip_dropped). Returns false when the cache
/// no longer held the message, so an Accept forwarded nothing. True says only that the cache held
/// it, not that it went anywhere: gossipsub drops `forward_msg`'s answer, false when no peer is a
/// recipient, and a send refused by a full queue (`behaviour.rs:979-985`, `:3007-3040`).
fn report_gossip_verdict(
    swarm: &mut Swarm<Behaviour>,
    id: &gossipsub::MessageId,
    fwd: &PeerId,
    forward: bool,
) -> bool {
    let acceptance = if forward {
        gossipsub::MessageAcceptance::Accept
    } else {
        gossipsub::MessageAcceptance::Ignore
    };
    swarm
        .behaviour_mut()
        .gossipsub
        .report_message_validation_result(id, fwd, acceptance)
}

/// A gossip payload that fails to decode or validate strikes NOBODY.
/// The claimed author cannot be authenticated (see handle_gossipsub_event) and the forwarder did
/// not write it, so there is no sound target. The defence against a junk flood is the
/// per-connection budget in allow_gossip plus the quarantine disconnect, both keyed on the
/// noise-authenticated forwarder, and at the FIRST HOP that forwarder IS the flooder.
fn note_gossip_dropped(dropped: &mut u64, fwd: PeerId, topic: &str, why: &str) {
    if let Some(n) = log_due(dropped) {
        println!("[p2p] dropped gossip on {topic} from {fwd}: {why} (dropped_total={n})");
    }
}

/// Counts one event of a kind and returns the running total when it is a power of two, so a
/// flood costs log lines logarithmic in its size and each line carries the total so far.
fn log_due(count: &mut u64) -> Option<u64> {
    *count = count.saturating_add(1);
    count.is_power_of_two().then_some(*count)
}

/// Escaped characters of a peer's text that one log line carries.
const PEER_TEXT_LOGGED: usize = 200;

/// A peer's text (an Err answer's message) for a log line: its length in bytes and its first
/// characters escaped (`char::escape_debug`) up to PEER_TEXT_LOGGED bytes of output. Printed whole, a
/// peer's newlines would forge lines in the operator's journal, which log monitors read, and one
/// answer of short lines could fill a journal rate limit (500 lines a minute, say).
fn peer_text(s: &str) -> String {
    let mut shown = String::new();
    let mut cut = false;
    for c in s.chars() {
        let escaped = c.escape_debug().to_string();
        if shown.len() + escaped.len() > PEER_TEXT_LOGGED {
            cut = true;
            break;
        }
        shown.push_str(&escaped);
    }
    format!("{} bytes: \"{shown}\"{}", s.len(), if cut { "..." } else { "" })
}

/// Asks the swarm to close every connection to `p` and records why, for its close line.
fn disconnect_peer(
    swarm: &mut Swarm<Behaviour>,
    closing: &mut HashMap<PeerId, &'static str>,
    p: PeerId,
    why: &'static str,
) {
    closing.insert(p, why);
    let _ = swarm.disconnect_peer_id(p);
}

/// The close line of one connection and its cause kind (the rate-limit key): our own reason when
/// we asked for the close, else the transport's cause. libp2p reports no cause for an active
/// close, which is the remote's close or a handler that let an idle connection go.
fn close_line(
    peer: &PeerId,
    dialer: bool,
    remaining: u32,
    ours: Option<&str>,
    cause: Option<&ConnectionError>,
) -> (String, String) {
    let transport = match cause {
        Some(ConnectionError::KeepAliveTimeout) => Some(("keep-alive timeout".to_string(), String::new())),
        Some(ConnectionError::IO(e)) => Some((format!("io {:?}", e.kind()), format!(": {e}"))),
        None => None,
    };
    let kind = match (ours, &transport) {
        (Some(why), _) => format!("by us: {why}"),
        (None, Some((k, _))) => k.clone(),
        (None, None) => "closed by the remote or idle".to_string(),
    };
    let detail = match (ours, &transport) {
        (Some(_), Some((k, d))) => format!(" (transport: {k}{d})"),
        (None, Some((_, d))) => d.clone(),
        _ => String::new(),
    };
    let side = if dialer { "dialed by us" } else { "inbound" };
    let line = format!("[p2p] closed connection to {peer} ({side}, {remaining} left): {kind}{detail}");
    (kind, line)
}

// ── bounded publish-retry queue ─────────────────────────────────────────────────────────────────
// gossipsub.publish is SINGLE-SHOT, and upstream discards its errors at every application call site.
// Two of those sites originate content this node is the sole/first source of: the mined-block
// header announce and the tx gossip. A swallowed NoPeersSubscribedToTopic there (e.g. right after a
// restart, before the mesh re-forms) silently strands submitted txs in this node's mempool (while a
// local miner mines empty blocks) or leaves a freshly mined block unannounced (its coinbase at
// orphan risk). Those two are queued here and re-attempted on the existing 5s poll tick.
// Err(Duplicate) is RETRYABLE: gossipsub's AllQueuesFull path inserts the message into its
// duplicate cache BEFORE returning the error (0.50.1 behaviour.rs:701-702 then :737), and a tx
// this node first received from a peer is in that cache from its receipt (:1992), so a retry
// reports Duplicate (:658-666) having sent nothing. A publish with no subscribed peer fails before
// the insert (:694-697), so its retry is tried again at once.
//
// When Duplicate ends is not a timer: the duplicate cache prunes lazily, in 0.48 and 0.50.1 alike.
// publish checks `duplicate_cache.contains` (0.50.1 behaviour.rs:658, 0.48 :621), a map lookup
// that ignores expiry (time_cache.rs:164-166 and :192-194, the same in both); an expired id is
// removed only in `TimeCache::entry` (:138-140), which runs when gossipsub records an id: a
// publish of ours (:701, 0.48 :739) or any received message (:1992, 0.48 :1793). So a retry goes
// out on the first tick after some id is recorded past the 60 s window; on a live chain the next
// block's header gossip records one. An entry therefore stays while it still matters
// (`RetryFor`), not for a count of attempts. Each tick costs, per entry, one signed raw message
// (publish signs before it checks the cache, :647) and one cache lookup.
//
// The RELAY publish sites (re-broadcasting a header/tx we RECEIVED from a peer) deliberately do NOT
// queue: the message is already propagating via the sender + mesh redundancy, and a received
// message sits in our own 60s duplicate cache, so a queued relay would only ever re-flood a stale
// header once its cache entry expired: pointless traffic. Relay sites pass insure=false.
//
// Bounds: 256 entries, the oldest tx out first. A tx entry leaves once our mempool no longer
// holds its bytes (the tx was mined or evicted, or another encoding of its txid replaced it), so
// it is not re-flooded as a now-invalid tx (which would earn peer strikes) nor as bytes the pool
// does not hold; a header entry leaves once that header is not our tip (our tip moved, to a later
// block of ours or anyone's). A late accept (`RetryFor::LateTx`) is held back while it is queued
// and once it has gone out, and only then: one evicted unsent can be queued again. A tx entry also
// leaves once our own publish of its bytes is queued to a peer, a late accept's first attempt
// (`published`). An Accept of a received copy retires nothing (report_gossip_verdict: it reports a
// cache hit, not a send), so an entry whose bytes gossipsub did forward still goes out once, about
// a minute later.
const PUBLISH_RETRY_MAX_QUEUE: usize = 256;

/// What a queued publish is for, and so how long it is retried.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum RetryFor {
    /// A tx: while our mempool holds the queued bytes (`Mempool::holds_encoding`), not only its
    /// txid, which leaves the script_sigs out. A tx's gossip message is its consensus encoding
    /// byte for byte (`GossipTx` has that one field, and bincode frames no struct;
    /// `publish_retry_tests` publish the held bytes through this check).
    Tx(Hash32),
    /// A tx whose gossip check returned after gossipsub dropped its message (the check arm in
    /// `run_p2p_loop`), so the node publishes it itself: kept as `Tx`, and once it has gone out it
    /// is not published this way again while held (`PublishRetry::late_sent`).
    LateTx(Hash32),
    /// A header we mined: while it is our tip.
    Header(Hash32),
}

struct PublishEntry {
    topic: &'static str,
    bytes: Vec<u8>,
    attempts: u32,
    what: RetryFor,
}

#[derive(Default)]
struct PublishRetry {
    q: VecDeque<PublishEntry>,
    /// Held txs whose late accept has gone out. Once per tx while held: that publish leaves at
    /// least 60 s after the copy we received (our duplicate cache), when peers' entries for it
    /// have lapsed too, so it is new to them; were their checks of it late as well, each would
    /// publish it a minute later, and so on. Each `drain` forgets the txs the pool no longer holds,
    /// so between sweeps it can briefly hold a few txs the pool has since dropped beyond the pool's
    /// 50,000; it does not grow across sweeps.
    late_sent: HashSet<Hash32>,
    dropped_since_log: u64, // rate-limits the "queue full" log to one summary line per drain
}

impl PublishRetry {
    fn enqueue(&mut self, topic: &'static str, bytes: Vec<u8>, what: RetryFor) {
        // Dedup identical bytes: repeated duplicate submits re-gossip the same tx, each returning
        // Err(Duplicate) while the gossipsub cache holds it; without this every one would enqueue
        // another multi-KB clone (worst case 256 x 100KB of the same tx, re-published every tick).
        // A late accept of bytes already queued (a submit's, a parked tx's) takes that entry over,
        // so its publish counts as the late one.
        if let Some(e) = self.q.iter_mut().find(|e| e.topic == topic && e.bytes == bytes) {
            if matches!(what, RetryFor::LateTx(_)) {
                e.what = what;
            }
            return;
        }
        if self.q.len() >= PUBLISH_RETRY_MAX_QUEUE {
            // Evict the oldest TRANSACTION, not simply the oldest entry. A mined-header entry is
            // our own freshly solved block and is by construction the oldest the moment tx
            // pressure arrives, so a plain pop_front drops the one entry whose loss costs a block.
            let victim = self.q.iter().position(|e| e.topic == TOPIC_TX).unwrap_or(0);
            self.q.remove(victim);
            self.dropped_since_log += 1; // logged as a summary in drain(), not per drop (cold-sync spam)
        }
        self.q.push_back(PublishEntry { topic, bytes, attempts: 0, what });
    }

    #[cfg(test)]
    fn len(&self) -> usize {
        self.q.len()
    }

    /// Whether to publish `id` as a late accept of its gossip message `msg` (its consensus encoding,
    /// `RetryFor::Tx`): not gone out as one while held, `held` (the pool holds `msg`), and not
    /// queued as one with `msg`. One queued with other bytes of `id` (an encoding the pool has since
    /// replaced, which `drain` would drop unsent) leaves the queue and this one goes ahead. An entry
    /// evicted unsent leaves the queue, which releases it.
    fn claim_late(&mut self, id: Hash32, msg: &[u8], held: impl FnOnce() -> bool) -> bool {
        if self.late_sent.contains(&id) || !held() {
            return false;
        }
        match self.q.iter().position(|e| e.what == RetryFor::LateTx(id)) {
            Some(i) if self.q[i].bytes == msg => false,
            Some(i) => {
                self.q.remove(i);
                true
            }
            None => true,
        }
    }

    /// Publishes the gossip message `msg` of a claimed late accept `id` through `publish`, and
    /// queues it when that fails (our own duplicate cache holds the copy we received for 60 s, so
    /// it nearly always does).
    fn publish_late(
        &mut self,
        id: Hash32,
        msg: Vec<u8>,
        publish: impl FnOnce(Vec<u8>) -> std::result::Result<(), gossipsub::PublishError>,
    ) {
        match publish(msg.clone()) {
            Ok(()) => {
                self.late_sent.insert(id);
                self.published(&msg);
            }
            Err(_) => self.enqueue(TOPIC_TX, msg, RetryFor::LateTx(id)),
        }
    }

    /// Our own publish of the tx message `bytes` is queued to a peer (gossipsub's `publish` returns
    /// Ok only then, `behaviour.rs:724-737`): a queued entry of the same bytes (a submit's, a parked
    /// tx's) would only send them again once our duplicate cache lets it out, so it leaves.
    fn published(&mut self, bytes: &[u8]) {
        self.q.retain(|e| !(e.topic == TOPIC_TX && e.bytes == bytes));
    }

    /// Re-attempts every entry that still matters (`mempool`, `tip`) through `publish` and keeps
    /// the ones that failed for a reason that passes (`Duplicate`, `AllQueuesFull`, no subscribed
    /// peer).
    fn drain(
        &mut self,
        mempool: &Mempool,
        tip: &Hash32,
        mut publish: impl FnMut(&'static str, Vec<u8>) -> std::result::Result<(), gossipsub::PublishError>,
    ) {
        if self.dropped_since_log > 0 {
            println!("[p2p] publish-retry queue full: dropped {} oldest entr(ies)", self.dropped_since_log);
            self.dropped_since_log = 0;
        }
        self.late_sent.retain(|id| mempool.contains(id));
        if self.q.is_empty() {
            return;
        }
        let mut still: VecDeque<PublishEntry> = VecDeque::new();
        while let Some(mut e) = self.q.pop_front() {
            let matters = match e.what {
                RetryFor::Tx(id) | RetryFor::LateTx(id) => mempool.holds_encoding(&id, &e.bytes),
                RetryFor::Header(h) => *tip == h,
            };
            if !matters {
                continue;
            }
            use gossipsub::PublishError::{AllQueuesFull, Duplicate, NoPeersSubscribedToTopic};
            match publish(e.topic, e.bytes.clone()) {
                Ok(()) => {
                    if let RetryFor::LateTx(id) = e.what {
                        self.late_sent.insert(id);
                    }
                    println!("[p2p] publish-retry succeeded on {} after {} attempt(s)", e.topic, e.attempts + 1)
                }
                Err(Duplicate | AllQueuesFull(_) | NoPeersSubscribedToTopic) => {
                    e.attempts += 1;
                    still.push_back(e);
                }
                Err(err) => println!("[p2p] publish-retry dropped an entry on {} ({err}): not retryable", e.topic),
            }
        }
        self.q = still;
    }
}

/// Gossips a tx this node holds. `insure` queues a failed publish for retry (`GossipTxEvent::insure`).
fn publish_tx(swarm: &mut Swarm<Behaviour>, retryq: &mut PublishRetry, tx: &Transaction, insure: bool) -> Result<()> {
    if let Ok(tx_bytes) = crate::codec::consensus_bincode().serialize(tx) {
        if tx_bytes.len() > MAX_TX_BYTES {
            println!("[p2p] refusing to gossip oversized tx ({} bytes)", tx_bytes.len());
            return Ok(());
        }
    }

    let gt = GossipTx { tx: tx.clone() };
    let bytes = crate::codec::consensus_bincode().serialize(&gt)?;
    if bytes.len() <= MAX_GOSSIP_MSG_BYTES {
        // Queue on failure instead of discarding it (upstream discards it): otherwise this single
        // publish is a submitted tx's ONLY chance to reach the miners.
        // Happy path moves `bytes` into publish (no clone); the cold error path
        // re-serializes from `gt` and carries the txid so drain drops it if it mines.
        if let Err(e) = swarm.behaviour_mut().gossipsub.publish(IdentTopic::new(TOPIC_TX), bytes) {
            if insure {
                println!("[p2p] tx gossip publish failed ({e}), queued for retry");
                if let Ok(rebytes) = crate::codec::consensus_bincode().serialize(&gt) {
                    retryq.enqueue(TOPIC_TX, rebytes, RetryFor::Tx(crate::crypto::txid(&gt.tx)));
                }
            } else {
                // Re-gossip of a duplicate submit. NOT insured: the message-id is a
                // content hash, so a tx we already hold sits in our own 60 s duplicate
                // cache and Err(Duplicate) here is benign. Queuing it would schedule a
                // full-mesh re-broadcast about 60 s later, buyable with one
                // unauthenticated POST of any already-known transaction.
                println!("[p2p] duplicate re-gossip returned ({e}), not queued");
            }
        }
    }
    Ok(())
}

fn utxo_exists(db: &Stores, op: &OutPoint) -> bool {
    matches!(crate::state::db::get_utxo(db, op), Ok(Some(_)))
}

fn proposal_known(db: &Stores, id: &Hash32) -> bool {
    matches!(db.app.get(crate::state::app_state::k_proposal(id)), Ok(Some(_)))
}

/// What `tx` depends on that this node's state does not hold: inputs not in the UTXO set, and the
/// proposal of an Attest when it is not known (mempool admission refuses both,
/// `validate_tx_for_mempool`).
fn missing_deps(db: &Stores, tx: &Transaction) -> crate::net::orphan_txs::Deps {
    crate::net::orphan_txs::Deps {
        inputs: tx.inputs.iter().map(|i| i.prevout).filter(|op| !utxo_exists(db, op)).collect(),
        proposal: match &tx.app {
            crate::types::AppPayload::Attest { proposal_id, .. } if !proposal_known(db, proposal_id) => {
                Some(*proposal_id)
            }
            _ => None,
        },
    }
}

/// Re-checks the parked gossip txs after the tip moved, and gossips each one the mempool now admits
/// as a first accept (insured: a copy this node received is in gossipsub's duplicate cache, and
/// PublishRetry keeps it while it is in the mempool until gossipsub prunes that entry).
fn recheck_orphan_txs(
    orphans: &mut crate::net::orphan_txs::OrphanTxs,
    db: &Stores,
    mempool: &Mempool,
    swarm: &mut Swarm<Behaviour>,
    retryq: &mut PublishRetry,
    best_height: u64,
) -> Result<()> {
    if orphans.is_empty() {
        return Ok(());
    }
    use crate::net::orphan_txs::Recheck;
    let present = |d: &crate::net::orphan_txs::Deps| {
        d.inputs.iter().all(|op| utxo_exists(db, op)) && d.proposal.is_none_or(|id| proposal_known(db, &id))
    };
    let admitted = orphans.recheck(best_height, present, |tx| match mempool.insert_checked(db, tx.clone()) {
        Ok(true) => Recheck::Admitted,
        Ok(false) => Recheck::Held,
        Err(_) => {
            let still = missing_deps(db, tx);
            if still.is_empty() { Recheck::Refused } else { Recheck::Waiting(still) }
        }
    });
    for tx in admitted {
        println!("[p2p] parked gossip tx {} admitted after the tip moved; gossiping it", hex32(&crate::crypto::txid(&tx)));
        publish_tx(swarm, retryq, &tx, true)?;
    }
    Ok(())
}

// Announce a header. `insure`=true (the mined-block announce) queues a failed publish for retry;
// `insure`=false (relaying a peer's header) does not (see the queue's doc block). The happy path
// moves `bytes` into publish with no clone; only the cold error path re-serializes.
fn publish_header(swarm: &mut Swarm<Behaviour>, retryq: &mut PublishRetry, header: BlockHeader, insure: bool) -> Result<()> {
    let gh = GossipHeader { header };
    let bytes = crate::codec::consensus_bincode().serialize(&gh)?;

    if bytes.len() <= MAX_GOSSIP_MSG_BYTES {
        if let Err(e) = swarm
            .behaviour_mut()
            .gossipsub
            .publish(IdentTopic::new(TOPIC_HDR), bytes)
        {
            if insure {
                println!("[p2p] mined-header publish failed ({e}); queued for retry");
                if let Ok(rebytes) = crate::codec::consensus_bincode().serialize(&gh) {
                    retryq.enqueue(TOPIC_HDR, rebytes, RetryFor::Header(header_hash(&gh.header)));
                }
            }
        }
    }

    Ok(())
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
let outbound_peers = Arc::new(AtomicUsize::new(0));
let known_peers = Arc::new(AtomicUsize::new(0));
let last_tip_seen_unix = Arc::new(AtomicU64::new(0));
let last_peer_change_unix = Arc::new(AtomicU64::new(unix_now()));
let best_peer_height = Arc::new(AtomicU64::new(0));
let best_peer_work = Arc::new(RwLock::new(0u128));
let best_peer_tip = Arc::new(RwLock::new([0u8; 32]));

let listen_addr = Arc::new(RwLock::new(None));

let handle = NetHandle {
    peer_id,
    connected_peers: connected_peers.clone(),
    outbound_peers: outbound_peers.clone(),
    known_peers: known_peers.clone(),
    last_tip_seen_unix: last_tip_seen_unix.clone(),
    last_peer_change_unix: last_peer_change_unix.clone(),
    best_peer_height: best_peer_height.clone(),
    best_peer_work: best_peer_work.clone(),
     best_peer_tip: best_peer_tip.clone(),
    listen_addr: listen_addr.clone(),
};

    crate::state::subsystem::spawn_supervised(
        "p2p loop",
        &crate::state::subsystem::SUBSYSTEMS.p2p,
        async move {

if let Err(e) = run_p2p_loop(
    db,
    mempool,
    cfg,
    local_key,
    peer_id,
    connected_peers,
    outbound_peers,
    known_peers,
    last_tip_seen_unix,
    last_peer_change_unix,
    best_peer_height,
    best_peer_work,
    best_peer_tip,
    listen_addr,
    mined_rx,
    tx_gossip_rx,
    chain_lock,
)

        .await
        {
            eprintln!("{}", p2p_fatal_line(&e));
        }
    },
    );

    Ok(handle)
}

/// The p2p loop's exit line, with the whole error chain: the loop returns through `?` from many
/// places, and the top message alone does not say which.
fn p2p_fatal_line(e: &anyhow::Error) -> String {
    format!("[p2p] fatal: {e:#}")
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

type P2pTransport = libp2p::core::transport::Boxed<(PeerId, libp2p::core::muxing::StreamMuxerBox)>;

/// tcp + noise + yamux, upstream's transport, with a deadline on each connection's handshake,
/// inbound and outbound (`admission::HANDSHAKE_TIMEOUT`).
fn p2p_transport(local_key: &identity::Keypair) -> Result<P2pTransport> {
    Ok(tcp::tokio::Transport::new(tcp::Config::default().nodelay(true))
        .upgrade(upgrade::Version::V1)
        .authenticate(noise::Config::new(local_key)?)
        .multiplex(yamux::Config::default())
        .timeout(super::admission::HANDSHAKE_TIMEOUT)
        .boxed())
}

/// At most this many ids per IHAVE or IWANT. Each id costs 66 bytes on the wire, and gossipsub
/// 0.50.1 refuses an RPC with more than 16 KiB of control (247 of our ids on the header topic) by
/// closing the stream; the fifth stream disables gossip on the connection. Uncapped, a catch-up or
/// relay burst puts every id of the last three heartbeats in one IHAVE (docs/behaviour.md,
/// "Dependency internals the code relies on").
const MAX_GOSSIP_IDS_PER_CONTROL: usize = 200;

/// Control bytes accepted per RPC: the whole-RPC bound (gossipsub 0.48 has no control limit). A
/// node on gossipsub 0.47 or 0.48, as upstream v1.1.2 is, sends IHAVEs of up to 5000 ids with no
/// control limit. Back to the 16 KiB default only once no peer on the network sends more.
const MAX_GOSSIP_CONTROL_BYTES_RECEIVED: usize = MAX_GOSSIP_MSG_BYTES;

/// `validate_messages`: a received message is forwarded only once the gossip arm reports it
/// Accept (report_gossip_verdict), so a message this node could not index or admit stops here.
/// `ValidationMode` is the separate signature policy: signatures are checked when present.
fn gossipsub_config() -> gossipsub::Config {
    gossipsub::ConfigBuilder::default()
        .validation_mode(ValidationMode::Permissive)
        .validate_messages()
        .heartbeat_interval(Duration::from_secs(1))
        .max_transmit_size(MAX_GOSSIP_MSG_BYTES)
        .max_control_messages_sent(MAX_GOSSIP_IDS_PER_CONTROL)
        .max_control_message_size(MAX_GOSSIP_CONTROL_BYTES_RECEIVED)
        .message_id_fn(|m: &gossipsub::Message| {
            use blake3::Hasher;
            let mut h = Hasher::new();
            h.update(&m.data);
            gossipsub::MessageId::from(h.finalize().to_hex().to_string())
        })
        .build()
        .expect("the gossipsub config is static and valid")
}


async fn run_p2p_loop(
    db: Arc<Stores>,
    mempool: Arc<Mempool>,
    cfg: NetConfig,
    local_key: identity::Keypair,
    peer_id: PeerId,
    connected_peers: Arc<AtomicUsize>,
    outbound_peers: Arc<AtomicUsize>,
     known_peers_atomic: Arc<AtomicUsize>,
    last_tip_seen_unix: Arc<AtomicU64>,
    last_peer_change_unix: Arc<AtomicU64>,
    best_peer_height_atomic: Arc<AtomicU64>,
    best_peer_work: Arc< RwLock<u128> >,
    best_peer_tip: Arc<RwLock<Hash32>>,
    listen_addr: Arc<RwLock<Option<Multiaddr>>>,

    mut mined_rx: tokio::sync::mpsc::UnboundedReceiver<MinedHeaderEvent>,
    mut tx_gossip_rx: tokio::sync::mpsc::UnboundedReceiver<GossipTxEvent>,
    chain_lock: ChainLock,
) -> Result<()> {


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
    

    let transport = p2p_transport(&local_key)?;

    #[allow(unused_mut)]
    let mut authenticity = MessageAuthenticity::Signed(local_key.clone());
    #[cfg(feature = "test-bypass")]
    if matches!(cfg.test_mode, TestPeerMode::AnonymousGossip) {
        authenticity = MessageAuthenticity::Anonymous;
    }
    let mut gossipsub =
        gossipsub::Behaviour::new(authenticity, gossipsub_config())
            .map_err(|e| anyhow::anyhow!(e))?;

    gossipsub.subscribe(&IdentTopic::new(TOPIC_HDR))?;
    gossipsub.subscribe(&IdentTopic::new(TOPIC_TX))?;

let rr_cfg = request_response::Config::default()
    .with_request_timeout(RR_REQUEST_TIMEOUT)
    .with_max_concurrent_streams(4);

let protocols = std::iter::once((SYNC_PROTOCOL, ProtocolSupport::Full));

let rr = request_response::Behaviour::<SyncCodec>::new(protocols, rr_cfg);

let identify = identify::Behaviour::new(
    identify::Config::new("/csd/id/1.0.0".to_string(), local_key.public())
        .with_interval(Duration::from_secs(30)),
);

let behaviour = Behaviour {
    limits: super::admission::connection_caps(u32::try_from(inbound_cap(cfg.is_bootnode)).unwrap_or(u32::MAX)),
    inbound_addresses: super::admission::InboundPerAddress::new(
        super::admission::MAX_PENDING_INBOUND_PER_IP,
        super::admission::MAX_ESTABLISHED_INBOUND_PER_IP,
    ),
    gossipsub,
    rr,
    identify,
};

    let mut swarm = Swarm::new(
        transport,
        behaviour,
        peer_id,
        libp2p::swarm::Config::with_tokio_executor(),
    );

let mut known_addrs: HashMap<PeerId, HashSet<Multiaddr>> =
    load_known_addrs(&cfg.datadir, peer_id);

known_peers_atomic.store(known_addrs.len(), Ordering::Relaxed);

let mut peer_quality: HashMap<PeerId, PeerQuality> =
    load_peer_quality(&cfg.datadir);

println!(
    "[pex] loaded {} peer quality records from disk",
    peer_quality.len()
);

println!(
    "[pex] loaded {} known peers from disk",
    known_addrs.len()
);

let mut last_peer_save = Instant::now();

let mut last_redial = Instant::now() - Duration::from_secs(60);
let mut last_dial_by_addr: HashMap<Multiaddr, Instant> = HashMap::new();
let mut addr_backoff: HashMap<Multiaddr, (u32, Instant)> = HashMap::new();
// Consecutive dial timeouts per address (without its /p2p suffix), for `note_addr_timeout`.
let mut addr_timeouts: HashMap<Multiaddr, u8> = HashMap::new();
let bootnode_peers: HashSet<PeerId> = cfg.bootnodes.iter().filter_map(peer_id_from_multiaddr).collect();
let mut pending_dials: HashMap<PeerId, HashSet<Multiaddr>> = HashMap::new();

// Inbound failures, all ours (`Event::InboundFailure`), for the power-of-two log line.
let mut inbound_failures_ours: u64 = 0;

swarm.listen_on(cfg.listen.clone())?;
println!("[p2p] listening on {}", cfg.listen);

for a in &cfg.bootnodes {

    println!("[p2p] dialing bootnode {a}");

    if let Some(pid) = peer_id_from_multiaddr(a) {
        if should_store_discovered_addr(peer_id, pid, a) {
            insert_known_addr(&mut known_addrs, pid, a.clone());
        }

        if addr_is_backed_off(&addr_backoff, a) {
            continue;
        }

        let _ = swarm.dial(a.clone());
        last_dial_by_addr.insert(a.clone(), Instant::now());
        note_pending_dial(&mut pending_dials, pid, a.clone());
    } else {
        if addr_is_backed_off(&addr_backoff, a) {
            continue;
        }

        let _ = swarm.dial(a.clone());
        last_dial_by_addr.insert(a.clone(), Instant::now());
    }
}

let mut startup_peer_ids: Vec<PeerId> = known_addrs.keys().copied().collect();

sort_peer_ids_by_quality(&mut startup_peer_ids, &peer_quality);
startup_peer_ids.truncate(STARTUP_PREFERRED_PEERS);

let mut startup_dials = 0usize;

for pid in startup_peer_ids {
    if startup_dials >= MAX_STARTUP_DIALS {
        break;
    }

    if pid == peer_id {
        continue;
    }

    let addrs = sorted_peer_addrs_for_export(peer_id, pid, &known_addrs);

    for addr in addrs {
        if startup_dials >= MAX_STARTUP_DIALS {
            break;
        }

        if addr_is_backed_off(&addr_backoff, &addr) {
            continue;
        }

        if let Some(n) = peer_line(&pid, Line::Dial) {
            println!("[pex] startup dial known peer {pid} via {addr} since_last_line={n}");
        }

        let _ = swarm.dial(addr.clone());
        startup_dials += 1;
        last_dial_by_addr.insert(addr.clone(), Instant::now());
        note_pending_dial(&mut pending_dials, pid, addr);
    }
}

    let mut connected: HashSet<PeerId> = HashSet::new();

    // NEW: connection refcount to avoid duplicate “connected” spam
    let mut conn_refcnt: HashMap<PeerId, usize> = HashMap::new();

    // Peers WE dialed (outbound). An attacker cannot force us to open these, so
    // they are the anti-eclipse anchor: protect them from excess-cap eviction (never from the hard
    // accept-cap, from a ban/quarantine, or from libp2p tearing down a dead connection). Shedding is
    // always possible: a misbehaving dialed peer is banned/quarantined and thereby loses protection
    // (see maybe_evict_excess_peers), so protection can never wedge the node over cap.
    let mut outbound: HashSet<PeerId> = HashSet::new();

let mut connected_since: HashMap<PeerId, Instant> = HashMap::new();
let mut last_sync_request_from: HashMap<PeerId, Instant> = HashMap::new();

let mut last_useful_peer_at: HashMap<PeerId, Instant> = HashMap::new();

    let mut peer_heights: HashMap<PeerId, u64> = HashMap::new();
    let mut peer_work: HashMap<PeerId, u128> = HashMap::new();
let mut peer_tips: HashMap<PeerId, Hash32> = HashMap::new();

    let mut sync_peer: Option<PeerId> = None;

let mut last_logged_tip: HashMap<PeerId, (u64, u128, u128)> = HashMap::new();


    // NEW: peer scoring + quarantine
    let mut peer_score: HashMap<PeerId, i32> = HashMap::new();
    let mut quarantine: HashMap<PeerId, Instant> = HashMap::new();

    let mut providers: HashMap<Hash32, PeerId> = HashMap::new();

let mut bad_providers: HashMap<Hash32, HashMap<PeerId, Instant>> = HashMap::new();
    // Bodies stored before this process started may complete a chain: the first stall may sweep.
    let mut body_refetch = BodyRefetch { armed: true, ..BodyRefetch::default() };
    let mut retired_block_requests = RetiredBlockRequests::default();
    #[cfg(feature = "test-bypass")]
    let mut stalled_channels: Vec<request_response::ResponseChannel<SyncResponse>> = Vec::new();
    #[cfg(feature = "test-bypass")]
    let mut delayed_responses: Vec<(request_response::ResponseChannel<SyncResponse>, SyncResponse)> = Vec::new();
    #[cfg(feature = "test-bypass")]
    let mut pushed_body: Option<Block> = None;
    #[cfg(feature = "test-bypass")]
    let mut replay_turn: u64 = 0;

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

    let mut gossip_dropped: u64 = 0;
    let mut gossip_tx_checks = GossipTxChecks::default();
    let mut orphan_txs = crate::net::orphan_txs::OrphanTxs::default();
    let mut orphans_checked_at_tip: Hash32 = local_tip_and_work(&db).0;
    // Our reason for each disconnect we asked for, until its ConnectionClosed (disconnect_peer).
    let mut closing: HashMap<PeerId, &'static str> = HashMap::new();
    // Second inbound connections asked to close (`maybe_shed_second_inbound`), each until it closes,
    // with the reason for its close line.
    let mut shed: HashMap<ConnectionId, &'static str> = HashMap::new();
    // Our requests until the request-response layer reports on them, and those of them whose
    // failure a connection we shed queued at its close, for the OutboundFailure arm.
    let mut unreported: Unreported<request_response::OutboundRequestId> = Unreported::new();
    // Closes seen per cause, for the power-of-two close line.
    let mut close_counts: HashMap<String, u64> = HashMap::new();
    // When the live lane's seam stopped polling the swarm (`TEST_HOLD_SWARM_AFTER_SHED`); always
    // None outside it.
    #[cfg(feature = "test-bypass")]
    let mut swarm_held_since: Option<Instant> = None;
    #[cfg(not(feature = "test-bypass"))]
    let swarm_held_since: Option<Instant> = None;

let mut poll = interval(Duration::from_secs(5));
poll.set_missed_tick_behavior(MissedTickBehavior::Skip);

let mut background: Background<request_response::OutboundRequestId> = Background::new(
    Duration::from_secs(REGULAR_TIP_POLL_SECS),
    Duration::from_secs(HEADERS_REQ_COOLDOWN_SECS),
    Duration::from_secs(60),
    BACKGROUND_CEILING,
);

let mut last_bootstrap_req_at: HashMap<PeerId, Instant> = HashMap::new();
let mut last_disconnect_at: HashMap<PeerId, Instant> = HashMap::new();
let mut last_stale_penalty_at: HashMap<PeerId, Instant> = HashMap::new();

let p2p_started_at = Instant::now();
let mut last_score_decay = Instant::now();

let mut serves = Serves::new(&cfg);

// failed gossip publishes (mined-header announce, tx gossip) awaiting re-attempt; see the
// queue's doc block next to publish_header.
let mut publish_retry: PublishRetry = PublishRetry::default();

    loop {
        tokio::select! {

_ = poll.tick() => {

#[cfg(feature = "test-bypass")]
for (channel, response) in delayed_responses.drain(..) {
    let _ = swarm.behaviour_mut().rr.send_response(channel, response);
}
let (tip_now, height_now, _) = local_tip_and_work(&db);
publish_retry.drain(mempool.as_ref(), &tip_now, |topic, bytes| {
    swarm.behaviour_mut().gossipsub.publish(IdentTopic::new(topic), bytes).map(|_| ())
});
if tip_now != orphans_checked_at_tip {
    orphans_checked_at_tip = tip_now;
    recheck_orphan_txs(&mut orphan_txs, &db, &mempool, &mut swarm, &mut publish_retry, best_hdr_height.max(height_now))?;
}

background.expire(Instant::now());
let open: HashSet<PeerId> = swarm.connected_peers().copied().collect();
prune_peer_state(&mut buckets, &mut bans, &mut quarantine, &mut peer_score, &connected, &open);
peer_lines_tick(|p| open.contains(p));
if last_score_decay.elapsed() >= Duration::from_secs(SCORE_DECAY_EVERY_SECS) {
    decay_scores(&mut peer_score);
    last_score_decay = Instant::now();
}
#[cfg(feature = "test-bypass")]
{
    TEST_PEER_SCORES.lock().unwrap().insert(peer_id, peer_score.clone());
}
prune_bad_providers(&mut bad_providers);
#[cfg(feature = "test-bypass")]
{
    let stamps = bad_providers.iter().flat_map(|(h, by)| by.keys().map(move |p| (*h, *p))).collect();
    TEST_BAD_PROVIDERS.lock().unwrap().insert(peer_id, (Instant::now(), stamps));
}
closing.retain(|p, _| connected.contains(p));
#[cfg(feature = "test-bypass")]
if swarm_held_since.is_some_and(|t| t.elapsed() >= TEST_SWARM_HOLD) {
    swarm_held_since = None;
    TEST_HOLD_SWARM_AFTER_SHED.lock().unwrap().insert(peer_id, Some(Instant::now()));
}
// A banned peer's connections close here at any height.
for p in banned_with_connections(&open, &bans, &closing) {
    disconnect_peer(&mut swarm, &mut closing, p, "banned");
}

prune_addr_backoff(&mut addr_backoff);
prune_dial_state(
    &mut last_disconnect_at,
    &mut last_dial_by_addr,
    &mut peer_quality,
    &mut addr_timeouts,
    &known_addrs,
    &connected,
);

if last_peer_save.elapsed() >= Duration::from_secs(SAVE_PEERS_EVERY_SECS) {
    save_known_addrs(&cfg.datadir, peer_id, &known_addrs);

known_peers_atomic.store(known_addrs.len(), Ordering::Relaxed);

    save_peer_quality(&cfg.datadir, &peer_quality);
    last_peer_save = Instant::now();
}


scrub_stale_inflight(
    &mut inflight,
    &mut rid_to_hash,
    &mut want_blocks,
    &mut retired_block_requests,
);
retired_block_requests.prune();

let _ = compact_and_log_want_queue(
    &db,
    &pending_apply,
    &inflight,
    &mut want_blocks,
    &body_refetch,
    "poll",
);

prune_ephemeral_sync_state(
    &db,
    &mut pending_apply,
    &mut providers,
    &mut seen_blocks,
);
body_refetch.prune(&db);


                // bootnode auto-redial (with backoff + connected-skip)

let redial_due = bootnode_redial_due(
    p2p_started_at.elapsed() < Duration::from_secs(COLD_START_SECS),
    connected.len(),
    outbound.len(),
    effective_max_connected(cfg.is_bootnode),
);

if redial_due && last_redial.elapsed() >= Duration::from_secs(REDIAL_EVERY_SECS) {

    for a in &cfg.bootnodes {
        if let Some(pid) = peer_id_from_multiaddr(a) {
            // A banned bootnode's connection would be closed at connect.
            if connected.contains(&pid) || is_banned(&bans, &pid) {
                continue;
            }
        }

        if addr_is_backed_off(&addr_backoff, a) {
            continue;
        }

        if let Some(t0) = last_dial_by_addr.get(a) {
            if t0.elapsed() < Duration::from_secs(DIAL_BACKOFF_SECS) {
                continue;
            }
        }

        println!("[p2p] redial bootnode {a}");
        let _ = swarm.dial(a.clone());
        last_dial_by_addr.insert(a.clone(), Instant::now());

        if let Some(pid) = peer_id_from_multiaddr(a) {
            note_pending_dial(&mut pending_dials, pid, a.clone());
        }
    }

    last_redial = Instant::now();
}

// regular tip polling + stale fallback
let tip_age = unix_now().saturating_sub(last_tip_seen_unix.load(Ordering::Relaxed));

// Poll ALL connected eligible peers, not just sync_peer.
// Otherwise one stale bootnode can trap us on old peer_work.
{
    let stale_due = tip_age >= TIP_POLL_SECS;
    let eligible = eligible_peers(&connected, &bans, &quarantine);
    pump_background(&mut swarm, &mut background, &mut unreported, &db, &eligible, stale_due);
}

// Recompute live best-peer metrics from current eligible peers.

let (best_h, best_w) = recompute_best_peer_metrics(
    &connected,
    &peer_heights,
    &peer_work,
    &bans,
    &quarantine,
);

best_peer_height_atomic.store(best_h, Ordering::Relaxed);
*best_peer_work.write().await = best_w;

penalize_stale_peers(
    &connected,
    &peer_heights,
    &peer_work,
    &mut peer_score,
    &mut quarantine,
    &mut last_stale_penalty_at,
    best_h,
    best_w,
);

let (_local_tip, local_height, _local_work) = local_tip_and_work(&db);

maybe_evict_bootnode_peers(
    &mut swarm,
    &mut closing,
    &cfg,
    &connected,
    &connected_since,
    &last_sync_request_from,
    &peer_heights,
    local_height,
);

maybe_evict_excess_peers(
    &mut swarm,
    &mut closing,
    &cfg,
    &connected,
    &connected_since,
    &peer_score,
    &peer_work,
    &outbound,
    &bans,
    &quarantine,
);

maybe_evict_idle_peers(
    &mut swarm,
    &mut closing,
    &cfg,
    &connected,
    &connected_since,
    &last_useful_peer_at,
    &peer_score,
    &peer_work,
    best_w,
);

maybe_shed_second_inbound(
    &mut swarm,
    &closing,
    &mut shed,
    &cfg,
    &connected,
    &connected_since,
    &peer_score,
    &peer_work,
    &outbound,
    &bans,
    &quarantine,
);

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
        if let Some(n) = peer_line(&p, Line::SyncPeer) {
            println!("[sync] switching sync_peer -> {p} since_last_line={n}");
        }
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

let mut peer_ids: Vec<PeerId> = known_addrs.keys().copied().collect();
sort_peer_ids_by_quality(&mut peer_ids, &peer_quality);

let mut dials_this_poll = 0usize;

println!(
    "[mem] known_peers={} providers={} inflight={} rid_to_hash={} background_rr={} pending_apply={} seen_blocks={}",
    known_addrs.len(),
    providers.len(),
    inflight.len(),
    rid_to_hash.len(),
    background.in_flight(),
    pending_apply.len(),
    seen_blocks.len(),
);


for pid in peer_ids {

    let max_connected = effective_max_connected(cfg.is_bootnode);

    if connected.len() >= max_connected {
        break;
    }

    if pid == peer_id
        || connected.contains(&pid)
        || is_banned(&bans, &pid)
        || is_quarantined(&quarantine, &pid)
    {
        continue;
    }

    if let Some(t0) = last_disconnect_at.get(&pid) {
        if t0.elapsed() < Duration::from_secs(PEER_DISCONNECT_COOLDOWN_SECS) {
            continue;
        }
    }

    let addrs = sorted_peer_addrs_for_export(peer_id, pid, &known_addrs);

    for addr in addrs {

if addr_is_backed_off(&addr_backoff, &addr) {
    continue;
}

        if let Some(t0) = last_dial_by_addr.get(&addr) {
            if t0.elapsed() < Duration::from_secs(PEER_REDIAL_EVERY_SECS) {
                continue;
            }
        }

if dials_this_poll >= MAX_DIALS_PER_POLL
    || swarm.network_info().connection_counters().num_pending_outgoing() as usize
        >= MAX_PENDING_OUTGOING_DIALS
{
    break;
}

        if let Some(n) = peer_line(&pid, Line::Dial) {
            println!("[pex] periodic redial {pid} via {addr} since_last_line={n}");
        }

let _ = swarm.dial(addr.clone());
dials_this_poll += 1;
last_dial_by_addr.insert(addr.clone(), Instant::now());
note_pending_dial(&mut pending_dials, pid, addr);

    }
}

let _ = pump_blocks(
    &mut swarm,
    &mut unreported,
    sync_peer,
    &connected,
    &providers,
    &mut bad_providers,
    &bans,
    &mut quarantine,
    &mut rid_to_hash,
    &db,
    &pending_apply,
    &mut want_blocks,
    &mut inflight,
    &body_refetch,    &mut retired_block_requests,
);

if let Err(e) = body_refetch.sweep(&db, best_hdr_work, &mut pending_apply) {
    println!("[sync] stall sweep failed: {e:#}");
}

try_apply_pending(
    &db,
    mempool.as_ref(),
    &mut pending_apply,
    &providers,
    &mut peer_quality,
    &mut peer_score,
    &mut quarantine,
    &chain_lock,
    &mut body_refetch,
    &mut bad_providers,
    &mut want_blocks,
);
	
let _ = pump_blocks(
    &mut swarm,
    &mut unreported,
    sync_peer,
    &connected,
    &providers,
    &mut bad_providers,
    &bans,
    &mut quarantine,
    &mut rid_to_hash,
    &db,
    &pending_apply,
    &mut want_blocks,
    &mut inflight,
    &body_refetch,    &mut retired_block_requests,
);

            }

Some(ev) = mined_rx.recv() => {
    let _ = publish_header(&mut swarm, &mut publish_retry, ev.header, true);
}

            Some(ev) = tx_gossip_rx.recv() => {
                publish_tx(&mut swarm, &mut publish_retry, &ev.tx, ev.insure)?;
            }

            // A gossip tx check returned (`GossipTxChecks`): report its verdict. Forwarded when the
            // pool holds this tx byte for byte, newly or already: a resubmitted tx is re-gossiped
            // (api tx_submit) to reach nodes that missed it, across nodes that hold it. "Already
            // held" alone is not enough: a txid leaves the script_sigs out (crypto::txid), so a copy
            // with other signature bytes has the same txid and a new message id. A refusal strikes
            // nobody: the author of a gossip tx cannot be authenticated and the forwarder did not
            // write it (handle_gossipsub_event), and a node behind the tip rejects valid live txs.
            // One refused while an input or its proposal is missing here is parked, keyed by the
            // message's content hash, and gossiped once admitted (recheck_orphan_txs).
            Some(done) = gossip_tx_checks.running.join_next(), if gossip_tx_checks.is_running() => {
                match done {
                    Ok(GossipTxChecked { check, outcome }) => {
                        let inputs = check.tx.inputs.len();
                        let (forward, admitted) = match outcome {
                            Ok(forward) => (forward, Some(check.tx)),
                            Err(deps) => {
                                let height = best_hdr_height.max(local_tip_and_work(&db).1);
                                let len = check.tx_bytes.len();
                                let why = if orphan_txs.park(check.key, check.tx, len, deps, height) {
                                    "gossip tx parked: an input or its proposal is not here yet"
                                } else {
                                    "gossip tx failed mempool validation"
                                };
                                note_gossip_dropped(&mut gossip_dropped, check.fwd, TOPIC_TX, why);
                                (false, None)
                            }
                        };
                        if !forward {
                            charge_gossip_tx_refusal(&mut buckets, check.fwd, inputs);
                        }
                        let forwarded = report_gossip_verdict(&mut swarm, &check.msg_id, &check.fwd, forward);
                        // `forwarded` retires no queued publish of these bytes: gossipsub reports
                        // the cache hit, not whether the forward reached a peer.
                        // The check returned after gossipsub dropped the message (5 heartbeats
                        // unreported), so the Accept forwarded nothing and gossipsub never sent it
                        // on. Publish the tx as a first accept, as recheck_orphan_txs does, once
                        // per tx while held (`PublishRetry::claim_late`) and while the pool still
                        // holds these bytes; it waits in PublishRetry until our own duplicate cache
                        // lets it out.
                        if let Some(tx) = admitted.filter(|_| forward && !forwarded) {
                            let id = crate::crypto::txid(&tx);
                            let held = || mempool.holds_encoding(&id, &check.tx_bytes);
                            if publish_retry.claim_late(id, &check.tx_bytes, held) {
                                println!(
                                    "[p2p] gossip tx {} admitted after gossipsub dropped its message; gossiping it",
                                    hex32(&id)
                                );
                                if let Ok(msg) = crate::codec::consensus_bincode().serialize(&GossipTx { tx }) {
                                    publish_retry.publish_late(id, msg, |m| {
                                        swarm.behaviour_mut().gossipsub.publish(IdentTopic::new(TOPIC_TX), m).map(|_| ())
                                    });
                                }
                            }
                        }
                    }
                    Err(e) => println!("[p2p] a gossip tx check did not finish: {e}"),
                }
                gossip_tx_checks.start_waiting(&db, &mempool);
            }

            // An inbound request served off the loop (`Serves`): send its answer. A join error is a
            // panic in a serve, which ends the loop as the awaited serve did, or the task's
            // cancellation, which happens only when the runtime shuts down.
            Some(done) = serves.running.join_next(), if !serves.running.is_empty() => {
                let served = done.map_err(|e| anyhow::anyhow!("serve task join error: {e}"))??;
                #[cfg(feature = "test-bypass")]
                {
                    TEST_SERVES_PENDING.lock().unwrap().insert(peer_id, serves.running.len());
                }
                if let Some(response) = served.response {
                    #[cfg(feature = "test-bypass")]
                    {
                        *TEST_SERVES_ANSWERED.lock().unwrap().entry(peer_id).or_insert(0) += 1;
                    }
                    let _ = swarm.behaviour_mut().rr.send_response(served.channel, response);
                }
            }

            swarm_ev = swarm.select_next_some(), if swarm_held_since.is_none() => {
                match swarm_ev {

SwarmEvent::NewListenAddr { address, .. } => {
    println!("[p2p] NewListenAddr: {}", address);

    // store first usable listen addr
    let mut g = listen_addr.write().await;
    if g.is_none() {
        *g = Some(address.clone());
    }
}

SwarmEvent::ConnectionEstablished { peer_id, endpoint, .. } => {
    for addr in take_pending_dials(&mut pending_dials, &peer_id) {
        note_addr_dial_success(&mut addr_backoff, &addr);
    }
    if let libp2p::core::ConnectedPoint::Dialer { address, .. } = &endpoint {
        clear_addr_timeouts(&mut addr_timeouts, address);
    }

    // A banned peer's connection is closed, never kept uncounted: one kept open outside
    // `connected` would serve the peer once the ban was pruned.
    if is_banned(&bans, &peer_id) {
        if let Some(n) = log_due(close_counts.entry("connect while banned".to_string()).or_default()) {
            println!("[p2p] closing a connection from banned peer {peer_id} (so_far={n})");
        }
        disconnect_peer(&mut swarm, &mut closing, peer_id, "banned");
        continue;
    }

    let e = conn_refcnt.entry(peer_id).or_insert(0);
    *e += 1;

    // Record peers we dialed (Dialer endpoint) for anti-eclipse eviction protection.
    if endpoint.is_dialer() {
        outbound.insert(peer_id);
        store_outbound_gauge(&outbound_peers, &outbound);
    }

    let is_first_logical_connection = connected.insert(peer_id);
    if !is_first_logical_connection {
        continue;
    }

let max_connected = effective_max_connected(cfg.is_bootnode);

if connected.len() > max_connected.saturating_add(PEER_CAP_BURST) {
    if let Some(n) = peer_line(&peer_id, Line::Connect) {
        println!(
            "[p2p] over hard cap after connect: connected={} max={}, disconnecting {} since_last_line={n}",
            connected.len(),
            max_connected,
            peer_id
        );
    }

    connected.remove(&peer_id);
    conn_refcnt.remove(&peer_id);
    outbound.remove(&peer_id);
    store_outbound_gauge(&outbound_peers, &outbound);
    connected_peers.store(connected.len(), Ordering::Relaxed);

    disconnect_peer(&mut swarm, &mut closing, peer_id, "over the hard cap at connect");
    continue;
}

    if let Some(n) = peer_line(&peer_id, Line::Connect) {
        println!("[p2p] connected: {peer_id} since_last_line={n}");
    }
    connected_peers.store(connected.len(), Ordering::Relaxed);
    mark_peer_change(&last_peer_change_unix);

connected_since.insert(peer_id, Instant::now());

last_useful_peer_at.insert(peer_id, Instant::now());

note_connected(peer_quality.entry(peer_id).or_default(), endpoint.is_dialer(), unix_now());

if !is_quarantined(&quarantine, &peer_id) {
    owe_bootstrap(peer_id, &mut last_bootstrap_req_at, &mut background);
    pump_background(&mut swarm, &mut background, &mut unreported, &db, &eligible_peers(&connected, &bans, &quarantine), false);

    if sync_peer.is_none() {
        sync_peer = Some(peer_id);
    }
}
}

SwarmEvent::OutgoingConnectionError { peer_id, error, .. } => {
    if dial_refused_by_us(&error) {
        let _ = forget_refused_dial(&mut pending_dials, peer_id);
        if let Some(n) = log_due(close_counts.entry("dial refused by our limits".to_string()).or_default()) {
            println!("[p2p] a dial to {peer_id:?} refused by our connection limits: {error} (so_far={n})");
        }
        continue;
    }
    match peer_id {
        Some(p) => {
            if let Some(n) = peer_line(&p, Line::DialFailure) {
                println!("[p2p] OutgoingConnectionError peer={:?} err={:?} since_last_line={n}", peer_id, error);
            }
        }
        // A dial without a peer id: a configured bootnode's address.
        None => println!("[p2p] OutgoingConnectionError peer={:?} err={:?}", peer_id, error),
    }

    if let Some(pid) = peer_id {

{
    let q = peer_quality.entry(pid).or_default();
    q.dial_failure = q.dial_failure.saturating_add(1);
}


for addr in take_pending_dials(&mut pending_dials, &pid) {
    if let Some(n) = peer_line(&pid, Line::DialFailure) {
        println!("[pex] backing off addr for {pid} -> {addr} since_last_line={n}");
    }
    note_addr_dial_failure(&mut addr_backoff, &addr);
}

        last_disconnect_at.insert(pid, Instant::now());

        for addr in timed_out_dial_addrs(&error) {
            if note_addr_timeout(
                &mut known_addrs,
                &mut addr_timeouts,
                pid,
                &addr,
                &bootnode_peers,
                !connected.is_empty(),
            ) {
                if let Some(n) = peer_line(&pid, Line::DialFailure) {
                    println!("[pex] removing addr for {pid} -> {addr}: {ADDR_TIMEOUTS_TO_EVICT} dial timeouts in a row since_last_line={n}");
                }
                known_peers_atomic.store(known_addrs.len(), Ordering::Relaxed);
            }
        }

        for (addr, why) in forget_failed_dial_addrs(&mut known_addrs, &pid, &error) {
            if let Some(n) = peer_line(&pid, Line::DialFailure) {
                println!("[pex] removing {why} addr for {pid} -> {addr} since_last_line={n}");
            }
        }
        known_peers_atomic.store(known_addrs.len(), Ordering::Relaxed);
    }
}

SwarmEvent::IncomingConnectionError { local_addr, send_back_addr, error, .. } => {
    // One line per kind at powers of two: refusals by our limits and handshakes past their deadline
    // come at the rate a remote opens connections.
    let kind = match &error {
        libp2p::swarm::ListenError::Denied { .. } => "inbound refused by our limits",
        _ => "inbound handshake failed",
    };
    if let Some(n) = log_due(close_counts.entry(kind.to_string()).or_default()) {
        println!(
            "[p2p] IncomingConnectionError local_addr={:?} send_back_addr={:?} err={:?} ({kind}, so_far={n})",
            local_addr, send_back_addr, error
        );
    }
}

SwarmEvent::Dialing { peer_id, connection_id } => {
    match peer_id {
        Some(p) => {
            if let Some(n) = peer_line(&p, Line::Dial) {
                println!("[p2p] Dialing peer={:?} conn={:?} since_last_line={n}", peer_id, connection_id);
            }
        }
        // A dial without a peer id: a configured bootnode's address.
        None => println!("[p2p] Dialing peer={:?} conn={:?}", peer_id, connection_id),
    }
}

                    SwarmEvent::ConnectionClosed { peer_id, connection_id, endpoint, num_established, cause, .. } => {
                        let closing_why = if num_established == 0 { closing.remove(&peer_id) } else { closing.get(&peer_id).copied() };
                        let shed_why = shed.remove(&connection_id);
                        if shed_why.is_some() {
                            let rr = &swarm.behaviour().rr;
                            unreported.shed_closed(connection_id, &peer_id, |rid| rr.is_pending_outbound(&peer_id, rid));
                            #[cfg(feature = "test-bypass")]
                            if TEST_HOLD_SWARM_AFTER_SHED.lock().unwrap().contains_key(swarm.local_peer_id()) {
                                swarm_held_since.get_or_insert_with(Instant::now);
                            }
                        }
                        let ours = shed_why.or(closing_why);
                        let (kind, line) = close_line(&peer_id, endpoint.is_dialer(), num_established, ours, cause.as_ref());
                        if let Some(n) = log_due(close_counts.entry(kind).or_default()) {
                            println!("{line} (closes_with_this_cause={n})");
                        }
                        // NEW: refcount; only treat 1->0 as “disconnected”
                        if let Some(e) = conn_refcnt.get_mut(&peer_id) {
                            if *e > 0 { *e -= 1; }
                            if *e > 0 {
                                continue;
                            }
                        }
                        conn_refcnt.remove(&peer_id);
                        outbound.remove(&peer_id);
                        store_outbound_gauge(&outbound_peers, &outbound);

                        if connected.remove(&peer_id) {
                            connected_peers.store(connected.len(), Ordering::Relaxed);
                        }

                        mark_peer_change(&last_peer_change_unix);

			last_disconnect_at.insert(peer_id, Instant::now());
			last_bootstrap_req_at.remove(&peer_id);

                        peer_heights.remove(&peer_id);
                        peer_work.remove(&peer_id);
                         peer_tips.remove(&peer_id);
                        background.forget(&peer_id);

last_stale_penalty_at.remove(&peer_id);

connected_since.remove(&peer_id);
last_sync_request_from.remove(&peer_id);

last_useful_peer_at.remove(&peer_id);

let (best_h, best_w) = recompute_best_peer_metrics(
    &connected,
    &peer_heights,
    &peer_work,
    &bans,
    &quarantine,
);

best_peer_height_atomic.store(best_h, Ordering::Relaxed);
*best_peer_work.write().await = best_w;

let best_tip_now = recompute_best_peer_tip(
    &connected,
    &peer_tips,
    &peer_work,
    &peer_score,
    &bans,
    &quarantine,
);
*best_peer_tip.write().await = best_tip_now;

peer_gone(&peer_id);


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

let _ = compact_and_log_want_queue(
    &db,
    &pending_apply,
    &inflight,
    &mut want_blocks,
    &body_refetch,
    "connection-closed",
);


                        if sync_peer == Some(peer_id) {
                            sync_peer = None;
                        }
                    }

                    SwarmEvent::Behaviour(event) => {

if let OutEvent::Identify(identify::Event::Received { peer_id: remote_peer, info, .. }) = &event {
    let pid = *remote_peer;

    if pid != peer_id {
        for addr in info.listen_addrs.iter().cloned() {
            let full: Multiaddr = with_p2p_suffix(addr, pid);

            if should_store_discovered_addr(peer_id, pid, &full) {
                if insert_known_addr_is_new(&mut known_addrs, pid, full.clone()) {
                    if let Some(n) = peer_line(&pid, Line::LearnedAddr) {
                        println!("[pex] learned addr for {pid} -> {full} since_last_line={n}");
                    }
                }

known_peers_atomic.store(known_addrs.len(), Ordering::Relaxed);

            }
        }

save_known_addrs(&cfg.datadir, peer_id, &known_addrs);

if !is_banned(&bans, &pid) && !is_quarantined(&quarantine, &pid) {
    owe_bootstrap(pid, &mut last_bootstrap_req_at, &mut background);
    pump_background(&mut swarm, &mut background, &mut unreported, &db, &eligible_peers(&connected, &bans, &quarantine), false);
}
    }
}

                        if let Some((fwd, msg_id, data, topic)) = handle_gossipsub_event(&event) {
                            // gossipsub forwards this message only
                            // if we report Accept, so every path through `judge` ends in a verdict,
                            // reported once below: `true` forwards it to the mesh, `false` drops it.
                            // rustc refuses `continue` and `break` inside a closure (E0267), so no
                            // path leaves the loop iteration unreported; a store error reports
                            // `false` and then ends the loop. A gossip
                            // tx handed to `gossip_tx_checks` sets `checked_later`, and the check
                            // arm reports its verdict when the check returns.
                            let mut checked_later = false;
                            let mut judge = || -> Result<bool> {
                            if data.len() > MAX_GOSSIP_MSG_BYTES {
                                note_gossip_dropped(
                                    &mut gossip_dropped,
                                    fwd,
                                    &topic,
                                    "oversized gossip msg",
                                );
                                return Ok(false);
                            }

// CATCH-UP GUARD (caught_up): `gossip_gate` disconnects a banned or quarantined forwarder only while
// we are within CATCHUP_LAG blocks of the best peer. A node behind cannot validate current gossip and
// would shed the peers it syncs from (a catching-up node can end at 0 peers that way).
let caught_up = {
    let bh = peer_heights.values().copied().max().unwrap_or(0);
    let lh = local_tip_and_work(&db).1;
    // bh==0 (no peer heights yet, e.g. startup) => treat as behind => lenient. At tip => aggressive.
    const CATCHUP_LAG: u64 = 3;
    bh > 0 && lh.saturating_add(CATCHUP_LAG) >= bh
};

// The transport gate (`gossip_gate`) is keyed on the FORWARDER, deliberately, and it is the only
// peer-keyed gossip control: a content failure strikes nobody (see handle_gossipsub_event).
//
// A sourceless message is NOT dropped here. The message id is computed over `m.data` only
// (the message_id_fn in run_p2p_loop), so a signature-stripped copy of an honest header carries the
// same id as the signed original; dropping it at the app would suppress the original through
// gossipsub's duplicate cache, which is inserted at behaviour.rs:1992 (0.50.1) BEFORE the app
// event is emitted at :2032. Sourceless messages are processed on their merits: content validity
// does not depend on who claims to have sent it.
match gossip_gate(&mut buckets, &mut bans, &quarantine, fwd, caught_up) {
    GossipGate::Admit => {}
    GossipGate::Drop(why) => {
        note_gossip_dropped(&mut gossip_dropped, fwd, &topic, why);
        #[cfg(feature = "test-bypass")]
        {
            if why == "gossip rate limit" && topic == TOPIC_HDR {
                if let Ok(gh) = decode_wire::<GossipHeader>(&data, MAX_GOSSIP_MSG_BYTES as u64) {
                    TEST_RATE_DROPPED_HEADERS.lock().unwrap().entry((peer_id, fwd)).or_default().insert(header_hash(&gh.header));
                }
            }
        }
        return Ok(false);
    }
    GossipGate::Disconnect(why) => {
        disconnect_peer(&mut swarm, &mut closing, fwd, why);
        return Ok(false);
    }
}

                            if topic == TOPIC_HDR {
                                let gh: GossipHeader =
                                    match decode_wire(&data, MAX_GOSSIP_MSG_BYTES as u64) {
                                    Ok(x) => x,
                                    Err(_) => {
                                        note_gossip_dropped(
                                            &mut gossip_dropped,
                                            fwd,
                                            &topic,
                                            "bad gossip header decode",
                                        );
                                        return Ok(false);
                                    }
                                };

                                let h = header_hash(&gh.header);

                                if !accept_header_universe_pow(&cfg, &gh.header, &h, &fwd) {
                                    note_gossip_dropped(
                                        &mut gossip_dropped,
                                        fwd,
                                        &topic,
                                        "gossip header failed pow/limit/universe",
                                    );
                                    return Ok(false);
                                }

                                mark_tip_seen(&last_tip_seen_unix);

// Do not treat gossip source as block provider.
// It may only be relaying the header.
// providers.entry(h).or_insert(p);

let mut newly_indexed_header = false;

{
    let _g = chain_lock.lock();

    if get_hidx(&db, &h)?.is_none() {
        if gh.header.prev == [0u8; 32] {
            if index_header(&db, &gh.header, None).is_ok() {
                newly_indexed_header = true;
            }
        } else if let Some(parent) = get_hidx(&db, &gh.header.prev)? {
            if index_header(&db, &gh.header, Some(&parent)).is_ok() {
                newly_indexed_header = true;
            }
        } else {
            // This answers "who do I talk to next", so it must be a peer
            // we hold a connection to: the noise-authenticated forwarder, never an unauthenticated
            // `from`. Unconditional, as in upstream, so a parent-unknown header always takes
            // this arm and returns instead of falling through unindexed.
            // The headers request is owed to the forwarder until it is sent (`Background`).
            if let Some(n) = peer_line(&fwd, Line::ParentUnknown) {
                println!("[sync] gossip header parent unknown; headers owed by {} for {} since_last_line={n}", fwd, hex32(&h));
            }
            background.want(fwd, Asked::Headers, Instant::now());
            pump_background(&mut swarm, &mut background, &mut unreported, &db, &eligible_peers(&connected, &bans, &quarantine), false);
            // Not forwarded: its PoW is checked only against its own bits, which a header with an
            // invented parent can set to the PoW limit. Its re-announce once the parent arrives
            // (publish_header in the headers response) is refused while gossipsub's duplicate
            // cache holds its id (0.50.1 behaviour.rs:658-666, 60 s), so peers take it from another
            // mesh path or from their own headers round.
            return Ok(false);
        }
    }
}

                                // Credited to the forwarder, and only for
                                // a header this message indexed: a known or refused header is no
                                // new work.
                                if newly_indexed_header {
                                    bump_score(&mut peer_score, &mut quarantine, fwd, 1);
                                }

if seen_blocks.insert(h) {
    // With CSD_GOSSIP_FETCH on, ENQUEUE the announced block immediately (a gossip
    // header we just indexed, parent known, whose block we lack) so the pump_blocks call right below
    // fetches it this tick instead of waiting for the ~10s tip-pull headers round. We do NOT register
    // the announcer as providers[h]: propagation_source is the mesh FORWARDER, which may have relayed
    // the header before it holds the block; recording it as the provider (and eager-requesting the
    // body from it) risks a 120s bad-stamp on one of the few peers that serve old blocks. Provider
    // discovery stays with headers-sync, which learns a peer that actually served a block.
    // pump_blocks picks an eligible peer via its normal branches; if none has it yet, the block is
    // fetched on the next headers round exactly as upstream. CSD_GOSSIP_FETCH=0 (default) =>
    // upstream behavior (wait).
    if gossip_fetch_enabled() && newly_indexed_header {
        let already_have_block = db.blocks.get(k_block(&h))?.is_some();
        if !already_have_block
            && !inflight.contains_key(&h)
            && !pending_apply.contains_key(&h)
            && !want_blocks.iter().any(|x| x == &h)
            && want_blocks.len() < MAX_WANT_QUEUE
        {
            want_blocks.push_back(h);
        }
    }

let _ = compact_and_log_want_queue(
    &db,
    &pending_apply,
    &inflight,
    &mut want_blocks,
    &body_refetch,
    "gossip-hdr",
);

    if sync_peer.is_none() {
        // Same rule: this answers "who do I talk to next".
        sync_peer = Some(fwd);
    }
}

let _ = pump_blocks(
    &mut swarm,
    &mut unreported,
    sync_peer,
    &connected,
    &providers,
    &mut bad_providers,
    &bans,
    &mut quarantine,
    &mut rid_to_hash,
    &db,
    &pending_apply,
    &mut want_blocks,
    &mut inflight,
    &body_refetch,    &mut retired_block_requests,
);

                                // Forwarded only when this message is what indexed the header. One
                                // already indexed is not: every header a node indexes from a headers
                                // response is published as new gossip (a syncing node publishes its
                                // whole catch-up), and forwarding old ones would carry that, or a
                                // replay of the chain's history, to every node.
                                Ok(newly_indexed_header)
                            } else if topic == TOPIC_TX {
                                let gt: GossipTx =
                                    match decode_wire(&data, MAX_GOSSIP_MSG_BYTES as u64) {
                                    Ok(x) => x,
                                    Err(_) => {
                                        note_gossip_dropped(
                                            &mut gossip_dropped,
                                            fwd,
                                            &topic,
                                            "bad gossip tx decode",
                                        );
                                        return Ok(false);
                                    }
                                };

                                let Ok(tx_bytes) = crate::codec::consensus_bincode().serialize(&gt.tx) else {
                                    return Ok(false);
                                };
                                if tx_bytes.len() > MAX_TX_BYTES {
                                    note_gossip_dropped(
                                        &mut gossip_dropped,
                                        fwd,
                                        &topic,
                                        "gossip tx oversized",
                                    );
                                    return Ok(false);
                                }
                                if gossip_tx_refusals_spent(&mut buckets, fwd) {
                                    note_gossip_dropped(&mut gossip_dropped, fwd, &topic, "gossip tx refusal budget");
                                    return Ok(false);
                                }

                                // Checked off the loop; the check arm reports the verdict.
                                let key = *blake3::hash(&data).as_bytes();
                                let check = GossipTxCheck { fwd, msg_id: msg_id.clone(), key, tx: gt.tx, tx_bytes };
                                if gossip_tx_checks.push(check, &db, &mempool) {
                                    checked_later = true;
                                } else {
                                    note_gossip_dropped(&mut gossip_dropped, fwd, &topic, "gossip tx check queue full");
                                }
                                Ok(false)
                            } else {
                                Ok(false)
                            }
                            };
                            let verdict = judge();
                            if !checked_later {
                                let _ = report_gossip_verdict(&mut swarm, &msg_id, &fwd, matches!(verdict, Ok(true)));
                            }
                            verdict?;
                        }





                        if let Some(rr_ev) = as_rr_event(event) {
                            use request_response::{Event, Message};

                            // The answer or failure of a request of ours ends
                            // its `Unreported` entry, here, before any arm can skip it; a failure on
                            // a connection we shed is ours while that connection's record holds.
                            let on_shed_connection = match &rr_ev {
                                Event::Message { connection_id, message: Message::Response { request_id, .. }, .. }
                                | Event::OutboundFailure { connection_id, request_id, .. } => {
                                    unreported.reported(request_id, *connection_id)
                                }
                                _ => false,
                            };

                            match rr_ev {
                                Event::Message { peer, message, .. } => {
                                    if is_banned(&bans, &peer) || is_quarantined(&quarantine, &peer) {
                                        // Nothing from such a peer is handled, but an answer to one of
                                        // our block requests still frees its slot.
                                        if let Message::Response { request_id, .. } = &message {
                                            background.settle(request_id);
                                            if let Some(h) = release_unanswered_block_request(
                                                request_id, &mut rid_to_hash, &mut inflight, &mut want_blocks,
                                            ) {
                                                if let Some(n) = peer_line(&peer, Line::Block) {
                                                    println!("[sync] requeued {}: the answer came from {} after a ban or quarantine since_last_line={n}", hex32(&h), peer);
                                                }
                                            }
                                        }
                                        continue;
                                    }

                                    match message {

Message::Request { request, channel, .. } => {

// Past the window's figure a request is answered "rate limited" at once, before the serve
// permit, and the requester kept. An Err answer is the cheaper refusal for an upstream requester:
// its Err arm (d168f70 node.rs:4536-4560) stamps us a bad provider of a requested block for 120 s
// and charges nothing else, where a dropped answer is an OutboundFailure (:4573-4632): a timeout in
// its quality record, -1 to our score for a block request, the same stamp, and its sync peer
// switched away from us. The text avoids "unknown block" (-3, :4486) and "historical" (header-only).
match allow_rr_req(&mut buckets, &mut bans, peer) {
    RrAdmission::Serve => {}
    admission => {
        if admission == (RrAdmission::Throttled { entered: true }) {
            if let Some(n) = log_due(close_counts.entry("requests throttled".to_string()).or_default()) {
                println!(
                    "[p2p] throttling {peer} for the rest of its window: past {RL_MAX_RR_REQS_PER_WINDOW} requests (windows throttled so far={n})"
                );
            }
        }
        let _ = swarm.behaviour_mut().rr.send_response(
            channel,
            SyncResponse::Err { msg: "rate limited".into() },
        );
        continue;
    }
}

match &request {
      SyncRequest::GetTip
    | SyncRequest::GetHeadersByLocator { .. }
    | SyncRequest::GetHeaders { .. }
    | SyncRequest::GetBlock { .. } => {
        let now = Instant::now();
        last_sync_request_from.insert(peer, now);
        last_useful_peer_at.insert(peer, now);
    }
    _ => {}
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



// A request's lines, upstream's, sampled per peer and kind as upstream sampled
// GetTip's: `logged` is the requests of this kind since the peer's last line when one is due now
// (`peer_line`); the serve prints its lookup, HIT and anchor lines only then.
let logged = peer_line(&peer, Line::of(&request));
if let Some(n) = logged {
    match &request {
        SyncRequest::GetPeers { max } => {
            println!("[pex] recv GetPeers from {peer} max={max} requests_since_last_line={n}");
        }
        SyncRequest::GetTip => {
            println!("[sync-serve] recv GetTip from {peer} requests_since_last_line={n}");
        }
        SyncRequest::GetHeadersByLocator { locator, max } => {
            println!(
                "[sync-serve] recv GetHeadersByLocator from {peer} locator_len={} max={} requests_since_last_line={n}",
                locator.len(),
                max
            );
        }
        SyncRequest::GetHeaders { from_height, max } => {
            println!(
                "[sync-serve] recv GetHeaders from {peer} from_height={} max={} requests_since_last_line={n}",
                from_height,
                max
            );
        }
        SyncRequest::GetBlock { hash } => {
            println!("[sync-serve] recv GetBlock from {peer} hash={} requests_since_last_line={n}", hex32(hash));
        }
        SyncRequest::SubmitTx { .. } => {
            println!("[sync-serve] recv SubmitTx from {peer} requests_since_last_line={n}");
        }
    }
}
#[cfg(feature = "test-bypass")]
if matches!(request, SyncRequest::GetPeers { .. }) {
    *TEST_PEERS_REQUESTS_SERVED.lock().unwrap().entry((peer_id, peer)).or_insert(0) += 1;
}

// Test-only fault injection for the live p2p lane (tests/p2p_live_*.rs). Compiled in
// ONLY under the `test-bypass` cargo feature; production binaries contain no such
// branch, and `NetConfig` has no `test_mode` field there to activate it.
#[cfg(feature = "test-bypass")]
{
    if let (TestPeerMode::TipForHeaders(claim), SyncRequest::GetHeadersByLocator { .. }) = (&cfg.test_mode, &request) {
        let hi = get_hidx(&db, claim).ok().flatten().expect("the claimed header is indexed here");
        TEST_TIPS_FOR_HEADERS.fetch_add(1, Ordering::Relaxed);
        let resp = SyncResponse::Tip { hash: *claim, height: hi.height, chainwork: hi.chainwork };
        let _ = swarm.behaviour_mut().rr.send_response(channel, resp);
        continue;
    }

    if matches!(cfg.test_mode, TestPeerMode::ReplayHeaders)
        && matches!(request, SyncRequest::GetTip | SyncRequest::GetHeadersByLocator { .. })
    {
        let tip = get_tip(&db).ok().flatten().unwrap_or([0u8; 32]);
        let tip_header = served_header(&db, &tip).ok().flatten().expect("the replaying peer holds its tip");
        let to_tip = matches!(request, SyncRequest::GetTip);
        let resp = if to_tip && replay_turn % 2 == 1 {
            SyncResponse::Tip { hash: [0xEE; 32], height: u64::MAX, chainwork: u128::MAX }
        } else {
            let one = if to_tip {
                tip_header
            } else {
                served_header(&db, &tip_header.prev).ok().flatten().expect("the replaying peer holds its tip's parent")
            };
            TEST_REPLAYED_HEADERS[usize::from(!to_tip)].fetch_add(1, Ordering::Relaxed);
            println!("[p2p-test] answering {} from {peer} with {MAX_HEADERS_PER_SYNC} copies of a header", if to_tip { "GetTip" } else { "GetHeadersByLocator" });
            SyncResponse::Headers { headers: vec![one; MAX_HEADERS_PER_SYNC as usize] }
        };
        if to_tip {
            replay_turn += 1;
        }
        let _ = swarm.behaviour_mut().rr.send_response(channel, resp);
        continue;
    }

    if matches!(request, SyncRequest::GetBlock { .. }) {
        let stall = match cfg.test_mode {
            TestPeerMode::StallBlockResponses => true,
            TestPeerMode::StallFirstBlockRequest => stalled_channels.is_empty(),
            _ => false,
        };
        if stall {
            println!("[p2p-test] intentionally stalling GetBlock response from {peer}");
            TEST_STALLED_BLOCK_REQUESTS.fetch_add(1, Ordering::Relaxed);
            // Held, not dropped: a dropped channel fails the request at once (ResponseOmission),
            // where a silent peer leaves the requester to its timeout.
            stalled_channels.push(channel);
            continue;
        }

        if matches!(cfg.test_mode, TestPeerMode::AckBlockRequests) {
            println!("[p2p-test] intentionally answering GetBlock with Ack to {peer}");
            TEST_ACKED_BLOCK_REQUESTS.fetch_add(1, Ordering::Relaxed);
            let _ = swarm.behaviour_mut().rr.send_response(channel, SyncResponse::Ack);
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

        if let (TestPeerMode::DelayBlocksWithSpends | TestPeerMode::RepeatLastTxOfOddBlocks, SyncRequest::GetBlock { hash }) =
            (&cfg.test_mode, &request)
        {
            let stored = db.blocks.get(k_block(hash)).ok().flatten();
            let blk = stored.and_then(|v| crate::codec::consensus_bincode().deserialize::<Block>(&v).ok());
            let delay = matches!(cfg.test_mode, TestPeerMode::DelayBlocksWithSpends);
            match blk {
                Some(b) if delay && b.txs.len() > 1 => {
                    println!("[p2p-test] answering GetBlock {} to {peer} at the next poll tick", hex32(hash));
                    delayed_responses.push((channel, SyncResponse::Block { block: b }));
                    continue;
                }
                Some(mut b) if !delay && b.txs.len() > 1 && b.txs.len() % 2 == 1 => {
                    b.txs.push(b.txs[b.txs.len() - 1].clone());
                    TEST_SUBSTITUTED_BODIES_SERVED.fetch_add(1, Ordering::Relaxed);
                    println!("[p2p-test] serving {} with its last tx repeated to {peer}", hex32(hash));
                    let _ = swarm.behaviour_mut().rr.send_response(channel, SyncResponse::Block { block: b });
                    continue;
                }
                _ => {}
            }
        }

        if let (TestPeerMode::SubstituteSignatures | TestPeerMode::PushSubstitutedOnTip, SyncRequest::GetBlock { hash }) =
            (&cfg.test_mode, &request)
        {
            let stored = db.blocks.get(k_block(hash)).ok().flatten();
            let mut blk = stored
                .and_then(|v| crate::codec::consensus_bincode().deserialize::<Block>(&v).ok());
            let sig = blk.as_mut().and_then(|b| {
                b.txs.iter_mut().skip(1).flat_map(|tx| tx.inputs.iter_mut()).find(|i| i.script_sig.len() > 5)
            });
            if let Some(input) = sig {
                input.script_sig[5] ^= 0x01;
                TEST_SUBSTITUTED_BODIES_SERVED.fetch_add(1, Ordering::Relaxed);
                println!("[p2p-test] serving {} with an altered signature to {peer}", hex32(hash));
                let altered = blk.expect("the input belongs to it");
                if matches!(cfg.test_mode, TestPeerMode::PushSubstitutedOnTip) {
                    pushed_body = Some(altered.clone());
                }
                let _ = swarm.behaviour_mut().rr.send_response(channel, SyncResponse::Block { block: altered });
                continue;
            }
        }
    }

    if let (TestPeerMode::PushSubstitutedOnTip, SyncRequest::GetTip, Some(b)) =
        (&cfg.test_mode, &request, &pushed_body)
    {
        TEST_PUSHED_BODIES.fetch_add(1, Ordering::Relaxed);
        println!("[p2p-test] answering GetTip from {peer} with an altered block body");
        let _ = swarm.behaviour_mut().rr.send_response(channel, SyncResponse::Block { block: b.clone() });
        continue;
    }
}

match request {
    SyncRequest::GetPeers { max } => {
        let peers = export_peer_strings(
            peer_id,
            peer,
            &known_addrs,
            &peer_quality,
            (max as usize).min(MAX_PEERS_IN_EXCHANGE),
        );
        let _ = swarm.behaviour_mut().rr.send_response(channel, SyncResponse::Peers { peers });
    }
    other => {
        serves.start(channel, other, &db, peer, logged.is_some());
        #[cfg(feature = "test-bypass")]
        {
            TEST_SERVES_PENDING.lock().unwrap().insert(peer_id, serves.running.len());
        }
    }
}
                                        }

                                        Message::Response { request_id: rid, response } => {

let asked = background.settle(&rid);
// A freed slot goes out at once; a Tip answer first records the headers it may owe (the Tip arm).
if asked.is_some_and(|k| k != Asked::Tip) {
    pump_background(&mut swarm, &mut background, &mut unreported, &db, &eligible_peers(&connected, &bans, &quarantine), false);
}
if !matches!(response, SyncResponse::Block { .. } | SyncResponse::Err { .. }) {
    if let Some(h) = release_unanswered_block_request(&rid, &mut rid_to_hash, &mut inflight, &mut want_blocks) {
        note_wrong_kind_block_answer(h, peer, &mut bad_providers, &mut providers);
        if let Some(n) = peer_line(&peer, Line::Block) {
            println!("[sync] requeued {}: {} answered the block request with another kind of response since_last_line={n}", hex32(&h), peer);
        }
    }
}

                                            match response {

SyncResponse::Tip { hash: hash, height, chainwork } => {

if asked != Some(Asked::Tip) {
    if let Some(n) = peer_line(&peer, Line::Tip) {
        println!("[sync] dropped a Tip from {peer}: not an answer to our GetTip since_last_line={n}");
    }
    continue;
}

let indexed = if hash == [0u8; 32] { None } else { get_hidx(&db, &hash).ok().flatten() };
note_tip_answer(peer_quality.entry(peer).or_default(), asked, indexed.as_ref(), unix_now());

    mark_tip_seen(&last_tip_seen_unix);

last_useful_peer_at.insert(peer, Instant::now());


// A peer's Tip response is only an advertisement.
// It must NOT become trusted best-peer state unless we have indexed that header.
if hash == [0u8; 32] {
    peer_heights.insert(peer, 0);
    peer_work.insert(peer, 0);
    peer_tips.insert(peer, hash);
} else if let Some(hi) = indexed {
    peer_heights.insert(peer, hi.height);
    peer_work.insert(peer, hi.chainwork);
    peer_tips.insert(peer, hash);

} else {
    // Unknown advertised tip: request headers only.
    // Do not let unindexed peer claims affect miner gating.
    peer_heights.remove(&peer);
    peer_work.remove(&peer);
    peer_tips.remove(&peer);
}

let (best_h, best_w) = recompute_best_peer_metrics(
    &connected,
    &peer_heights,
    &peer_work,
    &bans,
    &quarantine,
);

best_peer_height_atomic.store(best_h, Ordering::Relaxed);
*best_peer_work.write().await = best_w;

let best_tip_now = recompute_best_peer_tip(
    &connected,
    &peer_tips,
    &peer_work,
    &peer_score,
    &bans,
    &quarantine,
);
*best_peer_tip.write().await = best_tip_now;


let (_dbg_tip, _dbg_h, _dbg_w) = local_tip_and_work(&db);
let last_logged = last_logged_tip.get(&peer).copied();

if should_log_tip_update(last_logged, height, chainwork, _dbg_w) {
    if let Some(n) = peer_line(&peer, Line::Tip) {
        println!(
            "[sync] tip from {}: remote_height={} remote_work={} local_work={} since_last_line={n}",
            peer, height, chainwork, _dbg_w
        );
    }
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
        if let Some(n) = peer_line(&p, Line::SyncPeer) {
            println!("[sync] switching sync_peer -> {p} since_last_line={n}");
        }
    }
}
sync_peer = next_sync_peer;

    let (applied_tip, _applied_h, applied_w) = local_tip_and_work(&db);

    let local_w = applied_w;
    let locator_tip = applied_tip;

if better_fork_tip(chainwork, &hash, local_w, &locator_tip) {
    background.want(peer, Asked::Headers, Instant::now());
    pump_background(&mut swarm, &mut background, &mut unreported, &db, &eligible_peers(&connected, &bans, &quarantine), false);
}
}

                                                SyncResponse::Headers { headers } => {
    if asked != Some(Asked::Headers) {
        if let Some(n) = peer_line(&peer, Line::Headers) {
            println!("[sync] dropped {} headers from {}: not an answer to our headers request since_last_line={n}", headers.len(), peer);
        }
        continue;
    }
    if headers.len() as u64 > MAX_HEADERS_PER_SYNC {
        note_invalid(&mut buckets, &mut bans, peer, "oversized headers response");
        bump_score(&mut peer_score, &mut quarantine, peer, SCORE_BAD_OVERSIZED_HEADERS);
        continue;
    }

    // An empty answer scores nobody: a peer whose chain has nothing above our locator's anchor
    // answers empty honestly, as when it relays a side-branch header whose parent we lack.
    #[cfg(feature = "test-bypass")]
    {
        if headers.is_empty() {
            *TEST_EMPTY_HEADERS_ANSWERS.lock().unwrap().entry(peer).or_insert(0) += 1;
        }
    }

    if let Some(n) = peer_line(&peer, Line::Headers) {
        println!("[sync] got headers from {} count={} since_last_line={n}", peer, headers.len());
    }

    // No score and no quality for the answer itself: a reply of copies of a header we hold costs
    // the peer nothing. Only a block it serves earns it credit.
    if !headers.is_empty() {
        mark_tip_seen(&last_tip_seen_unix);
        last_useful_peer_at.insert(peer, Instant::now());
        peer_quality.entry(peer).or_default().last_seen_unix = unix_now();
    }

    if sync_peer.is_none() {
        sync_peer = Some(peer);
    }

    // Keep headers in-order exactly as received.
    let mut indexed_batch: Vec<(Hash32, BlockHeader)> = Vec::new();

    for hdr in headers.into_iter() {
        let h = header_hash(&hdr);

        if !accept_header_universe_pow(&cfg, &hdr, &h, &peer) {
            note_invalid(&mut buckets, &mut bans, peer, "headers: invalid pow/limit/universe");
            bump_score(&mut peer_score, &mut quarantine, peer, SCORE_BAD_INVALID);
            continue;
        }

        providers.entry(h).or_insert(peer);

let mut newly_indexed_header = false;

let idx_res = {
    let _g = chain_lock.lock();

    if get_hidx(&db, &h)?.is_some() {
        Ok(())
    } else if hdr.prev == [0u8; 32] {
        let r = index_header(&db, &hdr, None);
        if r.is_ok() {
            newly_indexed_header = true;
        }
        r.map(|_| ())
    } else {
        let parent = get_hidx(&db, &hdr.prev)?;
        let Some(p) = parent else {
            continue;
        };

        let r = index_header(&db, &hdr, Some(&p));
        if r.is_ok() {
            newly_indexed_header = true;
        }
        r.map(|_| ())
    }
};

if idx_res.is_err() {
    note_invalid(&mut buckets, &mut bans, peer, "headers: index_header failed");
    bump_score(&mut peer_score, &mut quarantine, peer, SCORE_BAD_INVALID);
    continue;
}

// Relay valid/indexed headers immediately.
// This improves global propagation and reduces orphan advantage.
if newly_indexed_header {
    let _ = publish_header(&mut swarm, &mut publish_retry, hdr.clone(), false);
}
indexed_batch.push((h, hdr.clone()));

        if let Ok(Some(hi2)) = get_hidx(&db, &h) {

if better_fork_tip(hi2.chainwork, &h, best_hdr_work, &best_hdr_tip) {

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


if let Some((last_h, _last_hdr)) = indexed_batch.last() {
    if let Ok(Some(last_hi)) = get_hidx(&db, last_h) {
        let prev_tip = peer_tips.get(&peer).copied().unwrap_or([0u8; 32]);
        let prev_work = peer_work.get(&peer).copied().unwrap_or(0);
        let prev_height = peer_heights.get(&peer).copied().unwrap_or(0);

        if better_fork_tip(last_hi.chainwork, last_h, prev_work, &prev_tip) {
            peer_tips.insert(peer, *last_h);
            peer_work.insert(peer, last_hi.chainwork);
            peer_heights.insert(peer, last_hi.height);
        } else if last_hi.chainwork == prev_work && last_hi.height > prev_height {
            // keep height telemetry monotone if work matches
            peer_heights.insert(peer, last_hi.height);
        }
    }
}

    // Recompute best-peer metrics.

let (best_h, best_w) = recompute_best_peer_metrics(
    &connected,
    &peer_heights,
    &peer_work,
    &bans,
    &quarantine,
);

best_peer_height_atomic.store(best_h, Ordering::Relaxed);
*best_peer_work.write().await = best_w;

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
            if let Some(n) = peer_line(&p, Line::SyncPeer) {
                println!("[sync] switching sync_peer -> {p} since_last_line={n}");
            }
        }
    }
    sync_peer = next_sync_peer;

let best_tip_now = recompute_best_peer_tip(
    &connected,
    &peer_tips,
    &peer_work,
    &peer_score,
    &bans,
    &quarantine,
);
*best_peer_tip.write().await = best_tip_now;

    // Immediate request rule:
    // request the FIRST missing block in this exact batch whose parent raw block is grounded.
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
            db.blocks.get(k_block(&hdr.prev))?.is_some()
                || pending_apply.contains_key(&hdr.prev)
        };

        if parent_grounded {
            immediate_req = Some(*h);
            break;
        }
    }

    if let Some(h) = immediate_req {
        if !has_raw_or_pending(&db, &pending_apply, &h) && !inflight.contains_key(&h) {
            let mut candidates: Vec<PeerId> = providers.get(&h).copied().into_iter().collect();
            candidates.push(peer);
            candidates.extend(sync_peer);
            let usable = |p: &PeerId| can_take_block_request(p, &connected, &bans, &quarantine, &inflight);
            let request_peer = pick_block_peer(&candidates, usable, &h, &bad_providers, &body_refetch);

            if let Some(req_peer) = request_peer {
                let rid = send_our_request(&mut swarm, &mut unreported, &req_peer, SyncRequest::GetBlock { hash: h });
                note_block_request_sent(rid, req_peer, h, &mut rid_to_hash, &mut inflight);

                println!(
                    "[sync] immediate request block {} from {}",
                    hex32(&h),
                    req_peer
                );
            }
        }
    }

    let _ = pump_blocks(
        &mut swarm,
        &mut unreported,
        sync_peer,
        &connected,
        &providers,
        &mut bad_providers,
        &bans,
        &mut quarantine,
        &mut rid_to_hash,
        &db,
        &pending_apply,
        &mut want_blocks,
        &mut inflight,
        &body_refetch,        &mut retired_block_requests,
    );
}

SyncResponse::Block { block } => {
    let bh = header_hash(&block.header);
    if let Some(n) = peer_line(&peer, Line::Block) {
        println!("[sync] got block {} from {} since_last_line={n}", hex32(&bh), peer);
    }

    let expected_h = match rid_to_hash.remove(&rid) {
        Some(h) => h,
        None => {
            // Graceful late/duplicate response, only for a
            // GetBlock this node retired (RetiredBlockRequests), for that block, from the peer
            // asked, and not from a peer whose body for it failed. Keyed on the block's real hash
            // bh (get_hidx is true only after we indexed a full-PoW header):
            //   - header indexed AND block not yet stored -> still-wanted: ACCEPT it without penalty.
            //   - header indexed AND block already stored  -> benign DUPLICATE: drop it silently, no
            //     penalty (a retired request whose block since arrived from another peer
            //     must NOT strike a slow-but-honest peer toward quarantine).
            //   - a faulted source                          -> dropped silently: it may relay a body
            //     it has not validated.
            //   - otherwise (no indexed header, or an answer to another kind of request)
            //                                               -> unsolicited: strike as before.
            let verdict = late_block_verdict(
                retired_block_requests.take(&rid),
                &bh,
                &peer,
                get_hidx(&db, &bh)?.is_some(),
                db.blocks.get(k_block(&bh))?.is_some(),
                body_refetch.is_faulted(&bh, &peer),
            );
            match verdict {
                LateBlock::Accept => bh,
                LateBlock::Ignore => continue,
                LateBlock::Unsolicited => {
                    note_invalid(&mut buckets, &mut bans, peer, "unrequested block response");
                    bump_score(&mut peer_score, &mut quarantine, peer, SCORE_BAD_UNREQUESTED_BLOCK);
                    continue;
                }
            }
        }
    };

    if expected_h != bh {
        inflight.remove(&expected_h);

        note_invalid(&mut buckets, &mut bans, peer, "block response hash mismatch");
        bump_score(&mut peer_score, &mut quarantine, peer, SCORE_BAD_UNREQUESTED_BLOCK);

bad_providers.entry(expected_h).or_default().insert(peer, Instant::now());

        if want_blocks.len() < MAX_WANT_QUEUE {
            want_blocks.push_back(expected_h);
        }

        continue;
    }

    mark_tip_seen(&last_tip_seen_unix);

last_useful_peer_at.insert(peer, Instant::now());

    if let Ok(bytes) = crate::codec::consensus_bincode().serialize(&block) {
        if bytes.len() > MAX_BLOCK_BYTES {
            note_invalid(&mut buckets, &mut bans, peer, "block: oversized");
            bump_score(&mut peer_score, &mut quarantine, peer, SCORE_BAD_INVALID);
            continue;
        }
    }

    providers.insert(bh, peer);

if let Some(peers) = bad_providers.get_mut(&bh) {
    peers.remove(&peer);
    if peers.is_empty() {
        bad_providers.remove(&bh);
    }
}

    want_blocks.retain(|x| *x != bh);

    if let Some((_rid2, t0, asked_peer)) = inflight.remove(&expected_h) {
        if asked_peer == peer {
            let _elapsed = t0.elapsed().as_millis();
        }
    }

    if !accept_header_universe_pow(&cfg, &block.header, &bh, &peer) {
        note_invalid(&mut buckets, &mut bans, peer, "block: failed pow/limit/universe");
        bump_score(&mut peer_score, &mut quarantine, peer, SCORE_BAD_INVALID);
        continue;
    }

    // ---- lock only for raw-block store + header index ----
    {
        let _g = chain_lock.lock();

        // Body binding, store path 1 of 2. See store_block_bytes_checked.
        let outcome = store_block_bytes_checked(&db, &bh, &block)?;
        let stored_new = matches!(outcome, BlockStoreOutcome::Stored);
        match outcome {
            BlockStoreOutcome::Stored => {
                // `bh` itself goes into pending_apply below.
                for target in body_refetch.note_stored(bh, peer).into_iter().filter(|t| *t != bh) {
                    requeue_completable_tip(&db, &mut pending_apply, target)?;
                }
            }
            BlockStoreOutcome::AlreadyPresent => {}
            BlockStoreOutcome::RejectedMerkle => {
                note_invalid(
                    &mut buckets,
                    &mut bans,
                    peer,
                    "block: body does not bind to header",
                );
                bump_score(&mut peer_score, &mut quarantine, peer, SCORE_BAD_INVALID);
                continue;
            }
            BlockStoreOutcome::RejectedOversize => {
                note_invalid(&mut buckets, &mut bans, peer, "block: oversized (store)");
                bump_score(&mut peer_score, &mut quarantine, peer, SCORE_BAD_INVALID);
                continue;
            }
            BlockStoreOutcome::RejectedRepeatedTxid => {
                body_refetch.note_refused(bh, peer, &mut bad_providers, &mut want_blocks);
                continue;
            }
        }

        let idx_res = if block.header.prev == [0u8; 32] {
            index_header(&db, &block.header, None)
        } else if let Some(p) = get_hidx(&db, &block.header.prev)? {
            index_header(&db, &block.header, Some(&p))

} else {
    // parent header not known yet; keep raw block pending
    pending_apply.insert(bh, block);
    continue;
};


        if idx_res.is_err() {
            note_invalid(&mut buckets, &mut bans, peer, "block: index_header failed");
            bump_score(&mut peer_score, &mut quarantine, peer, SCORE_BAD_INVALID);
            continue;
        }

        // Credit only a body new here that bound, was stored and indexed: one refused on any of
        // those checks, or one we hold already, earns nothing.
        if stored_new {
            bump_score(&mut peer_score, &mut quarantine, peer, SCORE_GOOD_BLOCK);
            let q = peer_quality.entry(peer).or_default();
            q.good_block = q.good_block.saturating_add(1);
            q.last_seen_unix = unix_now();
        }

        if let Ok(Some(hi2)) = get_hidx(&db, &bh) {
            if better_fork_tip(hi2.chainwork, &bh, best_hdr_work, &best_hdr_tip) {
                best_hdr_tip = bh;
                best_hdr_height = hi2.height;
                best_hdr_work = hi2.chainwork;
            }
        }


if let Ok(Some(hi2)) = get_hidx(&db, &bh) {
    let prev_tip = peer_tips.get(&peer).copied().unwrap_or([0u8; 32]);
    let prev_work = peer_work.get(&peer).copied().unwrap_or(0);
    let prev_height = peer_heights.get(&peer).copied().unwrap_or(0);

    if better_fork_tip(hi2.chainwork, &bh, prev_work, &prev_tip) {
        peer_tips.insert(peer, bh);
        peer_work.insert(peer, hi2.chainwork);
        peer_heights.insert(peer, hi2.height);
    } else if hi2.chainwork == prev_work && hi2.height > prev_height {
        peer_heights.insert(peer, hi2.height);
    }
}
    }

// We now possess the full block and indexed its header,
// so it is safe to relay the header as a real provider.
let _ = publish_header(&mut swarm, &mut publish_retry, block.header.clone(), false);

let best_tip_now = recompute_best_peer_tip(
    &connected,
    &peer_tips,
    &peer_work,
    &peer_score,
    &bans,
    &quarantine,
);
*best_peer_tip.write().await = best_tip_now;

    pending_apply.insert(bh, block);
try_apply_pending(
    &db,
    mempool.as_ref(),
    &mut pending_apply,
    &providers,
    &mut peer_quality,
    &mut peer_score,
    &mut quarantine,
    &chain_lock,
    &mut body_refetch,
    &mut bad_providers,
    &mut want_blocks,
);
	
    compact_and_log_want_queue(
        &db,
        &pending_apply,
        &inflight,
        &mut want_blocks,
        &body_refetch,
        "block",
    )?;

    let _ = pump_blocks(
        &mut swarm,
        &mut unreported,
        sync_peer,
        &connected,
        &providers,
        &mut bad_providers,
        &bans,
        &mut quarantine,
        &mut rid_to_hash,
        &db,
        &pending_apply,
        &mut want_blocks,
        &mut inflight,
        &body_refetch,        &mut retired_block_requests,
    );
}

SyncResponse::Peers { peers } => {
    // Only the answer to our GetPeers (one every 30 s at most, `Background`): taken in reply to a
    // GetTip, a headers request or a GetBlock, a list would rewrite peers.txt and start dials with
    // every answer.
    if asked != Some(Asked::Peers) {
        if let Some(n) = peer_line(&peer, Line::Peers) {
            println!("[pex] dropped a Peers answer from {peer}: not an answer to our GetPeers since_last_line={n}");
        }
        continue;
    }
    let before = known_addrs.len();

parse_peer_strings_into_known_addrs(&mut known_addrs, peer_id, peers);

known_peers_atomic.store(known_addrs.len(), Ordering::Relaxed);



save_known_addrs(&cfg.datadir, peer_id, &known_addrs);

    let after = known_addrs.len();
    if let Some(n) = peer_line(&peer, Line::Peers) {
        println!("[pex] learned peer set from {peer} (known_peers {before} -> {after}) since_last_line={n}");
    }

    // Try dialing newly learned peers.

let mut peer_ids: Vec<PeerId> = known_addrs.keys().copied().collect();
sort_peer_ids_by_quality(&mut peer_ids, &peer_quality);

let mut dials_from_peers_response = 0usize;

for pid in peer_ids {

    let max_connected = effective_max_connected(cfg.is_bootnode);

    if connected.len() >= max_connected {
        break;
    }

    if pid == peer_id || connected.contains(&pid) || is_banned(&bans, &pid) {
        continue;
    }

    if let Some(t0) = last_disconnect_at.get(&pid) {
        if t0.elapsed() < Duration::from_secs(PEER_DISCONNECT_COOLDOWN_SECS) {
            continue;
        }
    }

    let addrs = sorted_peer_addrs_for_export(peer_id, pid, &known_addrs);

for addr in addrs {
    if addr_is_backed_off(&addr_backoff, &addr) {
        continue;
    }

    if let Some(t0) = last_dial_by_addr.get(&addr) {
        if t0.elapsed() < Duration::from_secs(DIAL_BACKOFF_SECS) {
            continue;
        }
    }


if dials_from_peers_response >= MAX_DIALS_FROM_PEERS_RESPONSE
    || swarm.network_info().connection_counters().num_pending_outgoing() as usize
        >= MAX_PENDING_OUTGOING_DIALS
{
    break;
}

    if let Some(n) = peer_line(&pid, Line::Dial) {
        println!("[pex] dialing learned peer {pid} via {addr} since_last_line={n}");
    }

    let _ = swarm.dial(addr.clone());
    last_dial_by_addr.insert(addr.clone(), Instant::now());
    note_pending_dial(&mut pending_dials, pid, addr);
dials_from_peers_response += 1;
}

}

}

                                                SyncResponse::Ack => {}

SyncResponse::Err { msg } => {

    if msg.contains("unknown block") {
        if let Some(h) = rid_to_hash.remove(&rid) {
            if let Some(n) = peer_line(&peer, Line::ErrorReply) {
                println!(
                    "[sync] unknown block from {} for hash={} provider={:?} sync_peer={:?} since_last_line={n}",
                    peer,
                    hex32(&h),
                    providers.get(&h),
                    sync_peer
                );
            }

            inflight.remove(&h);
            note_unknown_block_answer(
                h,
                peer,
                &mut bad_providers,
                &mut providers,
                &mut want_blocks,
            );

let _ = compact_and_log_want_queue(
    &db,
    &pending_apply,
    &inflight,
    &mut want_blocks,
    &body_refetch,
    "unknown-block",
);

        } else if let Some(n) = peer_line(&peer, Line::ErrorReply) {
            println!("[sync] unknown block from {peer}, but rid had no tracked hash since_last_line={n}");
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
        if let Some(n) = peer_line(&peer, Line::ErrorReply) {
            println!("[sync] error response from {peer}: {} since_last_line={n}", peer_text(&msg));
        }

        // csd-patches: a peer refusing to serve history is header-only: mark it so
        // the scheduler stops picking it for blocks. And free the inflight slot NOW
        // (don't wait out the 60s block timeout) + requeue to another peer.
        if msg.contains("historical") {
            note_header_only(&peer);
        }
        if let Some(h) = rid_to_hash.remove(&rid) {
            inflight.remove(&h);
            bad_providers.entry(h).or_default().insert(peer, Instant::now());
            if providers.get(&h) == Some(&peer) {
                providers.remove(&h);
            }
            if want_blocks.len() < MAX_WANT_QUEUE {
                want_blocks.push_back(h);
            }
        }
    }

}

                                            }
                                        }



                                    }
                                }


Event::OutboundFailure { peer, request_id, error, .. } => {

if background.settle(&request_id).is_some() {
    pump_background(&mut swarm, &mut background, &mut unreported, &db, &eligible_peers(&connected, &bans, &quarantine), false);
}

    let logged = peer_line(&peer, Line::OutboundFailure);
    if let Some(n) = logged {
        println!("[sync] outbound failure to {peer}: {error:?} since_last_line={n}");
    }
    // Our stream refusal and a connection we shed blame nobody: otherwise a shed connection's
    // GetBlock costs the honest peer -1, a 120 s stamp and its place as sync peer.
    let fault = outbound_fault(&error, on_shed_connection);

if charges_quality_timeout(&error) {
    let q = peer_quality.entry(peer).or_default();
    q.timeout = q.timeout.saturating_add(1);
    q.last_seen_unix = unix_now();
}

    if let Some(h) = rid_to_hash.remove(&request_id) {
        inflight.remove(&h);

        let servers = block_server_count(&connected, &bans, &quarantine);
        let stamped = note_block_request_failure(
            h,
            peer,
            fault,
            servers,
            &mut peer_score,
            &mut quarantine,
            &mut bad_providers,
            &mut providers,
            &mut want_blocks,
        );
        let note = match (fault, stamped) {
            (OutboundFault::OurStreamLimit, _) => " (our stream limit: nobody blamed)",
            (OutboundFault::OurShed, _) => " (a connection we shed: nobody blamed)",
            (OutboundFault::Peer, true) => "",
            (OutboundFault::Peer, false) => " (at most one block server: not stamped)",
        };
        if logged.is_some() {
            println!("[sync] requeued {} after outbound failure{note}", hex32(&h));
        }

        let _ = compact_and_log_want_queue(
            &db,
            &pending_apply,
            &inflight,
            &mut want_blocks,
            &body_refetch,
            "outbound-failure",
        );

    }

    if sync_peer == Some(peer) && fault == OutboundFault::Peer {
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
    // Logged, never counted against the requester. Upstream disconnects one at
    // 20 in 60 s (d168f70 node.rs:4633-4657), but none that request-response 0.30.0 reports is the
    // requester's doing: an Io is our write or close failing after the request was read
    // (handler.rs:149-157), a Timeout our late answer (:136-158), a ConnectionClosed or
    // ResponseOmission ours as well, and UnsupportedProtocols has no construction site (:248-256);
    // a request the codec cannot read is never reported (lib.rs:1001-1018).
    if let Some(n) = log_due(&mut inbound_failures_ours) {
        println!("[sync] inbound failure from {peer}: {error:?}, ours, not counted against it (uncounted_so_far={n})");
    }
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

/// The header of a block for a GetHeaders answer: from `hdr_raw` when its bytes decode to a header
/// that hashes to `hash`, else from the stored body, after which its header goes into `hdr_raw`,
/// so each served header is decoded from its body once. None when neither holds it.
fn served_header(db: &Stores, hash: &Hash32) -> Result<Option<BlockHeader>> {
    if let Some(raw) = crate::state::db::get_hdr_raw(db, hash)? {
        if let Ok(header) = crate::codec::consensus_bincode().deserialize::<BlockHeader>(&raw) {
            if header_hash(&header) == *hash {
                return Ok(Some(header));
            }
        }
    }
    let Some(bv) = db.blocks.get(k_block(hash))? else {
        return Ok(None);
    };
    if bv.len() > MAX_BLOCK_BYTES {
        bail!("db corruption: stored block exceeds MAX_BLOCK_BYTES");
    }
    let blk: Block = crate::codec::consensus_bincode().deserialize::<Block>(&bv)?;
    if header_hash(&blk.header) != *hash {
        bail!("db corruption: header hash mismatch for {}", hex32(hash));
    }
    let raw = crate::codec::consensus_bincode().serialize(&blk.header)?;
    crate::state::db::put_hdr_raw(db, hash, &raw)?;
    Ok(Some(blk.header))
}

/// A GetHeadersByLocator anchor (height and hash) and the hashes of the lowest `max` blocks above it;
/// None when no locator hash is on our chain.
type LocatorAnchor = Option<(u64, Hash32, VecDeque<Hash32>)>;

/// The anchor for `locator` on the chain ending at `tip`: through the height index when it is
/// fresh at `tip`, else by the walk.
fn locator_anchor(
    db: &Stores,
    tip: &Hash32,
    locator: &HashSet<Hash32>,
    max: u64,
    hash_at_height: impl FnMut(u64) -> Result<Option<Hash32>>,
) -> Result<LocatorAnchor> {
    match locator_anchor_by_height_index(db, tip, locator, max, hash_at_height)? {
        Some(anchored) => Ok(anchored),
        None => locator_anchor_by_walk(db, tip, locator, max),
    }
}

/// The anchor on the chain ending at `tip` is the highest locator hash on it, else genesis when the
/// locator holds the zero hash. This reads the height index (`hash_at_height`), a few reads per
/// locator hash and one per answered height; None when the index is not fresh at `tip` before and
/// after those reads, or misses a height, and the caller walks (`locator_anchor_by_walk`). The
/// reconciler rewrites height entries during a reorg and moves the freshness marker in the same
/// batch as each entry, so a marker still at `tip` after the reads means they described its chain,
/// unless the tip left and came back to `tip` within one answer.
fn locator_anchor_by_height_index(
    db: &Stores,
    tip: &Hash32,
    locator: &HashSet<Hash32>,
    max: u64,
    mut hash_at_height: impl FnMut(u64) -> Result<Option<Hash32>>,
) -> Result<Option<LocatorAnchor>> {
    let fresh = || crate::state::tx_scan::fresh_tip(db).as_ref() == Some(tip);
    if !fresh() {
        return Ok(None);
    }
    let Some(tip_hi) = get_hidx(db, tip)? else { return Ok(None) };
    let mut anchor: Option<(u64, Hash32)> = None;
    for h in locator {
        let Some(hi) = get_hidx(db, h)? else { continue };
        if hi.height <= tip_hi.height
            && anchor.is_none_or(|(a, _)| hi.height > a)
            && hash_at_height(hi.height)? == Some(*h)
        {
            anchor = Some((hi.height, *h));
        }
    }
    if anchor.is_none() && locator.contains(&[0u8; 32]) {
        let Some(genesis) = hash_at_height(0)? else { return Ok(None) };
        anchor = Some((0, genesis));
    }
    let Some((anchor_h, anchor_hash)) = anchor else { return Ok(fresh().then_some(None)) };
    let top = tip_hi.height.min(anchor_h.saturating_add(max));
    let mut above = VecDeque::with_capacity((top - anchor_h) as usize);
    for height in anchor_h + 1..=top {
        let Some(h) = hash_at_height(height)? else { return Ok(None) };
        above.push_back(h);
    }
    Ok(fresh().then_some(Some((anchor_h, anchor_hash, above))))
}

/// The same anchor by walking the header index down from `tip` to the highest locator match, one
/// read per block above it.
fn locator_anchor_by_walk(
    db: &Stores,
    tip: &Hash32,
    locator: &HashSet<Hash32>,
    max: u64,
) -> Result<LocatorAnchor> {
    let mut above: VecDeque<Hash32> = VecDeque::with_capacity(max as usize + 1);
    let mut cur = *tip;
    loop {
        let hi = get_hidx(db, &cur)?
            .ok_or_else(|| anyhow::anyhow!("missing idx for {}", hex32(&cur)))?;

        if locator.contains(&cur) {
            return Ok(Some((hi.height, cur, above)));
        }

        if hi.parent == [0u8; 32] {
            return Ok(locator.contains(&[0u8; 32]).then_some((0, cur, above)));
        }

        above.push_front(cur);
        if above.len() as u64 > max {
            above.pop_back();
        }

        cur = hi.parent;
    }
}

/// `logged`: print the answer's lines (`serve_request` prints a MISS).
fn handle_request_blocking(db: &Stores, req: SyncRequest, logged: bool) -> Result<SyncResponse> {
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

                let Some(header) = served_header(db, &cur)? else {
                    break;
                };
                out.push(header);

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

let locator_set: HashSet<Hash32> = locator.into_iter().collect();
let anchored = locator_anchor(db, &tip, &locator_set, max, |height| {
    crate::state::tx_index::get_block_hash_by_height(db, height)
})?;
let Some((anchor_h, anchor_hash, above)) = anchored else {
    return Ok(SyncResponse::Headers { headers: vec![] });
};

// Headers from the anchor up, stopping at the first that cannot be read or does not link to the
// one before, so the answer connects.
let mut out: Vec<BlockHeader> = Vec::with_capacity(above.len());
let mut prev = anchor_hash;
for h in &above {
    let Some(header) = served_header(db, h)? else { break };
    if header.prev != prev {
        break;
    }
    prev = *h;
    out.push(header);
}

if logged {
    println!(
        "[sync-serve] GetHeadersByLocator: anchor_h={} returning={} tip={}",
        anchor_h,
        out.len(),
        hex32(&tip),
    );
}

            Ok(SyncResponse::Headers { headers: out })
        }

SyncRequest::GetBlock { hash } => {
    if logged {
        println!("[sync-serve] GetBlock lookup {}", hex32(&hash));
    }

    let Some(v) = db.blocks.get(k_block(&hash))? else {
        bail!(UNKNOWN_BLOCK);
    };

    if logged {
        println!(
            "[sync-serve] GetBlock HIT {} bytes={}",
            hex32(&hash),
            v.len()
        );
    }

    if v.len() > MAX_BLOCK_BYTES {
        bail!("db corruption: stored block exceeds MAX_BLOCK_BYTES");
    }

    let blk: Block = crate::codec::consensus_bincode().deserialize::<Block>(&v)?;
    Ok(SyncResponse::Block { block: blk })
}


        SyncRequest::SubmitTx { tx: _tx } => Ok(SyncResponse::Ack),

SyncRequest::GetPeers { .. } => {
    bail!("GetPeers must be handled in event loop");
}

    }

}

#[cfg(test)]
mod node_key_tests {
    use super::*;

    // `nodekey.ed25519` as libp2p-identity 0.2.13 (the version under upstream's libp2p 0.54.1)
    // writes the ed25519 key from seed [7u8; 32], and that key's PeerId: produced by 0.2.13's own
    // `Keypair::ed25519_from_bytes(..).to_protobuf_encoding()`.
    const V0213_NODEKEY_HEX: &str = "080112400707070707070707070707070707070707070707070707070707070707070707\
        ea4a6c63e29c520abef5507b132ec5f9954776aebebe7b92421eea691446d22c";
    const V0213_PEER_ID: &str = "12D3KooWRawPbxPtP1eZaJpumGnyWX2DcUyd3RQnydr3eAto4Az7";

    #[test]
    fn a_node_key_written_before_the_upgrade_keeps_its_peer_id() {
        let dir = tempfile::TempDir::new().unwrap();
        let datadir = dir.path().to_str().unwrap();
        let bytes = hex::decode(V0213_NODEKEY_HEX).unwrap();
        std::fs::write(nodekey_path(datadir), &bytes).unwrap();

        let kp = load_or_create_node_key(datadir).unwrap();
        assert_eq!(
            PeerId::from(kp.public()).to_string(),
            V0213_PEER_ID,
            "a node upgraded across a libp2p-identity bump must keep its PeerId"
        );
        assert_eq!(kp.to_protobuf_encoding().unwrap(), bytes, "and write the key back byte for byte");
    }
}

#[cfg(test)]
mod body_refetch_tests {
    use super::*;

    // A peer whose body for a hash failed is asked for it last, and again only when no other
    // usable peer is left, after its 120 s stamp; faults end after BODY_SOURCE_SECS.
    #[test]
    fn a_faulted_source_is_asked_last_and_again_only_when_nobody_else_can_be() {
        let (h, bad, honest) = ([7u8; 32], PeerId::random(), PeerId::random());
        let mut refetch = BodyRefetch::default();
        let mut bad_providers: HashMap<Hash32, HashMap<PeerId, Instant>> = HashMap::new();
        refetch.note_fault(h, bad, &mut bad_providers);
        let all = |_: &PeerId| true;
        assert_eq!(pick_block_peer(&[bad, honest], all, &h, &bad_providers, &refetch), Some(honest));
        assert_eq!(pick_block_peer(&[bad], all, &h, &bad_providers, &refetch), None, "stamped");

        let expired = Instant::now() - Duration::from_secs(BAD_PROVIDER_RETRY_SECS + 1);
        bad_providers.get_mut(&h).unwrap().insert(bad, expired);
        assert!(refetch.is_faulted(&h, &bad), "the fault outlives the stamp");
        assert_eq!(pick_block_peer(&[bad, honest], all, &h, &bad_providers, &refetch), Some(honest));
        assert_eq!(
            pick_block_peer(&[bad], all, &h, &bad_providers, &refetch),
            Some(bad),
            "with nobody else left the faulted peer is asked again"
        );
        assert_eq!(pick_block_peer(&[bad, honest], |p| *p != honest, &h, &bad_providers, &refetch), Some(bad));

        let long_ago = Instant::now() - Duration::from_secs(BODY_SOURCE_SECS + 1);
        refetch.faulted.get_mut(&h).unwrap().insert(bad, long_ago);
        assert!(!refetch.is_faulted(&h, &bad), "the fault ends after BODY_SOURCE_SECS");
    }

    // A block response is a late block only as the answer to a retired GetBlock for that block
    // from the peer asked; an answer to another request (a GetTip, say) is unsolicited.
    #[test]
    fn a_late_block_is_taken_only_as_the_answer_to_a_retired_get_block() {
        let (h, other, p, q) = ([1u8; 32], [2u8; 32], PeerId::random(), PeerId::random());
        let v = |r: Option<(Hash32, PeerId)>, indexed, stored, faulted| late_block_verdict(r, &h, &p, indexed, stored, faulted);
        assert_eq!(v(Some((h, p)), true, false, false), LateBlock::Accept);
        assert_eq!(v(Some((h, p)), true, true, false), LateBlock::Ignore, "a duplicate is not struck");
        assert_eq!(v(Some((h, p)), true, false, true), LateBlock::Ignore, "a faulted source is not stored");
        assert_eq!(v(None, true, false, false), LateBlock::Unsolicited, "no retired GetBlock");
        assert_eq!(v(Some((other, p)), true, false, false), LateBlock::Unsolicited, "another block asked");
        assert_eq!(v(Some((h, q)), true, false, false), LateBlock::Unsolicited, "another peer asked");
        assert_eq!(v(Some((h, p)), false, false, false), LateBlock::Unsolicited, "no indexed header");
    }

    // A pending copy that repeats a txid can only have come from db.blocks (the network store
    // refuses such a body before it reaches pending_apply): the stored body is dropped, the block
    // queued, and nobody blamed, though `providers` names a peer for it.
    #[test]
    fn the_drain_drops_a_stored_repeated_txid_body_and_blames_nobody() {
        let tmp = tempfile::TempDir::new().unwrap();
        let db = Stores::open(tmp.path().to_str().unwrap()).unwrap();
        let cb = crate::chain::mine::coinbase([5u8; 20], 1, 1, None);
        let id = crate::crypto::txid(&cb);
        let merkle = crate::crypto::sha256d(&[id, id].concat());
        let header = BlockHeader { version: 1, prev: [0u8; 32], merkle, time: 0, bits: 0, nonce: 0 };
        let blk = Block { header, txs: vec![cb.clone(), cb] };
        let h = crate::chain::index::header_hash(&blk.header);
        db.blocks.insert(k_block(&h), crate::codec::consensus_bincode().serialize(&blk).unwrap()).unwrap();

        let peer = PeerId::random();
        let mut pending = HashMap::from([(h, blk)]);
        let providers = HashMap::from([(h, peer)]);
        let (mut quality, mut score, mut quarantine) = (HashMap::new(), HashMap::new(), HashMap::new());
        let (mut refetch, mut bad_providers, mut want) = (BodyRefetch::default(), HashMap::new(), VecDeque::new());
        try_apply_pending(
            &db, &Mempool::new(), &mut pending, &providers, &mut quality, &mut score, &mut quarantine,
            &crate::chain::lock::new_chain_lock(), &mut refetch, &mut bad_providers, &mut want,
        );
        assert!(db.blocks.get(k_block(&h)).unwrap().is_none(), "the stored body must be dropped");
        assert!(pending.is_empty());
        assert!(bad_providers.is_empty() && refetch.faulted.is_empty(), "nobody is blamed");
        assert_eq!(want, VecDeque::from([h]), "the block is fetched again");
    }

    // The +12 for a block that becomes canonical must not be paid whenever maybe_reorg_to returns
    // Ok, which it also does when it applies nothing. A pending block on
    // the tip that carries a bad mark is not applied, and its provider earns nothing.
    #[test]
    fn a_block_that_does_not_become_canonical_earns_its_provider_nothing() {
        use crate::chain::index::{put_hidx, HeaderIndex};
        let tmp = tempfile::TempDir::new().unwrap();
        let db = Stores::open(tmp.path().to_str().unwrap()).unwrap();
        let tip = [0x10u8; 32];
        put_hidx(&db, &HeaderIndex { hash: tip, parent: [0u8; 32], height: 0, chainwork: 1, bits: 0, time: 0 }).unwrap();
        crate::state::db::set_tip(&db, &tip).unwrap();
        db.blocks.insert(k_block(&tip), &b"parent body"[..]).unwrap();
        let cb = crate::chain::mine::coinbase([5u8; 20], 1, 1, None);
        let merkle = crate::chain::mine::merkle_root_txids(&[crate::crypto::txid(&cb)]);
        let blk = Block { header: BlockHeader { version: 1, prev: tip, merkle, time: 1, bits: 0, nonce: 0 }, txs: vec![cb] };
        let h = crate::chain::index::header_hash(&blk.header);
        put_hidx(&db, &HeaderIndex { hash: h, parent: tip, height: 1, chainwork: 2, bits: 0, time: 1 }).unwrap();
        db.meta.insert(crate::state::db::k_bad(&h), &b"1"[..]).unwrap();

        let peer = PeerId::random();
        let mut pending = HashMap::from([(h, blk)]);
        let providers = HashMap::from([(h, peer)]);
        let (mut quality, mut score, mut quarantine) = (HashMap::new(), HashMap::new(), HashMap::new());
        let (mut refetch, mut bad_providers, mut want) = (BodyRefetch::default(), HashMap::new(), VecDeque::new());
        try_apply_pending(
            &db, &Mempool::new(), &mut pending, &providers, &mut quality, &mut score, &mut quarantine,
            &crate::chain::lock::new_chain_lock(), &mut refetch, &mut bad_providers, &mut want,
        );
        assert_eq!(crate::state::db::get_tip(&db).unwrap(), Some(tip), "setup: the bad block is not applied");
        assert_eq!(score.get(&peer), None, "credited for a block that did not become canonical");
        assert_eq!(quality.get(&peer).map(|q: &PeerQuality| q.canonical_block).unwrap_or(0), 0);
    }

    // A reorg target waits on the first body missing above its fork point with the tip and is
    // retried when that body is stored. A `bad:` block stops the path too, with nothing to wait
    // on, and the stored chain under it is queued while it is heavier than the tip.
    #[test]
    fn a_reorg_waits_on_its_first_missing_apply_body_and_the_chain_under_a_bad_block_is_queued() {
        use crate::chain::index::{put_hidx, HeaderIndex};
        let tmp = tempfile::TempDir::new().unwrap();
        let db = Stores::open(tmp.path().to_str().unwrap()).unwrap();
        let (g, a1, b1, b2, b3) = ([0x10u8; 32], [0x11u8; 32], [0x21u8; 32], [0x22u8; 32], [0x23u8; 32]);
        for (hash, parent, height, chainwork) in [(g, [0u8; 32], 0, 1), (a1, g, 1, 2), (b1, g, 1, 2), (b2, b1, 2, 3), (b3, b2, 3, 4)] {
            put_hidx(&db, &HeaderIndex { hash, parent, height, chainwork, bits: 0, time: 0 }).unwrap();
        }
        let header = BlockHeader { version: 1, prev: [0u8; 32], merkle: [0u8; 32], time: 0, bits: 0, nonce: 0 };
        let body = crate::codec::consensus_bincode().serialize(&Block { header, txs: vec![] }).unwrap();
        for h in [g, a1, b2, b3] {
            db.blocks.insert(k_block(&h), body.clone()).unwrap();
        }
        crate::state::db::set_tip(&db, &a1).unwrap();
        let stop = |t: &Hash32| apply_path_stop(&db, t).unwrap().map(|s| (s.at, s.missing, s.applicable_head));
        assert_eq!(stop(&b3), Some((b1, true, None)));

        let mut refetch = BodyRefetch::default();
        let (mut pending, mut want) = (HashMap::new(), VecDeque::new());
        refetch.note_unreached(&db, b3, &mut pending, &mut want).unwrap();
        assert_eq!(want, VecDeque::from([b1]), "the awaited body is queued");
        assert!(refetch.wanted_below_tip(&db, &b1, 3), "requested while the waiting reorg is heavier");
        assert!(!refetch.wanted_below_tip(&db, &b1, 4));
        assert!(refetch.note_stored(b2, PeerId::random()).is_empty(), "another body retries nothing");
        assert_eq!(refetch.note_stored(b1, PeerId::random()), vec![b3]);
        assert!(refetch.waits.is_empty());

        db.blocks.insert(k_block(&b1), body.clone()).unwrap();
        db.blocks.remove(k_block(&b2)).unwrap();
        assert_eq!(stop(&b3), Some((b2, true, Some(b1))), "the first missing in apply order");
        db.blocks.insert(k_block(&b2), body).unwrap();
        assert_eq!(stop(&b3), None);

        db.meta.insert(crate::state::db::k_bad(&b3), &b"1"[..]).unwrap();
        assert_eq!(stop(&b3), Some((b3, false, Some(b2))));
        refetch.wait(&db, b3, b1);
        refetch.note_unreached(&db, b3, &mut pending, &mut want).unwrap();
        assert!(refetch.waits.is_empty(), "a target stopped by a bad block waits on nothing");
        assert!(pending.contains_key(&b2), "the stored chain under the bad block is queued");
    }

    // The cap counts branches: a chain of deferred targets holds one wait, the head's, so a fork
    // with more deferred blocks than MAX_REORG_WAITS does not evict the target of a lighter fork,
    // which is retried when its body is stored (two forks).
    #[test]
    fn a_chain_of_deferred_targets_holds_one_wait() {
        use crate::chain::index::{put_hidx, HeaderIndex};
        let tmp = tempfile::TempDir::new().unwrap();
        let db = Stores::open(tmp.path().to_str().unwrap()).unwrap();
        let hash = |fork: u8, i: usize| -> Hash32 {
            let mut h = [fork; 32];
            h[..8].copy_from_slice(&(i as u64).to_le_bytes());
            h
        };
        let put = |h: Hash32, parent: Hash32, height: u64, chainwork: u128, stored: bool| {
            put_hidx(&db, &HeaderIndex { hash: h, parent, height, chainwork, bits: 0, time: 0 }).unwrap();
            if stored {
                db.blocks.insert(k_block(&h), vec![1u8]).unwrap();
            }
        };
        let g = hash(0x10, 0);
        put(g, [0u8; 32], 0, 1, true);
        crate::state::db::set_tip(&db, &g).unwrap();
        let (a1, a2) = (hash(0xa0, 1), hash(0xa0, 2));
        put(a1, g, 1, 2, false);
        put(a2, a1, 2, 3, true);
        put(hash(0xb0, 1), g, 1, 10, false);
        for i in 2..=MAX_REORG_WAITS + 1 {
            put(hash(0xb0, i), hash(0xb0, i - 1), i as u64, 10 + i as u128, true);
        }

        let mut refetch = BodyRefetch::default();
        let (mut pending, mut want) = (HashMap::new(), VecDeque::new());
        refetch.note_unreached(&db, a2, &mut pending, &mut want).unwrap();
        for i in 2..=MAX_REORG_WAITS + 1 {
            refetch.note_unreached(&db, hash(0xb0, i), &mut pending, &mut want).unwrap();
        }
        assert_eq!(refetch.waits.len(), 2, "one wait per fork");
        assert_eq!(refetch.note_stored(a1, PeerId::random()), vec![a2], "the lighter fork is retried");
    }

    // Targets tried highest first (each becomes tryable when its parent arrives) must not fill the
    // cap. Equal work per block, tip h6; fork A to A9 and fork B to B265; A9 waits on A7, then B265
    // down to B10 wait on B7. A wait per target would hold 256 B waits and evict A9, so once A7
    // arrived and A7 and A8 applied, the complete, heavier A9 would be neither waiting nor pending.
    // One wait per chain keeps A9's; the stall sweep queues A9 even with no wait left.
    #[test]
    fn reverse_order_targets_hold_one_wait_and_the_sweep_finds_a_chain_without_one() {
        use crate::chain::index::{put_hidx, HeaderIndex};
        let tmp = tempfile::TempDir::new().unwrap();
        let db = Stores::open(tmp.path().to_str().unwrap()).unwrap();
        let header = BlockHeader { version: 1, prev: [0u8; 32], merkle: [0u8; 32], time: 0, bits: 0, nonce: 0 };
        let body = crate::codec::consensus_bincode().serialize(&Block { header, txs: vec![] }).unwrap();
        let hash = |fork: u8, h: u64| -> Hash32 {
            let mut x = [fork; 32];
            x[..8].copy_from_slice(&h.to_le_bytes());
            x
        };
        let put = |h: Hash32, parent: Hash32, height: u64, stored: bool| {
            put_hidx(&db, &HeaderIndex { hash: h, parent, height, chainwork: height as u128 + 1, bits: 0, time: 0 }).unwrap();
            if stored {
                db.blocks.insert(k_block(&h), body.clone()).unwrap();
            }
        };
        put(hash(0x10, 0), [0u8; 32], 0, true);
        for h in 1..=6 {
            put(hash(0x10, h), hash(0x10, h - 1), h, true);
        }
        crate::state::db::set_tip(&db, &hash(0x10, 6)).unwrap();
        let (a, b) = (|h| hash(0xa0, h), |h| hash(0xb0, h));
        for h in 7..=9 {
            put(a(h), if h == 7 { hash(0x10, 6) } else { a(h - 1) }, h, h != 7);
        }
        for h in 7..=265 {
            put(b(h), if h == 7 { hash(0x10, 6) } else { b(h - 1) }, h, h > 8);
        }

        let mut refetch = BodyRefetch::default();
        let (mut pending, mut want) = (HashMap::new(), VecDeque::new());
        refetch.note_unreached(&db, a(9), &mut pending, &mut want).unwrap();
        for h in (10..=265).rev() {
            refetch.note_unreached(&db, b(h), &mut pending, &mut want).unwrap();
        }
        assert_eq!(refetch.waits.len(), 2, "one wait per chain, whatever the order");

        db.blocks.insert(k_block(&a(7)), body.clone()).unwrap();
        assert_eq!(refetch.note_stored(a(7), PeerId::random()), vec![a(9)], "A9 is retried when A7 is stored");
        crate::state::db::set_tip(&db, &a(8)).unwrap();
        let best_hdr_work = 266;
        let stood = |tip: Hash32, interval: u64| Some((tip, Instant::now() - Duration::from_secs(interval), interval));
        assert_eq!(refetch.sweep(&db, best_hdr_work, &mut pending).unwrap(), None, "the tip has not stood still yet");
        refetch.stall = stood(a(8), STALL_SWEEP_SECS);
        assert_eq!(refetch.sweep(&db, best_hdr_work, &mut pending).unwrap(), Some(a(9)), "no wait, no pending: the sweep");
        assert!(pending.contains_key(&a(9)));

        pending.clear();
        assert_eq!(refetch.sweep(&db, best_hdr_work, &mut pending).unwrap(), None, "not again within the interval");
        refetch.armed = false;
        refetch.stall = stood(a(8), STALL_SWEEP_SECS);
        assert_eq!(refetch.sweep(&db, best_hdr_work, &mut pending).unwrap(), None, "a disarmed sweep does nothing");
        refetch.arm_sweep();
        crate::state::db::set_tip(&db, &a(9)).unwrap();
        refetch.stall = stood(a(9), STALL_SWEEP_SECS);
        assert_eq!(refetch.sweep(&db, 10, &mut pending).unwrap(), None, "at the tip the sweep does nothing");
        assert!(refetch.armed && refetch.stall.is_none(), "and no sweep ran");
        db.meta.insert(crate::state::db::k_bad(&a(9)), &b"1"[..]).unwrap();
        crate::state::db::set_tip(&db, &a(8)).unwrap();
        refetch.stall = stood(a(8), STALL_SWEEP_SECS);
        assert_eq!(refetch.sweep(&db, best_hdr_work, &mut pending).unwrap(), None, "a bad: chain is not queued");
        assert_eq!(refetch.stall.map(|s| s.2), Some(2 * STALL_SWEEP_SECS), "a sweep that queues nothing doubles the interval");
    }

    // The chain a sweep queues may be rejected (a heavier fork with an invalid block), and no new
    // body may follow. Tip B8, B9 complete above it, the heavier A7..A10 complete from h6: the
    // sweep queues A10, which fails and is marked bad; the next sweep must queue B9. A sweep that
    // disarmed when it ran would never sweep again without a new body.
    #[test]
    fn a_rejected_sweep_choice_leaves_the_sweep_armed_for_the_next_complete_chain() {
        use crate::chain::index::{put_hidx, HeaderIndex};
        let tmp = tempfile::TempDir::new().unwrap();
        let db = Stores::open(tmp.path().to_str().unwrap()).unwrap();
        let header = BlockHeader { version: 1, prev: [0u8; 32], merkle: [0u8; 32], time: 0, bits: 0, nonce: 0 };
        let body = crate::codec::consensus_bincode().serialize(&Block { header, txs: vec![] }).unwrap();
        let hash = |fork: u8, h: u64| -> Hash32 {
            let mut x = [fork; 32];
            x[..8].copy_from_slice(&h.to_le_bytes());
            x
        };
        let put = |h: Hash32, parent: Hash32, height: u64| {
            put_hidx(&db, &HeaderIndex { hash: h, parent, height, chainwork: height as u128 + 1, bits: 0, time: 0 }).unwrap();
            db.blocks.insert(k_block(&h), body.clone()).unwrap();
        };
        let (g, a, b) = (|h| hash(0x10, h), |h| hash(0xa0, h), |h| hash(0xb0, h));
        put(g(0), [0u8; 32], 0);
        for h in 1..=6 {
            put(g(h), g(h - 1), h);
        }
        for h in 7..=10 {
            put(a(h), if h == 7 { g(6) } else { a(h - 1) }, h);
        }
        for h in 7..=9 {
            put(b(h), if h == 7 { g(6) } else { b(h - 1) }, h);
        }
        crate::state::db::set_tip(&db, &b(8)).unwrap();
        let stood = || Some((b(8), Instant::now() - Duration::from_secs(STALL_SWEEP_SECS), STALL_SWEEP_SECS));

        let mut refetch = BodyRefetch { armed: true, ..BodyRefetch::default() };
        let mut pending = HashMap::new();
        refetch.stall = stood();
        assert_eq!(refetch.sweep(&db, 11, &mut pending).unwrap(), Some(a(10)), "the heaviest complete chain first");
        pending.remove(&a(10));
        for h in [a(7), a(10)] {
            db.meta.insert(crate::state::db::k_bad(&h), &b"1"[..]).unwrap();
        }
        refetch.stall = stood();
        assert_eq!(refetch.sweep(&db, 11, &mut pending).unwrap(), Some(b(9)), "B9 is queued without another body");
    }

    // A search paused over several ticks and discarded when the tip moves must leave the sweep
    // armed. Our own mined block moves the tip without storing a network body (no note_stored), so
    // otherwise a complete stored A5001..A5002, heavier than both tips, is never queued. 5,001
    // local headers make the first search pause.
    #[test]
    fn a_search_ended_by_a_mined_tip_leaves_the_sweep_armed() {
        use crate::chain::index::{put_hidx, HeaderIndex};
        let tmp = tempfile::TempDir::new().unwrap();
        let db = Stores::open(tmp.path().to_str().unwrap()).unwrap();
        let header = BlockHeader { version: 1, prev: [0u8; 32], merkle: [0u8; 32], time: 0, bits: 0, nonce: 0 };
        let body = crate::codec::consensus_bincode().serialize(&Block { header, txs: vec![] }).unwrap();
        let hash = |fork: u8, h: u64| -> Hash32 {
            let mut x = [fork; 32];
            x[..8].copy_from_slice(&h.to_le_bytes());
            x
        };
        let (mut headers, mut bodies) = (sled::Batch::default(), sled::Batch::default());
        for h in 0..=5000u64 {
            let parent = if h == 0 { [0u8; 32] } else { hash(0xb0, h - 1) };
            let hi = HeaderIndex { hash: hash(0xb0, h), parent, height: h, chainwork: h as u128 + 1, bits: 0, time: 0 };
            headers.insert(crate::state::db::k_hdr(&hi.hash), crate::codec::consensus_bincode().serialize(&hi).unwrap());
            bodies.insert(k_block(&hi.hash), body.clone());
        }
        db.hdr.apply_batch(headers).unwrap();
        db.blocks.apply_batch(bodies).unwrap();
        let put = |h: Hash32, parent: Hash32, height: u64| {
            put_hidx(&db, &HeaderIndex { hash: h, parent, height, chainwork: height as u128 + 1, bits: 0, time: 0 }).unwrap();
            db.blocks.insert(k_block(&h), body.clone()).unwrap();
        };
        put(hash(0xa0, 5001), hash(0xb0, 5000), 5001);
        put(hash(0xa0, 5002), hash(0xa0, 5001), 5002);
        crate::state::db::set_tip(&db, &hash(0xb0, 5000)).unwrap();
        let stood = |tip| Some((tip, Instant::now() - Duration::from_secs(STALL_SWEEP_SECS), STALL_SWEEP_SECS));

        let mut refetch = BodyRefetch { armed: true, ..BodyRefetch::default() };
        let mut pending = HashMap::new();
        refetch.stall = stood(hash(0xb0, 5000));
        assert_eq!(refetch.sweep(&db, 5003, &mut pending).unwrap(), None);
        assert!(refetch.search.is_some(), "the first search pauses");

        put(hash(0xb0, 5001), hash(0xb0, 5000), 5001);
        crate::state::db::set_tip(&db, &hash(0xb0, 5001)).unwrap();
        assert_eq!(refetch.sweep(&db, 5003, &mut pending).unwrap(), None, "the new tip ends that search");
        refetch.stall = stood(hash(0xb0, 5001));
        let found = (0..8).find_map(|_| refetch.sweep(&db, 5003, &mut pending).unwrap());
        assert_eq!(found, Some(hash(0xa0, 5002)), "A5002 is queued without another network body");
    }

    // Past MAX_REORG_WAITS the lightest waiting target is the one forgotten.
    #[test]
    fn reorg_waits_are_capped_by_dropping_the_lightest() {
        use crate::chain::index::{put_hidx, HeaderIndex};
        let tmp = tempfile::TempDir::new().unwrap();
        let db = Stores::open(tmp.path().to_str().unwrap()).unwrap();
        let target = |i: usize| -> Hash32 {
            let mut h = [0u8; 32];
            h[..8].copy_from_slice(&(i as u64).to_le_bytes());
            h[31] = 1;
            h
        };
        let mut refetch = BodyRefetch::default();
        for i in 0..=MAX_REORG_WAITS {
            let hash = target(i);
            let chainwork = if i == 7 { 1 } else { 100 + i as u128 };
            put_hidx(&db, &HeaderIndex { hash, parent: [0u8; 32], height: 1, chainwork, bits: 0, time: 0 }).unwrap();
            refetch.wait(&db, hash, [0xbbu8; 32]);
        }
        assert_eq!(refetch.waits.len(), MAX_REORG_WAITS);
        assert!(!refetch.waits.contains_key(&target(7)), "the lightest is dropped");
        assert!(refetch.waits.contains_key(&target(0)) && refetch.waits.contains_key(&target(MAX_REORG_WAITS)));
    }

    // A dropped body at the local chainwork stays wanted, and requestable, while the reorg it
    // failed is heavier; any other block at that chainwork is not requested (the fetch policy).
    #[test]
    fn a_dropped_body_below_the_tip_is_requested_while_its_reorg_is_heavier() {
        use crate::chain::index::{put_hidx, HeaderIndex};
        let tmp = tempfile::TempDir::new().unwrap();
        let db = Stores::open(tmp.path().to_str().unwrap()).unwrap();
        let hidx = |hash: Hash32, chainwork: u128| HeaderIndex {
            hash,
            parent: [0u8; 32],
            height: 1,
            chainwork,
            bits: 0,
            time: 0,
        };
        let (tip, dropped, target, other) = ([1u8; 32], [2u8; 32], [3u8; 32], [4u8; 32]);
        for (h, w) in [(tip, 100), (dropped, 100), (target, 200), (other, 100)] {
            put_hidx(&db, &hidx(h, w)).unwrap();
        }
        crate::state::db::set_tip(&db, &tip).unwrap();

        let mut refetch = BodyRefetch::default();
        let (mut bad_providers, mut want) = (HashMap::new(), VecDeque::new());
        refetch.on_dropped(&db, dropped, target, &mut bad_providers, &mut want);
        want.push_back(other);
        assert!(worth_requesting(&db, &dropped, 100, &refetch).unwrap());
        assert!(!worth_requesting(&db, &other, 100, &refetch).unwrap());

        compact_want_queue(&db, &HashMap::new(), &HashMap::new(), &mut want, &refetch).unwrap();
        assert_eq!(want, VecDeque::from([dropped]), "the dropped body stays queued, the other goes");

        refetch.waits.clear();
        assert!(!worth_requesting(&db, &dropped, 100, &refetch).unwrap(), "only while it is dropped");
    }
}

#[cfg(test)]
mod block_request_failure_tests {
    use super::*;

    // A failed GetBlock stamps the peer and drops it as provider only when another block server
    // is connected; the block is queued again and the peer scored down either way.
    #[test]
    fn a_sole_block_server_is_not_stamped_for_a_failed_request() {
        let (h, peer) = ([9u8; 32], PeerId::random());
        for (servers, stamped) in [(0usize, false), (1, false), (2, true)] {
            let (mut score, mut quar, mut bad) = (HashMap::new(), HashMap::new(), HashMap::new());
            let mut providers = HashMap::from([(h, peer)]);
            let mut want = VecDeque::new();
            let got = note_block_request_failure(h, peer, OutboundFault::Peer, servers, &mut score, &mut quar, &mut bad, &mut providers, &mut want);
            assert_eq!(got, stamped, "servers={servers}");
            assert_eq!(is_bad(&bad, &h, &peer), stamped, "servers={servers}");
            assert_eq!(providers.contains_key(&h), !stamped, "servers={servers}");
            assert_eq!(want, VecDeque::from([h]), "requeued, servers={servers}");
            assert_eq!(score.get(&peer), Some(&SCORE_BAD_TIMEOUT), "scored, servers={servers}");
        }
    }

    // With 8 block requests in flight to one peer over its 4 streams, our own handler refuses the
    // extra ones, and the failure arm must not score and stamp the honest peer for 120 s for
    // that. A local refusal is our limit: requeued, nobody scored, stamped or dropped as
    // provider, whatever the server count; and a peer at MAX_BLOCK_REQUESTS_PER_PEER or just
    // refused is not picked while another peer can be.
    #[test]
    fn a_local_stream_refusal_blames_nobody_and_a_full_peer_is_not_asked() {
        use std::io::{Error, ErrorKind};
        let refused = request_response::OutboundFailure::Io(Error::new(ErrorKind::Other, "max sub-streams reached"));
        assert!(is_local_stream_refusal(&refused));
        assert!(!is_local_stream_refusal(&request_response::OutboundFailure::Timeout));
        assert!(!is_local_stream_refusal(&request_response::OutboundFailure::Io(Error::new(ErrorKind::UnexpectedEof, "eof"))));

        let (h, peer, other) = ([8u8; 32], PeerId::random(), PeerId::random());
        let (mut score, mut quar, mut bad) = (HashMap::new(), HashMap::new(), HashMap::new());
        let mut providers = HashMap::from([(h, peer)]);
        let mut want = VecDeque::new();
        let stamped = note_block_request_failure(h, peer, OutboundFault::OurStreamLimit, 5, &mut score, &mut quar, &mut bad, &mut providers, &mut want);
        assert!(!stamped && bad.is_empty() && score.is_empty(), "nobody blamed");
        assert_eq!((providers.get(&h), want), (Some(&peer), VecDeque::from([h])), "kept as provider, requeued");

        let mut inflight: HashMap<Hash32, ((), Instant, PeerId)> = HashMap::new();
        let none = HashMap::new();
        let pick = |inflight: &HashMap<Hash32, ((), Instant, PeerId)>, cands: &[PeerId]| {
            pick_block_peer(cands, |p| has_stream_room(inflight, p), &h, &none, &BodyRefetch::default())
        };
        assert_eq!(pick(&inflight, &[peer, other]), Some(other), "just refused: passed over");
        STREAMS_FULL_PEERS.lock().unwrap().remove(&peer);
        assert_eq!(pick(&inflight, &[peer, other]), Some(peer));
        for i in 0..MAX_BLOCK_REQUESTS_PER_PEER as u8 {
            inflight.insert([i; 32], ((), Instant::now(), peer));
        }
        assert_eq!(pick(&inflight, &[peer, other]), Some(other), "at the per-peer cap: the other peer");
        assert_eq!(pick(&inflight, &[peer]), None, "and none while it is the only one");
    }

    // Our GetBlock in flight on a second inbound connection the poll tick shed fails as
    // ConnectionClosed. It blames nobody (no -1, no 120 s stamp, the sync peer stays), and the peer
    // is not passed over (it keeps its other connection). The
    // paired path: a ConnectionClosed on a connection we did not shed, and a timeout on one we did,
    // are still the peer's. `tests/p2p_live_inbound_saturation.rs` drives the real shed.
    #[test]
    fn a_connection_we_shed_blames_nobody_and_the_peers_own_failures_still_do() {
        use request_response::OutboundFailure;
        assert_eq!(outbound_fault(&OutboundFailure::ConnectionClosed, true), OutboundFault::OurShed);
        assert_eq!(outbound_fault(&OutboundFailure::ConnectionClosed, false), OutboundFault::Peer);
        assert_eq!(outbound_fault(&OutboundFailure::Timeout, true), OutboundFault::Peer);
        let refused = OutboundFailure::Io(std::io::Error::other("max sub-streams reached"));
        assert_eq!(outbound_fault(&refused, false), OutboundFault::OurStreamLimit);

        let (h, peer) = ([7u8; 32], PeerId::random());
        let (mut score, mut quar, mut bad) = (HashMap::new(), HashMap::new(), HashMap::new());
        let mut providers = HashMap::from([(h, peer)]);
        let mut want = VecDeque::new();
        let stamped = note_block_request_failure(h, peer, OutboundFault::OurShed, 5, &mut score, &mut quar, &mut bad, &mut providers, &mut want);
        assert!(!stamped && bad.is_empty() && score.is_empty(), "nobody blamed");
        assert_eq!((providers.get(&h), want), (Some(&peer), VecDeque::from([h])), "kept as provider, requeued");
        let none: HashMap<Hash32, ((), Instant, PeerId)> = HashMap::new();
        assert!(has_stream_room(&none, &peer), "passed over as if its streams were full");
    }

    // An answer the node drops (from a peer quarantined or banned since we asked, or not a block
    // or an error) must not leave its GetBlock in `inflight` until the 60 s sweep. The slot is
    // freed and the block requeued at once; a newer request for the same block keeps its slot, and
    // an answer to a request that was not a GetBlock changes nothing.
    #[test]
    fn an_unhandled_answer_frees_its_block_request_slot() {
        let (h, peer) = ([4u8; 32], PeerId::random());
        let mut rid_to_hash = HashMap::from([(1u64, h)]);
        let mut inflight = HashMap::from([(h, (1u64, Instant::now(), peer))]);
        let mut want = VecDeque::new();
        assert_eq!(release_unanswered_block_request(&1, &mut rid_to_hash, &mut inflight, &mut want), Some(h));
        assert!(inflight.is_empty() && rid_to_hash.is_empty(), "the slot is free");
        assert_eq!(want, VecDeque::from([h]), "requeued");

        let mut rid_to_hash = HashMap::from([(2u64, h), (3u64, h)]);
        let mut inflight = HashMap::from([(h, (3u64, Instant::now(), peer))]);
        assert_eq!(release_unanswered_block_request(&2, &mut rid_to_hash, &mut inflight, &mut want), Some(h));
        assert!(inflight.contains_key(&h), "the newer request for the block keeps its slot");
        assert_eq!(release_unanswered_block_request(&9, &mut rid_to_hash, &mut inflight, &mut want), None);
    }

    // is_local_stream_refusal matches the refusal text of libp2p-request-response 0.30.0
    // (handler.rs:208). A bump of that crate must re-read it (docs/behaviour.md "Dependency
    // internals the code relies on").
    #[test]
    fn the_stream_refusal_text_is_pinned_to_the_locked_request_response_version() {
        let lock = std::fs::read_to_string(concat!(env!("CARGO_MANIFEST_DIR"), "/Cargo.lock")).unwrap();
        let entry = lock.split("[[package]]").find(|p| p.contains("name = \"libp2p-request-response\"")).unwrap();
        assert!(
            entry.contains("version = \"0.30.0\""),
            "libp2p-request-response moved: re-read its handler.rs refusal text for is_local_stream_refusal, then update this check"
        );
    }

    // "Unknown block" costs no score: pump_blocks asks any connected peer, so at -3 an answer an
    // honest peer asked for ten bodies of a branch it does not hold would be quarantined. The
    // recorded provider is no exception: it may have served a body it had not validated and
    // dropped it since (chain::body_fault). Every peer that answers is stamped and
    // the next request goes elsewhere; nobody is scored.
    #[test]
    fn an_unknown_block_answer_costs_no_score_and_the_retry_goes_elsewhere() {
        let (provider, asked, other) = (PeerId::random(), PeerId::random(), PeerId::random());
        let (mut bad, mut providers, mut want) = (HashMap::new(), HashMap::new(), VecDeque::new());
        let refetch = BodyRefetch::default();
        let all = |_: &PeerId| true;
        for i in 0..10u8 {
            let h = [i; 32];
            providers.insert(h, provider);
            note_unknown_block_answer(h, asked, &mut bad, &mut providers, &mut want);
            assert!(is_bad(&bad, &h, &asked), "stamped for the block");
            assert_eq!(providers.get(&h), Some(&provider), "the provider stays the provider");
        }
        assert_eq!(want, (0..10u8).map(|i| [i; 32]).collect::<VecDeque<_>>(), "each block requeued");

        // The provider served the body (the GetBlock response records it), its own apply then
        // blamed the body and dropped it, and our retry reaches it: it answers "unknown block".
        let h = [0u8; 32];
        note_unknown_block_answer(h, provider, &mut bad, &mut providers, &mut want);
        assert!(is_bad(&bad, &h, &provider) && !providers.contains_key(&h), "stamped and dropped as provider");
        assert_eq!(
            pick_block_peer(&[provider, asked, other], all, &h, &bad, &refetch),
            Some(other),
            "the retry goes to a peer that has not answered unknown"
        );
    }

    #[test]
    fn block_servers_leave_out_banned_quarantined_and_header_only_peers() {
        let (a, b, c, d) = (PeerId::random(), PeerId::random(), PeerId::random(), PeerId::random());
        let connected = HashSet::from([a, b, c, d]);
        let bans = HashMap::from([(b, Instant::now())]);
        let quar = HashMap::from([(c, Instant::now())]);
        assert_eq!(block_server_count(&connected, &bans, &quar), 2);
        note_header_only(&d);
        assert_eq!(block_server_count(&connected, &bans, &quar), 1);
    }
}

#[cfg(test)]
mod logging_tests {
    use super::*;

    #[test]
    fn log_due_fires_at_powers_of_two_with_the_running_total() {
        let mut n = 0u64;
        let fired: Vec<u64> = (0..9).filter_map(|_| log_due(&mut n)).collect();
        assert_eq!(fired, vec![1, 2, 4, 8]);
        assert_eq!(n, 9);
    }

    #[test]
    fn a_close_line_names_our_reason_first_then_the_transport_cause() {
        let p = PeerId::random();
        let reset = || ConnectionError::IO(std::io::Error::new(std::io::ErrorKind::ConnectionReset, "reset by peer"));
        let (k, l) = close_line(&p, true, 0, Some("idle"), None);
        assert_eq!(k, "by us: idle");
        assert!(l.contains(&p.to_string()) && l.contains("dialed by us") && l.contains("0 left"), "{l}");
        let (k, l) = close_line(&p, false, 1, Some("quarantined"), Some(&reset()));
        assert_eq!(k, "by us: quarantined");
        assert!(l.contains("inbound") && l.contains("transport: io ConnectionReset: reset by peer"), "{l}");
        let (k, l) = close_line(&p, false, 0, None, Some(&reset()));
        assert_eq!(k, "io ConnectionReset");
        assert!(l.ends_with("io ConnectionReset: reset by peer"), "{l}");
        assert_eq!(close_line(&p, true, 0, None, Some(&ConnectionError::KeepAliveTimeout)).0, "keep-alive timeout");
        assert_eq!(close_line(&p, true, 0, None, None).0, "closed by the remote or idle");
    }

    #[test]
    fn quarantine_and_ban_report_only_the_transition() {
        let p = PeerId::random();
        let (mut scores, mut quar) = (HashMap::new(), HashMap::new());
        assert!(!bump_score(&mut scores, &mut quar, p, QUAR_SCORE_THRESHOLD + 1));
        assert!(bump_score(&mut scores, &mut quar, p, -1), "crossing the threshold enters quarantine");
        assert!(!bump_score(&mut scores, &mut quar, p, QUAR_SCORE_THRESHOLD), "already quarantined");
        assert!(is_quarantined(&quar, &p));
        quar.insert(p, Instant::now() - Duration::from_secs(QUAR_SECS + 1));
        // Entering quarantine reset the score to zero, so a new one takes a full threshold again.
        assert!(!bump_score(&mut scores, &mut quar, p, -1), "the reset leaves one penalty short of it");
        assert!(
            bump_score(&mut scores, &mut quar, p, QUAR_SCORE_THRESHOLD),
            "a new quarantine after the last one expired"
        );

        let mut bans = HashMap::new();
        assert!(ban_peer(&mut bans, p, "test"));
        assert!(!ban_peer(&mut bans, p, "test"), "already banned");
        bans.insert(p, Instant::now() - Duration::from_secs(BAN_SECS + 1));
        assert!(ban_peer(&mut bans, p, "test"));
        assert!(is_banned(&bans, &p));
    }

    // A peer's Err text printed whole and raw would let one answer forge lines in the operator's
    // journal or fill a journal rate limit (500 lines a minute, say) on its own.
    #[test]
    fn a_peers_text_is_logged_on_one_line_escaped_and_capped() {
        let forged = format!("x\n[node] clean shutdown at height 1\u{1b}[2J{}", "y".repeat(1 << 20));
        let line = peer_text(&forged);
        assert!(line.len() < 300, "{} bytes logged", line.len());
        assert!(!line.chars().any(char::is_control), "a raw control character reached the line: {line:?}");
        assert!(line.contains(&forged.len().to_string()), "the length is not named: {line}");
        assert!(line.contains("clean shutdown"), "the start of the text is not kept: {line}");
        // A short honest text reads as itself, and a cut never splits a character.
        assert!(peer_text("unknown block").contains("\"unknown block\""));
        assert!(peer_text(&"\u{e9}".repeat(150)).len() < 300);
        // Escaping cannot widen the line past the cap either.
        let escapes = peer_text(&"\u{1b}".repeat(1_000));
        assert!(escapes.len() < 300 && !escapes.chars().any(char::is_control), "{escapes}");
    }

    #[test]
    fn the_fatal_line_carries_the_whole_error_chain() {
        let e = anyhow::anyhow!("sled: io error").context("store block body").context("handle block response");
        let line = p2p_fatal_line(&e);
        assert!(line.contains("handle block response") && line.contains("store block body") && line.contains("sled: io error"), "{line}");
    }
}

#[cfg(test)]
mod header_serving_tests {
    use super::*;

    // A GetHeadersByLocator anchored at genesis that read and decoded every block body above the
    // anchor to answer `max` headers, on the one serve permit, would let one peer hold the node's
    // serving with it. The walk reads header indexes only, and the answered headers come
    // from `hdr_raw`, decoded from a body only the first time; they equal the bodies' headers, and
    // bytes in `hdr_raw` that do not hash to the block are not served.
    fn codec() -> crate::codec::ConsensusBincode {
        crate::codec::consensus_bincode()
    }

    /// A 300-block chain with header indexes and bodies, the tip at its top: the hashes and the
    /// encoded headers, by height.
    fn toy_chain(db: &Stores) -> (Vec<Hash32>, Vec<Vec<u8>>) {
        use crate::chain::index::put_hidx;
        let mut hashes = Vec::new();
        let mut headers = Vec::new();
        let mut prev = [0u8; 32];
        for height in 0..300u64 {
            let header = BlockHeader { version: 1, prev, merkle: [0u8; 32], time: height, bits: 0, nonce: 0 };
            let hash = header_hash(&header);
            put_hidx(db, &HeaderIndex { hash, parent: prev, height, chainwork: height as u128 + 1, bits: 0, time: height }).unwrap();
            db.blocks.insert(k_block(&hash), codec().serialize(&Block { header: header.clone(), txs: vec![] }).unwrap()).unwrap();
            hashes.push(hash);
            headers.push(codec().serialize(&header).unwrap());
            prev = hash;
        }
        crate::state::db::set_tip(db, &hashes[299]).unwrap();
        (hashes, headers)
    }

    fn answer(db: &Stores, req: SyncRequest) -> Vec<Vec<u8>> {
        match handle_request_blocking(db, req, false).unwrap() {
            SyncResponse::Headers { headers } => headers.iter().map(|h| codec().serialize(h).unwrap()).collect(),
            _ => panic!("not a headers answer"),
        }
    }

    #[test]
    fn a_locator_answer_reads_at_most_max_bodies_and_serves_headers_from_hdr_raw() {
        let tmp = tempfile::TempDir::new().unwrap();
        let db = Stores::open(tmp.path().to_str().unwrap()).unwrap();
        let (hashes, headers) = toy_chain(&db);
        let answer = |req: SyncRequest| answer(&db, req);
        let locator = || SyncRequest::GetHeadersByLocator { locator: vec![hashes[0]], max: 50 };

        assert_eq!(answer(locator()), headers[1..51], "the 50 headers above the anchor");
        assert_eq!(db.hdr_raw.len(), 50, "only the answered headers were read from bodies");
        for h in &hashes[1..51] {
            db.blocks.remove(k_block(h)).unwrap();
        }
        assert_eq!(answer(locator()), headers[1..51], "the same answer from hdr_raw alone");
        db.hdr_raw.insert(crate::state::db::k_hdr_raw(&hashes[1]), headers[2].clone()).unwrap();
        assert_eq!(answer(locator()), headers[1..1], "bytes that hash to another block are not served");

        let by_height = answer(SyncRequest::GetHeaders { from_height: 280, max: 1024 });
        assert_eq!(by_height, headers[280..300], "GetHeaders answers the same headers");
    }

    // Anchored by walking the header index down from the tip, a locator from a node syncing from
    // genesis would cost its server a walk of the whole chain for every 1,024 headers. With a fresh
    // height index the anchor comes from the locator hashes' heights; while the index is stale
    // (after a block, during its rebuild) the walk answers, and both answer the same headers.
    #[test]
    fn a_fresh_height_index_anchors_a_locator_without_the_walk() {
        let tmp = tempfile::TempDir::new().unwrap();
        let db = Stores::open(tmp.path().to_str().unwrap()).unwrap();
        let (hashes, headers) = toy_chain(&db);
        let off_chain = [0xEEu8; 32];
        let cases: Vec<(Vec<Hash32>, u64)> = vec![
            (vec![hashes[0]], 50),
            (vec![hashes[250], hashes[120], hashes[0]], 1024),
            (vec![hashes[10], hashes[200], off_chain], 50),
            (vec![off_chain, [0u8; 32]], 5),
            (vec![hashes[299]], 50),
            (vec![off_chain], 50),
        ];
        let ask = |locator: &Vec<Hash32>, max| answer(&db, SyncRequest::GetHeadersByLocator { locator: locator.clone(), max });
        let walked: Vec<_> = cases.iter().map(|(l, max)| ask(l, *max)).collect();
        assert_eq!(walked[1], headers[251..300], "the highest locator hash on the chain anchors");
        assert_eq!(walked[3], headers[1..6], "the zero hash anchors at genesis");
        assert!(walked[4].is_empty() && walked[5].is_empty());

        while !crate::state::tx_scan::reconcile_tick(&db, 1_000).unwrap() {}
        assert!(crate::state::tx_scan::idx_fresh(&db));
        for ((locator, max), want) in cases.iter().zip(&walked) {
            assert_eq!(&ask(locator, *max), want, "locator {:?}", locator.iter().map(hex32).collect::<Vec<_>>());
        }

        // The walk reads every header index above the anchor and fails on a missing one; the
        // indexed answer does not read them.
        db.hdr.remove(crate::state::db::k_hdr(&hashes[150])).unwrap();
        assert_eq!(ask(&cases[0].0, 50), headers[1..51]);
        assert_eq!(ask(&vec![hashes[100]], 1024), headers[101..300]);

        // A height entry rewritten to another branch mid-answer (a reorg) ends the answer there.
        let fork = BlockHeader { version: 1, prev: hashes[100], merkle: [1u8; 32], time: 160, bits: 0, nonce: 0 };
        let fork_hash = header_hash(&fork);
        db.blocks.insert(k_block(&fork_hash), codec().serialize(&Block { header: fork, txs: vec![] }).unwrap()).unwrap();
        db.idx.insert(crate::state::tx_index::k_hh(160), &fork_hash[..]).unwrap();
        assert_eq!(ask(&vec![hashes[120]], 1024), headers[121..160]);
    }

    // With the index checked fresh at tip A and its height entries read after, a reorg the
    // reconciler indexed in between would give a coherent answer from another chain, or no anchor
    // where A's walk has one. Freshness is checked again
    // after the reads, and a moved tip falls back to the walk from the captured tip.
    #[test]
    fn a_reorg_indexed_during_a_locator_answer_falls_back_to_the_walk_of_the_captured_tip() {
        use crate::chain::index::put_hidx;
        use crate::state::db::set_tip;
        use crate::state::tx_index::get_block_hash_by_height;
        use crate::state::tx_scan::{fresh_tip, reconcile_tick};
        let tmp = tempfile::TempDir::new().unwrap();
        let db = Stores::open(tmp.path().to_str().unwrap()).unwrap();
        let (hashes, _) = toy_chain(&db);
        let tip_a = hashes[299];
        let move_tip = |to: &Hash32| {
            set_tip(&db, to).unwrap();
            while !reconcile_tick(&db, 1_000).unwrap() {}
        };
        move_tip(&tip_a);

        // B: 120 blocks on A's block 200, longer than A, stored and indexed.
        let mut tip_b = hashes[200];
        for height in 201..=320u64 {
            let header = BlockHeader { version: 1, prev: tip_b, merkle: [2u8; 32], time: height, bits: 0, nonce: 0 };
            let hash = header_hash(&header);
            put_hidx(&db, &HeaderIndex { hash, parent: tip_b, height, chainwork: height as u128 + 1_000, bits: 0, time: height }).unwrap();
            db.blocks.insert(k_block(&hash), codec().serialize(&Block { header, txs: vec![] }).unwrap()).unwrap();
            tip_b = hash;
        }

        for (locator, what) in [(vec![hashes[150]], "a B suffix above an A anchor"), (vec![hashes[250]], "no anchor")] {
            let set: HashSet<Hash32> = locator.iter().copied().collect();
            let walked = locator_anchor_by_walk(&db, &tip_a, &set, 1024).unwrap();
            assert!(walked.as_ref().is_some_and(|(_, _, above)| above.back() == Some(&tip_a)));

            // The node reorgs to B and the reconciler indexes it after the first height read.
            let mut reorged = false;
            let answered = locator_anchor(&db, &tip_a, &set, 1024, |height| {
                if !reorged {
                    reorged = true;
                    move_tip(&tip_b);
                }
                get_block_hash_by_height(&db, height)
            })
            .unwrap();
            assert!(reorged && fresh_tip(&db) == Some(tip_b));
            assert_eq!(answered, walked, "{what}: the answer is A's walk");
            move_tip(&tip_a);
        }
    }
}

#[cfg(test)]
mod peer_state_tests {
    use super::*;

    #[test]
    fn a_dial_backoff_grows_across_its_own_expiry() {
        let mut backoff: HashMap<Multiaddr, (u32, Instant)> = HashMap::new();
        let a: Multiaddr = "/ip4/45.33.1.1/tcp/17999".parse().unwrap();

        note_addr_dial_failure(&mut backoff, &a);
        assert_eq!(backoff[&a].0, 1);
        // The first backoff has run out; the prune on the next poll tick must keep the count.
        backoff.get_mut(&a).unwrap().1 = Instant::now();
        prune_addr_backoff(&mut backoff);
        assert!(!addr_is_backed_off(&backoff, &a), "an expired backoff no longer blocks a dial");

        note_addr_dial_failure(&mut backoff, &a);
        let (fails, until) = backoff[&a];
        assert_eq!(fails, 2, "the second failure in a row escalates");
        assert!(until > Instant::now() + Duration::from_secs(addr_backoff_secs(1)));

        // Honest path: a connection clears it, and the next failure starts at the first step.
        note_addr_dial_success(&mut backoff, &a);
        note_addr_dial_failure(&mut backoff, &a);
        assert_eq!(backoff[&a].0, 1);
    }

    // The shedding of second inbound connections takes its peers from the cap evictor's order;
    // this pins that order's protections. A peer younger than
    // PROTECT_NEW_PEER_SECS and a peer we dialed are never in it, but a dialed peer that is banned or
    // quarantined is; the rest come worst first (lower score, then lower work, then older).
    #[test]
    fn the_cap_eviction_order_keeps_young_and_dialed_peers_out() {
        let [young, dialed, dialed_banned, dialed_quarantined, low, high, older] = [(); 7].map(|_| PeerId::random());
        let old = Instant::now() - Duration::from_secs(PROTECT_NEW_PEER_SECS + 5);
        let connected = HashSet::from([young, dialed, dialed_banned, dialed_quarantined, low, high, older]);
        let mut since: HashMap<PeerId, Instant> = connected.iter().map(|p| (*p, old)).collect();
        since.insert(young, Instant::now());
        since.insert(older, old - Duration::from_secs(60));
        let scores = HashMap::from([(low, -5), (high, 10), (older, 10), (dialed_banned, 50), (dialed_quarantined, 50)]);
        let outbound = HashSet::from([dialed, dialed_banned, dialed_quarantined]);
        let bans = HashMap::from([(dialed_banned, Instant::now())]);
        let quarantine = HashMap::from([(dialed_quarantined, Instant::now())]);
        let order: Vec<PeerId> = cap_eviction_order(&connected, &since, &scores, &HashMap::new(), &outbound, &bans, &quarantine)
            .into_iter()
            .map(|(p, ..)| p)
            .collect();
        assert!(!order.contains(&young), "a peer younger than PROTECT_NEW_PEER_SECS can be shed");
        assert!(!order.contains(&dialed), "a peer we dialed can be shed");
        // The paired path: the misbehaving dialed peers lose their protection, and the rest are ordered.
        assert_eq!(order.len(), 5, "{order:?}");
        assert_eq!(order[0], low, "the lowest score first");
        assert_eq!(&order[1..3], &[older, high], "at one score, the older first");
        assert!(order[3..].contains(&dialed_banned) && order[3..].contains(&dialed_quarantined));
    }

    #[test]
    fn inbound_peers_do_not_stop_the_bootnode_redial() {
        let (max, cold, warm) = (32, true, false);
        // A mainnet node as measured: 16 connected, 7 of them dialed by us.
        assert!(bootnode_redial_due(warm, 16, 7, max), "inbound peers must not count toward the floor");
        // Honest paths, as before: enough dialed peers, or few connections of any kind.
        assert!(!bootnode_redial_due(warm, 16, MIN_OUTBOUND_PEERS, max));
        assert!(bootnode_redial_due(warm, MIN_OUTBOUND_PEERS - 1, MIN_OUTBOUND_PEERS - 1, max));
        assert!(bootnode_redial_due(cold, COLD_START_MIN_PEERS - 1, COLD_START_MIN_PEERS - 1, max));
        assert!(!bootnode_redial_due(cold, COLD_START_MIN_PEERS, 0, max));
        // At the cap the floor does not dial, or the cap evictor would shed inbound peers for it.
        assert!(!bootnode_redial_due(warm, max, 7, max));
    }

    #[test]
    fn a_score_is_bounded_forgets_and_starts_again_after_quarantine() {
        let mut scores: HashMap<PeerId, i32> = HashMap::new();
        let mut quar: HashMap<PeerId, Instant> = HashMap::new();
        let (farmer, honest, offender) = (PeerId::random(), PeerId::random(), PeerId::random());

        // Forwarding headers buys no more than the ceiling, and the ceiling does not buy immunity.
        for _ in 0..10_000 {
            bump_score(&mut scores, &mut quar, farmer, 1);
        }
        assert_eq!(scores[&farmer], SCORE_MAX);
        for _ in 0..14 {
            assert!(!bump_score(&mut scores, &mut quar, farmer, SCORE_BAD_INVALID));
        }
        assert!(bump_score(&mut scores, &mut quar, farmer, SCORE_BAD_INVALID));

        // Quarantine resets the score: the next single penalty does not send the peer back.
        assert_eq!(scores.get(&farmer).copied().unwrap_or(0), 0);
        quar.clear();
        assert!(!bump_score(&mut scores, &mut quar, farmer, SCORE_BAD_INVALID));

        // Honest path: a peer whose block requests time out once a minute is never quarantined,
        // because its penalties decay as fast as they come.
        for _ in 0..600 {
            assert!(!bump_score(&mut scores, &mut quar, honest, SCORE_BAD_TIMEOUT));
            decay_scores(&mut scores);
        }
        assert!(!is_quarantined(&quar, &honest));

        // Decay: one short of the threshold, a peer recovers toward zero over minutes.
        bump_score(&mut scores, &mut quar, offender, QUAR_SCORE_THRESHOLD + 1);
        for _ in 0..7 {
            decay_scores(&mut scores);
        }
        assert!(scores[&offender] > QUAR_SCORE_THRESHOLD / 2, "{}", scores[&offender]);
    }

    fn addr_n(n: u16) -> Multiaddr {
        format!("/ip4/45.33.{}.{}/tcp/17999", n / 250 + 1, n % 250 + 1).parse().unwrap()
    }

    #[test]
    fn a_dial_timeout_reads_as_a_timeout_in_the_shape_the_swarm_reports_it() {
        use libp2p::core::transport::TransportError;
        use libp2p::swarm::DialError;

        // A node's journal line for a timed-out dial (address and peer id replaced).
        const LIVE: &str = "Transport([(/ip4/203.0.113.9/tcp/17999/p2p/PEER, Other(Custom { kind: Other, \
            error: Left(Left(Os { code: 110, kind: TimedOut, message: \"Connection timed out\" })) }))])";
        assert!(dial_error_text_is_timeout(LIVE));

        let a = addr_n(1);
        let dial = |os: i32| {
            DialError::Transport(vec![(
                a.clone(),
                TransportError::Other(std::io::Error::other(std::io::Error::from_raw_os_error(os))),
            )])
        };
        assert_eq!(timed_out_dial_addrs(&dial(110)), vec![a.clone()], "ETIMEDOUT");
        assert!(timed_out_dial_addrs(&dial(111)).is_empty(), "ECONNREFUSED is not a timeout");
        assert!(timed_out_dial_addrs(&DialError::Aborted).is_empty());
    }

    // The transport ends a dial at its handshake deadline
    // (`admission::HANDSHAKE_TIMEOUT`), before the kernel's connect timeout; the boxed transport
    // reports it as libp2p-core's TransportTimeoutError::Timeout inside io::Error::other. The book's
    // eviction of dead addresses counts it as a timeout, or no dead address would leave it again.
    #[test]
    fn a_dial_past_our_handshake_deadline_reads_as_a_timeout() {
        use libp2p::core::transport::{timeout::TransportTimeoutError, TransportError};
        use libp2p::swarm::DialError;
        let a = addr_n(1);
        let deadline = TransportTimeoutError::<std::io::Error>::Timeout;
        let dial = DialError::Transport(vec![(a.clone(), TransportError::Other(std::io::Error::other(deadline)))]);
        assert_eq!(timed_out_dial_addrs(&dial), vec![a.clone()], "{dial:?}");
        // Another error inside the same wrapper is not a timeout.
        let refused = TransportTimeoutError::Other(std::io::Error::from_raw_os_error(111));
        let dial = DialError::Transport(vec![(a, TransportError::Other(std::io::Error::other(refused)))]);
        assert!(timed_out_dial_addrs(&dial).is_empty(), "{dial:?}");
    }

    // A ban of a peer outside `connected` (one that reconnected while banned) pruned after BAN_SECS
    // would have its requests and gossip served over that connection.
    // The ban's entry is kept while the peer holds any connection, and the poll tick closes a banned
    // peer's connections.
    #[test]
    fn a_ban_is_kept_while_the_peer_holds_a_connection_and_its_connections_are_closed() {
        let (ghost, gone, counted) = (PeerId::random(), PeerId::random(), PeerId::random());
        let lapsed = Instant::now() - Duration::from_secs(BAN_SECS + 1);
        let mut bans = HashMap::from([(ghost, lapsed), (gone, lapsed), (counted, Instant::now())]);
        let open = HashSet::from([ghost, counted]);
        prune_peer_state(
            &mut HashMap::new(),
            &mut bans,
            &mut HashMap::new(),
            &mut HashMap::new(),
            &HashSet::from([counted]),
            &open,
        );
        assert!(bans.contains_key(&ghost), "a ban was pruned while its peer held a connection");
        assert!(!bans.contains_key(&gone), "a lapsed ban of a peer with no connection is kept");
        // The poll tick closes the banned peer's connections, and not a peer we are closing already.
        let honest = PeerId::random();
        let open = HashSet::from([counted, honest]);
        assert_eq!(banned_with_connections(&open, &bans, &HashMap::new()), vec![counted]);
        assert!(banned_with_connections(&open, &bans, &HashMap::from([(counted, "banned")])).is_empty());
    }

    // A dial our own connection limits refused (the peer holds its connections already, or we are at
    // the cap) blames nobody: no dial failure, no backoff, no address forgotten.
    #[test]
    fn a_dial_our_limits_refused_blames_nobody() {
        use libp2p::swarm::{ConnectionDenied, DialError};
        let ours = DialError::Denied { cause: ConnectionDenied::new(std::io::Error::other("limit")) };
        assert!(dial_refused_by_us(&ours));
        assert!(!dial_refused_by_us(&DialError::Aborted));
        let wrong = DialError::WrongPeerId { obtained: PeerId::random(), address: addr_n(1) };
        assert!(!dial_refused_by_us(&wrong));
        // The refused dial's pending entry must not stay until the peer's next connection event. It
        // is dropped, and only that peer's.
        let (refused, other) = (PeerId::random(), PeerId::random());
        let mut pending: HashMap<PeerId, HashSet<Multiaddr>> = HashMap::new();
        note_pending_dial(&mut pending, refused, addr_n(1));
        note_pending_dial(&mut pending, other, addr_n(2));
        assert_eq!(forget_refused_dial(&mut pending, Some(refused)), vec![addr_n(1)]);
        assert!(!pending.contains_key(&refused) && pending.contains_key(&other));
        assert!(forget_refused_dial(&mut pending, None).is_empty());
    }

    #[test]
    fn an_address_leaves_the_book_after_three_timeouts_in_a_row_and_only_that_address() {
        let mut book: HashMap<PeerId, HashSet<Multiaddr>> = HashMap::new();
        for n in 0..40u16 {
            book.insert(PeerId::random(), HashSet::from([addr_n(100 + n)]));
        }
        let honest = PeerId::random();
        let (dead, live) = (addr_n(1), addr_n(2));
        book.insert(honest, HashSet::from([dead.clone().with(libp2p::multiaddr::Protocol::P2p(honest)), live.clone()]));
        let mut counts = HashMap::new();
        let none = HashSet::new();

        // Honest path: a connection between timeouts starts the count again.
        assert!(!note_addr_timeout(&mut book, &mut counts, honest, &dead, &none, true));
        assert!(!note_addr_timeout(&mut book, &mut counts, honest, &dead, &none, true));
        clear_addr_timeouts(&mut counts, &dead);
        assert!(!note_addr_timeout(&mut book, &mut counts, honest, &dead, &none, true));
        assert!(!note_addr_timeout(&mut book, &mut counts, honest, &dead, &none, true));
        assert_eq!(book[&honest].len(), 2);
        // Nothing counts while this node holds no connection.
        assert!(!note_addr_timeout(&mut book, &mut counts, honest, &dead, &none, false));
        assert_eq!(book[&honest].len(), 2);

        assert!(note_addr_timeout(&mut book, &mut counts, honest, &dead, &none, true));
        assert_eq!(book[&honest], HashSet::from([live.clone()]), "only the dead address goes");

        // A configured bootnode is never evicted.
        let boot = PeerId::random();
        book.insert(boot, HashSet::from([addr_n(3)]));
        let boots = HashSet::from([boot]);
        for _ in 0..5 {
            assert!(!note_addr_timeout(&mut book, &mut counts, boot, &addr_n(3), &boots, true));
        }
        assert!(book.contains_key(&boot));

        // Timeouts do not take the book below MIN_KNOWN_PEERS_KEPT peers.
        let mut small: HashMap<PeerId, HashSet<Multiaddr>> = HashMap::new();
        let peers: Vec<PeerId> = (0..MIN_KNOWN_PEERS_KEPT).map(|_| PeerId::random()).collect();
        for (i, p) in peers.iter().enumerate() {
            small.insert(*p, HashSet::from([addr_n(300 + i as u16)]));
        }
        for _ in 0..ADDR_TIMEOUTS_TO_EVICT {
            note_addr_timeout(&mut small, &mut counts, peers[0], &addr_n(300), &none, true);
        }
        assert_eq!(small.len(), MIN_KNOWN_PEERS_KEPT);
    }

    // Anyone can advertise an address carrying an honest peer's id. A dial to it that meets
    // another identity or a closed port says nothing about the honest peer's other addresses.
    #[test]
    fn a_failed_dial_forgets_only_the_address_it_used() {
        use libp2p::core::transport::TransportError;
        use libp2p::multiaddr::Protocol;
        use libp2p::swarm::DialError;

        let honest = PeerId::random();
        let verified = addr_n(1).with(Protocol::P2p(honest));
        let planted = addr_n(2).with(Protocol::P2p(honest));
        let book_with_both = || HashMap::from([(honest, HashSet::from([verified.clone(), planted.clone()]))]);
        let os_error = |a: &Multiaddr, code: i32| {
            DialError::Transport(vec![(
                a.clone(),
                TransportError::Other(std::io::Error::other(std::io::Error::from_raw_os_error(code))),
            )])
        };

        let mut book = book_with_both();
        let wrong = DialError::WrongPeerId { obtained: PeerId::random(), address: planted.clone() };
        assert_eq!(forget_failed_dial_addrs(&mut book, &honest, &wrong), vec![(planted.clone(), "wrong-peer-id")]);
        assert_eq!(book[&honest], HashSet::from([verified.clone()]), "another identity at a planted address");

        let mut book = book_with_both();
        assert_eq!(forget_failed_dial_addrs(&mut book, &honest, &os_error(&planted, 111)), vec![(planted.clone(), "refused")]);
        assert_eq!(book[&honest], HashSet::from([verified.clone()]), "a planted closed port");

        // Honest path: the refusing address itself goes, matched without its /p2p suffix, and the
        // peer's entry with it when it was the last one.
        let mut book = HashMap::from([(honest, HashSet::from([addr_n(3)]))]);
        let removed = forget_failed_dial_addrs(&mut book, &honest, &os_error(&addr_n(3).with(Protocol::P2p(honest)), 111));
        assert_eq!(removed, vec![(addr_n(3), "refused")]);
        assert!(!book.contains_key(&honest));

        // A timeout is counted by note_addr_timeout, not forgotten here.
        assert!(forget_failed_dial_addrs(&mut book_with_both(), &honest, &os_error(&planted, 110)).is_empty());
    }

    #[test]
    fn one_peers_response_adds_at_most_sixteen_new_peers() {
        let me = PeerId::random();
        let known = PeerId::random();
        let mut book: HashMap<PeerId, HashSet<Multiaddr>> =
            HashMap::from([(known, HashSet::from([addr_n(1).with(libp2p::multiaddr::Protocol::P2p(known))]))]);
        let mut response: Vec<String> = (0..40u16)
            .map(|n| addr_n(10 + n).with(libp2p::multiaddr::Protocol::P2p(PeerId::random())).to_string())
            .collect();
        // An address for a peer already in the book is still taken past the cap.
        response.push(addr_n(2).with(libp2p::multiaddr::Protocol::P2p(known)).to_string());

        parse_peer_strings_into_known_addrs(&mut book, me, response);

        assert_eq!(book.len(), 1 + MAX_NEW_PEERS_PER_RESPONSE, "one response cannot fill the book");
        assert_eq!(book[&known].len(), 2);
    }

    // An IPv4 address in its IPv6-mapped form must not escape the IPv4 rules, or a peer could plant
    // loopback and private targets that fail at once (the transport's IPv6 sockets are v6-only,
    // libp2p-tcp 0.45.0 lib.rs:203-205) and are never evicted; 0.0.0.0/8 and 240.0.0.0/4 are
    // refused in both forms.
    #[test]
    fn mapped_and_reserved_ipv4_addresses_do_not_enter_the_book() {
        let me = PeerId::random();
        let stored = |a: &str| {
            let p = PeerId::random();
            let addr: Multiaddr = format!("{a}/tcp/17999/p2p/{p}").parse().unwrap();
            should_store_discovered_addr(me, p, &addr) && should_dial_discovered_addr(me, p, &addr)
        };
        for planted in [
            "/ip6/::ffff:127.0.0.1",
            "/ip6/::ffff:10.0.0.1",
            "/ip6/::ffff:192.168.1.1",
            "/ip6/::ffff:100.64.0.1",
            "/ip6/::ffff:0.1.2.3",
            "/ip4/0.1.2.3",
            "/ip4/240.0.0.1",
            "/ip4/255.255.255.254",
            "/ip6/::ffff:240.0.0.1",
        ] {
            assert!(!stored(planted), "{planted} entered the book");
        }
        // The paired honest path: public IPv4 addresses, an IPv6 address the IPv6 rules admit (the
        // documentation prefix 2001:db8::/32 is not among the ranges they refuse; the IPv4
        // documentation ranges are, so the IPv4 examples are public ones), and a mapped public
        // IPv4, which the IPv4 rules admit.
        for public in ["/ip4/8.8.8.8", "/ip4/1.0.0.1", "/ip4/223.255.255.1", "/ip6/2001:db8::2", "/ip6/::ffff:8.8.8.8"] {
            assert!(stored(public), "{public} was refused");
        }
    }

    #[test]
    fn dial_state_keeps_what_a_cooldown_reads_and_drops_the_rest() {
        let past = Instant::now()
            .checked_sub(Duration::from_secs(61))
            .expect("the monotonic clock is over a minute old");
        let (fresh, stale, known, live, gone) = (
            PeerId::random(),
            PeerId::random(),
            PeerId::random(),
            PeerId::random(),
            PeerId::random(),
        );
        let addr = |n: u8| -> Multiaddr { format!("/ip4/203.0.113.{n}/tcp/17999").parse().unwrap() };

        let mut last_disconnect_at = HashMap::from([(fresh, Instant::now()), (stale, past)]);
        let mut last_dial_by_addr = HashMap::from([(addr(1), Instant::now()), (addr(2), past)]);
        let mut peer_quality: HashMap<PeerId, PeerQuality> =
            [known, live, gone].into_iter().map(|p| (p, PeerQuality::default())).collect();
        let known_addrs = HashMap::from([(known, HashSet::from([addr(3)]))]);
        let connected = HashSet::from([live]);

        prune_dial_state(
            &mut last_disconnect_at,
            &mut last_dial_by_addr,
            &mut peer_quality,
            &mut HashMap::new(),
            &known_addrs,
            &connected,
        );

        // Honest path: an entry still inside its cooldown stays, or a peer would be redialed early.
        assert!(last_disconnect_at.contains_key(&fresh));
        assert!(last_dial_by_addr.contains_key(&addr(1)));
        assert!(peer_quality.contains_key(&known) && peer_quality.contains_key(&live));
        // What no cooldown and no dial order reads any more is gone.
        assert!(!last_disconnect_at.contains_key(&stale));
        assert!(!last_dial_by_addr.contains_key(&addr(2)));
        assert!(!peer_quality.contains_key(&gone));
    }

    #[test]
    fn outbound_gauge_moves_with_the_outbound_set() {
        let gauge = AtomicUsize::new(0);
        let mut outbound: HashSet<PeerId> = HashSet::new();
        let (a, b) = (PeerId::random(), PeerId::random());
        outbound.insert(a);
        store_outbound_gauge(&gauge, &outbound);
        outbound.insert(b);
        store_outbound_gauge(&gauge, &outbound);
        assert_eq!(gauge.load(Ordering::Relaxed), 2);
        outbound.remove(&a);
        store_outbound_gauge(&gauge, &outbound);
        assert_eq!(gauge.load(Ordering::Relaxed), 1);
    }

    #[test]
    fn learned_addr_is_new_once_per_peer_and_addr() {
        let mut known: HashMap<PeerId, HashSet<Multiaddr>> = HashMap::new();
        let (a, b) = (PeerId::random(), PeerId::random());
        let addr: Multiaddr = "/ip4/10.0.0.1/tcp/17999".parse().unwrap();
        let other: Multiaddr = "/ip4/10.0.0.2/tcp/17999".parse().unwrap();

        assert!(insert_known_addr_is_new(&mut known, a, addr.clone()));
        for _ in 0..25 {
            assert!(!insert_known_addr_is_new(&mut known, a, addr.clone()));
        }
        assert!(insert_known_addr_is_new(&mut known, a, other.clone()));
        assert!(!insert_known_addr_is_new(&mut known, a, other));
        assert!(insert_known_addr_is_new(&mut known, b, addr.clone()));
        assert_eq!(known[&a].len(), 2);
        assert_eq!(known[&b].len(), 1);
    }

    #[test]
    fn learned_addr_refused_by_the_per_peer_cap_is_not_new() {
        let mut known: HashMap<PeerId, HashSet<Multiaddr>> = HashMap::new();
        let a = PeerId::random();
        for i in 0..MAX_ADDRS_PER_PEER {
            let m: Multiaddr = format!("/ip4/10.0.1.{i}/tcp/17999").parse().unwrap();
            assert!(insert_known_addr_is_new(&mut known, a, m));
        }
        let over: Multiaddr = "/ip4/10.0.2.1/tcp/17999".parse().unwrap();
        assert!(!insert_known_addr_is_new(&mut known, a, over.clone()));
        assert!(!known[&a].contains(&over));
    }

    // The swarm loop is one task, but `tokio::spawn` on the multi-threaded runtime may poll it on
    // a different worker thread after any await point. These two tests pin the property that the
    // per-peer maps survive that: they fail if either map is a thread_local, because the write and
    // the read then land in different maps.

    #[test]
    fn outbound_pacing_accumulates_across_threads() {
        let peer = PeerId::random();
        let half = (OUTBOUND_MAX_RR_PER_PEER_PER_WINDOW / 2) as usize;

        // Two threads, each sending fewer requests than the per-peer cap on its own.
        let mut handles = Vec::new();
        for _ in 0..2 {
            handles.push(std::thread::spawn(move || {
                for _ in 0..half {
                    pace_note_sent(&peer);
                }
            }));
        }
        for h in handles {
            h.join().expect("pacing thread");
        }

        // Together they reached the cap, so the peer must read as saturated from anywhere.
        assert!(
            pace_saturated(&peer),
            "outbound pacing did not observe {} sends made on other threads",
            2 * half
        );
    }

    /// Requests a requester of ours sends to one server in `secs` of virtual time, 1 ms steps: block
    /// requests whenever demand is there and the pacer allows (two in flight on a 1 ms round trip,
    /// so two a step at most), and the unpaced background requests (`Background`: a GetTip at first
    /// sight and at each 5 s poll tick while our tip is stale, a headers request every 20 s, a peers
    /// request every 30 s).
    /// `checked_at` is a pacer check with no send, `demand_from` when block demand appears. The
    /// server is the real `allow_rr_req`, upstream's 120 in its window (d168f70 node.rs:53, :1300-1320).
    /// Returns (block requests sent, the server's verdict on the first refused request).
    fn pace_against_the_server(checked_at: f64, demand_from: f64, secs: f64) -> (u32, Option<f64>) {
        let (us, base) = (PeerId::random(), Instant::now());
        let at = |t: f64| base + Duration::from_secs_f64(t);
        let (mut buckets, mut bans) = (HashMap::new(), HashMap::new());
        let mut sent = 0u32;
        let mut refused_at = None;
        let mut serve = |t: f64, buckets: &mut HashMap<PeerId, RateBucket>, bans: &mut HashMap<PeerId, Instant>| {
            if allow_rr_req_at(buckets, bans, us, UPSTREAM_RR_REQS_PER_WINDOW, at(t)) != RrAdmission::Serve && refused_at.is_none() {
                refused_at = Some(t);
            }
        };
        let mut checked = false;
        for ms in 0..(secs * 1000.0) as u64 {
            let t = ms as f64 / 1000.0;
            if !checked && t >= checked_at {
                let _ = pace_saturated_at(&us, at(t));
                checked = true;
            }
            if ms == 3 || ms % 5_000 == 0 || ms % 20_000 == 1 || ms % 30_000 == 2 {
                serve(t, &mut buckets, &mut bans);
            }
            if t >= demand_from {
                for _ in 0..2 {
                    if pace_saturated_at(&us, at(t)) {
                        break;
                    }
                    pace_note_sent_at(&us, at(t));
                    sent += 1;
                    serve(t, &mut buckets, &mut bans);
                }
            }
        }
        (sent, refused_at)
    }

    // A pacing window that starts on a check lets demand that comes late in a window send 90 at its
    // end and 90 more at the start of the next, 180 inside one window of the server, which bans us
    // for ten minutes at the 121st.
    #[test]
    fn our_pacing_never_crosses_an_honest_servers_request_limit() {
        for (checked_at, demand_from) in [(0.0, 9.9), (0.0, 0.0), (3.0, 9.999), (0.0, 5.0)] {
            let (sent, refused) = pace_against_the_server(checked_at, demand_from, 40.0);
            assert_eq!(refused, None, "check at {checked_at} s, demand from {demand_from} s: refused after {sent} sent");
        }
        // The paired honest path: a long catch-up still sends its 90 a window.
        let (sent, refused) = pace_against_the_server(0.0, 0.0, 60.0);
        assert_eq!(refused, None);
        assert!(sent >= 6 * OUTBOUND_MAX_RR_PER_PEER_PER_WINDOW, "{sent} block requests in 60 s");
    }

    // The immediate request on a new child header must not have its own copy of the block-request
    // checks and record, whose pacing could be removed unseen. Both senders go through
    // can_take_block_request and note_block_request_sent.
    #[test]
    fn a_block_request_is_paced_and_recorded_whichever_sender_sends_it() {
        let (p, other) = (PeerId::random(), PeerId::random());
        let connected = HashSet::from([p, other]);
        let (bans, quar) = (HashMap::new(), HashMap::new());
        let mut inflight: HashMap<Hash32, (u32, Instant, PeerId)> = HashMap::new();
        let mut rid_to_hash: HashMap<u32, Hash32> = HashMap::new();
        for i in 0..OUTBOUND_MAX_RR_PER_PEER_PER_WINDOW {
            assert!(can_take_block_request(&p, &connected, &bans, &quar, &inflight), "block request {} refused", i + 1);
            let mut h = [0u8; 32];
            h[..4].copy_from_slice(&i.to_le_bytes());
            note_block_request_sent(i, p, h, &mut rid_to_hash, &mut inflight);
            assert_eq!((inflight[&h].0, inflight[&h].2, rid_to_hash[&i]), (i, p, h), "recorded in flight");
            // The answer frees the stream; the pace keeps the send.
            inflight.remove(&h);
            rid_to_hash.remove(&i);
        }
        assert!(!can_take_block_request(&p, &connected, &bans, &quar, &inflight), "past the pace");
        assert!(can_take_block_request(&other, &connected, &bans, &quar, &inflight), "another peer is not paced by it");
        // A full stream budget refuses on its own.
        let mut busy: HashMap<Hash32, (u32, Instant, PeerId)> = HashMap::new();
        for i in 0..MAX_BLOCK_REQUESTS_PER_PEER as u32 {
            note_block_request_sent(1_000 + i, other, [0xEE - i as u8; 32], &mut rid_to_hash, &mut busy);
        }
        assert!(!can_take_block_request(&other, &connected, &bans, &quar, &busy));
    }

    // An honest upstream node's pacer does not bound what it sends one peer (a thread_local map,
    // d168f70 node.rs:1053-1057, on a multi-thread runtime), so requests past
    // RL_MAX_RR_REQS_PER_WINDOW are answered "rate limited" for the rest of the window, and the peer
    // is neither banned nor closed.
    #[test]
    fn a_request_flood_is_throttled_for_its_window_and_never_banned() {
        let (p, base) = (PeerId::random(), Instant::now());
        let (mut buckets, mut bans) = (HashMap::new(), HashMap::new());
        let at = |ms: u64| base + Duration::from_millis(ms);
        let ask = |buckets: &mut HashMap<PeerId, RateBucket>, bans: &mut HashMap<PeerId, Instant>, ms: u64| {
            allow_rr_req_at(buckets, bans, p, RL_MAX_RR_REQS_PER_WINDOW, at(ms))
        };
        for i in 1..=RL_MAX_RR_REQS_PER_WINDOW {
            assert_eq!(ask(&mut buckets, &mut bans, u64::from(i)), RrAdmission::Serve, "request {i}");
        }
        let past = RL_MAX_RR_REQS_PER_WINDOW + 1;
        assert_eq!(ask(&mut buckets, &mut bans, 2_000), RrAdmission::Throttled { entered: true }, "request {past}");
        for i in 1..=50u32 {
            assert_eq!(ask(&mut buckets, &mut bans, 2_000 + u64::from(i)), RrAdmission::Throttled { entered: false }, "request {}", past + i);
        }
        assert!(!is_banned(&bans, &p), "a request flood banned the peer");
        assert!(bans.is_empty());
        // The next window serves it again.
        assert_eq!(ask(&mut buckets, &mut bans, 10_001), RrAdmission::Serve, "the next window refused it");
    }

    // Pins the ban boundaries, so a stock 3 for invalid messages, which the constant's comment
    // records as collapsing a catching-up node's peers to 0, or a > turned >=, fails here. Requests
    // are throttled past 1,200 in a window in every mode, upstream's bootnode figure (d168f70
    // node.rs:54), and never banned, so the 121st to the 1,200th, which an upstream server bans for
    // (:53), are served (an honest upstream node's pacer runs per worker thread and can pass 120);
    // the invalid-message ban falls at upstream's 32 (:59).
    #[test]
    fn the_request_throttle_and_invalid_message_ban_fall_at_their_figures() {
        // The figure itself, not the constant, so that changing the constant fails here.
        const FIGURE: u32 = 1_200;
        let (p, mut buckets, mut bans) = (PeerId::random(), HashMap::new(), HashMap::new());
        for i in 1..=FIGURE {
            assert_eq!(allow_rr_req(&mut buckets, &mut bans, p), RrAdmission::Serve, "request {i} of {FIGURE} refused");
        }
        let next = allow_rr_req(&mut buckets, &mut bans, p);
        assert_eq!(next, RrAdmission::Throttled { entered: true }, "request {} of the window", FIGURE + 1);
        assert!(!is_banned(&bans, &p), "requests past the figure banned the peer");
        let (p, mut buckets, mut bans) = (PeerId::random(), HashMap::new(), HashMap::new());
        for _ in 1..32 {
            note_invalid(&mut buckets, &mut bans, p, "test");
        }
        assert!(!is_banned(&bans, &p), "banned at 31 invalid messages");
        note_invalid(&mut buckets, &mut bans, p, "test");
        assert!(is_banned(&bans, &p), "not banned at the 32nd invalid message");
        // An invalid-message ban still holds the peer's requests and closes its connections.
        assert_eq!(allow_rr_req(&mut buckets, &mut bans, p), RrAdmission::Banned);
        assert_eq!(banned_with_connections(&HashSet::from([p]), &bans, &HashMap::new()), vec![p]);
    }

    // The persisted reputation file round-trips exactly. Upstream's loader reads canonical_block
    // from index 11 and everything from index 6 onward shifted by one, so a peer's canonical-block
    // count comes back as its timeout count and last_seen_unix comes back as 0. peer_quality_score
    // charges -20 per timeout and -50 for a record older than a day, so the file systematically
    // demotes the peers that served best, and re-saves the rotated values so it compounds on every
    // restart.
    #[test]
    fn peer_quality_round_trip_is_identity() {
        let dir = tempfile::TempDir::new().expect("tempdir");
        let path = dir.path().to_str().unwrap().to_string();
        let peer = PeerId::random();

        // A distinct value per field, so ANY rotation is visible.
        let q = PeerQuality {
            dial_success: 11,
            dial_failure: 22,
            good_tip: 33,
            good_block: 55,
            canonical_block: 66,
            timeout: 77,
            invalid: 88,
            last_seen_unix: unix_now(),
            last_tip_height: 1010,
            last_tip_work: 1111,
        };
        let expect_last_seen = q.last_seen_unix;
        let mut m = HashMap::new();
        m.insert(peer, q);
        save_peer_quality(&path, &m);

        let back = load_peer_quality(&path);
        let got = back.get(&peer).expect("record survives the round trip");
        assert_eq!(got.dial_success, 11);
        assert_eq!(got.dial_failure, 22);
        assert_eq!(got.good_tip, 33);
        assert_eq!(got.good_block, 55);
        assert_eq!(got.canonical_block, 66, "canonical_block rotated");
        assert_eq!(got.timeout, 77, "timeout rotated (this is the -20/each field)");
        assert_eq!(got.invalid, 88, "invalid rotated");
        assert_eq!(got.last_seen_unix, expect_last_seen, "last_seen_unix rotated");
        assert_eq!(got.last_tip_height, 1010);
        assert_eq!(got.last_tip_work, 1111);
    }

    // A Tip answer that wrote the claimed height and work into the quality record before the header
    // was checked would let a u128::MAX claim outrank every honest peer in the dial order and the
    // persisted records. Only a header we indexed moves them.
    #[test]
    fn a_tip_answer_ranks_a_peer_by_the_header_we_indexed() {
        let hi = HeaderIndex { hash: [1u8; 32], parent: [0u8; 32], height: 500, chainwork: 9_000_000_000_000, bits: 0, time: 0 };
        let mut honest = PeerQuality::default();
        note_tip_answer(&mut honest, Some(Asked::Tip), Some(&hi), 100);
        assert_eq!((honest.good_tip, honest.last_seen_unix), (1, 100));
        assert_eq!((honest.last_tip_height, honest.last_tip_work), (500, 9_000_000_000_000), "an indexed tip raises the quality");

        // The honest peer's next tip is ahead of our index; its checked tip stands.
        note_tip_answer(&mut honest, Some(Asked::Tip), None, 110);
        assert_eq!((honest.good_tip, honest.last_tip_height, honest.last_tip_work), (2, 500, 9_000_000_000_000));

        // A claim on a header we do not hold, or the zero hash, counts the answer and nothing else.
        let mut claimant = PeerQuality::default();
        note_tip_answer(&mut claimant, Some(Asked::Tip), None, 100);
        assert_eq!((claimant.good_tip, claimant.last_tip_height, claimant.last_tip_work), (1, 0, 0));
        assert!(peer_quality_score(&honest) > peer_quality_score(&claimant));

        // A Tip sent in answer to our headers request, or to nothing we asked, does not count as a
        // Tip answer.
        for asked in [Some(Asked::Headers), None] {
            let mut q = claimant.clone();
            note_tip_answer(&mut q, asked, Some(&hi), 200);
            assert_eq!((q.good_tip, q.last_seen_unix, q.last_tip_height), (1, 100, 0), "asked {asked:?}");
        }
    }

    // If every connection, inbound included, added a dial success worth 20 points and every Tip
    // answer 5, neither capped, an identity that reconnected to us or just stayed connected would
    // outrank honest block providers in our dials, our Peers answers and the persisted records (a
    // farmed record: dial_success 300, good_tip 300).
    #[test]
    fn reconnecting_or_staying_connected_does_not_outrank_serving_blocks() {
        let mut farmer = PeerQuality::default();
        for _ in 0..300 {
            note_connected(&mut farmer, false, 1_000);
        }
        assert_eq!(farmer.dial_success, 0, "an inbound connection is not a dial of ours");
        // A record persisted with farmed counts keeps them; they rank no higher than these.
        let farmed = PeerQuality { dial_success: 300, good_tip: 60_480, last_seen_unix: unix_now(), ..PeerQuality::default() };
        let mut provider = PeerQuality { canonical_block: 3, good_block: 3, last_seen_unix: unix_now(), ..PeerQuality::default() };
        for _ in 0..2 {
            note_connected(&mut provider, true, unix_now());
        }
        assert_eq!(provider.dial_success, 2, "a dial of ours that connects counts");
        assert!(
            peer_quality_score(&provider) > peer_quality_score(&farmed),
            "provider {} vs farmed {}",
            peer_quality_score(&provider),
            peer_quality_score(&farmed)
        );
        let (p, f) = (PeerId::random(), PeerId::random());
        let mut order = vec![f, p];
        sort_peer_ids_by_quality(&mut order, &HashMap::from([(p, provider), (f, farmed)]));
        assert_eq!(order, vec![p, f], "the block provider is dialed and exported first");
        // Below the caps each dial and each answer still counts.
        let one = PeerQuality { dial_success: 1, good_tip: 1, ..PeerQuality::default() };
        assert!(peer_quality_score(&one) > peer_quality_score(&PeerQuality::default()));
    }

    // Only the request-response timeout is charged as a timeout (-20 in the dial order), not a
    // connection closed by the peer's restart or by our own disconnect with a request in flight.
    #[test]
    fn only_a_request_timeout_is_charged_as_a_timeout() {
        use request_response::OutboundFailure;
        assert!(charges_quality_timeout(&OutboundFailure::Timeout));
        assert!(!charges_quality_timeout(&OutboundFailure::ConnectionClosed));
        assert!(!charges_quality_timeout(&OutboundFailure::DialFailure));
        assert!(!charges_quality_timeout(&OutboundFailure::UnsupportedProtocols));
        let refused = std::io::Error::other("max sub-streams reached");
        assert!(!charges_quality_timeout(&OutboundFailure::Io(refused)));
        let reset = std::io::Error::new(std::io::ErrorKind::ConnectionReset, "reset");
        assert!(!charges_quality_timeout(&OutboundFailure::Io(reset)));
    }

    // A Headers answer that added its length to good_headers (15 points each in the dial order)
    // would let 1,024 copies of a known header every 10 s farm the persisted records. The column
    // stays for the v2 format and ranks nothing, also when a file holds a farmed count.
    #[test]
    fn a_persisted_header_count_ranks_nothing() {
        let dir = tempfile::TempDir::new().expect("tempdir");
        let path = dir.path().to_str().unwrap().to_string();
        let (farmed, plain) = (PeerId::random(), PeerId::random());
        let now = unix_now();
        let row = |p: &PeerId, gh: u64| format!("{p} 1 0 3 {gh} 2 1 0 0 {now} 50 9000");
        std::fs::write(
            peer_scores_path(&path),
            [PEER_QUALITY_FORMAT.to_string(), row(&farmed, 92_160_000), row(&plain, 0)].join("\n"),
        )
        .unwrap();
        let back = load_peer_quality(&path);
        assert_eq!(peer_quality_score(&back[&farmed]), peer_quality_score(&back[&plain]));

        save_peer_quality(&path, &back);
        let text = std::fs::read_to_string(peer_scores_path(&path)).unwrap();
        let farmed_row = text.lines().find(|l| l.starts_with(&farmed.to_string())).unwrap();
        assert_eq!(farmed_row.split_whitespace().nth(4), Some("0"), "the column is written as 0");
    }

    #[test]
    fn peer_quality_rejects_the_pre_v018_format() {
        let dir = tempfile::TempDir::new().expect("tempdir");
        let path = dir.path().to_str().unwrap().to_string();
        // TWO records, deliberately. With a one-line fixture this test passes even with the
        // format guard deleted, because `lines.next()` consumes the only record as a header and
        // the map comes back empty either way. It would then be green while the loader happily
        // re-imported the rotated values it exists to reject.
        let legacy = format!(
            "{} 1 0 0 0 0 1783804074 0 0 0 0 0\n{} 2 0 0 0 0 1783804075 0 0 0 0 0",
            PeerId::random(),
            PeerId::random()
        );
        std::fs::write(peer_scores_path(&path), legacy).expect("write legacy file");

        assert!(
            load_peer_quality(&path).is_empty(),
            "a rotated legacy file must be ignored, not imported"
        );

        // And the guard is what does it: the same records under a v2 header DO load, so the test
        // is discriminating rather than passing for an unrelated reason.
        let tagged = format!(
            "{PEER_QUALITY_FORMAT}\n{} 1 2 3 4 5 6 7 8 9 10 11",
            PeerId::random()
        );
        std::fs::write(peer_scores_path(&path), tagged).expect("write tagged file");
        assert_eq!(
            load_peer_quality(&path).len(),
            1,
            "a correctly tagged file must still load"
        );
    }

    #[test]
    fn peer_quality_save_is_bounded() {
        let dir = tempfile::TempDir::new().expect("tempdir");
        let path = dir.path().to_str().unwrap().to_string();

        let mut m = HashMap::new();
        for i in 0..(MAX_QUALITY_RECORDS + 500) {
            let mut q = PeerQuality::default();
            q.last_seen_unix = unix_now();
            q.canonical_block = i as u64; // higher index = better score
            m.insert(PeerId::random(), q);
        }
        // Plus one record that is far too old to be worth keeping.
        let mut stale = PeerQuality::default();
        stale.last_seen_unix = unix_now() - QUALITY_RECORD_MAX_AGE_SECS - 1;
        stale.canonical_block = u64::MAX / 2; // would otherwise rank first
        let stale_peer = PeerId::random();
        m.insert(stale_peer, stale);

        save_peer_quality(&path, &m);
        let back = load_peer_quality(&path);

        assert!(
            back.len() <= MAX_QUALITY_RECORDS,
            "persisted {} records, cap is {}",
            back.len(),
            MAX_QUALITY_RECORDS
        );
        assert!(
            !back.contains_key(&stale_peer),
            "a month-old record must be dropped even though it scores highest"
        );
    }

    #[test]
    fn header_only_mark_is_visible_from_another_thread() {
        let peer = PeerId::random();
        std::thread::spawn(move || note_header_only(&peer))
            .join()
            .expect("marking thread");

        assert!(
            is_header_only(&peer),
            "header-only mark written on another thread was not observed"
        );
    }
}

// ── gossip peer identity ────────────────────────────────────────────────────────────────────────
//
// The principle, one sentence: under ValidationMode::Permissive the gossip AUTHOR cannot be
// authenticated and the FORWARDER did not write the payload, so a content-level failure has no
// sound strike target and strikes nobody; every peer identity the gossip arm uses for anything is
// the noise-authenticated propagation_source.
#[cfg(test)]
mod gossip_attribution_tests {
    use super::*;

    /// The gossip arm's decode: the production decoder with the gossip size limit.
    fn decode_as_the_gossip_arm_does<T: serde::de::DeserializeOwned>(
        data: &[u8],
    ) -> Result<T, bincode::Error> {
        decode_wire(data, MAX_GOSSIP_MSG_BYTES as u64)
    }

    fn msg_event(source: Option<PeerId>, forwarder: PeerId, data: Vec<u8>, topic: &str) -> OutEvent {
        OutEvent::Gossipsub(gossipsub::Event::Message {
            propagation_source: forwarder,
            message_id: gossipsub::MessageId::from("test"),
            message: gossipsub::Message {
                source,
                data,
                sequence_number: Some(1),
                topic: IdentTopic::new(topic).hash(),
            },
        })
    }

    // ================= ATTACK HALF =================

    // ---- (a): a peer NAMED in an unsigned message cannot be damaged by being named ----
    #[test]
    fn victim_named_in_an_unsigned_message_cannot_be_damaged() {
        // COMPILE-TIME TRIPWIRE. Any future edit that puts an `Option<PeerId>` source back into
        // the return type fails the build with this test's name on it. That is the durable half:
        // `message.source` is unauthenticated under ValidationMode::Permissive and must never
        // re-enter this node's decision surface.
        let _: fn(&OutEvent) -> Option<(PeerId, gossipsub::MessageId, Vec<u8>, String)> =
            handle_gossipsub_event;

        let victim = PeerId::random();
        let relay = PeerId::random();
        assert_ne!(victim, relay);

        // 3 bytes on TOPIC_TX: too short to decode, the decode-failure arm.
        let ev = msg_event(Some(victim), relay, vec![0u8, 1, 2], TOPIC_TX);
        let (fwd, _id, data, topic) = handle_gossipsub_event(&ev).expect("gossip event");

        assert_eq!(
            fwd, relay,
            "the only peer identity the gossip arm may use is the noise-authenticated forwarder"
        );
        assert_eq!(topic, TOPIC_TX);
        assert!(
            decode_as_the_gossip_arm_does::<GossipTx>(&data).is_err(),
            "the fixture payload must actually reach the decode-failure arm"
        );

        // The decode-failure arm's ONLY remaining action, run hard.
        let mut bans: HashMap<PeerId, Instant> = HashMap::new();
        let mut buckets: HashMap<PeerId, RateBucket> = HashMap::new();
        let mut scores: HashMap<PeerId, i32> = HashMap::new();
        let mut quar: HashMap<PeerId, Instant> = HashMap::new();
        let mut dropped: u64 = 0;

        for _ in 0..(RL_MAX_INVALID_PER_WINDOW * 4) {
            note_gossip_dropped(&mut dropped, fwd, &topic, "bad gossip tx decode");
        }

        const WHY: &str = "an unsigned TOPIC_TX message with from=<victim> and no signature must \
             not cost <victim> anything; protocol.rs:409-419 leaves `from` attacker-chosen, and \
             five of these used to quarantine a named honest peer for 300s and 32 used to ban it \
             for 600s fleet-wide";

        assert!(bans.is_empty(), "{WHY}");
        assert!(buckets.is_empty(), "{WHY}");
        assert!(scores.is_empty(), "{WHY}");
        assert!(quar.is_empty(), "{WHY}");
        assert!(!is_banned(&bans, &victim), "{WHY}");
        assert!(!is_quarantined(&quar, &victim), "{WHY}");
        assert!(!scores.contains_key(&victim), "{WHY}");
    }

    // ---- (b): a sourceless message is PROCESSED, not dropped ----
    #[test]
    fn sourceless_gossip_is_processed_not_dropped() {
        let relay = PeerId::random();

        let gh = GossipHeader {
            header: BlockHeader {
                version: 1,
                prev: [0u8; 32],
                merkle: [7u8; 32],
                time: 1,
                bits: 0x1e00ffff,
                nonce: 0,
            },
        };
        let honest_header_bytes = crate::codec::consensus_bincode().serialize(&gh).unwrap();

        const WHY: &str = "the gossipsub message id is computed over m.data only, so a \
             signature-stripped copy of an honest header shares its id with the signed original; \
             dropping the stripped copy at the app suppresses the ORIGINAL through gossipsub's \
             duplicate cache (behaviour.rs:1992 inserts before the app event at :2032), which is \
             a self-inflicted stall on the header topic";

        let ev = msg_event(None, relay, honest_header_bytes, TOPIC_HDR);
        let (fwd, _id, data, topic) = handle_gossipsub_event(&ev).expect(WHY);

        assert_eq!(fwd, relay, "{WHY}");
        assert_eq!(topic, TOPIC_HDR, "{WHY}");
        assert!(
            decode_as_the_gossip_arm_does::<GossipHeader>(&data).is_ok(),
            "{WHY}"
        );
    }

    // ---- (c): the executed proof of the peer_score bound ----
    #[test]
    fn gossip_never_keys_peer_state_on_an_identity_we_do_not_hold() {
        let victim = PeerId::random();
        let relay = PeerId::random();

        let mut bans: HashMap<PeerId, Instant> = HashMap::new();
        let mut buckets: HashMap<PeerId, RateBucket> = HashMap::new();
        let mut scores: HashMap<PeerId, i32> = HashMap::new();
        let mut quarantine: HashMap<PeerId, Instant> = HashMap::new();
        let mut dropped: u64 = 0;

        for _ in 0..(RL_MAX_INVALID_PER_WINDOW * 4) {
            note_gossip_dropped(&mut dropped, relay, TOPIC_TX, "bad gossip tx decode");
        }

        // The way the real arm keys peer_score: the forwarder, and only the forwarder.
        bump_score(&mut scores, &mut quarantine, relay, 1);

        let mut connected: HashSet<PeerId> = HashSet::new();
        connected.insert(relay);
        assert!(!connected.contains(&victim));

        prune_peer_state(
            &mut buckets,
            &mut bans,
            &mut quarantine,
            &mut scores,
            &connected,
            &connected,
        );

        assert!(
            scores.keys().all(|p| connected.contains(p)),
            "peer_score is the one strike map with no expiry, so every key must be a peer we \
             hold a connection to (or one held by a live ban, quarantine or rate bucket); an \
             attacker-supplied PeerId must be unrepresentable here"
        );
    }

    // ================= HONEST HALF (paired happy-path) =================

    #[test]
    fn honest_relayed_traffic_still_credits_the_forwarder_and_is_never_struck() {
        let relay = PeerId::random();

        let mut bans: HashMap<PeerId, Instant> = HashMap::new();
        let mut buckets: HashMap<PeerId, RateBucket> = HashMap::new();
        let mut scores: HashMap<PeerId, i32> = HashMap::new();
        let mut quar: HashMap<PeerId, Instant> = HashMap::new();

        // PRODUCTION'S EXACT PUBLISH SHAPE for the tx topic.
        let gt = GossipTx {
            tx: crate::chain::mine::coinbase([0x11u8; 20], 1, 1, None),
        };
        let bytes = crate::codec::consensus_bincode().serialize(&gt).unwrap();

        const WHY: &str = "an honest neighbour relaying 1000 real txs must end the window \
             unbanned, unquarantined, and with its credit intact; this is the leg that proves the \
             fix did not trade one partition for another";

        // 1000 is deliberately under RL_MAX_GOSSIP_MSGS_PER_WINDOW (1024) so the transport budget
        // is not what is under test here.
        for _ in 0..1000 {
            assert!(allow_gossip(&mut buckets, &mut bans, relay), "{WHY}");

            let ev = msg_event(None, relay, bytes.clone(), TOPIC_TX);
            let (fwd, _id, data, _topic) = handle_gossipsub_event(&ev).expect(WHY);
            assert_eq!(fwd, relay, "{WHY}");
            assert!(
                decode_as_the_gossip_arm_does::<GossipTx>(&data).is_ok(),
                "{WHY}"
            );

            bump_score(&mut scores, &mut quar, relay, 1);
        }

        assert!(!is_banned(&bans, &relay), "{WHY}");
        assert!(!is_quarantined(&quar, &relay), "{WHY}");
        assert_eq!(
            scores.get(&relay).copied(),
            Some(SCORE_MAX),
            "{WHY} (the good-behaviour credit still lands, up to the ceiling, so sync-peer selection \
             keeps its signal)"
        );
        assert_eq!(buckets.get(&relay).map(|b| b.invalid), Some(0), "{WHY}");
    }

    #[test]
    fn header_relay_targets_the_forwarder_for_the_headers_request() {
        let relay = PeerId::random();
        let claimed = PeerId::random();

        let ev = msg_event(Some(claimed), relay, vec![9, 9, 9], TOPIC_HDR);
        let (fwd, _id, _data, _topic) = handle_gossipsub_event(&ev).expect("gossip event");

        assert_eq!(
            fwd, relay,
            "requesting headers from an unauthenticated `from` dials an identity we hold no \
             connection to and keys its background demand on it"
        );
    }

    // The gossip arm's verdict reporting, PublishRetry and the forwarder attribution rule rest on
    // libp2p-gossipsub 0.50.1 as read in docs/behaviour.md "Dependency internals the code relies
    // on" (validation mode,
    // report_message_validation_result, the duplicate cache before publish, Permissive signature
    // checks). A bump of that crate must re-read those lines.
    #[test]
    fn the_gossipsub_behaviour_we_rely_on_is_pinned_to_the_locked_version() {
        let lock = std::fs::read_to_string(concat!(env!("CARGO_MANIFEST_DIR"), "/Cargo.lock")).unwrap();
        let entry = lock.split("[[package]]").find(|p| p.contains("name = \"libp2p-gossipsub\"")).unwrap();
        assert!(
            entry.contains("version = \"0.50.1\"") && entry.contains("registry+"),
            "libp2p-gossipsub moved: re-read the lines RELEASING.md \"Dependency bumps\" cites, then update this check"
        );
    }

    // ---- a padded copy of an honest message does not decode ----
    #[test]
    fn a_padded_copy_of_an_honest_message_does_not_decode() {
        use futures::io::Cursor;
        use request_response::Codec;

        const WHY: &str = "a padded copy carries a new gossip id, and a node that decoded it would \
             judge the original's content under that id; each byte appended is one more id";
        let pad = |bytes: &[u8]| [bytes, &[0u8]].concat();

        // Production's publish shapes for both topics.
        let gh = GossipHeader {
            header: BlockHeader {
                version: 1,
                prev: [3u8; 32],
                merkle: [7u8; 32],
                time: 1,
                bits: 0x1e00ffff,
                nonce: 0,
            },
        };
        let gt = GossipTx {
            tx: crate::chain::mine::coinbase([0x11u8; 20], 1, 1, None),
        };
        let hdr = crate::codec::consensus_bincode().serialize(&gh).unwrap();
        let tx = crate::codec::consensus_bincode().serialize(&gt).unwrap();
        assert!(decode_as_the_gossip_arm_does::<GossipHeader>(&hdr).is_ok());
        assert!(decode_as_the_gossip_arm_does::<GossipTx>(&tx).is_ok());
        assert!(decode_as_the_gossip_arm_does::<GossipHeader>(&pad(&hdr)).is_err(), "{WHY}");
        assert!(decode_as_the_gossip_arm_does::<GossipTx>(&pad(&tx)).is_err(), "{WHY}");

        // The request-response codec through its own read path, as write_request and
        // write_response encode.
        let req = crate::codec::consensus_bincode().serialize(&SyncRequest::GetTip).unwrap();
        let resp = crate::codec::consensus_bincode()
            .serialize(&SyncResponse::Peers { peers: vec!["x".into()] })
            .unwrap();
        let read_req = |b: Vec<u8>| {
            futures::executor::block_on(SyncCodec.read_request(&SYNC_PROTOCOL, &mut Cursor::new(b)))
        };
        let read_resp = |b: Vec<u8>| {
            futures::executor::block_on(SyncCodec.read_response(&SYNC_PROTOCOL, &mut Cursor::new(b)))
        };
        assert!(read_req(req.clone()).is_ok());
        assert!(read_resp(resp.clone()).is_ok());
        assert!(read_req(pad(&req)).is_err(), "a request frame with bytes past its value is refused");
        assert!(read_resp(pad(&resp)).is_err(), "a response frame with bytes past its value is refused");
    }

    // At the tip, the forwarder of message 1,025 in a rate window is not disconnected: over the
    // budget is a drop; ban and quarantine still disconnect at the tip.
    #[test]
    fn over_the_gossip_budget_drops_and_keeps_the_forwarder() {
        let (relay, banned, quarantined) = (PeerId::random(), PeerId::random(), PeerId::random());
        let mut buckets: HashMap<PeerId, RateBucket> = HashMap::new();
        let mut bans: HashMap<PeerId, Instant> = HashMap::new();
        let mut quar: HashMap<PeerId, Instant> = HashMap::new();
        for caught_up in [true, false] {
            buckets.clear();
            for i in 1..=RL_MAX_GOSSIP_MSGS_PER_WINDOW {
                assert_eq!(gossip_gate(&mut buckets, &mut bans, &quar, relay, caught_up), GossipGate::Admit, "message {i}");
            }
            assert_eq!(
                gossip_gate(&mut buckets, &mut bans, &quar, relay, caught_up),
                GossipGate::Drop("gossip rate limit"),
                "caught_up={caught_up}"
            );
        }
        assert!(bans.is_empty() && quar.is_empty(), "the budget bans and quarantines nobody");

        ban_peer(&mut bans, banned, "test");
        quar.insert(quarantined, Instant::now());
        assert_eq!(gossip_gate(&mut buckets, &mut bans, &quar, banned, true), GossipGate::Disconnect("banned"));
        assert_eq!(gossip_gate(&mut buckets, &mut bans, &quar, quarantined, true), GossipGate::Disconnect("quarantined"));
        assert_eq!(gossip_gate(&mut buckets, &mut bans, &quar, banned, false), GossipGate::Drop("banned"));
        assert_eq!(gossip_gate(&mut buckets, &mut bans, &quar, quarantined, false), GossipGate::Drop("quarantined"));

        // Quarantined after spending its budget: at the tip it
        // is still disconnected, not only dropped until the window ends.
        quar.insert(relay, Instant::now());
        assert_eq!(gossip_gate(&mut buckets, &mut bans, &quar, relay, true), GossipGate::Disconnect("quarantined"));
    }

    // A forwarder is charged the inputs of the gossip txs its checks refused, the
    // unit of a check's cost, and once 4,096 are charged in a window its next txs are dropped
    // unchecked, with nothing struck; a new window checks them again. Paired honest path: txs that
    // are admitted are not charged, so a relay's admitted traffic never reaches the budget.
    #[test]
    fn refused_gossip_txs_are_charged_by_inputs_and_dropped_past_the_budget_without_a_strike() {
        let relay = PeerId::random();
        let mut buckets: HashMap<PeerId, RateBucket> = HashMap::new();
        let full = crate::params::MAX_TX_INPUTS;
        for i in 1..=RL_MAX_GOSSIP_TX_INPUTS_PER_WINDOW as usize / full {
            assert!(!gossip_tx_refusals_spent(&mut buckets, relay), "full-width refusal {i} is checked");
            charge_gossip_tx_refusal(&mut buckets, relay, full);
        }
        assert!(gossip_tx_refusals_spent(&mut buckets, relay), "a ninth wide refusal is dropped unchecked");
        let b = &buckets[&relay];
        assert_eq!((b.gossip_tx_refused_inputs, b.invalid), (RL_MAX_GOSSIP_TX_INPUTS_PER_WINDOW, 0), "nothing struck");

        buckets.get_mut(&relay).unwrap().window_start = Instant::now() - RL_WINDOW;
        assert!(!gossip_tx_refusals_spent(&mut buckets, relay), "a new window checks again");

        // Admitted txs are never charged: any number of them leaves the budget unspent.
        buckets.clear();
        for _ in 0..RL_MAX_GOSSIP_MSGS_PER_WINDOW {
            assert!(!gossip_tx_refusals_spent(&mut buckets, relay));
        }
    }
}

// ---------------------------------------------------------------------------
// The sync transport cap is upstream's 1 MiB. Every message of this node fits under it, its miner's
// largest block included; a block above it is neither read nor written, a valid one that
// upstream's miner can make included (tests/consensus_accepts_a_block_above_the_transport_cap.rs).
// ---------------------------------------------------------------------------
#[cfg(test)]
mod sync_transport_cap_tests {
    use super::*;
    use crate::net::proto::SyncResponse;
    use crate::types::{Block, BlockHeader, OutPoint, Transaction, TxIn, TxOut};
    use futures::io::Cursor;
    use libp2p::request_response::Codec as _;

    fn header() -> BlockHeader {
        BlockHeader { version: 1, prev: [0u8; 32], merkle: [0u8; 32], time: 0, bits: 0, nonce: 0 }
    }

    // A block of `bytes` serialized bytes (transport-level test: wire size, not validity).
    fn block_of(bytes: usize) -> Block {
        let tx = |pad: usize| Transaction {
            version: 1,
            inputs: vec![TxIn { prevout: OutPoint { txid: [0u8; 32], vout: 0 }, script_sig: vec![0xAB; pad] }],
            outputs: vec![TxOut { value: 1, script_pubkey: [0u8; 20] }],
            locktime: 0,
            app: crate::types::AppPayload::None,
        };
        let c = crate::codec::consensus_bincode();
        let overhead = c.serialized_size(&Block { header: header(), txs: vec![tx(0)] }).unwrap() as usize;
        let block = Block { header: header(), txs: vec![tx(bytes - overhead)] };
        assert_eq!(c.serialized_size(&block).unwrap() as usize, bytes);
        block
    }

    fn wire<T: serde::Serialize>(m: &T) -> u64 {
        crate::codec::consensus_bincode().serialized_size(m).unwrap()
    }

    fn write_then_read(resp: SyncResponse) -> std::io::Result<SyncResponse> {
        futures::executor::block_on(async {
            let mut out = Cursor::new(Vec::new());
            SyncCodec.write_response(&SYNC_PROTOCOL, &mut out, resp).await?;
            SyncCodec.read_response(&SYNC_PROTOCOL, &mut Cursor::new(out.into_inner())).await
        })
    }

    #[test]
    fn the_transport_cap_is_upstreams_1_mib() {
        assert_eq!(MAX_RR_MSG_BYTES, 1024 * 1024);
    }

    // Red-first for the restored cap: a consensus-valid size between 1 MiB and MAX_BLOCK_BYTES is
    // refused on read (upstream's "response too large") and on write. A node that read and served
    // it would be on the side of the split that upstream nodes cannot follow.
    #[test]
    fn a_block_above_1_mib_is_neither_read_nor_written() {
        let big = SyncResponse::Block { block: block_of(1_100_000) };
        assert!(wire(&big) > 1024 * 1024 && 1_100_000 <= MAX_BLOCK_BYTES, "fixture: above upstream's cap, within consensus");
        let bytes = crate::codec::consensus_bincode().serialize(&big).unwrap();
        let read = futures::executor::block_on(SyncCodec.read_response(&SYNC_PROTOCOL, &mut Cursor::new(bytes)));
        let Err(err) = read else { panic!("a response above the cap must not be read") };
        assert_eq!((err.kind(), err.to_string()), (std::io::ErrorKind::InvalidData, RESPONSE_TOO_LARGE.to_string()));
        assert!(write_then_read(big).is_err(), "a response above the cap must not be written");
    }

    // Paired honest path: our miner's largest block (`template_byte_cap`) round-trips, and so do a
    // full headers answer and the largest peers answer, locator and tx, whose limits upstream
    // shares. Upstream's miner is not covered: it fills templates up to 2 MiB less 16 KiB, so a
    // valid block it makes can be refused
    // (`tests/consensus_accepts_a_block_above_the_transport_cap.rs`).
    #[test]
    fn our_largest_block_and_the_other_message_kinds_fit_under_the_cap() {
        let largest_block = SyncResponse::Block { block: block_of(crate::chain::mine::template_byte_cap()) };
        assert!(wire(&largest_block) < MAX_RR_MSG_BYTES, "our miner's largest block: {}", wire(&largest_block));
        assert!(matches!(write_then_read(largest_block), Ok(SyncResponse::Block { .. })));

        let headers = SyncResponse::Headers { headers: vec![header(); MAX_HEADERS_PER_SYNC as usize] };
        assert_eq!(wire(&headers), 86_028);
        assert!(matches!(write_then_read(headers), Ok(SyncResponse::Headers { .. })));

        // Peers: at most MAX_PEERS_IN_EXCHANGE peers with MAX_ADDRS_PER_PEER addresses each, both
        // upstream's values; 256 bytes is above any /ip4 or /ip6 tcp address with a /p2p suffix.
        let peers = SyncResponse::Peers { peers: vec!["x".repeat(256); MAX_PEERS_IN_EXCHANGE * MAX_ADDRS_PER_PEER] };
        let locator = SyncRequest::GetHeadersByLocator { locator: vec![[0u8; 32]; MAX_LOCATOR_LEN], max: MAX_HEADERS_PER_SYNC };
        let tx = SyncRequest::SubmitTx { tx: block_of(MAX_TX_BYTES + 100).txs.remove(0) };
        for (name, n) in [("peers", wire(&peers)), ("locator", wire(&locator)), ("tx", wire(&tx))] {
            assert!(n < MAX_RR_MSG_BYTES / 4, "{name}: {n} bytes");
        }
    }

    /// A reader that counts the bytes taken from it.
    struct Counted {
        inner: Cursor<Vec<u8>>,
        taken: usize,
    }

    impl futures::AsyncRead for Counted {
        fn poll_read(
            mut self: std::pin::Pin<&mut Self>,
            cx: &mut std::task::Context<'_>,
            buf: &mut [u8],
        ) -> std::task::Poll<std::io::Result<usize>> {
            let polled = std::pin::Pin::new(&mut self.inner).poll_read(cx, buf);
            if let std::task::Poll::Ready(Ok(n)) = polled {
                self.taken += n;
            }
            polled
        }
    }

    fn read_request_bytes(bytes: Vec<u8>) -> (std::io::Result<SyncRequest>, usize) {
        let mut io = Counted { inner: Cursor::new(bytes), taken: 0 };
        let read = futures::executor::block_on(SyncCodec.read_request(&SYNC_PROTOCOL, &mut io));
        (read, io.taken)
    }

    fn write_then_read_request(req: SyncRequest) -> std::io::Result<SyncRequest> {
        futures::executor::block_on(async {
            let mut out = Cursor::new(Vec::new());
            SyncCodec.write_request(&SYNC_PROTOCOL, &mut out, req).await?;
            SyncCodec.read_request(&SYNC_PROTOCOL, &mut Cursor::new(out.into_inner())).await
        })
    }

    /// A tx of `bytes` serialized bytes, the most a valid one holds at MAX_TX_BYTES.
    fn tx_of(bytes: usize) -> Transaction {
        let c = crate::codec::consensus_bincode();
        let mut tx = block_of(1_000).txs.remove(0);
        tx.inputs[0].script_sig.clear();
        let overhead = c.serialized_size(&tx).unwrap() as usize;
        tx.inputs[0].script_sig = vec![0xAB; bytes - overhead];
        assert_eq!(c.serialized_size(&tx).unwrap() as usize, bytes);
        tx
    }

    /// The largest request of each kind any honest node sends or this node answers, in
    /// `SyncRequest`'s order.
    fn largest_requests() -> Vec<SyncRequest> {
        vec![
            SyncRequest::GetTip,
            SyncRequest::GetHeaders { from_height: u64::MAX, max: u64::MAX },
            SyncRequest::GetHeadersByLocator { locator: vec![[0xAB; 32]; MAX_LOCATOR_LEN], max: u64::MAX },
            SyncRequest::GetBlock { hash: [0xAB; 32] },
            SyncRequest::SubmitTx { tx: tx_of(MAX_TX_BYTES) },
            SyncRequest::GetPeers { max: u16::MAX },
        ]
    }

    // An inbound request is not read into a buffer up to the wire limit whatever its kind, four
    // streams a connection: no request we answer needs more than a 128-hash locator (4,116 bytes)
    // except SubmitTx, which we do not act on.
    #[test]
    fn a_request_is_read_only_up_to_its_kinds_largest_encoding() {
        let flood = SyncRequest::GetHeadersByLocator { locator: vec![[0u8; 32]; 28_000], max: 1 };
        let bytes = crate::codec::consensus_bincode().serialize(&flood).unwrap();
        assert!(bytes.len() > 896_000 && (bytes.len() as u64) < MAX_RR_MSG_BYTES, "fixture under the wire limit");
        let (read, taken) = read_request_bytes(bytes);
        assert!(read.is_err(), "a locator of 28,000 hashes was read");
        let limit = wire(&largest_requests()[2]) as usize;
        assert!(taken <= limit + 1, "{taken} bytes taken for a kind whose largest is {limit}");

        // A request one byte over its kind's largest, and a kind that does not exist.
        for req in largest_requests() {
            let mut over = crate::codec::consensus_bincode().serialize(&req).unwrap();
            over.push(0);
            let (read, taken) = read_request_bytes(over.clone());
            assert!(read.is_err() && taken <= over.len(), "{req:?} plus one byte");
        }
        let (read, taken) = read_request_bytes([6u32.to_le_bytes().to_vec(), vec![0; 1_000]].concat());
        assert!(read.is_err() && taken <= 8, "an unknown kind took {taken} bytes");
    }

    // The paired honest path: the largest request of every kind is read whole, with upstream's
    // largest locator (64 hashes and the zero hash, build_locator at v1.0.0 to main d168f70) and
    // ours, which is the same.
    #[test]
    fn the_largest_request_of_every_kind_is_read() {
        for (tag, req) in largest_requests().into_iter().enumerate() {
            let size = wire(&req);
            assert_eq!(request_limit(tag as u32), Some(size), "{req:?}: its kind's limit is its largest encoding");
            let back = write_then_read_request(req.clone()).unwrap_or_else(|e| panic!("{req:?} ({size} bytes): {e}"));
            assert_eq!(wire(&back), size);
        }
        let upstream_locator = SyncRequest::GetHeadersByLocator { locator: vec![[1u8; 32]; 65], max: MAX_HEADERS_PER_SYNC };
        assert_eq!(wire(&upstream_locator), 2_100);
        assert!(write_then_read_request(upstream_locator).is_ok());
    }
}

#[cfg(test)]
mod publish_retry_tests {
    use super::*;
    use crate::types::{AppPayload, OutPoint, TxIn, TxOut};
    use libp2p::gossipsub::PublishError;

    /// A spend of `[n; 32]:0` whose script_sig is `sig`: the txid leaves `sig` out.
    fn spend(n: u8, sig: Vec<u8>) -> Transaction {
        Transaction {
            version: 1,
            inputs: vec![TxIn { prevout: OutPoint { txid: [n; 32], vout: 0 }, script_sig: sig }],
            outputs: vec![TxOut { value: 1, script_pubkey: [0u8; 20] }],
            locktime: 0,
            app: AppPayload::None,
        }
    }

    fn held_tx(mp: &Mempool, n: u8) -> Hash32 {
        mp.force_insert_for_test(spend(n, vec![]), 1)
    }

    /// The bytes publish_tx queues for `tx`.
    fn gossip_msg(tx: &Transaction) -> Vec<u8> {
        crate::codec::consensus_bincode().serialize(&GossipTx { tx: tx.clone() }).unwrap()
    }

    // A tx retry that checked only that the pool held its txid would be wrong: a txid leaves the
    // script_sigs out (crypto::txid), so when the queued encoding left the pool and another
    // encoding of the same txid was admitted before the next drain, the retry would publish bytes
    // the pool does not hold. The paired honest path: an entry queued as publish_tx queues
    // it goes out once while the pool holds those bytes.
    #[test]
    fn a_tx_retry_leaves_when_the_pool_holds_another_encoding_of_its_txid() {
        let mp = Mempool::new();
        let (a, b) = (spend(1, vec![1]), spend(1, vec![2]));
        assert_eq!(crate::crypto::txid(&a), crate::crypto::txid(&b), "fixture: one txid, two encodings");
        let id = mp.force_insert_for_test(a.clone(), 1);
        let tip = [0u8; 32];
        let mut q = PublishRetry::default();
        q.enqueue(TOPIC_TX, gossip_msg(&a), RetryFor::Tx(id));
        q.drain(&mp, &tip, |_, _| Err(PublishError::Duplicate));
        assert_eq!(q.len(), 1, "the pool holds the queued bytes: the entry stays");

        assert!(mp.remove(&id));
        mp.force_insert_for_test(b.clone(), 1);
        let mut published = Vec::new();
        q.drain(&mp, &tip, |_, bytes| {
            published.push(bytes);
            Ok(())
        });
        assert!(published.is_empty(), "the retry published encoding A while the pool holds encoding B of its txid");
        assert_eq!(q.len(), 0, "an entry whose bytes the pool no longer holds leaves");

        q.enqueue(TOPIC_TX, gossip_msg(&b), RetryFor::Tx(id));
        q.drain(&mp, &tip, |_, bytes| {
            published.push(bytes);
            Ok(())
        });
        assert_eq!((published, q.len()), (vec![gossip_msg(&b)], 0), "the held bytes go out once");
    }

    // A tx published because its gossip check returned late goes out
    // once while it is held; a later late check of it publishes nothing, nor does one whose checked
    // bytes the pool no longer holds. Once the pool drops it, the bound lets it go again. A late
    // accept of bytes a submit or a parked tx already queued takes that entry over, so the one
    // publish counts as the late one.
    #[test]
    fn a_tx_whose_check_returned_late_is_published_once_while_held() {
        let mp = Mempool::new();
        let tx = spend(1, vec![]);
        let id = mp.force_insert_for_test(tx.clone(), 1);
        let msg = gossip_msg(&tx);
        let tip = [0u8; 32];
        let mut q = PublishRetry::default();
        assert!(!q.claim_late(id, &msg, || false), "the pool does not hold the checked bytes");
        assert!(q.claim_late(id, &msg, || true), "the first late check of a held tx");
        q.publish_late(id, msg.clone(), |_| Ok(()));
        assert!(!q.claim_late(id, &msg, || true), "a second late check of the same held tx");
        q.drain(&mp, &tip, |_, _| Ok(()));
        assert!(!q.claim_late(id, &msg, || true), "a tick later, still held");
        assert!(mp.remove(&id));
        q.drain(&mp, &tip, |_, _| Ok(()));
        assert!(q.claim_late(id, &msg, || true), "after the pool dropped it");

        let id = mp.force_insert_for_test(tx, 1);
        q.enqueue(TOPIC_TX, msg.clone(), RetryFor::Tx(id));
        assert!(q.claim_late(id, &msg, || true), "fixture: a late check of bytes a submit queued");
        q.publish_late(id, msg.clone(), |_| Err(PublishError::Duplicate));
        assert_eq!(q.len(), 1, "one entry for one message");
        assert!(!q.claim_late(id, &msg, || true), "queued under the submit's entry: a second late check");
        q.drain(&mp, &tip, |_, _| Ok(()));
        assert!(!q.claim_late(id, &msg, || true), "gone out through the submit's entry: a second late publish");
    }

    // A late check claims its txid, its publish returns Duplicate and it waits in the queue; 256
    // later entries evict it before it goes out. Were the claim to stay while the tx is held, no
    // later late check could queue it again. A late accept is held back while it is queued and
    // once it has gone out, and only then.
    #[test]
    fn a_late_accept_evicted_from_the_queue_before_it_went_out_can_be_queued_again() {
        let mp = Mempool::new();
        let late = spend(0, vec![]);
        let id = mp.force_insert_for_test(late.clone(), 1);
        let msg = gossip_msg(&late);
        let tip = [0u8; 32];
        let mut q = PublishRetry::default();
        assert!(q.claim_late(id, &msg, || true));
        q.publish_late(id, msg.clone(), |_| Err(PublishError::Duplicate));
        assert!(!q.claim_late(id, &msg, || true), "queued: a second late check of the same held tx");
        for n in 1..=PUBLISH_RETRY_MAX_QUEUE as u32 {
            let filler = spend(2, n.to_le_bytes().to_vec());
            q.enqueue(TOPIC_TX, gossip_msg(&filler), RetryFor::Tx(crate::crypto::txid(&filler)));
        }
        assert_eq!(q.len(), PUBLISH_RETRY_MAX_QUEUE, "the queue bound holds");
        assert!(
            q.claim_late(id, &msg, || true),
            "a late accept evicted from the queue before it went out kept its claim: no later late check can queue it while held"
        );
        q.publish_late(id, msg.clone(), |_| Err(PublishError::Duplicate));
        let mut published = 0;
        q.drain(&mp, &tip, |_, bytes| {
            published += usize::from(bytes == msg);
            Ok(())
        });
        assert_eq!(published, 1, "the late accept queued again goes out");
        assert!(!q.claim_late(id, &msg, || true), "gone out: a second late publish while held");
    }

    // A late accept of encoding A waits in the queue; the pool replaces A with a valid B of the
    // same txid (other script_sig bytes) and B's check returns late before the next drain. Were
    // B's claim refused for A's entry, which the drain then drops unsent, B would be held with no
    // publish queued. A queued late accept of bytes the pool no longer holds gives way to a claim
    // of the held bytes; a second claim of those is still held back.
    #[test]
    fn a_late_accept_of_a_replaced_encoding_gives_way_to_one_of_the_held_encoding() {
        let mp = Mempool::new();
        let (a, b) = (spend(1, vec![1]), spend(1, vec![2]));
        let (msg_a, msg_b) = (gossip_msg(&a), gossip_msg(&b));
        let id = mp.force_insert_for_test(a, 1);
        let mut q = PublishRetry::default();
        assert!(q.claim_late(id, &msg_a, || mp.holds_encoding(&id, &msg_a)), "fixture: the late check of A");
        q.publish_late(id, msg_a.clone(), |_| Err(PublishError::Duplicate));
        assert!(!q.claim_late(id, &msg_a, || mp.holds_encoding(&id, &msg_a)), "queued: a second late check of A");
        assert!(mp.remove(&id));
        mp.force_insert_for_test(b, 1);
        assert!(
            q.claim_late(id, &msg_b, || mp.holds_encoding(&id, &msg_b)),
            "B's late check was refused for A's queued late accept, which the next drain drops unsent"
        );
        q.publish_late(id, msg_b.clone(), |_| Err(PublishError::Duplicate));
        assert_eq!(q.len(), 1, "B's late accept took the place of A's");
        assert!(!q.claim_late(id, &msg_b, || mp.holds_encoding(&id, &msg_b)), "queued: a second late check of B");
        let mut published = Vec::new();
        q.drain(&mp, &[0u8; 32], |_, bytes| {
            published.push(bytes);
            Ok(())
        });
        assert_eq!(published, vec![msg_b.clone()], "the held encoding goes out once");
        assert!(!q.claim_late(id, &msg_b, || mp.holds_encoding(&id, &msg_b)), "gone out: a second late publish of B while held");
    }

    // A late accept's own first publish, queued to a peer, retires a submit's queued publish of the
    // same bytes, which would only send them again a minute later; an entry of other bytes stays.
    // Nothing else retires an entry early: an Accept of a received copy reports a cache hit, not a
    // send (`tests/p2p_live_gossip_tx_checks_off_loop.rs` pins
    // that through the p2p loop).
    #[test]
    fn our_own_publish_of_queued_bytes_retires_their_entry() {
        let mp = Mempool::new();
        let (submitted, other) = (spend(1, vec![]), spend(2, vec![]));
        let [submitted_id, other_id] = [&submitted, &other].map(|t| mp.force_insert_for_test(t.clone(), 1));
        let mut q = PublishRetry::default();
        q.enqueue(TOPIC_TX, gossip_msg(&submitted), RetryFor::Tx(submitted_id));
        q.enqueue(TOPIC_TX, gossip_msg(&other), RetryFor::Tx(other_id));
        q.publish_late(submitted_id, gossip_msg(&submitted), |_| Ok(()));
        assert!(!q.claim_late(submitted_id, &gossip_msg(&submitted), || true), "gone out: a second late publish while held");
        let mut published = Vec::new();
        q.drain(&mp, &[0u8; 32], |_, bytes| {
            published.push(bytes);
            Ok(())
        });
        assert_eq!(
            published,
            vec![gossip_msg(&other)],
            "a submit's queued publish outlived a late accept's publish of the same bytes"
        );
    }

    // gossipsub's duplicate cache prunes an expired id only when it records another one, so how
    // long a retry answers Duplicate depends on traffic, not on a timer. A tx entry outlives any
    // fixed count of attempts while the tx is held, and leaves when the tx does.
    #[test]
    fn a_retry_lasts_while_its_tx_is_held_or_its_header_is_the_tip() {
        let mp = Mempool::new();
        let (held, sent) = (held_tx(&mp, 1), held_tx(&mp, 2));
        let (ours, other) = ([7u8; 32], [8u8; 32]);
        let mut q = PublishRetry::default();
        q.enqueue(TOPIC_TX, gossip_msg(&spend(1, vec![])), RetryFor::Tx(held));
        q.enqueue(TOPIC_HDR, vec![2], RetryFor::Header(ours));

        // 100 ticks of Duplicate: more than eight minutes, past any small fixed give-up count.
        for _ in 0..100 {
            q.drain(&mp, &ours, |_, _| Err(PublishError::Duplicate));
        }
        assert_eq!(q.len(), 2, "both entries still matter, so both are still queued");

        // The tx is mined (it leaves the mempool) and the tip moves past our header: both go,
        // and neither is published again.
        mp.remove(&held);
        q.drain(&mp, &other, |topic, _| panic!("re-published a {topic} entry that no longer matters"));
        assert_eq!(q.len(), 0);

        // Honest path: once the cache lets it through, the entry is published once and leaves.
        let msg = gossip_msg(&spend(2, vec![]));
        q.enqueue(TOPIC_TX, msg.clone(), RetryFor::Tx(sent));
        let mut published = Vec::new();
        q.drain(&mp, &other, |_, bytes| {
            published.push(bytes);
            Ok(())
        });
        assert_eq!((published, q.len()), (vec![msg], 0));
    }
}

#[cfg(test)]
mod gossip_wire_tests {
    use super::*;
    use libp2p::gossipsub::{PeerScoreParams, PeerScoreThresholds, PublishError};

    type GossipSwarm = Swarm<gossipsub::Behaviour>;

    /// A swarm with the production transport, gossipsub config and swarm config, subscribed to
    /// the header topic and listening on loopback.
    fn gossip_swarm(cfg: gossipsub::Config) -> GossipSwarm {
        let key = identity::Keypair::generate_ed25519();
        let peer_id = key.public().to_peer_id();
        let gs = gossipsub::Behaviour::new(MessageAuthenticity::Signed(key.clone()), cfg).unwrap();
        let mut swarm = Swarm::new(
            p2p_transport(&key).unwrap(),
            gs,
            peer_id,
            libp2p::swarm::Config::with_tokio_executor(),
        );
        swarm.behaviour_mut().subscribe(&IdentTopic::new(TOPIC_HDR)).unwrap();
        swarm.listen_on("/ip4/127.0.0.1/tcp/0".parse().unwrap()).unwrap();
        swarm
    }

    enum Either {
        A(SwarmEvent<gossipsub::Event>),
        B(SwarmEvent<gossipsub::Event>),
    }

    /// Polls both swarms until `done` returns true or `limit` passes; returns whether it did.
    /// `done` also runs every 100 ms with no event, for state that changes without one.
    async fn drive(
        a: &mut GossipSwarm,
        b: &mut GossipSwarm,
        limit: Duration,
        mut done: impl FnMut(&mut GossipSwarm, &mut GossipSwarm, Option<Either>) -> bool,
    ) -> bool {
        let deadline = tokio::time::Instant::now() + limit;
        let mut tick = interval(Duration::from_millis(100));
        loop {
            let ev = tokio::select! {
                e = a.select_next_some() => Some(Either::A(e)),
                e = b.select_next_some() => Some(Either::B(e)),
                _ = tick.tick() => None,
                _ = tokio::time::sleep_until(deadline) => return false,
            };
            if done(a, b, ev) {
                return true;
            }
        }
    }

    async fn listen_addr(s: &mut GossipSwarm) -> Multiaddr {
        loop {
            if let SwarmEvent::NewListenAddr { address, .. } = s.select_next_some().await {
                return address;
            }
        }
    }

    /// Connects `b` to `a` and waits until each has seen the other subscribe to the header topic.
    async fn connect_subscribed(a: &mut GossipSwarm, b: &mut GossipSwarm) {
        let addr = listen_addr(a).await;
        let _ = listen_addr(b).await;
        b.dial(addr).unwrap();
        let (a_id, b_id) = (*a.local_peer_id(), *b.local_peer_id());
        let (mut a_saw, mut b_saw) = (false, false);
        let ok = drive(a, b, Duration::from_secs(10), |_, _, ev| {
            match ev {
                Some(Either::A(SwarmEvent::Behaviour(gossipsub::Event::Subscribed { peer_id, .. }))) => {
                    a_saw |= peer_id == b_id
                }
                Some(Either::B(SwarmEvent::Behaviour(gossipsub::Event::Subscribed { peer_id, .. }))) => {
                    b_saw |= peer_id == a_id
                }
                _ => {}
            }
            a_saw && b_saw
        })
        .await;
        assert!(ok, "setup: the two swarms did not connect and subscribe");
    }

    fn header_like(tag: u32) -> Vec<u8> {
        let mut v = vec![0u8; 120];
        v[..4].copy_from_slice(&tag.to_le_bytes());
        v
    }

    /// A publishes six heartbeats of 300 header-sized messages (the catch-up shape) with B
    /// subscribed outside its mesh, then one probe; returns whether B received the probe.
    async fn probe_reaches_non_mesh_peer_after_burst(
        sender: gossipsub::Config,
        receiver: gossipsub::Config,
    ) -> bool {
        let mut a = gossip_swarm(sender);
        let mut b = gossip_swarm(receiver);
        // Peer scoring is only this test's way to hold B outside A's mesh (a mesh needs a score of
        // at least 0) while B still gets IHAVE (above gossip_threshold -10) and A's own publishes
        // (above publish_threshold -50). Production runs without scoring and has non-mesh peers
        // once it holds more than mesh_n_high of them.
        a.behaviour_mut()
            .with_peer_score(PeerScoreParams::default(), PeerScoreThresholds::default())
            .unwrap();
        connect_subscribed(&mut a, &mut b).await;
        let b_id = *b.local_peer_id();
        assert!(a.behaviour_mut().set_application_score(&b_id, -0.5), "setup: A does not score B");
        let topic = IdentTopic::new(TOPIC_HDR);
        let hash = topic.hash();
        let out_of_mesh = drive(&mut a, &mut b, Duration::from_secs(10), |a, _, _| {
            !a.behaviour().mesh_peers(&hash).any(|p| *p == b_id)
        })
        .await;
        assert!(out_of_mesh, "setup: B stayed in A's mesh");

        let mut tag = 0u32;
        for _ in 0..6 {
            for _ in 0..300 {
                tag += 1;
                a.behaviour_mut().publish(topic.clone(), header_like(tag)).unwrap();
            }
            drive(&mut a, &mut b, Duration::from_millis(1100), |_, _, _| false).await;
        }

        let probe = header_like(u32::MAX);
        a.behaviour_mut().publish(topic.clone(), probe.clone()).unwrap();
        drive(&mut a, &mut b, Duration::from_secs(10), |_, _, ev| {
            matches!(ev, Some(Either::B(SwarmEvent::Behaviour(gossipsub::Event::Message { ref message, .. })))
                if message.data == probe)
        })
        .await
    }

    // Both directions of the 16 KiB control limit (MAX_GOSSIP_IDS_PER_CONTROL and
    // MAX_GOSSIP_CONTROL_BYTES_RECEIVED): our IHAVE must fit a receiver on upstream's default, and
    // our receiver must take the IHAVE a gossipsub 0.48 node sends (no control limit,
    // truncation at 5000 ids, the same one-IHAVE-per-heartbeat shape).
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_catch_up_burst_keeps_gossip_flowing_to_a_peer_outside_the_mesh() {
        let mut upstream_receiver = gossipsub::ConfigBuilder::from(gossipsub_config());
        upstream_receiver.max_control_message_size(16 * 1024);
        let mut v0114_sender = gossipsub::ConfigBuilder::from(gossipsub_config());
        v0114_sender.max_control_messages_sent(5000);
        let (ours_to_upstream, v0114_to_ours) = tokio::join!(
            probe_reaches_non_mesh_peer_after_burst(gossipsub_config(), upstream_receiver.build().unwrap()),
            probe_reaches_non_mesh_peer_after_burst(v0114_sender.build().unwrap(), gossipsub_config()),
        );
        assert!(ours_to_upstream, "a receiver on the 16 KiB default stopped taking our gossip after a burst");
        assert!(v0114_to_ours, "this node stopped taking a 0.1.14 peer's gossip after its burst");
    }

    // gossipsub 0.47 (upstream v1.1.2's) has an unbounded per-connection send queue, a memory leak
    // under a stalled peer, fixed by 0.48's bounded one. In 0.50.1 it is one data queue of
    // connection_handler_queue_len (queue.rs:36-84, behaviour.rs:3431), and publish reports
    // AllQueuesFull once every recipient's queue is full (behaviour.rs:736-737).
    // B is connected and subscribed but never polled again, so nothing it is sent is read.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_peer_that_stops_reading_fills_a_bounded_queue() {
        let cfg = gossipsub_config();
        let queue_len = cfg.connection_handler_queue_len();
        let mut a = gossip_swarm(cfg);
        let mut b = gossip_swarm(gossipsub_config());
        connect_subscribed(&mut a, &mut b).await;
        let topic = IdentTopic::new(TOPIC_HDR);

        // What the stalled connection can absorb before the queue: one yamux stream window
        // (256 KiB) of 1 KiB messages, plus the codec's write buffer.
        let in_flight_allowance = 1_000;
        let attempts: u32 = 20_000;
        let mut full_at = None;
        for i in 0..attempts {
            let mut data = vec![0u8; 1024];
            data[..4].copy_from_slice(&i.to_le_bytes());
            match a.behaviour_mut().publish(topic.clone(), data) {
                Ok(_) => {}
                Err(PublishError::AllQueuesFull(_)) => {
                    full_at = Some(i as usize);
                    break;
                }
                Err(e) => panic!("publish {i}: {e:?}"),
            }
            // Let A's connection task drain what it can into the stalled stream.
            if i % 100 == 0 {
                let _ = tokio::time::timeout(Duration::from_millis(5), a.select_next_some()).await;
            }
        }
        let full_at = full_at.unwrap_or_else(|| {
            panic!("{attempts} publishes to a peer that stopped reading were all queued: the send queue is not bounded")
        });
        assert!(
            full_at <= queue_len.saturating_add(in_flight_allowance),
            "the queue refused only at publish {full_at}, past its length {queue_len} plus {in_flight_allowance} in flight"
        );
        assert!(full_at >= queue_len, "the queue refused at publish {full_at}, before holding its length {queue_len}");
        drop(b);
    }
}
