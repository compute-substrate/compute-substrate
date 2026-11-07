// src/api/mod.rs

use axum::{
    extract::{Path, Query, State},
    http::{header::RETRY_AFTER, StatusCode},
    response::{IntoResponse, Response},
    routing::{get, post},
    Json, Router,
};

use serde::{Deserialize, Serialize};
use std::sync::Arc;

use std::collections::HashMap;

use libp2p::PeerId;
use crate::chain::index::{get_hidx, HeaderIndex};
use crate::crypto::{sighash, txid};
use crate::net::mempool::{Mempool, MempoolStats};
use crate::net::GossipTxEvent;
use crate::state::app_state::{get_proposal, get_topk, k_proposal, Attestation, Proposal};
use crate::state::db::{get_tip, k_block, Stores};
use crate::types::{AppPayload, Block, Hash32, OutPoint, Transaction, TxOut};
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use crate::params::GENESIS_HASH;

fn c() -> crate::codec::ConsensusBincode {
    crate::codec::consensus_bincode()
}

#[derive(Clone)]
pub struct ApiState {
    pub db: Arc<Stores>,
    pub mempool: Arc<Mempool>,
    // IMPORTANT: must be GossipTxEvent so node.rs can publish it to gossipsub
    pub tx_gossip: tokio::sync::mpsc::UnboundedSender<GossipTxEvent>,
pub connected_peers: Arc<AtomicUsize>,
// peers we dialed; see net::node::store_outbound_gauge.
pub outbound_peers: Arc<AtomicUsize>,
pub known_peers: Arc<AtomicUsize>,
pub peer_id: PeerId,
// the two p2p gauges /health needs to answer "is this node actually
// keeping up", instead of every consumer inferring it from wall-clock tip staleness.
pub best_peer_height: Arc<AtomicU64>,
pub last_tip_activity_unix: Arc<AtomicU64>,
}

#[derive(Serialize)]
struct TipResp {
    tip: String,
    height: u64,
    chainwork: String,
}

#[derive(Serialize)]
struct HealthResp {
    pub ok: bool,
    pub tip: String,
    pub height: u64,
    pub chainwork: String,
pub peer_count: usize,
pub known_peers: usize,
    pub mempool_tx_count: usize,
    pub mempool_spent_outpoints: usize,
    pub mempool_bytes: usize,
    pub mempool_min_feerate_ppm: Option<u64>,
    pub mempool_max_feerate_ppm: Option<u64>,
    // Additive only. Nothing above changed name, type or position, so
    // every existing consumer keeps parsing this response unchanged. Deliberately no version or
    // build string here: /health is the route a reverse proxy may expose to the public internet,
    // and the build identity belongs on the operator-only /node/info route below.
    /// Highest height any connected peer has advertised, or null when no peer has answered yet.
    ///
    /// These three are OPTION ON PURPOSE. Reporting 0 for "unknown" is what makes a peerless
    /// node that has just restarted look identical, on exactly the fields meant to detect it, to
    /// a perfectly synced one: no peers means best_peer_height 0, so blocks_behind 0, and no
    /// observed tip activity means an age of 0. A monitor written against these fields would
    /// read "0 behind, 0 seconds since activity" and see health. null cannot be mistaken for
    /// healthy, and it is JSON-additive, so no existing consumer breaks.
    pub best_peer_height: Option<u64>,
    /// best_peer_height - height, i.e. how far this node is behind the network it can see.
    /// null when no peer has advertised a height yet.
    pub blocks_behind: Option<u64>,
    /// Seconds since the p2p loop last observed tip activity, or null if it never has. Same
    /// signal the miner gate uses; a node whose RPC answers while this climbs is the wedge shape.
    pub secs_since_tip_activity: Option<u64>,
}

/// Build identity plus the same liveness gauges, for an operator's monitoring and
/// triage: one curl tells you which binary is answering, whether it is keeping up, and
/// whether its txid index is converged. Kept off /health on purpose, because /health may be
/// reverse-proxied publicly and the exact build string is not something to advertise there.
/// The RPC listener binds loopback by default; a reverse proxy in front of the RPC should not
/// forward this path.
#[derive(Serialize)]
struct NodeInfoResp {
    pub ok: bool,
    pub version: String,
    pub peer_id: String,
    pub height: u64,
    pub best_peer_height: Option<u64>,
    pub blocks_behind: Option<u64>,
    pub secs_since_tip_activity: Option<u64>,
    pub tx_index_converged: bool,
    pub peer_count: usize,
    pub known_peers: usize,
    /// Liveness of the long-lived background tasks. A panicked p2p loop or reconciler leaves the
    /// process up and the RPC answering, so without this the only symptom is a tip that quietly
    /// stops moving.
    pub subsystems: serde_json::Value,
    /// Additive. Panics since process start, from the process-wide hook.
    /// Includes panics no subsystem slot can see (libp2p connection tasks, RPC handlers).
    pub panic_count: u64,
    /// Additive. Connected peers we dialed. Over-counts while a dialer
    /// connection lingers: a peer leaves the set only when its last connection closes.
    pub outbound_peers: u64,
    /// Additive. peer_count minus outbound_peers.
    pub inbound_peers: u64,
    /// Additive. `bad:` marks: block hashes this node will not reorg
    /// through until the next restart's rebuild. Null when the count cannot be read.
    pub bad_block_marks: Option<u64>,
    /// Additive. Stored block bodies dropped since process start because
    /// they repeat a txid or carry a failing signature, which another body with the same hash
    /// need not (`chain::body_fault`).
    pub dropped_block_bodies: u64,
}

#[derive(Serialize)]
struct P2pInfoResp {
    pub ok: bool,
    pub peer_id: String,
    pub peer_count: usize,
    pub known_peers: usize,
}

#[derive(Serialize)]
struct MetricsResp {
    pub ok: bool,
    pub tip: String,
    pub height: u64,
    pub chainwork: String,
pub peer_count: usize,
pub known_peers: usize,
    pub mempool_tx_count: usize,
    pub mempool_spent_outpoints: usize,
    pub mempool_bytes: usize,
    pub mempool_min_feerate_ppm: Option<u64>,
    pub mempool_max_feerate_ppm: Option<u64>,
}

#[derive(Serialize)]
struct OracleResp {
    pub ok: bool,
    pub tip: String,
    pub height: u64,
    pub chainwork: String,
    pub peer_count: usize,
    pub connected: bool,
    pub last_block_age_s: u64,
    pub healthy: bool,
    pub advancing: bool,
}

#[derive(Serialize)]
pub struct DomainItem {
    pub domain: String,
    pub proposals: u64,
    pub attestations: u64,
}

#[derive(Serialize)]
pub struct DomainsResp {
    pub ok: bool,
    pub tip: String,
    pub height: u64,
    pub count: usize,
    pub domains: Vec<DomainItem>,
}

#[derive(Deserialize)]
pub struct TxSubmitReq {
    pub tx: Transaction,
}

#[derive(Serialize)]
pub struct TxSubmitResp {
    pub ok: bool,
    pub txid: String,
    pub mempool_len: usize,
    pub err: Option<String>,
}

#[derive(Serialize)]
pub struct WindowResp {
    pub tip: String,
    pub height: u64,
    pub epoch: u64,
    pub top: Vec<serde_json::Value>,
}

#[derive(Serialize)]
pub struct UtxoItem {
    pub txid: String,
    pub vout: u32,
    pub value: u64,
    pub height: u64,
    pub confirmations: u64,
    pub coinbase: bool,
}

#[derive(Serialize)]
pub struct UtxosResp {
    pub ok: bool,
    pub addr20: String,
    pub count: usize,
    pub confirmed_balance: u64,
    /// Null unless the request asked `?lifetime=true`; capped at u64::MAX, which an address's
    /// coinbases can pass (docs/behaviour.md "The address index", lifetime totals).
    pub mined_lifetime: Option<u64>,
    pub mined_unspent: u64,
    pub coinbase_lifetime_outputs: Option<u64>,
    pub coinbase_unspent_outputs: u64,
    pub utxos: Vec<UtxoItem>,
    /// The tip the answer was read at ("0x" and 64 hex digits); null when `ok` is false or the
    /// node has no tip. A read racing a block's apply can still mix the two states.
    pub tip: Option<String>,
}

#[derive(Serialize)]
pub struct AddressActivityItem {
    pub kind: String,
    pub txid: String,
    pub block_hash: String,
    pub height: u64,
    pub time: u64,
    pub value_delta: i128,
    pub domain: Option<String>,
    pub proposal_id: Option<String>,
    pub payload_hash: Option<String>,
    pub uri: Option<String>,
}

#[derive(Serialize)]
pub struct AddressActivityResp {
    pub ok: bool,
    pub addr20: String,
    pub count: usize,
    pub proposals_created: u64,
    pub attestations_submitted: u64,
    pub total_fees_paid: u64,
    pub activity: Vec<AddressActivityItem>,
}

#[derive(Deserialize, Default)]
pub struct AddressActivityQuery {
    pub limit: Option<usize>,
    pub include_mined: Option<bool>,
}

#[derive(Deserialize, Default)]
pub struct UtxosQuery {
    pub available: Option<bool>,
    pub min_value: Option<u64>,
    pub smallest: Option<bool>,
    pub limit: Option<usize>,
    pub lifetime: Option<bool>,
}

#[derive(Serialize)]
pub struct BlockResp {
    pub ok: bool,
    pub hash: String,
    pub height: Option<u64>,
    pub chainwork: Option<String>,
    pub header: serde_json::Value,
    pub txs: Vec<serde_json::Value>,
}

#[derive(Serialize)]
pub struct TxResp {
    pub ok: bool,
    pub txid: String,
    pub block_hash: Option<String>,
    pub height: Option<u64>,
    pub time: Option<u64>,
    pub tx: Option<serde_json::Value>,
    pub err: Option<String>,
    // Set only on a proved absence (walked to genesis, or a fresh txid index
    // answered). Skipped otherwise so a Found response stays byte-identical to upstream's.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub complete: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub scanned: Option<u64>,
}

#[derive(Serialize)]
pub struct TopGlobalItem {
    pub proposal_id: String,
    pub economic_weight: u128,
    pub domain: String,
    pub payload_hash: String,
    pub uri: String,
    pub expires_epoch: u64,
}

// ===========================
// Recent blocks feed structs
// ===========================

#[derive(Serialize)]
pub struct RecentBlockItem {
    pub height: u64,
    pub hash: String,
    pub prev: String,
    pub time: u64,
    pub txs: usize,
}

#[derive(Serialize)]
pub struct RecentBlocksResp {
    pub ok: bool,
    pub tip: String,
    pub height: u64,
    pub scanned_blocks: u64,
    pub count: usize,
    pub blocks: Vec<RecentBlockItem>,
}

// ===========================
// Tx template structs
// ===========================

#[derive(Deserialize)]
pub struct TxTemplateProposeReq {
    /// Base tx with inputs/outputs/locktime chosen by client.
    /// Must have app=None and empty script_sig for signing.
    pub tx: Transaction,
    pub domain: String,
    /// 0x-prefixed 32-byte hex
    pub payload_hash: String,
    pub uri: String,
    pub expires_epoch: u64,
}

#[derive(Deserialize)]
pub struct TxTemplateAttestReq {
    pub tx: Transaction,
    /// 0x-prefixed 32-byte hex
    pub proposal_id: String,
    pub score: u32,
    pub confidence: u32,
}

#[derive(Serialize)]
pub struct TxTemplateResp {
    pub ok: bool,
    pub unsigned_txid: String,
    pub signing_hash: String,
    pub unsigned_tx: Transaction,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub note: Option<String>,
}

// ===========================
// Recent proposals feed structs
// ===========================

#[derive(Serialize)]
pub struct RecentProposalItem {
    pub proposal_id: String,
    pub txid: String,
    pub block_hash: String,
    pub height: u64,
    pub time: u64,
    pub domain: String,
    pub payload_hash: String,
    pub uri: String,
    pub expires_epoch: u64,
}

#[derive(Serialize)]
pub struct RecentProposalsResp {
    pub ok: bool,
    pub tip: String,
    pub height: u64,
    pub scanned_blocks: u64,
    pub count: usize,
    pub proposals: Vec<RecentProposalItem>,
}

// ===========================
// Recent attestations feed structs
// ===========================

#[derive(Default, Clone)]
struct AttStats {
    count: u64,
    score_sum: u64,
    conf_sum: u64,
}

#[derive(Serialize)]
pub struct RecentAttestedItem {
    pub proposal_id: String,
    pub attest_count: u64,
    pub score_sum: u64,
    pub confidence_sum: u64,
    pub domain: String,
    pub payload_hash: String,
    pub uri: String,
    pub expires_epoch: u64,
}

#[derive(Serialize)]
pub struct RecentAttestedResp {
    pub ok: bool,
    pub tip: String,
    pub height: u64,
    pub scanned_blocks: u64,
    pub count: usize,
    pub items: Vec<RecentAttestedItem>,
}

#[allow(clippy::too_many_arguments)]
pub fn router(
    db: Arc<Stores>,
    mempool: Arc<Mempool>,
    tx_gossip: tokio::sync::mpsc::UnboundedSender<GossipTxEvent>,
connected_peers: Arc<AtomicUsize>,
outbound_peers: Arc<AtomicUsize>,
known_peers: Arc<AtomicUsize>,
peer_id: PeerId,
best_peer_height: Arc<AtomicU64>,
last_tip_activity_unix: Arc<AtomicU64>,
) -> Router {
    let st = ApiState {
        db,
        mempool,
        tx_gossip,
connected_peers,
outbound_peers,
known_peers,
peer_id,
best_peer_height,
last_tip_activity_unix,
    };

    Router::new()
        .route("/health", get(health))
        .route("/node/info", get(node_info))
        .route("/peers", get(peers))
.route("/p2p/info", get(p2p_info))
        .route("/metrics", get(metrics))
        .route("/oracle", get(oracle))
        .route("/tip", get(tip))
        .route("/mempool", get(mempool_info))
        .route("/mempool/txids", get(mempool_txids))
        // Explorer-grade read endpoints:
.route("/block/height/:height", get(block_by_height_get))
        .route("/block/:hash", get(block_get))
        .route("/tx/:id", get(tx_get))
//tx proof endpoint for authorization object
.route("/proof/tx/:txid", get(tx_proof_get))
        .route("/utxos/:addr20", get(utxos_for_addr20))

.route("/address/:addr20/activity", get(address_activity_get))

        // Recent blocks:
        .route("/recent/blocks/:limit", get(recent_blocks))
        // Recent computations:
        .route("/recent/proposals/:limit", get(recent_proposals))
        .route(
            "/recent/proposals/:domain/:limit",
            get(recent_proposals_by_domain),
        )

        .route("/proposals/:limit", get(all_proposals))
        .route("/proposals/:domain/:limit", get(all_proposals_by_domain))
    
        .route("/recent/attestations/:limit", get(most_attested_global))
        .route(
            "/recent/attestations/:domain/:limit",
            get(most_attested_by_domain),
        )
        // Computation window:
        .route("/window/:domain", get(window_domain))
        .route("/top/global", get(top_global))
        .route("/top/active", get(top_active))
        .route("/top/all-time", get(top_all_time))
        .route("/top/:domain", get(top_current))
        .route("/top/:domain/:epoch", get(top_epoch))

        // Canonical app endpoints:
        .route("/proposal/:id", get(proposal_get))
        .route("/topk/:epoch/:domain", get(topk_get))
        .route("/domains", get(domains_list))
        // Tx template helpers (public attestation surface):
        .route("/tx/template/propose", post(tx_template_propose))
        .route("/tx/template/attest", post(tx_template_attest))
        // Optional write endpoint:
        .route("/tx/submit", post(tx_submit))
        .with_state(st)

}

async fn health(State(st): State<ApiState>) -> Json<HealthResp> {
    Json(health_resp(&st, &crate::state::subsystem::SUBSYSTEMS))
}

/// `ok` is false while a long-lived task (p2p, the txid reconciler, the miner) has exited or
/// panicked: the RPC keeps answering after one dies, with a frozen tip when it is p2p. The status
/// stays 200, so a monitor that checks only the status sees no change; /node/info names the task.
fn health_resp(st: &ApiState, subsystems: &crate::state::subsystem::Subsystems) -> HealthResp {
    // No unwrap on the db reads: a malformed meta:tip or an undecodable header would panic the
    // handler and drop the connection on the one endpoint every monitor polls. Degrade to the
    // zero tip, exactly as the pre-existing zero_hidx fallback already does one line down.
    let tip = get_tip(&st.db).ok().flatten().unwrap_or([0u8; 32]);
    let hi = get_hidx(&st.db, &tip)
        .ok()
        .flatten()
        .unwrap_or_else(|| zero_hidx(tip));

    let s: MempoolStats = st.mempool.stats();

    let best_peer_height = st.best_peer_height.load(Ordering::Relaxed);
    let last_activity = st.last_tip_activity_unix.load(Ordering::Relaxed);
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);

    HealthResp {
        ok: subsystems.all_healthy(),
        tip: format!("0x{}", hex::encode(tip)),
        height: hi.height,
        chainwork: hi.chainwork.to_string(),
  peer_count: st.connected_peers.load(Ordering::Relaxed),
known_peers: st.known_peers.load(Ordering::Relaxed),
        mempool_tx_count: s.txs,
        mempool_spent_outpoints: s.spent_len,
        mempool_bytes: s.total_bytes,
        mempool_min_feerate_ppm: s.min_feerate_ppm,
        mempool_max_feerate_ppm: s.max_feerate_ppm,
        best_peer_height: (best_peer_height > 0).then_some(best_peer_height),
        blocks_behind: (best_peer_height > 0).then(|| best_peer_height.saturating_sub(hi.height)),
        secs_since_tip_activity: (last_activity > 0).then(|| now.saturating_sub(last_activity)),
    }
}

async fn node_info(State(st): State<ApiState>) -> Json<NodeInfoResp> {
    let tip = get_tip(&st.db).ok().flatten().unwrap_or([0u8; 32]);
    let height = get_hidx(&st.db, &tip)
        .ok()
        .flatten()
        .map(|hi| hi.height)
        .unwrap_or(0);

    let best_peer_height = st.best_peer_height.load(Ordering::Relaxed);
    let last_activity = st.last_tip_activity_unix.load(Ordering::Relaxed);
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);

    let peers = st.connected_peers.load(Ordering::Relaxed);
    let outbound = st.outbound_peers.load(Ordering::Relaxed);

    Json(NodeInfoResp {
        ok: true,
        version: env!("CARGO_PKG_VERSION").to_string(),
        peer_id: st.peer_id.to_string(),
        height,
        best_peer_height: (best_peer_height > 0).then_some(best_peer_height),
        blocks_behind: (best_peer_height > 0).then(|| best_peer_height.saturating_sub(height)),
        secs_since_tip_activity: (last_activity > 0).then(|| now.saturating_sub(last_activity)),
        // Index state stays HERE and not on /health: a reverse proxy may expose /health to
        // the public internet, and this field announces in real time when this node's absence
        // answers are degraded to 503 SCAN_HORIZON rather than proved, which is a free
        // restart-timing and degraded-mode oracle for anyone who can reach it.
        tx_index_converged: crate::state::tx_scan::idx_fresh(&st.db),
        peer_count: peers,
        known_peers: st.known_peers.load(Ordering::Relaxed),
        subsystems: crate::state::subsystem::SUBSYSTEMS.report(),
        panic_count: crate::state::subsystem::PANIC_COUNT.load(Ordering::Relaxed),
        outbound_peers: outbound as u64,
        inbound_peers: peers.saturating_sub(outbound) as u64,
        bad_block_marks: crate::state::db::bad_mark_count(&st.db).ok().map(|n| n as u64),
        dropped_block_bodies: crate::state::db::DROPPED_BLOCK_BODIES.load(Ordering::Relaxed),
    })
}

async fn metrics(State(st): State<ApiState>) -> Json<MetricsResp> {
    let tip = get_tip(&st.db).unwrap().unwrap_or([0u8; 32]);
    let hi = get_hidx(&st.db, &tip)
        .unwrap()
        .unwrap_or_else(|| zero_hidx(tip));

    let s: MempoolStats = st.mempool.stats();

    Json(MetricsResp {
        ok: true,
        tip: format!("0x{}", hex::encode(tip)),
        height: hi.height,
        chainwork: hi.chainwork.to_string(),
        peer_count: st.connected_peers.load(Ordering::Relaxed),
        known_peers: st.known_peers.load(Ordering::Relaxed),
        mempool_tx_count: s.txs,
        mempool_spent_outpoints: s.spent_len,
        mempool_bytes: s.total_bytes,
        mempool_min_feerate_ppm: s.min_feerate_ppm,
        mempool_max_feerate_ppm: s.max_feerate_ppm,
    })
}

async fn oracle(State(st): State<ApiState>) -> Json<OracleResp> {
    use crate::params::TARGET_BLOCK_SECS;
    use std::time::{SystemTime, UNIX_EPOCH};

    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();

    let tip = get_tip(&st.db).unwrap().unwrap_or([0u8; 32]);
    let hi = get_hidx(&st.db, &tip)
        .unwrap()
        .unwrap_or_else(|| zero_hidx(tip));

    // Prefer actual tip block header time; fall back to header index time.
    let last_block_time = if let Some(v) = st.db.blocks.get(k_block(&tip)).unwrap() {
        match c().deserialize::<Block>(&v) {
            Ok(blk) => blk.header.time,
            Err(_) => hi.time,
        }
    } else {
        hi.time
    };

    let last_block_age_s = now.saturating_sub(last_block_time);

    // TARGET_BLOCK_SECS (120 s): healthy up to 360 s, advancing up to 720 s.
    let healthy_max = 3 * TARGET_BLOCK_SECS;
    let advancing_max = 6 * TARGET_BLOCK_SECS;

    let healthy = last_block_age_s <= healthy_max;
    let advancing = last_block_age_s <= advancing_max;

    let peer_count = st.connected_peers.load(Ordering::Relaxed);
    let connected = peer_count >= 3;

    Json(OracleResp {
        ok: true,
        tip: format!("0x{}", hex::encode(tip)),
        height: hi.height,
        chainwork: hi.chainwork.to_string(),
        peer_count,
        connected,
        last_block_age_s,
        healthy,
        advancing,
    })
}

fn zero_hidx(tip: Hash32) -> HeaderIndex {
    HeaderIndex {
        hash: tip,
        parent: [0u8; 32],
        height: 0,
        chainwork: 0,
        bits: 0,
        time: 0,
    }
}


fn app_payload_json(app: &AppPayload) -> serde_json::Value {
    match app {
        AppPayload::None => serde_json::json!({
            "type": "None"
        }),

        AppPayload::Propose {
            domain,
            payload_hash,
            uri,
            expires_epoch,
        } => serde_json::json!({
            "type": "Propose",
            "domain": domain,
            "payload_hash": format!("0x{}", hex::encode(payload_hash)),
            "uri": uri,
            "expires_epoch": expires_epoch
        }),

        AppPayload::Attest {
            proposal_id,
            score,
            confidence,
        } => serde_json::json!({
            "type": "Attest",
            "proposal_id": format!("0x{}", hex::encode(proposal_id)),
            "score": score,
            "confidence": confidence
        }),
    }
}

fn parse_hash32(s: &str) -> Result<Hash32, String> {
    let s = s.trim().strip_prefix("0x").unwrap_or(s.trim());
    let bytes = hex::decode(s).map_err(|_| "bad hex".to_string())?;
    if bytes.len() != 32 {
        return Err("hash must be 32 bytes".to_string());
    }
    let mut out = [0u8; 32];
    out.copy_from_slice(&bytes);
    Ok(out)
}

async fn peers(State(st): State<ApiState>) -> Json<serde_json::Value> {
    Json(serde_json::json!({
        "ok": true,
        "peer_count": st.connected_peers.load(Ordering::Relaxed),
 "known_peers": st.known_peers.load(Ordering::Relaxed),
    }))
}

async fn p2p_info(State(st): State<ApiState>) -> Json<P2pInfoResp> {
    Json(P2pInfoResp {
        ok: true,
        peer_id: st.peer_id.to_string(),
        peer_count: st.connected_peers.load(Ordering::Relaxed),
known_peers: st.known_peers.load(Ordering::Relaxed),
    })
}

async fn top_active(State(st): State<ApiState>) -> Response {
    offload_display(move || top_active_blocking(st).into_response()).await
}

fn top_active_blocking(st: ApiState) -> Json<serde_json::Value> {
    use std::collections::HashMap;

    #[derive(Default)]
    struct ActiveStats {
        attest_count: u64,
        economic_weight: u128,
        raw_score_sum: u64,
        raw_confidence_sum: u64,
    }

    let tip = get_tip(&st.db).unwrap().unwrap_or([0u8; 32]);
    let hi = get_hidx(&st.db, &tip)
        .unwrap()
        .unwrap_or_else(|| zero_hidx(tip));

    let current_epoch = crate::state::app_state::epoch_of(hi.height);

    let mut stats: HashMap<Hash32, ActiveStats> = HashMap::new();

    for item in st.db.app.iter() {
        let Ok((k, v)) = item else { continue };

        if k.len() != 1 + 32 || k[0] != b'A' {
            continue;
        }

        let att: Attestation = match c().deserialize(&v) {
            Ok(a) => a,
            Err(_) => continue,
        };

        let Some(pv) = st.db.app.get(k_proposal(&att.proposal_id)).unwrap() else {
            continue;
        };

        let prop: Proposal = match c().deserialize(&pv) {
            Ok(p) => p,
            Err(_) => continue,
        };

        if current_epoch > prop.expires_epoch {
            continue;
        }

        let e = stats.entry(att.proposal_id).or_default();
        e.attest_count = e.attest_count.saturating_add(1);
        e.economic_weight = e.economic_weight.saturating_add(att.weight as u128);
        e.raw_score_sum = e.raw_score_sum.saturating_add(att.score as u64);
        e.raw_confidence_sum = e.raw_confidence_sum.saturating_add(att.confidence as u64);
    }

    let mut out: Vec<serde_json::Value> = vec![];

    for (pid, s) in stats {
        if s.economic_weight == 0 {
            continue;
        }

        let Some(v) = st.db.app.get(k_proposal(&pid)).unwrap() else {
            continue;
        };

        let prop: Proposal = match c().deserialize(&v) {
            Ok(p) => p,
            Err(_) => continue,
        };

        if current_epoch > prop.expires_epoch {
            continue;
        }

        out.push(serde_json::json!({
            "proposal_id": format!("0x{}", hex::encode(pid)),
            "domain": prop.domain,
            "economic_weight": s.economic_weight,
            "attest_count": s.attest_count,
            "raw_score_sum": s.raw_score_sum,
            "raw_confidence_sum": s.raw_confidence_sum,
            "payload_hash": format!("0x{}", hex::encode(prop.payload_hash)),
            "uri": prop.uri,
            "created_epoch": prop.created_epoch,
            "expires_epoch": prop.expires_epoch
        }));
    }

    out.sort_by(|a, b| {
        let aw = a["economic_weight"].as_u64().unwrap_or(0);
        let bw = b["economic_weight"].as_u64().unwrap_or(0);

        bw.cmp(&aw)
            .then_with(|| {
                let ac = a["attest_count"].as_u64().unwrap_or(0);
                let bc = b["attest_count"].as_u64().unwrap_or(0);
                bc.cmp(&ac)
            })
            .then_with(|| {
                let ap = a["proposal_id"].as_str().unwrap_or("");
                let bp = b["proposal_id"].as_str().unwrap_or("");
                ap.cmp(bp)
            })
    });

    out.truncate(50);

    Json(serde_json::json!({
        "ok": true,
        "tip": format!("0x{}", hex::encode(tip)),
        "height": hi.height,
        "current_epoch": current_epoch,
        "top": out
    }))
}

async fn top_all_time(State(st): State<ApiState>) -> Response {
    offload_display(move || top_all_time_blocking(st).into_response()).await
}

fn top_all_time_blocking(st: ApiState) -> Json<serde_json::Value> {
    use std::collections::HashMap;

    #[derive(Default)]
    struct AllTimeStats {
        attest_count: u64,
        economic_weight: u128,
        raw_score_sum: u64,
        raw_confidence_sum: u64,
    }

    let tip = get_tip(&st.db).unwrap().unwrap_or([0u8; 32]);
    let hi = get_hidx(&st.db, &tip)
        .unwrap()
        .unwrap_or_else(|| zero_hidx(tip));

    let mut stats: HashMap<Hash32, AllTimeStats> = HashMap::new();

    for item in st.db.app.iter() {
        let Ok((k, v)) = item else { continue };

        if k.len() != 1 + 32 || k[0] != b'A' {
            continue;
        }

        let att: Attestation = match c().deserialize(&v) {
            Ok(a) => a,
            Err(_) => continue,
        };

        let e = stats.entry(att.proposal_id).or_default();
        e.attest_count = e.attest_count.saturating_add(1);
        e.economic_weight = e.economic_weight.saturating_add(att.weight as u128);
        e.raw_score_sum = e.raw_score_sum.saturating_add(att.score as u64);
        e.raw_confidence_sum = e.raw_confidence_sum.saturating_add(att.confidence as u64);
    }

    let mut out: Vec<serde_json::Value> = vec![];

    for (pid, s) in stats {
        if s.economic_weight == 0 {
            continue;
        }

        let Some(v) = st.db.app.get(k_proposal(&pid)).unwrap() else {
            continue;
        };

        let prop: Proposal = match c().deserialize(&v) {
            Ok(p) => p,
            Err(_) => continue,
        };

        out.push(serde_json::json!({
            "proposal_id": format!("0x{}", hex::encode(pid)),
            "domain": prop.domain,
            "economic_weight": s.economic_weight,
            "attest_count": s.attest_count,
            "raw_score_sum": s.raw_score_sum,
            "raw_confidence_sum": s.raw_confidence_sum,
            "payload_hash": format!("0x{}", hex::encode(prop.payload_hash)),
            "uri": prop.uri,
            "created_epoch": prop.created_epoch,
            "expires_epoch": prop.expires_epoch
        }));
    }

    out.sort_by(|a, b| {
        let aw = a["economic_weight"].as_u64().unwrap_or(0);
        let bw = b["economic_weight"].as_u64().unwrap_or(0);

        bw.cmp(&aw)
            .then_with(|| {
                let ac = a["attest_count"].as_u64().unwrap_or(0);
                let bc = b["attest_count"].as_u64().unwrap_or(0);
                bc.cmp(&ac)
            })
            .then_with(|| {
                let ap = a["proposal_id"].as_str().unwrap_or("");
                let bp = b["proposal_id"].as_str().unwrap_or("");
                ap.cmp(bp)
            })
    });

    out.truncate(50);

    Json(serde_json::json!({
        "ok": true,
        "tip": format!("0x{}", hex::encode(tip)),
        "height": hi.height,
        "top": out
    }))
}

        
async fn top_global(State(st): State<ApiState>) -> Response {
    offload_display(move || top_global_blocking(st).into_response()).await
}

fn top_global_blocking(st: ApiState) -> Json<serde_json::Value> {
    use std::collections::HashMap;

    let tip = get_tip(&st.db).unwrap().unwrap_or([0u8; 32]);
    let hi = get_hidx(&st.db, &tip)
        .unwrap()
        .unwrap_or_else(|| zero_hidx(tip));

    let epoch = crate::state::app_state::epoch_of(hi.height).saturating_sub(1);

    // 1. get all domains
    let domains_resp = domains_list_blocking(st.clone());
    let domains = domains_resp.0.domains;

    let mut global: Vec<TopGlobalItem> = vec![];

    // 2. merge all domain topk
    for d in domains {
        let rows = get_topk(&st.db, epoch, &d.domain).unwrap_or_default();

        for (pid, weight) in rows {
            if weight == 0 {
    continue;
}
            let Some(v) = st.db.app.get(k_proposal(&pid)).unwrap() else { continue };
            let prop: Proposal = match c().deserialize(&v) {
                Ok(p) => p,
                Err(_) => continue,
            };

            global.push(TopGlobalItem {
                proposal_id: format!("0x{}", hex::encode(pid)),
                economic_weight: weight,
                domain: prop.domain,
                payload_hash: format!("0x{}", hex::encode(prop.payload_hash)),
                uri: prop.uri,
                expires_epoch: prop.expires_epoch,
            });
        }
    }

    // 3. sort globally by economic weight
    global.sort_by(|a, b| {
        b.economic_weight
            .cmp(&a.economic_weight)
            .then_with(|| a.proposal_id.cmp(&b.proposal_id))
    });

    global.truncate(50);

    Json(serde_json::json!({
        "ok": true,
        "epoch": epoch,
        "top": global
    }))
}

async fn domains_list(State(st): State<ApiState>) -> Response {
    offload_display(move || domains_list_blocking(st).into_response()).await
}

fn domains_list_blocking(st: ApiState) -> Json<DomainsResp> {
    use std::collections::HashMap;

    let tip = get_tip(&st.db).unwrap().unwrap_or([0u8; 32]);
    let hi = get_hidx(&st.db, &tip)
        .unwrap()
        .unwrap_or_else(|| zero_hidx(tip));

    let mut props_by_domain: HashMap<String, u64> = HashMap::new();
    let mut atts_by_domain: HashMap<String, u64> = HashMap::new();

    // 1) Count proposals directly from app state
    for item in st.db.app.iter() {
        let Ok((k, v)) = item else { continue };

        // proposal keys only
        if k.len() != 1 + 32 || k[0] != b'P' {
            continue;
        }

        let prop: Proposal = match c().deserialize(&v) {
            Ok(p) => p,
            Err(_) => continue,
        };

        *props_by_domain.entry(prop.domain).or_insert(0) += 1;
    }

    // 2) Count attestations by scanning recent canonical blocks
    //    and mapping proposal_id -> proposal.domain from app state
    const MAX_BACK: u64 = 100_000;

    let mut cur_hash = tip;
    let mut cur_height = hi.height;
    let mut scanned: u64 = 0;

    while scanned < MAX_BACK {
        let Some(v) = st.db.blocks.get(k_block(&cur_hash)).unwrap() else {
            break;
        };

        let blk: Block = match c().deserialize(&v) {
            Ok(b) => b,
            Err(_) => break,
        };

        for tx in blk.txs.iter().skip(1) {
            if let AppPayload::Attest { proposal_id, .. } = &tx.app {
                let Some(pv) = st.db.app.get(k_proposal(proposal_id)).unwrap() else {
                    continue;
                };

                let prop: Proposal = match c().deserialize(&pv) {
                    Ok(p) => p,
                    Err(_) => continue,
                };

                *atts_by_domain.entry(prop.domain).or_insert(0) += 1;
            }
        }

        scanned += 1;

        if blk.header.prev == [0u8; 32] || cur_height == 0 {
            break;
        }

        cur_hash = blk.header.prev;
        cur_height = cur_height.saturating_sub(1);
    }

    // 3) Merge observed domains
    let mut merged: HashMap<String, DomainItem> = HashMap::new();

    for (domain, proposals) in props_by_domain {
        merged
            .entry(domain.clone())
            .or_insert(DomainItem {
                domain,
                proposals: 0,
                attestations: 0,
            })
            .proposals = proposals;
    }

    for (domain, attestations) in atts_by_domain {
        merged
            .entry(domain.clone())
            .or_insert(DomainItem {
                domain,
                proposals: 0,
                attestations: 0,
            })
            .attestations = attestations;
    }

    let mut domains: Vec<DomainItem> = merged.into_values().collect();

    // Sort by attestations desc, then proposals desc, then domain asc
    domains.sort_by(|a, b| {
        b.attestations
            .cmp(&a.attestations)
            .then_with(|| b.proposals.cmp(&a.proposals))
            .then_with(|| a.domain.cmp(&b.domain))
    });

    Json(DomainsResp {
        ok: true,
        tip: format!("0x{}", hex::encode(tip)),
        height: hi.height,
        count: domains.len(),
        domains,
    })
}

fn parse_addr20(s: &str) -> Result<[u8; 20], String> {
    let s = s.trim().strip_prefix("0x").unwrap_or(s.trim());
    let bytes = hex::decode(s).map_err(|_| "bad hex".to_string())?;
    if bytes.len() != 20 {
        return Err("addr20 must be 20 bytes".to_string());
    }
    let mut out = [0u8; 20];
    out.copy_from_slice(&bytes);
    Ok(out)
}

// Harden template requests: base tx must be unsigned (scriptsigs empty) and app=None.
fn ensure_base_unsigned(tx: &Transaction) -> Result<(), String> {
    match &tx.app {
        AppPayload::None => {}
        _ => return Err("base tx must have app=None".to_string()),
    }
    for (i, inp) in tx.inputs.iter().enumerate() {
        if !inp.script_sig.is_empty() {
            return Err(format!("base tx input[{i}] script_sig must be empty"));
        }
    }
    Ok(())
}

async fn tip(State(st): State<ApiState>) -> Json<TipResp> {
    let tip = get_tip(&st.db).unwrap().unwrap_or([0u8; 32]);
    let hi = get_hidx(&st.db, &tip)
        .unwrap()
        .unwrap_or_else(|| zero_hidx(tip));

    Json(TipResp {
        tip: format!("0x{}", hex::encode(tip)),
        height: hi.height,
        chainwork: hi.chainwork.to_string(),
    })
}

/// GET /block/:hash
async fn block_get(Path(hash): Path<String>, State(st): State<ApiState>) -> Json<BlockResp> {
    let bh = match parse_hash32(&hash) {
        Ok(h) => h,
        Err(e) => {
            return Json(BlockResp {
                ok: false,
                hash: hash.clone(),
                height: None,
                chainwork: None,
                header: serde_json::json!({ "err": e }),
                txs: vec![],
            })
        }
    };

    let Some(v) = st.db.blocks.get(k_block(&bh)).unwrap() else {
        return Json(BlockResp {
            ok: false,
            hash: format!("0x{}", hex::encode(bh)),
            height: None,
            chainwork: None,
            header: serde_json::json!({ "err": "not found" }),
            txs: vec![],
        });
    };

    let blk: Block = match c().deserialize(&v) {
        Ok(b) => b,
        Err(e) => {
            return Json(BlockResp {
                ok: false,
                hash: format!("0x{}", hex::encode(bh)),
                height: None,
                chainwork: None,
                header: serde_json::json!({ "err": format!("decode block: {e}") }),
                txs: vec![],
            })
        }
    };

    let hi = get_hidx(&st.db, &bh).unwrap();
    let (height, chainwork) = if let Some(hi) = hi {
        (Some(hi.height), Some(hi.chainwork.to_string()))
    } else {
        (None, None)
    };

    let header_json = serde_json::json!({
        "version": blk.header.version,
        "prev": format!("0x{}", hex::encode(blk.header.prev)),
        "merkle": format!("0x{}", hex::encode(blk.header.merkle)),
        "time": blk.header.time,
        "bits": blk.header.bits,
        "nonce": blk.header.nonce,
    });

let txs_json: Vec<serde_json::Value> = blk
    .txs
    .iter()
    .map(|tx| {
        let id = txid(tx);

        let inputs_json: Vec<serde_json::Value> = tx.inputs.iter().map(|inp| {
            let script_sig_hex = format!("0x{}", hex::encode(&inp.script_sig));

            // Your coinbase format is:
            // [height_le_bytes][0x00][memo...]
            // So decode printable text after the first 0x00, if present.

let script_sig_text = if inp.prevout.txid == [0u8; 32] && inp.prevout.vout == u32::MAX {
    if inp.script_sig.len() > 9 {
        std::str::from_utf8(&inp.script_sig[9..])
            .ok()
            .map(|s| s.to_string())
    } else {
        None
    }
} else {
    None
};

            serde_json::json!({
                "prev_txid": format!("0x{}", hex::encode(inp.prevout.txid)),
                "vout": inp.prevout.vout,
                "script_sig": script_sig_hex,
                "script_sig_text": script_sig_text,
            })
        }).collect();

        serde_json::json!({
            "txid": format!("0x{}", hex::encode(id)),
            "version": tx.version,
            "inputs": inputs_json,
            "outputs": tx.outputs.iter().map(|o| {
                serde_json::json!({
                    "value": o.value,
                    "script_pubkey": format!("0x{}", hex::encode(o.script_pubkey)),
                })
            }).collect::<Vec<_>>(),
            "locktime": tx.locktime,
"app": app_payload_json(&tx.app),
        })
    })
    .collect();

    Json(BlockResp {
        ok: true,
        hash: format!("0x{}", hex::encode(bh)),
        height,
        chainwork,
        header: header_json,
        txs: txs_json,
    })
}


async fn block_by_height_get(
    Path(height): Path<u64>,
    State(st): State<ApiState>,
) -> Response {
    let tip = get_tip(&st.db).unwrap().unwrap_or([0u8; 32]);
    let hi = get_hidx(&st.db, &tip)
        .unwrap()
        .unwrap_or_else(|| zero_hidx(tip));

    if height > hi.height {
        return Json(BlockResp {
            ok: false,
            hash: "".to_string(),
            height: None,
            chainwork: None,
            header: serde_json::json!({ "err": "height beyond tip" }),
            txs: vec![],
        })
        .into_response();
    }

    // O(1) height->hash via the txid index's k_hh entries when the completeness marker
    // is fresh. The walk below stays as the fallback and stays UNCAPPED on purpose: a
    // wallet's emergency fallback can depend on /block/height/:h
    // answering to genesis regardless of index state.
    if let Some(h) = crate::state::tx_scan::canonical_hash_at_height(&st.db, height) {
        return block_get(Path(format!("0x{}", hex::encode(h))), State(st))
            .await
            .into_response();
    }

    // The fallback below is an UNCAPPED tip-to-genesis walk, kept uncapped
    // on purpose (a wallet's emergency fallback can depend on it answering at any
    // depth). Uncapped and on a runtime worker are two different things though: it was the last
    // O(chain) read still able to starve the p2p loop, and it runs precisely when the index is
    // stale, which is when an indexer is polling hardest. Offload it and gate it like the rest.
    let st_fb = st.clone();
    let resolved = offload_resolve_height(move || block_by_height_fallback(height, st_fb)).await;
    return match resolved {
        Ok(h) => block_get(Path(format!("0x{}", hex::encode(h))), State(st))
            .await
            .into_response(),
        Err(resp) => resp,
    };
}

/// Same admission gate and blocking-pool handoff as the other O(chain) reads, but this one
/// resolves a hash rather than producing the body, so the async caller can reuse `block_get`.
async fn offload_resolve_height<F>(f: F) -> Result<Hash32, Response>
where
    F: FnOnce() -> Result<Hash32, Response> + Send + 'static,
{
    let Some(_permit) = acquire_or_shed(heavy_scan_gate()).await else {
        return Err(scan_unavailable_busy(
            "SCAN_BUSY",
            "too many chain scans in flight; this is a load shed, not a statement about the height",
        ));
    };
    match tokio::task::spawn_blocking(move || {
        let _p = _permit;
        f()
    })
    .await
    {
        Ok(r) => r,
        Err(e) => {
            eprintln!("[api] height walk task failed: {e}");
            Err(scan_unavailable_busy(
                "SCAN_TASK_FAILED",
                "height walk did not complete",
            ))
        }
    }
}

fn block_by_height_fallback(height: u64, st: ApiState) -> Result<Hash32, Response> {
    let Ok(Some(tip)) = get_tip(&st.db) else {
        return Err(
            Json(serde_json::json!({ "ok": false, "error": "no chain tip" })).into_response()
        );
    };
    let hi = get_hidx(&st.db, &tip)
        .ok()
        .flatten()
        .unwrap_or_else(|| zero_hidx(tip));

    let mut cur_hash = tip;
    let mut cur_height = hi.height;

    while cur_height > height {
        let Some(v) = st.db.blocks.get(k_block(&cur_hash)).ok().flatten() else {
            return Err(Json(BlockResp {
                ok: false,
                hash: format!("0x{}", hex::encode(cur_hash)),
                height: Some(cur_height),
                chainwork: None,
                header: serde_json::json!({ "err": "missing block while walking back" }),
                txs: vec![],
            })
            .into_response());
        };

        let blk: Block = match c().deserialize(&v) {
            Ok(b) => b,
            Err(e) => {
                return Err(Json(BlockResp {
                    ok: false,
                    hash: format!("0x{}", hex::encode(cur_hash)),
                    height: Some(cur_height),
                    chainwork: None,
                    header: serde_json::json!({ "err": format!("decode block: {e}") }),
                    txs: vec![],
                })
                .into_response())
            }
        };

        cur_hash = blk.header.prev;
        cur_height = cur_height.saturating_sub(1);
    }

    Ok(cur_hash)
}


/// One admission gate shared by every handler whose cost is O(chain).
///
/// Moving those handlers to the blocking pool severs them from the p2p runtime, which is what the
/// measured 44x-to-176x head-of-line win against upstream comes from, but it bounds nothing on its
/// own: tokio's blocking pool defaults to 512 threads, a node host may have 6 cores, and
/// dropping the handler future when a client hangs up does NOT cancel the blocking task. So
/// issuing requests and disconnecting costs an attacker nothing and buys hundreds of concurrent
/// full-chain scans. A small permit count plus a fast 503 is the difference between "slow under
/// load" and "the swarm loop gets no CPU".
///
/// Sized well above observed traffic: a mainnet node behind a public wallet backend served a
/// few hundred of these per day.
/// SEPARATE gates, on purpose. A single shared pool lets six concurrent `/utxos` at ~140 ms each
/// block every `/tx/:id` for that whole window, and `/tx/:id` is the endpoint a wallet polls
/// hardest: it verifies one per transaction INPUT, so a legitimate multi-input send fans out
/// several at once.
const TX_LOOKUP_PERMITS: usize = 32;
const HEAVY_SCAN_PERMITS: usize = 6;
/// Display-only O(chain) reads (/domains, /proposals/*, /top/global,
/// /top/active, /top/all-time) get their own pool, so a flood of them sheds here and
/// takes no permit a wallet's /utxos, /address or /tx/:id reads need. Sized for a display
/// client's legitimate burst: /domains, then one /proposals/<d>/40 per domain at once (32 domains
/// on mainnet, ~330-380 ms each on a mainnet node), all inside DISPLAY_GATE_WAIT_MS.
const DISPLAY_SCAN_PERMITS: usize = 4;
const DISPLAY_GATE_WAIT_MS: u64 = 8_000;

/// Wait briefly rather than refusing instantly. `try_acquire` turns a legitimate burst into a
/// 503 even though each request finishes in well under a millisecond on a fresh index. A short
/// bounded wait costs a queued caller nothing when the index is fresh (the queue drains in
/// microseconds) and still sheds hard against a caller that is actually saturating the node.
const GATE_WAIT_MS: u64 = 250;

static TX_LOOKUP_GATE: std::sync::OnceLock<Arc<tokio::sync::Semaphore>> =
    std::sync::OnceLock::new();
static HEAVY_SCAN_GATE: std::sync::OnceLock<Arc<tokio::sync::Semaphore>> =
    std::sync::OnceLock::new();
static DISPLAY_SCAN_GATE: std::sync::OnceLock<Arc<tokio::sync::Semaphore>> =
    std::sync::OnceLock::new();

/// /tx/submit validation (`Mempool::insert_checked`: every input's spent
/// output and signature) runs on the blocking pool, at most SUBMIT_PERMITS at once, so on a
/// six-core host at most a third of the cores go to it. Inline on a runtime worker, refusals of
/// wide txs from a few client IPs queued every RPC handler behind them. A submit waits for its
/// permit with no deadline of the node's own and no cap on waiters: under a flood an honest submit
/// is queued, not refused. A client's deadline bounds the wait (a client that gives up after a
/// few seconds hangs up), so the wait stays cancellable; what runs after it does not
/// (`admit_and_gossip`).
const SUBMIT_PERMITS: usize = 2;
static SUBMIT_GATE: std::sync::OnceLock<Arc<tokio::sync::Semaphore>> = std::sync::OnceLock::new();

fn submit_gate() -> &'static Arc<tokio::sync::Semaphore> {
    SUBMIT_GATE.get_or_init(|| Arc::new(tokio::sync::Semaphore::new(SUBMIT_PERMITS)))
}

fn tx_lookup_gate() -> &'static Arc<tokio::sync::Semaphore> {
    TX_LOOKUP_GATE.get_or_init(|| Arc::new(tokio::sync::Semaphore::new(TX_LOOKUP_PERMITS)))
}

fn heavy_scan_gate() -> &'static Arc<tokio::sync::Semaphore> {
    HEAVY_SCAN_GATE.get_or_init(|| Arc::new(tokio::sync::Semaphore::new(HEAVY_SCAN_PERMITS)))
}

fn display_scan_gate() -> &'static Arc<tokio::sync::Semaphore> {
    DISPLAY_SCAN_GATE.get_or_init(|| Arc::new(tokio::sync::Semaphore::new(DISPLAY_SCAN_PERMITS)))
}

async fn acquire_or_shed(
    gate: &'static Arc<tokio::sync::Semaphore>,
) -> Option<tokio::sync::OwnedSemaphorePermit> {
    acquire_within(gate, std::time::Duration::from_millis(GATE_WAIT_MS)).await
}

async fn acquire_within(
    gate: &'static Arc<tokio::sync::Semaphore>,
    wait: std::time::Duration,
) -> Option<tokio::sync::OwnedSemaphorePermit> {
    tokio::time::timeout(wait, gate.clone().acquire_owned())
        .await
        .ok()
        .and_then(|r| r.ok())
}

/// Test seam: the saturation tests shorten the display wait instead of sleeping 8 s.
#[cfg(test)]
static DISPLAY_GATE_WAIT_OVERRIDE_MS: AtomicU64 = AtomicU64::new(0);

fn display_gate_wait() -> std::time::Duration {
    #[cfg(test)]
    {
        let ms = DISPLAY_GATE_WAIT_OVERRIDE_MS.load(Ordering::SeqCst);
        if ms > 0 {
            return std::time::Duration::from_millis(ms);
        }
    }
    std::time::Duration::from_millis(DISPLAY_GATE_WAIT_MS)
}

/// 503 body for a request refused or failed by the offload path. Deliberately NOT a 200 with an
/// empty result: on these endpoints an empty answer is a claim, and the caller must be able to
/// tell "no" from "I could not look".
fn scan_unavailable_busy(code: &'static str, err: &'static str) -> Response {
    (
        StatusCode::SERVICE_UNAVAILABLE,
        [(RETRY_AFTER, "2")],
        Json(serde_json::json!({ "ok": false, "code": code, "err": err, "retry_after_secs": 2 })),
    )
        .into_response()
}

/// Run an O(chain) read on the blocking pool, behind the admission gate.
async fn offload_o_chain<F>(f: F) -> Response
where
    F: FnOnce() -> Response + Send + 'static,
{
    offload_gated(tx_lookup_gate(), std::time::Duration::from_millis(GATE_WAIT_MS), f).await
}

/// Same as `offload_o_chain`, on the display pool.
async fn offload_display<F>(f: F) -> Response
where
    F: FnOnce() -> Response + Send + 'static,
{
    offload_gated(display_scan_gate(), display_gate_wait(), f).await
}

async fn offload_gated<F>(
    gate: &'static Arc<tokio::sync::Semaphore>,
    wait: std::time::Duration,
    f: F,
) -> Response
where
    F: FnOnce() -> Response + Send + 'static,
{
    let Some(_permit) = acquire_within(gate, wait).await else {
        return scan_unavailable_busy(
            "SCAN_BUSY",
            "too many chain scans in flight; this is a load shed, not a statement about the query",
        );
    };
    match tokio::task::spawn_blocking(move || {
        let _p = _permit;
        f()
    })
    .await
    {
        Ok(r) => r,
        Err(e) => {
            eprintln!("[api] chain scan task failed: {e}");
            scan_unavailable_busy("SCAN_TASK_FAILED", "chain scan did not complete")
        }
    }
}

/// Scan budget for the /tx and /proof/tx fallback walk (a parameter of the pure
/// `find_tx_in_chain`; this is the API's default budget).
pub const TX_SCAN_MAX_BACK: u64 = 100_000;

/// Retry-After seconds advertised on SCAN_HORIZON / SCAN_INCOMPLETE / SCAN_DECODE 503s.
/// The background index reconciler converges within minutes even from cold.
const SCAN_RETRY_AFTER_SECS: u64 = 30;

/// Wire mapping for the non-decisive scan outcomes (normative spec: docs/behaviour.md
/// "The `/tx/:id` and `/proof/tx/:txid` outcome contract"). Horizon and Incomplete MUST be
/// non-2xx-non-404 so fielded wallets classify them `transient` (fail closed) instead of
/// `notfound` (silent ghost).
fn scan_unavailable(want: &Hash32, outcome: &crate::state::tx_scan::ScanOutcome) -> Response {
    use crate::state::tx_scan::{ScanOutcome, WHY_DECODE};
    let body = match outcome {
        ScanOutcome::Horizon {
            scanned,
            stopped_at_height,
        } => serde_json::json!({
            "ok": false,
            "txid": format!("0x{}", hex::encode(want)),
            "code": "SCAN_HORIZON",
            "err": "scan horizon reached before absence could be proved",
            "scanned": scanned,
            "stopped_at_height": stopped_at_height,
            "retry_after_secs": SCAN_RETRY_AFTER_SECS,
        }),
        ScanOutcome::Incomplete { at, why } => serde_json::json!({
            "ok": false,
            "txid": format!("0x{}", hex::encode(want)),
            "code": if *why == WHY_DECODE { "SCAN_DECODE" } else { "SCAN_INCOMPLETE" },
            "err": "chain walk could not complete; absence not proved",
            "at": format!("0x{}", hex::encode(at)),
            "why": why,
            "retry_after_secs": SCAN_RETRY_AFTER_SECS,
        }),
        // Found/Absent are decisive and never routed here.
        _ => serde_json::json!({ "ok": false, "code": "SCAN_INCOMPLETE" }),
    };
    (
        StatusCode::SERVICE_UNAVAILABLE,
        [(RETRY_AFTER, SCAN_RETRY_AFTER_SECS.to_string())],
        Json(body),
    )
        .into_response()
}

/// The index answers this in O(1) only while its completeness marker is fresh. It is NOT fresh
/// for a window after every new block, and not at all while the reconciler is rebuilding, and in
/// those windows this falls through to `find_tx_in_chain`, which reads and decodes up to
/// TX_SCAN_MAX_BACK block bodies. That is the same O(chain) work as /utxos, on the endpoint a
/// wallet polls hardest, so it belongs behind the same gate. Measured against upstream, which has
/// no index at all: an absent-txid lookup is 0.46 ms here versus 146 ms there.
async fn tx_get(Path(id): Path<String>, State(st): State<ApiState>) -> Response {
    offload_o_chain(move || tx_get_blocking(id, st)).await
}

fn tx_get_blocking(
    id: String,
    st: ApiState,
) -> Response {
    let want = match parse_hash32(&id) {
        Ok(x) => x,
        Err(e) => {
            return Json(TxResp {
                ok: false,
                txid: id,
                block_hash: None,
                height: None,
                time: None,
                tx: None,
                err: Some(e),
                complete: None,
                scanned: None,
            })
            .into_response()
        }
    };

    use crate::state::tx_scan::{locate_tx, ScanOutcome, WHY_MISSING_BODY};

    match locate_tx(&st.db, &want, TX_SCAN_MAX_BACK) {
        ScanOutcome::Found {
            block_hash,
            height,
            index_in_block,
        } => {
            // Re-load the located block and build the response EXACTLY as upstream's scan does:
            // an in-horizon hit (and now an index hit) stays byte-identical on the wire.
            let Ok(Some(v)) = st.db.blocks.get(k_block(&block_hash)) else {
                return scan_unavailable(
                    &want,
                    &ScanOutcome::Incomplete {
                        at: block_hash,
                        why: WHY_MISSING_BODY,
                    },
                );
            };
            let blk: Block = match c().deserialize(&v) {
                Ok(b) => b,
                Err(_) => {
                    return scan_unavailable(
                        &want,
                        &ScanOutcome::Incomplete {
                            at: block_hash,
                            why: crate::state::tx_scan::WHY_DECODE,
                        },
                    )
                }
            };
            let Some(tx) = blk.txs.get(index_in_block) else {
                return scan_unavailable(
                    &want,
                    &ScanOutcome::Incomplete {
                        at: block_hash,
                        why: WHY_MISSING_BODY,
                    },
                );
            };

            let inputs_json: Vec<serde_json::Value> = tx.inputs.iter().map(|inp| {
                let script_sig_hex = format!("0x{}", hex::encode(&inp.script_sig));

                let script_sig_text = if inp.prevout.txid == [0u8; 32] && inp.prevout.vout == u32::MAX {
                    if inp.script_sig.len() > 9 {
                        std::str::from_utf8(&inp.script_sig[9..])
                            .ok()
                            .map(|s| s.to_string())
                    } else {
                        None
                    }
                } else {
                    None
                };

                serde_json::json!({
                    "prev_txid": format!("0x{}", hex::encode(inp.prevout.txid)),
                    "vout": inp.prevout.vout,
                    "script_sig": script_sig_hex,
                    "script_sig_text": script_sig_text,
                })
            }).collect();

            let tx_json = serde_json::json!({
                "txid": format!("0x{}", hex::encode(want)),
                "version": tx.version,
                "inputs": inputs_json,
                "outputs": tx.outputs.iter().map(|o| {
                    serde_json::json!({
                        "value": o.value,
                        "script_pubkey": format!("0x{}", hex::encode(o.script_pubkey)),
                    })
                }).collect::<Vec<_>>(),
                "locktime": tx.locktime,
"app": app_payload_json(&tx.app),
            });

            Json(TxResp {
                ok: true,
                txid: format!("0x{}", hex::encode(want)),
                block_hash: Some(format!("0x{}", hex::encode(block_hash))),
                height: Some(height),
                time: Some(blk.header.time),
                tx: Some(tx_json),
                err: None,
                complete: None,
                scanned: None,
            })
            .into_response()
        }
        ScanOutcome::Absent { scanned } => Json(TxResp {
            ok: false,
            txid: format!("0x{}", hex::encode(want)),
            block_hash: None,
            height: None,
            time: None,
            tx: None,
            err: Some("not found".to_string()),
            complete: Some(true),
            scanned: Some(scanned),
        })
        .into_response(),
        other => scan_unavailable(&want, &other),
    }
}

fn merkle_branch(txids: &[[u8; 32]], index: usize) -> Vec<serde_json::Value> {
    let mut branch = vec![];
    let mut layer = txids.to_vec();
    let mut idx = index;

    while layer.len() > 1 {
        let sibling_idx = if idx % 2 == 0 { idx + 1 } else { idx - 1 };
        let sibling = if sibling_idx < layer.len() {
            layer[sibling_idx]
        } else {
            layer[idx]
        };

        branch.push(serde_json::json!({
            "hash": format!("0x{}", hex::encode(sibling)),
            "position": if idx % 2 == 0 { "right" } else { "left" }
        }));

        let mut next = Vec::with_capacity((layer.len() + 1) / 2);
        let mut i = 0usize;

        while i < layer.len() {
            let left = layer[i];
            let right = if i + 1 < layer.len() { layer[i + 1] } else { layer[i] };

            let mut buf = [0u8; 64];
            buf[..32].copy_from_slice(&left);
            buf[32..].copy_from_slice(&right);
            next.push(crate::crypto::sha256d(&buf));

            i += 2;
        }

        idx /= 2;
        layer = next;
    }

    branch
}

fn tx_json(tx: &Transaction, id: Hash32) -> serde_json::Value {
    serde_json::json!({
        "txid": format!("0x{}", hex::encode(id)),
        "version": tx.version,
        "locktime": tx.locktime,
        "app": app_payload_json(&tx.app),
        "inputs": tx.inputs.iter().map(|inp| {
            serde_json::json!({
                "prev_txid": format!("0x{}", hex::encode(inp.prevout.txid)),
                "vout": inp.prevout.vout,
                "script_sig": format!("0x{}", hex::encode(&inp.script_sig)),
            })
        }).collect::<Vec<_>>(),
        "outputs": tx.outputs.iter().enumerate().map(|(i, o)| {
            serde_json::json!({
                "vout": i,
                "value": o.value,
                "script_pubkey": format!("0x{}", hex::encode(o.script_pubkey)),
            })
        }).collect::<Vec<_>>(),
    })
}

async fn tx_proof_get(State(st): State<ApiState>, Path(id): Path<String>) -> Response {
    offload_o_chain(move || tx_proof_get_blocking(st, id)).await
}

fn tx_proof_get_blocking(
    st: ApiState,
    id: String,
) -> Response {
    let want = match parse_hash32(&id) {
        Ok(h) => h,
        Err(e) => return Json(serde_json::json!({ "ok": false, "error": e })).into_response(),
    };

    use crate::state::tx_scan::{locate_tx, ScanOutcome, WHY_DECODE, WHY_MISSING_BODY};

    // The same four-way outcome mapping as /tx/:id (normative spec: docs/behaviour.md
    // "The `/tx/:id` and `/proof/tx/:txid` outcome contract").
    match locate_tx(&st.db, &want, TX_SCAN_MAX_BACK) {
        ScanOutcome::Found {
            block_hash,
            height,
            index_in_block,
        } => {
            let Ok(Some(v)) = st.db.blocks.get(k_block(&block_hash)) else {
                return scan_unavailable(
                    &want,
                    &ScanOutcome::Incomplete {
                        at: block_hash,
                        why: WHY_MISSING_BODY,
                    },
                );
            };
            let blk: Block = match c().deserialize(&v) {
                Ok(b) => b,
                Err(_) => {
                    return scan_unavailable(
                        &want,
                        &ScanOutcome::Incomplete {
                            at: block_hash,
                            why: WHY_DECODE,
                        },
                    )
                }
            };
            let txids: Vec<[u8; 32]> = blk.txs.iter().map(|tx| txid(tx)).collect();
            let i = index_in_block;
            let Some(tx) = blk.txs.get(i) else {
                return scan_unavailable(
                    &want,
                    &ScanOutcome::Incomplete {
                        at: block_hash,
                        why: WHY_MISSING_BODY,
                    },
                );
            };

            // Tip height for confirmations + the scan-equivalent `scanned` value
            // (tip_height - height + 1 = blocks upstream's walk reports on this hit),
            // so an index-served proof is byte-identical to a scan-served one.
            let tip = get_tip(&st.db).ok().flatten().unwrap_or([0u8; 32]);
            let tip_height = get_hidx(&st.db, &tip)
                .ok()
                .flatten()
                .map(|hi| hi.height)
                .unwrap_or(height);

            Json(serde_json::json!({
                "ok": true,
                "genesis_hash": format!("0x{}", hex::encode(GENESIS_HASH)),
                "txid": format!("0x{}", hex::encode(want)),
                "tx_index": i,
                "tx_raw": format!("0x{}", hex::encode(c().serialize(tx).unwrap())),
"tx": tx_json(tx, want),
                "block_hash": format!("0x{}", hex::encode(block_hash)),
                "height": height,
                "confirmations": tip_height.saturating_sub(height).saturating_add(1),
                "header": {
                    "version": blk.header.version,
                    "prev": format!("0x{}", hex::encode(blk.header.prev)),
                    "merkle": format!("0x{}", hex::encode(blk.header.merkle)),
                    "time": blk.header.time,
                    "bits": blk.header.bits,
                    "nonce": blk.header.nonce,
                },
                "merkle_branch": merkle_branch(&txids, i),
                "scanned": tip_height.saturating_sub(height).saturating_add(1)
            }))
            .into_response()
        }
        ScanOutcome::Absent { scanned } => Json(serde_json::json!({
            "ok": false,
            "txid": format!("0x{}", hex::encode(want)),
            "error": "tx not found in main chain",
            "scanned": scanned,
            "complete": true
        }))
        .into_response(),
        other => scan_unavailable(&want, &other),
    }
}

/// GET /utxos/:addr20
///
/// One address's unspent outputs, from the address index while it is current at the tip and from
/// a scan of the whole UTXO tree otherwise (`state::addr_index`; docs/behaviour.md "The address
/// index"). Both answers are the same; the index's costs that address's outputs, the scan's the
/// whole UTXO set. The body runs on the blocking pool, behind the heavy-scan gate, because the
/// scan and the lifetime walk are O(chain) whenever the index is not current.
async fn utxos_for_addr20(
    Path(addr20): Path<String>,
    Query(q): Query<UtxosQuery>,
    State(st): State<ApiState>,
) -> Response {
    let Some(_permit) = acquire_or_shed(heavy_scan_gate()).await else {
        return scan_unavailable_busy(
            "SCAN_BUSY",
            "too many chain scans in flight; this is a load shed, not a statement about the address",
        );
    };
    let read = tokio::task::spawn_blocking(move || {
        let _p = _permit;
        utxos_for_addr20_blocking(addr20, q, st)
    })
    .await;
    match read {
        Ok(Ok(r)) => return Json(r).into_response(),
        Ok(Err(e)) => eprintln!("[api] utxo read failed: {e:#}"),
        Err(e) => eprintln!("[api] utxo scan task failed: {e}"),
    }
    // An internal failure MUST NOT be answerable as "this address has no coins". This is a
    // wallet's coin-selection input: a 200 with count 0 and an empty utxo list is shape-identical
    // to a genuinely empty address, so any consumer that does not check `ok` would render a zero
    // balance and build the wrong transaction. Same confident-lie class the tx index removes, so
    // answer 503 and let the caller retry.
    (
        StatusCode::SERVICE_UNAVAILABLE,
        [(RETRY_AFTER, "5")],
        Json(serde_json::json!({
            "ok": false,
            "code": "SCAN_TASK_FAILED",
            "err": "utxo scan did not complete; this is NOT an assertion that the address has no coins",
            "retry_after_secs": 5,
        })),
    )
        .into_response()
}

fn utxos_for_addr20_blocking(addr20: String, q: UtxosQuery, st: ApiState) -> anyhow::Result<UtxosResp> {
    let Ok(a) = parse_addr20(&addr20) else {
        return Ok(UtxosResp {
            ok: false,
            addr20,
            count: 0,
            confirmed_balance: 0,
            mined_lifetime: None,
            mined_unspent: 0,
            coinbase_lifetime_outputs: None,
            coinbase_unspent_outputs: 0,
            utxos: vec![],
            tip: None,
        });
    };
    let read = crate::state::addr_index::read(st.db.as_ref(), &a, q.lifetime.unwrap_or(false))?;
    Ok(utxos_resp(a, read, &q, &st.mempool))
}

/// The /utxos body for one address's read: the query's filters and order, then the totals.
fn utxos_resp(a: [u8; 20], read: crate::state::addr_index::AddrRead, q: &UtxosQuery, mempool: &Mempool) -> UtxosResp {
    let tip_height = read.tip_height;
    let mut out: Vec<UtxoItem> = read
        .utxos
        .into_iter()
        .map(|u| UtxoItem {
            txid: format!("0x{}", hex::encode(u.op.txid)),
            vout: u.op.vout,
            value: u.value,
            height: u.height,
            confirmations: if u.height == 0 || tip_height < u.height { 0 } else { tip_height - u.height + 1 },
            coinbase: u.coinbase,
        })
        .collect();

    if q.available.unwrap_or(false) {
        out.retain(|u| !mempool.has_spent_outpoint_hex(&u.txid, u.vout));
    }
    if let Some(min) = q.min_value {
        out.retain(|u| u.value >= min);
    }
    if q.smallest.unwrap_or(false) {
        out.sort_by_key(|u| u.value);
    } else {
        out.sort_by(|a, b| {
            b.height
                .cmp(&a.height)
                .then_with(|| b.confirmations.cmp(&a.confirmations))
                .then_with(|| a.txid.cmp(&b.txid))
                .then_with(|| a.vout.cmp(&b.vout))
        });
    }

    // The totals cover every coin that passed the filters; `limit` shortens only the list.
    let confirmed_balance: u64 = out.iter().map(|u| u.value).sum();
    let mined_unspent: u64 = out.iter().filter(|u| u.coinbase).map(|u| u.value).sum();
    let coinbase_unspent_outputs = out.iter().filter(|u| u.coinbase).count() as u64;
    if let Some(limit) = q.limit {
        out.truncate(limit);
    }

    UtxosResp {
        ok: true,
        addr20: format!("0x{}", hex::encode(a)),
        count: out.len(),
        confirmed_balance,
        mined_lifetime: read.lifetime.map(|t| t.0),
        mined_unspent,
        coinbase_lifetime_outputs: read.lifetime.map(|t| t.1),
        coinbase_unspent_outputs,
        utxos: out,
        tip: read.tip.map(|t| format!("0x{}", hex::encode(t))),
    }
}

async fn address_activity_get(
    Path(addr20): Path<String>,
    Query(q): Query<AddressActivityQuery>,
    State(st): State<ApiState>,
) -> Response {
    // Same offload as /utxos above, and more so: this one clones every block on the chain and
    // builds a map of every outpoint ever created before applying `limit`. The RPC binds
    // loopback by default, so this is about not letting an operator's own
    // explorer query stall block apply.
    let Some(_permit) = acquire_or_shed(heavy_scan_gate()).await else {
        return scan_unavailable_busy("SCAN_BUSY", "too many chain scans in flight");
    };
    match tokio::task::spawn_blocking(move || {
        let _p = _permit;
        address_activity_get_blocking(addr20, q, st)
    })
    .await
    {
        Ok(r) => r.into_response(),
        Err(e) => {
            // Same reasoning as /utxos: an empty activity list is a claim, not an error.
            eprintln!("[api] activity scan task failed: {e}");
            (
                StatusCode::SERVICE_UNAVAILABLE,
                [(RETRY_AFTER, "5")],
                Json(serde_json::json!({
                    "ok": false,
                    "code": "SCAN_TASK_FAILED",
                    "err": "activity scan did not complete",
                    "retry_after_secs": 5,
                })),
            )
                .into_response()
        }
    }
}

fn address_activity_get_blocking(
    addr20: String,
    q: AddressActivityQuery,
    st: ApiState,
) -> Json<AddressActivityResp> {

    let a = match parse_addr20(&addr20) {
        Ok(x) => x,
        Err(_) => {
            return Json(AddressActivityResp {
                ok: false,
                addr20,
                count: 0,
                proposals_created: 0,
                attestations_submitted: 0,
                total_fees_paid: 0,
                activity: vec![],
            })
        }
    };

    let tip = get_tip(st.db.as_ref()).ok().flatten().unwrap_or([0u8; 32]);
    let hi = get_hidx(st.db.as_ref(), &tip)
        .ok()
        .flatten()
        .unwrap_or_else(|| zero_hidx(tip));

    let mut blocks: Vec<(Hash32, u64, Block)> = vec![];
    let mut cur_hash = tip;
    let mut cur_height = hi.height;

    loop {
        let Some(v) = st.db.blocks.get(k_block(&cur_hash)).unwrap() else {
            break;
        };

        let blk: Block = match c().deserialize(&v) {
            Ok(b) => b,
            Err(_) => break,
        };

        blocks.push((cur_hash, cur_height, blk.clone()));

        if blk.header.prev == [0u8; 32] || cur_height == 0 {
            break;
        }

        cur_hash = blk.header.prev;
        cur_height = cur_height.saturating_sub(1);
    }

    blocks.reverse();

    let mut outpoint_map: HashMap<OutPoint, TxOut> = HashMap::new();

    for (_bh, _height, blk) in &blocks {
        for tx in &blk.txs {
            let id = txid(tx);


            for (vout, out) in tx.outputs.iter().enumerate() {
                outpoint_map.insert(
                    OutPoint {
                        txid: id,
                        vout: vout as u32,
                    },
                    out.clone(),
                );
            }
        }
    }

    let mut activity: Vec<AddressActivityItem> = vec![];
    let mut proposals_created: u64 = 0;
    let mut attestations_submitted: u64 = 0;
    let mut total_fees_paid: u64 = 0;

for (bh, height, blk) in blocks {
    for tx in &blk.txs {
        let id = txid(tx);

        let is_coinbase = tx
            .inputs
            .first()
            .map(|inp| inp.prevout.txid == [0u8; 32] && inp.prevout.vout == u32::MAX)
            .unwrap_or(false);

        let output_to_addr: u64 = tx.outputs

                .iter()
                .filter(|o| o.script_pubkey == a)
                .map(|o| o.value)
                .sum();

            let input_from_addr: u64 = tx.inputs
                .iter()
                .filter_map(|inp| outpoint_map.get(&inp.prevout))
                .filter(|o| o.script_pubkey == a)
                .map(|o| o.value)
                .sum();

            if output_to_addr == 0 && input_from_addr == 0 {
                continue;
            }

if is_coinbase && !q.include_mined.unwrap_or(false) {
    continue;
}

            let value_delta: i128 = output_to_addr as i128 - input_from_addr as i128;
            let fee_paid = input_from_addr.saturating_sub(output_to_addr);

            match &tx.app {
                AppPayload::Propose {
                    domain,
                    payload_hash,
                    uri,
                    ..
                } => {
                    proposals_created = proposals_created.saturating_add(1);
                    total_fees_paid = total_fees_paid.saturating_add(fee_paid);

                    activity.push(AddressActivityItem {
                        kind: "proposal".to_string(),
                        txid: format!("0x{}", hex::encode(id)),
                        block_hash: format!("0x{}", hex::encode(bh)),
                        height,
                        time: blk.header.time,
                        value_delta,
                        domain: Some(domain.clone()),
                        proposal_id: Some(format!("0x{}", hex::encode(id))),
                        payload_hash: Some(format!("0x{}", hex::encode(payload_hash))),
                        uri: Some(uri.clone()),
                    });
                }

                AppPayload::Attest { proposal_id, .. } => {
                    attestations_submitted = attestations_submitted.saturating_add(1);
                    total_fees_paid = total_fees_paid.saturating_add(fee_paid);

                    activity.push(AddressActivityItem {
                        kind: "attestation".to_string(),
                        txid: format!("0x{}", hex::encode(id)),
                        block_hash: format!("0x{}", hex::encode(bh)),
                        height,
                        time: blk.header.time,
                        value_delta,
                        domain: None,
                        proposal_id: Some(format!("0x{}", hex::encode(proposal_id))),
                        payload_hash: None,
                        uri: None,
                    });
                }

                AppPayload::None => {
                    activity.push(AddressActivityItem {
                        kind: if input_from_addr == 0 { "received" } else { "transfer" }.to_string(),
                        txid: format!("0x{}", hex::encode(id)),
                        block_hash: format!("0x{}", hex::encode(bh)),
                        height,
                        time: blk.header.time,
                        value_delta,
                        domain: None,
                        proposal_id: None,
                        payload_hash: None,
                        uri: None,
                    });
                }
            }
        }
    }

    activity.sort_by(|a, b| {
        b.height
            .cmp(&a.height)
            .then_with(|| a.txid.cmp(&b.txid))
    });

let limit = q.limit.unwrap_or(100).min(500);
activity.truncate(limit);

    Json(AddressActivityResp {
        ok: true,
        addr20: format!("0x{}", hex::encode(a)),
        count: activity.len(),
        proposals_created,
        attestations_submitted,
        total_fees_paid,
        activity,
    })
}

// ===========================
// Recent blocks feed
// ===========================

/// GET /recent/blocks/:limit
async fn recent_blocks(
    Path(limit): Path<u64>,
    State(st): State<ApiState>,
) -> Json<RecentBlocksResp> {
    const MAX_LIMIT: u64 = 50;
    const MAX_BACK: u64 = 5000;

    let want = limit.min(MAX_LIMIT).max(1);

    let tip = get_tip(&st.db).unwrap().unwrap_or([0u8; 32]);
    let hi = get_hidx(&st.db, &tip)
        .unwrap()
        .unwrap_or_else(|| zero_hidx(tip));

    let mut cur_hash = tip;
    let mut cur_height = hi.height;
    let mut scanned: u64 = 0;

    let mut blocks: Vec<RecentBlockItem> = vec![];

    while scanned < MAX_BACK && (blocks.len() as u64) < want {
        let Some(v) = st.db.blocks.get(k_block(&cur_hash)).unwrap() else {
            break;
        };
        let blk: Block = match c().deserialize(&v) {
            Ok(b) => b,
            Err(_) => break,
        };

        blocks.push(RecentBlockItem {
            height: cur_height,
            hash: format!("0x{}", hex::encode(cur_hash)),
            prev: format!("0x{}", hex::encode(blk.header.prev)),
            time: blk.header.time,
            txs: blk.txs.len(),
        });

        scanned += 1;

        if blk.header.prev == [0u8; 32] || cur_height == 0 {
            break;
        }
        cur_hash = blk.header.prev;
        cur_height = cur_height.saturating_sub(1);
    }

    Json(RecentBlocksResp {
        ok: true,
        tip: format!("0x{}", hex::encode(tip)),
        height: hi.height,
        scanned_blocks: scanned,
        count: blocks.len(),
        blocks,
    })
}

// ===========================
// Recent proposals feed
// ===========================

fn scan_recent_proposals(
    st: &ApiState,
    domain_filter: Option<&str>,
    want: u64,
    max_back: u64,
) -> (Hash32, u64, u64, Vec<RecentProposalItem>) {
    use std::collections::HashSet;

    let tip = get_tip(&st.db).unwrap().unwrap_or([0u8; 32]);
    let hi = get_hidx(&st.db, &tip)
        .unwrap()
        .unwrap_or_else(|| zero_hidx(tip));

    let mut proposals: Vec<RecentProposalItem> = vec![];
    let mut cur_hash = tip;
    let mut cur_height = hi.height;
    let mut scanned: u64 = 0;

    let mut seen: HashSet<[u8; 32]> = HashSet::new();

    while scanned < max_back && proposals.len() < (want as usize) {
        let Some(v) = st.db.blocks.get(k_block(&cur_hash)).unwrap() else {
            break;
        };
        let blk: Block = match c().deserialize(&v) {
            Ok(b) => b,
            Err(_) => break,
        };

        for tx in blk.txs.iter().skip(1) {
            if let AppPayload::Propose {
                domain,
                payload_hash,
                uri,
                expires_epoch,
            } = &tx.app
            {
                if let Some(df) = domain_filter {
                    if domain != df {
                        continue;
                    }
                }

                let pid = txid(tx); // proposal_id == txid for propose
                if seen.insert(pid) {
                    proposals.push(RecentProposalItem {
                        proposal_id: format!("0x{}", hex::encode(pid)),
                        txid: format!("0x{}", hex::encode(pid)),
                        block_hash: format!("0x{}", hex::encode(cur_hash)),
                        height: cur_height,
                        time: blk.header.time,
                        domain: domain.clone(),
                        payload_hash: format!("0x{}", hex::encode(payload_hash)),
                        uri: uri.clone(),
                        expires_epoch: *expires_epoch,
                    });
                    if proposals.len() >= (want as usize) {
                        break;
                    }
                }
            }
        }

        scanned += 1;

        if blk.header.prev == [0u8; 32] || cur_height == 0 {
            break;
        }
        cur_hash = blk.header.prev;
        cur_height = cur_height.saturating_sub(1);
    }

    (tip, hi.height, scanned, proposals)
}

/// GET /recent/proposals/:limit
async fn recent_proposals(Path(limit): Path<u64>, State(st): State<ApiState>) -> Response {
    offload_display(move || recent_proposals_blocking(limit, st).into_response()).await
}

fn recent_proposals_blocking(limit: u64, st: ApiState) -> Json<RecentProposalsResp> {
    const MAX_LIMIT: u64 = 200;
    const MAX_BACK: u64 = 2_000;
    let want = limit.min(MAX_LIMIT).max(1);

    let (tip, height, scanned, proposals) = scan_recent_proposals(&st, None, want, MAX_BACK);

    Json(RecentProposalsResp {
        ok: true,
        tip: format!("0x{}", hex::encode(tip)),
        height,
        scanned_blocks: scanned,
        count: proposals.len(),
        proposals,
    })
}

/// GET /recent/proposals/:domain/:limit
async fn recent_proposals_by_domain(
    Path((domain, limit)): Path<(String, u64)>,
    State(st): State<ApiState>,
) -> Response {
    offload_display(move || recent_proposals_by_domain_blocking(domain, limit, st).into_response())
        .await
}

fn recent_proposals_by_domain_blocking(
    domain: String,
    limit: u64,
    st: ApiState,
) -> Json<RecentProposalsResp> {
    const MAX_LIMIT: u64 = 200;
    const MAX_BACK: u64 = 5_000;
    let want = limit.min(MAX_LIMIT).max(1);

    let (tip, height, scanned, proposals) =
        scan_recent_proposals(&st, Some(&domain), want, MAX_BACK);

    Json(RecentProposalsResp {
        ok: true,
        tip: format!("0x{}", hex::encode(tip)),
        height,
        scanned_blocks: scanned,
        count: proposals.len(),
        proposals,
    })
}

fn scan_all_proposals_from_app(
    st: &ApiState,
    domain_filter: Option<&str>,
    want: u64,
) -> (Hash32, u64, Vec<RecentProposalItem>) {
    use std::collections::HashSet;

    let tip = get_tip(&st.db).unwrap().unwrap_or([0u8; 32]);
    let hi = get_hidx(&st.db, &tip)
        .unwrap()
        .unwrap_or_else(|| zero_hidx(tip));

    let mut proposals: Vec<RecentProposalItem> = vec![];
    let mut seen: HashSet<Hash32> = HashSet::new();

    let mut cur_hash = tip;
    let mut cur_height = hi.height;

    loop {
        let Some(v) = st.db.blocks.get(k_block(&cur_hash)).unwrap() else {
            break;
        };

        let blk: Block = match c().deserialize(&v) {
            Ok(b) => b,
            Err(_) => break,
        };

        for tx in blk.txs.iter().skip(1) {
            if let AppPayload::Propose {
                domain,
                payload_hash,
                uri,
                expires_epoch,
            } = &tx.app
            {
                if let Some(df) = domain_filter {
                    if domain != df {
                        continue;
                    }
                }

                let pid = txid(tx);

                if seen.insert(pid) {
                    proposals.push(RecentProposalItem {
                        proposal_id: format!("0x{}", hex::encode(pid)),
                        txid: format!("0x{}", hex::encode(pid)),
                        block_hash: format!("0x{}", hex::encode(cur_hash)),
                        height: cur_height,
                        time: blk.header.time,
                        domain: domain.clone(),
                        payload_hash: format!("0x{}", hex::encode(payload_hash)),
                        uri: uri.clone(),
                        expires_epoch: *expires_epoch,
                    });
                }
            }
        }

        if blk.header.prev == [0u8; 32] || cur_height == 0 {
            break;
        }

        cur_hash = blk.header.prev;
        cur_height = cur_height.saturating_sub(1);
    }

    proposals.sort_by(|a, b| {
        b.height
            .cmp(&a.height)
            .then_with(|| a.proposal_id.cmp(&b.proposal_id))
    });

    proposals.truncate(want as usize);

    (tip, hi.height, proposals)
}
/// GET /proposals/:limit
async fn all_proposals(Path(limit): Path<u64>, State(st): State<ApiState>) -> Response {
    offload_display(move || all_proposals_blocking(limit, st).into_response()).await
}

fn all_proposals_blocking(limit: u64, st: ApiState) -> Json<RecentProposalsResp> {
    const MAX_LIMIT: u64 = 500;
    let want = limit.min(MAX_LIMIT).max(1);

    let (tip, height, proposals) = scan_all_proposals_from_app(&st, None, want);

    Json(RecentProposalsResp {
        ok: true,
        tip: format!("0x{}", hex::encode(tip)),
        height,
        scanned_blocks: 0,
        count: proposals.len(),
        proposals,
    })
}

/// GET /proposals/:domain/:limit
async fn all_proposals_by_domain(
    Path((domain, limit)): Path<(String, u64)>,
    State(st): State<ApiState>,
) -> Response {
    offload_display(move || all_proposals_by_domain_blocking(domain, limit, st).into_response())
        .await
}

fn all_proposals_by_domain_blocking(
    domain: String,
    limit: u64,
    st: ApiState,
) -> Json<RecentProposalsResp> {
    const MAX_LIMIT: u64 = 500;
    let want = limit.min(MAX_LIMIT).max(1);

    let (tip, height, proposals) = scan_all_proposals_from_app(&st, Some(&domain), want);

    Json(RecentProposalsResp {
        ok: true,
        tip: format!("0x{}", hex::encode(tip)),
        height,
        scanned_blocks: 0,
        count: proposals.len(),
        proposals,
    })
}

// ===========================
// Recent attestations feed
// ===========================

fn scan_attestations(
    st: &ApiState,
    domain_filter: Option<&str>,
    want: u64,
    max_back: u64,
) -> (Hash32, u64, u64, Vec<RecentAttestedItem>) {
    use std::collections::HashMap;

    let tip = get_tip(&st.db).unwrap().unwrap_or([0u8; 32]);
    let hi = get_hidx(&st.db, &tip)
        .unwrap()
        .unwrap_or_else(|| zero_hidx(tip));

    let mut cur_hash = tip;
    let mut cur_height = hi.height;
    let mut scanned: u64 = 0;

    let mut stats: HashMap<[u8; 32], AttStats> = HashMap::new();

    while scanned < max_back {
        let Some(v) = st.db.blocks.get(k_block(&cur_hash)).unwrap() else {
            break;
        };
        let blk: Block = match c().deserialize(&v) {
            Ok(b) => b,
            Err(_) => break,
        };

        for tx in blk.txs.iter().skip(1) {
            if let AppPayload::Attest {
                proposal_id,
                score,
                confidence,
            } = &tx.app
            {
                // If domain-filtered, only count attestations whose proposal matches domain.
                if let Some(df) = domain_filter {
                    let Some(pv) = st.db.app.get(k_proposal(proposal_id)).unwrap() else {
                        continue;
                    };
                    let prop: Proposal = match c().deserialize(&pv) {
                        Ok(p) => p,
                        Err(_) => continue,
                    };
                    if prop.domain != df {
                        continue;
                    }
                }

                let e = stats.entry(*proposal_id).or_default();
                e.count += 1;
                e.score_sum += *score as u64;
                e.conf_sum += *confidence as u64;
            }
        }

        scanned += 1;

        if blk.header.prev == [0u8; 32] || cur_height == 0 {
            break;
        }
        cur_hash = blk.header.prev;
        cur_height = cur_height.saturating_sub(1);
    }

    let mut items: Vec<RecentAttestedItem> = vec![];
    for (pid, stt) in stats {
        let Some(pv) = st.db.app.get(k_proposal(&pid)).unwrap() else {
            continue;
        };
        let prop: Proposal = match c().deserialize(&pv) {
            Ok(p) => p,
            Err(_) => continue,
        };

        if let Some(df) = domain_filter {
            if prop.domain != df {
                continue;
            }
        }

        items.push(RecentAttestedItem {
            proposal_id: format!("0x{}", hex::encode(pid)),
            attest_count: stt.count,
            score_sum: stt.score_sum,
            confidence_sum: stt.conf_sum,
            domain: prop.domain,
            payload_hash: format!("0x{}", hex::encode(prop.payload_hash)),
            uri: prop.uri,
            expires_epoch: prop.expires_epoch,
        });
    }

    items.sort_by(|a, b| {
        b.attest_count
            .cmp(&a.attest_count)
            .then_with(|| b.score_sum.cmp(&a.score_sum))
    });

    if items.len() > (want as usize) {
        items.truncate(want as usize);
    }

    (tip, hi.height, scanned, items)
}

/// GET /recent/attestations/:limit
async fn most_attested_global(Path(limit): Path<u64>, State(st): State<ApiState>) -> Response {
    offload_display(move || most_attested_global_blocking(limit, st).into_response()).await
}

fn most_attested_global_blocking(limit: u64, st: ApiState) -> Json<RecentAttestedResp> {
    const MAX_LIMIT: u64 = 200;
    const MAX_BACK: u64 = 5_000;
    let want = limit.min(MAX_LIMIT).max(1);

    let (tip, height, scanned, items) = scan_attestations(&st, None, want, MAX_BACK);

    Json(RecentAttestedResp {
        ok: true,
        tip: format!("0x{}", hex::encode(tip)),
        height,
        scanned_blocks: scanned,
        count: items.len(),
        items,
    })
}

/// GET /recent/attestations/:domain/:limit
async fn most_attested_by_domain(
    Path((domain, limit)): Path<(String, u64)>,
    State(st): State<ApiState>,
) -> Response {
    offload_display(move || most_attested_by_domain_blocking(domain, limit, st).into_response())
        .await
}

fn most_attested_by_domain_blocking(
    domain: String,
    limit: u64,
    st: ApiState,
) -> Json<RecentAttestedResp> {
    const MAX_LIMIT: u64 = 200;
    const MAX_BACK: u64 = 10_000;
    let want = limit.min(MAX_LIMIT).max(1);

    let (tip, height, scanned, items) = scan_attestations(&st, Some(&domain), want, MAX_BACK);

    Json(RecentAttestedResp {
        ok: true,
        tip: format!("0x{}", hex::encode(tip)),
        height,
        scanned_blocks: scanned,
        count: items.len(),
        items,
    })
}

// ===========================
// Computation window + canonical endpoints
// ===========================

// Keyed top-k read (one row plus its proposals), not a chain walk: ungated.
async fn window_domain(Path(domain): Path<String>, State(st): State<ApiState>) -> Json<WindowResp> {
    let tip = get_tip(&st.db).unwrap().unwrap_or([0u8; 32]);
    let hi = get_hidx(&st.db, &tip)
        .unwrap()
        .unwrap_or_else(|| zero_hidx(tip));

let epoch = crate::state::app_state::epoch_of(hi.height).saturating_sub(1);
    let rows = get_topk(&st.db, epoch, &domain).unwrap_or_default();
    let mut top: Vec<serde_json::Value> = vec![];
    for (pid, score) in rows {
        let Some(v) = st.db.app.get(k_proposal(&pid)).unwrap() else {
            continue;
        };
        let prop: Proposal = match c().deserialize(&v) {
            Ok(p) => p,
            Err(_) => continue,
        };

        top.push(serde_json::json!({
            "proposal_id": format!("0x{}", hex::encode(pid)),
            "score": score,
            "domain": prop.domain,
            "payload_hash": format!("0x{}", hex::encode(prop.payload_hash)),
            "uri": prop.uri,
            "expires_epoch": prop.expires_epoch
        }));
    }

    Json(WindowResp {
        tip: format!("0x{}", hex::encode(tip)),
        height: hi.height,
        epoch,
        top,
    })
}

// Keyed top-k reads (one row plus its proposals), not chain walks: ungated.
async fn top_current(
    Path(domain): Path<String>,
    State(st): State<ApiState>,
) -> Json<serde_json::Value> {
    let tip = get_tip(&st.db).unwrap().unwrap_or([0u8; 32]);
    let hi = get_hidx(&st.db, &tip)
        .unwrap()
        .unwrap_or_else(|| zero_hidx(tip));

let epoch = crate::state::app_state::epoch_of(hi.height).saturating_sub(1);
    top_for_epoch_impl(&st, domain, epoch)
}

async fn top_epoch(
    Path((domain, epoch)): Path<(String, u64)>,
    State(st): State<ApiState>,
) -> Json<serde_json::Value> {
    top_for_epoch_impl(&st, domain, epoch)
}

fn top_for_epoch_impl(st: &ApiState, domain: String, epoch: u64) -> Json<serde_json::Value> {
let rows = get_topk(&st.db, epoch, &domain).unwrap_or_default();
    
    let out: Vec<serde_json::Value> = rows
        .into_iter()
        .filter_map(|(pid, score)| {
            let v = st.db.app.get(k_proposal(&pid)).ok().flatten()?;
            let prop: Proposal = c().deserialize(&v).ok()?;
            Some(serde_json::json!({
                "proposal_id": format!("0x{}", hex::encode(pid)),
                "score": score,
                "domain": prop.domain,
                "payload_hash": format!("0x{}", hex::encode(prop.payload_hash)),
                "uri": prop.uri,
                "expires_epoch": prop.expires_epoch
            }))
        })
        .collect();

    Json(serde_json::json!({ "epoch": epoch, "domain": domain, "top": out }))
}

async fn proposal_get(
    Path(id): Path<String>,
    State(st): State<ApiState>,
) -> Json<serde_json::Value> {
    let pid = match parse_hash32(&id) {
        Ok(x) => x,
        Err(e) => return Json(serde_json::json!({ "ok": false, "err": e })),
    };

let Some(prop) = get_proposal(&st.db, &pid).unwrap() else {
    return Json(serde_json::json!({ "ok": false, "err": "not found" }));
};

    Json(serde_json::json!({
        "ok": true,
        "proposal": {
            "proposal_id": format!("0x{}", hex::encode(prop.id)),
            "domain": prop.domain,
            "payload_hash": format!("0x{}", hex::encode(prop.payload_hash)),
            "uri": prop.uri,
            "created_height": prop.created_height,
            "created_epoch": prop.created_epoch,
            "fee": prop.fee,
            "proposer": format!("0x{}", hex::encode(prop.proposer)),
            "expires_epoch": prop.expires_epoch
        }
    }))
}

async fn topk_get(
    Path((epoch, domain)): Path<(u64, String)>,
    State(st): State<ApiState>,
) -> Json<serde_json::Value> {
    let rows = get_topk(&st.db, epoch, &domain).unwrap_or_default();
    let out: Vec<serde_json::Value> = rows
        .into_iter()
        .map(|(pid, score)| {
            serde_json::json!({
                "proposal_id": format!("0x{}", hex::encode(pid)),
                "score": score
            })
        })
        .collect();

    Json(serde_json::json!({
        "ok": true,
        "epoch": epoch,
        "domain": domain,
        "topk": out
    }))
}

// ================================
// Template endpoint handlers
// ================================

async fn tx_template_propose(
    State(_st): State<ApiState>,
    Json(req): Json<TxTemplateProposeReq>,
) -> Json<TxTemplateResp> {
    if let Err(e) = ensure_base_unsigned(&req.tx) {
        return Json(TxTemplateResp {
            ok: false,
            unsigned_txid: "".to_string(),
            signing_hash: format!("err:{e}"),
            unsigned_tx: req.tx,
            note: None,
        });
    }

    let payload_hash = match parse_hash32(&req.payload_hash) {
        Ok(x) => x,
        Err(e) => {
            return Json(TxTemplateResp {
                ok: false,
                unsigned_txid: "".to_string(),
                signing_hash: format!("err:{e}"),
                unsigned_tx: req.tx,
                note: None,
            })
        }
    };

    let mut tx = req.tx;
    tx.app = AppPayload::Propose {
        domain: req.domain,
        payload_hash,
        uri: req.uri,
        expires_epoch: req.expires_epoch,
    };

    let unsigned_txid = txid(&tx);
    let signing_hash = sighash(&tx);

    Json(TxTemplateResp {
        ok: true,
        unsigned_txid: format!("0x{}", hex::encode(unsigned_txid)),
        signing_hash: format!("0x{}", hex::encode(signing_hash)),
        unsigned_tx: tx,
        note: Some(
            "Sign signing_hash (CSD_SIG_V1) with each input key; script_sig=[0x40][sig64][0x21][pub33]. Then POST {tx} to /tx/submit."
                .to_string(),
        ),
    })
}

async fn tx_template_attest(
    State(_st): State<ApiState>,
    Json(req): Json<TxTemplateAttestReq>,
) -> Json<TxTemplateResp> {
    if let Err(e) = ensure_base_unsigned(&req.tx) {
        return Json(TxTemplateResp {
            ok: false,
            unsigned_txid: "".to_string(),
            signing_hash: format!("err:{e}"),
            unsigned_tx: req.tx,
            note: None,
        });
    }

    let proposal_id = match parse_hash32(&req.proposal_id) {
        Ok(x) => x,
        Err(e) => {
            return Json(TxTemplateResp {
                ok: false,
                unsigned_txid: "".to_string(),
                signing_hash: format!("err:{e}"),
                unsigned_tx: req.tx,
                note: None,
            })
        }
    };

    let mut tx = req.tx;
    tx.app = AppPayload::Attest {
        proposal_id,
        score: req.score,
        confidence: req.confidence,
    };

    let unsigned_txid = txid(&tx);
    let signing_hash = sighash(&tx);

    Json(TxTemplateResp {
        ok: true,
        unsigned_txid: format!("0x{}", hex::encode(unsigned_txid)),
        signing_hash: format!("0x{}", hex::encode(signing_hash)),
        unsigned_tx: tx,
        note: Some(
            "Sign signing_hash (CSD_SIG_V1) with each input key; script_sig=[0x40][sig64][0x21][pub33]. Then POST {tx} to /tx/submit."
                .to_string(),
        ),
    })
}

async fn mempool_info(State(st): State<ApiState>) -> Json<serde_json::Value> {
    let s: MempoolStats = st.mempool.stats();

    Json(serde_json::json!({
        "ok": true,
        "tx_count": s.txs,
        "spent_outpoints": s.spent_len,
        "bytes": s.total_bytes,
        "min_feerate_ppm": s.min_feerate_ppm,
        "max_feerate_ppm": s.max_feerate_ppm,
    }))
}

const MEMPOOL_TXIDS_MAX: usize = 1000;

/// GET /mempool/txids: [{txid, age_secs}] for up to MEMPOOL_TXIDS_MAX mempool txs, oldest first,
/// with `total` (the pool's tx count) and `truncated` (the list stopped short of it). The
/// txid-level source a stranded-tx monitor needs to confirm a SPECIFIC tx is still pending across
/// ticks (the count-based /mempool signal false-fires under any sustained flow). Loopback-gated
/// like every other RPC route; read-only.
async fn mempool_txids(State(st): State<ApiState>) -> Json<serde_json::Value> {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    let (listed, total) = st.mempool.txids_with_age(now, MEMPOOL_TXIDS_MAX);
    let rows: Vec<serde_json::Value> = listed
        .into_iter()
        .map(|(id, age)| serde_json::json!({ "txid": format!("0x{}", hex::encode(id)), "age_secs": age }))
        .collect();
    Json(serde_json::json!({
        "ok": true,
        "count": rows.len(),
        "total": total,
        "truncated": rows.len() < total,
        "txids": rows,
    }))
}

/// What a `/tx/submit` check decided, once the gossip event it calls for is sent.
enum SubmitOutcome {
    Admitted,
    /// A tx with this txid is held; the held tx was re-gossiped.
    Duplicate,
    /// A different held tx spends these coins; nothing was gossiped.
    Conflict,
    Refused(anyhow::Error),
}

/// Checks `tx` for the mempool, admits it, and sends the gossip event the outcome calls for, with
/// no await in between. Run on the blocking pool, it finishes once started: a caller that hangs up
/// while its tx is checked (hyper then drops the handler) cannot leave an admitted tx ungossiped.
fn admit_and_gossip(
    db: &Stores,
    mempool: &Mempool,
    gossip: &tokio::sync::mpsc::UnboundedSender<GossipTxEvent>,
    tx: Transaction,
) -> SubmitOutcome {
    let id = txid(&tx);
    let txid_hex = format!("0x{}", hex::encode(id));

    // Single source of truth for mempool acceptance:
    // - validates structure + sigs + fee floors
    // - ensures inputs exist in current canonical UTXO set (so it can mine "now")
    // - prevents in-mempool double-spends
    match mempool.insert_checked(db, tx.clone()) {
        Ok(true) => {
            if let Some(first_inp) = tx.inputs.first() {
                println!(
                    "[tx_submit] ACCEPT txid={} first_input=0x{}:{}",
                    txid_hex,
                    hex::encode(first_inp.prevout.txid),
                    first_inp.prevout.vout
                );
            } else {
                println!("[tx_submit] ACCEPT txid={} no-inputs", txid_hex);
            }

            if let AppPayload::Propose { domain, .. } = &tx.app {
                println!("[tx_submit] app=Propose domain={}", domain);
            }
            if let AppPayload::Attest { proposal_id, .. } = &tx.app {
                println!(
                    "[tx_submit] app=Attest proposal_id=0x{}",
                    hex::encode(proposal_id)
                );
            }

            if let Err(e) = gossip.send(GossipTxEvent { tx, insure: true }) {
                println!("[tx_submit] gossip send failed for {}: {}", txid_hex, e);
            }
            SubmitOutcome::Admitted
        }
        Ok(false) => {
            // Re-gossip on a duplicate submit, but ONLY when a tx with this txid is held, and then
            // the held tx itself: a txid leaves the script_sigs out (crypto::txid), so the submitted
            // tx can carry other signature bytes, and gossiping it would publish a copy no node holds
            // (one new gossip id per POST). The original submit's gossip publish is single-shot and its errors are swallowed (e.g.
            // NoPeersSubscribedToTopic right after startup), so a tx can sit here unminable while wallets
            // resubmit byte-identical copies (deterministic signing) and get this branch forever.
            // A resubmit is the user asking "please propagate this";
            // re-sending the gossip event un-strands it network-wide (peers that saw it dedupe by
            // message-id; peers that never saw it finally get it). The held-tx guard matters:
            // Ok(false) also covers an input CONFLICT with a DIFFERENT mempool tx, and re-gossiping
            // an unheld conflicting tx would make this node amplify double-spend attempts.
            // Distinct err strings for the two Ok(false) truths: downstream
            // consumers (a proxy that submits to two backends, a wallet's duplicate-submit
            // classification) match /already present/; with one combined string they treated a
            // CONFLICT as a duplicate too: a proxy would copy a rejected double-spend to the second
            // backend and a wallet would tell the user their payment "should settle" when it never
            // will. The duplicate string still contains "already present", so older clients keep
            // matching exactly the case they meant.
            if let Some(held) = mempool.get(&id) {
                if let Err(e) = gossip.send(GossipTxEvent { tx: held, insure: false }) {
                    println!("[tx_submit] duplicate re-gossip send failed for {}: {}", txid_hex, e);
                } else {
                    println!("[tx_submit] DUPLICATE txid={} re-gossiped (held in mempool)", txid_hex);
                }
                SubmitOutcome::Duplicate
            } else {
                println!("[tx_submit] REJECT txid={} reason=mempool-conflict (not held; no re-gossip)", txid_hex);
                SubmitOutcome::Conflict
            }
        }
        Err(e) => {
            println!("[tx_submit] REJECT txid={} err={}", txid_hex, e);
            SubmitOutcome::Refused(e)
        }
    }
}

async fn tx_submit(State(st): State<ApiState>, Json(req): Json<TxSubmitReq>) -> Json<TxSubmitResp> {
    let txid_hex = format!("0x{}", hex::encode(txid(&req.tx)));

    // The wait for a permit is cancellable, so the clients' deadlines bound the queue
    // (`submit_gate`); once the permit is taken, the check, the admission and the gossip event
    // run to their end on the blocking pool whether or not this handler is still polled. A caller
    // that hung up gets no answer; its tx is held and gossiped, and a retry is answered
    // "already present in mempool" and re-gossips it.
    let permit = submit_gate()
        .clone()
        .acquire_owned()
        .await
        .expect("the submit gate is never closed");
    let (db, mempool, gossip) = (st.db.clone(), st.mempool.clone(), st.tx_gossip.clone());
    let outcome = tokio::task::spawn_blocking(move || {
        let _permit = permit;
        admit_and_gossip(&db, &mempool, &gossip, req.tx)
    })
    .await
    .unwrap_or_else(|e| SubmitOutcome::Refused(anyhow::anyhow!("submit validation did not finish: {e}")));

    let err = match outcome {
        SubmitOutcome::Admitted => None,
        SubmitOutcome::Duplicate => Some("already present in mempool".to_string()),
        SubmitOutcome::Conflict => {
            Some("mempool conflict: a different pending transaction spends these coins".to_string())
        }
        SubmitOutcome::Refused(e) => Some(e.to_string()),
    };
    Json(TxSubmitResp {
        ok: err.is_none(),
        txid: txid_hex,
        mempool_len: st.mempool.len(),
        err,
    })
}

#[cfg(test)]
fn test_api_state(dir: &tempfile::TempDir) -> ApiState {
    ApiState {
        db: Arc::new(Stores::open(dir.path().to_str().unwrap()).unwrap()),
        mempool: Arc::new(Mempool::new()),
        tx_gossip: tokio::sync::mpsc::unbounded_channel().0,
        connected_peers: Arc::new(AtomicUsize::new(0)),
        outbound_peers: Arc::new(AtomicUsize::new(0)),
        known_peers: Arc::new(AtomicUsize::new(0)),
        peer_id: PeerId::random(),
        best_peer_height: Arc::new(AtomicU64::new(0)),
        last_tip_activity_unix: Arc::new(AtomicU64::new(0)),
    }
}

#[cfg(test)]
mod tx_submit_tests {
    use super::*;
    use crate::state::db::k_utxo;
    use crate::types::TxIn;

    const SK: [u8; 32] = [21u8; 32];

    // The submit gate is a process-wide static, so these tests take it one at a time: a permit
    // another test holds would make `a_submit_is_validated_off_the_runtime_thread` pass on the wait
    // for it, whatever runs the validation.
    static SUBMIT_LOCK: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

    /// A tx spending a funded coin, signed with `nonce` as extra nonce data when given: the same
    /// txid either way, other script_sig bytes.
    fn signed(nonce: Option<[u8; 32]>) -> Transaction {
        signed_paying(995_000, nonce)
    }

    /// Funds the coin `tx` spends, owned by SK's key.
    fn fund(st: &ApiState, tx: &Transaction) {
        let (_, pub33) = crate::crypto::sign_tx_compact_secp256k1(tx, SK);
        let coin = TxOut { value: 1_000_000, script_pubkey: crate::crypto::hash160(&pub33) };
        st.db.utxo.insert(k_utxo(&tx.inputs[0].prevout), c().serialize(&coin).unwrap()).unwrap();
    }

    /// As `signed`, paying `value`: another value is another txid spending the same coin.
    fn signed_paying(value: u64, nonce: Option<[u8; 32]>) -> Transaction {
        use secp256k1::{Message, PublicKey, Secp256k1, SecretKey};
        let secp = Secp256k1::new();
        let sk = SecretKey::from_slice(&SK).unwrap();
        let mut tx = Transaction {
            version: 1,
            inputs: vec![TxIn { prevout: OutPoint { txid: [5u8; 32], vout: 0 }, script_sig: vec![] }],
            outputs: vec![TxOut { value, script_pubkey: [9u8; 20] }],
            locktime: 0,
            app: AppPayload::None,
        };
        let msg = Message::from_digest_slice(&sighash(&tx)).unwrap();
        let mut sig = match nonce {
            Some(n) => secp.sign_ecdsa_with_noncedata(&msg, &sk, &n),
            None => secp.sign_ecdsa(&msg, &sk),
        };
        sig.normalize_s();
        let mut ss = vec![64u8];
        ss.extend_from_slice(&sig.serialize_compact());
        ss.push(33);
        ss.extend_from_slice(&PublicKey::from_secret_key(&secp, &sk).serialize());
        tx.inputs[0].script_sig = ss;
        tx
    }

    #[tokio::test]
    async fn a_duplicate_submit_regossips_the_held_tx_not_the_submitted_copy() {
        let _g = SUBMIT_LOCK.lock().await;
        let dir = tempfile::TempDir::new().unwrap();
        let (tx_gossip, mut gossiped) = tokio::sync::mpsc::unbounded_channel();
        let st = ApiState { tx_gossip, ..test_api_state(&dir) };

        let held = signed(None);
        let other_sig = signed(Some([7u8; 32]));
        assert_eq!(txid(&held), txid(&other_sig));
        assert_ne!(held.inputs[0].script_sig, other_sig.inputs[0].script_sig);
        fund(&st, &held);
        let bytes = |tx: &Transaction| c().serialize(tx).unwrap();

        let first = tx_submit(State(st.clone()), Json(TxSubmitReq { tx: held.clone() })).await.0;
        assert!(first.ok, "{:?}", first.err);
        assert!(gossiped.try_recv().unwrap().insure);

        // Honest path: a byte-identical resubmit is re-gossiped (the strand cure).
        let again = tx_submit(State(st.clone()), Json(TxSubmitReq { tx: held.clone() })).await.0;
        assert_eq!(again.err.as_deref(), Some("already present in mempool"));
        assert_eq!(bytes(&gossiped.try_recv().unwrap().tx), bytes(&held));

        let copy = tx_submit(State(st.clone()), Json(TxSubmitReq { tx: other_sig })).await.0;
        assert_eq!(copy.err.as_deref(), Some("already present in mempool"));
        assert_eq!(
            bytes(&gossiped.try_recv().unwrap().tx),
            bytes(&held),
            "a resubmit with other signature bytes re-gossips the held tx; gossiping the copy \
             would publish bytes no node holds, a new gossip id for every POST"
        );
    }

    // /tx/submit validates at most two txs at once
    // (SUBMIT_PERMITS) and queues the next instead of refusing it. With both permits held, a submit
    // is still waiting after four times the read gates' shedding wait; once a permit frees it is
    // admitted, the honest path through the real handler.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_full_submit_gate_queues_a_submit_and_admits_it_once_a_permit_frees() {
        let _g = SUBMIT_LOCK.lock().await;
        let dir = tempfile::TempDir::new().unwrap();
        let st = test_api_state(&dir);
        let tx = signed(None);
        fund(&st, &tx);

        let held = submit_gate().clone().acquire_many_owned(2).await.unwrap();
        let submit = tokio::spawn(tx_submit(State(st.clone()), Json(TxSubmitReq { tx: tx.clone() })));
        tokio::time::sleep(std::time::Duration::from_millis(4 * GATE_WAIT_MS)).await;
        assert!(!submit.is_finished(), "a submit was validated while every validation permit was held");
        assert_eq!(st.mempool.len(), 0);

        drop(held);
        let resp = tokio::time::timeout(std::time::Duration::from_secs(30), submit)
            .await
            .expect("the queued submit finishes once a permit frees")
            .unwrap()
            .0;
        assert!(resp.ok, "the queued submit was refused: {:?}", resp.err);
        assert!(st.mempool.contains(&txid(&tx)));
    }

    // A submit's validation runs on the blocking pool, so the runtime thread
    // that took the request is free while a wide tx is checked. On a one-thread runtime, the
    // submit task yields at its validation instead of running it to the end inside one poll.
    #[tokio::test(flavor = "current_thread")]
    async fn a_submit_is_validated_off_the_runtime_thread() {
        let _g = SUBMIT_LOCK.lock().await;
        const INPUTS: usize = 512;
        let dir = tempfile::TempDir::new().unwrap();
        let st = test_api_state(&dir);
        let mut tx = Transaction {
            version: 1,
            inputs: (0..INPUTS as u32)
                .map(|i| TxIn { prevout: OutPoint { txid: [6u8; 32], vout: i }, script_sig: vec![] })
                .collect(),
            outputs: vec![TxOut { value: 1_000 * INPUTS as u64 - 1, script_pubkey: [9u8; 20] }],
            locktime: 0,
            app: AppPayload::None,
        };
        let (sig64, pub33) = crate::crypto::sign_tx_compact_secp256k1(&tx, SK);
        let coin = TxOut { value: 1_000, script_pubkey: crate::crypto::hash160(&pub33) };
        let mut ss = vec![64u8];
        ss.extend_from_slice(&sig64);
        ss.push(33);
        ss.extend_from_slice(&pub33);
        for inp in &mut tx.inputs {
            inp.script_sig = ss.clone();
            st.db.utxo.insert(k_utxo(&inp.prevout), c().serialize(&coin).unwrap()).unwrap();
        }
        tx.inputs[INPUTS - 1].script_sig[10] ^= 0x01;

        let submit = tokio::spawn(tx_submit(State(st.clone()), Json(TxSubmitReq { tx })));
        tokio::task::yield_now().await;
        assert!(!submit.is_finished(), "the submit was validated inside one poll of the runtime thread");
        let resp = submit.await.unwrap().0;
        assert!(!resp.ok);
        assert!(resp.err.unwrap().contains("signature"));
    }

    // A caller that hangs up while its submit is checked makes hyper
    // drop the handler (no half-close, hyper-1.8.1 `proto/h1/conn.rs:490-503`), and a client's
    // deadline does that. When the check ran on the blocking pool and admitted the tx while the
    // gossip send waited in the handler, a dropped handler left the tx held and never gossiped. The handler
    // is held off the runtime thread until the check has admitted the tx, then cancelled.
    #[tokio::test(flavor = "current_thread")]
    async fn a_submit_whose_caller_hangs_up_during_its_check_is_still_gossiped() {
        let _g = SUBMIT_LOCK.lock().await;
        let dir = tempfile::TempDir::new().unwrap();
        let (tx_gossip, mut gossiped) = tokio::sync::mpsc::unbounded_channel();
        let st = ApiState { tx_gossip, ..test_api_state(&dir) };
        let tx = signed(None);
        fund(&st, &tx);

        let submit = tokio::spawn(tx_submit(State(st.clone()), Json(TxSubmitReq { tx: tx.clone() })));
        tokio::task::yield_now().await;
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(30);
        while !st.mempool.contains(&txid(&tx)) {
            assert!(std::time::Instant::now() < deadline, "the submit's check never admitted the tx");
            std::thread::sleep(std::time::Duration::from_millis(5));
        }
        submit.abort();
        assert!(submit.await.err().is_some_and(|e| e.is_cancelled()), "the handler finished before it was cancelled");

        let ev = tokio::time::timeout(std::time::Duration::from_secs(5), gossiped.recv())
            .await
            .expect("an admitted tx whose submit handler was dropped was never gossiped")
            .unwrap();
        assert!(ev.insure, "a first accept is gossiped insured");
        assert_eq!(c().serialize(&ev.tx).unwrap(), c().serialize(&tx).unwrap());
    }

    // The wait for a permit stays cancellable: the queue has no waiter cap and the clients'
    // deadlines bound it (SUBMIT_PERMITS), so a caller that hangs up before its check starts
    // leaves the queue, and its tx is neither checked nor gossiped.
    #[tokio::test(flavor = "current_thread")]
    async fn a_submit_whose_caller_hangs_up_while_queued_is_never_checked() {
        let _g = SUBMIT_LOCK.lock().await;
        let dir = tempfile::TempDir::new().unwrap();
        let (tx_gossip, mut gossiped) = tokio::sync::mpsc::unbounded_channel();
        let st = ApiState { tx_gossip, ..test_api_state(&dir) };
        let tx = signed(None);
        fund(&st, &tx);

        let held = submit_gate().clone().acquire_many_owned(SUBMIT_PERMITS as u32).await.unwrap();
        let submit = tokio::spawn(tx_submit(State(st.clone()), Json(TxSubmitReq { tx: tx.clone() })));
        tokio::task::yield_now().await;
        submit.abort();
        assert!(submit.await.err().is_some_and(|e| e.is_cancelled()));
        drop(held);

        tokio::time::sleep(std::time::Duration::from_millis(500)).await;
        assert!(!st.mempool.contains(&txid(&tx)), "a submit whose caller left the queue was checked");
        assert!(gossiped.try_recv().is_err());
        assert_eq!(submit_gate().available_permits(), SUBMIT_PERMITS);
    }

    // A wallet and a proxy that submits to two backends read /already present/ as "held, will
    // settle". A different tx spending the same coin gets the conflict text, which must not match
    // it, and is not gossiped: re-gossiping it would make this node relay double-spend attempts.
    #[tokio::test]
    async fn a_conflicting_submit_is_refused_as_a_conflict_and_not_gossiped() {
        let _g = SUBMIT_LOCK.lock().await;
        let dir = tempfile::TempDir::new().unwrap();
        let (tx_gossip, mut gossiped) = tokio::sync::mpsc::unbounded_channel();
        let st = ApiState { tx_gossip, ..test_api_state(&dir) };

        let held = signed(None);
        let conflict = signed_paying(990_000, None);
        assert_ne!(txid(&held), txid(&conflict));
        assert_eq!(held.inputs[0].prevout, conflict.inputs[0].prevout);
        fund(&st, &held);

        let first = tx_submit(State(st.clone()), Json(TxSubmitReq { tx: held.clone() })).await.0;
        assert!(first.ok, "{:?}", first.err);
        assert!(gossiped.try_recv().is_ok());

        let refused = tx_submit(State(st.clone()), Json(TxSubmitReq { tx: conflict })).await.0;
        assert!(!refused.ok);
        let err = refused.err.unwrap();
        assert_eq!(err, "mempool conflict: a different pending transaction spends these coins");
        assert!(!err.contains("already present"), "consumers would read the conflict as held");
        assert!(gossiped.try_recv().is_err(), "the conflicting tx was gossiped");
        assert!(st.mempool.contains(&txid(&held)) && st.mempool.len() == 1, "the held tx stays");
    }
}

#[cfg(test)]
mod mempool_txids_tests {
    use super::*;

    // A list that stops at 1,000 with nothing to say so leaves a consumer to copy
    // the constant and guess. `total` and `truncated` say it; under the cap they say nothing is
    // missing.
    #[tokio::test]
    async fn the_txid_list_says_when_it_stops_short_of_the_pool() {
        use crate::types::TxIn;
        let dir = tempfile::TempDir::new().unwrap();
        let st = test_api_state(&dir);
        let tx = |n: u32| Transaction {
            version: 1,
            inputs: vec![TxIn { prevout: OutPoint { txid: [1u8; 32], vout: n }, script_sig: vec![] }],
            outputs: vec![TxOut { value: 1, script_pubkey: [2u8; 20] }],
            locktime: 0,
            app: AppPayload::None,
        };
        for n in 0..3 {
            st.mempool.force_insert_for_test(tx(n), 1);
        }
        let j = mempool_txids(State(st.clone())).await.0;
        assert_eq!((j["count"].as_u64(), j["total"].as_u64(), j["truncated"].as_bool()), (Some(3), Some(3), Some(false)));

        for n in 3..MEMPOOL_TXIDS_MAX as u32 + 1 {
            st.mempool.force_insert_for_test(tx(n), 1);
        }
        let j = mempool_txids(State(st)).await.0;
        assert_eq!(j["txids"].as_array().unwrap().len(), MEMPOOL_TXIDS_MAX);
        assert_eq!(
            (j["count"].as_u64(), j["total"].as_u64(), j["truncated"].as_bool()),
            (Some(MEMPOOL_TXIDS_MAX as u64), Some(MEMPOOL_TXIDS_MAX as u64 + 1), Some(true))
        );
    }
}

#[cfg(test)]
mod utxos_tests {
    use super::*;
    use crate::state::db::k_utxo;

    #[test]
    fn the_balance_covers_every_coin_when_the_list_is_limited() {
        let dir = tempfile::TempDir::new().unwrap();
        let st = test_api_state(&dir);
        let owner = [4u8; 20];
        for (tag, value) in [(1u8, 300u64), (2, 500)] {
            let op = OutPoint { txid: [tag; 32], vout: 0 };
            let coin = TxOut { value, script_pubkey: owner };
            st.db.utxo.insert(k_utxo(&op), c().serialize(&coin).unwrap()).unwrap();
        }
        let addr = format!("0x{}", hex::encode(owner));
        let query = |limit| UtxosQuery { available: None, min_value: None, smallest: Some(true), limit, lifetime: None };

        let all = utxos_for_addr20_blocking(addr.clone(), query(None), st.clone()).unwrap();
        assert_eq!((all.count, all.confirmed_balance), (2, 800));

        let one = utxos_for_addr20_blocking(addr, query(Some(1)), st).unwrap();
        assert_eq!(one.utxos.len(), 1, "limit shortens the list");
        assert_eq!(
            one.confirmed_balance, 800,
            "confirmed_balance is the address's balance over the filtered coins, not the sum of the \
             first `limit` of them"
        );
    }

    // The lifetime totals walk every block body, inside the heavy-scan gate a public
    // reverse proxy can reach. They run only on `?lifetime=true`; without it the
    // two keys stay, as null.
    #[test]
    fn the_lifetime_walk_runs_only_when_asked() {
        use crate::state::db::k_meta_tip;
        use crate::types::{BlockHeader, TxIn};
        let dir = tempfile::TempDir::new().unwrap();
        let st = test_api_state(&dir);
        let owner = [4u8; 20];
        let coinbase = Transaction {
            version: 1,
            inputs: vec![TxIn { prevout: OutPoint { txid: [0u8; 32], vout: u32::MAX }, script_sig: vec![] }],
            outputs: vec![TxOut { value: 700, script_pubkey: owner }],
            locktime: 0,
            app: AppPayload::None,
        };
        let block = Block {
            header: BlockHeader { version: 1, prev: [0u8; 32], merkle: [0u8; 32], time: 1, bits: 0, nonce: 0 },
            txs: vec![coinbase],
        };
        let tip = [7u8; 32];
        st.db.blocks.insert(k_block(&tip), c().serialize(&block).unwrap()).unwrap();
        st.db.meta.insert(k_meta_tip(), &tip[..]).unwrap();
        let op = OutPoint { txid: [1u8; 32], vout: 0 };
        st.db.utxo.insert(k_utxo(&op), c().serialize(&TxOut { value: 300, script_pubkey: owner }).unwrap()).unwrap();
        let addr = format!("0x{}", hex::encode(owner));
        let ask = |uri: &str| {
            let q = Query::<UtxosQuery>::try_from_uri(&uri.parse().unwrap()).unwrap().0;
            utxos_for_addr20_blocking(addr.clone(), q, st.clone()).unwrap()
        };

        let plain = ask("http://n/utxos/a?available=true");
        assert_eq!((plain.mined_lifetime, plain.coinbase_lifetime_outputs), (None, None), "no walk unless asked");
        let j = serde_json::to_value(&plain).unwrap();
        assert!(j["mined_lifetime"].is_null() && j["coinbase_lifetime_outputs"].is_null(), "the keys stay: {j}");
        assert_eq!((plain.ok, plain.count, plain.confirmed_balance), (true, 1, 300));

        let asked = ask("http://n/utxos/a?available=true&lifetime=true");
        assert_eq!((asked.mined_lifetime, asked.coinbase_lifetime_outputs), (Some(700), Some(1)));
        assert_eq!((asked.ok, asked.count, asked.confirmed_balance), (true, 1, 300));
    }

    // A read of one address must not scan the whole UTXO tree, or
    // its cost grows with every other address's coins, inside the 6-permit heavy-scan gate.
    #[test]
    fn one_address_read_does_not_scale_with_the_utxo_set() {
        let target = [0x7au8; 20];
        let addr = format!("0x{}", hex::encode(target));
        let query = || UtxosQuery { available: Some(true), min_value: None, smallest: None, limit: None, lifetime: None };
        let cost = |others: usize| {
            let dir = tempfile::TempDir::new().unwrap();
            let st = test_api_state(&dir);
            crate::testutil::chain_paying(st.db.as_ref(), others, target, 3).unwrap();
            while !crate::state::tx_scan::reconcile_tick(st.db.as_ref(), 1_000).unwrap() {}
            let r = utxos_for_addr20_blocking(addr.clone(), query(), st.clone()).unwrap();
            assert_eq!((r.ok, r.count, r.confirmed_balance), (true, 3, 3));
            crate::testutil::fastest(5, || {
                utxos_for_addr20_blocking(addr.clone(), query(), st.clone()).unwrap();
            })
        };
        let (small, large) = (cost(2_000), cost(32_000));
        eprintln!("[cost] one address's 3 coins beside 2,000 other coins: {small:?}; beside 32,000: {large:?}");
        assert!(
            large < small * 3 + std::time::Duration::from_micros(300),
            "one address's read grew with the other addresses' coins: {small:?} -> {large:?}"
        );
    }

    // The answer names the tip it was read at, so a caller can tell which
    // block's state a balance is from, whichever path read it.
    #[test]
    fn the_answer_names_the_tip_it_was_read_at() {
        let dir = tempfile::TempDir::new().unwrap();
        let st = test_api_state(&dir);
        let target = [0x7au8; 20];
        crate::testutil::chain_paying(st.db.as_ref(), 10, target, 3).unwrap();
        let tip = format!("0x{}", hex::encode(get_tip(st.db.as_ref()).unwrap().unwrap()));
        let ask = |addr: String| {
            let q = UtxosQuery { available: Some(true), min_value: None, smallest: None, limit: None, lifetime: None };
            serde_json::to_value(utxos_for_addr20_blocking(addr, q, st.clone()).unwrap()).unwrap()
        };
        let addr = format!("0x{}", hex::encode(target));
        let scanned = ask(addr.clone());
        assert_eq!((scanned["tip"].as_str(), scanned["count"].as_u64()), (Some(tip.as_str()), Some(3)), "{scanned}");
        while !crate::state::tx_scan::reconcile_tick(st.db.as_ref(), 1_000).unwrap() {}
        let indexed = ask(addr);
        assert_eq!((indexed["tip"].as_str(), indexed["count"].as_u64()), (Some(tip.as_str()), Some(3)), "{indexed}");
        let refused = ask("0xnot-an-address".into());
        assert!(refused["ok"] == false && refused["tip"].is_null(), "{refused}");
    }
}

#[cfg(test)]
mod display_gate_tests {
    use super::*;
    use crate::state::app_state::k_attest;
    use crate::state::db::k_meta_tip;
    use crate::types::{TxIn, TxOut};
    use crate::types::BlockHeader;

    // The display gate is a process-wide static, so these tests take it one at a time.
    static GATE_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

    fn app_tx(app: AppPayload) -> Transaction {
        Transaction {
            version: 1,
            inputs: vec![TxIn { prevout: OutPoint { txid: [9u8; 32], vout: 0 }, script_sig: vec![] }],
            outputs: vec![TxOut { value: 1, script_pubkey: [1u8; 20] }],
            locktime: 0,
            app,
        }
    }

    /// A one-block chain with a proposal and an attestation in it, plus app-state rows for two
    /// domains, so every display route has something to render.
    fn seed(db: &Stores) {
        let propose = app_tx(AppPayload::Propose {
            domain: "alpha".into(),
            payload_hash: [3u8; 32],
            uri: "ipfs://alpha".into(),
            expires_epoch: 10,
        });
        let p1 = txid(&propose);
        let attest = app_tx(AppPayload::Attest { proposal_id: p1, score: 90, confidence: 80 });
        let coinbase = app_tx(AppPayload::None);
        let block = Block {
            header: BlockHeader { version: 1, prev: [0u8; 32], merkle: [0u8; 32], time: 1_700_000_000, bits: 0, nonce: 0 },
            txs: vec![coinbase, propose, attest],
        };
        let tip = [7u8; 32];
        db.blocks.insert(k_block(&tip), c().serialize(&block).unwrap()).unwrap();
        db.meta.insert(k_meta_tip(), &tip[..]).unwrap();

        let p2 = [2u8; 32];
        for (id, domain, fee) in [(p1, "alpha", 5u64), (p2, "beta", 3u64)] {
            let prop = Proposal {
                id,
                domain: domain.into(),
                payload_hash: [4u8; 32],
                uri: format!("ipfs://{domain}"),
                created_height: 0,
                created_epoch: 0,
                expires_epoch: 10,
                fee,
                proposer: [5u8; 20],
            };
            db.app.insert(k_proposal(&id), c().serialize(&prop).unwrap()).unwrap();
            let att = Attestation {
                id: [fee as u8; 32],
                proposal_id: id,
                weight: fee,
                height: 0,
                epoch: 0,
                attester: [6u8; 20],
                score: 90,
                confidence: 80,
            };
            db.app.insert(k_attest(&att.id), c().serialize(&att).unwrap()).unwrap();
            let rows: Vec<(Hash32, u128)> = vec![(id, fee as u128)];
            db.app
                .insert(crate::state::app_state::k_topk(0, domain), c().serialize(&rows).unwrap())
                .unwrap();
        }
    }

    async fn status_and_body(r: Response) -> (u16, String) {
        let status = r.status().as_u16();
        let bytes = axum::body::to_bytes(r.into_body(), usize::MAX).await.unwrap();
        (status, String::from_utf8(bytes.to_vec()).unwrap())
    }

    /// Every display route, called through its axum handler exactly as the router does.
    async fn display_routes(st: &ApiState) -> Vec<(&'static str, u16, String)> {
        let s = || State(st.clone());
        vec![
            ("/domains", status_and_body(domains_list(s()).await.into_response()).await),
            ("/proposals/10", status_and_body(all_proposals(Path(10), s()).await.into_response()).await),
            ("/proposals/alpha/10", status_and_body(all_proposals_by_domain(Path(("alpha".into(), 10)), s()).await.into_response()).await),
            ("/window/alpha", status_and_body(window_domain(Path("alpha".into()), s()).await.into_response()).await),
            ("/top/global", status_and_body(top_global(s()).await.into_response()).await),
            ("/top/active", status_and_body(top_active(s()).await.into_response()).await),
            ("/top/all-time", status_and_body(top_all_time(s()).await.into_response()).await),
            ("/top/alpha", status_and_body(top_current(Path("alpha".into()), s()).await.into_response()).await),
            ("/top/beta/0", status_and_body(top_epoch(Path(("beta".into(), 0)), s()).await.into_response()).await),
            ("/recent/proposals/10", status_and_body(recent_proposals(Path(10), s()).await.into_response()).await),
            ("/recent/proposals/alpha/10", status_and_body(recent_proposals_by_domain(Path(("alpha".into(), 10)), s()).await.into_response()).await),
            ("/recent/attestations/10", status_and_body(most_attested_global(Path(10), s()).await.into_response()).await),
            ("/recent/attestations/alpha/10", status_and_body(most_attested_by_domain(Path(("alpha".into(), 10)), s()).await.into_response()).await),
        ]
        .into_iter()
        .map(|(p, (code, body))| (p, code, body))
        .collect()
    }

    /// Bodies captured from the ungated handlers on `seed`, before the display gate was added:
    /// the gate must not change a byte of any answer.
    const PRE_GATE_BODIES: [(&str, u16, &str); 13] = [
        ("/domains", 200, r#"{"ok":true,"tip":"0x0707070707070707070707070707070707070707070707070707070707070707","height":0,"count":2,"domains":[{"domain":"alpha","proposals":1,"attestations":1},{"domain":"beta","proposals":1,"attestations":0}]}"#),
        ("/proposals/10", 200, r#"{"ok":true,"tip":"0x0707070707070707070707070707070707070707070707070707070707070707","height":0,"scanned_blocks":0,"count":1,"proposals":[{"proposal_id":"0x807a2f18cddbebe0c737fbbe97530191c38100d3244e5df301d041d242977ce2","txid":"0x807a2f18cddbebe0c737fbbe97530191c38100d3244e5df301d041d242977ce2","block_hash":"0x0707070707070707070707070707070707070707070707070707070707070707","height":0,"time":1700000000,"domain":"alpha","payload_hash":"0x0303030303030303030303030303030303030303030303030303030303030303","uri":"ipfs://alpha","expires_epoch":10}]}"#),
        ("/proposals/alpha/10", 200, r#"{"ok":true,"tip":"0x0707070707070707070707070707070707070707070707070707070707070707","height":0,"scanned_blocks":0,"count":1,"proposals":[{"proposal_id":"0x807a2f18cddbebe0c737fbbe97530191c38100d3244e5df301d041d242977ce2","txid":"0x807a2f18cddbebe0c737fbbe97530191c38100d3244e5df301d041d242977ce2","block_hash":"0x0707070707070707070707070707070707070707070707070707070707070707","height":0,"time":1700000000,"domain":"alpha","payload_hash":"0x0303030303030303030303030303030303030303030303030303030303030303","uri":"ipfs://alpha","expires_epoch":10}]}"#),
        ("/window/alpha", 200, r#"{"tip":"0x0707070707070707070707070707070707070707070707070707070707070707","height":0,"epoch":0,"top":[{"domain":"alpha","expires_epoch":10,"payload_hash":"0x0404040404040404040404040404040404040404040404040404040404040404","proposal_id":"0x807a2f18cddbebe0c737fbbe97530191c38100d3244e5df301d041d242977ce2","score":5,"uri":"ipfs://alpha"}]}"#),
        ("/top/global", 200, r#"{"epoch":0,"ok":true,"top":[{"domain":"alpha","economic_weight":5,"expires_epoch":10,"payload_hash":"0x0404040404040404040404040404040404040404040404040404040404040404","proposal_id":"0x807a2f18cddbebe0c737fbbe97530191c38100d3244e5df301d041d242977ce2","uri":"ipfs://alpha"},{"domain":"beta","economic_weight":3,"expires_epoch":10,"payload_hash":"0x0404040404040404040404040404040404040404040404040404040404040404","proposal_id":"0x0202020202020202020202020202020202020202020202020202020202020202","uri":"ipfs://beta"}]}"#),
        ("/top/active", 200, r#"{"current_epoch":0,"height":0,"ok":true,"tip":"0x0707070707070707070707070707070707070707070707070707070707070707","top":[{"attest_count":1,"created_epoch":0,"domain":"alpha","economic_weight":5,"expires_epoch":10,"payload_hash":"0x0404040404040404040404040404040404040404040404040404040404040404","proposal_id":"0x807a2f18cddbebe0c737fbbe97530191c38100d3244e5df301d041d242977ce2","raw_confidence_sum":80,"raw_score_sum":90,"uri":"ipfs://alpha"},{"attest_count":1,"created_epoch":0,"domain":"beta","economic_weight":3,"expires_epoch":10,"payload_hash":"0x0404040404040404040404040404040404040404040404040404040404040404","proposal_id":"0x0202020202020202020202020202020202020202020202020202020202020202","raw_confidence_sum":80,"raw_score_sum":90,"uri":"ipfs://beta"}]}"#),
        ("/top/all-time", 200, r#"{"height":0,"ok":true,"tip":"0x0707070707070707070707070707070707070707070707070707070707070707","top":[{"attest_count":1,"created_epoch":0,"domain":"alpha","economic_weight":5,"expires_epoch":10,"payload_hash":"0x0404040404040404040404040404040404040404040404040404040404040404","proposal_id":"0x807a2f18cddbebe0c737fbbe97530191c38100d3244e5df301d041d242977ce2","raw_confidence_sum":80,"raw_score_sum":90,"uri":"ipfs://alpha"},{"attest_count":1,"created_epoch":0,"domain":"beta","economic_weight":3,"expires_epoch":10,"payload_hash":"0x0404040404040404040404040404040404040404040404040404040404040404","proposal_id":"0x0202020202020202020202020202020202020202020202020202020202020202","raw_confidence_sum":80,"raw_score_sum":90,"uri":"ipfs://beta"}]}"#),
        ("/top/alpha", 200, r#"{"domain":"alpha","epoch":0,"top":[{"domain":"alpha","expires_epoch":10,"payload_hash":"0x0404040404040404040404040404040404040404040404040404040404040404","proposal_id":"0x807a2f18cddbebe0c737fbbe97530191c38100d3244e5df301d041d242977ce2","score":5,"uri":"ipfs://alpha"}]}"#),
        ("/top/beta/0", 200, r#"{"domain":"beta","epoch":0,"top":[{"domain":"beta","expires_epoch":10,"payload_hash":"0x0404040404040404040404040404040404040404040404040404040404040404","proposal_id":"0x0202020202020202020202020202020202020202020202020202020202020202","score":3,"uri":"ipfs://beta"}]}"#),
        ("/recent/proposals/10", 200, r#"{"ok":true,"tip":"0x0707070707070707070707070707070707070707070707070707070707070707","height":0,"scanned_blocks":1,"count":1,"proposals":[{"proposal_id":"0x807a2f18cddbebe0c737fbbe97530191c38100d3244e5df301d041d242977ce2","txid":"0x807a2f18cddbebe0c737fbbe97530191c38100d3244e5df301d041d242977ce2","block_hash":"0x0707070707070707070707070707070707070707070707070707070707070707","height":0,"time":1700000000,"domain":"alpha","payload_hash":"0x0303030303030303030303030303030303030303030303030303030303030303","uri":"ipfs://alpha","expires_epoch":10}]}"#),
        ("/recent/proposals/alpha/10", 200, r#"{"ok":true,"tip":"0x0707070707070707070707070707070707070707070707070707070707070707","height":0,"scanned_blocks":1,"count":1,"proposals":[{"proposal_id":"0x807a2f18cddbebe0c737fbbe97530191c38100d3244e5df301d041d242977ce2","txid":"0x807a2f18cddbebe0c737fbbe97530191c38100d3244e5df301d041d242977ce2","block_hash":"0x0707070707070707070707070707070707070707070707070707070707070707","height":0,"time":1700000000,"domain":"alpha","payload_hash":"0x0303030303030303030303030303030303030303030303030303030303030303","uri":"ipfs://alpha","expires_epoch":10}]}"#),
        ("/recent/attestations/10", 200, r#"{"ok":true,"tip":"0x0707070707070707070707070707070707070707070707070707070707070707","height":0,"scanned_blocks":1,"count":1,"items":[{"proposal_id":"0x807a2f18cddbebe0c737fbbe97530191c38100d3244e5df301d041d242977ce2","attest_count":1,"score_sum":90,"confidence_sum":80,"domain":"alpha","payload_hash":"0x0404040404040404040404040404040404040404040404040404040404040404","uri":"ipfs://alpha","expires_epoch":10}]}"#),
        ("/recent/attestations/alpha/10", 200, r#"{"ok":true,"tip":"0x0707070707070707070707070707070707070707070707070707070707070707","height":0,"scanned_blocks":1,"count":1,"items":[{"proposal_id":"0x807a2f18cddbebe0c737fbbe97530191c38100d3244e5df301d041d242977ce2","attest_count":1,"score_sum":90,"confidence_sum":80,"domain":"alpha","payload_hash":"0x0404040404040404040404040404040404040404040404040404040404040404","uri":"ipfs://alpha","expires_epoch":10}]}"#),
    ];

    // /health: with `ok` true whatever had died, a node whose p2p task had panicked would
    // answer ok with a frozen tip and a monitor would have to read /node/info. It is false once a
    // supervised task has panicked (spawn_supervised, the production path), still answered as 200.
    #[tokio::test]
    async fn health_ok_is_false_once_a_supervised_task_has_died() {
        use crate::state::subsystem::{spawn_supervised, Subsystems};
        let dir = tempfile::TempDir::new().unwrap();
        let st = test_api_state(&dir);
        let tasks: &'static Subsystems = Box::leak(Box::new(Subsystems::new()));
        assert!(health_resp(&st, tasks).ok, "a fresh node is ok");
        spawn_supervised("health-test", &tasks.p2p, async { panic!("health test: a deliberate p2p panic") });
        for _ in 0..100 {
            if !tasks.all_healthy() {
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(20)).await;
        }
        assert!(!health_resp(&st, tasks).ok, "a dead p2p task is not ok");
    }

    #[tokio::test]
    async fn node_info_reports_bad_marks_and_dropped_bodies() {
        let dir = tempfile::TempDir::new().unwrap();
        let st = test_api_state(&dir);
        let before = node_info(State(st.clone())).await.0;
        assert_eq!(before.bad_block_marks, Some(0));

        st.db.meta.insert(crate::state::db::k_bad(&[1u8; 32]), &b"1"[..]).unwrap();
        st.db.meta.insert(crate::state::db::k_bad(&[2u8; 32]), &b"1"[..]).unwrap();
        st.db.blocks.insert(k_block(&[3u8; 32]), &b"body"[..]).unwrap();
        crate::state::db::drop_block_body(&st.db, &[3u8; 32]).unwrap();

        let after = node_info(State(st)).await.0;
        assert_eq!(after.bad_block_marks, Some(2));
        assert!(after.dropped_block_bodies > before.dropped_block_bodies);
    }

    #[tokio::test]
    async fn node_info_reports_outbound_and_inbound_peers() {
        let dir = tempfile::tempdir().unwrap();
        let st = test_api_state(&dir);
        st.connected_peers.store(10, Ordering::Relaxed);
        st.outbound_peers.store(3, Ordering::Relaxed);
        let (_, body) = status_and_body(node_info(State(st.clone())).await.into_response()).await;
        let j: serde_json::Value = serde_json::from_str(&body).unwrap();
        assert_eq!((j["peer_count"].as_u64(), j["outbound_peers"].as_u64(), j["inbound_peers"].as_u64()), (Some(10), Some(3), Some(7)));
        st.outbound_peers.store(4, Ordering::Relaxed);
        let (_, body) = status_and_body(node_info(State(st)).await.into_response()).await;
        let j: serde_json::Value = serde_json::from_str(&body).unwrap();
        assert_eq!((j["outbound_peers"].as_u64(), j["inbound_peers"].as_u64()), (Some(4), Some(6)));
    }

    // Honest path: an unloaded request answers byte-identically to the ungated handler.
    #[tokio::test]
    async fn unloaded_display_routes_answer_as_before_the_gate() {
        let _g = GATE_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let dir = tempfile::tempdir().unwrap();
        let st = test_api_state(&dir);
        seed(&st.db);
        let got = display_routes(&st).await;
        assert_eq!(got.len(), PRE_GATE_BODIES.len());
        for ((path, code, body), (want_path, want_code, want_body)) in got.iter().zip(PRE_GATE_BODIES) {
            assert_eq!(*path, want_path);
            assert_eq!(*code, want_code, "{path}: status changed");
            assert_eq!(body, want_body, "{path}: body changed");
        }
    }

    /// Shortens the display wait for one test and restores it on drop, so a failing assert
    /// does not leak the override into the next test.
    struct ShortDisplayWait;
    impl ShortDisplayWait {
        fn set(ms: u64) -> Self {
            DISPLAY_GATE_WAIT_OVERRIDE_MS.store(ms, Ordering::SeqCst);
            ShortDisplayWait
        }
    }
    impl Drop for ShortDisplayWait {
        fn drop(&mut self) {
            DISPLAY_GATE_WAIT_OVERRIDE_MS.store(0, Ordering::SeqCst);
        }
    }

    // Paired happy path, through the real handler: a display client's burst (one /proposals/<d>/40
    // per domain, all at once; 32 domains on mainnet) is answered in full with the unloaded body.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn a_display_burst_of_32_proposal_reads_all_answer() {
        let _g = GATE_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let dir = tempfile::tempdir().unwrap();
        let st = test_api_state(&dir);
        seed(&st.db);
        let want = PRE_GATE_BODIES.iter().find(|r| r.0 == "/proposals/alpha/10").unwrap().2;
        let burst = (0..32).map(|_| {
            let st = st.clone();
            tokio::spawn(async move {
                // limit 40 as a display client sends it; the seeded store holds one proposal, so the
                // body equals the captured /proposals/alpha/10 one.
                let r = all_proposals_by_domain(Path(("alpha".into(), 40)), State(st)).await;
                status_and_body(r).await
            })
        });
        for (i, r) in futures::future::join_all(burst).await.into_iter().enumerate() {
            let (code, body) = r.unwrap();
            assert_eq!(code, 200, "burst request {i} was refused: {body}");
            assert_eq!(body, want, "burst request {i}");
        }
    }

    // Red-first for the pool sizing: the same 32-request burst at a mainnet node's per-scan cost
    // (380 ms, the slowest /proposals/<d>/40 measured) must fit the display pool's
    // permits and wait. With 2 permits and 250 ms, 30 of the 32 shed.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn a_display_burst_at_live_scan_cost_fits_the_display_pool() {
        let _g = GATE_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let burst = (0..32).map(|_| {
            tokio::spawn(offload_display(|| {
                std::thread::sleep(std::time::Duration::from_millis(380));
                StatusCode::OK.into_response()
            }))
        });
        let codes: Vec<u16> = futures::future::join_all(burst)
            .await
            .into_iter()
            .map(|r| r.unwrap().status().as_u16())
            .collect();
        let shed = codes.iter().filter(|c| **c != 200).count();
        assert_eq!(shed, 0, "{shed} of 32 display reads were shed");
    }

    // Red-first: with the display pool saturated, every gated display read sheds with the shared
    // SCAN_BUSY 503, the keyed top-k reads still answer, and /utxos (heavy-scan pool) still gets
    // its permit.
    #[tokio::test]
    async fn a_saturated_display_pool_sheds_without_starving_utxos() {
        let _g = GATE_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let _wait = ShortDisplayWait::set(50);
        let dir = tempfile::tempdir().unwrap();
        let st = test_api_state(&dir);
        seed(&st.db);

        let held = display_scan_gate()
            .clone()
            .acquire_many_owned(DISPLAY_SCAN_PERMITS as u32)
            .await
            .unwrap();

        let ungated = ["/window/alpha", "/top/alpha", "/top/beta/0"];
        for (path, code, body) in display_routes(&st).await {
            if ungated.contains(&path) {
                let want = PRE_GATE_BODIES.iter().find(|r| r.0 == path).unwrap();
                assert_eq!((code, body.as_str()), (want.1, want.2), "{path} is a keyed read and must not be gated");
                continue;
            }
            assert_eq!(code, 503, "{path} ran while the display pool was full");
            let j: serde_json::Value = serde_json::from_str(&body).unwrap();
            assert_eq!(j["code"], "SCAN_BUSY", "{path}");
        }

        let utxos = utxos_for_addr20(
            Path(format!("0x{}", "11".repeat(20))),
            Query(UtxosQuery { available: None, min_value: None, smallest: None, limit: None, lifetime: None }),
            State(st.clone()),
        )
        .await;
        let (code, body) = status_and_body(utxos).await;
        assert_eq!(code, 200, "/utxos was starved by the display pool: {body}");
        let j: serde_json::Value = serde_json::from_str(&body).unwrap();
        assert_eq!(j["ok"], true);

        drop(held);
        let (code, _) = status_and_body(domains_list(State(st.clone())).await).await;
        assert_eq!(code, 200, "the display pool did not recover once permits were released");
    }

    /// Holds `size` permits of `gate`, then expects the gated request to wait GATE_WAIT_MS and shed
    /// with SCAN_BUSY; after the permits are released it must answer without shedding.
    async fn assert_gate_sheds_at<F, Fut>(name: &str, gate: &'static Arc<tokio::sync::Semaphore>, size: u32, call: F)
    where
        F: Fn() -> Fut,
        Fut: std::future::Future<Output = Response>,
    {
        let held = gate.clone().acquire_many_owned(size).await.unwrap();
        let t = std::time::Instant::now();
        let (code, body) = status_and_body(call().await).await;
        let waited = t.elapsed();
        assert_eq!(code, 503, "{name}: answered with all {size} permits held: {body}");
        let j: serde_json::Value = serde_json::from_str(&body).unwrap();
        assert_eq!(j["code"], "SCAN_BUSY", "{name}");
        assert!(
            waited >= std::time::Duration::from_millis(GATE_WAIT_MS)
                && waited < std::time::Duration::from_millis(GATE_WAIT_MS + 2_000),
            "{name}: shed after {waited:?}, not after the {GATE_WAIT_MS} ms wait"
        );

        drop(held);
        let (code, body) = status_and_body(call().await).await;
        let j: serde_json::Value = serde_json::from_str(&body).unwrap_or_default();
        assert_ne!(j["code"], "SCAN_BUSY", "{name}: still shedding once the permits were released ({code})");
    }

    // The heavy-scan gate and the txid-lookup admission control, pinned
    // by size and wait: 6 permits for the heavy scans (/utxos), 32 for the txid lookups (/tx/:id).
    // A larger pool would let more scans run at once than the node's cores carry.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn the_heavy_scan_and_tx_lookup_gates_shed_at_their_sizes() {
        let _g = GATE_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let dir = tempfile::tempdir().unwrap();
        let st = test_api_state(&dir);
        seed(&st.db);

        assert_gate_sheds_at("/utxos", heavy_scan_gate(), 6, || {
            utxos_for_addr20(
                Path(format!("0x{}", "11".repeat(20))),
                Query(UtxosQuery { available: None, min_value: None, smallest: None, limit: None, lifetime: None }),
                State(st.clone()),
            )
        })
        .await;
        assert_gate_sheds_at("/tx/:id", tx_lookup_gate(), 32, || {
            tx_get(Path(format!("0x{}", "ab".repeat(32))), State(st.clone()))
        })
        .await;
    }
}
