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
use crate::state::db::{get_tip, get_utxo_meta, k_block, Stores};
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
    // ADDITIVE ONLY. Nothing above changed name, type or position, so
    // every existing consumer keeps parsing this response unchanged. Deliberately NO version or
    // build string here: /health is reverse-proxied to the public internet by the front door,
    // and the build identity belongs on the ops-only /node/info route below.
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

/// Build identity plus the same liveness gauges, for the canary and
/// incident triage: one curl tells you which binary is answering, whether it is keeping up, and
/// whether its txid index is converged. Kept OFF /health on purpose, because /health is
/// reverse-proxied publicly and the exact build string is not something to advertise there.
/// The RPC listener binds loopback, and no front-door proxy forwards this path.
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
    pub mined_lifetime: u64,
    pub mined_unspent: u64,
    pub coinbase_lifetime_outputs: u64,
    pub coinbase_unspent_outputs: u64,
    pub utxos: Vec<UtxoItem>,
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
    // Set ONLY on a proved absence (walked to genesis, or a fresh txid index
    // answered). Skipped otherwise so a Found response stays byte-identical to pre-0.1.6.
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

    Json(HealthResp {
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
        best_peer_height: (best_peer_height > 0).then_some(best_peer_height),
        blocks_behind: (best_peer_height > 0).then(|| best_peer_height.saturating_sub(hi.height)),
        secs_since_tip_activity: (last_activity > 0).then(|| now.saturating_sub(last_activity)),
    })
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

    Json(NodeInfoResp {
        ok: true,
        version: env!("CARGO_PKG_VERSION").to_string(),
        peer_id: st.peer_id.to_string(),
        height,
        best_peer_height: (best_peer_height > 0).then_some(best_peer_height),
        blocks_behind: (best_peer_height > 0).then(|| best_peer_height.saturating_sub(height)),
        secs_since_tip_activity: (last_activity > 0).then(|| now.saturating_sub(last_activity)),
        // Index state stays HERE and not on /health: the front door reverse-proxies /health to
        // the public internet, and this field announces in real time when this node's absence
        // answers are degraded to 503 SCAN_HORIZON rather than proved, which is a free
        // restart-timing and degraded-mode oracle for anyone who can reach it.
        tx_index_converged: crate::state::tx_scan::idx_fresh(&st.db),
        peer_count: st.connected_peers.load(Ordering::Relaxed),
        known_peers: st.known_peers.load(Ordering::Relaxed),
        subsystems: crate::state::subsystem::SUBSYSTEMS.report(),
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

    // 60s target:
    // healthy   <= 180s
    // advancing <= 360s
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

async fn top_active(State(st): State<ApiState>) -> Json<serde_json::Value> {
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

async fn top_all_time(State(st): State<ApiState>) -> Json<serde_json::Value> {
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

        
async fn top_global(State(st): State<ApiState>) -> Json<serde_json::Value> {
    use std::collections::HashMap;

    let tip = get_tip(&st.db).unwrap().unwrap_or([0u8; 32]);
    let hi = get_hidx(&st.db, &tip)
        .unwrap()
        .unwrap_or_else(|| zero_hidx(tip));

    let epoch = crate::state::app_state::epoch_of(hi.height).saturating_sub(1);

    // 1. get all domains
    let domains_resp = domains_list(State(st.clone())).await;
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

async fn domains_list(State(st): State<ApiState>) -> Json<DomainsResp> {
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
    // is fresh. The walk below stays as the fallback and stays UNCAPPED on purpose: the
    // a client's emergency fallback path depends on /block/height/:h answering to genesis
    // regardless of index state.
    if let Some(h) = crate::state::tx_scan::canonical_hash_at_height(&st.db, height) {
        return block_get(Path(format!("0x{}", hex::encode(h))), State(st))
            .await
            .into_response();
    }

    // The fallback below is an UNCAPPED tip-to-genesis walk, kept uncapped
    // on purpose (the wallet's documented emergency fallback depends on it answering at any
    // depth). Uncapped and on a runtime worker are two different things though: it was the last
    // O(chain) read still able to starve the p2p loop, and it runs precisely when the index is
    // stale, which is when the indexer is polling hardest. Offload it and gate it like the rest.
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
/// own: tokio's blocking pool defaults to 512 threads, this unit is pinned to 6 cores, and
/// dropping the handler future when a client hangs up does NOT cancel the blocking task. So
/// issuing requests and disconnecting costs an attacker nothing and buys hundreds of concurrent
/// full-chain scans. A small permit count plus a fast 503 is the difference between "slow under
/// load" and "the swarm loop gets no CPU".
///
/// Sized well above real traffic: the front door serves a few hundred of these per DAY.
/// SEPARATE gates, on purpose. A single shared pool lets six concurrent `/utxos` at ~140 ms each
/// block every `/tx/:id` for that whole window, and `/tx/:id` is the endpoint the wallet polls
/// hardest: it verifies one per transaction INPUT, so a legitimate multi-input send fans out
/// several at once.
const TX_LOOKUP_PERMITS: usize = 32;
const HEAVY_SCAN_PERMITS: usize = 6;

/// Wait briefly rather than refusing instantly. `try_acquire` turns a legitimate burst into a
/// 503 even though each request finishes in well under a millisecond on a fresh index. A short
/// bounded wait costs a queued caller nothing when the index is fresh (the queue drains in
/// microseconds) and still sheds hard against a caller that is actually saturating the node.
const GATE_WAIT_MS: u64 = 250;

static TX_LOOKUP_GATE: std::sync::OnceLock<Arc<tokio::sync::Semaphore>> =
    std::sync::OnceLock::new();
static HEAVY_SCAN_GATE: std::sync::OnceLock<Arc<tokio::sync::Semaphore>> =
    std::sync::OnceLock::new();

fn tx_lookup_gate() -> &'static Arc<tokio::sync::Semaphore> {
    TX_LOOKUP_GATE.get_or_init(|| Arc::new(tokio::sync::Semaphore::new(TX_LOOKUP_PERMITS)))
}

fn heavy_scan_gate() -> &'static Arc<tokio::sync::Semaphore> {
    HEAVY_SCAN_GATE.get_or_init(|| Arc::new(tokio::sync::Semaphore::new(HEAVY_SCAN_PERMITS)))
}

async fn acquire_or_shed(
    gate: &'static Arc<tokio::sync::Semaphore>,
) -> Option<tokio::sync::OwnedSemaphorePermit> {
    tokio::time::timeout(
        std::time::Duration::from_millis(GATE_WAIT_MS),
        gate.clone().acquire_owned(),
    )
    .await
    .ok()
    .and_then(|r| r.ok())
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
    let Some(_permit) = acquire_or_shed(tx_lookup_gate()).await else {
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
/// `find_tx_in_chain`, no longer a buried const; this is the API's default budget).
pub const TX_SCAN_MAX_BACK: u64 = 100_000;

/// Retry-After seconds advertised on SCAN_HORIZON / SCAN_INCOMPLETE / SCAN_DECODE 503s.
/// The background index reconciler converges within minutes even from cold.
const SCAN_RETRY_AFTER_SECS: u64 = 30;

/// Wire mapping for the non-decisive scan outcomes (normative spec: node README
/// "Scan-outcome wire contract"). Horizon and Incomplete MUST be non-2xx-non-404 so fielded
/// wallets classify them `transient` (fail closed) instead of `notfound` (silent ghost).
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
/// TX_SCAN_MAX_BACK block bodies. That is the same O(chain) work as /utxos, on the endpoint the
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
            // Re-load the located block and build the response EXACTLY as pre-0.1.6 did:
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

    // The same four-way outcome mapping as /tx/:id (normative spec: node README
    // "Scan-outcome wire contract").
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
            // (tip_height - height + 1 = blocks a pre-0.1.6 walk reported on this hit),
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
/// Offload the two O(chain) read handlers to the blocking pool.
///
/// Measured on this host at tip ~61,200: /tip answers in well under a millisecond, /utxos in
/// ~137 ms REGARDLESS of the address, because the cost is a full UTXO-tree scan plus a
/// tip-to-genesis block walk, not the result size. /address/:addr20/activity is worse (~270 ms
/// and ~48 MB of transient allocation per call). Both were plain `async fn` bodies, so that work
/// ran on the same multi-threaded runtime that `tokio::spawn`s the p2p loop.
///
/// /utxos is on the public proxy allowlist under a generic per-IP request budget that was sized
/// against /tx/:id back when THAT was the linear scan. /tx/:id is O(1) now and /utxos is not, so
/// a caller staying inside its allowed request rate can spend minutes of node CPU per wall-clock
/// minute and starve the swarm task: the RPC keeps answering while the tip stops moving, which
/// is exactly the wedge shape /health's new liveness fields exist to report. Moving the body to
/// the blocking pool severs that coupling. It does not make the endpoint cheap, and an address
/// index is the durable fix; this is the small, byte-identical half.
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
    match tokio::task::spawn_blocking(move || {
        let _p = _permit;
        utxos_for_addr20_blocking(addr20, q, st)
    })
    .await
    {
        Ok(r) => r.into_response(),
        Err(e) => {
            // An internal failure MUST NOT be answerable as "this address has no coins". This is
            // the wallet's coin-selection input: a 200 with count 0 and an empty utxo list is
            // shape-identical to a genuinely empty address, so any consumer that does not check
            // `ok` would render a zero balance and build the wrong transaction. Same
            // confident-lie class the tx index removes, so answer 503 and let the caller retry.
            eprintln!("[api] utxo scan task failed: {e}");
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
    }
}

fn utxos_for_addr20_blocking(
    addr20: String,
    q: UtxosQuery,
    st: ApiState,
) -> Json<UtxosResp> {
    let a = match parse_addr20(&addr20) {
        Ok(x) => x,
        Err(_) => {
return Json(UtxosResp {

    ok: false,

    addr20,

    count: 0,

    confirmed_balance: 0,

    mined_lifetime: 0,

    mined_unspent: 0,

    coinbase_lifetime_outputs: 0,

    coinbase_unspent_outputs: 0,

    utxos: vec![],
            })
        }
    };

    // Tip height for confirmations
    let tip_height: u64 = get_tip(st.db.as_ref())
        .ok()
        .flatten()
        .and_then(|tip| get_hidx(st.db.as_ref(), &tip).ok().flatten())
        .map(|hi| hi.height)
        .unwrap_or(0);

    let mut out: Vec<UtxoItem> = vec![];

    for item in st.db.utxo.iter() {
        let Ok((k, v)) = item else { continue };

        // Support both "U" prefixed and legacy raw key formats
        let (txid_slice, vout_slice) = if k.len() == 1 + 32 + 4 && k[0] == b'U' {
            (&k[1..33], &k[33..37])
        } else if k.len() == 32 + 4 {
            (&k[0..32], &k[32..36])
        } else {
            continue;
        };

        let txo: TxOut = match c().deserialize(&v) {
            Ok(x) => x,
            Err(_) => continue,
        };

        if txo.script_pubkey != a {
            continue;
        }

        let mut txid_bytes = [0u8; 32];
        txid_bytes.copy_from_slice(txid_slice);

        let mut vout_le = [0u8; 4];
        vout_le.copy_from_slice(vout_slice);
        let vout = u32::from_le_bytes(vout_le);

        let op = OutPoint {
            txid: txid_bytes,
            vout,
        };

        let (height, coinbase) = match get_utxo_meta(st.db.as_ref(), &op).ok().flatten() {
            Some(m) => (m.height, m.coinbase),
            None => (0u64, false),
        };

        let confirmations: u64 = if height == 0 || tip_height < height {
            0
        } else {
            tip_height - height + 1
        };

        out.push(UtxoItem {
            txid: format!("0x{}", hex::encode(txid_bytes)),
            vout,
            value: txo.value,
            height,
            confirmations,
            coinbase,
        });
    }

    if q.available.unwrap_or(false) {
        out.retain(|u| !st.mempool.has_spent_outpoint_hex(&u.txid, u.vout));
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

if let Some(limit) = q.limit {
    out.truncate(limit);
}

let confirmed_balance: u64 = out.iter().map(|u| u.value).sum();

let mined_unspent: u64 = out
    .iter()
    .filter(|u| u.coinbase)
    .map(|u| u.value)
    .sum();

let coinbase_unspent_outputs: u64 =
    out.iter().filter(|u| u.coinbase).count() as u64;

// Historical lifetime coinbase scan over canonical chain.
let mut mined_lifetime: u64 = 0;
let mut coinbase_lifetime_outputs: u64 = 0;

let tip = get_tip(st.db.as_ref())
    .ok()
    .flatten()
    .unwrap_or([0u8; 32]);

let hi = get_hidx(st.db.as_ref(), &tip)
    .ok()
    .flatten()
    .unwrap_or_else(|| zero_hidx(tip));

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

    // Coinbase tx is txs[0]
    if let Some(cb) = blk.txs.first() {
        for outp in &cb.outputs {
            if outp.script_pubkey == a {
                mined_lifetime =
                    mined_lifetime.saturating_add(outp.value);

                coinbase_lifetime_outputs =
                    coinbase_lifetime_outputs.saturating_add(1);
            }
        }
    }

    if blk.header.prev == [0u8; 32] || cur_height == 0 {
        break;
    }

    cur_hash = blk.header.prev;
    cur_height = cur_height.saturating_sub(1);
}

Json(UtxosResp {
    ok: true,
    addr20: format!("0x{}", hex::encode(a)),
    count: out.len(),
    confirmed_balance,
    mined_lifetime,
    mined_unspent,
    coinbase_lifetime_outputs,
    coinbase_unspent_outputs,
    utxos: out,
})

}

async fn address_activity_get(
    Path(addr20): Path<String>,
    Query(q): Query<AddressActivityQuery>,
    State(st): State<ApiState>,
) -> Response {
    // Same offload as /utxos above, and more so: this one clones every block on the chain and
    // builds a map of every outpoint ever created before applying `limit`. It is loopback-only
    // today (no front-door proxy forwards it), so this is about not letting an operator's own
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
async fn recent_proposals(
    Path(limit): Path<u64>,
    State(st): State<ApiState>,
) -> Json<RecentProposalsResp> {
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
async fn all_proposals(
    Path(limit): Path<u64>,
    State(st): State<ApiState>,
) -> Json<RecentProposalsResp> {
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
async fn most_attested_global(
    Path(limit): Path<u64>,
    State(st): State<ApiState>,
) -> Json<RecentAttestedResp> {
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

/// GET /mempool/txids: [{txid, age_secs}] for up to 1000 mempool txs, oldest first. The
/// txid-level source the strand sentinel needs to confirm a SPECIFIC tx is still pending across
/// ticks (the count-based /mempool signal false-fires under any sustained flow). Loopback-gated
/// like every other RPC route; read-only.
async fn mempool_txids(State(st): State<ApiState>) -> Json<serde_json::Value> {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    let rows: Vec<serde_json::Value> = st
        .mempool
        .txids_with_age(now, 1000)
        .into_iter()
        .map(|(id, age)| serde_json::json!({ "txid": format!("0x{}", hex::encode(id)), "age_secs": age }))
        .collect();
    Json(serde_json::json!({ "ok": true, "count": rows.len(), "txids": rows }))
}

async fn tx_submit(State(st): State<ApiState>, Json(req): Json<TxSubmitReq>) -> Json<TxSubmitResp> {
    let id = txid(&req.tx);
    let txid_hex = format!("0x{}", hex::encode(id));




    // Single source of truth for mempool acceptance:
    // - validates structure + sigs + fee floors
    // - ensures inputs exist in current canonical UTXO set (so it can mine "now")
    // - prevents in-mempool double-spends

match st.mempool.insert_checked(&st.db, req.tx.clone()) {
    Ok(true) => {
        if let Some(first_inp) = req.tx.inputs.first() {
            println!(
                "[tx_submit] ACCEPT txid={} first_input=0x{}:{}",
                txid_hex,
                hex::encode(first_inp.prevout.txid),
                first_inp.prevout.vout
            );
        } else {
            println!("[tx_submit] ACCEPT txid={} no-inputs", txid_hex);
        }

        if let AppPayload::Propose { domain, .. } = &req.tx.app {
            println!("[tx_submit] app=Propose domain={}", domain);
        }
        if let AppPayload::Attest { proposal_id, .. } = &req.tx.app {
            println!(
                "[tx_submit] app=Attest proposal_id=0x{}",
                hex::encode(proposal_id)
            );
        }

        if let Err(e) = st.tx_gossip.send(GossipTxEvent { tx: req.tx, insure: true }) {
            println!("[tx_submit] gossip send failed for {}: {}", txid_hex, e);
        }

        return Json(TxSubmitResp {
            ok: true,
            txid: txid_hex,
            mempool_len: st.mempool.len(),
            err: None,
        });
    }
    Ok(false) => {
        // Re-gossip on a duplicate submit, but ONLY when this exact tx is what we hold: the
        // original submit's gossip publish is single-shot and its errors are swallowed (e.g.
        // InsufficientPeers right after startup), so a tx can sit here unminable while wallets
        // resubmit byte-identical copies (deterministic signing) and get this branch forever,
        // the 2026-06-12 ~40min strand. A resubmit is the user asking "please propagate this";
        // re-sending the gossip event un-strands it network-wide (peers that saw it dedupe by
        // message-id; peers that never saw it finally get it). The contains() guard matters:
        // Ok(false) also covers an input CONFLICT with a DIFFERENT mempool tx, and re-gossiping
        // an unheld conflicting tx would make this node amplify double-spend attempts.
        // Distinct err strings for the two Ok(false) truths (review-gate finding): downstream
        // consumers (a proxy's dual-submit insurance, a wallet's duplicate-submit
        // classification) match /already present/, and with one combined string they treated a
        // CONFLICT as a duplicate too: the proxy would copy a rejected double-spend to the second
        // backend and the wallet would tell the user their payment "should settle" when it never
        // will. The duplicate string still contains "already present", so older clients keep
        // matching exactly the case they meant.
        let err_msg = if st.mempool.contains(&id) {
            if let Err(e) = st.tx_gossip.send(GossipTxEvent { tx: req.tx, insure: false }) {
                println!("[tx_submit] duplicate re-gossip send failed for {}: {}", txid_hex, e);
            } else {
                println!("[tx_submit] DUPLICATE txid={} re-gossiped (held in mempool)", txid_hex);
            }
            "already present in mempool"
        } else {
            println!("[tx_submit] REJECT txid={} reason=mempool-conflict (not held; no re-gossip)", txid_hex);
            "mempool conflict: a different pending transaction spends these coins"
        };
        return Json(TxSubmitResp {
            ok: false,
            txid: txid_hex,
            mempool_len: st.mempool.len(),
            err: Some(err_msg.to_string()),
        });
    }
    Err(e) => {
        println!("[tx_submit] REJECT txid={} err={}", txid_hex, e);
        return Json(TxSubmitResp {
            ok: false,
            txid: txid_hex,
            mempool_len: st.mempool.len(),
            err: Some(e.to_string()),
        });
    }
};
}
