// src/api/mod.rs
use axum::{
    extract::{Path, State},
    routing::{get, post},
    Json, Router,
};
use serde::{Deserialize, Serialize};
use std::sync::Arc;

use crate::chain::index::{get_hidx, HeaderIndex};
use crate::crypto::{sighash, txid};
use crate::net::mempool::{Mempool, MempoolStats};
use crate::net::GossipTxEvent;
use crate::net::GossipTxEvent as _; // keep type visible even if optimized paths change
use crate::state::app_state::{get_proposal, get_topk, k_proposal, Proposal};
use crate::state::db::{get_tip, get_utxo_meta, k_block, Stores};
use crate::types::{AppPayload, Block, Hash32, OutPoint, Transaction, TxOut};
use std::sync::atomic::{AtomicUsize, Ordering};

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
    pub mempool_tx_count: usize,
    pub mempool_spent_outpoints: usize,
    pub mempool_bytes: usize,
    pub mempool_min_feerate_ppm: Option<u64>,
    pub mempool_max_feerate_ppm: Option<u64>,
}

#[derive(Serialize)]
struct MetricsResp {
    pub ok: bool,
    pub tip: String,
    pub height: u64,
    pub chainwork: String,
pub peer_count: usize,
    pub mempool_tx_count: usize,
    pub mempool_spent_outpoints: usize,
    pub mempool_bytes: usize,
    pub mempool_min_feerate_ppm: Option<u64>,
    pub mempool_max_feerate_ppm: Option<u64>,
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
    pub utxos: Vec<UtxoItem>,
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

pub fn router(
    db: Arc<Stores>,
    mempool: Arc<Mempool>,
    tx_gossip: tokio::sync::mpsc::UnboundedSender<GossipTxEvent>,
connected_peers: Arc<AtomicUsize>,
) -> Router {
    let st = ApiState {
        db,
        mempool,
        tx_gossip,
connected_peers,
    };

    Router::new()
        .route("/health", get(health))
  .route("/peers", get(peers))
        .route("/metrics", get(metrics))
        .route("/tip", get(tip))
        .route("/mempool", get(mempool_info))
        // Explorer-grade read endpoints:
        .route("/block/:hash", get(block_get))
        .route("/utxos/:addr20", get(utxos_for_addr20))
        // Recent blocks:
        .route("/recent/blocks/:limit", get(recent_blocks))
        // Recent computations:
        .route("/recent/proposals/:limit", get(recent_proposals))
        .route(
            "/recent/proposals/:domain/:limit",
            get(recent_proposals_by_domain),
        )
        .route("/recent/attestations/:limit", get(most_attested_global))
        .route(
            "/recent/attestations/:domain/:limit",
            get(most_attested_by_domain),
        )
        // Computation window:
        .route("/window/:domain", get(window_domain))
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
    let tip = get_tip(&st.db).unwrap().unwrap_or([0u8; 32]);
    let hi = get_hidx(&st.db, &tip)
        .unwrap()
        .unwrap_or_else(|| zero_hidx(tip));

    let s: MempoolStats = st.mempool.stats();

    Json(HealthResp {
        ok: true,
        tip: format!("0x{}", hex::encode(tip)),
        height: hi.height,
        chainwork: hi.chainwork.to_string(),
  peer_count: st.connected_peers.load(Ordering::Relaxed),
        mempool_tx_count: s.txs,
        mempool_spent_outpoints: s.spent_len,
        mempool_bytes: s.total_bytes,
        mempool_min_feerate_ppm: s.min_feerate_ppm,
        mempool_max_feerate_ppm: s.max_feerate_ppm,
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
        mempool_tx_count: s.txs,
        mempool_spent_outpoints: s.spent_len,
        mempool_bytes: s.total_bytes,
        mempool_min_feerate_ppm: s.min_feerate_ppm,
        mempool_max_feerate_ppm: s.max_feerate_ppm,
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
            "app": format!("{:?}", tx.app),
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

/// GET /utxos/:addr20
async fn utxos_for_addr20(
    Path(addr20): Path<String>,
    State(st): State<ApiState>,
) -> Json<UtxosResp> {
    let a = match parse_addr20(&addr20) {
        Ok(x) => x,
        Err(_) => {
            return Json(UtxosResp {
                ok: false,
                addr20,
                count: 0,
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

    out.sort_by(|a, b| b.value.cmp(&a.value));

    Json(UtxosResp {
        ok: true,
        addr20: format!("0x{}", hex::encode(a)),
        count: out.len(),
        utxos: out,
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

let epoch = crate::state::app_state::epoch_of(hi.height);
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

let epoch = crate::state::app_state::epoch_of(hi.height);
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
            "proposal_id": prop.id,
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
    let rows = topk_snapshot(&st.db, epoch, &domain).unwrap_or_default();
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

async fn tx_submit(State(st): State<ApiState>, Json(req): Json<TxSubmitReq>) -> Json<TxSubmitResp> {
    let id = txid(&req.tx);
    let txid_hex = format!("0x{}", hex::encode(id));

    // Single source of truth for mempool acceptance:
    // - validates structure + sigs + fee floors
    // - ensures inputs exist in current canonical UTXO set (so it can mine "now")
    // - prevents in-mempool double-spends
    let inserted = match st.mempool.insert_checked(&st.db, req.tx.clone()) {
        Ok(true) => true,
        Ok(false) => false, // already present OR conflicts with current mempool spends
        Err(_) => {
            return Json(TxSubmitResp {
                ok: false,
                txid: txid_hex,
                mempool_len: st.mempool.len(),
            });
        }
    };

    if inserted {
        let _ = st.tx_gossip.send(GossipTxEvent { tx: req.tx });
    }

    Json(TxSubmitResp {
        ok: inserted,
        txid: txid_hex,
        mempool_len: st.mempool.len(),
    })
}
