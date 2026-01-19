use axum::{Router, routing::get, extract::State, Json};
use serde::Serialize;
use std::sync::Arc;

use crate::state::db::{Stores, get_tip};
use crate::chain::index::get_hidx;

#[derive(Clone)]
pub struct ApiState {
    pub db: Arc<Stores>,
}

#[derive(Serialize)]
struct TipResp {
    tip: String,
    height: u64,
    chainwork: String,
}

pub fn router(db: Arc<Stores>) -> Router {
    let st = ApiState { db };
    Router::new()
        .route("/health", get(health))
        .route("/tip", get(tip))
        .route("/top/:domain", get(top))
        .with_state(st)
}

async fn health() -> Json<serde_json::Value> {
    Json(serde_json::json!({"ok": true}))
}

async fn tip(State(st): State<ApiState>) -> Json<TipResp> {
    let tip = get_tip(&st.db).unwrap().unwrap_or([0u8;32]);
    let hi = get_hidx(&st.db, &tip).unwrap().unwrap_or(crate::chain::index::HeaderIndex {
        hash: tip, parent: [0u8;32], height: 0, chainwork: 0, bits: 0, time: 0
    });
    Json(TipResp {
        tip: format!("0x{}", hex::encode(tip)),
        height: hi.height,
        chainwork: hi.chainwork.to_string(),
    })
}

async fn top(
    axum::extract::Path(domain): axum::extract::Path<String>,
    State(st): State<ApiState>,
) -> Json<serde_json::Value> {
    let tip = get_tip(&st.db).unwrap().unwrap_or([0u8;32]);
    let hi = get_hidx(&st.db, &tip).unwrap().unwrap();
    let epoch = crate::state::app::current_epoch(hi.height);
    let rows = crate::state::app::top_k(&st.db, epoch, &domain, crate::params::TOP_K).unwrap();

    let out: Vec<serde_json::Value> = rows.into_iter().map(|(pid, score, prop)| {
        serde_json::json!({
            "proposal_id": format!("0x{}", hex::encode(pid)),
            "score": score,
            "domain": prop.domain,
            "payload_hash": format!("0x{}", hex::encode(prop.payload_hash)),
            "uri": prop.uri,
            "expires_epoch": prop.expires_epoch
        })
    }).collect();

    Json(serde_json::json!({ "epoch": epoch, "domain": domain, "top": out }))
}
