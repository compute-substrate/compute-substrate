// src/state/app.rs
use anyhow::{bail, Result};
use serde::{Deserialize, Serialize};

use crate::params::{EPOCH_LEN, TOP_K};
use crate::state::db::Stores;
use crate::types::{AppPayload, Hash20, Hash32, Transaction};

/// epoch = height / EPOCH_LEN (deterministic)
pub fn current_epoch(height: u64) -> u64 {
    height / EPOCH_LEN
}

// -----------------------------
// Canonical objects (stored in db.app)
// -----------------------------

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Proposal {
    pub domain: String,
    pub payload_hash: Hash32,
    pub uri: String,
    pub created_height: u64,
    pub created_epoch: u64,
    pub fee: u64,
    pub proposer: Hash20,
    pub expires_epoch: u64,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Attestation {
    pub proposal_id: Hash32,
    pub weight: u64, // consensus rule: weight = tx fee
    pub height: u64,
    pub epoch: u64,
}

/// Generic undo record for app tree mutations.
/// If `prev` is None, key didn't exist and must be removed on rollback.
/// If `prev` is Some(bytes), restore those bytes on rollback.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AppUndo {
    pub key: Vec<u8>,
    pub prev: Option<Vec<u8>>,
}

// -----------------------------
// Keyspace
// -----------------------------
// P + txid(32)                        -> Proposal
// A + attest_txid(32)                 -> Attestation
// S + epoch(8be) + domainlen(2be) + domain + proposal_id(32) -> u128 score
// K + epoch(8be) + domainlen(2be) + domain                  -> Vec<(proposal_id, score)> (len <= TOP_K)

fn be_u64(x: u64) -> [u8; 8] {
    x.to_be_bytes()
}
fn be_u16(x: u16) -> [u8; 2] {
    x.to_be_bytes()
}

pub fn k_proposal(id: &Hash32) -> Vec<u8> {
    let mut k = Vec::with_capacity(1 + 32);
    k.push(b'P');
    k.extend_from_slice(id);
    k
}

pub fn k_attest(attest_txid: &Hash32) -> Vec<u8> {
    let mut k = Vec::with_capacity(1 + 32);
    k.push(b'A');
    k.extend_from_slice(attest_txid);
    k
}

pub fn k_score(epoch: u64, domain: &str, proposal_id: &Hash32) -> Vec<u8> {
    let d = domain.as_bytes();
    let dl: u16 = d.len().try_into().unwrap_or(u16::MAX); // domain length > u16::MAX is practically impossible here

    let mut k = Vec::with_capacity(1 + 8 + 2 + d.len() + 32);
    k.push(b'S');
    k.extend_from_slice(&be_u64(epoch));
    k.extend_from_slice(&be_u16(dl));
    k.extend_from_slice(d);
    k.extend_from_slice(proposal_id);
    k
}

pub fn k_topk(epoch: u64, domain: &str) -> Vec<u8> {
    let d = domain.as_bytes();
    let dl: u16 = d.len().try_into().unwrap_or(u16::MAX);

    let mut k = Vec::with_capacity(1 + 8 + 2 + d.len());
    k.push(b'K');
    k.extend_from_slice(&be_u64(epoch));
    k.extend_from_slice(&be_u16(dl));
    k.extend_from_slice(d);
    k
}

fn score_prefix(epoch: u64, domain: &str) -> Vec<u8> {
    let d = domain.as_bytes();
    let dl: u16 = d.len().try_into().unwrap_or(u16::MAX);

    let mut p = Vec::with_capacity(1 + 8 + 2 + d.len());
    p.push(b'S');
    p.extend_from_slice(&be_u64(epoch));
    p.extend_from_slice(&be_u16(dl));
    p.extend_from_slice(d);
    p
}

// -----------------------------
// Internal helpers
// -----------------------------

fn app_put_with_undo(
    db: &Stores,
    key: Vec<u8>,
    value: Vec<u8>,
    undos: &mut Vec<AppUndo>,
) -> Result<()> {
    let prev = db.app.get(&key)?.map(|iv| iv.to_vec());
    undos.push(AppUndo {
        key: key.clone(),
        prev,
    });
    db.app.insert(key, value)?;
    Ok(())
}

fn app_del_with_undo(db: &Stores, key: Vec<u8>, undos: &mut Vec<AppUndo>) -> Result<()> {
    let prev = db.app.get(&key)?.map(|iv| iv.to_vec());
    undos.push(AppUndo {
        key: key.clone(),
        prev,
    });
    db.app.remove(key)?;
    Ok(())
}

// -----------------------------
// Consensus codec helpers (FROZEN)
// -----------------------------

#[inline]
fn c() -> crate::codec::ConsensusBincode {
    crate::codec::consensus_bincode()
}

fn read_u128(v: &[u8]) -> Result<u128> {
    c().deserialize::<u128>(v)
        .map_err(|e| anyhow::anyhow!("decode u128: {e}"))
}

fn write_u128(x: u128) -> Result<Vec<u8>> {
    Ok(c().serialize(&x)?)
}

// -----------------------------
// Consensus-critical apply + rollback
// -----------------------------

/// Apply app mutation for a tx. Returns reorg-safe undo records (must be stored under block undo).
///
/// Deterministic rules implemented:
/// - epoch = height / EPOCH_LEN
/// - attest.weight = tx_fee
/// - attest must reference an existing proposal (else invalid)
/// - after each propose/attest, recompute Top-K for (epoch, domain) deterministically and store snapshot
pub fn apply_app_tx(
    db: &Stores,
    tx: &Transaction,
    height: u64,
    txid: &Hash32,
    tx_fee: u64,
    proposer: Hash20,
) -> Result<Vec<AppUndo>> {
    let epoch = current_epoch(height);
    let mut undos: Vec<AppUndo> = vec![];

    match &tx.app {
        AppPayload::None => return Ok(undos),

        AppPayload::Propose {
            domain,
            payload_hash,
            uri,
            expires_epoch,
        } => {
            // Proposal object
            let prop = Proposal {
                domain: domain.clone(),
                payload_hash: *payload_hash,
                uri: uri.clone(),
                created_height: height,
                created_epoch: epoch,
                fee: tx_fee,
                proposer,
                expires_epoch: *expires_epoch,
            };

            let kp = k_proposal(txid);
            app_put_with_undo(db, kp, c().serialize(&prop)?, &mut undos)?;

            // Ensure score entry exists for this epoch/domain/proposal (start at 0)
            let ks = k_score(epoch, domain, txid);
            if db.app.get(&ks)?.is_none() {
                app_put_with_undo(db, ks, write_u128(0)?, &mut undos)?;
            }

            // Recompute Top-K snapshot for this (epoch, domain)
            recompute_topk(db, epoch, domain, &mut undos)?;
            Ok(undos)
        }

        AppPayload::Attest {
            proposal_id,
            score: _score,
            confidence: _confidence,
        } => {
            // Must reference an existing proposal
            let kp = k_proposal(proposal_id);
            let Some(pv) = db.app.get(&kp)? else {
                bail!("attest references missing proposal");
            };
            let prop: Proposal = c().deserialize::<Proposal>(&pv)?;

            // Optional: enforce not expired at current epoch (comment out if you don't want this yet)
            if epoch > prop.expires_epoch {
                bail!("proposal expired");
            }

            // Store attestation object keyed by its txid
            let att = Attestation {
                proposal_id: *proposal_id,
                weight: tx_fee, // consensus rule
                height,
                epoch,
            };
            let ka = k_attest(txid);
            app_put_with_undo(db, ka, c().serialize(&att)?, &mut undos)?;

            // Update score(epoch, domain, proposal_id) += weight
            let ks = k_score(epoch, &prop.domain, proposal_id);
            let prev = db.app.get(&ks)?;
            let cur = if let Some(v) = prev {
                read_u128(&v)?
            } else {
                0
            };
            let next = cur.saturating_add(tx_fee as u128);
            app_put_with_undo(db, ks, write_u128(next)?, &mut undos)?;

            // Recompute Top-K snapshot for this (epoch, domain)
            recompute_topk(db, epoch, &prop.domain, &mut undos)?;
            Ok(undos)
        }
    }
}

/// Deterministically recompute Top-K for (epoch, domain) by scanning score keys for that prefix.
/// Tie-breaker: higher score first, then lexicographically smaller proposal_id (deterministic).
fn recompute_topk(db: &Stores, epoch: u64, domain: &str, undos: &mut Vec<AppUndo>) -> Result<()> {
    let prefix = score_prefix(epoch, domain);

    let mut rows: Vec<(Hash32, u128)> = vec![];

    for item in db.app.scan_prefix(prefix) {
        let (k, v) = item?;
        // key ends with proposal_id(32)
        if k.len() < 32 {
            continue;
        }
        let pid_off = k.len() - 32;
        let mut pid = [0u8; 32];
        pid.copy_from_slice(&k[pid_off..]);
        let sc = read_u128(&v)?;
        rows.push((pid, sc));
    }

    rows.sort_by(|a, b| {
        // score desc, pid asc
        b.1.cmp(&a.1).then_with(|| a.0.cmp(&b.0))
    });

    if rows.len() > TOP_K {
        rows.truncate(TOP_K);
    }

    let kt = k_topk(epoch, domain);
    app_put_with_undo(db, kt, c().serialize(&rows)?, undos)?;
    Ok(())
}

/// Read Top-K rows for (epoch, domain). Returns Vec of (proposal_id, score).
pub fn topk_snapshot(db: &Stores, epoch: u64, domain: &str) -> Result<Vec<(Hash32, u128)>> {
    let kt = k_topk(epoch, domain);
    let Some(v) = db.app.get(&kt)? else {
        return Ok(vec![]);
    };
    Ok(c().deserialize::<Vec<(Hash32, u128)>>(&v)?)
}

/// Rollback app undos (MUST be applied in reverse order).
pub fn rollback_app_undo(db: &Stores, undos: &[AppUndo]) -> Result<()> {
    for u in undos.iter().rev() {
        match &u.prev {
            None => {
                // key did not exist before -> remove it
                db.app.remove(&u.key)?;
            }
            Some(prev_bytes) => {
                // restore previous value
                db.app.insert(&u.key, prev_bytes.clone())?;
            }
        }
    }
    Ok(())
}
