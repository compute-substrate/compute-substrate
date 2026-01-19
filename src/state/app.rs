use anyhow::{Result, bail};
use crate::types::{Transaction, AppPayload, Hash32};
use crate::crypto::txid;
use crate::params::EPOCH_LEN;
use crate::state::db::Stores;

fn k_prop(pid: &Hash32) -> Vec<u8> {
    let mut k = Vec::with_capacity(1+32);
    k.push(b'P'); k.extend_from_slice(pid); k
}
fn k_score(epoch: u64, pid: &Hash32) -> Vec<u8> {
    let mut k = Vec::with_capacity(1+8+32);
    k.push(b'S');
    k.extend_from_slice(&epoch.to_le_bytes());
    k.extend_from_slice(pid);
    k
}
fn k_domain(pid: &Hash32) -> Vec<u8> {
    let mut k = Vec::with_capacity(1+32);
    k.push(b'D'); k.extend_from_slice(pid); k
}

#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct Proposal {
    pub domain: String,
    pub payload_hash: Hash32,
    pub uri: String,
    pub created_epoch: u64,
    pub expires_epoch: u64,
}

pub fn current_epoch(height: u64) -> u64 {
    height / EPOCH_LEN
}

/// Apply app payload; record inserted keys into `undo_keys` so reorg can delete them.
pub fn apply_app(db: &Stores, tx: &Transaction, now_epoch: u64, undo_keys: &mut Vec<Vec<u8>>) -> Result<()> {
    match &tx.app {
        AppPayload::None => Ok(()),

        AppPayload::Propose { domain, payload_hash, uri, expires_epoch } => {
            if *expires_epoch <= now_epoch { bail!("proposal already expired"); }
            let pid = txid(tx);
            let prop = Proposal {
                domain: domain.clone(),
                payload_hash: *payload_hash,
                uri: uri.clone(),
                created_epoch: now_epoch,
                expires_epoch: *expires_epoch,
            };
            let kp = k_prop(&pid);
            if db.app.get(&kp)?.is_some() { bail!("proposal exists"); }
            db.app.insert(&kp, bincode::serialize(&prop)?)?;
            undo_keys.push(kp);

            // store domain separately for quick filtering
            let kd = k_domain(&pid);
            db.app.insert(&kd, domain.as_bytes())?;
            undo_keys.push(kd);

            Ok(())
        }

        AppPayload::Attest { proposal_id, score, confidence } => {
            // Validate proposal exists
            let kp = k_prop(proposal_id);
            let Some(v) = db.app.get(&kp)? else { bail!("unknown proposal"); };
            let prop: Proposal = bincode::deserialize(&v)?;
            if now_epoch >= prop.expires_epoch { bail!("proposal expired"); }

            // score accumulator per (epoch, proposal)
            let ks = k_score(now_epoch, proposal_id);
            let mut cur: u64 = if let Some(v) = db.app.get(&ks)? {
                bincode::deserialize(&v)?
            } else {
                // if inserting first time, record for undo
                undo_keys.push(ks.clone());
                0
            };

            let w = (*score as u64).saturating_mul((*confidence as u64).max(1));
            cur = cur.saturating_add(w);
            db.app.insert(&ks, bincode::serialize(&cur)?)?;

            Ok(())
        }
    }
}

/// Query Top-K proposals for a domain in a given epoch (deterministic, computed from stored scores).
pub fn top_k(db: &Stores, epoch: u64, domain: &str, k: usize) -> Result<Vec<(Hash32, u64, Proposal)>> {
    let mut out = vec![];

    // Iterate proposals (P prefix)
    for item in db.app.scan_prefix([b'P']) {
        let (key, val) = item?;
        if key.len() != 1+32 { continue; }
        let mut pid = [0u8;32];
        pid.copy_from_slice(&key[1..33]);

        let prop: Proposal = bincode::deserialize(&val)?;
        if epoch >= prop.expires_epoch { continue; }
        if prop.domain != domain { continue; }

        let ks = k_score(epoch, &pid);
        let score: u64 = if let Some(v) = db.app.get(&ks)? { bincode::deserialize(&v)? } else { 0 };

        out.push((pid, score, prop));
    }

    out.sort_by(|a,b| b.1.cmp(&a.1));
    out.truncate(k);
    Ok(out)
}
