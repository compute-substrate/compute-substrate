// src/state/app_state.rs
use anyhow::{bail, Result};
use serde::{Deserialize, Serialize};

use crate::crypto::hash160;
use crate::params::{EPOCH_LEN, MAX_DOMAIN_BYTES, MAX_URI_BYTES, TOP_K};
use crate::state::db::Stores;
use crate::types::{AppPayload, Hash32, Transaction};

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Proposal {
    pub id: Hash32, // proposal txid
    pub domain: String,
    pub payload_hash: Hash32,
    pub uri: String,
    pub created_height: u64,
    pub created_epoch: u64,
    pub expires_epoch: u64,
    pub fee: u64,
    pub proposer: [u8; 20],
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Attestation {
    pub id: Hash32,          // attest txid
    pub proposal_id: Hash32, // referenced proposal txid
    pub weight: u64,         // == tx fee
    pub height: u64,
    pub epoch: u64,
    pub attester: [u8; 20],
    pub score: u32,
    pub confidence: u32,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum AppUndo {
    PutProposal { key: Vec<u8>, prev: Option<Vec<u8>> },
    PutAttest { key: Vec<u8>, prev: Option<Vec<u8>> },
    PutScore { key: Vec<u8>, prev: Option<Vec<u8>> },
    PutTopK { key: Vec<u8>, prev: Option<Vec<u8>> },
}

pub fn epoch_of(height: u64) -> u64 {
    height / EPOCH_LEN
}

// ---------------- keys (deterministic prefixes) ----------------
// P | proposal_id(32)
pub fn k_proposal(id: &Hash32) -> Vec<u8> {
    let mut k = Vec::with_capacity(1 + 32);
    k.push(b'P');
    k.extend_from_slice(id);
    k
}

// A | attest_txid(32)
pub fn k_attest(id: &Hash32) -> Vec<u8> {
    let mut k = Vec::with_capacity(1 + 32);
    k.push(b'A');
    k.extend_from_slice(id);
    k
}

/// Score key: S | epoch(u64be) | domain_len(u16be) | domain(bytes) | proposal_id(32)
pub fn k_score(epoch: u64, domain: &str, proposal_id: &Hash32) -> Vec<u8> {
    let d = domain.as_bytes();
    let mut k = Vec::with_capacity(1 + 8 + 2 + d.len() + 32);
    k.push(b'S');
    k.extend_from_slice(&epoch.to_be_bytes());
    k.extend_from_slice(&(d.len() as u16).to_be_bytes());
    k.extend_from_slice(d);
    k.extend_from_slice(proposal_id);
    k
}

/// TopK key: K | epoch(u64be) | domain_len(u16be) | domain(bytes)
pub fn k_topk(epoch: u64, domain: &str) -> Vec<u8> {
    let d = domain.as_bytes();
    let mut k = Vec::with_capacity(1 + 8 + 2 + d.len());
    k.push(b'K');
    k.extend_from_slice(&epoch.to_be_bytes());
    k.extend_from_slice(&(d.len() as u16).to_be_bytes());
    k.extend_from_slice(d);
    k
}

/// Prefix for scanning scores: S | epoch | domain_len | domain
fn p_scores(epoch: u64, domain: &str) -> Vec<u8> {
    let d = domain.as_bytes();
    let mut p = Vec::with_capacity(1 + 8 + 2 + d.len());
    p.push(b'S');
    p.extend_from_slice(&epoch.to_be_bytes());
    p.extend_from_slice(&(d.len() as u16).to_be_bytes());
    p.extend_from_slice(d);
    p
}

fn read_opt(tree: &sled::Tree, key: &[u8]) -> Result<Option<Vec<u8>>> {
    Ok(tree.get(key)?.map(|v| v.to_vec()))
}

fn put_with_undo(
    tree: &sled::Tree,
    key: Vec<u8>,
    val: Vec<u8>,
    undos: &mut Vec<AppUndo>,
    kind: AppUndo,
) -> Result<()> {
    undos.push(kind);
    tree.insert(&key, val)?;
    Ok(())
}

/// scriptsig format: [sig_len u8][sig64][pub_len u8][pub33]
fn sender_h160_from_tx(tx: &Transaction) -> [u8; 20] {
    let Some(inp0) = tx.inputs.first() else {
        return [0u8; 20];
    };
    let sig = inp0.script_sig.as_slice();
    if sig.len() < 1 + 64 + 1 + 33 {
        return [0u8; 20];
    }
    let sig_len = sig[0] as usize;
    if sig_len != 64 {
        return [0u8; 20];
    }
    let pub_len = sig[65] as usize;
    if pub_len != 33 {
        return [0u8; 20];
    }
    let pub33 = &sig[66..99];
    hash160(pub33)
}

/// CONSENSUS: domain/uri constraints must be enforced here because they affect key encoding.
///
/// - domain is embedded in sled keys with a u16 length prefix => domain.len() MUST fit u16
/// - also cap domain/uri to mainnet limits (anti-DoS)
fn enforce_domain_uri_limits(domain: &str, uri: &str) -> Result<()> {
    let d = domain.as_bytes();
    let u = uri.as_bytes();

    if d.is_empty() {
        bail!("domain empty");
    }
    if u.is_empty() {
        bail!("uri empty");
    }

    if d.len() > MAX_DOMAIN_BYTES {
        bail!(
            "domain too long: {} > MAX_DOMAIN_BYTES={}",
            d.len(),
            MAX_DOMAIN_BYTES
        );
    }
    if u.len() > MAX_URI_BYTES {
        bail!(
            "uri too long: {} > MAX_URI_BYTES={}",
            u.len(),
            MAX_URI_BYTES
        );
    }

    if d.len() > (u16::MAX as usize) {
        bail!("domain too long for u16 length prefix: {}", d.len());
    }

    Ok(())
}

// ------------- public API (CONSENSUS CRITICAL) -------------

/// Apply one tx’s app payload (CONSENSUS CRITICAL).
/// `fee` must be canonical (computed by UTXO validation).
pub fn apply_app_tx(
    db: &Stores,
    tx: &Transaction,
    height: u64,
    txid: &Hash32,
    fee: u64,
) -> Result<Vec<AppUndo>> {
    let mut undos: Vec<AppUndo> = vec![];
    let epoch = epoch_of(height);
    let who = sender_h160_from_tx(tx);

    // CONSENSUS codec (frozen bincode config)
    let c = crate::codec::consensus_bincode();

    match &tx.app {
        AppPayload::None => return Ok(undos),

        AppPayload::Propose {
            domain,
            payload_hash,
            uri,
            expires_epoch,
        } => {
            // CONSENSUS: key-safety + DoS limits
            enforce_domain_uri_limits(domain, uri)?;

            // CONSENSUS: expiry must not be in the past at creation time
            if *expires_epoch < epoch {
                bail!(
                    "proposal expires_epoch {} is < current epoch {}",
                    expires_epoch,
                    epoch
                );
            }

            let pkey = k_proposal(txid);
            let prev = read_opt(&db.app, &pkey)?;
            let prop = Proposal {
                id: *txid,
                domain: domain.clone(),
                payload_hash: *payload_hash,
                uri: uri.clone(),
                created_height: height,
                created_epoch: epoch,
                expires_epoch: *expires_epoch,
                fee,
                proposer: who,
            };
            let bytes = c.serialize(&prop)?;
            put_with_undo(
                &db.app,
                pkey.clone(),
                bytes,
                &mut undos,
                AppUndo::PutProposal { key: pkey, prev },
            )?;

            // Ensure score entry exists (0) for this proposal in this epoch+domain
            let skey = k_score(epoch, domain.as_str(), txid);
            let prevs = read_opt(&db.app, &skey)?;
            if prevs.is_none() {
                let z: u128 = 0;
                let zb = c.serialize(&z)?;
                put_with_undo(
                    &db.app,
                    skey.clone(),
                    zb,
                    &mut undos,
                    AppUndo::PutScore {
                        key: skey,
                        prev: prevs,
                    },
                )?;
            }

            recompute_topk(db, epoch, domain.as_str(), &mut undos)?;
        }

        AppPayload::Attest {
            proposal_id,
            score,
            confidence,
        } => {
            // referenced proposal must exist
            let pkey = k_proposal(proposal_id);
            let Some(pv) = db.app.get(&pkey)? else {
                bail!(
                    "ATTEST references unknown proposal {}",
                    hex::encode(proposal_id)
                );
            };
            let prop: Proposal = c.deserialize::<Proposal>(&pv)?;

            // CONSENSUS: enforce expiry
            if epoch > prop.expires_epoch {
                bail!(
                    "ATTEST after proposal expiry: epoch {} > expires_epoch {}",
                    epoch,
                    prop.expires_epoch
                );
            }

            // Defensive: proposal.domain is used in key encoding; ensure it remains key-safe.
            // (Should already be safe if created under the Propose rules above.)
            if prop.domain.as_bytes().len() > (u16::MAX as usize)
                || prop.domain.as_bytes().len() > MAX_DOMAIN_BYTES
            {
                bail!("proposal domain invalid/too long for key encoding");
            }

            // store attestation
            let akey = k_attest(txid);
            let preva = read_opt(&db.app, &akey)?;
            let att = Attestation {
                id: *txid,
                proposal_id: *proposal_id,
                weight: fee,
                height,
                epoch,
                attester: who,
                score: *score,
                confidence: *confidence,
            };
            let bytes = c.serialize(&att)?;
            put_with_undo(
                &db.app,
                akey.clone(),
                bytes,
                &mut undos,
                AppUndo::PutAttest {
                    key: akey,
                    prev: preva,
                },
            )?;

            // bump score for (epoch, domain_of_proposal, proposal_id)
            let skey = k_score(epoch, prop.domain.as_str(), proposal_id);
            let prevs = read_opt(&db.app, &skey)?;
            let cur: u128 = if let Some(v) = prevs.as_ref() {
                c.deserialize::<u128>(v)?
            } else {
                0
            };
            let next = cur.saturating_add(fee as u128);
            let nb = c.serialize(&next)?;
            put_with_undo(
                &db.app,
                skey.clone(),
                nb,
                &mut undos,
                AppUndo::PutScore {
                    key: skey,
                    prev: prevs,
                },
            )?;

            recompute_topk(db, epoch, prop.domain.as_str(), &mut undos)?;
        }
    }

    Ok(undos)
}

/// Deterministically recompute TopK for (epoch, domain) by scanning scores prefix.
fn recompute_topk(db: &Stores, epoch: u64, domain: &str, undos: &mut Vec<AppUndo>) -> Result<()> {
    // Domain must be key-safe (consensus invariant).
    if domain.as_bytes().len() > (u16::MAX as usize) || domain.as_bytes().len() > MAX_DOMAIN_BYTES {
        bail!("domain invalid/too long for key encoding");
    }

    // CONSENSUS codec (frozen bincode config)
    let c = crate::codec::consensus_bincode();

    let prefix = p_scores(epoch, domain);

    let mut all: Vec<(Hash32, u128)> = vec![];

    for item in db.app.scan_prefix(prefix) {
        let (k, v) = item?;
        if k.len() < 32 {
            continue;
        }
        let mut pid = [0u8; 32];
        pid.copy_from_slice(&k[k.len() - 32..]);
        let score: u128 = c.deserialize::<u128>(&v)?;
        all.push((pid, score));
    }

    // deterministic sort: score desc, then proposal_id asc
    all.sort_by(|(a_id, a_s), (b_id, b_s)| b_s.cmp(a_s).then_with(|| a_id.cmp(b_id)));
    all.truncate(TOP_K);

    let tkey = k_topk(epoch, domain);
    let prev = read_opt(&db.app, &tkey)?;
    let bytes = c.serialize(&all)?;
    put_with_undo(
        &db.app,
        tkey.clone(),
        bytes,
        undos,
        AppUndo::PutTopK { key: tkey, prev },
    )?;

    Ok(())
}

/// Roll back a vector of AppUndo entries in reverse order (CONSENSUS CRITICAL).
pub fn rollback_app_undo(db: &Stores, undos: &[AppUndo]) -> Result<()> {
    for u in undos.iter().rev() {
        match u {
            AppUndo::PutProposal { key, prev }
            | AppUndo::PutAttest { key, prev }
            | AppUndo::PutScore { key, prev }
            | AppUndo::PutTopK { key, prev } => {
                restore(&db.app, key, prev)?;
            }
        }
    }
    Ok(())
}

fn restore(tree: &sled::Tree, key: &[u8], prev: &Option<Vec<u8>>) -> Result<()> {
    match prev {
        Some(v) => {
            tree.insert(key, v.as_slice())?;
        }
        None => {
            let _ = tree.remove(key)?;
        }
    }
    Ok(())
}

// ----------------- convenience getters (non-consensus, but must decode stored consensus bytes) -----------------

pub fn get_proposal(db: &Stores, id: &Hash32) -> Result<Option<Proposal>> {
    let k = k_proposal(id);
    let Some(v) = db.app.get(k)? else {
        return Ok(None);
    };
    Ok(Some(
        crate::codec::consensus_bincode().deserialize::<Proposal>(&v)?,
    ))
}

pub fn get_topk(db: &Stores, epoch: u64, domain: &str) -> Result<Vec<(Hash32, u128)>> {
    let k = k_topk(epoch, domain);
    let Some(v) = db.app.get(k)? else {
        return Ok(vec![]);
    };
    Ok(crate::codec::consensus_bincode().deserialize::<Vec<(Hash32, u128)>>(&v)?)
}
