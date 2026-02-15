// src/state/fingerprint.rs
use anyhow::{Context, Result};

use crate::state::db::{get_tip, Stores};

#[derive(Clone, Debug)]
pub struct StateFingerprint {
    pub tip: [u8; 32],
    pub utxo_root: [u8; 32],
    pub utxo_meta_root: [u8; 32],
    pub app_root: [u8; 32],
}

fn hash_tree_kv(tree: &sled::Tree) -> Result<[u8; 32]> {
    // Deterministic over key-order iteration.
    let mut h = blake3::Hasher::new();

    for item in tree.iter() {
        let (k, v) = item.context("sled iter item")?;
        h.update(&(k.len() as u64).to_le_bytes());
        h.update(&k);
        h.update(&(v.len() as u64).to_le_bytes());
        h.update(&v);
    }

    Ok(*h.finalize().as_bytes())
}

pub fn fingerprint(db: &Stores) -> Result<StateFingerprint> {
    let tip = get_tip(db)?.unwrap_or([0u8; 32]);
    Ok(StateFingerprint {
        tip,
        utxo_root: hash_tree_kv(&db.utxo).context("hash utxo tree")?,
        utxo_meta_root: hash_tree_kv(&db.utxo_meta).context("hash utxo_meta tree")?,
        app_root: hash_tree_kv(&db.app).context("hash app tree")?,
    })
}

pub fn fmt32(h: &[u8; 32]) -> String {
    format!("0x{}", hex::encode(h))
}

pub fn fmt_fp(fp: &StateFingerprint) -> String {
    format!(
        "tip={} utxo={} utxo_meta={} app={}",
        fmt32(&fp.tip),
        fmt32(&fp.utxo_root),
        fmt32(&fp.utxo_meta_root),
        fmt32(&fp.app_root),
    )
}
