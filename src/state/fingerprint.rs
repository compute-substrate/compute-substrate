// src/state/fingerprint.rs
use anyhow::Result;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StateFingerprint {
    pub tip: [u8; 32],
    pub utxo_root: [u8; 32],
    pub utxo_meta_root: [u8; 32],
    pub app_root: [u8; 32],
}

/// Hash a tree deterministically by folding kv hashes in key order.
/// NOTE: This is a *test/diagnostic* fingerprint; not consensus-critical.
fn hash_tree_kv(tree: &sled::Tree) -> Result<[u8; 32]> {
    use sha2::{Digest, Sha256};

    let mut h = Sha256::new();
    for kv in tree.iter() {
        let (k, v) = kv?;
        h.update(&k);
        h.update(&v);
    }
    let out = h.finalize();
    let mut r = [0u8; 32];
    r.copy_from_slice(&out);
    Ok(r)
}

pub fn fingerprint(db: &crate::state::db::Stores) -> Result<StateFingerprint> {
    use crate::state::db::get_tip;

    let tip = get_tip(db)?.unwrap_or([0u8; 32]);

    Ok(StateFingerprint {
        tip,
        utxo_root: hash_tree_kv(&db.utxo)?,
        utxo_meta_root: hash_tree_kv(&db.utxo_meta)?,
        app_root: hash_tree_kv(&db.app)?,
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
