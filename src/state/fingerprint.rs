// src/state/fingerprint.rs
use anyhow::Result;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StateFingerprint {
    pub tip: [u8; 32],
    pub utxo_root: [u8; 32],
    pub utxo_meta_root: [u8; 32],
    pub app_root: [u8; 32],
}

fn hash_tree_kv(tree: &sled::Tree) -> Result<[u8; 32]> {
    use sha2::{Digest, Sha256};

    let mut hasher = Sha256::new();
    for kv in tree.iter() {
        let (k, v) = kv?;
        hasher.update(&k);
        hasher.update(&v);
    }
    let out = hasher.finalize();
    let mut h = [0u8; 32];
    h.copy_from_slice(&out);
    Ok(h)
}

pub fn fingerprint(db: &crate::state::db::Stores) -> Result<StateFingerprint> {
    // NOTE: These trees must match what you consider “consensus state”.
    let tip = crate::state::db::get_tip(db)?.unwrap_or([0u8; 32]);

    let utxo_root = hash_tree_kv(&db.utxo)?;
    let utxo_meta_root = hash_tree_kv(&db.utxo_meta)?;
    let app_root = hash_tree_kv(&db.app)?;

    Ok(StateFingerprint {
        tip,
        utxo_root,
        utxo_meta_root,
        app_root,
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
