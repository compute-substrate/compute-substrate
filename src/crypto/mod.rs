// src/crypto/mod.rs
use sha2::{Sha256, Digest};
use ripemd::Ripemd160;
use crate::types::{Hash32, Hash20, Transaction};
use secp256k1::{Secp256k1, Message, PublicKey, ecdsa::Signature};
use anyhow::Result;

pub fn sha256d(data: &[u8]) -> Hash32 {
    let h1 = Sha256::digest(data);
    let h2 = Sha256::digest(&h1);
    let mut out = [0u8; 32];
    out.copy_from_slice(&h2);
    out
}

pub fn hash160(pubkey_bytes: &[u8]) -> Hash20 {
    let s = Sha256::digest(pubkey_bytes);
    let r = Ripemd160::digest(&s);
    let mut out = [0u8; 20];
    out.copy_from_slice(&r);
    out
}

// txid excludes script_sig
pub fn txid(tx: &Transaction) -> Hash32 {
    let mut stripped = tx.clone();
    for i in stripped.inputs.iter_mut() {
        i.script_sig.clear();
    }
    let bytes = bincode::serialize(&stripped).expect("serialize");
    sha256d(&bytes)
}

pub fn verify_sig(tx: &Transaction, sig64: &[u8;64], pub33: &[u8]) -> Result<()> {
    let digest = txid(tx);
    let msg = Message::from_digest_slice(&digest)?;
    let pk = PublicKey::from_slice(pub33)?;
    let sig = Signature::from_compact(sig64)?;
    Secp256k1::verification_only().verify_ecdsa(&msg, &sig, &pk)?;
    Ok(())
}
