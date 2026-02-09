// src/crypto/mod.rs
//
// Consensus hashing + signature rules (FROZEN).
//
// IMPORTANT:
// - All consensus-critical serialization MUST use crate::codec::consensus_bincode().
// - Treat Cargo.lock + exact crate versions as consensus-critical once mainnet launches.

use anyhow::{bail, Result};
use ripemd::Ripemd160;
use secp256k1::{ecdsa::Signature, Message, PublicKey, Secp256k1};
use sha2::{Digest, Sha256};

use crate::params::CHAIN_ID_HASH;
use crate::types::{Hash20, Hash32, Transaction};

pub fn sha256d(data: &[u8]) -> Hash32 {
    let h1 = Sha256::digest(data);
    let h2 = Sha256::digest(&h1);
    let mut out = [0u8; 32];
    out.copy_from_slice(&h2);
    out
}

pub fn sha256(data: &[u8]) -> Hash32 {
    let h = Sha256::digest(data);
    let mut out = [0u8; 32];
    out.copy_from_slice(&h);
    out
}

pub fn hash160(pubkey_bytes: &[u8]) -> Hash20 {
    let s = Sha256::digest(pubkey_bytes);
    let r = Ripemd160::digest(&s);
    let mut out = [0u8; 20];
    out.copy_from_slice(&r);
    out
}

/// Return tx clone with all script_sig cleared.
fn stripped_tx(tx: &Transaction) -> Transaction {
    let mut stripped = tx.clone();
    for i in stripped.inputs.iter_mut() {
        i.script_sig.clear();
    }
    stripped
}

/// Transaction identifier (consensus object id).
/// Deterministic and does NOT include signatures.
///
/// NOTE:
/// - txid() strips script_sig.
/// - Coinbase uniqueness must therefore be ensured by some other committed field
///   (you do locktime = height in mine.rs, and also script_sig commits height for policy).
pub fn txid(tx: &Transaction) -> Hash32 {
    let stripped = stripped_tx(tx);
    let bytes = crate::codec::consensus_bincode()
        .serialize(&stripped)
        .expect("consensus serialize(txid)");
    sha256d(&bytes)
}

/// Tagged-hash helper (BIP340-style): sha256( sha256(tag)||sha256(tag)||msg )
fn tagged_hash(tag: &[u8], msg: &[u8]) -> Hash32 {
    let tag_hash = sha256(tag);
    let mut buf = Vec::with_capacity(32 + 32 + msg.len());
    buf.extend_from_slice(&tag_hash);
    buf.extend_from_slice(&tag_hash);
    buf.extend_from_slice(msg);
    sha256(&buf)
}

/// Stable signature hash rule (FROZEN: CSD_SIG_V1)
///
/// 1) strip all script_sig
/// 2) preimage = bincode(stripped_tx) || CHAIN_ID_HASH
/// 3) sighash = sha256d( tagged_hash("CSD_SIG_V1", preimage) )
///
/// Notes:
/// - domain-separated via CHAIN_ID_HASH (frozen constant)
/// - signature does not cover itself
/// - tagged hash prevents cross-protocol collisions
pub fn sighash(tx: &Transaction) -> Hash32 {
    let stripped = stripped_tx(tx);
    let mut pre = crate::codec::consensus_bincode()
        .serialize(&stripped)
        .expect("consensus serialize(sighash)");
    pre.extend_from_slice(&CHAIN_ID_HASH);
    let th = tagged_hash(b"CSD_SIG_V1", &pre);
    sha256d(&th)
}

/// Verify compact 64-byte ECDSA signature over sighash(tx).
///
/// Consensus rules:
/// - pubkey must be 33-byte compressed secp256k1 pubkey
/// - signature must be compact 64-byte ECDSA
/// - signature must be LOW-S canonical (reject high-S)
pub fn verify_sig(tx: &Transaction, sig64: &[u8; 64], pub33: &[u8]) -> Result<()> {
    if pub33.len() != 33 {
        bail!("pubkey must be 33 bytes compressed");
    }

    let digest = sighash(tx);
    let msg = Message::from_digest_slice(&digest)?;

    let pk = PublicKey::from_slice(pub33)?;

    // Parse compact sig
    let sig = Signature::from_compact(sig64)?;

    // Enforce LOW-S canonicality as a consensus rule.
    // If normalizing would change the signature, it was high-S => reject.
    let mut norm = sig;
    norm.normalize_s();
    if norm.serialize_compact() != sig.serialize_compact() {
        bail!("non-canonical signature (high-S)");
    }

    Secp256k1::verification_only().verify_ecdsa(&msg, &sig, &pk)?;
    Ok(())
}
