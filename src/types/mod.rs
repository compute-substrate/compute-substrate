// src/types/mod.rs
//
// CONSENSUS WARNING:
// These types participate in txid/sighash, block hashing, and/or state transitions.
// - Do NOT reorder struct fields.
// - Do NOT reorder enum variants.
// - Do NOT change integer widths.
// Any of the above can change serialization/hashes and cause a hard fork.

use serde::{Deserialize, Serialize};

pub type Hash32 = [u8; 32];
pub type Hash20 = [u8; 20];

#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub struct OutPoint {
    pub txid: Hash32,
    pub vout: u32,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct TxIn {
    pub prevout: OutPoint,

    /// v0 scriptsig:
    /// - normal tx inputs: [sig_len=64][sig64][pub_len=33][pub33] => 99 bytes
    /// - coinbase input: height.to_le_bytes() => 8 bytes
    ///
    /// Exact size rules are enforced in utxo/block validation.
    ///
    /// CONSENSUS: Serialize this as raw bytes (not a Vec<u8> element list).
    #[serde(with = "serde_bytes")]
    pub script_sig: Vec<u8>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct TxOut {
    pub value: u64,

    /// v0 script_pubkey is always 20-byte hash160(pubkey)
    pub script_pubkey: Hash20,
}

/// CONSENSUS WARNING:
/// Enum variant order is part of encoding. Do NOT reorder variants.
/// If you need to extend this, only append new variants at the end.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum AppPayload {
    None,
    Propose {
        /// Consensus: enforce byte length limits in validation.
        /// Recommend freezing allowed character set (e.g. ASCII) at mainnet.
        domain: String,
        payload_hash: Hash32,
        uri: String,
        expires_epoch: u64,
    },
    Attest {
        proposal_id: Hash32,
        score: u32,
        confidence: u32,
    },
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Transaction {
    pub version: u32,
    pub inputs: Vec<TxIn>,
    pub outputs: Vec<TxOut>,
    pub locktime: u32,
    pub app: AppPayload,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct BlockHeader {
    pub version: u32,
    pub prev: Hash32,
    pub merkle: Hash32,
    pub time: u64,
    pub bits: u32,

    /// CONSENSUS: nonce is 32-bit (matches header_hash serialization in chain/index.rs).
    pub nonce: u32,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Block {
    pub header: BlockHeader,
    pub txs: Vec<Transaction>,
}
