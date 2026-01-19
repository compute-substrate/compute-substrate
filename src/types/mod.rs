// src/types/mod.rs
use serde::{Serialize, Deserialize};

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
    pub script_sig: Vec<u8>, // v0: [sig_len][sig64][pub_len][pub33]
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct TxOut {
    pub value: u64,
    pub script_pubkey: Vec<u8>, // v0: 20-byte hash160(pubkey)
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum AppPayload {
    None,
    Propose { domain: String, payload_hash: Hash32, uri: String, expires_epoch: u64 },
    Attest  { proposal_id: Hash32, score: u32, confidence: u32 },
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
    pub nonce: u64,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Block {
    pub header: BlockHeader,
    pub txs: Vec<Transaction>,
}
