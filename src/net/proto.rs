use serde::{Serialize, Deserialize};
use crate::types::{Hash32, Block, BlockHeader, Transaction};

#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum SyncRequest {
    GetTip,
    GetHeaders { from_height: u64, max: u64 },
    GetBlock { hash: Hash32 },
    SubmitTx { tx: Transaction },
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum SyncResponse {
    Tip { hash: Hash32, height: u64, chainwork: u128 },
    Headers { headers: Vec<(BlockHeader, Hash32, u64, u128)> }, // (header, hash, height, chainwork)
    Block { block: Block },
    Ack,
    Err { msg: String },
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct GossipHeader {
    pub header: BlockHeader,
    pub hash: Hash32,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct GossipTx {
    pub tx: Transaction,
}

pub const TOPIC_HDR: &str = "csd/hdr/1";
pub const TOPIC_TX:  &str = "csd/tx/1";
pub const SYNC_PROTO: &str = "/csd/sync/1";
