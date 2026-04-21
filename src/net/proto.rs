//src/net/proto.rs
use crate::types::{Block, BlockHeader, Hash32, Transaction};
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum SyncRequest {
    GetTip,
    GetHeaders { from_height: u64, max: u64 },
    GetHeadersByLocator { locator: Vec<Hash32>, max: u64 },
    GetBlock { hash: Hash32 },
    SubmitTx { tx: Transaction },
GetPeers { max: u16 },
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum SyncResponse {
    Tip {
        hash: Hash32,
        height: u64,
        chainwork: u128,
    },

    Headers {
        headers: Vec<BlockHeader>,
    },

    Block {
        block: Block,
    },

    Ack,
    Err {
        msg: String,
    },

Peers { peers: Vec<String> },

}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct GossipHeader {
    pub header: BlockHeader,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct GossipTx {
    pub tx: Transaction,
}

pub const TOPIC_HDR: &str = "csd/hdr/1";
pub const TOPIC_TX: &str = "csd/tx/1";


pub const SYNC_PROTO: &str = "/csd/sync/2";
