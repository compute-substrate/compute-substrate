pub mod mempool;
pub mod node;
pub mod proto;

use crate::types::{Block, BlockHeader, Hash32, Transaction};

#[derive(Clone, Debug)]
pub struct MinedHeaderEvent {
    pub hash: Hash32,
    pub header: BlockHeader,
    pub block: Block,
}

#[derive(Clone, Debug)]
pub struct GossipTxEvent {
    pub tx: Transaction,
}
