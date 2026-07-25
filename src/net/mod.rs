pub mod mempool;
pub mod node;
pub mod proto;

use crate::types::{BlockHeader, Hash32, Transaction};

#[derive(Clone, Debug)]
pub struct MinedHeaderEvent {
    pub hash: Hash32,
    pub header: BlockHeader,
}

#[derive(Clone, Debug)]
pub struct GossipTxEvent {
    pub tx: Transaction,
    /// Queue a failed publish for retry, mirroring `publish_header`'s `insure`.
    ///
    /// TRUE only for the first accept of a transaction into our mempool, which is the case the
    /// stranding insurance exists for. FALSE for the re-gossip of a duplicate submit, because
    /// there the publish can return Err(Duplicate) for a benign reason: the message-id is a hash
    /// of the content, so a transaction we RECEIVED from a peer already sits in our own 60 s
    /// duplicate cache. Insuring that retry means an unauthenticated POST of any already-known
    /// transaction schedules a full-mesh re-broadcast of it about 60 s later, once the caches
    /// expire. The re-gossip itself is still worth doing; only the insured replay is not.
    pub insure: bool,
}
