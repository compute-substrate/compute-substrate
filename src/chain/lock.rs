// src/chain/lock.rs
use std::sync::Arc;

/// Global chain write lock.
/// Use this to serialize all chainstate mutations (UTXO/app DB writes, reorgs, tip updates, etc.)
pub type ChainLock = Arc<parking_lot::Mutex<()>>;

pub fn new_chain_lock() -> ChainLock {
    Arc::new(parking_lot::Mutex::new(()))
}
