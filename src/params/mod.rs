// src/params/mod.rs
use crate::types::Hash32;

pub const CHAIN_ID: &str = "compute-substrate-testnet-1";

// Testnet defaults (tune later)
pub const TARGET_BLOCK_SECS: u64 = 60;
pub const INITIAL_BITS: u32 = 0x1f00ffff; // "Bitcoin-like" easy target (testnet)
pub const EPOCH_LEN: u64 = 60;
pub const TOP_K: usize = 25;

// Fees (in sat-style units of Token)
pub const MIN_FEE_PROPOSE: u64 = 10_000;
pub const MIN_FEE_ATTEST: u64  = 2_000;

// Block subsidy (testnet)
pub const COIN: u64 = 100_000_000;
pub const BLOCK_REWARD: u64 = 50 * COIN;

// Hardcode a genesis hash after you generate it once.
pub const GENESIS_HASH: Hash32 = [0u8; 32];
