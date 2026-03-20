// src/params/mod.rs
use crate::types::Hash32;

// -------------------- chain identity (CONSENSUS) --------------------
//
// We keep a human-readable string for display,
// but we FREEZE the hash used in consensus sighash tagging.
//
// CHAIN_ID_HASH = sha256("compute-substrate-mainnet")
pub const CHAIN_ID: &str = "compute-substrate-mainnet";
pub const CHAIN_ID_HASH: Hash32 = [
    0x1b, 0x17, 0xc7, 0xb0, 0x4d, 0x05, 0x39, 0x46, 0x74, 0xca, 0x2c, 0x8e, 0x24, 0xf7, 0x43, 0x3e,
    0x25, 0x1a, 0x19, 0x73, 0xca, 0xc2, 0x00, 0x0c, 0x7b, 0x60, 0x96, 0x65, 0x46, 0xe0, 0xb8, 0x75,
];

pub const CHAIN_NAME: &str = "Compute Substrate";
pub const TICKER: &str = "CSD";

pub const GENESIS_EPIGRAPH: &str =
    "Reuters 2026-02-05: Britain to work with Microsoft to build deepfake detection system.";

pub const TARGET_BLOCK_SECS: u64 = 60;

// Initial difficulty target (compact bits).
// This sets the starting difficulty at genesis; subsequent blocks follow the difficulty adjustment rules in code.
pub const INITIAL_BITS: u32 = 0x1d00ffff;

// -----------------------------------------------------------------------------
// Difficulty / PoW (LWMA per-block retarget)
// -----------------------------------------------------------------------------

// --- Mainnet consensus limits (anti-DoS) ---
pub const MAX_TX_BYTES: usize = 100_000; // 100 KB
pub const MAX_TX_INPUTS: usize = 512;
pub const MAX_TX_OUTPUTS: usize = 512;
pub const MAX_SCRIPTSIG_BYTES: usize = 99; // exact scriptsig format for NON-coinbase
pub const MAX_DOMAIN_BYTES: usize = 128;
pub const MAX_URI_BYTES: usize = 512;

// Block limits
pub const MAX_BLOCK_TXS: usize = 2_000; // count cap
pub const MAX_BLOCK_BYTES: usize = 2 * 1024 * 1024; // 2 MiB

// Maximum target (easiest difficulty).
pub const POW_LIMIT_BITS: u32 = 0x1f00ffff;

// LWMA window size (number of most-recent blocks used).
// With 60s blocks, 90 blocks ≈ 90 minutes. Good default for early survivability + stability.
pub const LWMA_WINDOW: usize = 90;

// Clamp solve times to reduce timestamp gaming impact and prevent instability.
// Standard LWMA uses max_solvetime = 6*T (and min 1 second).
pub const LWMA_SOLVETIME_MAX_FACTOR: u64 = 12;

// Legacy retarget params (kept so existing code/notes compile, but NOT used by LWMA):
pub const RETARGET_INTERVAL: u64 = 360;
pub const RETARGET_CLAMP_FACTOR: u64 = 4; // legacy (unused)

// -----------------------------------------------------------------------------
// Timestamp policy params (CONSENSUS OBJECTIVE in chain/index.rs)
// -----------------------------------------------------------------------------
pub const MAX_FUTURE_DRIFT_SECS: u64 = 2 * 60 * 60;
pub const MTP_WINDOW: usize = 11;
pub const MIN_BLOCK_SPACING_SECS: u64 = 30;

// App-layer epoching (consensus-critical only insofar as app rules are consensus)
// (You currently use epoch_of(height) in consensus app state application.)
pub const EPOCH_LEN: u64 = 60;
pub const TOP_K: usize = 25;

// Fees (in base units, 1 CSD = COIN units)
pub const MIN_FEE_PROPOSE: u64 = 25_000_000;
pub const MIN_FEE_ATTEST: u64 = 5_000_000;

pub const COIN: u64 = 100_000_000; // 1 CSD = 1e8 base units

pub const INITIAL_REWARD: u64 = 50 * COIN;
pub const HALVING_INTERVAL: u64 = 2_102_400; // ~4 years at 60s blocks
pub const MAX_HALVINGS: u64 = 64;

pub const GENESIS_HASH: [u8; 32] = [
    0x00, 0x00, 0x00, 0x00, 0x5b, 0x9d, 0x12, 0xda,
    0x07, 0xf3, 0x04, 0xe8, 0x5e, 0x73, 0xdc, 0x73,
    0x1d, 0x57, 0xa3, 0x30, 0x48, 0x10, 0xec, 0x20,
    0xb6, 0x34, 0xd3, 0xda, 0xdc, 0x86, 0x24, 0x6a,
];

pub fn block_reward(height: u64) -> u64 {
    let halvings = height / HALVING_INTERVAL;
    if halvings >= MAX_HALVINGS {
        return 0;
    }
    INITIAL_REWARD >> (halvings as u32)
}
