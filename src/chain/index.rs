// src/chain/index.rs
use anyhow::{bail, Result};
use serde::{Deserialize, Serialize};

use crate::chain::pow::{bits_within_pow_limit, expected_bits, pow_ok, work_from_bits};
use crate::chain::time::{median_time_past, now_secs};
use crate::crypto::sha256d;
use crate::params::{GENESIS_HASH, MAX_FUTURE_DRIFT_SECS, MIN_BLOCK_SPACING_SECS};
use crate::state::db::{k_hdr, Stores};
use crate::types::{BlockHeader, Hash32};

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct HeaderIndex {
    pub hash: Hash32,
    pub parent: Hash32,
    pub height: u64,
    pub chainwork: u128,
    pub bits: u32,
    pub time: u64,
}

/// Canonical, consensus-stable header hash.
/// Avoid bincode/serde to prevent accidental consensus splits.
/// Layout (all fixed):
/// - version: u32 LE
/// - prev: 32 bytes
/// - merkle: 32 bytes
/// - time: u64 LE
/// - bits: u32 LE
/// - nonce: u32 LE

pub fn header_hash(h: &BlockHeader) -> Hash32 {
    // Canonical layout:
    // version: u32 LE     bytes 0..4
    // prev:    32 bytes   bytes 4..36
    // merkle:  32 bytes   bytes 36..68
    // time:    u64 LE     bytes 68..76
    // bits:    u32 LE     bytes 76..80
    // nonce:   u32 LE     bytes 80..84
    let mut buf = [0u8; 84];

    buf[0..4].copy_from_slice(&h.version.to_le_bytes());
    buf[4..36].copy_from_slice(&h.prev);
    buf[36..68].copy_from_slice(&h.merkle);
    buf[68..76].copy_from_slice(&h.time.to_le_bytes());
    buf[76..80].copy_from_slice(&h.bits.to_le_bytes());
    buf[80..84].copy_from_slice(&h.nonce.to_le_bytes());

    sha256d(&buf)
}

pub fn get_hidx(db: &Stores, hash: &Hash32) -> Result<Option<HeaderIndex>> {
    if let Some(v) = db.hdr.get(k_hdr(hash))? {
        Ok(Some(
            crate::codec::consensus_bincode().deserialize::<HeaderIndex>(&v)?,
        ))
    } else {
        Ok(None)
    }
}

pub fn put_hidx(db: &Stores, hi: &HeaderIndex) -> Result<()> {
    db.hdr.insert(
        k_hdr(&hi.hash),
        crate::codec::consensus_bincode().serialize(hi)?,
    )?;
    Ok(())
}

/// In tests/integration tests we sometimes want to build toy chains with arbitrary genesis.
/// IMPORTANT: In release builds, this is always false.
#[cfg(test)]
fn allow_foreign_genesis_for_tests() -> bool {
    true
}

#[cfg(not(test))]
fn allow_foreign_genesis_for_tests() -> bool {
    false
}

/// Insert a header index entry (CONSENSUS CRITICAL)
pub fn index_header(
    db: &Stores,
    hdr: &BlockHeader,
    expected_parent: Option<&HeaderIndex>,
) -> Result<HeaderIndex> {
    let hash = header_hash(hdr);

    // If already indexed, return it (idempotent; helps sync races).
    if let Some(existing) = get_hidx(db, &hash)? {
        return Ok(existing);
    }

    // ---- Genesis identity ----
    if hdr.prev == [0u8; 32] {
        // Production rule: genesis must match params::GENESIS_HASH.
        // Test rule: allow arbitrary genesis so integration tests can build toy chains.
        if hash != GENESIS_HASH && !allow_foreign_genesis_for_tests() {
            bail!("foreign genesis header");
        }
        if expected_parent.is_some() {
            bail!("genesis must not have parent");
        }
    }

    // ---- Parent / height ----
    let (height, parent_hi) = if hdr.prev == [0u8; 32] {
        (0u64, None)
    } else {
        let p = expected_parent.ok_or_else(|| anyhow::anyhow!("parent missing"))?;
        if p.hash != hdr.prev {
            bail!("parent mismatch");
        }
        (p.height + 1, Some(p))
    };

    // ----------------- time guardrails (CONSENSUS, OBJECTIVE) -----------------
    
    if let Some(p) = parent_hi {
        let min_allowed = p.time.saturating_add(MIN_BLOCK_SPACING_SECS);
        if hdr.time < min_allowed {
            bail!(
                "time too early: {} < parent+min_spacing({})",
                hdr.time,
                min_allowed
            );
        }

        let mtp = median_time_past(db, &p.hash)?;
        if hdr.time <= mtp {
            bail!("time <= MTP: {} <= {}", hdr.time, mtp);
        }

        // Future bound relative to local wall clock.
        // This is required so timestamps can track real elapsed mining time,
        // which LWMA needs in order to retarget correctly.
        let max_allowed = now_secs().saturating_add(MAX_FUTURE_DRIFT_SECS);
        if hdr.time > max_allowed {
            bail!(
                "time too far in future: {} > now+drift({})",
                hdr.time,
                max_allowed
            );
        }

    }
    // ------------------------------------------------------------------------

    // ---- Difficulty rules ----
    if !bits_within_pow_limit(hdr.bits) {
        bail!("bits beyond pow limit");
    }

    let want_bits = expected_bits(db, height, parent_hi)?;
    if hdr.bits != want_bits {
        bail!("unexpected bits: got {} want {}", hdr.bits, want_bits);
    }

    // ---- PoW ----
    if !pow_ok(&hash, hdr.bits) {
        bail!("invalid PoW");
    }

    // ---- Chainwork ----
    let self_work = work_from_bits(hdr.bits)?;
    let chainwork = if let Some(p) = parent_hi {
        p.chainwork.saturating_add(self_work)
    } else {
        self_work
    };

    let hi = HeaderIndex {
        hash,
        parent: hdr.prev,
        height,
        chainwork,
        bits: hdr.bits,
        time: hdr.time,
    };

put_hidx(db, &hi)?;
Ok(hi)

}
