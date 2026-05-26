// src/chain/index.rs
use anyhow::{bail, Result};
use serde::{Deserialize, Serialize};

use crate::chain::pow::{bits_within_pow_limit, expected_bits, pow_ok, work_from_bits};
use crate::chain::time::{median_time_past, now_secs};
use crate::crypto::sha256d;
use sha2::{Digest, Sha256};
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

/// Canonical 84-byte header serialization (single source of truth).
/// Layout:
///   version u32 LE [0..4], prev [4..36], merkle [36..68],
///   time u64 LE [68..76], bits u32 LE [76..80], nonce u32 LE [80..84]
#[inline]
pub fn serialize_header(h: &BlockHeader) -> [u8; 84] {
    let mut buf = [0u8; 84];
    buf[0..4].copy_from_slice(&h.version.to_le_bytes());
    buf[4..36].copy_from_slice(&h.prev);
    buf[36..68].copy_from_slice(&h.merkle);
    buf[68..76].copy_from_slice(&h.time.to_le_bytes());
    buf[76..80].copy_from_slice(&h.bits.to_le_bytes());
    buf[80..84].copy_from_slice(&h.nonce.to_le_bytes());
    buf
}

pub fn header_hash(h: &BlockHeader) -> Hash32 {
    sha256d(&serialize_header(h))
}

// -------------------- midstate fast path (mining hot loop) --------------------
//
// SHA-256 processes 64-byte blocks. The header is 84 bytes => block1 = [0..64]
// (version+prev+merkle[0..28]) and block2 = [64..84] (merkle[28..32]+time+bits
// +nonce) plus padding. block1 is CONSTANT across a nonce/time sweep, so we
// absorb it once into a "midstate" hasher and per-nonce only feed the 20-byte
// tail. Recompute the midstate only when version/prev/merkle change.
//
// header_hash_mid(base, tail) is BIT-IDENTICAL to header_hash for the matching
// header (see test below) — pure speedup, zero consensus impact.

/// Tail byte offsets, relative to byte 64: merkle[28..32]=[0..4], time=[4..12],
/// bits=[12..16], nonce=[16..20].
pub const MID_TAIL_NONCE: core::ops::Range<usize> = 16..20;

/// Absorb block1; returns the reusable midstate hasher and the 20-byte tail.
#[inline]
pub fn header_midstate(h: &BlockHeader) -> (Sha256, [u8; 20]) {
    let buf = serialize_header(h);
    let mut base = Sha256::new();
    base.update(&buf[0..64]);
    let mut tail = [0u8; 20];
    tail.copy_from_slice(&buf[64..84]);
    (base, tail)
}

/// Finish a hash from a cached midstate + tail (set tail[MID_TAIL_NONCE] first).
#[inline]
pub fn header_hash_mid(base: &Sha256, tail: &[u8; 20]) -> Hash32 {
    let mut first = base.clone();
    first.update(&tail[..]);
    let a = first.finalize();
    let b = Sha256::digest(&a);
    let mut out = [0u8; 32];
    out.copy_from_slice(&b);
    out
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

#[cfg(test)]
mod midstate_tests {
    use super::*;
    use crate::types::BlockHeader;

    // The midstate fast path MUST equal the consensus header_hash for every
    // header, or the miner could produce blocks the network rejects. Sweep
    // nonce + time (the block2 fields) under one cached midstate, plus random
    // version/prev/merkle (block1 fields) to re-derive the midstate.
    #[test]
    fn midstate_matches_header_hash() {
        let mut seed: u64 = 0x243f6a8885a308d3;
        let mut rng = || {
            seed ^= seed << 13;
            seed ^= seed >> 7;
            seed ^= seed << 17;
            seed
        };
        for _ in 0..50_000 {
            let mut prev = [0u8; 32];
            let mut merkle = [0u8; 32];
            for b in prev.iter_mut() {
                *b = rng() as u8;
            }
            for b in merkle.iter_mut() {
                *b = rng() as u8;
            }
            let mut h = BlockHeader {
                version: rng() as u32,
                prev,
                merkle,
                time: rng(),
                bits: rng() as u32,
                nonce: 0,
            };
            let (base, mut tail) = header_midstate(&h);
            for _ in 0..4 {
                h.nonce = rng() as u32;
                tail[MID_TAIL_NONCE].copy_from_slice(&h.nonce.to_le_bytes());
                assert_eq!(
                    header_hash(&h),
                    header_hash_mid(&base, &tail),
                    "midstate diverged from consensus header_hash"
                );
            }
        }
    }
}
