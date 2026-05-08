// src/chain/pow.rs
use anyhow::{bail, Result};
use num_bigint::BigUint;
use num_traits::{One, ToPrimitive, Zero};

use crate::chain::index::{get_hidx, HeaderIndex};
use crate::params::{
    INITIAL_BITS, LWMA_SOLVETIME_MAX_FACTOR, LWMA_WINDOW, POW_LIMIT_BITS, TARGET_BLOCK_SECS,
};
use crate::state::db::Stores;
use crate::types::Hash32;

// -------------------- compact bits <-> 256-bit target --------------------
//
// Bitcoin-style "compact" format:
// bits = [exponent:8][mantissa:23][sign:1]
// target = mantissa * 256^(exponent-3)

fn bits_parts(bits: u32) -> (u32, u32) {
    let exp = (bits >> 24) & 0xff;
    let mant = bits & 0x00ff_ffff;
    (exp, mant)
}

/// Compact bits -> 32-byte BE target.
/// Returns [0;32] on invalid encoding.
pub fn bits_to_target_bytes(bits: u32) -> [u8; 32] {
    let (exp_u32, mant) = bits_parts(bits);
    let exp = exp_u32 as usize;

    if exp == 0 || mant == 0 {
        return [0u8; 32];
    }
    if (mant & 0x0080_0000) != 0 {
        return [0u8; 32];
    }
    if exp > 32 {
        return [0u8; 32];
    }

    let mant_u = BigUint::from(mant as u64);

    let target = if exp_u32 <= 3 {
        let shift = 8u32 * (3u32 - exp_u32);
        mant_u >> shift
    } else {
        let shift = 8u32 * (exp_u32 - 3u32);
        mant_u << shift
    };

    if target.is_zero() || target.bits() > 256 {
        return [0u8; 32];
    }

    biguint_to_target_bytes(&target)
}

/// 32-byte BE target -> compact bits (canonical). Returns 0 for zero target.
pub fn target_bytes_to_bits(target: [u8; 32]) -> u32 {
    let x = BigUint::from_bytes_be(&target);
    if x.is_zero() {
        return 0;
    }

    let bytes = x.to_bytes_be();
    let mut exp = bytes.len() as u32;

    let mut mant: u32 = if exp <= 3 {
        let shift = 8u32 * (3u32 - exp);
        let m = (&x << shift).to_u64().unwrap_or(u64::MAX);
        (m as u32) & 0x00ff_ffff
    } else {
        ((bytes[0] as u32) << 16) | ((bytes[1] as u32) << 8) | (bytes[2] as u32)
    };

    if (mant & 0x0080_0000) != 0 {
        mant >>= 8;
        exp += 1;
    }

    mant &= 0x00ff_ffff;
    (exp << 24) | mant
}

fn biguint_to_target_bytes(x: &BigUint) -> [u8; 32] {
    let mut out = [0u8; 32];
    let bytes = x.to_bytes_be();
    if bytes.is_empty() {
        return out;
    }
    let slice = if bytes.len() > 32 {
        &bytes[bytes.len() - 32..]
    } else {
        &bytes[..]
    };
    let start = 32 - slice.len();
    out[start..].copy_from_slice(slice);
    out
}

/// Enforce "not easier than pow limit" (target <= limit_target).
pub fn bits_within_pow_limit(bits: u32) -> bool {
    if bits == 0 {
        return false;
    }
    let t = bits_to_target_bytes(bits);
    if t == [0u8; 32] {
        return false;
    }
    let limit = bits_to_target_bytes(POW_LIMIT_BITS);
    if limit == [0u8; 32] {
        return false;
    }
    t <= limit
}

/// Integration-test friendly bypass switch.
/// Use: `CSD_BYPASS_POW=1 cargo test ...`
fn bypass_pow() -> bool {
    match std::env::var("CSD_BYPASS_POW") {
        Ok(v) => {
            let v = v.trim().to_ascii_lowercase();
            v == "1" || v == "true" || v == "yes" || v == "on"
        }
        Err(_) => false,
    }
}

#[derive(Clone, Copy)]
pub struct PowTarget {
    target: [u8; 32],
    target_hi: u128,
}

impl PowTarget {
    pub fn from_bits(bits: u32) -> Option<Self> {
        if !bits_within_pow_limit(bits) {
            return None;
        }

        let target = bits_to_target_bytes(bits);
        if target == [0u8; 32] {
            return None;
        }

        let mut hi = [0u8; 16];
        hi.copy_from_slice(&target[..16]);

        Some(Self {
            target,
            target_hi: u128::from_be_bytes(hi),
        })
    }

    #[inline(always)]
    pub fn check(&self, hash: &Hash32) -> bool {
        let mut hi = [0u8; 16];
        hi.copy_from_slice(&hash[..16]);

        let hash_hi = u128::from_be_bytes(hi);

        if hash_hi > self.target_hi {
            return false;
        }

        if hash_hi < self.target_hi {
            return true;
        }

        hash <= &self.target
    }
}

/// STRICT PoW validity: hash <= target (both BE).

pub fn pow_ok_strict(hash: &Hash32, bits: u32) -> bool {
    let Some(target) = PowTarget::from_bits(bits) else {
        return false;
    };

    target.check(hash)
}

/// PoW validity used by consensus code.
/// If CSD_BYPASS_POW=1 is set (integration tests), always returns true.
pub fn pow_ok(hash: &Hash32, bits: u32) -> bool {
    if bypass_pow() {
        let _ = (hash, bits);
        return true;
    }
    pow_ok_strict(hash, bits)
}

/// Bitcoin-style work from target:
/// work = floor(2^256 / (target + 1)), clamped to u128.
pub fn work_from_bits(bits: u32) -> Result<u128> {
    if !bits_within_pow_limit(bits) {
        bail!("bits beyond pow limit (or zero/invalid)");
    }

    let t_bytes = bits_to_target_bytes(bits);
    let target = BigUint::from_bytes_be(&t_bytes);

    if target.is_zero() {
        bail!("invalid target (zero)");
    }

    let two_256: BigUint = BigUint::one() << 256;
    let denom = &target + BigUint::one();
    let w = two_256 / denom;

    let max = BigUint::from(u128::MAX);
    let w = if w > max { max } else { w };
    Ok(w.to_u128().unwrap_or(u128::MAX))
}

/// STRICT LWMA expected bits.
pub fn expected_bits_strict(db: &Stores, height: u64, parent: Option<&HeaderIndex>) -> Result<u32> {
    if height == 0 {
        if !bits_within_pow_limit(INITIAL_BITS) {
            bail!("INITIAL_BITS invalid or beyond POW_LIMIT_BITS");
        }
        return Ok(INITIAL_BITS);
    }

    let parent =
        parent.ok_or_else(|| anyhow::anyhow!("expected_bits: missing parent for height>0"))?;

    if !bits_within_pow_limit(parent.bits) {
        bail!("expected_bits: parent.bits invalid/beyond pow limit");
    }

    if height < 2 {
        return Ok(parent.bits);
    }

    let mut n = LWMA_WINDOW.min(height as usize);
    if n < 2 {
        return Ok(parent.bits);
    }
    if n > 1000 {
        n = 1000;
    }

    let mut times: Vec<u64> = Vec::with_capacity(n);
    let mut targets: Vec<BigUint> = Vec::with_capacity(n);

    let mut cur = parent.clone();
    for _ in 0..n {
        let tb = bits_to_target_bytes(cur.bits);
        if tb == [0u8; 32] {
            bail!("expected_bits: invalid compact bits in history window");
        }
        times.push(cur.time);
        targets.push(BigUint::from_bytes_be(&tb));

        if cur.parent == [0u8; 32] {
            break;
        }
        if times.len() >= n {
            break;
        }
        let prev = get_hidx(db, &cur.parent)?
            .ok_or_else(|| anyhow::anyhow!("expected_bits: missing ancestor during LWMA walk"))?;
        cur = prev;
    }

    if times.len() < 2 {
        return Ok(parent.bits);
    }

    times.reverse();
    targets.reverse();

    let m = times.len();
    if m < 2 {
        return Ok(parent.bits);
    }

    let t = TARGET_BLOCK_SECS.max(1);
    let max_solvetime = (LWMA_SOLVETIME_MAX_FACTOR.max(1)).saturating_mul(t);

    let mut weighted_sum: u128 = 0;
    let mut denom: u128 = 0;

    for i in 1..m {
        let dt = times[i].saturating_sub(times[i - 1]);
        let st = dt.clamp(1, max_solvetime);
        let w = i as u128;
        weighted_sum = weighted_sum.saturating_add((st as u128).saturating_mul(w));
        denom = denom.saturating_add(w);
    }

    if denom == 0 {
        return Ok(parent.bits);
    }

    let avg_solvetime = (weighted_sum / denom) as u64;

    let mut sum_target = BigUint::zero();
    for tg in &targets {
        sum_target += tg;
    }
    let avg_target = sum_target / BigUint::from(m as u64);

    let mut next_target = avg_target * BigUint::from(avg_solvetime) / BigUint::from(t);

    let limit_tb = bits_to_target_bytes(POW_LIMIT_BITS);
    if limit_tb == [0u8; 32] {
        bail!("POW_LIMIT_BITS invalid (params)");
    }
    let limit = BigUint::from_bytes_be(&limit_tb);
    if next_target > limit {
        next_target = limit;
    }
    if next_target.is_zero() || next_target.bits() > 256 {
        return Ok(POW_LIMIT_BITS);
    }

    let tb = biguint_to_target_bytes(&next_target);
    let bits = target_bytes_to_bits(tb);

    if !bits_within_pow_limit(bits) {
        return Ok(POW_LIMIT_BITS);
    }

    Ok(bits)
}

/// expected_bits used by consensus code.
/// If CSD_BYPASS_POW=1 is set (integration tests), keep it stable: parent.bits.
pub fn expected_bits(db: &Stores, height: u64, parent: Option<&HeaderIndex>) -> Result<u32> {
    if bypass_pow() {
        let _ = db;
        if height == 0 {
            return Ok(INITIAL_BITS);
        }
        if let Some(p) = parent {
            return Ok(p.bits);
        }
        bail!("expected_bits(test-bypass): missing parent for height>0");
    }

    expected_bits_strict(db, height, parent)
}
