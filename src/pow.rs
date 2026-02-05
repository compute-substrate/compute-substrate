use anyhow::{Result, bail};
use num_bigint::BigUint;
use num_traits::{Zero, ToPrimitive};

use crate::types::Hash32;
use crate::params::{POW_LIMIT_BITS, TARGET_BLOCK_SECS, RETARGET_INTERVAL, RETARGET_CLAMP_FACTOR};

fn bytes_be_to_big(x: &[u8]) -> BigUint {
    BigUint::from_bytes_be(x)
}

fn big_to_32be(x: &BigUint) -> [u8; 32] {
    let mut out = [0u8; 32];
    let b = x.to_bytes_be();
    let start = 32usize.saturating_sub(b.len());
    out[start..].copy_from_slice(&b[b.len().saturating_sub(32)..]);
    out
}

/// Bitcoin-style compact bits -> full 256-bit target (big-endian bytes)
pub fn bits_to_target(bits: u32) -> [u8; 32] {
    let exp = ((bits >> 24) & 0xff) as u32;
    let mant = (bits & 0x00ff_ffff) as u32;

    // target = mantissa * 256^(exp-3)
    // exp is number of bytes of the full target.
    let mut t = BigUint::from(mant);

    if exp <= 3 {
        let shift = 8 * (3 - exp);
        t >>= shift;
    } else {
        let shift = 8 * (exp - 3);
        t <<= shift;
    }

    big_to_32be(&t)
}

/// Full target -> compact bits (best-effort canonicalization)
pub fn target_to_bits(target_be: &[u8; 32]) -> u32 {
    // Canonicalize like Bitcoin: exponent = number of bytes, mantissa = top 3 bytes.
    let t = bytes_be_to_big(target_be);
    if t.is_zero() {
        return 0;
    }

    let mut b = t.to_bytes_be();
    // Strip leading zeros
    while b.first() == Some(&0) {
        b.remove(0);
    }
    let mut exp = b.len() as u32;

    // mantissa is the first 3 bytes of the big-endian number
    let mut mant: u32 = 0;
    if b.len() >= 3 {
        mant = ((b[0] as u32) << 16) | ((b[1] as u32) << 8) | (b[2] as u32);
    } else if b.len() == 2 {
        mant = ((b[0] as u32) << 16) | ((b[1] as u32) << 8);
    } else if b.len() == 1 {
        mant = (b[0] as u32) << 16;
    }

    // If mantissa's top bit is set, shift right by a byte and bump exponent
    if (mant & 0x0080_0000) != 0 {
        mant >>= 8;
        exp += 1;
    }

    (exp << 24) | (mant & 0x00ff_ffff)
}

/// Compare hash <= target (both interpreted as big-endian integers)
pub fn check_pow(hash: &Hash32, bits: u32) -> bool {
    let target = bits_to_target(bits);
    bytes_be_to_big(hash) <= bytes_be_to_big(&target)
}

pub fn pow_limit_target() -> [u8; 32] {
    bits_to_target(POW_LIMIT_BITS)
}

/// Compute next difficulty bits at `height` (where `height` is the height of the NEW block)
/// Uses headers' times to retarget every RETARGET_INTERVAL blocks.
pub fn next_bits<F>(
    height: u64,
    parent_bits: u32,
    parent_time: u64,
    get_ancestor: F,
) -> Result<u32>
where
    F: Fn(u64) -> Result<(u64, u32)>, // (time, bits) at a given height on canonical chain
{
    // No retarget until we have enough history
    if height == 0 || height % RETARGET_INTERVAL != 0 {
        return Ok(parent_bits);
    }

    let first_height = height - RETARGET_INTERVAL;
    let (first_time, _first_bits) = get_ancestor(first_height)?;
    let last_time = parent_time;

    let expected = RETARGET_INTERVAL * TARGET_BLOCK_SECS;
    let mut actual = if last_time > first_time { last_time - first_time } else { 1 };

    // Clamp to [expected/4, expected*4]
    let min = expected / RETARGET_CLAMP_FACTOR;
    let max = expected * RETARGET_CLAMP_FACTOR;
    if actual < min { actual = min; }
    if actual > max { actual = max; }

    let old_target = bytes_be_to_big(&bits_to_target(parent_bits));
    let new_target = (old_target * BigUint::from(actual)) / BigUint::from(expected);

    // Cap at pow limit
    let limit = bytes_be_to_big(&pow_limit_target());
    let capped = if new_target > limit { limit } else { new_target };

    Ok(target_to_bits(&big_to_32be(&capped)))
}	
