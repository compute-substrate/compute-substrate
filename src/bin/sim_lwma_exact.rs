use num_bigint::BigUint;
use num_traits::Zero;

use csd::chain::pow::{bits_to_target_bytes, target_bytes_to_bits};
use csd::params::{
    INITIAL_BITS, LWMA_SOLVETIME_MAX_FACTOR, LWMA_WINDOW, POW_LIMIT_BITS, TARGET_BLOCK_SECS,
};

fn biguint_to_32be(x: &BigUint) -> [u8; 32] {
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

fn main() {
    let t = TARGET_BLOCK_SECS.max(1);
    let window = LWMA_WINDOW;

    println!("target={}s window={}", t, window);

    // Start with a steady-state history at target spacing.
    let mut times: Vec<u64> = vec![t; window];
    let mut current_target =
        BigUint::from_bytes_be(&bits_to_target_bytes(INITIAL_BITS));

    let limit = BigUint::from_bytes_be(&bits_to_target_bytes(POW_LIMIT_BITS));

    for height in 0..400u64 {
        let hashpower_mult = if height < 120 {
            1.0
        } else if height < 240 {
            10.0
        } else {
            0.2
        };

        let expected_solve = (t as f64 / hashpower_mult) as u64;
        let solve_time = expected_solve.max(1);

        // advance timestamp
        let last_time = *times.last().unwrap_or(&t);
        times.push(last_time + solve_time);
        if times.len() > window {
            times.remove(0);
        }

        // Build a target window that mirrors chain behavior:
        // targets[i] corresponds to bits of historical blocks.
        // Here we approximate "history" as repeating the current target,
        // which is fine for convergence testing under step-changes.
        let mut targets: Vec<BigUint> = vec![current_target.clone(); times.len()];

        // ---- LWMA (exact math, BigUint targets) ----
        let m = times.len();
        if m < 2 {
            let bits = target_bytes_to_bits(biguint_to_32be(&current_target));
            println!(
                "h={} power={:.1} solve={} avg={} bits=0x{:08x}",
                height, hashpower_mult, solve_time, solve_time, bits
            );
            continue;
        }

        let max_solvetime = LWMA_SOLVETIME_MAX_FACTOR.max(1) * t;

        let mut weighted_sum: u128 = 0;
        let mut denom: u128 = 0;
        for i in 1..m {
            let dt = times[i].saturating_sub(times[i - 1]);
            let st = dt.clamp(1, max_solvetime);
            let w = i as u128;
            weighted_sum = weighted_sum.saturating_add((st as u128).saturating_mul(w));
            denom = denom.saturating_add(w);
        }

        let avg_solvetime = ((weighted_sum / denom) as u64).max(1);

        let mut sum_target = BigUint::zero();
        for tg in &targets {
            sum_target += tg;
        }
        let avg_target = sum_target / BigUint::from(m as u64);

        let mut next_target =
            avg_target * BigUint::from(avg_solvetime) / BigUint::from(t);

        // clamp to POW limit (easiest)
        if next_target > limit {
            next_target = limit.clone();
        }
        if next_target.is_zero() {
            next_target = limit.clone();
        }

        // canonical bits from canonical target bytes (mirrors pow.rs)
        let tb = biguint_to_32be(&next_target);
        let bits = target_bytes_to_bits(tb);

        // update "current" target for next iteration
        current_target = BigUint::from_bytes_be(&tb);

        println!(
            "h={} power={:.1} solve={} avg={} bits=0x{:08x}",
            height, hashpower_mult, solve_time, avg_solvetime, bits
        );
    }
}
