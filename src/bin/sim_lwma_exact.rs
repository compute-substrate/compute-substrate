use num_bigint::BigUint;
use num_traits::{One, Zero};

use compute_substrate::chain::pow::{
    bits_to_target_bytes, target_bytes_to_bits,
};
use compute_substrate::params::{
    INITIAL_BITS, LWMA_SOLVETIME_MAX_FACTOR, LWMA_WINDOW, POW_LIMIT_BITS, TARGET_BLOCK_SECS,
};

fn main() {
    let t = TARGET_BLOCK_SECS;
    let window = LWMA_WINDOW;

    println!("target={}s window={}", t, window);

    let mut times: Vec<u64> = vec![t; window];
    let mut targets: Vec<BigUint> =
        vec![BigUint::from_bytes_be(&bits_to_target_bytes(INITIAL_BITS)); window];

    let mut current_target = targets.last().unwrap().clone();

    for height in 0..400 {
        let hashpower_mult = if height < 120 {
            1.0
        } else if height < 240 {
            10.0
        } else {
            0.2
        };

        let expected_solve = (t as f64 / hashpower_mult) as u64;
        let solve_time = expected_solve.max(1);

        // simulate new timestamp
        let last_time = times.last().copied().unwrap_or(t);
        times.push(last_time + solve_time);
        if times.len() > window {
            times.remove(0);
        }

        targets.push(current_target.clone());
        if targets.len() > window {
            targets.remove(0);
        }

        // ---- LWMA ----
        let m = times.len();
        let max_solvetime = LWMA_SOLVETIME_MAX_FACTOR * t;

        let mut weighted_sum: u128 = 0;
        let mut denom: u128 = 0;

        for i in 1..m {
            let dt = times[i].saturating_sub(times[i - 1]);
            let st = dt.clamp(1, max_solvetime);
            let w = i as u128;
            weighted_sum += (st as u128) * w;
            denom += w;
        }

        let avg_solvetime = (weighted_sum / denom) as u64;

        let mut sum_target = BigUint::zero();
        for tg in &targets {
            sum_target += tg;
        }
        let avg_target = sum_target / BigUint::from(m as u64);

        let mut next_target =
            avg_target * BigUint::from(avg_solvetime) / BigUint::from(t);

        let limit = BigUint::from_bytes_be(&bits_to_target_bytes(POW_LIMIT_BITS));
        if next_target > limit {
            next_target = limit;
        }

        if next_target.is_zero() {
            next_target = limit.clone();
        }

        let tb = {
            let mut out = [0u8; 32];
            let bytes = next_target.to_bytes_be();
            let slice = if bytes.len() > 32 {
                &bytes[bytes.len() - 32..]
            } else {
                &bytes[..]
            };
            let start = 32 - slice.len();
            out[start..].copy_from_slice(slice);
            out
        };

        let bits = target_bytes_to_bits(tb);
        current_target = BigUint::from_bytes_be(&tb);

        println!(
            "h={} power={:.1} solve={} avg={} bits=0x{:08x}",
            height, hashpower_mult, solve_time, avg_solvetime, bits
        );
    }
}
