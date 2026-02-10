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
    let window = LWMA_WINDOW.max(2);

    println!("target={}s window={}", t, window);

    // Proper timestamp history: 0,60,120,... (monotonic)
    let mut times: Vec<u64> = (0..window as u64).map(|i| i * t).collect();

    // Keep per-block target history (ring buffer) like the real chain.
    let init_tb = bits_to_target_bytes(INITIAL_BITS);
    let init_target = BigUint::from_bytes_be(&init_tb);
    let mut targets: Vec<BigUint> = vec![init_target.clone(); window];

    let limit_tb = bits_to_target_bytes(POW_LIMIT_BITS);
    let limit = BigUint::from_bytes_be(&limit_tb);

    for height in 0..400u64 {
        let hashpower_mult = if height < 120 {
            1.0
        } else if height < 240 {
            10.0
        } else {
            0.2
        };

        // Deterministic solve time for now (stochastic version comes next)
        let expected_solve = (t as f64 / hashpower_mult) as u64;
        let solve_time = expected_solve.max(1);

        // advance timestamp history
        let last_time = *times.last().unwrap();
        let new_time = last_time + solve_time;
        times.push(new_time);
        times.remove(0);

        // LWMA
        let m = times.len();
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

        // avg target from history window
        let mut sum_target = BigUint::zero();
        for tg in &targets {
            sum_target += tg;
        }
        let avg_target = sum_target / BigUint::from(m as u64);

        let mut next_target =
            avg_target * BigUint::from(avg_solvetime) / BigUint::from(t);

        // clamp easiest
        if next_target > limit {
            next_target = limit.clone();
        }
        if next_target.is_zero() {
            next_target = limit.clone();
        }

        // canonical bits exactly like chain
        let tb = biguint_to_32be(&next_target);
        let bits = target_bytes_to_bits(tb);

        // update per-block target history with what the chain would commit
        let committed_target = BigUint::from_bytes_be(&tb);
        targets.push(committed_target);
        targets.remove(0);

        println!(
            "h={} power={:.1} solve={} avg={} bits=0x{:08x}",
            height, hashpower_mult, solve_time, avg_solvetime, bits
        );
    }
}
