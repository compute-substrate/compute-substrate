// tests/miner_future_parent_lwma.rs
//
// The miner's effect on difficulty when it builds at once on a parent
// stamped ahead of the wall clock (`csd::chain::mine::miner_block_time`). Its children carry
// stamps of parent.time + 60 until the wall clock catches up with the chain, so LWMA (45-block
// window, 120 s target, solvetimes clamped to [1, 1440] s) reads 60 s solvetimes for those blocks.
// The simulation drives the consensus retarget (`expected_bits_strict`) over a header index with
// deterministic expected solve times: a constant total hashrate that solves a baseline block in
// 120 s, 60 blocks at that pace, then one block stamped 7,000 s ahead, then 300 blocks. A share
// `ours` of the hashrate follows this miner's rule and the rest upstream's rule (wait until the
// wall clock reaches parent.time + 60, then stamp the clock): 1.0 is a network where every miner
// follows this rule, 0.11 one where 11% of the hashrate does and the rest runs upstream's miner,
// 0.0 a network of upstream miners only. It pins the trade: the share on this rule keeps producing
// during the stall (all at once: the first child within the margin's wait), the compressed stamps raise
// the difficulty by a bounded factor while the chain is ahead of the clock, and it returns to the
// baseline.

use anyhow::Result;

use csd::chain::index::{put_hidx, HeaderIndex};
use csd::chain::mine::{miner_block_time, MINER_CLOCK_SKEW_MARGIN_SECS};
use csd::chain::pow::{expected_bits_strict, work_from_bits};
use csd::chain::time::median_time_past;
use csd::params::{MIN_BLOCK_SPACING_SECS, TARGET_BLOCK_SECS};
use csd::state::db::Stores;

const BASE_BITS: u32 = 0x1c00_ffff;
const HISTORY: u64 = 60;
const AFTER: u64 = 300;
const ATTACK_LEAD_SECS: u64 = 7_000;

struct Run {
    /// Wall-clock seconds from the attack block until the first child is found.
    first_child_after: u64,
    /// Highest difficulty after the attack, as a multiple of the baseline.
    max_difficulty: f64,
    /// Blocks after the attack until a block is stamped at the wall clock again.
    catch_up_blocks: u64,
    /// Difficulty of the last block, as a multiple of the baseline.
    final_difficulty: f64,
    /// Wall-clock seconds for the 300 blocks after the attack.
    wall_for_after: u64,
}

fn hash(height: u64) -> [u8; 32] {
    let mut h = [0u8; 32];
    h[..8].copy_from_slice(&height.to_le_bytes());
    h[31] = 0xA5;
    h
}

fn run(ours: f64) -> Result<Run> {
    let tmp = tempfile::TempDir::new()?;
    let db = Stores::open(tmp.path().to_str().unwrap())?;
    let base_work = work_from_bits(BASE_BITS)? as f64;
    let difficulty = |bits: u32| -> f64 { work_from_bits(bits).unwrap() as f64 / base_work };

    let mut wall: u64 = 1_800_000_000;
    let mut parent = HeaderIndex { hash: hash(0), parent: [0u8; 32], height: 0, chainwork: 0, bits: BASE_BITS, time: wall };
    put_hidx(&db, &parent)?;
    let add = |db: &Stores, parent: &HeaderIndex, bits: u32, time: u64| -> Result<HeaderIndex> {
        let hi = HeaderIndex { hash: hash(parent.height + 1), parent: parent.hash, height: parent.height + 1, chainwork: 0, bits, time };
        put_hidx(db, &hi)?;
        Ok(hi)
    };
    for _ in 1..HISTORY {
        wall += TARGET_BLOCK_SECS;
        parent = add(&db, &parent, BASE_BITS, wall)?;
    }
    // The attack block, found at the usual pace and stamped 7,000 s ahead.
    let bits = expected_bits_strict(&db, parent.height + 1, Some(&parent))?;
    wall += (TARGET_BLOCK_SECS as f64 * difficulty(bits)) as u64;
    parent = add(&db, &parent, bits, wall + ATTACK_LEAD_SECS)?;
    let attack_wall = wall;

    let (mut first_child_after, mut max_difficulty, mut catch_up_blocks) = (0u64, 0f64, 0u64);
    for k in 1..=AFTER {
        let mtp = median_time_past(&db, &parent.hash)?;
        let min_ok = (parent.time + MIN_BLOCK_SPACING_SECS).max(mtp + 1);
        let bits = expected_bits_strict(&db, parent.height + 1, Some(&parent))?;
        let d = difficulty(bits);
        max_difficulty = max_difficulty.max(d);
        // Seconds for the whole hashrate to find this block.
        let solve = TARGET_BLOCK_SECS as f64 * d;
        let stamp = if wall >= min_ok {
            // Both rules stamp the wall clock and the whole hashrate mines.
            if catch_up_blocks == 0 {
                catch_up_blocks = k;
            }
            let at = wall;
            wall += solve.round() as u64;
            at
        } else {
            // The share on this rule starts at once (or after the margin's wait) and stamps min_ok; the
            // rest starts at min_ok and stamps the clock, which is min_ok then.
            let ours_start = match miner_block_time(wall, min_ok) {
                Ok(_) => wall,
                Err(wait) => wall + wait,
            };
            let ours_work = if ours > 0.0 { ours * (min_ok - ours_start.min(min_ok)) as f64 / solve } else { 0.0 };
            wall = if ours_work >= 1.0 {
                ours_start + (solve / ours).round() as u64
            } else {
                min_ok + ((1.0 - ours_work) * solve).round() as u64
            };
            min_ok
        };
        if k == 1 {
            first_child_after = wall - attack_wall;
        }
        parent = add(&db, &parent, bits, stamp)?;
    }
    Ok(Run {
        first_child_after,
        max_difficulty,
        catch_up_blocks,
        final_difficulty: difficulty(parent.bits),
        wall_for_after: wall - attack_wall,
    })
}

#[test]
fn building_at_once_on_a_future_parent_keeps_producing_and_bounds_the_difficulty_rise() -> Result<()> {
    let all = run(1.0)?;
    let mixed = run(0.11)?;
    let before = run(0.0)?;
    for (name, r) in [("all miners on this rule", &all), ("11% on this rule, 89% on upstream's", &mixed), ("all on upstream's rule", &before)] {
        println!(
            "[lwma] {name}: first child {} s after the attack block, stamps at the wall clock again from block {}, \
             max difficulty {:.2}x, final {:.2}x, {} s for {AFTER} blocks",
            r.first_child_after, r.catch_up_blocks, r.max_difficulty, r.final_difficulty, r.wall_for_after
        );
    }
    // Liveness: with every miner on this rule the first child comes within the margin's wait plus a
    // block; with an 11% share, well before the stall of upstream's rule ends.
    assert!(all.first_child_after <= MINER_CLOCK_SKEW_MARGIN_SECS + 2 * TARGET_BLOCK_SECS, "{}", all.first_child_after);
    assert!(before.first_child_after >= ATTACK_LEAD_SECS, "{}", before.first_child_after);
    assert!(mixed.first_child_after < before.first_child_after / 2, "{}", mixed.first_child_after);
    // The cost: compressed stamps raise the difficulty while the chain is ahead of the clock, by a
    // bounded factor, and it returns to the baseline once the stamps follow the clock again.
    for (name, r) in [("all", &all), ("mixed", &mixed)] {
        assert!(r.max_difficulty < 3.5, "{name}: max difficulty {:.2}x", r.max_difficulty);
        assert!((r.final_difficulty - 1.0).abs() < 0.1, "{name}: final difficulty {:.2}x", r.final_difficulty);
        assert!(r.catch_up_blocks > 0, "{name}: the stamps never caught up with the wall clock");
    }
    Ok(())
}
