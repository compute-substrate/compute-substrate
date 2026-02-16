// tests/reorg_randomized.rs
use anyhow::{Context, Result};
use rand::{rngs::StdRng, Rng, SeedableRng};
use tempfile::TempDir;

use csd::chain::reorg::maybe_reorg_to;
use csd::state::fingerprint::{fingerprint, fmt_fp};
use csd::state::db::set_tip;

mod testutil_chain;
use testutil_chain::*;

#[test]
fn reorg_equivalence_randomized_many_shapes() -> Result<()> {
    set_test_env();

    let mut rng = StdRng::seed_from_u64(0xC0FFEE);

    // Keep this modest; make it large in CI/nightly.
    let cases = 50u64;

    for case in 0..cases {
        let tmp1 = TempDir::new().context("tmp1")?;
        let db1 = open_db(&tmp1).context("open db1")?;

        // Random-ish parameters
        let base_len = rng.gen_range(10..60) as u64;
        let fork_height = rng.gen_range(2..(base_len - 2)) as u64;
        let fork_len = rng.gen_range(3..60) as u64;

        // Use constant bits; expected_bits should accept under bypass mode.
        let bits = csd::params::INITIAL_BITS;

        let a = build_chain(&db1, base_len, 1_700_000_000 + case * 10_000, bits)
            .with_context(|| format!("build base case={case}"))?;
        let tip_a = *a.last().unwrap();

        let b_tail = build_fork(&db1, &a, fork_height, fork_len, 1_700_000_000 + case * 10_000, bits)
            .with_context(|| format!("build fork case={case}"))?;
        let tip_b = *b_tail.last().unwrap();

        // Force canonical tip back to A, then reorg to B
        set_tip(&db1, &tip_a).context("force tip A")?;
        maybe_reorg_to(&db1, &tip_b, None).context("reorg to B")?;

        let fp1 = fingerprint(&db1).context("fp1")?;

        // Canonical chain = A[0..fork_height) + B_tail
        let mut canon = Vec::new();
        canon.extend_from_slice(&a[0..fork_height as usize]);
        canon.extend_from_slice(&b_tail);

        let tmp2 = TempDir::new().context("tmp2")?;
        let db2 = open_db(&tmp2).context("open db2")?;
        replay_chain(&db2, &db1, &canon).context("replay canon")?;

        let fp2 = fingerprint(&db2).context("fp2")?;

        if fp1 != fp2 {
            eprintln!("case={case} base_len={base_len} fork_height={fork_height} fork_len={fork_len}");
            eprintln!("[db1] {}", fmt_fp(&fp1));
            eprintln!("[db2] {}", fmt_fp(&fp2));
            anyhow::bail!("fingerprint mismatch in randomized case {case}");
        }
    }

    Ok(())
}
