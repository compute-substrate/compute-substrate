// src/bin/reorg_crash_driver.rs
use anyhow::{Context, Result};
use std::env;

use csd::chain::reorg::{maybe_reorg_to, recover_if_needed};
use csd::state::db::{get_tip, set_tip, Stores};
use csd::testutil; // <-- IMPORTANT: bring the module into scope

fn main() -> Result<()> {
    testutil::set_test_env();

    let db_path = env::var("CSD_DRIVER_DB").unwrap_or_else(|_| "/tmp/csd_reorg_driver_db".into());
    let base_len: u64 = env::var("CSD_DRIVER_BASE_LEN")
        .unwrap_or_else(|_| "60".into())
        .parse()
        .context("parse CSD_DRIVER_BASE_LEN")?;
    let fork_height: u64 = env::var("CSD_DRIVER_FORK_HEIGHT")
        .unwrap_or_else(|_| "20".into())
        .parse()
        .context("parse CSD_DRIVER_FORK_HEIGHT")?;
    let fork_len: u64 = env::var("CSD_DRIVER_FORK_LEN")
        .unwrap_or_else(|_| "50".into())
        .parse()
        .context("parse CSD_DRIVER_FORK_LEN")?;
    let bits: u32 = env::var("CSD_DRIVER_BITS")
        .unwrap_or_else(|_| format!("{}", csd::params::INITIAL_BITS))
        .parse()
        .context("parse CSD_DRIVER_BITS")?;

    let db = Stores::open(&db_path).context("Stores::open")?;

    // Complete interrupted reorg if present
    recover_if_needed(&db, None).context("recover_if_needed")?;

    // Build base + fork
    let a = testutil::build_chain(&db, base_len, 1_700_000_000, bits).context("build base")?;
    let tip_a = *a.last().unwrap();

    let b_tail =
        testutil::build_fork(&db, &a, fork_height, fork_len, 1_700_000_000, bits).context("fork")?;
    let tip_b = *b_tail.last().unwrap();

    // Force tip back to A then reorg to B
    set_tip(&db, &tip_a).context("set_tip(A)")?;
    maybe_reorg_to(&db, &tip_b, None).context("maybe_reorg_to(B)")?;

    let tip = get_tip(&db)?.unwrap_or([0u8; 32]);
    println!("[driver] done. tip=0x{}", hex::encode(tip));
    Ok(())
}
