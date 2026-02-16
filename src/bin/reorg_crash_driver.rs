// src/bin/reorg_crash_driver.rs
use anyhow::{Context, Result};
use std::env;

use csd::chain::reorg::{maybe_reorg_to, recover_if_needed};
use csd::state::db::set_tip;
use csd::state::fingerprint::fingerprint;

mod testutil {
    include!(concat!(env!("CARGO_MANIFEST_DIR"), "/tests/testutil_chain.rs"));
}

fn main() -> Result<()> {
    // Args:
    // 1) datadir
    // 2) base_len
    // 3) fork_height
    // 4) fork_len
    // 5) mode: "reorg" or "recover"
    // Output: prints fingerprint tip/roots in json-ish lines.

    let datadir = env::args().nth(1).context("datadir")?;
    let base_len: u64 = env::args().nth(2).context("base_len")?.parse()?;
    let fork_height: u64 = env::args().nth(3).context("fork_height")?.parse()?;
    let fork_len: u64 = env::args().nth(4).context("fork_len")?.parse()?;
    let mode = env::args().nth(5).context("mode")?;

    testutil::set_test_env();

    let db = csd::state::db::Stores::open(&datadir).context("Stores::open")?;

    // If DB empty, build the scenario.
    if csd::state::db::get_tip(&db)?.is_none() {
        let bits = csd::params::INITIAL_BITS;
        let a = testutil::build_chain(&db, base_len, 1_700_000_000, bits).context("build base")?;
        let tip_a = *a.last().unwrap();
        let b_tail = testutil::build_fork(&db, &a, fork_height, fork_len, 1_700_000_000, bits)
            .context("build fork")?;
        let tip_b = *b_tail.last().unwrap();

        // Store these in env for later, but simplest: just set tip to A, then reorg to B (reorg mode)
        set_tip(&db, &tip_a).context("set tip A")?;
        env::set_var("CSD_DRIVER_TIP_B", hex::encode(tip_b));
    }

    match mode.as_str() {
        "reorg" => {
            let tip_b_hex = env::var("CSD_DRIVER_TIP_B").context("missing CSD_DRIVER_TIP_B")?;
            let mut tip_b = [0u8; 32];
            let b = hex::decode(tip_b_hex)?;
            tip_b.copy_from_slice(&b);

            maybe_reorg_to(&db, &tip_b, None).context("maybe_reorg_to")?;
        }
        "recover" => {
            recover_if_needed(&db, None).context("recover_if_needed")?;
        }
        _ => anyhow::bail!("mode must be reorg|recover"),
    }

    let fp = fingerprint(&db).context("fingerprint")?;
    println!(
        "{{\"tip\":\"0x{}\",\"utxo\":\"0x{}\",\"utxo_meta\":\"0x{}\",\"app\":\"0x{}\"}}",
        hex::encode(fp.tip),
        hex::encode(fp.utxo_root),
        hex::encode(fp.utxo_meta_root),
        hex::encode(fp.app_root)
    );

    Ok(())
}
