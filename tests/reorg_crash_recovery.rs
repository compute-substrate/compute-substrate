// tests/reorg_crash_recovery.rs
use anyhow::{Context, Result};
use std::process::Command;
use tempfile::TempDir;

mod testutil_chain;
use testutil_chain::*;

fn run_driver(datadir: &str, crash_at: Option<&str>, mode: &str) -> Result<(bool, String)> {
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_reorg_crash_driver"));
    cmd.arg(datadir)
        .arg("40") // base_len
        .arg("20") // fork_height
        .arg("35") // fork_len
        .arg(mode);

    // test env
    cmd.env("CSD_TEST_BYPASS_POW", "1");
    cmd.env("CSD_TEST_BYPASS_GENESIS", "1");

    // failpoint (optional)
    if let Some(fp) = crash_at {
        cmd.env("CSD_CRASH_AT", fp);
    }

    let out = cmd.output().context("driver output")?;
    let ok = out.status.success();
    let stdout = String::from_utf8_lossy(&out.stdout).to_string();
    let stderr = String::from_utf8_lossy(&out.stderr).to_string();
    Ok((ok, format!("{stdout}{stderr}")))
}

#[test]
fn crash_fuzz_reorg_then_recover_matches_clean_replay() -> Result<()> {
    set_test_env();

    // Persistent dir across subprocesses
    let tmp = TempDir::new().context("tmp")?;
    let datadir = tmp.path().to_str().unwrap().to_string();

    // A small curated set of failpoints that cover boundaries.
    // You can expand this list once everything is stable.
    let points = vec![
        "journal_write:pre",
        "journal_write:pre_flush",
        "journal_write:post_flush",
        "reorg:after_journal_start",
        "undo:0:pre",
        "undo:0:post_tip_pre_flush",
        "undo:0:post_flush_pre_journal",
        "undo:0:post_journal",
        "reorg:at_ancestor_post_flush",
        "reorg:after_apply_start",
        "apply:0:pre",
        "apply:0:post_tip_pre_flush",
        "apply:0:post_flush_pre_journal",
        "apply:0:post_journal",
        "reorg:pre_journal_clear",
        "journal_clear:pre",
        "journal_clear:pre_flush",
        "journal_clear:post_flush",
    ];

    // Baseline: run without crash; record final fingerprint line.
    let (ok0, out0) = run_driver(&datadir, None, "reorg").context("baseline reorg")?;
    anyhow::ensure!(ok0, "baseline reorg failed: {out0}");
    let baseline = out0
        .lines()
        .rev()
        .find(|l| l.trim_start().starts_with("{\"tip\""))
        .context("baseline fingerprint missing")?
        .to_string();

    for p in points {
        // New fresh dir per point so cases are independent
        let tmp = TempDir::new().context("tmp")?;
        let datadir = tmp.path().to_str().unwrap().to_string();

        // Run reorg driver with crashpoint -> expect failure (abort)
        let (_ok, _out) = run_driver(&datadir, Some(p), "reorg")
            .with_context(|| format!("crash run at {p}"))?;

        // Now run recovery in a fresh process (must succeed)
        let (ok2, out2) = run_driver(&datadir, None, "recover")
            .with_context(|| format!("recover after crash {p}"))?;
        anyhow::ensure!(ok2, "recover failed after crash {p}: {out2}");

        // Now run reorg again without crash and ensure we land on baseline
        let (ok3, out3) = run_driver(&datadir, None, "reorg")
            .with_context(|| format!("final reorg after recover {p}"))?;
        anyhow::ensure!(ok3, "final reorg failed after crash {p}: {out3}");

        let final_line = out3
            .lines()
            .rev()
            .find(|l| l.trim_start().starts_with("{\"tip\""))
            .context("final fingerprint missing")?
            .to_string();

        anyhow::ensure!(
            final_line == baseline,
            "fingerprint mismatch after crash {p}\nwant={baseline}\ngot ={final_line}"
        );
    }

    Ok(())
}
