// `csd utxo-index-check --datadir <dir>`: the offline comparison of the address index with the scan,
// for a copy of a live datadir. It refuses what `csd fingerprint` refuses (a
// path that is not a datadir, one with no tip), refuses an index that is not current at the tip
// unless asked to build it, passes when every address reads the same both ways, fails, naming
// what differs, when the index lost an entry, and stops a build that cannot reach the tip.

use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

use anyhow::Result;
use tempfile::TempDir;

use csd::state::db::{get_tip, k_block, Stores};

fn run(args: &[&str]) -> (bool, String, String) {
    let out = Command::new(env!("CARGO_BIN_EXE_csd")).args(args).output().expect("run csd");
    (
        out.status.success(),
        String::from_utf8_lossy(&out.stdout).into_owned(),
        String::from_utf8_lossy(&out.stderr).into_owned(),
    )
}

/// `run`, but a csd still running after `limit` is killed and reported as None.
fn run_within(args: &[&str], limit: Duration) -> Option<(bool, String, String)> {
    let mut child = Command::new(env!("CARGO_BIN_EXE_csd"))
        .args(args)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("run csd");
    let deadline = Instant::now() + limit;
    while child.try_wait().expect("poll csd").is_none() {
        if Instant::now() > deadline {
            child.kill().ok();
            child.wait().ok();
            return None;
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    let out = child.wait_with_output().expect("csd output");
    Some((
        out.status.success(),
        String::from_utf8_lossy(&out.stdout).into_owned(),
        String::from_utf8_lossy(&out.stderr).into_owned(),
    ))
}

#[test]
fn utxo_index_check_refuses_what_is_not_a_synced_datadir() -> Result<()> {
    let tmp = TempDir::new()?;
    let missing = tmp.path().join("nope");
    let (ok, _, err) = run(&["utxo-index-check", "--datadir", missing.to_str().unwrap()]);
    assert!(!ok && err.contains("datadir does not exist"), "{err}");

    let empty = tmp.path().join("empty");
    drop(Stores::open(empty.to_str().unwrap())?);
    let (ok, _, err) = run(&["utxo-index-check", "--datadir", empty.to_str().unwrap()]);
    assert!(!ok && err.contains("no chain tip"), "{err}");
    Ok(())
}

#[test]
fn utxo_index_check_passes_a_current_index_and_names_a_lost_entry() -> Result<()> {
    let tmp = TempDir::new()?;
    let dir = tmp.path().to_str().unwrap();
    {
        let db = Stores::open(dir)?;
        csd::testutil::chain_paying(&db, 40, [0x7a; 20], 3)?;
        db.flush_all()?;
    }

    let (ok, _, err) = run(&["utxo-index-check", "--datadir", dir]);
    assert!(!ok && err.contains("not current at the tip") && err.contains("--build-index"), "{err}");

    let (ok, out, err) = run(&["utxo-index-check", "--datadir", dir, "--build-index"]);
    assert!(ok, "{out}{err}");
    assert!(out.contains("mismatches    0") && out.contains("utxo_rows     45") && out.contains("index_entries 45"), "{out}");

    // Without its build flag, a current index is compared as it is.
    let (ok, out, err) = run(&["utxo-index-check", "--datadir", dir]);
    assert!(ok && !out.contains("index built"), "{out}{err}");

    {
        let db = Stores::open(dir)?;
        let key = db.idx.scan_prefix(b"a/").keys().next().expect("an index entry")?;
        db.idx.remove(key)?;
        db.flush_all()?;
    }
    let (ok, out, err) = run(&["utxo-index-check", "--datadir", dir]);
    assert!(!ok && err.contains("disagrees with the scan"), "{err}");
    assert!(out.contains("index holds 44 entries") && out.contains("mismatch      0x"), "{out}");
    Ok(())
}

// Offline nothing can supply a canonical block's missing body, so a build that cannot index it must
// stop and name it rather than retry forever.
#[test]
fn utxo_index_check_build_stops_at_a_missing_canonical_body_and_names_it() -> Result<()> {
    let tmp = TempDir::new()?;
    let dir = tmp.path().to_str().unwrap();
    let (tip, body) = {
        let db = Stores::open(dir)?;
        csd::testutil::chain_paying(&db, 40, [0x7a; 20], 3)?;
        let tip = get_tip(&db)?.expect("a tip");
        let body = db.blocks.remove(k_block(&tip))?.expect("the tip's body");
        db.flush_all()?;
        (tip, body)
    };
    let build = ["utxo-index-check", "--datadir", dir, "--build-index"];
    let limit = Duration::from_secs(60);

    let (ok, out, err) = run_within(&build, limit)
        .unwrap_or_else(|| panic!("the build still ran after {limit:?} with the tip's body missing"));
    assert!(!ok && !out.contains("mismatches"), "{out}{err}");
    assert!(err.contains(&format!("height 1, block 0x{}", hex::encode(tip))), "{err}");

    // The same datadir with the body back builds to the tip and compares.
    {
        let db = Stores::open(dir)?;
        db.blocks.insert(k_block(&tip), body)?;
        db.flush_all()?;
    }
    let (ok, out, err) = run_within(&build, limit).expect("the build of an intact datadir ends");
    assert!(ok && out.contains("index built") && out.contains("mismatches    0"), "{out}{err}");
    Ok(())
}
