// A crash leaves no /utxos answer different from the scan's. A child process applies blocks and reorgs through the production
// path and runs the index reconciler, as a node does, until it is killed with SIGKILL at a random
// moment (a timed sleep; where it lands is not recorded, and SIGKILL keeps the kernel page cache,
// so this covers sled's unwritten buffers, not a power loss). The parent then recovers the datadir
// as a booting node does (`recover_if_needed`, which
// rebuilds the state from genesis) and requires every address's /utxos read to equal the scan's,
// whichever path answers, and, once the reconciler has caught up, the index to equal the scan for
// every address and to hold exactly the UTXO tree's outputs. Sled recovers each batch whole
// (`apply_batch` seals it), so after a crash the index covers exactly the blocks up to its marker,
// and a read uses it only while that marker is the tip. docs/behaviour.md "The address index".
#![cfg(feature = "test-bypass")] // toy-chain fixture: needs the PoW/genesis bypass (cargo test --features test-bypass)

mod testutil_addr_chain;

use std::io::{BufRead, BufReader};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

use anyhow::{Context, Result};
use tempfile::TempDir;

use csd::chain::reorg::recover_if_needed;
use csd::state::addr_index::{check_against_scan, read, read_via_scan};
use csd::state::db::{get_tip, Stores};
use csd::state::tx_scan::reconcile_tick;
use testutil_addr_chain::{answer, assert_index_equals_scan, reconcile, ChainGen};

const DIR_ENV: &str = "CSD_ADDR_CRASH_DIR";
const SEED_ENV: &str = "CSD_ADDR_CRASH_SEED";
const KEYS: usize = 8;
const RECEIVE_ONLY: usize = 4;
const CHILD: &str = "a_kill_at_any_moment_leaves_no_answer_different_from_the_scan";

/// The child's work: recover as a booting node does, then apply blocks and reorgs and run the
/// reconciler until killed (or for a minute).
fn write_until_killed(dir: &str, seed: &str) -> Result<()> {
    let db = Stores::open(dir)?;
    recover_if_needed(&db, None)?;
    let mut gen = ChainGen::new(seed.parse()?, KEYS, RECEIVE_ONLY);
    gen.relearn(&db)?;
    if get_tip(&db)?.is_none() {
        gen.extend(&db, false, false)?;
    }
    println!("READY");
    let end = Instant::now() + Duration::from_secs(60);
    while Instant::now() < end {
        let height = csd::chain::index::get_hidx(&db, &get_tip(&db)?.context("tip")?)?.context("hidx")?.height;
        match gen.roll(10) {
            0 if height > 8 => {
                let depth = 1 + gen.roll(6);
                gen.reorg(&db, depth)?;
            }
            1 => {
                let spend = gen.roll(2) == 0;
                gen.extend(&db, true, spend)?;
            }
            _ => {
                gen.extend(&db, false, false)?;
            }
        }
        for _ in 0..1 + gen.roll(2) {
            reconcile_tick(&db, 1 + gen.roll(3) as usize)?;
        }
    }
    Ok(())
}

#[test]
fn a_kill_at_any_moment_leaves_no_answer_different_from_the_scan() -> Result<()> {
    // The same test binary, started by this test with the two variables set, is the child.
    if let (Ok(dir), Ok(seed)) = (std::env::var(DIR_ENV), std::env::var(SEED_ENV)) {
        return write_until_killed(&dir, &seed);
    }
    let dir = TempDir::new()?;
    let path = dir.path().to_str().unwrap().to_string();
    let universe = ChainGen::new(0, KEYS, RECEIVE_ONLY).universe();
    let exe = std::env::current_exe()?;
    let (mut index_answered, mut scan_answered) = (0usize, 0usize);
    const ROUNDS: u64 = 16;

    for round in 0..ROUNDS {
        let mut child = Command::new(&exe)
            .args([CHILD, "--exact", "--nocapture", "--test-threads=1"])
            .env(DIR_ENV, &path)
            .env(SEED_ENV, round.to_string())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()?;
        let mut lines = BufReader::new(child.stdout.take().context("child stdout")?).lines();
        let ready = lines.by_ref().map_while(|l| l.ok()).any(|l| l == "READY");
        assert!(ready, "round {round}: the child did not reach its write loop");
        std::thread::sleep(Duration::from_millis(150 + (round * 137) % 900));
        child.kill()?;
        child.wait()?;
        drop(lines);

        let db = Stores::open(&path)?;
        recover_if_needed(&db, None).with_context(|| format!("round {round}: recovery"))?;
        for a in &universe {
            let r = read(&db, a, true)?;
            if r.via_index {
                index_answered += 1;
            } else {
                scan_answered += 1;
            }
            assert_eq!(answer(r), answer(read_via_scan(&db, a, true)?), "round {round}: 0x{}", hex::encode(a));
        }
        reconcile(&db, 64)?;
        assert_index_equals_scan(&db, &universe, &format!("round {round} after catch-up"))?;
        let check = check_against_scan(&db)?;
        assert!(check.mismatches.is_empty(), "round {round}: {:?}", check.mismatches);
        eprintln!(
            "[crash] round {round}: height {}, {} UTXO rows, index entries {}",
            check.height, check.utxo_rows, check.index_entries
        );
    }
    eprintln!(
        "[crash] {ROUNDS} kills; reads right after recovery: {index_answered} answered by the index, {scan_answered} by the scan"
    );
    Ok(())
}
