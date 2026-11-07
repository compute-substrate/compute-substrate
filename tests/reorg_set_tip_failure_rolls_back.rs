#![cfg(feature = "test-bypass")] // toy-chain fixture: needs the PoW/genesis bypass (cargo test --features test-bypass)
// A block whose apply succeeded must be undone by the reorg rollback whatever fails
// after it. The failure is injected through the test-bypass seam CSD_TEST_FAIL_SET_TIP
// (state/db.rs `set_tip`). Paired honest path: the same reorg on the same datadir with the seam
// unset reaches the fork tip with the state of a from-genesis replay.

use anyhow::Result;
use tempfile::TempDir;

use csd::chain::reorg::maybe_reorg_to;
use csd::state::db::{get_tip, k_bad_prefix, Stores};
use csd::state::fingerprint::fingerprint;
use csd::types::Hash32;

mod testutil_chain;
use testutil_chain::{
    build_base_chain, flush_all_state_trees, open_db, replay_canonical_from_tip,
    store_index_fork_block_to,
};

const START: u64 = 1_700_300_000;
// Fork coinbases pay another address, so a fork coinbase left behind is a UTXO the old chain lacks.
const FORK_MINER: [u8; 20] = [0xF0; 20];

fn fork_index_only(db: &Stores, base: &[Hash32], fork_height: u64, len: u64) -> Result<Vec<Hash32>> {
    let mut out = Vec::new();
    let mut prev = base[(fork_height - 1) as usize];
    for h in fork_height..fork_height + len {
        prev = store_index_fork_block_to(db, prev, h, START + h * 60 + 17, FORK_MINER)?;
        out.push(prev);
    }
    Ok(out)
}

/// Base chain h0..h11 applied, fork h8..h13 stored and indexed; `set_tip` fails for fork[fail_at].
fn reorg_with_set_tip_failure_at(fail_at: usize) -> Result<()> {
    let tmp = TempDir::new()?;
    let db = open_db(&tmp)?;
    let base = build_base_chain(&db, 12, START)?;
    let old_tip = *base.last().unwrap();
    let fork = fork_index_only(&db, &base, 8, 6)?;
    let new_tip = *fork.last().unwrap();
    flush_all_state_trees(&db)?;
    let before = fingerprint(&db)?;

    std::env::set_var("CSD_TEST_FAIL_SET_TIP", hex::encode(fork[fail_at]));
    let res = maybe_reorg_to(&db, &new_tip, None);
    std::env::remove_var("CSD_TEST_FAIL_SET_TIP");

    let err = res.expect_err("the injected set_tip failure must fail the reorg");
    assert!(
        format!("{err:#}").contains("CSD_TEST_FAIL_SET_TIP"),
        "the reorg failed for another reason: {err:#}"
    );
    assert_eq!(get_tip(&db)?, Some(old_tip), "tip must be back at the old tip");
    assert_eq!(
        fingerprint(&db)?,
        before,
        "the failed reorg left fork state behind (set_tip failed at fork[{fail_at}])"
    );
    assert_eq!(
        db.meta.scan_prefix(k_bad_prefix()).count(),
        0,
        "a set_tip failure is not a block fault"
    );

    maybe_reorg_to(&db, &new_tip, None)?;
    assert_eq!(get_tip(&db)?, Some(new_tip), "the retry must reach the fork tip");
    let tmp_replay = TempDir::new()?;
    let replay = open_db(&tmp_replay)?;
    replay_canonical_from_tip(&replay, &db, new_tip)?;
    assert_eq!(
        fingerprint(&db)?,
        fingerprint(&replay)?,
        "state after the retry must equal a from-genesis replay of the fork"
    );
    Ok(())
}

// One test function on purpose: the seam is a process-wide environment variable.
#[test]
fn set_tip_failure_after_apply_rolls_back_every_applied_block() -> Result<()> {
    // First apply-path block: nothing applied before it.
    reorg_with_set_tip_failure_at(0)?;
    // A later block: two blocks applied and committed before it.
    reorg_with_set_tip_failure_at(2)
}
