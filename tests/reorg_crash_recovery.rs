// tests/reorg_crash_recovery.rs
use anyhow::{Context, Result};
use rand::{rngs::StdRng, Rng, SeedableRng};
use tempfile::TempDir;

use csd::chain::index::{get_hidx, HeaderIndex};
use csd::chain::reorg::{maybe_reorg_to, recover_if_needed};
use csd::chain::reorg_journal::{journal_clear, journal_write, Phase, ReorgJournal};
use csd::state::fingerprint::{fingerprint, fmt_fp};
use csd::state::db::{get_tip, set_tip, Stores};
use csd::state::utxo::{undo_block, validate_and_apply_block};
use csd::state::app_state::epoch_of;

mod testutil_chain;
use testutil_chain::{
    assert_tip_eq, build_base_chain, build_fork_index_only, flush_all_state_trees, open_db,
    replay_canonical_from_tip,
};

fn must_hidx(db: &Stores, h: &[u8; 32]) -> Result<HeaderIndex> {
    get_hidx(db, h)?.ok_or_else(|| anyhow::anyhow!("missing hidx for 0x{}", hex::encode(h)))
}

fn find_ancestor(db: &Stores, mut a: HeaderIndex, mut b: HeaderIndex) -> Result<HeaderIndex> {
    while a.height > b.height {
        a = must_hidx(db, &a.parent)?;
    }
    while b.height > a.height {
        b = must_hidx(db, &b.parent)?;
    }
    while a.hash != b.hash {
        a = must_hidx(db, &a.parent)?;
        b = must_hidx(db, &b.parent)?;
    }
    Ok(a)
}

fn build_paths(db: &Stores, old_tip: [u8; 32], new_tip: [u8; 32]) -> Result<(HeaderIndex, Vec<[u8; 32]>, Vec<[u8; 32]>)> {
    let old_hi = must_hidx(db, &old_tip)?;
    let new_hi = must_hidx(db, &new_tip)?;
    let anc = find_ancestor(db, old_hi.clone(), new_hi.clone())?;

    // undo: old_tip -> ancestor (exclusive)
    let mut undo_path = vec![];
    let mut cur = old_hi;
    while cur.hash != anc.hash {
        undo_path.push(cur.hash);
        cur = must_hidx(db, &cur.parent)?;
    }

    // apply: ancestor -> new_tip (exclusive), in forward order
    let mut apply_path = vec![];
    let mut cur2 = new_hi;
    while cur2.hash != anc.hash {
        apply_path.push(cur2.hash);
        cur2 = must_hidx(db, &cur2.parent)?;
    }
    apply_path.reverse();

    Ok((anc, undo_path, apply_path))
}

fn apply_block_by_hash(db: &Stores, bh: &[u8; 32]) -> Result<()> {
    let Some(v) = db.blocks.get(csd::state::db::k_block(bh))? else {
        anyhow::bail!("missing block bytes for 0x{}", hex::encode(bh));
    };
    let blk: csd::types::Block = csd::codec::consensus_bincode().deserialize(&v)?;
    let hi = must_hidx(db, bh)?;
    validate_and_apply_block(db, &blk, epoch_of(hi.height), hi.height)?;
    set_tip(db, bh)?;
    Ok(())
}

#[test]
fn crash_fuzz_reorg_then_recover_matches_clean_replay() -> Result<()> {
    let mut rng = StdRng::seed_from_u64(9001);

    // Keep small but meaningful; run more locally when you want.
    let cases = 20usize;

    for case in 0..cases {
        let base_len: u64 = rng.gen_range(15..=70);
        let fork_height: u64 = rng.gen_range(1..base_len);
        let fork_len: u64 = rng.gen_range(5..=60);
        let start_time = 1_700_100_000u64 + (case as u64) * 50_000;

        // ---- Clean DB (reference) ----
        let tmp_clean = TempDir::new().context("tmp_clean")?;
        let db_clean = open_db(&tmp_clean).context("open db_clean")?;

        let a = build_base_chain(&db_clean, base_len, start_time).context("build base(clean)")?;
        let tip_a = *a.last().unwrap();

        let b_tail =
            build_fork_index_only(&db_clean, &a, fork_height, fork_len, start_time).context("build fork(clean)")?;
        let tip_b = *b_tail.last().unwrap();

        // Ensure we are on base tip before reorg.
        set_tip(&db_clean, &tip_a).context("set tip_a(clean)")?;
        assert_tip_eq(&db_clean, tip_a)?;

        maybe_reorg_to(&db_clean, &tip_b, None).context("maybe_reorg_to(clean)")?;
        let final_tip_clean = get_tip(&db_clean)?.unwrap();

        let fp_clean = fingerprint(&db_clean).context("fp_clean")?;

        // ---- Crash DB (simulate interrupted reorg) ----
        let tmp_crash = TempDir::new().context("tmp_crash")?;
        {
            let db_crash = open_db(&tmp_crash).context("open db_crash")?;

            // Build same base+fork deterministically by copying bytes from clean DB:
            // easiest is just replay the final clean canonical chain construction steps:
            // but we need fork headers/bytes too, so we replay base from scratch and then rebuild fork the same way.
            // (Everything deterministic due to expected_bits + fixed times)
            let a2 = build_base_chain(&db_crash, base_len, start_time).context("build base(crash)")?;
            let tip_a2 = *a2.last().unwrap();

            let b2_tail =
                build_fork_index_only(&db_crash, &a2, fork_height, fork_len, start_time).context("build fork(crash)")?;
            let tip_b2 = *b2_tail.last().unwrap();

            set_tip(&db_crash, &tip_a2).context("set tip_a(crash)")?;
            assert_tip_eq(&db_crash, tip_a2)?;

            // Compute paths on crash DB.
            let (anc, undo_path, apply_path) = build_paths(&db_crash, tip_a2, tip_b2).context("build_paths")?;

            // Choose crash point:
            // - randomly crash during undo or apply
            // - and at some cursor boundary (including 0)
            let crash_during_apply = rng.gen_bool(0.5);

            let crash_undo_steps = rng.gen_range(0..=undo_path.len());
            let crash_apply_steps = rng.gen_range(0..=apply_path.len());

            let (phase, cursor) = if crash_during_apply {
                (Phase::Apply, crash_apply_steps as u64)
            } else {
                (Phase::Undo, crash_undo_steps as u64)
            };

            println!(
                "case={case} base_len={base_len} fork_height={fork_height} fork_len={fork_len} phase={:?} cursor={cursor}",
                phase
            );

            // Start journal (like maybe_reorg_to would).
            let mut j = ReorgJournal {
                old_tip: tip_a2,
                new_tip: tip_b2,
                ancestor: anc.hash,
                phase: Phase::Undo,
                cursor: 0,
                undo_path: undo_path.clone(),
                apply_path: apply_path.clone(),
            };
            journal_write(&db_crash, &j).context("journal_write(pre)")?;

            // Execute partial steps, ensuring the journal cursor corresponds to durable state:
            // after each undo/apply + set_tip, flush trees, then update cursor+journal.
            // This matches the durability model in your reorg.rs.
            if phase == Phase::Undo {
                // perform `cursor` undo steps
                for i in 0..(cursor as usize) {
                    let bh = undo_path[i];
                    let hi = must_hidx(&db_crash, &bh)?;
                    undo_block(&db_crash, &bh).with_context(|| format!("undo_block {}", hex::encode(bh)))?;
                    set_tip(&db_crash, &hi.parent)?;
                    flush_all_state_trees(&db_crash).context("flush after undo")?;

                    j.phase = Phase::Undo;
                    j.cursor = (i as u64) + 1;
                    journal_write(&db_crash, &j).context("journal_write(progress undo)")?;
                }
                // leave journal in Undo phase at cursor; simulate crash now (drop db handle)
            } else {
                // First fully undo to ancestor (because Apply phase assumes we're at ancestor).
                for (i, bh) in undo_path.iter().enumerate() {
                    let hi = must_hidx(&db_crash, bh)?;
                    undo_block(&db_crash, bh)?;
                    set_tip(&db_crash, &hi.parent)?;
                    flush_all_state_trees(&db_crash).context("flush after undo-to-ancestor")?;

                    j.phase = Phase::Undo;
                    j.cursor = (i as u64) + 1;
                    journal_write(&db_crash, &j)?;
                }
                set_tip(&db_crash, &anc.hash)?;
                flush_all_state_trees(&db_crash)?;

                // Switch journal to Apply at cursor 0, like reorg.rs does.
                j.phase = Phase::Apply;
                j.cursor = 0;
                journal_write(&db_crash, &j).context("journal_write(at_ancestor)")?;

                // Apply `cursor` blocks.
                for i in 0..(cursor as usize) {
                    let bh = apply_path[i];
                    apply_block_by_hash(&db_crash, &bh).with_context(|| format!("apply {}", hex::encode(bh)))?;
                    flush_all_state_trees(&db_crash).context("flush after apply")?;

                    j.phase = Phase::Apply;
                    j.cursor = (i as u64) + 1;
                    journal_write(&db_crash, &j).context("journal_write(progress apply)")?;
                }

                // leave journal in Apply phase at cursor; simulate crash now
            }

            // Don’t clear journal — we want recovery to see it.
            drop(db_crash);
        }

        // Reopen and recover
        let db_reopen = Stores::open(tmp_crash.path().to_str().unwrap()).context("reopen db")?;
        recover_if_needed(&db_reopen, None).context("recover_if_needed")?;
        let fp_recovered = fingerprint(&db_reopen).context("fp_recovered")?;

        // Compare recovered with clean reference by replaying clean canonical into a fresh DB,
        // to make sure state is *exactly* reproducible.
        let tmp_replay = TempDir::new().context("tmp_replay")?;
        let db_replay = open_db(&tmp_replay).context("open db_replay")?;
        replay_canonical_from_tip(&db_replay, &db_clean, final_tip_clean).context("replay canonical")?;
        let fp_replayed = fingerprint(&db_replay).context("fp_replayed")?;

        if fp_recovered.tip != fp_replayed.tip
            || fp_recovered.utxo_root != fp_replayed.utxo_root
            || fp_recovered.utxo_meta_root != fp_replayed.utxo_meta_root
            || fp_recovered.app_root != fp_replayed.app_root
        {
            println!("case={case} mismatch");
            println!("[clean ] {}", fmt_fp(&fp_clean));
            println!("[replay] {}", fmt_fp(&fp_replayed));
            println!("[recov ] {}", fmt_fp(&fp_recovered));
            anyhow::bail!("crash-recovery fingerprint mismatch in case {case}");
        }

        // Cleanup
        let _ = journal_clear(&db_reopen);
        drop(db_reopen);
        drop(db_clean);
        drop(db_replay);
    }

    Ok(())
}
