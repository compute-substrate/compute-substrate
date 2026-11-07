#![cfg(feature = "test-bypass")] // toy-chain fixture: needs the PoW/genesis bypass (cargo test --features test-bypass)
// Which reorg apply failures write a `bad:` mark, and that a rebuild drops the marks.
// A mark is written only when validate_and_apply_block rejects the block's content. A failure
// raised by this node's own storage (an unreadable stored coin inside validation, an unreadable
// stored body before it) leaves no mark, and the same chain is followed once the store is repaired.
// The recovery_* tests: which chain the journal-less recovery of every boot rebuilds when a
// stored chain fails validation.

use anyhow::Result;
use tempfile::TempDir;

use csd::chain::index::{get_hidx, header_hash, index_header};
use csd::chain::mine::coinbase;
use csd::chain::reorg::{maybe_reorg_to, recover_if_needed};
use csd::codec::consensus_bincode;
use csd::crypto::txid;
use csd::params::block_reward;
use csd::state::db::{get_tip, k_bad, k_bad_prefix, k_block, k_utxo, Stores};
use csd::state::fingerprint::fingerprint;
use csd::types::{Block, Hash32, OutPoint};

mod testutil_chain;
use testutil_chain::{
    build_base_chain, flush_all_state_trees, make_test_header, open_db, replay_canonical_from_tip,
    store_index_fork_block_to,
};

const START: u64 = 1_700_400_000;
const FORK_MINER: [u8; 20] = [0xF1; 20];

/// Base chain h0..h11, applied; returns the base hashes.
fn base(db: &Stores) -> Result<Vec<Hash32>> {
    build_base_chain(db, 12, START)
}

/// Valid fork h8..h13, stored and indexed only (heavier than the base tip h11).
fn valid_fork(db: &Stores, base: &[Hash32]) -> Result<Vec<Hash32>> {
    let mut out = Vec::new();
    let mut prev = base[7];
    for h in 8..14u64 {
        prev = store_index_fork_block_to(db, prev, h, START + h * 60 + 17, FORK_MINER)?;
        out.push(prev);
    }
    Ok(out)
}

/// Store and index a coinbase-only block paying `value` (no apply).
fn store_index_coinbase_block(db: &Stores, parent: Hash32, height: u64, value: u64) -> Result<Hash32> {
    let txs = vec![coinbase(FORK_MINER, value, height, None)];
    let header = make_test_header(db, parent, &txs, height)?;
    let blk = Block { header, txs };
    let bh = header_hash(&blk.header);
    db.blocks.insert(k_block(&bh), consensus_bincode().serialize(&blk)?)?;
    index_header(db, &blk.header, get_hidx(db, &parent)?.as_ref())?;
    Ok(bh)
}

fn bad_marks(db: &Stores) -> usize {
    db.meta.scan_prefix(k_bad_prefix()).count()
}

fn assert_follows(db: &Stores, tip: Hash32) -> Result<()> {
    assert_eq!(get_tip(db)?, Some(tip), "the node must be on the fork tip");
    let tmp = TempDir::new()?;
    let replay = open_db(&tmp)?;
    replay_canonical_from_tip(&replay, db, tip)?;
    assert_eq!(
        fingerprint(db)?,
        fingerprint(&replay)?,
        "state must equal a from-genesis replay of the fork"
    );
    Ok(())
}

// (a) A bincode error raised inside validate_and_apply_block by an unreadable stored coin: the
// apply reads the fork coinbase's outpoint before writing it.
#[test]
fn a_codec_error_from_the_local_utxo_tree_marks_nothing() -> Result<()> {
    let tmp = TempDir::new()?;
    let db = open_db(&tmp)?;
    let base = base(&db)?;
    let old_tip = *base.last().unwrap();
    let fork = valid_fork(&db, &base)?;
    let new_tip = *fork.last().unwrap();

    let blk0: Block = consensus_bincode().deserialize(&db.blocks.get(k_block(&fork[0]))?.unwrap())?;
    let cb_op = OutPoint { txid: txid(&blk0.txs[0]), vout: 0 };
    db.utxo.insert(k_utxo(&cb_op), &[0xAB, 0xCD, 0xEF][..])?;
    flush_all_state_trees(&db)?;
    let before = fingerprint(&db)?;

    let err = maybe_reorg_to(&db, &new_tip, None).expect_err("the unreadable stored coin must fail the apply");
    assert!(
        format!("{err:#}").contains("validate_and_apply_block"),
        "the failure must come from inside block validation: {err:#}"
    );
    assert_eq!(get_tip(&db)?, Some(old_tip));
    assert_eq!(fingerprint(&db)?, before, "the failed reorg left state behind");
    assert_eq!(bad_marks(&db), 0, "a local codec error must not mark the block or the tip bad");

    db.utxo.remove(k_utxo(&cb_op))?;
    maybe_reorg_to(&db, &new_tip, None)?;
    assert_follows(&db, new_tip)
}

// (a) A bincode error from an unreadable stored body, before validation runs.
#[test]
fn an_unreadable_stored_body_marks_nothing() -> Result<()> {
    let tmp = TempDir::new()?;
    let db = open_db(&tmp)?;
    let base = base(&db)?;
    let old_tip = *base.last().unwrap();
    let fork = valid_fork(&db, &base)?;
    let new_tip = *fork.last().unwrap();

    let body = db.blocks.get(k_block(&fork[1]))?.unwrap();
    db.blocks.insert(k_block(&fork[1]), &[0xFF; 7][..])?;
    flush_all_state_trees(&db)?;
    let before = fingerprint(&db)?;

    let err = maybe_reorg_to(&db, &new_tip, None).expect_err("the unreadable body must fail the apply");
    assert!(format!("{err:#}").contains("load_block"), "unexpected failure: {err:#}");
    assert_eq!(get_tip(&db)?, Some(old_tip));
    assert_eq!(fingerprint(&db)?, before, "the failed reorg left state behind");
    assert_eq!(bad_marks(&db), 0, "an unreadable local body must not mark the block or the tip bad");

    db.blocks.insert(k_block(&fork[1]), body)?;
    maybe_reorg_to(&db, &new_tip, None)?;
    assert_follows(&db, new_tip)
}

// (b) Paired honest path for the classifier: a consensus rejection still marks the rejected
// block and the tip, and the mark still stops the next attempt.
#[test]
fn a_consensus_rejection_marks_the_block_and_the_tip() -> Result<()> {
    let tmp = TempDir::new()?;
    let db = open_db(&tmp)?;
    let base = base(&db)?;
    let old_tip = *base.last().unwrap();

    let f8 = store_index_fork_block_to(&db, base[7], 8, START + 8 * 60 + 17, FORK_MINER)?;
    let f9_bad = store_index_coinbase_block(&db, f8, 9, block_reward(9) + 1)?;
    let mut tip = f9_bad;
    for h in 10..13u64 {
        tip = store_index_coinbase_block(&db, tip, h, block_reward(h))?;
    }
    flush_all_state_trees(&db)?;
    let before = fingerprint(&db)?;

    let err = maybe_reorg_to(&db, &tip, None).expect_err("an overpaying coinbase must be rejected");
    assert!(format!("{err:#}").contains("coinbase value wrong"), "unexpected failure: {err:#}");
    assert_eq!(get_tip(&db)?, Some(old_tip));
    assert_eq!(fingerprint(&db)?, before, "the failed reorg left state behind");
    assert_eq!(bad_marks(&db), 2, "exactly the rejected block and the tip are marked");
    assert!(db.meta.get(k_bad(&f9_bad))?.is_some(), "the rejected block must be marked");
    assert!(db.meta.get(k_bad(&tip))?.is_some(), "the tip must be marked");
    assert!(db.meta.get(k_bad(&f8))?.is_none(), "the valid block before it must not be marked");

    maybe_reorg_to(&db, &tip, None)?;
    assert_eq!(get_tip(&db)?, Some(old_tip), "the mark must stop the next attempt");
    Ok(())
}

// (c) A rebuild drops planted marks, and the chain they refused is followed afterwards. The
// first fork body is withheld during recovery so the rebuild targets the old tip.
#[test]
fn a_rebuild_clears_bad_marks_and_the_refused_chain_is_followed() -> Result<()> {
    let tmp = TempDir::new()?;
    let db = open_db(&tmp)?;
    let base = base(&db)?;
    let old_tip = *base.last().unwrap();
    let fork = valid_fork(&db, &base)?;
    let new_tip = *fork.last().unwrap();

    let body0 = db.blocks.remove(k_block(&fork[0]))?.unwrap();
    db.meta.insert(k_bad(&fork[2]), &b"1"[..])?;
    db.meta.insert(k_bad(&new_tip), &b"1"[..])?;
    flush_all_state_trees(&db)?;
    assert_eq!(bad_marks(&db), 2);

    recover_if_needed(&db, None)?;
    assert_eq!(get_tip(&db)?, Some(old_tip), "recovery must rebuild to the old tip");
    assert_eq!(bad_marks(&db), 0, "the rebuild must drop every bad mark");

    db.blocks.insert(k_block(&fork[0]), body0)?;
    maybe_reorg_to(&db, &new_tip, None)?;
    assert_follows(&db, new_tip)
}

// Journal-less recovery runs on every boot. When the heaviest stored chain holds a block that fails
// validation, it must rebuild the heaviest chain whose blocks validate. Here: base to h11, a valid
// fork to h13, and a heavier stored fork to h14 whose h9 overpays its coinbase.
#[test]
fn recovery_rebuilds_the_heaviest_chain_that_validates() -> Result<()> {
    let tmp = TempDir::new()?;
    let db = open_db(&tmp)?;
    let base = base(&db)?;
    let valid_tip = *valid_fork(&db, &base)?.last().unwrap();

    let bad_tip = invalid_fork(&db, &base)?;
    assert!(
        get_hidx(&db, &bad_tip)?.unwrap().chainwork > get_hidx(&db, &valid_tip)?.unwrap().chainwork,
        "fixture: the invalid fork must be the heaviest stored chain"
    );
    flush_all_state_trees(&db)?;

    let boots: Vec<_> = (0..2)
        .map(|_| recover_if_needed(&db, None).map_err(|e| format!("{e:#}")))
        .collect();
    assert!(boots.iter().all(|b| b.is_ok()), "a boot failed recovery: {boots:?}");
    assert_follows(&db, valid_tip)
}

/// A fork to h14 from base[7] whose h9 overpays its coinbase; returns its tip.
fn invalid_fork(db: &Stores, base: &[Hash32]) -> Result<Hash32> {
    let b8 = store_index_fork_block_to(db, base[7], 8, START + 8 * 60 + 17, [0xB2; 20])?;
    let mut tip = store_index_coinbase_block(db, b8, 9, block_reward(9) + 1)?;
    for h in 10..15u64 {
        tip = store_index_coinbase_block(db, tip, h, block_reward(h))?;
    }
    Ok(tip)
}

// The pre-recovery tip stays a candidate after a rejection: the heavier valid fork lacks a body,
// so the old tip (h11) is the heaviest chain that validates, not the rejected chain's prefix (h8).
#[test]
fn recovery_keeps_the_pre_recovery_tip_as_a_candidate() -> Result<()> {
    let tmp = TempDir::new()?;
    let db = open_db(&tmp)?;
    let base = base(&db)?;
    let old_tip = *base.last().unwrap();
    let valid = valid_fork(&db, &base)?;
    db.blocks.remove(k_block(&valid[4]))?;
    invalid_fork(&db, &base)?;
    flush_all_state_trees(&db)?;

    recover_if_needed(&db, None)?;
    assert_follows(&db, old_tip)
}

// The blocks-only selection, used when no header index entry is usable, skips the rejected chain too.
#[test]
fn recovery_without_a_header_index_skips_the_invalid_chain() -> Result<()> {
    let tmp = TempDir::new()?;
    let db = open_db(&tmp)?;
    let base = base(&db)?;
    let old_tip = *base.last().unwrap();
    invalid_fork(&db, &base)?;
    db.hdr.clear()?;
    flush_all_state_trees(&db)?;

    recover_if_needed(&db, None)?;
    assert_eq!(get_tip(&db)?, Some(old_tip));
    let tmp_ref = TempDir::new()?;
    let reference = open_db(&tmp_ref)?;
    build_base_chain(&reference, 12, START)?;
    assert_eq!(fingerprint(&db)?, fingerprint(&reference)?, "state must equal the base chain's");
    Ok(())
}

// The node's own chain can be the rejected one: base[9]'s stored body no longer matches its header
// (a local corruption that still decodes). Recovery rebuilds the heaviest chain below it.
#[test]
fn recovery_skips_the_pre_recovery_tip_when_its_chain_fails_validation() -> Result<()> {
    let tmp = TempDir::new()?;
    let db = open_db(&tmp)?;
    let base = base(&db)?;
    let mut blk: Block = consensus_bincode().deserialize(&db.blocks.get(k_block(&base[9]))?.unwrap())?;
    blk.txs[0].outputs[0].value += 1;
    db.blocks.insert(k_block(&base[9]), consensus_bincode().serialize(&blk)?)?;
    flush_all_state_trees(&db)?;

    recover_if_needed(&db, None)?;
    assert_follows(&db, base[8])
}

// Paired honest path: when the heaviest stored chain validates, recovery rebuilds to it.
#[test]
fn recovery_rebuilds_the_heaviest_stored_chain_when_it_validates() -> Result<()> {
    let tmp = TempDir::new()?;
    let db = open_db(&tmp)?;
    let base = base(&db)?;
    let fork_tip = *valid_fork(&db, &base)?.last().unwrap();
    flush_all_state_trees(&db)?;

    recover_if_needed(&db, None)?;
    assert_follows(&db, fork_tip)
}
