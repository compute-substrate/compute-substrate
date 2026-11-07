#![cfg(feature = "test-bypass")] // toy-chain fixture: needs the PoW/genesis bypass (cargo test --features test-bypass)
// A block hash does not commit to non-coinbase script_sig (crypto::txid strips it), so a peer can
// store a body with altered signatures under an honest header: the merkle bind accepts it. Such a
// body must cost the peer that body only: it is dropped, the hash is not marked, and the honest
// body is accepted when it arrives. A block that breaks a committed rule is still marked.

use anyhow::Result;
use tempfile::TempDir;

use csd::chain::index::{get_hidx, header_hash, index_header};
use csd::chain::mine::coinbase;
use csd::chain::reorg::{maybe_reorg_to, recover_if_needed};
use csd::chain::reorg_journal::{journal_read, journal_write, Phase, ReorgJournal};
use csd::codec::consensus_bincode;
use csd::crypto::{sign_tx_compact_secp256k1, txid};
use csd::net::node::{outbound_block_refusal, store_block_bytes_checked, BlockStoreOutcome, NetConfig, TestPeerMode};
use csd::params::block_reward;
use csd::state::db::{get_tip, k_bad, k_bad_prefix, k_block, set_tip, Stores, DROPPED_BLOCK_BODIES};
use csd::state::fingerprint::fingerprint;
use csd::state::app_state::epoch_of;
use csd::state::utxo::{undo_block, validate_and_apply_block, validate_block_merkle};
use csd::types::{AppPayload, Block, Hash32, OutPoint, Transaction, TxIn, TxOut};

mod testutil_chain;
use testutil_chain::{
    build_base_chain, flush_all_state_trees, make_test_header, open_db, replay_canonical_from_tip,
    store_index_fork_block_to, test_signer_addr, test_signer_sk,
};

use std::sync::atomic::Ordering;

const START: u64 = 1_700_500_000;
const FORK_MINER: [u8; 20] = [0xF2; 20];

/// A spend of `prevout` (a signer-owned coinbase) to the signer, signed after `outputs` are set.
fn signed_spend(prevout: OutPoint, outputs: Vec<TxOut>) -> Transaction {
    let mut tx = Transaction {
        version: 1,
        inputs: vec![TxIn { prevout, script_sig: vec![] }],
        outputs,
        locktime: 0,
        app: AppPayload::None,
    };
    let (sig64, pub33) = sign_tx_compact_secp256k1(&tx, test_signer_sk());
    let mut ss = Vec::with_capacity(99);
    ss.push(64u8);
    ss.extend_from_slice(&sig64);
    ss.push(33u8);
    ss.extend_from_slice(&pub33);
    tx.inputs[0].script_sig = ss;
    tx
}

/// Fork block h8 off base[7]: coinbase plus a signed spend of base[1]'s coinbase paying `extra`
/// more than it spends (0 is valid).
fn fork_block_with_spend(db: &Stores, base: &[Hash32], extra: u64) -> Result<Block> {
    let blk1: Block = consensus_bincode().deserialize(&db.blocks.get(k_block(&base[1]))?.unwrap())?;
    let cb1 = &blk1.txs[0];
    let out = TxOut { value: cb1.outputs[0].value + extra, script_pubkey: test_signer_addr() };
    let spend = signed_spend(OutPoint { txid: txid(cb1), vout: 0 }, vec![out]);
    let txs = vec![coinbase(FORK_MINER, block_reward(8), 8, None), spend];
    let header = make_test_header(db, base[7], &txs, 8)?;
    Ok(Block { header, txs })
}

/// The same block with one signature byte flipped: same txids, so the same header binds it.
fn substituted(honest: &Block) -> Block {
    let mut b = honest.clone();
    b.txs[1].inputs[0].script_sig[5] ^= 0x01;
    b
}

/// Stores `blk` through the network store path, indexes its header and builds a coinbase-only
/// fork h9..h13 on it; returns (its hash, the fork tip).
fn store_with_heavier_fork(db: &Stores, blk: &Block) -> Result<(Hash32, Hash32)> {
    let h8 = header_hash(&blk.header);
    assert!(matches!(store_block_bytes_checked(db, &h8, blk)?, BlockStoreOutcome::Stored));
    index_header(db, &blk.header, get_hidx(db, &blk.header.prev)?.as_ref())?;
    let mut tip = h8;
    for h in 9..14u64 {
        tip = store_index_fork_block_to(db, tip, h, START + h * 60 + 17, FORK_MINER)?;
    }
    flush_all_state_trees(db)?;
    Ok((h8, tip))
}

fn bad_marks(db: &Stores) -> usize {
    db.meta.scan_prefix(k_bad_prefix()).count()
}

fn assert_follows(db: &Stores, tip: Hash32) -> Result<()> {
    assert_eq!(get_tip(db)?, Some(tip), "the node is not on the expected tip");
    let tmp = TempDir::new()?;
    let replay = open_db(&tmp)?;
    replay_canonical_from_tip(&replay, db, tip)?;
    assert_eq!(fingerprint(db)?, fingerprint(&replay)?, "state must equal a from-genesis replay");
    Ok(())
}

#[test]
fn a_substituted_signature_drops_the_body_and_marks_nothing() -> Result<()> {
    let tmp = TempDir::new()?;
    let db = open_db(&tmp)?;
    let base = build_base_chain(&db, 12, START)?;
    let old_tip = *base.last().unwrap();
    let honest = fork_block_with_spend(&db, &base, 0)?;
    let poisoned = substituted(&honest);
    assert_eq!(txid(&honest.txs[1]), txid(&poisoned.txs[1]), "fixture: txid ignores script_sig");
    assert!(validate_block_merkle(&poisoned).is_ok(), "fixture: the substituted body binds");
    let (h8, tip) = store_with_heavier_fork(&db, &poisoned)?;
    let dropped_before = DROPPED_BLOCK_BODIES.load(Ordering::Relaxed);

    let err = maybe_reorg_to(&db, &tip, None).expect_err("the altered signature must fail the apply");
    assert_eq!(get_tip(&db)?, Some(old_tip));
    assert_eq!(bad_marks(&db), 0, "nothing honest may be marked for a substituted body");
    assert!(db.blocks.get(k_block(&h8))?.is_none(), "the substituted body must be dropped");
    assert!(format!("{err:#}").contains("was dropped"), "unexpected failure: {err:#}");
    assert!(DROPPED_BLOCK_BODIES.load(Ordering::Relaxed) > dropped_before, "the drop is counted");

    // The honest body, as a later fetch delivers it, is stored and the chain is followed.
    assert!(matches!(store_block_bytes_checked(&db, &h8, &honest)?, BlockStoreOutcome::Stored));
    maybe_reorg_to(&db, &tip, None)?;
    assert_follows(&db, tip)
}

/// The same block with the spend re-signed by another key: a valid signature by that key over the
/// same sighash, with its pubkey. The txids, and so the header, still bind it; the pubkey does not
/// own the spent coin.
fn resigned_by_another_key(honest: &Block) -> Block {
    const OTHER_SK: [u8; 32] = [0x5A; 32];
    let mut b = honest.clone();
    let (sig64, pub33) = sign_tx_compact_secp256k1(&b.txs[1], OTHER_SK);
    let mut ss = Vec::with_capacity(99);
    ss.push(64u8);
    ss.extend_from_slice(&sig64);
    ss.push(33u8);
    ss.extend_from_slice(&pub33);
    b.txs[1].inputs[0].script_sig = ss;
    b
}

// A peer re-signs a spend with its own key over the same sighash. Every signature
// verifies, and the spend fails only the owner check ("pubkey hash mismatch"), on bytes the header
// does not fix; `first_body_fault`'s pubkey arm blames the body, so it is dropped and nothing honest
// is marked. The honest body is then followed.
#[test]
fn a_spend_resigned_by_another_key_drops_the_body_and_marks_nothing() -> Result<()> {
    let tmp = TempDir::new()?;
    let db = open_db(&tmp)?;
    let base = build_base_chain(&db, 12, START)?;
    let old_tip = *base.last().unwrap();
    let honest = fork_block_with_spend(&db, &base, 0)?;
    let resigned = resigned_by_another_key(&honest);
    assert_eq!(txid(&honest.txs[1]), txid(&resigned.txs[1]), "fixture: txid ignores script_sig");
    assert_ne!(honest.txs[1].inputs[0].script_sig, resigned.txs[1].inputs[0].script_sig);
    let (sig64, pub33) = csd::state::utxo::parse_scriptsig(&resigned.txs[1].inputs[0].script_sig)?;
    csd::crypto::verify_sig(&resigned.txs[1], &sig64, &pub33)?;
    let (h8, tip) = store_with_heavier_fork(&db, &resigned)?;

    let err = maybe_reorg_to(&db, &tip, None).expect_err("a spend by a key that does not own the coin must fail");
    assert_eq!(get_tip(&db)?, Some(old_tip));
    assert_eq!(bad_marks(&db), 0, "nothing honest may be marked for a re-signed body");
    assert!(db.blocks.get(k_block(&h8))?.is_none(), "the re-signed body must be dropped");
    assert!(format!("{err:#}").contains("was dropped"), "unexpected failure: {err:#}");

    assert!(matches!(store_block_bytes_checked(&db, &h8, &honest)?, BlockStoreOutcome::Stored));
    maybe_reorg_to(&db, &tip, None)?;
    assert_follows(&db, tip)
}

// Paired honest path for the blame: valid signatures, but the spend pays out more than it spends
// (a committed rule), so every body with this hash fails and the hash and tip are marked.
#[test]
fn a_committed_rule_broken_under_valid_signatures_still_marks_the_hash() -> Result<()> {
    let tmp = TempDir::new()?;
    let db = open_db(&tmp)?;
    let base = build_base_chain(&db, 12, START)?;
    let old_tip = *base.last().unwrap();
    let (h8, tip) = store_with_heavier_fork(&db, &fork_block_with_spend(&db, &base, 1)?)?;

    let err = maybe_reorg_to(&db, &tip, None).expect_err("an overspending tx must be rejected");
    assert!(format!("{err:#}").contains("outputs exceed inputs"), "unexpected failure: {err:#}");
    assert_eq!(get_tip(&db)?, Some(old_tip));
    assert_eq!(bad_marks(&db), 2);
    assert!(db.meta.get(k_bad(&h8))?.is_some() && db.meta.get(k_bad(&tip))?.is_some());
    assert!(db.blocks.get(k_block(&h8))?.is_some(), "a body whose signatures hold is kept");
    Ok(())
}

// The boot rebuild meets the same body: it is dropped, nothing is marked, and recovery rebuilds
// the old chain.
#[test]
fn recovery_drops_a_substituted_body_and_rebuilds_the_old_chain() -> Result<()> {
    let tmp = TempDir::new()?;
    let db = open_db(&tmp)?;
    let base = build_base_chain(&db, 12, START)?;
    let old_tip = *base.last().unwrap();
    let honest = fork_block_with_spend(&db, &base, 0)?;
    let (h8, _tip) = store_with_heavier_fork(&db, &substituted(&honest))?;

    recover_if_needed(&db, None)?;
    assert_follows(&db, old_tip)?;
    assert!(db.blocks.get(k_block(&h8))?.is_none(), "the substituted body must be dropped");
    assert_eq!(bad_marks(&db), 0);
    Ok(())
}

// A reorg whose first apply block fails, interrupted before the rollback cleared its journal: the
// boot finds the journal at (Apply, 0) with the tip at the ancestor. Replaying it as written
// fails on that block at every boot, so recovery drops the journal and rebuilds the heaviest
// chain that validates. Both blames: a committed rule (overspend) and a substituted signature.
#[test]
fn a_journal_whose_first_apply_block_fails_recovers_without_it() -> Result<()> {
    for substitute in [false, true] {
        let tmp = TempDir::new()?;
        let db = open_db(&tmp)?;
        let base = build_base_chain(&db, 12, START)?;
        let old_tip = *base.last().unwrap();
        let blk = if substitute {
            substituted(&fork_block_with_spend(&db, &base, 0)?)
        } else {
            fork_block_with_spend(&db, &base, 1)?
        };
        let (h8, tip) = store_with_heavier_fork(&db, &blk)?;

        let undo_path: Vec<Hash32> = base[8..].iter().rev().copied().collect();
        for bh in &undo_path {
            undo_block(&db, bh)?;
            set_tip(&db, &get_hidx(&db, bh)?.unwrap().parent)?;
        }
        let mut apply_path = vec![h8];
        let mut cur = tip;
        while cur != h8 {
            apply_path.insert(1, cur);
            cur = get_hidx(&db, &cur)?.unwrap().parent;
        }
        let j = ReorgJournal {
            seq: 0,
            old_tip,
            new_tip: tip,
            ancestor: base[7],
            phase: Phase::Apply,
            cursor: 0,
            undo_path,
            apply_path,
        };
        journal_write(&db, &j)?;
        flush_all_state_trees(&db)?;

        for boot in 1..=2 {
            let r = recover_if_needed(&db, None);
            assert!(r.is_ok(), "substitute={substitute} boot {boot}: recovery failed: {:#}", r.unwrap_err());
            assert_follows(&db, old_tip)?;
        }
        assert!(journal_read(&db)?.is_none(), "substitute={substitute}: the journal must be gone");
        assert_eq!(bad_marks(&db), 0);
        assert_eq!(db.blocks.get(k_block(&h8))?.is_none(), substitute, "only a substituted body is dropped");
    }
    Ok(())
}

/// Fork block h8 off base[7]: coinbase plus signed spends of base[1..=n]'s coinbases.
fn block_with_spends(db: &Stores, base: &[Hash32], n: usize) -> Result<Block> {
    let mut txs = vec![coinbase(FORK_MINER, block_reward(8), 8, None)];
    for bh in &base[1..=n] {
        let b: Block = consensus_bincode().deserialize(&db.blocks.get(k_block(bh))?.unwrap())?;
        let cb = &b.txs[0];
        let out = TxOut { value: cb.outputs[0].value, script_pubkey: test_signer_addr() };
        txs.push(signed_spend(OutPoint { txid: txid(cb), vout: 0 }, vec![out]));
    }
    let header = make_test_header(db, base[7], &txs, 8)?;
    Ok(Block { header, txs })
}

fn net_cfg(genesis_hash: Hash32) -> NetConfig {
    NetConfig {
        datadir: "/nonexistent".to_string(),
        listen: "/ip4/127.0.0.1/tcp/0".parse().unwrap(),
        bootnodes: vec![],
        genesis_hash,
        is_bootnode: false,
        test_mode: TestPeerMode::Normal,
    }
}

// The merkle root repeats the last node of an odd layer, so repeating the last tx (three leaves)
// or the last two (six leaves, a three-node layer) gives a body that binds to the honest header
// with only honest signatures. Such a body is neither stored nor served;
// the honest body still is.
#[test]
fn a_body_that_repeats_txids_is_refused_at_store_and_at_serve() -> Result<()> {
    let tmp = TempDir::new()?;
    let db = open_db(&tmp)?;
    let base = build_base_chain(&db, 12, START)?;
    let cfg = net_cfg(base[0]);
    for (n, repeat) in [(2usize, 1usize), (5, 2)] {
        let honest = block_with_spends(&db, &base, n)?;
        let h8 = header_hash(&honest.header);
        let mut repeated = honest.clone();
        repeated.txs.extend_from_slice(&honest.txs[honest.txs.len() - repeat..]);
        assert!(validate_block_merkle(&repeated).is_ok(), "fixture: the repeated body binds");
        let verdict = validate_and_apply_block(&db, &repeated, epoch_of(8), 8);
        assert!(
            format!("{:#}", verdict.expect_err("consensus must reject it")).contains("duplicate txid within block"),
            "n={n}: the store refuses only what consensus rejects"
        );

        assert!(
            matches!(store_block_bytes_checked(&db, &h8, &repeated)?, BlockStoreOutcome::RejectedRepeatedTxid),
            "n={n}: a body that repeats a txid must not be stored"
        );
        assert!(db.blocks.get(k_block(&h8))?.is_none());
        assert!(outbound_block_refusal(&cfg, &repeated, &h8).is_some(), "n={n}: it must not be served");

        assert!(matches!(store_block_bytes_checked(&db, &h8, &honest)?, BlockStoreOutcome::Stored));
        assert_eq!(outbound_block_refusal(&cfg, &honest, &h8), None, "n={n}: the honest body is served");
    }
    Ok(())
}

// A body that repeats a txid and is already in the store (written by a version whose store
// refused nothing) is dropped at its failed apply, not marked, and the honest chain is followed
// once the honest body arrives.
#[test]
fn a_stored_body_that_repeats_a_txid_is_dropped_not_marked() -> Result<()> {
    let tmp = TempDir::new()?;
    let db = open_db(&tmp)?;
    let base = build_base_chain(&db, 12, START)?;
    let old_tip = *base.last().unwrap();
    let honest = block_with_spends(&db, &base, 2)?;
    let mut repeated = honest.clone();
    repeated.txs.push(honest.txs[2].clone());
    let h8 = header_hash(&honest.header);
    db.blocks.insert(k_block(&h8), consensus_bincode().serialize(&repeated)?)?;
    index_header(&db, &honest.header, get_hidx(&db, &base[7])?.as_ref())?;
    let mut tip = h8;
    for h in 9..14u64 {
        tip = store_index_fork_block_to(&db, tip, h, START + h * 60 + 17, FORK_MINER)?;
    }
    flush_all_state_trees(&db)?;

    let err = maybe_reorg_to(&db, &tip, None).expect_err("a repeated txid must fail the apply");
    assert_eq!(get_tip(&db)?, Some(old_tip));
    assert_eq!(bad_marks(&db), 0, "nothing honest may be marked for a repeated-txid body");
    assert!(db.blocks.get(k_block(&h8))?.is_none(), "the repeated-txid body must be dropped");
    assert!(format!("{err:#}").contains("was dropped"), "unexpected failure: {err:#}");

    assert!(matches!(store_block_bytes_checked(&db, &h8, &honest)?, BlockStoreOutcome::Stored));
    maybe_reorg_to(&db, &tip, None)?;
    assert_follows(&db, tip)
}

// A reorg to a heavier fork whose first block's body was dropped (altered signatures),
// interrupted after the rollback flushed the ancestor and before it re-applied the old chain:
// journal at (Apply, 0), tip at the ancestor, the apply-path body gone. Recovery must rebuild the
// heaviest complete valid chain, the old tip here, not stop at the ancestor.
#[test]
fn recovery_after_a_dropped_apply_body_rebuilds_the_old_tip_not_the_ancestor() -> Result<()> {
    let tmp = TempDir::new()?;
    let db = open_db(&tmp)?;
    let base = build_base_chain(&db, 12, START)?;
    let old_tip = *base.last().unwrap();
    let (h8, tip) = store_with_heavier_fork(&db, &substituted(&fork_block_with_spend(&db, &base, 0)?))?;

    let undo_path: Vec<Hash32> = base[8..].iter().rev().copied().collect();
    for bh in &undo_path {
        undo_block(&db, bh)?;
        set_tip(&db, &get_hidx(&db, bh)?.unwrap().parent)?;
    }
    let mut apply_path = vec![h8];
    let mut cur = tip;
    while cur != h8 {
        apply_path.insert(1, cur);
        cur = get_hidx(&db, &cur)?.unwrap().parent;
    }
    let j = ReorgJournal {
        seq: 0, old_tip, new_tip: tip, ancestor: base[7], phase: Phase::Apply, cursor: 0, undo_path, apply_path,
    };
    journal_write(&db, &j)?;
    db.blocks.remove(k_block(&h8))?;
    flush_all_state_trees(&db)?;

    recover_if_needed(&db, None)?;
    assert_follows(&db, old_tip)?;
    assert!(journal_read(&db)?.is_none(), "the journal must be gone");
    Ok(())
}

// Canonical A11, a complete valid fork B to h13, and a heavier fork C to h14 whose C8 has
// altered signatures. Recovery tries C14, drops C8, and must then rebuild B13, the heaviest chain
// left that is complete and validates, not fall back to A11.
#[test]
fn recovery_continues_past_a_chain_with_a_dropped_body_to_the_next_heaviest() -> Result<()> {
    let tmp = TempDir::new()?;
    let db = open_db(&tmp)?;
    let base = build_base_chain(&db, 12, START)?;
    let mut b_tip = base[7];
    for h in 8..14u64 {
        b_tip = store_index_fork_block_to(&db, b_tip, h, START + h * 60 + 23, [0xB0; 20])?;
    }
    let (c8, c13) = store_with_heavier_fork(&db, &substituted(&fork_block_with_spend(&db, &base, 0)?))?;
    let c14 = store_index_fork_block_to(&db, c13, 14, START + 14 * 60 + 17, FORK_MINER)?;
    assert!(get_hidx(&db, &c14)?.unwrap().chainwork > get_hidx(&db, &b_tip)?.unwrap().chainwork);
    flush_all_state_trees(&db)?;

    recover_if_needed(&db, None)?;
    assert!(db.blocks.get(k_block(&c8))?.is_none(), "the altered body is dropped");
    assert_follows(&db, b_tip)
}
