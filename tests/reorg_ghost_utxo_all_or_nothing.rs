// Ghost-UTXO regression test (Plan 69, batch BN / finding 9:
// NODE-REORG-PARTIAL-APPLY-GHOST).
//
// `validate_and_apply_block` mutates the sled UTXO/app trees DIRECTLY while accumulating an
// in-memory `undo`, and only persists that undo log on SUCCESS. Historically, any early
// `?`/bail! inside (missing utxo, app-phase existence/expiry, bad coinbase value) dropped
// the in-memory `undo` and left the partial tree writes committed: a ghost create-output
// persisted and a ghost-deleted input was never restored (the twice-observed h47114
// incident; V28 sharpens the trigger, since a payment-bearing fill Attest that references a
// short-lived / reorg-orphaned proposal is a designed-in boundary condition).
//
// After the fix, a REJECTED block must leave ZERO residue: spent inputs restored, created
// outputs absent, app-state byte-for-byte unchanged. These tests exercise all four early-bail
// points, including the V28-shaped fill-Attest triggers (orphaned/unknown proposal AND
// expired short-lived proposal).
//
// NOTE ON HARNESS: the repo's testutil_chain builds toy chains via `index_header`, whose
// genesis-identity check is gated on `#[cfg(test)]` (`allow_foreign_genesis_for_tests`). That
// cfg is NOT active for the lib when it is linked by an integration test, so the toy-chain
// helpers "foreign genesis header"-fail under a plain `cargo test` (documented pre-existing
// upstream rot in README.md; several reorg_*/consensus_* share it). `validate_and_apply_block`
// itself never touches the header index or genesis, so this test drives it DIRECTLY: it injects
// spendable UTXOs into the sled trees and hand-builds blocks. That isolates exactly the
// all-or-nothing apply surface and runs green with no special flags.

use anyhow::Result;
use tempfile::TempDir;

use csd::crypto::{hash160, sha256d, sign_tx_compact_secp256k1, txid};
use csd::params::{block_reward, MIN_FEE_ATTEST, MIN_FEE_PROPOSE};
use csd::state::app_state::{epoch_of, get_proposal, k_attest};
use csd::state::db::{
    get_utxo, get_utxo_meta, k_undo, put_utxo, put_utxo_meta, Stores, UtxoMeta,
};
use csd::state::utxo::{undo_block, validate_and_apply_block};
use csd::types::{AppPayload, Block, BlockHeader, Hash20, Hash32, OutPoint, Transaction, TxIn, TxOut};

const SK: [u8; 32] = [21u8; 32];
const COIN_VALUE: u64 = 1_000_000_000;

// -----------------------------------------------------------------------------
// helpers (no testutil / no genesis / no header index)
// -----------------------------------------------------------------------------

fn open_db(tmp: &TempDir) -> Stores {
    Stores::open(tmp.path().to_str().unwrap()).expect("open db")
}

fn signer_addr() -> Hash20 {
    let dummy = Transaction {
        version: 1,
        inputs: vec![TxIn {
            prevout: OutPoint {
                txid: [0u8; 32],
                vout: 0,
            },
            script_sig: vec![],
        }],
        outputs: vec![TxOut {
            value: 1,
            script_pubkey: [0u8; 20],
        }],
        locktime: 0,
        app: AppPayload::None,
    };
    let (_sig64, pub33) = sign_tx_compact_secp256k1(&dummy, SK);
    hash160(&pub33)
}

fn sign_all(mut tx: Transaction) -> Transaction {
    let (sig64, pub33) = sign_tx_compact_secp256k1(&tx, SK);
    let mut ss = Vec::with_capacity(99);
    ss.push(64u8);
    ss.extend_from_slice(&sig64);
    ss.push(33u8);
    ss.extend_from_slice(&pub33);
    for inp in &mut tx.inputs {
        inp.script_sig = ss.clone();
    }
    tx
}

/// Inject a spendable coin (owned by SK) straight into the UTXO trees.
fn inject_coin(db: &Stores, tag: u8) -> OutPoint {
    let op = OutPoint {
        txid: [tag; 32],
        vout: 0,
    };
    put_utxo(
        db,
        &op,
        &TxOut {
            value: COIN_VALUE,
            script_pubkey: signer_addr(),
        },
    )
    .unwrap();
    put_utxo_meta(
        db,
        &op,
        &UtxoMeta {
            height: 1,
            coinbase: true,
        },
    )
    .unwrap();
    op
}

/// Consensus merkle (matches utxo.rs `merkle_root_txids`: duplicate last if odd).
fn merkle_root(txs: &[Transaction]) -> Hash32 {
    let mut layer: Vec<Hash32> = txs.iter().map(txid).collect();
    if layer.is_empty() {
        return [0u8; 32];
    }
    while layer.len() > 1 {
        let mut next = Vec::with_capacity((layer.len() + 1) / 2);
        let mut i = 0usize;
        while i < layer.len() {
            let l = layer[i];
            let r = if i + 1 < layer.len() { layer[i + 1] } else { layer[i] };
            let mut buf = [0u8; 64];
            buf[..32].copy_from_slice(&l);
            buf[32..].copy_from_slice(&r);
            next.push(sha256d(&buf));
            i += 2;
        }
        layer = next;
    }
    layer[0]
}

/// Build a block. `validate_and_apply_block` only checks the merkle commitment (not time /
/// bits / PoW, which live in the header-index path we deliberately bypass).
fn mk_block(prev: Hash32, txs: Vec<Transaction>) -> Block {
    let merkle = merkle_root(&txs);
    Block {
        header: BlockHeader {
            version: 1,
            prev,
            merkle,
            time: 0,
            bits: 0,
            nonce: 0,
        },
        txs,
    }
}

fn block_hash(blk: &Block) -> Hash32 {
    csd::chain::index::header_hash(&blk.header)
}

fn attest_tx(input: OutPoint, proposal_id: Hash32) -> Transaction {
    sign_all(Transaction {
        version: 1,
        inputs: vec![TxIn {
            prevout: input,
            script_sig: vec![0u8; 99],
        }],
        outputs: vec![TxOut {
            value: COIN_VALUE - MIN_FEE_ATTEST,
            script_pubkey: [0x42; 20],
        }],
        locktime: 0,
        app: AppPayload::Attest {
            proposal_id,
            score: 1,
            confidence: 1,
        },
    })
}

fn propose_tx(input: OutPoint, expires_epoch: u64) -> Transaction {
    sign_all(Transaction {
        version: 1,
        inputs: vec![TxIn {
            prevout: input,
            script_sig: vec![0u8; 99],
        }],
        outputs: vec![TxOut {
            value: COIN_VALUE - MIN_FEE_PROPOSE,
            script_pubkey: [0x41; 20],
        }],
        locktime: 0,
        app: AppPayload::Propose {
            domain: "dvp".into(),
            payload_hash: [0x11; 32],
            uri: "csd://fclaim/short".into(),
            expires_epoch,
        },
    })
}

type Snap = std::collections::BTreeMap<Vec<u8>, Vec<u8>>;

macro_rules! snap {
    ($tree:expr) => {{
        let m: Snap = $tree
            .iter()
            .map(|r| {
                let (k, v) = r.expect("tree iter");
                (k.to_vec(), v.to_vec())
            })
            .collect();
        m
    }};
}

/// Snapshot every tree `validate_and_apply_block` can write to.
fn state_snapshot(db: &Stores) -> (Snap, Snap, Snap, Snap) {
    (snap!(db.utxo), snap!(db.utxo_meta), snap!(db.app), snap!(db.undo))
}

/// The core zero-residue assertion, shared by all four bail-point tests.
fn assert_zero_residue(
    db: &Stores,
    before: &(Snap, Snap, Snap, Snap),
    block_hash: &Hash32,
    spent_inputs: &[OutPoint],
    created_outputs: &[OutPoint],
) -> Result<()> {
    let after = state_snapshot(db);

    // 1) Definitive check: NOTHING moved in any mutated tree.
    assert_eq!(
        &after, before,
        "ghost residue: mutated-tree state changed after a REJECTED block"
    );

    // 2) Explicit spot checks (readability / intent).
    for op in spent_inputs {
        assert_eq!(
            get_utxo(db, op)?.map(|o| o.value),
            Some(COIN_VALUE),
            "spent input {} not restored after reject",
            hex::encode(op.txid)
        );
        assert!(
            get_utxo_meta(db, op)?.is_some(),
            "spent-input meta {} not restored",
            hex::encode(op.txid)
        );
    }
    for op in created_outputs {
        assert!(
            get_utxo(db, op)?.is_none(),
            "ghost create-output {}:{} persisted after reject",
            hex::encode(op.txid),
            op.vout
        );
        assert!(
            get_utxo_meta(db, op)?.is_none(),
            "ghost create-output meta {}:{} persisted after reject",
            hex::encode(op.txid),
            op.vout
        );
    }

    // 3) No undo log persisted for the failing block (it bailed before the persist).
    assert!(
        db.undo.get(k_undo(block_hash))?.is_none(),
        "an undo log was persisted for a rejected block"
    );
    Ok(())
}

fn out0(tx: &Transaction) -> OutPoint {
    OutPoint {
        txid: txid(tx),
        vout: 0,
    }
}

// -----------------------------------------------------------------------------
// Bail point 1 (V28-shaped): fill Attest referencing an ORPHANED / unknown proposal.
//   -> app_state.rs existence bail, AFTER the fill spent its input + created change.
// -----------------------------------------------------------------------------
#[test]
fn ghost_reject_attest_unknown_proposal_leaves_zero_residue() -> Result<()> {
    let tmp = TempDir::new()?;
    let db = open_db(&tmp);
    let height = 6u64;

    let buyer = inject_coin(&db, 0xB1);
    let fill = attest_tx(buyer, [0xAB; 32]); // 0xAB..: non-zero, never proposed
    let cb = csd::chain::mine::coinbase(
        [0x99; 20],
        block_reward(height) + MIN_FEE_ATTEST,
        height,
        None,
    );
    let cb_op = out0(&cb);
    let fill_txid = txid(&fill);
    let fill_out = out0(&fill);
    let blk = mk_block([0u8; 32], vec![cb, fill]);
    let bh = block_hash(&blk);

    let before = state_snapshot(&db);
    let err = validate_and_apply_block(&db, &blk, epoch_of(height), height)
        .expect_err("attest on unknown proposal must be rejected");
    let msg = format!("{err:#}");
    assert!(msg.contains("proposal"), "unexpected error: {msg}");

    assert_zero_residue(&db, &before, &bh, &[buyer], &[fill_out, cb_op])?;
    assert!(get_proposal(&db, &[0xAB; 32])?.is_none());
    assert!(db.app.get(k_attest(&fill_txid))?.is_none());
    Ok(())
}

// -----------------------------------------------------------------------------
// Bail point 2 (V28-shaped): fill Attest referencing an EXPIRED short-lived proposal.
//   -> app_state.rs expiry bail, AFTER the fill spent its input + created change.
//   The referenced proposal EXISTS (applied earlier) and must remain untouched.
// -----------------------------------------------------------------------------
#[test]
fn ghost_reject_attest_expired_proposal_leaves_zero_residue() -> Result<()> {
    let tmp = TempDir::new()?;
    let db = open_db(&tmp);

    // A short-lived proposal, valid at creation (height 7 -> epoch 0, expires_epoch 0).
    let p_in = inject_coin(&db, 0xC1);
    let prop = propose_tx(p_in, 0);
    let proposal_id = txid(&prop);
    let cb7 = csd::chain::mine::coinbase(signer_addr(), block_reward(7) + MIN_FEE_PROPOSE, 7, None);
    let propose_blk = mk_block([0u8; 32], vec![cb7, prop]);
    validate_and_apply_block(&db, &propose_blk, epoch_of(7), 7).expect("propose must apply");
    assert!(get_proposal(&db, &proposal_id)?.is_some(), "propose must be live");

    // The fill lands at height 30 (epoch 1) > expires_epoch 0: the proposal is now EXPIRED.
    let height = 30u64;
    assert_eq!(epoch_of(height), 1);
    let buyer = inject_coin(&db, 0xC2);
    let fill = attest_tx(buyer, proposal_id);
    let fill_txid = txid(&fill);
    let cb = csd::chain::mine::coinbase(
        [0x99; 20],
        block_reward(height) + MIN_FEE_ATTEST,
        height,
        None,
    );
    let cb_op = out0(&cb);
    let fill_out = out0(&fill);
    let blk = mk_block([1u8; 32], vec![cb, fill]);
    let bh = block_hash(&blk);

    let before = state_snapshot(&db);
    let err = validate_and_apply_block(&db, &blk, epoch_of(height), height)
        .expect_err("attest after proposal expiry must be rejected");
    let msg = format!("{err:#}");
    assert!(
        msg.contains("expiry") || msg.contains("expires_epoch") || msg.contains("epoch"),
        "unexpected error: {msg}"
    );

    assert_zero_residue(&db, &before, &bh, &[buyer], &[fill_out, cb_op])?;
    assert!(
        get_proposal(&db, &proposal_id)?.is_some(),
        "expired proposal must survive a rejected fill unchanged"
    );
    assert!(db.app.get(k_attest(&fill_txid))?.is_none());
    Ok(())
}

// -----------------------------------------------------------------------------
// Bail point 3: bad coinbase value.
//   The Propose is fully applied (spend + create + phase-1 app write), THEN the coinbase
//   value check bails. Everything must roll back.
// -----------------------------------------------------------------------------
#[test]
fn ghost_reject_bad_coinbase_value_leaves_zero_residue() -> Result<()> {
    let tmp = TempDir::new()?;
    let db = open_db(&tmp);
    let height = 6u64;

    let p_in = inject_coin(&db, 0xD1);
    let prop = propose_tx(p_in, epoch_of(height) + 5);
    let propose_txid = txid(&prop);
    // reward + fee would be correct; +1 makes the coinbase check bail AFTER the propose applied.
    let cb = csd::chain::mine::coinbase(
        [0x99; 20],
        block_reward(height) + MIN_FEE_PROPOSE + 1,
        height,
        None,
    );
    let cb_op = out0(&cb);
    let prop_out = out0(&prop);
    let blk = mk_block([0u8; 32], vec![cb, prop]);
    let bh = block_hash(&blk);

    let before = state_snapshot(&db);
    let err = validate_and_apply_block(&db, &blk, epoch_of(height), height)
        .expect_err("bad coinbase value must be rejected");
    let msg = format!("{err:#}");
    assert!(msg.contains("coinbase value wrong"), "unexpected error: {msg}");

    assert_zero_residue(&db, &before, &bh, &[p_in], &[prop_out, cb_op])?;
    assert!(
        get_proposal(&db, &propose_txid)?.is_none(),
        "proposal from a rejected block leaked into app-state"
    );
    Ok(())
}

// -----------------------------------------------------------------------------
// Bail point 4: missing utxo mid-first-loop.
//   tx1 (a plain spend) is fully applied, then tx2 references a non-existent utxo and bails
//   inside the first loop. tx1's spend + create must be fully reversed.
// -----------------------------------------------------------------------------
#[test]
fn ghost_reject_missing_utxo_midloop_leaves_zero_residue() -> Result<()> {
    let tmp = TempDir::new()?;
    let db = open_db(&tmp);
    let height = 6u64;

    let a = inject_coin(&db, 0xE1);
    let tx1 = sign_all(Transaction {
        version: 1,
        inputs: vec![TxIn {
            prevout: a,
            script_sig: vec![0u8; 99],
        }],
        outputs: vec![TxOut {
            value: COIN_VALUE - 1_000,
            script_pubkey: [0x51; 20],
        }],
        locktime: 0,
        app: AppPayload::None,
    });
    // tx2 references a utxo that was never created -> "missing utxo" bail mid-first-loop.
    let tx2 = Transaction {
        version: 1,
        inputs: vec![TxIn {
            prevout: OutPoint {
                txid: [0xFE; 32],
                vout: 0,
            },
            script_sig: vec![0u8; 99], // 99-byte dummy: passes structure, bails at get_utxo
        }],
        outputs: vec![TxOut {
            value: 1,
            script_pubkey: [0x52; 20],
        }],
        locktime: 0,
        app: AppPayload::None,
    };
    let cb = csd::chain::mine::coinbase([0x99; 20], block_reward(height), height, None);
    let cb_op = out0(&cb);
    let blk = mk_block([0u8; 32], vec![cb, tx1.clone(), tx2.clone()]);
    let bh = block_hash(&blk);

    let before = state_snapshot(&db);
    let err = validate_and_apply_block(&db, &blk, epoch_of(height), height)
        .expect_err("missing utxo must be rejected");
    let msg = format!("{err:#}");
    assert!(msg.contains("missing utxo"), "unexpected error: {msg}");

    assert_zero_residue(&db, &before, &bh, &[a], &[out0(&tx1), out0(&tx2), cb_op])?;
    Ok(())
}

// -----------------------------------------------------------------------------
// SUCCESS-path parity: the refactored `undo_block` (which now calls the shared `apply_undo`)
// must reverse a FULLY-APPLIED block back to its exact prior state. This is the reorg-rollback
// path (reorg.rs calls undo_block on each applied_new block on rollback); the repo's reorg_*
// integration suite is harness-dead in this fork (foreign-genesis + a PoW-bypass that no longer
// exists), so this drives the same machinery directly.
// -----------------------------------------------------------------------------
#[test]
fn undo_block_via_apply_undo_roundtrips_to_prior_state() -> Result<()> {
    let tmp = TempDir::new()?;
    let db = open_db(&tmp);
    let height = 6u64;

    let coin = inject_coin(&db, 0xA1);
    let pristine = state_snapshot(&db); // just the injected coin

    // A valid block: coinbase + a propose (spend + create + app write + topk).
    let prop = propose_tx(coin, epoch_of(height) + 5);
    let proposal_id = txid(&prop);
    let prop_out = out0(&prop);
    let cb = csd::chain::mine::coinbase(
        [0x99; 20],
        block_reward(height) + MIN_FEE_PROPOSE,
        height,
        None,
    );
    let cb_out = out0(&cb);
    let blk = mk_block([0u8; 32], vec![cb, prop]);
    let bh = block_hash(&blk);

    validate_and_apply_block(&db, &blk, epoch_of(height), height).expect("valid block must apply");

    // Success mutated state: coin spent, change + coinbase created, proposal live, undo persisted.
    assert!(get_utxo(&db, &coin)?.is_none(), "input should be spent");
    assert!(get_utxo(&db, &prop_out)?.is_some(), "change should exist");
    assert!(get_utxo(&db, &cb_out)?.is_some(), "coinbase output should exist");
    assert!(get_proposal(&db, &proposal_id)?.is_some(), "proposal should be live");
    assert!(db.undo.get(k_undo(&bh))?.is_some(), "undo log should be persisted");

    // Roll it back via the refactored undo_block -> apply_undo.
    undo_block(&db, &bh).expect("undo_block must succeed");

    assert_eq!(
        state_snapshot(&db),
        pristine,
        "undo_block did not restore the exact prior state"
    );
    assert!(get_utxo(&db, &coin)?.is_some(), "input must be restored");
    assert!(get_proposal(&db, &proposal_id)?.is_none(), "proposal must be gone");
    assert!(db.undo.get(k_undo(&bh))?.is_none(), "undo log must be removed");
    Ok(())
}

// -----------------------------------------------------------------------------
// A SAME-BLOCK create-then-spend outpoint must NOT resurrect as a
// phantom UTXO when the block is undone (the reorg-disconnect path). tx1 creates X and tx2 spends X
// within one block (consensus-legal: tx1's put_utxo makes X visible to tx2). Historically apply_undo
// restored X (it is in BOTH undo.created and undo.spent), leaving a phantom absent in a from-genesis
// replay: a long-running incrementally-reorging node then diverged from a fresh node on a later spend
// of X, which is a consensus fork. Reordering the undo alone does not fix this.
// This drives the real validate_and_apply_block + undo_block; WITHOUT the created_set dedup the killer
// assertion below finds X restored (Some) and fails; WITH the fix X is absent, matching from-genesis.
// -----------------------------------------------------------------------------
#[test]
fn reorg_undo_same_block_create_then_spend_leaves_no_phantom() -> Result<()> {
    let tmp = TempDir::new()?;
    let db = open_db(&tmp);
    let height = 6u64;

    let c = inject_coin(&db, 0xC3);
    let pristine = state_snapshot(&db); // just the injected coin C

    // tx1 spends C and creates X, owned by SK so tx2 (same block) can spend it.
    let tx1 = sign_all(Transaction {
        version: 1,
        inputs: vec![TxIn { prevout: c, script_sig: vec![0u8; 99] }],
        outputs: vec![TxOut { value: COIN_VALUE - 1_000, script_pubkey: signer_addr() }],
        locktime: 0,
        app: AppPayload::None,
    });
    let x = out0(&tx1); // txid strips scriptSig, so this is stable post-sign
    // tx2 spends X (created by tx1 IN THIS BLOCK) and creates Y.
    let tx2 = sign_all(Transaction {
        version: 1,
        inputs: vec![TxIn { prevout: x, script_sig: vec![0u8; 99] }],
        outputs: vec![TxOut { value: COIN_VALUE - 2_000, script_pubkey: [0x53; 20] }],
        locktime: 0,
        app: AppPayload::None,
    });
    let y = out0(&tx2);
    // coinbase collects both fees (1_000 + 1_000).
    let cb = csd::chain::mine::coinbase([0x99; 20], block_reward(height) + 2_000, height, None);
    let cb_op = out0(&cb);
    let blk = mk_block([0u8; 32], vec![cb, tx1, tx2]);
    let bh = block_hash(&blk);

    validate_and_apply_block(&db, &blk, epoch_of(height), height)
        .expect("a same-block create-then-spend chain is consensus-legal and must apply");

    // Applied state: C spent, X spent-by-tx2 (NOT a live UTXO), Y + coinbase present.
    assert!(get_utxo(&db, &c)?.is_none(), "C should be spent by tx1");
    assert!(get_utxo(&db, &x)?.is_none(), "X should be spent by tx2 (absent while applied)");
    assert!(get_utxo(&db, &y)?.is_some(), "Y should exist");
    assert!(get_utxo(&db, &cb_op)?.is_some(), "coinbase output should exist");

    // Undo the block (reorg disconnect). The KILLER assertion: X must stay absent (no phantom).
    undo_block(&db, &bh).expect("undo_block must succeed");
    assert!(
        get_utxo(&db, &x)?.is_none(),
        "same-block create-then-spend outpoint X resurrected as a phantom UTXO on undo"
    );
    assert!(get_utxo_meta(&db, &x)?.is_none(), "phantom X meta resurrected on undo");
    assert_eq!(
        state_snapshot(&db),
        pristine,
        "undo did not converge to the from-genesis (pristine) UTXO set"
    );
    assert!(get_utxo(&db, &c)?.is_some(), "C must be restored after undo");
    assert!(db.undo.get(k_undo(&bh))?.is_none(), "undo log must be removed");
    Ok(())
}
