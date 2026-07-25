// Regression tests: a rejected block, and a reorg undo, must leave no UTXO residue.
//
// `validate_and_apply_block` mutates the sled UTXO/app trees DIRECTLY while accumulating an
// in-memory `undo`, and only persists that undo log on SUCCESS. Any early `?`/bail! inside
// (missing utxo, app-phase existence/expiry, bad coinbase value) therefore dropped the in-memory
// `undo` and left the partial tree writes committed: a created output persisted, and a spent
// input was never restored. We hit this twice on mainnet. An attestation that references an
// unknown (reorg-orphaned) or expired proposal is the easiest trigger, because that check runs
// after the transaction has already spent its input and created its change output.
//
// After the fix, a REJECTED block must leave ZERO residue: spent inputs restored, created outputs
// absent, app state byte-for-byte unchanged. These tests exercise all four early-bail points.
// The last two cover the undo path instead: a same-block create-then-spend must not resurrect on
// undo, and a pre-block coin whose txid the block's coinbase duplicates must still be restored.
//
// NOTE ON HARNESS: testutil_chain builds toy chains via `index_header`, whose genesis-identity
// check is gated on `#[cfg(test)]` (`allow_foreign_genesis_for_tests`). That cfg is NOT active
// for the lib when it is linked by an integration test, so the toy-chain helpers fail with
// "foreign genesis header" under a plain `cargo test`. That is pre-existing on main and several
// reorg_* and consensus_* targets share it. `validate_and_apply_block` itself never touches the
// header index or genesis, so these tests drive it DIRECTLY: they inject spendable UTXOs into the
// sled trees and hand-build blocks. That isolates exactly the apply/undo surface and runs green
// with no special flags.

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
// Bail point 1: an Attest referencing an ORPHANED / unknown proposal.
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
// Bail point 2: an Attest referencing an EXPIRED short-lived proposal.
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

// -----------------------------------------------------------------------------
// The created-set skip must NOT drop a restore when the outpoint existed BEFORE the block.
//
// Nothing enforces a height commitment in the coinbase script_sig yet
// (COINBASE_HEIGHT_PREFIX_ACTIVATION_HEIGHT = u64::MAX), so a coinbase txid can collide with an
// earlier, still-unspent coinbase: within one halving epoch, a block with the same fee total and
// the same miner address produces byte-identical coinbase bytes.
//
// Non-coinbase transactions are applied BEFORE the coinbase, so such a block can spend the
// pre-block coin at (T,0) in its transaction loop and then have its own coinbase recreate (T,0).
// That puts one outpoint in BOTH undo.created and undo.spent for a reason that is not a
// same-block create-then-spend, and undo must restore the pre-block coin rather than delete it.
//
// The coinbase output is written last, so no transaction in the same block can ever spend it.
// An outpoint that is both created by the coinbase and spent in this block is therefore always
// this case, never the honest one.
// -----------------------------------------------------------------------------
#[test]
fn undo_restores_a_pre_block_coin_whose_txid_the_coinbase_duplicates() -> Result<()> {
    let tmp = TempDir::new()?;
    let db = open_db(&tmp);
    let height = 9u64;
    let fee = 1_000u64;
    const OLD_VALUE: u64 = 777_000_000;

    // This block's coinbase.
    let cb = csd::chain::mine::coinbase(signer_addr(), block_reward(height) + fee, height, None);
    let cb_op = out0(&cb);

    // An earlier block produced a byte-identical coinbase, so (T,0) already exists, is unspent,
    // and holds a different value. Seeded directly: what is under test is undo, not how the
    // collision arises.
    put_utxo(
        &db,
        &cb_op,
        &TxOut {
            value: OLD_VALUE,
            script_pubkey: signer_addr(),
        },
    )?;
    put_utxo_meta(
        &db,
        &cb_op,
        &UtxoMeta {
            height: 1,
            coinbase: true,
        },
    )?;
    let pristine = state_snapshot(&db);

    // A regular transaction in this block spends that pre-block coin.
    let tx1 = sign_all(Transaction {
        version: 1,
        inputs: vec![TxIn {
            prevout: cb_op,
            script_sig: vec![0u8; 99],
        }],
        outputs: vec![TxOut {
            value: OLD_VALUE - fee,
            script_pubkey: [0x71; 20],
        }],
        locktime: 0,
        app: AppPayload::None,
    });

    let blk = mk_block([0u8; 32], vec![cb, tx1]);
    let bh = block_hash(&blk);
    validate_and_apply_block(&db, &blk, epoch_of(height), height)
        .expect("a block whose coinbase txid duplicates an earlier one is currently consensus-legal");

    // While applied, (T,0) exists again and holds THIS block's coinbase value.
    let applied = get_utxo(&db, &cb_op)?.expect("coinbase output present while applied");
    assert_eq!(applied.value, block_reward(height) + fee);

    undo_block(&db, &bh).expect("undo_block must succeed");

    let restored = get_utxo(&db, &cb_op)?.expect(
        "the PRE-BLOCK coin at (T,0) must be restored on undo, not dropped by the created-set skip",
    );
    assert_eq!(restored.value, OLD_VALUE, "restored the wrong value at (T,0)");
    assert_eq!(
        state_snapshot(&db),
        pristine,
        "undo did not converge to the pre-block state"
    );
    Ok(())
}

// The created-set skip was still a PROXY for the property it wanted.
//
// The previous commit on this branch refined it to `created_set.contains(op) && !meta.coinbase`, which covers the case where
// the duplicate-coinbase block SPENDS the pre-block coin. It does not cover the case where the
// block merely OVERWRITES it, nor the non-coinbase leg, because `meta.coinbase` is not the property
// under test. The property under test is "did this outpoint hold a coin BEFORE this block".
//
// This commit captures exactly that, at the FIRST touch of each outpoint during apply, and routes the
// outpoint into exactly one of `undo.created` (did not exist: delete on undo) or `undo.spent`
// (existed: restore that value on undo). The three tests below are the legs the refined proxy still gets wrong.
// -----------------------------------------------------------------------------

/// Leg 1: the duplicate-coinbase block does NOT spend the pre-block coin, it only overwrites it.
/// The outpoint therefore lands in `undo.created` alone, and the created-loop deletes it, so a coin
/// that a from-genesis replay still holds is gone. Cheaper to construct than the this change case: an
/// empty block, no spend transaction.
#[test]
fn undo_restores_an_unspent_pre_block_coinbase_that_the_new_coinbase_overwrote() -> Result<()> {
    let tmp = TempDir::new()?;
    let db = open_db(&tmp);
    let height = 9u64;

    // Empty block, so the coinbase value is exactly the reward and no fee matching is needed.
    let cb = csd::chain::mine::coinbase(signer_addr(), block_reward(height), height, None);
    let cb_op = out0(&cb);

    // An earlier block produced a byte-identical coinbase and its output is still unspent.
    put_utxo(&db, &cb_op, &cb.outputs[0])?;
    put_utxo_meta(&db, &cb_op, &UtxoMeta { height: 1, coinbase: true })?;
    let pristine = state_snapshot(&db);

    let blk = mk_block([0u8; 32], vec![cb]);
    let bh = block_hash(&blk);
    validate_and_apply_block(&db, &blk, epoch_of(height), height)
        .expect("a block whose coinbase txid duplicates an earlier one is consensus-legal today");

    undo_block(&db, &bh).expect("undo_block must succeed");

    assert!(
        get_utxo(&db, &cb_op)?.is_some(),
        "the pre-block coin at (T,0) must survive undo; a from-genesis replay without this block \
         still holds it"
    );
    assert_eq!(state_snapshot(&db), pristine, "undo did not converge to the pre-block state");
    Ok(())
}

/// Leg 2: the same overwrite, but on a NON-coinbase output, which is the leg `meta.coinbase`
/// structurally cannot see. Reachable only after a coinbase duplication has already recreated a
/// spent input, so it is a second step rather than a second bug, but it is the same divergence.
#[test]
fn undo_restores_a_pre_block_noncoinbase_output_that_a_replayed_tx_overwrote() -> Result<()> {
    let tmp = TempDir::new()?;
    let db = open_db(&tmp);
    let height = 9u64;
    const OLD_VALUE: u64 = 654_000_000;

    // The input the replayed transaction spends.
    let funding = inject_coin(&db, 0xC1);

    // The transaction being replayed. Its txid fixes the outpoint it creates.
    let replay = sign_all(Transaction {
        version: 1,
        inputs: vec![TxIn { prevout: funding, script_sig: vec![0u8; 99] }],
        outputs: vec![TxOut { value: COIN_VALUE - 1_000, script_pubkey: signer_addr() }],
        locktime: 0,
        app: AppPayload::None,
    });
    let replay_op = out0(&replay);

    // That outpoint already holds a coin from when the transaction was first mined. Seeded
    // directly: what is under test is undo, not how the collision arises.
    put_utxo(&db, &replay_op, &TxOut { value: OLD_VALUE, script_pubkey: signer_addr() })?;
    put_utxo_meta(&db, &replay_op, &UtxoMeta { height: 2, coinbase: false })?;
    let pristine = state_snapshot(&db);

    let fee = 1_000u64;
    let cb = csd::chain::mine::coinbase(signer_addr(), block_reward(height) + fee, height, None);
    let blk = mk_block([0u8; 32], vec![cb, replay]);
    let bh = block_hash(&blk);
    validate_and_apply_block(&db, &blk, epoch_of(height), height)
        .expect("replaying a transaction whose output is still unspent is consensus-legal today");

    undo_block(&db, &bh).expect("undo_block must succeed");

    let restored = get_utxo(&db, &replay_op)?.expect(
        "the pre-block non-coinbase coin must be restored on undo, not deleted by the created-loop",
    );
    assert_eq!(restored.value, OLD_VALUE, "restored the wrong value");
    assert_eq!(state_snapshot(&db), pristine, "undo did not converge to the pre-block state");
    Ok(())
}

/// Leg 3: pins the MECHANISM rather than a symptom. The block touches one outpoint three times:
/// it spends the pre-block coin, a replayed transaction recreates it, and a third transaction
/// spends it again. Only the FIRST touch sees the pre-block value, so an implementation that
/// records the value at every touch (or at the last one) restores this block's own value instead of
/// the ancestor's and diverges without ever deleting anything.
#[test]
fn undo_restores_the_first_touch_value_when_a_block_spends_recreates_and_respends() -> Result<()> {
    let tmp = TempDir::new()?;
    let db = open_db(&tmp);
    let height = 9u64;
    const OLD_VALUE: u64 = 500_000_000;
    const FEE: u64 = 1_000;

    // Funding for the replayed transaction.
    let funding = inject_coin(&db, 0xC2);

    // The replayed transaction. Its txid fixes the contested outpoint.
    let replay = sign_all(Transaction {
        version: 1,
        inputs: vec![TxIn { prevout: funding, script_sig: vec![0u8; 99] }],
        outputs: vec![TxOut { value: COIN_VALUE - FEE, script_pubkey: signer_addr() }],
        locktime: 0,
        app: AppPayload::None,
    });
    let contested = out0(&replay);

    // Pre-block: the contested outpoint already holds a DIFFERENT value.
    put_utxo(&db, &contested, &TxOut { value: OLD_VALUE, script_pubkey: signer_addr() })?;
    put_utxo_meta(&db, &contested, &UtxoMeta { height: 3, coinbase: false })?;
    let pristine = state_snapshot(&db);

    // tx_a spends the PRE-BLOCK coin at the contested outpoint.
    let tx_a = sign_all(Transaction {
        version: 1,
        inputs: vec![TxIn { prevout: contested, script_sig: vec![0u8; 99] }],
        outputs: vec![TxOut { value: OLD_VALUE - FEE, script_pubkey: [0x81; 20] }],
        locktime: 0,
        app: AppPayload::None,
    });

    // tx_c spends the contested outpoint AGAIN, after `replay` has recreated it.
    let tx_c = sign_all(Transaction {
        version: 1,
        inputs: vec![TxIn { prevout: contested, script_sig: vec![0u8; 99] }],
        outputs: vec![TxOut { value: COIN_VALUE - FEE - FEE, script_pubkey: [0x82; 20] }],
        locktime: 0,
        app: AppPayload::None,
    });

    // Three transactions, each paying FEE.
    let cb = csd::chain::mine::coinbase(signer_addr(), block_reward(height) + 3 * FEE, height, None);
    let blk = mk_block([0u8; 32], vec![cb, tx_a, replay, tx_c]);
    let bh = block_hash(&blk);
    validate_and_apply_block(&db, &blk, epoch_of(height), height)
        .expect("spend, replay-recreate and respend are each consensus-legal today");

    undo_block(&db, &bh).expect("undo_block must succeed");

    let restored = get_utxo(&db, &contested)?
        .expect("the contested outpoint must be restored to its pre-block coin");
    assert_eq!(
        restored.value, OLD_VALUE,
        "undo restored a value this block wrote instead of the pre-block value"
    );
    assert_eq!(state_snapshot(&db), pristine, "undo did not converge to the pre-block state");
    Ok(())
}

/// The invariant this change establishes, asserted DIRECTLY on the log the apply path produces:
/// no outpoint may appear in both `undo.created` and `undo.spent`. That is what lets the undo side
/// stop inferring. Exercised on an honest same-block create-then-spend, which is precisely the shape
/// that used to land in both lists.
#[test]
fn an_undo_log_never_puts_an_outpoint_in_both_lists() -> Result<()> {
    let tmp = TempDir::new()?;
    let db = open_db(&tmp);
    let height = 7u64;
    const FEE: u64 = 1_000;

    let coin = inject_coin(&db, 0xB7);

    // tx1 creates an output; tx2, in the SAME block, spends it.
    let tx1 = sign_all(Transaction {
        version: 1,
        inputs: vec![TxIn { prevout: coin, script_sig: vec![0u8; 99] }],
        outputs: vec![TxOut { value: COIN_VALUE - FEE, script_pubkey: signer_addr() }],
        locktime: 0,
        app: AppPayload::None,
    });
    let mid = out0(&tx1);
    let tx2 = sign_all(Transaction {
        version: 1,
        inputs: vec![TxIn { prevout: mid, script_sig: vec![0u8; 99] }],
        outputs: vec![TxOut { value: COIN_VALUE - FEE - FEE, script_pubkey: [0x91; 20] }],
        locktime: 0,
        app: AppPayload::None,
    });

    let cb = csd::chain::mine::coinbase(signer_addr(), block_reward(height) + 2 * FEE, height, None);
    let blk = mk_block([0u8; 32], vec![cb, tx1, tx2]);
    let undo = validate_and_apply_block(&db, &blk, epoch_of(height), height).expect("apply");

    // The create-then-spend outpoint is recorded ONCE, as created (delete on undo).
    assert!(undo.created.contains(&mid), "the same-block output must be in created");
    assert!(
        !undo.spent.iter().any(|(op, _, _)| *op == mid),
        "a log written by this code must NOT also record the same-block output as spent; that ambiguity is what \
         the undo side used to have to guess its way out of"
    );

    // And no outpoint at all appears in both lists.
    let created: std::collections::HashSet<OutPoint> = undo.created.iter().copied().collect();
    let both: Vec<OutPoint> = undo
        .spent
        .iter()
        .map(|(op, _, _)| *op)
        .filter(|op| created.contains(op))
        .collect();
    assert!(both.is_empty(), "outpoints in BOTH lists: {both:?}");
    Ok(())
}

/// LEGACY LOG COMPATIBILITY, pinned rather than asserted in a comment.
///
/// Undo logs written by this change and earlier are still on disk and still replayable, and they DO put
/// a same-block create-then-spend outpoint in both lists. This hand-builds a log in the old shape
/// and replays it through the real `undo_block`, so the retained create-then-spend skip is proven to still be doing
/// its job. Delete this test only when the skip itself can go.
#[test]
fn a_legacy_shaped_undo_log_still_replays_without_resurrecting_a_phantom() -> Result<()> {
    let tmp = TempDir::new()?;
    let db = open_db(&tmp);
    let height = 8u64;

    // State as it would be with the block APPLIED: the pre-block coin `spent_op` is gone, and the
    // block's own output `mid` is present.
    let spent_op = OutPoint { txid: [0xD1; 32], vout: 0 };
    let spent_out = TxOut { value: 4_200_000, script_pubkey: signer_addr() };
    let spent_meta = UtxoMeta { height: 2, coinbase: true };

    let mid = OutPoint { txid: [0xD2; 32], vout: 0 };
    let mid_out = TxOut { value: 111_000, script_pubkey: signer_addr() };
    put_utxo(&db, &mid, &mid_out)?;
    put_utxo_meta(&db, &mid, &UtxoMeta { height, coinbase: false })?;

    // The OLD log shape: `mid` was created and then spent inside the block, so it appears in BOTH
    // lists, and `spent_op` is an ordinary pre-block spend.
    let legacy = csd::state::utxo::UndoLog {
        spent: vec![
            (spent_op, spent_out.clone(), spent_meta),
            (mid, mid_out.clone(), UtxoMeta { height, coinbase: false }),
        ],
        created: vec![mid],
        app_undo: vec![],
    };

    let bh = [0xEE; 32];
    let bytes = csd::codec::consensus_bincode().serialize(&legacy).expect("serialize legacy undo");
    db.undo.insert(k_undo(&bh), bytes)?;

    undo_block(&db, &bh).expect("a legacy-shaped undo log must still replay");

    assert!(
        get_utxo(&db, &mid)?.is_none(),
        "the same-block create-then-spend outpoint must NOT be resurrected; removing the retained \
         skip would reintroduce the phantom for every log written before this change"
    );
    let restored = get_utxo(&db, &spent_op)?.expect("the ordinary pre-block spend must be restored");
    assert_eq!(restored.value, spent_out.value);
    Ok(())
}

/// The other legacy-log shape: TWO `undo.spent` entries for one outpoint.
///
/// Earlier binaries pushed a spent entry on EVERY spend, so a block that spent an outpoint,
/// recreated it via a replayed txid and spent it again produced two entries: the first holding the
/// pre-block coin, the second holding what the block itself wrote. Replaying that in order leaves the
/// LAST value in place, so the node ends up holding a coin the ancestor state never had. This pins
/// the first-entry-wins rule that makes such a log replay correctly.
#[test]
fn a_legacy_log_with_two_spent_entries_for_one_outpoint_restores_the_pre_block_value() -> Result<()> {
    let tmp = TempDir::new()?;
    let db = open_db(&tmp);
    let height = 8u64;

    let contested = OutPoint { txid: [0xD3; 32], vout: 0 };
    let pre_block = TxOut { value: 900_000_000, script_pubkey: signer_addr() };
    let within_block = TxOut { value: 7_000, script_pubkey: signer_addr() };

    // The old shape: first entry is the pre-block coin, second is the block's own recreation.
    // `contested` is NOT in `created`, because the block did not create it out of nothing.
    let legacy = csd::state::utxo::UndoLog {
        spent: vec![
            (contested, pre_block.clone(), UtxoMeta { height: 3, coinbase: false }),
            (contested, within_block, UtxoMeta { height, coinbase: false }),
        ],
        created: vec![],
        app_undo: vec![],
    };

    let bh = [0xEF; 32];
    let bytes = csd::codec::consensus_bincode().serialize(&legacy).expect("serialize legacy undo");
    db.undo.insert(k_undo(&bh), bytes)?;

    undo_block(&db, &bh).expect("a legacy log with a repeated outpoint must still replay");

    let restored = get_utxo(&db, &contested)?.expect("the contested outpoint must be restored");
    assert_eq!(
        restored.value, pre_block.value,
        "the FIRST spent entry holds the pre-block coin; restoring the later one leaves this node \
         holding a coin the ancestor state never had"
    );
    Ok(())
}
