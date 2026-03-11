// tests/mempool_standardness_rejection.rs

use anyhow::Result;
use tempfile::TempDir;

use csd::net::mempool::Mempool;
use csd::state::db::{k_utxo, Stores};
use csd::types::{AppPayload, OutPoint, Transaction, TxIn, TxOut};

mod testutil_chain;
use testutil_chain::open_db;

const SK: [u8; 32] = [7u8; 32];

fn h20(n: u8) -> [u8; 20] {
    [n; 20]
}

fn signer_addr(sk32: [u8; 32]) -> [u8; 20] {
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

    let (_sig64, pub33) = csd::crypto::sign_tx_compact_secp256k1(&dummy, sk32);
    csd::crypto::hash160(&pub33)
}

fn dummy_prev(n: u8) -> OutPoint {
    OutPoint {
        txid: [n; 32],
        vout: 0,
    }
}

fn insert_utxo(db: &Stores, op: OutPoint, value: u64, owner: [u8; 20]) -> Result<()> {
    let out = TxOut {
        value,
        script_pubkey: owner,
    };

    db.utxo.insert(
        k_utxo(&op),
        csd::codec::consensus_bincode().serialize(&out)?,
    )?;

    Ok(())
}

fn signed_basic_tx(prev: OutPoint, value: u64, fee: u64, to: [u8; 20]) -> Transaction {
    let send = value - fee;

    let mut tx = Transaction {
        version: 1,
        inputs: vec![TxIn {
            prevout: prev,
            script_sig: vec![0u8; 99],
        }],
        outputs: vec![TxOut {
            value: send,
            script_pubkey: to,
        }],
        locktime: 0,
        app: AppPayload::None,
    };

    let (sig64, pub33) = csd::crypto::sign_tx_compact_secp256k1(&tx, SK);

    let mut ss = Vec::with_capacity(99);
    ss.push(64);
    ss.extend_from_slice(&sig64);
    ss.push(33);
    ss.extend_from_slice(&pub33);
    tx.inputs[0].script_sig = ss;

    tx
}

#[test]
fn mempool_rejects_invalid_shape_and_nonstandard_txs() -> Result<()> {
    let tmp = TempDir::new()?;
    let db = open_db(&tmp)?;
    let mp = Mempool::new();

    let owner = signer_addr(SK);
    let v = 1_000_000u64;

    // Seed spendable UTXOs
    for tag in 1u8..=8u8 {
        insert_utxo(&db, dummy_prev(tag), v, owner)?;
    }

    // Control: valid tx must be accepted
    let good = signed_basic_tx(dummy_prev(1), v, 1_000, h20(1));
    assert_eq!(mp.insert_checked(&db, good)?, true);
    assert_eq!(mp.len(), 1);

    // 1) No inputs (coinbase-like) must be rejected
    let no_inputs = Transaction {
        version: 1,
        inputs: vec![],
        outputs: vec![TxOut {
            value: v,
            script_pubkey: h20(2),
        }],
        locktime: 0,
        app: AppPayload::None,
    };
    assert!(mp.insert_checked(&db, no_inputs).is_err());
    assert_eq!(mp.len(), 1);

    // 2) Missing UTXO must be rejected
    let missing_utxo = signed_basic_tx(dummy_prev(99), v, 1_000, h20(3));
    assert!(mp.insert_checked(&db, missing_utxo).is_err());
    assert_eq!(mp.len(), 1);

    // 3) Negative fee / overspend must be rejected
    let overspend = signed_basic_tx(dummy_prev(2), v, 0, h20(4));
    let mut overspend_bad = overspend.clone();
    overspend_bad.outputs[0].value = v + 1;
    assert!(mp.insert_checked(&db, overspend_bad).is_err());
    assert_eq!(mp.len(), 1);

    // 4) Bad script_sig shape must be rejected
    let mut bad_scriptsig = signed_basic_tx(dummy_prev(3), v, 1_000, h20(5));
    bad_scriptsig.inputs[0].script_sig = vec![1, 2, 3, 4];
    assert!(mp.insert_checked(&db, bad_scriptsig).is_err());
    assert_eq!(mp.len(), 1);

    // 5) Duplicate prevout inside same tx should be rejected
    let mut dup_prevout = signed_basic_tx(dummy_prev(4), v, 1_000, h20(6));
    dup_prevout.inputs.push(dup_prevout.inputs[0].clone());
    assert!(mp.insert_checked(&db, dup_prevout).is_err());
    assert_eq!(mp.len(), 1);

    // 6) Zero-output tx should be rejected
    let mut zero_outputs = signed_basic_tx(dummy_prev(5), v, 1_000, h20(7));
    zero_outputs.outputs.clear();
    let (sig64, pub33) = csd::crypto::sign_tx_compact_secp256k1(&zero_outputs, SK);
    let mut ss = Vec::with_capacity(99);
    ss.push(64);
    ss.extend_from_slice(&sig64);
    ss.push(33);
    ss.extend_from_slice(&pub33);
    zero_outputs.inputs[0].script_sig = ss;
    assert!(mp.insert_checked(&db, zero_outputs).is_err());
    assert_eq!(mp.len(), 1);

    // 7) Tampered signature must be rejected
    let mut bad_sig = signed_basic_tx(dummy_prev(6), v, 1_000, h20(8));
    bad_sig.inputs[0].script_sig[10] ^= 0x01;
    assert!(mp.insert_checked(&db, bad_sig).is_err());
    assert_eq!(mp.len(), 1);

    // 8) Mempool conflict still must not mutate pool
    let valid_a = signed_basic_tx(dummy_prev(7), v, 2_000, h20(9));
    let valid_b_conflict = signed_basic_tx(dummy_prev(7), v, 3_000, h20(10));

    assert_eq!(mp.insert_checked(&db, valid_a)?, true);
    assert_eq!(mp.len(), 2);

    // conflict returns Ok(false), not Err
    assert_eq!(mp.insert_checked(&db, valid_b_conflict)?, false);
    assert_eq!(mp.len(), 2);

    Ok(())
}
