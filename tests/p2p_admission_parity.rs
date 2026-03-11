// tests/p2p_admission_parity.rs

use anyhow::{bail, Result};
use tempfile::TempDir;

use csd::crypto::txid;
use csd::net::mempool::Mempool;
use csd::state::db::{k_utxo, Stores};
use csd::types::{AppPayload, OutPoint, Transaction, TxIn, TxOut};

mod testutil_chain;
use testutil_chain::open_db;

const SK: [u8; 32] = [11u8; 32];

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

fn make_tx(prev_tag: u8, value: u64, fee: u64, to: [u8; 20]) -> Transaction {
    let send = value - fee;

    let mut tx = Transaction {
        version: 1,
        inputs: vec![TxIn {
            prevout: dummy_prev(prev_tag),
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

fn make_invalid_empty_inputs() -> Transaction {
    Transaction {
        version: 1,
        inputs: vec![],
        outputs: vec![TxOut {
            value: 1,
            script_pubkey: h20(0xEE),
        }],
        locktime: 0,
        app: AppPayload::None,
    }
}

fn txids_in_sample_order(mp: &Mempool) -> Vec<[u8; 32]> {
    mp.sample(1000).into_iter().map(|tx| txid(&tx)).collect()
}

// "RPC path": direct structured submit.
fn rpc_submit(mp: &Mempool, db: &Stores, tx: Transaction) -> Result<bool> {
    mp.insert_checked(db, tx)
}

// "P2P path": decode canonical wire bytes, then submit.
// This gives us a real admission-parity test at the boundary:
// same tx semantics whether it arrives as an in-memory object or over the wire.
fn peer_submit(mp: &Mempool, db: &Stores, tx: &Transaction) -> Result<bool> {
    let c = csd::codec::consensus_bincode();
    let raw = c.serialize(tx)?;
    let decoded: Transaction = c.deserialize(&raw)?;
    mp.insert_checked(db, decoded)
}

fn peer_submit_raw(mp: &Mempool, db: &Stores, raw: &[u8]) -> Result<bool> {
    let c = csd::codec::consensus_bincode();
    let decoded: Transaction = c.deserialize(raw)?;
    mp.insert_checked(db, decoded)
}

#[test]
fn p2p_admission_matches_rpc_path_for_valid_invalid_duplicate_and_conflict_cases() -> Result<()> {
    let tmp = TempDir::new()?;
    let db = open_db(&tmp)?;

    let owner = signer_addr(SK);
    let v = 1_000_000u64;

    for tag in 1u8..=6u8 {
        insert_utxo(&db, dummy_prev(tag), v, owner)?;
    }

    // Keep the two paths isolated so we can compare exact outcomes.
    let mp_rpc = Mempool::new();
    let mp_p2p = Mempool::new();

    // ----------------------------------------------------------------
    // 1) Valid tx: accepted identically and produces identical mempool state
    // ----------------------------------------------------------------
    let good = make_tx(1, v, 5_000, h20(1));

    let rpc_ok = rpc_submit(&mp_rpc, &db, good.clone())?;
    let p2p_ok = peer_submit(&mp_p2p, &db, &good)?;

    assert_eq!(rpc_ok, p2p_ok, "valid tx admission mismatch");
    assert!(rpc_ok, "valid tx should be accepted on both paths");

    assert_eq!(mp_rpc.len(), mp_p2p.len(), "len mismatch after valid admit");
    assert_eq!(
        txids_in_sample_order(&mp_rpc),
        txids_in_sample_order(&mp_p2p),
        "mempool ordering mismatch after valid admit"
    );

    // ----------------------------------------------------------------
    // 2) Duplicate tx: both should return Ok(false), no state drift
    // ----------------------------------------------------------------
    let rpc_dup = rpc_submit(&mp_rpc, &db, good.clone())?;
    let p2p_dup = peer_submit(&mp_p2p, &db, &good)?;

    assert_eq!(rpc_dup, p2p_dup, "duplicate tx behavior mismatch");
    assert!(!rpc_dup, "duplicate tx should return false on both paths");

    assert_eq!(mp_rpc.len(), mp_p2p.len(), "len mismatch after duplicate");
    assert_eq!(
        txids_in_sample_order(&mp_rpc),
        txids_in_sample_order(&mp_p2p),
        "mempool ordering mismatch after duplicate"
    );

    // ----------------------------------------------------------------
    // 3) Conflict tx: both should return Ok(false)
    // ----------------------------------------------------------------
    let conflict = make_tx(1, v, 7_000, h20(9)); // spends same prevout as `good`

    let rpc_conflict = rpc_submit(&mp_rpc, &db, conflict.clone())?;
    let p2p_conflict = peer_submit(&mp_p2p, &db, &conflict)?;

    assert_eq!(rpc_conflict, p2p_conflict, "conflict behavior mismatch");
    assert!(!rpc_conflict, "conflicting tx should return false on both paths");

    assert_eq!(mp_rpc.len(), mp_p2p.len(), "len mismatch after conflict");
    assert_eq!(
        txids_in_sample_order(&mp_rpc),
        txids_in_sample_order(&mp_p2p),
        "mempool ordering mismatch after conflict"
    );

    // ----------------------------------------------------------------
    // 4) Invalid-shape tx: both should error
    // ----------------------------------------------------------------
    let bad_shape = make_invalid_empty_inputs();

    let rpc_err = rpc_submit(&mp_rpc, &db, bad_shape.clone());
    let p2p_err = peer_submit(&mp_p2p, &db, &bad_shape);

    assert!(rpc_err.is_err(), "RPC path should reject invalid-shape tx");
    assert!(p2p_err.is_err(), "P2P path should reject invalid-shape tx");

    assert_eq!(mp_rpc.len(), mp_p2p.len(), "len mismatch after bad-shape reject");
    assert_eq!(
        txids_in_sample_order(&mp_rpc),
        txids_in_sample_order(&mp_p2p),
        "mempool ordering mismatch after bad-shape reject"
    );

    // ----------------------------------------------------------------
    // 5) Corrupt wire bytes: P2P decode should fail before admission
    // ----------------------------------------------------------------
    let mut raw = csd::codec::consensus_bincode().serialize(&make_tx(2, v, 2_000, h20(2)))?;
    if raw.is_empty() {
        bail!("serialized tx unexpectedly empty");
    }
    raw.truncate(raw.len() - 1);

    let corrupt = peer_submit_raw(&mp_p2p, &db, &raw);
    assert!(corrupt.is_err(), "corrupt wire payload should fail decode");

    // No state drift from corrupt payload
    assert_eq!(mp_rpc.len(), mp_p2p.len(), "len mismatch after corrupt raw bytes");
    assert_eq!(
        txids_in_sample_order(&mp_rpc),
        txids_in_sample_order(&mp_p2p),
        "mempool ordering mismatch after corrupt raw bytes"
    );

    Ok(())
}
