use anyhow::Result;
use tempfile::TempDir;

use csd::crypto::txid;
use csd::net::mempool::Mempool;
use csd::state::db::{k_utxo, Stores};
use csd::types::{AppPayload, OutPoint, Transaction, TxIn, TxOut};

mod testutil_chain;
use testutil_chain::open_db;

const SK: [u8; 32] = [33u8; 32];

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

fn txids_in_sample_order(mp: &Mempool) -> Vec<[u8; 32]> {
    mp.sample(1000).into_iter().map(|tx| txid(&tx)).collect()
}

#[test]
fn mempool_count_cap_evicts_lowest_feerate_deterministically() -> Result<()> {
    let tmp = TempDir::new()?;
    let db = open_db(&tmp)?;

    let owner = signer_addr(SK);
    let v = 1_000_000u64;

    for tag in 1u8..=6u8 {
        insert_utxo(&db, dummy_prev(tag), v, owner)?;
    }

    let mp = Mempool::new_with_limits(3, 10_000_000, 100);

    let t1 = make_tx(1, v, 1_000, h20(1));
    let t2 = make_tx(2, v, 2_000, h20(2));
    let t3 = make_tx(3, v, 3_000, h20(3));

    assert_eq!(mp.insert_checked(&db, t1.clone())?, true);
    assert_eq!(mp.insert_checked(&db, t2.clone())?, true);
    assert_eq!(mp.insert_checked(&db, t3.clone())?, true);

    assert_eq!(mp.len(), 3);
    assert_eq!(
        txids_in_sample_order(&mp),
        vec![txid(&t3), txid(&t2), txid(&t1)]
    );

    let t4 = make_tx(4, v, 4_000, h20(4));
    assert_eq!(mp.insert_checked(&db, t4.clone())?, true);

    assert_eq!(mp.len(), 3);
    let order = txids_in_sample_order(&mp);
    assert_eq!(order, vec![txid(&t4), txid(&t3), txid(&t2)]);
    assert!(!mp.contains(&txid(&t1)));

    let weak = make_tx(5, v, 500, h20(5));
    let before = txids_in_sample_order(&mp);
    assert!(mp.insert_checked(&db, weak).is_err());
    let after = txids_in_sample_order(&mp);
    assert_eq!(before, after, "non-competitive insert must not mutate pool");

    Ok(())
}

#[test]
fn mempool_byte_cap_evicts_until_under_limit() -> Result<()> {
    let tmp = TempDir::new()?;
    let db = open_db(&tmp)?;

    let owner = signer_addr(SK);
    let v = 1_000_000u64;

    for tag in 1u8..=6u8 {
        insert_utxo(&db, dummy_prev(tag), v, owner)?;
    }

    let probe = make_tx(1, v, 1_000, h20(1));
    let one_tx_bytes = csd::codec::consensus_bincode().serialized_size(&probe)? as usize;

    let mp = Mempool::new_with_limits(100, one_tx_bytes * 3, 100);

    let t1 = make_tx(1, v, 1_000, h20(1));
    let t2 = make_tx(2, v, 2_000, h20(2));
    let t3 = make_tx(3, v, 3_000, h20(3));

    assert_eq!(mp.insert_checked(&db, t1.clone())?, true);
    assert_eq!(mp.insert_checked(&db, t2.clone())?, true);
    assert_eq!(mp.insert_checked(&db, t3.clone())?, true);

    assert_eq!(mp.len(), 3);
    assert!(mp.total_bytes() <= one_tx_bytes * 3);

    let t4 = make_tx(4, v, 4_000, h20(4));
    assert_eq!(mp.insert_checked(&db, t4.clone())?, true);

    assert_eq!(mp.len(), 3);
    assert!(mp.total_bytes() <= one_tx_bytes * 3);

    let order = txids_in_sample_order(&mp);
    assert_eq!(order, vec![txid(&t4), txid(&t3), txid(&t2)]);
    assert!(!mp.contains(&txid(&t1)));

    Ok(())
}

#[test]
fn mempool_equal_feerate_eviction_is_deterministic_by_txid() -> Result<()> {
    let tmp = TempDir::new()?;
    let db = open_db(&tmp)?;

    let owner = signer_addr(SK);
    let v = 1_000_000u64;

    for tag in 1u8..=5u8 {
        insert_utxo(&db, dummy_prev(tag), v, owner)?;
    }

    let mp = Mempool::new_with_limits(2, 10_000_000, 100);

    let tie_a = make_tx(1, v, 6_000, h20(10));
    let tie_b = make_tx(2, v, 6_000, h20(11));

    assert_eq!(mp.insert_checked(&db, tie_a.clone())?, true);
    assert_eq!(mp.insert_checked(&db, tie_b.clone())?, true);

    let a = txid(&tie_a);
    let b = txid(&tie_b);

    let initial = txids_in_sample_order(&mp);
    let expected_initial = if a < b { vec![a, b] } else { vec![b, a] };
    assert_eq!(initial, expected_initial);

    let higher = make_tx(3, v, 7_000, h20(12));
    assert_eq!(mp.insert_checked(&db, higher.clone())?, true);

    let hi = txid(&higher);
    let expected_survivor = if a < b { b } else { a };

    let final_order = txids_in_sample_order(&mp);
    assert_eq!(final_order, vec![hi, expected_survivor]);

    let evicted = if a < b { a } else { b };
    assert!(!mp.contains(&evicted));

    Ok(())
}
