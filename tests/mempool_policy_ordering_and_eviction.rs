use anyhow::Result;
use tempfile::TempDir;

use csd::crypto::txid;
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
fn mempool_policy_ordering_and_basic_admission() -> Result<()> {
    let tmp = TempDir::new()?;
    let db = open_db(&tmp)?;

    let mp = Mempool::new();

    let v = 1_000_000u64;
    let owner = signer_addr(SK);

    // Seed UTXOs so insert_checked can validate.
    // They must belong to the same signer that creates the spending txs.
    for tag in 1u8..=8u8 {
        insert_utxo(&db, dummy_prev(tag), v, owner)?;
    }

    let t1 = make_tx(1, v, 1_000, h20(1));
    let t2 = make_tx(2, v, 2_000, h20(2));
    let t3 = make_tx(3, v, 3_000, h20(3));
    let t4 = make_tx(4, v, 4_000, h20(4));
    let t5 = make_tx(5, v, 5_000, h20(5));

    assert_eq!(mp.insert_checked(&db, t1.clone())?, true);
    assert_eq!(mp.insert_checked(&db, t2.clone())?, true);
    assert_eq!(mp.insert_checked(&db, t3.clone())?, true);
    assert_eq!(mp.insert_checked(&db, t4.clone())?, true);
    assert_eq!(mp.insert_checked(&db, t5.clone())?, true);

    assert_eq!(mp.len(), 5);

    // Highest feerate first
    let order = txids_in_sample_order(&mp);
    assert_eq!(
        order,
        vec![txid(&t5), txid(&t4), txid(&t3), txid(&t2), txid(&t1)],
        "mempool ordering should be highest feerate first"
    );

    // Duplicate insert: Ok(false), no mutation
    let before = txids_in_sample_order(&mp);
    assert_eq!(mp.insert_checked(&db, t3.clone())?, false);
    let after = txids_in_sample_order(&mp);
    assert_eq!(before, after);

    // Conflict insert: Ok(false), no mutation
    let conflicting = make_tx(5, v, 6_000, h20(9));
    let before_conflict = txids_in_sample_order(&mp);
    assert_eq!(mp.insert_checked(&db, conflicting)?, false);
    let after_conflict = txids_in_sample_order(&mp);
    assert_eq!(before_conflict, after_conflict);

    // Low fee but valid
    let t6 = make_tx(6, v, 10, h20(6));
    assert_eq!(mp.insert_checked(&db, t6.clone())?, true);

    let order2 = txids_in_sample_order(&mp);
    assert_eq!(order2.first().copied(), Some(txid(&t5)));
    assert_eq!(order2.last().copied(), Some(txid(&t6)));

    // Tie-break determinism
    let tie_a = make_tx(7, v, 6_000, h20(7));
    let tie_b = make_tx(8, v, 6_000, h20(8));

    assert_eq!(mp.insert_checked(&db, tie_a.clone())?, true);
    assert_eq!(mp.insert_checked(&db, tie_b.clone())?, true);

    let order3 = txids_in_sample_order(&mp);
    let a = txid(&tie_a);
    let b = txid(&tie_b);

    let pos_a = order3.iter().position(|x| *x == a).unwrap();
    let pos_b = order3.iter().position(|x| *x == b).unwrap();

    assert!(
        (a < b && pos_a < pos_b) || (b < a && pos_b < pos_a),
        "equal-feerate txs must be ordered deterministically by txid"
    );

    Ok(())
}
