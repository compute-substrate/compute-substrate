use anyhow::Result;
use tempfile::TempDir;

use csd::crypto::txid;
use csd::net::mempool::Mempool;
use csd::types::{AppPayload, OutPoint, Transaction, TxIn, TxOut};

mod testutil_chain;
use testutil_chain::open_db;

const SK: [u8; 32] = [7u8; 32];

fn h20(n: u8) -> [u8; 20] {
    [n; 20]
}

fn dummy_prev(n: u8) -> OutPoint {
    OutPoint { txid: [n; 32], vout: 0 }
}

fn make_tx(prev_tag: u8, value: u64, fee: u64) -> Transaction {
    let send = value - fee;

    let mut tx = Transaction {
        version: 1,
        inputs: vec![TxIn {
            prevout: dummy_prev(prev_tag),
            script_sig: vec![0u8; 99],
        }],
        outputs: vec![TxOut {
            value: send,
            script_pubkey: h20(prev_tag),
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

fn txids_in_mining_order(mp: &Mempool) -> Vec<[u8; 32]> {
    mp.select_for_block()
        .into_iter()
        .map(|tx| txid(&tx))
        .collect()
}

#[test]
fn mempool_policy_ordering_and_eviction() -> Result<()> {
    let tmp = TempDir::new()?;
    let db = open_db(&tmp)?;

    // Small cap for testing
    let mut mp = Mempool::new_with_limits(5, &db);

    // value constant so feerate ~ fee
    let v = 1_000_000;

    // Insert 5 txs with increasing fee
    let t1 = make_tx(1, v, 1_000);
    let t2 = make_tx(2, v, 2_000);
    let t3 = make_tx(3, v, 3_000);
    let t4 = make_tx(4, v, 4_000);
    let t5 = make_tx(5, v, 5_000);

    mp.insert(t1.clone())?;
    mp.insert(t2.clone())?;
    mp.insert(t3.clone())?;
    mp.insert(t4.clone())?;
    mp.insert(t5.clone())?;

    // ---- Ordering test ----
    let order = txids_in_mining_order(&mp);
    assert_eq!(
        order,
        vec![
            txid(&t5),
            txid(&t4),
            txid(&t3),
            txid(&t2),
            txid(&t1),
        ],
        "feerate ordering incorrect"
    );

    // ---- Eviction test (better tx evicts worst) ----
    let better = make_tx(6, v, 10_000);
    mp.insert(better.clone())?;

    let order = txids_in_mining_order(&mp);
    assert!(
        !order.contains(&txid(&t1)),
        "lowest feerate tx should be evicted"
    );
    assert!(
        order.contains(&txid(&better)),
        "better tx should be admitted"
    );

    // ---- Rejection test (worse tx rejected, state unchanged) ----
    let before = txids_in_mining_order(&mp);
    let worse = make_tx(7, v, 10); // tiny fee
    let r = mp.insert(worse.clone());
    assert!(r.is_err(), "worse tx should be rejected");

    let after = txids_in_mining_order(&mp);
    assert_eq!(before, after, "mempool mutated on rejected insert");

    // ---- Deterministic tie-break test ----
    let tie1 = make_tx(8, v, 6_000);
    let tie2 = make_tx(9, v, 6_000);

    mp.insert(tie1.clone())?;
    mp.insert(tie2.clone())?;

    let order = txids_in_mining_order(&mp);

    let a = txid(&tie1);
    let b = txid(&tie2);

    let pos_a = order.iter().position(|x| *x == a).unwrap();
    let pos_b = order.iter().position(|x| *x == b).unwrap();

    assert!(
        (a < b && pos_a < pos_b) || (b < a && pos_b < pos_a),
        "tie-break must be deterministic by txid"
    );

    Ok(())
}
