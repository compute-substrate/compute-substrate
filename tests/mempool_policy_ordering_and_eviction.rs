use anyhow::Result;
use tempfile::TempDir;

use csd::crypto::txid;
use csd::net::mempool::Mempool;
use csd::state::db::{k_utxo, Stores, Utxo};
use csd::types::{AppPayload, OutPoint, Transaction, TxIn, TxOut};

mod testutil_chain;
use testutil_chain::open_db;

const SK: [u8; 32] = [7u8; 32];

fn h20(n: u8) -> [u8; 20] {
    [n; 20]
}

fn dummy_prev(n: u8) -> OutPoint {
    OutPoint {
        txid: [n; 32],
        vout: 0,
    }
}

fn insert_utxo(db: &Stores, op: OutPoint, value: u64, owner: [u8; 20]) -> Result<()> {
    let u = Utxo {
        value,
        script_pubkey: owner,
        height: 1,
        coinbase: false,
    };
    db.utxo.insert(k_utxo(&op), csd::codec::consensus_bincode().serialize(&u)?)?;
    Ok(())
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

fn txids_in_sample_order(mp: &Mempool) -> Vec<[u8; 32]> {
    mp.sample(1000).into_iter().map(|tx| txid(&tx)).collect()
}

#[test]
fn mempool_policy_ordering_and_basic_admission() -> Result<()> {
    let tmp = TempDir::new()?;
    let db = open_db(&tmp)?;

    let mp = Mempool::new();

    let v = 1_000_000u64;

    // Seed backing UTXOs so insert_checked() can validate against canonical UTXO set.
    for tag in 1u8..=7u8 {
        insert_utxo(&db, dummy_prev(tag), v, h20(tag))?;
    }

    let t1 = make_tx(1, v, 1_000);
    let t2 = make_tx(2, v, 2_000);
    let t3 = make_tx(3, v, 3_000);
    let t4 = make_tx(4, v, 4_000);
    let t5 = make_tx(5, v, 5_000);

    assert_eq!(mp.insert_checked(&db, t1.clone())?, true);
    assert_eq!(mp.insert_checked(&db, t2.clone())?, true);
    assert_eq!(mp.insert_checked(&db, t3.clone())?, true);
    assert_eq!(mp.insert_checked(&db, t4.clone())?, true);
    assert_eq!(mp.insert_checked(&db, t5.clone())?, true);

    assert_eq!(mp.len(), 5);

    // Deterministic high-feerate-first ordering via sample()
    let order = txids_in_sample_order(&mp);
    assert_eq!(
        order,
        vec![txid(&t5), txid(&t4), txid(&t3), txid(&t2), txid(&t1)],
        "mempool sample ordering should be highest feerate first"
    );

    // Duplicate insert should return Ok(false), not mutate state.
    let before = txids_in_sample_order(&mp);
    assert_eq!(mp.insert_checked(&db, t3.clone())?, false);
    let after = txids_in_sample_order(&mp);
    assert_eq!(before, after, "duplicate insert mutated mempool");

    // Conflict insert should return Ok(false), not mutate state.
    let conflicting = make_tx(5, v, 6_000); // spends same prevout as t5
    let before_conflict = txids_in_sample_order(&mp);
    assert_eq!(mp.insert_checked(&db, conflicting)?, false);
    let after_conflict = txids_in_sample_order(&mp);
    assert_eq!(before_conflict, after_conflict, "conflict insert mutated mempool");

    // Low-fee but valid tx should still be admitted if above policy floor.
    let t6 = make_tx(6, v, 10);
    assert_eq!(mp.insert_checked(&db, t6.clone())?, true);

    let order2 = txids_in_sample_order(&mp);
    assert_eq!(order2.first().copied(), Some(txid(&t5)));
    assert_eq!(order2.last().copied(), Some(txid(&t6)));

    // Tie-break determinism: equal fee/value => equal feerate, ordered by txid.
    let tie_a = make_tx(7, v, 6_000);
    insert_utxo(&db, dummy_prev(8), v, h20(8))?;
    let tie_b = make_tx(8, v, 6_000);

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
