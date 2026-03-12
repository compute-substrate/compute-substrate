use anyhow::{ensure, Result};
use tempfile::TempDir;

use csd::chain::mine::{build_template_for_tests, coinbase};
use csd::crypto::txid;
use csd::net::mempool::Mempool;
use csd::state::db::{k_utxo, Stores};
use csd::types::{AppPayload, OutPoint, Transaction, TxIn, TxOut};

mod testutil_chain;
use testutil_chain::open_db;

const SK: [u8; 32] = [21u8; 32];

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

fn make_tx(
    prev_tag: u8,
    input_value: u64,
    fee: u64,
    to: [u8; 20],
    extra_outputs: usize,
) -> Transaction {
    let dust_total = extra_outputs as u64;
    let send = input_value - fee - dust_total;

    let mut outputs = vec![TxOut {
        value: send,
        script_pubkey: to,
    }];

    for _ in 0..extra_outputs {
        outputs.push(TxOut {
            value: 1,
            script_pubkey: h20(0xEE),
        });
    }

    let mut tx = Transaction {
        version: 1,
        inputs: vec![TxIn {
            prevout: dummy_prev(prev_tag),
            script_sig: vec![0u8; 99],
        }],
        outputs,
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

fn tx_bytes(tx: &Transaction) -> usize {
    csd::codec::consensus_bincode()
        .serialized_size(tx)
        .expect("serialized_size(tx)") as usize
}

fn admit_tx(db: &Stores, mp: &Mempool, tx: Transaction) -> Result<()> {
    let added = mp.insert_checked(db, tx)?;
    ensure!(added, "tx was not added to mempool");
    Ok(())
}

fn template_ids(
    db: &Stores,
    mp: &Mempool,
    height: u64,
    max_mempool_txs: usize,
    byte_cap: usize,
) -> Result<Vec<[u8; 32]>> {
    let (_txs, ids, _fees) =
        build_template_for_tests(db, mp, h20(0xAA), height, max_mempool_txs, byte_cap)?;
    Ok(ids)
}

#[test]
fn higher_feerate_beats_lower_feerate_even_if_absolute_fee_is_smaller() -> Result<()> {
    let tmp = TempDir::new()?;
    let db = open_db(&tmp)?;
    let mp = Mempool::new();

    let owner = signer_addr(SK);
    let v = 1_000_000u64;

    insert_utxo(&db, dummy_prev(1), v, owner)?;
    insert_utxo(&db, dummy_prev(2), v, owner)?;

    let tx_high_feerate = make_tx(1, v, 4_000, h20(0x10), 0);
    let tx_low_feerate = make_tx(2, v, 6_000, h20(0x20), 30);

    let id_hi = txid(&tx_high_feerate);
    let id_lo = txid(&tx_low_feerate);

    admit_tx(&db, &mp, tx_high_feerate)?;
    admit_tx(&db, &mp, tx_low_feerate)?;

    let ids = template_ids(&db, &mp, 1, 16, usize::MAX)?;

    assert_eq!(ids, vec![id_hi, id_lo]);

    Ok(())
}

#[test]
fn equal_feerate_tie_breaks_by_txid() -> Result<()> {
    let tmp = TempDir::new()?;
    let db = open_db(&tmp)?;
    let mp = Mempool::new();

    let owner = signer_addr(SK);
    let v = 1_000_000u64;

    insert_utxo(&db, dummy_prev(11), v, owner)?;
    insert_utxo(&db, dummy_prev(12), v, owner)?;

    let tx_a = make_tx(11, v, 5_000, h20(0x31), 5);
    let tx_b = make_tx(12, v, 5_000, h20(0x32), 5);

    let id_a = txid(&tx_a);
    let id_b = txid(&tx_b);

    admit_tx(&db, &mp, tx_a)?;
    admit_tx(&db, &mp, tx_b)?;

    let ids = template_ids(&db, &mp, 1, 16, usize::MAX)?;

    let expected = if id_a < id_b {
        vec![id_a, id_b]
    } else {
        vec![id_b, id_a]
    };

    assert_eq!(ids, expected);

    Ok(())
}

#[test]
fn block_byte_pressure_skips_deterministically_and_preserves_order() -> Result<()> {
    let tmp = TempDir::new()?;
    let db = open_db(&tmp)?;
    let mp = Mempool::new();

    let owner = signer_addr(SK);
    let v = 1_000_000u64;

    insert_utxo(&db, dummy_prev(21), v, owner)?;
    insert_utxo(&db, dummy_prev(22), v, owner)?;
    insert_utxo(&db, dummy_prev(23), v, owner)?;

    let tx1 = make_tx(21, v, 8_000, h20(0x41), 0);
    let tx2 = make_tx(22, v, 7_000, h20(0x42), 80);
    let tx3 = make_tx(23, v, 6_000, h20(0x43), 0);

    let id1 = txid(&tx1);
    let id2 = txid(&tx2);
    let id3 = txid(&tx3);

    admit_tx(&db, &mp, tx1.clone())?;
    admit_tx(&db, &mp, tx2.clone())?;
    admit_tx(&db, &mp, tx3.clone())?;

    let cb = coinbase(h20(0xAA), csd::params::block_reward(1), 1, None);
    let cb_bytes = tx_bytes(&cb);

    let cap = cb_bytes + tx_bytes(&tx1) + tx_bytes(&tx3);

    let ids = template_ids(&db, &mp, 1, 16, cap)?;

    assert_eq!(ids, vec![id1, id3]);
    assert!(!ids.contains(&id2));

    Ok(())
}

#[test]
fn same_mempool_and_db_state_yields_identical_included_txids() -> Result<()> {
    let tmp1 = TempDir::new()?;
    let tmp2 = TempDir::new()?;

    let db1 = open_db(&tmp1)?;
    let db2 = open_db(&tmp2)?;

    let mp1 = Mempool::new();
    let mp2 = Mempool::new();

    let owner = signer_addr(SK);
    let v = 1_000_000u64;

    for tag in [31u8, 32u8, 33u8, 34u8] {
        insert_utxo(&db1, dummy_prev(tag), v, owner)?;
        insert_utxo(&db2, dummy_prev(tag), v, owner)?;
    }

    let txs = vec![
        make_tx(31, v, 9_000, h20(0x51), 0),
        make_tx(32, v, 5_000, h20(0x52), 10),
        make_tx(33, v, 7_000, h20(0x53), 3),
        make_tx(34, v, 7_000, h20(0x54), 3),
    ];

    for tx in txs.clone() {
        admit_tx(&db1, &mp1, tx)?;
    }

    for tx in txs {
        admit_tx(&db2, &mp2, tx)?;
    }

    let ids1 = template_ids(&db1, &mp1, 1, 16, usize::MAX)?;
    let ids2 = template_ids(&db2, &mp2, 1, 16, usize::MAX)?;

    assert_eq!(ids1, ids2);

    Ok(())
}
