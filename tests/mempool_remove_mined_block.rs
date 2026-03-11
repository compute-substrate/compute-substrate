// tests/mempool_remove_mined_block.rs

use anyhow::Result;
use tempfile::TempDir;

use csd::crypto::txid;
use csd::net::mempool::Mempool;
use csd::state::db::{k_utxo, Stores};
use csd::types::{AppPayload, Block, BlockHeader, OutPoint, Transaction, TxIn, TxOut};

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

fn make_tx(prev: OutPoint, value: u64, fee: u64, to: [u8; 20]) -> Transaction {
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
fn mempool_remove_mined_block_and_conflicts() -> Result<()> {
    let tmp = TempDir::new()?;
    let db = open_db(&tmp)?;
    let mp = Mempool::new();

    let owner = signer_addr(SK);
    let v = 1_000_000u64;

    insert_utxo(&db, dummy_prev(1), v, owner)?;
    insert_utxo(&db, dummy_prev(2), v, owner)?;
    insert_utxo(&db, dummy_prev(3), v, owner)?;
    insert_utxo(&db, dummy_prev(4), v, owner)?;

    let tx1 = make_tx(dummy_prev(1), v, 1_000, h20(1));
    let tx2 = make_tx(dummy_prev(2), v, 2_000, h20(2));
    let tx3 = make_tx(dummy_prev(3), v, 3_000, h20(3));

    assert_eq!(mp.insert_checked(&db, tx1.clone())?, true);
    assert_eq!(mp.insert_checked(&db, tx2.clone())?, true);
    assert_eq!(mp.insert_checked(&db, tx3.clone())?, true);
    assert_eq!(mp.len(), 3);

    // conflict tx is not inserted, but we’ll still test remove_conflicts path via mined inputs
    let conflict_with_tx3 = make_tx(dummy_prev(3), v, 4_000, h20(9));
    assert_eq!(mp.insert_checked(&db, conflict_with_tx3)?, false);
    assert_eq!(mp.len(), 3);

    let coinbase = Transaction {
        version: 1,
        inputs: vec![],
        outputs: vec![TxOut {
            value: 50_00000000,
            script_pubkey: h20(0xAA),
        }],
        locktime: 0,
        app: AppPayload::None,
    };

    // Mine tx2 only
    let blk = Block {
        header: BlockHeader {
            version: 1,
            prev: [0u8; 32],
            merkle_root: [0u8; 32],
            time: 1_700_000_000,
            bits: 0,
            nonce: 0,
        },
        txs: vec![coinbase, tx2.clone()],
    };

    let removed = mp.remove_mined_block(&blk);
    assert!(removed >= 1, "expected at least mined tx to be removed");

    assert!(!mp.contains(&txid(&tx2)));
    assert!(mp.contains(&txid(&tx1)));
    assert!(mp.contains(&txid(&tx3)));
    assert_eq!(mp.len(), 2);

    // Now mine a tx that spends prevout 3; that should remove tx3 from mempool
    let blk2 = Block {
        header: BlockHeader {
            version: 1,
            prev: [1u8; 32],
            merkle_root: [0u8; 32],
            time: 1_700_000_001,
            bits: 0,
            nonce: 0,
        },
        txs: vec![
            Transaction {
                version: 1,
                inputs: vec![],
                outputs: vec![TxOut {
                    value: 50_00000000,
                    script_pubkey: h20(0xBB),
                }],
                locktime: 0,
                app: AppPayload::None,
            },
            make_tx(dummy_prev(3), v, 5_000, h20(8)),
        ],
    };

    let removed2 = mp.remove_mined_block(&blk2);
    assert!(removed2 >= 1, "expected conflict cleanup to remove tx3");

    assert!(mp.contains(&txid(&tx1)));
    assert!(!mp.contains(&txid(&tx3)));
    assert_eq!(mp.len(), 1);

    Ok(())
}
