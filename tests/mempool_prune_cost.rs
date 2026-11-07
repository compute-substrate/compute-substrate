// tests/mempool_prune_cost.rs
//
// A prune that runs the full admission check (`validate_tx_for_mempool`), as upstream's does, on
// every held tx at every block and before every template, signatures included, inside the reorg
// under the chain lock, took about 28 s per block with the pool at its spent-input cap of 512-input
// txs. A held tx's signatures, owners and values cannot change, so prune re-checks only its spent
// outputs and its app state. Pinned as a ratio measured in the same process: one prune of a pool of
// valid 512-input txs against one signature check of each of their inputs. The paired honest
// paths: prune keeps every valid tx, and drops one whose spent output is gone.

use anyhow::Result;

use csd::crypto::{hash160, sighash, sign_tx_compact_secp256k1, txid, verify_sig_digest};
use csd::net::mempool::Mempool;
use csd::state::db::{del_utxo, put_utxo, put_utxo_meta, Stores, UtxoMeta};
use csd::state::utxo::parse_scriptsig;
use csd::types::{AppPayload, OutPoint, Transaction, TxIn, TxOut};

mod testutil_chain;
use testutil_chain::fastest;

const SK: [u8; 32] = [0x32; 32];
const INPUTS: usize = 512;
const TXS: usize = 8;
const COIN_VALUE: u64 = 10_000;

fn wide_tx(db: &Stores, owner: [u8; 20], n: usize) -> Result<Transaction> {
    let mut tx = Transaction {
        version: 1,
        inputs: (0..INPUTS as u32)
            .map(|i| TxIn { prevout: OutPoint { txid: [n as u8 + 1; 32], vout: i }, script_sig: vec![] })
            .collect(),
        outputs: vec![TxOut { value: COIN_VALUE * INPUTS as u64 - 100_000, script_pubkey: [0x53; 20] }],
        locktime: 0,
        app: AppPayload::None,
    };
    for inp in &tx.inputs {
        put_utxo(db, &inp.prevout, &TxOut { value: COIN_VALUE, script_pubkey: owner })?;
        put_utxo_meta(db, &inp.prevout, &UtxoMeta { height: 1, coinbase: false })?;
    }
    let (sig64, pub33) = sign_tx_compact_secp256k1(&tx, SK);
    let mut ss = vec![64u8];
    ss.extend_from_slice(&sig64);
    ss.push(33);
    ss.extend_from_slice(&pub33);
    for inp in &mut tx.inputs {
        inp.script_sig = ss.clone();
    }
    Ok(tx)
}

#[test]
fn prune_does_not_check_the_signatures_of_held_txs_again() -> Result<()> {
    let tmp = tempfile::TempDir::new()?;
    let db = Stores::open(tmp.path().to_str().unwrap())?;
    let probe = Transaction { version: 1, inputs: vec![], outputs: vec![], locktime: 0, app: AppPayload::None };
    let owner = hash160(&sign_tx_compact_secp256k1(&probe, SK).1);
    let txs: Vec<Transaction> = (0..TXS).map(|n| wide_tx(&db, owner, n)).collect::<Result<_>>()?;
    let mp = Mempool::new();
    for tx in &txs {
        assert!(mp.insert_checked(&db, tx.clone())?, "fixture: a valid wide tx is admitted");
    }

    let prune = fastest(3, || assert_eq!(mp.prune(&db), 0, "prune keeps every valid held tx"));
    let signatures = fastest(3, || {
        for tx in &txs {
            let digest = sighash(tx);
            for inp in &tx.inputs {
                let (sig64, pub33) = parse_scriptsig(&inp.script_sig).unwrap();
                verify_sig_digest(&digest, &sig64, &pub33).unwrap();
            }
        }
    });
    let ratio = prune.as_secs_f64() / signatures.as_secs_f64();
    println!(
        "[prune-cost] {TXS} held txs of {INPUTS} inputs: prune {prune:?}, their signature checks {signatures:?}, ratio {ratio:.3}"
    );
    assert!(
        ratio < 0.25,
        "one prune cost {ratio:.3} times the signature checks of the txs it holds ({prune:?} against \
         {signatures:?}): prune is checking signatures again"
    );
    assert_eq!(mp.len(), TXS);

    // Honest path of the recheck that stays: a held tx whose spent output is gone is dropped.
    del_utxo(&db, &txs[0].inputs[INPUTS - 1].prevout)?;
    assert_eq!(mp.prune(&db), 1);
    assert!(!mp.contains(&txid(&txs[0])) && mp.len() == TXS - 1);
    Ok(())
}
