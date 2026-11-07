// tests/sighash_once_cost.rs
//
// Upstream's verify_sig recomputes `sighash(tx)` for each input, so refusing a wide tx whose last
// signature is bad costs inputs x tx size. With one sighash per tx the refusal costs about one signature check per input. Pinned as a ratio measured in the
// same process: mempool admission of such a tx against the bare signature checks of its inputs
// over one precomputed digest, both in thread CPU time.

use anyhow::Result;

use csd::crypto::{hash160, sighash, sign_tx_compact_secp256k1, verify_sig_digest};
use csd::net::mempool::Mempool;
use csd::state::db::{put_utxo, put_utxo_meta, Stores, UtxoMeta};
use csd::state::utxo::parse_scriptsig;
use csd::types::{AppPayload, OutPoint, Transaction, TxIn, TxOut};

mod testutil_chain;
use testutil_chain::fastest;

const SK: [u8; 32] = [0x31; 32];
const COIN_VALUE: u64 = 10_000;

fn funded_db(inputs: usize) -> Result<(tempfile::TempDir, Stores, Vec<OutPoint>)> {
    let tmp = tempfile::TempDir::new()?;
    let db = Stores::open(tmp.path().to_str().unwrap())?;
    let (_, pub33) = sign_tx_compact_secp256k1(&spend(&[], 0), SK);
    let owner = hash160(&pub33);
    let mut ops = Vec::with_capacity(inputs);
    for i in 0..inputs {
        let mut txid = [0x40u8; 32];
        txid[..4].copy_from_slice(&(i as u32).to_le_bytes());
        let op = OutPoint { txid, vout: 0 };
        put_utxo(&db, &op, &TxOut { value: COIN_VALUE, script_pubkey: owner })?;
        put_utxo_meta(&db, &op, &UtxoMeta { height: 1, coinbase: false })?;
        ops.push(op);
    }
    Ok((tmp, db, ops))
}

fn spend(ops: &[OutPoint], out_value: u64) -> Transaction {
    Transaction {
        version: 1,
        inputs: ops.iter().map(|op| TxIn { prevout: *op, script_sig: vec![] }).collect(),
        outputs: vec![TxOut { value: out_value, script_pubkey: [0x52; 20] }],
        locktime: 0,
        app: AppPayload::None,
    }
}

/// Every input signed by the owner (one sighash covers them all, so one signature serves).
fn signed(mut tx: Transaction) -> Transaction {
    let (sig64, pub33) = sign_tx_compact_secp256k1(&tx, SK);
    let mut ss = vec![64u8];
    ss.extend_from_slice(&sig64);
    ss.push(33);
    ss.extend_from_slice(&pub33);
    for inp in &mut tx.inputs {
        inp.script_sig = ss.clone();
    }
    tx
}

#[test]
fn refusing_a_wide_tx_costs_one_signature_check_per_input() -> Result<()> {
    const INPUTS: usize = 512;
    let (_tmp, db, ops) = funded_db(INPUTS)?;

    // Pays one unit less than it spends, with the last signature broken: every input but the
    // last verifies, then the last fails.
    let mut wide = signed(spend(&ops, COIN_VALUE * INPUTS as u64 - 1));
    wide.inputs[INPUTS - 1].script_sig[10] ^= 0x01;

    let mp = Mempool::new();
    let refusal = fastest(3, || {
        let err = mp.insert_checked(&db, wide.clone()).expect_err("the broken last signature is refused");
        assert!(err.to_string().contains("signature"), "{err:#}");
    });

    let parsed: Vec<_> = wide.inputs.iter().map(|i| parse_scriptsig(&i.script_sig).unwrap()).collect();
    let bare = fastest(3, || {
        let digest = sighash(&wide);
        for (sig64, pub33) in &parsed {
            let _ = verify_sig_digest(&digest, sig64, pub33);
        }
    });

    let ratio = refusal.as_secs_f64() / bare.as_secs_f64();
    println!("[sighash-cost] {INPUTS} inputs: refusal {refusal:?}, bare signature checks {bare:?}, ratio {ratio:.2}");
    assert!(
        ratio < 2.0,
        "refusing a {INPUTS}-input tx cost {ratio:.2} times its bare signature checks \
         ({refusal:?} against {bare:?}): the sighash is computed per input again"
    );
    assert_eq!(mp.len(), 0, "nothing is stored for a refused tx");

    // Paired honest path: a balanced 4-input spend of the same owner's coins is admitted.
    let honest = signed(spend(&ops[..4], COIN_VALUE * 4 - 1_000));
    assert!(mp.insert_checked(&db, honest)?, "a balanced 4-input spend is admitted");
    Ok(())
}
