// tests/sighash_once_differential.rs
//
// `validate_tx_inputs_outputs` verifies every input against one sighash per tx
// (`crypto::TxSigChecker`) instead of `verify_sig` recomputing it per input. `sighash(tx)` takes no
// input index, so accept and reject cannot change; this differential checks it on real mainnet
// transactions. The reference is upstream main d168f70's code, copied below verbatim: `verify_sig` from
// src/crypto/mod.rs and the input loop of `validate_tx_inputs_outputs` from src/state/utxo.rs.
//
// Corpus: tests/fixtures/mainnet_sighash_corpus.txt, a sample of mainnet transactions with the
// outputs they spend (one per line: the tx as consensus bincode hex, then `value:script_pubkey`
// per input). CSD_SIGHASH_CORPUS=<path> runs a larger file of the same format.
//
// Each tx is checked as mined and in five altered forms that make one input fail at a different
// step: a flipped signature byte on the last input, the last signature in its high-S form, a wrong
// pubkey tag byte on a middle input, the first input's pubkey replaced by another key's, and the
// last input's spent output missing. For every form, each input's verdict from the reference
// `verify_sig`, from `crypto::verify_sig` and from one `TxSigChecker` must agree (Ok, or the same
// error text), and for transactions without an app payload the whole admission check
// (`validate_tx_for_mempool`, whose other steps are no-ops for them) must give the reference
// loop's verdict.

use anyhow::{bail, Context, Result};
use secp256k1::{ecdsa::Signature, Message, PublicKey, Secp256k1};

use csd::crypto::{hash160, sighash, txid, verify_sig, TxSigChecker};
use csd::state::db::{del_utxo, get_utxo, put_utxo, Stores};
use csd::state::utxo::{parse_scriptsig, validate_tx_for_mempool};
use csd::types::{AppPayload, Hash20, OutPoint, Transaction, TxOut};

// ---- reference: upstream main d168f70 src/crypto/mod.rs verify_sig, verbatim ----
fn old_verify_sig(tx: &Transaction, sig64: &[u8; 64], pub33: &[u8]) -> Result<()> {
    if pub33.len() != 33 {
        bail!("pubkey must be 33 bytes compressed");
    }

    let digest = sighash(tx);
    let msg = Message::from_digest_slice(&digest)?;

    let pk = PublicKey::from_slice(pub33)?;

    // Parse compact sig
    let sig = Signature::from_compact(sig64)?;

    // Enforce LOW-S canonicality as a consensus rule.
    // If normalizing would change the signature, it was high-S => reject.
    let mut norm = sig;
    norm.normalize_s();
    if norm.serialize_compact() != sig.serialize_compact() {
        bail!("non-canonical signature (high-S)");
    }

    Secp256k1::verification_only().verify_ecdsa(&msg, &sig, &pk)?;
    Ok(())
}

// ---- reference: upstream main d168f70 src/state/utxo.rs validate_tx_inputs_outputs, verbatim ----
fn old_validate_tx_inputs_outputs(db: &Stores, tx: &Transaction) -> Result<(u64, u64, u64)> {
    let mut in_sum: u64 = 0;

    for inp in &tx.inputs {
        let prev = get_utxo(db, &inp.prevout)?.ok_or_else(|| anyhow::anyhow!("missing utxo"))?;

        let (sig64, pub33) = parse_scriptsig(&inp.script_sig)?;

        // script_pubkey is Hash20; compute address hash from pubkey
        let addr20: Hash20 = hash160(&pub33);
        if prev.script_pubkey != addr20 {
            bail!("pubkey hash mismatch");
        }

        // CONSENSUS: signature verifies over global tx sighash.
        old_verify_sig(tx, &sig64, &pub33)?;

        in_sum = in_sum
            .checked_add(prev.value)
            .ok_or_else(|| anyhow::anyhow!("overflow"))?;
    }

    let mut out_sum: u64 = 0;
    for out in &tx.outputs {
        out_sum = out_sum
            .checked_add(out.value)
            .ok_or_else(|| anyhow::anyhow!("overflow"))?;
    }

    if out_sum > in_sum {
        bail!("outputs exceed inputs");
    }

    let fee = in_sum - out_sum;
    Ok((in_sum, out_sum, fee))
}

struct CorpusTx {
    tx: Transaction,
    prevouts: Vec<TxOut>,
}

fn load_corpus() -> Result<(String, Vec<CorpusTx>)> {
    let path = std::env::var("CSD_SIGHASH_CORPUS").unwrap_or_else(|_| {
        concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fixtures/mainnet_sighash_corpus.txt").to_string()
    });
    let text = std::fs::read_to_string(&path).with_context(|| format!("read {path}"))?;
    let mut out = Vec::new();
    for (n, line) in text.lines().enumerate() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let mut fields = line.split_whitespace();
        let tx_hex = fields.next().context("empty line")?;
        let tx: Transaction = csd::codec::consensus_bincode()
            .deserialize(&hex::decode(tx_hex)?)
            .with_context(|| format!("{path}:{}: decode tx", n + 1))?;
        let mut prevouts = Vec::new();
        for f in fields {
            let (v, spk) = f.split_once(':').context("prevout field is value:script_pubkey")?;
            let spk: Hash20 = hex::decode(spk)?.try_into().map_err(|_| anyhow::anyhow!("spk length"))?;
            prevouts.push(TxOut { value: v.parse()?, script_pubkey: spk });
        }
        if prevouts.len() != tx.inputs.len() {
            bail!("{path}:{}: {} prevouts for {} inputs", n + 1, prevouts.len(), tx.inputs.len());
        }
        out.push(CorpusTx { tx, prevouts });
    }
    Ok((path, out))
}

fn verdict<T>(r: &Result<T>) -> Option<String> {
    r.as_ref().err().map(|e| e.to_string())
}

/// n - s for the secp256k1 group order n: the high-S twin of a low-S signature.
fn high_s(sig64: &[u8; 64]) -> [u8; 64] {
    const N: [u8; 32] = [
        0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFE,
        0xBA, 0xAE, 0xDC, 0xE6, 0xAF, 0x48, 0xA0, 0x3B, 0xBF, 0xD2, 0x5E, 0x8C, 0xD0, 0x36, 0x41, 0x41,
    ];
    let mut out = *sig64;
    let mut borrow = 0i16;
    for i in (0..32).rev() {
        let d = N[i] as i16 - sig64[32 + i] as i16 - borrow;
        borrow = if d < 0 { 1 } else { 0 };
        out[32 + i] = (d + 256 * borrow) as u8;
    }
    out
}

/// The altered forms of a mined tx, each with the outpoint to leave out of the store (if any).
fn variants(tx: &Transaction) -> Vec<(&'static str, Transaction, Option<OutPoint>)> {
    let last = tx.inputs.len() - 1;
    let mid = tx.inputs.len() / 2;
    let mut v = vec![("as mined", tx.clone(), None)];

    let mut t = tx.clone();
    t.inputs[last].script_sig[40] ^= 0x01;
    v.push(("flipped signature byte, last input", t, None));

    let mut t = tx.clone();
    let mut sig64 = [0u8; 64];
    sig64.copy_from_slice(&t.inputs[last].script_sig[1..65]);
    t.inputs[last].script_sig[1..65].copy_from_slice(&high_s(&sig64));
    v.push(("high-S signature, last input", t, None));

    let mut t = tx.clone();
    t.inputs[mid].script_sig[65] = 32;
    v.push(("wrong pubkey tag byte, middle input", t, None));

    let mut t = tx.clone();
    let other = csd::crypto::sign_tx_compact_secp256k1(tx, [0x77; 32]).1;
    t.inputs[0].script_sig[66..99].copy_from_slice(&other);
    v.push(("another key's pubkey, first input", t, None));

    v.push(("spent output missing, last input", tx.clone(), Some(tx.inputs[last].prevout)));
    v
}

#[test]
fn hoisted_sighash_verification_matches_the_per_input_reference_on_mainnet_txs() -> Result<()> {
    let (path, corpus) = load_corpus()?;
    assert!(!corpus.is_empty(), "empty corpus {path}");

    let tmp = tempfile::TempDir::new()?;
    let db = Stores::open(tmp.path().to_str().unwrap())?;
    for c in &corpus {
        for (inp, out) in c.tx.inputs.iter().zip(&c.prevouts) {
            put_utxo(&db, &inp.prevout, out)?;
        }
    }

    let (mut txs, mut inputs, mut checks, mut whole, mut mined_ok) = (0usize, 0usize, 0usize, 0usize, 0usize);
    let mut refusals: std::collections::BTreeMap<String, usize> = Default::default();
    for c in &corpus {
        txs += 1;
        inputs += c.tx.inputs.len();
        for (label, v, missing) in variants(&c.tx) {
            // Per input: the reference, the new wrapper and one checker for the whole tx agree.
            let mut checker = TxSigChecker::new(&v);
            for (i, inp) in v.inputs.iter().enumerate() {
                let Ok((sig64, pub33)) = parse_scriptsig(&inp.script_sig) else { continue };
                let old = verdict(&old_verify_sig(&v, &sig64, &pub33));
                assert_eq!(verdict(&verify_sig(&v, &sig64, &pub33)), old, "{label}: input {i} of 0x{}", hex::encode(txid(&v)));
                assert_eq!(verdict(&checker.verify(&sig64, &pub33)), old, "{label}: input {i} of 0x{}", hex::encode(txid(&v)));
                checks += 1;
            }

            // Whole tx, for txs whose admission adds nothing after the input loop.
            if matches!(v.app, AppPayload::None) {
                let saved = match missing {
                    Some(op) => {
                        let o = get_utxo(&db, &op)?.context("fixture: prevout stored")?;
                        del_utxo(&db, &op)?;
                        Some((op, o))
                    }
                    None => None,
                };
                let old = verdict(&old_validate_tx_inputs_outputs(&db, &v));
                let new = verdict(&validate_tx_for_mempool(&db, &v));
                if let Some((op, o)) = saved {
                    put_utxo(&db, &op, &o)?;
                }
                assert_eq!(new, old, "{label}: 0x{}", hex::encode(txid(&v)));
                if label == "as mined" {
                    assert_eq!(old, None, "a mined tx must pass the reference: 0x{}", hex::encode(txid(&v)));
                    mined_ok += 1;
                } else {
                    *refusals.entry(old.unwrap_or_else(|| "accepted".into())).or_default() += 1;
                }
                whole += 1;
            }
        }
    }
    println!(
        "[sighash-differential] corpus={path} txs={txs} inputs={inputs} per-input checks={checks} \
         whole-tx checks={whole} (mined txs accepted: {mined_ok}) altered-form verdicts={refusals:?}"
    );
    Ok(())
}
