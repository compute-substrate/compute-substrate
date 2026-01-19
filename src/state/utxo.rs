use anyhow::{Result, bail};
use serde::{Serialize, Deserialize};

use crate::types::{Block, Transaction, TxOut, OutPoint, AppPayload};
use crate::crypto::{txid, verify_sig, hash160};
use crate::params::{MIN_FEE_PROPOSE, MIN_FEE_ATTEST, BLOCK_REWARD};
use crate::state::db::{Stores, get_utxo, put_utxo, del_utxo, k_undo};

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct UndoLog {
    pub spent: Vec<(OutPoint, TxOut)>, // restore on undo
    pub created: Vec<OutPoint>,        // delete on undo
    pub app_keys_inserted: Vec<Vec<u8>>, // delete on undo (app tree keys)
}

fn parse_scriptsig(sig: &[u8]) -> Result<([u8;64], Vec<u8>)> {
    // [sig_len u8][sig64][pub_len u8][pub33]
    if sig.len() < 1 + 64 + 1 + 33 { bail!("bad scriptsig"); }
    let sig_len = sig[0] as usize;
    if sig_len != 64 { bail!("expected 64-byte compact sig"); }
    let mut sig64 = [0u8;64];
    sig64.copy_from_slice(&sig[1..65]);
    let pub_len = sig[65] as usize;
    if pub_len != 33 { bail!("expected 33-byte compressed pubkey"); }
    let pub33 = sig[66..99].to_vec();
    Ok((sig64, pub33))
}

fn is_coinbase(tx: &Transaction) -> bool {
    tx.inputs.len() == 1 && tx.inputs[0].prevout.txid == [0u8;32] && tx.inputs[0].prevout.vout == u32::MAX
}

pub fn validate_and_apply_block(db: &Stores, block: &Block, now_epoch: u64) -> Result<UndoLog> {
    // tx[0] must be coinbase
    if block.txs.is_empty() { bail!("empty block"); }
    if !is_coinbase(&block.txs[0]) { bail!("first tx must be coinbase"); }

    let mut undo = UndoLog { spent: vec![], created: vec![], app_keys_inserted: vec![] };

    // Apply non-coinbase txs first to compute fees; then coinbase.
    let mut total_fees: i128 = 0;

    for (i, tx) in block.txs.iter().enumerate() {
        if i == 0 { continue; }

        let (in_sum, out_sum, fee) = validate_tx_inputs_outputs(db, tx)?;
        enforce_app_fee_floor(tx, fee as u64)?;
        total_fees += fee as i128;

        // Spend inputs
        for inp in &tx.inputs {
            let prev = get_utxo(db, &inp.prevout)?.ok_or_else(|| anyhow::anyhow!("missing utxo"))?;
            undo.spent.push((inp.prevout, prev.clone()));
            del_utxo(db, &inp.prevout)?;
        }

        // Create outputs
        let txh = txid(tx);
        for (vout, out) in tx.outputs.iter().enumerate() {
            let op = OutPoint { txid: txh, vout: vout as u32 };
            put_utxo(db, &op, out)?;
            undo.created.push(op);
        }

        // App state (reorg-safe via undo keys)
        crate::state::app::apply_app(db, tx, now_epoch, &mut undo.app_keys_inserted)?;
        // (apply_app must only INSERT keys it records)
    }

    // Coinbase: allow paying reward + fees
    {
        let cb = &block.txs[0];
        if cb.outputs.len() != 1 { bail!("coinbase must have 1 output"); }
        let expected = (BLOCK_REWARD as i128 + total_fees) as i128;
        if (cb.outputs[0].value as i128) != expected {
            bail!("coinbase value wrong: got {}, expected {}", cb.outputs[0].value, expected);
        }

        let cbh = txid(cb);
        let op = OutPoint { txid: cbh, vout: 0 };
        put_utxo(db, &op, &cb.outputs[0])?;
        undo.created.push(op);
    }

    // Save undo log keyed by block hash
    let bh = crate::chain::index::header_hash(&block.header);
    db.undo.insert(k_undo(&bh), bincode::serialize(&undo)?)?;
    Ok(undo)
}

pub fn undo_block(db: &Stores, block_hash: &[u8;32]) -> Result<()> {
    let Some(v) = db.undo.get(k_undo(block_hash))? else { bail!("missing undo"); };
    let undo: UndoLog = bincode::deserialize(&v)?;

    // Undo app inserts
    for k in undo.app_keys_inserted {
        db.app.remove(k)?;
    }

    // Delete created UTXOs
    for op in undo.created {
        del_utxo(db, &op)?;
    }

    // Restore spent UTXOs
    for (op, out) in undo.spent {
        put_utxo(db, &op, &out)?;
    }

    // remove undo log itself (optional; keep for debugging? we remove to be clean)
    db.undo.remove(k_undo(block_hash))?;
    Ok(())
}

fn validate_tx_inputs_outputs(db: &Stores, tx: &Transaction) -> Result<(u64,u64,i64)> {
    if tx.inputs.is_empty() { bail!("no inputs"); }

    let txh = crate::crypto::txid(tx);

    let mut in_sum: u64 = 0;
    for inp in &tx.inputs {
        let prev = get_utxo(db, &inp.prevout)?.ok_or_else(|| anyhow::anyhow!("missing utxo"))?;

        // verify ownership: script_pubkey is 20-byte hash160(pubkey)
        if prev.script_pubkey.len() != 20 { bail!("bad script_pubkey"); }

        let (sig64, pub33) = parse_scriptsig(&inp.script_sig)?;
        let h160 = hash160(&pub33);
        if prev.script_pubkey != h160.to_vec() { bail!("pubkey hash mismatch"); }

        // verify signature over stripped txid
        let pub_slice = pub33.as_slice();
        verify_sig(tx, &sig64, pub_slice.try_into().map_err(|_| anyhow::anyhow!("pubkey len"))?)?;

        in_sum = in_sum.checked_add(prev.value).ok_or_else(|| anyhow::anyhow!("overflow"))?;
    }

    let mut out_sum: u64 = 0;
    for out in &tx.outputs {
        out_sum = out_sum.checked_add(out.value).ok_or_else(|| anyhow::anyhow!("overflow"))?;
    }

    if out_sum > in_sum { bail!("outputs exceed inputs"); }
    let fee = (in_sum - out_sum) as i64;

    // prevent txid unused warning:
    let _ = txh;

    Ok((in_sum, out_sum, fee))
}

fn enforce_app_fee_floor(tx: &Transaction, fee: u64) -> Result<()> {
    match &tx.app {
        AppPayload::None => Ok(()),
        AppPayload::Propose {..} => {
            if fee < MIN_FEE_PROPOSE { bail!("fee too low for propose"); }
            Ok(())
        }
        AppPayload::Attest {..} => {
            if fee < MIN_FEE_ATTEST { bail!("fee too low for attest"); }
            Ok(())
        }
    }
}
