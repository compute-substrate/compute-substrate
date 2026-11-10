// src/chain/body_fault.rs
//! Whom a content rejection blames: the block hash, or only the stored body. Two kinds of body
//! bind to an honest header and differ from the honest body: the same txids with other
//! non-coinbase script_sigs (`crypto::txid` leaves them out), and a txid list with a repeated
//! suffix, because the merkle root repeats the last node of an odd layer (`utxo.rs`
//! `merkle_root_txids`). The second kind repeats txids by construction. Refusing the hash for either would
//! let any peer make an honest block look invalid.

use anyhow::Result;
use std::collections::HashMap;

use crate::crypto::{hash160, is_coinbase_input, txid, TxSigChecker};
use crate::state::db::{drop_block_body, get_utxo, Stores};
use crate::state::utxo::parse_scriptsig;
use crate::types::{Block, Hash32, OutPoint, TxOut};

/// The verdict on a block that `validate_and_apply_block` rejected for its content.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Blame {
    /// No txid repeats and every signature checks out, so the failing rule read only data every
    /// body with this hash shares: the hash may be refused.
    Block,
    /// A txid repeats or a signature fails, so another body with the same hash may be valid. The
    /// body has been removed from `db.blocks`.
    Body,
}

/// Context on an apply error whose stored body was dropped under `Blame::Body`.
#[derive(Debug)]
pub struct BodyDropped(pub Hash32);

impl std::fmt::Display for BodyDropped {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "body of block 0x{} failed on bytes its header does not fix and was dropped", hex::encode(self.0))
    }
}

/// Blames a content rejection of `block` (hash `bh`) and, for `Blame::Body`, drops its stored body.
/// Runs on the pre-block state, which `validate_and_apply_block` restores after a rejection.
pub fn blame_rejection(db: &Stores, bh: &Hash32, block: &Block) -> Result<Blame> {
    if let Some(why) = first_body_fault(db, block)? {
        println!("[reorg] block 0x{}: {why}; dropping the body, not the hash", hex::encode(bh));
        drop_block_body(db, bh)?;
        return Ok(Blame::Body);
    }
    Ok(Blame::Block)
}

/// The first index whose txid an earlier transaction of `block` already has.
pub fn first_repeated_txid(block: &Block) -> Option<usize> {
    let mut seen = std::collections::HashSet::with_capacity(block.txs.len());
    block.txs.iter().position(|tx| !seen.insert(txid(tx)))
}

/// Finds what a body may hold that another body with the same hash does not: a repeated txid, or
/// an uncommitted script_sig that fails the steps `validate_tx_inputs_outputs` applies to it
/// (utxo.rs: parse, pubkey hash against the spent output, signature), replayed over the block's
/// own spends and creates in order. An input whose spent output does not exist is skipped: that
/// failure is in data every such body shares.
pub fn first_body_fault(db: &Stores, block: &Block) -> Result<Option<String>> {
    if let Some(i) = first_repeated_txid(block) {
        return Ok(Some(format!("tx {i} repeats an earlier txid")));
    }
    // Outputs this block spent (None) or created (Some), ahead of the stored UTXO set.
    let mut overlay: HashMap<OutPoint, Option<TxOut>> = HashMap::new();

    for (ti, tx) in block.txs.iter().enumerate().skip(1) {
        let mut prevs = Vec::with_capacity(tx.inputs.len());
        for inp in &tx.inputs {
            prevs.push(match overlay.get(&inp.prevout) {
                Some(o) => o.clone(),
                None => get_utxo(db, &inp.prevout)?,
            });
        }

        let mut sigs = TxSigChecker::new(tx);
        for (ii, (inp, prev)) in tx.inputs.iter().zip(&prevs).enumerate() {
            if is_coinbase_input(&inp.prevout) {
                continue;
            }
            let fault = match parse_scriptsig(&inp.script_sig) {
                Err(e) => Some(e.to_string()),
                Ok((sig64, pub33)) => match prev {
                    None => None,
                    Some(prev) if prev.script_pubkey != hash160(&pub33) => {
                        Some("pubkey hash mismatch".to_string())
                    }
                    Some(_) => sigs.verify(&sig64, &pub33).err().map(|e| e.to_string()),
                },
            };
            if let Some(why) = fault {
                return Ok(Some(format!("tx {ti} input {ii}: {why}")));
            }
        }

        for inp in &tx.inputs {
            overlay.insert(inp.prevout, None);
        }
        let id = txid(tx);
        for (vout, out) in tx.outputs.iter().enumerate() {
            overlay.insert(OutPoint { txid: id, vout: vout as u32 }, Some(out.clone()));
        }
    }
    Ok(None)
}
