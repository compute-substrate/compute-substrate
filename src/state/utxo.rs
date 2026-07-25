// src/state/utxo.rs
use anyhow::{bail, Result};
use serde::{Deserialize, Serialize};
use std::collections::HashSet;

use crate::crypto::{hash160, sha256d, txid, verify_sig};
use crate::params::{
    MAX_BLOCK_BYTES, MAX_BLOCK_TXS, MAX_DOMAIN_BYTES, MAX_SCRIPTSIG_BYTES, MAX_TX_BYTES,
    MAX_TX_INPUTS, MAX_TX_OUTPUTS, MAX_URI_BYTES, MIN_FEE_ATTEST, MIN_FEE_PROPOSE,
};
use crate::state::app_state::{apply_app_tx, rollback_app_undo, AppUndo};
use crate::state::db::{
    del_utxo, del_utxo_meta, get_utxo, get_utxo_meta, k_undo, put_utxo, put_utxo_meta, Stores,
    UtxoMeta,
};
use crate::types::{AppPayload, Block, Hash20, Hash32, OutPoint, Transaction, TxOut};

// Consensus rule activation guard.
//
// For now this is intentionally disabled to preserve compatibility with
// already-mined historical blocks and unknown peers. Updated miners may still
// *produce* height-prefixed coinbase script_sigs, but nodes will not reject
// older/non-prefixed coinbases until a coordinated activation height is chosen.
const COINBASE_HEIGHT_PREFIX_ACTIVATION_HEIGHT: u64 = u64::MAX;


#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct UndoLog {
    pub spent: Vec<(OutPoint, TxOut, UtxoMeta)>, // restore on undo
    pub created: Vec<OutPoint>,                  // delete on undo
    pub app_undo: Vec<AppUndo>,                  // rollback on undo (reverse order)
}

/// scriptsig format (matches wallet.rs maker):
/// [sig_len u8][sig64][pub_len u8][pub33]
///
/// NOTE: coinbase script_sig is special-cased elsewhere and is NOT this format.
fn parse_scriptsig(sig: &[u8]) -> Result<([u8; 64], [u8; 33])> {
    // Exact format is 99 bytes: 1 + 64 + 1 + 33
    if sig.len() != MAX_SCRIPTSIG_BYTES {
        bail!("bad scriptsig len");
    }
    if sig[0] != 64 {
        bail!("expected 64-byte compact sig");
    }

    let mut sig64 = [0u8; 64];
    sig64.copy_from_slice(&sig[1..65]);

    if sig[65] != 33 {
        bail!("expected 33-byte compressed pubkey");
    }

    let mut pub33 = [0u8; 33];
    pub33.copy_from_slice(&sig[66..99]);

    Ok((sig64, pub33))
}

fn is_coinbase(tx: &Transaction) -> bool {
    tx.inputs.len() == 1
        && tx.inputs[0].prevout.txid == [0u8; 32]
        && tx.inputs[0].prevout.vout == u32::MAX
}

/// Future consensus rule: enforce coinbase script_sig height prefix after activation.
fn validate_coinbase_scriptsig_height(cb: &Transaction, height: u64) -> Result<()> {
    let want = height.to_le_bytes(); // 8 bytes
    let got = cb
        .inputs
        .get(0)
        .ok_or_else(|| anyhow::anyhow!("coinbase missing input"))?
        .script_sig
        .as_slice();

    // NEW: allow optional memo bytes, but require the first 8 bytes to be the height
    if got.len() < 8 {
        bail!(
            "coinbase script_sig must be at least 8 bytes (height.to_le_bytes prefix). got_len={}",
            got.len()
        );
    }

    if &got[..8] != want.as_slice() {
        bail!("coinbase script_sig must start with height.to_le_bytes()");
    }

    // Optional: DoS guard. Pick a small cap that still allows memos.
    // (If you don't want a new const, hardcode 256 here.)
    const MAX_COINBASE_SCRIPTSIG_BYTES: usize = 256;
    if got.len() > MAX_COINBASE_SCRIPTSIG_BYTES {
        bail!(
            "coinbase script_sig too large. got_len={} max={}",
            got.len(),
            MAX_COINBASE_SCRIPTSIG_BYTES
        );
    }

    Ok(())
}

/// Bitcoin-ish merkle root from txids.
/// - leaves are txid bytes
/// - internal nodes are sha256d(left || right), duplicating last if odd
fn merkle_root_txids(txids: &[[u8; 32]]) -> [u8; 32] {
    if txids.is_empty() {
        return [0u8; 32];
    }
    let mut layer: Vec<[u8; 32]> = txids.to_vec();
    while layer.len() > 1 {
        let mut next: Vec<[u8; 32]> = Vec::with_capacity((layer.len() + 1) / 2);
        let mut i = 0usize;
        while i < layer.len() {
            let left = layer[i];
            let right = if i + 1 < layer.len() {
                layer[i + 1]
            } else {
                layer[i]
            };
            let mut buf = [0u8; 64];
            buf[..32].copy_from_slice(&left);
            buf[32..].copy_from_slice(&right);
            next.push(sha256d(&buf));
            i += 2;
        }
        layer = next;
    }
    layer[0]
}

fn validate_block_merkle(block: &Block) -> Result<()> {
    let mut ids: Vec<[u8; 32]> = Vec::with_capacity(block.txs.len());
    for tx in &block.txs {
        ids.push(txid(tx));
    }
    let mr = merkle_root_txids(&ids);
    if mr != block.header.merkle {
        bail!("bad merkle: header does not commit to tx body");
    }
    Ok(())
}

/// Public helper: mempool acceptance should match consensus checks as much as possible.
pub fn validate_tx_for_mempool(db: &Stores, tx: &Transaction) -> Result<()> {
    if is_coinbase(tx) {
        bail!("coinbase not allowed in mempool");
    }

    validate_tx_structure_noncoinbase(tx)?;
    let (_in_sum, _out_sum, fee) = validate_tx_inputs_outputs(db, tx)?;
    enforce_app_fee_floor(tx, fee)?;
    validate_app_sanity(tx)?;

    Ok(())
}

fn app_phase(tx: &Transaction) -> u8 {
    match &tx.app {
        AppPayload::Propose { .. } => 0,
        AppPayload::Attest { .. } => 1,
        AppPayload::None => 2,
    }
}

/// Validate + apply a block.
/// `height` must be the height of this block in the canonical chain when applied.
pub fn validate_and_apply_block(
    db: &Stores,
    block: &Block,
    _now_epoch: u64,
    height: u64,
) -> Result<UndoLog> {
    if block.txs.is_empty() {
        bail!("empty block");
    }

    if block.txs.len() > MAX_BLOCK_TXS {
        bail!("too many txs in block");
    }

    let c = crate::codec::consensus_bincode();

    // consensus size cap (use deterministic codec)
    let blk_bytes = c.serialized_size(block)? as usize;
    if blk_bytes > MAX_BLOCK_BYTES {
        bail!("block too large");
    }

    // consensus: header must commit to body
    validate_block_merkle(block)?;

    // CONSENSUS: txids must be unique within a block, otherwise UTXO keys collide (txid,vout).
    {
        let mut seen_txids = HashSet::<[u8; 32]>::with_capacity(block.txs.len());
        for tx in &block.txs {
            let id = txid(tx);
            if !seen_txids.insert(id) {
                bail!("duplicate txid within block");
            }
        }
    }

    // First tx must be coinbase.
    let cb = &block.txs[0];
    if !is_coinbase(cb) {
        bail!("first tx must be coinbase");
    }
    if !matches!(cb.app, AppPayload::None) {
        bail!("coinbase must not carry app payload");
    }
    if cb.outputs.len() != 1 {
        bail!("coinbase must have 1 output");
    }
// Consensus-gated coinbase height-prefix rule.
//
// Do not apply retroactively: historical blocks may have been mined before
// this rule existed. Enforcing it before activation would make existing chain
// history fail rebuild/reorg recovery.
if height >= COINBASE_HEIGHT_PREFIX_ACTIVATION_HEIGHT {
    validate_coinbase_scriptsig_height(cb, height)?;
}

    // coinbase output must be pay-to-hash20 (fixed type)
    let _coinbase_addr: Hash20 = cb.outputs[0].script_pubkey;

    let mut undo = UndoLog {
        spent: vec![],
        created: vec![],
        app_undo: vec![],
    };

    // Outpoints this block has already touched.
    //
    // The undo log has to answer one question per outpoint: did it hold a coin BEFORE this block? If
    // it did, undo must RESTORE that coin; if it did not, undo must DELETE the outpoint. Only the
    // FIRST touch of an outpoint reads the pre-block value, because every later read inside this
    // block returns something this block itself wrote. So each outpoint is classified once, on first
    // touch, and routed into exactly ONE of `undo.spent` (existed: restore it) or `undo.created`
    // (did not exist: delete it).
    //
    // Deciding this on the apply side is what lets `apply_undo` stop inferring. Inferring it from the
    // finished log is not reliable: "the outpoint is in both lists" is also true when a duplicate
    // coinbase txid recreates a coin the block spent, and no property of the stored entries
    // distinguishes the two cases in general.
    let mut first_touch: HashSet<OutPoint> = HashSet::new();

    // FINDING 9 (NODE-REORG-PARTIAL-APPLY-GHOST): make per-block apply ALL-OR-NOTHING.
    // The body below mutates the sled UTXO/app trees directly while accumulating the
    // in-memory `undo`, and that undo log is only persisted on success (at the end). Any
    // early `?`/bail! inside (missing utxo, app-phase existence/expiry, bad coinbase value)
    // previously DROPPED the in-memory `undo` and left the partial tree writes committed:
    // created outputs persist and spent inputs are never restored (the root
    // cause). We run the fallible body in a closure; on Err we replay the accumulated
    // `undo` so a REJECTED block leaves ZERO residue, then re-return the ORIGINAL error.
    // The SUCCESS path is byte-for-byte unchanged (same accept/reject decisions, same
    // persisted undo bytes).
    let apply_result: Result<()> = (|| {

    // Apply non-coinbase txs first (fees), then coinbase.
    // UTXO spends/creates must still follow original tx order exactly.
    // But app payloads must apply in deterministic semantic phases:
    //     1) Propose
    //     2) Attest
    // This allows same-block Attest(tx2) to see Propose(tx1) even when both are mined together.
    let mut total_fees: u64 = 0;

    // Cache canonical per-tx metadata while preserving original block order for UTXO application.
    let mut applied_txs: Vec<(Transaction, Hash32, u64)> = Vec::with_capacity(block.txs.len().saturating_sub(1));

    for (i, tx) in block.txs.iter().enumerate() {
        if i == 0 {
            continue;
        }

        // CRITICAL: forbid any additional coinbase txs
        if is_coinbase(tx) {
            bail!("multiple coinbase txs in block");
        }

        validate_tx_structure_noncoinbase(tx)?;
        let (_in_sum, _out_sum, fee) = validate_tx_inputs_outputs(db, tx)?;
        enforce_app_fee_floor(tx, fee)?;
        validate_app_sanity(tx)?;

        total_fees = total_fees
            .checked_add(fee)
            .ok_or_else(|| anyhow::anyhow!("fee overflow"))?;

        // Spend inputs (capture BOTH TxOut and meta for undo)
        for inp in &tx.inputs {
            let prev =
                get_utxo(db, &inp.prevout)?.ok_or_else(|| anyhow::anyhow!("missing utxo"))?;
            let prev_meta = get_utxo_meta(db, &inp.prevout)?
                .ok_or_else(|| anyhow::anyhow!("missing utxo meta"))?;

            // Record the pre-block coin only on the FIRST touch. A second spend of the same
            // outpoint inside this block is spending something this block recreated, so its value
            // is not what undo must restore, and the pre-block state is already recorded.
            if first_touch.insert(inp.prevout) {
                undo.spent.push((inp.prevout, prev.clone(), prev_meta));
            }

            del_utxo(db, &inp.prevout)?;
            del_utxo_meta(db, &inp.prevout)?;
        }

        // Create outputs (+ meta)
        let txh = txid(tx);
        for (vout, out) in tx.outputs.iter().enumerate() {
            let op = OutPoint {
                txid: txh,
                vout: vout as u32,
            };
            // Classify by pre-block existence, once, BEFORE the write. A create can OVERWRITE a
            // coin that was already there, and in that case undo must restore the old coin rather
            // than delete the outpoint. `put_utxo` is a blind overwrite, so the old value has to be
            // read out here or it is lost.
            if first_touch.insert(op) {
                classify_created_outpoint(db, &op, &mut undo)?;
            }

            put_utxo(db, &op, out)?;
            put_utxo_meta(
                db,
                &op,
                &UtxoMeta {
                    height,
                    coinbase: false,
                },
            )?;
        }

        applied_txs.push((tx.clone(), txh, fee));
    }

    // Phase 1: proposals
    for (tx, txh, fee) in applied_txs.iter() {
        if app_phase(tx) == 0 {
            let app_undos = apply_app_tx(db, tx, height, txh, *fee)?;
            undo.app_undo.extend(app_undos);
        }
    }

    // Phase 2: attestations
    for (tx, txh, fee) in applied_txs.iter() {
        if app_phase(tx) == 1 {
            let app_undos = apply_app_tx(db, tx, height, txh, *fee)?;
            undo.app_undo.extend(app_undos);
        }
    }

    // Phase 3: AppPayload::None (normally no-op, but keep deterministic structure explicit)
    for (tx, txh, fee) in applied_txs.iter() {
        if app_phase(tx) == 2 {
            let app_undos = apply_app_tx(db, tx, height, txh, *fee)?;
            undo.app_undo.extend(app_undos);
        }
    }

    // Coinbase must equal reward(height) + fees.
    {
        let reward = crate::params::block_reward(height);
        let expected = reward
            .checked_add(total_fees)
            .ok_or_else(|| anyhow::anyhow!("coinbase expected overflow"))?;

        if cb.outputs[0].value != expected {
            bail!(
                "coinbase value wrong: got {}, expected {}",
                cb.outputs[0].value,
                expected
            );
        }

        let cbh = txid(cb);
        let op = OutPoint { txid: cbh, vout: 0 };

        // Same classification as the non-coinbase creates above. This is the reachable case: while
        // the height-prefix rule is gated off, a block can replay an earlier coinbase's exact bytes
        // and so overwrite a coinbase output that is still unspent.
        if first_touch.insert(op) {
            classify_created_outpoint(db, &op, &mut undo)?;
        }

        put_utxo(db, &op, &cb.outputs[0])?;
        put_utxo_meta(
            db,
            &op,
            &UtxoMeta {
                height,
                coinbase: true,
            },
        )?;
    }

    Ok(())
    })();

    // On ANY validation failure, reverse the partial in-memory writes so the
    // rejected block leaves zero residue, then return the ORIGINAL validation error. The
    // cleanup is best-effort (its own error must not mask the real reject reason).
    if let Err(e) = apply_result {
        if let Err(rollback_err) = apply_undo(db, &undo) {
            // The block is still rejected and the original reason is still what we return, but a
            // failed rollback means the trees may now hold part of a rejected block. Nothing
            // downstream can detect that, so it has to be loud: the datadir needs comparing
            // against a from-genesis rebuild before it is trusted.
            eprintln!(
                "[state] CRITICAL: rollback of a rejected block failed: {rollback_err:#}. \
                 UTXO/app state may contain partial writes from that block. Compare this datadir \
                 against a from-genesis rebuild (`csd fingerprint --datadir <dir>`) before \
                 trusting it. Original rejection: {e:#}"
            );
        }
        return Err(e);
    }

    // Save undo log keyed by block hash (CONSENSUS DB encoding)
    let bh = crate::chain::index::header_hash(&block.header);
    db.undo.insert(k_undo(&bh), c.serialize(&undo)?)?;
    Ok(undo)
}

/// Replay an `UndoLog` to reverse a block's writes (CONSENSUS-CRITICAL ORDER):
///   1) roll back app-state puts (reverse order), 2) delete created UTXOs,
///   3) restore spent UTXOs.
/// This is the EXACT reverse that was previously inlined in `undo_block`; it is now shared
/// so the error/cleanup path of `validate_and_apply_block` can replay the IN-MEMORY undo of
/// a partially-applied, then-rejected block. The step ORDER is unchanged from the
/// historical `undo_block`; the one behavioural correction is below: a same-block
/// create-then-spend outpoint is no longer restored as a phantom (this converges incremental
/// undo to the from-genesis UTXO set; it is not an app-layer/consensus-rule change).
/// Record how a created outpoint must be undone, by reading whether it already held a coin. Call
/// ONCE per outpoint, on its first touch, BEFORE the write.
///
/// `Some` means this create is an overwrite of a coin that existed before the block, so undo has to
/// put that coin back: the entry goes in `undo.spent`, which is exactly "restore this on undo", and
/// the outpoint is deliberately NOT added to `undo.created`, because deleting it would destroy a coin
/// a from-genesis replay still holds. `None` means the outpoint is genuinely new, so undo deletes it.
///
/// Every outpoint therefore ends up in at most one of the two lists. On a chain where txids are
/// unique this always takes the `None` branch and the persisted undo bytes are unchanged.
fn classify_created_outpoint(db: &Stores, op: &OutPoint, undo: &mut UndoLog) -> Result<()> {
    match get_utxo(db, op)? {
        Some(old_out) => {
            let old_meta = get_utxo_meta(db, op)?
                .ok_or_else(|| anyhow::anyhow!("utxo present without meta at {op:?}"))?;
            undo.spent.push((*op, old_out, old_meta));
        }
        None => undo.created.push(*op),
    }
    Ok(())
}

fn apply_undo(db: &Stores, undo: &UndoLog) -> Result<()> {
    rollback_app_undo(db, &undo.app_undo)?;

    // delete created utxos (+meta)
    for op in &undo.created {
        del_utxo(db, op)?;
        del_utxo_meta(db, op)?;
    }

    // Net out same-block create-then-spend pairs on undo. An outpoint CREATED and SPENT within one
    // block must be ABSENT after undo, not restored: at the ancestor state it does not exist.
    // Restoring it resurrects a phantom UTXO that a from-genesis replay does not have, and a later
    // spend of the phantom is then accepted by the incrementally-reorging node and rejected by a
    // fresh one, which is a consensus fork.
    //
    // This skip is a COMPATIBILITY PATH for undo logs already on disk, not the mechanism. The apply
    // side now classifies every outpoint on first touch by whether it held a coin before the block
    // (see classify_created_outpoint), so a log written by this code never puts an outpoint in both
    // lists and never reaches this `continue`. Logs written by earlier binaries DO, and they are
    // still replayable, so removing the skip would resurrect the phantom when replaying them.
    //
    // The `!meta.coinbase` condition is likewise only meaningful for those older logs. It is a proxy
    // for pre-block existence and it is not a faithful one: it does not see a duplicate coinbase txid
    // that OVERWRITES a still-unspent coinbase without spending it, and it cannot see the
    // non-coinbase form of the same overwrite at all, since coinbase-ness is not the property being
    // tested. Classifying on the apply side is what removes the guesswork; this pair of conditions
    // only has to be good enough for the shapes older logs actually contain.
    //
    // The durable closure for the underlying duplicate-txid hazard is to make coinbase txids
    // consensus-unique by activating `validate_coinbase_scriptsig_height` at a coordinated height.
    // That is a one-line change to the constant and a no-op for every honest block, since miners
    // already commit the height in both `script_sig` and `locktime`. It would also let this whole
    // skip be deleted.
    let created_set: HashSet<OutPoint> = undo.created.iter().copied().collect();

    // restore spent utxos (+meta)
    let mut restored: HashSet<OutPoint> = HashSet::new();
    for (op, out, meta) in &undo.spent {
        // Older-log path only; inert for logs written by this code (see above).
        if created_set.contains(op) && !meta.coinbase {
            continue;
        }
        // First entry wins. Only the first `undo.spent` entry for an outpoint holds its pre-block
        // value; an older log can carry a later entry recording something the block itself wrote,
        // and restoring that one last leaves this node holding a coin the ancestor never had.
        if !restored.insert(*op) {
            continue;
        }
        put_utxo(db, op, out)?;
        put_utxo_meta(db, op, meta)?;
    }

    Ok(())
}

pub fn undo_block(db: &Stores, block_hash: &[u8; 32]) -> Result<()> {
    let Some(v) = db.undo.get(k_undo(block_hash))? else {
        bail!("missing undo");
    };

    let c = crate::codec::consensus_bincode();
    let undo: UndoLog = c.deserialize(&v)?;

    apply_undo(db, &undo)?;

    db.undo.remove(k_undo(block_hash))?;
    Ok(())
}

// -----------------------------------------------------------------------------
// Consensus validation helpers
// -----------------------------------------------------------------------------

fn validate_tx_structure_noncoinbase(tx: &Transaction) -> Result<()> {
    if tx.inputs.is_empty() {
        bail!("no inputs");
    }
    if tx.outputs.is_empty() {
        bail!("no outputs");
    }

    let c = crate::codec::consensus_bincode();

    // serialized size cap (deterministic codec)
    let tx_bytes = c.serialized_size(tx)? as usize;
    if tx_bytes > MAX_TX_BYTES {
        bail!("tx too large");
    }

    if tx.inputs.len() > MAX_TX_INPUTS {
        bail!("too many inputs");
    }
    if tx.outputs.len() > MAX_TX_OUTPUTS {
        bail!("too many outputs");
    }

    // scriptsig is fixed-size for normal spends
    for inp in &tx.inputs {
        if inp.script_sig.len() != MAX_SCRIPTSIG_BYTES {
            bail!("bad scriptsig len");
        }
    }

    // no duplicate inputs
    let mut seen = HashSet::<OutPoint>::new();
    for inp in &tx.inputs {
        if !seen.insert(inp.prevout) {
            bail!("duplicate input outpoint");
        }
    }

    Ok(())
}

fn validate_tx_inputs_outputs(db: &Stores, tx: &Transaction) -> Result<(u64, u64, u64)> {
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
        verify_sig(tx, &sig64, &pub33)?;

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

fn enforce_app_fee_floor(tx: &Transaction, fee: u64) -> Result<()> {
    match &tx.app {
        AppPayload::None => Ok(()),
        AppPayload::Propose { .. } => {
            if fee < MIN_FEE_PROPOSE {
                bail!("fee too low for propose");
            }
            Ok(())
        }
        AppPayload::Attest { .. } => {
            if fee < MIN_FEE_ATTEST {
                bail!("fee too low for attest");
            }
            Ok(())
        }
    }
}

fn validate_app_sanity(tx: &Transaction) -> Result<()> {
    match &tx.app {
        AppPayload::None => Ok(()),

        AppPayload::Propose {
            domain,
            payload_hash,
            uri,
            expires_epoch: _,
        } => {
            if domain.trim().is_empty() {
                bail!("propose domain empty");
            }
            if uri.trim().is_empty() {
                bail!("propose uri empty");
            }

            if domain.as_bytes().len() > MAX_DOMAIN_BYTES {
                bail!("propose domain too long");
            }
            if uri.as_bytes().len() > MAX_URI_BYTES {
                bail!("propose uri too long");
            }

            if *payload_hash == [0u8; 32] {
                bail!("propose payload_hash is all-zero (did you pass an empty env var?)");
            }
            Ok(())
        }

        AppPayload::Attest {
            proposal_id,
            score: _,
            confidence: _,
        } => {
            if *proposal_id == [0u8; 32] {
                bail!("attest proposal_id is zero");
            }
            Ok(())
        }
    }
}
