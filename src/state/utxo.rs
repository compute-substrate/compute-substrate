// src/state/utxo.rs
use anyhow::{bail, Result};
use serde::{Deserialize, Serialize};
use std::collections::HashSet;

use crate::crypto::{hash160, sha256d, txid, TxSigChecker};
use crate::params::{
    MAX_BLOCK_BYTES, MAX_BLOCK_TXS, MAX_DOMAIN_BYTES, MAX_SCRIPTSIG_BYTES, MAX_TX_BYTES,
    MAX_TX_INPUTS, MAX_TX_OUTPUTS, MAX_URI_BYTES, MIN_FEE_ATTEST, MIN_FEE_PROPOSE,
};
use crate::chain::index::get_hidx;
use crate::state::app_state::{
    apply_app_tx, epoch_of, k_proposal, rollback_app_undo, AppUndo, Proposal,
};
use crate::state::db::{
    del_utxo, del_utxo_meta, get_tip, get_utxo, get_utxo_meta, k_undo, put_utxo, put_utxo_meta,
    Stores, UtxoMeta,
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
/// `pub` so `chain::body_fault` can re-check a rejected body's signatures with the same parse;
/// visibility only.
pub fn parse_scriptsig(sig: &[u8]) -> Result<([u8; 64], [u8; 33])> {
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

/// This is the only body-to-header bind in the tree, and upstream runs it only here, inside
/// `validate_and_apply_block`, i.e. after the network path has already persisted the bytes. It is
/// `pub` so `net::node` can run the identical check before a store and before a serve. Consensus
/// behaviour is unchanged: same function, same call site, same result.
pub fn validate_block_merkle(block: &Block) -> Result<()> {
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
    validate_app_state_mempool(db, tx)?;

    Ok(())
}

/// The admission gate shared by mempool insert, prune, and the miner template filter must not
/// accept a transaction that consensus apply would reject. `validate_app_sanity` checks only app
/// *syntax*; the apply path (`app_state.rs`) additionally rejects a Propose whose `expires_epoch`
/// is in the past and an Attest to an unknown or expired proposal. A tx that passes the former but
/// fails the latter is a landmine: it is admitted, survives prune, and is selected into block
/// templates, but any block containing it fails `validate_and_apply_block`, stalling every miner
/// that includes it for as long as it sits in the mempool (up to the 36h TTL).
///
/// Mirror the apply-time state checks here, read-only, against the epoch of the next block
/// (`tip_height + 1`): the block a template is being built for, and the earliest block an admitted
/// tx could be mined into. So admission, prune, and template selection all agree with consensus.
///
/// `pub` so mempool prune re-checks this alone with the spent outputs (`Mempool::prune`);
/// visibility only.
pub fn validate_app_state_mempool(db: &Stores, tx: &Transaction) -> Result<()> {
    // Epoch of the block being built / next to be applied. No tip yet (early sync / toy chain)
    // degrades to epoch 0, which is permissive and matches genesis-era apply.
    let tip_height = match get_tip(db)? {
        Some(h) => get_hidx(db, &h)?.map(|hi| hi.height).unwrap_or(0),
        None => 0,
    };
    let epoch = epoch_of(tip_height + 1);

    match &tx.app {
        AppPayload::None => Ok(()),

        AppPayload::Propose { expires_epoch, .. } => {
            // Mirror app_state.rs: apply bails when `expires_epoch < epoch`.
            if *expires_epoch < epoch {
                bail!(
                    "propose expires_epoch {} is < next-block epoch {}",
                    expires_epoch,
                    epoch
                );
            }
            Ok(())
        }

        AppPayload::Attest { proposal_id, .. } => {
            // Mirror app_state.rs: apply bails on an unknown proposal, and on `epoch > expires`.
            let pkey = k_proposal(proposal_id);
            let Some(pv) = db.app.get(&pkey)? else {
                bail!(
                    "attest references unknown proposal {}",
                    hex::encode(proposal_id)
                );
            };
            let prop: Proposal = crate::codec::consensus_bincode().deserialize(&pv)?;
            if epoch > prop.expires_epoch {
                bail!(
                    "attest after proposal expiry: epoch {} > expires_epoch {}",
                    epoch,
                    prop.expires_epoch
                );
            }
            Ok(())
        }
    }
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
    // The undo log has to answer exactly one question per outpoint: did it hold a coin before this
    // block? If yes, undo must restore that coin; if no, undo must delete the outpoint. Only the
    // first touch of an outpoint reads the pre-block value: every later read inside this block
    // returns something this block itself wrote. So each outpoint is classified once, on first
    // touch, and routed into exactly one of `undo.spent` (existed: restore it) or `undo.created`
    // (did not exist: delete it).
    //
    // This replaces an inference on the undo side, which asked "is this outpoint in both lists"
    // (and later also "is its meta non-coinbase"). Both were proxies for pre-block existence and
    // both had blind spots (see the three undo_restores_* tests). Classifying at the source
    // removes the inference entirely.
    let mut first_touch: HashSet<OutPoint> = HashSet::new();

    // Per-block apply is all-or-nothing.
    // The body below mutates the sled UTXO/app trees directly while accumulating the in-memory
    // `undo`, and that undo log is only persisted on success (at the end). In upstream's code any
    // early `?`/bail! inside (missing utxo, app-phase existence/expiry, bad coinbase value) drops
    // the in-memory `undo` and leaves the partial tree writes committed: created outputs of the
    // rejected block persist and its deleted inputs are never restored, so the node's UTXO set
    // departs from a from-genesis replay. The fallible body runs in a closure; on Err the
    // accumulated `undo` is replayed so a rejected block leaves no residue, then the original
    // error is returned. The success path is byte-for-byte unchanged (same accept/reject
    // decisions, same persisted undo bytes), so block validity does not change.
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

            // Record the pre-block coin only on the first touch. A second spend of the same
            // outpoint inside this block is spending something this block recreated, so its value
            // is not what undo must restore, and the outpoint's pre-block state is already
            // recorded from the first touch.
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
            // Classify by pre-block existence, once, before the write.
            // A create can overwrite a coin that was already there (a replayed transaction whose
            // output is still unspent), and in that case undo must restore the old coin rather than
            // delete the outpoint. `put_utxo` is a blind overwrite, so the old value has to be read
            // out here or it is gone.
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

        // Same classification as the non-coinbase creates above. This is the reachable case:
        // coinbase txids are not consensus-unique while the height-prefix rule is gated off at
        // COINBASE_HEIGHT_PREFIX_ACTIVATION_HEIGHT = u64::MAX, so a block can replay an earlier
        // coinbase's exact bytes and overwrite a coin that is still unspent.
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

    // On any validation failure, reverse the partial in-memory writes so the rejected block
    // leaves no residue, then return the original validation error. The cleanup is best-effort
    // (its own error must not mask the real reject reason).
    if let Err(e) = apply_result {
        if let Err(rollback_err) = apply_undo(db, &undo) {
            // The block is still rejected and the original reason is still what we return, but a
            // failed rollback means the trees may hold part of a rejected block. Nothing
            // downstream detects that, so it has to be loud and name the check.
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

/// Record how a created outpoint must be undone, by reading whether it held a coin before this
/// block. Call once per outpoint, on its first touch, before the write.
///
/// `Some` means this create is an overwrite of a coin that already existed, so undo has to put that
/// coin back: it goes in `undo.spent`, which is exactly "restore this on undo", and it is
/// deliberately not added to `undo.created`, because deleting the outpoint would destroy a coin a
/// from-genesis replay still holds. `None` means the outpoint is genuinely new, so undo deletes it.
///
/// Every outpoint therefore appears in at most one of the two lists, which is what makes the undo
/// side need no inference. On the honest chain this function always takes the `None` branch (txids
/// are unique, so nothing is ever overwritten) and the persisted undo bytes are unchanged.
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

/// Replay an `UndoLog` to reverse a block's writes (CONSENSUS-CRITICAL ORDER):
///   1) roll back app-state puts (reverse order), 2) delete created UTXOs,
///   3) restore spent UTXOs.
/// This is the exact reverse that upstream inlines in `undo_block`; it is shared so the
/// error/cleanup path of `validate_and_apply_block` can replay the in-memory undo of a
/// partially-applied, then-rejected block. The step order is upstream's; the one behavioural
/// correction is the skip below: a same-block create-then-spend outpoint is not restored as a
/// phantom (this converges incremental undo to the from-genesis UTXO set; it is not an
/// app-layer or consensus-rule change).
fn apply_undo(db: &Stores, undo: &UndoLog) -> Result<()> {
    rollback_app_undo(db, &undo.app_undo)?;

    // delete created utxos (+meta)
    for op in &undo.created {
        del_utxo(db, op)?;
        del_utxo_meta(db, op)?;
    }

    // An outpoint created and spent within the same block must be absent after undo, not
    // restored. Upstream's undo restores it, resurrecting a phantom UTXO absent from a
    // from-genesis replay, so a long-running node that reorgs incrementally diverges from a
    // freshly-synced one (a later spend of the phantom is accepted by one and rejected by the
    // other: a consensus fork).
    //
    // This skip is a compatibility path for undo logs in the older layout, not the mechanism. The
    // apply side classifies every outpoint on first touch by whether it held a coin before the
    // block, and routes it into exactly one of `undo.created` or `undo.spent` (see
    // classify_created_outpoint). A log written by this code therefore never has an outpoint in
    // both lists and never reaches this `continue`. It is retained because undo logs in the older
    // layout (upstream's) can still be on disk and replayable: those logs put a same-block
    // create-then-spend outpoint in both lists, and dropping the skip would resurrect the phantom
    // when replaying them. Do not remove it while such logs can be reached.
    //
    // The `&& !meta.coinbase` refinement is likewise only for older-layout logs. It was a proxy for
    // pre-block existence and it had blind spots on both sides: it missed the case where the
    // duplicate-coinbase block overwrote the coin without spending it, and the whole non-coinbase leg,
    // because coinbase-ness is simply not the property the skip needed to test. Pinned by
    // undo_restores_an_unspent_pre_block_coinbase_that_the_new_coinbase_overwrote,
    // undo_restores_a_pre_block_noncoinbase_output_that_a_replayed_tx_overwrote and
    // undo_restores_the_first_touch_value_when_a_block_spends_recreates_and_respends.
    //
    // The durable closure for the underlying hazard is still to make coinbase txids consensus-unique
    // by activating `validate_coinbase_scriptsig_height` at a coordinated height (one line, and
    // measured to be a no-op for the miners of a 6,168-block sample spread across the mainnet chain:
    // every coinbase in it commits its height in both script_sig and locktime, and no two coinbase txids
    // repeat). That would also let this whole skip be deleted.
    let created_set: HashSet<OutPoint> = undo.created.iter().copied().collect();

    // restore spent utxos (+meta)
    let mut restored: HashSet<OutPoint> = HashSet::new();
    for (op, out, meta) in &undo.spent {
        // Older-layout logs only; inert for logs written by this code (see above).
        if created_set.contains(op) && !meta.coinbase {
            continue;
        }
        // First entry wins. Only the first `undo.spent` entry for an outpoint holds its
        // pre-block value; an older-layout log can carry a later entry recording something the
        // block itself wrote, and restoring that last would leave this node holding a coin the
        // ancestor state never had.
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
    // One sighash per tx, not per input (`crypto::TxSigChecker`).
    let mut sigs = TxSigChecker::new(tx);

    for inp in &tx.inputs {
        let prev = get_utxo(db, &inp.prevout)?.ok_or_else(|| anyhow::anyhow!("missing utxo"))?;

        let (sig64, pub33) = parse_scriptsig(&inp.script_sig)?;

        // script_pubkey is Hash20; compute address hash from pubkey
        let addr20: Hash20 = hash160(&pub33);
        if prev.script_pubkey != addr20 {
            bail!("pubkey hash mismatch");
        }

        // CONSENSUS: signature verifies over global tx sighash.
        sigs.verify(&sig64, &pub33)?;

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

// ---------------------------------------------------------------------------
// Tests for the mempool app-state admission gate (validate_app_state_mempool):
// refusals (the landmine must be refused at admission) and paired happy paths (a
// valid Propose/Attest must still be admitted and still apply). State is set up
// directly (put_utxo / put_hidx / set_tip), so no PoW / chain-building is needed
// and the tests run under `cargo test --lib`.
// ---------------------------------------------------------------------------
#[cfg(test)]
mod mempool_appstate_tests {
    use super::*;
    use crate::chain::index::{put_hidx, HeaderIndex};
    use crate::crypto::sign_tx_compact_secp256k1;
    use crate::params::{MIN_FEE_ATTEST, MIN_FEE_PROPOSE};
    use crate::state::app_state::apply_app_tx;
    use crate::state::db::set_tip;
    use crate::types::{OutPoint, TxIn, TxOut};
    use tempfile::TempDir;

    const SK: [u8; 32] = [7u8; 32];
    const START_TIME: u64 = 1_702_000_000;
    // Coin value used by the test UTXOs (100 CSD in base units).
    const COIN: u64 = 10_000_000_000;

    fn signer_addr() -> [u8; 20] {
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
        let (_sig, pub33) = sign_tx_compact_secp256k1(&dummy, SK);
        hash160(&pub33)
    }

    fn sign(mut tx: Transaction) -> Transaction {
        let (sig64, pub33) = sign_tx_compact_secp256k1(&tx, SK);
        let mut ss = Vec::with_capacity(99);
        ss.push(64);
        ss.extend_from_slice(&sig64);
        ss.push(33);
        ss.extend_from_slice(&pub33);
        for inp in &mut tx.inputs {
            inp.script_sig = ss.clone();
        }
        tx
    }

    // Fabricate a canonical tip at `height` so the gate reads the intended epoch.
    // Only `height` is load-bearing here (the gate reads hi.height); no PoW is involved.
    fn set_tip_at_height(db: &Stores, height: u64) {
        let mut hash = [0u8; 32];
        hash[0..8].copy_from_slice(&height.to_le_bytes());
        hash[31] = 0xFF;
        let hi = HeaderIndex {
            hash,
            parent: [0u8; 32],
            height,
            chainwork: 0,
            bits: 0,
            time: START_TIME,
        };
        put_hidx(db, &hi).unwrap();
        set_tip(db, &hash).unwrap();
    }

    fn insert_utxo(db: &Stores, op: OutPoint, value: u64, owner: [u8; 20]) {
        put_utxo(
            db,
            &op,
            &TxOut {
                value,
                script_pubkey: owner,
            },
        )
        .unwrap();
        put_utxo_meta(db, &op, &UtxoMeta {
            height: 1,
            coinbase: false,
        })
        .unwrap();
    }

    fn propose_tx(op: OutPoint, owner: [u8; 20], expires_epoch: u64) -> Transaction {
        sign(Transaction {
            version: 1,
            inputs: vec![TxIn {
                prevout: op,
                script_sig: vec![0u8; 99],
            }],
            outputs: vec![TxOut {
                value: COIN - MIN_FEE_PROPOSE,
                script_pubkey: owner,
            }],
            locktime: 0,
            app: AppPayload::Propose {
                domain: "test-domain".to_string(),
                payload_hash: [0x66; 32],
                uri: "https://example.com/x".to_string(),
                expires_epoch,
            },
        })
    }

    fn attest_tx(op: OutPoint, owner: [u8; 20], proposal_id: [u8; 32]) -> Transaction {
        sign(Transaction {
            version: 1,
            inputs: vec![TxIn {
                prevout: op,
                script_sig: vec![0u8; 99],
            }],
            outputs: vec![TxOut {
                value: COIN - MIN_FEE_ATTEST,
                script_pubkey: owner,
            }],
            locktime: 0,
            app: AppPayload::Attest {
                proposal_id,
                score: 1,
                confidence: 0,
            },
        })
    }

    fn open_db() -> (TempDir, Stores) {
        let tmp = TempDir::new().unwrap();
        let db = Stores::open(tmp.path().to_str().unwrap()).unwrap();
        (tmp, db)
    }

    // A past-expiry Propose must be refused at admission. Upstream's admission, which has no
    // state check, admits it (this assertion fails there); consensus apply rejects it with or
    // without the gate.
    #[test]
    fn expired_propose_is_a_landmine_and_is_now_refused() {
        let (_tmp, db) = open_db();
        let owner = signer_addr();
        // Tip at height 59 -> next block height 60 -> epoch 2 (EPOCH_LEN=30).
        set_tip_at_height(&db, 59);
        let op = OutPoint {
            txid: [0x01; 32],
            vout: 0,
        };
        insert_utxo(&db, op, COIN, owner);

        // expires_epoch 1 < next-block epoch 2 -> a landmine.
        let tx = propose_tx(op, owner, 1);

        // Consensus apply rejects it, with or without the admission gate.
        let id = txid(&tx);
        assert!(
            apply_app_tx(&db, &tx, 60, &id, MIN_FEE_PROPOSE).is_err(),
            "apply must reject a past-expiry propose"
        );

        // Admission must refuse it too, for the expiry reason (upstream's admission admits it).
        let err = validate_tx_for_mempool(&db, &tx)
            .expect_err("mempool gate must refuse a past-expiry propose");
        assert!(
            format!("{err:#}").contains("expires_epoch"),
            "the refusal must be the expiry check, not another cause: {err:#}"
        );
    }

    // An Attest to an unknown proposal must be refused at admission.
    #[test]
    fn attest_to_unknown_proposal_is_a_landmine_and_is_now_refused() {
        let (_tmp, db) = open_db();
        let owner = signer_addr();
        set_tip_at_height(&db, 59);
        let op = OutPoint {
            txid: [0x02; 32],
            vout: 0,
        };
        insert_utxo(&db, op, COIN, owner);

        let tx = attest_tx(op, owner, [0xAB; 32]); // never created

        let id = txid(&tx);
        assert!(
            apply_app_tx(&db, &tx, 60, &id, MIN_FEE_ATTEST).is_err(),
            "apply must reject an attest to an unknown proposal"
        );
        let err = validate_tx_for_mempool(&db, &tx)
            .expect_err("mempool gate must refuse an attest to an unknown proposal");
        assert!(
            format!("{err:#}").contains("unknown proposal"),
            "the refusal must be the unknown-proposal check, not another cause: {err:#}"
        );
    }

    // An Attest to an expired proposal must be refused at admission.
    #[test]
    fn attest_to_expired_proposal_is_a_landmine_and_is_now_refused() {
        let (_tmp, db) = open_db();
        let owner = signer_addr();

        // Create the proposal while the next-block epoch is 0 (tip height 1), expiring at epoch 1.
        set_tip_at_height(&db, 1);
        let pop = OutPoint {
            txid: [0x03; 32],
            vout: 0,
        };
        insert_utxo(&db, pop, COIN, owner);
        let proposal_tx = propose_tx(pop, owner, 1);
        let proposal_id = txid(&proposal_tx);
        apply_app_tx(&db, &proposal_tx, 2, &proposal_id, MIN_FEE_PROPOSE)
            .expect("proposal valid at epoch 0");

        // Advance the tip so the next block is in epoch 2 (past the proposal's expiry).
        set_tip_at_height(&db, 59);

        let aop = OutPoint {
            txid: [0x04; 32],
            vout: 0,
        };
        insert_utxo(&db, aop, COIN, owner);
        let tx = attest_tx(aop, owner, proposal_id);

        let id = txid(&tx);
        assert!(
            apply_app_tx(&db, &tx, 60, &id, MIN_FEE_ATTEST).is_err(),
            "apply must reject an attest after proposal expiry"
        );
        let err = validate_tx_for_mempool(&db, &tx)
            .expect_err("mempool gate must refuse an attest after proposal expiry");
        assert!(
            format!("{err:#}").contains("expiry"),
            "the refusal must be the expiry check, not another cause: {err:#}"
        );
    }

    // Paired happy path: a valid Propose and a valid Attest must be admitted and must apply.
    // Guards against the gate over-refusing the honest path. Passes with or without the gate.
    #[test]
    fn valid_propose_and_attest_are_admitted_and_apply() {
        let (_tmp, db) = open_db();
        let owner = signer_addr();
        set_tip_at_height(&db, 59); // next-block epoch 2

        let pop = OutPoint {
            txid: [0x05; 32],
            vout: 0,
        };
        insert_utxo(&db, pop, COIN, owner);
        // Valid: expires_epoch 3 >= next-block epoch 2.
        let proposal_tx = propose_tx(pop, owner, 3);
        assert!(
            validate_tx_for_mempool(&db, &proposal_tx).is_ok(),
            "a valid propose must be admitted"
        );
        let proposal_id = txid(&proposal_tx);
        apply_app_tx(&db, &proposal_tx, 60, &proposal_id, MIN_FEE_PROPOSE)
            .expect("a valid propose must apply");

        let aop = OutPoint {
            txid: [0x06; 32],
            vout: 0,
        };
        insert_utxo(&db, aop, COIN, owner);
        let att = attest_tx(aop, owner, proposal_id);
        assert!(
            validate_tx_for_mempool(&db, &att).is_ok(),
            "a valid attest must be admitted"
        );
        let aid = txid(&att);
        apply_app_tx(&db, &att, 60, &aid, MIN_FEE_ATTEST).expect("a valid attest must apply");
    }

    // Boundary happy path: a Propose expiring exactly at the next-block epoch is still valid
    // (apply rejects only `expires_epoch < epoch`), and must be admitted.
    #[test]
    fn propose_expiring_at_next_block_epoch_is_admitted() {
        let (_tmp, db) = open_db();
        let owner = signer_addr();
        set_tip_at_height(&db, 59); // next-block epoch 2
        let op = OutPoint {
            txid: [0x07; 32],
            vout: 0,
        };
        insert_utxo(&db, op, COIN, owner);
        let tx = propose_tx(op, owner, 2); // expires_epoch == next-block epoch
        assert!(
            validate_tx_for_mempool(&db, &tx).is_ok(),
            "a propose expiring exactly at the next-block epoch must be admitted"
        );
    }

    // Consensus parity: the mempool gate is deliberately stricter than consensus apply.
    // Consensus apply processes all Proposes before all Attests within a block, so a same-block
    // create-then-attest is valid at apply. The mempool gate cannot see same-block creates (it
    // checks the CURRENT state), so it refuses an Attest whose proposal is not yet in state.
    // This is safe: the gate never runs at block validation, so the node still accepts such a
    // block from any peer; the local miner simply won't hold the Attest until the proposal is in
    // state (one block later). This test proves the consensus behaviour is unchanged.
    #[test]
    fn consensus_apply_still_accepts_same_block_create_then_attest() {
        let (_tmp, db) = open_db();
        let owner = signer_addr();

        // Two spendable UTXOs (one for the propose fee, one for the attest fee).
        let op1 = OutPoint {
            txid: [0x11; 32],
            vout: 0,
        };
        let op2 = OutPoint {
            txid: [0x22; 32],
            vout: 0,
        };
        insert_utxo(&db, op1, COIN, owner);
        insert_utxo(&db, op2, COIN, owner);

        let height = 60u64; // epoch 2
        let propose = propose_tx(op1, owner, 5);
        let proposal_id = txid(&propose);
        let attest = attest_tx(op2, owner, proposal_id); // references the same-block proposal

        // Build a block [coinbase, propose, attest] with a correct merkle and a coinbase that
        // collects reward + both app fees.
        let fees = MIN_FEE_PROPOSE + MIN_FEE_ATTEST;
        let cb = crate::chain::mine::coinbase(
            owner,
            crate::params::block_reward(height) + fees,
            height,
            None,
        );
        let txs = vec![cb, propose, attest.clone()];
        let ids: Vec<Hash32> = txs.iter().map(txid).collect();
        let merkle = merkle_root_txids(&ids);
        let blk = crate::types::Block {
            header: crate::types::BlockHeader {
                version: 1,
                prev: [0u8; 32],
                merkle,
                time: START_TIME,
                bits: 0,
                nonce: 0,
            },
            txs,
        };

        // Gate (checked before apply): the proposal is not yet in state, so the mempool gate
        // refuses the Attest with "unknown proposal", the deliberate, stricter-than-consensus
        // behaviour.
        // (Asserted before apply, and on the reason: after apply the proposal IS in state and the
        // spent input would make this fail on "missing utxo" instead - vacuous.)
        let gate_err = validate_tx_for_mempool(&db, &attest)
            .expect_err("the mempool gate must refuse an attest whose proposal is not yet in state");
        assert!(
            format!("{gate_err:#}").contains("unknown proposal"),
            "the refusal must be the gate's unknown-proposal check, not another cause: {gate_err:#}"
        );

        // Consensus parity: apply accepts the same-block create-then-attest (unchanged by the gate).
        validate_and_apply_block(&db, &blk, epoch_of(height), height)
            .expect("consensus apply must accept a same-block create-then-attest");
    }
}
