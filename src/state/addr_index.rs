// src/state/addr_index.rs
//
// The address index behind /utxos: each address's unspent outputs, so a read costs that address's
// outputs and not a scan of the whole UTXO tree. Design and reasons: docs/behaviour.md "The
// address index".
//
// The txid-index reconciler writes it, one block per batch, in the same `idx` batch as the block's
// locators and the completeness marker (`tx_index::index_canonical_block`), so after any crash it
// covers exactly the blocks up to `idx:tip_hash`. Nothing in the block apply path writes it. A read
// uses it only while that marker equals `meta:tip`, before and after the read, and takes every
// output's membership from the UTXO tree: the index names candidates, the UTXO tree decides.

use std::collections::hash_map::Entry;
use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};

use anyhow::{anyhow, bail, Context, Result};

use crate::chain::index::get_hidx;
use crate::crypto::txid;
use crate::state::db::{get_tip, get_utxo, get_utxo_meta, k_block, k_utxo, Stores};
use crate::state::tx_scan::{fresh_tip, idx_tip, PLANNING_ERROR_TAG};
use crate::types::{Block, Hash20, Hash32, OutPoint, TxOut};

fn c() -> crate::codec::ConsensusBincode {
    crate::codec::consensus_bincode()
}

// Keys in the `idx` tree. An outpoint is written as the UTXO tree writes it (`k_utxo` without its
// prefix byte: txid, then vout little-endian), so one address's prefix scan visits its outputs in
// the UTXO tree's own key order, the order the scan reports them in.
const ADDR_OUT: &[u8] = b"a/"; // a/<addr20><outpoint> -> empty: an unspent output paying addr20
const OUT_OWNER: &[u8] = b"ao/"; // ao/<outpoint> -> addr20: whom an unspent output pays
const BLOCK_UNDO: &[u8] = b"au/"; // au/<block hash> -> what the block replaced (`BlockUndo`)
const LIFETIME: &[u8] = b"al/"; // al/<addr20> -> mined (u128 BE), outputs (u64 BE): coinbase totals

const OUTPOINT_LEN: usize = 36;

fn outpoint_bytes(op: &OutPoint) -> Vec<u8> {
    k_utxo(op)[1..].to_vec()
}

fn decode_outpoint(b: &[u8]) -> Option<OutPoint> {
    if b.len() != OUTPOINT_LEN {
        return None;
    }
    let mut txid = [0u8; 32];
    txid.copy_from_slice(&b[..32]);
    let vout = u32::from_le_bytes(b[32..].try_into().ok()?);
    Some(OutPoint { txid, vout })
}

/// The prefix of every index entry of `addr`.
pub fn k_addr_prefix(addr: &Hash20) -> Vec<u8> {
    [ADDR_OUT, addr.as_slice()].concat()
}

fn k_addr_out(addr: &Hash20, op: &OutPoint) -> Vec<u8> {
    [ADDR_OUT, addr.as_slice(), &outpoint_bytes(op)].concat()
}

fn k_out_owner(op: &OutPoint) -> Vec<u8> {
    [OUT_OWNER, &outpoint_bytes(op)].concat()
}

fn k_block_undo(block_hash: &Hash32) -> Vec<u8> {
    [BLOCK_UNDO, block_hash.as_slice()].concat()
}

fn k_lifetime(addr: &Hash20) -> Vec<u8> {
    [LIFETIME, addr.as_slice()].concat()
}

/// An entry that does not decode means the index is broken, which a rebuild cures, so it carries
/// the tag that makes the reconciler reset after repeated failures.
fn broken(what: String) -> anyhow::Error {
    anyhow!("{PLANNING_ERROR_TAG} address index: {what}")
}

fn decode_addr(b: &[u8]) -> Option<Hash20> {
    b.try_into().ok()
}

// -----------------------------------------------------------------------------
// The block replay the index applies: the UTXO changes of `validate_and_apply_block`, in its order
// -----------------------------------------------------------------------------

/// One UTXO change of a block's apply: a spent input, or a created output and whom it pays.
#[derive(Clone, Copy)]
enum Step {
    Spend(OutPoint),
    Create(OutPoint, Hash20),
}

impl Step {
    fn outpoint(&self) -> OutPoint {
        match *self {
            Step::Spend(op) | Step::Create(op, _) => op,
        }
    }

    fn owner_after(&self) -> Option<Hash20> {
        match *self {
            Step::Spend(_) => None,
            Step::Create(_, a) => Some(a),
        }
    }
}

/// The UTXO changes of `blk` in the order `validate_and_apply_block` makes them: each non-coinbase
/// transaction spends its inputs and then creates its outputs, and the coinbase's one output is
/// created last.
fn utxo_steps(blk: &Block) -> Vec<Step> {
    let mut steps = Vec::new();
    for tx in blk.txs.iter().skip(1) {
        steps.extend(tx.inputs.iter().map(|i| Step::Spend(i.prevout)));
        let id = txid(tx);
        steps.extend(tx.outputs.iter().enumerate().map(|(vout, out)| {
            Step::Create(OutPoint { txid: id, vout: vout as u32 }, out.script_pubkey)
        }));
    }
    if let Some(cb) = blk.txs.first() {
        if let Some(out) = cb.outputs.first() {
            steps.push(Step::Create(OutPoint { txid: txid(cb), vout: 0 }, out.script_pubkey));
        }
    }
    steps
}

/// The outputs that count toward an address's lifetime coinbase totals: every output of the
/// block's first transaction, as the block walk counts them.
fn lifetime_outputs(blk: &Block) -> &[TxOut] {
    blk.txs.first().map(|cb| cb.outputs.as_slice()).unwrap_or(&[])
}

/// What indexing a block replaced: each outpoint the block touched that the index held before it,
/// with its owner then. Taking the block back out restores exactly these and removes the rest.
type BlockUndo = Vec<(OutPoint, Hash20)>;

fn owner_of(db: &Stores, op: &OutPoint) -> Result<Option<Hash20>> {
    match db.idx.get(k_out_owner(op))? {
        None => Ok(None),
        Some(v) => decode_addr(&v)
            .map(Some)
            .ok_or_else(|| broken(format!("owner entry of {}:{} is {} bytes", hex::encode(op.txid), op.vout, v.len()))),
    }
}

/// Moves `op` from owner `from` to owner `to` in `batch` (None: not an unspent output).
fn set_owner(batch: &mut sled::Batch, op: &OutPoint, from: Option<Hash20>, to: Option<Hash20>) {
    if from == to {
        return;
    }
    if let Some(a) = from {
        batch.remove(k_addr_out(&a, op));
    }
    match to {
        Some(b) => {
            batch.insert(k_addr_out(&b, op), &[][..]);
            batch.insert(k_out_owner(op), &b[..]);
        }
        None => batch.remove(k_out_owner(op)),
    }
}

/// Adds one canonical block to `batch`: its spends and creates, the record that undoes them and its
/// coinbase totals. Reads the index as the blocks before it left it, so the caller applies `batch`
/// before it indexes the next block.
pub(crate) fn index_block(db: &Stores, batch: &mut sled::Batch, block_hash: &Hash32, blk: &Block) -> Result<()> {
    let mut before: HashMap<OutPoint, Option<Hash20>> = HashMap::new();
    let mut after: HashMap<OutPoint, Option<Hash20>> = HashMap::new();
    let mut touched: Vec<OutPoint> = Vec::new();
    for step in utxo_steps(blk) {
        let op = step.outpoint();
        if let Entry::Vacant(e) = before.entry(op) {
            e.insert(owner_of(db, &op)?);
            touched.push(op);
        }
        after.insert(op, step.owner_after());
    }
    let mut undo: BlockUndo = Vec::new();
    for op in &touched {
        let (was, now) = (before[op], after[op]);
        if let Some(a) = was {
            undo.push((*op, a));
        }
        set_owner(batch, op, was, now);
    }
    batch.insert(k_block_undo(block_hash), c().serialize(&undo)?);
    add_lifetime(db, batch, blk, true)
}

/// Takes the last indexed block back out of the index in `batch`: every outpoint it touched returns
/// to the owner the index held before it, and its coinbase totals are subtracted.
pub(crate) fn unindex_block(db: &Stores, batch: &mut sled::Batch, block_hash: &Hash32, blk: &Block) -> Result<()> {
    let undo: BlockUndo = match db.idx.get(k_block_undo(block_hash))? {
        Some(v) => c()
            .deserialize(&v)
            .map_err(|e| broken(format!("undo record of block 0x{}: {e}", hex::encode(block_hash))))?,
        None => return Err(broken(format!("no undo record for block 0x{}", hex::encode(block_hash)))),
    };
    let was: HashMap<OutPoint, Hash20> = undo.into_iter().collect();
    let mut seen: HashSet<OutPoint> = HashSet::new();
    for step in utxo_steps(blk) {
        let op = step.outpoint();
        if seen.insert(op) {
            set_owner(batch, &op, owner_of(db, &op)?, was.get(&op).copied());
        }
    }
    batch.remove(k_block_undo(block_hash));
    add_lifetime(db, batch, blk, false)
}

/// The exact (mined, outputs) `al/` holds for `addr`. `mined` is a u128 because a miner that pays
/// its own coins as fees into its own coinbases can carry it past u64::MAX; `outputs` grows by one
/// a coinbase.
fn lifetime_of(db: &Stores, addr: &Hash20) -> Result<(u128, u64)> {
    let Some(v) = db.idx.get(k_lifetime(addr))? else {
        return Ok((0, 0));
    };
    if v.len() != 24 {
        return Err(broken(format!("lifetime entry of 0x{} is {} bytes", hex::encode(addr), v.len())));
    }
    let mined = u128::from_be_bytes(v[..16].try_into().expect("16 bytes"));
    let outputs = u64::from_be_bytes(v[16..].try_into().expect("8 bytes"));
    Ok((mined, outputs))
}

fn add_lifetime(db: &Stores, batch: &mut sled::Batch, blk: &Block, add: bool) -> Result<()> {
    let mut per: BTreeMap<Hash20, (u128, u64)> = BTreeMap::new();
    for out in lifetime_outputs(blk) {
        let e = per.entry(out.script_pubkey).or_default();
        e.0 += u128::from(out.value);
        e.1 += 1;
    }
    for (addr, (value, outputs)) in per {
        let (mined, count) = lifetime_of(db, &addr)?;
        let next = if add {
            mined.checked_add(value).zip(count.checked_add(outputs))
        } else {
            mined.checked_sub(value).zip(count.checked_sub(outputs))
        };
        let Some((mined, count)) = next else {
            return Err(broken(format!("lifetime totals of 0x{} out of range", hex::encode(addr))));
        };
        if (mined, count) == (0, 0) {
            batch.remove(k_lifetime(&addr));
        } else {
            batch.insert(k_lifetime(&addr), [&mined.to_be_bytes()[..], &count.to_be_bytes()[..]].concat());
        }
    }
    Ok(())
}

// -----------------------------------------------------------------------------
// Reads
// -----------------------------------------------------------------------------

/// One unspent output as /utxos reports it, before formatting.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AddrUtxo {
    pub op: OutPoint,
    pub value: u64,
    pub height: u64,
    pub coinbase: bool,
}

/// What /utxos reads for one address.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AddrRead {
    /// The tip the read is for (None: the datadir has no tip).
    pub tip: Option<Hash32>,
    /// The tip's height, 0 without a header index for it (confirmations count from it).
    pub tip_height: u64,
    /// The address's unspent outputs in the UTXO tree's key order.
    pub utxos: Vec<AddrUtxo>,
    /// (mined, outputs) of every coinbase output ever paid to the address, when asked for; `mined`
    /// capped at u64::MAX, as the block walk saturates.
    pub lifetime: Option<(u64, u64)>,
    /// Whether the index answered (false: the UTXO-tree scan and the block walk did).
    pub via_index: bool,
}

fn with_meta(db: &Stores, op: OutPoint, out: &TxOut) -> AddrUtxo {
    let (height, coinbase) = match get_utxo_meta(db, &op).ok().flatten() {
        Some(m) => (m.height, m.coinbase),
        None => (0, false),
    };
    AddrUtxo { op, value: out.value, height, coinbase }
}

/// What /utxos reports for `addr`: the index's answer while it is current, else the scan's.
pub fn read(db: &Stores, addr: &Hash20, lifetime: bool) -> Result<AddrRead> {
    match read_via_index(db, addr, lifetime) {
        Some(r) => Ok(r),
        None => read_via_scan(db, addr, lifetime),
    }
}

/// The index's answer, or None when the caller must scan: the index is not current at the tip,
/// the marker or the tip moved during the read, or a read failed.
pub fn read_via_index(db: &Stores, addr: &Hash20, lifetime: bool) -> Option<AddrRead> {
    read_via_index_at(db, addr, lifetime, fresh_tip(db)?)
}

/// The index's answer for `at_tip`, the tip `fresh_tip` returned before the call: None when the
/// marker or the tip is no longer `at_tip` once the read is done, or a read failed.
pub fn read_via_index_at(db: &Stores, addr: &Hash20, lifetime: bool, at_tip: Hash32) -> Option<AddrRead> {
    let tip_height = get_hidx(db, &at_tip).ok().flatten()?.height;
    let mut utxos = Vec::new();
    for kv in db.idx.scan_prefix(k_addr_prefix(addr)) {
        let (k, _) = kv.ok()?;
        let op = decode_outpoint(&k[ADDR_OUT.len() + 20..])?;
        if let Some(out) = get_utxo(db, &op).ok()? {
            if out.script_pubkey == *addr {
                utxos.push(with_meta(db, op, &out));
            }
        }
    }
    let totals = match lifetime {
        true => {
            let (mined, outputs) = lifetime_of(db, addr).ok()?;
            Some((u64::try_from(mined).unwrap_or(u64::MAX), outputs))
        }
        false => None,
    };
    // A new block between the two tip reads may have changed what the index holds.
    if idx_tip(db) != Some(at_tip) || get_tip(db).ok().flatten() != Some(at_tip) {
        return None;
    }
    Some(AddrRead { tip: Some(at_tip), tip_height, utxos, lifetime: totals, via_index: true })
}

/// The UTXO tree row the scan reads, or None for a key or value the scan skips. Besides the
/// `k_utxo` form it accepts the raw 36-byte key, a form nothing in this repo writes.
fn utxo_row(k: &[u8], v: &[u8]) -> Option<(OutPoint, TxOut)> {
    let op = match k.len() {
        37 if k[0] == b'U' => decode_outpoint(&k[1..])?,
        36 => decode_outpoint(k)?,
        _ => return None,
    };
    let out: TxOut = c().deserialize(v).ok()?;
    Some((op, out))
}

fn scan_rows(db: &Stores, mut f: impl FnMut(OutPoint, TxOut)) {
    for (k, v) in db.utxo.iter().flatten() {
        if let Some((op, out)) = utxo_row(&k, &v) {
            f(op, out);
        }
    }
}

/// `addr`'s unspent outputs read from the whole UTXO tree.
pub fn scan_utxos(db: &Stores, addr: &Hash20) -> Vec<AddrUtxo> {
    let mut utxos = Vec::new();
    scan_rows(db, |op, out| {
        if out.script_pubkey == *addr {
            utxos.push(with_meta(db, op, &out));
        }
    });
    utxos
}

/// The scan's answer: the UTXO tree read whole and, when asked for, the block walk.
pub fn read_via_scan(db: &Stores, addr: &Hash20, lifetime: bool) -> Result<AddrRead> {
    let tip = get_tip(db).ok().flatten();
    let tip_height = tip
        .and_then(|t| get_hidx(db, &t).ok().flatten())
        .map(|hi| hi.height)
        .unwrap_or(0);
    let utxos = scan_utxos(db, addr);
    let totals = match lifetime {
        true => Some(lifetime_walk(db, tip, addr)?),
        false => None,
    };
    Ok(AddrRead { tip, tip_height, utxos, lifetime: totals, via_index: false })
}

/// Visits the stored chain from `tip` down by `header.prev`, until genesis, height 0, a missing
/// body or one that does not decode.
fn walk_blocks(db: &Stores, tip: Option<Hash32>, mut f: impl FnMut(&Block)) -> Result<()> {
    let mut cur = tip.unwrap_or([0u8; 32]);
    let mut height = get_hidx(db, &cur).ok().flatten().map(|hi| hi.height).unwrap_or(0);
    loop {
        let Some(v) = db.blocks.get(k_block(&cur)).context("read a block body")? else {
            return Ok(());
        };
        let Ok(blk) = c().deserialize::<Block>(&v) else {
            return Ok(());
        };
        f(&blk);
        if blk.header.prev == [0u8; 32] || height == 0 {
            return Ok(());
        }
        cur = blk.header.prev;
        height -= 1;
    }
}

/// (mined, outputs) of every coinbase output paying `addr` on the chain from `tip` down: one read
/// and decode per block.
pub fn lifetime_walk(db: &Stores, tip: Option<Hash32>, addr: &Hash20) -> Result<(u64, u64)> {
    let (mut mined, mut outputs) = (0u64, 0u64);
    walk_blocks(db, tip, |blk| {
        for out in lifetime_outputs(blk).iter().filter(|o| o.script_pubkey == *addr) {
            mined = mined.saturating_add(out.value);
            outputs = outputs.saturating_add(1);
        }
    })?;
    Ok((mined, outputs))
}

// -----------------------------------------------------------------------------
// The offline comparison (`csd utxo-index-check` and the replay tests)
// -----------------------------------------------------------------------------

/// The result of comparing the index with the scan over a whole datadir.
#[derive(Debug)]
pub struct IndexCheck {
    pub tip: Hash32,
    pub height: u64,
    /// Addresses compared: every address the UTXO tree, the index or a coinbase on the chain names.
    pub addresses: usize,
    pub utxo_rows: usize,
    pub index_entries: usize,
    pub lifetime_addresses: usize,
    pub mismatches: Vec<String>,
}

/// For every address the UTXO tree, the index or a coinbase on the chain names, compares the
/// index's read (`read_via_index`, the one /utxos uses) with the scan's (`scan_utxos` and the block
/// walk), and checks that the index holds exactly the UTXO tree's outputs. Needs the index current
/// at the tip.
pub fn check_against_scan(db: &Stores) -> Result<IndexCheck> {
    let Some(tip) = fresh_tip(db) else {
        bail!(
            "the index is not current at the tip (marker {}, tip {})",
            idx_tip(db).map(hex::encode).unwrap_or_else(|| "none".into()),
            get_tip(db).ok().flatten().map(hex::encode).unwrap_or_else(|| "none".into())
        );
    };
    let height = get_hidx(db, &tip)?.ok_or_else(|| anyhow!("no header index for the tip"))?.height;
    let mut mismatches = Vec::new();

    let mut row_owner: HashMap<OutPoint, Hash20> = HashMap::new();
    scan_rows(db, |op, out| {
        row_owner.insert(op, out.script_pubkey);
    });
    let utxo_rows = row_owner.len();
    let holders: BTreeSet<Hash20> = row_owner.values().copied().collect();

    let mut walked: BTreeMap<Hash20, (u64, u64)> = BTreeMap::new();
    walk_blocks(db, Some(tip), |blk| {
        for out in lifetime_outputs(blk) {
            let e = walked.entry(out.script_pubkey).or_default();
            *e = (e.0.saturating_add(out.value), e.1.saturating_add(1));
        }
    })?;

    let mut addresses: BTreeSet<Hash20> = holders.iter().chain(walked.keys()).copied().collect();
    let mut index_entries = 0usize;
    for kv in db.idx.scan_prefix(ADDR_OUT) {
        let (k, _) = kv?;
        index_entries += 1;
        let (Some(addr), Some(op)) = (
            decode_addr(&k[ADDR_OUT.len()..ADDR_OUT.len() + 20]),
            decode_outpoint(&k[ADDR_OUT.len() + 20..]),
        ) else {
            mismatches.push(format!("undecodable index key {}", hex::encode(&k)));
            continue;
        };
        addresses.insert(addr);
        if owner_of(db, &op)? != Some(addr) {
            mismatches.push(format!("entry {}:{} of 0x{} has no matching owner entry", hex::encode(op.txid), op.vout, hex::encode(addr)));
        }
        if row_owner.get(&op) != Some(&addr) {
            mismatches.push(format!("index names {}:{} for 0x{}, the UTXO tree does not", hex::encode(op.txid), op.vout, hex::encode(addr)));
        }
    }
    let owners = db.idx.scan_prefix(OUT_OWNER).count();
    if index_entries != utxo_rows || owners != utxo_rows {
        mismatches.push(format!("index holds {index_entries} entries and {owners} owners, the UTXO tree {utxo_rows} rows"));
    }
    let mut lifetime_addresses = 0usize;
    for kv in db.idx.scan_prefix(LIFETIME) {
        let (k, _) = kv?;
        lifetime_addresses += 1;
        if let Some(addr) = decode_addr(&k[LIFETIME.len()..]) {
            addresses.insert(addr);
        }
    }

    for addr in &addresses {
        let Some(got) = read_via_index(db, addr, true) else {
            mismatches.push(format!("0x{}: the index read fell back to the scan", hex::encode(addr)));
            continue;
        };
        let want = if holders.contains(addr) { scan_utxos(db, addr) } else { Vec::new() };
        if got.utxos != want {
            mismatches.push(format!(
                "0x{}: index {} outputs, scan {} (or a different order or field)",
                hex::encode(addr),
                got.utxos.len(),
                want.len()
            ));
        }
        let want_life = walked.get(addr).copied().unwrap_or((0, 0));
        if got.lifetime != Some(want_life) {
            mismatches.push(format!("0x{}: lifetime index {:?}, walk {want_life:?}", hex::encode(addr), got.lifetime));
        }
        if got.tip_height != height {
            mismatches.push(format!("0x{}: tip height {} against {height}", hex::encode(addr), got.tip_height));
        }
    }

    Ok(IndexCheck {
        tip,
        height,
        addresses: addresses.len(),
        utxo_rows,
        index_entries,
        lifetime_addresses,
        mismatches,
    })
}

// docs/behaviour.md "The address index", lifetime totals: a miner that recycles its own coins
// through fees into its own coinbases can carry an address's mined total past u64::MAX. The index
// keeps the exact total and serves it capped at u64::MAX, the block walk's saturated answer.
#[cfg(test)]
mod lifetime_limit_tests {
    use super::*;
    use crate::chain::index::{header_hash, put_hidx, HeaderIndex};
    use crate::chain::mine::coinbase;
    use crate::params::COIN;
    use crate::state::db::set_tip;
    use crate::state::tx_index::{index_canonical_block, unindex_canonical_block};
    use crate::types::BlockHeader;

    /// Stores a block on `prev`, with its header index, whose coinbase pays `value` to `addr`.
    fn put_block(db: &Stores, prev: Hash32, height: u64, addr: Hash20, value: u64) -> Result<Hash32> {
        let header = BlockHeader { version: 1, prev, merkle: [0u8; 32], time: height, bits: 0, nonce: 0 };
        let hash = header_hash(&header);
        let blk = Block { header, txs: vec![coinbase(addr, value, height, None)] };
        db.blocks.insert(k_block(&hash), c().serialize(&blk)?)?;
        put_hidx(db, &HeaderIndex { hash, parent: prev, height, chainwork: height.into(), bits: 0, time: height })?;
        Ok(hash)
    }

    /// Indexes `hash` as the reconciler does and makes it the tip.
    fn connect(db: &Stores, hash: &Hash32, height: u64) -> Result<()> {
        assert!(index_canonical_block(db, hash, height)?);
        set_tip(db, hash)
    }

    type Totals = Option<(u64, u64)>;

    /// The lifetime totals /utxos serves for `addr` (`read`, the handler's call), whether the index
    /// answered, and the totals the scan's block walk answers at the same tip.
    fn served_and_walked(db: &Stores, addr: &Hash20) -> Result<(Totals, bool, Totals)> {
        let r = read(db, addr, true)?;
        Ok((r.lifetime, r.via_index, read_via_scan(db, addr, true)?.lifetime))
    }

    #[test]
    fn lifetime_totals_past_u64_max_are_stored_exactly_served_capped_and_taken_back_out() -> Result<()> {
        let dir = tempfile::TempDir::new()?;
        let db = Stores::open(dir.path().to_str().context("temp path")?)?;
        crate::state::tx_scan::reset_index(&db)?; // the version marker, as the reconciler writes it first
        let (honest, a): (Hash20, Hash20) = ([0x11; 20], [0x42; 20]);
        let b0 = put_block(&db, [0u8; 32], 0, honest, 50 * COIN)?;
        let b1 = put_block(&db, b0, 1, a, u64::MAX - 10)?;
        let b2 = put_block(&db, b1, 2, a, 100)?;
        connect(&db, &b0, 0)?;
        connect(&db, &b1, 1)?;
        let below = Some((u64::MAX - 10, 1));
        assert_eq!(served_and_walked(&db, &a)?, (below, true, below));

        connect(&db, &b2, 2)?;
        assert_eq!(lifetime_of(&db, &a)?, (u128::from(u64::MAX) + 90, 2), "the total past u64::MAX is stored exactly");
        let capped = Some((u64::MAX, 2));
        assert_eq!(served_and_walked(&db, &a)?, (capped, true, capped), "served capped, the walk's answer");
        let ordinary = Some((50 * COIN, 1));
        assert_eq!(served_and_walked(&db, &honest)?, (ordinary, true, ordinary), "an ordinary total as before");

        // A reorg back across the limit: taking b2 out restores the exact total before it.
        unindex_canonical_block(&db, &b2, 2, Some(&b1))?;
        set_tip(&db, &b1)?;
        assert_eq!(lifetime_of(&db, &a)?, (u128::from(u64::MAX - 10), 1));
        assert_eq!(served_and_walked(&db, &a)?, (below, true, below));
        Ok(())
    }
}
