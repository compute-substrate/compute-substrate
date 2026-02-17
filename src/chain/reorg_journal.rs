// src/chain/reorg_journal.rs
use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};

use crate::chain::failpoints;
use crate::state::db::{meta_del, meta_get_bytes, meta_put_bytes, Stores};
use crate::types::Hash32;

// ----------------------
// Keys (double-buffered journal)
// ----------------------
fn k_reorg_slot_a() -> &'static [u8] {
    b"reorg:in_progress:a"
}
fn k_reorg_slot_b() -> &'static [u8] {
    b"reorg:in_progress:b"
}
fn k_reorg_active() -> &'static [u8] {
    b"reorg:in_progress:active"
}

fn read_active(db: &Stores) -> Result<u8> {
    match meta_get_bytes(db, k_reorg_active())? {
        Some(v) if !v.is_empty() => Ok(v[0] & 1),
        _ => Ok(0),
    }
}

fn write_active(db: &Stores, which: u8) -> Result<()> {
    meta_put_bytes(db, k_reorg_active(), &[which & 1])?;
    db.meta.flush().context("flush meta after write_active")?;
    Ok(())
}

fn slot_key(which: u8) -> &'static [u8] {
    if (which & 1) == 0 {
        k_reorg_slot_a()
    } else {
        k_reorg_slot_b()
    }
}

fn other_slot(which: u8) -> u8 {
    (which ^ 1) & 1
}

// ----------------------
// Types
// ----------------------

#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub enum Phase {
    Undo,
    Apply,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ReorgJournal {
    // Monotonic journal version. Lets us select the newest valid record if both exist.
    // Old journals (from before this field existed) decode with seq=0.
    #[serde(default)]
    pub seq: u64,

    pub old_tip: Hash32,
    pub new_tip: Hash32,
    pub ancestor: Hash32,
    pub phase: Phase,
    pub cursor: u64,

    pub undo_path: Vec<Hash32>,
    pub apply_path: Vec<Hash32>,
}

// ----------------------
// Read / write / clear
// ----------------------

pub fn journal_read(db: &Stores) -> Result<Option<ReorgJournal>> {
    // Try active slot first; if missing/corrupt, fall back to the other slot.
    let active = read_active(db).context("read_active")?;
    let a_key = slot_key(active);
    let b_key = slot_key(other_slot(active));

    let decode = |bytes: &[u8]| -> Result<ReorgJournal> {
        crate::codec::consensus_bincode()
            .deserialize::<ReorgJournal>(bytes)
            .context("decode reorg journal")
    };

    let a = match meta_get_bytes(db, a_key)? {
        Some(v) => decode(&v).ok(),
        None => None,
    };

    let b = match meta_get_bytes(db, b_key)? {
        Some(v) => decode(&v).ok(),
        None => None,
    };

    // Prefer newest seq; tie-break prefers active slot (a).
    let picked = match (a, b) {
        (None, None) => return Ok(None),
        (Some(x), None) => x,
        (None, Some(y)) => y,
        (Some(x), Some(y)) => {
            if y.seq > x.seq {
                y
            } else {
                x
            }
        }
    };

    Ok(Some(picked))
}

pub fn journal_write(db: &Stores, j: &ReorgJournal) -> Result<()> {
    failpoints::hit("journal_write:pre");

    let active = read_active(db).context("read_active")?;
    let target = other_slot(active);
    let target_key = slot_key(target);

    // ✅ Monotonic seq derived from DB state (max(seqA, seqB) + 1)
    let decode = |bytes: &[u8]| -> Result<ReorgJournal> {
        crate::codec::consensus_bincode()
            .deserialize::<ReorgJournal>(bytes)
            .context("decode reorg journal")
    };

    let a_seq = match meta_get_bytes(db, k_reorg_slot_a())? {
        Some(v) => decode(&v).ok().map(|jj| jj.seq).unwrap_or(0),
        None => 0,
    };
    let b_seq = match meta_get_bytes(db, k_reorg_slot_b())? {
        Some(v) => decode(&v).ok().map(|jj| jj.seq).unwrap_or(0),
        None => 0,
    };
    let next_seq = a_seq.max(b_seq).saturating_add(1);

    let mut jj = j.clone();
    jj.seq = next_seq;

    let bytes = crate::codec::consensus_bincode()
        .serialize(&jj)
        .context("encode reorg journal")?;

    // 1) Write new bytes to inactive slot
    meta_put_bytes(db, target_key, &bytes)?;

    failpoints::hit("journal_write:pre_flush");

    // Make the slot write durable
    db.meta.flush().context("flush meta after journal_write(slot)")?;

    failpoints::hit("journal_write:post_flush");

    // 2) Flip active pointer (durable)
    write_active(db, target).context("write_active")?;

    Ok(())
}

pub fn journal_clear(db: &Stores) -> Result<()> {
    failpoints::hit("journal_clear:pre");

    meta_del(db, k_reorg_active())?;
    meta_del(db, k_reorg_slot_a())?;
    meta_del(db, k_reorg_slot_b())?;

    failpoints::hit("journal_clear:pre_flush");
    db.meta.flush().context("flush meta after journal_clear")?;
    failpoints::hit("journal_clear:post_flush");

    Ok(())
}
