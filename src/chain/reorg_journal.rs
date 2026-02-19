// src/chain/reorg_journal.rs
use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use sled::transaction::{ConflictableTransactionError, TransactionError};

use crate::chain::failpoints;
use crate::state::db::{meta_get_bytes, Stores};
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

fn decode(bytes: &[u8]) -> Result<ReorgJournal> {
    crate::codec::consensus_bincode()
        .deserialize::<ReorgJournal>(bytes)
        .context("decode reorg journal")
}

fn encode(j: &ReorgJournal) -> Result<Vec<u8>> {
    crate::codec::consensus_bincode()
        .serialize(j)
        .context("encode reorg journal")
}

fn read_active_best_effort(db: &Stores) -> Result<u8> {
    match meta_get_bytes(db, k_reorg_active())? {
        Some(v) if !v.is_empty() => Ok(v[0] & 1),
        _ => Ok(0),
    }
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
    // Active pointer is advisory; we still pick max(seq) across both slots.
    let active = read_active_best_effort(db).context("read_active_best_effort")?;

    let a = match meta_get_bytes(db, k_reorg_slot_a())? {
        Some(v) => decode(&v).ok(),
        None => None,
    };
    let b = match meta_get_bytes(db, k_reorg_slot_b())? {
        Some(v) => decode(&v).ok(),
        None => None,
    };

    let picked = match (a, b) {
        (None, None) => return Ok(None),
        (Some(x), None) => x,
        (None, Some(y)) => y,
        (Some(x), Some(y)) => {
            if y.seq > x.seq {
                y
            } else if x.seq > y.seq {
                x
            } else {
                // Tie-break: prefer the active slot
                let prefer_a = (active & 1) == 0;
                if prefer_a { x } else { y }
            }
        }
    };

    Ok(Some(picked))
}

pub fn journal_write(db: &Stores, j: &ReorgJournal) -> Result<()> {
    failpoints::hit("journal_write:pre");

    // Atomic update: write inactive slot + flip active pointer together.
    db.meta
        .transaction(|tx| {
            // Read current active *inside* transaction.
            let active = match tx.get(k_reorg_active())? {
                Some(v) if !v.is_empty() => v[0] & 1,
                _ => 0,
            };
            let target = other_slot(active);
            let target_key = slot_key(target);

            // Compute next seq from both slots (decode best-effort).
            let a_seq = match tx.get(k_reorg_slot_a())? {
                Some(v) => decode(&v).ok().map(|jj| jj.seq).unwrap_or(0),
                None => 0,
            };
            let b_seq = match tx.get(k_reorg_slot_b())? {
                Some(v) => decode(&v).ok().map(|jj| jj.seq).unwrap_or(0),
                None => 0,
            };
            let next_seq = a_seq.max(b_seq).saturating_add(1);

            let mut jj = j.clone();
            jj.seq = next_seq;

            let bytes = match encode(&jj) {
                Ok(b) => b,
                Err(e) => return Err(ConflictableTransactionError::Abort(e)),
            };

            // We want the crash-fuzz failpoint to be meaningful:
            // it should occur BEFORE we make the journal durable.
            failpoints::hit("journal_write:pre_flush");

            // 1) Write new bytes to inactive slot
            tx.insert(target_key, bytes)?;

            // 2) Flip active pointer
            tx.insert(k_reorg_active(), vec![target & 1])?;

            Ok(())
        })
        .map_err(|e: TransactionError<anyhow::Error>| match e {
            TransactionError::Abort(ae) => ae,
            TransactionError::Storage(se) => anyhow::anyhow!(se),
        })
        .context("meta.transaction(journal_write)")?;

    // ✅ CRITICAL: durability barrier for crash-fuzz
    // Transaction commit is atomic but not guaranteed durable across a simulated crash.
    db.db.flush().context("db.flush after journal_write")?;

    failpoints::hit("journal_write:post_flush");
    Ok(())
}

pub fn journal_clear(db: &Stores) -> Result<()> {
    failpoints::hit("journal_clear:pre");

    db.meta
        .transaction(|tx| {
            // Same deal: allow fuzz to crash before the durable barrier.
            failpoints::hit("journal_clear:pre_flush");

            tx.remove(k_reorg_active())?;
            tx.remove(k_reorg_slot_a())?;
            tx.remove(k_reorg_slot_b())?;

            Ok(())
        })
        .map_err(|e: TransactionError<anyhow::Error>| match e {
            TransactionError::Abort(ae) => ae,
            TransactionError::Storage(se) => anyhow::anyhow!(se),
        })
        .context("meta.transaction(journal_clear)")?;

    // ✅ CRITICAL: durability barrier for crash-fuzz
    db.db.flush().context("db.flush after journal_clear")?;

    failpoints::hit("journal_clear:post_flush");
    Ok(())
}
