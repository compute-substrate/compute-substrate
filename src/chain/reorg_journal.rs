// src/chain/reorg_journal.rs
use anyhow::{Context, Result};
use serde::{Deserialize, Deserializer, Serialize};

use crate::chain::failpoints;
use crate::state::db::{k_reorg_in_progress, meta_del, meta_get_bytes, meta_put_bytes, Stores};
use crate::types::Hash32;

#[derive(Clone, Copy, Debug, Serialize, PartialEq, Eq)]
pub enum Phase {
    Undo,  // undoing old branch toward ancestor
    Apply, // applying new branch from ancestor toward new_tip
}

// Backward/forward compatible Phase decoding.
// - Accepts "Undo"/"Apply" (string form)
// - Accepts 0/1 (u64) in case an older encoding wrote variants numerically
impl<'de> Deserialize<'de> for Phase {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct PhaseVisitor;

        impl<'de> serde::de::Visitor<'de> for PhaseVisitor {
            type Value = Phase;

            fn expecting(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
                write!(f, "Phase as \"Undo\"|\"Apply\" or 0|1")
            }

            fn visit_str<E>(self, v: &str) -> std::result::Result<Self::Value, E>
            where
                E: serde::de::Error,
            {
                match v {
                    "Undo" => Ok(Phase::Undo),
                    "Apply" => Ok(Phase::Apply),
                    other => Err(E::custom(format!("unknown Phase string: {other}"))),
                }
            }

            fn visit_u64<E>(self, v: u64) -> std::result::Result<Self::Value, E>
            where
                E: serde::de::Error,
            {
                match v {
                    0 => Ok(Phase::Undo),
                    1 => Ok(Phase::Apply),
                    other => Err(E::custom(format!("unknown Phase discrim: {other}"))),
                }
            }

            fn visit_i64<E>(self, v: i64) -> std::result::Result<Self::Value, E>
            where
                E: serde::de::Error,
            {
                if v < 0 {
                    return Err(E::custom("Phase discrim must be non-negative"));
                }
                self.visit_u64(v as u64)
            }
        }

        // Try to deserialize as either string or integer.
        deserializer.deserialize_any(PhaseVisitor)
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ReorgJournal {
    pub old_tip: Hash32,
    pub new_tip: Hash32,
    pub ancestor: Hash32,
    pub phase: Phase,

    // How far we progressed:
    // - Undo phase: number of blocks undone from old branch
    // - Apply phase: number of blocks applied on new branch
    pub cursor: u64,

    // Full paths (hashes only; bytes live in db.blocks)
    pub undo_path: Vec<Hash32>,  // old_tip -> ancestor (exclusive)
    pub apply_path: Vec<Hash32>, // ancestor -> new_tip (exclusive)
}

pub fn journal_read(db: &Stores) -> Result<Option<ReorgJournal>> {
    let Some(v) = meta_get_bytes(db, k_reorg_in_progress())? else {
        return Ok(None);
    };
    let j = crate::codec::consensus_bincode()
        .deserialize::<ReorgJournal>(&v)
        .context("decode reorg journal")?;
    Ok(Some(j))
}

/// Persist the crash-recovery journal.
/// MAINNET HARDENING:
/// - Flush only the meta tree so a kill -9 never leaves a "stale" journal on disk.
///
/// TEST HARDENING:
/// - failpoints around journal boundaries.
pub fn journal_write(db: &Stores, j: &ReorgJournal) -> Result<()> {
    failpoints::hit("journal_write:pre");

    let bytes = crate::codec::consensus_bincode()
        .serialize(j)
        .context("encode reorg journal")?;

    meta_put_bytes(db, k_reorg_in_progress(), &bytes)?;

    failpoints::hit("journal_write:pre_flush");
    db.meta.flush().context("flush meta after journal_write")?;
    failpoints::hit("journal_write:post_flush");

    Ok(())
}

/// Clear the journal after successful completion (or clean rollback).
pub fn journal_clear(db: &Stores) -> Result<()> {
    failpoints::hit("journal_clear:pre");

    meta_del(db, k_reorg_in_progress())?;

    failpoints::hit("journal_clear:pre_flush");
    db.meta.flush().context("flush meta after journal_clear")?;
    failpoints::hit("journal_clear:post_flush");

    Ok(())
}
