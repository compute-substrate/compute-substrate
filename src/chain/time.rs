// src/chain/time.rs
use anyhow::Result;

use crate::chain::index::get_hidx;
use crate::params::MTP_WINDOW;
use crate::state::db::Stores;
use crate::types::Hash32;

/// Median Time Past (MTP) over the last `MTP_WINDOW` headers ending at `tip` (inclusive).
///
/// Deterministic behavior:
/// - Walks back via HeaderIndex.parent links.
/// - If the chain is shorter than `MTP_WINDOW`, uses whatever is available.
/// - If `tip` cannot be resolved to a header index entry, returns 0 (defensive).
///
/// Notes:
/// - Purely derived from indexed chain data (no wallclock).
pub fn median_time_past(db: &Stores, tip: &Hash32) -> Result<u64> {
    // Be robust to MTP_WINDOW being defined as u64 in params.
    let window: usize = MTP_WINDOW as usize;

    let mut times: Vec<u64> = Vec::with_capacity(window);
    let mut cur = *tip;

    for _ in 0..window {
        let Some(hi) = get_hidx(db, &cur)? else {
            break;
        };

        times.push(hi.time);

        cur = hi.parent;
        if cur == [0u8; 32] {
            break;
        }
    }

    if times.is_empty() {
        return Ok(0);
    }

    times.sort_unstable();
    Ok(times[times.len() / 2])
}
