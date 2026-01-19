use anyhow::Result;
use serde::{Serialize, Deserialize};

use crate::types::{Hash32, BlockHeader};
use crate::crypto::sha256d;
use crate::state::db::{Stores, k_hdr};

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct HeaderIndex {
    pub hash: Hash32,
    pub parent: Hash32,
    pub height: u64,
    pub chainwork: u128,
    pub bits: u32,
    pub time: u64,
}

pub fn header_hash(h: &BlockHeader) -> Hash32 {
    let bytes = bincode::serialize(h).expect("serialize header");
    sha256d(&bytes)
}

/// Very simple "work" function for v0:
/// higher difficulty (lower target) should mean more work.
/// This is NOT Bitcoin-accurate; it is deterministic and monotonic for our bits format.
fn work_from_bits(bits: u32) -> u128 {
    // bits format here is arbitrary; we just make work increase as bits decreases.
    // Avoid division by zero:
    let x = (bits as u128).max(1);
    (1u128 << 64) / x
}

pub fn get_hidx(db: &Stores, hash: &Hash32) -> Result<Option<HeaderIndex>> {
    if let Some(v) = db.hdr.get(k_hdr(hash))? {
        Ok(Some(bincode::deserialize(&v)?))
    } else {
        Ok(None)
    }
}

pub fn put_hidx(db: &Stores, hi: &HeaderIndex) -> Result<()> {
    db.hdr.insert(k_hdr(&hi.hash), bincode::serialize(hi)?)?;
    Ok(())
}

/// Insert a header index entry (requires parent known unless height==0 genesis).
pub fn index_header(db: &Stores, hdr: &BlockHeader, expected_parent: Option<&HeaderIndex>) -> Result<HeaderIndex> {
    let hash = header_hash(hdr);

    let (height, chainwork) = if hdr.prev == [0u8; 32] {
        (0u64, work_from_bits(hdr.bits))
    } else {
        let p = expected_parent.expect("parent must be provided");
        (p.height + 1, p.chainwork + work_from_bits(hdr.bits))
    };

    let hi = HeaderIndex {
        hash,
        parent: hdr.prev,
        height,
        chainwork,
        bits: hdr.bits,
        time: hdr.time,
    };

    put_hidx(db, &hi)?;
    Ok(hi)
}
