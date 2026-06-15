use csd::chain::index::header_hash;
use csd::types::BlockHeader;
use std::time::{Duration, Instant};

fn main() {
    let secs: u64 = std::env::args()
        .nth(1)
        .and_then(|s| s.parse().ok())
        .unwrap_or(2);
    let until = Instant::now() + Duration::from_secs(secs);
    let mut hdr = BlockHeader {
        version: 1,
        prev: [1u8; 32],
        merkle: [2u8; 32],
        time: 1_781_309_630,
        bits: 0x1b019c51,
        nonce: 0,
    };
    let mut n: u64 = 0;
    while Instant::now() < until {
        let _ = header_hash(&hdr);
        hdr.nonce = hdr.nonce.wrapping_add(1);
        n += 1;
    }
    let elapsed = secs as f64;
    println!("hashes={n} seconds={elapsed:.3} hps={:.3}", n as f64 / elapsed);
}
