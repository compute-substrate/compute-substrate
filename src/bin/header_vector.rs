use csd::chain::index::header_hash;
use csd::chain::pow::bits_to_target_bytes;
use csd::types::BlockHeader;

fn main() {
    let hdr = BlockHeader {
        version: 1,
        prev: [0x11u8; 32],
        merkle: [0x22u8; 32],
        time: 1_781_309_630,
        bits: 0x1f7fffff,
        nonce: 12345,
    };
    let mut raw = [0u8; 84];
    raw[0..4].copy_from_slice(&hdr.version.to_le_bytes());
    raw[4..36].copy_from_slice(&hdr.prev);
    raw[36..68].copy_from_slice(&hdr.merkle);
    raw[68..76].copy_from_slice(&hdr.time.to_le_bytes());
    raw[76..80].copy_from_slice(&hdr.bits.to_le_bytes());
    raw[80..84].copy_from_slice(&hdr.nonce.to_le_bytes());
    println!("header=0x{}", hex::encode(raw));
    println!("target=0x{}", hex::encode(bits_to_target_bytes(hdr.bits)));
    println!("nonce={}", hdr.nonce);
    println!("hash=0x{}", hex::encode(header_hash(&hdr)));
}
