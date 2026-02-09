// tests/golden_vectors.rs
//
// Golden vectors: consensus invariants.
// If any of these change, it's a HARD FORK (or DB / wire incompat).
//
// Run:
//   cargo test -q --test golden_vectors -- --nocapture
// Or (if you keep them ignored):
//   cargo test -q --test golden_vectors -- --ignored --nocapture

use csd as csd;

fn hex32(b: [u8; 32]) -> String {
    format!("0x{}", hex::encode(b))
}

#[test]
fn golden_vectors_freeze() {
    // 1) POW limit target bytes (bits -> target)
    let pow_limit_bits = csd::params::POW_LIMIT_BITS;
    assert_eq!(pow_limit_bits, 0x1f00ffff);

    let target = csd::chain::pow::bits_to_target_bytes(pow_limit_bits);
    assert_eq!(
        hex32(target),
        "0x0000ffff00000000000000000000000000000000000000000000000000000000"
    );

    // 2) txid() / sighash() invariants for a synthetic tx
    // This matches the bytes your test printed (tx_consensus_bytes=...).
    let tx = csd::types::Transaction {
        version: 1,
        inputs: vec![csd::types::TxIn {
            prevout: csd::types::OutPoint {
                txid: [7u8; 32],
                vout: 3,
            },
            script_sig: vec![1, 2, 3, 4, 5],
        }],
        outputs: vec![
            csd::types::TxOut {
                value: 42,
                script_pubkey: [9u8; 20],
            },
            csd::types::TxOut {
                value: 1000,
                script_pubkey: [8u8; 20],
            },
        ],
        locktime: 0x00000039,
        app: csd::types::AppPayload::None,
    };

    let txid = csd::crypto::txid(&tx);
    assert_eq!(
        hex32(txid),
        "0x064e34c1b49cfbad85b25d621f8d8f1a4c0902d07736a170abeb73dddeeb4481"
    );

    let sighash = csd::crypto::sighash(&tx);
    assert_eq!(
        hex32(sighash),
        "0xd45485be974d2a1f43252e866be1e0af9bc469e0c3f04024266a6a25b9f1ff17"
    );

    // 3) header_hash() byte layout invariant for a synthetic header
    let hdr = csd::types::BlockHeader {
        version: 1,
        prev: [1u8; 32],
        merkle: [2u8; 32],
        time: 0x000000006553f100, // 1700000000 LE in your printed bytes
        bits: 0x1f00ffff,
        nonce: 0x12345678,
    };

    let hh = csd::chain::index::header_hash(&hdr);
    assert_eq!(
        hex32(hh),
        "0x43d20f3acdf747e099025c89abed445c29275d8891b6e8469b3d64543af82b06"
    );

    // 4) Consensus serialization bytes are frozen too
    // Header bytes from your output:
    // hdr_consensus_bytes=
    // 0x
    // 01000000
    // 01..(32x)
    // 02..(32x)
    // 00f1536500000000
    // ffff001f
    // 78563412
    let hdr_bytes = csd::codec::consensus_bincode().serialize(&hdr).unwrap();
    assert_eq!(
        format!("0x{}", hex::encode(hdr_bytes)),
        "0x010000000101010101010101010101010101010101010101010101010101010101010101020202020202020202020202020202020202020202020202020202020202020200f1536500000000ffff001f78563412"
    );

    // Tx bytes from your output:
    let tx_bytes = csd::codec::consensus_bincode().serialize(&tx).unwrap();
    assert_eq!(
        format!("0x{}", hex::encode(tx_bytes)),
        "0x0100000001000000000000000707070707070707070707070707070707070707070707070707070707070707030000000500000000000000010203040502000000000000002a000000000000000909090909090909090909090909090909090909e80300000000000008080808080808080808080808080808080808083930000000000000"
    );
}
