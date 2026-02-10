// tests/golden_vectors.rs
//
// Golden vectors for consensus-critical hashing/serialization.
// Run the printer (ignored) when you *intentionally* change consensus bytes:
//
//   cargo test -q --test golden_vectors -- --ignored --nocapture
//
// Then paste the emitted constants into the EXPECT_* below and re-run:
//
//   cargo test -q --test golden_vectors
//

use csd::{
    chain::{index::header_hash, pow::bits_to_target_bytes},
    crypto::{sighash, txid},
    params::{POW_LIMIT_BITS},
    types::{AppPayload, BlockHeader, Hash20, OutPoint, Transaction, TxIn, TxOut},
};

fn hex32(h: &[u8; 32]) -> String {
    format!("0x{}", hex::encode(h))
}

fn hex_bytes(b: &[u8]) -> String {
    format!("0x{}", hex::encode(b))
}

// --- PASTE THESE INTO tests/golden_vectors.rs ---
const EXPECT_POW_LIMIT_TARGET: &str =
    "0x0000ffff00000000000000000000000000000000000000000000000000000000";
const EXPECT_TXID: &str =
    "0x876f5cbd6770ce8679730b8ad565ba136fa30bd750ef4f3345b8f7289393dd6b";
const EXPECT_SIGHASH: &str =
    "0x4a852522eed155b7763f425df1233daa132482e47249696905cdcc775a5113e2";
const EXPECT_HEADER_HASH: &str =
    "0x43d20f3acdf747e099025c89abed445c29275d8891b6e8469b3d64543af82b06";
const EXPECT_HDR_CONSENSUS_BYTES: &str =
    "0x010000000101010101010101010101010101010101010101010101010101010101010101020202020202020202020202020202020202020202020202020202020202020200f1536500000000ffff001f78563412";
const EXPECT_TX_CONSENSUS_BYTES: &str =
    "0x0100000001000000000000000000000000000000000000000000000000000000000000000000000000000000030000000500000000000000010203040502000000000000002a000000000000000909090909090909090909090909090909090909e80300000000000008080808080808080808080808080808080808083939000000000000";
// --- END ---

fn make_header() -> BlockHeader {
    BlockHeader {
        version: 1,
        prev: [0x01u8; 32],
        merkle: [0x02u8; 32],
        // 1700000000
        time: 1_700_000_000u64,
        // 0x1f00ffff
        bits: 0x1f00ffffu32,
        // 0x12345678
        nonce: 0x12345678u32,
    }
}

fn make_tx() -> Transaction {
    Transaction {
        version: 1,
        inputs: vec![TxIn {
            prevout: OutPoint {
                // all-zero txid in this synthetic vector
                txid: [0u8; 32],
                vout: 3,
            },
            // script_sig will be stripped for txid/sighash anyway, but is included for bytes vector
            script_sig: vec![1, 2, 3, 4, 5],
        }],
        outputs: vec![
            TxOut {
                value: 42,
                script_pubkey: [0x09u8; 20] as Hash20,
            },
            TxOut {
                value: 1000,
                script_pubkey: [0x08u8; 20] as Hash20,
            },
        ],
        // 0x3939 (14649)
        locktime: 0x3939u32,
        app: AppPayload::None,
    }
}

#[test]
fn golden_vectors_freeze() {
    // POW limit target bytes
    let pow_limit_target = bits_to_target_bytes(POW_LIMIT_BITS);
    assert_eq!(hex32(&pow_limit_target), EXPECT_POW_LIMIT_TARGET);

    // TX id + sighash
    let tx = make_tx();
    let got_txid = txid(&tx);
    let got_sighash = sighash(&tx);
    assert_eq!(hex32(&got_txid), EXPECT_TXID);
    assert_eq!(hex32(&got_sighash), EXPECT_SIGHASH);

    // Header hash
    let hdr = make_header();
    let got_hh = header_hash(&hdr);
    assert_eq!(hex32(&got_hh), EXPECT_HEADER_HASH);

    // Consensus bytes (frozen bincode settings)
    let hdr_bytes = csd::codec::consensus_bincode()
        .serialize(&hdr)
        .expect("serialize header");
    let tx_bytes = csd::codec::consensus_bincode()
        .serialize(&tx)
        .expect("serialize tx");
    assert_eq!(hex_bytes(&hdr_bytes), EXPECT_HDR_CONSENSUS_BYTES);
    assert_eq!(hex_bytes(&tx_bytes), EXPECT_TX_CONSENSUS_BYTES);
}

#[test]
#[ignore]
fn golden_vectors_print_constants() {
    let pow_limit_target = bits_to_target_bytes(POW_LIMIT_BITS);
    let tx = make_tx();
    let hdr = make_header();

    let got_txid = txid(&tx);
    let got_sighash = sighash(&tx);
    let got_hh = header_hash(&hdr);

    let hdr_bytes = csd::codec::consensus_bincode()
        .serialize(&hdr)
        .expect("serialize header");
    let tx_bytes = csd::codec::consensus_bincode()
        .serialize(&tx)
        .expect("serialize tx");

    println!("\n--- PASTE THESE INTO tests/golden_vectors.rs ---");
    println!(
        "const EXPECT_POW_LIMIT_TARGET: &str = \"{}\";",
        hex32(&pow_limit_target)
    );
    println!("const EXPECT_TXID: &str = \"{}\";", hex32(&got_txid));
    println!(
        "const EXPECT_SIGHASH: &str = \"{}\";",
        hex32(&got_sighash)
    );
    println!(
        "const EXPECT_HEADER_HASH: &str = \"{}\";",
        hex32(&got_hh)
    );
    println!(
        "const EXPECT_HDR_CONSENSUS_BYTES: &str = \"{}\";",
        hex_bytes(&hdr_bytes)
    );
    println!(
        "const EXPECT_TX_CONSENSUS_BYTES: &str = \"{}\";",
        hex_bytes(&tx_bytes)
    );
    println!("--- END ---\n");
}
