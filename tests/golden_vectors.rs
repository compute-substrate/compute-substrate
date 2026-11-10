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
// Re-frozen for POW_LIMIT_BITS = 0x1e00ffff (exponent 30 -> 3 leading zero bytes). The old value
// 0x0000ffff... was for 0x1f00ffff and was never updated when mainnet tightened the pow limit.
const EXPECT_POW_LIMIT_TARGET: &str =
    "0x000000ffff000000000000000000000000000000000000000000000000000000";
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

/// n - s on the 256-bit big-endian S half of a compact signature, n the secp256k1 group order:
/// the other valid S for the same signature, so a low-S signature turns into its high-S twin.
fn high_s_twin(sig64: &[u8; 64]) -> [u8; 64] {
    const N: [u8; 32] = [
        0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFE,
        0xBA, 0xAE, 0xDC, 0xE6, 0xAF, 0x48, 0xA0, 0x3B, 0xBF, 0xD2, 0x5E, 0x8C, 0xD0, 0x36, 0x41, 0x41,
    ];
    let mut out = *sig64;
    let mut borrow = 0i16;
    for i in (0..32).rev() {
        let mut d = N[i] as i16 - sig64[32 + i] as i16 - borrow;
        borrow = 0;
        if d < 0 {
            d += 256;
            borrow = 1;
        }
        out[32 + i] = d as u8;
    }
    out
}

// The LOW-S rule of `crypto::verify_sig`: a signature is accepted only in its low-S form, so a
// signed transaction has one valid signature encoding, not two.
#[test]
fn a_high_s_signature_is_refused_and_its_low_s_twin_verifies() {
    let sk = [7u8; 32];
    let tx = make_tx();
    let (sig64, pub33) = csd::crypto::sign_tx_compact_secp256k1(&tx, sk);

    csd::crypto::verify_sig(&tx, &sig64, &pub33).expect("the low-S signature verifies");

    let high = high_s_twin(&sig64);
    assert_ne!(high, sig64);
    assert_eq!(high_s_twin(&high), sig64, "n - (n - s) = s");
    assert!(
        csd::crypto::verify_sig(&tx, &high, &pub33).is_err(),
        "the high-S twin of a valid signature must be refused"
    );
}
