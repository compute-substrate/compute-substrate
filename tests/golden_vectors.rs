// tests/golden_vectors.rs
//
// Golden vectors for consensus invariants.
// These tests are meant to fail loudly if ANY consensus-critical byte layout changes.
//
// Workflow:
// 1) To (re)generate vectors after an intentional consensus change:
//      cargo test -q --test golden_vectors -- --ignored --nocapture
//    Then copy the printed values into the EXPECT_* consts below.
// 2) Normal freeze test:
//      cargo test -q --test golden_vectors
//
// NOTE: integration tests import the crate by *package name*.
// Your package is `csd` (as shown by "could not compile `csd` (test ...)").
//
// If you rename the package, update `use csd as cs;` accordingly.

use csd as cs;

fn hex32(h: &[u8; 32]) -> String {
    format!("0x{}", hex::encode(h))
}

fn hex_bytes(b: &[u8]) -> String {
    format!("0x{}", hex::encode(b))
}

// ---------------------------
// FROZEN EXPECTATIONS
// ---------------------------
//
// After you run the ignored regen test, paste the printed values here.
// Keep these as *strings* so diffs are clean in git.
//
// IMPORTANT: These should ONLY change if you are intentionally hard-forking
// consensus serialization/hashing rules.

const EXPECT_POW_LIMIT_BITS: u32 = cs::params::POW_LIMIT_BITS;

// Update these from regen output:
const EXPECT_POW_LIMIT_TARGET: &str =
    "0x0000ffff00000000000000000000000000000000000000000000000000000000";

// You already observed a drift here; update EXPECT_TXID to match current output
// once you confirm regen print matches the runtime you intend to freeze.
const EXPECT_TXID: &str =
    "0xcfbb845b508307bffbaebb5b8fe82fa03677b0c75b497e4b58c9f45645c8421e";

// Fill these from regen output (or keep old if they still match):
const EXPECT_SIGHASH: &str =
    "0xd45485be974d2a1f43252e866be1e0af9bc469e0c3f04024266a6a25b9f1ff17";

const EXPECT_HEADER_HASH: &str =
    "0x43d20f3acdf747e099025c89abed445c29275d8891b6e8469b3d64543af82b06";

// These bytes are the *consensus_bincode* bytes of the constructed objects.
// If these drift, you have a consensus-breaking serialization change.
const EXPECT_HDR_CONSENSUS_BYTES: &str =
    "0x010000000101010101010101010101010101010101010101010101010101010101010101020202020202020202020202020202020202020202020202020202020202020200f1536500000000ffff001f78563412";

const EXPECT_TX_CONSENSUS_BYTES: &str =
    "0x0100000001000000000000000707070707070707070707070707070707070707070707070707070707070707030000000500000000000000010203040502000000000000002a000000000000000909090909090909090909090909090909090909e80300000000000008080808080808080808080808080808080808083930000000000000";

// ---------------------------
// TEST VECTOR CONSTRUCTION
// ---------------------------

fn make_header() -> cs::types::BlockHeader {
    cs::types::BlockHeader {
        version: 1,
        prev: [0x01u8; 32],
        merkle: [0x02u8; 32],
        time: 1700000000,          // 0x6553f100
        bits: cs::params::POW_LIMIT_BITS, // 0x1f00ffff
        nonce: 0x12345678,
    }
}

fn make_tx() -> cs::types::Transaction {
    use cs::types::{AppPayload, OutPoint, Transaction, TxIn, TxOut};

    Transaction {
        version: 1,
        inputs: vec![TxIn {
            prevout: OutPoint {
                txid: [0u8; 32],
                vout: 3,
            },
            // IMPORTANT: txid()/sighash() strip this. This is here to ensure stripping is stable.
            script_sig: vec![1, 2, 3, 4, 5],
        }],
        outputs: vec![
            TxOut {
                value: 42,
                script_pubkey: [9u8; 20],
            },
            TxOut {
                value: 1000,
                script_pubkey: [8u8; 20],
            },
        ],
        locktime: 0x3939, // 14649
        app: AppPayload::None,
    }
}

// ---------------------------
// REGEN (ignored) TEST
// ---------------------------

#[test]
#[ignore]
fn golden_vectors_regen_print() {
    println!("POW_LIMIT_BITS=0x{:08x}", EXPECT_POW_LIMIT_BITS);

    let t = cs::chain::pow::bits_to_target_bytes(EXPECT_POW_LIMIT_BITS);
    println!("POW_LIMIT target={}", hex32(&t));

    let tx = make_tx();
    let txid = cs::crypto::txid(&tx);
    let sighash = cs::crypto::sighash(&tx);
    println!("txid={}", hex32(&txid));
    println!("sighash={}", hex32(&sighash));

    let hdr = make_header();
    let h = cs::chain::index::header_hash(&hdr);
    println!("header_hash={}", hex32(&h));

    let hdr_bytes = cs::codec::consensus_bincode().serialize(&hdr).unwrap();
    let tx_bytes = cs::codec::consensus_bincode().serialize(&tx).unwrap();
    println!("hdr_consensus_bytes={}", hex_bytes(&hdr_bytes));
    println!("tx_consensus_bytes={}", hex_bytes(&tx_bytes));
}

// ---------------------------
// FREEZE TEST
// ---------------------------

#[test]
fn golden_vectors_freeze() {
    // POW limit target bytes
    let t = cs::chain::pow::bits_to_target_bytes(EXPECT_POW_LIMIT_BITS);
    assert_eq!(hex32(&t), EXPECT_POW_LIMIT_TARGET);

    // txid/sighash stability
    let tx = make_tx();
    let txid = cs::crypto::txid(&tx);
    let sighash = cs::crypto::sighash(&tx);
    assert_eq!(hex32(&txid), EXPECT_TXID);
    assert_eq!(hex32(&sighash), EXPECT_SIGHASH);

    // header hash stability
    let hdr = make_header();
    let hh = cs::chain::index::header_hash(&hdr);
    assert_eq!(hex32(&hh), EXPECT_HEADER_HASH);

    // consensus serialization stability
    let hdr_bytes = cs::codec::consensus_bincode().serialize(&hdr).unwrap();
    let tx_bytes = cs::codec::consensus_bincode().serialize(&tx).unwrap();
    assert_eq!(hex_bytes(&hdr_bytes), EXPECT_HDR_CONSENSUS_BYTES);
    assert_eq!(hex_bytes(&tx_bytes), EXPECT_TX_CONSENSUS_BYTES);
}
