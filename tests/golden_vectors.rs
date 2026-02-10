// tests/golden_vectors.rs
//
// Golden vectors for consensus invariants.
// If these drift unintentionally, you've made a consensus-breaking change.
//
// Usage:
//   1) Regen (prints fresh EXPECT_* lines):
//        cargo test -q --test golden_vectors -- --ignored --nocapture
//   2) Freeze (must pass in CI):
//        cargo test -q --test golden_vectors

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
// After running the regen test, paste the printed EXPECT_* lines here.
// ONLY change these when you intentionally hard-fork consensus.

const EXPECT_POW_LIMIT_BITS: u32 = cs::params::POW_LIMIT_BITS;

// NOTE: update all these from regen output as a *set*
const EXPECT_POW_LIMIT_TARGET: &str =
    "0x0000ffff00000000000000000000000000000000000000000000000000000000";

const EXPECT_TXID: &str =
    "0x876f5cbd6770ce8679730b8ad565ba136fa30bd750ef4f3345b8f7289393dd6b";

const EXPECT_SIGHASH: &str =
    "0xd45485be974d2a1f43252e866be1e0af9bc469e0c3f04024266a6a25b9f1ff17";

const EXPECT_HEADER_HASH: &str =
    "0x43d20f3acdf747e099025c89abed445c29275d8891b6e8469b3d64543af82b06";

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
        time: 1700000000,
        bits: cs::params::POW_LIMIT_BITS,
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
        locktime: 0x3939,
        app: AppPayload::None,
    }
}

// ---------------------------
// REGEN (ignored) TEST
// ---------------------------

#[test]
#[ignore]
fn golden_vectors_regen_print() {
    let t = cs::chain::pow::bits_to_target_bytes(EXPECT_POW_LIMIT_BITS);

    let tx = make_tx();
    let txid = cs::crypto::txid(&tx);
    let sighash = cs::crypto::sighash(&tx);

    let hdr = make_header();
    let hh = cs::chain::index::header_hash(&hdr);

    let hdr_bytes = cs::codec::consensus_bincode().serialize(&hdr).unwrap();
    let tx_bytes = cs::codec::consensus_bincode().serialize(&tx).unwrap();

    println!("\n--- PASTE THESE INTO tests/golden_vectors.rs ---");
    println!("const EXPECT_POW_LIMIT_TARGET: &str = \"{}\";", hex32(&t));
    println!("const EXPECT_TXID: &str = \"{}\";", hex32(&txid));
    println!("const EXPECT_SIGHASH: &str = \"{}\";", hex32(&sighash));
    println!("const EXPECT_HEADER_HASH: &str = \"{}\";", hex32(&hh));
    println!("const EXPECT_HDR_CONSENSUS_BYTES: &str = \"{}\";", hex_bytes(&hdr_bytes));
    println!("const EXPECT_TX_CONSENSUS_BYTES: &str = \"{}\";", hex_bytes(&tx_bytes));
    println!("--- END ---\n");
}

// ---------------------------
// FREEZE TEST
// ---------------------------

#[test]
fn golden_vectors_freeze() {
    // Compute actuals
    let t = cs::chain::pow::bits_to_target_bytes(EXPECT_POW_LIMIT_BITS);

    let tx = make_tx();
    let txid = cs::crypto::txid(&tx);
    let sighash = cs::crypto::sighash(&tx);

    let hdr = make_header();
    let hh = cs::chain::index::header_hash(&hdr);

    let hdr_bytes = cs::codec::consensus_bincode().serialize(&hdr).unwrap();
    let tx_bytes = cs::codec::consensus_bincode().serialize(&tx).unwrap();

    // Helpful debug prints on failure
    let got_pow_target = hex32(&t);
    let got_txid = hex32(&txid);
    let got_sighash = hex32(&sighash);
    let got_header_hash = hex32(&hh);
    let got_hdr_bytes = hex_bytes(&hdr_bytes);
    let got_tx_bytes = hex_bytes(&tx_bytes);

    if got_txid != EXPECT_TXID {
        eprintln!("[golden_vectors] txid mismatch");
        eprintln!("  got:  {}", got_txid);
        eprintln!("  want: {}", EXPECT_TXID);
    }

    // Assert freeze invariants
    assert_eq!(got_pow_target, EXPECT_POW_LIMIT_TARGET);
    assert_eq!(got_txid, EXPECT_TXID);
    assert_eq!(got_sighash, EXPECT_SIGHASH);
    assert_eq!(got_header_hash, EXPECT_HEADER_HASH);
    assert_eq!(got_hdr_bytes, EXPECT_HDR_CONSENSUS_BYTES);
    assert_eq!(got_tx_bytes, EXPECT_TX_CONSENSUS_BYTES);
}
