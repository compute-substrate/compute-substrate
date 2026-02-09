// tests/golden_vectors.rs
use csd as csd;

fn hex32(b: &[u8; 32]) -> String {
    format!("0x{}", hex::encode(b))
}
fn hex_bytes(b: &[u8]) -> String {
    format!("0x{}", hex::encode(b))
}

fn u32_be(x: u32) -> [u8; 4] {
    x.to_be_bytes()
}

#[test]
fn golden_bits_to_target_pow_limit() {
    // This one you *can* make golden immediately, because it’s purely bits->target.
    // Fill EXPECTED_TARGET_BE once using the generator test below.
    let target = csd::chain::pow::bits_to_target_bytes(csd::params::POW_LIMIT_BITS);

    const EXPECTED_TARGET_BE_HEX: &str = "0xTODO_PASTE_TARGET32";
    assert_eq!(hex32(&target), EXPECTED_TARGET_BE_HEX);
}

#[test]
fn golden_txid_and_sighash() {
    use csd::types::*;

    // A deterministic tx (not coinbase) with fixed fields.
    // NOTE: txid()/sighash() strip script_sig, so script_sig content must not matter here.
    let tx = Transaction {
        version: 1,
        inputs: vec![TxIn {
            prevout: OutPoint {
                txid: [7u8; 32],
                vout: 3,
            },
            script_sig: vec![1, 2, 3, 4, 5], // should be stripped
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
        locktime: 12345,
        app: AppPayload::None,
    };

    let txid = csd::crypto::txid(&tx);
    let sigh = csd::crypto::sighash(&tx);

    const EXPECTED_TXID_HEX: &str = "0xTODO_PASTE_TXID32";
    const EXPECTED_SIGHASH_HEX: &str = "0xTODO_PASTE_SIGHASH32";

    assert_eq!(hex32(&txid), EXPECTED_TXID_HEX);
    assert_eq!(hex32(&sigh), EXPECTED_SIGHASH_HEX);
}

#[test]
fn golden_header_hash_layout() {
    use csd::types::*;

    // Fixed header with explicit fields.
    // If you ever change header layout, endian, nonce width, etc. this will trip.
    let hdr = BlockHeader {
        version: 1,
        prev: [1u8; 32],
        merkle: [2u8; 32],
        time: 1700000000,
        bits: 0x1f00ffff,
        nonce: 0x12345678,
    };

    let h = csd::chain::index::header_hash(&hdr);

    const EXPECTED_HEADER_HASH_HEX: &str = "0xTODO_PASTE_HDRHASH32";
    assert_eq!(hex32(&h), EXPECTED_HEADER_HASH_HEX);
}

/// One-time helper: prints the exact bytes/hashes you must paste into the constants above.
/// Run with:
///   cargo test -q --test golden_vectors -- --ignored --nocapture
#[test]
#[ignore]
fn _print_vectors_once() {
    use csd::types::*;

    // ---- bits -> target ----
    let target = csd::chain::pow::bits_to_target_bytes(csd::params::POW_LIMIT_BITS);
    println!("POW_LIMIT_BITS=0x{:08x}", csd::params::POW_LIMIT_BITS);
    println!("POW_LIMIT target={}", hex32(&target));

    // ---- txid/sighash ----
    let tx = Transaction {
        version: 1,
        inputs: vec![TxIn {
            prevout: OutPoint {
                txid: [7u8; 32],
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
        locktime: 12345,
        app: AppPayload::None,
    };
    println!("txid={}", hex32(&csd::crypto::txid(&tx)));
    println!("sighash={}", hex32(&csd::crypto::sighash(&tx)));

    // ---- header_hash ----
    let hdr = BlockHeader {
        version: 1,
        prev: [1u8; 32],
        merkle: [2u8; 32],
        time: 1700000000,
        bits: 0x1f00ffff,
        nonce: 0x12345678,
    };
    println!("header_hash={}", hex32(&csd::chain::index::header_hash(&hdr)));

    // Optional: also print the exact consensus-serialized bytes if you want to freeze that too.
    let hdr_bytes = csd::codec::consensus_bincode().serialize(&hdr).unwrap();
    println!("hdr_consensus_bytes={}", hex_bytes(&hdr_bytes));
    let tx_bytes = csd::codec::consensus_bincode().serialize(&tx).unwrap();
    println!("tx_consensus_bytes={}", hex_bytes(&tx_bytes));
}
