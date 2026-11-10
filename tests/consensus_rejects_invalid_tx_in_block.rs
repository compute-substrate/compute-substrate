// tests/consensus_rejects_invalid_tx_in_block.rs
#![cfg(feature = "test-bypass")] // toy-chain fixture: needs the PoW/genesis bypass (cargo test --features test-bypass)
use anyhow::{Context, Result};
use tempfile::TempDir;

use csd::chain::index::header_hash;
use csd::crypto::txid;
use csd::state::db::{k_utxo, put_utxo_meta, Stores, UtxoMeta};
use csd::net::mempool::Mempool;
use csd::types::{AppPayload, Block, OutPoint, Transaction, TxIn, TxOut};

mod testutil_chain;
use testutil_chain::{build_base_chain_with_miner, make_test_header, open_db};

const SK: [u8; 32] = [21u8; 32];

fn h20(n: u8) -> [u8; 20] {
    [n; 20]
}

fn signer_addr(sk32: [u8; 32]) -> [u8; 20] {
    let dummy = Transaction {
        version: 1,
        inputs: vec![TxIn {
            prevout: OutPoint {
                txid: [0u8; 32],
                vout: 0,
            },
            script_sig: vec![],
        }],
        outputs: vec![TxOut {
            value: 1,
            script_pubkey: [0u8; 20],
        }],
        locktime: 0,
        app: AppPayload::None,
    };

    let (_sig64, pub33) = csd::crypto::sign_tx_compact_secp256k1(&dummy, sk32);
    csd::crypto::hash160(&pub33)
}

/// A coin with its UtxoMeta, as an applied block leaves it: `validate_and_apply_block` reads the
/// meta of every input it spends and refuses a coin without one ("missing utxo meta").
fn insert_utxo(db: &Stores, op: OutPoint, value: u64, owner: [u8; 20]) -> Result<()> {
    let out = TxOut {
        value,
        script_pubkey: owner,
    };

    db.utxo.insert(
        k_utxo(&op),
        csd::codec::consensus_bincode().serialize(&out)?,
    )?;
    put_utxo_meta(db, &op, &UtxoMeta { height: 1, coinbase: false })?;

    Ok(())
}

fn make_signed_tx(prevout: OutPoint, input_value: u64, fee: u64, to: [u8; 20]) -> Transaction {
    make_signed_tx_by(SK, prevout, input_value, fee, to)
}

/// A spend of `prevout` signed by `sk`, whoever owns the coin.
fn make_signed_tx_by(sk: [u8; 32], prevout: OutPoint, input_value: u64, fee: u64, to: [u8; 20]) -> Transaction {
    let send = input_value - fee;

    let mut tx = Transaction {
        version: 1,
        inputs: vec![TxIn {
            prevout,
            script_sig: vec![0u8; 99],
        }],
        outputs: vec![TxOut {
            value: send,
            script_pubkey: to,
        }],
        locktime: 0,
        app: AppPayload::None,
    };

    let (sig64, pub33) = csd::crypto::sign_tx_compact_secp256k1(&tx, sk);

    let mut ss = Vec::with_capacity(99);
    ss.push(64);
    ss.extend_from_slice(&sig64);
    ss.push(33);
    ss.extend_from_slice(&pub33);
    tx.inputs[0].script_sig = ss;

    tx
}

fn persist_index_apply_block(db: &Stores, blk: &Block, height: u64) -> Result<[u8; 32]> {
    let bh = header_hash(&blk.header);

    let bytes = csd::codec::consensus_bincode()
        .serialize(blk)
        .context("serialize block")?;
    db.blocks
        .insert(csd::state::db::k_block(&bh), bytes)
        .context("db.blocks.insert")?;

    let parent_hi = if blk.header.prev == [0u8; 32] {
        None
    } else {
        csd::chain::index::get_hidx(db, &blk.header.prev).context("get_hidx(parent)")?
    };

    csd::chain::index::index_header(db, &blk.header, parent_hi.as_ref()).context("index_header")?;
    csd::state::utxo::validate_and_apply_block(db, blk, csd::state::app_state::epoch_of(height), height)
        .with_context(|| format!("validate_and_apply_block h={height}"))?;
    csd::state::db::set_tip(db, &bh).context("set_tip")?;

    Ok(bh)
}

fn setup_tip() -> Result<(tempfile::TempDir, Stores, [u8; 32], u64)> {
    let tmp = TempDir::new()?;
    let db = open_db(&tmp)?;
    let miner = h20(0x11);

    let shared_len = 7u64;
    let start_time = 1_701_100_000u64;

    let shared = build_base_chain_with_miner(&db, shared_len, start_time, miner)
        .context("build shared chain")?;
    let tip = shared[(shared_len - 1) as usize];

    Ok((tmp, db, tip, shared_len))
}

#[test]
fn rejects_block_with_bad_signature_in_non_coinbase_tx() -> Result<()> {
    let (_tmp, db, parent_tip, next_height) = setup_tip()?;

    let owner = signer_addr(SK);
    let prevout = OutPoint {
        txid: [0x11; 32],
        vout: 0,
    };
    let value = 1_000_000u64;
    insert_utxo(&db, prevout, value, owner)?;

    let mut bad_tx = make_signed_tx(prevout, value, 5_000, h20(0x41));
    bad_tx.inputs[0].script_sig[10] ^= 0x01; // corrupt signature bytes

    let cb = csd::chain::mine::coinbase(
        h20(0xAA),
        csd::params::block_reward(next_height),
        next_height,
        None,
    );

    let txs = vec![cb, bad_tx];
    let hdr = make_test_header(&db, parent_tip, &txs, next_height)?;
    let blk = Block { header: hdr, txs };

    let err = persist_index_apply_block(&db, &blk, next_height).unwrap_err();
    let msg = format!("{err:#}");
    assert!(
        msg.contains("signature")
            || msg.contains("sig")
            || msg.contains("script")
            || msg.contains("witness")
            || msg.contains("verify"),
        "unexpected error: {msg}"
    );

    Ok(())
}

#[test]
fn rejects_block_with_missing_input_utxo() -> Result<()> {
    let (_tmp, db, parent_tip, next_height) = setup_tip()?;

    let missing_prevout = OutPoint {
        txid: [0x22; 32],
        vout: 0,
    };

    let bad_tx = make_signed_tx(missing_prevout, 1_000_000, 5_000, h20(0x42));

    let cb = csd::chain::mine::coinbase(
        h20(0xAA),
        csd::params::block_reward(next_height),
        next_height,
        None,
    );

    let txs = vec![cb, bad_tx];
    let hdr = make_test_header(&db, parent_tip, &txs, next_height)?;
    let blk = Block { header: hdr, txs };

    let err = persist_index_apply_block(&db, &blk, next_height).unwrap_err();
    let msg = format!("{err:#}");
    assert!(
        msg.contains("missing")
            || msg.contains("utxo")
            || msg.contains("prevout")
            || msg.contains("not found"),
        "unexpected error: {msg}"
    );

    Ok(())
}

#[test]
fn rejects_block_with_outputs_exceeding_inputs() -> Result<()> {
    let (_tmp, db, parent_tip, next_height) = setup_tip()?;

    let owner = signer_addr(SK);
    let prevout = OutPoint {
        txid: [0x33; 32],
        vout: 0,
    };
    let value = 1_000_000u64;
    insert_utxo(&db, prevout, value, owner)?;

    // Construct the overspend transaction FIRST, then sign that exact tx.
    let send = value + 1; // outputs exceed inputs
    let mut bad_tx = Transaction {
        version: 1,
        inputs: vec![TxIn {
            prevout,
            script_sig: vec![0u8; 99],
        }],
        outputs: vec![TxOut {
            value: send,
            script_pubkey: h20(0x43),
        }],
        locktime: 0,
        app: AppPayload::None,
    };

    let (sig64, pub33) = csd::crypto::sign_tx_compact_secp256k1(&bad_tx, SK);
    let mut ss = Vec::with_capacity(99);
    ss.push(64);
    ss.extend_from_slice(&sig64);
    ss.push(33);
    ss.extend_from_slice(&pub33);
    bad_tx.inputs[0].script_sig = ss;

    let cb = csd::chain::mine::coinbase(
        h20(0xAA),
        csd::params::block_reward(next_height),
        next_height,
        None,
    );

    let txs = vec![cb, bad_tx];
    let hdr = make_test_header(&db, parent_tip, &txs, next_height)?;
    let blk = Block { header: hdr, txs };

    let err = persist_index_apply_block(&db, &blk, next_height).unwrap_err();
    let msg = format!("{err:#}");

    assert!(
        msg.contains("exceed")
            || msg.contains("inputs")
            || msg.contains("outputs")
            || msg.contains("fee")
            || msg.contains("money range")
            || msg.contains("in_sum")
            || msg.contains("out_sum"),
        "unexpected error: {msg}"
    );

    Ok(())
}

#[test]
fn rejects_block_with_double_spend_inside_same_block() -> Result<()> {
    let (_tmp, db, parent_tip, next_height) = setup_tip()?;

    let owner = signer_addr(SK);
    let prevout = OutPoint {
        txid: [0x44; 32],
        vout: 0,
    };
    let value = 1_000_000u64;
    insert_utxo(&db, prevout, value, owner)?;

    let tx1 = make_signed_tx(prevout, value, 5_000, h20(0x51));
    let tx2 = make_signed_tx(prevout, value, 7_000, h20(0x52));

    assert_ne!(txid(&tx1), txid(&tx2), "sanity: txids should differ");

    // The coin has its meta and the coinbase pays both fees, so the second spend of the coin is
    // the only fault in this block: the block is refused at tx2, after tx1 spent the coin.
    let cb = csd::chain::mine::coinbase(
        h20(0xAA),
        csd::params::block_reward(next_height) + 5_000 + 7_000,
        next_height,
        None,
    );

    let txs = vec![cb, tx1, tx2];
    let hdr = make_test_header(&db, parent_tip, &txs, next_height)?;
    let blk = Block { header: hdr, txs };

    let err = persist_index_apply_block(&db, &blk, next_height).unwrap_err();
    assert_eq!(
        err.root_cause().to_string(),
        "missing utxo",
        "the in-block double spend must be refused at the second spend: {err:#}"
    );

    Ok(())
}

// The owner check (utxo.rs validate_tx_inputs_outputs: the spent output's hash20 must be the
// hash160 of the input's pubkey) is the spend authorization. A coin owned by key A, spent with a
// signature that verifies under key B's pubkey, is refused at block validation and at mempool
// admission. The owner's own spend of the same coin is the paired honest path.
#[test]
fn a_coin_spent_with_another_keys_valid_signature_is_refused() -> Result<()> {
    const OTHER_SK: [u8; 32] = [22u8; 32];
    let (_tmp, db, parent_tip, next_height) = setup_tip()?;

    let owner = signer_addr(SK);
    assert_ne!(owner, signer_addr(OTHER_SK), "fixture: two different keys");
    let prevout = OutPoint {
        txid: [0x55; 32],
        vout: 0,
    };
    let value = 1_000_000u64;
    let fee = 5_000u64;
    insert_utxo(&db, prevout, value, owner)?;

    let thief = make_signed_tx_by(OTHER_SK, prevout, value, fee, h20(0x61));
    let (sig64, pub33) = csd::state::utxo::parse_scriptsig(&thief.inputs[0].script_sig)?;
    csd::crypto::verify_sig(&thief, &sig64, &pub33).context("fixture: the thief's signature is valid")?;

    let err = Mempool::new()
        .insert_checked(&db, thief.clone())
        .expect_err("admission must refuse a spend by a key that does not own the coin");
    assert_eq!(err.root_cause().to_string(), "pubkey hash mismatch", "admission: {err:#}");

    let cb = |paid_fee: u64| {
        csd::chain::mine::coinbase(
            h20(0xAA),
            csd::params::block_reward(next_height) + paid_fee,
            next_height,
            None,
        )
    };
    let txs = vec![cb(fee), thief];
    let hdr = make_test_header(&db, parent_tip, &txs, next_height)?;
    let err = persist_index_apply_block(&db, &Block { header: hdr, txs }, next_height).unwrap_err();
    assert_eq!(err.root_cause().to_string(), "pubkey hash mismatch", "block: {err:#}");

    // Honest path: the owner's spend of the same coin is admitted and its block applies.
    let honest = make_signed_tx(prevout, value, fee, h20(0x62));
    assert!(Mempool::new().insert_checked(&db, honest.clone())?, "the owner's spend is admitted");
    let txs = vec![cb(fee), honest];
    let hdr = make_test_header(&db, parent_tip, &txs, next_height)?;
    persist_index_apply_block(&db, &Block { header: hdr, txs }, next_height)
        .context("the owner's spend must apply")?;

    Ok(())
}
