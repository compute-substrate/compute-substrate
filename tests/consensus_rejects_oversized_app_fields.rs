// tests/consensus_rejects_oversized_app_fields.rs
use anyhow::{Context, Result};
use std::sync::Arc;
use tempfile::TempDir;

use csd::chain::index::{get_hidx, header_hash, index_header};
use csd::crypto::hash160;
use csd::params::{MAX_DOMAIN_BYTES, MAX_URI_BYTES, MIN_FEE_PROPOSE};
use csd::state::app_state::epoch_of;
use csd::state::db::{get_tip, k_block, k_utxo, put_utxo_meta, set_tip, Stores, UtxoMeta};
use csd::state::utxo::validate_and_apply_block;
use csd::types::{AppPayload, Block, Hash20, Hash32, OutPoint, Transaction, TxIn, TxOut};

mod testutil_chain;
use testutil_chain::{make_test_header, open_db};

const SK: [u8; 32] = [21u8; 32];

fn h20(n: u8) -> Hash20 {
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
    hash160(&pub33)
}

fn insert_spendable_utxo(
    db: &Stores,
    op: OutPoint,
    value: u64,
    owner: [u8; 20],
    height: u64,
) -> Result<()> {
    let out = TxOut {
        value,
        script_pubkey: owner,
    };

    db.utxo.insert(
        k_utxo(&op),
        csd::codec::consensus_bincode().serialize(&out)?,
    )?;

    put_utxo_meta(
        db,
        &op,
        &UtxoMeta {
            height,
            coinbase: false,
        },
    )?;

    Ok(())
}

fn persist_index_apply_block(db: &Stores, blk: &Block, height: u64) -> Result<Hash32> {
    let bh = header_hash(&blk.header);

    let bytes = csd::codec::consensus_bincode()
        .serialize(blk)
        .context("serialize block")?;
    db.blocks
        .insert(k_block(&bh), bytes)
        .context("db.blocks.insert")?;

    let parent_hi = if blk.header.prev == [0u8; 32] {
        None
    } else {
        get_hidx(db, &blk.header.prev).context("get_hidx(parent)")?
    };

    index_header(db, &blk.header, parent_hi.as_ref()).context("index_header")?;
    validate_and_apply_block(db, blk, epoch_of(height), height)
        .with_context(|| format!("apply h={height}"))?;
    set_tip(db, &bh).context("set_tip")?;

    Ok(bh)
}

fn make_signed_propose_tx(
    prevout: OutPoint,
    input_value: u64,
    fee: u64,
    to: [u8; 20],
    domain: String,
    uri: String,
) -> Transaction {
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
        app: AppPayload::Propose {
            domain,
            payload_hash: [7u8; 32],
            uri,
            expires_epoch: 999_999,
        },
    };

    let (sig64, pub33) = csd::crypto::sign_tx_compact_secp256k1(&tx, SK);

    let mut ss = Vec::with_capacity(99);
    ss.push(64);
    ss.extend_from_slice(&sig64);
    ss.push(33);
    ss.extend_from_slice(&pub33);
    tx.inputs[0].script_sig = ss;

    tx
}

fn current_tip_and_next_height(db: &Stores) -> Result<(Hash32, u64)> {
    let tip = get_tip(db)?
        .context("missing tip")?;
    let hi = get_hidx(db, &tip)?
        .context("missing tip hidx")?;
    Ok((tip, hi.height + 1))
}

#[test]
fn rejects_propose_with_domain_too_long() -> Result<()> {
    let tmp = TempDir::new().context("tmp")?;
    let db = Arc::new(open_db(&tmp).context("open db")?);

    let owner = signer_addr(SK);
    let miner = h20(0xAA);

    let (tip, height) = current_tip_and_next_height(&db)?;

    let prevout = OutPoint {
        txid: [0xD1; 32],
        vout: 0,
    };
    let input_value = 1_000_000u64;
    let fee = MIN_FEE_PROPOSE;

    insert_spendable_utxo(&db, prevout, input_value, owner, height - 1)
        .context("insert spendable utxo")?;

    let bad_tx = make_signed_propose_tx(
        prevout,
        input_value,
        fee,
        h20(0x44),
        "d".repeat(MAX_DOMAIN_BYTES + 1),
        "https://example.com/ok".to_string(),
    );

    let cb = csd::chain::mine::coinbase(
        miner,
        csd::params::block_reward(height) + fee,
        height,
        None,
    );
    let txs = vec![cb, bad_tx];

    let hdr = make_test_header(&db, tip, &txs, height)
        .with_context(|| format!("make_test_header h={height}"))?;
    let blk = Block { header: hdr, txs };

    let err = validate_and_apply_block(&db, &blk, epoch_of(height), height)
        .expect_err("block with oversized propose.domain must be rejected");

    let msg = format!("{err:#}");
    assert!(
        msg.contains("propose domain too long"),
        "unexpected error: {msg}"
    );

    Ok(())
}

#[test]
fn rejects_propose_with_uri_too_long() -> Result<()> {
    let tmp = TempDir::new().context("tmp")?;
    let db = Arc::new(open_db(&tmp).context("open db")?);

    let owner = signer_addr(SK);
    let miner = h20(0xBB);

    let (tip, height) = current_tip_and_next_height(&db)?;

    let prevout = OutPoint {
        txid: [0xD2; 32],
        vout: 0,
    };
    let input_value = 1_000_000u64;
    let fee = MIN_FEE_PROPOSE;

    insert_spendable_utxo(&db, prevout, input_value, owner, height - 1)
        .context("insert spendable utxo")?;

    let bad_tx = make_signed_propose_tx(
        prevout,
        input_value,
        fee,
        h20(0x55),
        "valid-domain".to_string(),
        "u".repeat(MAX_URI_BYTES + 1),
    );

    let cb = csd::chain::mine::coinbase(
        miner,
        csd::params::block_reward(height) + fee,
        height,
        None,
    );
    let txs = vec![cb, bad_tx];

    let hdr = make_test_header(&db, tip, &txs, height)
        .with_context(|| format!("make_test_header h={height}"))?;
    let blk = Block { header: hdr, txs };

    let err = validate_and_apply_block(&db, &blk, epoch_of(height), height)
        .expect_err("block with oversized propose.uri must be rejected");

    let msg = format!("{err:#}");
    assert!(
        msg.contains("propose uri too long"),
        "unexpected error: {msg}"
    );

    Ok(())
}
