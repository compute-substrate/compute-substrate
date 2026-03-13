// tests/consensus_rejects_oversized_app_fields.rs
use anyhow::{Context, Result};
use std::sync::Arc;
use tempfile::TempDir;

use csd::crypto::{hash160, sha256d, txid};
use csd::params::{MAX_DOMAIN_BYTES, MAX_URI_BYTES, MIN_FEE_PROPOSE};
use csd::state::app_state::epoch_of;
use csd::state::db::{k_utxo, put_utxo_meta, Stores, UtxoMeta};
use csd::state::utxo::validate_and_apply_block;
use csd::types::{AppPayload, Block, BlockHeader, Hash20, OutPoint, Transaction, TxIn, TxOut};

mod testutil_chain;
use testutil_chain::open_db;

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

fn merkle_root_txids(txids: &[[u8; 32]]) -> [u8; 32] {
    if txids.is_empty() {
        return [0u8; 32];
    }

    let mut layer: Vec<[u8; 32]> = txids.to_vec();
    while layer.len() > 1 {
        let mut next = Vec::with_capacity((layer.len() + 1) / 2);
        let mut i = 0usize;

        while i < layer.len() {
            let left = layer[i];
            let right = if i + 1 < layer.len() { layer[i + 1] } else { layer[i] };

            let mut buf = [0u8; 64];
            buf[..32].copy_from_slice(&left);
            buf[32..].copy_from_slice(&right);
            next.push(sha256d(&buf));

            i += 2;
        }

        layer = next;
    }

    layer[0]
}

fn merkle_root(txs: &[Transaction]) -> [u8; 32] {
    let mut ids = Vec::with_capacity(txs.len());
    for tx in txs {
        ids.push(txid(tx));
    }
    merkle_root_txids(&ids)
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

fn make_block_with_txs(height: u64, txs: Vec<Transaction>) -> Block {
    let hdr = BlockHeader {
        version: 1,
        prev: [0u8; 32],
        merkle: merkle_root(&txs),
        time: 1_700_000_000 + height,
        bits: 0x1e00ffff,
        nonce: 0,
    };

    Block { header: hdr, txs }
}

#[test]
fn rejects_propose_with_domain_too_long() -> Result<()> {
    let tmp = TempDir::new().context("tmp")?;
    let db = Arc::new(open_db(&tmp).context("open db")?);

    let owner = signer_addr(SK);
    let miner = h20(0xAA);
    let height = 1u64;

    let prevout = OutPoint {
        txid: [0xD1; 32],
        vout: 0,
    };
    let input_value = 1_000_000u64;
    let fee = MIN_FEE_PROPOSE;

    insert_spendable_utxo(&db, prevout, input_value, owner, 0)
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

    let blk = make_block_with_txs(height, vec![cb, bad_tx]);

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
    let height = 1u64;

    let prevout = OutPoint {
        txid: [0xD2; 32],
        vout: 0,
    };
    let input_value = 1_000_000u64;
    let fee = MIN_FEE_PROPOSE;

    insert_spendable_utxo(&db, prevout, input_value, owner, 0)
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

    let blk = make_block_with_txs(height, vec![cb, bad_tx]);

    let err = validate_and_apply_block(&db, &blk, epoch_of(height), height)
        .expect_err("block with oversized propose.uri must be rejected");

    let msg = format!("{err:#}");
    assert!(
        msg.contains("propose uri too long"),
        "unexpected error: {msg}"
    );

    Ok(())
}
