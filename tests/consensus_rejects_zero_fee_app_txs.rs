use anyhow::{Context, Result};
use tempfile::TempDir;

use csd::chain::index::{get_hidx, header_hash, index_header};
use csd::crypto::txid;
use csd::state::app_state::epoch_of;
use csd::state::db::{k_block, set_tip, Stores};
use csd::state::utxo::validate_and_apply_block;
use csd::types::{AppPayload, Block, Hash20, Hash32, OutPoint, Transaction, TxIn, TxOut};

mod testutil_chain;
use testutil_chain::{build_base_chain_with_miner, make_test_header, open_db};

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
    csd::crypto::hash160(&pub33)
}

fn make_signed_app_tx(
    prevout: OutPoint,
    input_value: u64,
    fee: u64,
    to: [u8; 20],
    app: AppPayload,
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
        app,
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

#[test]
fn rejects_zero_fee_propose_tx_in_block() -> Result<()> {
    let tmp = TempDir::new()?;
    let db = open_db(&tmp)?;

    let miner_shared = signer_addr(SK);
    let miner_block = h20(0xAA);

    let shared_len = 7u64;
    let start_time = 1_701_400_000u64;

    let shared = build_base_chain_with_miner(&db, shared_len, start_time, miner_shared)
        .context("build shared chain")?;
    let parent = shared[(shared_len - 1) as usize];

    let parent_block_bytes = db
        .blocks
        .get(k_block(&parent))?
        .context("missing parent block bytes")?;
    let parent_block: Block = csd::codec::consensus_bincode()
        .deserialize(&parent_block_bytes)
        .context("deserialize parent block")?;

    let spend_prevout = OutPoint {
        txid: txid(&parent_block.txs[0]),
        vout: 0,
    };
    let input_value = parent_block.txs[0].outputs[0].value;

    let propose_tx = make_signed_app_tx(
        spend_prevout,
        input_value,
        0, // intentionally zero fee
        h20(0x44),
        AppPayload::Propose {
            domain: "test-domain".to_string(),
            payload_hash: [7u8; 32],
            uri: "ipfs://test".to_string(),
            expires_epoch: 999,
        },
    );

    let height = shared_len;
    let cb = csd::chain::mine::coinbase(
        miner_block,
        csd::params::block_reward(height),
        height,
        None,
    );

    let txs = vec![cb, propose_tx];
    let hdr = make_test_header(&db, parent, &txs, height)
        .context("make_test_header")?;
    let blk = Block { header: hdr, txs };

    let err = persist_index_apply_block(&db, &blk, height)
        .expect_err("zero-fee propose tx must be rejected");

    let msg = format!("{err:#}");
    assert!(
        msg.contains("fee too low for propose"),
        "unexpected error: {msg}"
    );

    Ok(())
}

#[test]
fn rejects_zero_fee_attest_tx_in_block() -> Result<()> {
    let tmp = TempDir::new()?;
    let db = open_db(&tmp)?;

    let miner_shared = signer_addr(SK);
    let miner_block = h20(0xBB);

    let shared_len = 7u64;
    let start_time = 1_701_400_100u64;

    let shared = build_base_chain_with_miner(&db, shared_len, start_time, miner_shared)
        .context("build shared chain")?;
    let parent = shared[(shared_len - 1) as usize];

    let parent_block_bytes = db
        .blocks
        .get(k_block(&parent))?
        .context("missing parent block bytes")?;
    let parent_block: Block = csd::codec::consensus_bincode()
        .deserialize(&parent_block_bytes)
        .context("deserialize parent block")?;

    let spend_prevout = OutPoint {
        txid: txid(&parent_block.txs[0]),
        vout: 0,
    };
    let input_value = parent_block.txs[0].outputs[0].value;

    let attest_tx = make_signed_app_tx(
        spend_prevout,
        input_value,
        0, // intentionally zero fee
        h20(0x55),
        AppPayload::Attest {
            proposal_id: [9u8; 32],
            score: 1,
            confidence: 1,
        },
    );

    let height = shared_len;
    let cb = csd::chain::mine::coinbase(
        miner_block,
        csd::params::block_reward(height),
        height,
        None,
    );

    let txs = vec![cb, attest_tx];
    let hdr = make_test_header(&db, parent, &txs, height)
        .context("make_test_header")?;
    let blk = Block { header: hdr, txs };

    let err = persist_index_apply_block(&db, &blk, height)
        .expect_err("zero-fee attest tx must be rejected");

    let msg = format!("{err:#}");
    assert!(
        msg.contains("fee too low for attest"),
        "unexpected error: {msg}"
    );

    Ok(())
}
