// tests/consensus_rejects_duplicate_txids_in_block.rs
#![cfg(feature = "test-bypass")]

use anyhow::{Context, Result};
use tempfile::TempDir;

use csd::chain::index::{get_hidx, header_hash, index_header};
use csd::crypto::txid;
use csd::state::app_state::epoch_of;
use csd::state::db::{k_block, set_tip, Stores};
use csd::state::utxo::validate_and_apply_block;
use csd::types::{AppPayload, Block, Hash20, Hash32, OutPoint, Transaction, TxIn, TxOut};

mod testutil_chain;
use testutil_chain::{assert_tip_eq, build_base_chain_with_miner, make_test_header, open_db};

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

fn make_signed_tx(prevout: OutPoint, input_value: u64, fee: u64, to: [u8; 20]) -> Transaction {
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

    let (sig64, pub33) = csd::crypto::sign_tx_compact_secp256k1(&tx, SK);

    let mut ss = Vec::with_capacity(99);
    ss.push(64);
    ss.extend_from_slice(&sig64);
    ss.push(33);
    ss.extend_from_slice(&pub33);
    tx.inputs[0].script_sig = ss;

    tx
}

#[test]
fn rejects_block_with_duplicate_txids() -> Result<()> {
    let tmp = TempDir::new().context("tmp")?;
    let db = open_db(&tmp).context("open db")?;

    let miner_shared = signer_addr(SK);
    let miner_block = h20(0xA1);

    let shared_len = 7u64; // heights 0..6
    let start_time = 1_701_300_000u64;

    // Build a normal canonical prefix.
    let shared = build_base_chain_with_miner(&db, shared_len, start_time, miner_shared)
        .context("build shared chain")?;
    let common_tip = shared[(shared_len - 1) as usize];
    assert_tip_eq(&db, common_tip)?;

    // Load the shared-tip coinbase so we can build one valid spend.
    let common_tip_block_bytes = db
        .blocks
        .get(k_block(&common_tip))?
        .context("missing common tip block bytes")?;
    let common_tip_block: Block = csd::codec::consensus_bincode()
        .deserialize(&common_tip_block_bytes)
        .context("deserialize common tip block")?;

    let prevout = OutPoint {
        txid: txid(&common_tip_block.txs[0]),
        vout: 0,
    };
    let input_value = common_tip_block.txs[0].outputs[0].value;

    let spend = make_signed_tx(prevout, input_value, 5_000, h20(0x44));
    let spend_txid = txid(&spend);

    // Put the exact same tx twice in the same block.
    let height = shared_len;
    let cb = csd::chain::mine::coinbase(
        miner_block,
        csd::params::block_reward(height) + 10_000,
        height,
        None,
    );

    let txs = vec![cb, spend.clone(), spend.clone()];
    let hdr = make_test_header(&db, common_tip, &txs, height)
        .context("make_test_header duplicate-txid block")?;
    let blk = Block { header: hdr, txs };

    // Header indexing should succeed; transaction validity should fail.
    let bh = header_hash(&blk.header);

    let bytes = csd::codec::consensus_bincode()
        .serialize(&blk)
        .context("serialize dup-txid block")?;
    db.blocks
        .insert(k_block(&bh), bytes)
        .context("db.blocks.insert dup-txid block")?;

    let parent_hi = get_hidx(&db, &common_tip)
        .context("get_hidx(common_tip)")?
        .context("missing parent hidx")?;
    index_header(&db, &blk.header, Some(&parent_hi)).context("index_header dup-txid block")?;

    let err = validate_and_apply_block(&db, &blk, epoch_of(height), height)
        .expect_err("block with duplicate txids must be rejected");

    let msg = format!("{err:#}").to_lowercase();

    assert!(
        msg.contains("duplicate")
            || msg.contains("txid")
            || msg.contains("double spend")
            || msg.contains("already spent"),
        "unexpected error for duplicate txids (txid=0x{}): {}",
        hex::encode(spend_txid),
        err
    );

    Ok(())
}
