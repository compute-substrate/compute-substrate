// tests/consensus_rejects_non_first_coinbase.rs
use anyhow::{Context, Result};
use tempfile::TempDir;

use csd::chain::index::{get_hidx, index_header};
use csd::crypto::txid;
use csd::state::app_state::epoch_of;
use csd::state::db::k_block;
use csd::state::utxo::validate_and_apply_block;
use csd::types::{AppPayload, Block, Hash20, OutPoint, Transaction, TxIn, TxOut};

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

fn err_contains_any(err: &anyhow::Error, needles: &[&str]) -> bool {
    let s = format!("{err:#}").to_lowercase();
    needles.iter().any(|n| s.contains(&n.to_lowercase()))
}

#[test]
fn rejects_block_with_non_first_coinbase() -> Result<()> {
    let tmp = TempDir::new().context("tmp")?;
    let db = open_db(&tmp).context("open db")?;

    // Make the chain spendable by our test key so we can build a valid normal tx.
    let miner_shared = signer_addr(SK);
    let shared_len = 7u64;
    let start_time = 1_701_300_000u64;

    let shared = build_base_chain_with_miner(&db, shared_len, start_time, miner_shared)
        .context("build shared chain")?;
    let parent = shared[(shared_len - 1) as usize];
    let height = shared_len;

    // Load the current tip block so we can spend its coinbase in a valid non-coinbase tx.
    let parent_block_bytes = db
        .blocks
        .get(k_block(&parent))?
        .context("missing parent block bytes")?;
    let parent_block: Block = csd::codec::consensus_bincode()
        .deserialize(&parent_block_bytes)
        .context("deserialize parent block")?;

    let prevout = OutPoint {
        txid: txid(&parent_block.txs[0]),
        vout: 0,
    };
    let input_value = parent_block.txs[0].outputs[0].value;

    let normal_tx = make_signed_tx(prevout, input_value, 5_000, h20(0x44));

    // Illegal: coinbase appears at index 1, not index 0.
    let illegal_coinbase = csd::chain::mine::coinbase(
        h20(0xAA),
        csd::params::block_reward(height),
        height,
        None,
    );

    let txs = vec![normal_tx, illegal_coinbase];

    let hdr = make_test_header(&db, parent, &txs, height)
        .context("make_test_header")?;
    let blk = Block { header: hdr, txs };

    let parent_hi = get_hidx(&db, &parent)?
        .context("missing parent header index")?;
    index_header(&db, &blk.header, Some(&parent_hi))
        .context("index_header")?;

    let err = validate_and_apply_block(&db, &blk, epoch_of(height), height)
        .expect_err("block with non-first coinbase must be rejected");

    assert!(
        err_contains_any(
            &err,
            &[
                "coinbase",
                "first tx",
                "first transaction",
                "multiple coinbase",
                "non-first",
            ]
        ),
        "unexpected error: {err:#}"
    );

    Ok(())
}
