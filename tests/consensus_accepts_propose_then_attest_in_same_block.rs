use anyhow::{Context, Result};
use tempfile::TempDir;

use csd::crypto::txid;
use csd::params::{MIN_FEE_ATTEST, MIN_FEE_PROPOSE};
use csd::state::app_state::epoch_of;
use csd::state::db::k_block;
use csd::state::utxo::validate_and_apply_block;
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

fn sign_tx(mut tx: Transaction) -> Transaction {
    let (sig64, pub33) = csd::crypto::sign_tx_compact_secp256k1(&tx, SK);

    let mut ss = Vec::with_capacity(99);
    ss.push(64);
    ss.extend_from_slice(&sig64);
    ss.push(33);
    ss.extend_from_slice(&pub33);

    tx.inputs[0].script_sig = ss;
    tx
}

fn make_signed_propose_tx(
    prevout: OutPoint,
    input_value: u64,
    fee: u64,
    domain: &str,
    payload_hash: [u8; 32],
    uri: &str,
    expires_epoch: u64,
) -> Transaction {
    let send = input_value - fee;

    let tx = Transaction {
        version: 1,
        inputs: vec![TxIn {
            prevout,
            script_sig: vec![0u8; 99],
        }],
        outputs: vec![TxOut {
            value: send,
            script_pubkey: h20(0x41),
        }],
        locktime: 0,
        app: AppPayload::Propose {
            domain: domain.to_string(),
            payload_hash,
            uri: uri.to_string(),
            expires_epoch,
        },
    };

    sign_tx(tx)
}

fn make_signed_attest_tx(
    prevout: OutPoint,
    input_value: u64,
    fee: u64,
    proposal_id: [u8; 32],
) -> Transaction {
    let send = input_value - fee;

    let tx = Transaction {
        version: 1,
        inputs: vec![TxIn {
            prevout,
            script_sig: vec![0u8; 99],
        }],
        outputs: vec![TxOut {
            value: send,
            script_pubkey: h20(0x42),
        }],
        locktime: 0,
        app: AppPayload::Attest {
            proposal_id,
            score: 100,
            confidence: 100,
        },
    };

    sign_tx(tx)
}

#[test]
fn accepts_propose_then_attest_in_same_block() -> Result<()> {
    std::env::set_var("CSD_BYPASS_POW", "1");

    let tmp = TempDir::new().context("tmp")?;
    let db = open_db(&tmp).context("open db")?;

    let miner = signer_addr(SK);
    let shared_len = 8u64; // heights 0..7
    let start_time = 1_701_500_000u64;

    let shared = build_base_chain_with_miner(&db, shared_len, start_time, miner)
        .context("build shared chain")?;
    let parent = shared[(shared_len - 1) as usize];

    let parent_block_bytes = db
        .blocks
        .get(k_block(&parent))?
        .context("missing parent block bytes")?;
    let parent_block: Block = csd::codec::consensus_bincode()
        .deserialize(&parent_block_bytes)
        .context("deserialize parent block")?;

    let coinbase_txid = txid(&parent_block.txs[0]);
    let coinbase_value = parent_block.txs[0].outputs[0].value;

    // Two independent spendable UTXOs are needed so propose and attest are separate txs.
    // Use parent tip coinbase for propose, and parent-1 coinbase for attest.
    let grandparent = shared[(shared_len - 2) as usize];
    let grandparent_block_bytes = db
        .blocks
        .get(k_block(&grandparent))?
        .context("missing grandparent block bytes")?;
    let grandparent_block: Block = csd::codec::consensus_bincode()
        .deserialize(&grandparent_block_bytes)
        .context("deserialize grandparent block")?;

    let gp_coinbase_txid = txid(&grandparent_block.txs[0]);
    let gp_coinbase_value = grandparent_block.txs[0].outputs[0].value;

    let propose_prevout = OutPoint {
        txid: coinbase_txid,
        vout: 0,
    };

    let attest_prevout = OutPoint {
        txid: gp_coinbase_txid,
        vout: 0,
    };

    let propose_tx = make_signed_propose_tx(
        propose_prevout,
        coinbase_value,
        MIN_FEE_PROPOSE,
        "research",
        [0x11; 32],
        "https://example.com/p/1",
        epoch_of(shared_len) + 10,
    );

    let proposal_id = txid(&propose_tx);

    let attest_tx = make_signed_attest_tx(
        attest_prevout,
        gp_coinbase_value,
        MIN_FEE_ATTEST,
        proposal_id,
    );

    let height = shared_len;

    let total_fees = MIN_FEE_PROPOSE + MIN_FEE_ATTEST;
    let cb = csd::chain::mine::coinbase(
        h20(0x99),
        csd::params::block_reward(height) + total_fees,
        height,
        None,
    );

    let txs = vec![cb, propose_tx, attest_tx];
    let hdr = make_test_header(&db, parent, &txs, height).context("make_test_header")?;
    let blk = Block { header: hdr, txs };

    validate_and_apply_block(&db, &blk, epoch_of(height), height)
        .context("validate_and_apply_block should accept propose->attest ordering")?;

    Ok(())
}
