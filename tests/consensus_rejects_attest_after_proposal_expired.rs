use anyhow::{Context, Result};
use tempfile::TempDir;

use csd::crypto::{hash160, txid};
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
    hash160(&pub33)
}

fn sign_tx(mut tx: Transaction) -> Transaction {
    let (sig64, pub33) = csd::crypto::sign_tx_compact_secp256k1(&tx, SK);

    let mut ss = Vec::with_capacity(99);
    ss.push(64);
    ss.extend_from_slice(&sig64);
    ss.push(33);
    ss.extend_from_slice(&pub33);

    for inp in &mut tx.inputs {
        inp.script_sig = ss.clone();
    }

    tx
}

#[test]
fn rejects_attest_after_proposal_expired() -> Result<()> {
    std::env::set_var("CSD_BYPASS_POW", "1");

    let tmp = TempDir::new().context("tmp")?;
    let db = open_db(&tmp).context("open db")?;

    let miner = signer_addr(SK);

    // Build enough history so current epoch is definitely > 0 and we can create an expired proposal.
    let shared_len = 8u64; // heights 0..7
    let start_time = 1_701_800_000u64;

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

    let spend_prevout = OutPoint {
        txid: txid(&parent_block.txs[0]),
        vout: 0,
    };
    let input_value = parent_block.txs[0].outputs[0].value;

    let height = shared_len;
    let current_epoch = epoch_of(height);

    // Make the proposal already expired relative to the block height being validated.
    let expired_epoch = current_epoch.saturating_sub(1);

    let propose_tx = Transaction {
        version: 1,
        inputs: vec![TxIn {
            prevout: spend_prevout,
            script_sig: vec![0u8; 99],
        }],
        outputs: vec![TxOut {
            value: input_value - MIN_FEE_PROPOSE,
            script_pubkey: h20(0x41),
        }],
        locktime: 0,
        app: AppPayload::Propose {
            domain: "test-domain".to_string(),
            payload_hash: [0x11; 32],
            uri: "https://example.com/proposal".to_string(),
            expires_epoch: expired_epoch,
        },
    };
    let propose_tx = sign_tx(propose_tx);
    let proposal_id = txid(&propose_tx);

    // Attest references the proposal in the same block, but proposal is already expired.
    // Consensus should reject because the proposal itself is not valid/applicable.
    let attest_tx = Transaction {
        version: 1,
        inputs: vec![TxIn {
            prevout: OutPoint {
                txid: proposal_id,
                vout: 0,
            },
            script_sig: vec![0u8; 99],
        }],
        outputs: vec![TxOut {
            value: input_value
                .saturating_sub(MIN_FEE_PROPOSE)
                .saturating_sub(MIN_FEE_ATTEST),
            script_pubkey: h20(0x42),
        }],
        locktime: 0,
        app: AppPayload::Attest {
            proposal_id,
            score: 1,
            confidence: 1,
        },
    };
    let attest_tx = sign_tx(attest_tx);

    let total_fees = MIN_FEE_PROPOSE
        .checked_add(MIN_FEE_ATTEST)
        .context("fee overflow")?;

    let cb = csd::chain::mine::coinbase(
        h20(0x99),
        csd::params::block_reward(height) + total_fees,
        height,
        None,
    );

    let txs = vec![cb, propose_tx, attest_tx];
    let hdr = make_test_header(&db, parent, &txs, height).context("make_test_header")?;
    let blk = Block { header: hdr, txs };

    let err = validate_and_apply_block(&db, &blk, current_epoch, height)
        .expect_err("block with attest on already-expired proposal must be rejected");

    let msg = format!("{err:#}");
    assert!(
        msg.contains("expired")
            || msg.contains("proposal")
            || msg.contains("epoch"),
        "unexpected error: {msg}"
    );

    Ok(())
}
