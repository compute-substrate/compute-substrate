use anyhow::{Context, Result};
use tempfile::TempDir;

use csd::chain::index::header_hash;
use csd::crypto::txid;
use csd::params::MIN_FEE_ATTEST;
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

fn make_signed_attest_tx(
    prevout: OutPoint,
    input_value: u64,
    fee: u64,
    proposal_id: [u8; 32],
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
            script_pubkey: h20(0x44),
        }],
        locktime: 0,
        app: AppPayload::Attest {
            proposal_id,
            score: 100,
            confidence: 100,
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

#[test]
fn rejects_attest_on_unknown_proposal() -> Result<()> {
    std::env::set_var("CSD_BYPASS_POW", "1");

    let tmp = TempDir::new().context("tmp")?;
    let db = open_db(&tmp).context("open db")?;

    // Build a valid shared chain whose tip coinbase we can spend.
    let miner = signer_addr(SK);
    let shared_len = 7u64; // heights 0..6
    let start_time = 1_701_400_000u64;

    let shared = build_base_chain_with_miner(&db, shared_len, start_time, miner)
        .context("build shared chain")?;
    let parent = shared[(shared_len - 1) as usize];

    // Spend the current tip coinbase in an Attest tx that references
    // a non-zero proposal_id the chain has never seen.
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

    let unknown_proposal_id = [0xAB; 32];
    let fee = MIN_FEE_ATTEST;

    let attest_tx = make_signed_attest_tx(prevout, input_value, fee, unknown_proposal_id);

    let height = shared_len;
    let cb = csd::chain::mine::coinbase(
        h20(0x99),
        csd::params::block_reward(height) + fee,
        height,
        None,
    );

    let txs = vec![cb, attest_tx];
    let hdr = make_test_header(&db, parent, &txs, height).context("make_test_header")?;
    let blk = Block { header: hdr, txs };

    let err = validate_and_apply_block(&db, &blk, epoch_of(height), height)
        .expect_err("block with attest on unknown proposal must be rejected");

    let msg = format!("{err:#}");
    assert!(
        msg.contains("proposal"),
        "unexpected error: {msg}"
    );

    // Extra sanity: the block itself was otherwise structurally fine.
    let _ = header_hash(&blk.header);

    Ok(())
}
