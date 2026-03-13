use anyhow::{Context, Result};
use tempfile::TempDir;

use csd::crypto::{hash160, txid};
use csd::params::{EPOCH_LEN, MIN_FEE_ATTEST, MIN_FEE_PROPOSE};
use csd::state::app_state::epoch_of;
use csd::state::db::k_block;
use csd::state::utxo::validate_and_apply_block;
use csd::types::{AppPayload, Block, OutPoint, Transaction, TxIn, TxOut};

mod testutil_chain;
use testutil_chain::{build_base_chain_with_miner, make_test_header, open_db};

const SK: [u8; 32] = [21u8; 32];
const SK2: [u8; 32] = [22u8; 32];

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

fn sign_tx(mut tx: Transaction, sk: [u8; 32]) -> Transaction {
    let (sig64, pub33) = csd::crypto::sign_tx_compact_secp256k1(&tx, sk);

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
fn rejects_block_with_duplicate_attest_txids() -> Result<()> {
    std::env::set_var("CSD_BYPASS_POW", "1");

    let tmp = TempDir::new().context("tmp")?;
    let db = open_db(&tmp).context("open db")?;

    let miner = signer_addr(SK);
    let owner1 = signer_addr(SK);
    let owner2 = signer_addr(SK2);

    let shared_len = EPOCH_LEN + 2;
    let start_time = 1_702_200_000u64;

    let shared = build_base_chain_with_miner(&db, shared_len, start_time, miner)
        .context("build shared chain")?;
    let parent = shared[(shared_len - 1) as usize];
    let height = shared_len;
    let current_epoch = epoch_of(height);

    let parent_block_bytes = db
        .blocks
        .get(k_block(&parent))?
        .context("missing parent block bytes")?;
    let parent_block: Block = csd::codec::consensus_bincode()
        .deserialize(&parent_block_bytes)
        .context("deserialize parent block")?;

    let prev_propose = OutPoint {
        txid: txid(&parent_block.txs[0]),
        vout: 0,
    };
    let val_propose = parent_block.txs[0].outputs[0].value;

    let earlier_tip = shared[(shared_len - 2) as usize];
    let earlier_block_bytes = db
        .blocks
        .get(k_block(&earlier_tip))?
        .context("missing earlier block bytes")?;
    let earlier_block: Block = csd::codec::consensus_bincode()
        .deserialize(&earlier_block_bytes)
        .context("deserialize earlier block")?;

    let prev_attest = OutPoint {
        txid: txid(&earlier_block.txs[0]),
        vout: 0,
    };
    let val_attest = earlier_block.txs[0].outputs[0].value;

    let propose_tx = Transaction {
        version: 1,
        inputs: vec![TxIn {
            prevout: prev_propose,
            script_sig: vec![0u8; 99],
        }],
        outputs: vec![TxOut {
            value: val_propose - MIN_FEE_PROPOSE,
            script_pubkey: owner1,
        }],
        locktime: 0,
        app: AppPayload::Propose {
            domain: "dup-attest".to_string(),
            payload_hash: [0xAB; 32],
            uri: "https://example.com/dup-attest".to_string(),
            expires_epoch: current_epoch + 5,
        },
    };
    let propose_tx = sign_tx(propose_tx, SK);
    let proposal_id = txid(&propose_tx);

    let cb1 = csd::chain::mine::coinbase(
        h20(0x91),
        csd::params::block_reward(height) + MIN_FEE_PROPOSE,
        height,
        None,
    );

    let txs1 = vec![cb1, propose_tx];
    let hdr1 = make_test_header(&db, parent, &txs1, height)
        .context("make_test_header proposal block")?;
    let blk1 = Block {
        header: hdr1,
        txs: txs1,
    };

    validate_and_apply_block(&db, &blk1, current_epoch, height)
        .context("apply proposal block")?;

    let attest_tx = Transaction {
        version: 1,
        inputs: vec![TxIn {
            prevout: prev_attest,
            script_sig: vec![0u8; 99],
        }],
        outputs: vec![TxOut {
            value: val_attest - MIN_FEE_ATTEST,
            script_pubkey: owner2,
        }],
        locktime: 0,
        app: AppPayload::Attest {
            proposal_id,
            score: 777,
            confidence: 888,
        },
    };
    let attest_tx = sign_tx(attest_tx, SK2);
    let attest_tx_dup = attest_tx.clone();

    let next_height = height + 1;
    let next_epoch = epoch_of(next_height);
    let prev2 = csd::chain::index::header_hash(&blk1.header);

    let cb2 = csd::chain::mine::coinbase(
        h20(0x92),
        csd::params::block_reward(next_height) + (MIN_FEE_ATTEST * 2),
        next_height,
        None,
    );

    let txs2 = vec![cb2, attest_tx, attest_tx_dup];
    let hdr2 = make_test_header(&db, prev2, &txs2, next_height)
        .context("make_test_header duplicate attest block")?;
    let blk2 = Block {
        header: hdr2,
        txs: txs2,
    };

    let err = validate_and_apply_block(&db, &blk2, next_epoch, next_height)
        .expect_err("block with duplicate attest txids must be rejected");

    let msg = format!("{err:#}");
    assert!(
        msg.contains("duplicate txid within block"),
        "unexpected error: {msg}"
    );

    Ok(())
}
