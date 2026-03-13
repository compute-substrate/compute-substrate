use anyhow::{Context, Result};
use tempfile::TempDir;

use csd::crypto::{hash160, txid};
use csd::params::{EPOCH_LEN, MIN_FEE_PROPOSE};
use csd::state::app_state::{epoch_of, get_proposal};
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
fn accepts_propose_with_expires_epoch_equal_current() -> Result<()> {
    std::env::set_var("CSD_BYPASS_POW", "1");

    let tmp = TempDir::new().context("tmp")?;
    let db = open_db(&tmp).context("open db")?;

    let miner = signer_addr(SK);
    let owner = signer_addr(SK);

    // Force epoch >= 1 just to make this a real boundary test, not epoch-0 ambiguity.
    let shared_len = EPOCH_LEN + 1;
    let start_time = 1_702_100_000u64;

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
    assert!(current_epoch > 0, "test requires current_epoch > 0");

    let propose_tx = Transaction {
        version: 1,
        inputs: vec![TxIn {
            prevout: spend_prevout,
            script_sig: vec![0u8; 99],
        }],
        outputs: vec![TxOut {
            value: input_value - MIN_FEE_PROPOSE,
            script_pubkey: owner,
        }],
        locktime: 0,
        app: AppPayload::Propose {
            domain: "equal-current-epoch".to_string(),
            payload_hash: [0x77; 32],
            uri: "https://example.com/equal-current".to_string(),
            expires_epoch: current_epoch,
        },
    };
    let propose_tx = sign_tx(propose_tx);
    let proposal_id = txid(&propose_tx);

    let cb = csd::chain::mine::coinbase(
        h20(0x99),
        csd::params::block_reward(height) + MIN_FEE_PROPOSE,
        height,
        None,
    );

    let txs = vec![cb, propose_tx];
    let hdr = make_test_header(&db, parent, &txs, height).context("make_test_header")?;
    let blk = Block { header: hdr, txs };

    validate_and_apply_block(&db, &blk, current_epoch, height)
        .context("proposal with expires_epoch == current_epoch should be accepted")?;

    let prop = get_proposal(&db, &proposal_id)?
        .context("proposal should be persisted")?;

    assert_eq!(prop.id, proposal_id);
    assert_eq!(prop.created_epoch, current_epoch);
    assert_eq!(prop.expires_epoch, current_epoch);
    assert_eq!(prop.domain, "equal-current-epoch");
    assert_eq!(prop.uri, "https://example.com/equal-current");

    Ok(())
}
