use anyhow::{Context, Result};
use tempfile::TempDir;

use csd::chain::index::{get_hidx, header_hash, index_header};
use csd::crypto::{hash160, txid};
use csd::params::{EPOCH_LEN, MIN_FEE_PROPOSE};
use csd::state::app_state::epoch_of;
use csd::state::db::{k_block, set_tip, Stores};
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

fn persist_index_apply_block(db: &Stores, blk: &Block, height: u64) -> Result<[u8; 32]> {
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
        .with_context(|| format!("validate_and_apply_block h={height}"))?;
    set_tip(db, &bh).context("set_tip")?;

    Ok(bh)
}

#[test]
fn rejects_block_with_duplicate_propose_txids() -> Result<()> {
    std::env::set_var("CSD_BYPASS_POW", "1");

    let tmp = TempDir::new().context("tmp")?;
    let db = open_db(&tmp).context("open db")?;

    let miner = signer_addr(SK);
    let owner = signer_addr(SK);

    let shared_len = EPOCH_LEN + 2;
    let start_time = 1_702_300_000u64;

    let shared = build_base_chain_with_miner(&db, shared_len, start_time, miner)
        .context("build shared chain")?;
    let parent = shared[(shared_len - 1) as usize];
    let height = shared_len;

    let parent_block_bytes = db
        .blocks
        .get(k_block(&parent))?
        .context("missing parent block bytes")?;
    let parent_block: Block = csd::codec::consensus_bincode()
        .deserialize(&parent_block_bytes)
        .context("deserialize parent block")?;

    let prev1 = OutPoint {
        txid: txid(&parent_block.txs[0]),
        vout: 0,
    };
    let val1 = parent_block.txs[0].outputs[0].value;

    let earlier_tip = shared[(shared_len - 2) as usize];
    let earlier_block_bytes = db
        .blocks
        .get(k_block(&earlier_tip))?
        .context("missing earlier block bytes")?;
    let earlier_block: Block = csd::codec::consensus_bincode()
        .deserialize(&earlier_block_bytes)
        .context("deserialize earlier block")?;

    let prev2 = OutPoint {
        txid: txid(&earlier_block.txs[0]),
        vout: 0,
    };
    let val2 = earlier_block.txs[0].outputs[0].value;

    // First, apply a normal block so the duplicate-propose block has a valid indexed parent.
    let normal_tx = Transaction {
        version: 1,
        inputs: vec![TxIn {
            prevout: prev1,
            script_sig: vec![0u8; 99],
        }],
        outputs: vec![TxOut {
            value: val1 - MIN_FEE_PROPOSE,
            script_pubkey: owner,
        }],
        locktime: 0,
        app: AppPayload::Propose {
            domain: "baseline".to_string(),
            payload_hash: [0x11; 32],
            uri: "https://example.com/baseline".to_string(),
            expires_epoch: epoch_of(height) + 5,
        },
    };
    let normal_tx = sign_tx(normal_tx, SK);

    let cb1 = csd::chain::mine::coinbase(
        h20(0x91),
        csd::params::block_reward(height) + MIN_FEE_PROPOSE,
        height,
        None,
    );

    let txs1 = vec![cb1, normal_tx];
    let hdr1 = make_test_header(&db, parent, &txs1, height)
        .context("make_test_header baseline block")?;
    let blk1 = Block {
        header: hdr1,
        txs: txs1,
    };

    let prev_block_hash = persist_index_apply_block(&db, &blk1, height)
        .context("persist_index_apply_block baseline block")?;

    // Now create two identical propose txs => duplicate txids in same block.
    let dup_propose_tx = Transaction {
        version: 1,
        inputs: vec![TxIn {
            prevout: prev2,
            script_sig: vec![0u8; 99],
        }],
        outputs: vec![TxOut {
            value: val2 - MIN_FEE_PROPOSE,
            script_pubkey: owner,
        }],
        locktime: 0,
        app: AppPayload::Propose {
            domain: "dup-propose".to_string(),
            payload_hash: [0xAB; 32],
            uri: "https://example.com/dup-propose".to_string(),
            expires_epoch: epoch_of(height + 1) + 5,
        },
    };
    let dup_propose_tx = sign_tx(dup_propose_tx, SK);
    let dup_propose_tx2 = dup_propose_tx.clone();

    let next_height = height + 1;
    let next_epoch = epoch_of(next_height);

    let cb2 = csd::chain::mine::coinbase(
        h20(0x92),
        csd::params::block_reward(next_height) + (MIN_FEE_PROPOSE * 2),
        next_height,
        None,
    );

    let txs2 = vec![cb2, dup_propose_tx, dup_propose_tx2];
    let hdr2 = make_test_header(&db, prev_block_hash, &txs2, next_height)
        .context("make_test_header duplicate propose block")?;
    let blk2 = Block {
        header: hdr2,
        txs: txs2,
    };

    let err = validate_and_apply_block(&db, &blk2, next_epoch, next_height)
        .expect_err("block with duplicate propose txids must be rejected");

    let msg = format!("{err:#}");
    assert!(
        msg.contains("duplicate txid within block"),
        "unexpected error: {msg}"
    );

    Ok(())
}
