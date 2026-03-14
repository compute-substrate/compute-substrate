use anyhow::{Context, Result};
use tempfile::TempDir;

use csd::chain::index::{get_hidx, header_hash, index_header};
use csd::crypto::txid;
use csd::state::app_state::epoch_of;
use csd::state::db::{k_block, set_tip, Stores};
use csd::state::utxo::validate_and_apply_block;
use csd::types::{AppPayload, Block, Hash20, OutPoint, Transaction, TxIn, TxOut};

mod testutil_chain;
use testutil_chain::{build_base_chain_with_miner, open_db};

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
fn rejects_block_with_coinbase_wrong_value_when_fees_present() -> Result<()> {
    std::env::set_var("CSD_BYPASS_POW", "1");

    let tmp = TempDir::new().context("tmp")?;
    let db = open_db(&tmp).context("open db")?;

    let spendable_miner = signer_addr(SK);
    let block_miner = h20(0x77);

    let shared_len = 7u64;
    let start_time = 1_702_600_000u64;

    let shared = build_base_chain_with_miner(&db, shared_len, start_time, spendable_miner)
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

    let prevout = OutPoint {
        txid: txid(&parent_block.txs[0]),
        vout: 0,
    };
    let input_value = parent_block.txs[0].outputs[0].value;
    let fee = 5_000u64;

    let spend_tx = make_signed_tx(prevout, input_value, fee, h20(0x42));

    let wrong_coinbase_value = csd::params::block_reward(height);
    let coinbase = csd::chain::mine::coinbase(block_miner, wrong_coinbase_value, height, None);

    let txs = vec![coinbase, spend_tx];
    let hdr = testutil_chain::make_test_header(&db, parent, &txs, height)
        .context("make_test_header")?;
    let blk = Block { header: hdr, txs };

    let err = persist_index_apply_block(&db, &blk, height)
        .expect_err("block must be rejected when coinbase omits fees");

    let msg = format!("{err:#}");
    assert!(
        msg.contains("coinbase value wrong"),
        "unexpected error: {msg}"
    );

    Ok(())
}
