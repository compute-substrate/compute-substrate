#![cfg(feature = "test-bypass")] // toy-chain fixture: needs the PoW/genesis bypass (cargo test --features test-bypass)
use anyhow::{Context, Result};
use tempfile::TempDir;

use csd::crypto::txid;
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

#[test]
fn rejects_bad_scriptsig_length() -> Result<()> {

    let tmp = TempDir::new().context("tmp")?;
    let db = open_db(&tmp).context("open db")?;

    let miner = signer_addr(SK);
    let shared_len = 7u64;
    let start_time = 1_701_700_000u64;

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

    let prevout = OutPoint {
        txid: txid(&parent_block.txs[0]),
        vout: 0,
    };
    let input_value = parent_block.txs[0].outputs[0].value;

    // Intentionally malformed scriptSig
    let bad_tx = Transaction {
        version: 1,
        inputs: vec![TxIn {
            prevout,
            script_sig: vec![1, 2, 3], // invalid format
        }],
        outputs: vec![TxOut {
            value: input_value - 10_000,
            script_pubkey: h20(0x44),
        }],
        locktime: 0,
        app: AppPayload::None,
    };

    let height = shared_len;

    let cb = csd::chain::mine::coinbase(
        h20(0x99),
        csd::params::block_reward(height),
        height,
        None,
    );

    let txs = vec![cb, bad_tx];
    let hdr = make_test_header(&db, parent, &txs, height).context("make_test_header")?;
    let blk = Block { header: hdr, txs };

    let err = validate_and_apply_block(&db, &blk, epoch_of(height), height)
        .expect_err("block with malformed scriptSig must be rejected");

    let msg = format!("{err:#}");
    assert!(
        msg.contains("script")
            || msg.contains("sig")
            || msg.contains("script_sig"),
        "unexpected error: {msg}"
    );

    Ok(())
}

/// A spend of the parent block's coinbase (owned by `SK`), signed, at the fee `fee`.
fn signed_spend_of_parent_coinbase(parent_block: &Block, fee: u64) -> Transaction {
    let cb = &parent_block.txs[0];
    let mut tx = Transaction {
        version: 1,
        inputs: vec![TxIn {
            prevout: OutPoint { txid: txid(cb), vout: 0 },
            script_sig: vec![],
        }],
        outputs: vec![TxOut {
            value: cb.outputs[0].value - fee,
            script_pubkey: h20(0x45),
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

// The two tag bytes of a 99-byte script_sig (byte 0: the signature length 64, byte 65: the pubkey
// length 33, `utxo::parse_scriptsig`) sit outside the txid (`crypto::txid` strips script_sigs), so
// only this check fixes them: a node that accepted other tag bytes would accept bodies every other
// node refuses. Each case keeps a valid signature and pubkey and changes one tag byte; the
// untouched spend in the same block shape is the paired honest path.
#[test]
fn a_99_byte_script_sig_with_a_wrong_tag_byte_is_refused() -> Result<()> {
    let tmp = TempDir::new().context("tmp")?;
    let db = open_db(&tmp).context("open db")?;

    let shared_len = 7u64;
    let shared = build_base_chain_with_miner(&db, shared_len, 1_701_710_000, signer_addr(SK))
        .context("build shared chain")?;
    let parent = shared[(shared_len - 1) as usize];
    let parent_block: Block = csd::codec::consensus_bincode()
        .deserialize(&db.blocks.get(k_block(&parent))?.context("missing parent block bytes")?)
        .context("deserialize parent block")?;

    let height = shared_len;
    let fee = 10_000u64;
    let block_with = |spend: Transaction| -> Result<Block> {
        let cb = csd::chain::mine::coinbase(
            h20(0x99),
            csd::params::block_reward(height) + fee,
            height,
            None,
        );
        let txs = vec![cb, spend];
        let header = make_test_header(&db, parent, &txs, height)?;
        Ok(Block { header, txs })
    };

    let honest = signed_spend_of_parent_coinbase(&parent_block, fee);
    for (byte, value, want) in [
        (0usize, 63u8, "expected 64-byte compact sig"),
        (65usize, 32u8, "expected 33-byte compressed pubkey"),
    ] {
        let mut tampered = honest.clone();
        assert_eq!(tampered.inputs[0].script_sig.len(), 99, "fixture: the consensus length");
        tampered.inputs[0].script_sig[byte] = value;
        assert_eq!(txid(&tampered), txid(&honest), "fixture: the tag byte is outside the txid");
        let err = validate_and_apply_block(&db, &block_with(tampered)?, epoch_of(height), height)
            .expect_err("a wrong tag byte must be refused");
        assert_eq!(err.root_cause().to_string(), want, "byte {byte}: {err:#}");
    }

    validate_and_apply_block(&db, &block_with(honest)?, epoch_of(height), height)
        .context("the untampered spend must apply")?;
    Ok(())
}
