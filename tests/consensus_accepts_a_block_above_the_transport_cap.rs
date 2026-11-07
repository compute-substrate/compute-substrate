#![cfg(feature = "test-bypass")] // toy-chain fixture: needs the PoW/genesis bypass (cargo test --features test-bypass)
// Consensus admits a block up to MAX_BLOCK_BYTES (2 MiB), and upstream's unmodified miner fills a
// template up to 2 MiB less 16 KiB (main d168f70 `src/chain/mine.rs:29` and `:230`), while every
// node, upstream's and this one, refuses a request-response message of 1 MiB or more. A block of
// ordinary valid spends at about 1.2 MiB, which such a miner makes from enough pending txs, passes the header and body rules here and can be neither served nor read as
// a block answer. This pins the gap, which needs a change to upstream's miner or to the
// transport cap; this crate's miner stays below the cap (`template_byte_cap`). See
// docs/behaviour.md "Transport cap and blocks above 1 MiB".

use anyhow::{Context, Result};
use futures::io::Cursor;
use libp2p::request_response::Codec as _;
use tempfile::TempDir;

use csd::chain::index::{get_hidx, index_header};
use csd::crypto::sign_tx_compact_secp256k1;
use csd::net::node::SyncCodec;
use csd::net::proto::{SyncResponse, SYNC_PROTO};
use csd::params::{block_reward, MAX_BLOCK_BYTES, MAX_TX_BYTES, MAX_TX_INPUTS};
use csd::state::app_state::epoch_of;
use csd::state::db::{put_utxo, put_utxo_meta, UtxoMeta};
use csd::state::utxo::validate_and_apply_block;
use csd::types::{AppPayload, Block, OutPoint, Transaction, TxIn, TxOut};

mod testutil_chain;
use testutil_chain::{build_base_chain_with_miner, make_test_header, open_db, test_signer_addr, test_signer_sk};

const COIN_VALUE: u64 = 10_000;
const FEE: u64 = 1_000;
// 17 spends of 512 coins each: about 1.19 MiB.
const SPENDS: u8 = 17;

/// A valid spend of 512 coins of the test signer, funded in `db` as an applied block leaves them.
fn funded_wide_spend(db: &csd::state::db::Stores, tag: u8) -> Result<Transaction> {
    let coins: Vec<OutPoint> = (0..MAX_TX_INPUTS as u32).map(|vout| OutPoint { txid: [tag; 32], vout }).collect();
    for op in &coins {
        put_utxo(db, op, &TxOut { value: COIN_VALUE, script_pubkey: test_signer_addr() })?;
        put_utxo_meta(db, op, &UtxoMeta { height: 1, coinbase: false })?;
    }
    let mut tx = Transaction {
        version: 1,
        inputs: coins.iter().map(|op| TxIn { prevout: *op, script_sig: vec![] }).collect(),
        outputs: vec![TxOut { value: COIN_VALUE * coins.len() as u64 - FEE, script_pubkey: [0x42; 20] }],
        locktime: 0,
        app: AppPayload::None,
    };
    let (sig64, pub33) = sign_tx_compact_secp256k1(&tx, test_signer_sk());
    let mut ss = vec![64u8];
    ss.extend_from_slice(&sig64);
    ss.push(33);
    ss.extend_from_slice(&pub33);
    for i in tx.inputs.iter_mut() {
        i.script_sig = ss.clone();
    }
    Ok(tx)
}

#[test]
fn a_valid_block_above_1_mib_is_accepted_by_consensus_and_refused_by_the_transport() -> Result<()> {
    let tmp = TempDir::new()?;
    let db = open_db(&tmp)?;
    let base = build_base_chain_with_miner(&db, 7, 1_701_100_000, [0x11; 20]).context("base chain")?;
    let (parent, height) = (*base.last().unwrap(), base.len() as u64);

    let c = csd::codec::consensus_bincode();
    let mut txs = Vec::new();
    for tag in 1..=SPENDS {
        let tx = funded_wide_spend(&db, tag)?;
        assert!(c.serialized_size(&tx)? as usize <= MAX_TX_BYTES);
        txs.push(tx);
    }
    let fees = FEE * u64::from(SPENDS);
    txs.insert(0, csd::chain::mine::coinbase([0xAA; 20], block_reward(height) + fees, height, None));
    let block = Block { header: make_test_header(&db, parent, &txs, height)?, txs };

    let size = c.serialized_size(&block)? as usize;
    assert!(
        size > 1024 * 1024 && size <= MAX_BLOCK_BYTES - 16 * 1024,
        "fixture: {size} bytes, above the transport cap and within upstream's template budget"
    );

    // Consensus accepts it: the header rules (index_header) and the body rules.
    let parent_hi = get_hidx(&db, &parent)?.context("parent index")?;
    index_header(&db, &block.header, Some(&parent_hi)).context("index_header")?;
    validate_and_apply_block(&db, &block, epoch_of(height), height).context("validate_and_apply_block")?;

    // The transport refuses it: no server writes it, and no requester reads it.
    let answer = SyncResponse::Block { block };
    let bytes = c.serialize(&answer)?;
    let read = futures::executor::block_on(SyncCodec.read_response(&SYNC_PROTO, &mut Cursor::new(bytes)));
    let Err(err) = read else { panic!("a {size}-byte block answer was read") };
    assert_eq!(err.kind(), std::io::ErrorKind::InvalidData, "{err}");
    let written = futures::executor::block_on(SyncCodec.write_response(&SYNC_PROTO, &mut Cursor::new(Vec::new()), answer));
    assert!(written.is_err(), "a {size}-byte block answer was written");
    println!("[residual] a valid {size}-byte block: applied, and refused on read and on write");
    Ok(())
}
