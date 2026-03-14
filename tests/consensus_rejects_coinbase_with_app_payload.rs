use anyhow::{Context, Result};
use tempfile::TempDir;

use csd::chain::index::{get_hidx, header_hash, index_header};
use csd::state::app_state::epoch_of;
use csd::state::db::{k_block, set_tip, Stores};
use csd::state::utxo::validate_and_apply_block;
use csd::types::{AppPayload, Block, Transaction};

mod testutil_chain;
use testutil_chain::{build_base_chain_with_miner, make_coinbase_to, make_test_header, open_db};

fn h20(n: u8) -> [u8; 20] {
    [n; 20]
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
fn rejects_block_with_coinbase_app_payload() -> Result<()> {
    std::env::set_var("CSD_BYPASS_POW", "1");

    let tmp = TempDir::new().context("tmp")?;
    let db = open_db(&tmp).context("open db")?;

    let miner = h20(0x44);
    let shared_len = 7u64;
    let start_time = 1_702_400_000u64;

    let shared = build_base_chain_with_miner(&db, shared_len, start_time, miner)
        .context("build shared chain")?;
    let parent = shared[(shared_len - 1) as usize];
    let height = shared_len;

    let mut cb: Transaction = make_coinbase_to(height, miner);
    cb.app = AppPayload::Propose {
        domain: "coinbase-bad".to_string(),
        payload_hash: [0xAB; 32],
        uri: "https://example.com/coinbase-bad".to_string(),
        expires_epoch: epoch_of(height) + 5,
    };

    let txs = vec![cb];
    let hdr = make_test_header(&db, parent, &txs, height)
        .context("make_test_header")?;
    let blk = Block { header: hdr, txs };

    let err = persist_index_apply_block(&db, &blk, height)
        .expect_err("coinbase with app payload must be rejected");

    let msg = format!("{err:#}");
    assert!(
        msg.contains("coinbase must not carry app payload"),
        "unexpected error: {msg}"
    );

    Ok(())
}
