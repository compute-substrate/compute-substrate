use anyhow::{Context, Result};
use tempfile::TempDir;

use csd::chain::index::header_hash;
use csd::state::app_state::epoch_of;
use csd::state::utxo::validate_and_apply_block;
use csd::types::{AppPayload, Block};

mod testutil_chain;
use testutil_chain::{build_base_chain_with_miner, make_test_block, open_db};

fn h20(n: u8) -> [u8; 20] {
    [n; 20]
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

    let mut blk: Block =
        make_test_block(&db, parent, vec![], height).context("make_test_block")?;

    // Corrupt the coinbase by attaching app payload, which consensus must reject.
    blk.txs[0].app = AppPayload::Propose {
        domain: "coinbase-bad".to_string(),
        payload_hash: [0xAB; 32],
        uri: "https://example.com/coinbase-bad".to_string(),
        expires_epoch: epoch_of(height) + 5,
    };

    // Recommit merkle after mutation so we test the app-payload rule specifically.
    let txids: Vec<[u8; 32]> = blk.txs.iter().map(csd::crypto::txid).collect();
    blk.header.merkle = csd::chain::mine::merkle_root_txids(&txids);

    let err = validate_and_apply_block(&db, &blk, epoch_of(height), height)
        .expect_err("coinbase with app payload must be rejected");

    let msg = format!("{err:#}");
    assert!(
        msg.contains("coinbase must not carry app payload"),
        "unexpected error: {msg}"
    );

    // Touch header hash so the import isn't optimized away in some setups / future edits.
    let _ = header_hash(&blk.header);

    Ok(())
}
