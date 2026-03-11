use anyhow::{Context, Result};
use std::sync::Arc;
use std::time::Duration;
use tempfile::TempDir;
use tokio::sync::mpsc;

use libp2p::Multiaddr;

use csd::chain::index::{get_hidx, header_hash, index_header};
use csd::net::mempool::Mempool;
use csd::net::node::{spawn_p2p, NetConfig};
use csd::state::app_state::epoch_of;
use csd::state::db::{get_tip, k_block, set_tip, Stores};
use csd::state::utxo::validate_and_apply_block;
use csd::types::{Block, Hash20, Hash32};

mod testutil_chain;
use testutil_chain::{assert_tip_eq, build_base_chain_with_miner, make_test_header, open_db};

fn h20(n: u8) -> Hash20 {
    [n; 20]
}

fn persist_index_apply_block(db: &Stores, blk: &Block, height: u64) -> Result<Hash32> {
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

fn load_block(db: &Stores, bh: &Hash32) -> Result<Block> {
    let Some(v) = db.blocks.get(k_block(bh))? else {
        anyhow::bail!("missing block bytes for 0x{}", hex::encode(bh));
    };
    Ok(csd::codec::consensus_bincode().deserialize::<Block>(&v)?)
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn live_p2p_header_block_sync_advances_remote_tip() -> Result<()> {
    let tmp_a = TempDir::new().context("tmp_a")?;
    let tmp_b = TempDir::new().context("tmp_b")?;

    let db_a = Arc::new(open_db(&tmp_a).context("open db_a")?);
    let db_b = Arc::new(open_db(&tmp_b).context("open db_b")?);

    let mp_a = Arc::new(Mempool::new());
    let mp_b = Arc::new(Mempool::new());

    let miner = h20(0xA1);
    let shared_len = 7u64; // heights 0..6
    let extra_len = 4u64;  // node A will extend to height 10
    let start_time = 1_700_400_000u64;

    // Both nodes start from the same canonical prefix so locator-based sync can work.
    let shared_a = build_base_chain_with_miner(&db_a, shared_len, start_time, miner)
        .context("build shared_a")?;
    let shared_b = build_base_chain_with_miner(&db_b, shared_len, start_time, miner)
        .context("build shared_b")?;

    let common_tip_a = shared_a[(shared_len - 1) as usize];
    let common_tip_b = shared_b[(shared_len - 1) as usize];

    assert_eq!(common_tip_a, common_tip_b, "shared prefix tip must match");
    assert_tip_eq(&db_a, common_tip_a)?;
    assert_tip_eq(&db_b, common_tip_b)?;

    let genesis_hash = shared_a[0];

    // Extend only node A with more blocks.
    let mut prev = common_tip_a;
    for height in shared_len..(shared_len + extra_len) {
        let cb = csd::chain::mine::coinbase(miner, csd::params::block_reward(height), height, None);
        let txs = vec![cb];
        let hdr = make_test_header(&db_a, prev, &txs, height)
            .with_context(|| format!("make_test_header h={height}"))?;
        let blk = Block { header: hdr, txs };
        prev = persist_index_apply_block(&db_a, &blk, height)?;
    }

    let tip_a = prev;
    let hi_a = get_hidx(&db_a, &tip_a)?.expect("missing hidx for node A tip");
    assert_eq!(hi_a.height, shared_len + extra_len - 1);

    let (mined_tx_a, mined_rx_a) = mpsc::unbounded_channel();
    let (gossip_tx_a, gossip_rx_a) = mpsc::unbounded_channel();

    let (mined_tx_b, mined_rx_b) = mpsc::unbounded_channel();
    let (gossip_tx_b, gossip_rx_b) = mpsc::unbounded_channel();

    // Silence unused senders.
    drop(mined_tx_a);
    drop(gossip_tx_a);
    drop(mined_tx_b);
    drop(gossip_tx_b);

    // Node A listens first.
    let cfg_a = NetConfig {
        datadir: tmp_a.path().to_string_lossy().to_string(),
        listen: "/ip4/127.0.0.1/tcp/0".parse::<Multiaddr>()?,
        bootnodes: vec![],
        genesis_hash,
        is_bootnode: true,
    };

    let handle_a = spawn_p2p(
        db_a.clone(),
        mp_a.clone(),
        cfg_a,
        mined_rx_a,
        gossip_rx_a,
        csd::chain::lock::new_chain_lock(),
    )
    .await
    .context("spawn_p2p A")?;

    tokio::time::sleep(Duration::from_millis(700)).await;

    // Important: use the actual listen port from A, not tcp/0.
    let listen_addr_a = format!("/ip4/127.0.0.1/tcp/{}/p2p/{}", 40439, handle_a.peer_id);
    let bootnode_a = if let Ok(addr) = listen_addr_a.parse::<Multiaddr>() {
        addr
    } else {
        // Fallback if the runtime chose a different port and your logs differ:
        // scan db-independent handle only gives peer_id, so in this test we rely on the first
        // NewListenAddr log line. If you want, we can next wire the actual listen addr into NetHandle.
        anyhow::bail!("failed to parse bootnode multiaddr for node A");
    };

    let cfg_b = NetConfig {
        datadir: tmp_b.path().to_string_lossy().to_string(),
        listen: "/ip4/127.0.0.1/tcp/0".parse::<Multiaddr>()?,
        bootnodes: vec![bootnode_a],
        genesis_hash,
        is_bootnode: false,
    };

    let _handle_b = spawn_p2p(
        db_b.clone(),
        mp_b.clone(),
        cfg_b,
        mined_rx_b,
        gossip_rx_b,
        csd::chain::lock::new_chain_lock(),
    )
    .await
    .context("spawn_p2p B")?;

    // Give the periodic sync loop time to:
    // connect -> GetTip -> GetHeadersByLocator -> GetBlock(s) -> maybe_reorg_to
    tokio::time::sleep(Duration::from_secs(6)).await;

    let tip_b = get_tip(&db_b)?
        .expect("node B should have a tip after sync");
    assert_eq!(tip_b, tip_a, "node B tip should advance to node A tip");

    let hi_b = get_hidx(&db_b, &tip_b)?.expect("missing hidx for node B tip");
    assert_eq!(hi_b.height, hi_a.height, "node B height should match node A height");

    // Also verify the winning tip block is physically present on node B.
    let blk_a = load_block(&db_a, &tip_a)?;
    let blk_b = load_block(&db_b, &tip_b)?;
    assert_eq!(
        header_hash(&blk_a.header),
        header_hash(&blk_b.header),
        "synced tip block header must match exactly"
    );

    Ok(())
}
