use anyhow::{Context, Result};
use std::sync::Arc;
use std::time::Duration;
use tempfile::TempDir;
use tokio::sync::mpsc;

use libp2p::Multiaddr;

use csd::chain::index::{get_hidx, header_hash, index_header};
use csd::net::mempool::Mempool;
use csd::net::node::{spawn_p2p, NetConfig, TestPeerMode};
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

fn extend_chain(
    db: &Stores,
    start_tip: Hash32,
    start_height: u64,
    extra_len: u64,
    miner: Hash20,
) -> Result<Hash32> {
    let mut prev = start_tip;

    for height in start_height..(start_height + extra_len) {
        let cb = csd::chain::mine::coinbase(
            miner,
            csd::params::block_reward(height),
            height,
            None,
        );
        let txs = vec![cb];
        let hdr = make_test_header(db, prev, &txs, height)
            .with_context(|| format!("make_test_header h={height}"))?;
        let blk = Block { header: hdr, txs };
        prev = persist_index_apply_block(db, &blk, height)?;
    }

    Ok(prev)
}

async fn wait_for_listen_addr(
    handle: &csd::net::node::NetHandle,
    label: &str,
) -> Result<Multiaddr> {
    for _ in 0..60 {
        if let Some(addr) = handle.listen_addr().await {
            return Ok(addr);
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    anyhow::bail!("{label} did not expose listen_addr in time");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 6)]
async fn live_multi_peer_sync_converges_to_heaviest_branch() -> Result<()> {
    let tmp_a = TempDir::new().context("tmp_a")?;
    let tmp_b = TempDir::new().context("tmp_b")?;
    let tmp_c = TempDir::new().context("tmp_c")?;

    let db_a = Arc::new(open_db(&tmp_a).context("open db_a")?);
    let db_b = Arc::new(open_db(&tmp_b).context("open db_b")?);
    let db_c = Arc::new(open_db(&tmp_c).context("open db_c")?);

    let mp_a = Arc::new(Mempool::new());
    let mp_b = Arc::new(Mempool::new());
    let mp_c = Arc::new(Mempool::new());

    let miner_shared = h20(0x11);
    let miner_a = h20(0xA1);
    let miner_c = h20(0xC3);

    let shared_len = 7u64;       // heights 0..6
    let branch_a_extra = 3u64;   // A ends at height 9
    let branch_c_extra = 5u64;   // C ends at height 11 (heaviest)
    let start_time = 1_700_500_000u64;

    // Build the exact same shared prefix on all three nodes.
    let shared_a = build_base_chain_with_miner(&db_a, shared_len, start_time, miner_shared)
        .context("build shared_a")?;
    let shared_b = build_base_chain_with_miner(&db_b, shared_len, start_time, miner_shared)
        .context("build shared_b")?;
    let shared_c = build_base_chain_with_miner(&db_c, shared_len, start_time, miner_shared)
        .context("build shared_c")?;

    let common_tip_a = shared_a[(shared_len - 1) as usize];
    let common_tip_b = shared_b[(shared_len - 1) as usize];
    let common_tip_c = shared_c[(shared_len - 1) as usize];

    assert_eq!(common_tip_a, common_tip_b, "shared prefix A/B tip mismatch");
    assert_eq!(common_tip_a, common_tip_c, "shared prefix A/C tip mismatch");

    assert_tip_eq(&db_a, common_tip_a)?;
    assert_tip_eq(&db_b, common_tip_b)?;
    assert_tip_eq(&db_c, common_tip_c)?;

    let genesis_hash = shared_a[0];
    let branch_start_height = shared_len;

    // Extend A and C differently from the same common ancestor.
    let tip_a = extend_chain(&db_a, common_tip_a, branch_start_height, branch_a_extra, miner_a)
        .context("extend branch A")?;

    let tip_c = extend_chain(&db_c, common_tip_c, branch_start_height, branch_c_extra, miner_c)
        .context("extend branch C")?;

    let hi_a = get_hidx(&db_a, &tip_a)?.expect("missing hidx A");
    let hi_c = get_hidx(&db_c, &tip_c)?.expect("missing hidx C");

    assert!(
        hi_c.chainwork > hi_a.chainwork,
        "branch C must be heavier than branch A"
    );
    assert!(
        hi_c.height > hi_a.height,
        "branch C must also be longer in this test"
    );

    let (mined_tx_a, mined_rx_a) = mpsc::unbounded_channel();
    let (gossip_tx_a, gossip_rx_a) = mpsc::unbounded_channel();
    let (mined_tx_b, mined_rx_b) = mpsc::unbounded_channel();
    let (gossip_tx_b, gossip_rx_b) = mpsc::unbounded_channel();
    let (mined_tx_c, mined_rx_c) = mpsc::unbounded_channel();
    let (gossip_tx_c, gossip_rx_c) = mpsc::unbounded_channel();

    drop(mined_tx_a);
    drop(gossip_tx_a);
    drop(mined_tx_b);
    drop(gossip_tx_b);
    drop(mined_tx_c);
    drop(gossip_tx_c);

    // Start A first.
    let cfg_a = NetConfig {
        datadir: tmp_a.path().to_string_lossy().to_string(),
        listen: "/ip4/127.0.0.1/tcp/0".parse::<Multiaddr>()?,
        bootnodes: vec![],
        genesis_hash,
        is_bootnode: true,
        test_mode: TestPeerMode::Normal,
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

    // Start C second.
    let cfg_c = NetConfig {
        datadir: tmp_c.path().to_string_lossy().to_string(),
        listen: "/ip4/127.0.0.1/tcp/0".parse::<Multiaddr>()?,
        bootnodes: vec![],
        genesis_hash,
        is_bootnode: true,
        test_mode: TestPeerMode::Normal,
    };

    let handle_c = spawn_p2p(
        db_c.clone(),
        mp_c.clone(),
        cfg_c,
        mined_rx_c,
        gossip_rx_c,
        csd::chain::lock::new_chain_lock(),
    )
    .await
    .context("spawn_p2p C")?;

    let listen_a = wait_for_listen_addr(&handle_a, "node A").await?;
    let listen_c = wait_for_listen_addr(&handle_c, "node C").await?;

    let bootnode_a: Multiaddr = format!("{}/p2p/{}", listen_a, handle_a.peer_id)
        .parse()
        .context("parse bootnode_a")?;

    let bootnode_c: Multiaddr = format!("{}/p2p/{}", listen_c, handle_c.peer_id)
        .parse()
        .context("parse bootnode_c")?;

    // Start B last and connect to both competing peers.
    let cfg_b = NetConfig {
        datadir: tmp_b.path().to_string_lossy().to_string(),
        listen: "/ip4/127.0.0.1/tcp/0".parse::<Multiaddr>()?,
        bootnodes: vec![bootnode_a, bootnode_c],
        genesis_hash,
        is_bootnode: false,
        test_mode: TestPeerMode::Normal,
    };

        let handle_b = spawn_p2p(
        db_b.clone(),
        mp_b.clone(),
        cfg_b,
        mined_rx_b,
        gossip_rx_b,
        csd::chain::lock::new_chain_lock(),
    )
    .await
    .context("spawn_p2p B")?;
    let _listen_b = wait_for_listen_addr(&handle_b, "node B").await?;

    // Let both outbound connections and initial tip exchanges settle first.
    tokio::time::sleep(Duration::from_secs(2)).await;

    // Poll for convergence to the heaviest branch.
    let deadline = tokio::time::Instant::now() + Duration::from_secs(30);
    let mut last_tip_b = get_tip(&db_b)?.unwrap_or([0u8; 32]);
    let mut last_height_b = get_hidx(&db_b, &last_tip_b)?
        .map(|x| x.height)
        .unwrap_or(0);

    loop {
        last_tip_b = get_tip(&db_b)?.unwrap_or([0u8; 32]);
        last_height_b = get_hidx(&db_b, &last_tip_b)?
            .map(|x| x.height)
            .unwrap_or(0);

        if last_tip_b == tip_c {
            break;
        }

        if tokio::time::Instant::now() >= deadline {
            break;
        }

        tokio::time::sleep(Duration::from_millis(250)).await;
    }

        let hi_b = get_hidx(&db_b, &last_tip_b)?;
    assert_eq!(
        last_tip_b,
        tip_c,
        "node B must converge to the heaviest branch (node C), not merely the first peer heard (tip_b=0x{}, tip_c=0x{}, b_h={:?}, c_h={}, b_work={:?}, c_work={})",
        hex::encode(last_tip_b),
        hex::encode(tip_c),
        hi_b.as_ref().map(|x| x.height),
        hi_c.height,
        hi_b.as_ref().map(|x| x.chainwork),
        hi_c.chainwork,
    );

    let hi_b = hi_b.expect("missing hidx B final");
    assert_eq!(hi_b.height, hi_c.height, "node B height should match heaviest peer");
    assert_eq!(hi_b.chainwork, hi_c.chainwork, "node B chainwork should match heaviest peer");

    let blk_b = load_block(&db_b, &last_tip_b)?;
    let blk_c = load_block(&db_c, &tip_c)?;
    assert_eq!(
        header_hash(&blk_b.header),
        header_hash(&blk_c.header),
        "node B final tip block must match node C exactly"
    );

    Ok(())
}
