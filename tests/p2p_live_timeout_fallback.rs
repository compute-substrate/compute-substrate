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
async fn live_timeout_provider_falls_back_to_good_peer() -> Result<()> {
    let tmp_good = TempDir::new().context("tmp_good")?;
    let tmp_silent = TempDir::new().context("tmp_silent")?;
    let tmp_sync = TempDir::new().context("tmp_sync")?;

    let db_good = Arc::new(open_db(&tmp_good).context("open db_good")?);
    let db_silent = Arc::new(open_db(&tmp_silent).context("open db_silent")?);
    let db_sync = Arc::new(open_db(&tmp_sync).context("open db_sync")?);

    let mp_good = Arc::new(Mempool::new());
    let mp_silent = Arc::new(Mempool::new());
    let mp_sync = Arc::new(Mempool::new());

    let miner = h20(0xA1);
    let shared_len = 7u64; // heights 0..6
    let extra_len = 4u64; // heavier branch reaches height 10
    let start_time = 1_700_700_000u64;

    // All 3 nodes start from the same canonical prefix.
    let shared_good = build_base_chain_with_miner(&db_good, shared_len, start_time, miner)
        .context("build shared_good")?;
    let shared_silent = build_base_chain_with_miner(&db_silent, shared_len, start_time, miner)
        .context("build shared_silent")?;
    let shared_sync = build_base_chain_with_miner(&db_sync, shared_len, start_time, miner)
        .context("build shared_sync")?;

    let common_tip_good = shared_good[(shared_len - 1) as usize];
    let common_tip_silent = shared_silent[(shared_len - 1) as usize];
    let common_tip_sync = shared_sync[(shared_len - 1) as usize];

    assert_eq!(common_tip_good, common_tip_silent, "shared prefix mismatch");
    assert_eq!(common_tip_good, common_tip_sync, "shared prefix mismatch");

    assert_tip_eq(&db_good, common_tip_good)?;
    assert_tip_eq(&db_silent, common_tip_silent)?;
    assert_tip_eq(&db_sync, common_tip_sync)?;

    let genesis_hash = shared_good[0];

    // Build the heavier branch only on the GOOD provider.
    let mut prev = common_tip_good;
    for height in shared_len..(shared_len + extra_len) {
        let cb = csd::chain::mine::coinbase(miner, csd::params::block_reward(height), height, None);
        let txs = vec![cb];
        let hdr = make_test_header(&db_good, prev, &txs, height)
            .with_context(|| format!("make_test_header good h={height}"))?;
        let blk = Block { header: hdr, txs };
        prev = persist_index_apply_block(&db_good, &blk, height)?;
    }

    let tip_good = prev;
    let hi_good = get_hidx(&db_good, &tip_good)?.expect("missing hidx for good tip");
    assert_eq!(hi_good.height, shared_len + extra_len - 1);

    // SILENT provider gets the header index for the heavier branch,
    // but not the actual block bytes. So it can advertise height/work
    // and header chain, but GetBlock will fail with unknown block.
    let mut prev_silent = common_tip_silent;
    for height in shared_len..(shared_len + extra_len) {
        let bh_good = shared_good
            .get(height as usize)
            .copied()
            .unwrap_or([0u8; 32]);

        let src_bh = if bh_good != [0u8; 32] && db_good.blocks.get(k_block(&bh_good))?.is_some() {
            bh_good
        } else if height == shared_len {
            load_block(&db_good, &tip_good)?
                .header
                .prev
        } else {
            prev_silent
        };

        let blk_src = load_block(&db_good, &tip_good)
            .or_else(|_| load_block(&db_good, &prev))
            .context("load source block fallback")?;
        let _ = blk_src; // just to keep intent explicit

        let mut cur = tip_good;
        let wanted_height = height;
        loop {
            let hi = get_hidx(&db_good, &cur)?.expect("missing hidx while walking good chain");
            if hi.height == wanted_height {
                let blk = load_block(&db_good, &cur)?;
                let parent_hi = if blk.header.prev == [0u8; 32] {
                    None
                } else {
                    get_hidx(&db_silent, &blk.header.prev)
                        .context("get_hidx silent parent")?
                };
                index_header(&db_silent, &blk.header, parent_hi.as_ref())
                    .with_context(|| format!("index_header silent h={wanted_height}"))?;
                prev_silent = cur;
                break;
            }
            cur = hi.parent;
        }
    }

    let hi_silent = get_hidx(&db_silent, &prev_silent)?.expect("missing hidx silent tip");
    assert_eq!(hi_silent.height, hi_good.height, "silent provider must advertise same height");

    let (mined_tx_good, mined_rx_good) = mpsc::unbounded_channel();
    let (gossip_tx_good, gossip_rx_good) = mpsc::unbounded_channel();

    let (mined_tx_silent, mined_rx_silent) = mpsc::unbounded_channel();
    let (gossip_tx_silent, gossip_rx_silent) = mpsc::unbounded_channel();

    let (mined_tx_sync, mined_rx_sync) = mpsc::unbounded_channel();
    let (gossip_tx_sync, gossip_rx_sync) = mpsc::unbounded_channel();

    drop(mined_tx_good);
    drop(gossip_tx_good);
    drop(mined_tx_silent);
    drop(gossip_tx_silent);
    drop(mined_tx_sync);
    drop(gossip_tx_sync);

    // Start silent provider first.
    let cfg_silent = NetConfig {
        datadir: tmp_silent.path().to_string_lossy().to_string(),
        listen: "/ip4/127.0.0.1/tcp/0".parse::<Multiaddr>()?,
        bootnodes: vec![],
        genesis_hash,
        is_bootnode: true,
    };

    let handle_silent = spawn_p2p(
        db_silent.clone(),
        mp_silent.clone(),
        cfg_silent,
        mined_rx_silent,
        gossip_rx_silent,
        csd::chain::lock::new_chain_lock(),
    )
    .await
    .context("spawn_p2p silent")?;

    // Start good provider second.
    let cfg_good = NetConfig {
        datadir: tmp_good.path().to_string_lossy().to_string(),
        listen: "/ip4/127.0.0.1/tcp/0".parse::<Multiaddr>()?,
        bootnodes: vec![],
        genesis_hash,
        is_bootnode: true,
    };

    let handle_good = spawn_p2p(
        db_good.clone(),
        mp_good.clone(),
        cfg_good,
        mined_rx_good,
        gossip_rx_good,
        csd::chain::lock::new_chain_lock(),
    )
    .await
    .context("spawn_p2p good")?;

    tokio::time::sleep(Duration::from_millis(700)).await;

    let listen_silent = {
        let mut got: Option<Multiaddr> = None;
        for _ in 0..40 {
            if let Some(addr) = handle_silent.listen_addr().await {
                got = Some(addr);
                break;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
        got.context("silent provider did not expose listen_addr in time")?
    };

    let listen_good = {
        let mut got: Option<Multiaddr> = None;
        for _ in 0..40 {
            if let Some(addr) = handle_good.listen_addr().await {
                got = Some(addr);
                break;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
        got.context("good provider did not expose listen_addr in time")?
    };

    // Syncing node dials BOTH peers, with the silent one first.
    let bootnode_silent: Multiaddr =
        format!("{}/p2p/{}", listen_silent, handle_silent.peer_id)
            .parse()
            .context("parse bootnode_silent")?;

    let bootnode_good: Multiaddr =
        format!("{}/p2p/{}", listen_good, handle_good.peer_id)
            .parse()
            .context("parse bootnode_good")?;

    let cfg_sync = NetConfig {
        datadir: tmp_sync.path().to_string_lossy().to_string(),
        listen: "/ip4/127.0.0.1/tcp/0".parse::<Multiaddr>()?,
        bootnodes: vec![bootnode_silent, bootnode_good],
        genesis_hash,
        is_bootnode: false,
    };

    let _handle_sync = spawn_p2p(
        db_sync.clone(),
        mp_sync.clone(),
        cfg_sync,
        mined_rx_sync,
        gossip_rx_sync,
        csd::chain::lock::new_chain_lock(),
    )
    .await
    .context("spawn_p2p sync")?;

    // Need enough time for:
    // connect -> choose peer -> fetch headers -> fail block fetch from silent peer
    // -> mark bad provider / requeue -> fetch from good peer -> reorg/apply
    tokio::time::sleep(Duration::from_secs(10)).await;

    let tip_sync = get_tip(&db_sync)?
        .expect("sync node should have a tip");
    assert_eq!(
        tip_sync, tip_good,
        "sync node should converge to the good provider's heaviest tip after silent-provider fallback"
    );

    let hi_sync = get_hidx(&db_sync, &tip_sync)?.expect("missing hidx sync tip");
    assert_eq!(hi_sync.height, hi_good.height, "sync node height should match good provider");

    let blk_good = load_block(&db_good, &tip_good)?;
    let blk_sync = load_block(&db_sync, &tip_sync)?;
    assert_eq!(
        header_hash(&blk_good.header),
        header_hash(&blk_sync.header),
        "synced winning block header must match good provider exactly"
    );

    Ok(())
}
