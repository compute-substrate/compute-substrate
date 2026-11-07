#![cfg(feature = "test-bypass")] // live p2p lane: toy chains and the fault seam need the bypass (cargo test --features test-bypass)
// A peer serves an honest block with one signature byte altered: the txids, and so the header,
// still match, and the body is stored. The sync node must drop that body without marking the
// block, not ask that peer for it again, and apply the honest body from another peer: on a
// direct extension of its tip, and on a fork whose altered block sits at the local chainwork.
// The two tests share process-wide counters, so they run one at a time and compare deltas.

use anyhow::{Context, Result};
use std::sync::atomic::Ordering;
use std::sync::Arc;
use std::time::Duration;
use tempfile::TempDir;
use tokio::sync::mpsc;

use libp2p::Multiaddr;

use csd::chain::index::{get_hidx, header_hash, index_header};
use csd::chain::mine::coinbase;
use csd::crypto::{sign_tx_compact_secp256k1, txid};
use csd::net::mempool::Mempool;
use csd::net::node::{spawn_p2p, NetConfig, TestPeerMode, TEST_PEER_SCORES, TEST_PUSHED_BODIES, TEST_SUBSTITUTED_BODIES_SERVED};
use csd::params::block_reward;
use csd::state::app_state::epoch_of;
use csd::state::db::{
    bad_mark_count, get_tip, k_block, set_tip, Stores, DROPPED_BLOCK_BODIES,
};
use csd::state::utxo::validate_and_apply_block;
use csd::types::{AppPayload, Block, Hash32, OutPoint, Transaction, TxIn, TxOut};

mod testutil_chain;
use testutil_chain::{build_base_chain, make_test_header, open_db, test_signer_addr, test_signer_sk};

// Each wait ends on its event; the bounds stay below BAD_PROVIDER_RETRY_SECS (120 s,
// src/net/node.rs), so the bad peer stays ineligible for the block for the whole run.
const PHASE1_SECS: u64 = 30;
const CONVERGE_SECS: u64 = 45;
const START: u64 = 1_700_700_000;

static SERIAL: std::sync::Mutex<()> = std::sync::Mutex::new(());

fn counters() -> (u64, u64) {
    (
        TEST_SUBSTITUTED_BODIES_SERVED.load(Ordering::Relaxed),
        DROPPED_BLOCK_BODIES.load(Ordering::Relaxed),
    )
}

fn apply_block(db: &Stores, blk: &Block, height: u64) -> Result<Hash32> {
    let bh = header_hash(&blk.header);
    db.blocks.insert(k_block(&bh), csd::codec::consensus_bincode().serialize(blk)?)?;
    index_header(db, &blk.header, get_hidx(db, &blk.header.prev)?.as_ref())?;
    validate_and_apply_block(db, blk, epoch_of(height), height)
        .with_context(|| format!("apply h={height}"))?;
    set_tip(db, &bh)?;
    Ok(bh)
}

/// A spend of block `bh`'s coinbase to the signer, signed.
fn spend_of(db: &Stores, bh: &Hash32) -> Result<Transaction> {
    let b1: Block = csd::codec::consensus_bincode().deserialize(&db.blocks.get(k_block(bh))?.unwrap())?;
    let mut spend = Transaction {
        version: 1,
        inputs: vec![TxIn { prevout: OutPoint { txid: txid(&b1.txs[0]), vout: 0 }, script_sig: vec![] }],
        outputs: vec![TxOut { value: b1.txs[0].outputs[0].value, script_pubkey: test_signer_addr() }],
        locktime: 0,
        app: AppPayload::None,
    };
    let (sig64, pub33) = sign_tx_compact_secp256k1(&spend, test_signer_sk());
    spend.inputs[0].script_sig = [&[64u8][..], &sig64, &[33u8], &pub33].concat();
    Ok(spend)
}

/// Applies blocks at `heights` on top of `parent`, `spends` in the first one, coinbases paying
/// `miner`. Returns the first and the last hash.
fn extend(
    db: &Stores,
    parent: Hash32,
    heights: std::ops::Range<u64>,
    miner: [u8; 20],
    spends: Vec<Transaction>,
) -> Result<(Hash32, Hash32)> {
    let mut prev = parent;
    let mut first = None;
    let mut spends = Some(spends);
    for height in heights {
        let mut txs = vec![coinbase(miner, block_reward(height), height, None)];
        txs.extend(spends.take().unwrap_or_default());
        let header = make_test_header(db, prev, &txs, height)?;
        prev = apply_block(db, &Block { header, txs }, height)?;
        first.get_or_insert(prev);
    }
    Ok((first.expect("non-empty range"), prev))
}

async fn spawn(db: &Arc<Stores>, dir: &TempDir, bootnodes: Vec<Multiaddr>, genesis: Hash32, mode: TestPeerMode) -> Result<csd::net::node::NetHandle> {
    let (mined_tx, mined_rx) = mpsc::unbounded_channel();
    let (gossip_tx, gossip_rx) = mpsc::unbounded_channel();
    drop(mined_tx);
    drop(gossip_tx);
    let cfg = NetConfig {
        datadir: dir.path().to_string_lossy().to_string(),
        listen: "/ip4/127.0.0.1/tcp/0".parse::<Multiaddr>()?,
        bootnodes,
        genesis_hash: genesis,
        is_bootnode: true,
        test_mode: mode,
    };
    spawn_p2p(db.clone(), Arc::new(Mempool::new()), cfg, mined_rx, gossip_rx, csd::chain::lock::new_chain_lock())
        .await
        .context("spawn_p2p")
}

async fn dial_addr(handle: &csd::net::node::NetHandle) -> Result<Multiaddr> {
    for _ in 0..60 {
        if let Some(addr) = handle.listen_addr().await {
            return Ok(format!("{}/p2p/{}", addr, handle.peer_id).parse()?);
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    anyhow::bail!("no listen_addr in time");
}

async fn wait_until(secs: u64, mut done: impl FnMut() -> Result<bool>) -> Result<bool> {
    let deadline = tokio::time::Instant::now() + Duration::from_secs(secs);
    loop {
        if done()? {
            return Ok(true);
        }
        if tokio::time::Instant::now() >= deadline {
            return Ok(false);
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
}

/// Runs both phases: the substituting peer alone, then an honest peer. `altered` is the block the
/// substituting peer alters, `tip` the honest tip, `sync_tip` the sync node's tip before.
#[allow(clippy::too_many_arguments)]
async fn drop_then_fetch_from_honest_peer(
    (db_good, tmp_good): (&Arc<Stores>, &TempDir),
    (db_bad, tmp_bad): (&Arc<Stores>, &TempDir),
    (db_sync, tmp_sync): (&Arc<Stores>, &TempDir),
    genesis: Hash32,
    altered: Hash32,
    tip: Hash32,
    sync_tip: Hash32,
) -> Result<()> {
    let (served0, dropped0) = counters();

    // Phase 1: the substituting peer is the sync node's only peer.
    let bad = spawn(db_bad, tmp_bad, vec![], genesis, TestPeerMode::SubstituteSignatures).await?;
    let sync = spawn(db_sync, tmp_sync, vec![dial_addr(&bad).await?], genesis, TestPeerMode::Normal).await?;

    let dropped = wait_until(PHASE1_SECS, || Ok(counters().1 > dropped0)).await?;
    assert!(dropped, "the sync node did not drop the altered body within {PHASE1_SECS}s");
    assert_eq!(get_tip(db_sync)?, Some(sync_tip), "the altered block must not be applied");
    assert_eq!(bad_mark_count(db_sync)?, 0, "nothing honest may be marked");
    assert_eq!(counters().0 - served0, 1);
    tokio::time::sleep(Duration::from_millis(500)).await;
    assert!(db_sync.blocks.get(k_block(&altered))?.is_none(), "the dropped body must stay dropped");

    // Phase 2: an honest peer dials in; the body can only come from it.
    let _good = spawn(db_good, tmp_good, vec![dial_addr(&sync).await?], genesis, TestPeerMode::Normal).await?;
    let synced = wait_until(CONVERGE_SECS, || Ok(get_tip(db_sync)? == Some(tip))).await?;
    assert!(
        synced,
        "the sync node did not reach the honest tip within {CONVERGE_SECS}s (tip height {:?})",
        get_tip(db_sync)?.and_then(|t| get_hidx(db_sync, &t).ok().flatten()).map(|hi| hi.height)
    );
    assert_eq!(bad_mark_count(db_sync)?, 0, "nothing honest may be marked");
    assert_eq!(
        db_sync.blocks.get(k_block(&altered))?,
        db_good.blocks.get(k_block(&altered))?,
        "the stored body must be the honest one"
    );
    assert_eq!(
        counters().0 - served0,
        1,
        "the peer that served the altered body must not be asked for it again"
    );
    Ok(())
}

// The sync node is at h6; the honest chain h7 (a signed spend), h8, h9 extends it directly.
#[tokio::test(flavor = "multi_thread", worker_threads = 6)]
async fn live_substituted_body_is_dropped_and_fetched_from_another_peer() -> Result<()> {
    let _serial = SERIAL.lock().unwrap_or_else(|e| e.into_inner());
    let (tmp_good, tmp_bad, tmp_sync) = (TempDir::new()?, TempDir::new()?, TempDir::new()?);
    let db_good = Arc::new(open_db(&tmp_good)?);
    let db_bad = Arc::new(open_db(&tmp_bad)?);
    let db_sync = Arc::new(open_db(&tmp_sync)?);

    let base = build_base_chain(&db_good, 7, START)?;
    assert_eq!(build_base_chain(&db_bad, 7, START)?, base);
    assert_eq!(build_base_chain(&db_sync, 7, START)?, base);
    let spend = spend_of(&db_good, &base[1])?;
    let (h7, tip) = extend(&db_good, base[6], 7..10, [0x77; 20], vec![spend.clone()])?;
    assert_eq!(extend(&db_bad, base[6], 7..10, [0x77; 20], vec![spend])?, (h7, tip));

    drop_then_fetch_from_honest_peer(
        (&db_good, &tmp_good),
        (&db_bad, &tmp_bad),
        (&db_sync, &tmp_sync),
        base[0],
        h7,
        tip,
        base[6],
    )
    .await
}

// The sync node sits on its own A8; the honest fork B8 (a signed spend), B9 is heavier, and B8 is at
// the local chainwork, so only the refetch exception requests it again.
#[tokio::test(flavor = "multi_thread", worker_threads = 6)]
async fn live_substituted_body_below_local_chainwork_is_fetched_again() -> Result<()> {
    let _serial = SERIAL.lock().unwrap_or_else(|e| e.into_inner());
    let (tmp_good, tmp_bad, tmp_sync) = (TempDir::new()?, TempDir::new()?, TempDir::new()?);
    let db_good = Arc::new(open_db(&tmp_good)?);
    let db_bad = Arc::new(open_db(&tmp_bad)?);
    let db_sync = Arc::new(open_db(&tmp_sync)?);

    let base = build_base_chain(&db_good, 8, START)?;
    assert_eq!(build_base_chain(&db_bad, 8, START)?, base);
    assert_eq!(build_base_chain(&db_sync, 8, START)?, base);
    let spend = spend_of(&db_good, &base[1])?;
    let (b8, b9) = extend(&db_good, base[7], 8..10, [0x77; 20], vec![spend.clone()])?;
    assert_eq!(extend(&db_bad, base[7], 8..10, [0x77; 20], vec![spend])?, (b8, b9));
    let (a8, _) = extend(&db_sync, base[7], 8..9, [0xA8; 20], vec![])?;
    assert_eq!(
        get_hidx(&db_sync, &a8)?.unwrap().chainwork,
        get_hidx(&db_good, &b8)?.unwrap().chainwork,
        "fixture: B8 must sit at the local chainwork"
    );

    drop_then_fetch_from_honest_peer(
        (&db_good, &tmp_good),
        (&db_bad, &tmp_bad),
        (&db_sync, &tmp_sync),
        base[0],
        b8,
        b9,
        a8,
    )
    .await
}

// A peer serves h7 with its last tx repeated, a merkle duplicate of the honest list: the body binds
// but is refused at store, so it is never stored or dropped, the peer is not asked again, and the
// honest body comes from a second peer.
#[tokio::test(flavor = "multi_thread", worker_threads = 6)]
async fn live_repeated_suffix_body_is_refused_and_fetched_from_another_peer() -> Result<()> {
    let _serial = SERIAL.lock().unwrap_or_else(|e| e.into_inner());
    let (tmp_good, tmp_bad, tmp_sync) = (TempDir::new()?, TempDir::new()?, TempDir::new()?);
    let db_good = Arc::new(open_db(&tmp_good)?);
    let db_bad = Arc::new(open_db(&tmp_bad)?);
    let db_sync = Arc::new(open_db(&tmp_sync)?);

    let base = build_base_chain(&db_good, 7, START)?;
    assert_eq!(build_base_chain(&db_bad, 7, START)?, base);
    assert_eq!(build_base_chain(&db_sync, 7, START)?, base);
    let spends = vec![spend_of(&db_good, &base[1])?, spend_of(&db_good, &base[2])?];
    let (h7, tip) = extend(&db_good, base[6], 7..10, [0x77; 20], spends.clone())?;
    assert_eq!(extend(&db_bad, base[6], 7..10, [0x77; 20], spends)?, (h7, tip));
    let (served0, dropped0) = counters();

    let bad = spawn(&db_bad, &tmp_bad, vec![], base[0], TestPeerMode::RepeatLastTxOfOddBlocks).await?;
    let sync = spawn(&db_sync, &tmp_sync, vec![dial_addr(&bad).await?], base[0], TestPeerMode::Normal).await?;
    let served = wait_until(PHASE1_SECS, || Ok(counters().0 > served0)).await?;
    assert!(served, "the repeating peer was not asked within {PHASE1_SECS}s");
    tokio::time::sleep(Duration::from_millis(500)).await;
    assert_eq!(get_tip(&db_sync)?, Some(base[6]), "the repeated body must not be applied");
    assert_eq!(bad_mark_count(&db_sync)?, 0, "nothing honest may be marked");
    assert!(db_sync.blocks.get(k_block(&h7))?.is_none(), "the repeated body must not be stored");
    assert_eq!(counters().1, dropped0, "nothing to drop: it was refused at store");

    let _good = spawn(&db_good, &tmp_good, vec![dial_addr(&sync).await?], base[0], TestPeerMode::Normal).await?;
    let synced = wait_until(CONVERGE_SECS, || Ok(get_tip(&db_sync)? == Some(tip))).await?;
    assert!(
        synced,
        "the sync node did not reach the honest tip within {CONVERGE_SECS}s (tip height {:?})",
        get_tip(&db_sync)?.and_then(|t| get_hidx(&db_sync, &t).ok().flatten()).map(|hi| hi.height)
    );
    assert_eq!(bad_mark_count(&db_sync)?, 0);
    assert_eq!(db_sync.blocks.get(k_block(&h7))?, db_good.blocks.get(k_block(&h7))?, "the honest body is stored");
    assert_eq!(counters().0 - served0, 1, "the repeating peer must not be asked again");
    Ok(())
}

// After its body for h7 was dropped, the peer answers every GetTip with that body. A
// block response to another kind of request is not a late block response: it is not stored and
// not dropped a second time, and the honest body still comes from a second peer.
#[tokio::test(flavor = "multi_thread", worker_threads = 6)]
async fn live_block_pushed_in_answer_to_get_tip_is_not_stored() -> Result<()> {
    let _serial = SERIAL.lock().unwrap_or_else(|e| e.into_inner());
    let (tmp_good, tmp_bad, tmp_sync) = (TempDir::new()?, TempDir::new()?, TempDir::new()?);
    let db_good = Arc::new(open_db(&tmp_good)?);
    let db_bad = Arc::new(open_db(&tmp_bad)?);
    let db_sync = Arc::new(open_db(&tmp_sync)?);

    let base = build_base_chain(&db_good, 7, START)?;
    assert_eq!(build_base_chain(&db_bad, 7, START)?, base);
    assert_eq!(build_base_chain(&db_sync, 7, START)?, base);
    let spend = spend_of(&db_good, &base[1])?;
    let (h7, tip) = extend(&db_good, base[6], 7..10, [0x77; 20], vec![spend.clone()])?;
    assert_eq!(extend(&db_bad, base[6], 7..10, [0x77; 20], vec![spend])?, (h7, tip));
    let (served0, dropped0) = counters();
    let pushed0 = TEST_PUSHED_BODIES.load(Ordering::Relaxed);

    let bad = spawn(&db_bad, &tmp_bad, vec![], base[0], TestPeerMode::PushSubstitutedOnTip).await?;
    let sync = spawn(&db_sync, &tmp_sync, vec![dial_addr(&bad).await?], base[0], TestPeerMode::Normal).await?;
    let dropped = wait_until(PHASE1_SECS, || Ok(counters().1 > dropped0)).await?;
    assert!(dropped, "the sync node did not drop the altered body within {PHASE1_SECS}s");
    // GetTip goes out every 10 s (REGULAR_TIP_POLL_SECS): two pushes within 45 s.
    let pushed = wait_until(45, || Ok(TEST_PUSHED_BODIES.load(Ordering::Relaxed) >= pushed0 + 2)).await?;
    assert!(pushed, "the peer did not answer GetTip with the altered body twice within 45s");
    tokio::time::sleep(Duration::from_millis(500)).await;
    assert_eq!(counters().1 - dropped0, 1, "a pushed body must not be stored and dropped again");
    assert!(db_sync.blocks.get(k_block(&h7))?.is_none(), "the pushed body must not be stored");
    assert_eq!(bad_mark_count(&db_sync)?, 0, "nothing honest may be marked");
    assert_eq!(get_tip(&db_sync)?, Some(base[6]));

    let _good = spawn(&db_good, &tmp_good, vec![dial_addr(&sync).await?], base[0], TestPeerMode::Normal).await?;
    let synced = wait_until(CONVERGE_SECS, || Ok(get_tip(&db_sync)? == Some(tip))).await?;
    assert!(synced, "the sync node did not reach the honest tip within {CONVERGE_SECS}s");
    assert_eq!(db_sync.blocks.get(k_block(&h7))?, db_good.blocks.get(k_block(&h7))?, "the honest body is stored");
    assert_eq!(counters().1 - dropped0, 1);
    assert_eq!(counters().0 - served0, 1, "the altered body was served once by GetBlock");
    Ok(())
}

fn score(scorer: &libp2p::PeerId, peer: &libp2p::PeerId) -> i32 {
    TEST_PEER_SCORES.lock().unwrap().get(scorer).and_then(|m| m.get(peer).copied()).unwrap_or(0)
}

// Without the check, a served block earned +3 (and a good_block in the quality
// record) before its body was checked, so a genuine block answered with its last tx repeated,
// refused at store at no cost, still paid, across every block we ask for. The repeating peer
// serves only h7 and earns nothing for it; the honest peer that then serves h7 earns +3 and the
// +12 for its becoming the tip.
#[tokio::test(flavor = "multi_thread", worker_threads = 6)]
async fn live_a_refused_body_earns_its_server_nothing() -> Result<()> {
    let _serial = SERIAL.lock().unwrap_or_else(|e| e.into_inner());
    let (tmp_good, tmp_bad, tmp_sync) = (TempDir::new()?, TempDir::new()?, TempDir::new()?);
    let db_good = Arc::new(open_db(&tmp_good)?);
    let db_bad = Arc::new(open_db(&tmp_bad)?);
    let db_sync = Arc::new(open_db(&tmp_sync)?);

    let base = build_base_chain(&db_good, 7, START)?;
    assert_eq!(build_base_chain(&db_bad, 7, START)?, base);
    assert_eq!(build_base_chain(&db_sync, 7, START)?, base);
    let spends = vec![spend_of(&db_good, &base[1])?, spend_of(&db_good, &base[2])?];
    let (h7, _) = extend(&db_good, base[6], 7..8, [0x77; 20], spends.clone())?;
    assert_eq!(extend(&db_bad, base[6], 7..8, [0x77; 20], spends)?.0, h7);
    let (served0, _) = counters();

    let bad = spawn(&db_bad, &tmp_bad, vec![], base[0], TestPeerMode::RepeatLastTxOfOddBlocks).await?;
    let sync = spawn(&db_sync, &tmp_sync, vec![dial_addr(&bad).await?], base[0], TestPeerMode::Normal).await?;
    let (s, b) = (sync.peer_id, bad.peer_id);
    let highest = std::cell::Cell::new(0);
    let served = wait_until(PHASE1_SECS, || {
        highest.set(highest.get().max(score(&s, &b)));
        Ok(counters().0 > served0)
    })
    .await?;
    assert!(served, "the repeating peer was not asked within {PHASE1_SECS}s");
    // A poll tick (5 s) after copies out the score the sync node held.
    let _ = wait_until(6, || {
        highest.set(highest.get().max(score(&s, &b)));
        Ok(false)
    })
    .await?;
    assert!(db_sync.blocks.get(k_block(&h7))?.is_none(), "the repeated body must not be stored");
    assert_eq!(highest.get(), 0, "the repeating peer was credited for a body refused at store");

    let good = spawn(&db_good, &tmp_good, vec![dial_addr(&sync).await?], base[0], TestPeerMode::Normal).await?;
    let synced = wait_until(CONVERGE_SECS, || Ok(get_tip(&db_sync)? == Some(h7))).await?;
    assert!(synced, "the sync node did not apply the honest h7 within {CONVERGE_SECS}s");
    let credited = wait_until(6, || Ok(score(&s, &good.peer_id) >= 15)).await?;
    assert!(credited, "the honest server was not credited: {}", score(&s, &good.peer_id));
    assert!(score(&s, &b) <= 0, "the repeating peer: {}", score(&s, &b));
    Ok(())
}
