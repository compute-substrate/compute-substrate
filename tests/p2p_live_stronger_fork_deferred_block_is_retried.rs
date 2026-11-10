#![cfg(feature = "test-bypass")] // live p2p lane: toy chains and the fault seam need the bypass (cargo test --features test-bypass)
// A stronger head whose body arrives before an ancestor's makes maybe_reorg_to defer;
// try_apply_pending case 2 has already taken the head out of pending_apply, so the node used to stay
// short of the tip until the next block. The node must reach the tip once the missing body arrives.
// Waits end on their event; the bound only stops a run that never gets there.

use anyhow::{Context, Result};
use std::sync::Arc;
use std::time::Duration;
use tempfile::TempDir;
use tokio::sync::mpsc;

use libp2p::Multiaddr;

use csd::chain::index::{get_hidx, header_hash, index_header};
use csd::chain::mine::coinbase;
use csd::crypto::{sign_tx_compact_secp256k1, txid};
use csd::net::mempool::Mempool;
use csd::net::node::{spawn_p2p, NetConfig, TestPeerMode};
use csd::params::block_reward;
use csd::state::app_state::epoch_of;
use csd::state::db::{get_tip, k_block, set_tip, Stores};
use csd::state::utxo::validate_and_apply_block;
use csd::types::{AppPayload, Block, Hash32, OutPoint, Transaction, TxIn, TxOut};

mod testutil_chain;
use testutil_chain::{build_base_chain, make_test_header, open_db, test_signer_addr, test_signer_sk};

const CONVERGE_SECS: u64 = 60;
const START: u64 = 1_700_900_000;

fn apply_block(db: &Stores, blk: &Block, height: u64) -> Result<Hash32> {
    let bh = header_hash(&blk.header);
    db.blocks.insert(k_block(&bh), csd::codec::consensus_bincode().serialize(blk)?)?;
    index_header(db, &blk.header, get_hidx(db, &blk.header.prev)?.as_ref())?;
    validate_and_apply_block(db, blk, epoch_of(height), height).with_context(|| format!("apply h={height}"))?;
    set_tip(db, &bh)?;
    Ok(bh)
}

/// h7 carries a signed spend of h1's coinbase (when `spend`); h7 up to `end` (exclusive) on top of
/// h6. Returns them.
fn extend(db: &Stores, base: &[Hash32], spend: bool, end: u64) -> Result<Vec<Hash32>> {
    let mut txs7 = vec![coinbase([0x77; 20], block_reward(7), 7, None)];
    if spend {
        let b1: Block = csd::codec::consensus_bincode().deserialize(&db.blocks.get(k_block(&base[1]))?.unwrap())?;
        let mut tx = Transaction {
            version: 1,
            inputs: vec![TxIn { prevout: OutPoint { txid: txid(&b1.txs[0]), vout: 0 }, script_sig: vec![] }],
            outputs: vec![TxOut { value: b1.txs[0].outputs[0].value, script_pubkey: test_signer_addr() }],
            locktime: 0,
            app: AppPayload::None,
        };
        let (sig64, pub33) = sign_tx_compact_secp256k1(&tx, test_signer_sk());
        tx.inputs[0].script_sig = [&[64u8][..], &sig64, &[33u8], &pub33].concat();
        txs7.push(tx);
    }
    let mut out = Vec::new();
    let mut prev = base[6];
    for height in 7..end {
        let txs = if height == 7 {
            txs7.clone()
        } else {
            vec![coinbase([0x77; 20], block_reward(height), height, None)]
        };
        let header = make_test_header(db, prev, &txs, height)?;
        prev = apply_block(db, &Block { header, txs }, height)?;
        out.push(prev);
    }
    Ok(out)
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

fn height_of(db: &Stores) -> Result<Option<u64>> {
    Ok(get_tip(db)?.and_then(|t| get_hidx(db, &t).ok().flatten()).map(|hi| hi.height))
}

// Deterministic: the only peer answers h7 one poll tick late, so h8 and h9 arrive first and the
// reorg to h9 defers.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_head_that_arrives_before_its_ancestor_is_applied_when_the_ancestor_arrives() -> Result<()> {
    let (tmp_peer, tmp_sync) = (TempDir::new()?, TempDir::new()?);
    let db_peer = Arc::new(open_db(&tmp_peer)?);
    let db_sync = Arc::new(open_db(&tmp_sync)?);
    let base = build_base_chain(&db_peer, 7, START)?;
    assert_eq!(build_base_chain(&db_sync, 7, START)?, base);
    let tip = *extend(&db_peer, &base, true, 10)?.last().unwrap();

    let peer = spawn(&db_peer, &tmp_peer, vec![], base[0], TestPeerMode::DelayBlocksWithSpends).await?;
    let _sync = spawn(&db_sync, &tmp_sync, vec![dial_addr(&peer).await?], base[0], TestPeerMode::Normal).await?;
    let synced = wait_until(CONVERGE_SECS, || Ok(get_tip(&db_sync)? == Some(tip))).await?;
    assert!(synced, "the sync node stopped at height {:?}, short of 9", height_of(&db_sync)?);
    Ok(())
}

// Paired honest path, in the shape of p2p_live_invalid_provider_fallback: one peer lacks the h8
// body and answers "unknown block", a second has every body. It hit the stall in 5 of 20 runs, and
// with the re-queue undone it passed 40 of 40, so the test above is the pin.
#[tokio::test(flavor = "multi_thread", worker_threads = 6)]
async fn a_stronger_fork_with_a_body_missing_at_one_peer_converges() -> Result<()> {
    let (tmp_good, tmp_bad, tmp_sync) = (TempDir::new()?, TempDir::new()?, TempDir::new()?);
    let db_good = Arc::new(open_db(&tmp_good)?);
    let db_bad = Arc::new(open_db(&tmp_bad)?);
    let db_sync = Arc::new(open_db(&tmp_sync)?);
    let base = build_base_chain(&db_good, 7, START)?;
    assert_eq!(build_base_chain(&db_bad, 7, START)?, base);
    assert_eq!(build_base_chain(&db_sync, 7, START)?, base);
    let good = extend(&db_good, &base, false, 10)?;
    assert_eq!(extend(&db_bad, &base, false, 10)?, good);
    db_bad.blocks.remove(k_block(&good[1]))?;
    let tip = good[2];

    let bad = spawn(&db_bad, &tmp_bad, vec![], base[0], TestPeerMode::Normal).await?;
    let good_peer = spawn(&db_good, &tmp_good, vec![], base[0], TestPeerMode::Normal).await?;
    let boot = vec![dial_addr(&bad).await?, dial_addr(&good_peer).await?];
    let _sync = spawn(&db_sync, &tmp_sync, boot, base[0], TestPeerMode::Normal).await?;
    let synced = wait_until(CONVERGE_SECS, || Ok(get_tip(&db_sync)? == Some(tip))).await?;
    assert!(synced, "the sync node stopped at height {:?}, short of 9", height_of(&db_sync)?);
    Ok(())
}

// The best header's body is never served, so the best header tip cannot be
// applied, and the complete stored chain below it, heavier than the local tip, must be. One peer
// holds h7 to h9 and answers h7 one poll tick late, so the reorg to h9 defers; the other holds h7
// to h10 and answers every GetBlock "unknown block", so h10's header is indexed and its body never
// arrives.
#[tokio::test(flavor = "multi_thread", worker_threads = 6)]
async fn a_complete_stored_chain_below_a_bodiless_header_tip_is_applied() -> Result<()> {
    let (tmp_slow, tmp_hdr, tmp_sync) = (TempDir::new()?, TempDir::new()?, TempDir::new()?);
    let db_slow = Arc::new(open_db(&tmp_slow)?);
    let db_hdr = Arc::new(open_db(&tmp_hdr)?);
    let db_sync = Arc::new(open_db(&tmp_sync)?);
    let base = build_base_chain(&db_slow, 7, START)?;
    assert_eq!(build_base_chain(&db_hdr, 7, START)?, base);
    assert_eq!(build_base_chain(&db_sync, 7, START)?, base);
    let complete = extend(&db_slow, &base, true, 10)?;
    let longer = extend(&db_hdr, &base, true, 11)?;
    assert_eq!(longer[..3], complete[..]);
    let (h9, h10) = (complete[2], longer[3]);

    let slow = spawn(&db_slow, &tmp_slow, vec![], base[0], TestPeerMode::DelayBlocksWithSpends).await?;
    let hdr = spawn(&db_hdr, &tmp_hdr, vec![], base[0], TestPeerMode::UnknownBlockResponses).await?;
    let boot = vec![dial_addr(&slow).await?, dial_addr(&hdr).await?];
    let _sync = spawn(&db_sync, &tmp_sync, boot, base[0], TestPeerMode::Normal).await?;
    let synced = wait_until(CONVERGE_SECS, || Ok(get_tip(&db_sync)? == Some(h9))).await?;
    assert!(get_hidx(&db_sync, &h10)?.is_some(), "the sync node never indexed h10's header");
    assert!(synced, "the sync node stopped at height {:?}, short of 9", height_of(&db_sync)?);
    assert!(db_sync.blocks.get(k_block(&h10))?.is_none(), "h10's body is never served");
    Ok(())
}

// More deferred targets than the wait cap must not strand a complete chain. At h6
// with headers through h268, the bodies of h8, h9 and h11 to h267 arrive while h7 and h10 are
// withheld, so h9 and h12 to h267 (257 targets) defer on h7; a cap that evicts the lightest drops
// h9. Then h7 arrives from a peer that connects late: h7 and h8 apply, every other target defers again on
// h10, which is never served, and the complete, heavier h9 must still be applied. Storing the bodies
// takes about 125 s: the sync node asks one peer for more blocks than it has streams, and with hdr
// counted as a second block server each local refusal stamps srv for that block for 120 s, until
// hdr's "unknown block" answers quarantine it.
const OVERFLOW_TIP: u64 = 267;
const FILL_SECS: u64 = 240;

#[tokio::test(flavor = "multi_thread", worker_threads = 6)]
async fn a_complete_chain_is_applied_when_the_deferred_targets_overflow_the_wait_cap() -> Result<()> {
    let (tmp_srv, tmp_hdr, tmp_late, tmp_sync) = (TempDir::new()?, TempDir::new()?, TempDir::new()?, TempDir::new()?);
    let db_srv = Arc::new(open_db(&tmp_srv)?);
    let db_hdr = Arc::new(open_db(&tmp_hdr)?);
    let db_late = Arc::new(open_db(&tmp_late)?);
    let db_sync = Arc::new(open_db(&tmp_sync)?);
    let base = build_base_chain(&db_srv, 7, START)?;
    for db in [&db_hdr, &db_late, &db_sync] {
        assert_eq!(build_base_chain(db, 7, START)?, base);
    }
    // chain[i] is h(7 + i).
    let chain = extend(&db_srv, &base, false, OVERFLOW_TIP + 1)?;
    let longer = extend(&db_hdr, &base, false, OVERFLOW_TIP + 2)?;
    assert_eq!(longer[..chain.len()], chain[..]);
    assert_eq!(extend(&db_late, &base, false, 8)?, chain[..1]);
    let (h7, h9, h10) = (chain[0], chain[2], chain[3]);
    db_srv.blocks.remove(k_block(&h7))?;
    db_srv.blocks.remove(k_block(&h10))?;
    let served: Vec<Hash32> = chain.iter().copied().filter(|h| *h != h7 && *h != h10).collect();

    // srv serves every body but h7 and h10 ("unknown block"); hdr, one block longer, serves the
    // headers and no body.
    let srv = spawn(&db_srv, &tmp_srv, vec![], base[0], TestPeerMode::Normal).await?;
    let hdr = spawn(&db_hdr, &tmp_hdr, vec![], base[0], TestPeerMode::UnknownBlockResponses).await?;
    let boot = vec![dial_addr(&srv).await?, dial_addr(&hdr).await?];
    let sync = spawn(&db_sync, &tmp_sync, boot, base[0], TestPeerMode::Normal).await?;
    let started = std::time::Instant::now();
    let filled = wait_until(FILL_SECS, || {
        for h in &served {
            if !db_sync.blocks.contains_key(k_block(h))? {
                return Ok(false);
            }
        }
        Ok(true)
    })
    .await?;
    assert!(filled, "the sync node did not store the served bodies within {FILL_SECS}s");
    assert_eq!(height_of(&db_sync)?, Some(6), "nothing applies while h7 is missing");

    println!("overflow: served bodies stored in {:.1} s", started.elapsed().as_secs_f64());

    let started = std::time::Instant::now();
    let _late = spawn(&db_late, &tmp_late, vec![dial_addr(&sync).await?], base[0], TestPeerMode::Normal).await?;
    let synced = wait_until(CONVERGE_SECS, || Ok(get_tip(&db_sync)? == Some(h9))).await?;
    assert!(synced, "the sync node stopped at height {:?}, short of 9", height_of(&db_sync)?);
    println!("overflow: h9 applied {:.1} s after the late peer started", started.elapsed().as_secs_f64());
    assert!(db_sync.blocks.get(k_block(&h10))?.is_none(), "h10's body is never served");
    Ok(())
}

// The stall sweep is the only path here: the sync node holds the complete, heavier h7..h9 stored
// but not applied (no pending entry, no wait), and its one peer announces h10 and serves no body.
// The poll tick's sweep must find h9 once the tip has stood still for 30 s.
const SWEEP_SECS: u64 = 120;

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_stall_sweep_applies_a_complete_stored_chain_nothing_else_retries() -> Result<()> {
    let (tmp_src, tmp_hdr, tmp_sync) = (TempDir::new()?, TempDir::new()?, TempDir::new()?);
    let db_src = Arc::new(open_db(&tmp_src)?);
    let db_hdr = Arc::new(open_db(&tmp_hdr)?);
    let db_sync = Arc::new(open_db(&tmp_sync)?);
    let base = build_base_chain(&db_src, 7, START)?;
    assert_eq!(build_base_chain(&db_hdr, 7, START)?, base);
    assert_eq!(build_base_chain(&db_sync, 7, START)?, base);
    let fork = extend(&db_src, &base, false, 10)?;
    assert_eq!(extend(&db_hdr, &base, false, 11)?[..3], fork[..]);
    for h in &fork {
        let bytes = db_src.blocks.get(k_block(h))?.context("fork body")?;
        let blk: Block = csd::codec::consensus_bincode().deserialize(&bytes)?;
        db_sync.blocks.insert(k_block(h), bytes)?;
        index_header(&db_sync, &blk.header, get_hidx(&db_sync, &blk.header.prev)?.as_ref())?;
    }
    assert_eq!(height_of(&db_sync)?, Some(6));

    let hdr = spawn(&db_hdr, &tmp_hdr, vec![], base[0], TestPeerMode::UnknownBlockResponses).await?;
    let started = std::time::Instant::now();
    let _sync = spawn(&db_sync, &tmp_sync, vec![dial_addr(&hdr).await?], base[0], TestPeerMode::Normal).await?;
    let synced = wait_until(SWEEP_SECS, || Ok(get_tip(&db_sync)? == Some(fork[2]))).await?;
    assert!(synced, "the sync node stopped at height {:?}, short of 9", height_of(&db_sync)?);
    println!("stall sweep: h9 applied {:.1} s after the sync node started", started.elapsed().as_secs_f64());
    Ok(())
}
