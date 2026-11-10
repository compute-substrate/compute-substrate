#![cfg(feature = "test-bypass")] // live p2p lane: toy chains and the fault seam need the bypass (cargo test --features test-bypass)
use anyhow::{Context, Result};
use std::sync::atomic::Ordering;
use std::sync::Arc;
use std::time::Duration;
use tempfile::TempDir;
use tokio::sync::mpsc;

use libp2p::Multiaddr;

use csd::chain::index::{get_hidx, header_hash, index_header};
use csd::crypto::txid;
use csd::net::mempool::Mempool;
use csd::net::node::{spawn_p2p, NetConfig, NetHandle, TestPeerMode};
use csd::net::{GossipTxEvent, MinedHeaderEvent};
use csd::params::{INITIAL_REWARD, MIN_FEE_ATTEST, MIN_FEE_PROPOSE};
use csd::state::app_state::epoch_of;
use csd::state::db::{k_block, k_utxo, set_tip, Stores};
use csd::state::utxo::validate_and_apply_block;
use csd::types::{AppPayload, Block, BlockHeader, Hash32, OutPoint, Transaction, TxIn, TxOut};

mod testutil_chain;
use testutil_chain::{build_base_chain_with_miner, make_coinbase_to, make_test_header, open_db};

const SK: [u8; 32] = [21u8; 32];

// From the traffic past the duplicate window: a poll tick (5 s) and margin.
const RELAY_AFTER_CATCH_UP_SECS: u64 = 30;

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

fn dummy_prev(n: u8) -> OutPoint {
    OutPoint {
        txid: [n; 32],
        vout: 0,
    }
}

fn insert_utxo(db: &Stores, op: OutPoint, value: u64, owner: [u8; 20]) -> Result<()> {
    let out = TxOut {
        value,
        script_pubkey: owner,
    };

    db.utxo.insert(
        k_utxo(&op),
        csd::codec::consensus_bincode().serialize(&out)?,
    )?;

    Ok(())
}

fn make_tx(prev_tag: u8, value: u64, fee: u64, to: [u8; 20]) -> Transaction {
    make_tx_from(dummy_prev(prev_tag), value, fee, to)
}

fn make_tx_from(prevout: OutPoint, value: u64, fee: u64, to: [u8; 20]) -> Transaction {
    make_app_tx(prevout, value, fee, to, AppPayload::None)
}

fn make_app_tx(prevout: OutPoint, value: u64, fee: u64, to: [u8; 20], app: AppPayload) -> Transaction {
    let send = value - fee;

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
        app,
    };

    let (sig64, pub33) = csd::crypto::sign_tx_compact_secp256k1(&tx, SK);
    tx.inputs[0].script_sig = script_sig(&sig64, &pub33);

    tx
}

fn propose(prevout: OutPoint, value: u64, n: u8, expires_epoch: u64) -> Transaction {
    let app = AppPayload::Propose {
        domain: "research".to_string(),
        payload_hash: [n; 32],
        uri: format!("https://example.com/p/{n}"),
        expires_epoch,
    };
    make_app_tx(prevout, value, MIN_FEE_PROPOSE, h20(0x41), app)
}

fn attest(prevout: OutPoint, value: u64, proposal: &Transaction) -> Transaction {
    let app = AppPayload::Attest { proposal_id: txid(proposal), score: 100, confidence: 100 };
    make_app_tx(prevout, value, MIN_FEE_ATTEST, h20(0x42), app)
}

/// A block on `prev` at `height` paying `miner` the reward plus the fees of `txs`.
fn block_with(db: &Stores, prev: Hash32, height: u64, miner: [u8; 20], fees: u64, txs: Vec<Transaction>) -> Result<Block> {
    let cb = csd::chain::mine::coinbase(miner, csd::params::block_reward(height) + fees, height, None);
    let txs: Vec<Transaction> = std::iter::once(cb).chain(txs).collect();
    let header = make_test_header(db, prev, &txs, height)?;
    Ok(Block { header, txs })
}

/// Stores, indexes and applies `blk` as the tip (what a node's own miner does on a block it found).
fn apply_block(db: &Stores, blk: &Block, height: u64) -> Result<Hash32> {
    let bh = header_hash(&blk.header);
    db.blocks.insert(k_block(&bh), csd::codec::consensus_bincode().serialize(blk)?)?;
    let parent = get_hidx(db, &blk.header.prev)?.context("parent index")?;
    index_header(db, &blk.header, Some(&parent))?;
    validate_and_apply_block(db, blk, epoch_of(height), height)?;
    set_tip(db, &bh)?;
    Ok(bh)
}

fn script_sig(sig64: &[u8; 64], pub33: &[u8; 33]) -> Vec<u8> {
    let mut ss = Vec::with_capacity(99);
    ss.push(64);
    ss.extend_from_slice(sig64);
    ss.push(33);
    ss.extend_from_slice(pub33);
    ss
}

/// The same tx signed again with other nonce data: a second valid low-S signature, so other
/// script_sig bytes under the same txid (a txid leaves the script_sigs out).
fn resigned(tx: &Transaction) -> Transaction {
    use secp256k1::{Message, PublicKey, Secp256k1, SecretKey};

    let secp = Secp256k1::new();
    let sk = SecretKey::from_slice(&SK).unwrap();
    let msg = Message::from_digest_slice(&csd::crypto::sighash(tx)).unwrap();
    let mut sig = secp.sign_ecdsa_with_noncedata(&msg, &sk, &[7u8; 32]);
    sig.normalize_s();

    let mut out = tx.clone();
    out.inputs[0].script_sig = script_sig(
        &sig.serialize_compact(),
        &PublicKey::from_secret_key(&secp, &sk).serialize(),
    );
    out
}

struct LiveNode {
    db: Arc<Stores>,
    mp: Arc<Mempool>,
    lock: csd::chain::lock::ChainLock,
    handle: NetHandle,
    mined: mpsc::UnboundedSender<MinedHeaderEvent>,
    gossip: mpsc::UnboundedSender<GossipTxEvent>,
    _dir: TempDir,
}

async fn spawn_node(
    dir: TempDir,
    db: Stores,
    genesis_hash: Hash32,
    bootnodes: Vec<Multiaddr>,
    test_mode: TestPeerMode,
) -> Result<LiveNode> {
    let db = Arc::new(db);
    let mp = Arc::new(Mempool::new());
    let (mined, mined_rx) = mpsc::unbounded_channel();
    let (gossip, gossip_rx) = mpsc::unbounded_channel();
    let cfg = NetConfig {
        datadir: dir.path().to_string_lossy().to_string(),
        listen: "/ip4/127.0.0.1/tcp/0".parse()?,
        is_bootnode: bootnodes.is_empty(),
        bootnodes,
        genesis_hash,
        test_mode,
    };
    let lock = csd::chain::lock::new_chain_lock();
    let handle = spawn_p2p(db.clone(), mp.clone(), cfg, mined_rx, gossip_rx, lock.clone()).await?;
    Ok(LiveNode { db, mp, lock, handle, mined, gossip, _dir: dir })
}

async fn dial_addr(node: &LiveNode) -> Result<Multiaddr> {
    for _ in 0..60 {
        if let Some(addr) = node.handle.listen_addr().await {
            return Ok(format!("{}/p2p/{}", addr, node.handle.peer_id).parse()?);
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    anyhow::bail!("node did not expose its listen address in time")
}

async fn wait_for(secs: u64, mut done: impl FnMut() -> Result<bool>) -> Result<bool> {
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

fn announce(node: &LiveNode, header: BlockHeader) -> Result<Hash32> {
    let hash = header_hash(&header);
    node.mined.send(MinedHeaderEvent { hash, header })?;
    Ok(hash)
}

fn gossip(node: &LiveNode, tx: &Transaction) -> Result<()> {
    // The first-accept trigger (insure: true), as the production tx_submit path sends it.
    node.gossip.send(GossipTxEvent { tx: tx.clone(), insure: true })?;
    Ok(())
}

/// Gossip validation on a line A - B - C: C hears only what B forwards, and B
/// forwards a message only when its verdict is Accept. Loopback addresses are never exchanged
/// (`addr_is_public_or_dns`), so A and C stay unconnected; the end asserts it.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn live_p2p_gossip_crosses_a_relay_only_when_the_relay_admits_it() -> Result<()> {
    // The base chain pays the signer, so its coinbases fund the app txs below (a block can spend
    // only outputs a block created; the coins `insert_utxo` plants have no undo record).
    let owner = signer_addr(SK);
    let miner = owner;
    let base_len = 5u64;
    let start_time = 1_700_400_000u64;

    let (dir_a, dir_b, dir_c) = (TempDir::new()?, TempDir::new()?, TempDir::new()?);
    let (db_a, db_b, db_c) = (open_db(&dir_a)?, open_db(&dir_b)?, open_db(&dir_c)?);
    let base = build_base_chain_with_miner(&db_a, base_len, start_time, miner)?;
    assert_eq!(build_base_chain_with_miner(&db_b, base_len, start_time, miner)?, base);
    assert_eq!(build_base_chain_with_miner(&db_c, base_len, start_time, miner)?, base);
    let tip = base[(base_len - 1) as usize];

    let v = 1_000_000u64;
    // Coins 1, 3, 6, 7 and 8 exist on all three nodes.
    for db in [&db_a, &db_b, &db_c] {
        for tag in [1u8, 3, 6, 7, 8] {
            insert_utxo(db, dummy_prev(tag), v, owner)?;
        }
    }
    let av = INITIAL_REWARD;
    let base_coin = |h: u64| OutPoint { txid: txid(&make_coinbase_to(h, owner)), vout: 0 };
    // Blocks X and Y. X pays its coinbase to the signer and carries proposal P1 and a transfer T
    // to the signer; Y, on X, carries proposal P2. A and C have applied both and B neither; A and
    // C refuse to serve block bodies, so B stays behind until the test applies X, then Y, to B.
    let expires = epoch_of(base_len) + 10;
    let p1 = propose(base_coin(1), av, 1, expires);
    let t = make_tx_from(base_coin(2), av, 5_000, owner);
    let p2 = propose(base_coin(3), av, 2, expires);
    let x_blk = block_with(&db_a, tip, base_len, owner, MIN_FEE_PROPOSE + 5_000, vec![p1.clone(), t.clone()])?;
    let x = apply_block(&db_a, &x_blk, base_len)?;
    assert_eq!(apply_block(&db_c, &x_blk, base_len)?, x);
    let y_blk = block_with(&db_a, x, base_len + 1, owner, MIN_FEE_PROPOSE, vec![p2.clone()])?;
    let y = apply_block(&db_a, &y_blk, base_len + 1)?;
    assert_eq!(apply_block(&db_c, &y_blk, base_len + 1)?, y);
    let x_coin = OutPoint { txid: txid(&x_blk.txs[0]), vout: 0 };
    let t_coin = OutPoint { txid: txid(&t), vout: 0 };

    // Headers: `honest` extends the shared tip; `orphan` extends a header only C has indexed.
    let cb = |tag: u8| vec![csd::chain::mine::coinbase(h20(tag), csd::params::block_reward(base_len), base_len, None)];
    let honest = make_test_header(&db_a, tip, &cb(0xB1), base_len)?;
    let parent_only_c = make_test_header(&db_c, tip, &cb(0xB2), base_len)?;
    let parent_hi = get_hidx(&db_c, &tip)?.context("tip index")?;
    index_header(&db_c, &parent_only_c, Some(&parent_hi))?;
    let orphan = make_test_header(&db_c, header_hash(&parent_only_c), &cb(0xB3), base_len + 1)?;

    let node_b = spawn_node(dir_b, db_b, base[0], vec![], TestPeerMode::Normal).await?;
    let addr_b = dial_addr(&node_b).await?;
    let node_a = spawn_node(dir_a, db_a, base[0], vec![addr_b.clone()], TestPeerMode::UnknownBlockResponses).await?;
    let node_c = spawn_node(dir_c, db_c, base[0], vec![addr_b], TestPeerMode::UnknownBlockResponses).await?;

    // B holds two txs before anything is gossiped.
    let held_exact = make_tx(7, v, 5_000, h20(7));
    let held_other_sig = make_tx(6, v, 5_000, h20(6));
    assert!(node_b.mp.insert_checked(&node_b.db, held_exact.clone())?);
    assert!(node_b.mp.insert_checked(&node_b.db, held_other_sig.clone())?);

    let peers = |n: &LiveNode| n.handle.connected_peers.load(Ordering::Relaxed);
    let line = wait_for(15, || Ok(peers(&node_b) == 2 && peers(&node_a) == 1 && peers(&node_c) == 1)).await?;
    assert!(line, "B must connect to A and to C");
    // Subscriptions and mesh grafting (1 s heartbeats) settle before the first publish.
    tokio::time::sleep(Duration::from_secs(3)).await;

    // Honest path: a tx every node admits crosses B.
    let first = make_tx(1, v, 5_000, h20(1));
    gossip(&node_a, &first)?;
    let crossed = wait_for(15, || Ok(node_c.mp.contains(&txid(&first)))).await?;
    assert!(crossed, "a tx A, B and C all admit must reach C through B");
    assert!(node_b.mp.contains(&txid(&first)));

    // Parked at B until it catches up: a tx spending X's coinbase, a copy of it with a corrupted
    // signature gossiped first (same txid, a txid leaves the script_sigs out), an Attest whose
    // funding B has and whose proposal is in X, and an Attest funded by T (in X) for P2 (in Y).
    let unadmissible = make_tx_from(x_coin, x_blk.txs[0].outputs[0].value, 5_000, h20(2));
    let mut corrupted = unadmissible.clone();
    corrupted.inputs[0].script_sig[10] ^= 0x01;
    assert_eq!(txid(&corrupted), txid(&unadmissible));
    let funded_attest = attest(base_coin(4), av, &p1);
    let attest_after_funding = attest(t_coin, av - 5_000, &p2);
    let other_sig = resigned(&held_other_sig);
    assert_eq!(txid(&other_sig), txid(&held_other_sig));
    assert_ne!(other_sig.inputs[0].script_sig, held_other_sig.inputs[0].script_sig);
    let last = make_tx(3, v, 5_000, h20(3));
    let gossiped_at = tokio::time::Instant::now();
    for tx in [&corrupted, &unadmissible, &funded_attest, &attest_after_funding, &other_sig, &held_exact, &last] {
        gossip(&node_a, tx)?;
    }
    let both = wait_for(15, || {
        Ok(node_c.mp.contains(&txid(&last)) && node_c.mp.contains(&txid(&held_exact)))
    })
    .await?;
    assert!(
        both,
        "a tx B holds byte for byte crosses B (a resubmit's re-gossip must pass nodes that hold \
         it), and so does a later tx every node admits"
    );
    tokio::time::sleep(Duration::from_secs(1)).await;
    for (tx, what) in [(&unadmissible, "its coin is in X"), (&funded_attest, "its proposal is in X"), (&attest_after_funding, "its funding is in X and its proposal in Y")] {
        assert!(!node_c.mp.contains(&txid(tx)), "B cannot admit this tx yet ({what}, which B lacks), so B must not forward it");
    }
    assert!(
        !node_c.mp.contains(&txid(&other_sig)),
        "B holds this txid with other signature bytes; forwarding such copies would let anyone \
         mint new gossip ids for one held tx"
    );

    // B catches up: X is applied to B's store under B's chain lock, as B's own miner applies a
    // block (the sync path ends in the same tip change). B re-checks the tx it parked, admits it
    // and gossips it. B received a copy moments ago, still in gossipsub's 60 s duplicate cache, so
    // the publish waits in PublishRetry, which keeps it while B's mempool holds those bytes. gossipsub
    // drops an expired id only when it records another one (`TimeCache::entry`,
    // time_cache.rs:138-140; `contains` ignores expiry). The tx gossiped past the window stands for
    // the next block's header, which records one on a live chain.
    {
        let _held = node_b.lock.lock();
        assert_eq!(apply_block(&node_b.db, &x_blk, base_len)?, x);
    }
    // B re-checks with X applied: the honest copy and the funded Attest are admitted; the Attest
    // funded by T now has its funding and still lacks P2, so it stays parked.
    let at_x = wait_for(15, || Ok(node_b.mp.contains(&txid(&unadmissible)) && node_b.mp.contains(&txid(&funded_attest)))).await?;
    assert!(at_x, "with X applied, B must admit the honest copy (the corrupted one came first) and the Attest for P1");
    assert!(!node_b.mp.contains(&txid(&attest_after_funding)), "P2 is in Y, which B lacks");
    {
        let _held = node_b.lock.lock();
        assert_eq!(apply_block(&node_b.db, &y_blk, base_len + 1)?, y);
    }
    tokio::time::sleep_until(gossiped_at + Duration::from_secs(61)).await;
    gossip(&node_a, &make_tx(8, v, 5_000, h20(8)))?;
    let relayed = wait_for(RELAY_AFTER_CATCH_UP_SECS, || {
        Ok([&unadmissible, &funded_attest, &attest_after_funding].iter().all(|tx| node_c.mp.contains(&txid(tx))))
    })
    .await?;
    assert!(
        relayed,
        "once B has what they depend on, the txs B could not admit must reach C through B within \
         {RELAY_AFTER_CATCH_UP_SECS}s (C has: honest copy {}, funded Attest {}, Attest after funding {})",
        node_c.mp.contains(&txid(&unadmissible)),
        node_c.mp.contains(&txid(&funded_attest)),
        node_c.mp.contains(&txid(&attest_after_funding)),
    );
    assert_eq!(
        node_c.mp.get(&txid(&unadmissible)).map(|tx| tx.inputs[0].script_sig.clone()),
        Some(unadmissible.inputs[0].script_sig.clone()),
        "C holds the honest copy"
    );

    let orphan_hash = announce(&node_a, orphan)?;
    let honest_hash = announce(&node_a, honest)?;
    let indexed = wait_for(15, || Ok(get_hidx(&node_c.db, &honest_hash)?.is_some())).await?;
    assert!(
        indexed,
        "a header B indexes from gossip crosses B; no node holds its block, so gossip is C's \
         only way to learn it"
    );
    tokio::time::sleep(Duration::from_secs(1)).await;
    assert!(
        get_hidx(&node_c.db, &orphan_hash)?.is_none(),
        "B does not know this header's parent, so B must not forward it (C knows the parent and \
         would index it)"
    );

    assert_eq!(peers(&node_a), 1, "A must reach C only through B");
    assert_eq!(peers(&node_c), 1, "C must reach A only through B");
    Ok(())
}
