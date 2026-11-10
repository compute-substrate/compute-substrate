#![cfg(feature = "test-bypass")] // live p2p lane: toy chains and the fault seam need the bypass (cargo test --features test-bypass)
// A gossip arm that checks each gossip tx (`Mempool::insert_checked`) inline on the one p2p loop
// lets a peer gossiping copies of a wide tx whose last signature is bad hold the loop for every
// refusal, and every other event (GetTip answers, block and header answers, honest gossip) waits
// behind it. The checks run on the blocking pool and the loop reports each verdict when its check
// returns. A is a real node; X1 and X2 are bare
// gossipsub swarms that each gossip their full refusal budget (8 copies of a 512-input refusal, each
// copy a new message id); P asks A for its tip every 100 ms on its own connection; H, an honest
// relay, gossips a valid tx after the flood, which A must admit (the paired honest path).

use anyhow::{Context, Result};
use futures::StreamExt;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tempfile::TempDir;
use tokio::sync::mpsc;

use libp2p::{
    core::upgrade,
    gossipsub::{self, IdentTopic, MessageAuthenticity},
    identity, noise,
    request_response::{self, ProtocolSupport},
    swarm::SwarmEvent,
    tcp, yamux, Multiaddr, PeerId, Swarm, Transport,
};

use csd::chain::lock::new_chain_lock;
use csd::crypto::{hash160, sign_tx_compact_secp256k1, txid};
use csd::net::mempool::Mempool;
use csd::net::node::{spawn_p2p, NetConfig, SyncCodec, TestPeerMode};
use csd::net::proto::{GossipTx, SyncRequest, SyncResponse, SYNC_PROTO, TOPIC_TX};
use csd::params::MAX_TX_INPUTS;
use csd::state::db::{k_utxo, Stores};
use csd::types::{AppPayload, OutPoint, Transaction, TxIn, TxOut};

const ATTACKER_SK: [u8; 32] = [0x5a; 32];
const HONEST_SK: [u8; 32] = [0x3c; 32];
// Each attacker's refusal budget: RL_MAX_GOSSIP_TX_INPUTS_PER_WINDOW / MAX_TX_INPUTS.
const COPIES_PER_ATTACKER: u32 = 8;

fn transport(key: &identity::Keypair) -> libp2p::core::transport::Boxed<(PeerId, libp2p::core::muxing::StreamMuxerBox)> {
    tcp::tokio::Transport::new(tcp::Config::default().nodelay(true))
        .upgrade(upgrade::Version::V1)
        .authenticate(noise::Config::new(key).unwrap())
        .multiplex(yamux::Config::default())
        .boxed()
}

fn swarm_config() -> libp2p::swarm::Config {
    libp2p::swarm::Config::with_tokio_executor().with_idle_connection_timeout(Duration::from_secs(120))
}

fn script_sig(sig64: &[u8; 64], pub33: &[u8; 33]) -> Vec<u8> {
    let mut ss = vec![64u8];
    ss.extend_from_slice(sig64);
    ss.push(33);
    ss.extend_from_slice(pub33);
    ss
}

fn owner(sk: [u8; 32]) -> [u8; 20] {
    let probe = Transaction { version: 1, inputs: vec![], outputs: vec![], locktime: 0, app: AppPayload::None };
    hash160(&sign_tx_compact_secp256k1(&probe, sk).1)
}

fn attacker_coins() -> Vec<OutPoint> {
    (0..MAX_TX_INPUTS as u32).map(|i| OutPoint { txid: [0xC0; 32], vout: i }).collect()
}

const HONEST_COIN: OutPoint = OutPoint { txid: [0xD0; 32], vout: 0 };

/// The 512-input spend of the attacker's coins with every signature valid but the last, whose r
/// bytes carry `variant` (a new message id per copy; it still parses and stays low-S).
fn refusal(variant: u32) -> Transaction {
    let coins = attacker_coins();
    let mut tx = Transaction {
        version: 1,
        inputs: coins.iter().map(|op| TxIn { prevout: *op, script_sig: vec![] }).collect(),
        outputs: vec![TxOut { value: 10_000 * coins.len() as u64 - 1_000, script_pubkey: [0x99; 20] }],
        locktime: 0,
        app: AppPayload::None,
    };
    let (sig64, pub33) = sign_tx_compact_secp256k1(&tx, ATTACKER_SK);
    let ss = script_sig(&sig64, &pub33);
    for i in tx.inputs.iter_mut() {
        i.script_sig = ss.clone();
    }
    let last = tx.inputs.len() - 1;
    for (j, b) in variant.to_le_bytes().iter().enumerate() {
        tx.inputs[last].script_sig[10 + j] ^= b.wrapping_add(1);
    }
    tx
}

fn honest_spend() -> Transaction {
    honest_spend_of(HONEST_COIN)
}

/// A valid spend of `coin`, owned by HONEST_SK's key.
fn honest_spend_of(coin: OutPoint) -> Transaction {
    let mut tx = Transaction {
        version: 1,
        inputs: vec![TxIn { prevout: coin, script_sig: vec![] }],
        outputs: vec![TxOut { value: 9_000, script_pubkey: [0x42; 20] }],
        locktime: 0,
        app: AppPayload::None,
    };
    let (sig64, pub33) = sign_tx_compact_secp256k1(&tx, HONEST_SK);
    tx.inputs[0].script_sig = script_sig(&sig64, &pub33);
    tx
}

/// A received message: its author (`source`, which a forward keeps) and its bytes.
type Received = (Option<PeerId>, Vec<u8>);

/// A bare gossipsub swarm with identity `key`: publishes what it is sent once A is subscribed, and
/// passes every message it receives to `inbox`. Once its sender is dropped it leaves (its
/// connection to A closes).
async fn gossiper(
    key: identity::Keypair,
    a: Multiaddr,
    mut rx: mpsc::UnboundedReceiver<Vec<u8>>,
    ready: mpsc::UnboundedSender<()>,
    inbox: mpsc::UnboundedSender<Received>,
) {
    let cfg = gossipsub::ConfigBuilder::default().max_transmit_size(256 * 1024).build().unwrap();
    let gs: gossipsub::Behaviour = gossipsub::Behaviour::new(MessageAuthenticity::Signed(key.clone()), cfg).unwrap();
    let mut swarm = Swarm::new(transport(&key), gs, key.public().to_peer_id(), swarm_config());
    let topic = IdentTopic::new(TOPIC_TX);
    swarm.behaviour_mut().subscribe(&topic).unwrap();
    swarm.dial(a).unwrap();
    let mut subscribed = false;
    loop {
        tokio::select! {
            ev = swarm.select_next_some() => match ev {
                SwarmEvent::Behaviour(gossipsub::Event::Subscribed { .. }) if !subscribed => {
                    subscribed = true;
                    let _ = ready.send(());
                }
                SwarmEvent::Behaviour(gossipsub::Event::Message { message, .. }) => {
                    let _ = inbox.send((message.source, message.data));
                }
                _ => {}
            },
            p = rx.recv(), if subscribed => match p {
                Some(p) => {
                    let _ = swarm.behaviour_mut().publish(topic.clone(), p);
                }
                None => return,
            },
        }
    }
}

/// P: a GetTip to A every 100 ms on its own connection, until `secs`; (sent at, rtt or None).
async fn probe(a: Multiaddr, a_peer: PeerId, start: Instant, secs: u64) -> Vec<(f64, Option<f64>)> {
    let key = identity::Keypair::generate_ed25519();
    let rr = request_response::Behaviour::<SyncCodec>::new(
        std::iter::once((SYNC_PROTO, ProtocolSupport::Full)),
        request_response::Config::default().with_request_timeout(Duration::from_secs(15)),
    );
    let mut swarm = Swarm::new(transport(&key), rr, key.public().to_peer_id(), swarm_config());
    swarm.dial(a).unwrap();
    let mut out = Vec::new();
    let mut tick = tokio::time::interval(Duration::from_millis(100));
    let mut pending: Option<(request_response::OutboundRequestId, Instant)> = None;
    let mut connected = false;
    while start.elapsed() < Duration::from_secs(secs) {
        tokio::select! {
            _ = tick.tick() => {
                if connected && pending.is_none() {
                    let id = swarm.behaviour_mut().send_request(&a_peer, SyncRequest::GetTip);
                    pending = Some((id, Instant::now()));
                }
            }
            ev = swarm.select_next_some() => match ev {
                SwarmEvent::ConnectionEstablished { .. } => connected = true,
                SwarmEvent::Behaviour(request_response::Event::Message {
                    message: request_response::Message::Response { request_id, response }, ..
                }) => {
                    if let Some((id, t0)) = pending {
                        if id == request_id {
                            let ok = matches!(response, SyncResponse::Tip { .. });
                            out.push((t0.duration_since(start).as_secs_f64(), ok.then(|| t0.elapsed().as_secs_f64() * 1000.0)));
                            pending = None;
                        }
                    }
                }
                SwarmEvent::Behaviour(request_response::Event::OutboundFailure { request_id, .. }) => {
                    if let Some((id, t0)) = pending {
                        if id == request_id {
                            out.push((t0.duration_since(start).as_secs_f64(), None));
                            pending = None;
                        }
                    }
                }
                _ => {}
            }
        }
    }
    out
}

/// Node A on a fresh store holding `coins` (each 10,000 units, owned as given); returns its handle,
/// mempool and listen address.
async fn node_a(coins: &[(OutPoint, [u8; 20])]) -> Result<(NodeA, Arc<Mempool>, Multiaddr)> {
    let dir = TempDir::new()?;
    let db = Stores::open(dir.path().to_str().unwrap())?;
    let c = csd::codec::consensus_bincode();
    for (op, who) in coins {
        db.utxo.insert(k_utxo(op), c.serialize(&TxOut { value: 10_000, script_pubkey: *who })?)?;
    }
    let db = Arc::new(db);
    let mempool = Arc::new(Mempool::new());
    let (mined, mined_rx) = mpsc::unbounded_channel();
    let (gossip, gossip_rx) = mpsc::unbounded_channel();
    let cfg = NetConfig {
        datadir: dir.path().to_string_lossy().to_string(),
        listen: "/ip4/127.0.0.1/tcp/0".parse()?,
        bootnodes: vec![],
        genesis_hash: [0x77; 32],
        is_bootnode: true,
        test_mode: TestPeerMode::Normal,
    };
    let handle = spawn_p2p(db.clone(), mempool.clone(), cfg, mined_rx, gossip_rx, new_chain_lock()).await?;
    for _ in 0..100 {
        if let Some(addr) = handle.listen_addr().await {
            return Ok((NodeA { handle, db, gossip, _dir: dir, _mined: mined }, mempool, addr));
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    anyhow::bail!("A has no listen address")
}

/// Keeps A's store and channels alive with its handle. `db` and `gossip` are what `/tx/submit`
/// admits a tx with and sends its gossip event on.
struct NodeA {
    handle: csd::net::node::NetHandle,
    db: Arc<Stores>,
    gossip: mpsc::UnboundedSender<csd::net::GossipTxEvent>,
    _dir: TempDir,
    _mined: mpsc::UnboundedSender<csd::net::MinedHeaderEvent>,
}

/// A gossiper connected to A and subscribed; returns the channel its payloads go through.
async fn connected_gossiper(addr: &Multiaddr) -> Result<mpsc::UnboundedSender<Vec<u8>>> {
    Ok(connected_gossiper_with_id(addr).await?.0)
}

/// As `connected_gossiper`, with the gossiper's PeerId (the forwarder A sees).
async fn connected_gossiper_with_id(addr: &Multiaddr) -> Result<(mpsc::UnboundedSender<Vec<u8>>, PeerId)> {
    let (tx, id, _inbox) = connected_gossiper_with_inbox(addr).await?;
    Ok((tx, id))
}

/// As `connected_gossiper_with_id`, with the messages the gossiper receives.
async fn connected_gossiper_with_inbox(
    addr: &Multiaddr,
) -> Result<(mpsc::UnboundedSender<Vec<u8>>, PeerId, mpsc::UnboundedReceiver<Received>)> {
    let key = identity::Keypair::generate_ed25519();
    let id = key.public().to_peer_id();
    let (tx, rx) = mpsc::unbounded_channel();
    let (ready_tx, mut ready_rx) = mpsc::unbounded_channel();
    let (inbox_tx, inbox_rx) = mpsc::unbounded_channel();
    tokio::spawn(gossiper(key, addr.clone(), rx, ready_tx, inbox_tx));
    tokio::time::timeout(Duration::from_secs(30), ready_rx.recv()).await?.context("a gossiper never saw A subscribe")?;
    Ok((tx, id, inbox_rx))
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn gossip_txs_that_are_expensive_to_refuse_do_not_hold_the_p2p_loop() -> Result<()> {
    let mut coins: Vec<(OutPoint, [u8; 20])> = attacker_coins().into_iter().map(|op| (op, owner(ATTACKER_SK))).collect();
    coins.push((HONEST_COIN, owner(HONEST_SK)));
    let (_a, mempool, addr) = node_a(&coins).await?;
    let c = csd::codec::consensus_bincode();

    let mut senders = Vec::new();
    for _ in 0..3 {
        senders.push(connected_gossiper(&addr).await?);
    }
    let honest_relay = senders.pop().unwrap();
    let payloads: Vec<Vec<Vec<u8>>> = (0..senders.len() as u32)
        .map(|k| {
            (0..COPIES_PER_ATTACKER)
                .map(|v| c.serialize(&GossipTx { tx: refusal(v + k * 1_000) }).unwrap())
                .collect()
        })
        .collect();

    let start = Instant::now();
    let probe_task = tokio::spawn(probe(addr.clone(), _a.handle.peer_id, start, 8));
    tokio::time::sleep_until((start + Duration::from_secs(2)).into()).await;
    for (k, x) in senders.iter().enumerate() {
        for p in &payloads[k] {
            x.send(p.clone())?;
        }
    }
    tokio::time::sleep_until((start + Duration::from_secs(6)).into()).await;
    let honest = honest_spend();
    honest_relay.send(c.serialize(&GossipTx { tx: honest.clone() })?)?;
    let samples = probe_task.await?;

    let admitted = async {
        while !mempool.contains(&txid(&honest)) {
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
    };
    tokio::time::timeout(Duration::from_secs(30), admitted)
        .await
        .context("the honest gossip tx was never admitted after the flood")?;

    let during: Vec<_> = samples.iter().filter(|(t, _)| *t >= 2.0 && *t < 6.0).collect();
    let rtts: Vec<f64> = during.iter().filter_map(|(_, r)| *r).collect();
    let max = rtts.iter().cloned().fold(0.0, f64::max);
    let failed = during.len() - rtts.len();
    println!(
        "[off-loop] {} copies of a {}-input refusal from {} gossipers; GetTip during the flood: {} answered, max {max:.1} ms, {failed} failed",
        COPIES_PER_ATTACKER as usize * senders.len(),
        MAX_TX_INPUTS,
        senders.len(),
        rtts.len()
    );
    // One GetTip in flight every 100 ms over 4 s: about 40 when the loop is free.
    assert!(rtts.len() >= 30, "the probe got {} answers during the flood: the loop waited on the checks", rtts.len());
    assert_eq!(failed, 0, "GetTip requests failed during the flood");
    assert!(max < 500.0, "A answered a GetTip after {max:.1} ms while it refused gossip txs: the loop waited on the checks");
    assert_eq!(mempool.len(), 1, "only the honest tx is admitted");
    Ok(())
}

// The input budget charges refusals only: an honest relay that forwards
// nine valid 512-input txs in one window, 4,608 inputs, past the 4,096 budget, has every one of them
// checked and admitted, and a tenth sent after they were admitted, inside the same window, is
// checked and admitted too (admitted txs are not charged).
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn nine_valid_wide_txs_from_one_relay_in_a_window_are_all_admitted() -> Result<()> {
    const TXS: u8 = 9;
    let coins_of = |n: u8| -> Vec<OutPoint> {
        (0..MAX_TX_INPUTS as u32).map(|i| OutPoint { txid: [0xE0 + n; 32], vout: i }).collect()
    };
    let honest = owner(HONEST_SK);
    let coins: Vec<(OutPoint, [u8; 20])> = (0..=TXS).flat_map(|n| coins_of(n).into_iter().map(move |op| (op, honest))).collect();
    let (_a, mempool, addr) = node_a(&coins).await?;
    let relay = connected_gossiper(&addr).await?;

    let c = csd::codec::consensus_bincode();
    let wide = |n: u8| -> Result<([u8; 32], Vec<u8>)> {
        let ops = coins_of(n);
        let mut tx = Transaction {
            version: 1,
            inputs: ops.iter().map(|op| TxIn { prevout: *op, script_sig: vec![] }).collect(),
            outputs: vec![TxOut { value: 10_000 * ops.len() as u64 - 1_000, script_pubkey: [0x43; 20] }],
            locktime: 0,
            app: AppPayload::None,
        };
        let (sig64, pub33) = sign_tx_compact_secp256k1(&tx, HONEST_SK);
        let ss = script_sig(&sig64, &pub33);
        for i in tx.inputs.iter_mut() {
            i.script_sig = ss.clone();
        }
        Ok((txid(&tx), c.serialize(&GossipTx { tx })?))
    };
    let mut ids = Vec::new();
    for n in 0..TXS {
        let (id, bytes) = wide(n)?;
        ids.push(id);
        relay.send(bytes)?;
    }
    let all_in = async {
        while !ids.iter().all(|id| mempool.contains(id)) {
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
    };
    // All nine are sent at once, inside one 10 s window; the deadline only bounds a loaded host.
    let admitted = tokio::time::timeout(Duration::from_secs(60), all_in).await;
    let held = ids.iter().filter(|id| mempool.contains(id)).count();
    assert!(admitted.is_ok(), "{held} of {TXS} valid wide txs sent by one relay in one window were admitted");

    // The tenth, after the nine were admitted and charged nothing.
    let (id10, bytes10) = wide(TXS)?;
    relay.send(bytes10)?;
    let tenth_in = async {
        while !mempool.contains(&id10) {
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
    };
    assert!(
        tokio::time::timeout(Duration::from_secs(10), tenth_in).await.is_ok(),
        "a tenth valid wide tx from the relay, sent after nine were admitted in the window, was not admitted: admitted txs were charged"
    );
    Ok(())
}

// The refusal budget's real bound: it is read when a tx arrives and
// charged when the check returns, so one forwarder gets the eight full-width refusals the budget
// holds checked, plus whatever of its txs are queued or running when the eighth charge lands: at
// most 8 + 16 (GOSSIP_TX_CHECK_QUEUE_INPUTS / MAX_TX_INPUTS) + 2 (GOSSIP_TX_CHECKS_IN_FLIGHT) = 26.
// One forwarder sends 64 refusals 40 ms apart (a probe of this shape measured 18 checks); without
// the charge every one that finds room in the queue is checked.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn one_forwarders_refusals_checked_in_a_window_stay_within_the_budget_plus_the_queue() -> Result<()> {
    const BOUND: u64 = 8 + 16 + 2;
    let coins: Vec<(OutPoint, [u8; 20])> = attacker_coins().into_iter().map(|op| (op, owner(ATTACKER_SK))).collect();
    let (_a, _mempool, addr) = node_a(&coins).await?;
    let (forwarder, fwd) = connected_gossiper_with_id(&addr).await?;
    let c = csd::codec::consensus_bincode();
    let checks = || csd::net::node::TEST_GOSSIP_TX_CHECKS.lock().unwrap().get(&fwd).copied().unwrap_or(0);

    for v in 0..64u32 {
        forwarder.send(c.serialize(&GossipTx { tx: refusal(20_000 + v) })?)?;
        tokio::time::sleep(Duration::from_millis(40)).await;
    }
    // Every check started for this forwarder has been counted once its queue drains.
    tokio::time::sleep(Duration::from_secs(6)).await;
    let n = checks();
    println!("[refusal-budget] 64 refusals 40 ms apart from one forwarder: {n} checked (bound {BOUND})");
    assert!(n >= 8, "the forwarder's first eight refusals must be checked, {n} were");
    assert!(n <= BOUND, "{n} of one forwarder's refusals were checked in a window, above the budget plus the queue ({BOUND})");
    Ok(())
}

/// Messages a listener received, each with its arrival time in seconds after a start.
#[derive(Clone, Default)]
struct Arrivals(Arc<std::sync::Mutex<Vec<(f64, Received)>>>);

impl Arrivals {
    /// Logs what `inbox` receives, timed from `start`.
    fn log(mut inbox: mpsc::UnboundedReceiver<Received>, start: Instant) -> Self {
        let log = Self::default();
        let out = log.clone();
        tokio::spawn(async move {
            while let Some(m) = inbox.recv().await {
                out.0.lock().unwrap().push((start.elapsed().as_secs_f64(), m));
            }
        });
        log
    }

    /// When each copy of `m` arrived, and its author.
    fn of(&self, m: &[u8]) -> Vec<(f64, Option<PeerId>)> {
        self.0.lock().unwrap().iter().filter(|(_, (_, r))| r == m).map(|(t, (from, _))| (*t, *from)).collect()
    }

    /// When each copy of `m` arrived.
    fn times(&self, m: &[u8]) -> Vec<f64> {
        self.of(m).into_iter().map(|(t, _)| t).collect()
    }

    /// Waits until `m` has arrived or `deadline` after `start` has passed.
    async fn until(&self, m: &[u8], start: Instant, deadline: Duration) {
        while start.elapsed() < deadline && self.of(m).is_empty() {
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
    }
}

// Gossipsub keeps an unreported message for 5 heartbeats
// (`mcache.rs` shift); a gossip tx whose check returned later was admitted, and Accept found
// nothing to forward (`report_message_validation_result` returned false), so the tx stopped at
// this node. A checks X's txs 15 s late (TEST_GOSSIP_TX_CHECK_DELAY): heartbeats start 6 s after a
// node starts (`heartbeat_initial_delay` 5 s plus the 1 s interval) and each one is timed from the
// end of the last, so 7 s was not always past five of them. D, a listener connected only to A,
// must still receive X's tx, which A then publishes itself. That publish waits out A's own 60 s
// duplicate cache, which gossipsub prunes only when it records another id (`TimeCache::entry`), so
// X sends one more message past the window, as a live chain's next gossip would. The paired honest
// path: Y's tx, checked at once, reaches D through gossipsub's own forward, and only once (A
// publishes only what gossipsub could not forward).
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_gossip_tx_admitted_after_its_message_left_the_cache_still_reaches_the_next_node() -> Result<()> {
    const LATE: Duration = Duration::from_secs(15);
    const LATE_COIN: OutPoint = OutPoint { txid: [0xD1; 32], vout: 0 };
    let coins = vec![(HONEST_COIN, owner(HONEST_SK)), (LATE_COIN, owner(HONEST_SK))];
    let (_a, mempool, addr) = node_a(&coins).await?;
    let (_d, _, inbox) = connected_gossiper_with_inbox(&addr).await?;
    let (late_relay, x) = connected_gossiper_with_id(&addr).await?;
    let prompt_relay = connected_gossiper(&addr).await?;
    csd::net::node::TEST_GOSSIP_TX_CHECK_DELAY.lock().unwrap().insert(x, LATE);
    // A grafts its three peers into its mesh at its next heartbeats (1 s).
    tokio::time::sleep(Duration::from_secs(3)).await;

    let c = csd::codec::consensus_bincode();
    let (late, prompt) = (honest_spend_of(LATE_COIN), honest_spend());
    let late_msg = c.serialize(&GossipTx { tx: late.clone() })?;
    let prompt_msg = c.serialize(&GossipTx { tx: prompt })?;
    let sent = Instant::now();
    late_relay.send(late_msg.clone())?;
    prompt_relay.send(prompt_msg.clone())?;

    let at_d = Arrivals::log(inbox, sent);
    at_d.until(&prompt_msg, sent, Duration::from_secs(10)).await;
    assert!(!at_d.times(&prompt_msg).is_empty(), "a gossip tx checked at once was not forwarded to D");

    while !mempool.contains(&txid(&late)) {
        anyhow::ensure!(sent.elapsed() < Duration::from_secs(30), "A never admitted the late tx");
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    let admitted = sent.elapsed().as_secs_f64();

    tokio::time::sleep_until((sent + Duration::from_secs(62)).into()).await;
    late_relay.send(vec![0xFF; 4])?;
    at_d.until(&late_msg, sent, Duration::from_secs(85)).await;
    tokio::time::sleep(Duration::from_secs(1)).await;
    let (late_at, prompt_at) = (at_d.times(&late_msg), at_d.times(&prompt_msg));
    println!("[late-check] late tx admitted {admitted:.1} s after it was sent; D received it at {late_at:.1?} s, the prompt tx at {prompt_at:.1?} s");
    assert_eq!(
        late_at.len(),
        1,
        "A admitted the late tx {admitted:.1} s after it was sent, past gossipsub's 5 heartbeats, and D received it at {late_at:.1?} s"
    );
    assert!(
        late_at[0] > 60.0,
        "fixture: D received the late tx at {:.1} s, when A admitted it, so gossipsub still held its message",
        late_at[0]
    );
    assert_eq!(prompt_at.len(), 1, "a tx gossipsub forwarded was published again: D received it at {prompt_at:.1?} s");
    Ok(())
}

/// Names the authors of `got` for a failure message: A, or one of `peers` with its label.
fn labelled(got: &[(f64, Option<PeerId>)], a: PeerId, peers: &[(PeerId, &str)]) -> Vec<String> {
    let who = |p: &Option<PeerId>| match p {
        Some(p) if *p == a => "A",
        Some(p) => peers.iter().find(|(q, _)| q == p).map_or("?", |(_, n)| *n),
        None => "?",
    };
    got.iter().map(|(t, p)| format!("{t:.1} s from {}", who(p))).collect()
}

// An Accept reports that gossipsub still held the message, not
// that it sent it anywhere (`report_message_validation_result` returns true whatever
// `forward_msg` found, gossipsub 0.50.1 `behaviour.rs:979-984`). A checks X's tx 15 s late and
// queues its own publish, which waits out A's 60 s duplicate cache, and X leaves. At 62 s Y relays
// the same bytes; A checks them at once and reports Accept, which finds them cached and forwards
// them to nobody: Y wrote them and is A's only peer. If that Accept retired the queued
// publish and counted it as gone out, D, which connects once Y's copy has left A's cache, would
// never receive the tx. The queued publish now stands until A's own publish is queued: Y's message at
// 124 s lets it out, and D receives the tx from A, once: Y's message at 196 s, past the 60 s
// window of that publish, lets out nothing more (a late publish goes out at most once per tx while
// held).
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_late_accept_waiting_in_the_retry_queue_outlives_an_accept_that_forwarded_to_nobody() -> Result<()> {
    const LATE: Duration = Duration::from_secs(15);
    const LATE_COIN: OutPoint = OutPoint { txid: [0xD2; 32], vout: 0 };
    let (a, mempool, addr) = node_a(&[(LATE_COIN, owner(HONEST_SK))]).await?;
    let (late_relay, x) = connected_gossiper_with_id(&addr).await?;
    let (second_relay, y) = connected_gossiper_with_id(&addr).await?;
    csd::net::node::TEST_GOSSIP_TX_CHECK_DELAY.lock().unwrap().insert(x, LATE);
    // A grafts its peers into its mesh at its next heartbeats (1 s).
    tokio::time::sleep(Duration::from_secs(3)).await;

    let late = honest_spend_of(LATE_COIN);
    let late_msg = csd::codec::consensus_bincode().serialize(&GossipTx { tx: late.clone() })?;
    let sent = Instant::now();
    late_relay.send(late_msg.clone())?;
    while !mempool.contains(&txid(&late)) {
        anyhow::ensure!(sent.elapsed() < Duration::from_secs(30), "A never admitted the late tx");
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    drop(late_relay);

    tokio::time::sleep_until((sent + Duration::from_secs(62)).into()).await;
    second_relay.send(late_msg.clone())?;
    tokio::time::sleep_until((sent + Duration::from_secs(75)).into()).await;
    let (_d, d, inbox) = connected_gossiper_with_inbox(&addr).await?;
    let at_d = Arrivals::log(inbox, sent);
    tokio::time::sleep_until((sent + Duration::from_secs(124)).into()).await;
    second_relay.send(vec![0xFE; 4])?;
    tokio::time::sleep_until((sent + Duration::from_secs(196)).into()).await;
    second_relay.send(vec![0xFC; 4])?;
    // Past A's next drains (5 s apart).
    tokio::time::sleep_until((sent + Duration::from_secs(208)).into()).await;
    let got = at_d.of(&late_msg);
    let shown = labelled(&got, a.handle.peer_id, &[(x, "X"), (y, "Y"), (d, "D")]);
    println!("[late-then-accepted] D received the late tx at {shown:?}");
    assert!(
        got.first().is_some_and(|(t, p)| *p == Some(a.handle.peer_id) && *t > 120.0),
        "an Accept that forwarded Y's copy to nobody retired A's queued late accept: D received the tx at {shown:?}"
    );
    assert_eq!(got.len(), 1, "A's late accept went out more than once while held: D received the tx at {shown:?}");
    assert!(mempool.contains(&txid(&late)), "fixture: A still holds the tx");
    Ok(())
}

// The same Accept must not retire a `/tx/submit`'s insured publish. A holds
// its check of X's copy 2 s, inside gossipsub's cache; meanwhile the submit admits the same bytes,
// and its publish meets the copy's id in A's duplicate cache (Duplicate) and is queued, insured. X
// wrote the copy and is A's only peer, so the Accept forwards it to nobody. If that
// Accept retired the insured publish, D, which connects once the message has left A's cache,
// would never receive the tx. The insured publish now stands until A's own publish is queued: X's
// message at 62 s lets A's duplicate cache drop the tx's id, and D receives the tx from A.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_submits_insured_publish_outlives_an_accept_that_forwarded_to_nobody() -> Result<()> {
    const CHECK_DELAY: Duration = Duration::from_secs(2);
    const COIN: OutPoint = OutPoint { txid: [0xD3; 32], vout: 0 };
    let (a, mempool, addr) = node_a(&[(COIN, owner(HONEST_SK))]).await?;
    let (relay, x) = connected_gossiper_with_id(&addr).await?;
    csd::net::node::TEST_GOSSIP_TX_CHECK_DELAY.lock().unwrap().insert(x, CHECK_DELAY);
    let checks = || csd::net::node::TEST_GOSSIP_TX_CHECKS.lock().unwrap().get(&x).copied().unwrap_or(0);
    tokio::time::sleep(Duration::from_secs(3)).await;

    let tx = honest_spend_of(COIN);
    let msg = csd::codec::consensus_bincode().serialize(&GossipTx { tx: tx.clone() })?;
    let sent = Instant::now();
    relay.send(msg.clone())?;
    // A's check of the copy has started, so the copy's id is in A's duplicate cache.
    while checks() == 0 {
        anyhow::ensure!(sent.elapsed() < Duration::from_secs(10), "A never started checking X's copy");
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    // What /tx/submit does (`admit_and_gossip`): admit the tx, then send its insured gossip event.
    anyhow::ensure!(mempool.insert_checked(&a.db, tx.clone())?, "fixture: the submit admits the tx first");
    a.gossip.send(csd::net::GossipTxEvent { tx: tx.clone(), insure: true })?;
    anyhow::ensure!(sent.elapsed() < CHECK_DELAY, "fixture: the submit came after X's copy was checked");

    // The Accept lands at about 2 s and the message leaves A's cache 5 heartbeats later.
    tokio::time::sleep_until((sent + Duration::from_secs(10)).into()).await;
    let (_d, d, inbox) = connected_gossiper_with_inbox(&addr).await?;
    let at_d = Arrivals::log(inbox, sent);
    tokio::time::sleep_until((sent + Duration::from_secs(62)).into()).await;
    relay.send(vec![0xFD; 4])?;
    at_d.until(&msg, sent, Duration::from_secs(75)).await;
    tokio::time::sleep(Duration::from_secs(1)).await;
    let got = at_d.of(&msg);
    let shown = labelled(&got, a.handle.peer_id, &[(x, "X"), (d, "D")]);
    println!("[submit-insured] D received the submitted tx at {shown:?}");
    assert_eq!(checks(), 1, "fixture: A checked X's copy once");
    assert!(
        got.len() == 1 && got[0].1 == Some(a.handle.peer_id) && got[0].0 > 60.0,
        "an Accept that forwarded X's copy to nobody retired the submit's insured publish: D received the tx at {shown:?}"
    );
    assert!(mempool.contains(&txid(&tx)), "fixture: A still holds the tx");
    Ok(())
}
