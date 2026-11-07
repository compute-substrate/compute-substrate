#![cfg(feature = "test-bypass")] // live p2p lane: toy chains and the fault seam need the bypass (cargo test --features test-bypass)
// The class: log lines a remote peer drives at will. Upstream printed each at every event: three
// `[sync-serve]` lines a served block (3,600 in 10 s from one peer at the request throttle), a
// MISS line for every block asked for and not held (about 7,300 a minute from one
// peer), two lines for every header of a Headers answer refused (2,050 from one answer), and a few
// for every connection (66,000 a minute from one address opening them with fresh identities). Each
// spends the node's journal burst and hides the `[tx_submit] ACCEPT` lines an operator's alert reads.
//
// `src/net/serve_log.rs` samples them all: a peer's first line of a kind at once, then one a minute
// carrying the events since, the rest named when the peer disconnects; and at most
// CEILING lines a minute in all, what is held back named at the next minute's start.
//
// The node's lines are its process's stdout, so each test runs itself again as a child with CHILD
// set: the child runs a node and its peers and prints a mark before each phase; this side counts the
// child's lines per phase.

use anyhow::{ensure, Result};
use futures::StreamExt;
use std::collections::HashMap;
use std::net::Ipv4Addr;
use std::process::Command;
use std::sync::atomic::Ordering;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tempfile::TempDir;

use libp2p::{identity, request_response, swarm::SwarmEvent, Multiaddr, PeerId, Swarm};

use csd::chain::index::header_hash;
use csd::net::node::SyncCodec;
use csd::net::proto::{SyncRequest, SyncResponse};
use csd::state::db::k_block;
use csd::types::{AppPayload, Block, BlockHeader, Transaction};

mod testutil_chain;
use testutil_chain::{build_base_chain_with_miner, open_db};
mod testutil_p2p;
use testutil_p2p::{spawn_node_on, swarm_config, sync_rr, transport, transport_from, wait_until};

const CHILD: &str = "CSD_SERVE_LOG_CHILD";
const MARK: &str = "MARK ";
const START: u64 = 1_700_900_000;
/// Requests a requester keeps in flight: three of the connection's four streams, the fourth left to
/// the node's own background request to it.
const STREAMS: usize = 3;
/// `serve_log::PEER_LINES_PER_MINUTE`.
const CEILING: usize = 600;
/// How long the one peer sends every kind of request at the throttle: past a minute, so every kind's
/// line comes due again once.
const FLOOD: Duration = Duration::from_secs(62);
/// The bound on the peer-driven lines of that minute.
const MINUTE_BOUND: usize = 60;
/// A second loopback address, not exempt from the per-address admission caps as 127.0.0.1 is.
const SECOND: Ipv4Addr = Ipv4Addr::new(127, 0, 0, 2);

/// How a peer answers the node's requests to it.
type Answer = fn(&SyncRequest) -> SyncResponse;

fn not_served(_: &SyncRequest) -> SyncResponse {
    SyncResponse::Err { msg: "not served".into() }
}

struct Requester {
    swarm: Swarm<request_response::Behaviour<SyncCodec>>,
    node: PeerId,
    answer: Answer,
}

impl Requester {
    async fn connect(addr: Multiaddr, node: PeerId, from: Option<Ipv4Addr>, answer: Answer) -> Option<Self> {
        Self::connect_as(identity::Keypair::generate_ed25519(), addr, node, from, answer).await
    }

    /// `connect` with the identity `key`, so a peer can come back as itself.
    async fn connect_as(key: identity::Keypair, addr: Multiaddr, node: PeerId, from: Option<Ipv4Addr>, answer: Answer) -> Option<Self> {
        let t = match from {
            Some(ip) => transport_from(&key, ip),
            None => transport(&key),
        };
        let mut swarm = Swarm::new(t, sync_rr(), key.public().to_peer_id(), swarm_config());
        swarm.dial(addr).ok()?;
        let deadline = tokio::time::Instant::now() + Duration::from_secs(10);
        loop {
            match tokio::time::timeout_at(deadline, swarm.select_next_some()).await {
                Ok(SwarmEvent::ConnectionEstablished { .. }) => return Some(Self { swarm, node, answer }),
                Ok(SwarmEvent::OutgoingConnectionError { .. }) | Err(_) => return None,
                _ => {}
            }
        }
    }

    fn id(&self) -> PeerId {
        *self.swarm.local_peer_id()
    }

    /// Sends `reqs` in turn, `n` in all (or until `until`), at most STREAMS in flight, and answers the
    /// node's requests meanwhile. Returns each request's answers, by its index in `reqs`.
    async fn ask_each(&mut self, reqs: &[SyncRequest], n: usize, until: Option<Instant>) -> Vec<Vec<SyncResponse>> {
        let mut answers: Vec<Vec<SyncResponse>> = vec![Vec::new(); reqs.len()];
        let mut in_flight: HashMap<request_response::OutboundRequestId, usize> = HashMap::new();
        let (mut sent, mut next) = (0, 0);
        loop {
            let open = sent < n && until.is_none_or(|t| Instant::now() < t);
            while open && in_flight.len() < STREAMS && sent < n {
                let rid = self.swarm.behaviour_mut().send_request(&self.node, reqs[next].clone());
                in_flight.insert(rid, next);
                next = (next + 1) % reqs.len();
                sent += 1;
            }
            if in_flight.is_empty() && !open {
                return answers;
            }
            match tokio::time::timeout(Duration::from_millis(500), self.swarm.select_next_some()).await {
                Ok(SwarmEvent::Behaviour(request_response::Event::Message {
                    message: request_response::Message::Response { request_id, response }, ..
                })) => {
                    if let Some(i) = in_flight.remove(&request_id) {
                        answers[i].push(response);
                    }
                }
                Ok(SwarmEvent::Behaviour(request_response::Event::OutboundFailure { request_id, .. })) => {
                    in_flight.remove(&request_id);
                }
                Ok(SwarmEvent::Behaviour(request_response::Event::Message {
                    message: request_response::Message::Request { channel, request, .. }, ..
                })) => {
                    let a = (self.answer)(&request);
                    let _ = self.swarm.behaviour_mut().send_response(channel, a);
                }
                Ok(SwarmEvent::ConnectionClosed { .. }) => return answers,
                _ => {}
            }
        }
    }

    async fn ask(&mut self, req: SyncRequest) -> SyncResponse {
        let mut a = self.ask_each(&[req], 1, None).await;
        a[0].pop().expect("an answer")
    }

    /// Answers the node's requests for `d`.
    async fn serve_for(&mut self, d: Duration) {
        let end = tokio::time::Instant::now() + d;
        while let Ok(ev) = tokio::time::timeout_at(end, self.swarm.select_next_some()).await {
            if let SwarmEvent::Behaviour(request_response::Event::Message {
                message: request_response::Message::Request { channel, request, .. }, ..
            }) = ev
            {
                let a = (self.answer)(&request);
                let _ = self.swarm.behaviour_mut().send_response(channel, a);
            }
        }
    }
}

fn mark(phase: &str) {
    println!("{MARK}{phase}");
}

fn is_rate_limited(r: &SyncResponse) -> bool {
    matches!(r, SyncResponse::Err { msg } if msg == "rate limited")
}

/// The child's stdout as (phase, line) pairs, and the value of each `names` field.
fn phases(stdout: &str) -> (Vec<(String, String)>, HashMap<String, String>) {
    let (mut phase, mut lines, mut names) = (String::from("setup"), Vec::new(), HashMap::new());
    for line in stdout.lines() {
        if let Some(m) = line.strip_prefix(MARK) {
            if let Some(fields) = m.strip_prefix("names ") {
                for f in fields.split(' ') {
                    let (k, v) = f.split_once('=').unwrap();
                    names.insert(k.to_string(), v.to_string());
                }
            } else {
                phase = m.to_string();
            }
        } else {
            lines.push((phase.clone(), line.to_string()));
        }
    }
    (lines, names)
}

/// Runs `test` again as a child with CHILD set, and returns its stdout.
fn run_child(test: &str) -> String {
    let out = Command::new(std::env::current_exe().unwrap())
        .args([test, "--exact", "--nocapture", "--test-threads=1"])
        .env(CHILD, "1")
        .output()
        .unwrap();
    let stdout = String::from_utf8_lossy(&out.stdout).into_owned();
    assert!(out.status.success(), "the child failed:\n{}\n{}", stdout, String::from_utf8_lossy(&out.stderr));
    stdout
}

/// In the child, runs `f` on a runtime and returns true.
fn in_child<Fut: std::future::Future<Output = Result<()>>>(f: impl FnOnce() -> Fut) -> bool {
    if std::env::var(CHILD).is_err() {
        return false;
    }
    let rt = tokio::runtime::Builder::new_multi_thread().worker_threads(4).enable_all().build().unwrap();
    rt.block_on(f()).unwrap();
    true
}

/// The node's own periodic lines, which no peer drives.
fn node_own(l: &str) -> bool {
    l.starts_with("[mem]") || l.starts_with("[sync] queue status") || l.starts_with("[sync-debug]")
}

/// The number a line carries after `key=`.
fn field(l: &str, key: &str) -> Option<u64> {
    let at = l.find(&format!("{key}="))? + key.len() + 1;
    l[at..].split(|c: char| !c.is_ascii_digit()).next()?.parse().ok()
}

/// The count of `kind` a disconnect or summary line names.
fn named(l: &str, kind: &str) -> u64 {
    l.split(' ').find_map(|w| w.strip_prefix(&format!("{kind}="))).and_then(|n| n.parse().ok()).unwrap_or(0)
}

// ---------------------------------------------------------------------------------------------------
// One peer, every request kind at the throttle for a minute.

async fn one_peer_child() -> Result<()> {
    let tmp = TempDir::new()?;
    let db = Arc::new(open_db(&tmp)?);
    let chain = build_base_chain_with_miner(&db, 3, START, [0x11; 20])?;
    // A stored body that does not bind to its header: its serve answers an error
    // (`outbound_block_refusal`).
    let codec = csd::codec::consensus_bincode();
    let mut bad: Block = codec.deserialize(&db.blocks.get(k_block(&chain[2]))?.expect("stored"))?;
    bad.header.merkle = [0xAB; 32];
    let bad_hash = header_hash(&bad.header);
    db.blocks.insert(k_block(&bad_hash), codec.serialize(&bad)?)?;
    let (known, unknown) = (chain[1], [0xEE; 32]);

    let node = spawn_node_on(db, tmp, chain[0], vec![]).await?;
    let mut r1 = Requester::connect(node.dial_addr(), node.handle.peer_id, None, not_served).await.expect("r1 connects");
    let r1_id = r1.id();
    println!("{MARK}names r1={r1_id} known=0x{} unknown=0x{} bad=0x{}", hex::encode(known), hex::encode(unknown), hex::encode(bad_hash));
    tokio::time::sleep(Duration::from_millis(300)).await;
    let (stored, missing, refused) = (
        SyncRequest::GetBlock { hash: known },
        SyncRequest::GetBlock { hash: unknown },
        SyncRequest::GetBlock { hash: bad_hash },
    );
    let invalid = SyncRequest::GetHeaders { from_height: 0, max: 2_000 };

    mark("first");
    ensure!(matches!(r1.ask(stored.clone()).await, SyncResponse::Block { .. }), "the first GetBlock was not answered with its block");

    mark("events");
    let miss = r1.ask(missing.clone()).await;
    let err = r1.ask(refused.clone()).await;
    let tip = r1.ask(SyncRequest::GetTip).await;
    let inv: Vec<SyncResponse> = vec![r1.ask(invalid.clone()).await, r1.ask(invalid.clone()).await];
    ensure!(matches!(&miss, SyncResponse::Err { msg } if msg == "unknown block"), "{miss:?}");
    ensure!(matches!(&err, SyncResponse::Err { msg } if msg.contains("does not bind")), "{err:?}");
    ensure!(matches!(tip, SyncResponse::Tip { .. }), "{tip:?}");
    ensure!(inv.iter().all(|r| matches!(r, SyncResponse::Err { msg } if msg == "invalid headers request")), "{inv:?}");
    tokio::time::sleep(Duration::from_millis(300)).await;

    // Every kind in turn, at most STREAMS in flight, for FLOOD; two more invalid requests on the way
    // (four in all: a score of -24, above the quarantine's -30, and far below the ban's 32 a window).
    mark("flood");
    let tx = Transaction { version: 1, inputs: vec![], outputs: vec![], locktime: 0, app: AppPayload::None };
    let mix = vec![
        stored,
        missing,
        refused,
        SyncRequest::GetHeaders { from_height: 0, max: 16 },
        SyncRequest::GetHeadersByLocator { locator: vec![chain[0]], max: 16 },
        SyncRequest::GetTip,
        SyncRequest::GetPeers { max: 8 },
        SyncRequest::SubmitTx { tx },
    ];
    let t0 = Instant::now();
    let mut tally: Vec<(u64, u64)> = vec![(0, 0); mix.len() + 1];
    let mut flood_invalid = 0;
    for part in 0..3u32 {
        let until = t0 + FLOOD * (part + 1) / 3;
        let answers = r1.ask_each(&mix, usize::MAX, Some(until)).await;
        for (i, a) in answers.iter().enumerate() {
            tally[i].0 += a.iter().filter(|r| !is_rate_limited(r)).count() as u64;
            tally[i].1 += a.iter().filter(|r| is_rate_limited(r)).count() as u64;
        }
        if part < 2 {
            let r = r1.ask(invalid.clone()).await;
            flood_invalid += u64::from(matches!(&r, SyncResponse::Err { msg } if msg == "invalid headers request"));
        }
    }
    let served: Vec<String> = tally.iter().take(mix.len()).map(|(s, _)| s.to_string()).collect();
    let limited: u64 = tally.iter().map(|(_, l)| l).sum();
    println!(
        "{MARK}flood-done served={} rate_limited={limited} invalid={} secs={:.1}",
        served.join(","),
        2 + flood_invalid,
        t0.elapsed().as_secs_f64()
    );

    mark("gone");
    drop(r1);
    let peers = node.handle.connected_peers.clone();
    ensure!(wait_until(10, || peers.load(Ordering::Relaxed) == 0).await, "the first requester is still connected");
    tokio::time::sleep(Duration::from_secs(1)).await;

    mark("second");
    let mut r2 = Requester::connect(node.dial_addr(), node.handle.peer_id, None, not_served).await.expect("r2 connects");
    println!("{MARK}names r2={}", r2.id());
    ensure!(matches!(r2.ask(SyncRequest::GetBlock { hash: known }).await, SyncResponse::Block { .. }), "r2's GetBlock was not answered");
    tokio::time::sleep(Duration::from_millis(300)).await;
    mark("end");
    Ok(())
}

#[test]
fn one_peer_sending_every_request_kind_at_the_throttle_for_a_minute_writes_a_bounded_number_of_lines() {
    if in_child(one_peer_child) {
        return;
    }
    let stdout = run_child("one_peer_sending_every_request_kind_at_the_throttle_for_a_minute_writes_a_bounded_number_of_lines");
    let (lines, names) = phases(&stdout);
    let (r1, r2, known, unknown, bad) = (&names["r1"], &names["r2"], &names["known"], &names["unknown"], &names["bad"]);
    let of = |phase: &str| -> Vec<&str> { lines.iter().filter(|(p, _)| p.starts_with(phase)).map(|(_, l)| l.as_str()).collect() };
    let flood_done = stdout.lines().find(|l| l.starts_with("MARK flood-done")).unwrap_or("").to_string();
    eprintln!("[measure] {flood_done}");

    // The bound: a minute of every kind at the throttle wrote at most MINUTE_BOUND lines the peer drove
    // (its own and the serve's), against thousands of MISS lines alone before.
    let flood: Vec<&str> = of("flood").into_iter().filter(|l| !node_own(l)).collect();
    eprintln!("[measure] one peer, every request kind at the throttle for {FLOOD:?}: {} node lines", flood.len());
    for l in &flood {
        eprintln!("[measure]   {l}");
    }
    assert!(flood.len() <= MINUTE_BOUND, "a minute of one peer's requests wrote {} lines", flood.len());

    // The paired honest path. A peer's first request is logged at once, with the count it stands for.
    let serve = |phase: &str| -> Vec<&str> { of(phase).into_iter().filter(|l| l.starts_with("[sync-serve]")).collect() };
    let first = serve("first");
    assert_eq!(first.len(), 3, "{first:?}");
    assert!(first[0].contains(&format!("recv GetBlock from {r1} hash={known}")) && first[0].ends_with("requests_since_last_line=1"), "{first:?}");
    assert!(first[1].contains(&format!("GetBlock lookup {known}")) && first[2].contains(&format!("GetBlock HIT {known}")), "{first:?}");

    // Its first MISS, error answer and GetTip are logged at once though its GetBlock line is not due:
    // each kind keeps its own minute. Its first invalid request too, the second counted.
    let events = serve("events");
    assert!(events.iter().any(|l| l.contains(&format!("GetBlock MISS {unknown} from {r1} since_last_line=1"))), "{events:?}");
    assert!(
        events.iter().any(|l| l.contains(&format!("error answer to GetBlock {bad} from {r1}")) && l.contains("does not bind")),
        "{events:?}"
    );
    assert!(events.iter().any(|l| l.contains(&format!("recv GetTip from {r1}")) && l.ends_with("requests_since_last_line=1")), "{events:?}");
    assert!(!events.iter().any(|l| l.contains("recv GetBlock") || l.contains("lookup") || l.contains("HIT")), "{events:?}");
    assert_eq!(events.len(), 3, "{events:?}");
    let invalid_now: Vec<&str> = of("events").into_iter().filter(|l| l.contains(&format!("invalid from {r1}"))).collect();
    assert_eq!(invalid_now.len(), 1, "{invalid_now:?}");
    assert!(invalid_now[0].contains("invalid_in_window=1") && invalid_now[0].ends_with("since_last_line=1"), "{invalid_now:?}");

    // Nothing is hidden, only counted: for each kind, the counts on the peer's printed lines and on its
    // disconnect line add up to the requests served.
    let gone: Vec<&str> = of("gone").into_iter().filter(|l| l.contains(&format!("{r1} disconnected"))).collect();
    assert_eq!(gone.len(), 1, "{:?}", of("gone"));
    let served: Vec<u64> = flood_done.split("served=").nth(1).unwrap().split(' ').next().unwrap().split(',').map(|n| n.parse().unwrap()).collect();
    let invalid_served = field(&flood_done, "invalid").unwrap();
    let r1_lines: Vec<&str> = lines.iter().map(|(_, l)| l.as_str()).filter(|l| l.contains(r1.as_str())).collect();
    let printed = |prefix: &str, key: &str| -> u64 { r1_lines.iter().filter(|l| l.contains(prefix)).filter_map(|l| field(l, key)).sum() };
    let checks = [
        ("GetBlock", printed("recv GetBlock from", "requests_since_last_line"), 1 + 2 + served[0] + served[1] + served[2]),
        ("MISS", printed("GetBlock MISS", "since_last_line"), 1 + served[1]),
        ("error-answer", printed("error answer to GetBlock", "since_last_line"), 1 + served[2]),
        ("GetHeaders", printed("recv GetHeaders from", "requests_since_last_line"), served[3]),
        ("GetHeadersByLocator", printed("recv GetHeadersByLocator from", "requests_since_last_line"), served[4]),
        ("GetTip", printed("recv GetTip from", "requests_since_last_line"), 1 + served[5]),
        ("GetPeers", printed("recv GetPeers from", "requests_since_last_line"), served[6]),
        ("SubmitTx", printed("recv SubmitTx from", "requests_since_last_line"), served[7]),
        ("invalid", printed("invalid from", "since_last_line"), invalid_served),
    ];
    for (kind, on_lines, want) in checks {
        assert_eq!(on_lines + named(gone[0], kind), want, "{kind}: {on_lines} on its lines + the disconnect line: {}", gone[0]);
    }

    // Another peer's first request is logged at once.
    let second = serve("second");
    assert!(second.iter().any(|l| l.contains(&format!("recv GetBlock from {r2} hash={known}")) && l.ends_with("requests_since_last_line=1")), "{second:?}");
    assert!(second.iter().any(|l| l.contains(&format!("GetBlock HIT {known}"))), "{second:?}");
}

// ---------------------------------------------------------------------------------------------------
// One address opening connections with fresh identities, at its admission caps.

/// How long the churn runs; inside one minute of the ceiling's.
const CHURN: Duration = Duration::from_secs(25);
/// Identities in flight at once: the per-address cap on established inbound connections.
const AT_ONCE: usize = 8;

async fn churn_child() -> Result<()> {
    let tmp = TempDir::new()?;
    let db = Arc::new(open_db(&tmp)?);
    let chain = build_base_chain_with_miner(&db, 3, START, [0x11; 20])?;
    let node = spawn_node_on(db, tmp, chain[0], vec![]).await?;
    let (addr, id) = (node.dial_addr(), node.handle.peer_id);

    // An honest peer from 127.0.0.1, connected throughout.
    let mut honest = Requester::connect(addr.clone(), id, None, not_served).await.expect("the honest peer connects");
    println!("{MARK}names honest={}", honest.id());
    mark("honest");
    let t_honest = Instant::now();
    ensure!(matches!(honest.ask(SyncRequest::GetTip).await, SyncResponse::Tip { .. }), "the honest GetTip");

    mark("churn");
    let (mut attempts, mut answered) = (0u64, 0u64);
    let end = Instant::now() + CHURN;
    while Instant::now() < end {
        let mut set = tokio::task::JoinSet::new();
        for _ in 0..AT_ONCE {
            let addr = addr.clone();
            set.spawn(async move {
                let Some(mut p) = Requester::connect(addr, id, Some(SECOND), not_served).await else { return false };
                let a = p.ask_each(&[SyncRequest::GetTip, SyncRequest::GetBlock { hash: [0xEE; 32] }], 2, None).await;
                a.iter().any(|x| !x.is_empty())
            });
        }
        while let Some(r) = set.join_next().await {
            attempts += 1;
            answered += u64::from(r.unwrap_or(false));
        }
    }
    println!("{MARK}churn-done attempts={attempts} answered={answered}");

    // Once the ceiling's minute has passed, the honest peer's next GetTip is printed.
    mark("after");
    tokio::time::sleep(Duration::from_secs(66).saturating_sub(t_honest.elapsed())).await;
    honest.serve_for(Duration::from_millis(100)).await;
    ensure!(matches!(honest.ask(SyncRequest::GetTip).await, SyncResponse::Tip { .. }), "the honest GetTip after");
    tokio::time::sleep(Duration::from_millis(300)).await;
    mark("end");
    Ok(())
}

#[test]
fn fresh_identities_from_one_address_write_at_most_the_ceiling_a_minute() {
    if in_child(churn_child) {
        return;
    }
    let stdout = run_child("fresh_identities_from_one_address_write_at_most_the_ceiling_a_minute");
    let (lines, names) = phases(&stdout);
    let honest = &names["honest"];
    let churn_done = stdout.lines().find(|l| l.starts_with("MARK churn-done")).unwrap_or("").to_string();
    eprintln!("[measure] {churn_done}");
    let (attempts, answered) = (field(&churn_done, "attempts").unwrap(), field(&churn_done, "answered").unwrap());
    assert!(answered > CEILING as u64 / 2, "the churn made only {answered} identities that were answered");

    // The bound: the lines of each of the ceiling's minutes, split at the summary line that starts the
    // next, are at most CEILING, and a few counted at powers of two (`log_due`) beside them.
    let window_lines: Vec<&str> = lines
        .iter()
        .filter(|(p, l)| (p.starts_with("churn") || p == "after") && !node_own(l))
        .map(|(_, l)| l.as_str())
        .collect();
    let summaries: Vec<&str> = window_lines.iter().copied().filter(|l| l.contains("peer lines past the ceiling")).collect();
    let mut segments = vec![0usize];
    for l in &window_lines {
        if l.contains("peer lines past the ceiling") {
            segments.push(0);
        } else {
            *segments.last_mut().unwrap() += 1;
        }
    }
    eprintln!("[measure] {attempts} fresh identities from one address in {CHURN:?}: {} node lines; by minute: {segments:?}", window_lines.len());
    for s in &summaries {
        eprintln!("[measure]   {s}");
    }
    assert!(segments.iter().all(|n| *n <= CEILING + 64), "a minute of the churn wrote {segments:?} lines");
    let sampled = |l: &&str| l.contains("since_last_line=") || l.contains("not printed since") || l.contains("lookup") || l.contains("HIT");
    let mut sampled_segments = vec![0usize];
    for l in &window_lines {
        if l.contains("peer lines past the ceiling") {
            sampled_segments.push(0);
        } else if sampled(l) {
            *sampled_segments.last_mut().unwrap() += 1;
        }
    }
    assert!(sampled_segments.iter().all(|n| *n <= CEILING), "{sampled_segments:?}");

    // Nothing is hidden, only counted: every identity's connection is a printed connect line or a
    // connect event of a summary.
    assert!(!summaries.is_empty(), "no summary line");
    let printed_connects = window_lines.iter().filter(|l| l.starts_with("[p2p] connected:") && !l.contains(honest.as_str())).count() as u64;
    let held_connects: u64 = summaries.iter().map(|s| named(s, "connect")).sum();
    let connects = printed_connects + held_connects;
    assert!((answered..=attempts).contains(&connects), "{printed_connects} printed + {held_connects} held, for {answered} to {attempts} identities");

    // The paired honest path: the honest peer's first GetTip was printed at once, and its next one,
    // a minute later, is printed in the next minute of the ceiling.
    let tip = |phase: &str| lines.iter().any(|(p, l)| p == phase && l.contains(&format!("recv GetTip from {honest}")) && l.ends_with("requests_since_last_line=1"));
    assert!(tip("honest"), "the honest peer's first GetTip line");
    assert!(tip("after"), "the honest peer's GetTip line after the churn");
}

// ---------------------------------------------------------------------------------------------------
// One Headers answer of refused headers.

/// The node's GetTip to the peer: a tip it does not hold, claiming the most work, so it asks for headers.
fn junk_headers(req: &SyncRequest) -> SyncResponse {
    match req {
        SyncRequest::GetTip => SyncResponse::Tip { hash: [0x99; 32], height: 1_000_000, chainwork: u128::MAX / 2 },
        SyncRequest::GetHeadersByLocator { .. } => SyncResponse::Headers {
            headers: (0..1_024)
                .map(|nonce| BlockHeader { version: 1, prev: [0x55; 32], merkle: [0; 32], time: START, bits: 0, nonce })
                .collect(),
        },
        _ => not_served(req),
    }
}

async fn junk_headers_child() -> Result<()> {
    let tmp = TempDir::new()?;
    let db = Arc::new(open_db(&tmp)?);
    let chain = build_base_chain_with_miner(&db, 3, START, [0x11; 20])?;
    let node = spawn_node_on(db, tmp, chain[0], vec![]).await?;
    mark("answer");
    let mut j = Requester::connect(node.dial_addr(), node.handle.peer_id, None, junk_headers).await.expect("j connects");
    println!("{MARK}names j={}", j.id());
    j.serve_for(Duration::from_secs(3)).await;
    mark("gone");
    let peers = node.handle.connected_peers.clone();
    ensure!(wait_until(15, || peers.load(Ordering::Relaxed) == 0).await, "the banned peer is still connected");
    tokio::time::sleep(Duration::from_millis(500)).await;
    mark("end");
    Ok(())
}

#[test]
fn one_headers_answer_of_refused_headers_writes_a_bounded_number_of_lines() {
    if in_child(junk_headers_child) {
        return;
    }
    let stdout = run_child("one_headers_answer_of_refused_headers_writes_a_bounded_number_of_lines");
    let (lines, names) = phases(&stdout);
    let j = &names["j"];
    let all: Vec<&str> = lines.iter().filter(|(p, l)| (p == "answer" || p == "gone") && !node_own(l)).map(|(_, l)| l.as_str()).collect();
    eprintln!("[measure] one Headers answer of 1,024 headers past the PoW limit: {} node lines", all.len());
    for l in &all {
        eprintln!("[measure]   {l}");
    }
    assert!(all.len() <= 16, "one answer of refused headers wrote {} lines", all.len());

    // The paired honest path: the first refusal and strike are printed at once, and the quarantine
    // and the ban each once; the rest is counted on the disconnect line.
    let one = |pat: &str| all.iter().filter(|l| l.contains(pat) && l.contains(j.as_str())).count();
    assert_eq!(one("ignoring header bits beyond pow limit"), 1, "{all:?}");
    assert_eq!(one("headers: invalid pow/limit/universe (invalid_in_window=1) since_last_line=1"), 1, "{all:?}");
    assert_eq!(one("quarantining peer"), 1, "{all:?}");
    assert_eq!(one("banning peer"), 1, "{all:?}");
    let gone: Vec<&&str> = all.iter().filter(|l| l.contains(&format!("{j} disconnected"))).collect();
    assert_eq!(gone.len(), 1, "{all:?}");
    assert_eq!(named(gone[0], "refused-header"), 1_023, "{}", gone[0]);
    assert_eq!(named(gone[0], "invalid"), 1_023, "{}", gone[0]);
}

// ---------------------------------------------------------------------------------------------------
// A peer gone with events not printed: the poll tick names them once its lines are a minute old.

/// GetTips the peer sends after it comes back, all counted, none printed.
const BACK_TIPS: usize = 3;
/// How long the peer stays away: a minute after its last line, the poll tick's 5 s, and a margin.
const AWAY: Duration = Duration::from_secs(72);
/// Before this, no tick can find the peer's lines a minute old: its first disconnect line came
/// shortly before it went away.
const AWAY_EARLY: Duration = Duration::from_secs(45);

async fn away_child() -> Result<()> {
    let tmp = TempDir::new()?;
    let db = Arc::new(open_db(&tmp)?);
    let chain = build_base_chain_with_miner(&db, 3, START, [0x11; 20])?;
    let node = spawn_node_on(db, tmp, chain[0], vec![]).await?;
    let (addr, id) = (node.dial_addr(), node.handle.peer_id);
    let peers = node.handle.connected_peers.clone();
    let key = identity::Keypair::generate_ed25519();

    // Its first connection: one GetTip printed, the second named by its disconnect line.
    mark("first");
    let mut p = Requester::connect_as(key.clone(), addr.clone(), id, None, not_served).await.expect("p connects");
    println!("{MARK}names p={}", p.id());
    for _ in 0..2 {
        ensure!(matches!(p.ask(SyncRequest::GetTip).await, SyncResponse::Tip { .. }), "p's GetTip");
    }
    drop(p);
    ensure!(wait_until(10, || peers.load(Ordering::Relaxed) == 0).await, "p is still connected");
    tokio::time::sleep(Duration::from_millis(300)).await;

    // Back as itself within the minute: its connect and GetTips are counted, and its disconnect line
    // is not due again, so they are left unprinted when it goes.
    mark("back");
    let mut p = Requester::connect_as(key, addr, id, None, not_served).await.expect("p comes back");
    for _ in 0..BACK_TIPS {
        ensure!(matches!(p.ask(SyncRequest::GetTip).await, SyncResponse::Tip { .. }), "p's GetTip after it came back");
    }
    drop(p);
    ensure!(wait_until(10, || peers.load(Ordering::Relaxed) == 0).await, "p is still connected");

    // It stays away.
    mark("away");
    tokio::time::sleep(AWAY_EARLY).await;
    mark("away-late");
    tokio::time::sleep(AWAY - AWAY_EARLY).await;
    mark("end");
    Ok(())
}

#[test]
fn a_peer_gone_with_events_not_printed_has_them_named_by_the_poll_tick_a_minute_after_its_last_line() {
    if in_child(away_child) {
        return;
    }
    let stdout = run_child("a_peer_gone_with_events_not_printed_has_them_named_by_the_poll_tick_a_minute_after_its_last_line");
    let (lines, names) = phases(&stdout);
    let p = &names["p"];
    let of = |phase: &str, pat: &str| -> Vec<&str> {
        lines.iter().filter(|(ph, l)| ph == phase && l.contains(pat)).map(|(_, l)| l.as_str()).collect()
    };
    for (_, l) in lines.iter().filter(|(_, l)| l.contains(p.as_str())) {
        eprintln!("[measure]   {l}");
    }

    // The setup: its first disconnect line named the second GetTip, and when it went again within
    // the minute no disconnect line was due, so its events stayed in its entry.
    let first = of("first", &format!("{p} disconnected"));
    assert_eq!(first.len(), 1, "{first:?}");
    assert_eq!(named(first[0], "GetTip"), 1, "{}", first[0]);
    let back = of("back", &format!("{p} disconnected"));
    assert!(back.is_empty(), "a second disconnect line within the minute: {back:?}");

    // The poll tick: once its lines are a minute old it drops the entry and names what was not
    // printed, its GetTips and its connect after it came back. Not before: the entry outlives the
    // disconnect.
    let gone_pat = format!("[p2p] {p} gone; not printed since its last lines:");
    assert!(of("away", &gone_pat).is_empty(), "the entry went before its lines were a minute old: {:?}", of("away", &gone_pat));
    let gone = of("away-late", &gone_pat);
    assert_eq!(gone.len(), 1, "no line from the poll tick for the gone peer within {AWAY:?}: {:?}", of("away-late", p));
    assert_eq!(named(gone[0], "GetTip"), BACK_TIPS as u64, "{}", gone[0]);
    assert_eq!(named(gone[0], "connect"), 1, "{}", gone[0]);
}
