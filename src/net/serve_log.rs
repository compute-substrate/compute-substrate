//! The sampler for every log line a remote peer can drive at will: its requests
//! and our answers, its gossip's refusals, its strikes, bans and quarantines, its connections and
//! evictions, our requests to it and its answers, the addresses it gives us and our dials to them
//! (docs/behaviour.md "Peer-driven log lines"). Upstream prints each at every event, and the lines
//! can spend journald's rate-limit burst, so that the lines an operator's alert reads are dropped.
//!
//! Per peer and kind (`Line`), upstream's rule for GetTip's line (`GETTIP_LOG_EVERY_SECS`, v1.1.2
//! and d168f70 `src/net/node.rs`): a peer's first line of a kind at once, then at most one a minute,
//! carrying the kind's events since its last line, this one included. At a peer's last disconnect
//! one line names its events not printed, at most once a minute; its entry stays until its lines are
//! a minute old (`prune`), so a reconnect does not start its minute again. Nothing is hidden, only
//! counted.
//!
//! Fresh identities each have a first line, so the rule alone does not bound one address that churns
//! them; the ceiling does: at most PEER_LINES_PER_MINUTE lines a window, all peers and kinds
//! together, a line past it held back and its events named by the next window's first line. A peer
//! gets an entry only if the window has room; one stays while connected or with a line due, printed
//! or held, in the last minute.
//!
//! One sampler for the process (`PEER_LINES`): the ceiling bounds the process's journal, and the lines
//! are printed where upstream printed them, in the loop, its helpers and the serves on the blocking
//! pool. Not taken here: lines counted at powers of two (`log_due`), lines a peer pays proof of work
//! for, the poll tick's own lines, and the RPC's.

use std::collections::HashMap;
use std::sync::{LazyLock, Mutex};
use std::time::{Duration, Instant};

use libp2p::PeerId;

use super::proto::SyncRequest;

/// A peer's line of one kind comes at most this often (upstream's `GETTIP_LOG_EVERY_SECS`), and the
/// ceiling counts lines in windows of this length.
pub(crate) const SERVE_LOG_EVERY: Duration = Duration::from_secs(60);

/// Lines the sampler prints in one window, all peers and kinds together: 3.3 times the busiest
/// minute of an hour of a mainnet node's journal replayed under the per-peer rule (180), and a
/// ninth of a journald rate limit of 5,400 lines a minute, which leaves the node's other lines
/// room.
pub(crate) const PEER_LINES_PER_MINUTE: u32 = 600;

/// The kinds of peer-driven lines, each sampled on its own per peer.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Line {
    /// A request's recv line, and the lines its serve prints with it.
    GetTip,
    GetHeaders,
    GetHeadersByLocator,
    GetBlock,
    SubmitTx,
    GetPeers,
    /// A GetBlock for a block we do not store.
    Miss,
    /// Any other Err answer to a request.
    ErrorAnswer,
    /// `[p2p] invalid from`: a strike.
    Invalid,
    /// A header refused for its genesis, bits or PoW (gossip, a Headers answer, a block).
    RefusedHeader,
    /// A gossip header whose parent we lack.
    ParentUnknown,
    Ban,
    Quarantine,
    /// A peer's connection opening (or refused at the hard cap).
    Connect,
    /// An eviction or shed of the peer's connection.
    Evict,
    /// Our background request to the peer.
    Asked,
    /// Its answers to our requests: Tip, Headers, Peers, Block, an Err, a failed request.
    Tip,
    Headers,
    Peers,
    Block,
    ErrorReply,
    OutboundFailure,
    /// The peer made our sync peer.
    SyncPeer,
    /// An address of the peer learned from its identify.
    LearnedAddr,
    /// Our dial to the peer, and its failure.
    Dial,
    DialFailure,
    /// The line naming a peer's events not printed when its last connection closes.
    Gone,
}

const LINES: usize = 27;

const NAMES: [&str; LINES] = [
    "GetTip",
    "GetHeaders",
    "GetHeadersByLocator",
    "GetBlock",
    "SubmitTx",
    "GetPeers",
    "MISS",
    "error-answer",
    "invalid",
    "refused-header",
    "parent-unknown",
    "ban",
    "quarantine",
    "connect",
    "evict",
    "asked",
    "tip",
    "headers",
    "peers",
    "block",
    "error-reply",
    "outbound-failure",
    "sync-peer",
    "learned-addr",
    "dial",
    "dial-failure",
    "gone",
];

impl Line {
    /// The kind of a request's recv line.
    pub(crate) fn of(req: &SyncRequest) -> Line {
        match req {
            SyncRequest::GetTip => Line::GetTip,
            SyncRequest::GetHeaders { .. } => Line::GetHeaders,
            SyncRequest::GetHeadersByLocator { .. } => Line::GetHeadersByLocator,
            SyncRequest::GetBlock { .. } => Line::GetBlock,
            SyncRequest::SubmitTx { .. } => Line::SubmitTx,
            SyncRequest::GetPeers { .. } => Line::GetPeers,
        }
    }

    /// The kind as the lines name it.
    pub(crate) fn name(self) -> &'static str {
        NAMES[self as usize]
    }

    /// The lines one printed event of the kind writes at most: a GetBlock's recv, lookup and HIT, a
    /// locator's recv and anchor, a failed request's failure and requeue.
    fn lines(self) -> u32 {
        match self {
            Line::GetBlock => 3,
            Line::GetHeadersByLocator | Line::OutboundFailure => 2,
            _ => 1,
        }
    }
}

#[derive(Clone, Copy, Default)]
struct KindLog {
    last_line: Option<Instant>,
    /// Events of the kind since its last line.
    since: u64,
}

#[derive(Default)]
pub(crate) struct ServeLog {
    peers: HashMap<PeerId, [KindLog; LINES]>,
    /// Start of the ceiling's current window.
    window: Option<Instant>,
    /// Lines printed in it.
    printed: u32,
    /// Lines the ceiling held back in it, and the events they stood for, by kind.
    held_lines: u64,
    held: [u64; LINES],
}

impl ServeLog {
    /// Starts the next window once SERVE_LOG_EVERY has passed since this one began; returns the line
    /// naming what the ceiling held back in the window that ended, if it held any.
    pub(crate) fn roll(&mut self, now: Instant) -> Option<String> {
        if self.window.is_some_and(|t| now.saturating_duration_since(t) < SERVE_LOG_EVERY) {
            return None;
        }
        self.window = Some(now);
        self.printed = 0;
        let held_lines = std::mem::take(&mut self.held_lines);
        let held = std::mem::take(&mut self.held);
        (held_lines > 0).then(|| {
            let total: u64 = held.iter().sum();
            format!(
                "[p2p] peer lines past the ceiling of {PEER_LINES_PER_MINUTE} a minute: {held_lines} not printed, for {total} events: {}",
                named(&held)
            )
        })
    }

    /// Whether a due line is printed: false once the window's ceiling is reached, its events then
    /// counted for the window's summary.
    fn admit(&mut self, line: Line, events: u64) -> bool {
        self.admit_lines(line.lines(), &[(line, events)])
    }

    /// `lines` printed for `events`, or none of them.
    fn admit_lines(&mut self, lines: u32, events: &[(Line, u64)]) -> bool {
        if self.printed + lines <= PEER_LINES_PER_MINUTE {
            self.printed += lines;
            return true;
        }
        self.held_lines += 1;
        for (line, n) in events {
            self.held[*line as usize] += n;
        }
        false
    }

    /// Counts one event of `line` from `peer` at `now`. Its line is due when it is the peer's first of
    /// its kind or SERVE_LOG_EVERY has passed since the kind's last line; then, when the ceiling has
    /// room, returns the events of the kind since that line, this one included.
    pub(crate) fn due(&mut self, peer: PeerId, line: Line, now: Instant) -> Option<u64> {
        if !self.peers.contains_key(&peer) && self.printed + line.lines() > PEER_LINES_PER_MINUTE {
            // No entry past the ceiling: a new peer's first line would be due.
            self.admit(line, 1);
            return None;
        }
        let k = &mut self.peers.entry(peer).or_default()[line as usize];
        k.since += 1;
        if k.last_line.is_some_and(|t| now.saturating_duration_since(t) < SERVE_LOG_EVERY) {
            return None;
        }
        k.last_line = Some(now);
        let n = std::mem::take(&mut k.since);
        self.admit(line, n).then_some(n)
    }

    /// At the close of `peer`'s last connection: the line naming its events not printed since its last
    /// lines, if it has any and its last such line is a minute old. The entry stays (`prune`).
    pub(crate) fn gone(&mut self, peer: &PeerId, now: Instant) -> Option<String> {
        let kinds = self.peers.get_mut(peer)?;
        let gone = &mut kinds[Line::Gone as usize];
        if gone.last_line.is_some_and(|t| now.saturating_duration_since(t) < SERVE_LOG_EVERY) {
            return None;
        }
        let events = take_unprinted(kinds);
        if events.is_empty() {
            return None;
        }
        kinds[Line::Gone as usize].last_line = Some(now);
        self.admit_lines(1, &events).then(|| format!("[p2p] {peer} disconnected; not printed since its last lines: {}", listed(&events)))
    }

    /// Drops the entries of peers not connected whose lines are all a minute old; returns a line for
    /// each that still had events not printed.
    pub(crate) fn prune(&mut self, now: Instant, connected: impl Fn(&PeerId) -> bool) -> Vec<String> {
        let stale: Vec<PeerId> = self
            .peers
            .iter()
            .filter(|(p, kinds)| {
                !connected(p)
                    && kinds.iter().all(|k| k.last_line.is_none_or(|t| now.saturating_duration_since(t) >= SERVE_LOG_EVERY))
            })
            .map(|(p, _)| *p)
            .collect();
        let mut out = Vec::new();
        for p in stale {
            let Some(mut kinds) = self.peers.remove(&p) else { continue };
            let events = take_unprinted(&mut kinds);
            if !events.is_empty() && self.admit_lines(1, &events) {
                out.push(format!("[p2p] {p} gone; not printed since its last lines: {}", listed(&events)));
            }
        }
        out
    }
}

fn take_unprinted(kinds: &mut [KindLog; LINES]) -> Vec<(Line, u64)> {
    const ALL: [Line; LINES] = [
        Line::GetTip,
        Line::GetHeaders,
        Line::GetHeadersByLocator,
        Line::GetBlock,
        Line::SubmitTx,
        Line::GetPeers,
        Line::Miss,
        Line::ErrorAnswer,
        Line::Invalid,
        Line::RefusedHeader,
        Line::ParentUnknown,
        Line::Ban,
        Line::Quarantine,
        Line::Connect,
        Line::Evict,
        Line::Asked,
        Line::Tip,
        Line::Headers,
        Line::Peers,
        Line::Block,
        Line::ErrorReply,
        Line::OutboundFailure,
        Line::SyncPeer,
        Line::LearnedAddr,
        Line::Dial,
        Line::DialFailure,
        Line::Gone,
    ];
    ALL.iter()
        .zip(kinds.iter_mut())
        .filter(|(_, k)| k.since > 0)
        .map(|(line, k)| (*line, std::mem::take(&mut k.since)))
        .collect()
}

fn listed(events: &[(Line, u64)]) -> String {
    events.iter().map(|(line, n)| format!("{}={n}", line.name())).collect::<Vec<_>>().join(" ")
}

fn named(counts: &[u64; LINES]) -> String {
    NAMES.iter().zip(counts).filter(|(_, n)| **n > 0).map(|(name, n)| format!("{name}={n}")).collect::<Vec<_>>().join(" ")
}

static PEER_LINES: LazyLock<Mutex<ServeLog>> = LazyLock::new(|| Mutex::new(ServeLog::default()));

fn with_log<T>(f: impl FnOnce(&mut ServeLog, Instant) -> T) -> (Option<String>, T) {
    let now = Instant::now();
    let mut log = PEER_LINES.lock().unwrap_or_else(|e| e.into_inner());
    let summary = log.roll(now);
    let out = f(&mut log, now);
    (summary, out)
}

/// Whether `peer`'s line of `line` is printed now (`ServeLog::due`): Some(the events it stands for).
/// Prints the summary of the window that ended first, when there is one.
pub(crate) fn peer_line(peer: &PeerId, line: Line) -> Option<u64> {
    let (summary, n) = with_log(|log, now| log.due(*peer, line, now));
    if let Some(s) = summary {
        println!("{s}");
    }
    n
}

/// At the close of `peer`'s last connection (`ServeLog::gone`).
pub(crate) fn peer_gone(peer: &PeerId) {
    let (summary, line) = with_log(|log, now| log.gone(peer, now));
    for l in summary.into_iter().chain(line) {
        println!("{l}");
    }
}

/// At the poll tick: the summary of a window that ended with no line since, and `ServeLog::prune`.
pub(crate) fn peer_lines_tick(connected: impl Fn(&PeerId) -> bool) {
    let (summary, lines) = with_log(|log, now| log.prune(now, connected));
    for l in summary.into_iter().chain(lines) {
        println!("{l}");
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn at(t0: Instant, ms: u64) -> Instant {
        t0 + Duration::from_millis(ms)
    }

    // The minute the live test (tests/p2p_live_serve_log.rs) does not wait for: a kind's line is due
    // again SERVE_LOG_EVERY after its last, and carries every event since.
    #[test]
    fn a_kinds_line_is_due_at_once_then_a_minute_after_its_last_with_the_events_since() {
        let mut log = ServeLog::default();
        let (p, q, t0) = (PeerId::random(), PeerId::random(), Instant::now());
        let block = Line::of(&SyncRequest::GetBlock { hash: [1; 32] });
        assert_eq!(log.due(p, block, t0), Some(1));
        for i in 1..1_200 {
            assert_eq!(log.due(p, block, at(t0, i * 8)), None, "request {i}");
        }
        assert_eq!(log.due(p, Line::GetTip, at(t0, 1_000)), Some(1), "each kind keeps its own minute");
        assert_eq!(log.due(p, Line::Miss, at(t0, 1_000)), Some(1), "a MISS is a kind of its own");
        assert_eq!(log.due(p, Line::Miss, at(t0, 1_001)), None, "and is counted within its minute");
        assert_eq!(log.due(q, block, at(t0, 1_000)), Some(1), "and each peer");
        assert_eq!(log.due(p, block, at(t0, 59_999)), None);
        assert_eq!(log.due(p, block, t0 + SERVE_LOG_EVERY), Some(1_201), "the 1,199 unlogged and this one");
        assert_eq!(log.due(p, block, at(t0, 60_001)), None);

        let line = log.gone(&p, at(t0, 61_000)).expect("a GetBlock and a MISS are not printed yet");
        assert!(line.contains(&format!("{p} disconnected")) && line.ends_with(": GetBlock=1 MISS=1"), "{line}");
        assert_eq!(log.gone(&q, at(t0, 61_000)), None, "a peer with nothing unprinted leaves no line");
    }

    // A reconnect within the minute does not start the peer's lines again, and its disconnect line comes
    // at most once a minute; the entry goes once its lines are a minute old and it is not connected.
    #[test]
    fn a_peer_that_reconnects_keeps_its_minute_and_its_entry_goes_a_minute_after_its_last_line() {
        let mut log = ServeLog::default();
        let (p, t0) = (PeerId::random(), Instant::now());
        assert_eq!(log.due(p, Line::Connect, t0), Some(1));
        assert_eq!(log.due(p, Line::GetTip, t0), Some(1));
        assert_eq!(log.gone(&p, at(t0, 100)), None, "nothing unprinted");
        for i in 1..=100u64 {
            assert_eq!(log.due(p, Line::Connect, at(t0, 100 + i * 100)), None, "reconnect {i}");
            assert_eq!(log.due(p, Line::GetTip, at(t0, 100 + i * 100)), None, "reconnect {i}");
            let gone = log.gone(&p, at(t0, 150 + i * 100));
            assert_eq!(gone.is_some(), i == 1, "reconnect {i}: {gone:?}");
        }
        assert_eq!(log.prune(at(t0, 30_000), |_| false), Vec::<String>::new(), "lines under a minute old");
        assert_eq!(log.peers.len(), 1);
        let flushed = log.prune(at(t0, 70_000), |_| false);
        assert_eq!(flushed.len(), 1, "{flushed:?}");
        assert!(flushed[0].ends_with(": GetTip=99 connect=99"), "{flushed:?}");
        assert!(log.peers.is_empty());

        let q = PeerId::random();
        assert_eq!(log.due(q, Line::GetTip, at(t0, 70_000)), Some(1));
        assert!(log.prune(at(t0, 200_000), |p| *p == q).is_empty(), "a connected peer keeps its entry");
        assert_eq!(log.peers.len(), 1);
    }

    // Fresh identities: past the ceiling a line is held back and counted, a new peer gets no entry,
    // and the next window starts with the line naming what was held.
    #[test]
    fn past_the_ceiling_lines_are_held_and_counted_and_new_peers_get_no_entry() {
        let mut log = ServeLog::default();
        let t0 = Instant::now();
        assert_eq!(log.roll(t0), None);
        let ceiling = PEER_LINES_PER_MINUTE as usize;
        let mut printed = 0;
        for i in 0..ceiling + 500 {
            let p = PeerId::random();
            printed += usize::from(log.due(p, Line::Connect, at(t0, i as u64)).is_some());
        }
        assert_eq!(printed, ceiling);
        assert_eq!(log.peers.len(), ceiling, "no entry past the ceiling");
        // A peer with an entry: its due line is held, its events counted once.
        let p = *log.peers.keys().next().unwrap();
        assert_eq!(log.due(p, Line::GetTip, at(t0, 2_000)), None);
        assert_eq!(log.roll(at(t0, 59_999)), None, "the window has not ended");
        let summary = log.roll(t0 + SERVE_LOG_EVERY).expect("lines were held");
        assert!(summary.ends_with(": 501 not printed, for 501 events: GetTip=1 connect=500"), "{summary}");
        // The ceiling counts lines: a GetBlock printed writes three.
        let blocks = (0..ceiling).filter(|_| log.due(PeerId::random(), Line::GetBlock, t0 + SERVE_LOG_EVERY).is_some()).count();
        assert_eq!(blocks, ceiling / 3, "a new window has room for {} GetBlock lines", ceiling / 3);
        assert_eq!(log.printed, PEER_LINES_PER_MINUTE);
        assert_eq!(log.roll(at(t0, 61_000)), None);
    }
}
