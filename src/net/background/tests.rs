//! Honest and hostile request schedules, run on the real scheduler
//! the way node.rs drives it: `schedule` at every 5 s tick and whenever demand is recorded, each
//! answer settling after its peer's own delay. Gaps are measured from the previous request of the
//! same kind.

use super::*;

const TICK_MS: u64 = 5_000;
const STEP_MS: u64 = 100;

/// The per-peer bound, in ms: a peer that answers within `r_ms`, with `owed` kinds owed (at most
/// 3), sends a kind at most owed x (r + T + w) after its effective due time, T the 5 s tick (the
/// longest a free slot waits for a scheduler run) and `w_ms` the cross-peer wait: when the kind
/// falls due one request may be in flight, and each other owed kind due earlier goes once first.
/// The effective due time is a tip's period after the last (10 s), headers' max(owed, last
/// headers + 20 s), peers' owed time; so a kind of period `period_s` is sent at most
/// period + owed x (r + T + w) after the previous one of its kind.
fn per_peer_bound_ms(period_s: u64, owed: u64, r_ms: u64, w_ms: u64) -> u64 {
    period_s * 1000 + owed * (r_ms + TICK_MS + w_ms)
}

/// The cross-peer wait, in ms, counted over all `contenders`: every peer holding an outstanding
/// request, eligible or not (a quarantined peer keeps its slot until its request settles), and
/// every eligible peer that can fall due in the wait, each holding at most one request. With no
/// more than CEILING a place is always free,
/// so 0 beyond the next scheduler run (the T already in the per-peer bound); with more, within
/// ceil(contenders / CEILING) x (R + T), R the longest any request is held (the transport's limit
/// is about 25 s), since places go to the peer waiting longest since its last request, one per
/// peer, and every place frees within R and is refilled within T.
fn cross_peer_wait_ms(contenders: usize, hold_ms: u64) -> u64 {
    if contenders <= CEILING {
        return 0;
    }
    contenders.div_ceil(CEILING) as u64 * (hold_ms + TICK_MS)
}

struct Sim {
    b: Background<u64>,
    start: Instant,
    ms: u64,
    next: u64,
    pending: Vec<(u64, PeerId, Asked, u64)>,
    log: Vec<(u64, PeerId, Asked)>,
    most_in_flight: usize,
    /// For `watch`, the longest cross-peer admission wait: from the first 100 ms step at which it is
    /// free with a request due to its send, counted every step, so a wait still open at the end
    /// counts too.
    watch: Option<PeerId>,
    ready_since: Option<u64>,
    longest_admission_ms: u64,
}

impl Sim {
    fn new() -> Self {
        let b = Background::new(Duration::from_secs(10), Duration::from_secs(20), Duration::from_secs(60), CEILING);
        Sim { b, start: Instant::now(), ms: 0, next: 0, pending: Vec::new(), log: Vec::new(), most_in_flight: 0, watch: None, ready_since: None, longest_admission_ms: 0 }
    }

    fn now(&self) -> Instant {
        self.start + Duration::from_millis(self.ms)
    }

    fn pump(&mut self, eligible: &[PeerId], answer_ms: &dyn Fn(&PeerId, Asked) -> u64) {
        let now = self.now();
        for (p, kind) in self.b.schedule(eligible, now, false) {
            if Some(p) == self.watch {
                if let Some(since) = self.ready_since.take() {
                    self.longest_admission_ms = self.longest_admission_ms.max(self.ms - since);
                }
            }
            self.next += 1;
            self.b.sent(self.next, p, kind, now);
            self.pending.push((self.next, p, kind, self.ms + answer_ms(&p, kind)));
            self.log.push((self.ms, p, kind));
        }
        self.most_in_flight = self.most_in_flight.max(self.b.in_flight());
    }

    /// Runs to `until_s` as node.rs does: a scheduler run at each tick, when the eligible set
    /// changes (a connect), after a non-Tip answer frees a slot (before its contents are handled),
    /// and when `answered` records demand and returns true (as the Tip arm does); `tick` runs before
    /// each tick's run.
    fn run(
        &mut self,
        until_s: u64,
        eligible: &dyn Fn(u64) -> Vec<PeerId>,
        answer_ms: &dyn Fn(&PeerId, Asked) -> u64,
        answered: &mut dyn FnMut(&mut Background<u64>, PeerId, Asked, Instant) -> bool,
        tick: &mut dyn FnMut(&mut Background<u64>, u64, Instant),
    ) {
        let mut before: Vec<PeerId> = Vec::new();
        while self.ms <= until_s * 1000 {
            let peers = eligible(self.ms);
            let due: Vec<(u64, PeerId, Asked, u64)> = self.pending.iter().filter(|e| e.3 <= self.ms).copied().collect();
            self.pending.retain(|e| e.3 > self.ms);
            let now = self.now();
            for (rid, p, kind, _) in due {
                if self.b.settle(&rid).is_some() {
                    if kind != Asked::Tip {
                        self.pump(&peers, answer_ms);
                    }
                    if answered(&mut self.b, p, kind, now) {
                        self.pump(&peers, answer_ms);
                    }
                }
            }
            if let Some(w) = self.watch.filter(|w| peers.contains(w)) {
                if self.b.next_for(&w, now, false).is_some() {
                    let since = *self.ready_since.get_or_insert(self.ms);
                    self.longest_admission_ms = self.longest_admission_ms.max(self.ms - since);
                }
            }
            if self.ms % TICK_MS == 0 {
                tick(&mut self.b, self.ms, now);
                self.b.expire(now);
                self.pump(&peers, answer_ms);
            } else if peers != before {
                self.pump(&peers, answer_ms);
            }
            before = peers;
            self.ms += STEP_MS;
        }
    }

    /// Send times in ms of `kind` to `p`.
    fn times(&self, p: &PeerId, kind: Asked) -> Vec<u64> {
        self.log.iter().filter(|(_, q, k)| q == p && *k == kind).map(|(t, _, _)| *t).collect()
    }
}

fn max_gap(at: &[u64]) -> u64 {
    at.windows(2).map(|w| w[1] - w[0]).max().unwrap_or(u64::MAX)
}

fn nothing(_: &mut Background<u64>, _: PeerId, _: Asked, _: Instant) -> bool {
    false
}

fn no_tick(_: &mut Background<u64>, _: u64, _: Instant) {}

// One peer answering every request in 10.1 s is owed peers from its bootstrap and again
// at each identify exchange (every 30 s). Strict priority would send a GetTip every time its slot
// freed and never the peers request. Two kinds owed: each within 2 x (10.1 + 5) s of falling due.
#[test]
fn a_slow_peer_still_gets_its_owed_peers_request() {
    let p = PeerId::random();
    let r = 10_100;
    let mut sim = Sim::new();
    sim.b.want(p, Asked::Peers, sim.now());
    let mut identify = |b: &mut Background<u64>, ms: u64, now: Instant| {
        if ms % 30_000 == 0 {
            b.want(p, Asked::Peers, now);
        }
    };
    sim.run(600, &|_| vec![p], &|_, _| r, &mut nothing, &mut identify);
    let peers = sim.times(&p, Asked::Peers);
    assert!(!peers.is_empty(), "the owed peers request was never sent");
    assert!(peers[0] <= per_peer_bound_ms(0, 2, r, 0), "first peers request at {} ms", peers[0]);
    assert!(peers.len() >= 15, "peers requests in 600 s: {}", peers.len());
    let tips = sim.times(&p, Asked::Tip);
    assert!(max_gap(&tips) <= per_peer_bound_ms(10, 2, r, 0), "tip gap {} s: {tips:?}", max_gap(&tips));
}

// One heavier peer answering in 14 s is owed headers after every Tip answer, and a
// parent-unknown gossip header owes them again at 20 s. Two kinds owed: a GetTip at most
// 10 + 2 x 19 = 48 s after the last, headers at most 58 s.
#[test]
fn a_heavier_peer_answering_in_14_s_gets_both_kinds_within_the_bound() {
    let p = PeerId::random();
    let r = 14_000;
    let mut sim = Sim::new();
    let mut heavier = |b: &mut Background<u64>, q: PeerId, kind: Asked, now: Instant| {
        if kind == Asked::Tip {
            b.want(q, Asked::Headers, now);
            return true;
        }
        false
    };
    let mut gossip = |b: &mut Background<u64>, ms: u64, now: Instant| {
        if ms == 20_000 {
            b.want(p, Asked::Headers, now);
        }
    };
    sim.run(600, &|_| vec![p], &|_, _| r, &mut heavier, &mut gossip);
    let (tips, headers) = (sim.times(&p, Asked::Tip), sim.times(&p, Asked::Headers));
    assert!(max_gap(&tips) <= per_peer_bound_ms(10, 2, r, 0), "tip gap {}: {tips:?}", max_gap(&tips));
    assert!(max_gap(&headers) <= per_peer_bound_ms(20, 2, r, 0), "headers gap {}: {headers:?}", max_gap(&headers));
}

// Headers owed again after every answer, answers in 20.1 s. Strict headers priority would send
// one GetTip and 25 headers requests in 600 s. Two kinds owed: a GetTip at most 10 + 2 x 25.1 s
// after the last.
#[test]
fn refreshed_headers_demand_does_not_starve_the_peers_tip_polls() {
    let p = PeerId::random();
    let r = 20_100;
    let mut sim = Sim::new();
    let mut refresh = |b: &mut Background<u64>, q: PeerId, _: Asked, now: Instant| {
        b.want(q, Asked::Headers, now);
        true
    };
    sim.run(600, &|_| vec![p], &|_, _| r, &mut refresh, &mut no_tick);
    let (tips, headers) = (sim.times(&p, Asked::Tip), sim.times(&p, Asked::Headers));
    assert!(max_gap(&tips) <= per_peer_bound_ms(10, 2, r, 0), "tip gap {}: {tips:?}", max_gap(&tips));
    assert!(max_gap(&headers) <= per_peer_bound_ms(20, 2, r, 0), "headers gap {}: {headers:?}", max_gap(&headers));
    assert!(tips.len() as u64 >= 600_000 / per_peer_bound_ms(10, 2, r, 0), "tips in 600 s: {}", tips.len());
}

// Three kinds owed at once, answers in 4 s: each within its period plus 3 x 9 s.
#[test]
fn three_owed_kinds_take_turns() {
    let p = PeerId::random();
    let r = 4_000;
    let mut sim = Sim::new();
    let mut all = |b: &mut Background<u64>, q: PeerId, _: Asked, now: Instant| {
        b.want(q, Asked::Headers, now);
        b.want(q, Asked::Peers, now);
        false
    };
    sim.run(600, &|_| vec![p], &|_, _| r, &mut all, &mut no_tick);
    for (kind, period) in [(Asked::Tip, 10), (Asked::Headers, 20)] {
        let at = sim.times(&p, kind);
        assert!(max_gap(&at) <= per_peer_bound_ms(period, 3, r, 0), "{kind:?} gap {}: {at:?}", max_gap(&at));
    }
    assert!(sim.times(&p, Asked::Peers).len() >= 20);
}

// 21 peers (a mainnet node's count), answers in 0.1 s, past the ceiling: each GetTip within
// 10 s + (0.1 + 5 + ceil(21 / 16) x 5.1) s of the last.
#[test]
fn every_peer_is_tip_polled_within_the_bound_past_the_ceiling() {
    for n in [9usize, 21] {
        let peers: Vec<PeerId> = (0..n).map(|_| PeerId::random()).collect();
        let mut sim = Sim::new();
        let all = peers.clone();
        sim.run(240, &|_| all.clone(), &|_, _| 100, &mut nothing, &mut no_tick);
        for p in &peers {
            let at = sim.times(p, Asked::Tip);
            assert!(max_gap(&at) <= per_peer_bound_ms(10, 1, 100, cross_peer_wait_ms(n, 100)), "n={n}: {at:?}");
        }
        assert!(sim.most_in_flight <= CEILING);
    }
}

// Hostile peers that hold every request to the transport's 25 s and are owed
// headers again at once (8 of them, then 4), and an honest peer answering in 0.1 s that is owed
// headers after each Tip answer. Under the ceiling the honest peer waits on nobody: a GetTip within
// 10 + 2 x 5.1 s of the last, headers within 20 + 2 x 5.1 s.
#[test]
fn peers_holding_their_requests_do_not_delay_another() {
    for hostile_n in [8usize, 4] {
        let hostile: Vec<PeerId> = (0..hostile_n).map(|_| PeerId::random()).collect();
        let honest = PeerId::random();
        let mut sim = Sim::new();
        let all: Vec<PeerId> = hostile.iter().copied().chain([honest]).collect();
        for p in &hostile {
            sim.b.want(*p, Asked::Headers, sim.now());
        }
        let h = hostile.clone();
        let mut owe = |b: &mut Background<u64>, q: PeerId, kind: Asked, now: Instant| {
            if h.contains(&q) || kind == Asked::Tip {
                b.want(q, Asked::Headers, now);
                return true;
            }
            false
        };
        let answer = |q: &PeerId, _: Asked| if *q == honest { 100 } else { 25_000 };
        sim.run(600, &|_| all.clone(), &answer, &mut owe, &mut no_tick);
        let (tips, headers) = (sim.times(&honest, Asked::Tip), sim.times(&honest, Asked::Headers));
        assert!(max_gap(&tips) <= per_peer_bound_ms(10, 2, 100, 0), "hostile={hostile_n}: {tips:?}");
        assert!(max_gap(&headers) <= per_peer_bound_ms(20, 2, 100, 0), "hostile={hostile_n}: {headers:?}");
    }
}

// Four peers reconnect every 10 s (forgotten, then owed a peers request as on connect)
// and hold each request to the end of their connection; the honest peer is polled every 10 s.
#[test]
fn reconnecting_peers_do_not_delay_another() {
    let hostile: Vec<PeerId> = (0..4).map(|_| PeerId::random()).collect();
    let honest = PeerId::random();
    let mut sim = Sim::new();
    let all: Vec<PeerId> = hostile.iter().copied().chain([honest]).collect();
    let h = hostile.clone();
    let mut reconnect = |b: &mut Background<u64>, ms: u64, now: Instant| {
        if ms % 10_000 == 0 {
            for p in &h {
                b.forget(p);
                b.want(*p, Asked::Peers, now);
            }
        }
    };
    let answer = |q: &PeerId, _: Asked| if *q == honest { 100 } else { 60_000 };
    sim.run(600, &|_| all.clone(), &answer, &mut nothing, &mut reconnect);
    let tips = sim.times(&honest, Asked::Tip);
    assert!(max_gap(&tips) <= per_peer_bound_ms(10, 1, 100, 0), "{tips:?}");
}

// The admission allowance (connection cap 32 plus PEER_CAP_BURST 64): 95 hostile peers, each owed
// headers at once again and holding every request to 25 s, and one honest peer answering in 0.1 s
// that is owed headers after each Tip answer. At most CEILING requests are in flight, and the
// honest peer, whenever it is free with a request due, waits at most ceil(96 / 16) x 30 s = 180 s
// for a place. Every peer is also owed a peers request every 30 s, so three kinds are owed, and each
// kind's gap stays within its period + 3 x (0.1 + 5 + 180) s.
#[test]
fn ninety_six_peers_stay_under_the_ceiling_and_the_honest_one_is_served() {
    let mut peers: Vec<PeerId> = (0..96).map(|_| PeerId::random()).collect();
    peers.sort();
    let honest = *peers.last().unwrap();
    let hostile: Vec<PeerId> = peers[..95].to_vec();
    let mut sim = Sim::new();
    let all = peers.clone();
    let h = hostile.clone();
    let mut owe = |b: &mut Background<u64>, q: PeerId, kind: Asked, now: Instant| {
        if h.contains(&q) || kind == Asked::Tip {
            b.want(q, Asked::Headers, now);
            return true;
        }
        false
    };
    for p in &hostile {
        sim.b.want(*p, Asked::Headers, sim.now());
    }
    // Every peer is owed a peers request at each identify exchange, every 30 s.
    let everyone = all.clone();
    let mut identify = |b: &mut Background<u64>, ms: u64, now: Instant| {
        if ms % 30_000 == 0 {
            for p in &everyone {
                b.want(*p, Asked::Peers, now);
            }
        }
    };
    sim.watch = Some(honest);
    let answer = |q: &PeerId, _: Asked| if *q == honest { 100 } else { 25_000 };
    sim.run(1_800, &|_| all.clone(), &answer, &mut owe, &mut identify);
    assert!(sim.most_in_flight <= CEILING, "in flight {}", sim.most_in_flight);
    let wait = cross_peer_wait_ms(96, 25_000);
    assert_eq!(wait, 180_000);
    assert!(sim.longest_admission_ms <= wait, "the honest peer waited {} ms for a place", sim.longest_admission_ms);
    let (tips, headers, peers) =
        (sim.times(&honest, Asked::Tip), sim.times(&honest, Asked::Headers), sim.times(&honest, Asked::Peers));
    assert!(tips.first().is_some_and(|t| *t <= wait), "{tips:?}");
    for (kind, at, period) in [("tip", &tips, 10), ("headers", &headers, 20), ("peers", &peers, 30)] {
        assert!(at.len() >= 2 && max_gap(at) <= per_peer_bound_ms(period, 3, 100, wait), "{kind}: {at:?}");
    }
    let all_sends: Vec<u64> = sim.log.iter().filter(|(_, q, _)| *q == honest).map(|(t, _, _)| *t).collect();
    eprintln!(
        "[measure] 96 peers: honest request gap {} ms, longest admission {} ms; tip, headers, peers gaps {} / {} / {} ms",
        max_gap(&all_sends), sim.longest_admission_ms, max_gap(&tips), max_gap(&headers), max_gap(&peers)
    );
}

// One peer, step by step: polled and owed peers on connect, one request at a time, a headers
// cooldown, a stale tip polls at once, an expired request frees the peer, and a forgotten peer
// starts afresh.
#[test]
fn a_single_peer_gets_each_request_in_turn() {
    let p = PeerId::random();
    let t0 = Instant::now();
    let mut b: Background<u64> =
        Background::new(Duration::from_secs(10), Duration::from_secs(20), Duration::from_secs(60), CEILING);
    b.want(p, Asked::Peers, t0);
    assert_eq!(b.schedule(&[p], t0, false), vec![(p, Asked::Tip)], "first sight: the tip, ties to Tip");
    b.sent(1, p, Asked::Tip, t0);
    assert!(b.schedule(&[p], t0, false).is_empty(), "one in flight");
    assert_eq!(b.settle(&1), Some(Asked::Tip));
    assert_eq!(b.schedule(&[p], t0, false), vec![(p, Asked::Peers)]);
    b.sent(2, p, Asked::Peers, t0);
    b.settle(&2);
    b.want(p, Asked::Headers, t0);
    assert_eq!(b.schedule(&[p], t0, false), vec![(p, Asked::Headers)]);
    b.sent(3, p, Asked::Headers, t0);
    b.settle(&3);
    assert!(b.schedule(&[p], t0, false).is_empty(), "nothing owed, the tip not due");
    assert_eq!(b.schedule(&[p], t0, true), vec![(p, Asked::Tip)], "a stale tip polls at once");
    let t10 = t0 + Duration::from_secs(10);
    b.want(p, Asked::Headers, t10);
    assert_eq!(b.schedule(&[p], t10, false), vec![(p, Asked::Tip)], "headers in cooldown until 20");
    b.sent(5, p, Asked::Tip, t10);
    b.settle(&5);
    assert!(b.schedule(&[p], t0 + Duration::from_secs(15), false).is_empty());
    let t20 = t0 + Duration::from_secs(20);
    assert_eq!(b.schedule(&[p], t20, false), vec![(p, Asked::Tip)], "both due at 20: a tie goes to Tip");
    b.sent(6, p, Asked::Tip, t20);
    b.settle(&6);
    assert_eq!(b.schedule(&[p], t20, false), vec![(p, Asked::Headers)]);
    b.sent(4, p, Asked::Headers, t20);
    b.expire(t0 + Duration::from_secs(80));
    assert_eq!((b.in_flight(), b.settle(&4)), (0, None), "expired");
    b.forget(&p);
    assert_eq!(b.schedule(&[p], t0 + Duration::from_secs(80), false), vec![(p, Asked::Tip)]);
}

// The cross-peer wait counts every contender, the requests in flight included. Sixteen
// peers hold headers requests for 9 s from about 0.1 s; a seventeenth connects at 1 s with nothing
// else due anywhere. It waits for a place (about 8 s), within ceil(17 / 16) x (9 + 5) s.
#[test]
fn a_newcomer_waits_for_a_place_when_every_slot_is_held() {
    let held: Vec<PeerId> = (0..CEILING).map(|_| PeerId::random()).collect();
    let newcomer = PeerId::random();
    let mut sim = Sim::new();
    let h = held.clone();
    let eligible = |ms: u64| {
        let mut v = h.clone();
        if ms >= 1_000 {
            v.push(newcomer);
        }
        v
    };
    let mut heavier = |b: &mut Background<u64>, q: PeerId, kind: Asked, now: Instant| {
        if kind == Asked::Tip && q != newcomer {
            b.want(q, Asked::Headers, now);
            return true;
        }
        false
    };
    let answer = |q: &PeerId, kind: Asked| if *q != newcomer && kind == Asked::Headers { 9_000 } else { 100 };
    sim.watch = Some(newcomer);
    sim.run(30, &eligible, &answer, &mut heavier, &mut no_tick);
    eprintln!("[measure] newcomer admission wait {} ms", sim.longest_admission_ms);
    let first = sim.times(&newcomer, Asked::Tip)[0];
    let waited = first - 1_000;
    assert!(waited >= 7_000, "setup: every slot was held, yet the newcomer waited {waited} ms");
    assert!(waited <= cross_peer_wait_ms(CEILING + 1, 9_000), "waited {waited} ms");
    assert!(sim.longest_admission_ms <= cross_peer_wait_ms(CEILING + 1, 9_000));
}

// A newly owed kind is measured from its effective due time. Headers go out at once and
// are answered in 0.1 s; a parent-unknown gossip header owes headers again at once, but they are
// due only at the end of the 20 s cooldown, and sent within 2 x (0.1 + 5) s of it.
#[test]
fn newly_owed_headers_are_due_at_the_end_of_their_cooldown() {
    let p = PeerId::random();
    let mut sim = Sim::new();
    let mut flow = |b: &mut Background<u64>, q: PeerId, kind: Asked, now: Instant| {
        b.want(q, Asked::Headers, now);
        kind == Asked::Tip
    };
    sim.run(60, &|_| vec![p], &|_, _| 100, &mut flow, &mut no_tick);
    let headers = sim.times(&p, Asked::Headers);
    let (first, second) = (headers[0], headers[1]);
    assert!(second >= first + 20_000, "the cooldown was not kept: {headers:?}");
    let due = first + 20_000;
    assert!(second <= due + per_peer_bound_ms(0, 2, 100, 0), "sent {} ms after its due time", second - due);
}

// A quarantined peer leaves the eligible set but its request keeps its slot until it
// settles. Sixteen peers hold headers requests until about 9.1 s; one is quarantined at 0.5 s; a
// newcomer connects at 1 s. Eligible peers number 16, yet every slot is held: the contenders are
// 17, and the newcomer waits about 8.1 s, within ceil(17 / 16) x (9 + 5) s.
#[test]
fn a_quarantined_peers_request_still_holds_its_slot() {
    let held: Vec<PeerId> = (0..CEILING).map(|_| PeerId::random()).collect();
    let (quarantined, newcomer) = (held[0], PeerId::random());
    let mut sim = Sim::new();
    let h = held.clone();
    let eligible = |ms: u64| {
        let mut v: Vec<PeerId> = h.iter().copied().filter(|p| ms < 500 || *p != quarantined).collect();
        if ms >= 1_000 {
            v.push(newcomer);
        }
        v
    };
    let mut heavier = |b: &mut Background<u64>, q: PeerId, kind: Asked, now: Instant| {
        if kind == Asked::Tip && q != newcomer {
            b.want(q, Asked::Headers, now);
            return true;
        }
        false
    };
    let answer = |q: &PeerId, kind: Asked| if *q != newcomer && kind == Asked::Headers { 9_000 } else { 100 };
    sim.watch = Some(newcomer);
    sim.run(30, &eligible, &answer, &mut heavier, &mut no_tick);
    let waited = sim.times(&newcomer, Asked::Tip)[0] - 1_000;
    assert_eq!(eligible(2_000).len(), CEILING, "setup: 16 eligible");
    assert!(waited >= 7_000, "setup: the quarantined peer's request held its slot, yet the wait was {waited} ms");
    assert!(sim.longest_admission_ms <= cross_peer_wait_ms(CEILING + 1, 9_000), "waited {} ms", sim.longest_admission_ms);
    eprintln!("[measure] newcomer behind a quarantined holder waited {waited} ms");
}
