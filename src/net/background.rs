//! Background requests (GetTip, GetHeadersByLocator, GetPeers): what each peer is owed, one request
//! in flight per peer, at most CEILING in flight in all, sent in the order they fell due.
//!
//! Each owed kind has a due time: a tip `tip_every` after the last one sent (at first sight for a
//! new peer, at once while our tip is stale), headers from when they were owed or the end of the
//! headers cooldown, whichever is later, peers from when they were owed. A peer's next request is
//! its earliest due kind; across peers, free places go first to the peer that has waited longest
//! since its last request (since it was first seen, for a new one). Demand is kept
//! until it is sent or the peer disconnects. Block requests have their own budget (`inflight` in
//! node.rs) and are not counted here.

use std::collections::HashMap;
use std::hash::Hash;
use std::time::{Duration, Instant};

use libp2p::PeerId;

/// Background requests in flight across all peers. An answer is read up to the wire limit
/// (MAX_RR_MSG_BYTES, 1 MiB) before it is checked, so this bounds that buffer at 16 MiB, where one
/// request per admitted peer (up to the connection cap plus PEER_CAP_BURST: 96 by default, 128 on a
/// bootnode) would allow 96 to 128 MiB. 32 peers owe about 5 requests a second (a GetTip each
/// every 10 s, headers at most every 20 s, peers every 30 s); at an answer a second, 16 in flight
/// serve 16 a second.
pub(crate) const CEILING: usize = 16;

/// What an outstanding background request asked for. A Headers response is handled only as the
/// answer to our own headers request, a Tip response only as the answer to our GetTip and a Peers
/// response only as the answer to our GetPeers: this node's server answers each request with its
/// own kind or an error, so another kind comes from no honest peer.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub(crate) enum Asked {
    Tip,
    Headers,
    Peers,
}

pub(crate) struct Background<K> {
    asked: HashMap<K, (Instant, Asked, PeerId)>,
    busy: HashMap<PeerId, K>,
    last: HashMap<(PeerId, Asked), Instant>,
    /// Owed Headers and Peers, with the time each was first owed.
    wants: HashMap<(PeerId, Asked), Instant>,
    /// When each peer was first offered a request: a new peer's first GetTip is due then.
    seen: HashMap<PeerId, Instant>,
    /// When each peer was last sent any request: the cross-peer order.
    last_any: HashMap<PeerId, Instant>,
    tip_every: Duration,
    headers_cooldown: Duration,
    expire_after: Duration,
    ceiling: usize,
}

impl<K: Copy + Eq + Hash> Background<K> {
    /// `tip_every`: a peer is due a GetTip this long after its last; `headers_cooldown`: the least
    /// time between two headers requests to one peer; `expire_after`: a request not reported on by
    /// then frees its peer (the transport reports every request well within it).
    pub(crate) fn new(tip_every: Duration, headers_cooldown: Duration, expire_after: Duration, ceiling: usize) -> Self {
        Self {
            asked: HashMap::new(),
            busy: HashMap::new(),
            last: HashMap::new(),
            wants: HashMap::new(),
            seen: HashMap::new(),
            last_any: HashMap::new(),
            tip_every,
            headers_cooldown,
            expire_after,
            ceiling,
        }
    }

    /// Records that `p` is owed a request of `kind` (Headers or Peers; a Tip falls due by time).
    /// Owing it again keeps the first time.
    pub(crate) fn want(&mut self, p: PeerId, kind: Asked, now: Instant) {
        self.wants.entry((p, kind)).or_insert(now);
    }

    /// `p`'s next request and when it fell due: its earliest due kind (ties in `Asked` order), None
    /// while one is in flight to it or nothing is due.
    fn next_for(&self, p: &PeerId, now: Instant, stale_tip: bool) -> Option<(Instant, Asked)> {
        if self.busy.contains_key(p) {
            return None;
        }
        let tip_due = match self.last.get(&(*p, Asked::Tip)) {
            Some(t) if stale_tip => (*t + self.tip_every).min(now),
            Some(t) => *t + self.tip_every,
            None => self.seen.get(p).copied().unwrap_or(now).min(now),
        };
        let headers_due = self.wants.get(&(*p, Asked::Headers)).map(|owed| match self.last.get(&(*p, Asked::Headers)) {
            Some(t) => (*owed).max(*t + self.headers_cooldown),
            None => *owed,
        });
        let peers_due = self.wants.get(&(*p, Asked::Peers)).copied();
        [(Some(tip_due), Asked::Tip), (headers_due, Asked::Headers), (peers_due, Asked::Peers)]
            .into_iter()
            .filter_map(|(due, kind)| due.filter(|d| *d <= now).map(|d| (d, kind)))
            .min()
    }

    /// The requests to send now among `eligible`: each peer's next, the peer that has waited longest
    /// since its last request first, up to the free places under the ceiling.
    pub(crate) fn schedule(&mut self, eligible: &[PeerId], now: Instant, stale_tip: bool) -> Vec<(PeerId, Asked)> {
        for p in eligible {
            self.seen.entry(*p).or_insert(now);
        }
        let mut due: Vec<(Instant, PeerId, Asked)> = eligible
            .iter()
            .filter_map(|p| {
                let waited_since = self.last_any.get(p).copied().unwrap_or(self.seen[p]);
                self.next_for(p, now, stale_tip).map(|(_, k)| (waited_since, *p, k))
            })
            .collect();
        due.sort();
        let free = self.ceiling.saturating_sub(self.asked.len());
        due.into_iter().take(free).map(|(_, p, k)| (p, k)).collect()
    }

    /// Records the request `rid` of `kind` sent to `p`; it serves that demand.
    pub(crate) fn sent(&mut self, rid: K, p: PeerId, kind: Asked, now: Instant) {
        self.asked.insert(rid, (now, kind, p));
        self.busy.insert(p, rid);
        self.last.insert((p, kind), now);
        self.last_any.insert(p, now);
        self.wants.remove(&(p, kind));
    }

    /// The answer to (or failure of) `rid` frees its peer; returns what was asked, None for a
    /// request that is not ours or was already settled.
    pub(crate) fn settle(&mut self, rid: &K) -> Option<Asked> {
        let (_, kind, p) = self.asked.remove(rid)?;
        if self.busy.get(&p) == Some(rid) {
            self.busy.remove(&p);
        }
        Some(kind)
    }

    /// Frees the peers of requests older than `expire_after`.
    pub(crate) fn expire(&mut self, now: Instant) {
        let old: Vec<K> = self
            .asked
            .iter()
            .filter(|(_, (t, _, _))| now.duration_since(*t) >= self.expire_after)
            .map(|(rid, _)| *rid)
            .collect();
        for rid in old {
            self.settle(&rid);
        }
    }

    /// A disconnected peer is owed nothing; a later connection starts afresh, behind the peers
    /// already waiting.
    pub(crate) fn forget(&mut self, p: &PeerId) {
        if let Some(rid) = self.busy.remove(p) {
            self.asked.remove(&rid);
        }
        self.last.retain(|(q, _), _| q != p);
        self.wants.retain(|(q, _), _| q != p);
        self.seen.remove(p);
        self.last_any.remove(p);
    }

    pub(crate) fn in_flight(&self) -> usize {
        self.asked.len()
    }
}

#[cfg(test)]
mod tests;
