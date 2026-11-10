//! Our requests the request-response layer has not reported on yet, and which
//! of those reports belong to a connection we shed (`maybe_shed_second_inbound` in node.rs).
//!
//! The layer reports every request of ours once, as an answer or an OutboundFailure
//! (libp2p-request-response 0.30.0: an answer, a timeout or a stream failure at lib.rs:856-985, the
//! connection's close at :658-701, a dial failure at :704-733). A connection's close queues the
//! failures of our requests on it, and the loop handles them after the ConnectionClosed event: in
//! event order, with no bound in time, since other arms of the loop can run in between. So when a
//! connection we shed closes, the peer's requests the layer no longer holds as pending
//! (`is_pending_outbound`, :523-544) are those with a report queued, the
//! shed connection's failures among them, and the connection counts as shed until each of them has
//! been reported.
//!
//! Bounds: `peer_of` holds a request from its send to its report, so it holds our requests in
//! flight in the layer; `shed` holds only requests of `peer_of`. Connection ids come from one
//! process-wide counter (libp2p-swarm 0.48.0 connection.rs:66, :85-87), so a record kept until its
//! reports arrive is not mistaken for a later connection.

use std::collections::HashMap;
use std::hash::Hash;

use libp2p::swarm::ConnectionId;
use libp2p::PeerId;

pub(crate) struct Unreported<K> {
    /// Every request of ours not yet reported on, with the peer it went to.
    peer_of: HashMap<K, PeerId>,
    /// Those whose report was queued when a connection we shed closed, with that connection.
    shed: HashMap<K, ConnectionId>,
}

impl<K: Copy + Eq + Hash> Unreported<K> {
    pub(crate) fn new() -> Self {
        Self { peer_of: HashMap::new(), shed: HashMap::new() }
    }

    /// Records `rid`, just sent to `peer`.
    pub(crate) fn sent(&mut self, rid: K, peer: PeerId) {
        self.peer_of.insert(rid, peer);
    }

    /// `c`, a connection of `peer` we shed, has closed. `pending` tells whether the layer still holds
    /// a request as pending; the others of `peer` have their report queued, and keep `c` counted as
    /// shed until reported. One already keeping an earlier shed connection stays with it: a
    /// request's failure names the one connection it was on.
    pub(crate) fn shed_closed(&mut self, c: ConnectionId, peer: &PeerId, pending: impl Fn(&K) -> bool) {
        for (rid, p) in &self.peer_of {
            if p == peer && !pending(rid) && !self.shed.contains_key(rid) {
                self.shed.insert(*rid, c);
            }
        }
    }

    /// `rid`'s answer or failure, which came on `c`, has reached the loop. Returns whether `c` is a
    /// connection we shed that is still waiting for a report, as it is for each of its own failures.
    pub(crate) fn reported(&mut self, rid: &K, c: ConnectionId) -> bool {
        let shed = self.shed.values().any(|w| *w == c);
        self.peer_of.remove(rid);
        self.shed.remove(rid);
        shed
    }

    #[cfg(test)]
    fn sizes(&self) -> (usize, usize) {
        (self.peer_of.len(), self.shed.len())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // A shed connection is not remembered for a fixed time (5 s of wall clock would end
    // while its failures could still be queued). It counts as shed until each report queued at
    // its close has reached the loop, then the record is gone; a request still pending at the close
    // (on the connection the peer keeps) does not hold it, and a close with nothing queued leaves
    // none. `tests/p2p_live_inbound_saturation.rs` holds the real failures past a poll tick.
    #[test]
    fn a_shed_connection_counts_until_the_reports_queued_at_its_close_are_in() {
        let (p, q) = (PeerId::random(), PeerId::random());
        let (kept, shed, other) = (ConnectionId::new_unchecked(1), ConnectionId::new_unchecked(2), ConnectionId::new_unchecked(3));
        let mut u = Unreported::new();
        u.sent(10u64, p); // on the shed connection: its failure is queued at the close
        u.sent(11, p); // on the connection p keeps: still pending
        u.sent(12, p); // on the shed connection too
        u.sent(20, q);
        u.shed_closed(shed, &p, |rid| *rid == 11);
        assert_eq!(u.sizes(), (4, 2));

        assert!(!u.reported(&20, other), "another peer's failure is its own");
        assert!(u.reported(&10, shed), "a queued failure of the shed connection is ours");
        assert!(u.reported(&12, shed), "and so is the last one, whenever it comes");
        assert_eq!(u.sizes(), (1, 0), "the record ends with its last queued report");
        assert!(!u.reported(&11, kept), "the connection p keeps was not shed");
        assert_eq!(u.sizes(), (0, 0));

        u.sent(13, p);
        u.shed_closed(ConnectionId::new_unchecked(4), &p, |_| true);
        assert_eq!(u.sizes(), (1, 0), "nothing queued at the close: no record");
    }
}
