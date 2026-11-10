//! Connection admission: the transport's handshake
//! deadline, connection limits per peer, on established inbound connections and on inbound
//! handshakes (`ConnectionCaps`), and caps per address on inbound handshakes and established inbound
//! connections (`InboundPerAddress`). Without them, as in upstream v1.1.2, the
//! node bounds peers, not connections: one PeerId can hold any number of connections, a TCP
//! connection that never sends a byte is held until the remote closes it, and a dial to an address
//! that accepts TCP and never answers never fails.
//!
//! Every bound admits what an honest upstream node does (compute-substrate main d168f70 and
//! v1.1.2, `src/net/node.rs`, libp2p 0.54), but for the third connection of a dial race, refused
//! while the peer keeps two (MAX_ESTABLISHED_PER_PEER): see each constant. docs/behaviour.md
//! "Connection admission".

use std::collections::{HashMap, HashSet};
use std::convert::Infallible;
use std::fmt;
use std::net::IpAddr;
use std::task::{Context, Poll};
use std::time::Duration;

use libp2p::core::{multiaddr::Protocol, transport::PortUse, ConnectedPoint, Endpoint, Multiaddr};
use libp2p::swarm::{
    behaviour::ConnectionEstablished, dummy, ConnectionClosed, ConnectionDenied, ConnectionId, FromSwarm, ListenFailure,
    NetworkBehaviour, THandler, THandlerInEvent, THandlerOutEvent, ToSwarm,
};
use libp2p::PeerId;

/// A connection's TCP connect, protocol negotiation, noise handshake and yamux setup must finish
/// within this, inbound and outbound (libp2p-core 0.44.0 `Multiplexed::timeout`, `upgrade.rs:313`,
/// wraps both the dial and the listener upgrade, `transport/timeout.rs:92-93`). Upstream sets none;
/// its handshake with us takes a few round trips. Twice libp2p's own builder default (10 s,
/// libp2p 0.57.0 `builder/phase/swarm.rs:5`), and room for four lost SYNs (1, 2, 4 and 8 s).
pub(crate) const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(20);

/// Established connections to one peer, both directions together. Upstream dials every address it
/// holds of a peer it is not connected to (`swarm.dial(addr)`: `PeerCondition::Always`, libp2p-swarm
/// 0.45.1 `dial_opts.rs:163-166`, `:305-308`; the periodic redial, d168f70 node.rs:3074-3110), and
/// the same address twice at its start when it is a configured bootnode and in its book
/// (:2708-2766); with one address of ours in its book (a node with one public IPv4) that is two
/// connections, and a dial of ours to it at that moment makes a third. The third to complete its
/// handshake is refused, and the peer keeps the two it holds: the refusal comes after the
/// handshake, which upstream reads as a connection that opened and closed (its refcount,
/// :3195-3206, :3329-3336), not a failed dial (docs/behaviour.md "Connection admission").
pub(crate) const MAX_ESTABLISHED_PER_PEER: u32 = 2;

/// Inbound connections still in their handshake, from all addresses: idle TCP connections then hold
/// at most 1,024 descriptors and tasks, a sixty-fourth of a LimitNOFILE of 65,536, and leave
/// the rest to the node's files and its RPC listener. Far above any honest burst: every peer a
/// bootnode admits (128) dialing us eight times at once.
pub(crate) const MAX_PENDING_INBOUND: u32 = 1_024;

/// Inbound connections in their handshake from one address (an IPv6 /64 counts as one). One
/// upstream node dials at most every address it holds of ours in one pass, at most
/// MAX_ADDRS_PER_PEER (8, d168f70 node.rs:136), plus one as a configured bootnode at its start; 16
/// admits that with room for a second node behind the same address.
pub(crate) const MAX_PENDING_INBOUND_PER_IP: usize = 16;

/// Established inbound connections from one address (an IPv6 /64 counts as one), but 127.0.0.1 and
/// ::1 (`exempt_source`): an upstream node holds at most two connections to us
/// (MAX_ESTABLISHED_PER_PEER), so eight admits four nodes behind one address; on a mainnet node the
/// most connections one remote address held to its :17999 was three (read with `ss`).
pub(crate) const MAX_ESTABLISHED_INBOUND_PER_IP: usize = 8;

/// The limits for this node: at most MAX_ESTABLISHED_PER_PEER a peer, `incoming` established inbound
/// connections (the peer cap plus its burst, the count at which the connect arm drops a new peer, as
/// upstream's does, d168f70 node.rs:3212-3229), and MAX_PENDING_INBOUND in their handshake. Inbound
/// only: connections a remote opens never refuse our own dials, which keep the node from being
/// surrounded by peers it did not choose (`maybe_evict_excess_peers` protects the peers we dialed);
/// our dials are bounded by the dial loops, which stop at the peer cap.
pub fn connection_caps(incoming: u32) -> ConnectionCaps {
    ConnectionCaps {
        inbound_limit: incoming as usize,
        pending: HashSet::new(),
        inbound: HashSet::new(),
        by_peer: HashMap::new(),
    }
}

/// The connection limits of `connection_caps`, counted as libp2p's `connection_limits` 0.7.0 counts
/// them (`lib.rs:235-386`: the handshake count checked before the handshake, the per-peer and inbound
/// counts after it, every count moved on ConnectionEstablished, ConnectionClosed and ListenFailure),
/// but a peer's entry goes with its last connection. The crate removes the closed connection from
/// its peer's set and never the empty set (`lib.rs:353-356`, inserted at `:373-376`), so an identity
/// that connected once keeps an entry for good, and connecting with fresh identities grows the map
/// without bound.
pub struct ConnectionCaps {
    inbound_limit: usize,
    /// Inbound connections in their handshake.
    pending: HashSet<ConnectionId>,
    /// Established inbound connections.
    inbound: HashSet<ConnectionId>,
    /// Each peer's established connections, both directions; a peer has an entry only while it has
    /// a connection.
    by_peer: HashMap<PeerId, Vec<ConnectionId>>,
}

impl ConnectionCaps {
    fn of_peer(&self, peer: &PeerId) -> usize {
        self.by_peer.get(peer).map_or(0, Vec::len)
    }

    /// Established inbound connections, the count `incoming` caps.
    pub(crate) fn inbound(&self) -> usize {
        self.inbound.len()
    }

    /// `peer`'s established inbound connections, oldest first.
    pub(crate) fn inbound_of(&self, peer: &PeerId) -> Vec<ConnectionId> {
        self.by_peer.get(peer).map_or_else(Vec::new, |c| c.iter().filter(|id| self.inbound.contains(id)).copied().collect())
    }

    /// A second connection of `peer` that it opened to us, the newer of its inbound two, when it holds
    /// two connections and both are inbound; None otherwise.
    pub(crate) fn second_inbound(&self, peer: &PeerId) -> Option<ConnectionId> {
        let inbound = self.inbound_of(peer);
        (self.of_peer(peer) >= 2 && inbound.len() >= 2).then(|| inbound[inbound.len() - 1])
    }

    fn admit_peer(&self, peer: &PeerId) -> Result<(), ConnectionDenied> {
        if self.of_peer(peer) >= MAX_ESTABLISHED_PER_PEER as usize {
            return Err(ConnectionDenied::new(LimitReached { limit: MAX_ESTABLISHED_PER_PEER as usize, what: "connections to one peer" }));
        }
        Ok(())
    }
}

impl NetworkBehaviour for ConnectionCaps {
    type ConnectionHandler = dummy::ConnectionHandler;
    type ToSwarm = Infallible;

    fn handle_pending_inbound_connection(
        &mut self,
        id: ConnectionId,
        _local: &Multiaddr,
        _remote: &Multiaddr,
    ) -> Result<(), ConnectionDenied> {
        if self.pending.len() >= MAX_PENDING_INBOUND as usize {
            return Err(ConnectionDenied::new(LimitReached { limit: MAX_PENDING_INBOUND as usize, what: "inbound connections in their handshake" }));
        }
        self.pending.insert(id);
        Ok(())
    }

    fn handle_established_inbound_connection(
        &mut self,
        id: ConnectionId,
        peer: PeerId,
        _local: &Multiaddr,
        _remote: &Multiaddr,
    ) -> Result<THandler<Self>, ConnectionDenied> {
        self.pending.remove(&id);
        if self.inbound.len() >= self.inbound_limit {
            return Err(ConnectionDenied::new(LimitReached { limit: self.inbound_limit, what: "established inbound connections" }));
        }
        self.admit_peer(&peer)?;
        Ok(dummy::ConnectionHandler)
    }

    fn handle_established_outbound_connection(
        &mut self,
        _id: ConnectionId,
        peer: PeerId,
        _addr: &Multiaddr,
        _role: Endpoint,
        _port_use: PortUse,
    ) -> Result<THandler<Self>, ConnectionDenied> {
        self.admit_peer(&peer)?;
        Ok(dummy::ConnectionHandler)
    }

    fn on_swarm_event(&mut self, event: FromSwarm) {
        match event {
            FromSwarm::ListenFailure(ListenFailure { connection_id, .. }) => {
                self.pending.remove(&connection_id);
            }
            // Counted when the swarm admits it, after every behaviour's check.
            FromSwarm::ConnectionEstablished(ConnectionEstablished { peer_id, connection_id, endpoint, .. }) => {
                if endpoint.is_listener() {
                    self.inbound.insert(connection_id);
                }
                let conns = self.by_peer.entry(peer_id).or_default();
                if !conns.contains(&connection_id) {
                    conns.push(connection_id);
                }
            }
            FromSwarm::ConnectionClosed(ConnectionClosed { peer_id, connection_id, .. }) => {
                self.inbound.remove(&connection_id);
                if let Some(conns) = self.by_peer.get_mut(&peer_id) {
                    conns.retain(|c| *c != connection_id);
                    if conns.is_empty() {
                        self.by_peer.remove(&peer_id);
                    }
                }
            }
            _ => {}
        }
    }

    fn on_connection_handler_event(&mut self, _peer: PeerId, _id: ConnectionId, event: THandlerOutEvent<Self>) {
        libp2p::core::util::unreachable(event)
    }

    fn poll(&mut self, _cx: &mut Context<'_>) -> Poll<ToSwarm<Self::ToSwarm, THandlerInEvent<Self>>> {
        Poll::Pending
    }
}

/// The address an inbound connection is counted under: its IPv4 address (also in the mapped IPv6
/// form), or its IPv6 /64.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
enum Source {
    V4(std::net::Ipv4Addr),
    V6Net(u64),
}

fn remote_ip(remote: &Multiaddr) -> Option<IpAddr> {
    match remote.iter().next()? {
        Protocol::Ip4(v4) => Some(IpAddr::V4(v4)),
        Protocol::Ip6(v6) => Some(IpAddr::V6(v6)),
        _ => None,
    }
}

/// The addresses nodes on the same host connect to each other from (one dials another's loopback
/// bootnode, 127.0.0.1): their established connections are not capped per address. Another
/// loopback address comes only from a process on this host that chose it, and counts like any.
fn exempt_source(ip: IpAddr) -> bool {
    ip == IpAddr::V4(std::net::Ipv4Addr::LOCALHOST) || ip == IpAddr::V6(std::net::Ipv6Addr::LOCALHOST)
}

fn source(remote: &Multiaddr) -> Option<Source> {
    let ip = remote_ip(remote)?;
    Some(match ip {
        IpAddr::V4(v4) => Source::V4(v4),
        IpAddr::V6(v6) => match v6.to_ipv4_mapped() {
            Some(v4) => Source::V4(v4),
            None => Source::V6Net((u128::from(v6) >> 64) as u64),
        },
    })
}

/// The refusal of a connection past one of the admission limits.
#[derive(Debug)]
pub(crate) struct LimitReached {
    limit: usize,
    what: &'static str,
}

impl fmt::Display for LimitReached {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "at most {} {}", self.limit, self.what)
    }
}

impl std::error::Error for LimitReached {}

/// Connections counted per source address (`Source`), each by its ConnectionId.
#[derive(Default)]
struct PerSource {
    by_id: HashMap<ConnectionId, Source>,
    count: HashMap<Source, usize>,
}

impl PerSource {
    fn add(&mut self, id: ConnectionId, src: Source) {
        if self.by_id.insert(id, src).is_none() {
            *self.count.entry(src).or_insert(0) += 1;
        }
    }

    fn remove(&mut self, id: ConnectionId) {
        let Some(src) = self.by_id.remove(&id) else { return };
        if let Some(n) = self.count.get_mut(&src) {
            *n -= 1;
            if *n == 0 {
                self.count.remove(&src);
            }
        }
    }

    fn of(&self, src: Source) -> usize {
        self.count.get(&src).copied().unwrap_or(0)
    }
}

/// Refuses an inbound connection while MAX_PENDING_INBOUND_PER_IP from its address are in their
/// handshake, and an established one while its address holds MAX_ESTABLISHED_INBOUND_PER_IP
/// (127.0.0.1 and ::1 exempt). A connection leaves the handshake count when its handshake ends,
/// either way (established, or failed: a timeout, an error, a refusal by any limit), and the
/// established count when it closes.
pub struct InboundPerAddress {
    pending_limit: usize,
    established_limit: usize,
    pending: PerSource,
    established: PerSource,
}

impl InboundPerAddress {
    pub(crate) fn new(pending_limit: usize, established_limit: usize) -> Self {
        Self { pending_limit, established_limit, pending: PerSource::default(), established: PerSource::default() }
    }

    fn settle(&mut self, id: ConnectionId) {
        self.pending.remove(id);
    }

    #[cfg(test)]
    fn in_handshake(&self) -> usize {
        self.pending.by_id.len()
    }
}

impl NetworkBehaviour for InboundPerAddress {
    type ConnectionHandler = dummy::ConnectionHandler;
    type ToSwarm = Infallible;

    fn handle_pending_inbound_connection(
        &mut self,
        id: ConnectionId,
        _local: &Multiaddr,
        remote: &Multiaddr,
    ) -> Result<(), ConnectionDenied> {
        let Some(src) = source(remote) else { return Ok(()) };
        if self.pending.of(src) >= self.pending_limit {
            return Err(ConnectionDenied::new(LimitReached {
                limit: self.pending_limit,
                what: "inbound connections in their handshake from one address",
            }));
        }
        self.pending.add(id, src);
        Ok(())
    }

    fn handle_established_inbound_connection(
        &mut self,
        id: ConnectionId,
        _peer: PeerId,
        _local: &Multiaddr,
        remote: &Multiaddr,
    ) -> Result<THandler<Self>, ConnectionDenied> {
        self.settle(id);
        let capped = remote_ip(remote).is_some_and(|ip| !exempt_source(ip));
        if let Some(src) = source(remote).filter(|_| capped) {
            if self.established.of(src) >= self.established_limit {
                return Err(ConnectionDenied::new(LimitReached {
                    limit: self.established_limit,
                    what: "established inbound connections from one address",
                }));
            }
        }
        Ok(dummy::ConnectionHandler)
    }

    fn handle_established_outbound_connection(
        &mut self,
        _id: ConnectionId,
        _peer: PeerId,
        _addr: &Multiaddr,
        _role: Endpoint,
        _port_use: PortUse,
    ) -> Result<THandler<Self>, ConnectionDenied> {
        Ok(dummy::ConnectionHandler)
    }

    fn on_swarm_event(&mut self, event: FromSwarm) {
        match event {
            FromSwarm::ListenFailure(ListenFailure { connection_id, .. }) => self.settle(connection_id),
            // Counted when the swarm admits it, after every behaviour's check: a connection that a
            // later limit refuses is never counted here.
            FromSwarm::ConnectionEstablished(ConnectionEstablished { connection_id, endpoint, .. }) => {
                self.settle(connection_id);
                if let ConnectedPoint::Listener { send_back_addr, .. } = endpoint {
                    if let Some(src) = remote_ip(send_back_addr).filter(|ip| !exempt_source(*ip)).and(source(send_back_addr)) {
                        self.established.add(connection_id, src);
                    }
                }
            }
            FromSwarm::ConnectionClosed(ConnectionClosed { connection_id, .. }) => self.established.remove(connection_id),
            _ => {}
        }
    }

    fn on_connection_handler_event(&mut self, _peer: PeerId, _id: ConnectionId, event: THandlerOutEvent<Self>) {
        libp2p::core::util::unreachable(event)
    }

    fn poll(&mut self, _cx: &mut Context<'_>) -> Poll<ToSwarm<Self::ToSwarm, THandlerInEvent<Self>>> {
        Poll::Pending
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn addr(s: &str) -> Multiaddr {
        s.parse().unwrap()
    }

    fn admit(b: &mut InboundPerAddress, id: ConnectionId, remote: &str) -> bool {
        b.handle_pending_inbound_connection(id, &addr("/ip4/127.0.0.1/tcp/17999"), &addr(remote)).is_ok()
    }

    // The per-address handshake cap counts each address on its own, frees a slot when a handshake
    // ends either way, and counts an IPv6 /64 and the mapped form of an IPv4 address as one source.
    #[test]
    fn handshakes_are_capped_per_address_and_freed_when_they_end() {
        let mut b = InboundPerAddress::new(MAX_PENDING_INBOUND_PER_IP, MAX_ESTABLISHED_INBOUND_PER_IP);
        let ids: Vec<ConnectionId> = (0..MAX_PENDING_INBOUND_PER_IP).map(|_| ConnectionId::new_unchecked(rand_id())).collect();
        for id in &ids {
            assert!(admit(&mut b, *id, "/ip4/203.0.113.7/tcp/40000"));
        }
        let extra = ConnectionId::new_unchecked(rand_id());
        assert!(!admit(&mut b, extra, "/ip4/203.0.113.7/tcp/40001"), "one address past its cap");
        assert!(!admit(&mut b, extra, "/ip6/::ffff:203.0.113.7/tcp/40001"), "the same address, mapped");
        // The paired honest path: another address is admitted while this one is at its cap.
        let other = ConnectionId::new_unchecked(rand_id());
        assert!(admit(&mut b, other, "/ip4/198.51.100.9/tcp/40000"));

        // A handshake that ends, established or failed, frees its slot.
        let _ = b.handle_established_inbound_connection(ids[0], PeerId::random(), &addr("/ip4/127.0.0.1/tcp/17999"), &addr("/ip4/203.0.113.7/tcp/40000"));
        let freed = ConnectionId::new_unchecked(rand_id());
        assert!(admit(&mut b, freed, "/ip4/203.0.113.7/tcp/40002"));
        b.settle(ids[1]);
        b.settle(ids[1]);
        assert_eq!(b.in_handshake(), MAX_PENDING_INBOUND_PER_IP, "a second settle of one connection frees nothing");

        // One /64 is one source.
        let mut v6 = InboundPerAddress::new(2, MAX_ESTABLISHED_INBOUND_PER_IP);
        for (i, a) in ["/ip6/2001:db8:1:2::1/tcp/1", "/ip6/2001:db8:1:2:ffff::9/tcp/1"].iter().enumerate() {
            assert!(admit(&mut v6, ConnectionId::new_unchecked(1_000 + i), a));
        }
        assert!(!admit(&mut v6, ConnectionId::new_unchecked(1_002), "/ip6/2001:db8:1:2::77/tcp/1"));
        assert!(admit(&mut v6, ConnectionId::new_unchecked(1_003), "/ip6/2001:db8:1:3::1/tcp/1"));
    }

    fn inbound_from(remote: &str) -> ConnectedPoint {
        ConnectedPoint::Listener { local_addr: addr("/ip4/127.0.0.1/tcp/17999"), send_back_addr: addr(remote) }
    }

    /// Reports `id` from `remote` established to `b`, as the swarm does once every behaviour admitted it.
    fn establish<B: NetworkBehaviour>(b: &mut B, id: ConnectionId, endpoint: &ConnectedPoint) {
        b.on_swarm_event(FromSwarm::ConnectionEstablished(ConnectionEstablished {
            peer_id: PeerId::random(),
            connection_id: id,
            endpoint,
            failed_addresses: &[],
            other_established: 0,
        }));
    }

    fn close<B: NetworkBehaviour>(b: &mut B, id: ConnectionId, endpoint: &ConnectedPoint) {
        b.on_swarm_event(FromSwarm::ConnectionClosed(ConnectionClosed {
            peer_id: PeerId::random(),
            connection_id: id,
            endpoint,
            cause: None,
            remaining_established: 0,
        }));
    }

    // At most MAX_ESTABLISHED_INBOUND_PER_IP established
    // inbound connections from one address, 127.0.0.1 and ::1 exempt; a slot frees when one closes.
    #[test]
    fn established_inbound_connections_are_capped_per_address_but_loopback() {
        let mut b = InboundPerAddress::new(MAX_PENDING_INBOUND_PER_IP, MAX_ESTABLISHED_INBOUND_PER_IP);
        let from = |b: &mut InboundPerAddress, remote: &str| {
            let id = ConnectionId::new_unchecked(rand_id());
            let ok = b
                .handle_established_inbound_connection(id, PeerId::random(), &addr("/ip4/127.0.0.1/tcp/17999"), &addr(remote))
                .is_ok();
            if ok {
                establish(b, id, &inbound_from(remote));
            }
            (ok, id)
        };
        let mut held = Vec::new();
        for _ in 0..MAX_ESTABLISHED_INBOUND_PER_IP {
            let (ok, id) = from(&mut b, "/ip4/203.0.113.7/tcp/40000");
            assert!(ok);
            held.push(id);
        }
        assert!(!from(&mut b, "/ip4/203.0.113.7/tcp/40001").0, "one address past its cap");
        assert!(from(&mut b, "/ip4/198.51.100.9/tcp/40000").0, "another address");
        close(&mut b, held[0], &inbound_from("/ip4/203.0.113.7/tcp/40000"));
        assert!(from(&mut b, "/ip4/203.0.113.7/tcp/40002").0, "a closed connection frees its slot");
        // Nodes on the same host connect to each other from 127.0.0.1: never capped. Another loopback address is.
        for _ in 0..3 * MAX_ESTABLISHED_INBOUND_PER_IP {
            assert!(from(&mut b, "/ip4/127.0.0.1/tcp/50000").0);
            assert!(from(&mut b, "/ip6/::1/tcp/50000").0);
        }
        for _ in 0..MAX_ESTABLISHED_INBOUND_PER_IP {
            assert!(from(&mut b, "/ip4/127.0.0.2/tcp/50000").0);
        }
        assert!(!from(&mut b, "/ip4/127.0.0.2/tcp/50001").0);
    }

    // The established cap counts inbound connections only: counting both directions would let
    // inbound connections fill it and refuse our own dials.
    #[test]
    fn inbound_connections_never_refuse_our_own_dials() {
        let mut limits = connection_caps(2);
        let local = addr("/ip4/127.0.0.1/tcp/17999");
        for _ in 0..2 {
            let (id, peer) = (ConnectionId::new_unchecked(rand_id()), PeerId::random());
            assert!(limits.handle_established_inbound_connection(id, peer, &local, &addr("/ip4/203.0.113.7/tcp/1")).is_ok());
            establish(&mut limits, id, &inbound_from("/ip4/203.0.113.7/tcp/1"));
        }
        let third = ConnectionId::new_unchecked(rand_id());
        assert!(
            limits.handle_established_inbound_connection(third, PeerId::random(), &local, &addr("/ip4/198.51.100.9/tcp/1")).is_err(),
            "a third inbound connection past the inbound cap"
        );
        let ours = ConnectionId::new_unchecked(rand_id());
        let dialed = limits.handle_established_outbound_connection(
            ours,
            PeerId::random(),
            &addr("/ip4/198.51.100.9/tcp/17999"),
            Endpoint::Dialer,
            PortUse::Reuse,
        );
        assert!(dialed.is_ok(), "our own dial was refused by inbound connections");
    }

    fn rand_id() -> usize {
        use std::sync::atomic::{AtomicUsize, Ordering};
        static NEXT: AtomicUsize = AtomicUsize::new(1);
        NEXT.fetch_add(1, Ordering::Relaxed)
    }
}
