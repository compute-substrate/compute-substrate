// libp2p-connection-limits 0.7.0 removes a closed connection from its
// peer's set and never the empty set (lib.rs:353-356; the entry is made at :373-376), so connecting
// and disconnecting with fresh identities, under every concurrent limit, grew its map without bound.
// `admission::ConnectionCaps` drops a peer's entry with its last connection. This drives the calls
// the swarm makes for an inbound connection that opens and closes, for CHURN fresh identities, and
// compares the heap this thread holds afterwards with before (a counting allocator, so this file is
// its own test binary with one test). The crate's behaviour in its place was red here (see
// docs/behaviour.md "Connection admission").

use std::alloc::{GlobalAlloc, Layout, System};
use std::cell::Cell;

use libp2p::core::{ConnectedPoint, Multiaddr};
use libp2p::swarm::behaviour::ConnectionEstablished;
use libp2p::swarm::{ConnectionClosed, ConnectionId, FromSwarm, NetworkBehaviour};
use libp2p::PeerId;

use csd::net::admission::connection_caps;

thread_local! {
    /// Heap bytes this thread allocated and has not freed.
    static HELD: Cell<isize> = const { Cell::new(0) };
}

fn note(delta: isize) {
    let _ = HELD.try_with(|h| h.set(h.get() + delta));
}

struct Counting;

// SAFETY: every call is passed to the system allocator unchanged; the counting only reads sizes.
unsafe impl GlobalAlloc for Counting {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        let p = unsafe { System.alloc(layout) };
        if !p.is_null() {
            note(layout.size() as isize);
        }
        p
    }

    unsafe fn dealloc(&self, p: *mut u8, layout: Layout) {
        unsafe { System.dealloc(p, layout) };
        note(-(layout.size() as isize));
    }

    unsafe fn realloc(&self, p: *mut u8, layout: Layout, new_size: usize) -> *mut u8 {
        let q = unsafe { System.realloc(p, layout, new_size) };
        if !q.is_null() {
            note(new_size as isize - layout.size() as isize);
        }
        q
    }
}

#[global_allocator]
static COUNTING: Counting = Counting;

/// Fresh identities that connect and disconnect, one at a time.
const CHURN: usize = 20_000;

/// Opens and closes one inbound connection for each of `n` fresh identities, as the swarm reports
/// them to a behaviour that admits them.
fn churn<B: NetworkBehaviour>(b: &mut B, first_id: usize, n: usize) {
    let local: Multiaddr = "/ip4/127.0.0.1/tcp/17999".parse().unwrap();
    let remote: Multiaddr = "/ip4/203.0.113.7/tcp/40000".parse().unwrap();
    let endpoint = ConnectedPoint::Listener { local_addr: local.clone(), send_back_addr: remote.clone() };
    for i in first_id..first_id + n {
        let (id, peer) = (ConnectionId::new_unchecked(i), PeerId::random());
        assert!(b.handle_pending_inbound_connection(id, &local, &remote).is_ok());
        assert!(b.handle_established_inbound_connection(id, peer, &local, &remote).is_ok(), "identity {i} refused");
        b.on_swarm_event(FromSwarm::ConnectionEstablished(ConnectionEstablished {
            peer_id: peer,
            connection_id: id,
            endpoint: &endpoint,
            failed_addresses: &[],
            other_established: 0,
        }));
        b.on_swarm_event(FromSwarm::ConnectionClosed(ConnectionClosed {
            peer_id: peer,
            connection_id: id,
            endpoint: &endpoint,
            cause: None,
            remaining_established: 0,
        }));
    }
}

#[test]
fn identity_churn_leaves_the_admission_bookkeeping_at_its_baseline() {
    let mut caps = connection_caps(96);
    // Warm up: the random source and the maps' first allocations.
    churn(&mut caps, 1, 100);
    let before = HELD.with(Cell::get);
    churn(&mut caps, 1_000, CHURN);
    let grown = HELD.with(Cell::get) - before;
    eprintln!("[measure] heap held after {CHURN} fresh identities connected and left: {grown} bytes more");
    assert!(grown < 64 * 1024, "{CHURN} identities that left grew the admission bookkeeping by {grown} bytes");
}
