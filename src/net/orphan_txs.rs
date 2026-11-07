//! Gossip txs this node could not admit because something they depend on is not in its state yet:
//! an input not in its UTXO set, or for an Attest a proposal it does not know. The node is behind
//! the tip, or the dependency is not mined yet. Gossip validation forwards only what a node admits,
//! so without this set a relay that is behind stops such a tx for good, and nothing sends it again
//! (the node does no time-based rebroadcast). The node re-checks the set when its tip
//! moves and publishes what it now admits, which completes the relay step it skipped.
//!
//! Entries are keyed by the gossip message's content hash, not by txid: a txid leaves the
//! script_sigs out, so a copy with corrupted signatures would otherwise take the honest copy's
//! place. Copies of one txid are re-checked in arrival order; the first admitted one removes the
//! rest. Anyone can fill the set with txs naming dependencies that do not exist, or with copies of
//! one tx; that only pushes out other entries of this set, which before it existed were dropped on
//! arrival.

use std::collections::{BTreeMap, HashMap};

use crate::crypto::txid;
use crate::types::{Hash32, OutPoint, Transaction};

/// Entries held at most.
pub const ORPHAN_MAX_TXS: usize = 256;
/// Serialized tx bytes held at most (five txs of the 100 KB maximum, hundreds of ordinary ones).
pub const ORPHAN_MAX_BYTES: usize = 512 * 1024;
/// An entry leaves once the best header height has moved this far past where it was when parked
/// (about an hour at 120 s blocks). Header height, not tip height: a node catching up applies
/// blocks quickly, and its parked txs wait for the tip, not for a count of applied blocks.
pub const ORPHAN_EXPIRY_BLOCKS: u64 = 30;

/// What a parked tx waits for.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Deps {
    /// Inputs not in the UTXO set.
    pub inputs: Vec<OutPoint>,
    /// The proposal an Attest refers to, when it is not known.
    pub proposal: Option<Hash32>,
}

impl Deps {
    pub fn is_empty(&self) -> bool {
        self.inputs.is_empty() && self.proposal.is_none()
    }
}

/// The outcome of trying a ready entry against the mempool.
pub enum Recheck {
    /// Admitted: published by the caller; the other copies of its txid leave.
    Admitted,
    /// The mempool already holds this txid, or a conflicting spend: every copy leaves.
    Held,
    /// Refused while something it depends on is still missing: it stays, waiting for that.
    Waiting(Deps),
    /// Refused with nothing missing: this copy leaves, other copies stay.
    Refused,
}

struct Orphan {
    tx: Transaction,
    txid: Hash32,
    bytes: usize,
    deps: Deps,
    expires_at: u64,
    seq: u64,
}

#[derive(Default)]
pub struct OrphanTxs {
    by_key: HashMap<Hash32, Orphan>,
    /// Arrival order, for oldest-out eviction and for the order copies are tried.
    order: BTreeMap<u64, Hash32>,
    next_seq: u64,
    bytes: usize,
}

impl OrphanTxs {
    #[cfg(test)]
    pub fn len(&self) -> usize {
        self.by_key.len()
    }

    pub fn is_empty(&self) -> bool {
        self.by_key.is_empty()
    }

    #[cfg(test)]
    pub fn bytes(&self) -> usize {
        self.bytes
    }

    /// Holds `tx` (`bytes` serialized; `key` the gossip message's content hash) until `deps` are
    /// present. The oldest entries leave first to make room. Not held: empty `deps`, a key already
    /// held, or a tx larger than the whole byte budget.
    pub fn park(&mut self, key: Hash32, tx: Transaction, bytes: usize, deps: Deps, best_height: u64) -> bool {
        if deps.is_empty() || bytes > ORPHAN_MAX_BYTES || self.by_key.contains_key(&key) {
            return false;
        }
        while self.by_key.len() >= ORPHAN_MAX_TXS || self.bytes + bytes > ORPHAN_MAX_BYTES {
            let Some((_, oldest)) = self.order.pop_first() else { break };
            self.remove(&oldest);
        }
        let seq = self.next_seq;
        self.next_seq += 1;
        self.order.insert(seq, key);
        self.bytes += bytes;
        let expires_at = best_height.saturating_add(ORPHAN_EXPIRY_BLOCKS);
        let txid = txid(&tx);
        self.by_key.insert(key, Orphan { tx, txid, bytes, deps, expires_at, seq });
        true
    }

    /// Drops the entries expired at `best_height`, then tries, in arrival order, each entry whose
    /// dependencies are `present`, through `admit`. Returns the admitted txs.
    pub fn recheck(
        &mut self,
        best_height: u64,
        present: impl Fn(&Deps) -> bool,
        mut admit: impl FnMut(&Transaction) -> Recheck,
    ) -> Vec<Transaction> {
        let expired: Vec<Hash32> =
            self.order.values().filter(|k| best_height >= self.by_key[*k].expires_at).copied().collect();
        for k in expired {
            self.remove(&k);
        }
        let mut admitted = Vec::new();
        let keys: Vec<Hash32> = self.order.values().copied().collect();
        for k in keys {
            let Some(o) = self.by_key.get(&k) else { continue };
            if !present(&o.deps) {
                continue;
            }
            let id = o.txid;
            match admit(&o.tx) {
                Recheck::Admitted => {
                    if let Some(o) = self.remove(&k) {
                        admitted.push(o.tx);
                    }
                    self.remove_txid(&id);
                }
                Recheck::Held => self.remove_txid(&id),
                Recheck::Waiting(deps) => {
                    if let Some(o) = self.by_key.get_mut(&k) {
                        o.deps = deps;
                    }
                }
                Recheck::Refused => {
                    self.remove(&k);
                }
            }
        }
        admitted
    }

    fn remove_txid(&mut self, id: &Hash32) {
        let keys: Vec<Hash32> = self.by_key.iter().filter(|(_, o)| o.txid == *id).map(|(k, _)| *k).collect();
        for k in keys {
            self.remove(&k);
        }
    }

    fn remove(&mut self, key: &Hash32) -> Option<Orphan> {
        let o = self.by_key.remove(key)?;
        self.order.remove(&o.seq);
        self.bytes -= o.bytes;
        Some(o)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::{AppPayload, TxIn, TxOut};

    fn tx(n: u32, sig: u8) -> Transaction {
        Transaction {
            version: 1,
            inputs: vec![TxIn {
                prevout: OutPoint { txid: [7u8; 32], vout: n },
                script_sig: vec![sig; 10],
            }],
            outputs: vec![TxOut { value: 1, script_pubkey: [0u8; 20] }],
            locktime: 0,
            app: AppPayload::None,
        }
    }

    fn key(t: &Transaction) -> Hash32 {
        *blake3::hash(&crate::codec::consensus_bincode().serialize(t).unwrap()).as_bytes()
    }

    fn deps(t: &Transaction) -> Deps {
        Deps { inputs: t.inputs.iter().map(|i| i.prevout).collect(), proposal: None }
    }

    fn park(set: &mut OrphanTxs, t: &Transaction, bytes: usize, height: u64) -> bool {
        set.park(key(t), t.clone(), bytes, deps(t), height)
    }

    fn ids(txs: Vec<Transaction>) -> Vec<Hash32> {
        txs.iter().map(txid).collect()
    }

    // The set is reachable by anyone who can gossip, so its size is the bound that matters.
    #[test]
    fn the_set_holds_its_caps_oldest_out_and_releases_a_tx_once_its_inputs_exist() {
        let mut set = OrphanTxs::default();
        for n in 0..(ORPHAN_MAX_TXS as u32 + 10) {
            assert!(park(&mut set, &tx(n, 0), 100, 0));
        }
        assert_eq!(set.len(), ORPHAN_MAX_TXS);
        let ready = set.recheck(0, |d| d.inputs.iter().all(|op| op.vout <= 10), |_| Recheck::Admitted);
        assert_eq!(ids(ready), ids(vec![tx(10, 0)]), "the first ten went first");

        let mut by_bytes = OrphanTxs::default();
        for n in 0..20u32 {
            assert!(park(&mut by_bytes, &tx(n, 0), 100_000, 0));
        }
        assert!(by_bytes.bytes() <= ORPHAN_MAX_BYTES);
        assert_eq!(by_bytes.len(), ORPHAN_MAX_BYTES / 100_000);
        assert!(!park(&mut by_bytes, &tx(99, 0), ORPHAN_MAX_BYTES + 1, 0));

        // Honest path: a tx comes out once what it waits for exists, and not before.
        let mut set = OrphanTxs::default();
        let waiting = tx(1, 0);
        assert!(park(&mut set, &waiting, 100, 50));
        assert!(set.recheck(51, |_| false, |_| Recheck::Admitted).is_empty());
        assert_eq!(ids(set.recheck(52, |_| true, |_| Recheck::Admitted)), ids(vec![waiting]));
        assert!(set.is_empty() && set.bytes() == 0);

        // It expires by header height.
        assert!(park(&mut set, &tx(2, 0), 100, 50));
        assert!(set.recheck(50 + ORPHAN_EXPIRY_BLOCKS, |_| true, |_| Recheck::Admitted).is_empty());
        assert!(set.is_empty());
    }

    // A txid leaves the script_sigs out. A copy with corrupted signatures that arrives first must
    // not take the honest copy's place: both are kept, tried in arrival order, and the admitted one
    // removes the rest.
    #[test]
    fn copies_of_one_txid_are_kept_apart_and_tried_in_arrival_order() {
        let (bad, good) = (tx(1, 0xEE), tx(1, 0x01));
        assert_eq!(txid(&bad), txid(&good));
        let mut set = OrphanTxs::default();
        assert!(park(&mut set, &bad, 100, 0));
        assert!(park(&mut set, &good, 100, 0));
        assert!(!park(&mut set, &good, 100, 0), "an exact copy is one entry");

        let mut tried = Vec::new();
        let admitted = set.recheck(1, |_| true, |t| {
            tried.push(t.inputs[0].script_sig[0]);
            if t.inputs[0].script_sig[0] == 0xEE { Recheck::Refused } else { Recheck::Admitted }
        });
        assert_eq!(tried, vec![0xEE, 0x01]);
        assert_eq!(ids(admitted), ids(vec![good.clone()]));
        assert!(set.is_empty());

        // Once one copy is admitted, the others leave untried.
        let third = tx(1, 0x02);
        assert!(park(&mut set, &good, 100, 0));
        assert!(park(&mut set, &third, 100, 0));
        let mut tried = 0;
        set.recheck(1, |_| true, |_| {
            tried += 1;
            Recheck::Admitted
        });
        assert_eq!((tried, set.len()), (1, 0));
    }

    // What a parked tx waits for can change between parking and its re-check (a reorg can take
    // away the block that held its proposal). A copy refused while a dependency is missing again
    // stays, waiting for that, and is not tried before it exists.
    #[test]
    fn a_copy_refused_on_a_missing_dependency_stays_parked() {
        let mut set = OrphanTxs::default();
        let attest = tx(1, 0);
        assert!(park(&mut set, &attest, 100, 0));
        let proposal = [9u8; 32];
        let gone = Deps { inputs: vec![], proposal: Some(proposal) };
        assert!(set.recheck(1, |_| true, |_| Recheck::Waiting(gone.clone())).is_empty());
        assert_eq!(set.len(), 1);
        assert!(set.recheck(2, |d| d.proposal.is_none(), |_| panic!("tried while its proposal is missing")).is_empty());
        assert_eq!(ids(set.recheck(3, |_| true, |_| Recheck::Admitted)), ids(vec![attest]));
    }
}
