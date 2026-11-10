// Generated chains for the address-index tests (tests/addr_index_replay.rs, tests/addr_index_crash.rs):
// many addresses, signed spends (some of outputs made earlier in the same block), coinbases that
// repeat an earlier coinbase's txid, and reorgs, all applied through `maybe_reorg_to`, the path
// sync and the miner use. The generator keeps its own view of each block's UTXO set only to pick
// valid spends; what the tests compare is the node's own UTXO tree and index.
#![allow(dead_code)]

use std::collections::HashMap;

use anyhow::{bail, Context, Result};
use rand::{rngs::StdRng, Rng, SeedableRng};

use csd::chain::index::{get_hidx, header_hash, index_header};
use csd::chain::mine::{coinbase, merkle_root_txids};
use csd::chain::pow::expected_bits;
use csd::chain::reorg::maybe_reorg_to;
use csd::crypto::{hash160, sign_tx_compact_secp256k1, txid};
use csd::params::block_reward;
use csd::state::addr_index::{read_via_index, read_via_scan, AddrRead};
use csd::state::db::{get_tip, k_block, Stores};
use csd::state::tx_scan::reconcile_tick;
use csd::types::{AppPayload, Block, BlockHeader, Hash20, Hash32, OutPoint, Transaction, TxIn, TxOut};

type View = HashMap<OutPoint, TxOut>;

/// What a built block's coinbase does to the UTXO set, read from the block's transactions and its
/// parent's UTXO set.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Coinbase {
    /// A coinbase no earlier block of the branch made.
    New,
    /// It repeats an earlier coinbase whose output is still unspent and overwrites that coin.
    Overwrites,
    /// It repeats an earlier coinbase whose output an earlier block spent and creates it again.
    Recreates,
    /// It repeats an earlier coinbase whose output a transaction of the same block spends first,
    /// and then recreates the coin: the index's first touch of the outpoint finds its owner, the
    /// block spends it and creates it again (a no-op write that still records the owner for undo).
    SpendsThenRecreates,
}

/// What the generator remembers of a block it built.
struct Built {
    height: u64,
    parent: Hash32,
    /// The UTXO set after the block.
    view: View,
    coinbase: Transaction,
    fees: u64,
}

pub struct ChainGen {
    rng: StdRng,
    keys: Vec<([u8; 32], Hash20)>,
    receive_only: Vec<Hash20>,
    built: HashMap<Hash32, Built>,
}

fn key_addr(sk: [u8; 32]) -> Hash20 {
    hash160(&sign_tx_compact_secp256k1(&coinbase([0u8; 20], 1, 0, None), sk).1)
}

fn sign(mut tx: Transaction, sk: [u8; 32]) -> Transaction {
    let (sig, pubkey) = sign_tx_compact_secp256k1(&tx, sk);
    let ss = [&[64u8][..], &sig, &[33u8], &pubkey].concat();
    for i in &mut tx.inputs {
        i.script_sig = ss.clone();
    }
    tx
}

impl ChainGen {
    /// `keys` spending addresses and `receive_only` addresses without a key, the same for every
    /// seed; `seed` drives the choices.
    pub fn new(seed: u64, keys: usize, receive_only: usize) -> Self {
        let keys = (0..keys)
            .map(|i| {
                let mut sk = [0u8; 32];
                sk[0] = 1;
                sk[1] = i as u8;
                (sk, key_addr(sk))
            })
            .collect();
        let receive_only = (0..receive_only as u8).map(|i| [0xe0 ^ i; 20]).collect();
        ChainGen { rng: StdRng::seed_from_u64(seed), keys, receive_only, built: HashMap::new() }
    }

    /// One random choice for the caller (the crash test's workload).
    pub fn roll(&mut self, below: u64) -> u64 {
        self.rng.gen_range(0..below)
    }

    /// Every address the generator pays: the tests compare each of them.
    pub fn universe(&self) -> Vec<Hash20> {
        self.keys.iter().map(|k| k.1).chain(self.receive_only.iter().copied()).collect()
    }

    fn any_addr(&mut self) -> Hash20 {
        let n = self.keys.len() + self.receive_only.len();
        let i = self.rng.gen_range(0..n);
        if i < self.keys.len() {
            self.keys[i].1
        } else {
            self.receive_only[i - self.keys.len()]
        }
    }

    fn sk_of(&self, addr: &Hash20) -> Option<[u8; 32]> {
        self.keys.iter().find(|k| k.1 == *addr).map(|k| k.0)
    }

    /// Blocks the generator knows of on the chain ending at `tip`, tip first.
    fn branch(&self, tip: Hash32) -> Vec<Hash32> {
        let mut out = Vec::new();
        let mut cur = tip;
        while let Some(b) = self.built.get(&cur) {
            out.push(cur);
            cur = b.parent;
        }
        out
    }

    /// Builds a block on `parent`, stores it and indexes its header; the tip does not move.
    /// `dup`: the coinbase repeats the oldest coinbase of the branch whose output is still unspent
    /// and whose block paid no fees. With `spend` it repeats instead the oldest coinbase of the
    /// branch whose unspent output a key spends, whatever its block's fees, and a transaction of the
    /// block spends that output first, paying that block's fees again so the repeated coinbase's
    /// value balances. With no such coinbase the block gets a new one. Returns the hash and what the
    /// coinbase did.
    fn build(&mut self, db: &Stores, parent: Hash32, dup: bool, spend: bool) -> Result<(Hash32, Coinbase)> {
        let (height, mut view, parent_hi) = if parent == [0u8; 32] {
            (0, View::new(), None)
        } else {
            let hi = get_hidx(db, &parent)?.context("parent header index")?;
            (hi.height + 1, self.built[&parent].view.clone(), Some(hi))
        };
        let time = parent_hi.as_ref().map(|p| p.time + 60 + self.rng.gen_range(0..30)).unwrap_or(1_700_000_000);

        let mut txs: Vec<Transaction> = Vec::new();
        let mut fees = 0u64;
        let mut cb = None;
        if dup {
            let earlier = self
                .branch(parent)
                .into_iter()
                .rev()
                .map(|h| &self.built[&h])
                .find(|b| {
                    block_reward(b.height) == block_reward(height)
                        && view.contains_key(&OutPoint { txid: txid(&b.coinbase), vout: 0 })
                        && match spend {
                            false => b.fees == 0,
                            true => self.sk_of(&b.coinbase.outputs[0].script_pubkey).is_some(),
                        }
                })
                .map(|b| (b.coinbase.clone(), b.fees));
            if let Some((old, old_fees)) = earlier {
                let op = OutPoint { txid: txid(&old), vout: 0 };
                if spend {
                    let out = view.get(&op).cloned().context("the chosen coin is unspent")?;
                    let sk = self.sk_of(&old.outputs[0].script_pubkey).context("a key spends the chosen coin")?;
                    let to = self.any_addr();
                    fees = old_fees;
                    let tx = sign(
                        Transaction {
                            version: 1,
                            inputs: vec![TxIn { prevout: op, script_sig: vec![] }],
                            outputs: vec![TxOut { value: out.value - old_fees, script_pubkey: to }],
                            locktime: 0,
                            app: AppPayload::None,
                        },
                        sk,
                    );
                    view.remove(&op);
                    view.insert(OutPoint { txid: txid(&tx), vout: 0 }, tx.outputs[0].clone());
                    txs.push(tx);
                }
                cb = Some(old);
            }
        }
        if cb.is_none() {
            for _ in 0..self.rng.gen_range(0..5) {
                if let Some((tx, fee)) = self.random_spend(&view) {
                    for i in &tx.inputs {
                        view.remove(&i.prevout);
                    }
                    let id = txid(&tx);
                    for (v, out) in tx.outputs.iter().enumerate() {
                        view.insert(OutPoint { txid: id, vout: v as u32 }, out.clone());
                    }
                    fees += fee;
                    txs.push(tx);
                }
            }
        }
        let repeated = cb.is_some();
        let cb = match cb {
            Some(old) => old,
            None => {
                let miner = self.any_addr();
                coinbase(miner, block_reward(height) + fees, height, None)
            }
        };
        let cb_op = OutPoint { txid: txid(&cb), vout: 0 };
        let spent_here = txs.iter().any(|t| t.inputs.iter().any(|i| i.prevout == cb_op));
        let unspent_before = self.built.get(&parent).is_some_and(|b| b.view.contains_key(&cb_op));
        let kind = match (repeated, spent_here, unspent_before) {
            (false, _, _) => Coinbase::New,
            (true, true, _) => Coinbase::SpendsThenRecreates,
            (true, false, true) => Coinbase::Overwrites,
            (true, false, false) => Coinbase::Recreates,
        };
        view.insert(cb_op, cb.outputs[0].clone());
        txs.insert(0, cb.clone());

        let ids: Vec<Hash32> = txs.iter().map(txid).collect();
        let bits = expected_bits(db, height, parent_hi.as_ref())?;
        let header = BlockHeader { version: 1, prev: parent, merkle: merkle_root_txids(&ids), time, bits, nonce: 0 };
        let hash = header_hash(&header);
        let blk = Block { header, txs };
        db.blocks.insert(k_block(&hash), csd::codec::consensus_bincode().serialize(&blk)?)?;
        index_header(db, &blk.header, parent_hi.as_ref())?;
        self.built.insert(hash, Built { height, parent, view, coinbase: cb, fees });
        Ok((hash, kind))
    }

    /// A signed spend of one key's coins in `view` to one to four addresses, with a fee of 0 to
    /// 1,000; None when no key holds a coin.
    fn random_spend(&mut self, view: &View) -> Option<(Transaction, u64)> {
        let mut owned: Vec<(OutPoint, TxOut)> = view
            .iter()
            .filter(|(_, o)| self.sk_of(&o.script_pubkey).is_some() && o.value >= 8)
            .map(|(op, o)| (*op, o.clone()))
            .collect();
        if owned.is_empty() {
            return None;
        }
        owned.sort_by_key(|(op, _)| (op.txid, op.vout));
        let owner = owned[self.rng.gen_range(0..owned.len())].1.script_pubkey;
        let mine: Vec<(OutPoint, TxOut)> = owned.into_iter().filter(|(_, o)| o.script_pubkey == owner).collect();
        let take = self.rng.gen_range(1..=mine.len().min(3));
        let inputs = &mine[..take];
        let total: u64 = inputs.iter().map(|(_, o)| o.value).sum();
        let n_out = self.rng.gen_range(1..=4u64);
        let fee = self.rng.gen_range(0..=1_000u64).min(total - n_out);
        let mut left = total - fee;
        let mut outputs = Vec::new();
        for k in 0..n_out {
            let value = if k + 1 == n_out { left } else { self.rng.gen_range(1..=left - (n_out - k - 1)) };
            left -= value;
            outputs.push(TxOut { value, script_pubkey: self.any_addr() });
        }
        let tx = Transaction {
            version: 1,
            inputs: inputs.iter().map(|(op, _)| TxIn { prevout: *op, script_sig: vec![] }).collect(),
            outputs,
            locktime: 0,
            app: AppPayload::None,
        };
        Some((sign(tx, self.sk_of(&owner)?), fee))
    }

    /// The outpoint of the coinbase output of a block the generator built.
    pub fn coinbase_outpoint(&self, block: &Hash32) -> OutPoint {
        OutPoint { txid: txid(&self.built[block].coinbase), vout: 0 }
    }

    /// The block hash `depth` blocks below the tip.
    pub fn ancestor(&self, db: &Stores, depth: u64) -> Result<Hash32> {
        let mut cur = get_tip(db)?.context("no tip")?;
        for _ in 0..depth {
            cur = get_hidx(db, &cur)?.context("header index")?.parent;
        }
        Ok(cur)
    }

    /// Builds one block on the tip (the genesis on an empty datadir) and moves the tip to it;
    /// returns its hash and what its coinbase did (`build`).
    pub fn extend(&mut self, db: &Stores, dup: bool, spend: bool) -> Result<(Hash32, Coinbase)> {
        let parent = get_tip(db)?.unwrap_or([0u8; 32]);
        let (new, kind) = self.build(db, parent, dup, spend)?;
        Ok((self.move_tip(db, new)?, kind))
    }

    /// Builds `depth + 1` blocks on the block `depth` below the tip and reorgs to them.
    pub fn reorg(&mut self, db: &Stores, depth: u64) -> Result<Hash32> {
        let mut cur = self.ancestor(db, depth)?;
        for _ in 0..=depth {
            cur = self.build(db, cur, false, false)?.0;
        }
        self.move_tip(db, cur)
    }

    fn move_tip(&self, db: &Stores, new: Hash32) -> Result<Hash32> {
        maybe_reorg_to(db, &new, None)?;
        if get_tip(db)? != Some(new) {
            bail!("the tip did not move to 0x{}", hex::encode(new));
        }
        Ok(new)
    }

    /// Re-learns the chain after a restart: the views of every block on the chain to the tip,
    /// replayed from the stored bodies.
    pub fn relearn(&mut self, db: &Stores) -> Result<()> {
        let Some(tip) = get_tip(db)? else { return Ok(()) };
        let mut chain = Vec::new();
        let mut cur = tip;
        loop {
            chain.push(cur);
            let hi = get_hidx(db, &cur)?.context("header index")?;
            if hi.height == 0 {
                break;
            }
            cur = hi.parent;
        }
        let mut view = View::new();
        let mut parent = [0u8; 32];
        for h in chain.into_iter().rev() {
            let blk: Block = csd::codec::consensus_bincode().deserialize(&db.blocks.get(k_block(&h))?.context("body")?)?;
            let mut fees_in = 0u64;
            let mut fees_out = 0u64;
            for tx in blk.txs.iter().skip(1) {
                for i in &tx.inputs {
                    fees_in += view.remove(&i.prevout).map(|o| o.value).unwrap_or(0);
                }
                let id = txid(tx);
                for (v, out) in tx.outputs.iter().enumerate() {
                    fees_out += out.value;
                    view.insert(OutPoint { txid: id, vout: v as u32 }, out.clone());
                }
            }
            let cb = blk.txs[0].clone();
            view.insert(OutPoint { txid: txid(&cb), vout: 0 }, cb.outputs[0].clone());
            let height = get_hidx(db, &h)?.context("header index")?.height;
            self.built.insert(h, Built { height, parent, view: view.clone(), coinbase: cb, fees: fees_in - fees_out });
            parent = h;
        }
        Ok(())
    }
}

/// Runs the reconciler until the index is current, `budget` blocks a tick.
pub fn reconcile(db: &Stores, budget: usize) -> Result<()> {
    for _ in 0..1_000_000 {
        if reconcile_tick(db, budget)? {
            return Ok(());
        }
    }
    bail!("the index did not converge")
}

/// A read's answer: the tip, its height, the outputs and the lifetime totals.
pub type Answer = (Option<Hash32>, u64, Vec<csd::state::addr_index::AddrUtxo>, Option<(u64, u64)>);

/// A read without the field that says which path answered.
pub fn answer(r: AddrRead) -> Answer {
    (r.tip, r.tip_height, r.utxos, r.lifetime)
}

/// For every address in `universe`: the index's read equals the scan's, lifetime totals included.
/// Returns the number of reads compared.
pub fn assert_index_equals_scan(db: &Stores, universe: &[Hash20], ctx: &str) -> Result<usize> {
    for a in universe {
        let via_index = read_via_index(db, a, true)
            .with_context(|| format!("{ctx}: the index did not answer for 0x{}", hex::encode(a)))?;
        let via_scan = read_via_scan(db, a, true)?;
        if answer(via_index.clone()) != answer(via_scan.clone()) {
            bail!("{ctx}: 0x{} index {:?} scan {:?}", hex::encode(a), via_index, via_scan);
        }
    }
    Ok(universe.len())
}
