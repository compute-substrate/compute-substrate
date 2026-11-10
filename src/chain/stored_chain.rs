// src/chain/stored_chain.rs
//! Which stored chain this node can apply: the selection behind journal-less recovery
//! (`chain::reorg`) and the stall sweep (`net::node`). It decides only which chain is tried; every
//! block of that chain still goes through `validate_and_apply_block`.

use anyhow::Result;
use std::collections::{HashMap, HashSet};
use std::ops::Bound;

use crate::chain::index::{get_hidx, HeaderIndex};
use crate::state::db::{bad_mark_hash, get_tip, k_bad_prefix, k_block, Stores};
use crate::types::Hash32;

/// Recovery's selection: the highest-work candidate whose header chain has every body stored
/// down to a block `base` accepts and passes no block `on_rejected` holds. `no_index` decides a
/// candidate whose chain reaches a body without a header index.
pub(crate) fn best_complete(
    db: &Stores,
    candidates: Vec<HeaderIndex>,
    on_rejected: &mut RejectedChains,
    mut base: impl FnMut(&HeaderIndex) -> Result<bool>,
    mut no_index: impl FnMut(&Hash32) -> bool,
) -> Result<Option<HeaderIndex>> {
    let mut selection = Selection::new(candidates, on_rejected.rejected.clone());
    let mut reads = u64::MAX;
    let mut base = |hi: &HeaderIndex, _: &mut u64| base(hi).map(Some);
    match selection.run(db, &mut reads, &mut base, &mut no_index)? {
        Step::Found(hi) => Ok(Some(hi)),
        Step::Exhausted | Step::Paused => Ok(None),
    }
}

/// Where a search stands after `run`.
pub(crate) enum Step {
    Found(HeaderIndex),
    /// No candidate is complete.
    Exhausted,
    /// The reads ran out; `run` resumes where it stopped.
    Paused,
}

enum WalkEnd {
    Complete,
    Excluded,
    NoIndex,
}

/// Candidates heaviest first, each walked down to the first block that is excluded or has no
/// body, which excludes every block walked over it, or to a block the base accepts, which
/// selects the candidate. Exclusions only grow, so each block is read about once per search
/// however many candidates share it, and a paused walk resumes at the block it reached.
struct Selection {
    candidates: Vec<HeaderIndex>,
    next: usize,
    walk: Option<(Hash32, Vec<Hash32>)>,
    excluded: HashSet<Hash32>,
}

impl Selection {
    fn new(mut candidates: Vec<HeaderIndex>, excluded: HashSet<Hash32>) -> Self {
        // Heaviest first. The sort is stable, so equal work keeps the caller's order: the first
        // such block wins, as under better_candidate's strictly-greater rule.
        candidates.sort_by(|a, b| b.chainwork.cmp(&a.chainwork));
        Self { candidates, next: 0, walk: None, excluded }
    }

    /// Spends at most `reads`: two per block walked (its body and its header index), and whatever
    /// `base` counts.
    fn run(
        &mut self,
        db: &Stores,
        reads: &mut u64,
        base: &mut impl FnMut(&HeaderIndex, &mut u64) -> Result<Option<bool>>,
        no_index: &mut impl FnMut(&Hash32) -> bool,
    ) -> Result<Step> {
        while let Some(cand) = self.candidates.get(self.next) {
            let (mut cur, mut walked) = self.walk.take().unwrap_or_else(|| (cand.hash, Vec::new()));
            let end = loop {
                if self.excluded.contains(&cur) {
                    break WalkEnd::Excluded;
                }
                if *reads < 2 {
                    self.walk = Some((cur, walked));
                    return Ok(Step::Paused);
                }
                *reads -= 2;
                if !db.blocks.contains_key(k_block(&cur))? {
                    self.excluded.insert(cur);
                    break WalkEnd::Excluded;
                }
                let Some(hi) = get_hidx(db, &cur)? else { break WalkEnd::NoIndex };
                match base(&hi, reads)? {
                    None => {
                        self.walk = Some((cur, walked));
                        return Ok(Step::Paused);
                    }
                    Some(true) => break WalkEnd::Complete,
                    Some(false) => {
                        walked.push(cur);
                        cur = hi.parent;
                    }
                }
            };
            match end {
                WalkEnd::Complete => return Ok(Step::Found(cand.clone())),
                WalkEnd::Excluded => self.excluded.extend(walked),
                WalkEnd::NoIndex => {
                    if no_index(&cand.hash) {
                        return Ok(Step::Found(cand.clone()));
                    }
                }
            }
            self.next += 1;
        }
        Ok(Step::Exhausted)
    }
}

/// The stall sweep's search: the heaviest stored chain heavier than the local tip whose bodies
/// are all stored down to the local chain and that passes no `bad:` block (`maybe_reorg_to`
/// refuses one), run in slices of a given number of reads. It scans the header index for headers
/// heavier than the tip (one read per entry, one more for the body of each such header), then
/// the `bad:` marks (one read each), then walks the headers with a body heaviest first
/// (`Selection`), reading the local chain from the tip down only as far as a walk reaches (one
/// read per block). Every phase stops when the reads run out and resumes where it stopped.
pub(crate) struct AboveTip {
    tip: HeaderIndex,
    scan_after: Option<Vec<u8>>,
    scanned: bool,
    candidates: Vec<HeaderIndex>,
    marks_after: Option<Vec<u8>>,
    marks: HashSet<Hash32>,
    selection: Option<Selection>,
    local: LocalChain,
}

impl AboveTip {
    /// None when the node has no tip.
    pub(crate) fn new(db: &Stores) -> Result<Option<Self>> {
        let Some(tip) = get_tip(db)? else { return Ok(None) };
        let Some(tip_hi) = get_hidx(db, &tip)? else { return Ok(None) };
        let local = LocalChain { hashes: HashSet::from([tip_hi.hash]), lowest: tip_hi.clone() };
        Ok(Some(Self {
            tip: tip_hi,
            scan_after: None,
            scanned: false,
            candidates: Vec::new(),
            marks_after: None,
            marks: HashSet::new(),
            selection: None,
            local,
        }))
    }

    pub(crate) fn tip(&self) -> Hash32 {
        self.tip.hash
    }

    /// Spends at most `reads` and says where the search stands.
    pub(crate) fn run(&mut self, db: &Stores, reads: &mut u64) -> Result<Step> {
        if !self.scanned {
            let entries = match &self.scan_after {
                None => db.hdr.iter(),
                Some(k) => db.hdr.range::<Vec<u8>, _>((Bound::Excluded(k.clone()), Bound::Unbounded)),
            };
            for kv in entries {
                if *reads < 2 {
                    return Ok(Step::Paused);
                }
                *reads -= 1;
                let (k, v) = kv?;
                let hi: HeaderIndex = crate::codec::consensus_bincode().deserialize(&v)?;
                if hi.chainwork > self.tip.chainwork {
                    *reads -= 1;
                    if db.blocks.contains_key(k_block(&hi.hash))? {
                        self.candidates.push(hi);
                    }
                }
                self.scan_after = Some(k.to_vec());
            }
            self.scanned = true;
        }
        if self.selection.is_none() {
            let keys = match &self.marks_after {
                None => db.meta.scan_prefix(k_bad_prefix()),
                Some(k) => db.meta.range::<Vec<u8>, _>((Bound::Excluded(k.clone()), Bound::Unbounded)),
            };
            for k in keys.keys() {
                if *reads == 0 {
                    return Ok(Step::Paused);
                }
                *reads -= 1;
                let k = k?;
                if !k.starts_with(k_bad_prefix()) {
                    break;
                }
                self.marks.extend(bad_mark_hash(&k));
                self.marks_after = Some(k.to_vec());
            }
            let candidates = std::mem::take(&mut self.candidates);
            self.selection = Some(Selection::new(candidates, std::mem::take(&mut self.marks)));
        }
        let (selection, local) = (self.selection.as_mut().expect("set above"), &mut self.local);
        selection.run(db, reads, &mut |hi: &HeaderIndex, r: &mut u64| local.contains(db, hi, r), &mut |_: &Hash32| false)
    }
}

/// The local chain from the tip down, read only as far down as a query needs.
struct LocalChain {
    hashes: HashSet<Hash32>,
    lowest: HeaderIndex,
}

impl LocalChain {
    /// None when `reads` ran out first.
    fn contains(&mut self, db: &Stores, hi: &HeaderIndex, reads: &mut u64) -> Result<Option<bool>> {
        while self.lowest.height > hi.height {
            if *reads == 0 {
                return Ok(None);
            }
            *reads -= 1;
            let Some(parent) = get_hidx(db, &self.lowest.parent)? else { break };
            self.hashes.insert(parent.hash);
            self.lowest = parent;
        }
        Ok(Some(self.hashes.contains(&hi.hash)))
    }
}

/// Whether a block is, or descends from, a rejected block, by walking the header index down to the
/// lowest rejected height: journal-less recovery's check of its own tips (`reorg.rs`), which also
/// hands the rejected set to `best_complete`. Answers are cached along each walk; with nothing
/// rejected it reads nothing.
pub(crate) struct RejectedChains<'a> {
    db: &'a Stores,
    rejected: HashSet<Hash32>,
    min_height: u64,
    known: HashMap<Hash32, bool>,
}

impl<'a> RejectedChains<'a> {
    pub(crate) fn new(db: &'a Stores, rejected: &HashSet<Hash32>) -> Result<Self> {
        let mut chains = Self { db, rejected: HashSet::new(), min_height: u64::MAX, known: HashMap::new() };
        for h in rejected {
            chains.exclude(db, *h)?;
        }
        Ok(chains)
    }

    /// Adds `h`; cached answers are dropped, as a "no" may have become a "yes".
    fn exclude(&mut self, db: &Stores, h: Hash32) -> Result<()> {
        self.min_height = self.min_height.min(get_hidx(db, &h)?.map_or(0, |hi| hi.height));
        self.rejected.insert(h);
        self.known.clear();
        Ok(())
    }

    pub(crate) fn contains(&mut self, h: &Hash32) -> Result<bool> {
        if self.rejected.is_empty() {
            return Ok(false);
        }
        let mut walked = Vec::new();
        let mut cur = *h;
        let found = loop {
            if self.rejected.contains(&cur) {
                break true;
            }
            if let Some(&v) = self.known.get(&cur) {
                break v;
            }
            match get_hidx(self.db, &cur)? {
                Some(hi) if hi.height > self.min_height => {
                    walked.push(cur);
                    cur = hi.parent;
                }
                _ => break false,
            }
        };
        for w in walked {
            self.known.insert(w, found);
        }
        Ok(found)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // A sweep must cost reads linear in the headers, and stay within its slice.
    // Tip h2000, an unrelated `bad:` mark at height 1, 256 two-block forks above the tip whose first
    // body is missing, and one chain of 1,000 stored blocks above a missing one. A sweep that walks
    // the canonical history to the mark for each fork costs about 15M reads at height 60,000.
    #[test]
    fn a_sweep_reads_linearly_and_within_its_slice() {
        let tmp = tempfile::TempDir::new().unwrap();
        let db = Stores::open(tmp.path().to_str().unwrap()).unwrap();
        let hash = |fork: u16, h: u64| -> Hash32 {
            let mut x = [0u8; 32];
            x[..8].copy_from_slice(&h.to_le_bytes());
            x[8..10].copy_from_slice(&fork.to_le_bytes());
            x[31] = 1;
            x
        };
        let (mut headers, mut bodies) = (sled::Batch::default(), sled::Batch::default());
        let mut count = 0u64;
        let mut put = |h: Hash32, parent: Hash32, height: u64, chainwork: u128, stored: bool| {
            let hi = HeaderIndex { hash: h, parent, height, chainwork, bits: 0, time: 0 };
            headers.insert(crate::state::db::k_hdr(&h), crate::codec::consensus_bincode().serialize(&hi).unwrap());
            if stored {
                bodies.insert(k_block(&h), vec![1u8]);
            }
            count += 1;
        };
        let canon = |h| hash(0, h);
        put(canon(0), [0u8; 32], 0, 1, true);
        for h in 1..=2000 {
            put(canon(h), canon(h - 1), h, h as u128 + 1, true);
        }
        put(hash(1, 1), canon(0), 1, 2, true);
        for f in 2..258 {
            put(hash(f, 2001), canon(2000), 2001, 2002, false);
            put(hash(f, 2002), hash(f, 2001), 2002, 2003, true);
        }
        put(hash(300, 2001), canon(2000), 2001, 2002, false);
        for h in 2002..3001 {
            put(hash(300, h), hash(300, h - 1), h, h as u128 + 1, true);
        }
        db.hdr.apply_batch(headers).unwrap();
        db.blocks.apply_batch(bodies).unwrap();
        db.meta.insert(crate::state::db::k_bad(&hash(1, 1)), &b"1"[..]).unwrap();
        crate::state::db::set_tip(&db, &canon(2000)).unwrap();

        let mut whole = AboveTip::new(&db).unwrap().unwrap();
        let mut reads = u64::MAX;
        assert!(matches!(whole.run(&db, &mut reads).unwrap(), Step::Exhausted));
        let used = u64::MAX - reads;
        assert!(used <= 3 * count, "{used} reads for {count} headers");

        let mut sliced = AboveTip::new(&db).unwrap().unwrap();
        let mut slices = 0;
        loop {
            let mut reads = 1_000;
            let step = sliced.run(&db, &mut reads).unwrap();
            assert!(reads <= 1_000);
            slices += 1;
            match step {
                Step::Paused => assert!(slices < 100, "a sliced search ends"),
                Step::Exhausted => break,
                Step::Found(hi) => panic!("found {:?}", hi.height),
            }
        }
        assert!(slices as u64 >= used / 1_000, "{slices} slices of at most 1,000 reads for {used}");
    }

    // The `bad:` marks count in a slice too. With 50 marks and slices of 10
    // reads, a search pauses inside the mark phase and resumes there, and the complete chain whose
    // mark sorts last is still excluded.
    #[test]
    fn a_search_pauses_inside_the_bad_marks_and_resumes() {
        use crate::chain::index::put_hidx;
        let tmp = tempfile::TempDir::new().unwrap();
        let db = Stores::open(tmp.path().to_str().unwrap()).unwrap();
        let (g, t, c) = ([0x10u8; 32], [0x11u8; 32], [0xffu8; 32]);
        for (hash, parent, height) in [(g, [0u8; 32], 0u64), (t, g, 1), (c, t, 2)] {
            put_hidx(&db, &HeaderIndex { hash, parent, height, chainwork: height as u128 + 1, bits: 0, time: 0 }).unwrap();
            db.blocks.insert(k_block(&hash), vec![1u8]).unwrap();
        }
        crate::state::db::set_tip(&db, &t).unwrap();
        for i in 1..50u8 {
            db.meta.insert(crate::state::db::k_bad(&[i; 32]), &b"1"[..]).unwrap();
        }
        db.meta.insert(crate::state::db::k_bad(&c), &b"1"[..]).unwrap();

        let mut search = AboveTip::new(&db).unwrap().unwrap();
        let mut paused_in_marks = false;
        let outcome = loop {
            let mut reads = 10;
            let step = search.run(&db, &mut reads).unwrap();
            paused_in_marks |= search.scanned && search.selection.is_none();
            match step {
                Step::Paused => continue,
                other => break other,
            }
        };
        assert!(paused_in_marks, "a slice ended inside the mark phase");
        assert!(matches!(outcome, Step::Exhausted), "the chain through the last mark is excluded");
    }
}
