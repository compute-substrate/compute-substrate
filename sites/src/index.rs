// Which sites .csd names point to, read from this door's own node: every CairnX `nprofile` record
// (a name's profile, CairnX convention section 22) whose `contenthash` is ipfs://<CID>. A door keeps
// a site only while some name's latest profile, by the key that wrote it, points to it, and for a
// grace period after it stops: so whoever wants a site kept has paid for a record on the network,
// and nobody can push a name's own site out by writing a profile of their own for it.
//
// A door also keeps any site someone has paid to keep, name or not: a record under `csd.keep` whose
// text is the site's address (ipfs://<CID>) keeps it a year from where its time stands (or from that
// block, once it has run out), plus a year for every 0.25 CSD the record burns (an output to the
// all-zero address, which nobody can spend). Anyone can add time to any site, and anyone can add up
// how long a site is kept, from the records alone. So a site can outlive its name, and its maker.
//
// This doesn't decide who holds a name (readers do that, with Cairn's resolver). It only decides
// what's worth keeping.

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;

pub const DOMAIN: &str = "cairnx:v1";
// CairnX v1.9, when nprofile records began to count
pub const FIRST_HEIGHT: u64 = 36_700;
// how long a site stays after its name points elsewhere: 30 days of 2-minute blocks
pub const GRACE_BLOCKS: u64 = 30 * 24 * 30;
pub const KEEP_DOMAIN: &str = "csd.keep";
// no keep record is older than this block
pub const KEEP_FROM: u64 = 147_000;
// a year of 2-minute blocks
pub const YEAR_BLOCKS: u64 = 365 * 24 * 30;
// each 0.25 CSD burned adds a year
pub const PER_YEAR: u64 = 25_000_000;
pub const MAX_YEARS: u64 = 1000;

#[derive(Serialize, Deserialize, Default)]
pub struct Index {
    // the next block to read
    pub next: u64,
    // "<name> <author>" -> the site that key's latest profile for the name points to, and where
    pub current: BTreeMap<String, (String, u64)>,
    // sites no profile points to any more -> the block that stopped pointing to them
    pub dropped: BTreeMap<String, u64>,
    pub tip: u64,
    // sites paid to be kept -> the block they're kept until
    #[serde(default)]
    pub kept: BTreeMap<String, u64>,
    // the next block of keep records to read
    #[serde(default)]
    pub keep_next: u64,
}

impl Index {
    pub fn wanted(&self, cid: &str) -> bool {
        self.current.values().any(|(c, _)| c == cid)
            || self.dropped.get(cid).is_some_and(|&h| h + GRACE_BLOCKS > self.tip)
            || self.kept.get(cid).is_some_and(|&u| u > self.tip)
    }

    // One keep record, at `height`, burning `burned`
    pub fn keep(&mut self, cid: &str, burned: u64, height: u64) {
        let years = (1 + burned / PER_YEAR).min(MAX_YEARS);
        let until = self.kept.get(cid).copied().unwrap_or(0).max(height) + years * YEAR_BLOCKS;
        self.kept.insert(cid.to_string(), until);
    }

    // One nprofile record, at `height`, by `author`
    pub fn apply(&mut self, name: &str, author: &str, site: Option<String>, height: u64) {
        let key = format!("{name} {author}");
        if self.current.get(&key).is_some_and(|&(_, h)| h > height) {
            return; // an older record, read again
        }
        let old = match &site {
            Some(c) => self.current.insert(key, (c.clone(), height)),
            None => self.current.remove(&key),
        };
        if let Some(c) = &site {
            self.dropped.remove(c);
        }
        if let Some((c, _)) = old {
            if Some(&c) != site.as_ref() && !self.current.values().any(|(x, _)| *x == c) {
                self.dropped.insert(c, height);
            }
        }
    }
}

// What a CairnX record says, when it's a name's profile: (name, ipfs CID or none)
pub fn profile_site(uri: &str) -> Option<(String, Option<String>)> {
    let v: serde_json::Value = serde_json::from_str(uri).ok()?;
    if v.get("t")?.as_str()? != "nprofile" {
        return None;
    }
    let name = v.get("name")?.as_str()?.to_string();
    let site = v.get("p").and_then(|p| p.get("contenthash")).and_then(|c| c.as_str())
        .and_then(|c| c.strip_prefix("ipfs://"))
        .filter(|c| crate::car::parse_cid(c).is_some())
        .map(str::to_string);
    Some((name, site))
}

// A transaction in the node's encoding: (the key that signed its first input, its record's uri).
// The node this reads from has checked every signature itself.
pub fn parse_tx(b: &[u8]) -> Option<(String, String)> {
    parse_record(b).map(|r| (r.author, r.uri))
}

pub struct Record {
    pub author: String,
    pub uri: String,
    // CSD sent to the all-zero address, which nobody can spend
    pub burned: u64,
}

// What a keep record says: the site's CID
pub fn keep_site(uri: &str) -> Option<String> {
    uri.trim().strip_prefix("ipfs://").filter(|c| crate::car::parse_cid(c).is_some()).map(str::to_string)
}

pub fn parse_record(b: &[u8]) -> Option<Record> {
    let mut o = 0usize;
    let take = |o: &mut usize, n: usize| -> Option<&[u8]> { let s = b.get(*o..*o + n)?; *o += n; Some(s) };
    let u32_ = |o: &mut usize| -> Option<u32> { Some(u32::from_le_bytes(take(o, 4)?.try_into().ok()?)) };
    let u64_ = |o: &mut usize| -> Option<u64> { Some(u64::from_le_bytes(take(o, 8)?.try_into().ok()?)) };
    u32_(&mut o)?;
    let nin = u64_(&mut o)?;
    if nin == 0 || nin > 10_000 { return None; }
    let mut script0: Option<Vec<u8>> = None;
    for i in 0..nin {
        take(&mut o, 36)?;
        let n = u64_(&mut o)? as usize;
        let s = take(&mut o, n)?;
        if i == 0 { script0 = Some(s.to_vec()); }
    }
    let nout = u64_(&mut o)?;
    if nout > 10_000 { return None; }
    let mut burned = 0u64;
    for _ in 0..nout {
        let v = u64_(&mut o)?;
        if take(&mut o, 20)?.iter().all(|&x| x == 0) { burned = burned.saturating_add(v); }
    }
    u32_(&mut o)?; // locktime
    if u32_(&mut o)? != 1 { return None; } // a proposal
    let dl = u64_(&mut o)? as usize;
    if dl > 128 { return None; }
    take(&mut o, dl)?;
    take(&mut o, 32)?;
    let ul = u64_(&mut o)? as usize;
    if ul > 512 { return None; }
    let uri = String::from_utf8(take(&mut o, ul)?.to_vec()).ok()?;
    let s = script0?;
    if s.len() < 99 || s[0] != 64 || s[65] != 33 { return None; }
    let author = hex::encode(ripemd::Ripemd160::digest(Sha256::digest(&s[66..99])));
    Some(Record { author, uri, burned })
}

// Read the node's keep records from `index.keep_next` up to its tip
pub fn catch_up_keeps(node: &str, index: &mut Index) -> Result<(), String> {
    if index.keep_next < KEEP_FROM {
        index.keep_next = KEEP_FROM;
    }
    loop {
        let url = format!("{node}/events/{KEEP_DOMAIN}/{}/2000", index.keep_next);
        let j: serde_json::Value = ureq::get(&url).timeout(std::time::Duration::from_secs(60)).call()
            .map_err(|e| format!("reading {url}: {e}"))?.into_json().map_err(|e| e.to_string())?;
        if j["ok"] != true {
            return Err(format!("the node can't list keep records: {}", j));
        }
        for e in j["events"].as_array().cloned().unwrap_or_default() {
            let raw = e["tx_raw"].as_str().unwrap_or("").trim_start_matches("0x");
            let Ok(bytes) = hex::decode(raw) else { continue };
            let Some(r) = parse_record(&bytes) else { continue };
            if let Some(cid) = keep_site(&r.uri) {
                index.keep(&cid, r.burned, e["height"].as_u64().unwrap_or(0));
            }
        }
        let (to, tip) = (j["to"].as_u64().unwrap_or(0), j["tip_height"].as_u64().unwrap_or(0));
        if to < index.keep_next {
            return Ok(());
        }
        index.keep_next = to + 1;
        if to >= tip {
            return Ok(());
        }
    }
}

// Read the node's CairnX records from `index.next` up to its tip, 2000 blocks a request
pub fn catch_up(node: &str, index: &mut Index) -> Result<(), String> {
    if index.next < FIRST_HEIGHT {
        index.next = FIRST_HEIGHT;
    }
    loop {
        let url = format!("{node}/events/{}/{}/2000", DOMAIN.replace(':', "%3A"), index.next);
        let j: serde_json::Value = ureq::get(&url).timeout(std::time::Duration::from_secs(60)).call()
            .map_err(|e| format!("reading {url}: {e}"))?.into_json().map_err(|e| e.to_string())?;
        if j["ok"] != true {
            return Err(format!("the node can't list names' records: {}", j));
        }
        for e in j["events"].as_array().cloned().unwrap_or_default() {
            let raw = e["tx_raw"].as_str().unwrap_or("").trim_start_matches("0x");
            let Ok(bytes) = hex::decode(raw) else { continue };
            let Some((author, uri)) = parse_tx(&bytes) else { continue };
            if let Some((name, site)) = profile_site(&uri) {
                index.apply(&name, &author, site, e["height"].as_u64().unwrap_or(0));
            }
        }
        let (to, tip) = (j["to"].as_u64().unwrap_or(0), j["tip_height"].as_u64().unwrap_or(0));
        index.tip = tip;
        if to < index.next {
            return Ok(()); // nothing new
        }
        index.next = to + 1;
        if to >= tip {
            return Ok(());
        }
    }
}
