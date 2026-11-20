// Checking a site's .car against the address it's said to be, before keeping it: every block must
// hash to its own address, and every block reachable from the root must be there. The same check the
// Node app makes (app/resolver/src/site.ts), so a door keeps nothing a reader would refuse.
//
// Only what IPFS sites use: CIDv0 and CIDv1, sha2-256, dag-pb (folders and files) and raw leaves.

use sha2::{Digest, Sha256};
use std::collections::{HashMap, HashSet};

pub const DAG_PB: u64 = 0x70;
pub const RAW: u64 = 0x55;
const SHA2_256: u64 = 0x12;

#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
pub struct Cid {
    pub codec: u64,
    pub digest: [u8; 32],
}

fn varint(b: &[u8], at: &mut usize) -> Result<u64, String> {
    let mut x = 0u64;
    for i in 0..10 {
        let byte = *b.get(*at).ok_or("truncated")?;
        *at += 1;
        x |= ((byte & 0x7f) as u64) << (7 * i);
        if byte & 0x80 == 0 {
            return Ok(x);
        }
    }
    Err("bad varint".into())
}

// A CID in its binary form, starting at `at`; moves `at` past it
pub fn cid_bytes(b: &[u8], at: &mut usize) -> Result<Cid, String> {
    if b.get(*at) == Some(&0x12) && b.get(*at + 1) == Some(&0x20) {
        let d = b.get(*at + 2..*at + 34).ok_or("truncated")?;
        *at += 34;
        return Ok(Cid { codec: DAG_PB, digest: d.try_into().unwrap() });
    }
    if varint(b, at)? != 1 {
        return Err("unknown CID version".into());
    }
    let codec = varint(b, at)?;
    let (code, len) = (varint(b, at)?, varint(b, at)?);
    if code != SHA2_256 || len != 32 {
        return Err("a block uses a hash this doesn't check".into());
    }
    let d = b.get(*at..*at + 32).ok_or("truncated")?;
    *at += 32;
    Ok(Cid { codec, digest: d.try_into().unwrap() })
}

// A CIDv1 as text: b + base32, as names point to sites (ipfs://bafy…)
pub fn parse_cid(s: &str) -> Option<Cid> {
    let rest = s.strip_prefix('b')?;
    if rest.len() < 50 || rest.len() > 100 || !rest.chars().all(|c| c.is_ascii_lowercase() || ('2'..='7').contains(&c)) {
        return None;
    }
    let bytes = data_encoding::BASE32_NOPAD.decode(rest.to_ascii_uppercase().as_bytes()).ok()?;
    let mut at = 0;
    let c = cid_bytes(&bytes, &mut at).ok()?;
    (at == bytes.len() && (c.codec == DAG_PB || c.codec == RAW)).then_some(c)
}

// The links of a dag-pb node (protobuf: Links = field 2, each with Hash = field 1)
fn links(node: &[u8]) -> Result<Vec<Cid>, String> {
    let mut out = Vec::new();
    let mut at = 0;
    while at < node.len() {
        let tag = varint(node, &mut at)?;
        match tag & 7 {
            0 => {
                varint(node, &mut at)?;
            }
            2 => {
                let len = varint(node, &mut at)? as usize;
                let body = node.get(at..at + len).ok_or("truncated")?;
                at += len;
                if tag >> 3 == 2 {
                    let mut p = 0;
                    while p < body.len() {
                        let t = varint(body, &mut p)?;
                        match t & 7 {
                            0 => {
                                varint(body, &mut p)?;
                            }
                            2 => {
                                let l = varint(body, &mut p)? as usize;
                                let v = body.get(p..p + l).ok_or("truncated")?;
                                p += l;
                                if t >> 3 == 1 {
                                    let mut q = 0;
                                    out.push(cid_bytes(v, &mut q)?);
                                }
                            }
                            _ => return Err("bad link".into()),
                        }
                    }
                }
            }
            _ => return Err("bad dag-pb node".into()),
        }
    }
    Ok(out)
}

// The whole check. Returns how many bytes of blocks the site has.
pub fn check(car: &[u8], root: Cid) -> Result<usize, String> {
    let mut at = 0;
    let hlen = varint(car, &mut at)? as usize;
    at = at.checked_add(hlen).filter(|&a| a <= car.len()).ok_or("truncated header")?;
    let mut blocks: HashMap<Cid, (usize, usize)> = HashMap::new();
    while at < car.len() {
        let len = varint(car, &mut at)? as usize;
        let end = at.checked_add(len).filter(|&e| e <= car.len()).ok_or("truncated block")?;
        let mut p = at;
        let cid = cid_bytes(car, &mut p)?;
        if p > end {
            return Err("truncated block".into());
        }
        if Sha256::digest(&car[p..end]).as_slice() != cid.digest {
            return Err("a block doesn't match its address".into());
        }
        blocks.insert(cid, (p, end));
        at = end;
        if blocks.len() > 500_000 {
            return Err("too many blocks".into());
        }
    }
    // everything reachable from the root, present
    let (mut seen, mut todo, mut bytes) = (HashSet::new(), vec![root], 0usize);
    while let Some(c) = todo.pop() {
        if !seen.insert(c) {
            continue;
        }
        let &(s, e) = blocks.get(&c).ok_or("the site is incomplete")?;
        bytes += e - s;
        match c.codec {
            DAG_PB => todo.extend(links(&car[s..e])?),
            RAW => {}
            _ => return Err("a block of a kind sites don't use".into()),
        }
    }
    Ok(bytes)
}
