// src/bin/csd_anchor.rs
//
// csd-anchor: anchor the contents of a git repository on Compute Substrate.
//
// The substrate stays non-authoritative: this tool only records *that* a given
// set of bytes existed (content hashes + permalinks) at a given chain height.
// It says nothing about whether those bytes are correct.
//
// Workflow:
//   1. manifest  — hash a pinned git commit into a deterministic manifest.json
//   2. plan      — show what would be proposed and what it costs
//   3. fanout    — split wallet funds into one confirmed UTXO per proposal
//                  (the mempool only accepts spends of *confirmed* outputs)
//   4. submit    — build, sign and submit one PROPOSE per pending record
//   5. verify    — check every recorded proposal on chain against the manifest
//   6. diff      — compare two manifests (e.g. anchored release vs. a later commit)
//
// See anchor/README.md for the hash specification.

use std::collections::{BTreeMap, BTreeSet, HashSet};
use std::io::{BufRead, BufReader, Read, Write};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

use anyhow::{anyhow, bail, Context, Result};
use clap::{Parser, Subcommand, ValueEnum};
use secp256k1::{Message, PublicKey, Secp256k1, SecretKey};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use csd::crypto::{hash160, sha256d, sighash, txid};
use csd::params::{EPOCH_LEN, MAX_DOMAIN_BYTES, MAX_TX_OUTPUTS, MAX_URI_BYTES, MIN_FEE_PROPOSE};
use csd::types::{AppPayload, Hash32, OutPoint, Transaction, TxIn, TxOut};

const SPEC: &str = "csd-anchor/v1";
const TREE_TAG: &[u8] = b"csd-anchor/tree/v1\0";
const DEFAULT_DOMAIN: &str = "math/openai-math";
const ROOT_KEY: &str = "@root";
const DUST_LIMIT: u64 = 546; // matches the csd wallet's dust policy
/// Consensus requires >= 1 output per non-coinbase tx, so each proposal returns
/// this amount to the sender; each fan-out output therefore holds fee + RETURN_VALUE.
const RETURN_VALUE: u64 = DUST_LIMIT;
const FANOUT_MAX_OUTPUTS: usize = 500; // stay below MAX_TX_OUTPUTS with room for change
const FANOUT_MAX_INPUTS: usize = 300; // keeps fan-out txs well under MAX_TX_BYTES
const TEN_YEARS_OF_EPOCHS: u64 = 10 * 365 * 24 * 3600 / (120 * EPOCH_LEN);

// ----------------------------------------------------------------------------
// CLI
// ----------------------------------------------------------------------------

#[derive(Parser)]
#[command(
    name = "csd-anchor",
    about = "Anchor a git repository's contents on Compute Substrate (records only; asserts nothing)"
)]
struct Cli {
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Clone, Copy, ValueEnum, PartialEq, Eq)]
enum Mode {
    /// One proposal: the hash of manifest.json (commits to every file)
    Root,
    /// The root proposal plus one proposal per unit, so each manuscript can be attested to on its own
    All,
}

#[derive(Subcommand)]
enum Cmd {
    /// Hash a pinned commit into a deterministic manifest
    Manifest {
        /// Path to a local clone
        #[arg(long)]
        repo: PathBuf,
        /// Commit to pin (any rev; resolved to a full hash)
        #[arg(long, default_value = "HEAD")]
        commit: String,
        /// Public web URL of the repository, used to build permalinks
        #[arg(long, default_value = "https://github.com/openai/math")]
        repo_url: String,
        /// Directories whose immediate subdirectories become their own units
        #[arg(long, default_value = "preprints")]
        split: Vec<String>,
        /// Optional catalogue file (in the repo) listing the current units; marks units as in_catalogue
        #[arg(long, default_value = "CONTENTS.md")]
        catalogue: String,
        /// Output path
        #[arg(long, default_value = "manifest.json")]
        out: PathBuf,
    },

    /// Show what would be proposed and what it costs (no network needed)
    Plan {
        #[arg(long, default_value = "manifest.json")]
        manifest: PathBuf,
        #[arg(long, value_enum, default_value_t = Mode::All)]
        mode: Mode,
        #[arg(long, default_value_t = MIN_FEE_PROPOSE)]
        fee: u64,
    },

    /// Split wallet funds into one confirmed fee-sized UTXO per pending proposal
    Fanout {
        #[command(flatten)]
        net: NetArgs,
        #[arg(long, default_value = "manifest.json")]
        manifest: PathBuf,
        #[arg(long, default_value = "anchor-state.json")]
        state: PathBuf,
        #[arg(long, value_enum, default_value_t = Mode::All)]
        mode: Mode,
        /// Fee per PROPOSE (base units); each fan-out output has exactly this value
        #[arg(long, default_value_t = MIN_FEE_PROPOSE)]
        fee: u64,
        /// Fee for each fan-out transaction itself
        #[arg(long, default_value_t = 1_000_000)]
        fanout_fee: u64,
        /// Actually submit (default is a dry run)
        #[arg(long)]
        send: bool,
    },

    /// Build, sign and submit one PROPOSE per pending record
    Submit {
        #[command(flatten)]
        net: NetArgs,
        #[arg(long, default_value = "manifest.json")]
        manifest: PathBuf,
        #[arg(long, default_value = "anchor-state.json")]
        state: PathBuf,
        #[arg(long, value_enum, default_value_t = Mode::All)]
        mode: Mode,
        /// Where manifest.json is published (the root proposal's URI)
        #[arg(long)]
        manifest_uri: String,
        #[arg(long, default_value = DEFAULT_DOMAIN)]
        domain: String,
        #[arg(long, default_value_t = MIN_FEE_PROPOSE)]
        fee: u64,
        /// Epoch after which attestations are refused; default ≈ 10 years from now
        #[arg(long)]
        expires_epoch: Option<u64>,
        /// Stop after this many submissions (useful for a first small test)
        #[arg(long)]
        limit: Option<usize>,
        /// Actually submit (default is a dry run)
        #[arg(long)]
        send: bool,
    },

    /// Check recorded proposals on chain against the manifest (anyone can run this)
    Verify {
        #[arg(long, default_value = "http://127.0.0.1:8789")]
        rpc: String,
        #[arg(long, default_value = "manifest.json")]
        manifest: PathBuf,
        #[arg(long, default_value = "anchor-state.json")]
        state: PathBuf,
        /// Also print every record
        #[arg(long)]
        verbose: bool,
    },

    /// Find every proposal made for each record (e.g. duplicates), point the state at the earliest one
    Reconcile {
        #[arg(long, default_value = "http://127.0.0.1:8789")]
        rpc: String,
        #[arg(long, default_value = "manifest.json")]
        manifest: PathBuf,
        #[arg(long, default_value = "anchor-state.json")]
        state: PathBuf,
        /// First block height to scan (default: lowest recorded height - 20)
        #[arg(long)]
        from: Option<u64>,
        /// Last block height to scan (default: chain tip)
        #[arg(long)]
        to: Option<u64>,
        /// Write the updated state file (default: report only)
        #[arg(long)]
        write: bool,
    },

    /// Compare two manifests: which units are unchanged, changed, added or removed
    Diff {
        /// The anchored manifest
        old: PathBuf,
        /// A manifest of a later commit
        new: PathBuf,
        /// Write the report as JSON here too
        #[arg(long)]
        json: Option<PathBuf>,
    },
}

#[derive(clap::Args)]
struct NetArgs {
    #[arg(long, default_value = "http://127.0.0.1:8789")]
    rpc: String,
    /// File holding the 32-byte hex private key (alternatively set CSD_PRIVKEY)
    #[arg(long)]
    privkey_file: Option<PathBuf>,
}

// ----------------------------------------------------------------------------
// Manifest
// ----------------------------------------------------------------------------

#[derive(Serialize, Deserialize, Clone)]
struct Manifest {
    spec: String,
    hashing: Hashing,
    source: Source,
    file_count: u64,
    /// Tree hash over every tracked file in the commit
    commit_tree_hash: String,
    units: Vec<Unit>,
}

#[derive(Serialize, Deserialize, Clone)]
struct Hashing {
    leaf: String,
    tree: String,
    manifest: String,
}

#[derive(Serialize, Deserialize, Clone)]
struct Source {
    repo_url: String,
    commit: String,
    commit_time: String,
    git_tree: String,
}

#[derive(Serialize, Deserialize, Clone)]
struct Unit {
    path: String,
    /// "dir" or "file"
    kind: String,
    file_count: u64,
    tree_hash: String,
    uri: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    in_catalogue: Option<bool>,
    #[serde(skip_serializing_if = "Vec::is_empty", default)]
    labels: Vec<String>,
}

#[allow(dead_code)]
struct GitEntry {
    mode: String,
    kind: String,
    oid: String,
    path: String,
}

fn git(repo: &Path, args: &[&str]) -> Result<String> {
    let out = Command::new("git")
        .arg("-C")
        .arg(repo)
        .args(args)
        .output()
        .with_context(|| format!("running git {:?}", args))?;
    if !out.status.success() {
        bail!("git {:?} failed: {}", args, String::from_utf8_lossy(&out.stderr));
    }
    Ok(String::from_utf8(out.stdout)?.trim().to_string())
}

fn list_tree(repo: &Path, commit: &str) -> Result<Vec<GitEntry>> {
    let out = Command::new("git")
        .arg("-C")
        .arg(repo)
        .args(["ls-tree", "-r", "-z", "--full-tree", commit])
        .output()?;
    if !out.status.success() {
        bail!("git ls-tree failed: {}", String::from_utf8_lossy(&out.stderr));
    }
    let mut v = vec![];
    for rec in out.stdout.split(|b| *b == 0) {
        if rec.is_empty() {
            continue;
        }
        let tab = rec.iter().position(|b| *b == b'\t').ok_or_else(|| anyhow!("bad ls-tree record"))?;
        let meta = std::str::from_utf8(&rec[..tab])?;
        let path = String::from_utf8(rec[tab + 1..].to_vec())?;
        let mut it = meta.split(' ');
        let mode = it.next().unwrap_or_default().to_string();
        let kind = it.next().unwrap_or_default().to_string();
        let oid = it.next().unwrap_or_default().to_string();
        v.push(GitEntry { mode, kind, oid, path });
    }
    // Sort by raw path bytes: this order is part of the spec.
    v.sort_by(|a, b| a.path.as_bytes().cmp(b.path.as_bytes()));
    Ok(v)
}

/// Stream blob contents through `git cat-file --batch`, computing sha256d per blob.
/// Returns leaf hashes in the same order as `entries`, plus the content of
/// selected small files (READMEs and the catalogue) for labelling.
fn leaf_hashes(
    repo: &Path,
    entries: &[GitEntry],
    keep: &dyn Fn(&str) -> bool,
) -> Result<(Vec<Hash32>, BTreeMap<String, Vec<u8>>)> {
    let mut child = Command::new("git")
        .arg("-C")
        .arg(repo)
        .args(["cat-file", "--batch"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()?;

    let mut stdin = child.stdin.take().unwrap();
    let oids: Vec<String> = entries
        .iter()
        .filter(|e| e.kind == "blob")
        .map(|e| e.oid.clone())
        .collect();
    let writer = std::thread::spawn(move || -> Result<()> {
        for oid in oids {
            writeln!(stdin, "{}", oid)?;
        }
        Ok(())
    });

    let mut rd = BufReader::with_capacity(1 << 20, child.stdout.take().unwrap());
    let mut leaves = Vec::with_capacity(entries.len());
    let mut kept = BTreeMap::new();
    let total = entries.len();

    for (i, e) in entries.iter().enumerate() {
        if e.kind != "blob" {
            // Submodule (gitlink): commit to the pinned commit id.
            let tagged = format!("gitlink:{}", e.oid);
            leaves.push(sha256d(tagged.as_bytes()));
            continue;
        }
        let mut header = String::new();
        rd.read_line(&mut header)?;
        let parts: Vec<&str> = header.trim_end().split(' ').collect();
        if parts.len() != 3 || parts[0] != e.oid {
            bail!("unexpected cat-file header for {}: {:?}", e.path, header);
        }
        let size: usize = parts[2].parse()?;
        let keep_this = keep(&e.path);
        let mut h1 = Sha256::new();
        let mut buf = vec![0u8; 1 << 16];
        let mut left = size;
        let mut content = if keep_this { Vec::with_capacity(size) } else { vec![] };
        while left > 0 {
            let n = left.min(buf.len());
            rd.read_exact(&mut buf[..n])?;
            h1.update(&buf[..n]);
            if keep_this {
                content.extend_from_slice(&buf[..n]);
            }
            left -= n;
        }
        let mut nl = [0u8; 1];
        rd.read_exact(&mut nl)?;
        let first = h1.finalize();
        let second = Sha256::digest(first);
        let mut leaf = [0u8; 32];
        leaf.copy_from_slice(&second);
        leaves.push(leaf);
        if keep_this {
            kept.insert(e.path.clone(), content);
        }
        if (i + 1) % 20_000 == 0 {
            eprintln!("  hashed {}/{} files", i + 1, total);
        }
    }

    writer.join().map_err(|_| anyhow!("writer thread panicked"))??;
    child.wait()?;
    Ok((leaves, kept))
}

/// tree_hash = sha256d( "csd-anchor/tree/v1\0" || Σ (path_utf8 || 0x00 || leaf32) ),
/// over the given (path, leaf) pairs in ascending path-byte order.
fn tree_hash<'a>(items: impl Iterator<Item = (&'a str, &'a Hash32)>) -> Hash32 {
    let mut h = Sha256::new();
    h.update(TREE_TAG);
    for (p, leaf) in items {
        h.update(p.as_bytes());
        h.update([0u8]);
        h.update(leaf);
    }
    let first = h.finalize();
    let mut out = [0u8; 32];
    out.copy_from_slice(&Sha256::digest(first));
    out
}

fn unit_of(path: &str, split: &[String]) -> String {
    let mut parts = path.splitn(3, '/');
    let top = parts.next().unwrap_or_default();
    if split.iter().any(|s| s == top) {
        if let (Some(sub), Some(_)) = (parts.next(), parts.next()) {
            return format!("{}/{}", top, sub);
        }
    }
    top.to_string()
}

fn hex0x(h: &[u8]) -> String {
    format!("0x{}", hex::encode(h))
}

fn parse_h32(s: &str) -> Result<Hash32> {
    let b = hex::decode(s.trim_start_matches("0x"))?;
    if b.len() != 32 {
        bail!("expected 32-byte hex, got {} bytes", b.len());
    }
    let mut h = [0u8; 32];
    h.copy_from_slice(&b);
    Ok(h)
}

fn cmd_manifest(
    repo: &Path,
    commit: &str,
    repo_url: &str,
    split: &[String],
    catalogue: &str,
    out: &Path,
) -> Result<()> {
    let commit_full = git(repo, &["rev-parse", &format!("{}^{{commit}}", commit)])?;
    let commit_time = git(repo, &["show", "-s", "--format=%cI", &commit_full])?;
    let git_tree = git(repo, &["rev-parse", &format!("{}^{{tree}}", commit_full)])?;

    eprintln!("listing {} ...", commit_full);
    let entries = list_tree(repo, &commit_full)?;
    eprintln!("hashing {} files ...", entries.len());

    let split_owned = split.to_vec();
    let catalogue_owned = catalogue.to_string();
    let keep = move |p: &str| -> bool {
        if p == catalogue_owned {
            return true;
        }
        // README.md directly inside a split unit (used for the "withdrawn" label)
        let segs: Vec<&str> = p.split('/').collect();
        segs.len() == 3 && segs[2] == "README.md" && split_owned.iter().any(|s| s == segs[0])
    };
    let (leaves, kept) = leaf_hashes(repo, &entries, &keep)?;

    let all = tree_hash(entries.iter().map(|e| e.path.as_str()).zip(leaves.iter()));

    // Group into units, preserving path order within each unit.
    let mut groups: BTreeMap<String, Vec<usize>> = BTreeMap::new();
    for (i, e) in entries.iter().enumerate() {
        groups.entry(unit_of(&e.path, split)).or_default().push(i);
    }

    let catalogue_text = kept.get(catalogue).map(|b| String::from_utf8_lossy(b).to_string());

    let base = repo_url.trim_end_matches('/');
    let mut units = vec![];
    for (unit, idxs) in groups {
        let is_file = idxs.len() == 1 && entries[idxs[0]].path == unit;
        let th = tree_hash(idxs.iter().map(|&i| (entries[i].path.as_str(), &leaves[i])));
        let uri = if is_file {
            format!("{}/blob/{}/{}", base, commit_full, unit)
        } else {
            format!("{}/tree/{}/{}", base, commit_full, unit)
        };
        let is_split_unit = unit.contains('/');
        let in_catalogue = match (&catalogue_text, is_split_unit) {
            (Some(t), true) => Some(t.contains(&format!("{}/", unit))),
            _ => None,
        };
        let mut labels = vec![];
        if let Some(readme) = kept.get(&format!("{}/README.md", unit)) {
            let s = String::from_utf8_lossy(readme);
            if s.lines().take(12).any(|l| l.contains("**Withdrawn")) {
                labels.push("withdrawn".to_string());
            }
        }
        units.push(Unit {
            path: unit,
            kind: if is_file { "file".into() } else { "dir".into() },
            file_count: idxs.len() as u64,
            tree_hash: hex0x(&th),
            uri,
            in_catalogue,
            labels,
        });
    }

    let m = Manifest {
        spec: SPEC.into(),
        hashing: Hashing {
            leaf: "sha256d(blob bytes)".into(),
            tree: "sha256d(\"csd-anchor/tree/v1\\0\" || for each file in ascending path-byte order: path || 0x00 || leaf)".into(),
            manifest: "root payload_hash = sha256d(exact bytes of this file)".into(),
        },
        source: Source {
            repo_url: repo_url.into(),
            commit: commit_full.clone(),
            commit_time,
            git_tree,
        },
        file_count: entries.len() as u64,
        commit_tree_hash: hex0x(&all),
        units,
    };

    let mut bytes = serde_json::to_vec_pretty(&m)?;
    bytes.push(b'\n');
    std::fs::write(out, &bytes)?;

    let n_split = m.units.iter().filter(|u| u.path.contains('/')).count();
    let n_withdrawn = m.units.iter().filter(|u| u.labels.iter().any(|l| l == "withdrawn")).count();
    let n_cat = m.units.iter().filter(|u| u.in_catalogue == Some(true)).count();
    println!("manifest     {}", out.display());
    println!("commit       {}  ({})", m.source.commit, m.source.commit_time);
    println!("files        {}", m.file_count);
    println!("units        {} ({} split units, {} in catalogue, {} labelled withdrawn)", m.units.len(), n_split, n_cat, n_withdrawn);
    println!("tree hash    {}", m.commit_tree_hash);
    println!("root payload {}", hex0x(&sha256d(&bytes)));
    Ok(())
}

fn load_manifest(p: &Path) -> Result<(Manifest, Vec<u8>)> {
    let bytes = std::fs::read(p).with_context(|| format!("reading {}", p.display()))?;
    let m: Manifest = serde_json::from_slice(&bytes)?;
    if m.spec != SPEC {
        bail!("unsupported manifest spec {}", m.spec);
    }
    Ok((m, bytes))
}

// ----------------------------------------------------------------------------
// Records (what gets proposed)
// ----------------------------------------------------------------------------

struct Record {
    key: String,
    payload_hash: Hash32,
    uri: String,
}

fn records(m: &Manifest, manifest_bytes: &[u8], manifest_uri: &str, mode: Mode) -> Vec<Record> {
    let mut v = vec![Record {
        key: ROOT_KEY.into(),
        payload_hash: sha256d(manifest_bytes),
        uri: manifest_uri.into(),
    }];
    if mode == Mode::All {
        for u in &m.units {
            v.push(Record {
                key: u.path.clone(),
                payload_hash: parse_h32(&u.tree_hash).expect("manifest tree_hash"),
                uri: u.uri.clone(),
            });
        }
    }
    v
}

fn fmt_csd(base: u64) -> String {
    format!("{}.{:08} CSD", base / 100_000_000, base % 100_000_000)
}

fn cmd_plan(manifest: &Path, mode: Mode, fee: u64) -> Result<()> {
    let (m, bytes) = load_manifest(manifest)?;
    let recs = records(&m, &bytes, "<manifest-uri>", mode);
    let longest = recs.iter().map(|r| r.uri.len()).max().unwrap_or(0);
    let fanouts = recs.len().div_ceil(FANOUT_MAX_OUTPUTS);
    println!("commit          {}", m.source.commit);
    println!("proposals       {}", recs.len());
    println!("fee each        {}", fmt_csd(fee));
    println!("total fees      {}  (+ {} fan-out tx fee(s))", fmt_csd(fee * recs.len() as u64), fanouts);
    println!("funds to lock   {}  ({} base units per proposal return to you)", fmt_csd((fee + RETURN_VALUE) * recs.len() as u64), RETURN_VALUE);
    println!("longest uri     {} bytes (limit {})", longest, MAX_URI_BYTES);
    println!("blocks needed   ~{} (reference miner includes up to 500 txs per block)", recs.len().div_ceil(500));
    if longest > MAX_URI_BYTES {
        bail!("a URI exceeds MAX_URI_BYTES");
    }
    Ok(())
}

// ----------------------------------------------------------------------------
// State (resumable, idempotent)
// ----------------------------------------------------------------------------

#[derive(Serialize, Deserialize, Default)]
struct State {
    manifest_payload_hash: String,
    domain: String,
    /// Address that signed the proposals (hex addr20)
    #[serde(default)]
    sender: String,
    #[serde(default)]
    items: BTreeMap<String, Item>,
    #[serde(default)]
    fanouts: Vec<Fanout>,
}

#[derive(Serialize, Deserialize, Clone)]
struct Fanout {
    txid: String,
    outputs: usize,
    /// "submitted" | "confirmed" | "dropped"
    status: String,
    tx: Transaction,
}

#[derive(Serialize, Deserialize, Clone)]
struct Item {
    payload_hash: String,
    uri: String,
    txid: String,
    input: String,
    /// "submitted" | "confirmed"
    status: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    height: Option<u64>,
    /// Signed transaction, kept so an unmined proposal can be resubmitted unchanged.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    tx: Option<Transaction>,
    /// Other on-chain proposals of the same record (identical payload and uri), if any.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    duplicates: Vec<String>,
}

fn load_state(p: &Path) -> Result<State> {
    if !p.exists() {
        return Ok(State::default());
    }
    Ok(serde_json::from_slice(&std::fs::read(p)?)?)
}

fn save_state(p: &Path, s: &State) -> Result<()> {
    let tmp = p.with_extension("json.tmp");
    std::fs::write(&tmp, serde_json::to_vec_pretty(s)?)?;
    std::fs::rename(tmp, p)?;
    Ok(())
}

// ----------------------------------------------------------------------------
// Node RPC
// ----------------------------------------------------------------------------

struct Rpc {
    base: String,
    agent: ureq::Agent,
}

#[derive(Deserialize, Clone)]
struct Utxo {
    txid: String,
    vout: u32,
    value: u64,
}

impl Rpc {
    fn new(base: &str) -> Self {
        Rpc {
            base: base.trim_end_matches('/').to_string(),
            agent: ureq::AgentBuilder::new()
                .timeout(std::time::Duration::from_secs(600))
                .build(),
        }
    }
    fn get(&self, path: &str) -> Result<serde_json::Value> {
        let url = format!("{}{}", self.base, path);
        let r = self.agent.get(&url).call().map_err(|e| anyhow!("GET {}: {}", url, e))?;
        Ok(r.into_json()?)
    }
    fn height(&self) -> Result<u64> {
        self.get("/tip")?["height"].as_u64().ok_or_else(|| anyhow!("bad /tip response"))
    }
    fn utxos(&self, addr20: &[u8; 20]) -> Result<Vec<Utxo>> {
        let v = self.get(&format!("/utxos/{}?available=true", hex0x(addr20)))?;
        Ok(serde_json::from_value(v["utxos"].clone())?)
    }
    fn tx_confirmed(&self, id: &str) -> Result<bool> {
        Ok(self.get(&format!("/tx/{}", id))?["ok"].as_bool() == Some(true))
    }
    fn proposal(&self, id: &str) -> Result<Option<serde_json::Value>> {
        let v = self.get(&format!("/proposal/{}", id))?;
        if v["ok"].as_bool() == Some(true) {
            Ok(Some(v["proposal"].clone()))
        } else {
            Ok(None)
        }
    }
    fn submit(&self, tx: &Transaction) -> Result<(bool, String)> {
        let url = format!("{}/tx/submit", self.base);
        let body = serde_json::json!({ "tx": tx });
        let r = self.agent.post(&url).send_json(body).map_err(|e| anyhow!("POST {}: {}", url, e))?;
        let v: serde_json::Value = r.into_json()?;
        let ok = v["ok"].as_bool() == Some(true);
        let err = v["err"].as_str().unwrap_or_default().to_string();
        Ok((ok, err))
    }
}

// ----------------------------------------------------------------------------
// Keys and signing (same V1 model as the csd wallet)
// ----------------------------------------------------------------------------

struct Key {
    sk: SecretKey,
    pub33: [u8; 33],
    addr20: [u8; 20],
}

fn load_key(file: &Option<PathBuf>) -> Result<Key> {
    let raw = match file {
        Some(p) => std::fs::read_to_string(p).with_context(|| format!("reading {}", p.display()))?,
        None => std::env::var("CSD_PRIVKEY")
            .map_err(|_| anyhow!("no key: pass --privkey-file or set CSD_PRIVKEY"))?,
    };
    let b = hex::decode(raw.trim().trim_start_matches("0x"))?;
    let sk = SecretKey::from_slice(&b)?;
    let pk = PublicKey::from_secret_key(&Secp256k1::new(), &sk);
    let pub33 = pk.serialize();
    let addr20 = hash160(&pub33);
    Ok(Key { sk, pub33, addr20 })
}

fn sign(tx: &mut Transaction, key: &Key) -> Result<()> {
    for i in tx.inputs.iter_mut() {
        i.script_sig.clear();
    }
    let digest = sighash(tx);
    let msg = Message::from_digest_slice(&digest)?;
    let mut sig = Secp256k1::new().sign_ecdsa(&msg, &key.sk);
    sig.normalize_s();
    let sig64 = sig.serialize_compact();
    let mut ss = Vec::with_capacity(99);
    ss.push(64);
    ss.extend_from_slice(&sig64);
    ss.push(33);
    ss.extend_from_slice(&key.pub33);
    for i in tx.inputs.iter_mut() {
        i.script_sig = ss.clone();
    }
    Ok(())
}

fn outpoint(u: &Utxo) -> Result<OutPoint> {
    Ok(OutPoint { txid: parse_h32(&u.txid)?, vout: u.vout })
}

fn op_str(u: &Utxo) -> String {
    format!("{}:{}", u.txid, u.vout)
}

// ----------------------------------------------------------------------------
// Pending computation shared by fanout/submit
// ----------------------------------------------------------------------------

/// Refresh state against the chain and return the records that still need a proposal.
fn pending<'a>(rpc: &Rpc, st: &mut State, recs: &'a [Record]) -> Result<Vec<&'a Record>> {
    let mut out = vec![];
    for r in recs {
        if let Some(it) = st.items.get_mut(&r.key) {
            if it.status == "confirmed" {
                continue;
            }
            if let Some(p) = rpc.proposal(&it.txid)? {
                it.status = "confirmed".into();
                it.height = p["created_height"].as_u64();
                continue;
            }
        }
        out.push(r);
    }
    Ok(out)
}

fn check_state_matches(st: &mut State, manifest_payload: &str, domain: &str) -> Result<()> {
    if st.manifest_payload_hash.is_empty() {
        st.manifest_payload_hash = manifest_payload.to_string();
        st.domain = domain.to_string();
    } else if st.manifest_payload_hash != manifest_payload {
        bail!("state file belongs to a different manifest ({}); use a fresh --state", st.manifest_payload_hash);
    }
    Ok(())
}

// ----------------------------------------------------------------------------
// fanout
// ----------------------------------------------------------------------------

fn cmd_fanout(
    net: &NetArgs,
    manifest: &Path,
    state_p: &Path,
    mode: Mode,
    fee: u64,
    fanout_fee: u64,
    send: bool,
) -> Result<()> {
    let key = load_key(&net.privkey_file)?;
    let rpc = Rpc::new(&net.rpc);
    let (m, bytes) = load_manifest(manifest)?;
    let mut st = load_state(state_p)?;
    let recs = records(&m, &bytes, "", mode);

    let pend = pending(&rpc, &mut st, &recs)?;
    // Items already submitted and waiting in the mempool hold their own input.
    let waiting = pend.iter().filter(|r| st.items.contains_key(&r.key)).count();
    let need = pend.len() - waiting;

    // Fan-outs sent earlier but not yet mined will deliver their outputs soon:
    // count them so the same coins are never prepared twice.
    let mut incoming = 0usize;
    for f in st.fanouts.iter_mut().filter(|f| f.status == "submitted") {
        if rpc.tx_confirmed(&f.txid)? {
            f.status = "confirmed".into();
            continue;
        }
        if !send {
            incoming += f.outputs;
            continue;
        }
        let (ok, err) = rpc.submit(&f.tx)?;
        if ok || err.contains("already present") {
            incoming += f.outputs;
        } else if rpc.tx_confirmed(&f.txid)? {
            f.status = "confirmed".into();
        } else {
            eprintln!("earlier fan-out {} is no longer valid ({}); dropping it", f.txid, err);
            f.status = "dropped".into();
        }
    }

    let utxos = rpc.utxos(&key.addr20)?;
    let unit = fee + RETURN_VALUE;
    let ready = utxos.iter().filter(|u| u.value == unit).count();
    let to_make = need.saturating_sub(ready + incoming);

    println!("address        {}", hex0x(&key.addr20));
    println!("pending        {} ({} already in mempool)", pend.len(), waiting);
    println!("ready UTXOs    {} (value == fee + {})", ready, RETURN_VALUE);
    println!("incoming       {} (from unconfirmed fan-outs)", incoming);
    println!("to create      {}", to_make);
    if to_make == 0 {
        if send {
            save_state(state_p, &st)?;
        }
        println!("nothing to do; run `submit`");
        return Ok(());
    }

    let mut funding: Vec<Utxo> = utxos.into_iter().filter(|u| u.value != unit).collect();
    funding.sort_by(|a, b| b.value.cmp(&a.value));
    let mut fi = 0usize;

    let mut left = to_make;
    let mut txs = vec![];
    while left > 0 {
        let n = left.min(FANOUT_MAX_OUTPUTS).min(MAX_TX_OUTPUTS - 1);
        let need_value = unit * n as u64 + fanout_fee;
        let mut ins = vec![];
        let mut sum = 0u64;
        while sum < need_value && fi < funding.len() && ins.len() < FANOUT_MAX_INPUTS {
            sum += funding[fi].value;
            ins.push(funding[fi].clone());
            fi += 1;
        }
        if sum < need_value {
            if txs.is_empty() {
                if send {
                    save_state(state_p, &st)?;
                }
                bail!(
                    "not enough confirmed funds right now: need {} for {} outputs, {} spendable. \
                     If an earlier fan-out's change is still unconfirmed this resolves after the next block; \
                     otherwise top up the wallet",
                    fmt_csd(need_value),
                    n,
                    fmt_csd(sum)
                );
            }
            // Fund what we can now; the rest after this round's change confirms.
            break;
        }
        let mut outputs = vec![TxOut { value: unit, script_pubkey: key.addr20 }; n];
        let change = sum - need_value;
        if change >= DUST_LIMIT {
            outputs.push(TxOut { value: change, script_pubkey: key.addr20 });
        }
        let mut tx = Transaction {
            version: 1,
            inputs: ins
                .iter()
                .map(|u| Ok(TxIn { prevout: outpoint(u)?, script_sig: vec![] }))
                .collect::<Result<_>>()?,
            outputs,
            locktime: 0,
            app: AppPayload::None,
        };
        sign(&mut tx, &key)?;
        txs.push((tx, n));
        left -= n;
    }

    for (tx, n) in &txs {
        let id = hex0x(&txid(tx));
        if !send {
            println!("[dry-run] fan-out {}  outputs={}  inputs={}", id, n, tx.inputs.len());
            continue;
        }
        let (ok, err) = rpc.submit(tx)?;
        if ok {
            println!("fan-out submitted {}  outputs={}", id, n);
            st.fanouts.push(Fanout { txid: id, outputs: *n, status: "submitted".into(), tx: tx.clone() });
        } else {
            save_state(state_p, &st)?;
            bail!("fan-out {} rejected: {}", id, err);
        }
    }
    if left > 0 {
        println!("partial fan-out: {} outputs still to create once this round's change confirms", left);
    }
    if send {
        save_state(state_p, &st)?;
        println!("wait for 1 confirmation, then run `submit`");
    } else {
        println!("dry run only; add --send to submit");
    }
    Ok(())
}

// ----------------------------------------------------------------------------
// submit
// ----------------------------------------------------------------------------

#[allow(clippy::too_many_arguments)]
fn cmd_submit(
    net: &NetArgs,
    manifest: &Path,
    state_p: &Path,
    mode: Mode,
    manifest_uri: &str,
    domain: &str,
    fee: u64,
    expires_epoch: Option<u64>,
    limit: Option<usize>,
    send: bool,
) -> Result<()> {
    if domain.is_empty() || domain.len() > MAX_DOMAIN_BYTES {
        bail!("domain must be 1..={} bytes", MAX_DOMAIN_BYTES);
    }
    if manifest_uri.is_empty() || manifest_uri.len() > MAX_URI_BYTES {
        bail!("manifest uri must be 1..={} bytes", MAX_URI_BYTES);
    }
    if fee < MIN_FEE_PROPOSE {
        bail!("fee below consensus minimum {}", MIN_FEE_PROPOSE);
    }

    let key = load_key(&net.privkey_file)?;
    let rpc = Rpc::new(&net.rpc);
    let (m, bytes) = load_manifest(manifest)?;
    let mut st = load_state(state_p)?;
    check_state_matches(&mut st, &hex0x(&sha256d(&bytes)), domain)?;
    let recs = records(&m, &bytes, manifest_uri, mode);

    st.sender = hex0x(&key.addr20);
    let height = rpc.height()?;
    let epoch = height / EPOCH_LEN;
    let expires = expires_epoch.unwrap_or(epoch + TEN_YEARS_OF_EPOCHS);
    if expires < epoch {
        bail!("expires_epoch {} is before current epoch {}", expires, epoch);
    }

    let pend = pending(&rpc, &mut st, &recs)?;
    let pend_keys: Vec<String> = pend.iter().map(|r| r.key.clone()).collect();

    // Resubmit anything we already signed (idempotent). Drop it if its input is gone.
    let utxos = rpc.utxos(&key.addr20)?;
    let unit = fee + RETURN_VALUE;
    let mut free: Vec<Utxo> = utxos.iter().filter(|u| u.value == unit).cloned().collect();
    free.sort_by(|a, b| a.txid.cmp(&b.txid).then(a.vout.cmp(&b.vout)));
    let mut used: HashSet<String> = HashSet::new();

    let mut resubmitted = 0usize;
    let mut stuck: Vec<String> = vec![];
    for k in &pend_keys {
        let Some(it) = st.items.get(k).cloned() else { continue };
        if !send {
            continue;
        }
        let Some(tx) = it.tx.as_ref() else { continue };
        let (ok, err) = rpc.submit(tx)?;
        if ok || err.contains("already present") {
            used.insert(it.input.clone());
            resubmitted += 1;
            continue;
        }
        // Rejected. The usual reason is that a block mined it after our status check:
        // look again before doing anything else. Never re-sign automatically, because
        // re-signing a proposal that is already on chain pays for it twice.
        let id = hex0x(&txid(tx));
        if let Some(p) = rpc.proposal(&id)? {
            let e = st.items.get_mut(k).unwrap();
            e.status = "confirmed".into();
            e.txid = id;
            e.height = p["created_height"].as_u64();
            continue;
        }
        used.insert(it.input.clone());
        stuck.push(format!("{} ({}): {}", k, id, err));
    }
    free.retain(|u| !used.contains(&op_str(u)));

    if !stuck.is_empty() {
        save_state(state_p, &st)?;
        for s in &stuck {
            eprintln!("rejected and not found on chain: {}", s);
        }
        bail!(
            "{} previously signed proposals were rejected and are not on chain yet. \
             Nothing was re-signed. Wait a block and run again; if it persists, investigate before retrying",
            stuck.len()
        );
    }

    let todo: Vec<&Record> = pend.into_iter().filter(|r| !st.items.contains_key(&r.key)).collect();
    let todo_n = limit.map(|l| l.min(todo.len())).unwrap_or(todo.len());

    println!("address          {}", hex0x(&key.addr20));
    println!("height / epoch   {} / {}", height, epoch);
    println!("domain           {}", domain);
    println!("expires_epoch    {}", expires);
    println!("confirmed        {}", recs.len() - pend_keys.len());
    println!("in mempool       {}", resubmitted);
    println!("to submit now    {}", todo_n);
    println!("ready UTXOs      {}", free.len());

    // With --send, submit as many as there are prepared coins; the rest wait for the next round.
    let short = todo_n.saturating_sub(free.len());
    let batch = if send { todo_n - short } else { todo_n };
    if short > 0 && !send {
        println!("note: {} more fee-sized UTXOs needed; dry run continues with placeholder inputs", short);
    }

    let mut sent = 0usize;
    for (i, r) in todo.iter().take(batch).enumerate() {
        let input = free.get(i).cloned().unwrap_or(Utxo { txid: hex0x(&[0u8; 32]), vout: i as u32, value: unit });
        let mut tx = Transaction {
            version: 1,
            inputs: vec![TxIn { prevout: outpoint(&input)?, script_sig: vec![] }],
            outputs: vec![TxOut { value: RETURN_VALUE, script_pubkey: key.addr20 }],
            locktime: 0,
            app: AppPayload::Propose {
                domain: domain.to_string(),
                payload_hash: r.payload_hash,
                uri: r.uri.clone(),
                expires_epoch: expires,
            },
        };
        sign(&mut tx, &key)?;
        let id = hex0x(&txid(&tx));

        if !send {
            if i < 3 || i + 1 == todo_n {
                println!("[dry-run] {}  {}  {}", id, hex0x(&r.payload_hash), r.key);
            } else if i == 3 {
                println!("[dry-run] ...");
            }
            continue;
        }

        let (ok, err) = rpc.submit(&tx)?;
        if !ok {
            save_state(state_p, &st)?;
            bail!("submit for {} rejected: {}", r.key, err);
        }
        st.items.insert(
            r.key.clone(),
            Item {
                payload_hash: hex0x(&r.payload_hash),
                uri: r.uri.clone(),
                txid: id,
                input: op_str(&input),
                status: "submitted".into(),
                height: None,
                tx: Some(tx),
                duplicates: vec![],
            },
        );
        sent += 1;
        if sent % 50 == 0 {
            save_state(state_p, &st)?;
            println!("  submitted {}/{}", sent, todo_n);
        }
    }

    if send {
        save_state(state_p, &st)?;
        println!("submitted {} proposals; run `verify` once they are mined", sent);
        if short > 0 {
            println!("{} still waiting for prepared coins (run `fanout`, then `submit` again)", short);
            // Exit code 3 = partial progress, more rounds needed (used by run-openai-math.sh).
            std::process::exit(3);
        }
    } else {
        save_state_if_exists(state_p, &st)?;
        println!("dry run only; add --send to submit");
    }
    Ok(())
}

fn save_state_if_exists(p: &Path, st: &State) -> Result<()> {
    if p.exists() {
        save_state(p, st)?;
    }
    Ok(())
}

// ----------------------------------------------------------------------------
// verify
// ----------------------------------------------------------------------------

fn cmd_verify(rpc_url: &str, manifest: &Path, state_p: &Path, verbose: bool) -> Result<()> {
    let rpc = Rpc::new(rpc_url);
    let (m, bytes) = load_manifest(manifest)?;
    let st = load_state(state_p)?;
    let manifest_payload = hex0x(&sha256d(&bytes));
    let expected_units: BTreeMap<&str, &Unit> = m.units.iter().map(|u| (u.path.as_str(), u)).collect();

    let mut ok = 0usize;
    let mut bad = vec![];
    let mut missing = vec![];
    let mut heights = BTreeSet::new();

    for (k, it) in &st.items {
        let expected = if k == ROOT_KEY {
            manifest_payload.clone()
        } else {
            match expected_units.get(k.as_str()) {
                Some(u) => u.tree_hash.clone(),
                None => {
                    bad.push(format!("{}: not in manifest", k));
                    continue;
                }
            }
        };
        match rpc.proposal(&it.txid)? {
            None => missing.push(k.clone()),
            Some(p) => {
                let ph = p["payload_hash"].as_str().unwrap_or_default();
                let dom = p["domain"].as_str().unwrap_or_default();
                let uri = p["uri"].as_str().unwrap_or_default();
                let h = p["created_height"].as_u64().unwrap_or(0);
                if ph == expected && dom == st.domain && uri == it.uri {
                    ok += 1;
                    heights.insert(h);
                    if verbose {
                        println!("ok  h={:<7} {}  {}", h, it.txid, k);
                    }
                } else {
                    bad.push(format!("{}: on-chain payload {} / domain {} / uri {} does not match", k, ph, dom, uri));
                }
            }
        }
    }

    let not_attempted = (m.units.len() + 1).saturating_sub(st.items.len());
    println!("manifest         {}  (commit {})", manifest_payload, &m.source.commit[..12]);
    println!("on chain, match  {}", ok);
    println!("not yet mined    {}", missing.len());
    println!("mismatched       {}", bad.len());
    println!("never submitted  {}", not_attempted);
    let dups: usize = st.items.values().map(|i| i.duplicates.len()).sum();
    println!("duplicates       {}", dups);
    if let (Some(lo), Some(hi)) = (heights.iter().next(), heights.iter().last()) {
        println!("block heights    {}..={}", lo, hi);
    }
    if let Some(root) = st.items.get(ROOT_KEY) {
        println!("root proposal    {}", root.txid);
    }
    for b in &bad {
        println!("MISMATCH {}", b);
    }
    if !bad.is_empty() {
        bail!("{} mismatched records", bad.len());
    }
    Ok(())
}

// ----------------------------------------------------------------------------
// reconcile
// ----------------------------------------------------------------------------

fn cmd_reconcile(
    rpc_url: &str,
    manifest: &Path,
    state_p: &Path,
    from: Option<u64>,
    to: Option<u64>,
    write: bool,
) -> Result<()> {
    let rpc = Rpc::new(rpc_url);
    let (m, bytes) = load_manifest(manifest)?;
    let mut st = load_state(state_p)?;
    if st.items.is_empty() {
        bail!("state file has no records");
    }

    // Our address: every proposal returns its small output to the sender.
    let addr_hex = if !st.sender.is_empty() {
        st.sender.clone()
    } else {
        let addr = st
            .items
            .values()
            .find_map(|i| i.tx.as_ref().and_then(|t| t.outputs.first().map(|o| o.script_pubkey)))
            .ok_or_else(|| anyhow!("no sender address in state; cannot tell our proposals apart"))?;
        hex0x(&addr)
    };
    st.sender = addr_hex.clone();

    // Expected (payload_hash, uri) per key, from the manifest + state.
    let manifest_payload = hex0x(&sha256d(&bytes));
    let mut want: BTreeMap<(String, String), String> = BTreeMap::new();
    for (k, it) in &st.items {
        let ph = if k == ROOT_KEY {
            manifest_payload.clone()
        } else {
            match m.units.iter().find(|u| &u.path == k) {
                Some(u) => u.tree_hash.clone(),
                None => continue,
            }
        };
        want.insert((ph, it.uri.clone()), k.clone());
    }

    // Records saved before they were mined have no height yet: look it up, so the
    // scan starts near our records instead of at block 0.
    for it in st.items.values_mut() {
        if it.height.is_none() {
            if let Some(p) = rpc.proposal(&it.txid)? {
                it.height = p["created_height"].as_u64();
            }
        }
    }
    let heights: Vec<u64> = st.items.values().filter_map(|i| i.height).collect();
    if heights.is_empty() && from.is_none() {
        bail!("no record in the state file is on chain yet; pass --from to choose where to scan");
    }
    let lo = from.unwrap_or(heights.iter().min().copied().unwrap_or(0).saturating_sub(20));
    let tip = rpc.height()?;
    let hi = to.unwrap_or(tip).min(tip);

    // key -> [(height, index in block, txid)]
    let mut found: BTreeMap<String, Vec<(u64, usize, String)>> = BTreeMap::new();
    for h in lo..=hi {
        let b = rpc.get(&format!("/block/height/{}", h))?;
        let Some(txs) = b["txs"].as_array() else { continue };
        for (i, t) in txs.iter().enumerate() {
            let app = &t["app"];
            if app["type"].as_str() != Some("Propose") || app["domain"].as_str() != Some(st.domain.as_str()) {
                continue;
            }
            let to_us = t["outputs"]
                .as_array()
                .map(|o| o.iter().any(|x| x["script_pubkey"].as_str() == Some(addr_hex.as_str())))
                .unwrap_or(false);
            if !to_us {
                continue;
            }
            let key = (
                app["payload_hash"].as_str().unwrap_or_default().to_string(),
                app["uri"].as_str().unwrap_or_default().to_string(),
            );
            if let Some(k) = want.get(&key) {
                let id = t["txid"].as_str().unwrap_or_default().to_string();
                found.entry(k.clone()).or_default().push((h, i, id));
            }
        }
    }

    let mut changed = 0usize;
    let mut dup_total = 0usize;
    let mut missing = vec![];
    for (k, it) in st.items.iter_mut() {
        let Some(list) = found.get_mut(k) else {
            missing.push(k.clone());
            continue;
        };
        list.sort();
        let (h, _, first) = list[0].clone();
        // Keep duplicates found earlier (they may lie outside this scan), add new ones.
        let mut dups: Vec<String> = it.duplicates.clone();
        if it.txid != first && !dups.contains(&it.txid) {
            dups.push(it.txid.clone());
        }
        for x in &list[1..] {
            if !dups.contains(&x.2) {
                dups.push(x.2.clone());
            }
        }
        dups.retain(|d| d != &first);
        dup_total += dups.len();
        if it.txid != first {
            changed += 1;
            it.txid = first;
            it.tx = None; // the stored tx was a later copy
        }
        it.height = Some(h);
        it.status = "confirmed".into();
        it.duplicates = dups;
    }

    println!("scanned blocks       {}..={}", lo, hi);
    println!("sender               {}", addr_hex);
    println!("records              {}", st.items.len());
    println!("found on chain       {}", found.len());
    println!("duplicates           {}  ({} paid in extra fees)", dup_total, fmt_csd(dup_total as u64 * MIN_FEE_PROPOSE));
    println!("now point to earlier {}", changed);
    if !missing.is_empty() {
        println!("not found in range   {} (widen --from/--to)", missing.len());
        for k in missing.iter().take(5) {
            println!("  {}", k);
        }
    }
    if let Some(r) = st.items.get(ROOT_KEY) {
        println!("root proposal        {}", r.txid);
    }
    if write {
        if !missing.is_empty() {
            bail!("not writing: some records were not found in the scanned range");
        }
        save_state(state_p, &st)?;
        println!("state updated: {}", state_p.display());
    } else {
        println!("report only; add --write to update {}", state_p.display());
    }
    Ok(())
}

// ----------------------------------------------------------------------------
// diff
// ----------------------------------------------------------------------------

fn cmd_diff(old: &Path, new: &Path, json_out: &Option<PathBuf>) -> Result<()> {
    let (a, _) = load_manifest(old)?;
    let (b, _) = load_manifest(new)?;
    let am: BTreeMap<&str, &Unit> = a.units.iter().map(|u| (u.path.as_str(), u)).collect();
    let bm: BTreeMap<&str, &Unit> = b.units.iter().map(|u| (u.path.as_str(), u)).collect();

    let mut unchanged = vec![];
    let mut changed = vec![];
    let mut removed = vec![];
    let mut added = vec![];
    let mut newly_withdrawn = vec![];

    for (p, ua) in &am {
        match bm.get(p) {
            None => removed.push(p.to_string()),
            Some(ub) if ub.tree_hash == ua.tree_hash => unchanged.push(p.to_string()),
            Some(ub) => {
                changed.push(p.to_string());
                let was = ua.labels.iter().any(|l| l == "withdrawn");
                let now = ub.labels.iter().any(|l| l == "withdrawn");
                if now && !was {
                    newly_withdrawn.push(p.to_string());
                }
            }
        }
    }
    for p in bm.keys() {
        if !am.contains_key(p) {
            added.push(p.to_string());
        }
    }

    println!("old  {}  {}", &a.source.commit[..12], a.source.commit_time);
    println!("new  {}  {}", &b.source.commit[..12], b.source.commit_time);
    println!("unchanged  {}", unchanged.len());
    println!("changed    {}", changed.len());
    println!("added      {}", added.len());
    println!("removed    {}", removed.len());
    if !newly_withdrawn.is_empty() {
        println!("\nnewly labelled withdrawn:");
        for p in &newly_withdrawn {
            println!("  {}", p);
        }
    }
    for (title, list) in [("changed", &changed), ("added", &added), ("removed", &removed)] {
        if !list.is_empty() {
            println!("\n{}:", title);
            for p in list.iter() {
                println!("  {}", p);
            }
        }
    }

    if let Some(p) = json_out {
        let v = serde_json::json!({
            "old": { "commit": a.source.commit, "commit_time": a.source.commit_time, "commit_tree_hash": a.commit_tree_hash },
            "new": { "commit": b.source.commit, "commit_time": b.source.commit_time, "commit_tree_hash": b.commit_tree_hash },
            "unchanged": unchanged.len(),
            "changed": changed,
            "added": added,
            "removed": removed,
            "newly_withdrawn": newly_withdrawn,
        });
        std::fs::write(p, serde_json::to_vec_pretty(&v)?)?;
    }
    Ok(())
}

// ----------------------------------------------------------------------------

fn main() -> Result<()> {
    let cli = Cli::parse();
    match cli.cmd {
        Cmd::Manifest { repo, commit, repo_url, split, catalogue, out } => {
            cmd_manifest(&repo, &commit, &repo_url, &split, &catalogue, &out)
        }
        Cmd::Plan { manifest, mode, fee } => cmd_plan(&manifest, mode, fee),
        Cmd::Fanout { net, manifest, state, mode, fee, fanout_fee, send } => {
            cmd_fanout(&net, &manifest, &state, mode, fee, fanout_fee, send)
        }
        Cmd::Submit { net, manifest, state, mode, manifest_uri, domain, fee, expires_epoch, limit, send } => {
            cmd_submit(&net, &manifest, &state, mode, &manifest_uri, &domain, fee, expires_epoch, limit, send)
        }
        Cmd::Verify { rpc, manifest, state, verbose } => cmd_verify(&rpc, &manifest, &state, verbose),
        Cmd::Reconcile { rpc, manifest, state, from, to, write } => {
            cmd_reconcile(&rpc, &manifest, &state, from, to, write)
        }
        Cmd::Diff { old, new, json } => cmd_diff(&old, &new, &json),
    }
}
