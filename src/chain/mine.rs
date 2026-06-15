// src/chain/mine.rs
use anyhow::{anyhow, Result};

use crate::chain::index::{get_hidx, header_hash, index_header, HeaderIndex};
use crate::chain::lock::ChainLock;
use crate::chain::pow::{bits_to_target_bytes, expected_bits, PowTarget};
use crate::chain::reorg::maybe_reorg_to;
use crate::chain::time::{median_time_past, now_secs};
use crate::crypto::{sha256d, txid};
use crate::net::mempool::Mempool;
use crate::params::{
    block_reward, MAX_BLOCK_BYTES, MAX_FUTURE_DRIFT_SECS, MIN_BLOCK_SPACING_SECS,
};
use crate::state::app_state::epoch_of;
use crate::state::db::{get_tip, get_utxo, k_block, Stores};
use crate::state::utxo::validate_tx_for_mempool;
use crate::types::{
    AppPayload, Block, BlockHeader, Hash20, Hash32, OutPoint, Transaction, TxIn, TxOut,
};
use std::sync::{
atomic::{AtomicBool, AtomicU64, Ordering},
    mpsc,
    Arc, Mutex,
};
use std::thread;
use std::collections::HashSet;
use std::io::{BufRead, BufReader, Write};
use std::process::{Child, ChildStdin, Command, Stdio};
use std::time::{Duration, Instant};

const MINER_BLOCK_SIZE_SAFETY_BYTES: usize = 16 * 1024;



/// Bitcoin-ish merkle root from txids.
/// - leaves are txid bytes
/// - internal nodes are sha256d(left || right), duplicating last if odd
pub fn merkle_root_txids(txids: &[[u8; 32]]) -> [u8; 32] {
    if txids.is_empty() {
        return [0u8; 32];
    }
    let mut layer: Vec<[u8; 32]> = txids.to_vec();
    while layer.len() > 1 {
        let mut next: Vec<[u8; 32]> = Vec::with_capacity((layer.len() + 1) / 2);
        let mut i = 0usize;
        while i < layer.len() {
            let left = layer[i];
            let right = if i + 1 < layer.len() { layer[i + 1] } else { layer[i] };
            let mut buf = [0u8; 64];
            buf[..32].copy_from_slice(&left);
            buf[32..].copy_from_slice(&right);
            next.push(sha256d(&buf));
            i += 2;
        }
        layer = next;
    }
    layer[0]
}

fn merkle_root(txs: &[Transaction]) -> Hash32 {
    let mut ids: Vec<Hash32> = Vec::with_capacity(txs.len());
    for tx in txs {
        ids.push(txid(tx));
    }
    merkle_root_txids(&ids)
}

fn miner_entropy() -> Vec<u8> {
    let host = std::env::var("HOSTNAME").unwrap_or_else(|_| "unknown-host".to_string());
    let pid = std::process::id();
    let instance = std::env::var("CSD_MINER_ID").unwrap_or_else(|_| "default".to_string());

    format!("{host}:{pid}:{instance}").into_bytes()
}

fn mine_log_event(event: &str, height: u64, hash: Option<&Hash32>, msg: &str) {
    match hash {
        Some(h) => println!(
            "[mine-event] event={} height={} hash=0x{} {}",
            event,
            height,
            hex::encode(h),
            msg
        ),
        None => println!(
            "[mine-event] event={} height={} {}",
            event,
            height,
            msg
        ),
    }
}


/// Coinbase with guaranteed uniqueness:
/// - script_sig commits height (consensus rule enforced in utxo.rs)
/// - locktime commits height (also makes txid unique even if txid strips scriptsig)
pub fn coinbase(miner_h160: Hash20, value: u64, height: u64, memo: Option<&[u8]>) -> Transaction {
    let mut script_sig = height.to_le_bytes().to_vec();
    let locktime = height as u32;
    if let Some(m) = memo {
    script_sig.push(0x00);
    script_sig.extend_from_slice(m);
}
    Transaction {
        version: 1,
        inputs: vec![TxIn {
            prevout: OutPoint {
                txid: [0u8; 32],
                vout: u32::MAX,
            },
            script_sig,
        }],
        outputs: vec![TxOut {
            value,
            script_pubkey: miner_h160,
        }],
        locktime,
        app: AppPayload::None,
    }
}



/// Return (all_inputs_exist, in_sum)
fn sum_inputs_if_present(db: &Stores, tx: &Transaction) -> Result<(bool, u64)> {
    if tx.inputs.is_empty() {
        return Ok((false, 0));
    }

    let mut in_sum: u64 = 0;
    for inp in &tx.inputs {
        let prev = match get_utxo(db, &inp.prevout)? {
            Some(p) => p,
            None => return Ok((false, 0)),
        };

        in_sum = in_sum
            .checked_add(prev.value)
            .ok_or_else(|| anyhow!("overflow in_sum"))?;
    }

    Ok((true, in_sum))
}

fn sum_outputs(tx: &Transaction) -> Result<u64> {
    let mut out_sum: u64 = 0;
    for out in &tx.outputs {
        out_sum = out_sum
            .checked_add(out.value)
            .ok_or_else(|| anyhow!("overflow out_sum"))?;
    }
    Ok(out_sum)
}

/// Compute fee for a tx using the current UTXO set.
fn compute_fee_from_utxos(db: &Stores, tx: &Transaction) -> Result<u64> {
    let (ok, in_sum) = sum_inputs_if_present(db, tx)?;
    if !ok {
        return Err(anyhow!("missing utxo"));
    }

    let out_sum = sum_outputs(tx)?;
    if out_sum > in_sum {
        return Err(anyhow!("outputs exceed inputs"));
    }

    Ok(in_sum - out_sum)
}

/// Choose a block time that matches the consensus rules in index_header:
/// - time >= parent.time + MIN_BLOCK_SPACING_SECS
/// - time > MTP(parent)
/// - time <= now + MAX_FUTURE_DRIFT_SECS
///
/// Prefer wall-clock time when it is already valid, but do not sit idle when
/// the current chain tip is ahead of local time. Consensus permits a bounded
/// future timestamp, and miners already using that window can otherwise keep
/// our templates stale before we even start hashing.

fn choose_block_time(
    db: &Stores,
    parent_tip: &Hash32,
    parent_hi: Option<&HeaderIndex>,
    height: u64,
) -> Result<u64> {
    if *parent_tip == [0u8; 32] || parent_hi.is_none() {
        return Ok(0);
    }

    let p = parent_hi.unwrap();

    let mtp = median_time_past(db, &p.hash).unwrap_or(p.time);

    let min_ok = p.time
        .saturating_add(MIN_BLOCK_SPACING_SECS)
        .max(mtp.saturating_add(1));

    loop {
        ensure_tip_unchanged(db, parent_tip, height)?;

        let now = now_secs();

        if min_ok <= now {
            return Ok(now);
        }

        let max_allowed = now.saturating_add(MAX_FUTURE_DRIFT_SECS);
        if min_ok <= max_allowed {
            mine_log_event(
                "future_time_selected",
                height,
                None,
                &format!(
                    "time={} now={} max_allowed={} parent=0x{}",
                    min_ok,
                    now,
                    max_allowed,
                    hex::encode(parent_tip)
                ),
            );
            return Ok(min_ok);
        }

        let wait = min_ok.saturating_sub(max_allowed).min(5);

        println!(
            "[mine] waiting for wall clock: next_valid_time={} now={} max_allowed={} wait={}s",
            min_ok,
            now,
            max_allowed,
            wait
        );

        std::thread::sleep(std::time::Duration::from_secs(wait));
    }
}

fn ensure_tip_unchanged(db: &Stores, parent_tip: &Hash32, height: u64) -> Result<()> {
    let cur_tip = get_tip(db)?.unwrap_or([0u8; 32]);
    if cur_tip == *parent_tip {
        return Ok(());
    }

    mine_log_event(
        "candidate_stale_before_search",
        height,
        None,
        &format!(
            "old_prev=0x{} new_tip=0x{}",
            hex::encode(parent_tip),
            hex::encode(cur_tip)
        ),
    );

    Err(anyhow!("stale template"))
}

/// Build a fresh block template from the current tip + current UTXO set.
///
/// Key behavior:
/// - Only includes txs that are valid AND connectable *right now*
/// - Skips anything that fails validate_tx_for_mempool or has missing inputs
/// - Sorts by fee (desc) so miners converge under load
/// - also respects MAX_BLOCK_BYTES (consensus) so we never build an unmineable block

fn build_template(
    db: &Stores,
    mempool: &Mempool,
    miner_h160: Hash20,
    height: u64,
    max_mempool_txs: usize,
) -> Result<(Vec<Transaction>, Vec<Hash32>, u64)> {
    build_template_with_byte_cap(
        db,
        mempool,
        miner_h160,
        height,
        max_mempool_txs,
        MAX_BLOCK_BYTES.saturating_sub(MINER_BLOCK_SIZE_SAFETY_BYTES),
    )
}

fn build_template_with_byte_cap(
    db: &Stores,
    mempool: &Mempool,
    miner_h160: Hash20,
    height: u64,
    max_mempool_txs: usize,
    byte_cap: usize,
) -> Result<(Vec<Transaction>, Vec<Hash32>, u64)> {
    let c = crate::codec::consensus_bincode();
    let reward = block_reward(height);

    const CANDIDATE_MULT: usize = 8;
    let want_candidates = max_mempool_txs
        .saturating_mul(CANDIDATE_MULT)
        .max(max_mempool_txs);

    let sampled = mempool.sample(want_candidates);

    // (feerate_ppm, txid, tx, fee, tx_bytes)
    let mut candidates: Vec<(u64, Hash32, Transaction, u64, u64)> = Vec::new();

    for tx in sampled {
        let id = txid(&tx);

        if validate_tx_for_mempool(db, &tx).is_err() {
            continue;
        }

        let fee = match compute_fee_from_utxos(db, &tx) {
            Ok(f) => f,
            Err(_) => continue,
        };

        let tx_bytes = match c.serialized_size(&tx) {
            Ok(n) if n > 0 => n,
            _ => continue,
        };

        let feerate_ppm = ((fee as u128)
            .saturating_mul(1_000_000u128)
            / (tx_bytes as u128)) as u64;

        candidates.push((feerate_ppm, id, tx, fee, tx_bytes));
    }

    // feerate desc; tie-break by txid ASC
candidates.sort_by(|a, b| {
    use std::cmp::Ordering;

    let prio = |tx: &Transaction| match &tx.app {
        AppPayload::Propose { .. } => 0u8,
        AppPayload::Attest { .. } => 1u8,
        _ => 2u8,
    };

    match prio(&a.2).cmp(&prio(&b.2)) {
        Ordering::Equal => match b.0.cmp(&a.0) {
            Ordering::Equal => a.1.cmp(&b.1),
            o => o,
        },
        o => o,
    }
});

let entropy = miner_entropy();
let cb_placeholder = coinbase(miner_h160, reward, height, Some(&entropy));

    let cb_bytes = c.serialized_size(&cb_placeholder)? as usize;

    let mut remaining = byte_cap.saturating_sub(cb_bytes);

    let mut total_fees: u64 = 0;
    let mut included: Vec<Transaction> = Vec::with_capacity(max_mempool_txs);
    let mut included_ids: Vec<Hash32> = Vec::with_capacity(max_mempool_txs);
    let mut included_bytes: usize = 0;

let mut spent_in_template: HashSet<OutPoint> = HashSet::new();

    for (_feerate_ppm, id, tx, fee, tx_bytes_u64) in candidates.into_iter() {
        if included.len() >= max_mempool_txs {
            break;
        }

        let tx_bytes = tx_bytes_u64 as usize;



        if tx_bytes > remaining {
            continue;
        }

let conflicts_with_template = tx
    .inputs
    .iter()
    .any(|inp| spent_in_template.contains(&inp.prevout));

if conflicts_with_template {
    continue;
}

        total_fees = total_fees
            .checked_add(fee)
            .ok_or_else(|| anyhow!("fee overflow"))?;

for inp in &tx.inputs {
    spent_in_template.insert(inp.prevout.clone());
}

included_ids.push(id);
included.push(tx);



        remaining = remaining.saturating_sub(tx_bytes);
        included_bytes = included_bytes.saturating_add(tx_bytes);
    }

    println!(
        "[mine] template: height={} mempool_len={} sampled={} included={} total_fees={} block_bytes≈{} (cb_bytes={}, tx_bytes={})",
        height,
        mempool.len(),
        want_candidates.min(mempool.len()),
        included.len(),
        total_fees,
        cb_bytes.saturating_add(included_bytes),
        cb_bytes,
        included_bytes
    );

    let cb_value = reward
        .checked_add(total_fees)
        .ok_or_else(|| anyhow!("coinbase overflow"))?;
let cb = coinbase(miner_h160, cb_value, height, Some(&entropy));

    let mut final_txs: Vec<Transaction> = Vec::with_capacity(1 + included.len());
    final_txs.push(cb);
    final_txs.extend(included);

    Ok((final_txs, included_ids, total_fees))
}

#[cfg(test)]
pub fn build_template_for_tests(
    db: &Stores,
    mempool: &Mempool,
    miner_h160: Hash20,
    height: u64,
    max_mempool_txs: usize,
    byte_cap: usize,
) -> Result<(Vec<Transaction>, Vec<Hash32>, u64)> {
    build_template_with_byte_cap(
        db,
        mempool,
        miner_h160,
        height,
        max_mempool_txs,
        byte_cap,
    )
}

fn miner_thread_count() -> usize {
    if let Ok(v) = std::env::var("CSD_MINER_THREADS") {
        if let Ok(n) = v.parse::<usize>() {
            return n.max(1);
        }
    }

    let cores = std::thread::available_parallelism()
        .map(|n| n.get())
        .unwrap_or(1);

    let reserve = std::env::var("CSD_MINER_RESERVED_THREADS")
        .ok()
        .and_then(|v| v.parse::<usize>().ok())
        .unwrap_or(1);

    cores.saturating_sub(reserve).max(1)
}

fn cuda_miner_enabled() -> bool {
    std::env::var("CSD_CUDA_MINER")
        .map(|v| {
            let v = v.trim().to_ascii_lowercase();
            v == "1" || v == "true" || v == "yes" || v == "on"
        })
        .unwrap_or(false)
}

fn cuda_persistent_enabled() -> bool {
    std::env::var("CSD_CUDA_PERSISTENT")
        .map(|v| {
            let v = v.trim().to_ascii_lowercase();
            v == "1" || v == "true" || v == "yes" || v == "on"
        })
        .unwrap_or(false)
}

fn header_hex(h: &BlockHeader) -> String {
    let mut buf = [0u8; 84];
    buf[0..4].copy_from_slice(&h.version.to_le_bytes());
    buf[4..36].copy_from_slice(&h.prev);
    buf[36..68].copy_from_slice(&h.merkle);
    buf[68..76].copy_from_slice(&h.time.to_le_bytes());
    buf[76..80].copy_from_slice(&h.bits.to_le_bytes());
    buf[80..84].copy_from_slice(&h.nonce.to_le_bytes());
    hex::encode(buf)
}

fn parse_cuda_found(stdout: &str) -> Result<Option<(u32, Hash32)>> {
    let Some(line) = stdout.lines().find(|l| l.starts_with("FOUND ")) else {
        return Ok(None);
    };
    let mut nonce = None;
    let mut hash = None;
    for part in line.split_whitespace() {
        if let Some(v) = part.strip_prefix("nonce=") {
            nonce = Some(v.parse::<u32>()?);
        } else if let Some(v) = part.strip_prefix("hash=0x") {
            let bytes = hex::decode(v)?;
            if bytes.len() != 32 {
                return Err(anyhow!("cuda miner returned {}-byte hash", bytes.len()));
            }
            let mut h = [0u8; 32];
            h.copy_from_slice(&bytes);
            hash = Some(h);
        }
    }
    match (nonce, hash) {
        (Some(n), Some(h)) => Ok(Some((n, h))),
        _ => Err(anyhow!("malformed cuda miner FOUND line: {line}")),
    }
}

struct CudaPersistentWorker {
    bin: String,
    device: String,
    child: Child,
    stdin: ChildStdin,
    stdout: BufReader<std::process::ChildStdout>,
}

impl CudaPersistentWorker {
    fn start(bin: String, device: String) -> Result<Self> {
        let mut child = Command::new(&bin)
            .arg("--server")
            .arg(&device)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::inherit())
            .spawn()
            .map_err(|e| anyhow!("failed to start persistent cuda miner {bin} device={device}: {e}"))?;
        let stdin = child
            .stdin
            .take()
            .ok_or_else(|| anyhow!("persistent cuda miner stdin unavailable"))?;
        let stdout = child
            .stdout
            .take()
            .ok_or_else(|| anyhow!("persistent cuda miner stdout unavailable"))?;
        Ok(Self {
            bin,
            device,
            child,
            stdin,
            stdout: BufReader::new(stdout),
        })
    }

    fn restart(&mut self) -> Result<()> {
        self.stop();
        let fresh = Self::start(self.bin.clone(), self.device.clone())?;
        *self = fresh;
        Ok(())
    }

    fn stop(&mut self) {
        let _ = self.stdin.write_all(b"QUIT\n");
        let _ = self.stdin.flush();
        for _ in 0..20 {
            if matches!(self.child.try_wait(), Ok(Some(_))) {
                return;
            }
            thread::sleep(Duration::from_millis(10));
        }
        let _ = self.child.kill();
        let _ = self.child.wait();
    }

    fn search(
        &mut self,
        header_hex: &str,
        target_hex: &str,
        count: &str,
        blocks: &str,
        threads: &str,
    ) -> Result<Option<(u32, Hash32)>> {
        let request = format!(
            "{} {} 0 {} {} {} 1\n",
            header_hex, target_hex, count, blocks, threads
        );
        if self.stdin.write_all(request.as_bytes()).is_err() || self.stdin.flush().is_err() {
            self.restart()?;
            self.stdin.write_all(request.as_bytes())?;
            self.stdin.flush()?;
        }

        let mut line = String::new();
        let n = self.stdout.read_line(&mut line)?;
        if n == 0 {
            self.restart()?;
            return Err(anyhow!(
                "persistent cuda miner ended unexpectedly device={}",
                self.device
            ));
        }
        if line.starts_with("ERROR ") {
            return Err(anyhow!(
                "persistent cuda miner failed device={} line={}",
                self.device,
                line.trim()
            ));
        }
        parse_cuda_found(&line)
    }
}

impl Drop for CudaPersistentWorker {
    fn drop(&mut self) {
        self.stop();
    }
}

fn cuda_devices() -> Vec<String> {
    std::env::var("CSD_CUDA_DEVICES")
        .ok()
        .map(|v| {
            v.split(',')
                .map(|s| s.trim())
                .filter(|s| !s.is_empty())
                .map(|s| s.to_string())
                .collect::<Vec<_>>()
        })
        .filter(|v| !v.is_empty())
        .unwrap_or_else(|| {
            vec![std::env::var("CSD_CUDA_DEVICE").unwrap_or_else(|_| "0".to_string())]
        })
}

fn cuda_param_for_device(env_name: &str, default_value: &str, device: &str, index: usize) -> String {
    let Ok(raw) = std::env::var(env_name) else {
        return default_value.to_string();
    };

    let mut positional = Vec::new();
    for part in raw.split(',').map(str::trim).filter(|s| !s.is_empty()) {
        if let Some((k, v)) = part.split_once('=') {
            if k.trim() == device {
                return v.trim().to_string();
            }
        } else {
            positional.push(part);
        }
    }

    positional
        .get(index)
        .map(|v| (*v).to_string())
        .unwrap_or_else(|| default_value.to_string())
}

fn mine_one_cuda(
    db: &Stores,
    height: u64,
    parent_tip: Hash32,
    parent_hi_opt: Option<HeaderIndex>,
    mut hdr: BlockHeader,
    mut txs: Vec<Transaction>,
    pow_target: PowTarget,
) -> Result<(Hash32, Block)> {
    let bin = std::env::var("CSD_CUDA_BIN").unwrap_or_else(|_| "/usr/local/bin/csd-cuda-search".to_string());
    let devices = cuda_devices();
    let blocks = std::env::var("CSD_CUDA_BLOCKS").unwrap_or_else(|_| "4096".to_string());
    let threads = std::env::var("CSD_CUDA_THREADS").unwrap_or_else(|_| "256".to_string());
    let count = std::env::var("CSD_CUDA_COUNT").unwrap_or_else(|_| "4294967296".to_string());
    let target_hex = hex::encode(bits_to_target_bytes(hdr.bits));
    let (tx_cuda, rx_cuda) = mpsc::channel::<Result<Option<(String, u64, u32, Hash32, Vec<Transaction>, BlockHeader)>>>();
    let persistent = cuda_persistent_enabled();
    let persistent_workers = if persistent {
        let mut workers = Vec::with_capacity(devices.len());
        for device in &devices {
            workers.push(Arc::new(Mutex::new(CudaPersistentWorker::start(
                bin.clone(),
                device.clone(),
            )?)));
        }
        Some(workers)
    } else {
        None
    };
    let mut round: u64 = 0;
    loop {
        let cur_tip = get_tip(db)?.unwrap_or([0u8; 32]);
        if cur_tip != parent_tip {
            mine_log_event(
                "candidate_stale_before_solution",
                height,
                None,
                &format!(
                    "cuda=1 old_prev=0x{} new_tip=0x{}",
                    hex::encode(parent_tip),
                    hex::encode(cur_tip)
                ),
            );
            return Err(anyhow!("stale template"));
        }

        let round_started = Instant::now();
        for (device_idx, device) in devices.iter().enumerate() {
            let device_blocks =
                cuda_param_for_device("CSD_CUDA_BLOCKS_BY_DEVICE", &blocks, device, device_idx);
            let device_threads =
                cuda_param_for_device("CSD_CUDA_THREADS_BY_DEVICE", &threads, device, device_idx);
            let mut dhdr = hdr.clone();
            let mut dtxs = txs.clone();
            let extra_nonce = round
                .wrapping_mul(devices.len() as u64)
                .wrapping_add(device_idx as u64);
            dtxs[0].inputs[0].script_sig.push(0x00);
            dtxs[0]
                .inputs[0]
                .script_sig
                .extend_from_slice(format!("gpu:{device}:{extra_nonce}").as_bytes());
            dhdr.merkle = merkle_root(&dtxs);
            dhdr.nonce = 0;

            mine_log_event(
                "cuda_search_started",
                height,
                None,
                &format!(
                    "device={} count={} blocks={} threads={} extra_nonce={} prev=0x{} bits=0x{:08x}",
                    device,
                    count,
                    device_blocks,
                    device_threads,
                    extra_nonce,
                    hex::encode(dhdr.prev),
                    dhdr.bits,
                ),
            );

            let tx_cuda = tx_cuda.clone();
            let bin = bin.clone();
            let target_hex = target_hex.clone();
            let count = count.clone();
            let blocks = device_blocks;
            let threads = device_threads;
            let device = device.clone();
            let persistent_worker = persistent_workers
                .as_ref()
                .map(|workers| workers[device_idx].clone());
            thread::spawn(move || {
                let result = (|| -> Result<Option<(u32, Hash32)>> {
                    let header_arg = format!("0x{}", header_hex(&dhdr));
                    let target_arg = format!("0x{}", target_hex);
                    if let Some(worker) = persistent_worker {
                        let mut worker = worker
                            .lock()
                            .map_err(|_| anyhow!("persistent cuda worker lock poisoned"))?;
                        return worker.search(&header_arg, &target_arg, &count, &blocks, &threads);
                    }
                    let output = Command::new(&bin)
                        .arg(header_arg)
                        .arg(target_arg)
                        .arg("0")
                        .arg(&count)
                        .arg(&device)
                        .arg(&blocks)
                        .arg(&threads)
                        .output()
                        .map_err(|e| anyhow!("failed to run cuda miner {bin}: {e}"))?;

                    if !output.status.success() {
                        return Err(anyhow!(
                            "cuda miner failed device={} status={:?} stderr={}",
                            device,
                            output.status.code(),
                            String::from_utf8_lossy(&output.stderr)
                        ));
                    }

                    let stdout = String::from_utf8_lossy(&output.stdout);
                    parse_cuda_found(&stdout)
                })();

                match result {
                    Ok(Some((nonce, h))) => {
                        let _ = tx_cuda.send(Ok(Some((device, extra_nonce, nonce, h, dtxs, dhdr))));
                    }
                    Ok(None) => {
                        let _ = tx_cuda.send(Ok(None));
                    }
                    Err(e) => {
                        let _ = tx_cuda.send(Err(e));
                    }
                }
            });
        }

        let mut completed = 0usize;
        for _ in 0..devices.len() {
            if let Ok(result) = rx_cuda.recv() {
                completed += 1;
                let Some((device, extra_nonce, nonce, h, found_txs, mut found_hdr)) = result? else {
                    continue;
                };
                found_hdr.nonce = nonce;
                let local_h = header_hash(&found_hdr);
                if local_h != h {
                    return Err(anyhow!(
                        "cuda solution mismatch local=0x{} cuda=0x{}",
                        hex::encode(local_h),
                        hex::encode(h)
                    ));
                }
                if !pow_target.check(&h) {
                    return Err(anyhow!("cuda solution failed local pow check"));
                }
                mine_log_event(
                    "pow_solution_found",
                    height,
                    Some(&h),
                    &format!(
                        "cuda=1 device={} prev=0x{} bits=0x{:08x} time={} nonce={} extra_nonce={}",
                        device,
                        hex::encode(found_hdr.prev),
                        found_hdr.bits,
                        found_hdr.time,
                        found_hdr.nonce,
                        extra_nonce
                    ),
                );
                return Ok((h, Block { header: found_hdr, txs: found_txs }));
            }
        }

        let elapsed = round_started.elapsed();
        let searched = count
            .parse::<u64>()
            .unwrap_or(0)
            .saturating_mul(completed as u64);
        let hps = if elapsed.as_secs_f64() > 0.0 {
            searched as f64 / elapsed.as_secs_f64()
        } else {
            0.0
        };
        mine_log_event(
            "cuda_round_completed",
            height,
            None,
            &format!(
                "devices={} completed={} searched={} elapsed_ms={} hps={:.3}",
                devices.len(),
                completed,
                searched,
                elapsed.as_millis(),
                hps
            ),
        );

        round = round.wrapping_add(1);
        hdr.time = choose_block_time(db, &parent_tip, parent_hi_opt.as_ref(), height)?;
    }
}

/// Mine exactly one block.
///
/// CRITICAL: Do NOT apply blocks here.
/// Only persist + index, then call maybe_reorg_to() (single source of truth for apply/undo/tip).

pub fn mine_one(
    db: &Stores,
    mempool: &Mempool,
    miner_h160: Hash20,
    max_mempool_txs: usize,
    chain_lock: &ChainLock,
) -> Result<Hash32> {

const HASH_COUNTER_FLUSH_EVERY_NONCES: u64 = 4_194_304;

    
    let parent_tip: Hash32 = get_tip(db)?.unwrap_or([0u8; 32]);
    let parent_hi_opt = if parent_tip != [0u8; 32] {
        get_hidx(db, &parent_tip)?
    } else {
        None
    };

    let height = parent_hi_opt.as_ref().map(|h| h.height + 1).unwrap_or(0);

    let _epoch = epoch_of(height);

    let (mut txs, mut included_ids, _fees) =
        build_template(db, mempool, miner_h160, height, max_mempool_txs)?;

mine_log_event(
    "candidate_created",
    height,
    None,
    &format!(
        "prev=0x{} txs={} included_mempool_txs={} mempool_len={}",
        hex::encode(parent_tip),
        txs.len(),
        included_ids.len(),
        mempool.len()
    ),
);

    let mut hdr = BlockHeader {
        version: 1,
        prev: parent_tip,
        merkle: merkle_root(&txs),
        time: choose_block_time(db, &parent_tip, parent_hi_opt.as_ref(), height)?,
        bits: expected_bits(db, height, parent_hi_opt.as_ref())?,
        nonce: 0u32,
    };

ensure_tip_unchanged(db, &parent_tip, height)?;

let pow_target = PowTarget::from_bits(hdr.bits)
    .ok_or_else(|| anyhow!("invalid mining bits"))?;

println!(
    "[mine] enter: height={} prev=0x{} bits=0x{:08x} time={}",
    height,
    hex::encode(hdr.prev),
    hdr.bits,
    hdr.time
);

mine_log_event(
    "pow_search_started",
    height,
    None,
    &format!(
        "prev=0x{} bits=0x{:08x} time={} workers={}",
        hex::encode(hdr.prev),
        hdr.bits,
        hdr.time,
        miner_thread_count()
    ),
);

#[derive(Clone)]
enum MineMsg {
    Found(Hash32, Block),
    Stale,
}

let workers = miner_thread_count().min(u32::MAX as usize).max(1);
println!("[mine] workers={}", workers);

let stop = Arc::new(AtomicBool::new(false));
let stale = Arc::new(AtomicBool::new(false));
let hash_counter = Arc::new(AtomicU64::new(0));
let (tx_found, rx_found) = mpsc::channel::<MineMsg>();

thread::scope(|scope| {
    {
        let stop = stop.clone();
        let stale = stale.clone();
        let tx_found = tx_found.clone();

        scope.spawn(move || {
            while !stop.load(Ordering::Relaxed) {
                std::thread::sleep(std::time::Duration::from_millis(200));

                let cur_tip = get_tip(db).ok().flatten().unwrap_or([0u8; 32]);

if cur_tip != parent_tip {
    mine_log_event(
        "candidate_stale_before_solution",
        height,
        None,
        &format!(
            "old_prev=0x{} new_tip=0x{}",
            hex::encode(parent_tip),
            hex::encode(cur_tip)
        ),
    );

    stale.store(true, Ordering::Relaxed);
    stop.store(true, Ordering::Relaxed);

    if tx_found.send(MineMsg::Stale).is_err() {
        return;
    }
    return;
}

            }
        });
    }

    if cuda_miner_enabled() {
        let tx_found = tx_found.clone();
        let parent_hi_for_cuda = parent_hi_opt.clone();
        let cuda_hdr = hdr.clone();
        let cuda_txs = txs.clone();
        scope.spawn(move || {
            match mine_one_cuda(
                db,
                height,
                parent_tip,
                parent_hi_for_cuda,
                cuda_hdr,
                cuda_txs,
                pow_target,
            ) {
                Ok((h, block)) => {
                    let _ = tx_found.send(MineMsg::Found(h, block));
                }
                Err(e) => {
                    println!("[mine] cuda miner exited: {:?}", e);
                    let _ = tx_found.send(MineMsg::Stale);
                }
            }
        });
    } else {
    for worker_id in 0..workers {

        let stop = stop.clone();
        let tx_found = tx_found.clone();

let stale = stale.clone();
let hash_counter = hash_counter.clone();

let parent_hi_for_worker = parent_hi_opt.clone();
let mut whdr = hdr.clone();

let mut wtxs = txs.clone();

// Give each worker a unique coinbase script_sig.
// This changes coinbase txid -> merkle -> header search space.
wtxs[0].inputs[0].script_sig.push(0x00);
wtxs[0]
    .inputs[0]
    .script_sig
    .extend_from_slice(format!("worker:{worker_id}").as_bytes());

whdr.merkle = merkle_root(&wtxs);

let base_script_sig = wtxs[0].inputs[0].script_sig.clone();


        // Split nonce space across workers.
        whdr.nonce = worker_id as u32;
        let step = workers as u32;
let pow_target = pow_target;

scope.spawn(move || {
    let mut checks: u64 = 0;
    let mut extra_nonce: u64 = 0;

    loop {
if stop.load(Ordering::Relaxed) || stale.load(Ordering::Relaxed) {
    if checks > 0 {
        hash_counter.fetch_add(checks, Ordering::Relaxed);
    }
    return;
}

        let h = header_hash(&whdr);

if pow_target.check(&h) {

    if checks > 0 {
        hash_counter.fetch_add(checks, Ordering::Relaxed);
    }

    stop.store(true, Ordering::Relaxed);

mine_log_event(
    "pow_solution_found",
    height,
    Some(&h),
    &format!(
        "prev=0x{} bits=0x{:08x} time={} nonce={} worker_id={}",
        hex::encode(whdr.prev),
        whdr.bits,
        whdr.time,
        whdr.nonce,
        worker_id
    ),
);

    let block = Block {
                header: whdr.clone(),
                txs: wtxs.clone(),
            };

if tx_found.send(MineMsg::Found(h, block)).is_err() {
    return;
}
            return;
        }

        let old_nonce = whdr.nonce;
        whdr.nonce = whdr.nonce.wrapping_add(step);

if whdr.nonce < old_nonce {
    extra_nonce = extra_nonce.wrapping_add(1);

	    whdr.time = match choose_block_time(db, &parent_tip, parent_hi_for_worker.as_ref(), height) {
	        Ok(time) => time,
	        Err(_) => {
	            stale.store(true, Ordering::Relaxed);
	            stop.store(true, Ordering::Relaxed);
	            let _ = tx_found.send(MineMsg::Stale);
	            return;
	        }
	    };

    let marker = extra_nonce.to_le_bytes();

    wtxs[0].inputs[0].script_sig = base_script_sig.clone();
    wtxs[0].inputs[0].script_sig.push(0x00);
    wtxs[0]
        .inputs[0]
        .script_sig
        .extend_from_slice(&marker);

    whdr.merkle = merkle_root(&wtxs);
    whdr.nonce = worker_id as u32;
}

        checks = checks.wrapping_add(1);

if checks >= HASH_COUNTER_FLUSH_EVERY_NONCES {
    hash_counter.fetch_add(checks, Ordering::Relaxed);
    checks = 0;
}

    }
	});
	}
    }
	    drop(tx_found);

    match rx_found.recv() {
        Ok(MineMsg::Stale) => Err(anyhow!("stale template")),

Ok(MineMsg::Found(h, block)) => {
    let solved_hdr = block.header.clone();

let solved_at = Instant::now();

mine_log_event(
    "solution_received",
    height,
    Some(&h),
    &format!(
        "prev=0x{} txs={}",
        hex::encode(block.header.prev),
        block.txs.len()
    ),
);

if header_hash(&solved_hdr) != h {
    return Err(anyhow!("solved block hash/header mismatch"));
}

if solved_hdr.merkle != merkle_root(&block.txs) {
    return Err(anyhow!("solved block merkle mismatch"));
}

if !pow_target.check(&h) {
    return Err(anyhow!("solved block failed local pow check"));
}

            let _g = chain_lock.lock();

            let cur_tip = get_tip(db)?.unwrap_or([0u8; 32]);
            if cur_tip != solved_hdr.prev {
                println!(
                    "[mine] solved stale block: solved_prev=0x{} current_tip=0x{}",
                    hex::encode(solved_hdr.prev),
                    hex::encode(cur_tip),
                );
                return Err(anyhow!("solved stale block"));
            }

            let block_bytes = crate::codec::consensus_bincode().serialize(&block)?;

            if block_bytes.len() > MAX_BLOCK_BYTES {
                println!(
                    "[mine] refusing to store oversized block ({} > MAX_BLOCK_BYTES={})",
                    block_bytes.len(),
                    MAX_BLOCK_BYTES
                );
                return Err(anyhow!("oversized block template"));
            }

            db.blocks.insert(k_block(&h), block_bytes)?;

mine_log_event(
    "block_stored",
    height,
    Some(&h),
    &format!(
        "elapsed_ms={}",
        solved_at.elapsed().as_millis()
    ),
);

            let _hi = index_header(db, &solved_hdr, parent_hi_opt.as_ref())?;

mine_log_event(
    "block_indexed",
    height,
    Some(&h),
    &format!(
        "chainwork={} elapsed_ms={}",
        _hi.chainwork,
        solved_at.elapsed().as_millis()
    ),
);

            db.db.flush()?;

            if let Err(e) = maybe_reorg_to(db, &h, Some(mempool)) {
                println!("[mine] maybe_reorg_to failed for {}: {}", hex::encode(h), e);
                return Err(e);
            }

            let tip_after = get_tip(db)?.unwrap_or([0u8; 32]);
            let accepted_as_tip = tip_after == h;

if accepted_as_tip {
    mine_log_event(
        "block_accepted_canonical",
        height,
        Some(&h),
        &format!(
            "tip_after=0x{} elapsed_ms={}",
            hex::encode(tip_after),
            solved_at.elapsed().as_millis()
        ),
    );

                let removed = mempool.remove_mined_block(&block);

                if removed > 0 {
                    println!(
                        "[mempool] removed {} mined/conflicting txs after accepted block (mempool_len={}, spent_outpoints={})",
                        removed,
                        mempool.len(),
                        mempool.spent_len()
                    );
                }
            } else {

    mine_log_event(
        "block_orphaned",
        height,
        Some(&h),
        &format!(
            "tip_after=0x{} elapsed_ms={} included_mempool_txs={}",
            hex::encode(tip_after),
            solved_at.elapsed().as_millis(),
            included_ids.len()
        ),
    );

                println!(
                    "[mine] orphaned local win: 0x{} (tip_after=0x{})",
                    hex::encode(h),
                    hex::encode(tip_after),
                );
                println!(
                    "[mine] block {} was not selected as tip (tip_after={}); keeping {} txs in mempool",
                    hex::encode(h),
                    hex::encode(tip_after),
                    included_ids.len()
                );
            }

            let pruned = mempool.prune(db);
            if pruned > 0 {
                println!(
                    "[mempool] pruned {} txs after mining (mempool_len={}, spent_outpoints={})",
                    pruned,
                    mempool.len(),
                    mempool.spent_outpoints().len()
                );
            }

            Ok(h)
        }
        Err(_) => Err(anyhow!("miner workers exited without result")),
    }
})
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::chain::index::{get_hidx, header_hash, index_header};
    use crate::chain::lock::new_chain_lock;
    use crate::chain::pow::pow_ok;
    use crate::net::mempool::Mempool;
    use crate::params::{INITIAL_REWARD, POW_LIMIT_BITS};
    use crate::state::app_state::epoch_of;
    use crate::state::db::{get_tip, k_block, set_tip, Stores};
    use crate::state::utxo::validate_and_apply_block;
    use tempfile::TempDir;

    fn mine_test_header_with_cuda(mut hdr: BlockHeader) -> Result<BlockHeader> {
        let cuda_bin = std::env::var("CSD_CUDA_BIN")
            .unwrap_or_else(|_| "/usr/local/bin/csd-cuda-search".to_string());
        let device = std::env::var("CSD_CUDA_TEST_DEVICES")
            .unwrap_or_else(|_| "0".to_string())
            .split(',')
            .next()
            .unwrap_or("0")
            .trim()
            .to_string();
        let count = std::env::var("CSD_CUDA_TEST_GENESIS_COUNT")
            .unwrap_or_else(|_| "1000000000".to_string());
        let target_hex = hex::encode(crate::chain::pow::bits_to_target_bytes(hdr.bits));

        let output = Command::new(&cuda_bin)
            .arg(format!("0x{}", header_hex(&hdr)))
            .arg(format!("0x{}", target_hex))
            .arg("0")
            .arg(&count)
            .arg(&device)
            .arg("1024")
            .arg("256")
            .output()
            .map_err(|e| anyhow!("failed to run cuda miner {cuda_bin}: {e}"))?;

        if !output.status.success() {
            return Err(anyhow!(
                "cuda genesis miner failed status={:?} stderr={}",
                output.status.code(),
                String::from_utf8_lossy(&output.stderr)
            ));
        }

        let stdout = String::from_utf8_lossy(&output.stdout);
        let Some((nonce, h)) = parse_cuda_found(&stdout)? else {
            return Err(anyhow!("cuda genesis miner did not find a nonce: {stdout}"));
        };
        hdr.nonce = nonce;
        let local = header_hash(&hdr);
        if local != h {
            return Err(anyhow!(
                "cuda genesis solution mismatch local=0x{} cuda=0x{}",
                hex::encode(local),
                hex::encode(h)
            ));
        }
        if !pow_ok(&h, hdr.bits) {
            return Err(anyhow!("cuda genesis solution failed pow check"));
        }
        Ok(hdr)
    }

    fn install_easy_genesis(db: &Stores) -> Result<Hash32> {
        let txs = vec![coinbase(
            [0x33; 20],
            INITIAL_REWARD,
            0,
            Some(b"cuda-acceptance"),
        )];
        let hdr = mine_test_header_with_cuda(BlockHeader {
            version: 1,
            prev: [0u8; 32],
            merkle: merkle_root(&txs),
            time: crate::chain::time::now_secs().saturating_sub(120),
            bits: POW_LIMIT_BITS,
            nonce: 0,
        })?;
        let h = header_hash(&hdr);
        let block = Block { header: hdr, txs };
        db.blocks.insert(
            k_block(&h),
            crate::codec::consensus_bincode().serialize(&block)?,
        )?;
        index_header(db, &block.header, None)?;
        validate_and_apply_block(db, &block, epoch_of(0), 0)?;
        set_tip(db, &h)?;
        db.db.flush()?;
        Ok(h)
    }

    #[test]
    fn cuda_miner_solution_is_accepted_as_canonical_tip() -> Result<()> {
        if std::env::var("CSD_RUN_CUDA_ACCEPTANCE_TEST")
            .ok()
            .as_deref()
            != Some("1")
        {
            eprintln!("skipping CUDA acceptance test; set CSD_RUN_CUDA_ACCEPTANCE_TEST=1");
            return Ok(());
        }

        let cuda_bin = std::env::var("CSD_CUDA_BIN")
            .unwrap_or_else(|_| "/usr/local/bin/csd-cuda-search".to_string());
        if !std::path::Path::new(&cuda_bin).exists() {
            eprintln!("skipping CUDA acceptance test; missing {cuda_bin}");
            return Ok(());
        }

        std::env::set_var("CSD_CUDA_MINER", "1");
        std::env::set_var("CSD_CUDA_BIN", cuda_bin);
        std::env::set_var(
            "CSD_CUDA_DEVICES",
            std::env::var("CSD_CUDA_TEST_DEVICES").unwrap_or_else(|_| "0".to_string()),
        );
        std::env::set_var(
            "CSD_CUDA_COUNT",
            std::env::var("CSD_CUDA_TEST_COUNT").unwrap_or_else(|_| "10000000".to_string()),
        );
        std::env::set_var("CSD_CUDA_BLOCKS", "1024");
        std::env::set_var("CSD_CUDA_THREADS", "256");

        let temp = TempDir::new()?;
        let db = Stores::open(temp.path().to_str().unwrap())?;
        let genesis = install_easy_genesis(&db)?;
        let mempool = Mempool::new();
        let chain_lock = new_chain_lock();

        let mined = mine_one(&db, &mempool, [0x44; 20], 0, &chain_lock)?;
        let tip = get_tip(&db)?.ok_or_else(|| anyhow!("missing tip after CUDA mine_one"))?;
        assert_eq!(tip, mined);
        assert_ne!(tip, genesis);

        let hi = get_hidx(&db, &tip)?.ok_or_else(|| anyhow!("missing mined header index"))?;
        assert_eq!(hi.height, 1);
        let block_bytes = db
            .blocks
            .get(k_block(&tip))?
            .ok_or_else(|| anyhow!("missing mined block bytes"))?;
        let block: Block = crate::codec::consensus_bincode().deserialize(&block_bytes)?;
        assert_eq!(header_hash(&block.header), tip);
        assert!(pow_ok(&tip, block.header.bits));
        assert_eq!(block.header.prev, genesis);

        Ok(())
    }
}
