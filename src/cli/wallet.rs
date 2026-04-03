// src/cli/wallet.rs
use anyhow::{bail, Context, Result};
use rand::rngs::OsRng;
use secp256k1::{ecdsa::Signature, PublicKey, Secp256k1, SecretKey};
use serde::{Deserialize, Serialize};
use serde_json::json;
use std::io::{Read, Write};
use std::net::TcpStream;

use crate::crypto::{hash160, sha256d, sighash};
use crate::state::db::Stores;
use crate::types::{AppPayload, Hash32, OutPoint, Transaction, TxIn, TxOut};

const DUST_LIMIT: u64 = 546; // bitcoin-ish
const TX_SUBMIT_PATH: &str = "/tx/submit";

fn c() -> crate::codec::ConsensusBincode {
    crate::codec::consensus_bincode()
}

fn hex_strip(s: &str) -> &str {
    s.strip_prefix("0x").unwrap_or(s)
}

fn parse_hex_bytes(s: &str) -> Result<Vec<u8>> {
    let trimmed = s.trim();
    let stripped = hex_strip(trimmed);

    if stripped.is_empty() {
        bail!(
            "empty hex string (did you pass an empty env var like 0x$PAYLOAD_HASH?). \
             Provide hex like 0x<...>."
        );
    }

    let bytes = hex::decode(stripped)
        .with_context(|| format!("hex decode failed (len={}): {}", stripped.len(), stripped))?;
    Ok(bytes)
}

fn parse_hash32(s: &str) -> Result<Hash32> {
    let b = parse_hex_bytes(s)?;
    if b.len() != 32 {
        bail!("expected 32-byte hex (hash32), got {} bytes", b.len());
    }
    let mut out = [0u8; 32];
    out.copy_from_slice(&b);
    Ok(out)
}

fn parse_addr20(s: &str) -> Result<[u8; 20]> {
    let b = parse_hex_bytes(s)?;
    if b.len() != 20 {
        bail!("expected 20-byte hex (addr20), got {} bytes", b.len());
    }
    let mut out = [0u8; 20];
    out.copy_from_slice(&b);
    Ok(out)
}

/// scriptsig format (matches utxo.rs parser):
/// [sig_len u8][sig64][pub_len u8][pub33]
fn make_scriptsig(sig64: &[u8; 64], pub33: &[u8; 33]) -> Vec<u8> {
    let mut v = Vec::with_capacity(1 + 64 + 1 + 33);
    v.push(64u8);
    v.extend_from_slice(sig64);
    v.push(33u8);
    v.extend_from_slice(pub33);
    v
}

/// Parse input triple: "<txid>:<vout>:<value>"
fn parse_input_triple(s: &str) -> Result<(OutPoint, u64)> {
    let parts: Vec<&str> = s.split(':').collect();
    if parts.len() != 3 {
        bail!("input must be <txid>:<vout>:<value>");
    }
    let txid = parse_hash32(parts[0])
        .with_context(|| format!("bad txid in input triple: {}", parts[0]))?;
    let vout = parts[1].parse::<u32>().with_context(|| "bad vout")?;
    let value = parts[2].parse::<u64>().with_context(|| "bad value")?;
    Ok((OutPoint { txid, vout }, value))
}

/// Parse output pair: "<addr20>:<value>"
fn parse_output_pair(s: &str) -> Result<([u8; 20], u64)> {
    let parts: Vec<&str> = s.split(':').collect();
    if parts.len() != 2 {
        bail!("output must be <addr20>:<value>");
    }
    let addr = parse_addr20(parts[0])?;
    let value = parts[1]
        .parse::<u64>()
        .with_context(|| "bad output value")?;
    Ok((addr, value))
}

fn sk_from_hex(privkey_hex: &str) -> Result<SecretKey> {
    let b = parse_hex_bytes(privkey_hex)?;
    if b.len() != 32 {
        bail!("privkey must be 32 bytes hex");
    }
    Ok(SecretKey::from_slice(&b)?)
}

fn pub_from_sk(sk: &SecretKey) -> ([u8; 33], [u8; 20]) {
    let secp = Secp256k1::new();
    let pk = PublicKey::from_secret_key(&secp, sk);
    let pk33 = pk.serialize();
    let addr20 = hash160(&pk33);
    (pk33, addr20)
}

/// V1 signing model: sign the same tx digest, stamp same scriptsig into every input.
fn sign_tx_all_inputs(tx: &mut Transaction, sk: &SecretKey, pub33: &[u8; 33]) -> Result<()> {
    // signatures must be computed with script_sig cleared
    for i in tx.inputs.iter_mut() {
        i.script_sig.clear();
    }

    let digest = sighash(tx);
    let msg = secp256k1::Message::from_digest_slice(&digest)?;
    let sig: Signature = Secp256k1::new().sign_ecdsa(&msg, sk);
    let sig64 = sig.serialize_compact();

    for i in tx.inputs.iter_mut() {
        i.script_sig = make_scriptsig(&sig64, pub33);
    }

    Ok(())
}

fn checked_sum_u64<I: IntoIterator<Item = u64>>(it: I) -> Result<u64> {
    let mut s: u64 = 0;
    for v in it {
        s = s
            .checked_add(v)
            .ok_or_else(|| anyhow::anyhow!("u64 overflow"))?;
    }
    Ok(s)
}

fn build_base_tx(
    inputs: &[(OutPoint, u64)],
    outputs: &[([u8; 20], u64)],
    fee: u64,
    locktime: u32,
) -> Result<(Transaction, u64, u64)> {
    if inputs.is_empty() {
        bail!("need at least one input");
    }
    if outputs.is_empty() {
        bail!("need at least one output");
    }

    for (_a, v) in outputs.iter() {
        if *v == 0 {
            bail!("zero-value output not allowed (remove this check if intentional)");
        }
        if *v < DUST_LIMIT {
            bail!("output below dust limit ({}): value={}", DUST_LIMIT, v);
        }
    }

    let in_sum = checked_sum_u64(inputs.iter().map(|(_, v)| *v))?;
    let out_sum = checked_sum_u64(outputs.iter().map(|(_, v)| *v))?;

    let need = out_sum
        .checked_add(fee)
        .ok_or_else(|| anyhow::anyhow!("overflow out_sum+fee"))?;
    if need > in_sum {
        bail!(
            "insufficient input sum: in_sum={} out_sum={} fee={}",
            in_sum,
            out_sum,
            fee
        );
    }

    let tx_inputs = inputs
        .iter()
        .map(|(op, _v)| TxIn {
            prevout: *op,
            script_sig: vec![],
        })
        .collect::<Vec<_>>();

    let tx_outputs = outputs
        .iter()
        .map(|(addr20, v)| TxOut {
            value: *v,
            script_pubkey: *addr20,
        })
        .collect::<Vec<_>>();

    let tx = Transaction {
        version: 1,
        inputs: tx_inputs,
        outputs: tx_outputs,
        locktime,
        app: AppPayload::None,
    };

    Ok((tx, in_sum, out_sum))
}

/// ------------------------------
/// DB UTXO scanning (best-effort)
/// ------------------------------

#[derive(Debug, Clone, Serialize, Deserialize)]
struct UtxoValueCompat {
    txout: TxOut,
    height: u64,
    coinbase: bool,
}

fn parse_outpoint_from_key(k: &[u8]) -> Option<OutPoint> {
    let start = if k.len() == 1 + 32 + 4 && (k[0] == b'U' || k[0] == b'u') {
        1usize
    } else if k.len() == 32 + 4 {
        0usize
    } else {
        return None;
    };

    let txid_bytes = &k[start..start + 32];
    let vout_bytes = &k[start + 32..start + 32 + 4];

    let mut txid = [0u8; 32];
    txid.copy_from_slice(txid_bytes);

    let vout = u32::from_le_bytes([vout_bytes[0], vout_bytes[1], vout_bytes[2], vout_bytes[3]]);
    Some(OutPoint { txid, vout })
}

fn parse_txout_from_value(v: &[u8]) -> Option<TxOut> {
    // Current format: raw TxOut under consensus codec.
    if let Ok(txout) = c().deserialize::<TxOut>(v) {
        return Some(txout);
    }

    // Legacy fallbacks (old DBs only):
    if let Ok(txout) = bincode::deserialize::<TxOut>(v) {
        return Some(txout);
    }
    if let Ok((txout, _h)) = bincode::deserialize::<(TxOut, u64)>(v) {
        return Some(txout);
    }
    if let Ok(uv) = bincode::deserialize::<UtxoValueCompat>(v) {
        return Some(uv.txout);
    }

    None
}

/// Pick one input for addr20.
/// - smallest=false => pick largest (default)
/// - smallest=true  => pick smallest sufficient
fn pick_input_from_db(
    datadir: &str,
    addr20: [u8; 20],
    min_value: u64,
    smallest: bool,
) -> Result<(OutPoint, u64)> {
    let db = Stores::open(datadir).with_context(|| format!("open db at {datadir}"))?;
    let iter = db.utxo.iter();

    let mut best: Option<(OutPoint, u64)> = None;

    for item in iter {
        let (k, v) = item?;
        let Some(op) = parse_outpoint_from_key(&k) else {
            continue;
        };
        let Some(txout) = parse_txout_from_value(&v) else {
            continue;
        };

        if txout.script_pubkey != addr20 {
            continue;
        }

        let value = txout.value;
        if value < min_value {
            continue;
        }

        best = match best {
            None => Some((op, value)),
            Some((bop, bval)) => {
                if smallest {
                    if value < bval {
                        Some((op, value))
                    } else {
                        Some((bop, bval))
                    }
                } else if value > bval {
                    Some((op, value))
                } else {
                    Some((bop, bval))
                }
            }
        };
    }

    best.ok_or_else(|| {
        anyhow::anyhow!(
            "no spendable input found for addr20=0x{} min={} in datadir=/path/here
hint: pass --datadir or run `csd wallet set-datadir --datadir <path>`",
            hex::encode(addr20),
            min_value
        )
    })
}

fn sum_balance_from_db(datadir: &str, addr20: [u8; 20]) -> Result<(u64, usize)> {
    let db = Stores::open(datadir).with_context(|| format!("open db at {datadir}"))?;
    let iter = db.utxo.iter();

    let mut sum: u64 = 0;
    let mut count: usize = 0;

    for item in iter {
        let (_k, v) = item?;
        let Some(txout) = parse_txout_from_value(&v) else {
            continue;
        };
        if txout.script_pubkey != addr20 {
            continue;
        }
        sum = sum.saturating_add(txout.value);
        count += 1;
    }

    Ok((sum, count))
}

/// ------------------------------
/// HTTP submit to /tx/submit
/// ------------------------------

fn parse_http_url(url: &str) -> Result<(String, u16)> {
    let u = url.trim();

    if u.starts_with("https://") {
        bail!("https:// URLs not supported by this minimal submitter; terminate TLS in nginx and use http upstream.");
    }

    let u = u.strip_prefix("http://").unwrap_or(u);
    let mut parts = u.split('/');
    let hostport = parts.next().unwrap_or(u);

    let mut hp = hostport.split(':');
    let host = hp.next().unwrap_or("127.0.0.1").to_string();
    let port = hp
        .next()
        .map(|p| p.parse::<u16>())
        .transpose()?
        .unwrap_or(80);

    Ok((host, port))
}

fn http_post_json(host: &str, port: u16, path: &str, body: &str) -> Result<String> {
    let mut stream =
        TcpStream::connect((host, port)).with_context(|| format!("connect {}:{}", host, port))?;

    let req = format!(
        "POST {} HTTP/1.1\r\nHost: {}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
        path,
        host,
        body.len(),
        body
    );

    stream.write_all(req.as_bytes())?;
    stream.flush()?;

    let mut resp = String::new();
    stream.read_to_string(&mut resp)?;
    Ok(resp)
}

fn extract_http_body(resp: &str) -> &str {
    match resp.split_once("\r\n\r\n") {
        Some((_hdr, body)) => body,
        None => resp,
    }
}

fn http_status_ok(resp: &str) -> bool {
    let line1 = resp.lines().next().unwrap_or("");
    line1.contains(" 200 ") || line1.contains(" 201 ")
}

fn submit_tx(rpc_url: &str, tx: &Transaction) -> Result<serde_json::Value> {
    let (host, port) = parse_http_url(rpc_url)?;
    let tx_json = serde_json::to_value(tx)?;

    let body = serde_json::to_string(&json!({ "tx": tx_json }))?;
    let resp = http_post_json(&host, port, TX_SUBMIT_PATH, &body)?;

    let ok_http = http_status_ok(&resp);
    let body = extract_http_body(&resp);

    let parsed =
        serde_json::from_str::<serde_json::Value>(body).unwrap_or_else(|_| json!({ "raw": body }));
    Ok(json!({
        "http_ok": ok_http,
        "path": TX_SUBMIT_PATH,
        "resp": parsed
    }))
}

fn tx_hex_bincode(tx: &Transaction) -> Result<String> {
    let bytes = c().serialize(tx)?;
    Ok(format!("0x{}", hex::encode(bytes)))
}

fn mk_receipt(
    tx: &Transaction,
    spent: &[(OutPoint, u64)],
    fee: u64,
    change_addr20: Option<[u8; 20]>,
    submit: Option<serde_json::Value>,
) -> Result<serde_json::Value> {
    let txid = crate::crypto::txid(tx);

    let spent_vec = spent
        .iter()
        .map(|(op, v)| format!("0x{}:{}:{}", hex::encode(op.txid), op.vout, v))
        .collect::<Vec<_>>();

    let change_s = change_addr20.map(|a| format!("0x{}", hex::encode(a)));
    let tx_hex = tx_hex_bincode(tx)?;

    Ok(json!({
        "txid": format!("0x{}", hex::encode(txid)),
        "tx_hex": tx_hex,
        "fee": fee,
        "spent": spent_vec,
        "change": change_s,
        "app": tx.app,
        "tx": tx,
        "submit": submit,
    }))
}

/// --- Public commands ---

pub fn wallet_new() -> Result<()> {
    let secp = Secp256k1::new();
    let sk = SecretKey::new(&mut OsRng);
    let pk = PublicKey::from_secret_key(&secp, &sk);
    let pk33 = pk.serialize();
    let addr = hash160(&pk33);

    println!("privkey: 0x{}", hex::encode(sk.secret_bytes()));
    println!("pubkey:  0x{}", hex::encode(pk33));
    println!("addr20:  0x{}", hex::encode(addr));
    Ok(())
}

/// Print addr20/pubkey from privkey
pub fn wallet_addr(privkey: &str) -> Result<()> {
    let sk = sk_from_hex(privkey)?;
    let (pk33, addr20) = pub_from_sk(&sk);
    println!("pubkey:  0x{}", hex::encode(pk33));
    println!("addr20:  0x{}", hex::encode(addr20));
    Ok(())
}

/// Pick a single spendable input and print it as: <txid>:<vout>:<value>
pub fn wallet_input(
    datadir: &str,
    privkey: Option<&str>,
    address: Option<&str>,
    min: u64,
    smallest: bool,
) -> Result<()> {
    let addr20 = match (privkey, address) {
        (Some(pk), None) => {
            let sk = sk_from_hex(pk)?;
            let (_pk33, a) = pub_from_sk(&sk);
            a
        }
        (None, Some(a)) => parse_addr20(a)?,
        (Some(_), Some(_)) => bail!("provide either --privkey or --address, not both"),
        (None, None) => bail!("provide --privkey or --address"),
    };

    let (op, value) = pick_input_from_db(datadir, addr20, min, smallest)?;
    println!("0x{}:{}:{}", hex::encode(op.txid), op.vout, value);
    Ok(())
}

/// Show a minimal balance summary.
pub fn wallet_balance(datadir: &str, address: &str) -> Result<()> {
    let addr20 = parse_addr20(address)?;
    let (sum, count) = sum_balance_from_db(datadir, addr20)?;
    println!(
        "{}",
        serde_json::to_string_pretty(&json!({
            "addr20": format!("0x{}", hex::encode(addr20)),
            "confirmed": sum,
            "spendable": sum,
            "utxo_count": count
        }))?
    );
    Ok(())
}

/// Helper used by CLI --auto-input (returns "<txid>:<vout>:<value>")
pub fn wallet_pick_input(
    datadir: &str,
    privkey: &str,
    min_value: u64,
    smallest: bool,
) -> Result<String> {
    let sk = sk_from_hex(privkey)?;
    let (_pk33, addr20) = pub_from_sk(&sk);
    let (op, value) = pick_input_from_db(datadir, addr20, min_value, smallest)?;
    Ok(format!("0x{}:{}:{}", hex::encode(op.txid), op.vout, value))
}

/// Build + sign a plain spend tx.
pub fn wallet_spend(
    privkey: &str,
    inputs: Vec<String>,
    outputs: Vec<String>,
    fee: u64,
    change_addr20: Option<String>,
) -> Result<()> {
    let sk = sk_from_hex(privkey)?;
    let (pk33, self_addr) = pub_from_sk(&sk);

    let ins = inputs
        .iter()
        .map(|s| parse_input_triple(s.as_str()))
        .collect::<Result<Vec<_>>>()?;

    let outs0 = outputs
        .iter()
        .map(|s| parse_output_pair(s.as_str()))
        .collect::<Result<Vec<_>>>()?;

    let (mut tx, in_sum, out_sum) = build_base_tx(&ins, &outs0, fee, 0)?;

    let ch20 = match change_addr20 {
        Some(ch) => parse_addr20(&ch)?,
        None => self_addr,
    };

    let leftover = in_sum
        .checked_sub(out_sum)
        .ok_or_else(|| anyhow::anyhow!("underflow computing (in_sum - out_sum)"))?;

    if leftover < fee {
        bail!(
            "insufficient funds: in_sum={} out_sum={} fee={} (leftover={})",
            in_sum,
            out_sum,
            fee,
            leftover
        );
    }

    let change = leftover
        .checked_sub(fee)
        .ok_or_else(|| anyhow::anyhow!("underflow computing change"))?;

    let (actual_fee, change20) = if change >= DUST_LIMIT {
        tx.outputs.push(TxOut {
            value: change,
            script_pubkey: ch20,
        });
        (fee, Some(ch20))
    } else {
        let actual_fee = fee
            .checked_add(change)
            .ok_or_else(|| anyhow::anyhow!("fee overflow"))?;
        (actual_fee, None)
    };

    sign_tx_all_inputs(&mut tx, &sk, &pk33)?;

    let receipt = mk_receipt(&tx, &ins, actual_fee, change20, None)?;
    println!("{}", serde_json::to_string_pretty(&receipt)?);
    Ok(())
}

fn payload_hash_must_not_be_zero(h: &Hash32) -> Result<()> {
    if *h == [0u8; 32] {
        bail!(
            "payload_hash is all-zero. This usually means your shell variable was empty. \
             Generate a real hash and pass --payload-hash 0x<64 hex chars>."
        );
    }
    Ok(())
}

/// Build + sign a PROPOSE transaction.
pub fn wallet_propose(
    privkey: &str,
    inputs: Vec<String>,
    fee: u64,
    change_addr20: Option<String>,
    domain: String,
    payload_hash: String,
    uri: String,
    expires_epoch: u64,
) -> Result<()> {
    let sk = sk_from_hex(privkey)?;
    let (pk33, self_addr) = pub_from_sk(&sk);

    let ins = inputs
        .iter()
        .map(|s| parse_input_triple(s.as_str()))
        .collect::<Result<Vec<_>>>()?;

    let in_sum = checked_sum_u64(ins.iter().map(|(_, v)| *v))?;
    if fee > in_sum {
        bail!("fee exceeds input sum");
    }

    let ph = parse_hash32(&payload_hash)?;
    payload_hash_must_not_be_zero(&ph)?;

    let addr20 = if let Some(ch) = change_addr20.as_deref() {
        parse_addr20(ch)?
    } else {
        self_addr
    };

    let mut change_value = in_sum
        .checked_sub(fee)
        .ok_or_else(|| anyhow::anyhow!("underflow change_value"))?;
    if change_value < DUST_LIMIT {
        change_value = 0;
    }

    let mut tx = Transaction {
        version: 1,
        inputs: ins
            .iter()
            .map(|(op, _)| TxIn {
                prevout: *op,
                script_sig: vec![],
            })
            .collect(),
        outputs: if change_value > 0 {
            vec![TxOut {
                value: change_value,
                script_pubkey: addr20,
            }]
        } else {
            vec![]
        },
        locktime: 0,
        app: AppPayload::Propose {
            domain,
            payload_hash: ph,
            uri,
            expires_epoch,
        },
    };

    sign_tx_all_inputs(&mut tx, &sk, &pk33)?;

    let actual_fee = if change_value == 0 { in_sum } else { fee };
    let change_for_receipt = if change_value > 0 { Some(addr20) } else { None };
    let receipt = mk_receipt(&tx, &ins, actual_fee, change_for_receipt, None)?;
    println!("{}", serde_json::to_string_pretty(&receipt)?);
    Ok(())
}

/// Build + sign an ATTEST transaction.
pub fn wallet_attest(
    privkey: &str,
    inputs: Vec<String>,
    fee: u64,
    change_addr20: Option<String>,
    proposal_id: String,
    score: u32,
    confidence: u32,
) -> Result<()> {
    let sk = sk_from_hex(privkey)?;
    let (pk33, self_addr) = pub_from_sk(&sk);

    let ins = inputs
        .iter()
        .map(|s| parse_input_triple(s.as_str()))
        .collect::<Result<Vec<_>>>()?;

    let in_sum = checked_sum_u64(ins.iter().map(|(_, v)| *v))?;
    if fee > in_sum {
        bail!("fee exceeds input sum");
    }

    let addr20 = if let Some(ch) = change_addr20.as_deref() {
        parse_addr20(ch)?
    } else {
        self_addr
    };

    let mut change_value = in_sum
        .checked_sub(fee)
        .ok_or_else(|| anyhow::anyhow!("underflow change_value"))?;
    if change_value < DUST_LIMIT {
        change_value = 0;
    }

    let mut tx = Transaction {
        version: 1,
        inputs: ins
            .iter()
            .map(|(op, _)| TxIn {
                prevout: *op,
                script_sig: vec![],
            })
            .collect(),
        outputs: if change_value > 0 {
            vec![TxOut {
                value: change_value,
                script_pubkey: addr20,
            }]
        } else {
            vec![]
        },
        locktime: 0,
        app: AppPayload::Attest {
            proposal_id: parse_hash32(&proposal_id)?,
            score,
            confidence,
        },
    };

    sign_tx_all_inputs(&mut tx, &sk, &pk33)?;

    let actual_fee = if change_value == 0 { in_sum } else { fee };
    let change_for_receipt = if change_value > 0 { Some(addr20) } else { None };
    let receipt = mk_receipt(&tx, &ins, actual_fee, change_for_receipt, None)?;
    println!("{}", serde_json::to_string_pretty(&receipt)?);
    Ok(())
}

/// Build + sign + SUBMIT a PROPOSE transaction (one-shot).
pub fn wallet_propose_submit(
    rpc_url: &str,
    privkey: &str,
    inputs: Vec<String>,
    fee: u64,
    change_addr20: Option<String>,
    domain: String,
    payload_hash: String,
    uri: String,
    expires_epoch: u64,
) -> Result<()> {
    let sk = sk_from_hex(privkey)?;
    let (pk33, self_addr) = pub_from_sk(&sk);

    let ins = inputs
        .iter()
        .map(|s| parse_input_triple(s.as_str()))
        .collect::<Result<Vec<_>>>()?;

    let in_sum = checked_sum_u64(ins.iter().map(|(_, v)| *v))?;
    if fee > in_sum {
        bail!("fee exceeds input sum");
    }

    let addr20 = if let Some(ch) = change_addr20.as_deref() {
        parse_addr20(ch)?
    } else {
        self_addr
    };

    let ph = parse_hash32(&payload_hash)?;
    payload_hash_must_not_be_zero(&ph)?;

    let mut change_value = in_sum
        .checked_sub(fee)
        .ok_or_else(|| anyhow::anyhow!("underflow change_value"))?;
    if change_value < DUST_LIMIT {
        change_value = 0;
    }

    let mut tx = Transaction {
        version: 1,
        inputs: ins
            .iter()
            .map(|(op, _)| TxIn {
                prevout: *op,
                script_sig: vec![],
            })
            .collect(),
        outputs: if change_value > 0 {
            vec![TxOut {
                value: change_value,
                script_pubkey: addr20,
            }]
        } else {
            vec![]
        },
        locktime: 0,
        app: AppPayload::Propose {
            domain,
            payload_hash: ph,
            uri,
            expires_epoch,
        },
    };

    sign_tx_all_inputs(&mut tx, &sk, &pk33)?;

    let submit = submit_tx(rpc_url, &tx)
        .unwrap_or_else(|e| json!({ "http_ok": false, "error": e.to_string() }));

    let actual_fee = if change_value == 0 { in_sum } else { fee };
    let change_for_receipt = if change_value > 0 { Some(addr20) } else { None };
    let receipt = mk_receipt(&tx, &ins, actual_fee, change_for_receipt, Some(submit))?;
    println!("{}", serde_json::to_string_pretty(&receipt)?);
    Ok(())
}

/// Build + sign + SUBMIT an ATTEST transaction (one-shot).
pub fn wallet_attest_submit(
    rpc_url: &str,
    privkey: &str,
    inputs: Vec<String>,
    fee: u64,
    change_addr20: Option<String>,
    proposal_id: String,
    score: u32,
    confidence: u32,
) -> Result<()> {
    let sk = sk_from_hex(privkey)?;
    let (pk33, self_addr) = pub_from_sk(&sk);

    let ins = inputs
        .iter()
        .map(|s| parse_input_triple(s.as_str()))
        .collect::<Result<Vec<_>>>()?;

    let in_sum = checked_sum_u64(ins.iter().map(|(_, v)| *v))?;
    if fee > in_sum {
        bail!("fee exceeds input sum");
    }

    let addr20 = if let Some(ch) = change_addr20.as_deref() {
        parse_addr20(ch)?
    } else {
        self_addr
    };

    let mut change_value = in_sum
        .checked_sub(fee)
        .ok_or_else(|| anyhow::anyhow!("underflow change_value"))?;
    if change_value < DUST_LIMIT {
        change_value = 0;
    }

    let mut tx = Transaction {
        version: 1,
        inputs: ins
            .iter()
            .map(|(op, _)| TxIn {
                prevout: *op,
                script_sig: vec![],
            })
            .collect(),
        outputs: if change_value > 0 {
            vec![TxOut {
                value: change_value,
                script_pubkey: addr20,
            }]
        } else {
            vec![]
        },
        locktime: 0,
        app: AppPayload::Attest {
            proposal_id: parse_hash32(&proposal_id)?,
            score,
            confidence,
        },
    };

    sign_tx_all_inputs(&mut tx, &sk, &pk33)?;

    let submit = submit_tx(rpc_url, &tx)
        .unwrap_or_else(|e| json!({ "http_ok": false, "error": e.to_string() }));

    let actual_fee = if change_value == 0 { in_sum } else { fee };
    let change_for_receipt = if change_value > 0 { Some(addr20) } else { None };
    let receipt = mk_receipt(&tx, &ins, actual_fee, change_for_receipt, Some(submit))?;
    println!("{}", serde_json::to_string_pretty(&receipt)?);
    Ok(())
}

// Optional helper: compute a payload hash locally from bytes.
#[allow(dead_code)]
fn payload_hash_from_bytes(bytes: &[u8]) -> Hash32 {
    sha256d(bytes)
}
