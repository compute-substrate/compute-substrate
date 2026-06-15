use anyhow::{bail, Context, Result};
use csd::chain::genesis::ensure_genesis;
use csd::chain::index::{get_hidx, header_hash, index_header};
use csd::chain::reorg::maybe_reorg_to;
use csd::codec::consensus_bincode;
use csd::state::db::{k_block, Stores};
use csd::types::{AppPayload, Block, BlockHeader, Hash20, Hash32, OutPoint, Transaction, TxIn, TxOut};
use serde::Deserialize;
use std::sync::Arc;

#[derive(Deserialize)]
struct RpcBlock {
    hash: String,
    height: u64,
    header: RpcHeader,
    txs: Vec<RpcTx>,
}

#[derive(Deserialize)]
struct RpcHeader {
    version: u32,
    prev: String,
    merkle: String,
    time: u64,
    bits: u32,
    nonce: u32,
}

#[derive(Deserialize)]
struct RpcTx {
    version: u32,
    inputs: Vec<RpcIn>,
    outputs: Vec<RpcOut>,
    locktime: u32,
    app: RpcApp,
}

#[derive(Deserialize)]
struct RpcIn {
    prev_txid: String,
    vout: u32,
    script_sig: String,
}

#[derive(Deserialize)]
struct RpcOut {
    value: u64,
    script_pubkey: String,
}

#[derive(Deserialize)]
#[serde(tag = "type")]
enum RpcApp {
    None,
    Propose {
        domain: String,
        payload_hash: String,
        uri: String,
        expires_epoch: u64,
    },
    Attest {
        proposal_id: String,
        score: u32,
        confidence: u32,
    },
}

fn hex_bytes(s: &str) -> Result<Vec<u8>> {
    let s = s.strip_prefix("0x").unwrap_or(s);
    Ok(hex::decode(s)?)
}

fn h32(s: &str) -> Result<Hash32> {
    let b = hex_bytes(s)?;
    if b.len() != 32 {
        bail!("expected hash32, got {} bytes", b.len());
    }
    let mut out = [0u8; 32];
    out.copy_from_slice(&b);
    Ok(out)
}

fn h20(s: &str) -> Result<Hash20> {
    let b = hex_bytes(s)?;
    if b.len() != 20 {
        bail!("expected hash20, got {} bytes", b.len());
    }
    let mut out = [0u8; 20];
    out.copy_from_slice(&b);
    Ok(out)
}

fn into_block(r: RpcBlock) -> Result<Block> {
    let header = BlockHeader {
        version: r.header.version,
        prev: h32(&r.header.prev)?,
        merkle: h32(&r.header.merkle)?,
        time: r.header.time,
        bits: r.header.bits,
        nonce: r.header.nonce,
    };

    let txs = r
        .txs
        .into_iter()
        .map(|tx| -> Result<Transaction> {
            let inputs = tx
                .inputs
                .into_iter()
                .map(|i| -> Result<TxIn> {
                    Ok(TxIn {
                        prevout: OutPoint {
                            txid: h32(&i.prev_txid)?,
                            vout: i.vout,
                        },
                        script_sig: hex_bytes(&i.script_sig)?,
                    })
                })
                .collect::<Result<Vec<_>>>()?;

            let outputs = tx
                .outputs
                .into_iter()
                .map(|o| -> Result<TxOut> {
                    Ok(TxOut {
                        value: o.value,
                        script_pubkey: h20(&o.script_pubkey)?,
                    })
                })
                .collect::<Result<Vec<_>>>()?;

            let app = match tx.app {
                RpcApp::None => AppPayload::None,
                RpcApp::Propose {
                    domain,
                    payload_hash,
                    uri,
                    expires_epoch,
                } => AppPayload::Propose {
                    domain,
                    payload_hash: h32(&payload_hash)?,
                    uri,
                    expires_epoch,
                },
                RpcApp::Attest {
                    proposal_id,
                    score,
                    confidence,
                } => AppPayload::Attest {
                    proposal_id: h32(&proposal_id)?,
                    score,
                    confidence,
                },
            };

            Ok(Transaction {
                version: tx.version,
                inputs,
                outputs,
                locktime: tx.locktime,
                app,
            })
        })
        .collect::<Result<Vec<_>>>()?;

    let block = Block { header, txs };
    let got = header_hash(&block.header);
    let want = h32(&r.hash)?;
    if got != want {
        bail!(
            "hash mismatch at height {}: got 0x{}, want 0x{}",
            r.height,
            hex::encode(got),
            hex::encode(want)
        );
    }
    Ok(block)
}

fn fetch(base: &str, height: u64) -> Result<Block> {
    let body = if let Some(dir) = base.strip_prefix("file://") {
        let path = format!("{}/{}.json", dir.trim_end_matches('/'), height);
        std::fs::read_to_string(&path).with_context(|| format!("read {path}"))?
    } else {
        let url = format!("{}/block/height/{}", base.trim_end_matches('/'), height);
        ureq::get(&url)
            .call()
            .with_context(|| format!("GET {url}"))?
            .into_string()?
    };
    let v: serde_json::Value = serde_json::from_str(&body)?;
    if !v.get("ok").and_then(|x| x.as_bool()).unwrap_or(false) {
        bail!("rpc returned not ok at height {height}: {body}");
    }
    let rb: RpcBlock = serde_json::from_value(v)?;
    into_block(rb)
}

fn main() -> Result<()> {
    let mut args = std::env::args().skip(1);
    let datadir = args.next().unwrap_or_else(|| "/var/lib/csd/csd-miner".to_string());
    let to: u64 = args
        .next()
        .context("usage: bootstrap_rpc <datadir> <to_height> [base_url]")?
        .parse()?;
    let base = args
        .next()
        .unwrap_or_else(|| "https://cairn-substrate.com/api/rpc".to_string());

    let db = Arc::new(Stores::open(&datadir)?);
    let c = consensus_bincode();

    for height in 0..=to {
        let block = fetch(&base, height).with_context(|| format!("fetch height {height}"))?;
        let hash = header_hash(&block.header);
        if height == 0 {
            ensure_genesis(Arc::clone(&db), block.clone())?;
        } else {
            let parent = get_hidx(&db, &block.header.prev)?
                .with_context(|| format!("missing parent for height {height}"))?;
            index_header(&db, &block.header, Some(&parent))
                .with_context(|| format!("index height {height}"))?;
            db.blocks.insert(k_block(&hash), c.serialize(&block)?)?;
            maybe_reorg_to(&db, &hash, None).with_context(|| format!("apply height {height}"))?;
        }

        if height % 100 == 0 || height == to {
            println!("imported height={} hash=0x{}", height, hex::encode(hash));
        }
    }

    Ok(())
}
