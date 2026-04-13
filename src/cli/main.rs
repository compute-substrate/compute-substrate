// src/cli/main.rs
use anyhow::{Context, Result};
use clap::{ArgAction, Parser, Subcommand};
use std::sync::Arc;

use crate::state::db::Stores;

#[derive(Parser)]
#[command(
    name = "csd",
    version = "1.0",
    about = "Compute Substrate node and wallet CLI",
    long_about = "Compute Substrate node and wallet CLI.\n\nUse `csd node` to run a node or miner.\nUse `csd wallet` to create keys, inspect balances, build transactions, and submit proposals or attestations.",
    arg_required_else_help = true
)]
pub struct Cmd {
    #[command(subcommand)]
    pub cmd: Commands,
}

#[derive(Subcommand)]
pub enum Commands {
    /// Create a genesis block file
    Genesis {
        /// Output path for the genesis file
        #[arg(long, default_value = "genesis.bin")]
        out: String,

        /// 20-byte burn address used in genesis
        #[arg(long, default_value = "0x0000000000000000000000000000000000000000")]
        burn_addr20: String,
    },

    /// Chain inspection helpers
    Chain {
        #[command(subcommand)]
        c: ChainCmd,
    },

    /// Database inspection helpers
    Db {
        #[command(subcommand)]
        d: DbCmd,
    },

    /// Build, sign, and submit a proposal transaction (easy path)
    Propose {
        /// 32-byte private key hex; falls back to wallet config if omitted
        #[arg(long)]
        privkey: Option<String>,

        /// Input triple: <txid>:<vout>:<value>
        #[arg(long, action = ArgAction::Append)]
        input: Vec<String>,

        /// Auto-pick one local input from the wallet if no --input is provided
        #[arg(long)]
        auto_input: bool,

        /// Minimum value when using auto input; defaults to fee when omitted
        #[arg(long)]
        min_input: Option<u64>,

        /// Database directory for auto-input; falls back to wallet config if omitted
        #[arg(long)]
        datadir: Option<String>,

        /// Fee in native units
        #[arg(long)]
        fee: u64,

        /// Optional change addr20; defaults to sender addr20 or wallet config
        #[arg(long)]
        change: Option<String>,

        /// Proposal domain
        #[arg(long)]
        domain: String,

        /// Raw payload text; if provided, payload_hash is computed automatically
        #[arg(long)]
        payload: Option<String>,

        /// 32-byte payload hash
        #[arg(long)]
        payload_hash: Option<String>,

        /// Payload URI; defaults to payload text if --payload is used and --uri is omitted
        #[arg(long)]
        uri: Option<String>,

        /// Expiry epoch; if omitted, defaults to current_epoch + 10
        #[arg(long)]
        expires_epoch: Option<u64>,

        /// Node RPC base URL; falls back to wallet config if omitted
        #[arg(long)]
        rpc_url: Option<String>,
    },

    /// Build, sign, and submit an attestation transaction (easy path)
    Attest {
        /// 32-byte private key hex; falls back to wallet config if omitted
        #[arg(long)]
        privkey: Option<String>,

        /// Input triple: <txid>:<vout>:<value>
        #[arg(long, action = ArgAction::Append)]
        input: Vec<String>,

        /// Auto-pick one local input from the wallet if no --input is provided
        #[arg(long)]
        auto_input: bool,

        /// Minimum value when using auto input; defaults to fee when omitted
        #[arg(long)]
        min_input: Option<u64>,

        /// Database directory for auto-input; falls back to wallet config if omitted
        #[arg(long)]
        datadir: Option<String>,

        /// Fee in native units
        #[arg(long)]
        fee: u64,

        /// Optional change addr20; defaults to sender addr20 or wallet config
        #[arg(long)]
        change: Option<String>,

        /// Proposal txid / proposal id
        #[arg(long)]
        proposal_id: String,

        /// Attestation score
        #[arg(long)]
        score: u32,

        /// Attestation confidence
        #[arg(long)]
        confidence: u32,

        /// Node RPC base URL; falls back to wallet config if omitted
        #[arg(long)]
        rpc_url: Option<String>,
    },

    /// Build and sign a plain spend transaction (easy path)
    Spend {
        /// 32-byte private key hex; falls back to wallet config if omitted
        #[arg(long)]
        privkey: Option<String>,

        /// Input triple: <txid>:<vout>:<value>
        #[arg(long, action = ArgAction::Append)]
        input: Vec<String>,

        /// Auto-pick one local input from the wallet if no --input is provided
        #[arg(long)]
        auto_input: bool,

        /// Minimum value when using auto input
        #[arg(long)]
        min_input: Option<u64>,

        /// Database directory for auto-input; falls back to wallet config if omitted
        #[arg(long)]
        datadir: Option<String>,

        /// Output pair: <addr20>:<value>
        #[arg(long, action = ArgAction::Append)]
        output: Vec<String>,

        /// Fee in native units
        #[arg(long)]
        fee: u64,

        /// Optional change addr20; defaults to sender addr20 or wallet config
        #[arg(long)]
        change: Option<String>,
    },

    /// Run a node or miner
    Node {
        /// Database directory
        #[arg(long, default_value = "cs.db")]
        datadir: String,

        /// RPC listen address
        #[arg(long, default_value = "127.0.0.1:8789")]
        rpc: String,

        /// Enable mining
        #[arg(long)]
        mine: bool,

        /// Miner payout address (required with --mine)
        #[arg(long, default_value = "")]
        miner_addr20: String,

        /// Genesis block file
        #[arg(long, default_value = "genesis.bin")]
        genesis: String,

        /// P2P listen multiaddr
        #[arg(long, default_value = "/ip4/0.0.0.0/tcp/17999")]
        p2p_listen: String,

        /// Comma-separated bootnode multiaddrs
        #[arg(long, default_value = "")]
        bootnodes: String,

        /// P2P test mode (for staging/tests only)
        #[arg(long, default_value = "normal", hide = true)]
        p2p_test_mode: String,
    },

    /// Wallet and transaction tools
    Wallet {
        #[command(subcommand)]
        w: WalletCmd,
    },
}

#[derive(Subcommand)]
pub enum WalletCmd {
    /// Generate a new private key, pubkey, and addr20
    New,

    /// Recover pubkey and addr20 from a private key
    Recover {
        /// 32-byte private key hex
        #[arg(long)]
        privkey: String,
    },

    /// Initialize wallet defaults with a private key
    Init {
        /// 32-byte private key hex
        #[arg(long)]
        privkey: String,

        /// Optional default RPC URL
        #[arg(long)]
        rpc_url: Option<String>,

        /// Optional default datadir
        #[arg(long)]
        datadir: Option<String>,
    },

    /// Set the default RPC URL
    SetRpc {
        #[arg(long)]
        rpc_url: String,
    },

    /// Set the default datadir
    SetDatadir {
        #[arg(long)]
        datadir: String,
    },

    /// Show current wallet config
    Config,

    /// Find a spendable input in the local UTXO set
    Input {
        /// Private key to derive addr20 from
        #[arg(long)]
        privkey: Option<String>,

        /// Addr20 to search for directly
        #[arg(long)]
        address: Option<String>,

        /// Database directory
        #[arg(long, default_value = "cs.db")]
        datadir: String,

        /// Minimum input value
        #[arg(long, default_value_t = 0)]
        min: u64,

        /// Pick smallest sufficient UTXO instead of largest
        #[arg(long)]
        smallest: bool,
    },

    /// Show balance summary for an addr20
    Balance {
        /// 20-byte address hex
        #[arg(long)]
        address: String,

        /// Database directory
        #[arg(long, default_value = "cs.db")]
        datadir: String,
    },

    /// Build and sign a plain spend transaction
    Spend {
        /// 32-byte private key hex
        #[arg(long)]
        privkey: String,

        /// Input triple: <txid>:<vout>:<value>
        #[arg(long, action = ArgAction::Append)]
        input: Vec<String>,

        /// Auto-pick one local input from the wallet
        #[arg(long)]
        auto_input: bool,

        /// Minimum value when using --auto-input
        #[arg(long, default_value_t = 0)]
        min_input: u64,

        /// Database directory for --auto-input
        #[arg(long, default_value = "cs.db")]
        datadir: String,

        /// Output pair: <addr20>:<value>
        #[arg(long, action = ArgAction::Append)]
        output: Vec<String>,

        /// Fee in native units
        #[arg(long)]
        fee: u64,

        /// Optional change addr20; defaults to sender addr20
        #[arg(long)]
        change: Option<String>,
    },

    /// Build and sign a proposal transaction without submitting it
    ProposeBuild {
        /// 32-byte private key hex
        #[arg(long)]
        privkey: String,

        /// Input triple: <txid>:<vout>:<value>
        #[arg(long, action = ArgAction::Append)]
        input: Vec<String>,

        /// Auto-pick one local input from the wallet
        #[arg(long)]
        auto_input: bool,

        /// Minimum value when using --auto-input
        #[arg(long, default_value_t = 0)]
        min_input: u64,

        /// Database directory for --auto-input
        #[arg(long, default_value = "cs.db")]
        datadir: String,

        /// Fee in native units
        #[arg(long)]
        fee: u64,

        /// Optional change addr20; defaults to sender addr20
        #[arg(long)]
        change: Option<String>,

        /// Proposal domain
        #[arg(long)]
        domain: String,

        /// 32-byte payload hash
        #[arg(long)]
        payload_hash: String,

        /// Payload URI
        #[arg(long)]
        uri: String,

        /// Expiry epoch
        #[arg(long)]
        expires_epoch: u64,
    },

    /// Build and sign an attestation transaction without submitting it
    AttestBuild {
        /// 32-byte private key hex
        #[arg(long)]
        privkey: String,

        /// Input triple: <txid>:<vout>:<value>
        #[arg(long, action = ArgAction::Append)]
        input: Vec<String>,

        /// Auto-pick one local input from the wallet
        #[arg(long)]
        auto_input: bool,

        /// Minimum value when using --auto-input
        #[arg(long, default_value_t = 0)]
        min_input: u64,

        /// Database directory for --auto-input
        #[arg(long, default_value = "cs.db")]
        datadir: String,

        /// Fee in native units
        #[arg(long)]
        fee: u64,

        /// Optional change addr20; defaults to sender addr20
        #[arg(long)]
        change: Option<String>,

        /// Proposal txid / proposal id
        #[arg(long)]
        proposal_id: String,

        /// Attestation score
        #[arg(long)]
        score: u32,

        /// Attestation confidence
        #[arg(long)]
        confidence: u32,
    },

    /// Build, sign, and submit a proposal transaction
    Propose {
        /// 32-byte private key hex
        #[arg(long)]
        privkey: String,

        /// Input triple: <txid>:<vout>:<value>
        #[arg(long, action = ArgAction::Append)]
        input: Vec<String>,

        /// Auto-pick one local input from the wallet
        #[arg(long)]
        auto_input: bool,

        /// Minimum value when using --auto-input
        #[arg(long, default_value_t = 0)]
        min_input: u64,

        /// Database directory for --auto-input
        #[arg(long, default_value = "cs.db")]
        datadir: String,

        /// Fee in native units
        #[arg(long)]
        fee: u64,

        /// Optional change addr20; defaults to sender addr20
        #[arg(long)]
        change: Option<String>,

        /// Proposal domain
        #[arg(long)]
        domain: String,

        /// 32-byte payload hash
        #[arg(long)]
        payload_hash: String,

        /// Payload URI
        #[arg(long)]
        uri: String,

        /// Expiry epoch
        #[arg(long)]
        expires_epoch: u64,

        /// Node RPC base URL
        #[arg(long, default_value = "http://127.0.0.1:8789")]
        rpc_url: String,
    },

    /// Build, sign, and submit an attestation transaction
    Attest {
        /// 32-byte private key hex
        #[arg(long)]
        privkey: String,

        /// Input triple: <txid>:<vout>:<value>
        #[arg(long, action = ArgAction::Append)]
        input: Vec<String>,

        /// Auto-pick one local input from the wallet
        #[arg(long)]
        auto_input: bool,

        /// Minimum value when using --auto-input
        #[arg(long, default_value_t = 0)]
        min_input: u64,

        /// Database directory for --auto-input
        #[arg(long, default_value = "cs.db")]
        datadir: String,

        /// Fee in native units
        #[arg(long)]
        fee: u64,

        /// Optional change addr20; defaults to sender addr20
        #[arg(long)]
        change: Option<String>,

        /// Proposal txid / proposal id
        #[arg(long)]
        proposal_id: String,

        /// Attestation score
        #[arg(long)]
        score: u32,

        /// Attestation confidence
        #[arg(long)]
        confidence: u32,

        /// Node RPC base URL
        #[arg(long, default_value = "http://127.0.0.1:8789")]
        rpc_url: String,
    },
}

#[derive(Subcommand)]
pub enum ChainCmd {
    /// Sum block rewards from height 0..=height
    ExpectedSupply {
        /// Inclusive chain height
        #[arg(long)]
        height: u64,
    },
}

#[derive(Subcommand)]
pub enum DbCmd {
    /// Sum all current UTXO values in a datadir
    SumUtxos {
        /// Database directory
        #[arg(long, default_value = "cs.db")]
        datadir: String,
    },
}

/// Keep mempool consistent with the current canonical UTXO set.
fn prune_mempool(db: &Arc<Stores>, mempool: &Arc<crate::net::mempool::Mempool>) {
    let n = mempool.prune(db.as_ref());
    if n > 0 {
        eprintln!(
            "[mempool] pruned {} txs (mempool_len={}, spent_outpoints={})",
            n,
            mempool.len(),
            mempool.spent_len()
        );
    }
}

fn require_value<T>(v: Option<T>, msg: &str) -> Result<T> {
    v.ok_or_else(|| anyhow::anyhow!("{}", msg))
}

fn resolve_rpc_url(
    cli: Option<String>,
    cfg: &crate::cli::config::CliConfig,
) -> String {
    cli.or_else(|| cfg.default_rpc_url.clone())
        .unwrap_or_else(|| "http://127.0.0.1:8789".to_string())
}

fn resolve_datadir(
    cli: Option<String>,
    cfg: &crate::cli::config::CliConfig,
) -> String {
    cli.or_else(|| cfg.default_datadir.clone())
        .unwrap_or_else(|| "cs.db".to_string())
}

fn resolve_privkey(
    cli: Option<String>,
    cfg: &crate::cli::config::CliConfig,
) -> Result<String> {
    cli.or_else(|| cfg.default_privkey.clone()).ok_or_else(|| {
        anyhow::anyhow!(
            "no private key provided and no default configured; run `csd wallet init --privkey ...` or pass --privkey"
        )
    })
}

fn resolve_change(
    cli: Option<String>,
    cfg: &crate::cli::config::CliConfig,
) -> Option<String> {
    cli.or_else(|| cfg.default_change_addr20.clone())
}

fn compute_payload_hash_hex(payload: &str) -> String {
    let h = crate::crypto::sha256d(payload.as_bytes());
    format!("0x{}", hex::encode(h))
}

fn current_epoch_from_rpc(rpc_url: &str) -> Result<u64> {
    #[derive(serde::Deserialize)]
    struct TipResp {
        height: u64,
    }

    let url = format!("{}/tip", rpc_url.trim_end_matches('/'));
    let resp = ureq::get(&url)
        .call()
        .map_err(|e| anyhow::anyhow!("failed GET {}: {}", url, e))?;

    let body = resp
        .into_string()
        .map_err(|e| anyhow::anyhow!("failed reading {}: {}", url, e))?;

    let tip: TipResp = serde_json::from_str(&body)
        .map_err(|e| anyhow::anyhow!("failed parsing {} JSON: {}", url, e))?;

    Ok(tip.height / crate::params::EPOCH_LEN)
}

fn privkey_to_addr20_hex(privkey: &str) -> Result<String> {
    let s = privkey.strip_prefix("0x").unwrap_or(privkey);
    let sk_bytes = hex::decode(s)
        .map_err(|e| anyhow::anyhow!("invalid privkey hex: {}", e))?;
    if sk_bytes.len() != 32 {
        anyhow::bail!("privkey must be 32 bytes");
    }

    let secp = secp256k1::Secp256k1::new();
    let secret = secp256k1::SecretKey::from_slice(&sk_bytes)
        .map_err(|e| anyhow::anyhow!("invalid secp256k1 privkey: {}", e))?;
    let pubkey = secp256k1::PublicKey::from_secret_key(&secp, &secret);
    let pub33 = pubkey.serialize();

    let addr20 = crate::crypto::hash160(&pub33);
    Ok(format!("0x{}", hex::encode(addr20)))
}

fn normalize_hex_0x(s: &str) -> String {
    if s.starts_with("0x") || s.starts_with("0X") {
        s.to_ascii_lowercase()
    } else {
        format!("0x{}", s.to_ascii_lowercase())
    }
}

fn pick_input_from_rpc(
    rpc_url: &str,
    addr20: &str,
    min_value: u64,
    smallest: bool,
) -> Result<String> {
    #[derive(serde::Deserialize, Clone)]
    struct RpcUtxo {
        txid: String,
        vout: u32,
        value: u64,
    }

    #[derive(serde::Deserialize)]
    struct UtxosResp {
        utxos: Vec<RpcUtxo>,
    }

    let addr20 = normalize_hex_0x(addr20);

    let url = format!(
        "{}/utxos/{}?available=true&min_value={}&smallest={}&limit=1",
        rpc_url.trim_end_matches('/'),
        addr20,
        min_value,
        if smallest { "true" } else { "false" },
    );

    let resp = ureq::get(&url)
        .call()
        .map_err(|e| anyhow::anyhow!("failed GET {}: {}", url, e))?;

    let body = resp
        .into_string()
        .map_err(|e| anyhow::anyhow!("failed reading {}: {}", url, e))?;

    let parsed: UtxosResp = serde_json::from_str(&body)
        .map_err(|e| anyhow::anyhow!("failed parsing {} JSON: {}", url, e))?;

    let Some(picked) = parsed.utxos.first() else {
        anyhow::bail!(
            "no spendable input found via RPC for addr20={} min={}",
            addr20,
            min_value
        );
    };

    Ok(format!(
        "{}:{}:{}",
        normalize_hex_0x(&picked.txid),
        picked.vout,
        picked.value
    ))
}

pub async fn run() -> Result<()> {
    let cmd = Cmd::parse();

    let cfg = crate::cli::config::load_config()
        .context("failed to load CLI config")?;

    match cmd.cmd {

        Commands::Chain { c } => {
            match c {
                ChainCmd::ExpectedSupply { height } => {
                    let mut total: u128 = 0;
                    for h in 0..=height {
                        total = total
                            .checked_add(crate::params::block_reward(h) as u128)
                            .ok_or_else(|| anyhow::anyhow!("expected supply overflow"))?;
                    }
                    println!("{}", total);
                    Ok(())
                }
            }
        }

        Commands::Db { d } => {
            match d {
                DbCmd::SumUtxos { datadir } => {
                    let db = Stores::open(&datadir)?;
                    let c = crate::codec::consensus_bincode();

                    let mut total: u128 = 0;

                    for item in db.utxo.iter() {
                        let (_k, v) = item?;
                        let out: crate::types::TxOut = c.deserialize(&v)?;
                        total = total
                            .checked_add(out.value as u128)
                            .ok_or_else(|| anyhow::anyhow!("utxo sum overflow"))?;
                    }

                    println!("{}", total);
                    Ok(())
                }
            }
        }

        Commands::Spend {
            privkey,
            mut input,
            auto_input,
            min_input,
            datadir,
            output,
            fee,
            change,
        } => {
            use crate::cli::wallet::*;

            let privkey = resolve_privkey(privkey, &cfg)?;

            let rpc_url = resolve_rpc_url(None, &cfg);
            let _datadir = resolve_datadir(datadir, &cfg);
            let change = resolve_change(change, &cfg);

            if input.is_empty() || auto_input {
                if !input.is_empty() && auto_input {
                    anyhow::bail!("--auto-input cannot be combined with explicit --input");
                }
                let min_needed = min_input.unwrap_or(fee);
                let addr20 = privkey_to_addr20_hex(&privkey)?;
                let picked = pick_input_from_rpc(&rpc_url, &addr20, min_needed, false)?;
                input.push(picked);
            }

            wallet_spend(&privkey, input, output, fee, change)?;
            Ok(())
        }

        Commands::Propose {
            privkey,
            mut input,
            auto_input,
            min_input,
            datadir,
            fee,
            change,
            domain,
            payload,
            payload_hash,
            uri,
            expires_epoch,
            rpc_url,
        } => {
            use crate::cli::wallet::*;

            let privkey = resolve_privkey(privkey, &cfg)?;

            let rpc_url = resolve_rpc_url(rpc_url, &cfg);
            let _datadir = resolve_datadir(datadir, &cfg);
            let change = resolve_change(change, &cfg);

            if input.is_empty() || auto_input {
                if !input.is_empty() && auto_input {
                    anyhow::bail!("--auto-input cannot be combined with explicit --input");
                }
                let min_needed = min_input.unwrap_or(fee);
                let addr20 = privkey_to_addr20_hex(&privkey)?;
                let picked = pick_input_from_rpc(&rpc_url, &addr20, min_needed, false)?;
                input.push(picked);
            }

            let payload_hash = match (payload.as_deref(), payload_hash.as_deref()) {
                (Some(p), None) => compute_payload_hash_hex(p),
                (None, Some(h)) => h.to_string(),
                (Some(_), Some(_)) => {
                    anyhow::bail!("provide either --payload or --payload-hash, not both")
                }
                (None, None) => {
                    anyhow::bail!("missing payload; provide --payload or --payload-hash")
                }
            };

            let uri = match (uri, payload) {
                (Some(u), _) => u,
                (None, Some(p)) => p,
                (None, None) => anyhow::bail!("missing uri; provide --uri or use --payload"),
            };

            let expires_epoch = match expires_epoch {
                Some(e) => e,
                None => current_epoch_from_rpc(&rpc_url)? + 10,
            };

            wallet_propose_submit(
                &rpc_url,
                &privkey,
                input,
                fee,
                change,
                domain,
                payload_hash,
                uri,
                expires_epoch,
            )?;
            Ok(())
        }


        Commands::Attest {
            privkey,
            mut input,
            auto_input,
            min_input,
            datadir,
            fee,
            change,
            proposal_id,
            score,
            confidence,
            rpc_url,
        } => {
            use crate::cli::wallet::*;

            let privkey = resolve_privkey(privkey, &cfg)?;

            let rpc_url = resolve_rpc_url(rpc_url, &cfg);
            let _datadir = resolve_datadir(datadir, &cfg);
            let change = resolve_change(change, &cfg);

            if input.is_empty() || auto_input {
                if !input.is_empty() && auto_input {
                    anyhow::bail!("--auto-input cannot be combined with explicit --input");
                }
                let min_needed = min_input.unwrap_or(fee);
                let addr20 = privkey_to_addr20_hex(&privkey)?;
                let picked = pick_input_from_rpc(&rpc_url, &addr20, min_needed, false)?;
                input.push(picked);
            }

            wallet_attest_submit(
                &rpc_url,
                &privkey,
                input,
                fee,
                change,
                proposal_id,
                score,
                confidence,
            )?;
            Ok(())
        }

Commands::Wallet { w } => {
    use crate::cli::wallet::*;

    match w {
        WalletCmd::New => wallet_new()?,

        WalletCmd::Init {
            privkey,
            rpc_url,
            datadir,
        } => {
            let mut next = cfg.clone();
            next.default_privkey = Some(privkey);
            if let Some(r) = rpc_url {
                next.default_rpc_url = Some(r);
            }
            if let Some(d) = datadir {
                next.default_datadir = Some(d);
            }
            crate::cli::config::save_config(&next)?;
            println!(
                "saved wallet config to {}",
                crate::cli::config::config_path()?.display()
            );
        }

        WalletCmd::SetRpc { rpc_url } => {
            let mut next = cfg.clone();
            next.default_rpc_url = Some(rpc_url);
            crate::cli::config::save_config(&next)?;
            println!("updated wallet config");
        }

        WalletCmd::SetDatadir { datadir } => {
            let mut next = cfg.clone();
            next.default_datadir = Some(datadir);
            crate::cli::config::save_config(&next)?;
            println!("updated wallet config");
        }

        WalletCmd::Config => {
            println!(
                "{}",
                serde_json::to_string_pretty(&cfg)
                    .context("failed to serialize config")?
            );
        }

        WalletCmd::Recover { privkey } => wallet_addr(&privkey)?,

        WalletCmd::Input {
            privkey,
            address,
            datadir,
            min,
            smallest,
        } => {
            let datadir = if datadir == "cs.db" {
                resolve_datadir(None, &cfg)
            } else {
                datadir
            };

            let privkey_owned = privkey.or_else(|| cfg.default_privkey.clone());
            let address_owned = address.or_else(|| cfg.default_change_addr20.clone());

            wallet_input(
                &datadir,
                privkey_owned.as_deref(),
                address_owned.as_deref(),
                min,
                smallest,
            )?
        },

        WalletCmd::Balance { address, datadir } => wallet_balance(&datadir, &address)?,

        WalletCmd::Spend {
            privkey,
            mut input,
            auto_input,
            min_input,
            datadir,
            output,
            fee,
            change,
        } => {
            if auto_input {
                if !input.is_empty() {
                    anyhow::bail!("--auto-input cannot be combined with --input");
                }
                let picked = wallet_pick_input(&datadir, &privkey, min_input, false)?;
                input.push(picked);
            }
            wallet_spend(&privkey, input, output, fee, change)?
        }

        WalletCmd::ProposeBuild {
            privkey,
            mut input,
            auto_input,
            min_input,
            datadir,
            fee,
            change,
            domain,
            payload_hash,
            uri,
            expires_epoch,
        } => {
            if auto_input {
                if !input.is_empty() {
                    anyhow::bail!("--auto-input cannot be combined with --input");
                }
                let picked = wallet_pick_input(&datadir, &privkey, min_input, false)?;
                input.push(picked);
            }

            wallet_propose(
                &privkey,
                input,
                fee,
                change,
                domain,
                payload_hash,
                uri,
                expires_epoch,
            )?
        }

        WalletCmd::AttestBuild {
            privkey,
            mut input,
            auto_input,
            min_input,
            datadir,
            fee,
            change,
            proposal_id,
            score,
            confidence,
        } => {
            if auto_input {
                if !input.is_empty() {
                    anyhow::bail!("--auto-input cannot be combined with --input");
                }
                let picked = wallet_pick_input(&datadir, &privkey, min_input, false)?;
                input.push(picked);
            }

            wallet_attest(&privkey, input, fee, change, proposal_id, score, confidence)?
        }

        WalletCmd::Propose {
            privkey,
            mut input,
            auto_input,
            min_input,
            datadir,
            fee,
            change,
            domain,
            payload_hash,
            uri,
            expires_epoch,
            rpc_url,
        } => {
            if auto_input {
                if !input.is_empty() {
                    anyhow::bail!("--auto-input cannot be combined with --input");
                }
                let picked = wallet_pick_input(&datadir, &privkey, min_input, false)?;
                input.push(picked);
            }

            wallet_propose_submit(
                &rpc_url,
                &privkey,
                input,
                fee,
                change,
                domain,
                payload_hash,
                uri,
                expires_epoch,
            )?
        }

        WalletCmd::Attest {
            privkey,
            mut input,
            auto_input,
            min_input,
            datadir,
            fee,
            change,
            proposal_id,
            score,
            confidence,
            rpc_url,
        } => {
            if auto_input {
                if !input.is_empty() {
                    anyhow::bail!("--auto-input cannot be combined with --input");
                }
                let picked = wallet_pick_input(&datadir, &privkey, min_input, false)?;
                input.push(picked);
            }

            wallet_attest_submit(
                &rpc_url,
                &privkey,
                input,
                fee,
                change,
                proposal_id,
                score,
                confidence,
            )?
        }
    }

    Ok(())
}

        Commands::Genesis { out, burn_addr20 } => {
            let s = burn_addr20.strip_prefix("0x").unwrap_or(&burn_addr20);
            let bytes = hex::decode(s)?;
            if bytes.len() != 20 {
                anyhow::bail!("burn_addr20 must be 20 bytes hex");
            }
            let mut burn = [0u8; 20];
            burn.copy_from_slice(&bytes);

            let genesis = crate::chain::genesis::make_genesis_block(burn)?;
            let c = crate::codec::consensus_bincode();
            std::fs::write(&out, c.serialize(&genesis)?)?;
            println!("wrote genesis to {out}");
            let gh = crate::chain::index::header_hash(&genesis.header);
            println!("genesis_hash: 0x{}", hex::encode(gh));
            Ok(())
        }

        Commands::Node {
            datadir,
            rpc,
            mine,
            miner_addr20,
            genesis,
            p2p_listen,
            bootnodes,
            p2p_test_mode,
        } => {

            if let Ok(v) = std::env::var("CSD_CRASH_AT") {
        eprintln!("[failpoint] CSD_CRASH_AT={}", v);
    }
            
            std::fs::create_dir_all(&datadir)?;
            let db = Arc::new(Stores::open(&datadir)?);

            let gbytes = std::fs::read(&genesis)?;
            let c = crate::codec::consensus_bincode();
            let gblock: crate::types::Block = c.deserialize(&gbytes)?;
            crate::chain::genesis::ensure_genesis(db.clone(), gblock.clone())?;
            let genesis_hash = crate::chain::index::header_hash(&gblock.header);

            let mempool = Arc::new(crate::net::mempool::Mempool::new());

            let chain_lock = crate::chain::lock::new_chain_lock();

            {
                let _g = chain_lock.lock();
                crate::chain::reorg::recover_if_needed(db.as_ref(), Some(mempool.as_ref()))
                    .expect("reorg recovery failed");
                db.flush_meta().expect("db.flush_meta failed");
            }

            #[cfg(feature = "explorer-index")]
            {
       crate::state::tx_index::rebuild_canonical_index_from_tip(db.as_ref())
                    .expect("tx index rebuild failed");
            }

            let (tx_gossip_tx, tx_gossip_rx) =
                tokio::sync::mpsc::unbounded_channel::<crate::net::GossipTxEvent>();
            let (mined_hdr_tx, mined_hdr_rx) =
                tokio::sync::mpsc::unbounded_channel::<crate::net::MinedHeaderEvent>();

            let listen_ma: libp2p::Multiaddr = p2p_listen.parse()?;
            let boots: Vec<libp2p::Multiaddr> = if bootnodes.trim().is_empty() {
                vec![]
            } else {
                bootnodes
                    .split(',')
                    .map(|s| s.trim().parse())
                    .collect::<std::result::Result<Vec<_>, _>>()?
            };

                        let test_mode = match p2p_test_mode.as_str() {
                "normal" => crate::net::node::TestPeerMode::Normal,
                "stall-blocks" => crate::net::node::TestPeerMode::StallBlockResponses,
                "unknown-blocks" => crate::net::node::TestPeerMode::UnknownBlockResponses,
                other => anyhow::bail!(
                    "unknown --p2p-test-mode '{}'; expected one of: normal, stall-blocks, unknown-blocks",
                    other
                ),
            };

            let net_cfg = crate::net::node::NetConfig {
                datadir: datadir.clone(),
                listen: listen_ma,
                bootnodes: boots,
                genesis_hash,
                is_bootnode: !mine,
                test_mode,
            };

            // Start P2P and keep a handle for miner gating
            let net = crate::net::node::spawn_p2p(
                db.clone(),
                mempool.clone(),
                net_cfg,
                mined_hdr_rx,
                tx_gossip_rx,
                chain_lock.clone(),
            )
            .await?;

            let app = crate::api::router(
                db.clone(),
                mempool.clone(),
                tx_gossip_tx.clone(),
                net.connected_peers.clone(),
            );

            let listener = tokio::net::TcpListener::bind(&rpc).await?;
            println!("RPC on http://{}", rpc);

            if mine {
                if miner_addr20.trim().is_empty() {
                    anyhow::bail!("--mine requires --miner-addr20 20-byte hex");
                }

                let mut addr = [0u8; 20];
                let s = miner_addr20.strip_prefix("0x").unwrap_or(&miner_addr20);
                let bytes = hex::decode(s)?;
                if bytes.len() != 20 {
                    anyhow::bail!("miner_addr20 must be 20 bytes hex");
                }
                addr.copy_from_slice(&bytes);

                let db2 = db.clone();
                let mp2 = mempool.clone();
                let mined_tx = mined_hdr_tx.clone();
                let chain_lock2 = chain_lock.clone();

                // Gating constants:
                const TIP_FRESH_SECS: u64 = 30;
                const PEER_STABLE_SECS: u64 = 3;

                let net2 = net.clone();

                tokio::spawn(async move {
                    let max_mempool_txs: usize = 500;

                    let mut last_gate_log =
                        std::time::Instant::now() - std::time::Duration::from_secs(10);

                    loop {
                        tokio::time::sleep(std::time::Duration::from_millis(5)).await;

let peers = net2.connected_peers();
let tip_fresh = net2.is_tip_fresh(TIP_FRESH_SECS);
let peer_stable = net2.is_peer_stable(PEER_STABLE_SECS);
let best_peer_height = net2.best_peer_height();
let best_peer_work_lo = net2.best_peer_work_lo();

let local_tip = crate::state::db::get_tip(db2.as_ref())
    .ok()
    .flatten()
    .unwrap_or([0u8; 32]);

let local_hi = crate::chain::index::get_hidx(db2.as_ref(), &local_tip)
    .ok()
    .flatten();

let local_height = local_hi.as_ref().map(|h| h.height).unwrap_or(0);
let local_work_lo = local_hi
    .as_ref()
    .map(|h| (h.chainwork & (u64::MAX as u128)) as u64)
    .unwrap_or(0);

let sync_lag = best_peer_height.saturating_sub(local_height);

// Fresh-network bootstrap:
// if nobody is past genesis yet, allow mining to begin.
let bootstrap_genesis = best_peer_height == 0;

// Normal steady-state rule:
// allow a small trailing window so a miner that is actively syncing
// does not get permanently sidelined while the rest of the network advances.
const MAX_MINING_LAG_BLOCKS: u64 = 3;
let sync_close_enough = bootstrap_genesis || sync_lag <= MAX_MINING_LAG_BLOCKS;

if peers < 1 || !peer_stable || !tip_fresh || !sync_close_enough {
    if last_gate_log.elapsed() >= std::time::Duration::from_secs(30) {
        let last_tip = net2.last_tip_seen_unix();
        let last_peer_change = net2.last_peer_change_unix();
        eprintln!(
"[miner] gate: NOT mining (peers={}, effective_peers={}, tip_fresh={}, peer_stable={}, local_height={}, best_peer_height={}, sync_lag={}, max_mining_lag_blocks={}, bootstrap_genesis={}, sync_close_enough={}, local_work_lo={}, best_peer_work_lo={}, last_tip_seen_unix={}, last_peer_change_unix={})",            peers,
            peers,
            tip_fresh,
            peer_stable,
            local_height,
            best_peer_height,
            sync_lag,
            MAX_MINING_LAG_BLOCKS,
            bootstrap_genesis,
            sync_close_enough,
            local_work_lo,
            best_peer_work_lo,
            last_tip,
            last_peer_change
        );
        last_gate_log = std::time::Instant::now();
    }
    tokio::time::sleep(std::time::Duration::from_millis(200)).await;
    continue;
}

                        prune_mempool(&db2, &mp2);

                        let db3 = db2.clone();
                        let mp3 = mp2.clone();
                        let chain_lock3 = chain_lock2.clone();

                        let mined_join = tokio::task::spawn_blocking(move || {
                            crate::chain::mine::mine_one(
                                db3.as_ref(),
                                mp3.as_ref(),
                                addr,
                                max_mempool_txs,
                                &chain_lock3,
                            )
                        })
                        .await;

                        let mined_res = match mined_join {
                            Ok(res) => res,
                            Err(e) => {
                                eprintln!("[miner] mine_one JOIN ERR (panic/cancel?): {e}");
                                tokio::time::sleep(std::time::Duration::from_millis(200)).await;
                                continue;
                            }
                        };

                        let bh = match mined_res {
                            Ok(h) => h,
                            Err(e) => {
                                let msg = e.to_string();
                                if msg.contains("stale template")
                                    || msg.contains("solved stale block")
                                    || msg.contains("oversized block template")
                                {
                                    tokio::time::sleep(std::time::Duration::from_millis(10)).await;
                                    continue;
                                }

                                eprintln!("[miner] mine_one ERR: {:?}", e);
                                tokio::time::sleep(std::time::Duration::from_millis(200)).await;
                                continue;
                            }
                        };

                        let tip_now = crate::state::db::get_tip(db2.as_ref())
                            .ok()
                            .flatten()
                            .unwrap_or([0u8; 32]);
                        let accepted = tip_now == bh;

                        let mut txs_in_block = 0usize;

                        match db2.blocks.get(crate::state::db::k_block(&bh)) {
                            Ok(Some(v)) => {
                                let c = crate::codec::consensus_bincode();
                                match c.deserialize::<crate::types::Block>(&v) {
                                    Ok(blk) => {
                                        txs_in_block = blk.txs.len();
                                        let _ = mined_tx.send(crate::net::MinedHeaderEvent {
                                            hash: bh,
                                            header: blk.header.clone(),
                                        });
                                    }
                                    Err(e) => {
                                        eprintln!(
                                            "[mine] warning: failed to deserialize block {}: {e}",
                                            hex::encode(bh)
                                        );
                                    }
                                }
                            }
                            Ok(None) => {
                                eprintln!(
                                    "[mine] warning: missing block bytes for {}",
                                    hex::encode(bh)
                                );
                            }
                            Err(e) => {
                                eprintln!(
                                    "[mine] warning: db.blocks.get failed for {}: {e}",
                                    hex::encode(bh)
                                );
                            }
                        }

                        if accepted {
                            prune_mempool(&db2, &mp2);
                        }

                        println!(
                            "[mine] new block 0x{} (accepted_as_tip={}, txs_in_block={}, mempool_len={}, spent_outpoints={})",
                            hex::encode(bh),
                            accepted,
                            txs_in_block,
                            mp2.len(),
                            mp2.spent_len(),
                        );
                    }
                });
            }

            axum::serve(listener, app).await?;
            Ok(())
        }
    }
}
