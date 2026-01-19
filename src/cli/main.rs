use clap::{Parser, Subcommand};
use anyhow::Result;
use std::sync::Arc;

use crate::state::db::Stores;

#[derive(Parser)]
#[command(name="csd", version="0.1.0")]
pub struct Cmd {
    #[command(subcommand)]
    pub cmd: Commands,
}


#[derive(Subcommand)]
pub enum Commands {
    Genesis {
        #[arg(long, default_value="genesis.bin")]
        out: String,

        #[arg(long, default_value="0x0000000000000000000000000000000000000000")]
        burn_addr20: String,
    },

    Node {
        #[arg(long, default_value="cs.db")]
        datadir: String,

        #[arg(long, default_value="127.0.0.1:8789")]
        rpc: String,

        #[arg(long)]
        mine: bool,

        #[arg(long, default_value="")]
        miner_addr20: String,

        // ---- P2P ----
        #[arg(long, default_value="genesis.bin")]
        genesis: String,

        #[arg(long, default_value="/ip4/0.0.0.0/tcp/17999")]
        p2p_listen: String,

        #[arg(long, default_value="")]
        bootnodes: String, // comma-separated multiaddrs
    },

    Wallet {
        #[command(subcommand)]
        w: WalletCmd,
    },
}

#[derive(Subcommand)]
pub enum WalletCmd {
    New,
}

pub async fn run() -> Result<()> {
    let cmd = Cmd::parse();

    match cmd.cmd {
        Commands::Wallet { w } => {
            match w {
                WalletCmd::New => crate::cli::wallet::wallet_new()?,
            }
            Ok(())
        }

        Commands::Genesis { out, burn_addr20 } => {
            // Deterministic-ish genesis: mine a block whose prev=0, with coinbase paying to burn address.
            // This genesis is what all nodes must share.
            let s = burn_addr20.strip_prefix("0x").unwrap_or(&burn_addr20);
            let bytes = hex::decode(s)?;
            if bytes.len() != 20 { anyhow::bail!("burn_addr20 must be 20 bytes hex"); }
            let mut burn = [0u8;20];
            burn.copy_from_slice(&bytes);

            let genesis = crate::chain::genesis::make_genesis_block(burn)?;
            std::fs::write(&out, bincode::serialize(&genesis)?)?;
            println!("wrote genesis to {out}");
            let gh = crate::chain::index::header_hash(&genesis.header);
            println!("genesis_hash: 0x{}", hex::encode(gh));
            Ok(())
        }

        Commands::Node { datadir, rpc, mine, miner_addr20, genesis, p2p_listen, bootnodes } => {
            let db = Arc::new(Stores::open(&datadir)?);

            // Load genesis.bin and ensure it’s stored + applied if DB is empty
            let gbytes = std::fs::read(&genesis)?;
            let gblock: crate::types::Block = bincode::deserialize(&gbytes)?;
            crate::chain::genesis::ensure_genesis(db.clone(), gblock.clone())?;
            let genesis_hash = crate::chain::index::header_hash(&gblock.header);

            // start RPC
            let app = crate::api::router(db.clone());
            let listener = tokio::net::TcpListener::bind(&rpc).await?;
            println!("RPC on http://{}", rpc);

            // start P2P swarm
            let listen_ma: libp2p::Multiaddr = p2p_listen.parse()?;
            let boots: Vec<libp2p::Multiaddr> = if bootnodes.trim().is_empty() {
                vec![]
            } else {
                bootnodes.split(',').map(|s| s.trim().parse()).collect::<std::result::Result<Vec<_>,_>>()?
            };

            let net_cfg = crate::net::node::NetConfig {
                listen: listen_ma,
                bootnodes: boots,
                genesis_hash,
                is_bootnode: !mine,
            };

            tokio::spawn(crate::net::node::run_p2p(db.clone(), net_cfg));

            // miner loop if enabled
            if mine {
                let mut addr = [0u8;20];
                let s = miner_addr20.strip_prefix("0x").unwrap_or(&miner_addr20);
                let bytes = hex::decode(s)?;
                if bytes.len() != 20 { anyhow::bail!("miner_addr20 must be 20 bytes hex"); }
                addr.copy_from_slice(&bytes);
                let db2 = db.clone();

                tokio::spawn(async move {
                    loop {
                        let Ok(bh) = crate::chain::mine::mine_one(&db2, addr, vec![]) else {
                            tokio::time::sleep(std::time::Duration::from_millis(200)).await;
                            continue;
                        };

                        // gossip header to peers (P2P task already running; simplest v0 is to rely on peers pulling via sync,
                        // but we can also gossip via HTTP later. For now: P2P gossipsub happens inside the swarm as mined blocks
                        // are stored and can be fetched.
                        println!("[mine] new block {}", format!("0x{}", hex::encode(bh)));
                        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
                    }
                });
            }

            axum::serve(listener, app).await?;
            Ok(())
        }
    }
}
