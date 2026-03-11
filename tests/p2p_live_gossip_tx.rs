use anyhow::Result;
use std::sync::Arc;
use std::time::Duration;
use tempfile::TempDir;
use tokio::sync::mpsc;

use libp2p::Multiaddr;

use csd::net::mempool::Mempool;
use csd::net::node::{spawn_p2p, NetConfig};
use csd::state::db::{k_utxo, Stores};
use csd::types::{AppPayload, OutPoint, Transaction, TxIn, TxOut};

mod testutil_chain;
use testutil_chain::open_db;

const SK: [u8; 32] = [21u8; 32];

fn h20(n: u8) -> [u8; 20] {
    [n; 20]
}

fn signer_addr(sk32: [u8; 32]) -> [u8; 20] {
    let dummy = Transaction {
        version: 1,
        inputs: vec![TxIn {
            prevout: OutPoint {
                txid: [0u8; 32],
                vout: 0,
            },
            script_sig: vec![],
        }],
        outputs: vec![TxOut {
            value: 1,
            script_pubkey: [0u8; 20],
        }],
        locktime: 0,
        app: AppPayload::None,
    };

    let (_sig64, pub33) = csd::crypto::sign_tx_compact_secp256k1(&dummy, sk32);
    csd::crypto::hash160(&pub33)
}

fn dummy_prev(n: u8) -> OutPoint {
    OutPoint {
        txid: [n; 32],
        vout: 0,
    }
}

fn insert_utxo(db: &Stores, op: OutPoint, value: u64, owner: [u8; 20]) -> Result<()> {
    let out = TxOut {
        value,
        script_pubkey: owner,
    };

    db.utxo.insert(
        k_utxo(&op),
        csd::codec::consensus_bincode().serialize(&out)?,
    )?;

    Ok(())
}

fn make_tx(prev_tag: u8, value: u64, fee: u64, to: [u8; 20]) -> Transaction {
    let send = value - fee;

    let mut tx = Transaction {
        version: 1,
        inputs: vec![TxIn {
            prevout: dummy_prev(prev_tag),
            script_sig: vec![0u8; 99],
        }],
        outputs: vec![TxOut {
            value: send,
            script_pubkey: to,
        }],
        locktime: 0,
        app: AppPayload::None,
    };

    let (sig64, pub33) = csd::crypto::sign_tx_compact_secp256k1(&tx, SK);

    let mut ss = Vec::with_capacity(99);
    ss.push(64);
    ss.extend_from_slice(&sig64);
    ss.push(33);
    ss.extend_from_slice(&pub33);
    tx.inputs[0].script_sig = ss;

    tx
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn live_p2p_gossip_tx_reaches_remote_mempool() -> Result<()> {
    let tmp_a = TempDir::new()?;
    let tmp_b = TempDir::new()?;

    let db_a = Arc::new(open_db(&tmp_a)?);
    let db_b = Arc::new(open_db(&tmp_b)?);

    let mp_a = Arc::new(Mempool::new());
    let mp_b = Arc::new(Mempool::new());

    let owner = signer_addr(SK);
    let v = 1_000_000u64;

    insert_utxo(&db_a, dummy_prev(1), v, owner)?;
    insert_utxo(&db_b, dummy_prev(1), v, owner)?;

    let (_mined_tx_a, mined_rx_a) = mpsc::unbounded_channel();
    let (gossip_tx_a, gossip_rx_a) = mpsc::unbounded_channel();

    let (_mined_tx_b, mined_rx_b) = mpsc::unbounded_channel();
    let (_gossip_tx_b, gossip_rx_b) = mpsc::unbounded_channel();

    let genesis = [0u8; 32];

    // Use a real fixed port for node B so node A can actually dial it.
    let listen_b: Multiaddr = "/ip4/127.0.0.1/tcp/40439".parse()?;

    let cfg_b = NetConfig {
        datadir: tmp_b.path().to_string_lossy().to_string(),
        listen: listen_b.clone(),
        bootnodes: vec![],
        genesis_hash: genesis,
        is_bootnode: true,
    };

    let handle_b = spawn_p2p(
        db_b.clone(),
        mp_b.clone(),
        cfg_b,
        mined_rx_b,
        gossip_rx_b,
        csd::chain::lock::new_chain_lock(),
    )
    .await?;

    tokio::time::sleep(Duration::from_millis(700)).await;

    let addr_b: Multiaddr = format!("{}/p2p/{}", listen_b, handle_b.peer_id).parse()?;

    let cfg_a = NetConfig {
        datadir: tmp_a.path().to_string_lossy().to_string(),
        listen: "/ip4/127.0.0.1/tcp/0".parse::<Multiaddr>()?,
        bootnodes: vec![addr_b],
        genesis_hash: genesis,
        is_bootnode: false,
    };

    let _handle_a = spawn_p2p(
        db_a.clone(),
        mp_a.clone(),
        cfg_a,
        mined_rx_a,
        gossip_rx_a,
        csd::chain::lock::new_chain_lock(),
    )
    .await?;

    tokio::time::sleep(Duration::from_secs(2)).await;

    let tx = make_tx(1, v, 5_000, h20(9));
    gossip_tx_a.send(csd::net::GossipTxEvent { tx: tx.clone() })?;

    tokio::time::sleep(Duration::from_secs(2)).await;

    assert_eq!(mp_b.len(), 1, "remote mempool should receive tx via gossip");

    Ok(())
}
