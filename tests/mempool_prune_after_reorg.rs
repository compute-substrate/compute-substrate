use anyhow::{Context, Result};
use tempfile::TempDir;

use csd::chain::index::{get_hidx, header_hash, index_header};
use csd::chain::reorg::maybe_reorg_to;
use csd::crypto::txid;
use csd::net::mempool::Mempool;
use csd::state::app_state::epoch_of;
use csd::state::db::{k_block, set_tip, Stores};
use csd::state::utxo::validate_and_apply_block;
use csd::types::{AppPayload, Block, Hash20, Hash32, OutPoint, Transaction, TxIn, TxOut};

mod testutil_chain;
use testutil_chain::{
    assert_tip_eq, build_base_chain_with_miner, flush_all_state_trees, make_test_header, open_db,
};

fn h20(n: u8) -> Hash20 {
    [n; 20]
}

fn signer_addr(sk32: [u8; 32]) -> Hash20 {
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

fn load_block(db: &Stores, bh: &Hash32) -> Result<Block> {
    let Some(v) = db.blocks.get(k_block(bh))? else {
        anyhow::bail!("missing block bytes for 0x{}", hex::encode(bh));
    };
    Ok(csd::codec::consensus_bincode().deserialize::<Block>(&v)?)
}

fn make_spend_tx(
    prev: OutPoint,
    prev_value: u64,
    to: Hash20,
    send_value: u64,
    fee: u64,
    sk32: [u8; 32],
    app: AppPayload,
) -> Transaction {
    assert_eq!(prev_value, send_value + fee);

    let mut tx = Transaction {
        version: 1,
        inputs: vec![TxIn {
            prevout: prev,
            script_sig: vec![0u8; 99],
        }],
        outputs: vec![TxOut {
            value: send_value,
            script_pubkey: to,
        }],
        locktime: 0,
        app,
    };

    let (sig64, pub33) = csd::crypto::sign_tx_compact_secp256k1(&tx, sk32);

    let mut ss = Vec::with_capacity(99);
    ss.push(64u8);
    ss.extend_from_slice(&sig64);
    ss.push(33u8);
    ss.extend_from_slice(&pub33);

    tx.inputs[0].script_sig = ss;
    tx
}

fn persist_index_apply_block(db: &Stores, blk: &Block, height: u64) -> Result<Hash32> {
    let bh = header_hash(&blk.header);

    let bytes = csd::codec::consensus_bincode()
        .serialize(blk)
        .context("serialize block")?;
    db.blocks
        .insert(k_block(&bh), bytes)
        .context("db.blocks.insert")?;

    let parent_hi = if blk.header.prev == [0u8; 32] {
        None
    } else {
        get_hidx(db, &blk.header.prev).context("get_hidx(parent)")?
    };

    index_header(db, &blk.header, parent_hi.as_ref()).context("index_header")?;
    validate_and_apply_block(db, blk, epoch_of(height), height)
        .with_context(|| format!("validate_and_apply_block h={height}"))?;
    set_tip(db, &bh).context("set_tip")?;

    Ok(bh)
}

fn persist_index_only_block(db: &Stores, blk: &Block) -> Result<Hash32> {
    let bh = header_hash(&blk.header);

    let bytes = csd::codec::consensus_bincode()
        .serialize(blk)
        .context("serialize block")?;
    db.blocks
        .insert(k_block(&bh), bytes)
        .context("db.blocks.insert")?;

    let parent_hi = if blk.header.prev == [0u8; 32] {
        None
    } else {
        get_hidx(db, &blk.header.prev).context("get_hidx(parent)")?
    };

    index_header(db, &blk.header, parent_hi.as_ref()).context("index_header")?;
    Ok(bh)
}

#[test]
fn mempool_prunes_txs_invalidated_by_reorg() -> Result<()> {
    let tmp = TempDir::new().context("tmp")?;
    let db = open_db(&tmp).context("open db")?;

    let sk = [11u8; 32];
    let owner = signer_addr(sk);

    let miner_a = h20(0xA1);
    let miner_b = h20(0xB2);

    let shared_len = 12u64;
    let fork_parent_height = 6u64;
    let start_time = 1_700_400_000u64;

    let shared = build_base_chain_with_miner(&db, shared_len, start_time, owner)
        .context("build_base_chain_with_miner(shared)")?;
    let shared_tip = shared[fork_parent_height as usize];

    set_tip(&db, &shared_tip)?;
    assert_tip_eq(&db, shared_tip)?;

    // Grab two independent shared UTXOs:
    // - one to be spent inside canonical branch A
    // - one to remain unspent on A, so a mempool tx can be valid before reorg
    let spend_in_a_block_hash = shared[2];
    let mempool_utxo_block_hash = shared[3];

    let spend_in_a_block = load_block(&db, &spend_in_a_block_hash)?;
    let mempool_utxo_block = load_block(&db, &mempool_utxo_block_hash)?;

    let spend_in_a_cb = &spend_in_a_block.txs[0];
    let mempool_utxo_cb = &mempool_utxo_block.txs[0];

    let spend_in_a_op = OutPoint {
        txid: txid(spend_in_a_cb),
        vout: 0,
    };
    let mempool_prev = OutPoint {
        txid: txid(mempool_utxo_cb),
        vout: 0,
    };

    let spend_in_a_value = spend_in_a_cb.outputs[0].value;
    let mempool_prev_value = mempool_utxo_cb.outputs[0].value;

    // -----------------------------
    // Branch A: canonical first
    // -----------------------------
    let height_a1 = fork_parent_height + 1;

    let fee_a = csd::params::MIN_FEE_PROPOSE;
    let tx_a = make_spend_tx(
        spend_in_a_op,
        spend_in_a_value,
        owner,
        spend_in_a_value - fee_a,
        fee_a,
        sk,
        AppPayload::Propose {
            domain: "science".to_string(),
            payload_hash: [0xAA; 32],
            uri: "ipfs://branch-a/proposal".to_string(),
            expires_epoch: epoch_of(height_a1) + 3,
        },
    );

    let mut txs_a = Vec::new();
    txs_a.push(csd::chain::mine::coinbase(
        miner_a,
        csd::params::block_reward(height_a1) + fee_a,
        height_a1,
        None,
    ));
    txs_a.push(tx_a);

    let hdr_a1 = make_test_header(&db, shared_tip, &txs_a, height_a1)?;
    let blk_a1 = Block {
        header: hdr_a1,
        txs: txs_a,
    };
    let tip_a1 = persist_index_apply_block(&db, &blk_a1, height_a1)?;

    let height_a2 = fork_parent_height + 2;
    let txs_a2 = vec![csd::chain::mine::coinbase(
        miner_a,
        csd::params::block_reward(height_a2),
        height_a2,
        None,
    )];
    let hdr_a2 = make_test_header(&db, tip_a1, &txs_a2, height_a2)?;
    let blk_a2 = Block {
        header: hdr_a2,
        txs: txs_a2,
    };
    let tip_a2 = persist_index_apply_block(&db, &blk_a2, height_a2)?;
    assert_tip_eq(&db, tip_a2)?;

    // -----------------------------
    // Mempool tx valid on branch A
    // -----------------------------
    let mp = Mempool::new();

    let mp_fee = 5_000u64;
    let mempool_tx = make_spend_tx(
        mempool_prev,
        mempool_prev_value,
        h20(0x55),
        mempool_prev_value - mp_fee,
        mp_fee,
        sk,
        AppPayload::None,
    );
    let mempool_txid = txid(&mempool_tx);

    assert_eq!(mp.insert_checked(&db, mempool_tx.clone())?, true);
    assert!(mp.contains(&mempool_txid));
    assert_eq!(mp.len(), 1);

    // -----------------------------
    // Branch B: heavier fork that spends the mempool tx's prevout on-chain
    // -----------------------------
    let height_b1 = fork_parent_height + 1;

    let fee_b1 = csd::params::MIN_FEE_PROPOSE;
    let tx_b1 = make_spend_tx(
        mempool_prev,
        mempool_prev_value,
        owner,
        mempool_prev_value - fee_b1,
        fee_b1,
        sk,
        AppPayload::Propose {
            domain: "ai".to_string(),
            payload_hash: [0xBB; 32],
            uri: "ipfs://branch-b/consumes-mempool-prev".to_string(),
            expires_epoch: epoch_of(height_b1) + 4,
        },
    );

    let mut txs_b1 = Vec::new();
    txs_b1.push(csd::chain::mine::coinbase(
        miner_b,
        csd::params::block_reward(height_b1) + fee_b1,
        height_b1,
        None,
    ));
    txs_b1.push(tx_b1);

    let hdr_b1 = make_test_header(&db, shared_tip, &txs_b1, height_b1)?;
    let blk_b1 = Block {
        header: hdr_b1,
        txs: txs_b1,
    };
    let tip_b1 = persist_index_only_block(&db, &blk_b1)?;

    let height_b2 = fork_parent_height + 2;
    let txs_b2 = vec![csd::chain::mine::coinbase(
        miner_b,
        csd::params::block_reward(height_b2),
        height_b2,
        None,
    )];
    let hdr_b2 = make_test_header(&db, tip_b1, &txs_b2, height_b2)?;
    let blk_b2 = Block {
        header: hdr_b2,
        txs: txs_b2,
    };
    let tip_b2 = persist_index_only_block(&db, &blk_b2)?;

    let height_b3 = fork_parent_height + 3;
    let txs_b3 = vec![csd::chain::mine::coinbase(
        miner_b,
        csd::params::block_reward(height_b3),
        height_b3,
        None,
    )];
    let hdr_b3 = make_test_header(&db, tip_b2, &txs_b3, height_b3)?;
    let blk_b3 = Block {
        header: hdr_b3,
        txs: txs_b3,
    };
    let tip_b3 = persist_index_only_block(&db, &blk_b3)?;

    let hi_a = get_hidx(&db, &tip_a2)?.expect("missing hidx A");
    let hi_b = get_hidx(&db, &tip_b3)?.expect("missing hidx B");
    assert!(hi_b.height > hi_a.height, "branch B must beat branch A");

    flush_all_state_trees(&db)?;
    maybe_reorg_to(&db, &tip_b3, None).context("reorg A -> B")?;
    assert_tip_eq(&db, tip_b3)?;

    // After reorg, the prevout for mempool_tx has been consumed on canonical chain.
    // prune() should drop it.
    let removed = mp.prune(&db);
    assert_eq!(removed, 1, "expected exactly one invalidated mempool tx to be pruned");
    assert_eq!(mp.len(), 0);
    assert!(!mp.contains(&mempool_txid));

    Ok(())
}
