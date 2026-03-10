use anyhow::{Context, Result};
use tempfile::TempDir;

use csd::chain::reorg::maybe_reorg_to;
use csd::state::app_state::{epoch_of, get_topk};
use csd::state::db::{get_tip, set_tip, Stores};
use csd::state::utxo::validate_and_apply_block;
use csd::types::{AppPayload, Block, Hash20, Hash32, OutPoint, Transaction, TxIn, TxOut};

mod testutil_chain;
use testutil_chain::{build_base_chain_with_miner, make_test_header, open_db};

fn addr_from_sk(sk32: [u8; 32]) -> Hash20 {
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
            value: 0,
            script_pubkey: [0u8; 20],
        }],
        locktime: 0,
        app: AppPayload::None,
    };

    let (_sig64, pub33) = csd::crypto::sign_tx_compact_secp256k1(&dummy, sk32);
    csd::crypto::hash160(&pub33)
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

    // [sig_len u8][sig64][pub_len u8][pub33]
    let mut ss = Vec::with_capacity(99);
    ss.push(64u8);
    ss.extend_from_slice(&sig64);
    ss.push(33u8);
    ss.extend_from_slice(&pub33);

    tx.inputs[0].script_sig = ss;
    tx
}

fn apply_block(db: &Stores, blk: &Block, height: u64) -> Result<Hash32> {
    let bh = csd::chain::index::header_hash(&blk.header);

    // Persist block bytes first
    db.blocks.insert(
        csd::state::db::k_block(&bh),
        csd::codec::consensus_bincode().serialize(blk)?,
    )?;

    // Index header against parent, like normal chain processing
    let parent_hi = if blk.header.prev == [0u8; 32] {
        None
    } else {
        csd::chain::index::get_hidx(db, &blk.header.prev)?
    };

    csd::chain::index::index_header(db, &blk.header, parent_hi.as_ref())
        .with_context(|| format!("index_header h={height}"))?;

    // Apply consensus state transition
    validate_and_apply_block(db, blk, epoch_of(height), height)
        .with_context(|| format!("apply h={height}"))?;

    set_tip(db, &bh)?;
    db.db.flush()?;

    Ok(bh)
}

fn load_block(db: &Stores, bh: &Hash32) -> Result<Block> {
    let Some(v) = db.blocks.get(csd::state::db::k_block(bh))? else {
        anyhow::bail!("missing block bytes for 0x{}", hex::encode(bh));
    };
    Ok(csd::codec::consensus_bincode().deserialize::<Block>(&v)?)
}

#[test]
fn topk_full_stack_reorg_updates_and_rolls_back() -> Result<()> {
    let tmp = TempDir::new().context("tmp")?;
    let db = open_db(&tmp).context("open db")?;

    let sk_a = [7u8; 32];
    let sk_f = [11u8; 32];

    let addr_a = addr_from_sk(sk_a);
    let addr_f = addr_from_sk(sk_f);

    let domain = "science";

    // Must satisfy consensus minimums
    let propose_fee = csd::params::MIN_FEE_PROPOSE;
    let attest_fee_low = csd::params::MIN_FEE_ATTEST;
    let attest_fee_mid = csd::params::MIN_FEE_ATTEST + 10_000_000;
    let attest_fee_high = csd::params::MIN_FEE_ATTEST + 30_000_000;
    let attest_fee_top = csd::params::MIN_FEE_ATTEST + 60_000_000;

    let start_time = 1_700_100_000u64;
    let base = build_base_chain_with_miner(&db, 20, start_time, addr_a)
        .context("build_base_chain_with_miner")?;
    let tip_a = *base.last().unwrap();
    set_tip(&db, &tip_a)?;

    let b1 = load_block(&db, &base[5])?;
    let b2 = load_block(&db, &base[6])?;
    let b3 = load_block(&db, &base[7])?;

    let cb1 = csd::crypto::txid(&b1.txs[0]);
    let cb2 = csd::crypto::txid(&b2.txs[0]);
    let cb3 = csd::crypto::txid(&b3.txs[0]);

    let op1 = OutPoint { txid: cb1, vout: 0 };
    let op2 = OutPoint { txid: cb2, vout: 0 };
    let op3 = OutPoint { txid: cb3, vout: 0 };

    let v1 = b1.txs[0].outputs[0].value;
    let v2 = b2.txs[0].outputs[0].value;
    let v3 = b3.txs[0].outputs[0].value;

    let propose1 = make_spend_tx(
        op1,
        v1,
        addr_a,
        v1 - propose_fee,
        propose_fee,
        sk_a,
        AppPayload::Propose {
            domain: domain.to_string(),
            payload_hash: [1u8; 32],
            uri: "ipfs://p1".to_string(),
            expires_epoch: epoch_of(21) + 5,
        },
    );

    let propose2 = make_spend_tx(
        op2,
        v2,
        addr_a,
        v2 - propose_fee,
        propose_fee,
        sk_a,
        AppPayload::Propose {
            domain: domain.to_string(),
            payload_hash: [2u8; 32],
            uri: "ipfs://p2".to_string(),
            expires_epoch: epoch_of(21) + 5,
        },
    );

    let propose3 = make_spend_tx(
        op3,
        v3,
        addr_a,
        v3 - propose_fee,
        propose_fee,
        sk_a,
        AppPayload::Propose {
            domain: domain.to_string(),
            payload_hash: [3u8; 32],
            uri: "ipfs://p3".to_string(),
            expires_epoch: epoch_of(21) + 5,
        },
    );

    let tip_hi = csd::chain::index::get_hidx(&db, &tip_a)?.expect("tip hidx");
    let height_p = tip_hi.height + 1;

let reward_p = csd::params::block_reward(height_p);
let fees_p = propose_fee * 3;

let txs_p = vec![
    csd::chain::mine::coinbase(addr_a, reward_p + fees_p, height_p, None),
    propose1.clone(),
    propose2.clone(),
    propose3.clone(),
];

    let hdr_p = make_test_header(&db, tip_a, &txs_p, height_p)?;
    let blk_p = Block { header: hdr_p, txs: txs_p };
    let bh_p = apply_block(&db, &blk_p, height_p).context("apply proposals block")?;

    let pid1 = csd::crypto::txid(&propose1);
    let pid2 = csd::crypto::txid(&propose2);
    let pid3 = csd::crypto::txid(&propose3);

    let op_p1 = OutPoint { txid: pid1, vout: 0 };
    let op_p2 = OutPoint { txid: pid2, vout: 0 };
    let op_p3 = OutPoint { txid: pid3, vout: 0 };

    let pv1 = v1 - propose_fee;
    let pv2 = v2 - propose_fee;
    let pv3 = v3 - propose_fee;

    // Chain A: pid2 wins
    let a_att1 = make_spend_tx(
        op_p1,
        pv1,
        addr_a,
        pv1 - attest_fee_mid,
        attest_fee_mid,
        sk_a,
        AppPayload::Attest {
            proposal_id: pid1,
            score: 0,
            confidence: 0,
        },
    );
    let a_att2 = make_spend_tx(
        op_p2,
        pv2,
        addr_a,
        pv2 - attest_fee_top,
        attest_fee_top,
        sk_a,
        AppPayload::Attest {
            proposal_id: pid2,
            score: 0,
            confidence: 0,
        },
    );
    let a_att3 = make_spend_tx(
        op_p3,
        pv3,
        addr_a,
        pv3 - attest_fee_low,
        attest_fee_low,
        sk_a,
        AppPayload::Attest {
            proposal_id: pid3,
            score: 0,
            confidence: 0,
        },
    );

    let tip_hi2 = csd::chain::index::get_hidx(&db, &bh_p)?.expect("hidx p");
    let height_a = tip_hi2.height + 1;

let reward_a = csd::params::block_reward(height_a);
let fees_a = attest_fee_mid + attest_fee_top + attest_fee_low;

let txs_a = vec![
    csd::chain::mine::coinbase(addr_a, reward_a + fees_a, height_a, None),
    a_att1.clone(),
    a_att2.clone(),
    a_att3.clone(),
];

    let hdr_a = make_test_header(&db, bh_p, &txs_a, height_a)?;
    let blk_a = Block { header: hdr_a, txs: txs_a };
    let _bh_a = apply_block(&db, &blk_a, height_a).context("apply attests A")?;

    let ep_a = epoch_of(height_a);
    let topk_a = get_topk(&db, ep_a, domain).context("get_topk A")?;
    assert!(!topk_a.is_empty(), "TopK should not be empty");
    assert_eq!(topk_a[0].0, pid2, "expected pid2 top on chain A");

    // Build heavier fork B off bh_p
    let height_b1 = height_a;
    let txs_b1 = vec![
        csd::chain::mine::coinbase(addr_f, csd::params::block_reward(height_b1), height_b1, None),
    ];
    let hdr_b1 = make_test_header(&db, bh_p, &txs_b1, height_b1)?;
    let blk_b1 = Block { header: hdr_b1, txs: txs_b1 };
    let bh_b1 = csd::chain::index::header_hash(&blk_b1.header);
    db.blocks.insert(
        csd::state::db::k_block(&bh_b1),
        csd::codec::consensus_bincode().serialize(&blk_b1)?,
    )?;
    csd::chain::index::index_header(&db, &blk_b1.header, Some(&tip_hi2))?;

    let hi_b1 = csd::chain::index::get_hidx(&db, &bh_b1)?.expect("hidx b1");
    let height_b2 = hi_b1.height + 1;
    let txs_b2 = vec![
        csd::chain::mine::coinbase(addr_f, csd::params::block_reward(height_b2), height_b2, None),
    ];
    let hdr_b2 = make_test_header(&db, bh_b1, &txs_b2, height_b2)?;
    let blk_b2 = Block { header: hdr_b2, txs: txs_b2 };
    let bh_b2 = csd::chain::index::header_hash(&blk_b2.header);
    db.blocks.insert(
        csd::state::db::k_block(&bh_b2),
        csd::codec::consensus_bincode().serialize(&blk_b2)?,
    )?;
    csd::chain::index::index_header(&db, &blk_b2.header, Some(&hi_b1))?;

    let hi_b2 = csd::chain::index::get_hidx(&db, &bh_b2)?.expect("hidx b2");
    let height_b3 = hi_b2.height + 1;
    let txs_b3 = vec![
        csd::chain::mine::coinbase(addr_f, csd::params::block_reward(height_b3), height_b3, None),
    ];
    let hdr_b3 = make_test_header(&db, bh_b2, &txs_b3, height_b3)?;
    let blk_b3 = Block { header: hdr_b3, txs: txs_b3 };
    let bh_b3 = csd::chain::index::header_hash(&blk_b3.header);
    db.blocks.insert(
        csd::state::db::k_block(&bh_b3),
        csd::codec::consensus_bincode().serialize(&blk_b3)?,
    )?;
    csd::chain::index::index_header(&db, &blk_b3.header, Some(&hi_b2))?;

    let fund1_cb = csd::crypto::txid(&blk_b1.txs[0]);
    let fund2_cb = csd::crypto::txid(&blk_b2.txs[0]);
    let fund3_cb = csd::crypto::txid(&blk_b3.txs[0]);

    let fv1 = blk_b1.txs[0].outputs[0].value;
    let fv2 = blk_b2.txs[0].outputs[0].value;
    let fv3 = blk_b3.txs[0].outputs[0].value;

    // Chain B: pid3 wins
    let b_att1 = make_spend_tx(
        OutPoint { txid: fund1_cb, vout: 0 },
        fv1,
        addr_f,
        fv1 - attest_fee_mid,
        attest_fee_mid,
        sk_f,
        AppPayload::Attest {
            proposal_id: pid1,
            score: 0,
            confidence: 0,
        },
    );
    let b_att2 = make_spend_tx(
        OutPoint { txid: fund2_cb, vout: 0 },
        fv2,
        addr_f,
        fv2 - attest_fee_low,
        attest_fee_low,
        sk_f,
        AppPayload::Attest {
            proposal_id: pid2,
            score: 0,
            confidence: 0,
        },
    );
    let b_att3 = make_spend_tx(
        OutPoint { txid: fund3_cb, vout: 0 },
        fv3,
        addr_f,
        fv3 - attest_fee_top,
        attest_fee_top,
        sk_f,
        AppPayload::Attest {
            proposal_id: pid3,
            score: 0,
            confidence: 0,
        },
    );

    let hi_b3 = csd::chain::index::get_hidx(&db, &bh_b3)?.expect("hidx b3");
    let height_b4 = hi_b3.height + 1;

let reward_b = csd::params::block_reward(height_b4);
let fees_b = attest_fee_mid + attest_fee_low + attest_fee_top;

let txs_b4 = vec![
    csd::chain::mine::coinbase(addr_f, reward_b + fees_b, height_b4, None),
    b_att1,
    b_att2,
    b_att3,
];

    let hdr_b4 = make_test_header(&db, bh_b3, &txs_b4, height_b4)?;
    let blk_b4 = Block { header: hdr_b4, txs: txs_b4 };
    let bh_b4 = csd::chain::index::header_hash(&blk_b4.header);

    db.blocks.insert(
        csd::state::db::k_block(&bh_b4),
        csd::codec::consensus_bincode().serialize(&blk_b4)?,
    )?;
    csd::chain::index::index_header(&db, &blk_b4.header, Some(&hi_b3))?;
    db.db.flush()?;

    maybe_reorg_to(&db, &bh_b4, None).context("maybe_reorg_to fork B")?;

    let tip_after = get_tip(&db)?.unwrap();
    assert_eq!(tip_after, bh_b4, "fork B should become canonical for this test");

    let ep_b = epoch_of(height_b4);
    let topk_b = get_topk(&db, ep_b, domain).context("get_topk B")?;
    assert!(!topk_b.is_empty(), "TopK should not be empty after reorg");
    assert_eq!(topk_b[0].0, pid3, "expected pid3 top on chain B after reorg");

    Ok(())
}
