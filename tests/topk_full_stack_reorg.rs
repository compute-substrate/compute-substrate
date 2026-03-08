use anyhow::{Context, Result};
use tempfile::TempDir;

use csd::chain::reorg::maybe_reorg_to;
use csd::state::app_state::{epoch_of, get_topk};
use csd::state::db::{get_tip, set_tip, Stores};
use csd::state::utxo::validate_and_apply_block;
use csd::types::{AppPayload, Block, Hash20, Hash32, OutPoint, Transaction, TxIn, TxOut};

mod testutil_chain;
use testutil_chain::{build_base_chain, build_fork_index_only, open_db};

fn h20(n: u8) -> Hash20 {
    [n; 20]
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
    // One-input, one-output spend.
    // fee = prev_value - send_value
    assert_eq!(prev_value, send_value + fee);

    let mut tx = Transaction {
        version: 1,
        inputs: vec![TxIn {
            prevout: prev,
            script_sig: vec![0u8; 99], // filled after signing
        }],
        outputs: vec![TxOut {
            value: send_value,
            script_pubkey: to,
        }],
        locktime: 0,
        app,
    };

    let (sig64, pub33) = csd::crypto::sign_tx_compact_secp256k1(&tx, sk32);

    // scriptsig format: [sig_len u8][sig64][pub_len u8][pub33]
    let mut ss = Vec::with_capacity(99);
    ss.push(64u8);
    ss.extend_from_slice(&sig64);
    ss.push(33u8);
    ss.extend_from_slice(&pub33);

    tx.inputs[0].script_sig = ss;
    tx
}

fn apply_block(db: &Stores, blk: &Block, height: u64) -> Result<Hash32> {
    // Validate/apply and set tip exactly like consensus.
    validate_and_apply_block(db, blk, epoch_of(height), height)
        .with_context(|| format!("apply h={height}"))?;

    let bh = csd::chain::index::header_hash(&blk.header);
    set_tip(db, &bh)?;
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
    // This is a “real path” test:
    // - spends coinbase UTXOs
    // - pays fees that become attestation weight
    // - validate_and_apply_block updates app + utxo
    // - a reorg switches which attestations are canonical
    // - TopK must follow the canonical chain only

    let tmp = TempDir::new().context("tmp")?;
    let db = open_db(&tmp).context("open db")?;

    // Build a small base chain so we have spendable coinbase UTXOs.
    // testutil_chain::build_base_chain should create blocks + index headers + apply them.
    // If it only indexes, swap it for your “apply” builder.
    let start_time = 1_700_100_000u64;
    let base = build_base_chain(&db, 20, start_time).context("build_base_chain")?;
    let tip_a = *base.last().unwrap();
    set_tip(&db, &tip_a)?;

    // We’re going to spend 3 different coinbase outputs (from earlier blocks)
    // to create 3 proposals, and then attest with different fee weights.

    // --- pick three coinbase txids from early blocks ---
    // We’ll load block bodies and use tx0 (coinbase) outpoint as input.
    let b1 = load_block(&db, &base[5])?;
    let b2 = load_block(&db, &base[6])?;
    let b3 = load_block(&db, &base[7])?;

    let cb1 = csd::crypto::txid(&b1.txs[0]);
    let cb2 = csd::crypto::txid(&b2.txs[0]);
    let cb3 = csd::crypto::txid(&b3.txs[0]);

    let op1 = OutPoint { txid: cb1, vout: 0 };
    let op2 = OutPoint { txid: cb2, vout: 0 };
    let op3 = OutPoint { txid: cb3, vout: 0 };

    // coinbase value at those heights:
    let v1 = b1.txs[0].outputs[0].value;
    let v2 = b2.txs[0].outputs[0].value;
    let v3 = b3.txs[0].outputs[0].value;

    // Deterministic key (matches hash160(pub33) used by utxo validation)
    // NOTE: if you already have a wallet/test key helper, use it. This is just a fixed sk.
    let sk_a = [7u8; 32];
    let sk_b = [9u8; 32];

    let addr_a = h20(0xA1);
    let domain = "science";

    // Build 3 proposal txs in a single new block:
    // fees are small but nonzero; proposer output goes back to addr_a.
    let propose1 = make_spend_tx(
        op1, v1, addr_a,
        v1 - 10_000, 10_000,
        sk_a,
        AppPayload::Propose {
            domain: domain.to_string(),
            payload_hash: [1u8; 32],
            uri: "ipfs://p1".to_string(),
            expires_epoch: epoch_of(21) + 5,
        },
    );

    let propose2 = make_spend_tx(
        op2, v2, addr_a,
        v2 - 10_000, 10_000,
        sk_a,
        AppPayload::Propose {
            domain: domain.to_string(),
            payload_hash: [2u8; 32],
            uri: "ipfs://p2".to_string(),
            expires_epoch: epoch_of(21) + 5,
        },
    );

    let propose3 = make_spend_tx(
        op3, v3, addr_a,
        v3 - 10_000, 10_000,
        sk_a,
        AppPayload::Propose {
            domain: domain.to_string(),
            payload_hash: [3u8; 32],
            uri: "ipfs://p3".to_string(),
            expires_epoch: epoch_of(21) + 5,
        },
    );

    // Now we need a block that includes these txs (plus coinbase).
    // We’ll reuse your stored block builder from testutil_chain by creating a fork “index-only”
    // and then applying blocks by hash. But easiest: just create a manual block body and apply it.
    //
    // To keep this test independent from mining, we’ll load the tip block header and make a new header.
    // NOTE: this assumes you have a helper in testutil_chain for constructing a valid header for tests.
    // If you already have one, use it. Otherwise, you can copy your test header builder from other tests.

    let tip_hi = csd::chain::index::get_hidx(&db, &tip_a)?.expect("tip hidx");
    let height_p = tip_hi.height + 1;

    let mut txs_p = vec![
        // coinbase will be validated to be height.to_le_bytes() etc.
        csd::chain::mine::coinbase(addr_a, csd::params::block_reward(height_p), height_p, None),
        propose1.clone(),
        propose2.clone(),
        propose3.clone(),
    ];

    let hdr_p = testutil_chain::make_test_header(&db, tip_a, &txs_p, height_p)?;
    let blk_p = Block { header: hdr_p, txs: txs_p };

    let bh_p = apply_block(&db, &blk_p, height_p).context("apply proposals block")?;

    // Proposal IDs (txids) used by attestations
    let pid1 = csd::crypto::txid(&propose1);
    let pid2 = csd::crypto::txid(&propose2);
    let pid3 = csd::crypto::txid(&propose3);

    // Now create attestations with fee weights:
    // - chain A will favor pid2 (highest fee)
    // - chain B (fork) will favor pid3 (highest fee)
    //
    // We need spendable UTXOs to fund these attests; we’ll spend the proposer outputs we just made.
    // Those outputs are at (txid(proposeX), vout=0) and have value (vX - 10_000).

    let op_p1 = OutPoint { txid: pid1, vout: 0 };
    let op_p2 = OutPoint { txid: pid2, vout: 0 };
    let op_p3 = OutPoint { txid: pid3, vout: 0 };

    let pv1 = (v1 - 10_000);
    let pv2 = (v2 - 10_000);
    let pv3 = (v3 - 10_000);

    // Chain A attests: pid2 weight 50k, pid1 weight 30k, pid3 weight 10k
    let a_att1 = make_spend_tx(
        op_p1, pv1, addr_a,
        pv1 - 30_000, 30_000,
        sk_a,
        AppPayload::Attest { proposal_id: pid1, score: 0, confidence: 0 },
    );
    let a_att2 = make_spend_tx(
        op_p2, pv2, addr_a,
        pv2 - 50_000, 50_000,
        sk_a,
        AppPayload::Attest { proposal_id: pid2, score: 0, confidence: 0 },
    );
    let a_att3 = make_spend_tx(
        op_p3, pv3, addr_a,
        pv3 - 10_000, 10_000,
        sk_a,
        AppPayload::Attest { proposal_id: pid3, score: 0, confidence: 0 },
    );

    let tip_hi2 = csd::chain::index::get_hidx(&db, &bh_p)?.expect("hidx p");
    let height_a = tip_hi2.height + 1;

    let mut txs_a = vec![
        csd::chain::mine::coinbase(addr_a, csd::params::block_reward(height_a), height_a, None),
        a_att1.clone(),
        a_att2.clone(),
        a_att3.clone(),
    ];
    let hdr_a = testutil_chain::make_test_header(&db, bh_p, &txs_a, height_a)?;
    let blk_a = Block { header: hdr_a, txs: txs_a };
    let bh_a = apply_block(&db, &blk_a, height_a).context("apply attests A")?;

    // Assert TopK on canonical chain A
    let ep = epoch_of(height_a);
    let topk_a = get_topk(&db, ep, domain).context("get_topk A")?;
    assert!(!topk_a.is_empty(), "TopK should not be empty");
    assert_eq!(topk_a[0].0, pid2, "expected pid2 top on chain A");

    // ---- Now build a competing fork B off bh_p with different attestation weights ----
    //
    // We’ll create a fork chain in headers+blocks and then call maybe_reorg_to().
    // Easiest path: use build_fork_index_only to extend from base chain, but here we just need
    // to create an alternative block at height_a that spends DIFFERENT UTXOs.
    //
    // For that, we must fund fork-B attests from *different* UTXOs than chain A used.
    // We’ll use a different proposer key/address and spend the same proposal outputs is NOT possible
    // because those were spent in chain A. So instead: create fork-B attests that spend the *coinbase*
    // of the proposals block (blk_p) by sending to addr_b first in fork-B, then attesting.
    //
    // Simpler: create fork-B as: at height_a, include NO spends of proposal outputs; instead attest
    // using new funds coming from different UTXOs by re-spending different coinbases from earlier blocks.
    //
    // We already used cb1/cb2/cb3. Pick later coinbases for fork-B.

    let sk_f = [11u8; 32];
    let addr_f = h20(0xB2);

    let b4 = load_block(&db, &base[8])?;
    let b5 = load_block(&db, &base[9])?;
    let b6 = load_block(&db, &base[10])?;

    let cb4 = csd::crypto::txid(&b4.txs[0]);
    let cb5 = csd::crypto::txid(&b5.txs[0]);
    let cb6 = csd::crypto::txid(&b6.txs[0]);

    let op4 = OutPoint { txid: cb4, vout: 0 };
    let op5 = OutPoint { txid: cb5, vout: 0 };
    let op6 = OutPoint { txid: cb6, vout: 0 };

    let v4 = b4.txs[0].outputs[0].value;
    let v5 = b5.txs[0].outputs[0].value;
    let v6 = b6.txs[0].outputs[0].value;

    // Fork B attests: pid3 weight 70k, pid1 weight 20k, pid2 weight 10k
    let b_att1 = make_spend_tx(
        op4, v4, addr_f,
        v4 - 20_000, 20_000,
        sk_f,
        AppPayload::Attest { proposal_id: pid1, score: 0, confidence: 0 },
    );
    let b_att2 = make_spend_tx(
        op5, v5, addr_f,
        v5 - 10_000, 10_000,
        sk_f,
        AppPayload::Attest { proposal_id: pid2, score: 0, confidence: 0 },
    );
    let b_att3 = make_spend_tx(
        op6, v6, addr_f,
        v6 - 70_000, 70_000,
        sk_f,
        AppPayload::Attest { proposal_id: pid3, score: 0, confidence: 0 },
    );

    // Create fork-B block at same height_a but different body, parent=bh_p
    let mut txs_b = vec![
        csd::chain::mine::coinbase(addr_f, csd::params::block_reward(height_a), height_a, None),
        b_att1, b_att2, b_att3,
    ];
    let hdr_b = testutil_chain::make_test_header(&db, bh_p, &txs_b, height_a)?;
    let blk_b = Block { header: hdr_b, txs: txs_b };
    let bh_b = csd::chain::index::header_hash(&blk_b.header);

    // Persist fork-B block bytes + index header so maybe_reorg_to can choose it.
    db.blocks.insert(csd::state::db::k_block(&bh_b), csd::codec::consensus_bincode().serialize(&blk_b)?)?;
    csd::chain::index::index_header(&db, &blk_b.header, Some(&tip_hi2))?;
    db.db.flush()?;

    // Now force reorg choice to bh_b (if your maybe_reorg_to requires higher chainwork,
    // you can also add 1-2 extra blocks on top of B to make it heavier).
    maybe_reorg_to(&db, &bh_b, None).context("maybe_reorg_to fork B")?;

    let tip_after = get_tip(&db)?.unwrap();
    assert_eq!(tip_after, bh_b, "fork B should become canonical for this test");

    // TopK must now reflect fork B: pid3 should be top
    let topk_b = get_topk(&db, ep, domain).context("get_topk B")?;
    assert!(!topk_b.is_empty(), "TopK should not be empty after reorg");
    assert_eq!(topk_b[0].0, pid3, "expected pid3 top on chain B after reorg");

    Ok(())
}
