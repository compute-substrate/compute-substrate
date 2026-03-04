// tests/topk_app_state.rs
use anyhow::Result;
use tempfile::TempDir;

use csd::params::EPOCH_LEN;
use csd::state::app_state::{apply_app_tx, epoch_of, get_topk, rollback_app_undo};
use csd::state::db::Stores;
use csd::types::{AppPayload, OutPoint, Transaction, TxIn, TxOut};

type H32 = [u8; 32];
type H20 = [u8; 20];

fn h32(b: u8) -> H32 {
    [b; 32]
}

/// scriptsig format expected by sender_h160_from_tx:
/// [sig_len u8=64][sig64][pub_len u8=33][pub33]
fn scriptsig_with_pub33(pub0: u8) -> Vec<u8> {
    let mut v = Vec::with_capacity(99);
    v.push(64u8);
    v.extend_from_slice(&[0u8; 64]); // dummy sig
    v.push(33u8);
    let mut pub33 = [0u8; 33];
    pub33[0] = 0x02; // compressed pubkey prefix (not validated here)
    pub33[1] = pub0; // make it unique-ish per tx
    v.extend_from_slice(&pub33);
    debug_assert_eq!(v.len(), 99);
    v
}

fn dummy_tx(app: AppPayload, pub0: u8) -> Transaction {
    Transaction {
        version: 1,
        inputs: vec![TxIn {
            prevout: OutPoint {
                txid: [9u8; 32],
                vout: 0,
            },
            script_sig: scriptsig_with_pub33(pub0),
        }],
        outputs: vec![TxOut {
            value: 0,
            script_pubkey: [0u8; 20],
        }],
        locktime: 0,
        app,
    }
}

fn open_tmp_db() -> Result<(TempDir, Stores)> {
    let tmp = TempDir::new()?;
    let db = Stores::open(tmp.path().to_str().unwrap())?;
    Ok((tmp, db))
}

#[test]
fn topk_tie_break_is_lexicographic_proposal_id() -> Result<()> {
    let (_tmp, db) = open_tmp_db()?;

    let height = 5u64;
    let epoch = epoch_of(height);
    let domain = "finance";

    // Two proposals, ids chosen so p1 < p2 lexicographically.
    let p1 = h32(0x10);
    let p2 = h32(0x20);

    // Propose both (fee values don't matter for score; scores are attest-weight).
    let tx_p1 = dummy_tx(
        AppPayload::Propose {
            domain: domain.to_string(),
            payload_hash: h32(0xAA),
            uri: "ipfs://p1".to_string(),
            expires_epoch: epoch + 10,
        },
        1,
    );
    let tx_p2 = dummy_tx(
        AppPayload::Propose {
            domain: domain.to_string(),
            payload_hash: h32(0xBB),
            uri: "ipfs://p2".to_string(),
            expires_epoch: epoch + 10,
        },
        2,
    );

    let _u1 = apply_app_tx(&db, &tx_p1, height, &p1, 1)?;
    let _u2 = apply_app_tx(&db, &tx_p2, height, &p2, 1)?;

    // Attest to each with equal fee => equal score => tie-break by proposal_id asc.
    let fee = 100u64;

    let tx_a1 = dummy_tx(
        AppPayload::Attest {
            proposal_id: p1,
            score: 0,
            confidence: 0,
        },
        3,
    );
    let tx_a2 = dummy_tx(
        AppPayload::Attest {
            proposal_id: p2,
            score: 0,
            confidence: 0,
        },
        4,
    );

    let _ua1 = apply_app_tx(&db, &tx_a1, height + 1, &h32(0xA1), fee)?;
    let _ua2 = apply_app_tx(&db, &tx_a2, height + 2, &h32(0xA2), fee)?;

    let top = get_topk(&db, epoch, domain)?;
    assert!(top.len() >= 2);

    assert_eq!(top[0].0, p1, "tie-break should pick smaller proposal_id first");
    assert_eq!(top[0].1, fee as u128);
    assert_eq!(top[1].0, p2);
    assert_eq!(top[1].1, fee as u128);

    Ok(())
}

#[test]
fn topk_rolls_back_via_app_undo() -> Result<()> {
    let (_tmp, db) = open_tmp_db()?;

    let height = 10u64;
    let epoch = epoch_of(height);
    let domain = "science";

    let p1 = h32(0x11);
    let p2 = h32(0x22);

    // Propose two candidates.
    let tx_p1 = dummy_tx(
        AppPayload::Propose {
            domain: domain.to_string(),
            payload_hash: h32(0x01),
            uri: "ipfs://p1".to_string(),
            expires_epoch: epoch + 10,
        },
        10,
    );
    let tx_p2 = dummy_tx(
        AppPayload::Propose {
            domain: domain.to_string(),
            payload_hash: h32(0x02),
            uri: "ipfs://p2".to_string(),
            expires_epoch: epoch + 10,
        },
        11,
    );
    let _ = apply_app_tx(&db, &tx_p1, height, &p1, 1)?;
    let _ = apply_app_tx(&db, &tx_p2, height, &p2, 1)?;

    // Make p2 win first.
    let tx_a2 = dummy_tx(
        AppPayload::Attest {
            proposal_id: p2,
            score: 0,
            confidence: 0,
        },
        12,
    );
    let u_win_p2 = apply_app_tx(&db, &tx_a2, height + 1, &h32(0xB2), 200)?;

    let top = get_topk(&db, epoch, domain)?;
    assert_eq!(top[0].0, p2);

    // Then apply an attest that makes p1 win.
    let tx_a1 = dummy_tx(
        AppPayload::Attest {
            proposal_id: p1,
            score: 0,
            confidence: 0,
        },
        13,
    );
    let u_make_p1_win = apply_app_tx(&db, &tx_a1, height + 2, &h32(0xB1), 500)?;

    let top2 = get_topk(&db, epoch, domain)?;
    assert_eq!(top2[0].0, p1);

    // Now simulate a reorg rollback: undo the last attest, p2 should be back on top.
    rollback_app_undo(&db, &u_make_p1_win)?;
    let top3 = get_topk(&db, epoch, domain)?;
    assert_eq!(top3[0].0, p2, "after rollback, winner should revert");

    // Roll back the earlier attest too: now both should be score=0, tie-break => p1 first.
    rollback_app_undo(&db, &u_win_p2)?;
    let top4 = get_topk(&db, epoch, domain)?;
    assert_eq!(top4[0].0, p1, "with both scores zero, tie-break picks p1");

    Ok(())
}

#[test]
fn epoch_boundary_is_respected() -> Result<()> {
    let (_tmp, db) = open_tmp_db()?;

    let domain = "ai";

    // Put proposal at last height of epoch 0.
    let h0 = EPOCH_LEN - 1;
    let e0 = epoch_of(h0);
    assert_eq!(e0, 0);

    let p = h32(0x33);
    let tx_p = dummy_tx(
        AppPayload::Propose {
            domain: domain.to_string(),
            payload_hash: h32(0x03),
            uri: "ipfs://p".to_string(),
            expires_epoch: 10,
        },
        21,
    );
    let _ = apply_app_tx(&db, &tx_p, h0, &p, 1)?;

    // Attest one height later => epoch 1, should NOT affect TopK(epoch0).
    let h1 = EPOCH_LEN;
    let e1 = epoch_of(h1);
    assert_eq!(e1, 1);

    let tx_a = dummy_tx(
        AppPayload::Attest {
            proposal_id: p,
            score: 0,
            confidence: 0,
        },
        22,
    );
    let _ = apply_app_tx(&db, &tx_a, h1, &h32(0x44), 999)?;

    let top_e0 = get_topk(&db, e0, domain)?;
    // Proposal exists in epoch0 scores with 0 (created on Propose), so TopK should list it but with 0 weight.
    assert!(!top_e0.is_empty());
    assert_eq!(top_e0[0].0, p);
    assert_eq!(top_e0[0].1, 0u128, "epoch0 TopK must not include epoch1 attest weight");

    let top_e1 = get_topk(&db, e1, domain)?;
    assert!(!top_e1.is_empty());
    assert_eq!(top_e1[0].0, p);
    assert_eq!(top_e1[0].1, 999u128, "epoch1 TopK should include the attest weight");

    Ok(())
}

#[test]
fn topk_is_deterministic_across_two_dbs() -> Result<()> {
    let (_t1, db1) = open_tmp_db()?;
    let (_t2, db2) = open_tmp_db()?;

    let height = 7u64;
    let epoch = epoch_of(height);
    let domain = "finance";

    let p1 = h32(0x55);
    let p2 = h32(0x66);

    let tx_p1 = dummy_tx(
        AppPayload::Propose {
            domain: domain.to_string(),
            payload_hash: h32(0x10),
            uri: "ipfs://x".to_string(),
            expires_epoch: epoch + 10,
        },
        31,
    );
    let tx_p2 = dummy_tx(
        AppPayload::Propose {
            domain: domain.to_string(),
            payload_hash: h32(0x11),
            uri: "ipfs://y".to_string(),
            expires_epoch: epoch + 10,
        },
        32,
    );

    // Apply same sequence to both DBs.
    let _ = apply_app_tx(&db1, &tx_p1, height, &p1, 1)?;
    let _ = apply_app_tx(&db1, &tx_p2, height, &p2, 1)?;
    let _ = apply_app_tx(&db2, &tx_p1, height, &p1, 1)?;
    let _ = apply_app_tx(&db2, &tx_p2, height, &p2, 1)?;

    let tx_a1 = dummy_tx(
        AppPayload::Attest {
            proposal_id: p1,
            score: 1,
            confidence: 100,
        },
        33,
    );
    let tx_a2 = dummy_tx(
        AppPayload::Attest {
            proposal_id: p2,
            score: 1,
            confidence: 100,
        },
        34,
    );

    let _ = apply_app_tx(&db1, &tx_a1, height + 1, &h32(0xA1), 10)?;
    let _ = apply_app_tx(&db1, &tx_a2, height + 2, &h32(0xA2), 20)?;
    let _ = apply_app_tx(&db2, &tx_a1, height + 1, &h32(0xA1), 10)?;
    let _ = apply_app_tx(&db2, &tx_a2, height + 2, &h32(0xA2), 20)?;

    let top1 = get_topk(&db1, epoch, domain)?;
    let top2 = get_topk(&db2, epoch, domain)?;
    assert_eq!(top1, top2, "TopK must be deterministic across identical history");

    Ok(())
}
