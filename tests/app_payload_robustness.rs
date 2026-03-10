use anyhow::{Context, Result};
use rand::{rngs::StdRng, Rng, SeedableRng};
use std::collections::HashMap;
use tempfile::TempDir;

use csd::chain::index::{get_hidx, index_header};
use csd::chain::pow::expected_bits;
use csd::state::app_state::{epoch_of, get_topk};
use csd::state::db::{k_block, set_tip, Stores};
use csd::state::utxo::{undo_block, validate_and_apply_block};
use csd::types::{AppPayload, Block, BlockHeader, Hash20, Hash32, OutPoint, Transaction, TxIn, TxOut};

mod testutil_chain;
use testutil_chain::{make_test_header, open_db};

fn h20(n: u8) -> Hash20 {
    [n; 20]
}

fn signer_addr(sk32: [u8; 32]) -> Hash20 {
    // Dummy tx just to get the compressed pubkey from your exact signer helper.
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

fn apply_block(db: &Stores, blk: &Block, height: u64) -> Result<Hash32> {
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

fn build_owned_base_chain(
    db: &Stores,
    n: u64,
    start_time: u64,
    miner_addr: Hash20,
) -> Result<Vec<Hash32>> {
    let mut out = Vec::with_capacity(n as usize);
    let mut prev = [0u8; 32];

    for height in 0..n {
        let txs = vec![csd::chain::mine::coinbase(
            miner_addr,
            csd::params::block_reward(height),
            height,
            None,
        )];

        let parent_hi = if prev == [0u8; 32] {
            None
        } else {
            get_hidx(db, &prev).context("get_hidx(parent)")?
        };

        let bits = expected_bits(db, height, parent_hi.as_ref()).context("expected_bits")?;

        let hdr = BlockHeader {
            version: 1,
            prev,
            merkle: testutil_chain::merkle_root(&txs),
            time: start_time + height * 60,
            bits,
            nonce: 0, // test-bypass mode
        };

        let blk = Block { header: hdr, txs };
        let bh = csd::chain::index::header_hash(&blk.header);

        let bytes = csd::codec::consensus_bincode()
            .serialize(&blk)
            .context("serialize block")?;
        db.blocks
            .insert(k_block(&bh), bytes)
            .context("db.blocks.insert")?;

        index_header(db, &blk.header, parent_hi.as_ref()).context("index_header")?;
        validate_and_apply_block(db, &blk, epoch_of(height), height)
            .with_context(|| format!("apply h={height}"))?;
        set_tip(db, &bh).context("set_tip")?;

        out.push(bh);
        prev = bh;
    }

    Ok(out)
}

/// Spend a single UTXO into one output, paying `fee`.
/// script_sig is filled with a real compact signature + pubkey.
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

fn topk_ref(mut scores: Vec<(Hash32, u128)>, k: usize) -> Vec<(Hash32, u128)> {
    // score desc; proposal_id asc
    scores.sort_by(|(a_id, a_s), (b_id, b_s)| b_s.cmp(a_s).then_with(|| a_id.cmp(b_id)));
    scores.truncate(k);
    scores
}

#[test]
fn spam_many_propose_and_attest_matches_reference_model() -> Result<()> {
    let mut rng = StdRng::seed_from_u64(42);

    let tmp = TempDir::new().context("tmp")?;
    let db = open_db(&tmp).context("open db")?;

    let sk = [7u8; 32];
    let signer = signer_addr(sk);

    // Build enough coinbases to fund a bunch of txs, but pay them to the signer.
    let start_time = 1_700_100_000u64;
    let base = build_owned_base_chain(&db, 80, start_time, signer).context("build_owned_base_chain")?;
    let tip0 = *base.last().unwrap();
    set_tip(&db, &tip0)?;

    // Funding UTXOs = signer-owned coinbases
    let mut fund_utxos: Vec<(OutPoint, u64)> = Vec::new();
    for bh in base.iter().take(60).skip(2) {
        let b = load_block(&db, bh)?;
        let cb = &b.txs[0];
        let cbid = csd::crypto::txid(cb);
        let v = cb.outputs[0].value;
        fund_utxos.push((OutPoint { txid: cbid, vout: 0 }, v));
    }

    let domains = ["science", "finance", "ai", "weather", "sports"];
    let addr_miner = h20(0xA1);

    // Send change back to signer so future spends remain valid
    let addr_user = signer;

    let mut proposals_by_domain: HashMap<String, Vec<Hash32>> = HashMap::new();
    let mut ref_scores: HashMap<(u64, String), HashMap<Hash32, u128>> = HashMap::new();

    let blocks_to_make = 40usize;
    let mut cur_tip = tip0;
    let mut fund_i = 0usize;

    for _ in 0..blocks_to_make {
        let parent_hi = get_hidx(&db, &cur_tip)?.expect("missing parent hidx");
        let height = parent_hi.height + 1;
        let epoch = epoch_of(height);

        let mut txs: Vec<Transaction> = Vec::new();

        txs.push(csd::chain::mine::coinbase(
            addr_miner,
            csd::params::block_reward(height),
            height,
            None,
        ));

        let n_prop = rng.gen_range(0..=4);
        let n_att = rng.gen_range(0..=8);

        for _ in 0..n_prop {
            if fund_i >= fund_utxos.len() {
                break;
            }
            let (op, v) = fund_utxos[fund_i];
            fund_i += 1;

            let d = domains[rng.gen_range(0..domains.len())].to_string();
            let payload_hash: Hash32 = rng.gen();

            let expires_epoch = epoch + rng.gen_range(0..=5);

            let fee = csd::params::MIN_FEE_PROPOSE;
            let send = v.saturating_sub(fee);

            let tx = make_spend_tx(
                op,
                v,
                addr_user,
                send,
                fee,
                sk,
                AppPayload::Propose {
                    domain: d.clone(),
                    payload_hash,
                    uri: format!("ipfs://{}", hex::encode(payload_hash)),
                    expires_epoch,
                },
            );

            let pid = csd::crypto::txid(&tx);
            proposals_by_domain.entry(d.clone()).or_default().push(pid);

            ref_scores
                .entry((epoch, d.clone()))
                .or_default()
                .entry(pid)
                .or_insert(0);

            txs.push(tx);
        }

        for _ in 0..n_att {
            if fund_i >= fund_utxos.len() {
                break;
            }

            let eligible: Vec<String> = proposals_by_domain
                .iter()
                .filter(|(_, v)| !v.is_empty())
                .map(|(k, _)| k.clone())
                .collect();

            if eligible.is_empty() {
                break;
            }

            let d = eligible[rng.gen_range(0..eligible.len())].clone();
            let props = proposals_by_domain.get(&d).unwrap();
            let proposal_id = props[rng.gen_range(0..props.len())];

            let (op, v) = fund_utxos[fund_i];
            fund_i += 1;

            let fee = csd::params::MIN_FEE_ATTEST + (rng.gen_range(0..=5) as u64) * 100;
            let send = v.saturating_sub(fee);

            let tx = make_spend_tx(
                op,
                v,
                addr_user,
                send,
                fee,
                sk,
                AppPayload::Attest {
                    proposal_id,
                    score: rng.gen(),
                    confidence: rng.gen(),
                },
            );

            let m = ref_scores.entry((epoch, d.clone())).or_default();
            *m.entry(proposal_id).or_insert(0) += fee as u128;

            txs.push(tx);
        }

        let hdr = make_test_header(&db, cur_tip, &txs, height)?;
        let blk = Block { header: hdr, txs };

        let bh = apply_block(&db, &blk, height)?;
        cur_tip = bh;

        let d = domains[rng.gen_range(0..domains.len())].to_string();
        let key = (epoch, d.clone());
        let ref_map = ref_scores.get(&key).cloned().unwrap_or_default();

        let ref_vec: Vec<(Hash32, u128)> = ref_map.into_iter().collect();
        let ref_top = topk_ref(ref_vec, csd::params::TOP_K);

        let got = get_topk(&db, epoch, &d)?;
        if got != ref_top {
            anyhow::bail!(
                "TopK mismatch at epoch={} domain={}\n got={:?}\n ref={:?}",
                epoch,
                d,
                got,
                ref_top
            );
        }
    }

    Ok(())
}

#[test]
fn propose_and_attest_edge_cases_reject_correctly() -> Result<()> {
    let tmp = TempDir::new().context("tmp")?;
    let db = open_db(&tmp).context("open db")?;

    let sk = [7u8; 32];
    let signer = signer_addr(sk);

    let start_time = 1_700_100_000u64;
    let base = build_owned_base_chain(&db, 12, start_time, signer).context("build_owned_base_chain")?;
    let tip0 = *base.last().unwrap();
    set_tip(&db, &tip0)?;

    let b = load_block(&db, &base[5])?;
    let cb = &b.txs[0];
    let cbid = csd::crypto::txid(cb);
    let v = cb.outputs[0].value;
    let op = OutPoint { txid: cbid, vout: 0 };

    let addr_miner = h20(0xA1);
    let addr_user = signer;

    let parent_hi = get_hidx(&db, &tip0)?.expect("missing parent hidx");
    let height = parent_hi.height + 1;
    let epoch = epoch_of(height);

    // 1) PROPOSE with expires_epoch < current epoch must reject
    {
        let bad = make_spend_tx(
            op,
            v,
            addr_user,
            v - csd::params::MIN_FEE_PROPOSE,
            csd::params::MIN_FEE_PROPOSE,
            sk,
            AppPayload::Propose {
                domain: "science".to_string(),
                payload_hash: [9u8; 32],
                uri: "ipfs://x".to_string(),
                expires_epoch: epoch.saturating_sub(1),
            },
        );

        let fee = csd::params::MIN_FEE_PROPOSE;
        let txs = vec![
            csd::chain::mine::coinbase(
                addr_miner,
                csd::params::block_reward(height) + fee,
                height,
                None,
            ),
            bad,
        ];
        let hdr = make_test_header(&db, tip0, &txs, height)?;
        let blk = Block { header: hdr, txs };

        let err = validate_and_apply_block(&db, &blk, epoch, height).unwrap_err();
        let msg = format!("{err:?}");
        assert!(
            msg.contains("expires_epoch") && msg.contains("current epoch"),
            "unexpected error: {msg}"
        );
    }

    // 2) ATTEST referencing unknown proposal must reject
    {
        let b2 = load_block(&db, &base[6])?;
        let cb2 = &b2.txs[0];
        let op2 = OutPoint {
            txid: csd::crypto::txid(cb2),
            vout: 0,
        };
        let v2 = cb2.outputs[0].value;

        let unknown_pid: Hash32 = [1u8; 32];

        let att = make_spend_tx(
            op2,
            v2,
            addr_user,
            v2 - csd::params::MIN_FEE_ATTEST,
            csd::params::MIN_FEE_ATTEST,
            sk,
            AppPayload::Attest {
                proposal_id: unknown_pid,
                score: 0,
                confidence: 0,
            },
        );

        let h2 = height + 1;
        let ep2 = epoch_of(h2);
        let fee2 = csd::params::MIN_FEE_ATTEST;

        let txs = vec![
            csd::chain::mine::coinbase(
                addr_miner,
                csd::params::block_reward(h2) + fee2,
                h2,
                None,
            ),
            att,
        ];
        let hdr = make_test_header(&db, tip0, &txs, h2)?;
        let blk = Block { header: hdr, txs };

        let err = validate_and_apply_block(&db, &blk, ep2, h2).unwrap_err();
        let msg = format!("{err:?}");
        assert!(
            msg.contains("unknown proposal"),
            "unexpected error: {msg}"
        );
    }

    Ok(())
}

#[test]
fn app_undo_rolls_back_spam_block_correctly() -> Result<()> {
    let tmp = TempDir::new().context("tmp")?;
    let db = open_db(&tmp).context("open db")?;

    let sk = [7u8; 32];
    let signer = signer_addr(sk);

    let start_time = 1_700_100_000u64;
    let base = build_owned_base_chain(&db, 30, start_time, signer).context("build_owned_base_chain")?;
    let tip0 = *base.last().unwrap();
    set_tip(&db, &tip0)?;

    let mut fund: Vec<(OutPoint, u64)> = Vec::new();
    for bh in base.iter().take(20).skip(2) {
        let b = load_block(&db, bh)?;
        let cb = &b.txs[0];
        let cbid = csd::crypto::txid(cb);
        fund.push((OutPoint { txid: cbid, vout: 0 }, cb.outputs[0].value));
    }

    let addr_miner = h20(0xA1);
    let addr_user = signer;
    let domain = "science".to_string();

    let parent_hi = get_hidx(&db, &tip0)?.expect("missing parent hidx");
    let height = parent_hi.height + 1;
    let epoch = epoch_of(height);

    let mut txs: Vec<Transaction> = Vec::new();
    let mut total_fees: u64 = 0;

    // 5 proposals
    let mut pids: Vec<Hash32> = Vec::new();
    for i in 0..5usize {
        let (op, v) = fund[i];
        let fee = csd::params::MIN_FEE_PROPOSE;
        let send = v - fee;
        let ph = [i as u8; 32];

        let tx = make_spend_tx(
            op,
            v,
            addr_user,
            send,
            fee,
            sk,
            AppPayload::Propose {
                domain: domain.clone(),
                payload_hash: ph,
                uri: format!("ipfs://p{i}"),
                expires_epoch: epoch + 10,
            },
        );
        let pid = csd::crypto::txid(&tx);
        pids.push(pid);
        total_fees += fee;
        txs.push(tx);
    }

    // 10 attestations
    for j in 0..10usize {
        let (op, v) = fund[5 + j];
        let fee = csd::params::MIN_FEE_ATTEST + (j as u64) * 100;
        let send = v - fee;
        let pid = pids[j % pids.len()];

        let tx = make_spend_tx(
            op,
            v,
            addr_user,
            send,
            fee,
            sk,
            AppPayload::Attest {
                proposal_id: pid,
                score: 0,
                confidence: 0,
            },
        );
        total_fees += fee;
        txs.push(tx);
    }

    let mut all_txs = Vec::with_capacity(1 + txs.len());
    all_txs.push(csd::chain::mine::coinbase(
        addr_miner,
        csd::params::block_reward(height) + total_fees,
        height,
        None,
    ));
    all_txs.extend(txs);

    let hdr = make_test_header(&db, tip0, &all_txs, height)?;
    let blk = Block {
        header: hdr,
        txs: all_txs,
    };
    let bh = apply_block(&db, &blk, height).context("apply spam block")?;

    let got_before = get_topk(&db, epoch, &domain)?;
    assert!(!got_before.is_empty(), "expected non-empty TopK after spam block");

    undo_block(&db, &bh).context("undo_block")?;
    set_tip(&db, &tip0).context("set_tip parent")?;

    let got_after = get_topk(&db, epoch, &domain)?;
    assert!(
        got_after.is_empty(),
        "expected TopK to roll back to empty; got={:?}",
        got_after
    );

    Ok(())
}
