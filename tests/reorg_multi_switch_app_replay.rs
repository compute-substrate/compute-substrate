use anyhow::{Context, Result};
use tempfile::TempDir;

use csd::chain::index::{get_hidx, header_hash, index_header};
use csd::chain::reorg::maybe_reorg_to;
use csd::state::app_state::{epoch_of, get_topk};
use csd::state::db::{k_block, set_tip, Stores};
use csd::state::utxo::validate_and_apply_block;
use csd::types::{AppPayload, Block, Hash20, Hash32, OutPoint, Transaction, TxIn, TxOut};

mod testutil_chain;
use testutil_chain::{
    assert_tip_eq, build_base_chain_with_miner, flush_all_state_trees, make_test_header, open_db,
    replay_canonical_from_tip,
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

fn take_fund(
    funds: &[(OutPoint, u64)],
    fund_i: &mut usize,
    ctx: &str,
) -> (OutPoint, u64) {
    let idx = *fund_i;
    let (op, v) = *funds.get(idx).unwrap_or_else(|| {
        panic!(
            "funds exhausted in {ctx}: need index {}, have {}",
            idx,
            funds.len()
        )
    });
    *fund_i += 1;
    (op, v)
}

fn build_branch(
    db: &Stores,
    start_prev: Hash32,
    start_height: u64,
    num_blocks: u64,
    miner: Hash20,
    sk: [u8; 32],
    user_addr: Hash20,
    funds: &[(OutPoint, u64)],
    fund_i: &mut usize,
    flavor: u8,
    apply_now: bool,
) -> Result<Hash32> {
    let mut prev = start_prev;
    let mut props_science: Vec<Hash32> = Vec::new();
    let mut props_ai: Vec<Hash32> = Vec::new();

    for step in 0..num_blocks {
        let height = start_height + step;
        let epoch = epoch_of(height);

        let mut txs: Vec<Transaction> = Vec::new();
        let mut total_fees = 0u64;

        let propose_count = match flavor {
            0 => 2usize, // branch A
            1 => 3usize, // branch B
            _ => 2usize, // branch C
        };

        let attest_count = match flavor {
            0 => 2usize,
            1 => 4usize,
            _ => 5usize,
        };

        for j in 0..propose_count {
            let (op, v) = take_fund(
                funds,
                fund_i,
                &format!("build_branch flavor={} step={} propose={}", flavor, step, j),
            );

            let fee = csd::params::MIN_FEE_PROPOSE;
            let send = v - fee;
            total_fees += fee;

            let domain = match flavor {
                0 => {
                    if j % 2 == 0 { "science" } else { "ai" }
                }
                1 => {
                    if j == 0 { "science" } else { "ai" }
                }
                _ => {
                    if j == propose_count - 1 { "ai" } else { "science" }
                }
            }
            .to_string();

            let mut payload_hash = [0u8; 32];
            payload_hash[0] = 0x40 + flavor;
            payload_hash[1] = step as u8;
            payload_hash[2] = j as u8;
            if payload_hash == [0u8; 32] {
                payload_hash[0] = 1;
            }

            let tx = make_spend_tx(
                op,
                v,
                user_addr,
                send,
                fee,
                sk,
                AppPayload::Propose {
                    domain: domain.clone(),
                    payload_hash,
                    uri: format!("ipfs://branch-{flavor}/{epoch}/{step}/{j}"),
                    expires_epoch: epoch + 4 + (flavor as u64),
                },
            );

            let pid = csd::crypto::txid(&tx);
            if domain == "science" {
                props_science.push(pid);
            } else {
                props_ai.push(pid);
            }

            txs.push(tx);
        }

        for k in 0..attest_count {
            let target = match flavor {
                0 => {
                    if k % 2 == 0 && !props_science.is_empty() {
                        props_science[(step as usize + k) % props_science.len()]
                    } else if !props_ai.is_empty() {
                        props_ai[(step as usize + k) % props_ai.len()]
                    } else {
                        continue;
                    }
                }
                1 => {
                    if k % 3 == 0 && !props_science.is_empty() {
                        props_science[(step as usize + k) % props_science.len()]
                    } else if !props_ai.is_empty() {
                        props_ai[(step as usize + k) % props_ai.len()]
                    } else {
                        continue;
                    }
                }
                _ => {
                    if k % 2 == 1 && !props_ai.is_empty() {
                        props_ai[(step as usize + k) % props_ai.len()]
                    } else if !props_science.is_empty() {
                        props_science[(step as usize + k) % props_science.len()]
                    } else {
                        continue;
                    }
                }
            };

            let (op, v) = take_fund(
                funds,
                fund_i,
                &format!("build_branch flavor={} step={} attest={}", flavor, step, k),
            );

            let fee = csd::params::MIN_FEE_ATTEST + (flavor as u64) * 200 + (k as u64) * 77;
            let send = v - fee;
            total_fees += fee;

            let tx = make_spend_tx(
                op,
                v,
                user_addr,
                send,
                fee,
                sk,
                AppPayload::Attest {
                    proposal_id: target,
                    score: 10_000 + (flavor as u32) * 1000 + (step as u32) * 37 + k as u32,
                    confidence: 100 + (flavor as u32) * 10 + k as u32,
                },
            );

            txs.push(tx);
        }

        let mut all_txs = Vec::with_capacity(1 + txs.len());
        all_txs.push(csd::chain::mine::coinbase(
            miner,
            csd::params::block_reward(height) + total_fees,
            height,
            None,
        ));
        all_txs.extend(txs);

        let hdr = make_test_header(db, prev, &all_txs, height)?;
        let blk = Block {
            header: hdr,
            txs: all_txs,
        };

        let bh = if apply_now {
            persist_index_apply_block(db, &blk, height)?
        } else {
            persist_index_only_block(db, &blk)?
        };

        prev = bh;
    }

    Ok(prev)
}

#[test]
fn multi_reorg_sequence_with_app_state_matches_replay() -> Result<()> {
    let tmp = TempDir::new().context("tmp")?;
    let db = open_db(&tmp).context("open db")?;

    let sk = [9u8; 32];
    let signer = signer_addr(sk);

    let miner_a = h20(0xA1);
    let miner_b = h20(0xB2);
    let miner_c = h20(0xC3);
    let user_addr = signer;

    // Larger shared prefix so the synthetic multi-branch workload has enough funding.
    let shared_len = 220u64;
    let fork_parent_height = 100u64;
    let start_time = 1_700_300_000u64;

    let shared = build_base_chain_with_miner(&db, shared_len, start_time, signer)
        .context("build_base_chain_with_miner(shared)")?;
    let shared_tip = shared[fork_parent_height as usize];

    // Rewind logical tip to the intended fork point.
    set_tip(&db, &shared_tip)?;
    assert_tip_eq(&db, shared_tip)?;

    let mut funds: Vec<(OutPoint, u64)> = Vec::new();
    for bh in shared.iter().take(shared_len as usize).skip(2) {
        let b = load_block(&db, bh)?;
        let cb = &b.txs[0];
        let cbid = csd::crypto::txid(cb);
        let v = cb.outputs[0].value;
        funds.push((OutPoint { txid: cbid, vout: 0 }, v));
    }

    assert!(
        funds.len() >= 180,
        "not enough funding outputs for multi-switch test: have {}, need at least 180",
        funds.len()
    );

    let branch_start_height = fork_parent_height + 1;

    // Branch A: applied, becomes canonical first.
    let mut fund_a = 0usize;
    let tip_a = build_branch(
        &db,
        shared_tip,
        branch_start_height,
        6,
        miner_a,
        sk,
        user_addr,
        &funds,
        &mut fund_a,
        0,
        true,
    )?;
    assert_tip_eq(&db, tip_a)?;

    // Branch B: indexed only, heavier than A.
    let mut fund_b = 30usize;
    let tip_b = build_branch(
        &db,
        shared_tip,
        branch_start_height,
        8,
        miner_b,
        sk,
        user_addr,
        &funds,
        &mut fund_b,
        1,
        false,
    )?;

    let hi_a = get_hidx(&db, &tip_a)?.expect("missing hidx A");
    let hi_b = get_hidx(&db, &tip_b)?.expect("missing hidx B");
    assert!(hi_b.height > hi_a.height, "branch B must beat A");

    flush_all_state_trees(&db)?;
    maybe_reorg_to(&db, &tip_b, None).context("reorg A -> B")?;
    assert_tip_eq(&db, tip_b)?;

    // Branch C: also forks from same ancestor, even heavier than B.
    let mut fund_c = 70usize;
    let tip_c = build_branch(
        &db,
        shared_tip,
        branch_start_height,
        10,
        miner_c,
        sk,
        user_addr,
        &funds,
        &mut fund_c,
        2,
        false,
    )?;

    let hi_c = get_hidx(&db, &tip_c)?.expect("missing hidx C");
    assert!(hi_c.height > hi_b.height, "branch C must beat B");

    flush_all_state_trees(&db)?;
    maybe_reorg_to(&db, &tip_c, None).context("reorg B -> C")?;
    assert_tip_eq(&db, tip_c)?;

    // Replay winning chain into fresh DB and compare derived app state.
    let replay_tmp = TempDir::new().context("replay tmp")?;
    let replay_db = open_db(&replay_tmp).context("open replay db")?;
    replay_canonical_from_tip(&replay_db, &db, tip_c).context("replay_canonical_from_tip")?;
    assert_tip_eq(&replay_db, tip_c)?;

    let epochs_to_check = [
        epoch_of(fork_parent_height - 1),
        epoch_of(fork_parent_height),
        epoch_of(fork_parent_height + 1),
        epoch_of(fork_parent_height + 8),
        epoch_of(fork_parent_height + 10),
    ];

    for epoch in epochs_to_check {
        for domain in ["science", "ai"] {
            let got_live = get_topk(&db, epoch, domain)
                .with_context(|| format!("get_topk live epoch={epoch} domain={domain}"))?;
            let got_replay = get_topk(&replay_db, epoch, domain)
                .with_context(|| format!("get_topk replay epoch={epoch} domain={domain}"))?;

            assert_eq!(
                got_live, got_replay,
                "TopK mismatch after multi-reorg sequence for epoch={} domain={}",
                epoch, domain
            );
        }
    }

    Ok(())
}
