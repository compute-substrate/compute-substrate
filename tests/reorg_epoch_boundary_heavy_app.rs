// tests/reorg_epoch_boundary_heavy_app.rs

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

fn first_epoch_boundary() -> u64 {
    for h in 1..10_000u64 {
        if epoch_of(h - 1) != epoch_of(h) {
            return h;
        }
    }
    panic!("could not find epoch boundary");
}

#[test]
fn deep_reorg_across_epoch_boundary_with_heavy_app_history_matches_replay() -> Result<()> {
    let tmp = TempDir::new().context("tmp")?;
    let db = open_db(&tmp).context("open db")?;

    let sk = [7u8; 32];
    let signer = signer_addr(sk);

    let miner_main = h20(0xA1);
    let miner_fork = h20(0xB2);
    let user_addr = signer;

    let boundary_h = first_epoch_boundary();
    assert!(boundary_h >= 3, "boundary too early for fork setup");

    // Shared tip is 2 blocks before the epoch rollover.
    let fork_parent_height = boundary_h - 2;
    let shared_len = fork_parent_height + 1;

    let start_time = 1_700_200_000u64;
    let shared = build_base_chain_with_miner(&db, shared_len, start_time, signer)
        .context("build_base_chain_with_miner(shared)")?;
    let shared_tip = shared[fork_parent_height as usize];
    assert_tip_eq(&db, shared_tip)?;

    // Funding outputs from the shared prefix.
    let mut funds: Vec<(OutPoint, u64)> = Vec::new();
    for bh in shared.iter().skip(2) {
        let b = load_block(&db, bh)?;
        let cb = &b.txs[0];
        let cbid = csd::crypto::txid(cb);
        let v = cb.outputs[0].value;
        funds.push((OutPoint { txid: cbid, vout: 0 }, v));
    }
    assert!(
        funds.len() >= 86,
        "not enough funding outputs: have {}, need at least 86",
        funds.len()
    );

    // -----------------------------
    // Canonical branch (shorter)
    // -----------------------------
    let mut canon_prev = shared_tip;
    let mut canon_props_science: Vec<Hash32> = Vec::new();
    let mut canon_props_ai: Vec<Hash32> = Vec::new();
    let mut canon_fund_i = 0usize;
    let canon_blocks = 6u64;

    for step in 0..canon_blocks {
        let height = fork_parent_height + 1 + step;
        let epoch = epoch_of(height);

        let mut txs: Vec<Transaction> = Vec::new();
        let mut total_fees = 0u64;

        // 2 proposals per block
        for j in 0..2u8 {
            let (op, v) = funds[canon_fund_i];
            canon_fund_i += 1;

            let fee = csd::params::MIN_FEE_PROPOSE;
            let send = v - fee;
            total_fees += fee;

            let domain = if j % 2 == 0 { "science" } else { "ai" }.to_string();

            let mut payload_hash = [0u8; 32];
            payload_hash[0] = 0x10;
            payload_hash[1] = step as u8;
            payload_hash[2] = j;
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
                    uri: format!("ipfs://canon/{}/{}/{}", epoch, step, j),
                    expires_epoch: epoch + 3,
                },
            );

            let pid = csd::crypto::txid(&tx);
            if domain == "science" {
                canon_props_science.push(pid);
            } else {
                canon_props_ai.push(pid);
            }

            txs.push(tx);
        }

        // 3 attestations per block once proposals exist
        for k in 0..3usize {
            let target = match k % 2 {
                0 if !canon_props_science.is_empty() => {
                    canon_props_science[(step as usize + k) % canon_props_science.len()]
                }
                _ if !canon_props_ai.is_empty() => {
                    canon_props_ai[(step as usize + k) % canon_props_ai.len()]
                }
                _ => continue,
            };

            let (op, v) = funds[canon_fund_i];
            canon_fund_i += 1;

            let fee = csd::params::MIN_FEE_ATTEST + (k as u64) * 100;
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
                    score: (step as u32).wrapping_mul(17).wrapping_add(k as u32),
                    confidence: 100 + k as u32,
                },
            );

            txs.push(tx);
        }

        let mut all_txs = Vec::with_capacity(1 + txs.len());
        all_txs.push(csd::chain::mine::coinbase(
            miner_main,
            csd::params::block_reward(height) + total_fees,
            height,
            None,
        ));
        all_txs.extend(txs);

        let hdr = make_test_header(&db, canon_prev, &all_txs, height)?;
        let blk = Block { header: hdr, txs: all_txs };
        let bh = persist_index_apply_block(&db, &blk, height)?;
        canon_prev = bh;
    }

    let canon_tip = canon_prev;
    assert_tip_eq(&db, canon_tip)?;

    // -----------------------------
    // Competing fork branch (longer)
    // Crosses the same epoch boundary but with different app history.
    // -----------------------------
    let mut fork_prev = shared_tip;
    let mut fork_props_science: Vec<Hash32> = Vec::new();
    let mut fork_props_ai: Vec<Hash32> = Vec::new();
    let mut fork_fund_i = 12usize; // disjoint funding slice vs canonical
    let fork_blocks = 8u64;

    for step in 0..fork_blocks {
        let height = fork_parent_height + 1 + step;
        let epoch = epoch_of(height);

        let mut txs: Vec<Transaction> = Vec::new();
        let mut total_fees = 0u64;

        // Different mix than canonical: 1 science + 2 ai proposals per block
        for j in 0..3u8 {
            let (op, v) = funds[fork_fund_i];
            fork_fund_i += 1;

            let fee = csd::params::MIN_FEE_PROPOSE;
            let send = v - fee;
            total_fees += fee;

            let domain = if j == 0 { "science" } else { "ai" }.to_string();

            let mut payload_hash = [0u8; 32];
            payload_hash[0] = 0x20;
            payload_hash[1] = step as u8;
            payload_hash[2] = j;
            if payload_hash == [0u8; 32] {
                payload_hash[0] = 2;
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
                    uri: format!("ipfs://fork/{}/{}/{}", epoch, step, j),
                    expires_epoch: epoch + 5,
                },
            );

            let pid = csd::crypto::txid(&tx);
            if domain == "science" {
                fork_props_science.push(pid);
            } else {
                fork_props_ai.push(pid);
            }

            txs.push(tx);
        }

        // 4 attestations per block
        for k in 0..4usize {
            let target = match k % 3 {
                0 if !fork_props_science.is_empty() => {
                    fork_props_science[(step as usize + k) % fork_props_science.len()]
                }
                _ if !fork_props_ai.is_empty() => {
                    fork_props_ai[(step as usize + k) % fork_props_ai.len()]
                }
                _ => continue,
            };

            let (op, v) = funds[fork_fund_i];
            fork_fund_i += 1;

            let fee = csd::params::MIN_FEE_ATTEST + 200 + (k as u64) * 111;
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
                    score: 1_000 + (step as u32) * 31 + k as u32,
                    confidence: 200 + k as u32,
                },
            );

            txs.push(tx);
        }

        let mut all_txs = Vec::with_capacity(1 + txs.len());
        all_txs.push(csd::chain::mine::coinbase(
            miner_fork,
            csd::params::block_reward(height) + total_fees,
            height,
            None,
        ));
        all_txs.extend(txs);

        let hdr = make_test_header(&db, fork_prev, &all_txs, height)?;
        let blk = Block { header: hdr, txs: all_txs };
        let bh = persist_index_only_block(&db, &blk)?;
        fork_prev = bh;
    }

    let fork_tip = fork_prev;

    // Sanity: fork is strictly longer than canonical past the same fork point.
    let canon_tip_hi = get_hidx(&db, &canon_tip)?.expect("missing canon tip hidx");
    let fork_tip_hi = get_hidx(&db, &fork_tip)?.expect("missing fork tip hidx");
    assert!(fork_tip_hi.height > canon_tip_hi.height);

    flush_all_state_trees(&db)?;
    maybe_reorg_to(&db, &fork_tip, None).context("maybe_reorg_to(fork_tip)")?;
    assert_tip_eq(&db, fork_tip)?;

    // Replay winning chain into a fresh DB and require exact state agreement.
    let replay_tmp = TempDir::new().context("replay tmp")?;
    let replay_db = open_db(&replay_tmp).context("open replay db")?;
    replay_canonical_from_tip(&replay_db, &db, fork_tip).context("replay_canonical_from_tip")?;
    assert_tip_eq(&replay_db, fork_tip)?;

    let epochs_to_check = [
        epoch_of(boundary_h - 1),
        epoch_of(boundary_h),
        epoch_of(boundary_h + 1),
    ];

    for epoch in epochs_to_check {
        for domain in ["science", "ai"] {
            let got_live = get_topk(&db, epoch, domain)
                .with_context(|| format!("get_topk live epoch={epoch} domain={domain}"))?;
            let got_replay = get_topk(&replay_db, epoch, domain)
                .with_context(|| format!("get_topk replay epoch={epoch} domain={domain}"))?;

            assert_eq!(
                got_live, got_replay,
                "TopK mismatch after epoch-boundary reorg for epoch={} domain={}",
                epoch, domain
            );
        }
    }

    Ok(())
}
