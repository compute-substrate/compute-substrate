use anyhow::Result;
use crate::types::{Block, BlockHeader, Transaction, TxIn, TxOut, OutPoint, AppPayload, Hash32};
use crate::crypto::{sha256d, txid};
use crate::params::{INITIAL_BITS, BLOCK_REWARD};
use crate::chain::index::header_hash;
use crate::state::db::{Stores, k_block, get_tip};
use crate::chain::index::{get_hidx};
use crate::state::utxo::validate_and_apply_block;
use crate::state::app::current_epoch;

fn merkle_root(txs: &[Transaction]) -> Hash32 {
    // v0: merkle = sha256d(concat(txid))
    let mut bytes = vec![];
    for tx in txs {
        bytes.extend_from_slice(&txid(tx));
    }
    sha256d(&bytes)
}

fn target_ok(hash: &Hash32, bits: u32) -> bool {
    // v0: super-simple "bits": require first N leading zero bits-ish.
    // Interpret bits as "difficulty" threshold: higher bits => easier.
    // For testnet: keep easy: bits ~ 0x1f00ffff
    // Here we just require first byte == 0 for some roughness:
    let _ = bits;
    hash[0] == 0
}

pub fn coinbase(miner_h160: [u8;20], value: u64) -> Transaction {
    Transaction {
        version: 1,
        inputs: vec![TxIn {
            prevout: OutPoint { txid: [0u8;32], vout: u32::MAX },
            script_sig: vec![0u8; 8], // arbitrary
        }],
        outputs: vec![TxOut { value, script_pubkey: miner_h160.to_vec() }],
        locktime: 0,
        app: AppPayload::None,
    }
}

pub fn mine_one(db: &Stores, miner_h160: [u8;20], mempool: Vec<Transaction>) -> Result<Hash32> {
    let tip = get_tip(db)?.unwrap_or([0u8;32]);
    let parent_hi = if tip != [0u8;32] { get_hidx(db, &tip)? } else { None };
    let height = parent_hi.as_ref().map(|h| h.height + 1).unwrap_or(0);
    let epoch = current_epoch(height);

    // For v0: we do not select fees here; block validation will enforce coinbase = reward + fees
    // Simplest: mempool txs must already have fees; we compute total fees by validating in apply.
    // We'll set coinbase value later by trying with 0 then adjusting? We'll do a quick prepass:
    let mut fees_total: i128 = 0;
    for tx in &mempool {
        // rough prepass: compute fee by reading UTXOs (reuse utxo validate function)
        // We'll let block validation enforce exact values. Here we don't compute exact; set 0 and fail? nope.
        // So: keep v0 easiest: empty mempool until you wire tx submission.
        let _ = tx;
    }
    fees_total = 0;

    let cb = coinbase(miner_h160, (BLOCK_REWARD as i128 + fees_total) as u64);
    let mut txs = vec![cb];
    txs.extend_from_slice(&mempool);

    let merkle = merkle_root(&txs);

    let mut hdr = BlockHeader {
        version: 1,
        prev: tip,
        merkle,
        time: now_unix(),
        bits: INITIAL_BITS,
        nonce: 0,
    };

    loop {
        let h = header_hash(&hdr);
        if target_ok(&h, hdr.bits) {
            let block = Block { header: hdr.clone(), txs: txs.clone() };

            // store raw block
            db.blocks.insert(k_block(&h), bincode::serialize(&block)?)?;

            // index header (needs parent index)
            let parent_ref = if hdr.prev == [0u8;32] { None } else { parent_hi.as_ref() };
            let _hi = crate::chain::index::index_header(db, &hdr, parent_ref)?;

            // apply to state and set tip
            validate_and_apply_block(db, &block, epoch)?;
            crate::state::db::set_tip(db, &h)?;
            return Ok(h);
        }
        hdr.nonce = hdr.nonce.wrapping_add(1);
        if hdr.nonce == 0 { hdr.time = now_unix(); }
    }
}

fn now_unix() -> u64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs()
}
