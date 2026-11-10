// The block body bind: the store-time bind (both paths) and the serve-time bind.
//
// Store-time bind: a peer can answer SyncRequest::GetBlock with a real header and a substituted
// body. Without the bind the bytes were persisted first-writer-wins and the substitution was only
// caught in validate_and_apply_block, by which point reorg.rs had already written the block and
// the new tip into k_bad, kept until the next restart's rebuild, and the poisoned body stayed stored, so every
// later reorg through that height failed and marked again. One hostile peer, once, permanently.
// The bind covers txids, which leave out non-coinbase signatures, and the merkle root repeats the
// last node of an odd layer: a body with altered signatures or a repeated txid suffix still binds;
// tests/reorg_body_substitution.rs covers both.
//
// Serve-time bind: a node holding such a body would serve it again, which is the difference
// between one poisoned node and a cascade.
//
// Both halves live in one test on purpose: a merkle check bound to the wrong struct field refuses
// every block. That reads red against a "refuses the poison" assertion alone and looks like success
// while it would stop every node from accepting blocks. Each test here therefore asserts the honest
// copy of the same block still stores, still applies, and still serves.
//
// HARNESS NOTE, same as reorg_ghost_utxo_all_or_nothing.rs: testutil_chain builds toy chains via
// index_header, whose genesis-identity check is gated on #[cfg(test)], which is NOT active for the
// lib when an integration test links it, so those helpers "foreign genesis header"-fail under a
// plain cargo test (a limitation inherited from upstream). Neither store_block_bytes_checked nor
// validate_and_apply_block touches the header index, so this file hand-builds its blocks.

use tempfile::TempDir;

use csd::chain::index::header_hash;
use csd::chain::mine::coinbase;
use csd::chain::pow::pow_ok;
use csd::codec;
use csd::crypto::{sha256d, txid};
use csd::net::node::{
    outbound_block_refusal, store_block_bytes_checked, BlockStoreOutcome, NetConfig,
};
use csd::params::{GENESIS_HASH, INITIAL_REWARD};
use csd::state::app_state::epoch_of;
use csd::state::db::{get_utxo, k_block, Stores};
use csd::state::utxo::validate_and_apply_block;
use csd::types::{Block, BlockHeader, Hash20, Hash32, OutPoint};

const HONEST_MINER: Hash20 = [0x11u8; 20];
const ATTACKER: Hash20 = [0x41u8; 20];

fn open_db(tmp: &TempDir) -> Stores {
    Stores::open(tmp.path().to_str().unwrap()).expect("open db")
}

/// The consensus types do not derive PartialEq, so fixture identity is asserted on the canonical
/// serialization, which is the thing that actually has to be identical anyway.
fn ser<T: serde::Serialize>(v: &T) -> Vec<u8> {
    codec::consensus_bincode().serialize(v).unwrap()
}

/// Consensus merkle (matches utxo.rs merkle_root_txids: duplicate last if odd).
fn merkle_root(txs: &[csd::types::Transaction]) -> Hash32 {
    let mut layer: Vec<Hash32> = txs.iter().map(txid).collect();
    if layer.is_empty() {
        return [0u8; 32];
    }
    while layer.len() > 1 {
        let mut next = Vec::with_capacity((layer.len() + 1) / 2);
        let mut i = 0usize;
        while i < layer.len() {
            let l = layer[i];
            let r = if i + 1 < layer.len() { layer[i + 1] } else { layer[i] };
            let mut buf = [0u8; 64];
            buf[..32].copy_from_slice(&l);
            buf[32..].copy_from_slice(&r);
            next.push(sha256d(&buf));
            i += 2;
        }
        layer = next;
    }
    layer[0]
}

/// An honest coinbase-only block at `height`, and the poisoned twin: the SAME header byte for
/// byte, a different body underneath it. That is the whole attack.
fn honest_and_poisoned(height: u64) -> (Block, Block) {
    let honest_txs = vec![coinbase(HONEST_MINER, INITIAL_REWARD, height, None)];
    let header = BlockHeader {
        version: 1,
        prev: [0x99u8; 32],
        merkle: merkle_root(&honest_txs),
        time: 1_700_000_000,
        bits: 0,
        nonce: 0,
    };
    let poisoned_txs = vec![coinbase(ATTACKER, INITIAL_REWARD, height, None)];

    let honest = Block {
        header: header.clone(),
        txs: honest_txs,
    };
    let poisoned = Block {
        header,
        txs: poisoned_txs,
    };

    assert_eq!(
        ser(&poisoned.header),
        ser(&honest.header),
        "fixture must keep the header byte-identical, or it is not this attack"
    );
    assert_ne!(
        ser(&poisoned.txs),
        ser(&honest.txs),
        "fixture must actually substitute the body"
    );
    assert_eq!(
        header_hash(&poisoned.header),
        header_hash(&honest.header),
        "the substituted body must arrive under the SAME block hash"
    );

    (honest, poisoned)
}

#[test]
fn store_refuses_substituted_body_and_still_stores_and_applies_the_honest_one() {
    let tmp = TempDir::new().unwrap();
    let db = open_db(&tmp);

    let height = 1u64;
    let (honest, poisoned) = honest_and_poisoned(height);
    let bh = header_hash(&honest.header);

    // ---- half 1: the poison is refused AT STORE, and nothing is persisted ----
    assert_eq!(
        store_block_bytes_checked(&db, &bh, &poisoned).unwrap(),
        BlockStoreOutcome::RejectedMerkle,
        "a body that does not bind to its header must be refused at store"
    );
    assert!(
        db.blocks.get(k_block(&bh)).unwrap().is_none(),
        "REFUSED MEANS NOT PERSISTED: k_bad is written from the apply path, so any byte that \
         reaches db.blocks is already the whole defect"
    );

    // ---- half 2: the HONEST copy of the SAME block stores and applies cleanly ----
    assert_eq!(
        store_block_bytes_checked(&db, &bh, &honest).unwrap(),
        BlockStoreOutcome::Stored,
        "the honest body must still store; a bind on the wrong struct field refuses EVERY block, \
         which reads red on the poison half and stops every node from accepting blocks"
    );
    let stored = db.blocks.get(k_block(&bh)).unwrap().expect("stored bytes");
    assert_eq!(
        stored.to_vec(),
        ser(&honest),
        "stored bytes must be byte-identical to the honest block"
    );

    validate_and_apply_block(&db, &honest, epoch_of(height), height)
        .expect("the honest block must still apply cleanly under consensus");
    let cb_out = OutPoint {
        txid: txid(&honest.txs[0]),
        vout: 0,
    };
    assert!(
        get_utxo(&db, &cb_out).unwrap().is_some(),
        "the honest block's coinbase output must be in the UTXO set after apply"
    );

    // Re-offering the same honest block is a no-op, not a second write.
    assert_eq!(
        store_block_bytes_checked(&db, &bh, &honest).unwrap(),
        BlockStoreOutcome::AlreadyPresent
    );
}

#[test]
fn store_bind_is_the_same_rule_consensus_already_enforces() {
    // Consensus-neutrality, asserted rather than claimed: the store-time bind cannot refuse a body
    // that validate_and_apply_block accepts, because it calls the same function.
    let tmp = TempDir::new().unwrap();
    let db = open_db(&tmp);

    let height = 1u64;
    let (honest, poisoned) = honest_and_poisoned(height);

    assert!(
        validate_and_apply_block(&db, &poisoned, epoch_of(height), height).is_err(),
        "consensus already rejects this exact body; the store bind is strictly earlier, never \
         stricter"
    );
    assert!(
        validate_and_apply_block(&db, &honest, epoch_of(height), height).is_ok(),
        "and consensus accepts the honest one"
    );
}

// ---------------------------------------------------------------------------------------------
// The serve-time bind. This one needs a header that passes accept_header_universe_pow, so it uses
// the REAL mainnet genesis block, embedded here so the test has no external file dependency and
// self-verifies against params::GENESIS_HASH. (The repo-root genesis.bin dev fixture cannot be
// used: its own header does not commit to its own body, as in upstream, and it is left
// unchanged.)
// ---------------------------------------------------------------------------------------------

const MAINNET_GENESIS_HEX: &str = concat!(
    "010000000000000000000000000000000000000000000000000000000000000000000000b08e",
    "f271327d1e5996b1a24112a3d0c87c0d5401677719af6351d733492f9929f01cf26900000000",
    "ffff001eba5bbc00010000000000000001000000010000000000000000000000000000000000",
    "00000000000000000000000000000000000000000000ffffffff5f0000000000000000000000",
    "00000000005265757465727320323032362d30322d30353a204272697461696e20746f20776f",
    "726b2077697468204d6963726f736f667420746f206275696c64206465657066616b65206465",
    "74656374696f6e2073797374656d2e010000000000000000f2052a0100000000000000000000",
    "000000000000000000000000000000000000000000",
);

fn mainnet_genesis() -> Block {
    let hex = MAINNET_GENESIS_HEX;
    let bytes: Vec<u8> = (0..hex.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).unwrap())
        .collect();
    codec::consensus_bincode()
        .deserialize::<Block>(&bytes)
        .expect("decode embedded mainnet genesis")
}

fn net_cfg_for(genesis_hash: Hash32) -> NetConfig {
    NetConfig {
        datadir: "/nonexistent".to_string(),
        listen: "/ip4/127.0.0.1/tcp/0".parse().unwrap(),
        bootnodes: vec![],
        genesis_hash,
        is_bootnode: false,
        #[cfg(feature = "test-bypass")]
        test_mode: csd::net::node::TestPeerMode::Normal,
    }
}

#[test]
fn serve_refuses_substituted_body_and_still_serves_the_honest_one() {
    let honest = mainnet_genesis();
    let bh = header_hash(&honest.header);
    assert_eq!(
        bh, GENESIS_HASH,
        "the embedded fixture must be the real mainnet genesis"
    );
    assert!(
        pow_ok(&bh, honest.header.bits),
        "fixture must carry real PoW or this test proves nothing about the serve guard"
    );
    let cfg = net_cfg_for(bh);

    // ---- half 1: a real block still serves, unrefused ----
    assert_eq!(
        outbound_block_refusal(&cfg, &honest, &bh),
        None,
        "a real block must still be served; a bind on the wrong field silences the whole sync path"
    );

    // ---- half 2: a poisoned body already on disk is NOT re-served ----
    let poisoned = Block {
        header: honest.header.clone(),
        txs: vec![coinbase(ATTACKER, INITIAL_REWARD, 0, None)],
    };
    assert_eq!(
        header_hash(&poisoned.header),
        bh,
        "the poison must sit under the same block hash"
    );
    let refusal = outbound_block_refusal(&cfg, &poisoned, &bh)
        .expect("a body that does not bind to its header must not be re-served");
    assert!(
        refusal.contains("does not bind"),
        "the refusal must name the real reason, got {refusal:?}"
    );
    assert!(
        !refusal.contains("pow"),
        "a genuine header passes the PoW guard; if this reads as a PoW refusal then the bind is \
         not what refused, got {refusal:?}"
    );
}
