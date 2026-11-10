// The state fingerprint is what an operator compares between a live datadir and a from-genesis
// rebuild before replacing a node's binary or datadir, so its discriminating power is
// load-bearing. `csd fingerprint --datadir <dir>` is the wired entry point; these tests pin the
// function behind it.
//
// The property that matters: two nodes that hold the same consensus state produce the same
// fingerprint regardless of the order they got there, and any extra or missing UTXO shows up.
// A phantom coin (present on an incrementally reorging node, absent from a from-genesis replay)
// is exactly "one extra UTXO", so if that did not change the fingerprint the check would pass
// while the divergence it exists to catch went unnoticed.

use anyhow::Result;
use tempfile::TempDir;

use csd::state::db::{k_bad, k_undo, put_utxo, put_utxo_meta, set_tip, Stores, UtxoMeta};
use csd::state::fingerprint::{fingerprint, fmt_fp, local_chain_undo_root};
use csd::types::{OutPoint, TxOut};

fn open_db(tmp: &TempDir) -> Stores {
    Stores::open(tmp.path().to_str().unwrap()).expect("open db")
}

fn op(tag: u8) -> OutPoint {
    OutPoint {
        txid: [tag; 32],
        vout: 0,
    }
}

fn add_coin(db: &Stores, tag: u8, value: u64) -> Result<()> {
    put_utxo(
        db,
        &op(tag),
        &TxOut {
            value,
            script_pubkey: [tag; 20],
        },
    )?;
    put_utxo_meta(
        db,
        &op(tag),
        &UtxoMeta {
            height: 1,
            coinbase: false,
        },
    )?;
    Ok(())
}

#[test]
fn same_state_reached_in_a_different_order_fingerprints_identically() -> Result<()> {
    let t1 = TempDir::new()?;
    let t2 = TempDir::new()?;
    let a = open_db(&t1);
    let b = open_db(&t2);

    for tag in [0x11u8, 0x22, 0x33, 0x44] {
        add_coin(&a, tag, 1_000 + tag as u64)?;
    }
    // Same set, inserted in reverse.
    for tag in [0x44u8, 0x33, 0x22, 0x11] {
        add_coin(&b, tag, 1_000 + tag as u64)?;
    }
    set_tip(&a, &[0x99; 32])?;
    set_tip(&b, &[0x99; 32])?;

    let fa = fingerprint(&a)?;
    let fb = fingerprint(&b)?;
    assert_eq!(fa, fb, "insertion order must not affect the fingerprint");
    assert!(!fmt_fp(&fa).is_empty());
    Ok(())
}

#[test]
fn one_phantom_coin_changes_the_fingerprint() -> Result<()> {
    let t1 = TempDir::new()?;
    let t2 = TempDir::new()?;
    let live = open_db(&t1);
    let rebuilt = open_db(&t2);

    for tag in [0x11u8, 0x22, 0x33] {
        add_coin(&live, tag, 5_000)?;
        add_coin(&rebuilt, tag, 5_000)?;
    }
    set_tip(&live, &[0x99; 32])?;
    set_tip(&rebuilt, &[0x99; 32])?;
    assert_eq!(fingerprint(&live)?, fingerprint(&rebuilt)?, "baseline must match");

    // The live node carries one coin a from-genesis replay does not have.
    add_coin(&live, 0xEE, 811)?;

    let fl = fingerprint(&live)?;
    let fr = fingerprint(&rebuilt)?;
    assert_ne!(fl, fr, "a phantom coin must change the fingerprint");
    assert_ne!(fl.utxo_root, fr.utxo_root);
    assert_ne!(fl.utxo_meta_root, fr.utxo_meta_root);
    assert_eq!(fl.tip, fr.tip, "the divergence is in the set, not the tip");
    Ok(())
}

#[test]
fn a_changed_value_or_app_entry_changes_the_fingerprint() -> Result<()> {
    let t1 = TempDir::new()?;
    let t2 = TempDir::new()?;
    let a = open_db(&t1);
    let b = open_db(&t2);

    add_coin(&a, 0x11, 5_000)?;
    add_coin(&b, 0x11, 5_001)?; // same outpoint, different value
    assert_ne!(
        fingerprint(&a)?.utxo_root,
        fingerprint(&b)?.utxo_root,
        "a changed output value must change the utxo root"
    );

    let t3 = TempDir::new()?;
    let t4 = TempDir::new()?;
    let c = open_db(&t3);
    let d = open_db(&t4);
    add_coin(&c, 0x11, 5_000)?;
    add_coin(&d, 0x11, 5_000)?;
    assert_eq!(fingerprint(&c)?, fingerprint(&d)?);

    d.app.insert(b"some-app-key".as_slice(), b"v".as_slice())?;
    assert_ne!(
        fingerprint(&c)?.app_root,
        fingerprint(&d)?.app_root,
        "an app-state difference must change the app root"
    );
    Ok(())
}

// An empty or wrong path MUST NOT be comparable. `sled::open` creates a database when the path
// is not one, so every non-datadir hashes to the same constant: zero tip, and SHA-256 of the
// empty string for all three roots. Two mistyped paths therefore compare EQUAL, which would let
// the operator apply "identical fingerprints => safe to replace" to a comparison that never
// looked at any chain state. `csd fingerprint` refuses a datadir with no tip for this reason;
// this test pins the shape that makes the refusal necessary.
#[test]
fn a_datadir_with_no_tip_is_indistinguishable_and_must_be_refused() -> Result<()> {
    const EMPTY_SHA256: [u8; 32] = [
        0xe3, 0xb0, 0xc4, 0x42, 0x98, 0xfc, 0x1c, 0x14, 0x9a, 0xfb, 0xf4, 0xc8, 0x99, 0x6f, 0xb9,
        0x24, 0x27, 0xae, 0x41, 0xe4, 0x64, 0x9b, 0x93, 0x4c, 0xa4, 0x95, 0x99, 0x1b, 0x78, 0x52,
        0xb8, 0x55,
    ];

    let tmp = TempDir::new()?;
    let db = open_db(&tmp);
    let fp = fingerprint(&db)?;

    assert_eq!(fp.tip, [0u8; 32], "no tip reads as the zero hash");
    assert_eq!(
        fp.utxo_root, EMPTY_SHA256,
        "an empty tree hashes to the empty-string digest, which is why this is not comparable"
    );

    // The collision itself: a SECOND unrelated empty directory is byte-for-byte identical.
    let tmp2 = TempDir::new()?;
    let db2 = open_db(&tmp2);
    assert_eq!(
        fp,
        fingerprint(&db2)?,
        "two unrelated non-datadirs fingerprint identically: the CLI must refuse them, never \
         report them as a match"
    );

    // And the discriminator the CLI actually uses: no tip.
    assert!(
        csd::state::db::get_tip(&db)?.is_none(),
        "the CLI refuses on a missing tip; if this ever becomes Some, the guard is bypassed"
    );
    Ok(())
}

// `csd fingerprint --long` prints the bad-mark count, a figure an operator records for each node
// from its stopped datadir.
#[test]
fn fingerprint_long_prints_the_bad_mark_count() -> Result<()> {
    let tmp = TempDir::new()?;
    let run = |dir: &TempDir| -> Result<String> {
        let out = std::process::Command::new(env!("CARGO_BIN_EXE_csd"))
            .args(["fingerprint", "--datadir", dir.path().to_str().unwrap(), "--long"])
            .output()?;
        assert!(out.status.success(), "stderr: {}", String::from_utf8_lossy(&out.stderr));
        Ok(String::from_utf8(out.stdout)?)
    };
    {
        let db = open_db(&tmp);
        set_tip(&db, &[0x99; 32])?;
        db.db.flush()?;
    }
    let none = run(&tmp)?;
    assert!(none.lines().any(|l| l == "bad_marks     0"), "stdout: {none}");
    assert!(none.lines().any(|l| l.starts_with("undo          unknown")), "stdout: {none}");
    {
        let db = open_db(&tmp);
        db.meta.insert(k_bad(&[1; 32]), &b"1"[..])?;
        db.meta.insert(k_bad(&[2; 32]), &b"1"[..])?;
        db.db.flush()?;
    }
    let two = run(&tmp)?;
    assert!(two.lines().any(|l| l == "bad_marks     2"), "stdout: {two}");
    Ok(())
}

// `fingerprint()` leaves the undo tree out (it changes between versions), so it cannot show an
// undo log that would replay wrongly in a reorg. The local chain's undo root shows it, and
// ignores the logs a reorg leaves behind for blocks off the chain, which differ between healthy
// nodes and would otherwise be a false alarm.
#[test]
fn the_local_chain_undo_root_shows_a_changed_log_and_ignores_a_reorg_leftover() -> Result<()> {
    use csd::chain::index::{put_hidx, HeaderIndex};
    let tmp = TempDir::new()?;
    let db = open_db(&tmp);
    let chain = [[0x10u8; 32], [0x11; 32], [0x12; 32]];
    for (height, hash) in chain.iter().enumerate() {
        let parent = if height == 0 { [0u8; 32] } else { chain[height - 1] };
        put_hidx(&db, &HeaderIndex { hash: *hash, parent, height: height as u64, chainwork: height as u128 + 1, bits: 0, time: 0 })?;
        db.undo.insert(k_undo(hash), vec![height as u8; 4])?;
    }
    set_tip(&db, &chain[2])?;
    let root = local_chain_undo_root(&db)?.expect("the chain is indexed");

    db.undo.insert(k_undo(&[0x21; 32]), vec![9u8; 4])?;
    assert_eq!(local_chain_undo_root(&db)?, Some(root), "a log off the chain is not counted");
    db.undo.insert(k_undo(&chain[1]), vec![7u8; 4])?;
    assert_ne!(local_chain_undo_root(&db)?, Some(root), "a changed log on the chain is");
    Ok(())
}
