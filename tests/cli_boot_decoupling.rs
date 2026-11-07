// Boot decoupling of the node from the wallet config, and the CLI wallet's key handling and
// signing commands, driven through the real binary because the defect lives in the
// argument-dispatch order of `cli::run()`, not in a library function.
//
// The defect: `load_config()` ran before `match cmd.cmd`, so a present-but-malformed
// `~/.csd/config.json` refused to start `csd node` (and `csd chain`, `csd db`, `csd genesis`,
// `csd fingerprint`), none of which read the wallet config at all.
//
// `csd node` itself is not launched here (it is a p2p daemon that does not exit, and a sandboxed
// test environment may kill it), so the assertions use the sibling arms that share the same
// single load site and terminate: `csd chain` and `csd fingerprint`. The refusal that must be
// kept, on the arms that do read the config, is asserted in the same file.

use std::path::{Path, PathBuf};
use std::process::{Command, Output};

use tempfile::TempDir;

fn csd() -> &'static str {
    env!("CARGO_BIN_EXE_csd")
}

fn write_config(home: &Path, contents: &str) -> PathBuf {
    let dir = home.join(".csd");
    std::fs::create_dir_all(&dir).unwrap();
    let p = dir.join("config.json");
    std::fs::write(&p, contents).unwrap();
    p
}

fn run(home: &Path, args: &[&str]) -> Output {
    Command::new(csd())
        .args(args)
        .env("HOME", home)
        .output()
        .expect("run csd")
}

const MALFORMED: &str = "{ this is not json";

#[test]
fn a_malformed_wallet_config_no_longer_refuses_the_non_wallet_commands() {
    let home = TempDir::new().unwrap();
    write_config(home.path(), MALFORMED);

    // Stands in for `csd node`: same single load site, terminates, no daemon.
    let out = run(home.path(), &["chain", "expected-supply", "--height", "0"]);
    let stderr = String::from_utf8_lossy(&out.stderr).to_string();
    assert!(
        out.status.success(),
        "a command that never reads the wallet config must not be blocked by it. \
         status={:?} stderr={stderr}",
        out.status.code()
    );
    assert_eq!(
        String::from_utf8_lossy(&out.stdout).trim(),
        "5000000000",
        "and it must still produce its real answer"
    );

    // `csd fingerprint` is the pre-rotation check and is in the same class. It must fail for its
    // own reason (no such datadir), never for the wallet config.
    let missing = home.path().join("no-such-datadir");
    let out = run(
        home.path(),
        &["fingerprint", "--datadir", missing.to_str().unwrap()],
    );
    let stderr = String::from_utf8_lossy(&out.stderr).to_string();
    assert!(
        !stderr.contains("failed to load CLI config"),
        "fingerprint must not be gated on the wallet config; stderr={stderr}"
    );
}

#[test]
fn the_arms_that_do_read_the_config_still_refuse_a_malformed_one() {
    // The fix removes a refusal and must add none, and must not silently swallow one either: a
    // wallet command with an unreadable config must still say so rather than run on defaults.
    let home = TempDir::new().unwrap();
    write_config(home.path(), MALFORMED);

    let out = run(home.path(), &["wallet", "config"]);
    assert!(
        !out.status.success(),
        "a wallet command must still refuse an unreadable config"
    );
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("failed to load CLI config"),
        "and with the identical error as before; stderr={stderr}"
    );
}

#[test]
fn wallet_config_prints_a_redaction_not_the_private_key() {
    let home = TempDir::new().unwrap();
    let key = "1111111111111111111111111111111111111111111111111111111111111111";
    write_config(
        home.path(),
        &format!(
            r#"{{"default_privkey":"{key}","default_rpc_url":"http://127.0.0.1:8789","default_datadir":null,"default_change_addr20":null}}"#
        ),
    );

    let out = run(home.path(), &["wallet", "config"]);
    let stdout = String::from_utf8_lossy(&out.stdout).to_string();
    assert!(out.status.success(), "the happy path must still work");
    assert!(
        !stdout.contains(key),
        "`csd wallet config` printed the private key: {stdout}"
    );
    assert!(
        !stdout.contains(&key[..8]),
        "not even a prefix of the key: {stdout}"
    );
    assert!(
        stdout.contains("redacted"),
        "the field must still show as present: {stdout}"
    );
    // Paired happy path: the command still does what it is run for.
    assert!(
        stdout.contains("http://127.0.0.1:8789"),
        "every non-secret field must still print: {stdout}"
    );
}

#[test]
fn a_valid_config_still_drives_the_wallet_commands_unchanged() {
    // Paired happy path for the lazy load: an absent config and a valid config both behave
    // exactly as before.
    let home = TempDir::new().unwrap();
    let out = run(home.path(), &["wallet", "config"]);
    assert!(
        out.status.success(),
        "no config file at all is the fresh-install shape and must keep working"
    );

    write_config(
        home.path(),
        r#"{"default_privkey":null,"default_rpc_url":"http://127.0.0.1:8795","default_datadir":"/tmp/x","default_change_addr20":null}"#,
    );
    let out = run(home.path(), &["wallet", "config"]);
    let stdout = String::from_utf8_lossy(&out.stdout).to_string();
    assert!(out.status.success());
    assert!(stdout.contains("http://127.0.0.1:8795"));
    assert!(stdout.contains("/tmp/x"));
}

#[test]
fn a_config_written_by_the_cli_is_created_0600() {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;

        let home = TempDir::new().unwrap();
        let out = run(home.path(), &["wallet", "set-rpc", "--rpc-url", "http://127.0.0.1:8789"]);
        assert!(
            out.status.success(),
            "stderr={}",
            String::from_utf8_lossy(&out.stderr)
        );

        let p = home.path().join(".csd").join("config.json");
        let mode = std::fs::metadata(&p).unwrap().permissions().mode() & 0o777;
        assert_eq!(
            mode, 0o600,
            "the file that holds default_privkey must not be created world-readable"
        );
    }
}

// Every command that signs a transaction runs as upstream's does, with no flag gating it. Each
// run here ends on the test's missing or invalid key before any request (the key error names its
// own reason), and names an unroutable RPC, so nothing could reach a live node anyway.
#[test]
fn every_command_that_signs_a_transaction_runs_without_a_gate() {
    let home = TempDir::new().unwrap();
    const RPC: &str = "http://127.0.0.1:9";
    let commands: [(&str, Vec<&str>); 8] = [
        ("spend", vec!["spend", "--fee", "1"]),
        ("propose", vec!["propose", "--fee", "1", "--domain", "d", "--payload-hash", "00", "--rpc-url", RPC]),
        (
            "attest",
            vec!["attest", "--fee", "1", "--proposal-id", "00", "--score", "1", "--confidence", "1", "--rpc-url", RPC],
        ),
        ("wallet spend", vec!["wallet", "spend", "--privkey", "zz", "--fee", "1"]),
        (
            "wallet propose-build",
            vec!["wallet", "propose-build", "--privkey", "zz", "--fee", "1", "--domain", "d", "--payload-hash", "00", "--uri", "u", "--expires-epoch", "1"],
        ),
        (
            "wallet attest-build",
            vec!["wallet", "attest-build", "--privkey", "zz", "--fee", "1", "--proposal-id", "00", "--score", "1", "--confidence", "1"],
        ),
        (
            "wallet propose",
            vec!["wallet", "propose", "--privkey", "zz", "--fee", "1", "--domain", "d", "--payload-hash", "00", "--uri", "u", "--expires-epoch", "1", "--rpc-url", RPC],
        ),
        (
            "wallet attest",
            vec!["wallet", "attest", "--privkey", "zz", "--fee", "1", "--proposal-id", "00", "--score", "1", "--confidence", "1", "--rpc-url", RPC],
        ),
    ];

    for (name, args) in commands {
        let out = run(home.path(), &args);
        let stderr = String::from_utf8_lossy(&out.stderr).to_string();
        assert!(!stderr.contains("not supported"), "csd {name} is gated: {stderr}");
        assert!(!out.status.success(), "csd {name} ran with no usable key: {stderr}");
        assert!(
            stderr.contains("no private key provided") || stderr.contains("hex decode failed"),
            "csd {name} must stop on the test's key, for its own reason: {stderr}"
        );
    }

    // The flag is gone: clap refuses it as an unknown argument.
    let out = run(home.path(), &["spend", "--fee", "1", "--unsafe"]);
    let stderr = String::from_utf8_lossy(&out.stderr).to_string();
    assert!(!out.status.success() && stderr.contains("unexpected argument '--unsafe'"), "{stderr}");

    // A command that signs nothing runs too.
    let out = run(home.path(), &["chain", "expected-supply", "--height", "0"]);
    assert!(out.status.success());
}
