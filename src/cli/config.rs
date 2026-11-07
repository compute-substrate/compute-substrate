use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::PathBuf;

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct CliConfig {
    pub default_privkey: Option<String>,
    pub default_rpc_url: Option<String>,
    pub default_datadir: Option<String>,
    pub default_change_addr20: Option<String>,
}

pub fn config_path() -> Result<PathBuf> {
    let home = std::env::var("HOME").context("HOME not set")?;
    Ok(PathBuf::from(home).join(".csd").join("config.json"))
}

pub fn load_config() -> Result<CliConfig> {
    let path = config_path()?;
    if !path.exists() {
        return Ok(CliConfig::default());
    }

    let bytes = fs::read(&path)
        .with_context(|| format!("failed to read config {}", path.display()))?;
    let cfg = serde_json::from_slice::<CliConfig>(&bytes)
        .with_context(|| format!("failed to parse config {}", path.display()))?;
    Ok(cfg)
}

/// The private key is never printed. The placeholder
/// is deliberately not a masked prefix: a prefix of a 32-byte key is still key material.
pub const REDACTED_PRIVKEY: &str = "<redacted: see ~/.csd/config.json>";

pub fn redacted_config(cfg: &CliConfig) -> CliConfig {
    let mut out = cfg.clone();
    if out.default_privkey.is_some() {
        out.default_privkey = Some(REDACTED_PRIVKEY.to_string());
    }
    out
}

pub fn save_config(cfg: &CliConfig) -> Result<()> {
    let path = config_path()?;
    save_config_at(&path, cfg)
}

/// This file holds `default_privkey`, and `fs::write`
/// creates with 0666 masked by the umask, i.e. 0644 on a default shell. Create it 0600.
///
/// Note the honest limit: `OpenOptions::mode` applies at CREATION only, so a config file that
/// already exists keeps whatever mode it has; an existing file is not chmodded here.
pub fn save_config_at(path: &std::path::Path, cfg: &CliConfig) -> Result<()> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)
            .with_context(|| format!("failed to create {}", parent.display()))?;
    }

    let bytes = serde_json::to_vec_pretty(cfg)?;

    #[cfg(unix)]
    {
        use std::io::Write;
        use std::os::unix::fs::OpenOptionsExt;

        let mut f = fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .mode(0o600)
            .open(path)
            .with_context(|| format!("failed to write config {}", path.display()))?;
        f.write_all(&bytes)
            .with_context(|| format!("failed to write config {}", path.display()))?;
        return Ok(());
    }

    #[cfg(not(unix))]
    {
        fs::write(path, bytes)
            .with_context(|| format!("failed to write config {}", path.display()))?;
        Ok(())
    }
}

// ── tests: private key exposure ────────────────────────────────────────────────────────────────
#[cfg(test)]
mod key_exposure_tests {
    use super::*;
    use tempfile::TempDir;

    fn sample() -> CliConfig {
        CliConfig {
            default_privkey: Some(
                "1111111111111111111111111111111111111111111111111111111111111111".to_string(),
            ),
            default_rpc_url: Some("http://127.0.0.1:8789".to_string()),
            default_datadir: Some("/opt/substrate_miner/node-db".to_string()),
            default_change_addr20: Some("0x00000000000000000000000000000000000000ff".to_string()),
        }
    }

    #[test]
    fn printed_config_never_contains_the_private_key() {
        let cfg = sample();
        let shown = redacted_config(&cfg);
        let json = serde_json::to_string_pretty(&shown).unwrap();

        let key = cfg.default_privkey.as_deref().unwrap();
        assert!(
            !json.contains(key),
            "`csd wallet config` must not print default_privkey"
        );
        // Not even a prefix: a prefix of a 32-byte key is still key material.
        assert!(!json.contains(&key[..8]), "not even a prefix of the key");
        assert!(json.contains(REDACTED_PRIVKEY), "the field must still be shown as present");

        // Paired happy path: every other field is untouched, so the command stays useful.
        assert_eq!(shown.default_rpc_url, cfg.default_rpc_url);
        assert_eq!(shown.default_datadir, cfg.default_datadir);
        assert_eq!(shown.default_change_addr20, cfg.default_change_addr20);
    }

    #[test]
    fn a_config_with_no_key_is_printed_unchanged() {
        let mut cfg = sample();
        cfg.default_privkey = None;
        let shown = redacted_config(&cfg);
        assert!(shown.default_privkey.is_none(), "no placeholder is invented");
        assert_eq!(
            serde_json::to_string_pretty(&shown).unwrap(),
            serde_json::to_string_pretty(&cfg).unwrap()
        );
    }

    #[cfg(unix)]
    #[test]
    fn a_freshly_created_config_is_0600_and_round_trips() {
        use std::os::unix::fs::PermissionsExt;

        let tmp = TempDir::new().unwrap();
        let path = tmp.path().join(".csd").join("config.json");
        let cfg = sample();

        save_config_at(&path, &cfg).unwrap();

        let mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
        assert_eq!(
            mode, 0o600,
            "this file holds default_privkey; fs::write creates it 0644 under a default umask"
        );

        // Paired happy path: the file the CLI writes is still the file the CLI reads.
        let bytes = std::fs::read(&path).unwrap();
        let back: CliConfig = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(back.default_privkey, cfg.default_privkey);
        assert_eq!(back.default_rpc_url, cfg.default_rpc_url);
        assert_eq!(back.default_datadir, cfg.default_datadir);
        assert_eq!(back.default_change_addr20, cfg.default_change_addr20);

        // Rewriting truncates rather than leaving a tail of the previous, longer content.
        let mut shorter = CliConfig::default();
        shorter.default_rpc_url = Some("http://127.0.0.1:8795".to_string());
        save_config_at(&path, &shorter).unwrap();
        let back2: CliConfig = serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
        assert!(back2.default_privkey.is_none());
        assert_eq!(back2.default_rpc_url, shorter.default_rpc_url);
    }
}
