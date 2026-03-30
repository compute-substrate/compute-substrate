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

pub fn save_config(cfg: &CliConfig) -> Result<()> {
    let path = config_path()?;
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)
            .with_context(|| format!("failed to create {}", parent.display()))?;
    }

    let bytes = serde_json::to_vec_pretty(cfg)?;
    fs::write(&path, bytes)
        .with_context(|| format!("failed to write config {}", path.display()))?;
    Ok(())
}
