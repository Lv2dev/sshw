use directories::BaseDirs;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SshwConfig {
    pub version: u32,
    pub default: Option<String>,
    pub servers: BTreeMap<String, ServerConfig>,
}

impl Default for SshwConfig {
    fn default() -> Self {
        Self {
            version: 1,
            default: None,
            servers: BTreeMap::new(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ServerConfig {
    pub host: String,
    pub port: u16,
    pub user: String,
    pub auth: AuthConfig,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "type", rename_all = "lowercase")]
pub enum AuthConfig {
    Password { credential: String },
    Agent,
}

pub fn default_config_path() -> anyhow::Result<PathBuf> {
    let dirs = BaseDirs::new()
        .ok_or_else(|| anyhow::anyhow!("could not determine user config directory"))?;
    Ok(dirs.config_dir().join("sshw").join("servers.json"))
}

pub fn load_config(path: &Path) -> anyhow::Result<SshwConfig> {
    if !path.exists() {
        return Ok(SshwConfig::default());
    }

    let contents = fs::read_to_string(path)?;
    let config = serde_json::from_str(&contents)?;
    Ok(config)
}

pub fn save_config(path: &Path, config: &SshwConfig) -> anyhow::Result<()> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }

    let contents = serde_json::to_string_pretty(config)?;
    fs::write(path, contents)?;
    Ok(())
}
