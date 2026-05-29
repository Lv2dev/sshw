use crate::storage::write_owner_only_atomic;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::fs;
use std::path::Path;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SshwConfig {
    pub version: u32,
    pub default: Option<String>,
    pub servers: BTreeMap<String, ServerConfig>,
    /// Which credential backend this home uses. Defaults to the native OS
    /// keyring; older config files without the field load as `native`.
    #[serde(default)]
    pub credential_backend: CredentialBackend,
}

impl Default for SshwConfig {
    fn default() -> Self {
        Self {
            version: 1,
            default: None,
            servers: BTreeMap::new(),
            credential_backend: CredentialBackend::Native,
        }
    }
}

/// Selects the credential store implementation. `native` uses the OS keyring;
/// `session_only` keeps secrets in memory for the invocation (e.g. supplied
/// via `SSHW_PASSWORD`) and never persists them. An external-helper backend is
/// a planned extension behind the same `CredentialStore` trait.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Default)]
#[serde(rename_all = "snake_case")]
pub enum CredentialBackend {
    #[default]
    Native,
    SessionOnly,
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

pub fn load_config(path: &Path) -> anyhow::Result<SshwConfig> {
    if !path.exists() {
        return Ok(SshwConfig::default());
    }

    let contents = fs::read_to_string(path)
        .map_err(|err| anyhow::anyhow!("failed to load config at {}: {err}", path.display()))?;
    let config = serde_json::from_str(&contents)
        .map_err(|err| anyhow::anyhow!("failed to load config at {}: {err}", path.display()))?;
    Ok(config)
}

pub fn save_config(path: &Path, config: &SshwConfig) -> anyhow::Result<()> {
    let contents = serde_json::to_string_pretty(config)?;
    write_owner_only_atomic(path, &contents)
        .map_err(|err| anyhow::anyhow!("failed to save config at {}: {err}", path.display()))
}
