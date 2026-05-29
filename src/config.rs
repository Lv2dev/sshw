use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

#[cfg(unix)]
use std::os::unix::fs::OpenOptionsExt;

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
    let temp_path = temp_config_path(path);
    write_config_file(&temp_path, &contents)?;
    replace_config_file(&temp_path, path)?;
    set_config_permissions(path)?;
    Ok(())
}

fn temp_config_path(path: &Path) -> PathBuf {
    let file_name = path
        .file_name()
        .map(|name| name.to_string_lossy())
        .unwrap_or_else(|| "servers.json".into());
    let suffix = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_nanos())
        .unwrap_or_default();
    path.with_file_name(format!(
        ".{file_name}.{}.{}.tmp",
        std::process::id(),
        suffix
    ))
}

fn write_config_file(path: &Path, contents: &str) -> anyhow::Result<()> {
    let mut options = fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    options.mode(0o600);

    let mut file = options.open(path)?;
    file.write_all(contents.as_bytes())?;
    file.sync_all()?;
    Ok(())
}

fn replace_config_file(temp_path: &Path, path: &Path) -> anyhow::Result<()> {
    tempfile::TempPath::try_from_path(temp_path)?.persist(path)?;
    Ok(())
}

#[cfg(unix)]
fn set_config_permissions(path: &Path) -> anyhow::Result<()> {
    use std::os::unix::fs::PermissionsExt;

    fs::set_permissions(path, fs::Permissions::from_mode(0o600))?;
    Ok(())
}

#[cfg(not(unix))]
fn set_config_permissions(_path: &Path) -> anyhow::Result<()> {
    Ok(())
}

#[cfg(all(test, windows))]
mod tests {
    use super::replace_config_file;
    use std::fs;

    #[test]
    fn windows_replace_preserves_destination_when_rename_fails() {
        let temp = tempfile::tempdir().unwrap();
        let destination = temp.path().join("servers.json");
        let missing_temp = temp.path().join("missing.tmp");
        fs::write(&destination, "original").unwrap();

        let _err = replace_config_file(&missing_temp, &destination).unwrap_err();

        assert_eq!(fs::read_to_string(destination).unwrap(), "original");
    }
}
