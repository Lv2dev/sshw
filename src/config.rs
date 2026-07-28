use crate::home::{CredentialNamespace, CredentialPurpose, validate_server_name};
use crate::storage::write_owner_only_atomic;
use anyhow::Context;
use serde::{Deserialize, Deserializer, Serialize};
use std::collections::BTreeMap;
use std::fs;
use std::path::Path;

const CONFIG_VERSION: u32 = 1;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct SshwConfig {
    pub version: u32,
    pub default: Option<String>,
    pub servers: BTreeMap<String, ServerConfig>,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub privileges: BTreeMap<String, PrivilegeConfig>,
    /// Which credential backend this home uses. Defaults to the native OS
    /// keyring; older config files without the field load as `native`.
    #[serde(default)]
    pub credential_backend: CredentialBackend,
}

impl Default for SshwConfig {
    fn default() -> Self {
        Self {
            version: CONFIG_VERSION,
            default: None,
            servers: BTreeMap::new(),
            privileges: BTreeMap::new(),
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
#[serde(deny_unknown_fields)]
pub struct ServerConfig {
    pub host: String,
    pub port: u16,
    pub user: String,
    pub auth: AuthConfig,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
#[serde(tag = "type", rename_all = "lowercase")]
pub enum AuthConfig {
    Password { credential: String },
    Agent,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct AuthConfigWire {
    #[serde(rename = "type")]
    kind: AuthKind,
    #[serde(default)]
    credential: Option<String>,
}

#[derive(Deserialize)]
#[serde(rename_all = "lowercase")]
enum AuthKind {
    Password,
    Agent,
}

impl<'de> Deserialize<'de> for AuthConfig {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let wire = AuthConfigWire::deserialize(deserializer)?;
        match (wire.kind, wire.credential) {
            (AuthKind::Password, Some(credential)) => Ok(Self::Password { credential }),
            (AuthKind::Password, None) => Err(serde::de::Error::missing_field("credential")),
            (AuthKind::Agent, None) => Ok(Self::Agent),
            (AuthKind::Agent, Some(_)) => Err(serde::de::Error::custom(
                "unknown field `credential` for agent authentication",
            )),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct PrivilegeConfig {
    pub method: PrivilegeMethod,
    #[serde(default = "default_privilege_user")]
    pub user: String,
    pub credential: String,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum PrivilegeMethod {
    Sudo,
    Su,
}

fn default_privilege_user() -> String {
    "root".to_string()
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConfigRevision(Option<Vec<u8>>);

impl ConfigRevision {
    pub fn missing() -> Self {
        Self(None)
    }
}

pub fn load_config(path: &Path) -> anyhow::Result<SshwConfig> {
    load_config_with_revision(path).map(|(config, _revision)| config)
}

pub fn load_config_with_revision(path: &Path) -> anyhow::Result<(SshwConfig, ConfigRevision)> {
    let Some(contents) = read_config_contents(path)? else {
        return Ok((SshwConfig::default(), ConfigRevision::missing()));
    };
    let config: SshwConfig = serde_json::from_str(&contents)
        .map_err(|err| anyhow::anyhow!("failed to load config at {}: {err}", path.display()))?;
    if config.version != CONFIG_VERSION {
        return Err(anyhow::anyhow!(
            "failed to load config at {}: unsupported config version {}; supported version is {CONFIG_VERSION}",
            path.display(),
            config.version
        ));
    }
    let revision = ConfigRevision(Some(contents.into_bytes()));
    Ok((config, revision))
}

fn read_config_contents(path: &Path) -> anyhow::Result<Option<String>> {
    let contents = match fs::read_to_string(path) {
        Ok(contents) => contents,
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => {
            match fs::symlink_metadata(path) {
                Err(metadata_err) if metadata_err.kind() == std::io::ErrorKind::NotFound => {
                    return Ok(None);
                }
                Err(metadata_err) => {
                    return Err(anyhow::anyhow!(
                        "failed to load config at {}: {metadata_err}",
                        path.display()
                    ));
                }
                Ok(_) => {
                    return Err(anyhow::anyhow!(
                        "failed to load config at {}: {err}",
                        path.display()
                    ));
                }
            }
        }
        Err(err) => {
            return Err(anyhow::anyhow!(
                "failed to load config at {}: {err}",
                path.display()
            ));
        }
    };
    Ok(Some(contents))
}

pub fn save_config(path: &Path, config: &SshwConfig) -> anyhow::Result<()> {
    let contents = serde_json::to_string_pretty(config)?;
    write_owner_only_atomic(path, &contents)
        .with_context(|| format!("failed to save config at {}", path.display()))
}

pub fn save_config_if_unchanged(
    path: &Path,
    config: &SshwConfig,
    revision: &ConfigRevision,
) -> anyhow::Result<()> {
    let current = read_config_contents(path)
        .map_err(|err| {
            anyhow::anyhow!(
                "failed to save config at {} while checking its revision: {err}",
                path.display()
            )
        })?
        .map(String::into_bytes);
    if current != revision.0 {
        return Err(anyhow::anyhow!(
            "failed to save config at {}: config changed concurrently; retry the command",
            path.display()
        ));
    }
    save_config(path, config)
}

pub fn validate_config_credential_references(
    config: &SshwConfig,
    namespace: &CredentialNamespace,
) -> anyhow::Result<()> {
    let mut owners = BTreeMap::<&str, String>::new();

    if let Some(default) = config.default.as_deref() {
        validate_server_name(default)
            .map_err(|err| anyhow::anyhow!("invalid server name '{default}': {err}"))?;
        if !config.servers.contains_key(default) {
            return Err(anyhow::anyhow!(
                "default server '{default}' is not present in the config"
            ));
        }
    }

    for (name, server) in &config.servers {
        validate_server_name(name)
            .map_err(|err| anyhow::anyhow!("invalid server name '{name}': {err}"))?;
        if let AuthConfig::Password { credential } = &server.auth {
            validate_credential_owner(
                namespace,
                CredentialPurpose::Login,
                name,
                credential,
                &mut owners,
            )?;
        }
    }

    for (name, privilege) in &config.privileges {
        validate_server_name(name)
            .map_err(|err| anyhow::anyhow!("invalid server name '{name}': {err}"))?;
        validate_credential_owner(
            namespace,
            CredentialPurpose::Privilege,
            name,
            &privilege.credential,
            &mut owners,
        )?;
        if !config.servers.contains_key(name) {
            return Err(anyhow::anyhow!(
                "privilege configuration for server '{name}' has no matching server"
            ));
        }
    }

    Ok(())
}

fn validate_credential_owner<'a>(
    namespace: &CredentialNamespace,
    purpose: CredentialPurpose,
    server: &str,
    credential: &'a str,
    owners: &mut BTreeMap<&'a str, String>,
) -> anyhow::Result<()> {
    if !namespace.credential_key_matches(purpose, server, credential) {
        return Err(anyhow::anyhow!(
            "credential reference for server '{server}' does not belong to the active home"
        ));
    }

    let purpose_label = match purpose {
        CredentialPurpose::Login => "login",
        CredentialPurpose::Privilege => "privilege",
    };
    let owner = format!("{purpose_label}:{server}");
    if let Some(previous) = owners.insert(credential, owner.clone()) {
        return Err(anyhow::anyhow!(
            "credential key collision between '{previous}' and '{owner}'"
        ));
    }
    Ok(())
}
