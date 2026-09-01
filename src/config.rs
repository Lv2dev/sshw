use crate::home::{CredentialNamespace, CredentialPurpose, validate_server_name};
use crate::storage::write_owner_only_atomic;
use anyhow::Context;
use serde::{Deserialize, Deserializer, Serialize};
use serde_json::Value;
use std::collections::BTreeMap;
use std::fs;
use std::path::Path;

const CONFIG_VERSION: u32 = 2;
const LEGACY_CONFIG_VERSION: u32 = 1;

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
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
            version: CONFIG_VERSION,
            default: None,
            servers: BTreeMap::new(),
            credential_backend: CredentialBackend::Native,
        }
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ConfigV2Wire {
    version: u32,
    default: Option<String>,
    servers: BTreeMap<String, ServerConfig>,
    #[serde(default)]
    credential_backend: CredentialBackend,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ConfigV1Wire {
    version: u32,
    default: Option<String>,
    servers: BTreeMap<String, ServerConfigV1>,
    #[serde(default)]
    privileges: BTreeMap<String, PrivilegeConfig>,
    #[serde(default)]
    credential_backend: CredentialBackend,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ServerConfigV1 {
    host: String,
    port: u16,
    user: String,
    auth: AuthConfig,
}

impl<'de> Deserialize<'de> for SshwConfig {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value = Value::deserialize(deserializer)?;
        let version = value
            .get("version")
            .and_then(Value::as_u64)
            .ok_or_else(|| serde::de::Error::missing_field("version"))?;
        let version = u32::try_from(version)
            .map_err(|_| serde::de::Error::custom("config version is out of range"))?;

        match version {
            CONFIG_VERSION => {
                let wire: ConfigV2Wire =
                    serde_json::from_value(value).map_err(serde::de::Error::custom)?;
                debug_assert_eq!(wire.version, CONFIG_VERSION);
                Ok(Self {
                    version: CONFIG_VERSION,
                    default: wire.default,
                    servers: wire.servers,
                    credential_backend: wire.credential_backend,
                })
            }
            LEGACY_CONFIG_VERSION => {
                let wire: ConfigV1Wire =
                    serde_json::from_value(value).map_err(serde::de::Error::custom)?;
                migrate_v1(wire).map_err(serde::de::Error::custom)
            }
            unsupported => Err(serde::de::Error::custom(format!(
                "unsupported config version {unsupported}; supported versions are {LEGACY_CONFIG_VERSION} and {CONFIG_VERSION}"
            ))),
        }
    }
}

fn migrate_v1(mut wire: ConfigV1Wire) -> Result<SshwConfig, String> {
    debug_assert_eq!(wire.version, LEGACY_CONFIG_VERSION);
    let mut servers = BTreeMap::new();
    for (name, server) in wire.servers {
        let privilege = wire.privileges.remove(&name);
        let default_user = server.user;
        let mut accounts = BTreeMap::new();
        accounts.insert(
            default_user.clone(),
            AccountConfig {
                auth: server.auth,
                privilege,
            },
        );
        servers.insert(
            name,
            ServerConfig {
                host: server.host,
                port: server.port,
                default_user,
                accounts,
            },
        );
    }
    if let Some(orphan) = wire.privileges.keys().next() {
        return Err(format!(
            "privilege configuration for server '{orphan}' has no matching server"
        ));
    }
    Ok(SshwConfig {
        version: CONFIG_VERSION,
        default: wire.default,
        servers,
        credential_backend: wire.credential_backend,
    })
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
    pub default_user: String,
    pub accounts: BTreeMap<String, AccountConfig>,
}

impl ServerConfig {
    pub fn single_account(
        host: impl Into<String>,
        port: u16,
        user: impl Into<String>,
        auth: AuthConfig,
    ) -> Self {
        let user = user.into();
        let mut accounts = BTreeMap::new();
        accounts.insert(
            user.clone(),
            AccountConfig {
                auth,
                privilege: None,
            },
        );
        Self {
            host: host.into(),
            port,
            default_user: user,
            accounts,
        }
    }

    pub fn default_account(&self) -> Option<(&str, &AccountConfig)> {
        self.accounts
            .get_key_value(&self.default_user)
            .map(|(user, account)| (user.as_str(), account))
    }

    pub fn account(&self, user: &str) -> Option<&AccountConfig> {
        self.accounts.get(user)
    }

    pub fn account_mut(&mut self, user: &str) -> Option<&mut AccountConfig> {
        self.accounts.get_mut(user)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct AccountConfig {
    pub auth: AuthConfig,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub privilege: Option<PrivilegeConfig>,
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
        if !server.accounts.contains_key(&server.default_user) {
            return Err(anyhow::anyhow!(
                "default user '{}' is not registered for server '{name}'",
                server.default_user
            ));
        }
        for (user, account) in &server.accounts {
            validate_account_user(user).map_err(|err| {
                anyhow::anyhow!("invalid user '{user}' for server '{name}': {err}")
            })?;
            if let AuthConfig::Password { credential } = &account.auth {
                validate_credential_owner(
                    namespace,
                    CredentialPurpose::Login,
                    name,
                    user,
                    credential,
                    &mut owners,
                )?;
            }
            if let Some(privilege) = &account.privilege {
                validate_credential_owner(
                    namespace,
                    CredentialPurpose::Privilege,
                    name,
                    user,
                    &privilege.credential,
                    &mut owners,
                )?;
            }
        }
    }

    Ok(())
}

fn validate_credential_owner<'a>(
    namespace: &CredentialNamespace,
    purpose: CredentialPurpose,
    server: &str,
    user: &str,
    credential: &'a str,
    owners: &mut BTreeMap<&'a str, String>,
) -> anyhow::Result<()> {
    if !namespace.account_credential_key_matches(purpose, server, user, credential)
        && !namespace.credential_key_matches(purpose, server, credential)
    {
        return Err(anyhow::anyhow!(
            "credential reference does not belong to account '{server}/{user}' in the active home"
        ));
    }

    let purpose_label = match purpose {
        CredentialPurpose::Login => "login",
        CredentialPurpose::Privilege => "privilege",
    };
    let owner = format!("{purpose_label}:{server}/{user}");
    if let Some(previous) = owners.insert(credential, owner.clone()) {
        return Err(anyhow::anyhow!(
            "credential key collision between '{previous}' and '{owner}'"
        ));
    }
    Ok(())
}

pub fn validate_account_user(user: &str) -> anyhow::Result<()> {
    if user.trim().is_empty() {
        return Err(anyhow::anyhow!("user cannot be empty"));
    }
    if user.chars().any(char::is_control) {
        return Err(anyhow::anyhow!("user must not contain control characters"));
    }
    Ok(())
}
