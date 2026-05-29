use anyhow::Result;
use directories::BaseDirs;
use std::ffi::OsStr;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

/// Keyring namespace for a resolved home/profile.
///
/// Credential entries are always namespaced as `sshw:<token>:<server>` so that
/// the same server name in different profiles/homes never collides in the OS
/// credential store.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CredentialNamespace {
    token: String,
}

impl CredentialNamespace {
    /// Namespace for a registered profile, keyed by its stable profile id.
    pub fn profile(id: &str) -> Self {
        Self {
            token: id.to_string(),
        }
    }

    /// Namespace for an ad-hoc home directory (not in the registry), derived
    /// from a stable hash of the canonical home path.
    pub fn for_home(home: &Path) -> Self {
        Self {
            token: format!("home_{}", fnv1a_hex(&canonical_key(home))),
        }
    }

    pub fn token(&self) -> &str {
        &self.token
    }

    pub fn credential_key(&self, server: &str) -> String {
        format!("sshw:{}:{}", self.token, server)
    }
}

/// Filesystem layout + credential namespace for the active home.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResolvedHome {
    pub root: PathBuf,
    pub config_path: PathBuf,
    pub known_hosts_path: PathBuf,
    pub policy_path: PathBuf,
    pub audit_path: PathBuf,
    pub namespace: CredentialNamespace,
    /// Human-readable description of how this home was selected (for `doctor`).
    pub description: String,
}

impl ResolvedHome {
    fn for_root(root: PathBuf, namespace: CredentialNamespace, description: String) -> Self {
        Self {
            config_path: root.join("servers.json"),
            known_hosts_path: root.join("known_hosts"),
            policy_path: root.join("policy.json"),
            audit_path: root.join("audit.jsonl"),
            namespace,
            description,
            root,
        }
    }

    /// Ad-hoc home rooted at an explicit directory (used by `--home`/`SSHW_HOME`).
    pub fn ad_hoc(root: &Path, description: String) -> Self {
        let namespace = CredentialNamespace::for_home(root);
        Self::for_root(root.to_path_buf(), namespace, description)
    }

    /// Registered/built-in profile home rooted at an explicit directory.
    pub fn profile(root: PathBuf, profile_id: &str, description: String) -> Self {
        Self::for_root(root, CredentialNamespace::profile(profile_id), description)
    }

    /// Derive an ad-hoc home from an explicit `servers.json` path. Used by the
    /// backward-compatible `cli::execute` facade and tests that pass a config
    /// path directly: the parent directory is treated as the home root.
    pub fn from_config_path(config_path: &Path) -> Self {
        let root = config_path
            .parent()
            .map(Path::to_path_buf)
            .unwrap_or_else(|| PathBuf::from("."));
        let namespace = CredentialNamespace::for_home(&root);
        Self {
            config_path: config_path.to_path_buf(),
            known_hosts_path: root.join("known_hosts"),
            policy_path: root.join("policy.json"),
            audit_path: root.join("audit.jsonl"),
            namespace,
            description: format!("ad-hoc home {}", root.display()),
            root,
        }
    }
}

/// `<config_dir>/sshw` — the per-user sshw base directory.
pub fn sshw_base_dir() -> Result<PathBuf> {
    let dirs = BaseDirs::new()
        .ok_or_else(|| anyhow::anyhow!("could not determine user config directory"))?;
    Ok(dirs.config_dir().join("sshw"))
}

/// Built-in default profile home: `<config_dir>/sshw/profiles/default`.
pub fn default_home_dir() -> Result<PathBuf> {
    Ok(sshw_base_dir()?.join("profiles").join("default"))
}

/// Resolve the active home from the `--home` flag and `SSHW_HOME` env, falling
/// back to the built-in default profile home under `sshw_base`.
///
/// Priority: `--home` > `SSHW_HOME` > built-in default profile home. (M16 will
/// insert `--profile`/registry-default selection between the env var and the
/// built-in default.)
pub fn resolve_home(
    home_flag: Option<&Path>,
    env_home: Option<&OsStr>,
    sshw_base: &Path,
) -> ResolvedHome {
    if let Some(path) = home_flag {
        return ResolvedHome::ad_hoc(path, format!("--home {}", path.display()));
    }
    if let Some(env) = env_home {
        let path = Path::new(env);
        return ResolvedHome::ad_hoc(path, format!("SSHW_HOME {}", path.display()));
    }
    builtin_default_home(sshw_base)
}

/// Built-in default profile home: `<sshw_base>/profiles/default`.
pub fn builtin_default_home(sshw_base: &Path) -> ResolvedHome {
    let root = sshw_base.join("profiles").join("default");
    ResolvedHome::profile(root, "default", "default profile".to_string())
}

/// Path to the global profile registry: `<config_dir>/sshw/profiles.json`.
pub fn registry_path() -> Result<PathBuf> {
    Ok(sshw_base_dir()?.join("profiles.json"))
}

/// Generate a stable, persisted profile id from the profile name and home path.
/// The current time is mixed in so re-adding a removed name yields a fresh
/// namespace; the id is persisted in the registry and never recomputed.
pub fn generate_profile_id(name: &str, home: &Path) -> String {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_nanos())
        .unwrap_or_default();
    format!(
        "p_{}",
        fnv1a_hex(&format!("{}|{}|{}", canonical_key(home), name, nanos))
    )
}

/// Logical absolute path used as a stable hashing key. Does not require the
/// path to exist; on Windows the result is lowercased because paths there are
/// case-insensitive.
fn canonical_key(path: &Path) -> String {
    let absolute = std::path::absolute(path).unwrap_or_else(|_| path.to_path_buf());
    let text = absolute.to_string_lossy().to_string();
    if cfg!(windows) {
        text.to_lowercase()
    } else {
        text
    }
}

/// Deterministic FNV-1a 64-bit hash, hex encoded. Used only for credential
/// namespace separation, not for any security guarantee.
fn fnv1a_hex(input: &str) -> String {
    const OFFSET: u64 = 0xcbf2_9ce4_8422_2325;
    const PRIME: u64 = 0x0000_0100_0000_01b3;
    let mut hash = OFFSET;
    for byte in input.as_bytes() {
        hash ^= u64::from(*byte);
        hash = hash.wrapping_mul(PRIME);
    }
    format!("{hash:016x}")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fnv1a_is_deterministic_and_distinct() {
        assert_eq!(fnv1a_hex("abc"), fnv1a_hex("abc"));
        assert_ne!(fnv1a_hex("abc"), fnv1a_hex("abd"));
    }

    #[test]
    fn fnv1a_matches_known_vector() {
        // FNV-1a 64-bit of empty input is the offset basis.
        assert_eq!(fnv1a_hex(""), "cbf29ce484222325");
    }
}
