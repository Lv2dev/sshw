use anyhow::Result;
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use directories::BaseDirs;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CredentialPurpose {
    Login,
    Privilege,
}

impl CredentialPurpose {
    fn label(self) -> &'static str {
        match self {
            Self::Login => "login",
            Self::Privilege => "privilege",
        }
    }
}

/// Keyring namespace for a resolved home/profile.
///
/// New credential entries use an encoded, purpose-aware, generation-qualified
/// v2 key. Legacy v1 keys remain recognizable for existing configurations.
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

    pub fn legacy_credential_key(&self, server: &str) -> String {
        format!("sshw:{}:{}", self.token, server)
    }

    pub fn legacy_privilege_credential_key(&self, server: &str) -> String {
        format!("sshw:{}:privilege:{}", self.token, server)
    }

    /// Backward-compatible name for callers that still need the v1 login key.
    pub fn credential_key(&self, server: &str) -> String {
        self.legacy_credential_key(server)
    }

    /// Backward-compatible name for callers that still need the v1 privilege key.
    pub fn privilege_credential_key(&self, server: &str) -> String {
        self.legacy_privilege_credential_key(server)
    }

    pub fn new_credential_key(&self, purpose: CredentialPurpose, server: &str) -> String {
        self.credential_key_v2(purpose, server, &credential_generation())
    }

    pub fn credential_key_v2(
        &self,
        purpose: CredentialPurpose,
        server: &str,
        generation: &str,
    ) -> String {
        let token = URL_SAFE_NO_PAD.encode(self.token.as_bytes());
        let server = URL_SAFE_NO_PAD.encode(server.as_bytes());
        format!("sshw:v2:{token}:{}:{server}:{generation}", purpose.label())
    }

    pub fn credential_key_matches(
        &self,
        purpose: CredentialPurpose,
        server: &str,
        credential: &str,
    ) -> bool {
        let legacy = match purpose {
            CredentialPurpose::Login => self.legacy_credential_key(server),
            CredentialPurpose::Privilege => self.legacy_privilege_credential_key(server),
        };
        if credential == legacy {
            return true;
        }

        let mut parts = credential.split(':');
        let (
            Some(prefix),
            Some(version),
            Some(token),
            Some(key_purpose),
            Some(key_server),
            Some(generation),
        ) = (
            parts.next(),
            parts.next(),
            parts.next(),
            parts.next(),
            parts.next(),
            parts.next(),
        )
        else {
            return false;
        };
        if parts.next().is_some()
            || prefix != "sshw"
            || version != "v2"
            || key_purpose != purpose.label()
            || generation.is_empty()
            || !generation.bytes().all(|byte| byte.is_ascii_hexdigit())
        {
            return false;
        }

        let Ok(token) = URL_SAFE_NO_PAD.decode(token) else {
            return false;
        };
        let Ok(key_server) = URL_SAFE_NO_PAD.decode(key_server) else {
            return false;
        };
        token == self.token.as_bytes() && key_server == server.as_bytes()
    }
}

pub fn validate_server_name(name: &str) -> Result<()> {
    if name.trim().is_empty() {
        return Err(anyhow::anyhow!("server name cannot be empty"));
    }
    if name.chars().any(char::is_control) {
        return Err(anyhow::anyhow!(
            "server name must not contain control characters"
        ));
    }
    if name.starts_with("privilege:") {
        return Err(anyhow::anyhow!(
            "server name must not use the reserved 'privilege:' prefix"
        ));
    }
    Ok(())
}

fn credential_generation() -> String {
    static COUNTER: AtomicU64 = AtomicU64::new(0);

    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_nanos())
        .unwrap_or_default();
    let counter = COUNTER.fetch_add(1, Ordering::Relaxed);
    fnv1a_hex(&format!("{nanos}|{}|{counter}", std::process::id()))
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

/// Built-in default profile home: `<sshw_base>/profiles/default`. Used as the
/// final fallback in the home resolution chain
/// (`profile::resolve_home_with_registry`).
pub fn builtin_default_home(sshw_base: &Path) -> ResolvedHome {
    let root = sshw_base.join("profiles").join("default");
    ResolvedHome::profile(root, "default", "default profile".to_string())
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
    let normalized = lexical_normalize(&absolute);
    let text = normalized.to_string_lossy().to_string();
    // Windows and the default macOS filesystem are case-insensitive, so fold
    // case to keep the same directory mapping to one namespace.
    if cfg!(windows) || cfg!(target_os = "macos") {
        text.to_lowercase()
    } else {
        text
    }
}

/// Collapse `.` and `..` components lexically (without touching the filesystem)
/// so the same directory spelled differently hashes to one namespace.
fn lexical_normalize(path: &Path) -> PathBuf {
    use std::path::Component;

    let mut out = PathBuf::new();
    for component in path.components() {
        match component {
            Component::CurDir => {}
            Component::ParentDir => {
                out.pop();
            }
            other => out.push(other.as_os_str()),
        }
    }
    out
}

/// Profile ids reserved for the built-in default home and ad-hoc `--home`
/// namespaces. A registered profile must not reuse them, or it would share a
/// credential namespace with a different home.
pub fn is_reserved_profile_id(id: &str) -> bool {
    id.is_empty() || id == "default" || id.starts_with("home_")
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
