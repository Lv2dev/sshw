use anyhow::Result;
use serde::{Deserialize, Deserializer, Serialize};
use serde_json::Value;
use std::fs;
use std::path::Path;

const POLICY_VERSION: u32 = 2;
const LEGACY_POLICY_VERSION: u32 = 1;

/// On-disk policy document (`<home>/policy.json`). Every field defaults so a
/// minimal `{ "enabled": true, "allow_commands": ["ls"] }` parses.
#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct PolicyFile {
    pub version: u32,
    #[serde(default)]
    pub enabled: bool,
    #[serde(default)]
    pub allow_commands: Vec<String>,
    #[serde(default)]
    pub allow_put_paths: Vec<String>,
    #[serde(default)]
    pub allow_get_paths: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub allow_accounts: Vec<AccountRule>,
}

impl Default for PolicyFile {
    fn default() -> Self {
        Self {
            version: POLICY_VERSION,
            enabled: false,
            allow_commands: Vec::new(),
            allow_put_paths: Vec::new(),
            allow_get_paths: Vec::new(),
            allow_accounts: Vec::new(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct AccountRule {
    pub server: String,
    pub user: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct PolicyV1Wire {
    #[serde(default = "legacy_policy_version")]
    version: u32,
    #[serde(default)]
    enabled: bool,
    #[serde(default)]
    allow_commands: Vec<String>,
    #[serde(default)]
    allow_put_paths: Vec<String>,
    #[serde(default)]
    allow_get_paths: Vec<String>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct PolicyV2Wire {
    version: u32,
    #[serde(default)]
    enabled: bool,
    #[serde(default)]
    allow_commands: Vec<String>,
    #[serde(default)]
    allow_put_paths: Vec<String>,
    #[serde(default)]
    allow_get_paths: Vec<String>,
    #[serde(default)]
    allow_accounts: Vec<AccountRule>,
}

impl<'de> Deserialize<'de> for PolicyFile {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value = Value::deserialize(deserializer)?;
        let version = match value.get("version") {
            Some(value) => value
                .as_u64()
                .ok_or_else(|| serde::de::Error::custom("policy version must be an integer"))?,
            None => u64::from(LEGACY_POLICY_VERSION),
        };
        let version = u32::try_from(version)
            .map_err(|_| serde::de::Error::custom("policy version is out of range"))?;

        match version {
            LEGACY_POLICY_VERSION => {
                let wire: PolicyV1Wire =
                    serde_json::from_value(value).map_err(serde::de::Error::custom)?;
                debug_assert_eq!(wire.version, LEGACY_POLICY_VERSION);
                Ok(Self {
                    version: POLICY_VERSION,
                    enabled: wire.enabled,
                    allow_commands: wire.allow_commands,
                    allow_put_paths: wire.allow_put_paths,
                    allow_get_paths: wire.allow_get_paths,
                    allow_accounts: Vec::new(),
                })
            }
            POLICY_VERSION => {
                let wire: PolicyV2Wire =
                    serde_json::from_value(value).map_err(serde::de::Error::custom)?;
                debug_assert_eq!(wire.version, POLICY_VERSION);
                Ok(Self {
                    version: POLICY_VERSION,
                    enabled: wire.enabled,
                    allow_commands: wire.allow_commands,
                    allow_put_paths: wire.allow_put_paths,
                    allow_get_paths: wire.allow_get_paths,
                    allow_accounts: wire.allow_accounts,
                })
            }
            unsupported => Err(serde::de::Error::custom(format!(
                "unsupported policy version {unsupported}; supported versions are {LEGACY_POLICY_VERSION} and {POLICY_VERSION}"
            ))),
        }
    }
}

fn legacy_policy_version() -> u32 {
    LEGACY_POLICY_VERSION
}

/// Resolved enforcement state for an invocation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Policy {
    Disabled,
    Enabled(PolicyRules),
}

/// Allowlist rules used by an enforcing sandbox.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PolicyRules {
    allow_commands: Vec<String>,
    allow_put_paths: Vec<String>,
    allow_get_paths: Vec<String>,
    allow_accounts: Vec<AccountRule>,
}

impl PolicyRules {
    pub fn allows_command(&self, command: &str) -> bool {
        self.command_match(command).is_some()
    }

    fn command_match(&self, command: &str) -> Option<(&str, &'static str)> {
        let command = command.trim();
        let has_meta = contains_shell_metacharacters(command);
        self.allow_commands.iter().find_map(|entry| {
            let entry = entry.trim();
            if entry.is_empty() {
                return None;
            }
            // An exact full-command entry is always honored.
            if entry == command {
                let kind = if has_meta {
                    "exact"
                } else {
                    command_matches_simple(entry, command).unwrap_or("exact")
                };
                return Some((entry, kind));
            }
            // A command containing shell metacharacters can do more than run a
            // single program, so program-name / glob matches must not apply to
            // it: only an exact allowlist entry permits it.
            if has_meta {
                return None;
            }
            command_matches_simple(entry, command).map(|kind| (entry, kind))
        })
    }

    pub fn allows_put(&self, remote_path: &str) -> bool {
        path_is_allowed(&self.allow_put_paths, remote_path)
    }

    pub fn allows_get(&self, remote_path: &str) -> bool {
        path_is_allowed(&self.allow_get_paths, remote_path)
    }

    pub fn allows_account(&self, server: &str, user: &str, is_default: bool) -> bool {
        is_default || self.account_match(server, user).is_some()
    }

    fn account_match(&self, server: &str, user: &str) -> Option<&AccountRule> {
        self.allow_accounts
            .iter()
            .find(|entry| entry.server == server && entry.user == user)
    }
}

/// A policy-only decision, independent of safety, account existence and I/O.
/// Strings are redacted by the presentation layer before being displayed.
#[derive(Debug, Serialize)]
pub(crate) struct PolicyExplanation {
    pub allowed: bool,
    pub reason: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub matched_rule: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub match_type: Option<&'static str>,
}

impl PolicyExplanation {
    fn decision(allowed: bool, reason: &'static str) -> Self {
        Self {
            allowed,
            reason,
            matched_rule: None,
            match_type: None,
        }
    }

    fn matched(rule: &str, kind: &'static str) -> Self {
        Self {
            matched_rule: Some(rule.to_string()),
            match_type: Some(kind),
            ..Self::decision(true, "matched_rule")
        }
    }
}

impl Policy {
    pub(crate) fn explain_command(&self, command: &str) -> PolicyExplanation {
        let Self::Enabled(rules) = self else {
            return PolicyExplanation::decision(true, "policy_disabled");
        };
        if let Some((rule, kind)) = rules.command_match(command) {
            return PolicyExplanation::matched(rule, kind);
        }
        PolicyExplanation::decision(
            false,
            if contains_shell_metacharacters(command.trim()) {
                "exact_command_required"
            } else {
                "no_matching_rule"
            },
        )
    }

    pub(crate) fn explain_path(&self, path: &str, upload: bool) -> PolicyExplanation {
        let Self::Enabled(rules) = self else {
            return PolicyExplanation::decision(true, "policy_disabled");
        };
        let entries = if upload {
            &rules.allow_put_paths
        } else {
            &rules.allow_get_paths
        };
        if let Some(rule) = path_match(entries, path) {
            return PolicyExplanation::matched(rule, "path");
        }
        PolicyExplanation::decision(
            false,
            if has_parent_traversal(path) {
                "parent_traversal"
            } else {
                "no_matching_rule"
            },
        )
    }

    pub(crate) fn explain_account(
        &self,
        server: &str,
        user: &str,
        is_default: bool,
    ) -> PolicyExplanation {
        let Self::Enabled(rules) = self else {
            return PolicyExplanation::decision(true, "policy_disabled");
        };
        if is_default {
            return PolicyExplanation::decision(true, "default_account");
        }
        if let Some(entry) = rules.account_match(server, user) {
            return PolicyExplanation::matched(
                &format!("{}/{}", entry.server, entry.user),
                "account",
            );
        }
        PolicyExplanation::decision(false, "no_matching_rule")
    }
}

/// Lenient view of the policy file for diagnostics (`doctor`). Never errors.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PolicyStatus {
    pub present: bool,
    pub valid: bool,
    pub enabled: bool,
}

/// Resolve the enforcement state. `force_enable` is the `--policy` flag.
///
/// Fail-closed rules:
/// - `--policy` set but the file is missing -> error.
/// - the file is present but unparseable -> error (a broken policy is never
///   silently ignored).
///
/// Otherwise enforcement is enabled when `--policy` is set or the file's
/// `enabled` flag is true.
pub fn resolve_policy(policy_path: &Path, force_enable: bool) -> Result<Policy> {
    let Some(contents) = read_optional_policy(policy_path)? else {
        if force_enable {
            return Err(anyhow::anyhow!(
                "policy enforcement requested (--policy) but no policy file at {}",
                policy_path.display()
            ));
        }
        return Ok(Policy::Disabled);
    };
    let file = parse_policy_file(policy_path, &contents)?;

    if force_enable || file.enabled {
        Ok(Policy::Enabled(PolicyRules {
            allow_commands: file.allow_commands,
            allow_put_paths: file.allow_put_paths,
            allow_get_paths: file.allow_get_paths,
            allow_accounts: file.allow_accounts,
        }))
    } else {
        Ok(Policy::Disabled)
    }
}

/// Describe the policy file without enforcing or erroring, for `doctor`.
pub fn describe_policy(policy_path: &Path, force_enable: bool) -> PolicyStatus {
    match read_optional_policy(policy_path) {
        Ok(None) => PolicyStatus {
            present: false,
            valid: true,
            enabled: force_enable,
        },
        Ok(Some(contents)) => match parse_policy_file(policy_path, &contents) {
            Ok(file) => PolicyStatus {
                present: true,
                valid: true,
                enabled: force_enable || file.enabled,
            },
            Err(_) => PolicyStatus {
                present: true,
                valid: false,
                enabled: force_enable,
            },
        },
        Err(_) => PolicyStatus {
            present: true,
            valid: false,
            enabled: force_enable,
        },
    }
}

fn read_optional_policy(path: &Path) -> Result<Option<String>> {
    match fs::read_to_string(path) {
        Ok(contents) => Ok(Some(contents)),
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => {
            match fs::symlink_metadata(path) {
                Err(metadata_err) if metadata_err.kind() == std::io::ErrorKind::NotFound => {
                    Ok(None)
                }
                Err(metadata_err) => Err(anyhow::anyhow!(
                    "failed to read policy file at {}: {metadata_err}",
                    path.display()
                )),
                Ok(_) => Err(anyhow::anyhow!(
                    "failed to read policy file at {}: {err}",
                    path.display()
                )),
            }
        }
        Err(err) => Err(anyhow::anyhow!(
            "failed to read policy file at {}: {err}",
            path.display()
        )),
    }
}

fn parse_policy_file(path: &Path, contents: &str) -> Result<PolicyFile> {
    let file: PolicyFile = serde_json::from_str(contents)
        .map_err(|err| anyhow::anyhow!("invalid policy file at {}: {err}", path.display()))?;
    Ok(file)
}

pub(crate) fn load_policy_with_revision(
    path: &Path,
) -> Result<(Option<PolicyFile>, Option<String>)> {
    let contents = read_optional_policy(path)?;
    let file = contents
        .as_deref()
        .map(|text| parse_policy_file(path, text))
        .transpose()?;
    Ok((file, contents))
}

pub(crate) fn save_policy_if_unchanged(
    path: &Path,
    file: &PolicyFile,
    revision: &Option<String>,
) -> Result<()> {
    if &read_optional_policy(path)? != revision {
        return Err(anyhow::anyhow!(
            "policy file changed concurrently; inspect it and retry"
        ));
    }
    let contents = serde_json::to_string_pretty(file)?;
    crate::storage::write_owner_only_atomic(path, &contents)
}

fn command_matches_simple(entry: &str, command: &str) -> Option<&'static str> {
    if let Some(prefix) = entry.strip_suffix('*') {
        // An empty/whitespace-only prefix ("*") would match everything,
        // including destructive commands; refuse it.
        if prefix.trim().is_empty() {
            return None;
        }
        return command.starts_with(prefix).then_some("prefix");
    }

    // A bare program name (no whitespace) matches the command's program basename.
    if !entry.contains(char::is_whitespace)
        && let Some(program) = command.split_whitespace().next()
    {
        let basename = program.rsplit(['/', '\\']).next().unwrap_or(program);
        return (basename == entry).then_some("program");
    }

    None
}

fn contains_shell_metacharacters(command: &str) -> bool {
    command.chars().any(|c| {
        matches!(
            c,
            ';' | '&' | '|' | '`' | '$' | '(' | ')' | '<' | '>' | '\n' | '\r'
        )
    })
}

fn path_is_allowed(allowlist: &[String], path: &str) -> bool {
    path_match(allowlist, path).is_some()
}

fn path_match<'a>(allowlist: &'a [String], path: &str) -> Option<&'a str> {
    // Reject parent-directory traversal outright so it cannot escape an
    // allowed prefix lexically (e.g. /srv/app/../../etc).
    if has_parent_traversal(path) {
        return None;
    }
    allowlist.iter().find_map(|allowed| {
        // Skip empty entries (which would otherwise match every absolute
        // path) and normalize a trailing slash so "/srv/app/" behaves like
        // "/srv/app".
        let allowed = allowed.trim().trim_end_matches('/');
        (!allowed.is_empty() && path_within(allowed, path)).then_some(allowed)
    })
}

/// Lexical containment: `path` equals `allowed` or is a path-separated child of
/// it. Shared with `safety` so both modules use one definition. Lexical only —
/// it does not resolve remote symlinks or canonicalize paths.
pub(crate) fn path_within(allowed: &str, path: &str) -> bool {
    path == allowed
        || path
            .strip_prefix(allowed)
            .is_some_and(|rest| rest.starts_with('/'))
}

fn has_parent_traversal(path: &str) -> bool {
    path.split(['/', '\\']).any(|segment| segment == "..")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn policy_cas_does_not_overwrite_an_external_change() {
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("policy.json");
        let (_, revision) = load_policy_with_revision(&path).unwrap();
        std::fs::write(&path, r#"{"enabled":true}"#).unwrap();
        let err = save_policy_if_unchanged(&path, &PolicyFile::default(), &revision).unwrap_err();
        assert!(err.to_string().contains("changed concurrently"));
        assert_eq!(
            std::fs::read_to_string(&path).unwrap(),
            r#"{"enabled":true}"#
        );
    }

    fn rules() -> PolicyRules {
        PolicyRules {
            allow_commands: vec![
                "ls".to_string(),
                "systemctl status *".to_string(),
                "uptime".to_string(),
            ],
            allow_put_paths: vec!["/srv/app".to_string()],
            allow_get_paths: vec!["/var/log".to_string()],
            allow_accounts: Vec::new(),
        }
    }

    #[test]
    fn command_allowlist_matches_program_exact_and_glob() {
        let rules = rules();
        assert!(rules.allows_command("ls -la /srv"));
        assert!(rules.allows_command("/bin/ls"));
        assert!(rules.allows_command("uptime"));
        assert!(rules.allows_command("systemctl status nginx"));
        assert!(!rules.allows_command("rm -rf /"));
        assert!(!rules.allows_command("systemctl restart nginx"));
    }

    #[test]
    fn transfer_allowlist_matches_path_prefixes() {
        let rules = rules();
        assert!(rules.allows_put("/srv/app"));
        assert!(rules.allows_put("/srv/app/bin/run"));
        assert!(!rules.allows_put("/srv/apple"));
        assert!(!rules.allows_put("/etc/passwd"));
        assert!(rules.allows_get("/var/log/syslog"));
        assert!(!rules.allows_get("/root/.ssh/id_rsa"));
    }

    #[test]
    fn command_allowlist_rejects_shell_metacharacters() {
        let rules = rules();
        // "ls" is allowed, but compound/injected forms must not pass through it.
        assert!(!rules.allows_command("ls && rm -rf /"));
        assert!(!rules.allows_command("ls; whoami"));
        assert!(!rules.allows_command("ls | sh"));
        assert!(!rules.allows_command("ls $(rm -rf /)"));
        assert!(!rules.allows_command("uptime > /etc/passwd"));
        // The glob entry must not become a metacharacter bypass either.
        assert!(!rules.allows_command("systemctl status nginx && reboot"));
    }

    #[test]
    fn exact_entry_allows_a_compound_command() {
        let rules = PolicyRules {
            allow_commands: vec!["ls && echo done".to_string()],
            allow_put_paths: vec![],
            allow_get_paths: vec![],
            allow_accounts: Vec::new(),
        };
        assert!(rules.allows_command("ls && echo done"));
        assert!(!rules.allows_command("ls && echo other"));
    }

    #[test]
    fn transfer_allowlist_rejects_parent_traversal() {
        let rules = rules();
        assert!(!rules.allows_put("/srv/app/../../etc/passwd"));
        assert!(!rules.allows_get("/var/log/../../root/.ssh/id_rsa"));
    }
}
