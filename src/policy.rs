use anyhow::Result;
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::Path;

/// On-disk policy document (`<home>/policy.json`). Every field defaults so a
/// minimal `{ "enabled": true, "allow_commands": ["ls"] }` parses.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
pub struct PolicyFile {
    #[serde(default)]
    pub version: u32,
    #[serde(default)]
    pub enabled: bool,
    #[serde(default)]
    pub allow_commands: Vec<String>,
    #[serde(default)]
    pub allow_put_paths: Vec<String>,
    #[serde(default)]
    pub allow_get_paths: Vec<String>,
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
}

impl PolicyRules {
    pub fn allows_command(&self, command: &str) -> bool {
        let command = command.trim();
        let has_meta = contains_shell_metacharacters(command);
        self.allow_commands.iter().any(|entry| {
            let entry = entry.trim();
            if entry.is_empty() {
                return false;
            }
            // An exact full-command entry is always honored.
            if entry == command {
                return true;
            }
            // A command containing shell metacharacters can do more than run a
            // single program, so program-name / glob matches must not apply to
            // it: only an exact allowlist entry permits it.
            if has_meta {
                return false;
            }
            command_matches_simple(entry, command)
        })
    }

    pub fn allows_put(&self, remote_path: &str) -> bool {
        path_is_allowed(&self.allow_put_paths, remote_path)
    }

    pub fn allows_get(&self, remote_path: &str) -> bool {
        path_is_allowed(&self.allow_get_paths, remote_path)
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
    if !policy_path.exists() {
        if force_enable {
            return Err(anyhow::anyhow!(
                "policy enforcement requested (--policy) but no policy file at {}",
                policy_path.display()
            ));
        }
        return Ok(Policy::Disabled);
    }

    let contents = fs::read_to_string(policy_path).map_err(|err| {
        anyhow::anyhow!(
            "failed to read policy file at {}: {err}",
            policy_path.display()
        )
    })?;
    let file: PolicyFile = serde_json::from_str(&contents).map_err(|err| {
        anyhow::anyhow!("invalid policy file at {}: {err}", policy_path.display())
    })?;

    if force_enable || file.enabled {
        Ok(Policy::Enabled(PolicyRules {
            allow_commands: file.allow_commands,
            allow_put_paths: file.allow_put_paths,
            allow_get_paths: file.allow_get_paths,
        }))
    } else {
        Ok(Policy::Disabled)
    }
}

/// Describe the policy file without enforcing or erroring, for `doctor`.
pub fn describe_policy(policy_path: &Path, force_enable: bool) -> PolicyStatus {
    if !policy_path.exists() {
        return PolicyStatus {
            present: false,
            valid: true,
            enabled: force_enable,
        };
    }

    match fs::read_to_string(policy_path)
        .ok()
        .and_then(|contents| serde_json::from_str::<PolicyFile>(&contents).ok())
    {
        Some(file) => PolicyStatus {
            present: true,
            valid: true,
            enabled: force_enable || file.enabled,
        },
        None => PolicyStatus {
            present: true,
            valid: false,
            enabled: force_enable,
        },
    }
}

fn command_matches_simple(entry: &str, command: &str) -> bool {
    if let Some(prefix) = entry.strip_suffix('*') {
        // An empty/whitespace-only prefix ("*") would match everything,
        // including destructive commands; refuse it.
        if prefix.trim().is_empty() {
            return false;
        }
        return command.starts_with(prefix);
    }

    // A bare program name (no whitespace) matches the command's program basename.
    if !entry.contains(char::is_whitespace)
        && let Some(program) = command.split_whitespace().next()
    {
        let basename = program.rsplit(['/', '\\']).next().unwrap_or(program);
        return basename == entry;
    }

    false
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
    // Reject parent-directory traversal outright so it cannot escape an
    // allowed prefix lexically (e.g. /srv/app/../../etc).
    if has_parent_traversal(path) {
        return false;
    }
    allowlist.iter().any(|allowed| {
        // Skip empty entries (which would otherwise match every absolute
        // path) and normalize a trailing slash so "/srv/app/" behaves like
        // "/srv/app".
        let allowed = allowed.trim().trim_end_matches('/');
        !allowed.is_empty() && path_within(allowed, path)
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

    fn rules() -> PolicyRules {
        PolicyRules {
            allow_commands: vec![
                "ls".to_string(),
                "systemctl status *".to_string(),
                "uptime".to_string(),
            ],
            allow_put_paths: vec!["/srv/app".to_string()],
            allow_get_paths: vec!["/var/log".to_string()],
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
