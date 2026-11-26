//! Typed policy denials and observational recovery commands, never automatic grants.
use super::ExecContext;
use crate::error::classified_error;
use crate::local_command::{quote_local_argument, redacted_argument};
use crate::output::{ErrorKind, PolicySuggestion};
use std::fmt;

#[derive(Debug)]
pub(super) enum Rule {
    Account(String, String),
    Command(String),
    Path { value: String, upload: bool },
}

#[derive(Debug)]
struct Denial {
    reason: String,
    rule: Rule,
}
impl fmt::Display for Denial {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.reason)
    }
}
impl std::error::Error for Denial {}

#[derive(Debug)]
pub(crate) struct RecoveryError {
    source: anyhow::Error,
    pub(crate) suggestions: Vec<PolicySuggestion>,
}
impl fmt::Display for RecoveryError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.source)?;
        for suggestion in &self.suggestions {
            write!(
                f,
                "\npermission scope ({}): {}",
                suggestion.kind, suggestion.scope
            )?;
            if let Some(command) = &suggestion.command {
                write!(f, "\nnext: {command}")?;
            }
        }
        write!(
            f,
            "\nReview the scope before applying a grant; settings and remote OS permissions are unchanged."
        )
    }
}
impl std::error::Error for RecoveryError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        Some(self.source.as_ref())
    }
}

pub(super) fn denial(mut reason: String, rule: Rule) -> anyhow::Error {
    // Mask each sensitive value before joining the recovery prose or account pair.
    let values = match &rule {
        Rule::Account(server, user) => vec![server, user],
        Rule::Command(value) | Rule::Path { value, .. } => vec![value],
    };
    for value in values {
        if redacted_argument(value) != *value {
            reason = reason.replace(value, "<redacted>");
        }
    }
    classified_error(
        ErrorKind::Policy,
        anyhow::Error::new(Denial { reason, rule }),
    )
}

pub(super) fn attach(error: anyhow::Error, ctx: &ExecContext<'_>, global: bool) -> anyhow::Error {
    if error.chain().any(|cause| cause.is::<RecoveryError>()) {
        return error;
    }
    let Some(denial) = error
        .chain()
        .find_map(|cause| cause.downcast_ref::<Denial>())
    else {
        return error;
    };
    let suggestion = suggestion(&denial.rule, ctx, global);
    classified_error(
        ErrorKind::Policy,
        anyhow::Error::new(RecoveryError {
            source: error,
            suggestions: vec![suggestion],
        }),
    )
}

fn clean(value: &str) -> bool {
    !value.chars().any(char::is_control) && redacted_argument(value) == value
}

pub(super) fn launcher(ctx: &ExecContext<'_>, global: bool) -> Option<String> {
    if ctx
        .home
        .project
        .as_ref()
        .is_some_and(|project| project.policy == crate::project::ResourceSource::Global)
    {
        return None;
    }
    super::hints::settings_launcher(ctx, global)
}

fn suggestion(rule: &Rule, ctx: &ExecContext<'_>, global: bool) -> PolicySuggestion {
    let original_safe = match rule {
        Rule::Command(value) => clean(value) && !value.trim().is_empty() && value.trim() != "*",
        Rule::Account(server, user) => clean(server) && clean(user),
        Rule::Path { value, .. } => clean(value),
    };
    let (kind,values,scope)=match rule {
        Rule::Account(server,user)=>("account",vec![server.clone(),user.clone()],
            "Only this registered server/login account; command/path rules and remote privileges still apply.".to_string()),
        Rule::Command(value)=>{
            let kind=crate::policy::command_rule_kind(value);
            let scope=match kind {
                "program"=>"The whole program, including its arguments and subprocesses; shell compound syntax still needs an exact rule.",
                "prefix"=>"Every command with this trailing-* lexical prefix; review this broader grant before applying it.",
                _=>"This exact full command; other commands remain subject to policy.",
            };
            ("command",vec![value.trim().to_string()],scope.to_string())
        }
        Rule::Path{value,upload}=>{
            let scope="This remote path and its descendants, not only one file; remote symlinks and OS permissions are not resolved by policy.";
            let encoded=if value.starts_with('/') || value.starts_with("\\\\") || value.as_bytes().get(1)==Some(&b':') {
                format!("remote:{value}")
            } else {value.clone()};
            let valid=!value.trim().is_empty() && value.trim()==value && value!="*"
                && !value.trim_end_matches('/').is_empty()
                && !value.split(['/', '\\']).any(|part|part=="..")
                && super::transfer::policy_remote_path(&encoded).is_ok_and(|decoded|decoded==*value);
            if !valid {
                return PolicySuggestion {kind:if *upload {"put"} else {"get"},command:None,
                    scope:"No copyable grant: normalize the remote path and inspect `sshw policy show` using the same home/profile; root-only or parent-traversal paths cannot be granted.".into()};
            }
            (if *upload {"put"} else {"get"},vec![encoded],scope.to_string())
        }
    };
    let command = if original_safe && values.iter().all(|value| clean(value)) {
        launcher(ctx, global).map(|prefix| {
            format!(
                "{prefix} policy allow {kind} -- {}",
                values
                    .iter()
                    .map(|value| quote_local_argument(value))
                    .collect::<Vec<_>>()
                    .join(" ")
            )
        })
    } else {
        None
    };
    let mut scope = scope;
    if let Some(project) = &ctx.home.project
        && project.policy == crate::project::ResourceSource::Global
    {
        let hint = crate::project::initialization_hint(
            project.root.parent().unwrap_or(&project.root),
            false,
            true,
        );
        scope.push_str(&format!(" The policy is inherited and read-only in automatic project mode; {hint}, or use --global for an intentional global policy edit."));
    } else if command.is_none() {
        scope.push_str(" Copyable command omitted because values are sensitive/contain controls, cannot form a valid grant, or the home/profile selection cannot be reproduced. Inspect the same home's policy manually.");
    }
    PolicySuggestion {
        kind,
        command,
        scope,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::audit::NoopAudit;
    use crate::home::ResolvedHome;
    use crate::home::builtin_default_home;
    use crate::profile::{ProfileEntry, ProfileRegistry, save_registry};
    use std::collections::BTreeMap;

    #[test]
    fn policy_recovery_reproduces_profile_namespace_and_builtin_selection_without_writes() {
        let temp = tempfile::tempdir().unwrap();
        let registry_path = temp.path().join("profiles.json");
        let root = temp.path().join("profile home");
        let name = "prod's profile";
        let registry = ProfileRegistry {
            default: Some(name.into()),
            profiles: BTreeMap::from([(
                name.into(),
                ProfileEntry {
                    id: "p_prod".into(),
                    home: root.clone(),
                },
            )]),
            ..Default::default()
        };
        save_registry(&registry_path, &registry).unwrap();
        let home = ResolvedHome::profile(root.clone(), "p_prod", "selected".into());
        let ctx = ExecContext {
            home: &home,
            registry_path: &registry_path,
            policy_forced: false,
            audit: &NoopAudit,
        };
        let before = std::fs::read(&registry_path).unwrap();
        let hint = suggestion(&Rule::Account("web".into(), "ops".into()), &ctx, false);
        let command = hint.command.unwrap();
        assert!(command.starts_with(&format!("sshw --profile={}", quote_local_argument(name))));
        assert!(!command.contains("--home"));
        let command = suggestion(&Rule::Command("uptime".into()), &ctx, true).command;
        assert_eq!(
            command.as_deref(),
            Some("sshw --global policy allow command -- 'uptime'")
        );
        assert_eq!(std::fs::read(&registry_path).unwrap(), before);
        assert!(!root.exists());
        let stale = ResolvedHome::profile(root, "p_stale", "selected".into());
        let stale_ctx = ExecContext {
            home: &stale,
            ..ctx
        };
        assert!(
            suggestion(&Rule::Command("uptime".into()), &stale_ctx, false)
                .command
                .is_none()
        );
        save_registry(&registry_path, &ProfileRegistry::default()).unwrap();
        let builtin = builtin_default_home(temp.path());
        let builtin_ctx = ExecContext {
            home: &builtin,
            ..ctx
        };
        assert_eq!(
            suggestion(&Rule::Command("uptime".into()), &builtin_ctx, false)
                .command
                .as_deref(),
            Some("sshw --global policy allow command -- 'uptime'")
        );
        assert!(!builtin.root.exists());
    }

    #[test]
    fn policy_recovery_masks_each_account_value_and_does_not_wrap_non_policy_errors() {
        let temp = tempfile::tempdir().unwrap();
        let registry = temp.path().join("profiles.json");
        let home = ResolvedHome::ad_hoc(temp.path(), "test".into());
        let ctx = ExecContext {
            home: &home,
            registry_path: &registry,
            policy_forced: false,
            audit: &NoopAudit,
        };
        let error = denial(
            "account 'password=server-private/token=user-private' is blocked by policy".into(),
            Rule::Account(
                "password=server-private".into(),
                "token=user-private".into(),
            ),
        );
        let error = attach(error, &ctx, false);
        let response = crate::output::ErrorResponse::from_error(&error);
        let json = serde_json::to_string(&response).unwrap();
        assert!(!json.contains("server-private"));
        assert!(!json.contains("user-private"));
        assert!(response.suggestions[0].command.is_none());
        assert_eq!(response.error.exit_code, 7);
        let error = anyhow::Error::new(std::io::Error::new(
            std::io::ErrorKind::PermissionDenied,
            "local failure",
        ));
        let error = attach(error, &ctx, false);
        assert!(error.downcast_ref::<std::io::Error>().is_some());
        assert!(
            crate::output::ErrorResponse::from_error(&error)
                .suggestions
                .is_empty()
        );
    }
}
