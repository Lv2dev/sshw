//! Contextual lookup diagnostics. The unscoped error carries only the target;
//! copyable recovery commands are rendered at the execution boundary.
use super::{ExecContext, hints};
use crate::error::classified_error;
use crate::output::ErrorKind;
use std::fmt;

#[derive(Debug, Clone)]
pub(super) enum Lookup {
    DefaultServer { empty: bool },
    Server { name: String, quote_command: bool },
    Account { server: String, user: String },
    Privilege { server: String, user: String },
}

impl fmt::Display for Lookup {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::DefaultServer { .. } => f.write_str("no default server configured"),
            Self::Server { name, .. } => write!(
                f,
                "unknown server '{}'; only registered servers can be selected",
                hints::redacted_argument(name)
            ),
            Self::Account { server, user } => write!(
                f,
                "unknown account '{}/{}'",
                hints::redacted_argument(server),
                hints::redacted_argument(user)
            ),
            Self::Privilege { server, user } => write!(
                f,
                "privilege configuration missing for account '{}/{}'",
                hints::redacted_argument(server),
                hints::redacted_argument(user)
            ),
        }
    }
}
impl std::error::Error for Lookup {}

pub(super) fn error(lookup: Lookup) -> anyhow::Error {
    classified_error(ErrorKind::Config, anyhow::Error::new(lookup))
}

#[derive(Debug)]
struct ScopedLookup {
    source: anyhow::Error,
    guidance: String,
}
impl fmt::Display for ScopedLookup {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}\n{}", self.source, self.guidance)
    }
}
impl std::error::Error for ScopedLookup {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        Some(self.source.as_ref())
    }
}

pub(super) fn attach(error: anyhow::Error, ctx: &ExecContext<'_>, global: bool) -> anyhow::Error {
    if crate::output::classify_error(&error) != ErrorKind::Config {
        return error;
    }
    if error.chain().any(|cause| cause.is::<ScopedLookup>()) {
        return error;
    }
    let Some(lookup) = error
        .chain()
        .find_map(|cause| cause.downcast_ref::<Lookup>())
        .cloned()
    else {
        return error;
    };
    let commands = hints::RecoveryCommands::new(ctx, global);
    let mut guidance = "next: using the same home/profile/project selection".to_string();
    let fallback = "inspect the originally selected settings manually; a copyable command is omitted because its binding or values cannot be safely reproduced";
    match lookup {
        Lookup::DefaultServer { empty: true } => {
            let (summary, next) = hints::empty_server_list(ctx, global);
            guidance = format!("next: {summary}\n{next}");
        }
        Lookup::DefaultServer { empty: false } => {
            if let Some(list) = commands.read("sshw list", &[]) {
                guidance.push_str(&format!(", run `{list}` to see registered servers"));
            } else {
                guidance.push_str(&format!(", {fallback}"));
            }
            let template = format!(
                "sshw default -- {}",
                hints::quote_local_argument("<registered-server>")
            );
            if let Some(set) = commands.write(&template, &[]) {
                guidance.push_str(&format!(". To save a default, replace the placeholder in `{set}` with a registered server name.{}", commands.write_notice()));
            }
            guidance.push_str("\nTo select a server for one invocation, pass its name explicitly to run, put, or get.");
        }
        Lookup::Server {
            name,
            quote_command,
        } => {
            if let Some(list) = commands.read("sshw list", &[]) {
                guidance.push_str(&format!(", run `{list}` to see registered servers"));
            } else {
                guidance.push_str(&format!(", {fallback}"));
            }
            if let Some(add) = commands.write(&hints::server_add(&name), &[&name]) {
                guidance.push_str(&format!("; to register this name, replace the host/login-user placeholders in `{add}`. Registration uses hidden password input by default; insert --auth agent or --password-stdin before the command's -- as appropriate.{}", commands.write_notice()));
            } else {
                guidance.push_str(&format!("; {fallback}"));
            }
            if quote_command {
                guidance.push_str("\nQuote the whole remote command and keep the same selector: run <server> \"<command>\", or run \"<command>\" for the default server");
            }
        }
        Lookup::Account { server, user } => {
            if let Some(list) = commands.read(&hints::account_list(&server), &[&server]) {
                guidance.push_str(&format!(", run `{list}` to see registered login accounts"));
            } else {
                guidance.push_str(&format!(", {fallback}"));
            }
            guidance.push_str(". Account selection requires a registered login account; it does not override the SSH username");
            if let Some(add) =
                commands.write(&hints::account_add(&server, &user), &[&server, &user])
            {
                guidance.push_str(&format!("\nif a new login is needed, register it first with `{add}`. Password auth is the default; insert --auth agent or --password-stdin before -- as appropriate. Never put passwords in arguments.{}", commands.write_notice()));
            } else {
                guidance.push_str(&format!("\n{fallback}"));
            }
        }
        Lookup::Privilege { server, user } => {
            let command =
                hints::privilege_set(&server, &user, crate::config::PrivilegeMethod::Sudo, None);
            if let Some(command) = commands.write(&command, &[&server, &user]) {
                guidance.push_str(&format!(
                    ", configure privilege explicitly with `{command}` first.{}",
                    commands.write_notice()
                ));
            } else {
                guidance.push_str(&format!(", {fallback}"));
            }
        }
    }
    classified_error(
        ErrorKind::Config,
        anyhow::Error::new(ScopedLookup {
            source: error,
            guidance,
        }),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn contextual_lookup_preserves_outer_error_kinds_and_suppresses_unsafe_targets() {
        let temp = tempfile::tempdir().unwrap();
        let home = crate::home::ResolvedHome::ad_hoc(temp.path(), "selected".into());
        let registry = temp.path().join("profiles.json");
        let ctx = ExecContext {
            home: &home,
            registry_path: &registry,
            policy_forced: false,
            audit: &crate::audit::NoopAudit,
        };
        let wrapped = classified_error(
            ErrorKind::Ssh,
            error(Lookup::Account {
                server: "web".into(),
                user: "ops".into(),
            }),
        );
        let wrapped = attach(wrapped, &ctx, false);
        assert_eq!(crate::output::classify_error(&wrapped), ErrorKind::Ssh);
        assert!(!wrapped.to_string().contains("account add"));
        for value in ["token=marker", "line\nbreak"] {
            let scoped = attach(
                error(Lookup::Account {
                    server: value.into(),
                    user: value.into(),
                }),
                &ctx,
                false,
            );
            assert_eq!(crate::output::classify_error(&scoped), ErrorKind::Config);
            assert!(!scoped.to_string().contains("marker"));
            assert!(scoped.to_string().contains("copyable command is omitted"));
            assert!(!scoped.to_string().contains(" account add -- "));
        }
        assert!(!registry.exists());
    }
}
