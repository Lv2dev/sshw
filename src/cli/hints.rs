//! Copyable local commands. Options precede the positional boundary, and each
//! user-provided value is masked before platform-specific shell quoting.

use crate::config::PrivilegeMethod;
use crate::home::{CredentialNamespace, ResolvedHome, builtin_default_home};
pub(super) use crate::local_command::{quote_local_argument, redacted_argument};
use crate::output::{ErrorKind, classify_error};
use crate::ssh::known_hosts::{HostTrustError, HostTrustFailure};
use std::path::Path;

fn copyable(value: &str) -> bool {
    !value.chars().any(char::is_control) && redacted_argument(value) == value
}

/// Reproduce a trusted home binding without converting profile credentials to
/// an ad-hoc namespace. A missing/stale binding requires manual selection.
pub(super) fn home_launcher(home: &ResolvedHome, registry_path: &Path) -> Option<String> {
    if home.namespace == CredentialNamespace::for_home(&home.root) {
        let absolute = std::path::absolute(&home.root).ok()?;
        let value = absolute.to_str()?;
        return copyable(value).then(|| format!("sshw --home={}", quote_local_argument(value)));
    }
    if let Ok(registry) = crate::profile::load_registry(registry_path) {
        for (name, entry) in registry.profiles {
            if CredentialNamespace::profile(&entry.id) == home.namespace
                && entry.home == home.root
                && copyable(&name)
            {
                return Some(format!("sshw --profile={}", quote_local_argument(&name)));
            }
        }
        let builtin = builtin_default_home(registry_path.parent()?);
        if registry.default.is_none()
            && home.namespace == builtin.namespace
            && home.root == builtin.root
        {
            return Some("sshw".into());
        }
    }
    None
}

pub(super) fn settings_launcher(
    ctx: &super::ExecContext<'_>,
    global_selection: bool,
) -> Option<String> {
    let prefix = if let Some(project) = &ctx.home.project {
        crate::project::command_prefix(project.root.parent()?)?
    } else {
        let prefix = home_launcher(ctx.home, ctx.registry_path)?;
        if prefix == "sshw" || (global_selection && prefix.starts_with("sshw --profile=")) {
            "sshw --global".into()
        } else {
            prefix
        }
    };
    Some(if ctx.policy_forced {
        format!("{prefix} --policy")
    } else {
        prefix
    })
}

/// Read commands retain both project sources. Server mutations inherited from
/// global settings require an explicit global selector rather than a bypass.
pub(super) struct RecoveryCommands {
    read: Option<String>,
    write: Option<String>,
    pub inherited_servers: bool,
}

impl RecoveryCommands {
    pub fn new(ctx: &super::ExecContext<'_>, global_selection: bool) -> Self {
        let read = settings_launcher(ctx, global_selection);
        let inherited_servers = ctx
            .home
            .project
            .as_ref()
            .is_some_and(|project| project.servers == crate::project::ResourceSource::Global);
        let write = if inherited_servers {
            Some(
                if ctx.policy_forced {
                    "sshw --global --policy"
                } else {
                    "sshw --global"
                }
                .into(),
            )
        } else {
            read.clone()
        };
        Self {
            read,
            write,
            inherited_servers,
        }
    }

    fn command(prefix: &Option<String>, command: &str, values: &[&str]) -> Option<String> {
        if !values.iter().all(|value| copyable(value)) {
            return None;
        }
        Some(format!(
            "{} {}",
            prefix.as_deref()?,
            command.strip_prefix("sshw ")?
        ))
    }

    pub fn read(&self, command: &str, values: &[&str]) -> Option<String> {
        Self::command(&self.read, command, values)
    }

    pub fn write(&self, command: &str, values: &[&str]) -> Option<String> {
        Self::command(&self.write, command, values)
    }

    pub fn write_notice(&self) -> &'static str {
        if self.inherited_servers {
            " The server settings are inherited and read-only here; the write command intentionally targets global settings with --global."
        } else {
            ""
        }
    }
}

pub(super) fn registration_followups(
    ctx: &super::ExecContext<'_>,
    global_selection: bool,
    server: &str,
) -> String {
    if copyable(server)
        && let Some(prefix) = settings_launcher(ctx, global_selection)
    {
        return format!(
            "next: {prefix} trust -- {}\nthen: {prefix} run -- {} {}\n",
            quote_local_argument(server),
            quote_local_argument(server),
            quote_local_argument("hostname")
        );
    }
    "next: keep the original settings selection when approving the registered host and running a command; copyable commands are omitted because the selection/name cannot be safely reproduced\n".into()
}

pub(super) fn endpoint_update(
    ctx: &super::ExecContext<'_>,
    global_selection: bool,
    server: &str,
    host: Option<&str>,
    port: Option<u16>,
) -> String {
    if copyable(server)
        && host.is_none_or(copyable)
        && let Some(prefix) = settings_launcher(ctx, global_selection)
    {
        let host = host
            .map(|host| format!(" --host={}", quote_local_argument(host)))
            .unwrap_or_default();
        let port = port
            .map(|port| format!(" --port={port}"))
            .unwrap_or_default();
        return format!(
            "to change only the address and preserve accounts, passwords and privilege settings, use `{prefix} endpoint{host}{port} -- {}`",
            quote_local_argument(server)
        );
    }
    "to preserve accounts, passwords and privilege settings, use endpoint with the original settings selection; a copyable command is omitted because the selection or values cannot be safely reproduced".into()
}

fn registration_template(prefix: &str) -> String {
    format!(
        "{prefix} add --host {} --user {} -- {}",
        quote_local_argument("<host>"),
        quote_local_argument("<login-user>"),
        quote_local_argument("web")
    )
}

pub(super) fn empty_server_list(
    ctx: &super::ExecContext<'_>,
    global_selection: bool,
) -> (&'static str, String) {
    let prefix = settings_launcher(ctx, global_selection);
    if let Some(project) = &ctx.home.project
        && project.servers == crate::project::ResourceSource::Global
    {
        let global = if ctx.policy_forced {
            "sshw --global --policy"
        } else {
            "sshw --global"
        };
        let mut text = format!(
            "choose where to register (replace the host/login-user placeholders):\nglobal registration: {}\nlocal list: {}",
            registration_template(global),
            crate::project::initialization_hint(
                project.root.parent().unwrap_or(&project.root),
                true,
                false,
            )
        );
        if let Some(prefix) = prefix {
            text.push_str(&format!(
                "\nafter local initialization: {}",
                registration_template(&prefix)
            ));
        }
        return (
            "no servers registered in the inherited global list; project server settings are read-only",
            text,
        );
    }
    let guidance = match prefix {
        Some(prefix) => format!("replace the host/login-user placeholders and start with: {}", registration_template(&prefix)),
        None => "keep the original settings selection to register a server. A copyable command is unavailable for this selection".into(),
    };
    ("no servers registered in the selected list", guidance)
}

pub(super) fn no_matching_servers(ctx: &super::ExecContext<'_>, global_selection: bool) -> String {
    match settings_launcher(ctx, global_selection) {
        Some(prefix) => format!("no matching servers; use `{prefix} list` without --filter to see the selected list\n"),
        None => "no matching servers; remove --filter while keeping the original settings selection to see the selected list\n".into(),
    }
}

pub(super) fn trust(server: &str) -> String {
    format!("sshw trust -- {}", quote_local_argument(server))
}

pub(super) fn attach_host_trust(
    error: anyhow::Error,
    ctx: &super::ExecContext<'_>,
    global_selection: bool,
    server: &str,
) -> anyhow::Error {
    let Some(trust_error) = error
        .chain()
        .find_map(|cause| cause.downcast_ref::<HostTrustError>())
    else {
        return error;
    };
    if classify_error(&error) != ErrorKind::Ssh {
        return error;
    }
    let guidance = match &trust_error.failure {
        HostTrustFailure::Unapproved => {
            let commands = RecoveryCommands::new(ctx, global_selection);
            match commands.write(&trust(server), &[server]) {
                Some(command) => format!(
                    "compare the server fingerprint with a trusted source before approving it with `{command}`.{}",
                    commands.write_notice()
                ),
                None => "verify the server fingerprint through a trusted source, then explicitly select the original settings and server to approve it. A copyable command is unavailable for this selection".into(),
            }
        }
        HostTrustFailure::Changed(path) => {
            let path = std::path::absolute(path).unwrap_or_else(|_| path.clone());
            let path = crate::local_command::display_value(&path.display().to_string());
            format!(
                "verify the key change and new fingerprint with the server administrator before updating the recorded key in `{path}`"
            )
        }
    };
    let message = format!("{error}\nnext: {guidance}");
    error.context(message)
}

pub(super) fn account_password(server: &str, login_user: &str) -> String {
    format!(
        "sshw account add --auth password -- {} {}",
        quote_local_argument(server),
        quote_local_argument(login_user),
    )
}

pub(super) fn account_list(server: &str) -> String {
    format!("sshw account list -- {}", quote_local_argument(server))
}

pub(super) fn account_add(server: &str, login_user: &str) -> String {
    format!(
        "sshw account add -- {} {}",
        quote_local_argument(server),
        quote_local_argument(login_user),
    )
}

pub(super) fn server_add(server: &str) -> String {
    format!(
        "sshw add --host {} --user {} -- {}",
        quote_local_argument("<host>"),
        quote_local_argument("<login-user>"),
        quote_local_argument(server),
    )
}

pub(super) fn privilege_set(
    server: &str,
    login_user: &str,
    method: PrivilegeMethod,
    target_user: Option<&str>,
) -> String {
    let target = target_user
        .map(|user| format!(" --user={}", quote_local_argument(user)))
        .unwrap_or_default();
    format!(
        "sshw privilege set --account={} --method {}{target} -- {}",
        quote_local_argument(login_user),
        super::privilege::method_label(method),
        quote_local_argument(server),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn server_guidance_preserves_builtin_force_and_omits_unsafe_or_stale_bindings() {
        let temp = tempfile::tempdir().unwrap();
        let registry_path = temp.path().join("profiles.json");
        let home = builtin_default_home(temp.path());
        let ctx = super::super::ExecContext {
            home: &home,
            registry_path: &registry_path,
            policy_forced: true,
            audit: &crate::audit::NoopAudit,
        };
        let text = registration_followups(&ctx, false, "web");
        assert!(
            text.contains("next: sshw --global --policy trust --"),
            "{text}"
        );
        assert!(
            text.contains("then: sshw --global --policy run --"),
            "{text}"
        );
        assert!(!registry_path.exists());
        assert!(!home.root.exists());
        for name in ["token=alias-marker", "line\nbreak"] {
            let text = registration_followups(&ctx, false, name);
            assert!(text.contains("copyable commands are omitted"), "{text}");
            assert!(!text.contains("alias-marker"));
            assert!(!text.contains(" trust -- "));
            let endpoint = endpoint_update(&ctx, false, name, Some("192.0.2.20"), None);
            assert!(!endpoint.contains('`'));
            assert!(!endpoint.contains("alias-marker"));
        }
        let stale = ResolvedHome::profile(temp.path().join("stale"), "p_unbound", "stale".into());
        let stale_ctx = super::super::ExecContext {
            home: &stale,
            ..ctx
        };
        assert!(settings_launcher(&stale_ctx, false).is_none());
        assert!(!empty_server_list(&stale_ctx, false).1.contains("sshw add"));
        let sensitive =
            ResolvedHome::ad_hoc(&temp.path().join("token=path-marker"), "sensitive".into());
        let sensitive_ctx = super::super::ExecContext {
            home: &sensitive,
            ..ctx
        };
        let text = registration_followups(&sensitive_ctx, false, "web");
        assert!(text.contains("copyable commands are omitted"));
        assert!(!text.contains("path-marker"));
        assert!(!sensitive.root.exists());
    }
}
