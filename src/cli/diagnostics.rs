//! Local credential checks shared by doctor's human and JSON diagnostics.

use super::{hints, privilege, redacted_error_detail};
use crate::config::{AuthConfig, PrivilegeConfig, SshwConfig};
use crate::credentials::CredentialStore;
use crate::home::CredentialPurpose;
use crate::output::redact_secrets;
use serde::Serialize;
use zeroize::Zeroizing;

#[derive(Debug, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub(super) enum CredentialStatus {
    Ready,
    Missing,
    Unavailable,
    Invalid,
}

#[derive(Debug, Serialize)]
pub(super) struct CredentialCheck {
    pub server: String,
    pub user: String,
    pub purpose: &'static str,
    pub status: CredentialStatus,
    pub message: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub next_step: Option<String>,
}

pub(super) fn credential_checks<C: CredentialStore>(
    credentials: &C,
    config: &SshwConfig,
    selected_server: Option<&str>,
    selected_user: Option<&str>,
    recovery: &hints::RecoveryCommands,
) -> Vec<CredentialCheck> {
    let mut checks = Vec::new();
    for (name, server) in &config.servers {
        if selected_server.is_some_and(|selected| selected != name) {
            continue;
        }
        for (user, account) in &server.accounts {
            if selected_user.is_some_and(|selected| selected != user) {
                continue;
            }
            if let AuthConfig::Password { credential } = &account.auth {
                checks.push(check_credential(
                    credentials,
                    name,
                    user,
                    credential,
                    None,
                    recovery,
                ));
            }
            if let Some(privilege) = &account.privilege
                && let Some(credential) = &privilege.credential
            {
                checks.push(check_credential(
                    credentials,
                    name,
                    user,
                    credential,
                    Some(privilege),
                    recovery,
                ));
            }
        }
    }
    checks
}

fn check_credential<C: CredentialStore>(
    credentials: &C,
    server: &str,
    user: &str,
    credential: &str,
    privilege: Option<&PrivilegeConfig>,
    commands: &hints::RecoveryCommands,
) -> CredentialCheck {
    let (purpose, credential_user, label) = if let Some(privilege) = privilege {
        (
            CredentialPurpose::Privilege,
            privilege.user.as_str(),
            "privilege",
        )
    } else {
        (CredentialPurpose::Login, user, "login")
    };
    let result = credentials
        .get_password_for(purpose, credential, credential_user)
        .map(Zeroizing::new);
    let recovery = || {
        if !credentials.is_persistent() {
            return privilege.map(|privilege| privilege::recovery_step(server, user, privilege, false))
                .unwrap_or_else(|| "supply SSHW_PASSWORD at run time using the same home/profile selection; session-only passwords are not persisted. Never put passwords in arguments".into());
        }
        let (command, values) = if let Some(privilege) = privilege {
            (
                hints::privilege_set(server, user, privilege.method, Some(&privilege.user)),
                vec![server, user, privilege.user.as_str()],
            )
        } else {
            (hints::account_password(server, user), vec![server, user])
        };
        commands.write(&command, &values).map(|command| format!(
            "using the same home/profile/project selection, register the {label} password again with `{command}`; confirm the update, or insert --force and --password-stdin before -- for non-interactive secret-manager input.{}", commands.write_notice()
        )).unwrap_or_else(|| {
            let detail = privilege.map(|privilege| format!("method: {}; target: {}; ", privilege::method_label(privilege.method), hints::redacted_argument(&privilege.user))).unwrap_or_default();
            format!("{detail}keep the original settings selection when repairing this credential; no copyable command is available for its selection/values")
        })
    };
    let (status, message, next_step) = match result {
        Ok(password) => {
            if let Some(error) =
                privilege.and_then(|_| privilege::validate_privilege_password(&password).err())
            {
                (
                    CredentialStatus::Invalid,
                    format!(
                        "invalid {label} credential for {server}/{user}: {}",
                        redacted_error_detail(&error)
                    ),
                    Some(recovery()),
                )
            } else {
                (
                    CredentialStatus::Ready,
                    format!(
                        "{label} credential for {server}/{user} is locally available; remote authentication not tested"
                    ),
                    None,
                )
            }
        }
        Err(error) => {
            let missing = error.chain().any(|cause| {
                matches!(
                    cause.downcast_ref::<keyring_core::Error>(),
                    Some(keyring_core::Error::NoEntry)
                )
            });
            if missing {
                (
                    CredentialStatus::Missing,
                    format!(
                        "missing {label} credential for {server}/{user}: {}",
                        redacted_error_detail(&error)
                    ),
                    Some(recovery()),
                )
            } else {
                let retry = format!(
                    "sshw doctor --user={} -- {}",
                    hints::quote_local_argument(user),
                    hints::quote_local_argument(server)
                );
                let next = commands.read(&retry, &[server, user]).map(|command| format!("restore access to the credential backend, then rerun `{command}`; entry absence has not been confirmed"))
                    .unwrap_or_else(|| "restore access to the credential backend, then rerun doctor with the original settings selection; entry absence has not been confirmed".into());
                (
                    CredentialStatus::Unavailable,
                    format!(
                        "cannot read {label} credential for {server}/{user}: {}",
                        redacted_error_detail(&error)
                    ),
                    Some(next),
                )
            }
        }
    };
    CredentialCheck {
        server: redact_secrets(server),
        user: redact_secrets(user),
        purpose: label,
        status,
        message: redact_secrets(&message),
        next_step,
    }
}
