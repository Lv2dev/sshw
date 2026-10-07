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
) -> Vec<CredentialCheck> {
    let mut checks = Vec::new();
    for (name, server) in &config.servers {
        for (user, account) in &server.accounts {
            if let AuthConfig::Password { credential } = &account.auth {
                checks.push(check_credential(credentials, name, user, credential, None));
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
        if let Some(privilege) = privilege {
            privilege::recovery_step(server, user, privilege, credentials.is_persistent())
        } else if credentials.is_persistent() {
            format!(
                "using the same home/profile selection, register the account password again with {}; confirm the update, or insert --force and --password-stdin before -- for non-interactive secret-manager input",
                hints::account_password(server, user)
            )
        } else {
            "supply SSHW_PASSWORD at run time using the same home/profile selection; session-only passwords are not persisted. Never put passwords in arguments".to_string()
        }
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
                (CredentialStatus::Unavailable,
                    format!("cannot read {label} credential for {server}/{user}: {}", redacted_error_detail(&error)),
                    Some("restore access to the credential backend, then rerun sshw doctor using the same home/profile selection; entry absence has not been confirmed".to_string()))
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
