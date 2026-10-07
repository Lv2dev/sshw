use crate::output::{ConfigMutationOutput, DefaultChange, ErrorKind, redact_secrets};
use std::fmt;
use std::path::Path;

pub(crate) fn redacted_error_detail(error: &anyhow::Error) -> String {
    let mut details = Vec::new();
    for cause in error.chain() {
        let detail = redact_secrets(&cause.to_string());
        if details.last() != Some(&detail) {
            details.push(detail);
        }
    }
    details.join("\ncaused by: ")
}

pub(crate) fn diagnostic_path(path: &Path) -> String {
    let raw = path.display().to_string();
    let redacted = redact_secrets(&raw);
    if redacted != raw {
        "<redacted>".into()
    } else {
        raw
    }
}

pub(crate) fn persistence_error(
    source: anyhow::Error,
    operation: &str,
    path: &Path,
    recovery: &str,
) -> anyhow::Error {
    let detail = redacted_error_detail(&source);
    source.context(format!(
        "failed to {operation} at {}\ncaused by: {detail}\nnext: {recovery}",
        diagnostic_path(path)
    ))
}

/// Add the document's purpose without repeating the nested storage diagnostic.
pub(crate) fn persistence_context(
    source: anyhow::Error,
    operation: &str,
    path: &Path,
) -> anyhow::Error {
    let detail = redact_secrets(&source.to_string());
    source.context(format!(
        "failed to {operation} at {}: {detail}",
        diagnostic_path(path)
    ))
}

pub(crate) fn settings_error(
    source: anyhow::Error,
    label: &str,
    path: &Path,
    recovery: &str,
) -> anyhow::Error {
    let detail = redacted_error_detail(&source);
    source.context(format!(
        "{label} at {}\ncaused by: {detail}\nnext: {recovery}",
        diagnostic_path(path)
    ))
}

/// Error wrapper carrying a stable machine-facing kind independently from its
/// human-readable message and dynamic values.
#[derive(Debug)]
pub struct ClassifiedError {
    kind: ErrorKind,
    source: anyhow::Error,
}

impl ClassifiedError {
    pub fn kind(&self) -> ErrorKind {
        self.kind
    }
}

impl fmt::Display for ClassifiedError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.source.fmt(formatter)
    }
}

impl std::error::Error for ClassifiedError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        Some(self.source.as_ref())
    }
}

pub fn classified_error(kind: ErrorKind, source: anyhow::Error) -> anyhow::Error {
    anyhow::Error::new(ClassifiedError { kind, source })
}

pub fn classified_io_error(
    kind: ErrorKind,
    io_kind: std::io::ErrorKind,
    source: anyhow::Error,
) -> std::io::Error {
    std::io::Error::new(io_kind, ClassifiedError { kind, source })
}

pub fn app_error(kind: ErrorKind, message: impl Into<String>) -> anyhow::Error {
    classified_error(kind, anyhow::anyhow!(message.into()))
}

#[cfg(test)]
mod persistence_tests {
    use super::*;

    #[test]
    fn clear_persistence_diagnostics_redact_paths_causes_and_keep_typed_io() {
        let source = anyhow::Error::new(std::io::Error::new(std::io::ErrorKind::PermissionDenied,
            "token=persistence-secret\n-----BEGIN PRIVATE KEY-----\nprivate-material\n-----END PRIVATE KEY-----"))
            .context("storage service refused the request");
        let error = persistence_error(
            source,
            "write temporary state file",
            Path::new("token=path-secret"),
            "check parent permissions before retrying",
        );
        let error = persistence_context(
            error,
            "save config",
            Path::new("password=destination-secret"),
        );
        let error = classified_error(ErrorKind::Config, error);
        let response = crate::output::ErrorResponse::from_error(&error);
        assert_eq!(response.error.exit_code, 3);
        let rendered = format!("{} {:?}", response.error.message, response.error.causes);
        for secret in [
            "persistence-secret",
            "private-material",
            "path-secret",
            "destination-secret",
        ] {
            assert!(!rendered.contains(secret), "{rendered}");
        }
        assert!(
            response.error.message.contains("storage service refused")
                && response
                    .error
                    .message
                    .contains("next: check parent permissions")
        );
        assert!(error.chain().any(|cause| {
            cause
                .downcast_ref::<std::io::Error>()
                .is_some_and(|io| io.kind() == std::io::ErrorKind::PermissionDenied)
        }));
    }
}

#[derive(Debug)]
pub(crate) struct CredentialCleanupError {
    pub(crate) mutation: ConfigMutationOutput,
    source: anyhow::Error,
}

impl fmt::Display for CredentialCleanupError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "configuration changes saved; credential cleanup failed for server '{}'",
            redact_secrets(&self.mutation.server)
        )?;
        if let Some(account) = &self.mutation.account {
            write!(formatter, " account '{}'", redact_secrets(account))?;
        }
        if let Some(change) = &self.mutation.default_change {
            write!(formatter, "\n{}", change.human_message().trim_end())?;
        }
        // Redact each cause before combining it, including PEM block boundaries.
        let mut previous = None;
        for cause in self.source.chain() {
            let cause = redact_secrets(&cause.to_string());
            if previous.as_ref() != Some(&cause) {
                write!(formatter, "\ncaused by: {cause}")?;
                previous = Some(cause);
            }
        }
        Ok(())
    }
}

impl std::error::Error for CredentialCleanupError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        Some(self.source.as_ref())
    }
}

pub(crate) fn credential_cleanup_error(
    source: anyhow::Error,
    action: &'static str,
    server: &str,
    account: Option<&str>,
    default_change: Option<DefaultChange>,
) -> anyhow::Error {
    classified_error(
        ErrorKind::Auth,
        anyhow::Error::new(CredentialCleanupError {
            mutation: ConfigMutationOutput {
                config_applied: true,
                failed_stage: "credential_cleanup",
                action,
                server: server.to_owned(),
                account: account.map(str::to_owned),
                default_change,
            },
            source,
        }),
    )
}

pub trait ResultErrorKindExt<T> {
    fn with_error_kind(self, kind: ErrorKind) -> anyhow::Result<T>;
}

impl<T, E> ResultErrorKindExt<T> for Result<T, E>
where
    E: Into<anyhow::Error>,
{
    fn with_error_kind(self, kind: ErrorKind) -> anyhow::Result<T> {
        self.map_err(|error| {
            let error = error.into();
            if error
                .chain()
                .any(|cause| cause.downcast_ref::<ClassifiedError>().is_some())
            {
                error
            } else {
                classified_error(kind, error)
            }
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::output::ErrorResponse;

    #[test]
    fn cleanup_error_preserves_source_and_redacts_mutation_fields() {
        let source = anyhow::Error::new(std::io::Error::new(
            std::io::ErrorKind::PermissionDenied,
            "backend denied\n-----BEGIN OPENSSH PRIVATE KEY-----\nprivate-key-body\n-----END OPENSSH PRIVATE KEY-----",
        )).context("backend denied\n-----BEGIN OPENSSH PRIVATE KEY-----\nprivate-key-body\n-----END OPENSSH PRIVATE KEY-----");
        let error = credential_cleanup_error(
            source,
            "removed",
            "token=server-secret",
            Some("password=account-secret"),
            DefaultChange::between(
                "server",
                Some("token=previous-secret".into()),
                Some("token=current-secret".into()),
            ),
        );
        let original = error
            .chain()
            .find_map(|cause| cause.downcast_ref::<std::io::Error>())
            .unwrap();
        assert_eq!(original.kind(), std::io::ErrorKind::PermissionDenied);
        let response = ErrorResponse::from_error(&error);
        assert_eq!(response.error.kind, ErrorKind::Auth);
        assert!(
            response
                .error
                .causes
                .iter()
                .any(|cause| cause.contains("backend denied"))
        );
        let json = serde_json::to_value(&response).unwrap();
        assert_eq!(json["mutation"]["server"], "token=<redacted>");
        assert_eq!(json["mutation"]["account"], "password=<redacted>");
        assert_eq!(
            json["mutation"]["default_change"]["current"],
            "token=<redacted>"
        );
        let rendered = format!("{error}\n{}", json);
        for secret in [
            "server-secret",
            "account-secret",
            "previous-secret",
            "current-secret",
            "private-key-body",
        ] {
            assert!(!rendered.contains(secret), "{rendered}");
        }
    }
}
