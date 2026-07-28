use crate::output::ErrorKind;
use std::fmt;

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
