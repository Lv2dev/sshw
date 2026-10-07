//! Local shell arguments for diagnostic commands shared by CLI and profile selection.

pub(crate) fn redacted_argument(value: &str) -> String {
    let redacted = crate::output::redact_secrets(value);
    // Mask a whole sensitive argument so a later diagnostic redaction cannot
    // consume the command's remaining options or positional arguments.
    if redacted.contains("<redacted>") || redacted.contains("[redacted private key]") {
        "<redacted>".into()
    } else {
        redacted
    }
}

pub(crate) fn quote_local_argument(value: &str) -> String {
    let value = redacted_argument(value);
    if cfg!(windows) {
        format!("'{}'", value.replace('\'', "''"))
    } else {
        format!("'{}'", value.replace('\'', "'\"'\"'"))
    }
}
