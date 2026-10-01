//! Copyable local commands. Options precede the positional boundary, and each
//! user-provided value is masked before platform-specific shell quoting.

use crate::config::PrivilegeMethod;
use crate::output::redact_secrets;

pub(super) fn quote_local_argument(value: &str) -> String {
    let redacted = redact_secrets(value);
    // Hide the whole argument when it contains a secret pattern. Keeping its
    // assignment prefix would let later error redaction truncate the command.
    let value = if redacted.contains("<redacted>") || redacted.contains("[redacted private key]") {
        "<redacted>"
    } else {
        &redacted
    };
    if cfg!(windows) {
        // PowerShell escapes an apostrophe in a literal by doubling it.
        format!("'{}'", value.replace('\'', "''"))
    } else {
        super::shell_quote(value)
    }
}

pub(super) fn trust(server: &str) -> String {
    format!("sshw trust -- {}", quote_local_argument(server))
}

pub(super) fn run(server: &str, command: &str) -> String {
    format!(
        "sshw run -- {} {}",
        quote_local_argument(server),
        quote_local_argument(command)
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
