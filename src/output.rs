use crate::config::{AuthConfig, ServerConfig};
use crate::error::ClassifiedError;
use serde::Serialize;

const NONINTERACTIVE_STTY_NOISE: &str = "stty: 'standard input': Inappropriate ioctl for device";

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum ErrorKind {
    Safety,
    Config,
    Auth,
    Ssh,
    Io,
    Policy,
    /// CLI usage error (bad arguments / unknown subcommand) detected by the
    /// argument parser before a command runs. Kept distinct from `Safety` (2)
    /// so an agent can tell "called sshw wrong" apart from "a safety rail
    /// blocked the operation".
    Usage,
    Unknown,
}

impl ErrorKind {
    pub fn exit_code(self) -> i32 {
        match self {
            Self::Safety => 2,
            Self::Config => 3,
            Self::Auth => 4,
            Self::Ssh => 5,
            Self::Io => 6,
            Self::Policy => 7,
            Self::Usage => 9,
            Self::Unknown => 1,
        }
    }
}

/// Process exit code for when a remote command ran under sshw's control but
/// itself exited non-zero. Kept distinct from sshw's operational `ErrorKind`
/// codes (1-7) so a remote command's status can never be mistaken for an sshw
/// failure. The real remote status is still reported via `--json`
/// (`exit_status`) and a human-readable note on stderr.
pub const REMOTE_NONZERO_EXIT_CODE: i32 = 8;

#[derive(Debug, Clone, Serialize)]
pub struct ErrorResponse {
    pub ok: bool,
    pub error: ErrorBody,
}

impl ErrorResponse {
    pub fn from_error(err: &anyhow::Error) -> Self {
        let kind = classify_error(err);
        let mut chain = err.chain().map(|cause| redact_secrets(&cause.to_string()));
        let message = chain
            .next()
            .unwrap_or_else(|| redact_secrets(&err.to_string()));
        let mut previous = message.clone();
        let mut causes = Vec::new();
        for cause in chain {
            if cause != previous {
                previous = cause.clone();
                causes.push(cause);
            }
        }
        Self {
            ok: false,
            error: ErrorBody {
                kind,
                message,
                causes,
                exit_code: kind.exit_code(),
            },
        }
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct ErrorBody {
    pub kind: ErrorKind,
    pub message: String,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub causes: Vec<String>,
    pub exit_code: i32,
}

/// Legacy substring markers retained for errors that have not yet crossed a
/// typed application boundary. New production paths attach a [`ClassifiedError`]
/// and therefore remain stable when their human-readable message changes.
/// `ssh2::Error`/`io::Error` are also matched by type as a final fallback.
const SAFETY_MARKER: &str = "requires --yes";
const POLICY_MARKERS: [&str; 3] = ["blocked by policy", "policy file", "policy enforcement"];
const CONFIG_MARKERS: [&str; 17] = [
    "unknown server",
    "no default server configured",
    "failed to load config",
    "failed to load profile registry",
    "failed to save config",
    "profile '",
    "cannot use --home and --profile",
    "not present in the registry",
    "profile add requires",
    "privilege configuration",
    "confirmation requires an interactive terminal",
    "add cancelled",
    "trust cancelled",
    "removal cancelled",
    "privilege update cancelled",
    "privilege clear cancelled",
    "--password-stdin cannot be used with --auth agent",
];
const AUTH_MARKERS: [&str; 5] = [
    "missing credential",
    "credential backend unavailable",
    "authentication",
    "password cannot be empty",
    "must be a single line",
];
const SSH_MARKERS: [&str; 9] = [
    "host key",
    "known_hosts",
    "failed to connect to",
    "failed to resolve",
    "ssh handshake",
    "ssh session",
    "ssh transfer",
    "ended before the completion marker",
    "malformed completion marker",
];
const IO_MARKERS: [&str; 2] = ["local file already exists", "not a regular file"];

/// Map an error to a stable [`ErrorKind`] for agent consumption.
///
/// Typed application errors take precedence. Legacy markers and concrete
/// library error types remain as compatibility fallbacks.
pub fn classify_error(err: &anyhow::Error) -> ErrorKind {
    if let Some(classified) = err
        .chain()
        .find_map(|cause| cause.downcast_ref::<ClassifiedError>())
    {
        return classified.kind();
    }

    let message = format!("{err:#}").to_ascii_lowercase();

    if message.contains(SAFETY_MARKER) {
        return ErrorKind::Safety;
    }

    if POLICY_MARKERS.iter().any(|marker| message.contains(marker)) {
        return ErrorKind::Policy;
    }

    if CONFIG_MARKERS.iter().any(|marker| message.contains(marker)) {
        return ErrorKind::Config;
    }

    if AUTH_MARKERS.iter().any(|marker| message.contains(marker)) {
        return ErrorKind::Auth;
    }

    if SSH_MARKERS.iter().any(|marker| message.contains(marker))
        // ssh2 library errors (handshake/kex/known_hosts) carry no keyword and
        // are not io::Error, so match them by type as a fall-back rather than
        // letting them leak to the unknown bucket.
        || err
            .chain()
            .any(|cause| cause.downcast_ref::<ssh2::Error>().is_some())
    {
        return ErrorKind::Ssh;
    }

    if IO_MARKERS.iter().any(|marker| message.contains(marker))
        || err
            .chain()
            .any(|cause| cause.downcast_ref::<std::io::Error>().is_some())
    {
        return ErrorKind::Io;
    }

    ErrorKind::Unknown
}

#[derive(Debug, Clone, Serialize)]
pub struct RunOutput {
    /// Always `true`; mirrors the `ok` discriminator on the error envelope and
    /// the put/get success summaries so JSON consumers can branch on `ok`.
    pub ok: bool,
    pub server: String,
    pub user: String,
    pub command: String,
    pub exit_status: i32,
    pub stdout: String,
    pub stderr: String,
    pub duration_ms: u128,
}

#[derive(Debug, Clone, Serialize)]
pub struct ServerOutput {
    pub name: String,
    pub host: String,
    pub port: u16,
    pub user: String,
    pub account_count: usize,
    pub is_default: bool,
    pub auth: AuthOutput,
}

impl ServerOutput {
    pub fn from_config(name: &str, server: &ServerConfig, is_default: bool) -> Self {
        let (user, account) = server
            .default_account()
            .expect("validated server config must contain its default account");
        Self {
            name: name.to_string(),
            host: server.host.clone(),
            port: server.port,
            user: user.to_string(),
            account_count: server.accounts.len(),
            is_default,
            auth: AuthOutput::from_config(&account.auth),
        }
    }
}

#[derive(Debug, Clone, Serialize)]
#[serde(tag = "type", rename_all = "lowercase")]
pub enum AuthOutput {
    Password { credential: String },
    Agent,
}

impl AuthOutput {
    fn from_config(auth: &AuthConfig) -> Self {
        match auth {
            AuthConfig::Password { credential } => Self::Password {
                credential: credential.clone(),
            },
            AuthConfig::Agent => Self::Agent,
        }
    }
}

const REDACTED: &str = "<redacted>";

const SENSITIVE_KEYWORDS: &[&str] = &[
    "passphrase",
    "password",
    "passwd",
    "secret_access_key",
    "secret_key",
    "secret",
    "access_token",
    "refresh_token",
    "auth_token",
    "api_key",
    "apikey",
    "api-key",
    "token",
    "authorization",
    "credential",
    "private_key",
];

/// Mask high-confidence secret patterns so they are never echoed back to
/// callers (or written to the audit log). Conservative by design: it only
/// touches PEM private-key blocks, `keyword=value` / `keyword: value`
/// assignments for known-sensitive keywords, and bearer tokens, so ordinary
/// output and non-secret identifiers (e.g. credential names like
/// `sshw:p_abc:web`) pass through unchanged.
pub fn redact_secrets(input: &str) -> String {
    let without_keys = redact_private_key_blocks(input);
    redact_sensitive_lines(&without_keys)
}

fn redact_private_key_blocks(input: &str) -> String {
    let mut out = String::with_capacity(input.len());
    let mut in_key = false;

    for line in input.split_inclusive('\n') {
        let trimmed = line.trim();
        if in_key {
            if is_pem_marker(trimmed, "-----END") {
                in_key = false;
            }
            continue;
        }

        if is_pem_marker(trimmed, "-----BEGIN") {
            in_key = true;
            let newline = if line.ends_with('\n') { "\n" } else { "" };
            out.push_str(&format!("[redacted private key]{newline}"));
            continue;
        }

        out.push_str(line);
    }

    out
}

fn is_pem_marker(trimmed: &str, prefix: &str) -> bool {
    trimmed.starts_with(prefix) && trimmed.contains("PRIVATE KEY")
}

fn redact_sensitive_lines(input: &str) -> String {
    let mut out = String::with_capacity(input.len());
    for line in input.split_inclusive('\n') {
        out.push_str(&redact_line(line));
    }
    out
}

fn redact_line(line: &str) -> String {
    let (content, newline) = split_trailing_newline(line);
    let lower = content.to_ascii_lowercase();

    if let Some(value_start) = bearer_value_start(&lower, content) {
        return format!("{}{REDACTED}{newline}", &content[..value_start]);
    }

    for keyword in SENSITIVE_KEYWORDS {
        if let Some(value_start) = sensitive_value_start(&lower, content, keyword) {
            return format!("{}{REDACTED}{newline}", &content[..value_start]);
        }
    }

    line.to_string()
}

fn split_trailing_newline(line: &str) -> (&str, &str) {
    if let Some(stripped) = line.strip_suffix("\r\n") {
        (stripped, "\r\n")
    } else if let Some(stripped) = line.strip_suffix('\n') {
        (stripped, "\n")
    } else {
        (line, "")
    }
}

fn bearer_value_start(lower: &str, content: &str) -> Option<usize> {
    let marker = "bearer ";
    let pos = lower.find(marker)?;
    let value_start = pos + marker.len();
    if value_start < content.len() && !content[value_start..].trim().is_empty() {
        Some(value_start)
    } else {
        None
    }
}

/// Locate the start of a sensitive value: a `keyword` followed (after optional
/// whitespace) by `=` or `:`, then optional whitespace and an optional opening
/// quote. Returns the byte index in `content` where the value begins, or `None`
/// when the keyword is not used as an assignment.
fn sensitive_value_start(lower: &str, content: &str, keyword: &str) -> Option<usize> {
    let mut search_from = 0;
    while let Some(rel) = lower[search_from..].find(keyword) {
        let kw_end = search_from + rel + keyword.len();
        // Allow an optional closing quote between the keyword and its
        // separator so JSON keys such as `"password":"..."` are detected.
        let mut cursor = kw_end;
        if let Some(c @ ('"' | '\'')) = content[cursor..].chars().next() {
            cursor += c.len_utf8();
        }
        let after = &content[cursor..];
        let leading_ws = after.len() - after.trim_start().len();
        let separator = after.trim_start().chars().next();

        if matches!(separator, Some('=') | Some(':')) {
            let sep_idx = cursor + leading_ws + 1;
            let rest = &content[sep_idx..];
            let rest_ws = rest.len() - rest.trim_start().len();
            let mut value_start = sep_idx + rest_ws;
            if let Some(quote @ ('"' | '\'')) = content[value_start..].chars().next() {
                value_start += quote.len_utf8();
            }
            if value_start < content.len() && !content[value_start..].trim().is_empty() {
                return Some(value_start);
            }
        }

        search_from = kw_end;
    }

    None
}

pub fn filter_startup_stderr_noise(stderr: &str) -> String {
    let mut filtered = String::new();

    for line in stderr.split_inclusive('\n') {
        let trimmed = line.trim_end_matches(['\r', '\n']);
        if trimmed != NONINTERACTIVE_STTY_NOISE {
            filtered.push_str(line);
        }
    }

    filtered
}
