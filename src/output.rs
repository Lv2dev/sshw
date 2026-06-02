use crate::config::{AuthConfig, ServerConfig};
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
        Self {
            ok: false,
            error: ErrorBody {
                kind,
                message: err.to_string(),
                exit_code: kind.exit_code(),
            },
        }
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct ErrorBody {
    pub kind: ErrorKind,
    pub message: String,
    pub exit_code: i32,
}

/// Map an error to a stable [`ErrorKind`] for agent consumption.
///
/// Most kinds are inferred from substrings of the human-readable message, so
/// the marker phrases below are an implicit contract with the modules that
/// *produce* those messages (`safety`, `sandbox`, `cli::prompt`, `config`,
/// `profile`, `cli`). Changing a produced message so it no longer contains its
/// marker silently reclassifies the error to `Unknown`. `tests/output_tests.rs`
/// locks each marker → kind mapping to catch that regression; keep them in sync.
/// `ssh2::Error` and `io::Error` are matched by type as a fallback since they
/// carry no marker.
pub fn classify_error(err: &anyhow::Error) -> ErrorKind {
    let message = format!("{err:#}").to_ascii_lowercase();

    if message.contains("requires --yes") {
        return ErrorKind::Safety;
    }

    if message.contains("blocked by policy")
        || message.contains("policy file")
        || message.contains("policy enforcement")
    {
        return ErrorKind::Policy;
    }

    if message.contains("unknown server")
        || message.contains("no default server configured")
        || message.contains("failed to load config")
        || message.contains("failed to save config")
        || message.contains("profile '")
        || message.contains("cannot use --home and --profile")
        || message.contains("not present in the registry")
        || message.contains("profile add requires")
        || message.contains("privilege configuration")
        || message.contains("confirmation requires an interactive terminal")
        || message.contains("confirmation input ended before a response")
    {
        return ErrorKind::Config;
    }

    if message.contains("missing credential")
        || message.contains("credential store")
        || message.contains("authentication")
        || message.contains("password cannot be empty")
    {
        return ErrorKind::Auth;
    }

    if message.contains("host key")
        || message.contains("known_hosts")
        || message.contains("failed to connect to")
        || message.contains("failed to resolve")
        || message.contains("ssh handshake")
        || message.contains("ssh session")
        || message.contains("ssh transfer")
        // ssh2 library errors (handshake/kex/known_hosts) carry no keyword and
        // are not io::Error, so match them by type as a fall-back rather than
        // letting them leak to the unknown bucket.
        || err
            .chain()
            .any(|cause| cause.downcast_ref::<ssh2::Error>().is_some())
    {
        return ErrorKind::Ssh;
    }

    if message.contains("local file already exists")
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
    pub is_default: bool,
    pub auth: AuthOutput,
}

impl ServerOutput {
    pub fn from_config(name: &str, server: &ServerConfig, is_default: bool) -> Self {
        Self {
            name: name.to_string(),
            host: server.host.clone(),
            port: server.port,
            user: server.user.clone(),
            is_default,
            auth: AuthOutput::from_config(&server.auth),
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
