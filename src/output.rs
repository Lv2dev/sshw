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
            Self::Unknown => 1,
        }
    }
}

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

pub fn classify_error(err: &anyhow::Error) -> ErrorKind {
    let message = format!("{err:#}").to_ascii_lowercase();

    if message.contains("requires --yes") {
        return ErrorKind::Safety;
    }

    if message.contains("unknown server")
        || message.contains("no default server configured")
        || message.contains("failed to load config")
        || message.contains("failed to save config")
        || message.contains("profile '")
        || message.contains("cannot use --home and --profile")
        || message.contains("not present in the registry")
        || message.contains("profile add requires")
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
