use crate::config::{AuthConfig, ServerConfig};
use serde::Serialize;

const NONINTERACTIVE_STTY_NOISE: &str = "stty: 'standard input': Inappropriate ioctl for device";

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
