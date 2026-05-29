pub mod ssh2_client;

use crate::config::ServerConfig;
use crate::credentials::AuthMaterial;
use std::path::Path;

#[derive(Debug, Clone)]
pub struct RunResult {
    pub exit_status: i32,
    pub stdout: String,
    pub stderr: String,
    pub duration_ms: u128,
}

#[derive(Debug, Clone)]
pub struct TransferResult {
    pub bytes: u64,
    pub source: String,
    pub destination: String,
}

#[derive(Debug, Clone)]
pub struct HostKeyInfo {
    pub algorithm: String,
    pub fingerprint_sha256: String,
}

pub trait SshClient {
    fn host_key(&self, server: &ServerConfig) -> anyhow::Result<HostKeyInfo>;
    fn trust_host(
        &self,
        server_name: &str,
        server: &ServerConfig,
        expected_fingerprint_sha256: &str,
    ) -> anyhow::Result<HostKeyInfo>;
    fn run(
        &self,
        server: &ServerConfig,
        auth: &AuthMaterial,
        command: &str,
    ) -> anyhow::Result<RunResult>;
    fn put(
        &self,
        server: &ServerConfig,
        auth: &AuthMaterial,
        local: &Path,
        remote: &str,
    ) -> anyhow::Result<TransferResult>;
    fn get(
        &self,
        server: &ServerConfig,
        auth: &AuthMaterial,
        remote: &str,
        local: &Path,
        overwrite: bool,
    ) -> anyhow::Result<TransferResult>;
}
