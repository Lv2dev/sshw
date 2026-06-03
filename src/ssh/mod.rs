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
    /// Run `command`, writing `stdin` to the channel before draining output.
    ///
    /// `stdin` is written in full before output draining begins, so it must fit
    /// within the SSH channel's flow-control window (tens of KB). A larger
    /// payload combined with a command that emits substantial output before it
    /// finishes reading stdin can deadlock when no operation timeout is set. The
    /// only in-tree caller passes a single sudo password line, well within
    /// bounds. The default implementation reports the backend as unsupported.
    fn run_with_stdin(
        &self,
        server: &ServerConfig,
        auth: &AuthMaterial,
        command: &str,
        stdin: &str,
    ) -> anyhow::Result<RunResult> {
        let _ = (server, auth, command, stdin);
        Err(anyhow::anyhow!(
            "ssh session stdin is unsupported by this backend"
        ))
    }
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
