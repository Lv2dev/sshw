pub(crate) mod atomic_upload;
pub(crate) mod known_hosts;
pub mod ssh2_client;

use crate::config::ServerConfig;
use crate::credentials::AuthMaterial;
use std::path::Path;

/// Output captured before a failed command could be confirmed complete.
/// Display/Debug deliberately omit output; the CLI redacts it before returning it.
pub struct PartialRunError {
    pub source: anyhow::Error,
    pub stdout: String,
    pub stderr: String,
}

impl std::fmt::Debug for PartialRunError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PartialRunError")
            .field("source", &self.source)
            .finish_non_exhaustive()
    }
}
impl std::fmt::Display for PartialRunError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.source.fmt(f)
    }
}
impl std::error::Error for PartialRunError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        Some(self.source.as_ref())
    }
}

#[derive(Debug, Clone)]
pub struct RunResult {
    pub exit_status: i32,
    pub stdout: String,
    pub stderr: String,
    pub duration_ms: u128,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OutputStream {
    Stdout,
    Stderr,
}
/// Raw SSH output; callers must redact before displaying or recording it.
pub type OutputCallback<'a> = dyn FnMut(OutputStream, &[u8]) -> anyhow::Result<()> + 'a;

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

#[derive(Debug, Clone, Copy)]
pub struct SshTarget<'a> {
    pub server: &'a ServerConfig,
    pub user: &'a str,
}

impl<'a> SshTarget<'a> {
    pub fn new(server: &'a ServerConfig, user: &'a str) -> Self {
        Self { server, user }
    }
}

pub trait SshClient {
    /// Inspect the local agent only. None means this backend cannot probe it.
    fn agent_identity_count(&self) -> anyhow::Result<Option<usize>> {
        Ok(None)
    }
    fn host_key(&self, server: &ServerConfig) -> anyhow::Result<HostKeyInfo>;
    fn trust_host(
        &self,
        server_name: &str,
        server: &ServerConfig,
        expected_fingerprint_sha256: &str,
    ) -> anyhow::Result<HostKeyInfo>;
    fn run(
        &self,
        target: &SshTarget<'_>,
        auth: &AuthMaterial,
        command: &str,
    ) -> anyhow::Result<RunResult>;
    fn run_streaming(
        &self,
        target: &SshTarget<'_>,
        auth: &AuthMaterial,
        command: &str,
        stdin: Option<&str>,
        output: &mut OutputCallback<'_>,
    ) -> anyhow::Result<RunResult> {
        let _ = (target, auth, command, stdin, output);
        Err(anyhow::anyhow!(
            "streaming is unsupported by this SSH backend"
        ))
    }
    /// Run `command`, writing `stdin` to the channel before draining output.
    ///
    /// `stdin` is written in full before output draining begins, so it must fit
    /// within the SSH channel's flow-control window (tens of KB). A larger
    /// payload combined with a command that emits substantial output before it
    /// finishes reading stdin can deadlock if the caller explicitly disables
    /// the operation deadline. The only in-tree caller passes a single sudo
    /// password line, well within bounds. The default implementation reports
    /// the backend as unsupported.
    fn run_with_stdin(
        &self,
        target: &SshTarget<'_>,
        auth: &AuthMaterial,
        command: &str,
        stdin: &str,
    ) -> anyhow::Result<RunResult> {
        let _ = (target, auth, command, stdin);
        Err(anyhow::anyhow!(
            "ssh session stdin is unsupported by this backend"
        ))
    }
    /// Run `command` under a PTY, injecting `password` once when the remote
    /// emits a password prompt. Used for `su`, which reads its password from the
    /// controlling terminal (PTY) rather than stdin; PTY echo is disabled so the
    /// password is not echoed into the output.
    ///
    /// `command` is expected to frame its output with the BEGIN/END markers
    /// derived from `marker_nonce` (see `ssh2_client::su_begin_marker`); the
    /// backend uses the same nonce to extract exactly the command's stdout and
    /// exit code, so a command's own output cannot forge the framing. The
    /// default implementation reports the backend as unsupported.
    fn run_with_pty_password(
        &self,
        target: &SshTarget<'_>,
        auth: &AuthMaterial,
        command: &str,
        password: &str,
        marker_nonce: &str,
    ) -> anyhow::Result<RunResult> {
        let _ = (target, auth, command, password, marker_nonce);
        Err(anyhow::anyhow!(
            "ssh pty password injection is unsupported by this backend"
        ))
    }
    fn put(
        &self,
        target: &SshTarget<'_>,
        auth: &AuthMaterial,
        local: &Path,
        remote: &str,
    ) -> anyhow::Result<TransferResult>;
    fn put_with_mode(
        &self,
        target: &SshTarget<'_>,
        auth: &AuthMaterial,
        local: &Path,
        remote: &str,
        mode: u32,
    ) -> anyhow::Result<TransferResult> {
        if mode == 0o600 {
            self.put(target, auth, local, remote)
        } else {
            Err(anyhow::anyhow!(
                "this SSH backend does not support custom upload modes"
            ))
        }
    }
    fn put_atomic(
        &self,
        target: &SshTarget<'_>,
        auth: &AuthMaterial,
        local: &Path,
        remote: &str,
        mode: Option<u32>,
    ) -> anyhow::Result<TransferResult> {
        let _ = (target, auth, local, remote, mode);
        Err(anyhow::anyhow!(
            "atomic upload is unsupported by this SSH backend"
        ))
    }
    fn get(
        &self,
        target: &SshTarget<'_>,
        auth: &AuthMaterial,
        remote: &str,
        local: &Path,
        overwrite: bool,
    ) -> anyhow::Result<TransferResult>;
}
