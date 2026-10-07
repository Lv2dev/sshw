use super::known_hosts::read_known_hosts_file;
use super::{HostKeyInfo, PartialRunError, RunResult, SshClient, SshTarget, TransferResult};
use crate::config::ServerConfig;
use crate::credentials::AuthMaterial;
use crate::error::{
    ResultErrorKindExt, app_error, classified_error, classified_io_error, redacted_error_detail,
};
use crate::local_command::redacted_argument;
use crate::output::{ErrorKind, redact_secrets};
use anyhow::Context;
use base64::Engine;
use directories::BaseDirs;
use ssh2::{
    CheckResult, ErrorCode as Ssh2ErrorCode, HashType, HostKeyType, KnownHostFileKind,
    KnownHostKeyFormat, Session,
};
use std::fs;
use std::io::{self, Read, Write};
use std::net::{SocketAddr, TcpStream, ToSocketAddrs};
use std::path::{Path, PathBuf};
use std::sync::mpsc;
use std::thread;
use std::time::{Duration, Instant};

const DEFAULT_CONNECT_TIMEOUT: Duration = Duration::from_secs(15);
const DEFAULT_OPERATION_TIMEOUT: Duration = Duration::from_secs(15 * 60);
const DEFAULT_OUTPUT_LIMIT: usize = 16 * 1024 * 1024;
const WINDOWS_KEX_HANDSHAKE_RETRIES: usize = 2;

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct RuntimeLibraryVersions {
    pub(crate) libssh2: String,
    pub(crate) openssl: String,
}

pub(crate) fn runtime_library_versions() -> RuntimeLibraryVersions {
    RuntimeLibraryVersions {
        libssh2: option_env!("SSHW_LIBSSH2_VERSION")
            .unwrap_or("unavailable")
            .to_string(),
        openssl: option_env!("SSHW_OPENSSL_VERSION")
            .unwrap_or("unavailable")
            .to_string(),
    }
}

#[derive(Debug, Clone)]
pub struct Ssh2Client {
    connect_timeout: Duration,
    op_timeout: Option<Duration>,
    output_limit: usize,
    known_hosts_path: Option<PathBuf>,
}

impl Default for Ssh2Client {
    fn default() -> Self {
        Self {
            connect_timeout: DEFAULT_CONNECT_TIMEOUT,
            op_timeout: Some(DEFAULT_OPERATION_TIMEOUT),
            output_limit: DEFAULT_OUTPUT_LIMIT,
            known_hosts_path: None,
        }
    }
}

impl Ssh2Client {
    fn put_inner(
        &self,
        target: &SshTarget<'_>,
        auth: &AuthMaterial,
        local: &Path,
        remote: &str,
        mode: Option<u32>,
    ) -> anyhow::Result<TransferResult> {
        if mode.is_some_and(|mode| mode > 0o777) {
            return Err(app_error(
                ErrorKind::Config,
                "upload mode must be between 000 and 777",
            ));
        }
        // Open first, then inspect metadata on that exact handle. A path or
        // symlink replacement during network setup cannot change what is sent.
        let (mut local_file, metadata) = open_regular_local_file(local)?;

        // OpenSSH scp preserves the existing mode unless the sender requests
        // preserve mode (-p). libssh2 enables -p when timestamps are supplied.
        // Explicit --mode therefore stamps transfer time as well; ordinary put
        // retains the original protocol behavior and owner-only creation mode.
        let times = if mode.is_some() {
            let now = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .context("cannot determine upload timestamp")?
                .as_secs()
                .max(1);
            Some((now, now))
        } else {
            None
        };

        let known_hosts = self.resolved_known_hosts_path()?;
        let session = connect_verified_authenticated(
            target.server,
            target.user,
            auth,
            self.connect_timeout,
            self.op_timeout,
            &known_hosts,
        )?;
        let diagnostic = ScpDiagnostic::new(true, target, local, remote);
        let deadline = OperationDeadline::new(self.op_timeout);
        diagnostic.ssh_step(deadline.apply(&session), "open remote file")?;
        let mut remote_file = diagnostic.ssh_step(
            session.scp_send(
                Path::new(remote),
                mode.unwrap_or(0o600) as i32,
                metadata.len(),
                times,
            ),
            "open remote file",
        )?;
        // scp promised `metadata.len()` bytes up front. Cap the reader at that
        // length so a file that grows mid-transfer never writes past the
        // declared size, and fail closed below if fewer bytes were sent (the
        // file shrank), so a truncated upload is never reported as a success.
        let copied = diagnostic.step(
            copy_file_with_deadline(
                &mut local_file,
                &mut remote_file,
                metadata.len(),
                &session,
                &deadline,
            ),
            "send file data",
        )?;
        if copied != metadata.len() {
            return diagnostic.step(
                Err(anyhow::anyhow!(
                    "ssh transfer aborted: local file changed during transfer (expected {} bytes, sent {})",
                    metadata.len(),
                    copied
                )),
                "send file data",
            );
        }
        complete_scp_transfer(&session, &mut remote_file, &deadline, &diagnostic)?;

        Ok(TransferResult {
            bytes: copied,
            source: local.display().to_string(),
            destination: remote.to_string(),
        })
    }

    pub fn connect_timeout(&self) -> Duration {
        self.connect_timeout
    }

    /// Absolute timeout for remote operations (run/put/get) applied after the
    /// connection is established. `None` explicitly disables this bound;
    /// otherwise progress does not extend the deadline.
    pub fn with_op_timeout(mut self, op_timeout: Option<Duration>) -> Self {
        self.op_timeout = op_timeout;
        self
    }

    pub fn op_timeout(&self) -> Option<Duration> {
        self.op_timeout
    }

    /// Maximum combined stdout/stderr bytes retained for one remote command.
    pub fn with_output_limit(mut self, output_limit: usize) -> Self {
        self.output_limit = output_limit;
        self
    }

    pub fn output_limit(&self) -> usize {
        self.output_limit
    }

    /// Use an explicit `known_hosts` file (e.g. the active profile home's file)
    /// instead of the per-user default.
    pub fn with_known_hosts(mut self, path: PathBuf) -> Self {
        self.known_hosts_path = Some(path);
        self
    }

    pub fn known_hosts_override(&self) -> Option<&Path> {
        self.known_hosts_path.as_deref()
    }

    fn resolved_known_hosts_path(&self) -> anyhow::Result<PathBuf> {
        match &self.known_hosts_path {
            Some(path) => Ok(path.clone()),
            None => known_hosts_path(),
        }
    }
}

impl SshClient for Ssh2Client {
    fn agent_identity_count(&self) -> anyhow::Result<Option<usize>> {
        let session = Session::new()?;
        let mut agent = session.agent()?;
        agent
            .connect()
            .context("cannot connect to the local SSH agent")?;
        agent
            .list_identities()
            .context("cannot list SSH agent identities")?;
        Ok(Some(agent.identities()?.len()))
    }
    fn host_key(&self, server: &ServerConfig) -> anyhow::Result<HostKeyInfo> {
        let session = connect(server, self.connect_timeout).with_error_kind(ErrorKind::Ssh)?;
        host_key_info(&session).with_error_kind(ErrorKind::Ssh)
    }

    fn trust_host(
        &self,
        server_name: &str,
        server: &ServerConfig,
        expected_fingerprint_sha256: &str,
    ) -> anyhow::Result<HostKeyInfo> {
        let session = connect(server, self.connect_timeout).with_error_kind(ErrorKind::Ssh)?;
        let (key, key_type) = session
            .host_key()
            .ok_or_else(|| anyhow::anyhow!("server did not provide a host key"))?;
        ensure_supported_host_key(key_type)?;
        let info = host_key_info(&session)?;
        if info.fingerprint_sha256 != expected_fingerprint_sha256 {
            return Err(anyhow::anyhow!(
                "host key fingerprint changed before trust; expected {}, got {}",
                expected_fingerprint_sha256,
                info.fingerprint_sha256
            ));
        }

        let known_hosts_path = self.resolved_known_hosts_path()?;
        let mut known_hosts = session.known_hosts()?;

        if known_hosts_path.exists() {
            read_known_hosts_file(&mut known_hosts, &known_hosts_path)?;
        }

        match known_hosts.check_port(&server.host, server.port, key) {
            CheckResult::Match => Ok(info),
            CheckResult::Mismatch => Err(anyhow::anyhow!(
                "host key for {}:{} changed; refusing to overwrite trusted key",
                server.host,
                server.port
            )),
            CheckResult::Failure => Err(anyhow::anyhow!(
                "failed to check known_hosts for {}:{}",
                server.host,
                server.port
            )),
            CheckResult::NotFound => {
                let host_entry = known_host_name(&server.host, server.port);
                known_hosts.add(
                    &host_entry,
                    key,
                    known_host_comment(server_name),
                    KnownHostKeyFormat::from(key_type),
                )?;
                write_known_hosts_file(&known_hosts, &known_hosts_path)?;
                Ok(info)
            }
        }
    }

    fn run(
        &self,
        target: &SshTarget<'_>,
        auth: &AuthMaterial,
        command: &str,
    ) -> anyhow::Result<RunResult> {
        self.run_inner(target, auth, command, None, None)
    }

    fn run_with_stdin(
        &self,
        target: &SshTarget<'_>,
        auth: &AuthMaterial,
        command: &str,
        stdin: &str,
    ) -> anyhow::Result<RunResult> {
        self.run_inner(target, auth, command, Some(stdin), None)
    }

    fn run_streaming(
        &self,
        target: &SshTarget<'_>,
        auth: &AuthMaterial,
        command: &str,
        stdin: Option<&str>,
        output: &mut super::OutputCallback<'_>,
    ) -> anyhow::Result<RunResult> {
        self.run_inner(target, auth, command, stdin, Some(output))
    }

    fn run_with_pty_password(
        &self,
        target: &SshTarget<'_>,
        auth: &AuthMaterial,
        command: &str,
        password: &str,
        marker_nonce: &str,
    ) -> anyhow::Result<RunResult> {
        self.run_pty_inner(target, auth, command, password, marker_nonce)
    }

    fn put(
        &self,
        target: &SshTarget<'_>,
        auth: &AuthMaterial,
        local: &Path,
        remote: &str,
    ) -> anyhow::Result<TransferResult> {
        self.put_inner(target, auth, local, remote, None)
    }

    fn put_with_mode(
        &self,
        target: &SshTarget<'_>,
        auth: &AuthMaterial,
        local: &Path,
        remote: &str,
        mode: u32,
    ) -> anyhow::Result<TransferResult> {
        self.put_inner(target, auth, local, remote, Some(mode))
    }

    fn put_atomic(
        &self,
        target: &SshTarget<'_>,
        auth: &AuthMaterial,
        local: &Path,
        remote: &str,
        mode: Option<u32>,
    ) -> anyhow::Result<TransferResult> {
        if mode.is_some_and(|mode| mode > 0o777) {
            return Err(app_error(
                ErrorKind::Config,
                "upload mode must be between 000 and 777",
            ));
        }
        super::atomic_upload::parent_path(remote)?;
        let (mut file, metadata) = open_regular_local_file(local)?;
        let session = connect_verified_authenticated(
            target.server,
            target.user,
            auth,
            self.connect_timeout,
            self.op_timeout,
            &self.resolved_known_hosts_path()?,
        )?;
        let deadline = OperationDeadline::new(self.op_timeout);
        let bytes = super::atomic_upload::upload(
            &session,
            &mut file,
            metadata.len(),
            remote,
            mode.unwrap_or(0o600),
            &deadline,
        )?;
        Ok(TransferResult {
            bytes,
            source: local.display().to_string(),
            destination: remote.to_string(),
        })
    }

    fn get(
        &self,
        target: &SshTarget<'_>,
        auth: &AuthMaterial,
        remote: &str,
        local: &Path,
        overwrite: bool,
    ) -> anyhow::Result<TransferResult> {
        crate::storage::check_download_destination(local, overwrite)?;
        let known_hosts = self.resolved_known_hosts_path()?;
        let session = connect_verified_authenticated(
            target.server,
            target.user,
            auth,
            self.connect_timeout,
            self.op_timeout,
            &known_hosts,
        )?;
        let diagnostic = ScpDiagnostic::new(false, target, local, remote);
        let deadline = OperationDeadline::new(self.op_timeout);
        diagnostic.ssh_step(deadline.apply(&session), "open remote file")?;
        let (mut remote_file, stat) =
            diagnostic.ssh_step(session.scp_recv(Path::new(remote)), "open remote file")?;

        // Stage locally first. The final path stays untouched until both the
        // announced size and the remote SCP channel completion are verified.
        let staged = {
            let mut reader = DeadlineReader::new(&mut remote_file, &session, &deadline);
            diagnostic.step(
                crate::storage::stage_stream_owner_only(
                    local,
                    &mut reader,
                    overwrite,
                    Some(stat.size()),
                ),
                "receive file data to local staging",
            )?
        };

        let bytes = persist_after_scp_completion(staged, || {
            // `ssh2::Session::scp_recv` caps reads at the announced file size,
            // hiding SCP's trailing status byte. Acknowledge the completed file
            // so a normal source can exit 0; source-side errors still surface in
            // the SSH channel's non-zero exit status below.
            complete_scp_transfer(&session, &mut remote_file, &deadline, &diagnostic)
        })?;

        Ok(TransferResult {
            bytes,
            source: remote.to_string(),
            destination: local.display().to_string(),
        })
    }
}

impl Ssh2Client {
    fn run_inner(
        &self,
        target: &SshTarget<'_>,
        auth: &AuthMaterial,
        command: &str,
        stdin: Option<&str>,
        output: Option<&mut super::OutputCallback<'_>>,
    ) -> anyhow::Result<RunResult> {
        let started = Instant::now();
        let known_hosts = self.resolved_known_hosts_path()?;
        let session = connect_verified_authenticated(
            target.server,
            target.user,
            auth,
            self.connect_timeout,
            self.op_timeout,
            &known_hosts,
        )?;
        let diagnostic = RunDiagnostic {
            server: target.server,
            user: target.user,
        };
        let deadline = OperationDeadline::new(self.op_timeout);
        diagnostic.ssh_step(deadline.apply(&session), "open SSH session")?;
        let mut channel = diagnostic.ssh_step(session.channel_session(), "open SSH session")?;
        let result = (|| {
            diagnostic.ssh_step(deadline.apply(&session), "execute remote command")?;
            diagnostic.ssh_step(channel.exec(command), "execute remote command")?;
            if let Some(stdin) = stdin {
                diagnostic.ssh_step(deadline.apply(&session), "send command input")?;
                diagnostic.ssh_step(channel.write_all(stdin.as_bytes()), "send command input")?;
            }
            diagnostic.ssh_step(deadline.apply(&session), "send input EOF")?;
            diagnostic.ssh_step(channel.send_eof(), "send input EOF")?;

            let (stdout, stderr) = diagnostic.step(
                read_channel_outputs(&session, &mut channel, &deadline, self.output_limit, output),
                "read command output",
            )?;
            let completion = (|| {
                diagnostic.ssh_step(deadline.apply(&session), "wait for command completion")?;
                diagnostic.ssh_step(channel.wait_close(), "wait for command completion")?;
                diagnostic.step(
                    ensure_remote_command_not_signaled(&channel),
                    "check command exit signal",
                )?;
                diagnostic.ssh_step(channel.exit_status(), "read command exit status")
            })();
            let exit_status = completion.map_err(|source| PartialRunError {
                source,
                stdout: stdout.clone(),
                stderr: stderr.clone(),
            })?;

            Ok(RunResult {
                exit_status,
                stdout,
                stderr,
                duration_ms: started.elapsed().as_millis(),
            })
        })();
        if result.is_err() {
            // Bound blocking channel/session destruction after any run error,
            // including completion errors, regardless of the output mode.
            // Keep the original error and never reuse the operation timeout
            // (which can be 15 minutes or explicitly unlimited) for cleanup.
            session.set_timeout(100);
        }
        result
    }

    fn run_pty_inner(
        &self,
        target: &SshTarget<'_>,
        auth: &AuthMaterial,
        command: &str,
        password: &str,
        marker_nonce: &str,
    ) -> anyhow::Result<RunResult> {
        let started = Instant::now();
        let known_hosts = self.resolved_known_hosts_path()?;
        let session = connect_verified_authenticated(
            target.server,
            target.user,
            auth,
            self.connect_timeout,
            self.op_timeout,
            &known_hosts,
        )?;
        let diagnostic = RunDiagnostic {
            server: target.server,
            user: target.user,
        };
        let deadline = OperationDeadline::new(self.op_timeout);
        diagnostic.ssh_step(deadline.apply(&session), "open SSH session")?;
        let mut channel = diagnostic.ssh_step(session.channel_session(), "open SSH session")?;
        // Disable PTY echo so the injected password is never echoed back into
        // the output stream we collect.
        let mut modes = ssh2::PtyModes::new();
        modes.set_boolean(ssh2::PtyModeOpcode::ECHO, false);
        diagnostic.ssh_step(
            channel.request_pty("xterm", Some(modes), None),
            "request su PTY",
        )?;
        diagnostic.ssh_step(deadline.apply(&session), "execute su command")?;
        diagnostic.ssh_step(channel.exec(command), "execute su command")?;

        let begin_marker = su_begin_marker(marker_nonce);
        let raw = diagnostic.step(
            pty_collect_with_password(
                &session,
                &mut channel,
                password,
                &deadline,
                &begin_marker,
                self.output_limit,
            ),
            "read su PTY output",
        )?;
        diagnostic.ssh_step(deadline.apply(&session), "wait for su completion")?;
        diagnostic.ssh_step(channel.wait_close(), "wait for su completion")?;
        // The PTY channel exit status is unreliable (a signal-killed process can
        // report 0), so the command's real exit code comes from the END marker
        // the wrapper printed. Drain the channel status but do not trust it.
        let _ = channel.exit_status();
        let (stdout, exit_status) = diagnostic.step(
            extract_su_output(&raw, marker_nonce),
            "verify su completion",
        )?;

        Ok(RunResult {
            exit_status,
            stdout,
            // A PTY merges stdout and stderr into one stream; the marker framing
            // separates the command's output from the prompt/su noise.
            stderr: String::new(),
            duration_ms: started.elapsed().as_millis(),
        })
    }
}

pub(crate) fn open_regular_local_file(local: &Path) -> anyhow::Result<(fs::File, fs::Metadata)> {
    // Reject directories/devices/FIFOs before opening (a FIFO open may block).
    // This is only an early check: the opened handle is still checked below and
    // remains the handle whose bytes are sent by the transfer implementation.
    let before_open = fs::metadata(local).map_err(|error| local_file_error(local, error))?;
    if !before_open.is_file() {
        return Err(app_error(
            ErrorKind::Io,
            format!("local path is not a regular file: {}", local.display()),
        ));
    }
    let file = fs::File::open(local).map_err(|error| local_file_error(local, error))?;
    let metadata = file.metadata().with_error_kind(ErrorKind::Io)?;
    if !metadata.is_file() {
        return Err(app_error(
            ErrorKind::Io,
            format!("local path is not a regular file: {}", local.display()),
        ));
    }
    Ok((file, metadata))
}

fn local_file_error(local: &Path, error: io::Error) -> anyhow::Error {
    let description = match error.kind() {
        io::ErrorKind::NotFound => "local file not found",
        io::ErrorKind::PermissionDenied => "permission denied accessing local file",
        _ => "cannot access local file",
    };
    classified_error(
        ErrorKind::Io,
        anyhow::Error::new(error).context(format!("{description}: {}", local.display())),
    )
}

#[cfg(test)]
mod local_file_error_tests {
    use super::*;
    #[test]
    fn file_error_messages_preserve_the_os_cause_without_claiming_not_found() {
        for (kind, expected) in [
            (io::ErrorKind::PermissionDenied, "permission denied"),
            (io::ErrorKind::NotFound, "not found"),
            (io::ErrorKind::Other, "cannot access"),
        ] {
            let error = local_file_error(
                Path::new("fixture"),
                io::Error::new(kind, "synthetic OS cause"),
            );
            assert!(error.to_string().contains(expected));
            assert!(format!("{error:#}").contains("synthetic OS cause"));
            assert_eq!(crate::output::classify_error(&error), ErrorKind::Io);
            if kind != io::ErrorKind::NotFound {
                assert!(!error.to_string().contains("not found"));
            }
        }
    }
}

struct RunDiagnostic<'a> {
    server: &'a ServerConfig,
    user: &'a str,
}

impl RunDiagnostic<'_> {
    fn context(&self, error: anyhow::Error, stage: &str) -> anyhow::Error {
        let detail = redacted_error_detail(&error);
        let recovery = if stage == "open SSH session" || stage == "request su PTY" {
            "check the server's session/PTY limits and access for the selected login account"
        } else {
            "check the connection, server session/command permissions and the selected privilege method if used. Remote completion may be unconfirmed; inspect the command's effects before retrying"
        };
        error.context(format!(
            "SSH execution failed during {stage} for login account '{}' at {}:{}\ncaused by: {detail}\nnext: {recovery}",
            redacted_argument(self.user), redacted_argument(&self.server.host), self.server.port
        ))
    }

    fn step<T>(&self, result: anyhow::Result<T>, stage: &str) -> anyhow::Result<T> {
        result.map_err(|error| match error.downcast::<PartialRunError>() {
            Ok(mut partial) => {
                partial.source = self.context(partial.source, stage);
                anyhow::Error::new(partial)
            }
            Err(error) => self.context(error, stage),
        })
    }

    fn ssh_step<T, E: Into<anyhow::Error>>(
        &self,
        result: Result<T, E>,
        stage: &str,
    ) -> anyhow::Result<T> {
        self.step(
            result.map_err(Into::into).with_error_kind(ErrorKind::Ssh),
            stage,
        )
    }
}

struct ScpDiagnostic<'a> {
    upload: bool,
    server: &'a ServerConfig,
    user: &'a str,
    local: &'a Path,
    remote: &'a str,
}

impl<'a> ScpDiagnostic<'a> {
    fn new(upload: bool, target: &SshTarget<'a>, local: &'a Path, remote: &'a str) -> Self {
        Self {
            upload,
            server: target.server,
            user: target.user,
            local,
            remote,
        }
    }

    fn step<T>(&self, result: anyhow::Result<T>, stage: &str) -> anyhow::Result<T> {
        result.map_err(|error| {
            let detail = redacted_error_detail(&error);
            let recovery = if self.upload {
                "check the remote destination and its parent directory, write permissions for the selected login account, and server SCP support. The remote destination may have changed; inspect it before retrying"
            } else {
                "check that the remote source is a readable regular file for the selected login account, server SCP support, and local destination/parent permissions. Inspect the reported paths before retrying"
            };
            error.context(format!(
                "SCP {} failed during {stage} for login account '{}' at {}:{}\nlocal: {}\nremote: {}\ncaused by: {detail}\nnext: {recovery}",
                if self.upload { "upload" } else { "download" },
                redacted_argument(self.user), redacted_argument(&self.server.host), self.server.port,
                redacted_argument(&self.local.display().to_string()), redacted_argument(self.remote)
            ))
        })
    }

    fn ssh_step<T, E: Into<anyhow::Error>>(
        &self,
        result: Result<T, E>,
        stage: &str,
    ) -> anyhow::Result<T> {
        self.step(
            result.map_err(Into::into).with_error_kind(ErrorKind::Ssh),
            stage,
        )
    }
}

fn complete_scp_transfer(
    session: &Session,
    channel: &mut ssh2::Channel,
    deadline: &OperationDeadline,
    diagnostic: &ScpDiagnostic<'_>,
) -> anyhow::Result<()> {
    diagnostic.ssh_step(deadline.apply(session), "acknowledge transfer")?;
    diagnostic.ssh_step(channel.write_all(&[0]), "acknowledge transfer")?;
    diagnostic.ssh_step(deadline.apply(session), "send EOF")?;
    diagnostic.ssh_step(channel.send_eof(), "send EOF")?;
    diagnostic.ssh_step(deadline.apply(session), "wait for EOF")?;
    diagnostic.ssh_step(channel.wait_eof(), "wait for EOF")?;
    diagnostic.ssh_step(deadline.apply(session), "close channel")?;
    diagnostic.ssh_step(channel.close(), "close channel")?;
    diagnostic.ssh_step(deadline.apply(session), "wait for channel close")?;
    diagnostic.ssh_step(channel.wait_close(), "wait for channel close")?;
    diagnostic.step(
        ensure_scp_transfer_succeeded(channel),
        "verify remote completion",
    )
}

fn ensure_scp_transfer_succeeded(channel: &ssh2::Channel) -> anyhow::Result<()> {
    let signal = channel
        .exit_signal()
        .context("ssh transfer error")
        .with_error_kind(ErrorKind::Ssh)?;
    let exit_status = channel
        .exit_status()
        .context("ssh transfer error")
        .with_error_kind(ErrorKind::Ssh)?;
    validate_scp_completion(
        signal.exit_signal.as_deref(),
        signal.error_message.as_deref(),
        exit_status,
    )
}

fn validate_scp_completion(
    exit_signal: Option<&str>,
    error_message: Option<&str>,
    exit_status: i32,
) -> anyhow::Result<()> {
    if let Some(signal) = exit_signal.filter(|signal| !signal.is_empty()) {
        if let Some(message) = error_message.filter(|message| !message.is_empty()) {
            return Err(app_error(
                ErrorKind::Ssh,
                format!("ssh transfer error: remote scp terminated by signal {signal}: {message}"),
            ));
        }
        return Err(app_error(
            ErrorKind::Ssh,
            format!("ssh transfer error: remote scp terminated by signal {signal}"),
        ));
    }
    if exit_status != 0 {
        return Err(app_error(
            ErrorKind::Ssh,
            format!("ssh transfer error: remote scp exited with status {exit_status}"),
        ));
    }
    Ok(())
}

fn persist_after_scp_completion<F>(
    staged: crate::storage::StagedStreamWrite,
    complete: F,
) -> anyhow::Result<u64>
where
    F: FnOnce() -> anyhow::Result<()>,
{
    complete()?;
    staged.persist()
}

fn ensure_remote_command_not_signaled(channel: &ssh2::Channel) -> anyhow::Result<()> {
    let signal = channel
        .exit_signal()
        .context("ssh session error")
        .with_error_kind(ErrorKind::Ssh)?;
    let Some(signal_name) = signal.exit_signal.filter(|name| !name.is_empty()) else {
        return Ok(());
    };

    if let Some(remote_message) = signal.error_message.filter(|message| !message.is_empty()) {
        return Err(app_error(
            ErrorKind::Ssh,
            format!(
                "ssh session error: remote command terminated by signal {signal_name}: {remote_message}"
            ),
        ));
    }
    Err(app_error(
        ErrorKind::Ssh,
        format!("ssh session error: remote command terminated by signal {signal_name}"),
    ))
}

fn connect_verified_authenticated(
    server: &ServerConfig,
    user: &str,
    auth: &AuthMaterial,
    connect_timeout: Duration,
    op_timeout: Option<Duration>,
    known_hosts_path: &Path,
) -> anyhow::Result<Session> {
    let session = connect(server, connect_timeout).with_error_kind(ErrorKind::Ssh)?;
    verify_known_host(&session, server, known_hosts_path).with_error_kind(ErrorKind::Ssh)?;
    authenticate(&session, server, user, auth).with_error_kind(ErrorKind::Auth)?;
    // Switch from the connect-phase timeout to the operation budget (0 = an
    // explicit opt-out). Individual operation steps tighten this to the
    // absolute deadline's remaining time.
    session.set_timeout(op_timeout_millis(op_timeout));
    Ok(session)
}

#[derive(Clone, Copy)]
enum ConnectStage {
    Resolve,
    Tcp,
    Handshake,
}

fn diagnostic_value(value: &str) -> String {
    let redacted = redact_secrets(value);
    if redacted == value {
        redacted
    } else {
        "<redacted>".into()
    }
}

fn connect_diagnostic(
    source: anyhow::Error,
    server: &ServerConfig,
    timeout: Duration,
    stage: ConnectStage,
) -> anyhow::Error {
    let (operation, recovery) = match stage {
        ConnectStage::Resolve => (
            "resolve",
            "check the configured host/port, DNS availability and network connectivity",
        ),
        ConnectStage::Tcp => (
            "connect to",
            "check the configured host/port, that the SSH service is listening, and network/firewall access",
        ),
        ConnectStage::Handshake => (
            "complete SSH handshake with",
            "check that the endpoint is running SSH and inspect server/network logs before retrying",
        ),
    };
    let host = diagnostic_value(&server.host);
    let detail = redacted_error_detail(&source);
    source.context(format!(
        "failed to {operation} {host}:{} (connect timeout budget: {} ms)\ncaused by: {detail}\nnext: {recovery}",
        server.port,
        timeout.as_millis(),
    ))
}

fn connect(server: &ServerConfig, timeout: Duration) -> anyhow::Result<Session> {
    let address = format!("{}:{}", server.host, server.port);
    let deadline = ConnectDeadline::new(timeout);
    let resolver_address = address.clone();
    let socket_addrs = resolve_with_deadline(&deadline, move || {
        resolver_address
            .to_socket_addrs()
            .map(|addresses| addresses.collect())
    })
    .map_err(|error| connect_diagnostic(error, server, timeout, ConnectStage::Resolve))?;
    let mut last_error = None;
    let mut resolved_any = false;
    for socket_addr in socket_addrs {
        resolved_any = true;
        let mut kex_retries_remaining = WINDOWS_KEX_HANDSHAKE_RETRIES;
        loop {
            let remaining = deadline
                .remaining()
                .map_err(|error| connect_diagnostic(error, server, timeout, ConnectStage::Tcp))?;
            match TcpStream::connect_timeout(&socket_addr, remaining) {
                Ok(tcp) => {
                    let handshake = (|| -> anyhow::Result<Session> {
                        tcp.set_read_timeout(Some(deadline.remaining()?))?;
                        tcp.set_write_timeout(Some(deadline.remaining()?))?;
                        let mut session = Session::new()?;
                        session.set_timeout(timeout_millis(deadline.remaining()?));
                        session.set_tcp_stream(tcp);
                        session.handshake()?;
                        Ok(session)
                    })();
                    match handshake {
                        Ok(session) => return Ok(session),
                        Err(err)
                            if err.downcast_ref::<ssh2::Error>().is_some_and(|error| {
                                should_retry_windows_kex(error, kex_retries_remaining)
                            }) =>
                        {
                            kex_retries_remaining -= 1;
                        }
                        Err(err) => {
                            return Err(connect_diagnostic(
                                err,
                                server,
                                timeout,
                                ConnectStage::Handshake,
                            ));
                        }
                    }
                }
                Err(err) => {
                    last_error = Some(err);
                    break;
                }
            }
        }
    }

    if !resolved_any {
        return Err(connect_diagnostic(
            anyhow::anyhow!("resolver returned no addresses"),
            server,
            timeout,
            ConnectStage::Resolve,
        ));
    }

    let err = last_error
        .map(anyhow::Error::from)
        .unwrap_or_else(|| anyhow::anyhow!("no resolved address was reachable"));
    Err(connect_diagnostic(err, server, timeout, ConnectStage::Tcp))
}

fn should_retry_windows_kex(error: &ssh2::Error, retries_remaining: usize) -> bool {
    cfg!(windows)
        && retries_remaining > 0
        && matches!(
            error.code(),
            Ssh2ErrorCode::Session(code)
                if code == libssh2_sys::LIBSSH2_ERROR_KEY_EXCHANGE_FAILURE
        )
}

#[derive(Debug)]
struct ConnectDeadline {
    started: Instant,
    timeout: Duration,
}

impl ConnectDeadline {
    fn new(timeout: Duration) -> Self {
        Self {
            started: Instant::now(),
            timeout,
        }
    }

    fn remaining(&self) -> anyhow::Result<Duration> {
        let elapsed = self.started.elapsed();
        if elapsed >= self.timeout {
            return Err(self.timeout_error());
        }
        Ok(self.timeout - elapsed)
    }

    fn timeout_error(&self) -> anyhow::Error {
        app_error(
            ErrorKind::Ssh,
            format!(
                "ssh connect phase timed out after {} milliseconds",
                self.timeout.as_millis()
            ),
        )
    }
}

fn resolve_with_deadline<F>(
    deadline: &ConnectDeadline,
    resolver: F,
) -> anyhow::Result<Vec<SocketAddr>>
where
    F: FnOnce() -> io::Result<Vec<SocketAddr>> + Send + 'static,
{
    let (sender, receiver) = mpsc::sync_channel(1);
    thread::Builder::new()
        .name("sshw-dns-resolver".to_string())
        .spawn(move || {
            let _ = sender.send(resolver());
        })
        .with_error_kind(ErrorKind::Ssh)?;

    match receiver.recv_timeout(deadline.remaining()?) {
        Ok(Ok(addresses)) => Ok(addresses),
        Ok(Err(err)) => Err(anyhow::Error::new(err)),
        Err(mpsc::RecvTimeoutError::Timeout) => Err(deadline.timeout_error()),
        Err(mpsc::RecvTimeoutError::Disconnected) => Err(app_error(
            ErrorKind::Ssh,
            "failed to resolve address because the resolver stopped unexpectedly",
        )),
    }
}

pub(super) fn timeout_millis(timeout: Duration) -> u32 {
    timeout.as_millis().clamp(1, u32::MAX as u128) as u32
}

/// libssh2 blocking timeout in milliseconds for the operation phase. `None`
/// maps to `0`, which libssh2 treats as "no timeout".
fn op_timeout_millis(op_timeout: Option<Duration>) -> u32 {
    op_timeout.map(timeout_millis).unwrap_or(0)
}

#[derive(Debug, Clone, Copy)]
pub(super) struct OperationDeadline {
    started: Instant,
    timeout: Option<Duration>,
}

impl OperationDeadline {
    fn new(timeout: Option<Duration>) -> Self {
        Self {
            started: Instant::now(),
            timeout,
        }
    }

    pub(super) fn remaining(&self) -> anyhow::Result<Option<Duration>> {
        let Some(timeout) = self.timeout else {
            return Ok(None);
        };
        let elapsed = self.started.elapsed();
        if elapsed >= timeout {
            return Err(app_error(
                ErrorKind::Ssh,
                format!(
                    "ssh operation timed out after {} milliseconds",
                    timeout.as_millis()
                ),
            ));
        }
        Ok(Some(timeout - elapsed))
    }

    pub(super) fn apply(&self, session: &Session) -> anyhow::Result<()> {
        session.set_timeout(op_timeout_millis(self.remaining()?));
        Ok(())
    }

    fn apply_io(&self, session: &Session) -> io::Result<()> {
        let remaining = self
            .remaining()
            .map_err(|err| classified_io_error(ErrorKind::Ssh, io::ErrorKind::TimedOut, err))?;
        session.set_timeout(op_timeout_millis(remaining));
        Ok(())
    }
}

struct DeadlineReader<'a, R> {
    inner: &'a mut R,
    session: &'a Session,
    deadline: &'a OperationDeadline,
}

impl<'a, R> DeadlineReader<'a, R> {
    fn new(inner: &'a mut R, session: &'a Session, deadline: &'a OperationDeadline) -> Self {
        Self {
            inner,
            session,
            deadline,
        }
    }
}

impl<R: Read> Read for DeadlineReader<'_, R> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        self.deadline.apply_io(self.session)?;
        self.inner.read(buf).map_err(|error| {
            let kind = error.kind();
            classified_io_error(ErrorKind::Ssh, kind, anyhow::Error::new(error))
        })
    }
}

fn copy_file_with_deadline(
    local: &mut fs::File,
    remote: &mut ssh2::Channel,
    expected: u64,
    session: &Session,
    deadline: &OperationDeadline,
) -> anyhow::Result<u64> {
    let mut copied = 0u64;
    let mut buffer = [0u8; 32 * 1024];

    while copied < expected {
        deadline.apply(session).with_error_kind(ErrorKind::Ssh)?;
        let remaining = (expected - copied).min(buffer.len() as u64) as usize;
        let read = local
            .read(&mut buffer[..remaining])
            .with_error_kind(ErrorKind::Io)?;
        if read == 0 {
            break;
        }

        let mut written = 0;
        while written < read {
            deadline.apply(session).with_error_kind(ErrorKind::Ssh)?;
            let count = remote
                .write(&buffer[written..read])
                .context("ssh transfer error")
                .with_error_kind(ErrorKind::Ssh)?;
            if count == 0 {
                return Err(classified_error(
                    ErrorKind::Ssh,
                    anyhow::Error::new(io::Error::new(
                        io::ErrorKind::WriteZero,
                        "failed to write the complete local file to the SSH channel",
                    ))
                    .context("ssh transfer error"),
                ));
            }
            written += count;
        }
        copied += read as u64;
    }

    Ok(copied)
}

/// Drive a PTY-backed `su` execution: read the merged PTY output non-blocking,
/// inject `password` (plus a newline) exactly once when the password prompt is
/// detected, close channel input, then collect the rest until EOF. PTY echo is
/// disabled and the prompt locale is forced to English (LC_ALL=C) by the
/// caller, so the password is not reflected back.
fn pty_collect_with_password(
    session: &Session,
    channel: &mut ssh2::Channel,
    password: &str,
    deadline: &OperationDeadline,
    begin_marker: &str,
    output_limit: usize,
) -> anyhow::Result<String> {
    session.set_blocking(false);
    let collected = pty_collect_loop(
        session,
        channel,
        password,
        deadline,
        begin_marker,
        output_limit,
    );
    session.set_blocking(true);
    let out = collected?;
    Ok(decode_remote_output_lossy(out))
}

fn pty_collect_loop(
    session: &Session,
    channel: &mut ssh2::Channel,
    password: &str,
    deadline: &OperationDeadline,
    begin_marker: &str,
    output_limit: usize,
) -> anyhow::Result<Vec<u8>> {
    // Upper bound on the prompt/auth phase (before the command's BEGIN marker
    // appears) so a missing or unrecognized password prompt cannot hang forever
    // even when the caller explicitly disables the operation deadline.
    const PROMPT_WAIT: Duration = Duration::from_secs(30);
    let mut out = Vec::new();
    let mut buf = [0u8; 32 * 1024];
    let mut injected = false;
    let mut input_closed = false;
    let mut command_started = false;
    let prompt_started = Instant::now();

    loop {
        deadline.remaining()?;
        let mut progressed = false;
        match channel.read(&mut buf) {
            Ok(0) => break,
            Ok(n) => {
                append_output_bounded(&mut out, &buf[..n], 0, output_limit)?;
                progressed = true;
            }
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {}
            Err(e) => {
                return Err(classified_error(
                    ErrorKind::Ssh,
                    anyhow::Error::new(e).context("ssh session error"),
                ));
            }
        }

        if !command_started && contains_subslice(&out, begin_marker.as_bytes()) {
            // su authenticated and the wrapper began running the command; from
            // here the command's own runtime governs the timeout.
            command_started = true;
        }

        let should_inject = !injected && !command_started && output_has_password_prompt(&out);
        if !input_closed && (should_inject || command_started) {
            // Complete the one allowed input exchange and explicitly close
            // stdin. This lets commands that read to EOF terminate instead of
            // waiting forever on an open PTY channel.
            session.set_blocking(true);
            let write = (|| -> anyhow::Result<()> {
                deadline.apply(session)?;
                if should_inject {
                    channel
                        .write_all(password.as_bytes())
                        .and_then(|()| channel.write_all(b"\n"))
                        .context("ssh session error")?;
                }
                // SSH channel EOF alone does not make a PTY's canonical line
                // discipline return EOF. Queue the terminal VEOF character so
                // the privileged command cannot block reading stdin forever.
                channel.write_all(&[0x04]).context("ssh session error")?;
                channel.flush().context("ssh session error")?;
                deadline.apply(session)?;
                channel.send_eof().context("ssh session error")?;
                Ok(())
            })();
            session.set_blocking(false);
            write?;
            injected |= should_inject;
            input_closed = true;
            progressed = true;
        }

        if !command_started && prompt_started.elapsed() >= PROMPT_WAIT {
            return Err(app_error(
                ErrorKind::Ssh,
                "ssh session timed out waiting for the su password prompt or output",
            ));
        }
        if !progressed {
            std::thread::sleep(Duration::from_millis(5));
        }
    }

    Ok(out)
}

/// True if the accumulated PTY output is currently *waiting* at a password
/// prompt. Checked before injection only.
///
/// `su` prints the prompt without a trailing newline and then blocks for input,
/// so only the final unterminated line (the tail after the last `\n`/`\r`) is a
/// live prompt candidate — completed lines are already-past output. We require
/// that tail to contain "password" and, after trimming trailing spaces, end
/// with a colon. This stops an earlier banner/PAM line that merely mentions a
/// password (e.g. "Last password change: ..." or "...change your password")
/// from triggering an early injection before the real prompt appears. LC_ALL=C
/// makes `su`/PAM print the English "Password:" prompt. Limitation: a
/// non-standard prompt without a trailing colon would not be detected, in which
/// case the bounded prompt-wait surfaces a timeout rather than misfiring.
fn output_has_password_prompt(out: &[u8]) -> bool {
    let text = String::from_utf8_lossy(out);
    let tail = text.rsplit(['\n', '\r']).next().unwrap_or("");
    let lower = tail.to_ascii_lowercase();
    lower.contains("password") && lower.trim_end().ends_with(':')
}

/// Build the BEGIN marker that frames a `su` command's output on the PTY from a
/// per-execution `nonce`. The remote wrapper (`cli::su_command`) prints BEGIN,
/// then the command's own stdout, then the END marker followed by the command's
/// exit code and a trailing `__`. Shared with the cli so the producer and parser
/// agree on the protocol.
///
/// The nonce (hex, from `cli::su_marker_nonce`) makes the framing unpredictable
/// so a command's own stdout cannot accidentally — or via a `cat` of
/// attacker-influenced data — reproduce the END marker and thereby truncate the
/// captured output or spoof the exit code. A command that inspects its parent's
/// argv (e.g. `ps`/`/proc/<ppid>/cmdline`) could still read the nonce, but it is
/// already running as root in that case, so that is out of scope; the nonce
/// defends against accidental and data-borne collisions, not a process already
/// privileged enough to observe its launcher.
pub(crate) fn su_begin_marker(nonce: &str) -> String {
    format!("__SSHW_BEGIN_{nonce}__")
}

/// Prefix of the END marker for `nonce`; the command's exit-code digits and a
/// trailing `__` follow it.
pub(crate) fn su_end_prefix(nonce: &str) -> String {
    format!("__SSHW_END_{nonce}_")
}

/// True if `needle` occurs in `haystack` (byte search; no allocation).
fn contains_subslice(haystack: &[u8], needle: &[u8]) -> bool {
    needle.is_empty()
        || haystack
            .windows(needle.len())
            .any(|window| window == needle)
}

fn decode_remote_output_lossy(bytes: Vec<u8>) -> String {
    match String::from_utf8(bytes) {
        Ok(output) => output,
        Err(error) => String::from_utf8_lossy(&error.into_bytes()).into_owned(),
    }
}

/// Parse the marker-framed output of a `su` PTY run. Everything before BEGIN
/// (prompt, echo, su/login noise) is discarded; the bytes between BEGIN and END
/// are the command's stdout, and the digits after END are its exit code. A
/// missing BEGIN marker means su never reached the command (authentication
/// failed or the prompt was not answered), independent of any localized text —
/// this replaces both the fragile prompt-line stripping and the English-only
/// auth-failure substring match.
fn extract_su_output(raw: &str, marker_nonce: &str) -> anyhow::Result<(String, i32)> {
    let begin_marker = su_begin_marker(marker_nonce);
    let end_prefix = su_end_prefix(marker_nonce);
    let begin = raw.find(&begin_marker).ok_or_else(|| {
        app_error(
            ErrorKind::Auth,
            "su authentication failed or password prompt was not answered",
        )
    })?;
    let after_begin = begin + begin_marker.len();
    // Body starts after the newline that follows the BEGIN marker.
    let body_start = raw[after_begin..]
        .find('\n')
        .map(|nl| after_begin + nl + 1)
        .unwrap_or(after_begin);
    let end_rel = raw[body_start..].find(&end_prefix).ok_or_else(|| {
        app_error(
            ErrorKind::Ssh,
            "su output ended before the completion marker",
        )
    })?;
    let end_abs = body_start + end_rel;
    let body = &raw[body_start..end_abs];
    // Exit-code digits follow the END prefix (terminated by `__`).
    let after_end = end_abs + end_prefix.len();
    let marker_tail = &raw[after_end..];
    let digit_len = marker_tail
        .bytes()
        .take_while(|b| b.is_ascii_digit())
        .count();
    if digit_len == 0 || !marker_tail[digit_len..].starts_with("__") {
        return Err(app_error(
            ErrorKind::Ssh,
            "su output ended with a malformed completion marker",
        ));
    }
    let exit_code = marker_tail[..digit_len]
        .parse::<i32>()
        .context("su output ended with a malformed completion marker")
        .with_error_kind(ErrorKind::Ssh)?;
    let stdout = body.replace("\r\n", "\n").replace('\r', "\n");
    Ok((stdout, exit_code))
}

/// Read a channel's stdout and stderr concurrently so a large volume on one
/// stream cannot deadlock the other. libssh2 multiplexes both over one TCP
/// connection with per-stream flow-control windows; reading stdout fully before
/// touching stderr stalls the remote once the stderr window fills (and vice
/// versa).
///
/// Switches the session to non-blocking, drains both streams round-robin until
/// each reaches EOF, then restores blocking mode for the caller's `wait_close`.
/// Progress never extends the absolute operation deadline, and stdout plus
/// stderr may not exceed `output_limit` bytes in total.
fn read_channel_outputs(
    session: &Session,
    channel: &mut ssh2::Channel,
    deadline: &OperationDeadline,
    output_limit: usize,
    output: Option<&mut super::OutputCallback<'_>>,
) -> anyhow::Result<(String, String)> {
    session.set_blocking(false);
    let drained = drain_both_streams(channel, deadline, output_limit, output);
    session.set_blocking(true);
    let (out, err) = drained?;
    let stdout = decode_remote_output_lossy(out);
    let stderr = decode_remote_output_lossy(err);
    Ok((stdout, stderr))
}

fn drain_both_streams(
    channel: &mut ssh2::Channel,
    deadline: &OperationDeadline,
    output_limit: usize,
    mut output: Option<&mut super::OutputCallback<'_>>,
) -> anyhow::Result<(Vec<u8>, Vec<u8>)> {
    let mut out = Vec::new();
    let mut err = Vec::new();
    let mut out_done = false;
    let mut err_done = false;
    let mut buf = [0u8; 32 * 1024];

    let result = (|| -> anyhow::Result<()> {
        while !(out_done && err_done) {
            deadline.remaining()?;
            let mut progressed = false;

            if !out_done {
                match channel.read(&mut buf) {
                    Ok(0) => out_done = true,
                    Ok(n) => {
                        append_output_bounded(&mut out, &buf[..n], err.len(), output_limit)?;
                        if let Some(sink) = output.as_mut() {
                            sink(super::OutputStream::Stdout, &buf[..n])?;
                        }
                        progressed = true;
                    }
                    Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {}
                    Err(e) => {
                        return Err(classified_error(
                            ErrorKind::Ssh,
                            anyhow::Error::new(e).context("ssh session error"),
                        ));
                    }
                }
            }

            if !err_done {
                match channel.stderr().read(&mut buf) {
                    Ok(0) => err_done = true,
                    Ok(n) => {
                        append_output_bounded(&mut err, &buf[..n], out.len(), output_limit)?;
                        if let Some(sink) = output.as_mut() {
                            sink(super::OutputStream::Stderr, &buf[..n])?;
                        }
                        progressed = true;
                    }
                    Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {}
                    Err(e) => {
                        return Err(classified_error(
                            ErrorKind::Ssh,
                            anyhow::Error::new(e).context("ssh session error"),
                        ));
                    }
                }
            }

            if !(progressed || out_done && err_done) {
                std::thread::sleep(Duration::from_millis(5));
            }
        }
        Ok(())
    })();
    match result {
        Ok(()) => Ok((out, err)),
        Err(source) => Err(PartialRunError {
            source,
            stdout: decode_remote_output_lossy(out),
            stderr: decode_remote_output_lossy(err),
        }
        .into()),
    }
}

fn append_output_bounded(
    target: &mut Vec<u8>,
    bytes: &[u8],
    other_len: usize,
    output_limit: usize,
) -> anyhow::Result<()> {
    let combined = target
        .len()
        .checked_add(other_len)
        .and_then(|len| len.checked_add(bytes.len()))
        .unwrap_or(usize::MAX);
    if combined > output_limit {
        return Err(app_error(
            ErrorKind::Ssh,
            format!("ssh session output exceeded {output_limit}-byte limit"),
        ));
    }
    target.extend_from_slice(bytes);
    Ok(())
}

fn verify_known_host(
    session: &Session,
    server: &ServerConfig,
    known_hosts_path: &Path,
) -> anyhow::Result<()> {
    let (key, _key_type) = session
        .host_key()
        .ok_or_else(|| anyhow::anyhow!("server did not provide a host key"))?;
    if !known_hosts_path.exists() {
        return Err(unknown_host_key_error(server));
    }

    let mut known_hosts = session.known_hosts()?;
    read_known_hosts_file(&mut known_hosts, known_hosts_path)?;

    known_host_verification_result(
        known_hosts.check_port(&server.host, server.port, key),
        server,
    )
}

fn write_known_hosts_file(known_hosts: &ssh2::KnownHosts, path: &Path) -> anyhow::Result<()> {
    let mut output = String::new();
    for host in known_hosts.hosts()? {
        output.push_str(&known_hosts.write_string(&host, KnownHostFileKind::OpenSSH)?);
    }
    crate::storage::write_owner_only_atomic(path, &output)
        .with_context(|| format!("failed to write known_hosts file: {}", path.display()))
}

fn known_host_verification_result(
    result: CheckResult,
    server: &ServerConfig,
) -> anyhow::Result<()> {
    match result {
        CheckResult::Match => Ok(()),
        CheckResult::NotFound => Err(unknown_host_key_error(server)),
        CheckResult::Mismatch => Err(anyhow::anyhow!(
            "host key verification failed for {}:{}; trusted key changed",
            server.host,
            server.port
        )),
        CheckResult::Failure => Err(anyhow::anyhow!(
            "host key verification failed for {}:{}",
            server.host,
            server.port
        )),
    }
}

fn agent_auth_diagnostic(
    source: anyhow::Error,
    server: &ServerConfig,
    user: &str,
) -> anyhow::Error {
    let detail = redacted_error_detail(&source);
    source.context(format!(
        "SSH agent authentication failed for login account '{}' at {}:{}\ncaused by: {detail}\nnext: using the same home/profile and execution environment, run `sshw doctor` to check agent availability and identities; check the agent connection and load the intended key if needed, then verify that the server allows this login account/key",
        diagnostic_value(user), diagnostic_value(&server.host), server.port,
    ))
}

fn password_auth_diagnostic(
    source: anyhow::Error,
    server: &ServerConfig,
    user: &str,
) -> anyhow::Error {
    let detail = redacted_error_detail(&source);
    source.context(format!(
        "SSH password authentication failed for login account '{}' at {}:{}\ncaused by: {detail}\nnext: using the same home/profile selection, run `sshw doctor` to inspect local credential readiness; check the selected login password (SSHW_PASSWORD for session-only homes), the server's password authentication settings and whether this account is allowed to log in. Never put passwords in arguments",
        diagnostic_value(user), diagnostic_value(&server.host), server.port,
    ))
}

fn authenticate(
    session: &Session,
    server: &ServerConfig,
    user: &str,
    auth: &AuthMaterial,
) -> anyhow::Result<()> {
    match auth {
        AuthMaterial::Password(password) => {
            session
                .userauth_password(user, password)
                .map_err(|error| password_auth_diagnostic(error.into(), server, user))?;
        }
        AuthMaterial::Agent => {
            session
                .userauth_agent(user)
                .map_err(|error| agent_auth_diagnostic(error.into(), server, user))?;
        }
    }

    if !session.authenticated() {
        if matches!(auth, AuthMaterial::Password(_)) {
            return Err(password_auth_diagnostic(
                anyhow::anyhow!("SSH authentication did not complete"),
                server,
                user,
            ));
        }
        return Err(anyhow::anyhow!("SSH authentication failed"));
    }

    Ok(())
}

fn host_key_info(session: &Session) -> anyhow::Result<HostKeyInfo> {
    let (_key, key_type) = session
        .host_key()
        .ok_or_else(|| anyhow::anyhow!("server did not provide a host key"))?;
    ensure_supported_host_key(key_type)?;
    let fingerprint = session
        .host_key_hash(HashType::Sha256)
        .ok_or_else(|| anyhow::anyhow!("could not compute host key fingerprint"))?;

    Ok(HostKeyInfo {
        algorithm: host_key_algorithm(key_type).to_string(),
        fingerprint_sha256: format!(
            "SHA256:{}",
            base64::engine::general_purpose::STANDARD_NO_PAD.encode(fingerprint)
        ),
    })
}

fn ensure_supported_host_key(key_type: HostKeyType) -> anyhow::Result<()> {
    if matches!(key_type, HostKeyType::Unknown) {
        return Err(anyhow::anyhow!(
            "unsupported host key type from server; refusing to trust automatically"
        ));
    }
    Ok(())
}

fn host_key_algorithm(key_type: HostKeyType) -> &'static str {
    match key_type {
        HostKeyType::Unknown => "unknown",
        HostKeyType::Rsa => "ssh-rsa",
        HostKeyType::Dss => "ssh-dss",
        HostKeyType::Ecdsa256 => "ecdsa-sha2-nistp256",
        HostKeyType::Ecdsa384 => "ecdsa-sha2-nistp384",
        HostKeyType::Ecdsa521 => "ecdsa-sha2-nistp521",
        HostKeyType::Ed25519 => "ssh-ed25519",
    }
}

fn known_hosts_path() -> anyhow::Result<PathBuf> {
    let dirs = BaseDirs::new()
        .ok_or_else(|| anyhow::anyhow!("could not determine user home directory"))?;
    Ok(dirs.home_dir().join(".ssh").join("known_hosts"))
}

fn known_host_name(host: &str, port: u16) -> String {
    if port == 22 {
        host.to_string()
    } else {
        format!("[{host}]:{port}")
    }
}

fn known_host_comment(_server_name: &str) -> &'static str {
    "sshw"
}

fn unknown_host_key_error(server: &ServerConfig) -> anyhow::Error {
    anyhow::anyhow!(
        "host key for {}:{} is not trusted; run `sshw trust <name>` first",
        server.host,
        server.port
    )
}

#[cfg(test)]
mod tests {
    use crate::config::{AuthConfig, ServerConfig};
    use crate::error::ResultErrorKindExt;
    use crate::output::ErrorKind;
    use ssh2::CheckResult;
    use std::fs;

    const KNOWN_HOSTS_LINE: &str = "\
example.test ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIB9zU1OEQ2tzYhrXq4/DEjvRNvKv6cU4Xar6gghj1p7D
";

    #[test]
    fn run_diagnostic_preserves_native_codes_and_masks_account_endpoint_and_cause() {
        let server =
            ServerConfig::single_account("token=host-marker", 2222, "deploy", AuthConfig::Agent);
        let diagnostic = super::RunDiagnostic {
            server: &server,
            user: "password=user-marker",
        };
        let native = ssh2::Error::from_errno(ssh2::ErrorCode::Session(-21));
        let error = diagnostic
            .ssh_step(
                Err::<(), _>(anyhow::Error::new(native).context("token=cause-marker")),
                "open SSH session",
            )
            .unwrap_err();
        let response = crate::output::ErrorResponse::from_error(&error);
        assert_eq!(response.error.kind, ErrorKind::Ssh);
        assert_eq!(response.error.exit_code, 5);
        assert!(
            response.error.message.contains("open SSH session")
                && response.error.message.contains("session/PTY limits")
        );
        assert!(error.chain().any(|cause| {
            cause
                .downcast_ref::<ssh2::Error>()
                .is_some_and(|native| native.code() == ssh2::ErrorCode::Session(-21))
        }));
        let rendered = serde_json::to_string(&response).unwrap();
        for marker in ["host-marker", "user-marker", "cause-marker"] {
            assert!(!rendered.contains(marker), "{rendered}");
        }
    }

    #[test]
    fn run_diagnostic_retains_partial_output_and_io_kind_through_owned_downcast() {
        let server = ServerConfig::single_account("example.test", 22, "deploy", AuthConfig::Agent);
        let diagnostic = super::RunDiagnostic {
            server: &server,
            user: "deploy",
        };
        let source = crate::error::classified_error(
            ErrorKind::Io,
            anyhow::Error::new(std::io::Error::new(
                std::io::ErrorKind::BrokenPipe,
                "output sink closed",
            )),
        );
        let partial = crate::ssh::PartialRunError {
            source,
            stdout: "previous output".into(),
            stderr: "previous stderr".into(),
        };
        let error = diagnostic
            .step(
                Err::<(), _>(anyhow::Error::new(partial)),
                "read command output",
            )
            .unwrap_err();
        let partial = error.downcast::<crate::ssh::PartialRunError>().unwrap();
        assert_eq!(partial.stdout, "previous output");
        assert_eq!(partial.stderr, "previous stderr");
        let error = anyhow::Error::new(partial);
        let response = crate::output::ErrorResponse::from_error(&error);
        assert_eq!(response.error.kind, ErrorKind::Io);
        assert!(
            response.error.message.contains("read command output")
                && response.error.message.contains("output sink closed")
        );
        assert!(error.chain().any(|cause| {
            cause
                .downcast_ref::<std::io::Error>()
                .is_some_and(|io| io.kind() == std::io::ErrorKind::BrokenPipe)
        }));
        assert_eq!(response.partial_output.unwrap().stdout, "previous output");
    }

    #[test]
    fn scp_diagnostics_keep_native_codes_and_mask_fields_and_causes() {
        for upload in [false, true] {
            for sensitive in [false, true] {
                let server = ServerConfig::single_account(
                    if sensitive {
                        "token=host-marker"
                    } else {
                        "example.test"
                    },
                    2222,
                    "deploy",
                    AuthConfig::Agent,
                );
                let user = if sensitive {
                    "password=user-marker"
                } else {
                    "deploy"
                };
                let local = std::path::Path::new(if sensitive {
                    "token=local-marker"
                } else {
                    "local's $file"
                });
                let remote = if sensitive {
                    "password=remote-marker"
                } else {
                    "/srv/remote's $file"
                };
                let target = crate::ssh::SshTarget::new(&server, user);
                let diagnostic = super::ScpDiagnostic::new(upload, &target, local, remote);
                let native = ssh2::Error::from_errno(ssh2::ErrorCode::Session(
                    libssh2_sys::LIBSSH2_ERROR_SCP_PROTOCOL,
                ));
                let native_message = native.to_string();
                let source = if sensitive {
                    anyhow::Error::new(native).context("token=cause-marker\n-----BEGIN PRIVATE KEY-----\nkey-material\n-----END PRIVATE KEY-----")
                } else {
                    anyhow::Error::new(native)
                };
                let error = diagnostic
                    .ssh_step(Err::<(), _>(source), "open remote file")
                    .unwrap_err();
                let response = crate::output::ErrorResponse::from_error(&error);
                let rendered = serde_json::to_string(&response).unwrap();
                assert_eq!(response.error.kind, ErrorKind::Ssh);
                assert_eq!(response.error.exit_code, 5);
                assert!(
                    response
                        .error
                        .message
                        .contains("failed during open remote file for login account")
                );
                assert!(
                    response.error.message.contains("\nlocal: ")
                        && response.error.message.contains("\nremote: ")
                );
                assert!(
                    response.error.message.contains("server SCP support")
                        && response.error.message.contains("next:")
                );
                assert!(
                    response
                        .error
                        .causes
                        .iter()
                        .any(|cause| cause == &native_message)
                );
                assert!(error.chain().any(|cause| {
                    cause.downcast_ref::<ssh2::Error>().is_some_and(|native| {
                        native.code()
                            == ssh2::ErrorCode::Session(libssh2_sys::LIBSSH2_ERROR_SCP_PROTOCOL)
                    })
                }));
                if upload {
                    assert!(
                        response.error.message.contains("SCP upload")
                            && response.error.message.contains("may have changed")
                    );
                } else {
                    assert!(
                        response.error.message.contains("SCP download")
                            && response.error.message.contains("readable regular file")
                    );
                }
                if sensitive {
                    for marker in [
                        "host-marker",
                        "user-marker",
                        "local-marker",
                        "remote-marker",
                        "cause-marker",
                        "key-material",
                    ] {
                        assert!(!rendered.contains(marker), "{rendered}");
                    }
                } else {
                    assert!(
                        response.error.message.contains("example.test:2222")
                            && response.error.message.contains("local's $file")
                            && response.error.message.contains("/srv/remote's $file")
                    );
                }
            }
        }
    }

    #[test]
    fn scp_data_and_completion_context_preserves_io_classification_and_typed_sources() {
        let server = ServerConfig::single_account("example.test", 22, "deploy", AuthConfig::Agent);
        let target = crate::ssh::SshTarget::new(&server, "deploy");
        for upload in [false, true] {
            let diagnostic = super::ScpDiagnostic::new(
                upload,
                &target,
                std::path::Path::new("local"),
                "/srv/file",
            );
            for kind in [ErrorKind::Io, ErrorKind::Ssh] {
                for stage in [
                    "send file data",
                    "receive file data to local staging",
                    "verify remote completion",
                ] {
                    let source = crate::error::classified_error(
                        kind,
                        anyhow::Error::new(std::io::Error::new(
                            std::io::ErrorKind::TimedOut,
                            "transfer deadline elapsed",
                        )),
                    );
                    let error = diagnostic.step(Err::<(), _>(source), stage).unwrap_err();
                    let response = crate::output::ErrorResponse::from_error(&error);
                    assert_eq!(response.error.kind, kind);
                    assert!(
                        response.error.message.contains(stage)
                            && response.error.message.contains("transfer deadline elapsed")
                    );
                    assert!(error.chain().any(|cause| {
                        cause
                            .downcast_ref::<std::io::Error>()
                            .is_some_and(|io| io.kind() == std::io::ErrorKind::TimedOut)
                    }));
                }
            }
            assert_eq!(diagnostic.step(Ok(17), "send file data").unwrap(), 17);
        }
    }

    #[test]
    fn default_client_has_connect_timeout() {
        assert_eq!(
            super::Ssh2Client::default().connect_timeout(),
            std::time::Duration::from_secs(15)
        );
    }

    #[test]
    fn password_auth_diagnostics_preserve_native_errors_and_mask_each_field_and_cause() {
        for sensitive in [false, true] {
            let server = ServerConfig::single_account(
                if sensitive {
                    "token=host-marker"
                } else {
                    "example.test"
                },
                2222,
                "deploy",
                AuthConfig::Agent,
            );
            let user = if sensitive {
                "password=user-marker"
            } else {
                "deploy"
            };
            let native = ssh2::Error::from_errno(ssh2::ErrorCode::Session(
                libssh2_sys::LIBSSH2_ERROR_AUTHENTICATION_FAILED,
            ));
            let native_message = native.to_string();
            let source = if sensitive {
                anyhow::Error::new(native).context("password=cause-marker\n-----BEGIN PRIVATE KEY-----\nkey-material\n-----END PRIVATE KEY-----")
            } else {
                anyhow::Error::new(native)
            };
            let error = Err::<(), _>(super::password_auth_diagnostic(source, &server, user))
                .with_error_kind(ErrorKind::Auth)
                .unwrap_err();
            let response = crate::output::ErrorResponse::from_error(&error);
            let rendered = serde_json::to_string(&response).unwrap();
            assert_eq!(response.error.kind, ErrorKind::Auth);
            assert_eq!(response.error.exit_code, 4);
            assert!(
                response
                    .error
                    .message
                    .contains("SSH password authentication failed for login account")
            );
            assert!(
                response.error.message.contains("caused by:")
                    && response.error.message.contains("same home/profile")
                    && response.error.message.contains("sshw doctor")
            );
            assert!(
                response.error.message.contains("SSHW_PASSWORD")
                    && response
                        .error
                        .message
                        .contains("server's password authentication settings")
            );
            assert!(
                response
                    .error
                    .causes
                    .iter()
                    .any(|cause| cause == &native_message)
            );
            assert!(
                error
                    .chain()
                    .any(|cause| cause
                        .downcast_ref::<ssh2::Error>()
                        .is_some_and(|native| native.code()
                            == ssh2::ErrorCode::Session(
                                libssh2_sys::LIBSSH2_ERROR_AUTHENTICATION_FAILED
                            )))
            );
            if sensitive {
                for marker in ["host-marker", "user-marker", "cause-marker", "key-material"] {
                    assert!(!rendered.contains(marker));
                }
                assert!(response.error.message.contains("<redacted>"));
            } else {
                assert!(
                    response
                        .error
                        .message
                        .contains("'deploy' at example.test:2222")
                );
            }
        }
    }

    #[test]
    fn agent_auth_diagnostics_keep_native_source_and_mask_fields_and_causes() {
        for sensitive in [false, true] {
            let server = ServerConfig::single_account(
                if sensitive {
                    "token=host-marker"
                } else {
                    "example.test"
                },
                2222,
                "deploy",
                AuthConfig::Agent,
            );
            let user = if sensitive {
                "password=user-marker"
            } else {
                "deploy"
            };
            let native = ssh2::Error::from_errno(ssh2::ErrorCode::Session(
                libssh2_sys::LIBSSH2_ERROR_AGENT_PROTOCOL,
            ));
            let native_message = native.to_string();
            let source = if sensitive {
                anyhow::Error::new(native).context("agent unavailable: token=cause-marker\n-----BEGIN PRIVATE KEY-----\nkey-material\n-----END PRIVATE KEY-----")
            } else {
                anyhow::Error::new(native)
            };
            let error = super::agent_auth_diagnostic(source, &server, user);
            let error = Err::<(), _>(error)
                .with_error_kind(ErrorKind::Auth)
                .unwrap_err();
            let response = crate::output::ErrorResponse::from_error(&error);
            let rendered = serde_json::to_string(&response).unwrap();
            assert_eq!(response.error.exit_code, 4);
            assert!(
                response
                    .error
                    .message
                    .contains("SSH agent authentication failed for login account")
            );
            assert!(
                response.error.message.contains("caused by:")
                    && response.error.message.contains("sshw doctor")
            );
            assert!(
                response
                    .error
                    .message
                    .contains("same home/profile and execution environment")
            );
            assert!(
                response
                    .error
                    .causes
                    .iter()
                    .any(|cause| cause == &native_message)
            );
            assert!(error.chain().any(|cause| {
                cause.downcast_ref::<ssh2::Error>().is_some_and(|native| {
                    native.code()
                        == ssh2::ErrorCode::Session(libssh2_sys::LIBSSH2_ERROR_AGENT_PROTOCOL)
                })
            }));
            if sensitive {
                assert!(
                    response
                        .error
                        .message
                        .contains("'<redacted>' at <redacted>:2222")
                );
                for marker in ["host-marker", "user-marker", "cause-marker", "key-material"] {
                    assert!(!rendered.contains(marker), "{rendered}");
                }
            } else {
                assert!(
                    response
                        .error
                        .message
                        .contains("'deploy' at example.test:2222")
                );
                assert!(response.error.message.contains(&native_message));
            }
        }
    }

    #[test]
    fn connect_diagnostics_keep_typed_causes_and_redact_endpoint_and_secrets() {
        for (stage, operation) in [
            (super::ConnectStage::Resolve, "resolve"),
            (super::ConnectStage::Tcp, "connect to"),
        ] {
            let server = ServerConfig::single_account(
                "token=endpoint-secret",
                2222,
                "deploy",
                AuthConfig::Agent,
            );
            let error = anyhow::Error::new(std::io::Error::new(std::io::ErrorKind::ConnectionRefused,
                "socket failure: password=cause-secret\n-----BEGIN PRIVATE KEY-----\nprivate-material\n-----END PRIVATE KEY-----"))
                .context("setup denied");
            let error = super::connect_diagnostic(
                error,
                &server,
                std::time::Duration::from_millis(250),
                stage,
            );
            let error = Err::<(), _>(error)
                .with_error_kind(ErrorKind::Ssh)
                .unwrap_err();
            let response = crate::output::ErrorResponse::from_error(&error);
            let rendered = serde_json::to_string(&response).unwrap();
            for secret in ["endpoint-secret", "cause-secret", "private-material"] {
                assert!(!rendered.contains(secret), "{rendered}");
            }
            assert_eq!(response.error.exit_code, 5);
            assert!(
                response
                    .error
                    .message
                    .contains(&format!("failed to {operation} <redacted>:2222"))
            );
            assert!(
                response.error.message.contains("setup denied")
                    && response.error.message.contains("socket failure")
            );
            assert!(
                response
                    .error
                    .message
                    .contains("connect timeout budget: 250 ms")
                    && response.error.message.contains("next: check")
            );
            assert!(error.chain().any(|cause| {
                cause
                    .downcast_ref::<std::io::Error>()
                    .is_some_and(|io| io.kind() == std::io::ErrorKind::ConnectionRefused)
            }));
        }
    }

    #[test]
    fn connect_diagnostics_keep_native_handshake_error_and_recovery() {
        let server = ServerConfig::single_account("127.0.0.1", 2222, "deploy", AuthConfig::Agent);
        let native = ssh2::Error::from_errno(ssh2::ErrorCode::Session(
            libssh2_sys::LIBSSH2_ERROR_KEY_EXCHANGE_FAILURE,
        ));
        let message = native.to_string();
        let error = super::connect_diagnostic(
            native.into(),
            &server,
            std::time::Duration::from_secs(15),
            super::ConnectStage::Handshake,
        );
        let error = Err::<(), _>(error)
            .with_error_kind(ErrorKind::Ssh)
            .unwrap_err();
        let response = crate::output::ErrorResponse::from_error(&error);
        assert_eq!(response.error.exit_code, 5);
        assert!(
            response
                .error
                .message
                .contains("complete SSH handshake with 127.0.0.1:2222")
        );
        assert!(response.error.message.contains(&message));
        assert!(
            response
                .error
                .message
                .contains("next: check that the endpoint is running SSH")
        );
        assert!(response.error.causes.iter().any(|cause| cause == &message));
        assert!(error.chain().any(|cause| {
            cause.downcast_ref::<ssh2::Error>().is_some_and(|native| {
                native.code()
                    == ssh2::ErrorCode::Session(libssh2_sys::LIBSSH2_ERROR_KEY_EXCHANGE_FAILURE)
            })
        }));
    }

    #[test]
    fn resolver_wait_is_bounded_by_the_total_connect_deadline() {
        let (release_sender, release_receiver) = std::sync::mpsc::channel();
        let deadline = super::ConnectDeadline::new(std::time::Duration::from_millis(25));
        let err = super::resolve_with_deadline(&deadline, move || {
            release_receiver.recv().unwrap();
            Ok(vec!["127.0.0.1:22".parse().unwrap()])
        })
        .unwrap_err();
        release_sender.send(()).unwrap();

        assert!(err.to_string().contains("connect phase timed out"));
        let server = ServerConfig::single_account("example.test", 22, "deploy", AuthConfig::Agent);
        let err = super::connect_diagnostic(
            err,
            &server,
            std::time::Duration::from_millis(25),
            super::ConnectStage::Resolve,
        );
        let response = crate::output::ErrorResponse::from_error(&err);
        assert_eq!(response.error.exit_code, 5);
        assert!(
            response
                .error
                .message
                .contains("timed out after 25 milliseconds")
        );
        assert!(
            response
                .error
                .message
                .contains("connect timeout budget: 25 ms")
                && response.error.message.contains("DNS availability")
        );
    }

    #[test]
    fn connect_deadline_budget_decreases_across_attempts() {
        let deadline = super::ConnectDeadline::new(std::time::Duration::from_millis(200));
        let first = deadline.remaining().unwrap();
        std::thread::sleep(std::time::Duration::from_millis(20));
        let second = deadline.remaining().unwrap();

        assert!(second < first);
    }

    #[test]
    fn windows_kex_retry_is_exact_and_bounded() {
        let kex_error = ssh2::Error::from_errno(ssh2::ErrorCode::Session(
            libssh2_sys::LIBSSH2_ERROR_KEY_EXCHANGE_FAILURE,
        ));
        let socket_error = ssh2::Error::from_errno(ssh2::ErrorCode::Session(
            libssh2_sys::LIBSSH2_ERROR_SOCKET_SEND,
        ));
        let sftp_error = ssh2::Error::from_errno(ssh2::ErrorCode::SFTP(
            libssh2_sys::LIBSSH2_ERROR_KEY_EXCHANGE_FAILURE,
        ));

        assert_eq!(
            super::should_retry_windows_kex(&kex_error, 2),
            cfg!(windows)
        );
        assert_eq!(
            super::should_retry_windows_kex(&kex_error, 1),
            cfg!(windows)
        );
        assert!(!super::should_retry_windows_kex(&kex_error, 0));
        assert!(!super::should_retry_windows_kex(&socket_error, 2));
        assert!(!super::should_retry_windows_kex(&sftp_error, 2));
        assert_eq!(super::WINDOWS_KEX_HANDSHAKE_RETRIES, 2);
    }

    #[test]
    fn default_client_has_bounded_op_timeout() {
        assert_eq!(
            super::Ssh2Client::default().op_timeout(),
            Some(std::time::Duration::from_secs(15 * 60))
        );
    }

    #[test]
    fn default_client_has_bounded_output() {
        assert_eq!(
            super::Ssh2Client::default().output_limit(),
            16 * 1024 * 1024
        );
    }

    #[test]
    fn with_op_timeout_sets_op_timeout() {
        let client =
            super::Ssh2Client::default().with_op_timeout(Some(std::time::Duration::from_secs(30)));

        assert_eq!(
            client.op_timeout(),
            Some(std::time::Duration::from_secs(30))
        );
    }

    #[cfg(unix)]
    #[test]
    fn opened_local_file_keeps_original_identity_after_path_replacement() {
        use std::io::Read;
        use std::os::unix::fs::symlink;

        let temp = tempfile::tempdir().unwrap();
        let first = temp.path().join("first");
        let second = temp.path().join("second");
        let local = temp.path().join("local");
        std::fs::write(&first, b"first").unwrap();
        std::fs::write(&second, b"second").unwrap();
        symlink(&first, &local).unwrap();

        let (mut opened, metadata) = super::open_regular_local_file(&local).unwrap();
        std::fs::remove_file(&local).unwrap();
        symlink(&second, &local).unwrap();

        let mut contents = String::new();
        opened.read_to_string(&mut contents).unwrap();
        assert_eq!(metadata.len(), 5);
        assert_eq!(contents, "first");
    }

    #[cfg(windows)]
    #[test]
    fn opens_windows_local_path_with_forward_slashes() {
        use std::io::Read;
        use std::path::Path;

        let temp = tempfile::tempdir().unwrap();
        let local = temp.path().join("artifact.bin");
        std::fs::write(&local, b"sshw").unwrap();
        let forward_slash_path = local.to_string_lossy().replace('\\', "/");

        let (mut opened, metadata) =
            super::open_regular_local_file(Path::new(&forward_slash_path)).unwrap();
        let mut contents = Vec::new();
        opened.read_to_end(&mut contents).unwrap();

        assert_eq!(metadata.len(), 4);
        assert_eq!(contents, b"sshw");
    }

    #[test]
    fn op_timeout_millis_maps_none_to_unlimited_and_clamps() {
        assert_eq!(super::op_timeout_millis(None), 0);
        assert_eq!(
            super::op_timeout_millis(Some(std::time::Duration::from_secs(30))),
            30_000
        );
        assert_eq!(
            super::op_timeout_millis(Some(std::time::Duration::from_millis(u32::MAX as u64 + 1))),
            u32::MAX
        );
    }

    #[test]
    fn default_client_has_no_known_hosts_override() {
        assert_eq!(super::Ssh2Client::default().known_hosts_override(), None);
    }

    #[test]
    fn with_known_hosts_sets_override() {
        use std::path::{Path, PathBuf};

        let client = super::Ssh2Client::default().with_known_hosts(PathBuf::from("/x/known_hosts"));

        assert_eq!(
            client.known_hosts_override(),
            Some(Path::new("/x/known_hosts"))
        );
    }

    #[test]
    fn read_known_hosts_file_supports_non_ascii_paths() {
        let dir = tempfile::tempdir().unwrap();
        let known_hosts_path = dir.path().join("유니코드").join("known_hosts");
        fs::create_dir_all(known_hosts_path.parent().unwrap()).unwrap();
        fs::write(&known_hosts_path, KNOWN_HOSTS_LINE).unwrap();
        let session = ssh2::Session::new().unwrap();
        let mut known_hosts = session.known_hosts().unwrap();

        super::read_known_hosts_file(&mut known_hosts, &known_hosts_path).unwrap();

        assert_eq!(known_hosts.hosts().unwrap().len(), 1);
    }

    #[test]
    fn write_known_hosts_file_supports_non_ascii_paths() {
        let dir = tempfile::tempdir().unwrap();
        let known_hosts_path = dir.path().join("유니코드").join("known_hosts");
        let session = ssh2::Session::new().unwrap();
        let mut known_hosts = session.known_hosts().unwrap();
        known_hosts
            .read_str(KNOWN_HOSTS_LINE, ssh2::KnownHostFileKind::OpenSSH)
            .unwrap();

        super::write_known_hosts_file(&known_hosts, &known_hosts_path).unwrap();

        assert_eq!(
            fs::read_to_string(&known_hosts_path).unwrap(),
            KNOWN_HOSTS_LINE
        );
    }

    #[test]
    fn known_hosts_comment_never_contains_server_alias() {
        let alias = "web\ninjected.example ssh-ed25519 SYNTHETIC";

        assert_eq!(super::known_host_comment(alias), "sshw");
        assert!(!super::known_host_comment(alias).contains(['\r', '\n']));
    }

    #[test]
    fn scp_completion_accepts_only_clean_zero_exit() {
        super::validate_scp_completion(None, None, 0).unwrap();

        let status = super::validate_scp_completion(None, None, 1).unwrap_err();
        assert!(status.to_string().contains("status 1"));

        let signal =
            super::validate_scp_completion(Some("TERM"), Some("terminated"), 0).unwrap_err();
        assert!(signal.to_string().contains("signal TERM"));
        assert!(signal.to_string().contains("terminated"));
    }

    #[test]
    fn failed_scp_completion_drops_stage_and_preserves_destination() {
        let dir = tempfile::tempdir().unwrap();
        let destination = dir.path().join("download.txt");
        fs::write(&destination, "ORIGINAL").unwrap();
        let mut source = &b"NEWDATA"[..];
        let staged =
            crate::storage::stage_stream_owner_only(&destination, &mut source, true, Some(7))
                .unwrap();

        let err = super::persist_after_scp_completion(staged, || {
            super::validate_scp_completion(None, None, 1)
        })
        .unwrap_err();

        assert!(err.to_string().contains("status 1"));
        assert_eq!(fs::read_to_string(&destination).unwrap(), "ORIGINAL");
        assert_eq!(
            fs::read_dir(dir.path())
                .unwrap()
                .filter_map(Result::ok)
                .filter(|entry| entry.file_name().to_string_lossy().ends_with(".tmp"))
                .count(),
            0
        );
    }

    #[test]
    fn local_noclobber_race_remains_io_through_the_ssh_boundary() {
        let dir = tempfile::tempdir().unwrap();
        let destination = dir.path().join("download.txt");
        let mut source = &b"NEWDATA"[..];
        let staged =
            crate::storage::stage_stream_owner_only(&destination, &mut source, false, Some(7))
                .unwrap();
        fs::write(&destination, "COMPETING").unwrap();

        let local_error = super::persist_after_scp_completion(staged, || Ok(())).unwrap_err();
        let boundary_error = Err::<(), _>(local_error)
            .with_error_kind(ErrorKind::Ssh)
            .unwrap_err();

        assert_eq!(
            crate::output::classify_error(&boundary_error),
            ErrorKind::Io
        );
        assert_eq!(fs::read_to_string(destination).unwrap(), "COMPETING");
    }

    #[test]
    fn detects_password_prompt_in_pty_output() {
        assert!(super::output_has_password_prompt(b"Password: "));
        assert!(super::output_has_password_prompt(b"\r\nPassword:"));
        assert!(super::output_has_password_prompt(b"PASSWORD:"));
        assert!(!super::output_has_password_prompt(b"id -u\r\n0\r\n"));
        assert!(!super::output_has_password_prompt(b""));
    }

    #[test]
    fn ignores_password_mentioning_banner_before_the_real_prompt() {
        // A pre-prompt banner/PAM line that merely mentions "password" is NOT a
        // live colon-terminated prompt, so it must not trigger early injection.
        assert!(!super::output_has_password_prompt(
            b"Last password change: never"
        ));
        assert!(!super::output_has_password_prompt(
            b"You are required to change your password immediately\r\n"
        ));
        // The real prompt appearing after such a banner is still detected.
        assert!(super::output_has_password_prompt(
            b"You must change your password\r\nPassword: "
        ));
    }

    #[test]
    fn decodes_invalid_remote_output_lossily() {
        let output = super::decode_remote_output_lossy(b"ok:\xff\xfe\n".to_vec());

        assert_eq!(output, "ok:\u{fffd}\u{fffd}\n");
    }

    #[test]
    fn extract_su_output_returns_body_and_exit_code() {
        // Output is the bytes between BEGIN and END markers; prompt noise before
        // BEGIN is discarded, CRLF is normalized.
        let raw = "Password: \r\n__SSHW_BEGIN_deadbeef__\r\nhello\r\nworld\r\n__SSHW_END_deadbeef_0__\r\n";
        let (out, code) = super::extract_su_output(raw, "deadbeef").expect("marked output");
        assert_eq!(out, "hello\nworld\n");
        assert_eq!(code, 0);
    }

    #[test]
    fn extract_su_output_preserves_password_mentioning_lines() {
        // Marker framing must NOT drop legitimate output lines mentioning password.
        let raw =
            "__SSHW_BEGIN_deadbeef__\r\npassword policy: strong\r\n__SSHW_END_deadbeef_0__\r\n";
        let (out, _) = super::extract_su_output(raw, "deadbeef").expect("marked output");
        assert!(out.contains("password policy: strong"), "got: {out:?}");
    }

    #[test]
    fn extract_su_output_propagates_nonzero_exit_code() {
        let raw = "__SSHW_BEGIN_deadbeef__\r\nboom\r\n__SSHW_END_deadbeef_7__\r\n";
        let (_, code) = super::extract_su_output(raw, "deadbeef").expect("marked output");
        assert_eq!(code, 7);
    }

    #[test]
    fn extract_su_output_rejects_malformed_end_marker() {
        let no_digits = "__SSHW_BEGIN_deadbeef__\r\nboom\r\n__SSHW_END_deadbeef___\r\n";
        let missing_terminator = "__SSHW_BEGIN_deadbeef__\r\nboom\r\n__SSHW_END_deadbeef_7\r\n";
        let overflow = "__SSHW_BEGIN_deadbeef__\r\nboom\r\n__SSHW_END_deadbeef_99999999999__\r\n";

        assert!(super::extract_su_output(no_digits, "deadbeef").is_err());
        assert!(super::extract_su_output(missing_terminator, "deadbeef").is_err());
        assert!(super::extract_su_output(overflow, "deadbeef").is_err());
    }

    #[test]
    fn extract_su_output_errors_when_begin_marker_absent() {
        // No BEGIN marker => su never ran the command (auth failure / prompt not
        // handled), regardless of any localized failure text.
        let raw = "Password: \r\nsu: Authentication failure\r\n";
        assert!(super::extract_su_output(raw, "deadbeef").is_err());
    }

    #[test]
    fn extract_su_output_ignores_markers_without_the_run_nonce() {
        // A command whose stdout contains marker-shaped text WITHOUT this run's
        // nonce (the old fixed `__SSHW_END__0__`, a different nonce, or a forged
        // literal) must not truncate the body or spoof the exit code: only the
        // nonce-qualified END marker terminates the frame.
        let raw = "__SSHW_BEGIN_deadbeef__\r\nleak __SSHW_END__0__ and __SSHW_END_cafe_0__\r\nreal line\r\n__SSHW_END_deadbeef_7__\r\n";
        let (out, code) = super::extract_su_output(raw, "deadbeef").expect("marked output");
        assert!(out.contains("__SSHW_END__0__"), "got: {out:?}");
        assert!(out.contains("__SSHW_END_cafe_0__"), "got: {out:?}");
        assert!(out.contains("real line"), "got: {out:?}");
        assert_eq!(code, 7);
    }

    #[test]
    fn timeout_millis_clamps_to_session_timeout_range() {
        assert_eq!(
            super::timeout_millis(std::time::Duration::from_secs(15)),
            15_000
        );
        assert_eq!(
            super::timeout_millis(std::time::Duration::from_millis(u32::MAX as u64 + 1)),
            u32::MAX
        );
    }

    #[test]
    fn known_host_verification_accepts_match() {
        let server = server_config();

        super::known_host_verification_result(CheckResult::Match, &server).unwrap();
    }

    #[test]
    fn known_host_verification_rejects_not_found() {
        let server = server_config();

        let err =
            super::known_host_verification_result(CheckResult::NotFound, &server).unwrap_err();

        assert!(err.to_string().contains("not trusted"));
        assert!(err.to_string().contains("sshw trust"));
    }

    #[test]
    fn known_host_verification_rejects_mismatch() {
        let server = server_config();

        let err =
            super::known_host_verification_result(CheckResult::Mismatch, &server).unwrap_err();

        assert!(err.to_string().contains("trusted key changed"));
    }

    #[test]
    fn known_host_verification_rejects_failure() {
        let server = server_config();

        let err = super::known_host_verification_result(CheckResult::Failure, &server).unwrap_err();

        assert!(err.to_string().contains("host key verification failed"));
    }

    fn server_config() -> ServerConfig {
        ServerConfig::single_account("192.0.2.10", 2222, "deploy", AuthConfig::Agent)
    }
}
