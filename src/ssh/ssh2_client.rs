use super::{HostKeyInfo, RunResult, SshClient, TransferResult};
use crate::config::ServerConfig;
use crate::credentials::AuthMaterial;
use anyhow::Context;
use base64::Engine;
use directories::BaseDirs;
use ssh2::{CheckResult, HashType, HostKeyType, KnownHostFileKind, KnownHostKeyFormat, Session};
use std::fs;
use std::io::{Read, Write};
use std::net::{TcpStream, ToSocketAddrs};
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

const DEFAULT_CONNECT_TIMEOUT: Duration = Duration::from_secs(15);

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
    known_hosts_path: Option<PathBuf>,
}

impl Default for Ssh2Client {
    fn default() -> Self {
        Self {
            connect_timeout: DEFAULT_CONNECT_TIMEOUT,
            op_timeout: None,
            known_hosts_path: None,
        }
    }
}

impl Ssh2Client {
    pub fn connect_timeout(&self) -> Duration {
        self.connect_timeout
    }

    /// Inactivity timeout for remote operations (run/put/get) applied *after*
    /// the connection is established. `None` (the default) means no operation
    /// timeout, matching `ssh`'s behavior so long-running or quiet commands are
    /// not killed. Connection setup always uses `connect_timeout`.
    pub fn with_op_timeout(mut self, op_timeout: Option<Duration>) -> Self {
        self.op_timeout = op_timeout;
        self
    }

    pub fn op_timeout(&self) -> Option<Duration> {
        self.op_timeout
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
    fn host_key(&self, server: &ServerConfig) -> anyhow::Result<HostKeyInfo> {
        let session = connect(server, self.connect_timeout)?;
        host_key_info(&session)
    }

    fn trust_host(
        &self,
        server_name: &str,
        server: &ServerConfig,
        expected_fingerprint_sha256: &str,
    ) -> anyhow::Result<HostKeyInfo> {
        let session = connect(server, self.connect_timeout)?;
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
                    server_name,
                    KnownHostKeyFormat::from(key_type),
                )?;
                write_known_hosts_file(&known_hosts, &known_hosts_path)?;
                Ok(info)
            }
        }
    }

    fn run(
        &self,
        server: &ServerConfig,
        auth: &AuthMaterial,
        command: &str,
    ) -> anyhow::Result<RunResult> {
        self.run_inner(server, auth, command, None)
    }

    fn run_with_stdin(
        &self,
        server: &ServerConfig,
        auth: &AuthMaterial,
        command: &str,
        stdin: &str,
    ) -> anyhow::Result<RunResult> {
        self.run_inner(server, auth, command, Some(stdin))
    }

    fn run_with_pty_password(
        &self,
        server: &ServerConfig,
        auth: &AuthMaterial,
        command: &str,
        password: &str,
        marker_nonce: &str,
    ) -> anyhow::Result<RunResult> {
        self.run_pty_inner(server, auth, command, password, marker_nonce)
    }

    fn put(
        &self,
        server: &ServerConfig,
        auth: &AuthMaterial,
        local: &Path,
        remote: &str,
    ) -> anyhow::Result<TransferResult> {
        let metadata = fs::metadata(local)
            .with_context(|| format!("local file not found: {}", local.display()))?;
        if !metadata.is_file() {
            return Err(anyhow::anyhow!(
                "local path is not a regular file: {}",
                local.display()
            ));
        }

        let known_hosts = self.resolved_known_hosts_path()?;
        let session = connect_verified_authenticated(
            server,
            auth,
            self.connect_timeout,
            self.op_timeout,
            &known_hosts,
        )?;
        let local_file = fs::File::open(local)?;
        let mut remote_file = session
            .scp_send(Path::new(remote), 0o600, metadata.len(), None)
            .context("ssh transfer error")?;
        // scp promised `metadata.len()` bytes up front. Cap the reader at that
        // length so a file that grows mid-transfer never writes past the
        // declared size, and fail closed below if fewer bytes were sent (the
        // file shrank), so a truncated upload is never reported as a success.
        let mut bounded = local_file.take(metadata.len());
        let copied = std::io::copy(&mut bounded, &mut remote_file)?;
        if copied != metadata.len() {
            return Err(anyhow::anyhow!(
                "ssh transfer aborted: local file changed during transfer (expected {} bytes, sent {})",
                metadata.len(),
                copied
            ));
        }
        remote_file.send_eof().context("ssh transfer error")?;
        remote_file.wait_eof().context("ssh transfer error")?;
        remote_file.close().context("ssh transfer error")?;
        remote_file.wait_close().context("ssh transfer error")?;

        Ok(TransferResult {
            bytes: copied,
            source: local.display().to_string(),
            destination: remote.to_string(),
        })
    }

    fn get(
        &self,
        server: &ServerConfig,
        auth: &AuthMaterial,
        remote: &str,
        local: &Path,
        overwrite: bool,
    ) -> anyhow::Result<TransferResult> {
        let known_hosts = self.resolved_known_hosts_path()?;
        let session = connect_verified_authenticated(
            server,
            auth,
            self.connect_timeout,
            self.op_timeout,
            &known_hosts,
        )?;
        let (mut remote_file, stat) = session
            .scp_recv(Path::new(remote))
            .context("ssh transfer error")?;

        // Download to a sibling temp file and persist on success so a failed
        // transfer never truncates or replaces an existing local file. Pass the
        // SCP-announced size so a short/truncated download fails closed before
        // persisting, mirroring the upload truncation guard in `put`.
        let bytes = crate::storage::write_stream_owner_only_atomic(
            local,
            &mut remote_file,
            overwrite,
            Some(stat.size()),
        )?;

        remote_file.send_eof().context("ssh transfer error")?;
        remote_file.wait_eof().context("ssh transfer error")?;
        remote_file.close().context("ssh transfer error")?;
        remote_file.wait_close().context("ssh transfer error")?;

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
        server: &ServerConfig,
        auth: &AuthMaterial,
        command: &str,
        stdin: Option<&str>,
    ) -> anyhow::Result<RunResult> {
        let started = Instant::now();
        let known_hosts = self.resolved_known_hosts_path()?;
        let session = connect_verified_authenticated(
            server,
            auth,
            self.connect_timeout,
            self.op_timeout,
            &known_hosts,
        )?;
        let mut channel = session.channel_session().context("ssh session error")?;
        channel.exec(command).context("ssh session error")?;
        if let Some(stdin) = stdin {
            channel
                .write_all(stdin.as_bytes())
                .context("ssh session error")?;
            channel.send_eof().context("ssh session error")?;
        }

        let (stdout, stderr) = read_channel_outputs(&session, &mut channel, self.op_timeout)?;
        channel.wait_close().context("ssh session error")?;
        let exit_status = channel.exit_status().context("ssh session error")?;

        Ok(RunResult {
            exit_status,
            stdout,
            stderr,
            duration_ms: started.elapsed().as_millis(),
        })
    }

    fn run_pty_inner(
        &self,
        server: &ServerConfig,
        auth: &AuthMaterial,
        command: &str,
        password: &str,
        marker_nonce: &str,
    ) -> anyhow::Result<RunResult> {
        let started = Instant::now();
        let known_hosts = self.resolved_known_hosts_path()?;
        let session = connect_verified_authenticated(
            server,
            auth,
            self.connect_timeout,
            self.op_timeout,
            &known_hosts,
        )?;
        let mut channel = session.channel_session().context("ssh session error")?;
        // Disable PTY echo so the injected password is never echoed back into
        // the output stream we collect.
        let mut modes = ssh2::PtyModes::new();
        modes.set_boolean(ssh2::PtyModeOpcode::ECHO, false);
        channel
            .request_pty("xterm", Some(modes), None)
            .context("ssh session error")?;
        channel.exec(command).context("ssh session error")?;

        let begin_marker = su_begin_marker(marker_nonce);
        let raw = pty_collect_with_password(
            &session,
            &mut channel,
            password,
            self.op_timeout,
            &begin_marker,
        )?;
        channel.wait_close().context("ssh session error")?;
        // The PTY channel exit status is unreliable (a signal-killed process can
        // report 0), so the command's real exit code comes from the END marker
        // the wrapper printed. Drain the channel status but do not trust it.
        let _ = channel.exit_status();
        let (stdout, exit_status) = extract_su_output(&raw, marker_nonce)?;

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

fn connect_verified_authenticated(
    server: &ServerConfig,
    auth: &AuthMaterial,
    connect_timeout: Duration,
    op_timeout: Option<Duration>,
    known_hosts_path: &Path,
) -> anyhow::Result<Session> {
    let session = connect(server, connect_timeout)?;
    verify_known_host(&session, server, known_hosts_path)?;
    authenticate(&session, server, auth)?;
    // Switch from the connect-phase timeout to the operation timeout (0 = no
    // timeout) so long-running or quiet remote commands are not killed by the
    // connection setup timeout.
    session.set_timeout(op_timeout_millis(op_timeout));
    Ok(session)
}

fn connect(server: &ServerConfig, timeout: Duration) -> anyhow::Result<Session> {
    let address = format!("{}:{}", server.host, server.port);
    let mut last_error = None;
    let mut resolved_any = false;
    for socket_addr in address
        .to_socket_addrs()
        .with_context(|| format!("failed to resolve {address}"))?
    {
        resolved_any = true;
        match TcpStream::connect_timeout(&socket_addr, timeout) {
            Ok(tcp) => {
                tcp.set_read_timeout(Some(timeout))?;
                tcp.set_write_timeout(Some(timeout))?;
                let mut session = Session::new()?;
                session.set_timeout(timeout_millis(timeout));
                session.set_tcp_stream(tcp);
                session.handshake()?;
                return Ok(session);
            }
            Err(err) => last_error = Some(err),
        }
    }

    if !resolved_any {
        return Err(anyhow::anyhow!("failed to resolve {address}"));
    }

    let err = last_error
        .map(anyhow::Error::from)
        .unwrap_or_else(|| anyhow::anyhow!("no resolved address was reachable"));
    Err(err).with_context(|| {
        format!(
            "failed to connect to {}:{} within {} seconds",
            server.host,
            server.port,
            timeout.as_secs()
        )
    })
}

fn timeout_millis(timeout: Duration) -> u32 {
    timeout.as_millis().min(u32::MAX as u128) as u32
}

/// libssh2 blocking timeout in milliseconds for the operation phase. `None`
/// maps to `0`, which libssh2 treats as "no timeout".
fn op_timeout_millis(op_timeout: Option<Duration>) -> u32 {
    op_timeout.map(timeout_millis).unwrap_or(0)
}

/// Drive a PTY-backed `su` execution: read the merged PTY output non-blocking,
/// inject `password` (plus a newline) exactly once when the password prompt is
/// detected, then collect the rest until EOF. PTY echo is disabled and the
/// prompt locale is forced to English (LC_ALL=C) by the caller, so the password
/// is not reflected back. `op_timeout` is the same inactivity budget as `run`.
fn pty_collect_with_password(
    session: &Session,
    channel: &mut ssh2::Channel,
    password: &str,
    op_timeout: Option<Duration>,
    begin_marker: &str,
) -> anyhow::Result<String> {
    session.set_blocking(false);
    let collected = pty_collect_loop(session, channel, password, op_timeout, begin_marker);
    session.set_blocking(true);
    let out = collected?;
    String::from_utf8(out)
        .map_err(|err| std::io::Error::new(std::io::ErrorKind::InvalidData, err))
        .map_err(anyhow::Error::from)
}

fn pty_collect_loop(
    session: &Session,
    channel: &mut ssh2::Channel,
    password: &str,
    op_timeout: Option<Duration>,
    begin_marker: &str,
) -> anyhow::Result<Vec<u8>> {
    // Upper bound on the prompt/auth phase (before the command's BEGIN marker
    // appears) so a missing or unrecognized password prompt cannot hang forever
    // even when op_timeout is None.
    const PROMPT_WAIT: Duration = Duration::from_secs(30);
    let mut out = Vec::new();
    let mut buf = [0u8; 32 * 1024];
    let mut injected = false;
    let mut command_started = false;
    let mut last_progress = Instant::now();

    loop {
        let mut progressed = false;
        match channel.read(&mut buf) {
            Ok(0) => break,
            Ok(n) => {
                out.extend_from_slice(&buf[..n]);
                progressed = true;
            }
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {}
            Err(e) => return Err(anyhow::Error::new(e).context("ssh session error")),
        }

        if !command_started && contains_subslice(&out, begin_marker.as_bytes()) {
            // su authenticated and the wrapper began running the command; from
            // here the command's own runtime governs the timeout.
            command_started = true;
        }

        if !injected && !command_started && output_has_password_prompt(&out) {
            // The password is short; switch to blocking for an atomic write,
            // then restore non-blocking reads.
            session.set_blocking(true);
            let write = channel
                .write_all(password.as_bytes())
                .and_then(|()| channel.write_all(b"\n"));
            session.set_blocking(false);
            write.context("ssh session error")?;
            injected = true;
            progressed = true;
        }

        if progressed {
            last_progress = Instant::now();
        } else {
            // Before the command starts (prompt/auth phase) always bound the
            // wait, even when op_timeout is None; after it starts, honor
            // op_timeout (None = unlimited, like `run`).
            let deadline = if command_started {
                op_timeout
            } else {
                Some(op_timeout.map_or(PROMPT_WAIT, |t| t.min(PROMPT_WAIT)))
            };
            if deadline.is_some_and(|t| last_progress.elapsed() >= t) {
                return Err(anyhow::anyhow!(
                    "ssh session timed out waiting for the su password prompt or output"
                ));
            }
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
        anyhow::anyhow!("su authentication failed or password prompt was not answered")
    })?;
    let after_begin = begin + begin_marker.len();
    // Body starts after the newline that follows the BEGIN marker.
    let body_start = raw[after_begin..]
        .find('\n')
        .map(|nl| after_begin + nl + 1)
        .unwrap_or(after_begin);
    let end_rel = raw[body_start..]
        .find(&end_prefix)
        .ok_or_else(|| anyhow::anyhow!("su output ended before the completion marker"))?;
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
        anyhow::bail!("su output ended with a malformed completion marker");
    }
    let exit_code = marker_tail[..digit_len]
        .parse::<i32>()
        .context("su output ended with a malformed completion marker")?;
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
/// `op_timeout` is an *inactivity* budget matching the connection's operation
/// timeout: it fires only when neither stream makes progress for that long.
/// `None` waits indefinitely.
fn read_channel_outputs(
    session: &Session,
    channel: &mut ssh2::Channel,
    op_timeout: Option<Duration>,
) -> anyhow::Result<(String, String)> {
    session.set_blocking(false);
    let drained = drain_both_streams(channel, op_timeout);
    session.set_blocking(true);
    let (out, err) = drained?;
    let stdout = String::from_utf8(out)
        .map_err(|err| std::io::Error::new(std::io::ErrorKind::InvalidData, err))?;
    let stderr = String::from_utf8(err)
        .map_err(|err| std::io::Error::new(std::io::ErrorKind::InvalidData, err))?;
    Ok((stdout, stderr))
}

fn drain_both_streams(
    channel: &mut ssh2::Channel,
    op_timeout: Option<Duration>,
) -> anyhow::Result<(Vec<u8>, Vec<u8>)> {
    let mut out = Vec::new();
    let mut err = Vec::new();
    let mut out_done = false;
    let mut err_done = false;
    let mut buf = [0u8; 32 * 1024];
    let mut last_progress = Instant::now();

    while !(out_done && err_done) {
        let mut progressed = false;

        if !out_done {
            match channel.read(&mut buf) {
                Ok(0) => out_done = true,
                Ok(n) => {
                    out.extend_from_slice(&buf[..n]);
                    progressed = true;
                }
                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {}
                Err(e) => return Err(anyhow::Error::new(e).context("ssh session error")),
            }
        }

        if !err_done {
            match channel.stderr().read(&mut buf) {
                Ok(0) => err_done = true,
                Ok(n) => {
                    err.extend_from_slice(&buf[..n]);
                    progressed = true;
                }
                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {}
                Err(e) => return Err(anyhow::Error::new(e).context("ssh session error")),
            }
        }

        if progressed {
            last_progress = Instant::now();
        } else if !(out_done && err_done) {
            if op_timeout.is_some_and(|timeout| last_progress.elapsed() >= timeout) {
                return Err(anyhow::anyhow!("ssh session timed out waiting for output"));
            }
            std::thread::sleep(Duration::from_millis(5));
        }
    }

    Ok((out, err))
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

fn read_known_hosts_file(known_hosts: &mut ssh2::KnownHosts, path: &Path) -> anyhow::Result<()> {
    let content = fs::read_to_string(path)
        .with_context(|| format!("failed to read known_hosts file: {}", path.display()))?;
    for line in content.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }
        let mut entry = String::with_capacity(line.len() + 1);
        entry.push_str(line);
        entry.push('\n');
        known_hosts
            .read_str(&entry, KnownHostFileKind::OpenSSH)
            .with_context(|| format!("failed to parse known_hosts file: {}", path.display()))?;
    }
    Ok(())
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

fn authenticate(
    session: &Session,
    server: &ServerConfig,
    auth: &AuthMaterial,
) -> anyhow::Result<()> {
    match auth {
        AuthMaterial::Password(password) => {
            session
                .userauth_password(&server.user, password)
                .context("SSH authentication failed")?;
        }
        AuthMaterial::Agent => {
            session
                .userauth_agent(&server.user)
                .context("SSH agent authentication failed")?;
        }
    }

    if !session.authenticated() {
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
    use ssh2::CheckResult;
    use std::fs;

    const KNOWN_HOSTS_LINE: &str = "\
example.test ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIB9zU1OEQ2tzYhrXq4/DEjvRNvKv6cU4Xar6gghj1p7D
";

    #[test]
    fn default_client_has_connect_timeout() {
        assert_eq!(
            super::Ssh2Client::default().connect_timeout(),
            std::time::Duration::from_secs(15)
        );
    }

    #[test]
    fn default_client_has_no_op_timeout() {
        assert_eq!(super::Ssh2Client::default().op_timeout(), None);
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
        ServerConfig {
            host: "192.0.2.10".to_string(),
            port: 2222,
            user: "deploy".to_string(),
            auth: AuthConfig::Agent,
        }
    }
}
