use super::{HostKeyInfo, RunResult, SshClient, TransferResult};
use crate::config::ServerConfig;
use crate::credentials::AuthMaterial;
use anyhow::Context;
use base64::Engine;
use directories::BaseDirs;
use ssh2::{CheckResult, HashType, HostKeyType, KnownHostFileKind, KnownHostKeyFormat, Session};
use std::fs;
use std::io::Read;
use std::net::{TcpStream, ToSocketAddrs};
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

const DEFAULT_CONNECT_TIMEOUT: Duration = Duration::from_secs(15);

#[derive(Debug, Clone)]
pub struct Ssh2Client {
    connect_timeout: Duration,
    known_hosts_path: Option<PathBuf>,
}

impl Default for Ssh2Client {
    fn default() -> Self {
        Self {
            connect_timeout: DEFAULT_CONNECT_TIMEOUT,
            known_hosts_path: None,
        }
    }
}

impl Ssh2Client {
    pub fn connect_timeout(&self) -> Duration {
        self.connect_timeout
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
            known_hosts.read_file(&known_hosts_path, KnownHostFileKind::OpenSSH)?;
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
                if let Some(parent) = known_hosts_path.parent() {
                    fs::create_dir_all(parent)?;
                }
                let host_entry = known_host_name(&server.host, server.port);
                known_hosts.add(
                    &host_entry,
                    key,
                    server_name,
                    KnownHostKeyFormat::from(key_type),
                )?;
                known_hosts.write_file(&known_hosts_path, KnownHostFileKind::OpenSSH)?;
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
        let started = Instant::now();
        let known_hosts = self.resolved_known_hosts_path()?;
        let session =
            connect_verified_authenticated(server, auth, self.connect_timeout, &known_hosts)?;
        let mut channel = session.channel_session().context("ssh session error")?;
        channel.exec(command).context("ssh session error")?;

        let mut stdout = String::new();
        let mut stderr = String::new();
        channel.read_to_string(&mut stdout)?;
        channel.stderr().read_to_string(&mut stderr)?;
        channel.wait_close().context("ssh session error")?;
        let exit_status = channel.exit_status().context("ssh session error")?;

        Ok(RunResult {
            exit_status,
            stdout,
            stderr,
            duration_ms: started.elapsed().as_millis(),
        })
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
        let session =
            connect_verified_authenticated(server, auth, self.connect_timeout, &known_hosts)?;
        let mut local_file = fs::File::open(local)?;
        let mut remote_file = session
            .scp_send(Path::new(remote), 0o600, metadata.len(), None)
            .context("ssh transfer error")?;
        std::io::copy(&mut local_file, &mut remote_file)?;
        remote_file.send_eof().context("ssh transfer error")?;
        remote_file.wait_eof().context("ssh transfer error")?;
        remote_file.close().context("ssh transfer error")?;
        remote_file.wait_close().context("ssh transfer error")?;

        Ok(TransferResult {
            bytes: metadata.len(),
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
        let session =
            connect_verified_authenticated(server, auth, self.connect_timeout, &known_hosts)?;
        let (mut remote_file, stat) = session
            .scp_recv(Path::new(remote))
            .context("ssh transfer error")?;

        // Download to a sibling temp file and persist on success so a failed
        // transfer never truncates or replaces an existing local file.
        let bytes =
            crate::storage::write_stream_owner_only_atomic(local, &mut remote_file, overwrite)?;

        remote_file.send_eof().context("ssh transfer error")?;
        remote_file.wait_eof().context("ssh transfer error")?;
        remote_file.close().context("ssh transfer error")?;
        remote_file.wait_close().context("ssh transfer error")?;

        Ok(TransferResult {
            bytes: bytes.min(stat.size()),
            source: remote.to_string(),
            destination: local.display().to_string(),
        })
    }
}

fn connect_verified_authenticated(
    server: &ServerConfig,
    auth: &AuthMaterial,
    connect_timeout: Duration,
    known_hosts_path: &Path,
) -> anyhow::Result<Session> {
    let session = connect(server, connect_timeout)?;
    verify_known_host(&session, server, known_hosts_path)?;
    authenticate(&session, server, auth)?;
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
    known_hosts.read_file(known_hosts_path, KnownHostFileKind::OpenSSH)?;

    known_host_verification_result(
        known_hosts.check_port(&server.host, server.port, key),
        server,
    )
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
            session.userauth_password(&server.user, password)?;
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

    #[test]
    fn default_client_has_connect_timeout() {
        assert_eq!(
            super::Ssh2Client::default().connect_timeout(),
            std::time::Duration::from_secs(15)
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
