//! Real-SSH integration tests against a throwaway loopback sshd (Linux-only).
//!
//! These tests spawn a private OpenSSH server and ssh-agent, so they are
//! `#[ignore]`d by default and never run in the normal `cargo test` pass. Run
//! them on Linux with:
//!
//! ```sh
//! cargo test --test integration_ssh -- --ignored --test-threads=1
//! ```
//!
//! `--test-threads=1` is required: the harness sets `SSH_AUTH_SOCK` in the
//! process environment so libssh2's agent authentication can find the test
//! agent, and that global must not be raced between concurrent tests.
#![cfg(target_os = "linux")]

use clap::Parser;
use sshw::cli::{Cli, Prompter, execute};
use sshw::config::{
    AuthConfig, PrivilegeConfig, PrivilegeMethod, ServerConfig, SshwConfig, save_config,
};
use sshw::credentials::session_store::SessionOnlyStore;
use sshw::credentials::{AuthMaterial, CredentialStore};
use sshw::ssh::SshClient;
use sshw::ssh::ssh2_client::Ssh2Client;
use std::fs;
use std::net::{TcpListener, TcpStream};
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};
use tempfile::TempDir;

const TEST_USER: &str = "sshw";
const TEST_PASSWORD: &str = "sshw-integration-password";
const ROOT_PASSWORD: &str = "root-integration-password";

struct NoopPrompter;

impl Prompter for NoopPrompter {
    fn confirm(&mut self, _prompt: &str) -> anyhow::Result<bool> {
        Err(anyhow::anyhow!("unexpected prompt"))
    }

    fn password(&mut self, _prompt: &str) -> anyhow::Result<String> {
        Err(anyhow::anyhow!("unexpected password prompt"))
    }

    fn password_stdin(&mut self) -> anyhow::Result<String> {
        Err(anyhow::anyhow!("unexpected stdin password prompt"))
    }
}

/// A throwaway sshd + ssh-agent rooted in a temp dir. Everything is killed and
/// removed on drop. Runs entirely as the current (non-root) user: the private
/// sshd only accepts pubkey logins for that same user, which is all we need.
struct TestServer {
    _dir: TempDir,
    sshd: Child,
    agent: Child,
    port: u16,
    user: String,
    known_hosts: PathBuf,
}

impl TestServer {
    fn start() -> TestServer {
        let dir = tempfile::tempdir().expect("tempdir");
        let known_hosts = dir.path().join("known_hosts");
        Self::start_in(dir, known_hosts)
    }

    fn start_with_known_hosts(known_hosts: PathBuf) -> TestServer {
        let dir = tempfile::tempdir().expect("tempdir");
        Self::start_in(dir, known_hosts)
    }

    fn start_in(dir: TempDir, known_hosts: PathBuf) -> TestServer {
        let root = dir.path().to_path_buf();
        let user = std::env::var("USER")
            .or_else(|_| std::env::var("LOGNAME"))
            .expect("USER/LOGNAME env must be set");

        // Host key + client key (ed25519, no passphrase).
        let host_key = root.join("host_ed25519");
        keygen(&host_key);
        let client_key = root.join("client_ed25519");
        keygen(&client_key);

        // authorized_keys = the client public key.
        let authorized = root.join("authorized_keys");
        fs::copy(root.join("client_ed25519.pub"), &authorized).expect("authorized_keys");
        fs::set_permissions(&authorized, fs::Permissions::from_mode(0o600)).ok();

        let port = free_port();
        let pid_file = root.join("sshd.pid");
        let config = root.join("sshd_config");
        fs::write(
            &config,
            format!(
                "Port {port}\n\
                 ListenAddress 127.0.0.1\n\
                 HostKey {host}\n\
                 PidFile {pid}\n\
                 AuthorizedKeysFile {auth}\n\
                 PubkeyAuthentication yes\n\
                 PasswordAuthentication no\n\
                 KbdInteractiveAuthentication no\n\
                 UsePAM no\n\
                 StrictModes no\n\
                 LogLevel ERROR\n\
                 Subsystem sftp internal-sftp\n",
                host = host_key.display(),
                pid = pid_file.display(),
                auth = authorized.display(),
            ),
        )
        .expect("write sshd_config");

        // sshd in the foreground (-D) so the child stays alive; log to a file
        // for diagnosis on failure.
        let sshd_log = fs::File::create(root.join("sshd.log")).expect("sshd.log");
        let sshd = Command::new("/usr/sbin/sshd")
            .arg("-D")
            .arg("-e")
            .arg("-f")
            .arg(&config)
            .stdout(Stdio::null())
            .stderr(Stdio::from(sshd_log))
            .spawn()
            .expect("spawn sshd");

        // ssh-agent in the foreground bound to an explicit socket path.
        let auth_sock = root.join("agent.sock");
        let agent = Command::new("ssh-agent")
            .arg("-D")
            .arg("-a")
            .arg(&auth_sock)
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .expect("spawn ssh-agent");
        wait_for_path(&auth_sock);

        let added = Command::new("ssh-add")
            .arg(&client_key)
            .env("SSH_AUTH_SOCK", &auth_sock)
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .expect("ssh-add");
        assert!(added.success(), "ssh-add failed to load the test key");

        // libssh2's agent auth reads SSH_AUTH_SOCK from the process env.
        // Safe because the tests run single-threaded (--test-threads=1).
        unsafe {
            std::env::set_var("SSH_AUTH_SOCK", &auth_sock);
        }

        wait_for_port(port);

        TestServer {
            _dir: dir,
            sshd,
            agent,
            port,
            user,
            known_hosts,
        }
    }

    fn server(&self) -> ServerConfig {
        ServerConfig {
            host: "127.0.0.1".to_string(),
            port: self.port,
            user: self.user.clone(),
            auth: AuthConfig::Agent,
        }
    }

    fn client(&self) -> Ssh2Client {
        Ssh2Client::default().with_known_hosts(self.known_hosts.clone())
    }

    /// Connect once and trust the host key so later run/put/get pass the
    /// fail-closed known_hosts check.
    fn trust(&self) {
        let client = self.client();
        let server = self.server();
        let info = client.host_key(&server).expect("host_key");
        client
            .trust_host("test", &server, &info.fingerprint_sha256)
            .expect("trust_host");
    }
}

impl Drop for TestServer {
    fn drop(&mut self) {
        let _ = self.sshd.kill();
        let _ = self.agent.kill();
        let _ = self.sshd.wait();
        let _ = self.agent.wait();
    }
}

/// A throwaway Docker sshd used only for password auth. The normal OpenSSH
/// loopback harness stays host-local and agent-only so it never touches system
/// account passwords.
struct DockerPasswordServer {
    _dir: TempDir,
    container_id: String,
    image_tag: String,
    port: u16,
    known_hosts: PathBuf,
}

impl DockerPasswordServer {
    fn start() -> Option<DockerPasswordServer> {
        if !docker_available() {
            if docker_required() {
                panic!("Docker is required for the password auth integration test");
            }
            eprintln!("skipping password auth integration test: Docker is not available");
            return None;
        }

        let dir = tempfile::tempdir().expect("tempdir");
        let known_hosts = dir.path().join("known_hosts");
        let image_tag = format!("sshw-password-sshd:integration-{}", std::process::id());
        let fixture_dir =
            Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/password-sshd");

        let build = Command::new("docker")
            .args(["build", "-q", "-t"])
            .arg(&image_tag)
            .arg(&fixture_dir)
            .output()
            .expect("docker build");
        assert!(
            build.status.success(),
            "docker build failed:\n{}",
            String::from_utf8_lossy(&build.stderr)
        );

        let port = free_port();
        let run = Command::new("docker")
            .args(["run", "-d", "--rm", "-p"])
            .arg(format!("127.0.0.1:{port}:22"))
            .arg(&image_tag)
            .output()
            .expect("docker run");
        assert!(
            run.status.success(),
            "docker run failed:\n{}",
            String::from_utf8_lossy(&run.stderr)
        );
        let container_id = String::from_utf8_lossy(&run.stdout).trim().to_string();
        assert!(
            !container_id.is_empty(),
            "docker run returned no container id"
        );

        let server = password_server_config(port);
        if let Err(err) = wait_for_ssh_server(&server, Duration::from_secs(15)) {
            let logs = docker_logs(&container_id);
            let _ = Command::new("docker")
                .args(["rm", "-f"])
                .arg(&container_id)
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .status();
            panic!("{err}\ncontainer logs:\n{logs}");
        }

        Some(DockerPasswordServer {
            _dir: dir,
            container_id,
            image_tag,
            port,
            known_hosts,
        })
    }

    fn server(&self) -> ServerConfig {
        password_server_config(self.port)
    }

    fn client(&self) -> Ssh2Client {
        Ssh2Client::default().with_known_hosts(self.known_hosts.clone())
    }

    fn trust(&self) {
        let client = self.client();
        let server = self.server();
        let info = client.host_key(&server).expect("host_key");
        client
            .trust_host("docker-password", &server, &info.fingerprint_sha256)
            .expect("trust_host");
    }
}

impl Drop for DockerPasswordServer {
    fn drop(&mut self) {
        let _ = Command::new("docker")
            .args(["rm", "-f"])
            .arg(&self.container_id)
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status();
        let _ = Command::new("docker")
            .args(["rmi", "-f"])
            .arg(&self.image_tag)
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status();
    }
}

fn keygen(path: &Path) {
    let status = Command::new("ssh-keygen")
        .args(["-t", "ed25519", "-N", "", "-q", "-f"])
        .arg(path)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .expect("ssh-keygen");
    assert!(status.success(), "ssh-keygen failed for {}", path.display());
}

fn free_port() -> u16 {
    TcpListener::bind("127.0.0.1:0")
        .expect("bind")
        .local_addr()
        .expect("local_addr")
        .port()
}

fn wait_for_path(path: &Path) {
    let start = Instant::now();
    while !path.exists() {
        assert!(
            start.elapsed() < Duration::from_secs(5),
            "timeout waiting for {}",
            path.display()
        );
        std::thread::sleep(Duration::from_millis(20));
    }
}

fn wait_for_port(port: u16) {
    let start = Instant::now();
    loop {
        if TcpStream::connect(("127.0.0.1", port)).is_ok() {
            return;
        }
        assert!(
            start.elapsed() < Duration::from_secs(5),
            "timeout waiting for sshd on port {port}"
        );
        std::thread::sleep(Duration::from_millis(20));
    }
}

fn wait_for_ssh_server(server: &ServerConfig, timeout: Duration) -> Result<(), String> {
    let start = Instant::now();
    let mut last_error = "not attempted yet".to_string();
    loop {
        if start.elapsed() >= timeout {
            return Err(format!(
                "timeout waiting for Docker sshd on {}:{}; last error: {}",
                server.host, server.port, last_error
            ));
        }
        match Ssh2Client::default().host_key(server) {
            Ok(_) => return Ok(()),
            Err(err) => last_error = err.to_string(),
        }
        std::thread::sleep(Duration::from_millis(20));
    }
}

fn password_server_config(port: u16) -> ServerConfig {
    ServerConfig {
        host: "127.0.0.1".to_string(),
        port,
        user: TEST_USER.to_string(),
        auth: AuthConfig::Password {
            credential: "docker-password".to_string(),
        },
    }
}

fn docker_available() -> bool {
    Command::new("docker")
        .args(["version", "--format", "{{.Server.Version}}"])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .is_ok_and(|status| status.success())
}

fn docker_required() -> bool {
    std::env::var_os("CI").is_some()
        || std::env::var("SSHW_DOCKER_PASSWORD_TEST").as_deref() == Ok("1")
}

fn docker_logs(container_id: &str) -> String {
    match Command::new("docker").args(["logs", container_id]).output() {
        Ok(output) => {
            let mut logs = String::from_utf8_lossy(&output.stdout).into_owned();
            logs.push_str(&String::from_utf8_lossy(&output.stderr));
            logs
        }
        Err(err) => format!("failed to collect docker logs: {err}"),
    }
}

fn clone_known_host_entry_to_port(known_hosts: &Path, from_port: u16, to_port: u16) {
    let from = known_host_name("127.0.0.1", from_port);
    let to = known_host_name("127.0.0.1", to_port);
    let content = fs::read_to_string(known_hosts).expect("read known_hosts");
    let line = content
        .lines()
        .find(|line| line.split_whitespace().next() == Some(from.as_str()))
        .unwrap_or_else(|| panic!("known_hosts entry not found for {from}"));
    let cloned = line.replacen(&from, &to, 1);
    let mut updated = content;
    if !updated.ends_with('\n') {
        updated.push('\n');
    }
    updated.push_str(&cloned);
    updated.push('\n');
    fs::write(known_hosts, updated).expect("write cloned known_hosts entry");
}

fn known_host_name(host: &str, port: u16) -> String {
    if port == 22 {
        host.to_string()
    } else {
        format!("[{host}]:{port}")
    }
}

#[test]
#[ignore = "spawns a real sshd; run with --ignored --test-threads=1"]
fn run_executes_remote_command() {
    let srv = TestServer::start();
    srv.trust();

    let result = srv
        .client()
        .run(&srv.server(), &AuthMaterial::Agent, "echo hello")
        .expect("run");

    assert_eq!(result.exit_status, 0);
    assert_eq!(result.stdout.trim(), "hello");
}

#[test]
#[ignore = "spawns a real sshd; run with --ignored --test-threads=1"]
fn run_reports_remote_exit_status() {
    let srv = TestServer::start();
    srv.trust();

    let result = srv
        .client()
        .run(&srv.server(), &AuthMaterial::Agent, "exit 7")
        .expect("run");

    assert_eq!(result.exit_status, 7);
}

#[test]
#[ignore = "spawns a real sshd; run with --ignored --test-threads=1"]
fn run_rejects_remote_exit_signal() {
    let srv = TestServer::start();
    srv.trust();

    let err = srv
        .client()
        .run(&srv.server(), &AuthMaterial::Agent, "sh -c 'kill -TERM $$'")
        .expect_err("signal-terminated remote commands must fail closed");

    let message = format!("{err:#}");
    assert!(
        message.contains("remote command terminated by signal TERM"),
        "unexpected error: {message}"
    );
}

#[test]
#[ignore = "spawns a real sshd; run with --ignored --test-threads=1"]
fn run_rejected_when_host_key_not_trusted() {
    let srv = TestServer::start();
    // Intentionally skip srv.trust(): the host key is unknown.
    let err = srv
        .client()
        .run(&srv.server(), &AuthMaterial::Agent, "echo hi")
        .expect_err("run must fail closed on an untrusted host key");

    assert!(
        err.to_string().contains("host key"),
        "unexpected error: {err}"
    );
}

#[test]
#[ignore = "spawns a real sshd; run with --ignored --test-threads=1"]
fn run_rejects_changed_host_key_for_trusted_host() {
    let state = tempfile::tempdir().expect("tempdir");
    let known_hosts = state.path().join("known_hosts");
    let trusted = TestServer::start_with_known_hosts(known_hosts.clone());
    trusted.trust();

    let changed = TestServer::start_with_known_hosts(known_hosts.clone());
    clone_known_host_entry_to_port(&known_hosts, trusted.port, changed.port);

    let err = changed
        .client()
        .run(
            &changed.server(),
            &AuthMaterial::Agent,
            "echo should-not-run",
        )
        .expect_err("run must fail closed when a trusted host key changes");

    assert!(
        err.to_string().contains("trusted key changed"),
        "unexpected error: {err}"
    );
}

#[test]
#[ignore = "spawns a Docker-backed sshd; run with --ignored --test-threads=1"]
fn run_authenticates_with_password_against_real_sshd() {
    let Some(srv) = DockerPasswordServer::start() else {
        return;
    };
    srv.trust();

    let result = srv
        .client()
        .run(
            &srv.server(),
            &AuthMaterial::Password(TEST_PASSWORD.to_string()),
            "printf password-ok",
        )
        .expect("password-authenticated run");

    assert_eq!(result.exit_status, 0);
    assert_eq!(result.stdout, "password-ok");
}

#[test]
#[ignore = "spawns a Docker-backed sshd; run with --ignored --test-threads=1"]
fn run_as_root_uses_sudo_against_real_sshd_without_forwarding_password_stdin() {
    let Some(srv) = DockerPasswordServer::start() else {
        return;
    };
    srv.trust();

    let temp = tempfile::tempdir().expect("tempdir");
    let path = temp.path().join("servers.json");
    let mut config = SshwConfig {
        default: Some("docker-password".to_string()),
        ..SshwConfig::default()
    };
    config
        .servers
        .insert("docker-password".to_string(), srv.server());
    config.privileges.insert(
        "docker-password".to_string(),
        PrivilegeConfig {
            method: PrivilegeMethod::Sudo,
            user: "root".to_string(),
            credential: "docker-privilege".to_string(),
        },
    );
    save_config(&path, &config).expect("save config");

    let store = SessionOnlyStore::new();
    store
        .set_password("docker-password", TEST_USER, TEST_PASSWORD)
        .expect("store ssh password");
    store
        .set_password("docker-privilege", "root", TEST_PASSWORD)
        .expect("store privilege password");
    let mut prompter = NoopPrompter;

    let output = execute(
        Cli::try_parse_from([
            "sshw",
            "run",
            "docker-password",
            "id -u; cat",
            "--as-root",
            "--yes",
        ])
        .unwrap(),
        &path,
        &store,
        &srv.client(),
        &mut prompter,
    )
    .expect("run --as-root");

    assert_eq!(output.exit_code, 0);
    assert_eq!(output.stdout, "0\n");
    assert_eq!(output.stderr, "");
}

#[test]
#[ignore = "spawns a Docker-backed sshd; run with --ignored --test-threads=1"]
fn run_as_root_uses_su_against_real_sshd_with_pty_password() {
    let Some(srv) = DockerPasswordServer::start() else {
        return;
    };
    srv.trust();

    let temp = tempfile::tempdir().expect("tempdir");
    let path = temp.path().join("servers.json");
    let mut config = SshwConfig {
        default: Some("docker-password".to_string()),
        ..SshwConfig::default()
    };
    config
        .servers
        .insert("docker-password".to_string(), srv.server());
    config.privileges.insert(
        "docker-password".to_string(),
        PrivilegeConfig {
            method: PrivilegeMethod::Su,
            user: "root".to_string(),
            credential: "docker-privilege".to_string(),
        },
    );
    save_config(&path, &config).expect("save config");

    let store = SessionOnlyStore::new();
    store
        .set_password("docker-password", TEST_USER, TEST_PASSWORD)
        .expect("store ssh password");
    store
        .set_password("docker-privilege", "root", ROOT_PASSWORD)
        .expect("store privilege password");
    let mut prompter = NoopPrompter;

    let output = execute(
        Cli::try_parse_from([
            "sshw",
            "run",
            "docker-password",
            "id -u",
            "--as-root",
            "--yes",
        ])
        .unwrap(),
        &path,
        &store,
        &srv.client(),
        &mut prompter,
    )
    .expect("run --as-root via su");

    assert_eq!(
        output.exit_code, 0,
        "stdout={:?} stderr={:?}",
        output.stdout, output.stderr
    );
    // su ran the command as root (uid 0); the backend extracts the command
    // output from between the BEGIN/END markers.
    assert!(
        output.stdout.contains('0'),
        "su did not run as root: stdout={:?}",
        output.stdout
    );
    // The su password must never appear in the output.
    assert!(!output.stdout.contains(ROOT_PASSWORD));
    assert!(!output.stderr.contains(ROOT_PASSWORD));
}

#[test]
#[ignore = "spawns a Docker-backed sshd; run with --ignored --test-threads=1"]
fn run_as_root_su_preserves_output_mentioning_password() {
    let Some(srv) = DockerPasswordServer::start() else {
        return;
    };
    srv.trust();

    let temp = tempfile::tempdir().expect("tempdir");
    let path = temp.path().join("servers.json");
    let mut config = SshwConfig {
        default: Some("docker-password".to_string()),
        ..SshwConfig::default()
    };
    config
        .servers
        .insert("docker-password".to_string(), srv.server());
    config.privileges.insert(
        "docker-password".to_string(),
        PrivilegeConfig {
            method: PrivilegeMethod::Su,
            user: "root".to_string(),
            credential: "docker-privilege".to_string(),
        },
    );
    save_config(&path, &config).expect("save config");

    let store = SessionOnlyStore::new();
    store
        .set_password("docker-password", TEST_USER, TEST_PASSWORD)
        .expect("store ssh password");
    store
        .set_password("docker-privilege", "root", ROOT_PASSWORD)
        .expect("store privilege password");
    let mut prompter = NoopPrompter;

    let output = execute(
        Cli::try_parse_from([
            "sshw",
            "run",
            "docker-password",
            "echo SAW-password-line",
            "--as-root",
            "--yes",
        ])
        .unwrap(),
        &path,
        &store,
        &srv.client(),
        &mut prompter,
    )
    .expect("run --as-root via su");

    assert_eq!(output.exit_code, 0, "stdout={:?}", output.stdout);
    // A line mentioning "password" must survive: marker framing extracts the
    // command output structurally, unlike the old prompt-line heuristic that
    // dropped any line containing "password".
    assert!(
        output.stdout.contains("SAW-password-line"),
        "marker framing dropped legitimate output: stdout={:?}",
        output.stdout
    );
    assert!(!output.stdout.contains(ROOT_PASSWORD));
}

#[test]
#[ignore = "spawns a real sshd; run with --ignored --test-threads=1"]
fn put_then_get_roundtrip() {
    let srv = TestServer::start();
    srv.trust();
    let client = srv.client();
    let server = srv.server();

    let work = tempfile::tempdir().expect("tempdir");
    let src = work.path().join("src.bin");
    let payload = b"integration payload \x00\x01\x02 end\n";
    fs::write(&src, payload).expect("write src");

    let remote = format!("/tmp/sshw_it_{}.bin", std::process::id());
    let put = client
        .put(&server, &AuthMaterial::Agent, &src, &remote)
        .expect("put");
    assert_eq!(put.bytes, payload.len() as u64);

    let dest = work.path().join("dest.bin");
    let got = client
        .get(&server, &AuthMaterial::Agent, &remote, &dest, false)
        .expect("get");
    assert_eq!(got.bytes, payload.len() as u64);
    assert_eq!(fs::read(&dest).expect("read dest"), payload);

    let _ = client.run(&server, &AuthMaterial::Agent, &format!("rm -f {remote}"));
}

#[test]
#[ignore = "spawns a real sshd; run with --ignored --test-threads=1"]
fn put_rejects_remote_scp_sink_nonzero_exit_status() {
    let srv = TestServer::start();
    srv.trust();
    let client = srv.client();
    let server = srv.server();

    let work = tempfile::tempdir().expect("tempdir");
    let src = work.path().join("src.bin");
    fs::write(&src, b"payload for /dev/full\n").expect("write src");

    let err = client
        .put(&server, &AuthMaterial::Agent, &src, "/dev/full")
        .expect_err("remote scp sink failure must fail closed");

    let message = format!("{err:#}");
    assert!(
        message.contains("remote scp exited with status"),
        "unexpected error: {message}"
    );
}

#[test]
#[ignore = "spawns a real sshd; run with --ignored --test-threads=1"]
fn op_timeout_aborts_idle_command() {
    let srv = TestServer::start();
    srv.trust();
    let client = srv
        .client()
        .with_op_timeout(Some(Duration::from_millis(500)));

    let started = Instant::now();
    let err = client
        .run(&srv.server(), &AuthMaterial::Agent, "sleep 10")
        .expect_err("idle command must hit the operation timeout");
    assert!(
        started.elapsed() < Duration::from_secs(5),
        "op timeout did not fire promptly: {err}"
    );
}

#[test]
#[ignore = "spawns a real sshd; run with --ignored --test-threads=1"]
fn run_handles_large_stderr_without_deadlock() {
    let srv = TestServer::start();
    srv.trust();
    // Safety net: if the sequential stdout-then-stderr read deadlocks, the
    // operation timeout turns the hang into a failure instead of blocking
    // forever. A correct concurrent read finishes well under this budget.
    let client = srv.client().with_op_timeout(Some(Duration::from_secs(15)));

    // Emit several MB to stderr (far past the SSH channel window) plus a small
    // stdout marker written last. Reading stdout to EOF before touching stderr
    // stalls the remote once the stderr window fills.
    let cmd = "head -c 4194304 /dev/zero | base64 >&2; echo done";
    let result = client
        .run(&srv.server(), &AuthMaterial::Agent, cmd)
        .expect("run must not deadlock on large stderr");

    assert_eq!(result.exit_status, 0);
    assert_eq!(result.stdout.trim(), "done");
    assert!(
        result.stderr.len() > 1_000_000,
        "expected large stderr, got {} bytes",
        result.stderr.len()
    );
}
