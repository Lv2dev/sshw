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

use sshw::config::{AuthConfig, ServerConfig};
use sshw::credentials::AuthMaterial;
use sshw::ssh::SshClient;
use sshw::ssh::ssh2_client::Ssh2Client;
use std::fs;
use std::net::{TcpListener, TcpStream};
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};
use tempfile::TempDir;

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
            known_hosts: root.join("known_hosts"),
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
