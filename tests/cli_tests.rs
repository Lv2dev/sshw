use clap::Parser;
use sshw::cli::{AuthArg, Cli, Command, Prompter, execute};
use sshw::config::{AuthConfig, ServerConfig, SshwConfig, save_config};
use sshw::credentials::{AuthMaterial, CredentialStore, CredentialStoreHealth};
use sshw::ssh::{HostKeyInfo, RunResult, SshClient, TransferResult};
use std::cell::RefCell;
use std::collections::BTreeMap;
use std::path::Path;

#[test]
fn parses_add_with_default_password_auth() {
    let cli = Cli::try_parse_from([
        "sshw",
        "add",
        "server-alpha",
        "--host",
        "192.0.2.10",
        "--port",
        "2222",
        "--user",
        "deploy",
    ])
    .unwrap();

    let Command::Add(args) = cli.command else {
        panic!("expected add command");
    };

    assert_eq!(args.name, "server-alpha");
    assert_eq!(args.host, "192.0.2.10");
    assert_eq!(args.port, 2222);
    assert_eq!(args.user, "deploy");
    assert_eq!(args.auth, AuthArg::Password);
}

#[test]
fn parses_agent_add_run_and_trust() {
    Cli::try_parse_from([
        "sshw",
        "add",
        "server-beta",
        "--host",
        "192.0.2.11",
        "--port",
        "2222",
        "--user",
        "deploy",
        "--auth",
        "agent",
    ])
    .unwrap();

    let run = Cli::try_parse_from(["sshw", "run", "server-alpha", "pm2 status", "--json"]).unwrap();
    let Command::Run(args) = run.command else {
        panic!("expected run command");
    };
    assert!(args.json);
    assert_eq!(args.command, "pm2 status");

    let trust = Cli::try_parse_from(["sshw", "trust", "server-alpha", "--yes"]).unwrap();
    let Command::Trust(args) = trust.command else {
        panic!("expected trust command");
    };
    assert!(args.yes);
}

#[test]
fn list_json_redacts_secrets() {
    let temp = tempfile::tempdir().unwrap();
    let path = temp.path().join("servers.json");
    save_config(&path, &sample_config()).unwrap();
    let store = FakeCredentialStore::default();
    store
        .set_password("sshw:server-alpha", "deploy", "YOUR_PASSWORD")
        .unwrap();
    let ssh = FakeSshClient::default();
    let mut prompter = FakePrompter::default();

    let output = execute(
        Cli::try_parse_from(["sshw", "list", "--json"]).unwrap(),
        &path,
        &store,
        &ssh,
        &mut prompter,
    )
    .unwrap();

    assert_eq!(output.exit_code, 0);
    assert!(output.stdout.contains("\"name\":\"server-alpha\""));
    assert!(
        output
            .stdout
            .contains("\"credential\":\"sshw:server-alpha\"")
    );
    assert!(!output.stdout.contains("YOUR_PASSWORD"));
}

#[test]
fn unknown_server_returns_actionable_error() {
    let temp = tempfile::tempdir().unwrap();
    let path = temp.path().join("servers.json");
    save_config(&path, &sample_config()).unwrap();
    let store = FakeCredentialStore::default();
    let ssh = FakeSshClient::default();
    let mut prompter = FakePrompter::default();

    let err = execute(
        Cli::try_parse_from(["sshw", "show", "missing"]).unwrap(),
        &path,
        &store,
        &ssh,
        &mut prompter,
    )
    .unwrap_err();

    assert!(err.to_string().contains("unknown server"));
    assert!(err.to_string().contains("missing"));
}

#[test]
fn dangerous_run_is_blocked_before_ssh() {
    let temp = tempfile::tempdir().unwrap();
    let path = temp.path().join("servers.json");
    save_config(&path, &sample_config()).unwrap();
    let store = FakeCredentialStore::default();
    let ssh = FakeSshClient::default();
    let mut prompter = FakePrompter::default();

    let err = execute(
        Cli::try_parse_from(["sshw", "run", "server-alpha", "rm -rf /home/deploy/app"]).unwrap(),
        &path,
        &store,
        &ssh,
        &mut prompter,
    )
    .unwrap_err();

    assert!(err.to_string().contains("requires --yes"));
    assert!(ssh.run_commands.borrow().is_empty());
}

#[test]
fn remove_requires_confirmation_unless_yes() {
    let temp = tempfile::tempdir().unwrap();
    let path = temp.path().join("servers.json");
    save_config(&path, &sample_config()).unwrap();
    let store = FakeCredentialStore::default();
    let ssh = FakeSshClient::default();
    let mut prompter = FakePrompter {
        confirm: false,
        ..FakePrompter::default()
    };

    let err = execute(
        Cli::try_parse_from(["sshw", "remove", "server-alpha"]).unwrap(),
        &path,
        &store,
        &ssh,
        &mut prompter,
    )
    .unwrap_err();

    assert!(err.to_string().contains("removal cancelled"));
    let output = execute(
        Cli::try_parse_from(["sshw", "remove", "server-alpha", "--yes"]).unwrap(),
        &path,
        &store,
        &ssh,
        &mut FakePrompter::default(),
    )
    .unwrap();
    assert!(output.stdout.contains("removed server-alpha"));
}

#[test]
fn trust_passes_displayed_fingerprint_to_storage() {
    let temp = tempfile::tempdir().unwrap();
    let path = temp.path().join("servers.json");
    save_config(&path, &sample_config()).unwrap();
    let store = FakeCredentialStore::default();
    let ssh = FakeSshClient {
        host_key_fingerprint: "SHA256:displayed".to_string(),
        ..FakeSshClient::default()
    };
    let mut prompter = FakePrompter {
        confirm: true,
        ..FakePrompter::default()
    };

    let output = execute(
        Cli::try_parse_from(["sshw", "trust", "server-alpha"]).unwrap(),
        &path,
        &store,
        &ssh,
        &mut prompter,
    )
    .unwrap();

    assert!(output.stdout.contains("SHA256:displayed"));
    assert_eq!(
        ssh.trusted_expected_fingerprints.borrow().as_slice(),
        ["SHA256:displayed"]
    );
}

#[test]
fn get_existing_local_file_requires_yes_before_ssh() {
    let temp = tempfile::tempdir().unwrap();
    let path = temp.path().join("servers.json");
    save_config(&path, &sample_config()).unwrap();
    let local = temp.path().join("existing.txt");
    std::fs::write(&local, "keep").unwrap();
    let store = FakeCredentialStore::default();
    store
        .set_password("sshw:server-alpha", "deploy", "YOUR_PASSWORD")
        .unwrap();
    let ssh = FakeSshClient::default();
    let mut prompter = FakePrompter::default();

    let err = execute(
        Cli::try_parse_from([
            "sshw",
            "get",
            "server-alpha",
            "/tmp/remote.txt",
            local.to_str().unwrap(),
        ])
        .unwrap(),
        &path,
        &store,
        &ssh,
        &mut prompter,
    )
    .unwrap_err();

    assert!(err.to_string().contains("already exists"));
    assert!(ssh.get_calls.borrow().is_empty());
}

#[test]
fn get_existing_local_file_with_yes_allows_overwrite() {
    let temp = tempfile::tempdir().unwrap();
    let path = temp.path().join("servers.json");
    save_config(&path, &sample_config()).unwrap();
    let local = temp.path().join("existing.txt");
    std::fs::write(&local, "replace").unwrap();
    let store = FakeCredentialStore::default();
    store
        .set_password("sshw:server-alpha", "deploy", "YOUR_PASSWORD")
        .unwrap();
    let ssh = FakeSshClient::default();
    let mut prompter = FakePrompter::default();

    let output = execute(
        Cli::try_parse_from([
            "sshw",
            "get",
            "server-alpha",
            "/tmp/remote.txt",
            local.to_str().unwrap(),
            "--yes",
        ])
        .unwrap(),
        &path,
        &store,
        &ssh,
        &mut prompter,
    )
    .unwrap();

    assert!(output.stdout.contains("downloaded"));
    assert_eq!(ssh.get_calls.borrow().as_slice(), [true]);
}

#[test]
fn add_agent_update_deletes_old_password_credential() {
    let temp = tempfile::tempdir().unwrap();
    let path = temp.path().join("servers.json");
    save_config(&path, &sample_config()).unwrap();
    let store = FakeCredentialStore::default();
    store
        .set_password("sshw:server-alpha", "deploy", "YOUR_PASSWORD")
        .unwrap();
    let ssh = FakeSshClient::default();
    let mut prompter = FakePrompter::default();

    execute(
        Cli::try_parse_from([
            "sshw",
            "add",
            "server-alpha",
            "--host",
            "192.0.2.10",
            "--port",
            "2222",
            "--user",
            "deploy",
            "--auth",
            "agent",
            "--force",
        ])
        .unwrap(),
        &path,
        &store,
        &ssh,
        &mut prompter,
    )
    .unwrap();

    assert_eq!(
        store.deleted.borrow().as_slice(),
        [("sshw:server-alpha".to_string(), "deploy".to_string())]
    );
}

#[test]
fn run_json_filters_known_stty_startup_noise_but_keeps_real_stderr() {
    let temp = tempfile::tempdir().unwrap();
    let path = temp.path().join("servers.json");
    save_config(&path, &sample_config()).unwrap();
    let store = FakeCredentialStore::default();
    store
        .set_password("sshw:server-alpha", "deploy", "YOUR_PASSWORD")
        .unwrap();
    let ssh = FakeSshClient::with_stderr(
        "stty: 'standard input': Inappropriate ioctl for device\nactual warning\n",
    );
    let mut prompter = FakePrompter::default();

    let output = execute(
        Cli::try_parse_from(["sshw", "run", "server-alpha", "hostname", "--json"]).unwrap(),
        &path,
        &store,
        &ssh,
        &mut prompter,
    )
    .unwrap();

    let json: serde_json::Value = serde_json::from_str(output.stdout.trim()).unwrap();
    assert_eq!(json["stderr"], "actual warning\n");
    assert!(
        !output
            .stdout
            .contains("stty: 'standard input': Inappropriate ioctl for device")
    );
}

#[test]
fn run_human_filters_known_stty_startup_noise_but_keeps_real_stderr() {
    let temp = tempfile::tempdir().unwrap();
    let path = temp.path().join("servers.json");
    save_config(&path, &sample_config()).unwrap();
    let store = FakeCredentialStore::default();
    store
        .set_password("sshw:server-alpha", "deploy", "YOUR_PASSWORD")
        .unwrap();
    let ssh = FakeSshClient::with_stderr(
        "stty: 'standard input': Inappropriate ioctl for device\nactual warning\n",
    );
    let mut prompter = FakePrompter::default();

    let output = execute(
        Cli::try_parse_from(["sshw", "run", "server-alpha", "hostname"]).unwrap(),
        &path,
        &store,
        &ssh,
        &mut prompter,
    )
    .unwrap();

    assert_eq!(output.stdout, "ok\n");
    assert_eq!(output.stderr, "actual warning\n");
}

fn sample_config() -> SshwConfig {
    let mut servers = BTreeMap::new();
    servers.insert(
        "server-alpha".to_string(),
        ServerConfig {
            host: "192.0.2.10".to_string(),
            port: 2222,
            user: "deploy".to_string(),
            auth: AuthConfig::Password {
                credential: "sshw:server-alpha".to_string(),
            },
        },
    );

    SshwConfig {
        version: 1,
        default: Some("server-alpha".to_string()),
        servers,
    }
}

#[derive(Default)]
struct FakeCredentialStore {
    values: RefCell<BTreeMap<(String, String), String>>,
    deleted: RefCell<Vec<(String, String)>>,
}

impl CredentialStore for FakeCredentialStore {
    fn set_password(&self, credential: &str, user: &str, password: &str) -> anyhow::Result<()> {
        self.values.borrow_mut().insert(
            (credential.to_string(), user.to_string()),
            password.to_string(),
        );
        Ok(())
    }

    fn get_password(&self, credential: &str, user: &str) -> anyhow::Result<String> {
        self.values
            .borrow()
            .get(&(credential.to_string(), user.to_string()))
            .cloned()
            .ok_or_else(|| anyhow::anyhow!("missing credential"))
    }

    fn delete_password(&self, credential: &str, user: &str) -> anyhow::Result<()> {
        self.deleted
            .borrow_mut()
            .push((credential.to_string(), user.to_string()));
        Ok(())
    }

    fn health_check(&self) -> anyhow::Result<CredentialStoreHealth> {
        Ok(CredentialStoreHealth {
            backend: "fake".to_string(),
            available: true,
            message: "ok".to_string(),
        })
    }
}

#[derive(Default)]
struct FakeSshClient {
    run_commands: RefCell<Vec<String>>,
    trusted_expected_fingerprints: RefCell<Vec<String>>,
    get_calls: RefCell<Vec<bool>>,
    host_key_fingerprint: String,
    stderr: String,
}

impl FakeSshClient {
    fn with_stderr(stderr: &str) -> Self {
        Self {
            stderr: stderr.to_string(),
            ..Self::default()
        }
    }
}

impl SshClient for FakeSshClient {
    fn host_key(&self, _server: &ServerConfig) -> anyhow::Result<HostKeyInfo> {
        Ok(HostKeyInfo {
            algorithm: "ssh-ed25519".to_string(),
            fingerprint_sha256: if self.host_key_fingerprint.is_empty() {
                "SHA256:abc".to_string()
            } else {
                self.host_key_fingerprint.clone()
            },
        })
    }

    fn trust_host(
        &self,
        _server_name: &str,
        server: &ServerConfig,
        expected_fingerprint_sha256: &str,
    ) -> anyhow::Result<HostKeyInfo> {
        self.trusted_expected_fingerprints
            .borrow_mut()
            .push(expected_fingerprint_sha256.to_string());
        let host_key = self.host_key(server)?;
        if host_key.fingerprint_sha256 != expected_fingerprint_sha256 {
            return Err(anyhow::anyhow!("host key fingerprint changed before trust"));
        }
        Ok(host_key)
    }

    fn run(
        &self,
        _server: &ServerConfig,
        _auth: &AuthMaterial,
        command: &str,
    ) -> anyhow::Result<RunResult> {
        self.run_commands.borrow_mut().push(command.to_string());
        Ok(RunResult {
            exit_status: 0,
            stdout: "ok\n".to_string(),
            stderr: self.stderr.clone(),
            duration_ms: 1,
        })
    }

    fn put(
        &self,
        _server: &ServerConfig,
        _auth: &AuthMaterial,
        local: &Path,
        remote: &str,
    ) -> anyhow::Result<TransferResult> {
        Ok(TransferResult {
            bytes: 1,
            source: local.display().to_string(),
            destination: remote.to_string(),
        })
    }

    fn get(
        &self,
        _server: &ServerConfig,
        _auth: &AuthMaterial,
        remote: &str,
        local: &Path,
        overwrite: bool,
    ) -> anyhow::Result<TransferResult> {
        self.get_calls.borrow_mut().push(overwrite);
        Ok(TransferResult {
            bytes: 1,
            source: remote.to_string(),
            destination: local.display().to_string(),
        })
    }
}

#[derive(Default)]
struct FakePrompter {
    confirm: bool,
}

impl Prompter for FakePrompter {
    fn confirm(&mut self, _prompt: &str) -> anyhow::Result<bool> {
        Ok(self.confirm)
    }

    fn password(&mut self, _prompt: &str) -> anyhow::Result<String> {
        Ok("YOUR_PASSWORD".to_string())
    }
}
