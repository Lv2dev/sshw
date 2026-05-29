use clap::Parser;
use sshw::cli::{AuthArg, Cli, Command, Prompter, execute, execute_for_runtime};
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
    assert_eq!(args.target, ["server-alpha", "pm2 status"]);

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
fn json_run_unknown_server_returns_structured_error() {
    let temp = tempfile::tempdir().unwrap();
    let path = temp.path().join("servers.json");
    save_config(&path, &sample_config()).unwrap();
    let store = FakeCredentialStore::default();
    let ssh = FakeSshClient::default();
    let mut prompter = FakePrompter::default();

    let output = execute_for_runtime(
        Cli::try_parse_from(["sshw", "run", "missing", "hostname", "--json"]).unwrap(),
        &path,
        &store,
        &ssh,
        &mut prompter,
    );

    let json: serde_json::Value = serde_json::from_str(output.stdout.trim()).unwrap();
    assert_eq!(output.exit_code, 3);
    assert_eq!(output.stderr, "");
    assert_eq!(json["ok"], false);
    assert_eq!(json["error"]["kind"], "config");
    assert_eq!(json["error"]["exit_code"], 3);
    assert!(
        json["error"]["message"]
            .as_str()
            .unwrap()
            .contains("unknown server 'missing'")
    );
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
fn json_dangerous_run_returns_safety_error_before_ssh() {
    let temp = tempfile::tempdir().unwrap();
    let path = temp.path().join("servers.json");
    save_config(&path, &sample_config()).unwrap();
    let store = FakeCredentialStore::default();
    let ssh = FakeSshClient::default();
    let mut prompter = FakePrompter::default();

    let output = execute_for_runtime(
        Cli::try_parse_from([
            "sshw",
            "run",
            "server-alpha",
            "rm -rf /home/deploy/app",
            "--json",
        ])
        .unwrap(),
        &path,
        &store,
        &ssh,
        &mut prompter,
    );

    let json: serde_json::Value = serde_json::from_str(output.stdout.trim()).unwrap();
    assert_eq!(output.exit_code, 2);
    assert_eq!(output.stderr, "");
    assert_eq!(json["error"]["kind"], "safety");
    assert_eq!(json["error"]["exit_code"], 2);
    assert!(
        json["error"]["message"]
            .as_str()
            .unwrap()
            .contains("requires --yes")
    );
    assert!(ssh.run_commands.borrow().is_empty());
}

#[test]
fn json_run_missing_credential_returns_auth_error() {
    let temp = tempfile::tempdir().unwrap();
    let path = temp.path().join("servers.json");
    save_config(&path, &sample_config()).unwrap();
    let store = FakeCredentialStore::default();
    let ssh = FakeSshClient::default();
    let mut prompter = FakePrompter::default();

    let output = execute_for_runtime(
        Cli::try_parse_from(["sshw", "run", "server-alpha", "hostname", "--json"]).unwrap(),
        &path,
        &store,
        &ssh,
        &mut prompter,
    );

    let json: serde_json::Value = serde_json::from_str(output.stdout.trim()).unwrap();
    assert_eq!(output.exit_code, 4);
    assert_eq!(output.stderr, "");
    assert_eq!(json["error"]["kind"], "auth");
    assert_eq!(json["error"]["exit_code"], 4);
    assert!(
        json["error"]["message"]
            .as_str()
            .unwrap()
            .contains("missing credential entry")
    );
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
        password: None,
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
        password: None,
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
fn human_get_existing_local_file_returns_io_exit_code() {
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

    let output = execute_for_runtime(
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
    );

    assert_eq!(output.exit_code, 6);
    assert_eq!(output.stdout, "");
    assert!(output.stderr.contains("local file already exists"));
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
fn add_password_rejects_empty_password_before_storing_secret() {
    let temp = tempfile::tempdir().unwrap();
    let path = temp.path().join("servers.json");
    save_config(&path, &SshwConfig::default()).unwrap();
    let store = FakeCredentialStore::default();
    let ssh = FakeSshClient::default();
    let mut prompter = FakePrompter {
        confirm: false,
        password: Some(String::new()),
    };

    let err = execute(
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
        ])
        .unwrap(),
        &path,
        &store,
        &ssh,
        &mut prompter,
    )
    .unwrap_err();

    assert!(err.to_string().contains("password cannot be empty"));
    assert!(store.values.borrow().is_empty());
}

#[test]
fn put_to_system_path_requires_yes_before_ssh() {
    let temp = tempfile::tempdir().unwrap();
    let path = temp.path().join("servers.json");
    save_config(&path, &sample_config()).unwrap();
    let local = temp.path().join("app");
    std::fs::write(&local, "binary").unwrap();
    let store = FakeCredentialStore::default();
    store
        .set_password("sshw:server-alpha", "deploy", "YOUR_PASSWORD")
        .unwrap();
    let ssh = FakeSshClient::default();
    let mut prompter = FakePrompter::default();

    let err = execute(
        Cli::try_parse_from([
            "sshw",
            "put",
            "server-alpha",
            local.to_str().unwrap(),
            "/usr/bin/app",
        ])
        .unwrap(),
        &path,
        &store,
        &ssh,
        &mut prompter,
    )
    .unwrap_err();

    assert!(err.to_string().contains("requires --yes"));
    assert!(ssh.put_calls.borrow().is_empty());
}

#[test]
fn put_to_system_path_with_yes_allows_upload() {
    let temp = tempfile::tempdir().unwrap();
    let path = temp.path().join("servers.json");
    save_config(&path, &sample_config()).unwrap();
    let local = temp.path().join("app");
    std::fs::write(&local, "binary").unwrap();
    let store = FakeCredentialStore::default();
    store
        .set_password("sshw:server-alpha", "deploy", "YOUR_PASSWORD")
        .unwrap();
    let ssh = FakeSshClient::default();
    let mut prompter = FakePrompter::default();

    let output = execute(
        Cli::try_parse_from([
            "sshw",
            "put",
            "server-alpha",
            local.to_str().unwrap(),
            "/usr/bin/app",
            "--yes",
        ])
        .unwrap(),
        &path,
        &store,
        &ssh,
        &mut prompter,
    )
    .unwrap();

    assert!(output.stdout.contains("uploaded"));
    assert_eq!(ssh.put_calls.borrow().as_slice(), ["/usr/bin/app"]);
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

#[test]
fn run_uses_default_server_when_name_is_omitted() {
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
        Cli::try_parse_from(["sshw", "run", "hostname"]).unwrap(),
        &path,
        &store,
        &ssh,
        &mut prompter,
    )
    .unwrap();

    assert_eq!(output.stdout, "ok\n");
    assert_eq!(ssh.run_commands.borrow().as_slice(), ["hostname"]);
}

#[test]
fn run_without_name_requires_configured_default() {
    let temp = tempfile::tempdir().unwrap();
    let path = temp.path().join("servers.json");
    let mut config = sample_config();
    config.default = None;
    save_config(&path, &config).unwrap();
    let store = FakeCredentialStore::default();
    let ssh = FakeSshClient::default();
    let mut prompter = FakePrompter::default();

    let err = execute(
        Cli::try_parse_from(["sshw", "run", "hostname"]).unwrap(),
        &path,
        &store,
        &ssh,
        &mut prompter,
    )
    .unwrap_err();

    assert!(err.to_string().contains("no default server configured"));
    assert!(ssh.run_commands.borrow().is_empty());
}

#[test]
fn put_uses_default_server_when_name_is_omitted() {
    let temp = tempfile::tempdir().unwrap();
    let path = temp.path().join("servers.json");
    save_config(&path, &sample_config()).unwrap();
    let local = temp.path().join("app");
    std::fs::write(&local, "binary").unwrap();
    let store = FakeCredentialStore::default();
    store
        .set_password("sshw:server-alpha", "deploy", "YOUR_PASSWORD")
        .unwrap();
    let ssh = FakeSshClient::default();
    let mut prompter = FakePrompter::default();

    let output = execute(
        Cli::try_parse_from(["sshw", "put", local.to_str().unwrap(), "/tmp/app"]).unwrap(),
        &path,
        &store,
        &ssh,
        &mut prompter,
    )
    .unwrap();

    assert!(output.stdout.contains("uploaded"));
    assert_eq!(ssh.put_calls.borrow().as_slice(), ["/tmp/app"]);
}

#[test]
fn get_uses_default_server_when_name_is_omitted() {
    let temp = tempfile::tempdir().unwrap();
    let path = temp.path().join("servers.json");
    save_config(&path, &sample_config()).unwrap();
    let local = temp.path().join("download.txt");
    let store = FakeCredentialStore::default();
    store
        .set_password("sshw:server-alpha", "deploy", "YOUR_PASSWORD")
        .unwrap();
    let ssh = FakeSshClient::default();
    let mut prompter = FakePrompter::default();

    let output = execute(
        Cli::try_parse_from(["sshw", "get", "/tmp/remote.txt", local.to_str().unwrap()]).unwrap(),
        &path,
        &store,
        &ssh,
        &mut prompter,
    )
    .unwrap();

    assert!(output.stdout.contains("downloaded"));
    assert_eq!(ssh.get_calls.borrow().as_slice(), [false]);
}

#[test]
fn default_command_prints_and_updates_default_server() {
    let temp = tempfile::tempdir().unwrap();
    let path = temp.path().join("servers.json");
    let mut config = sample_config();
    config.servers.insert(
        "server-beta".to_string(),
        ServerConfig {
            host: "192.0.2.11".to_string(),
            port: 22,
            user: "deploy".to_string(),
            auth: AuthConfig::Agent,
        },
    );
    save_config(&path, &config).unwrap();
    let store = FakeCredentialStore::default();
    let ssh = FakeSshClient::default();

    let current = execute(
        Cli::try_parse_from(["sshw", "default"]).unwrap(),
        &path,
        &store,
        &ssh,
        &mut FakePrompter::default(),
    )
    .unwrap();
    assert_eq!(current.stdout, "server-alpha\n");

    let updated = execute(
        Cli::try_parse_from(["sshw", "default", "server-beta"]).unwrap(),
        &path,
        &store,
        &ssh,
        &mut FakePrompter::default(),
    )
    .unwrap();
    assert_eq!(updated.stdout, "default set to server-beta\n");

    let current = execute(
        Cli::try_parse_from(["sshw", "default"]).unwrap(),
        &path,
        &store,
        &ssh,
        &mut FakePrompter::default(),
    )
    .unwrap();
    assert_eq!(current.stdout, "server-beta\n");
}

#[test]
fn doctor_json_reports_missing_credentials_without_secrets() {
    let temp = tempfile::tempdir().unwrap();
    let path = temp.path().join("servers.json");
    save_config(&path, &sample_config()).unwrap();
    let store = FakeCredentialStore::default();
    let ssh = FakeSshClient::default();
    let mut prompter = FakePrompter::default();

    let output = execute(
        Cli::try_parse_from(["sshw", "doctor", "--json"]).unwrap(),
        &path,
        &store,
        &ssh,
        &mut prompter,
    )
    .unwrap();

    let json: serde_json::Value = serde_json::from_str(output.stdout.trim()).unwrap();
    assert_eq!(json["credential_backend"], "fake");
    assert_eq!(json["credential_available"], true);
    assert_eq!(
        json["missing_credentials"],
        serde_json::json!(["server-alpha"])
    );
    assert!(!output.stdout.contains("YOUR_PASSWORD"));
}

#[test]
fn parses_global_home_flag_before_subcommand() {
    let cli = Cli::try_parse_from(["sshw", "--home", "/proj/.sshw", "list"]).unwrap();

    assert_eq!(cli.home.as_deref(), Some(Path::new("/proj/.sshw")));
    assert!(matches!(cli.command, Command::List(_)));
}

#[test]
fn parses_global_home_flag_after_subcommand() {
    let cli = Cli::try_parse_from(["sshw", "list", "--home", "/proj/.sshw"]).unwrap();

    assert_eq!(cli.home.as_deref(), Some(Path::new("/proj/.sshw")));
}

#[test]
fn add_password_stores_namespaced_credential_key() {
    let temp = tempfile::tempdir().unwrap();
    let path = temp.path().join("servers.json");
    save_config(&path, &SshwConfig::default()).unwrap();
    let store = FakeCredentialStore::default();
    let ssh = FakeSshClient::default();
    let mut prompter = FakePrompter {
        confirm: false,
        password: Some("secret-pw".to_string()),
    };

    execute(
        Cli::try_parse_from([
            "sshw",
            "add",
            "web",
            "--host",
            "192.0.2.10",
            "--port",
            "22",
            "--user",
            "deploy",
        ])
        .unwrap(),
        &path,
        &store,
        &ssh,
        &mut prompter,
    )
    .unwrap();

    let keys: Vec<(String, String)> = store.values.borrow().keys().cloned().collect();
    assert_eq!(keys.len(), 1);
    let (credential, user) = &keys[0];
    assert_eq!(user, "deploy");
    // Always namespaced: sshw:<namespace>:web, never the legacy sshw:web.
    let segments: Vec<&str> = credential.split(':').collect();
    assert_eq!(segments.len(), 3, "credential was {credential}");
    assert_eq!(segments[0], "sshw");
    assert_eq!(segments[2], "web");
    assert_ne!(credential.as_str(), "sshw:web");
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
    put_calls: RefCell<Vec<String>>,
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
        self.put_calls.borrow_mut().push(remote.to_string());
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
    password: Option<String>,
}

impl Prompter for FakePrompter {
    fn confirm(&mut self, _prompt: &str) -> anyhow::Result<bool> {
        Ok(self.confirm)
    }

    fn password(&mut self, _prompt: &str) -> anyhow::Result<String> {
        Ok(self
            .password
            .clone()
            .unwrap_or_else(|| "YOUR_PASSWORD".to_string()))
    }
}
