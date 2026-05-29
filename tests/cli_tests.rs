use clap::Parser;
use sshw::audit::FileAuditSink;
use sshw::cli::{
    AuthArg, Cli, Command, ExecContext, Prompter, execute, execute_for_runtime, execute_with,
};
use sshw::config::{AuthConfig, ServerConfig, SshwConfig, save_config};
use sshw::credentials::{AuthMaterial, CredentialStore, CredentialStoreHealth};
use sshw::home::ResolvedHome;
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

#[test]
fn parses_global_profile_flag() {
    let cli = Cli::try_parse_from(["sshw", "--profile", "prod", "list"]).unwrap();

    assert_eq!(cli.profile.as_deref(), Some("prod"));
    assert!(matches!(cli.command, Command::List(_)));
}

#[test]
fn profile_add_list_show_default_remove_round_trip() {
    let temp = tempfile::tempdir().unwrap();
    let path = temp.path().join("servers.json");
    save_config(&path, &SshwConfig::default()).unwrap();
    let store = FakeCredentialStore::default();
    let ssh = FakeSshClient::default();
    let prod_home = temp.path().join("prod-home");
    let prod_home = prod_home.to_str().unwrap();

    let added = execute(
        Cli::try_parse_from(["sshw", "profile", "add", "prod", "--home", prod_home]).unwrap(),
        &path,
        &store,
        &ssh,
        &mut FakePrompter::default(),
    )
    .unwrap();
    assert!(added.stdout.contains("added profile prod"));

    let listed = execute(
        Cli::try_parse_from(["sshw", "profile", "list"]).unwrap(),
        &path,
        &store,
        &ssh,
        &mut FakePrompter::default(),
    )
    .unwrap();
    assert!(listed.stdout.contains("prod"));
    assert!(listed.stdout.contains("id=p_"));
    // first profile added becomes the registry default
    assert!(listed.stdout.contains("* prod"));

    let shown = execute(
        Cli::try_parse_from(["sshw", "profile", "show", "prod"]).unwrap(),
        &path,
        &store,
        &ssh,
        &mut FakePrompter::default(),
    )
    .unwrap();
    assert!(shown.stdout.contains("id: p_"));
    assert!(shown.stdout.contains("default: true"));

    let removed = execute(
        Cli::try_parse_from(["sshw", "profile", "remove", "prod"]).unwrap(),
        &path,
        &store,
        &ssh,
        &mut FakePrompter::default(),
    )
    .unwrap();
    assert!(removed.stdout.contains("removed profile prod"));

    let empty = execute(
        Cli::try_parse_from(["sshw", "profile", "list"]).unwrap(),
        &path,
        &store,
        &ssh,
        &mut FakePrompter::default(),
    )
    .unwrap();
    assert_eq!(empty.stdout, "");
}

#[test]
fn profile_add_requires_home() {
    let temp = tempfile::tempdir().unwrap();
    let path = temp.path().join("servers.json");
    save_config(&path, &SshwConfig::default()).unwrap();
    let store = FakeCredentialStore::default();
    let ssh = FakeSshClient::default();

    let err = execute(
        Cli::try_parse_from(["sshw", "profile", "add", "prod"]).unwrap(),
        &path,
        &store,
        &ssh,
        &mut FakePrompter::default(),
    )
    .unwrap_err();

    assert!(err.to_string().contains("requires --home"));
}

#[test]
fn run_redacts_secrets_in_output() {
    let temp = tempfile::tempdir().unwrap();
    let path = temp.path().join("servers.json");
    save_config(&path, &sample_config()).unwrap();
    let store = FakeCredentialStore::default();
    store
        .set_password("sshw:server-alpha", "deploy", "YOUR_PASSWORD")
        .unwrap();
    let mut prompter = FakePrompter::default();

    let human = execute(
        Cli::try_parse_from(["sshw", "run", "server-alpha", "cat env"]).unwrap(),
        &path,
        &store,
        &FakeSshClient::with_stdout("db password=hunter2\nok\n"),
        &mut prompter,
    )
    .unwrap();
    assert!(human.stdout.contains("password=<redacted>"));
    assert!(!human.stdout.contains("hunter2"));

    let json_out = execute(
        Cli::try_parse_from(["sshw", "run", "server-alpha", "cat env", "--json"]).unwrap(),
        &path,
        &store,
        &FakeSshClient::with_stdout("db password=hunter2\n"),
        &mut prompter,
    )
    .unwrap();
    let json: serde_json::Value = serde_json::from_str(json_out.stdout.trim()).unwrap();
    assert!(
        json["stdout"]
            .as_str()
            .unwrap()
            .contains("password=<redacted>")
    );
    assert!(!json_out.stdout.contains("hunter2"));
}

fn write_policy(dir: &Path, contents: &str) {
    std::fs::write(dir.join("policy.json"), contents).unwrap();
}

#[test]
fn run_writes_redacted_audit_record() {
    let temp = tempfile::tempdir().unwrap();
    let path = temp.path().join("servers.json");
    save_config(&path, &sample_config()).unwrap();
    let store = FakeCredentialStore::default();
    store
        .set_password("sshw:server-alpha", "deploy", "YOUR_PASSWORD")
        .unwrap();
    let ssh = FakeSshClient::default();
    let audit_path = temp.path().join("audit.jsonl");
    let audit = FileAuditSink::new(audit_path.clone());
    let home = ResolvedHome::from_config_path(&path);
    let registry = temp.path().join("profiles.json");
    let ctx = ExecContext {
        home: &home,
        registry_path: &registry,
        policy_forced: false,
        audit: &audit,
    };

    execute_with(
        Cli::try_parse_from(["sshw", "run", "server-alpha", "mysql --password=hunter2"]).unwrap(),
        &ctx,
        &store,
        &ssh,
        &mut FakePrompter::default(),
    )
    .unwrap();

    let log = std::fs::read_to_string(&audit_path).unwrap();
    let rec: serde_json::Value = serde_json::from_str(log.trim()).unwrap();
    assert_eq!(rec["action"], "run");
    assert_eq!(rec["server"], "server-alpha");
    assert_eq!(rec["status"], "ok");
    assert!(!log.contains("hunter2"), "secret leaked into audit log");
    assert!(rec["detail"].as_str().unwrap().contains("<redacted>"));
}

#[test]
fn failed_run_is_audited_with_error_status() {
    let temp = tempfile::tempdir().unwrap();
    let path = temp.path().join("servers.json");
    save_config(&path, &sample_config()).unwrap();
    let store = FakeCredentialStore::default();
    let ssh = FakeSshClient::default();
    let audit_path = temp.path().join("audit.jsonl");
    let audit = FileAuditSink::new(audit_path.clone());
    let home = ResolvedHome::from_config_path(&path);
    let registry = temp.path().join("profiles.json");
    let ctx = ExecContext {
        home: &home,
        registry_path: &registry,
        policy_forced: false,
        audit: &audit,
    };

    let _ = execute_with(
        Cli::try_parse_from(["sshw", "run", "missing", "hostname"]).unwrap(),
        &ctx,
        &store,
        &ssh,
        &mut FakePrompter::default(),
    );

    let log = std::fs::read_to_string(&audit_path).unwrap();
    let rec: serde_json::Value = serde_json::from_str(log.trim()).unwrap();
    assert_eq!(rec["action"], "run");
    assert_eq!(rec["server"], "missing");
    assert_eq!(rec["status"], "error");
    assert_eq!(rec["exit_code"], 3);
}

#[test]
fn read_only_commands_are_not_audited() {
    let temp = tempfile::tempdir().unwrap();
    let path = temp.path().join("servers.json");
    save_config(&path, &sample_config()).unwrap();
    let store = FakeCredentialStore::default();
    let ssh = FakeSshClient::default();
    let audit_path = temp.path().join("audit.jsonl");
    let audit = FileAuditSink::new(audit_path.clone());
    let home = ResolvedHome::from_config_path(&path);
    let registry = temp.path().join("profiles.json");
    let ctx = ExecContext {
        home: &home,
        registry_path: &registry,
        policy_forced: false,
        audit: &audit,
    };

    execute_with(
        Cli::try_parse_from(["sshw", "list"]).unwrap(),
        &ctx,
        &store,
        &ssh,
        &mut FakePrompter::default(),
    )
    .unwrap();

    assert!(
        !audit_path.exists(),
        "list should not write an audit record"
    );
}

#[test]
fn policy_allows_listed_command_and_blocks_others() {
    let temp = tempfile::tempdir().unwrap();
    let path = temp.path().join("servers.json");
    save_config(&path, &sample_config()).unwrap();
    write_policy(
        temp.path(),
        r#"{"version":1,"enabled":true,"allow_commands":["uptime"]}"#,
    );
    let store = FakeCredentialStore::default();
    store
        .set_password("sshw:server-alpha", "deploy", "YOUR_PASSWORD")
        .unwrap();
    let ssh = FakeSshClient::default();
    let mut prompter = FakePrompter::default();

    let allowed = execute(
        Cli::try_parse_from(["sshw", "run", "--policy", "server-alpha", "uptime"]).unwrap(),
        &path,
        &store,
        &ssh,
        &mut prompter,
    )
    .unwrap();
    assert_eq!(allowed.stdout, "ok\n");

    let denied = execute_for_runtime(
        Cli::try_parse_from([
            "sshw",
            "run",
            "--policy",
            "server-alpha",
            "whoami",
            "--json",
        ])
        .unwrap(),
        &path,
        &store,
        &ssh,
        &mut prompter,
    );
    assert_eq!(denied.exit_code, 7);
    let json: serde_json::Value = serde_json::from_str(denied.stdout.trim()).unwrap();
    assert_eq!(json["error"]["kind"], "policy");
    assert!(
        json["error"]["message"]
            .as_str()
            .unwrap()
            .contains("blocked by policy")
    );
    // Only the allowed command reached the SSH layer.
    assert_eq!(ssh.run_commands.borrow().as_slice(), ["uptime"]);
}

#[test]
fn policy_flag_without_file_fails_closed() {
    let temp = tempfile::tempdir().unwrap();
    let path = temp.path().join("servers.json");
    save_config(&path, &sample_config()).unwrap();
    let store = FakeCredentialStore::default();
    store
        .set_password("sshw:server-alpha", "deploy", "YOUR_PASSWORD")
        .unwrap();
    let ssh = FakeSshClient::default();
    let mut prompter = FakePrompter::default();

    let out = execute_for_runtime(
        Cli::try_parse_from([
            "sshw",
            "run",
            "--policy",
            "server-alpha",
            "uptime",
            "--json",
        ])
        .unwrap(),
        &path,
        &store,
        &ssh,
        &mut prompter,
    );

    assert_eq!(out.exit_code, 7);
    let json: serde_json::Value = serde_json::from_str(out.stdout.trim()).unwrap();
    assert_eq!(json["error"]["kind"], "policy");
    assert!(
        json["error"]["message"]
            .as_str()
            .unwrap()
            .contains("no policy file")
    );
    assert!(ssh.run_commands.borrow().is_empty());
}

#[test]
fn policy_blocks_put_and_get_outside_allowlist() {
    let temp = tempfile::tempdir().unwrap();
    let path = temp.path().join("servers.json");
    save_config(&path, &sample_config()).unwrap();
    write_policy(
        temp.path(),
        r#"{"enabled":true,"allow_put_paths":["/srv/app"],"allow_get_paths":["/var/log"]}"#,
    );
    let store = FakeCredentialStore::default();
    store
        .set_password("sshw:server-alpha", "deploy", "YOUR_PASSWORD")
        .unwrap();
    let ssh = FakeSshClient::default();
    let mut prompter = FakePrompter::default();
    let local = temp.path().join("artifact");
    std::fs::write(&local, "x").unwrap();

    let put_err = execute(
        Cli::try_parse_from([
            "sshw",
            "put",
            "--policy",
            "server-alpha",
            local.to_str().unwrap(),
            "/tmp/app",
        ])
        .unwrap(),
        &path,
        &store,
        &ssh,
        &mut prompter,
    )
    .unwrap_err();
    assert!(put_err.to_string().contains("blocked by policy"));
    assert!(ssh.put_calls.borrow().is_empty());

    let get_err = execute(
        Cli::try_parse_from([
            "sshw",
            "get",
            "--policy",
            "server-alpha",
            "/etc/secret",
            temp.path().join("out").to_str().unwrap(),
        ])
        .unwrap(),
        &path,
        &store,
        &ssh,
        &mut prompter,
    )
    .unwrap_err();
    assert!(get_err.to_string().contains("blocked by policy"));
    assert!(ssh.get_calls.borrow().is_empty());
}

#[test]
fn policy_denied_put_and_get_use_exit_code_7() {
    let temp = tempfile::tempdir().unwrap();
    let path = temp.path().join("servers.json");
    save_config(&path, &sample_config()).unwrap();
    write_policy(
        temp.path(),
        r#"{"enabled":true,"allow_put_paths":["/srv/app"],"allow_get_paths":["/var/log"]}"#,
    );
    let store = FakeCredentialStore::default();
    store
        .set_password("sshw:server-alpha", "deploy", "YOUR_PASSWORD")
        .unwrap();
    let ssh = FakeSshClient::default();
    let local = temp.path().join("artifact");
    std::fs::write(&local, "x").unwrap();

    let put = execute_for_runtime(
        Cli::try_parse_from([
            "sshw",
            "put",
            "--policy",
            "server-alpha",
            local.to_str().unwrap(),
            "/tmp/app",
        ])
        .unwrap(),
        &path,
        &store,
        &ssh,
        &mut FakePrompter::default(),
    );
    assert_eq!(put.exit_code, 7);
    assert!(put.stderr.contains("blocked by policy"));

    let get = execute_for_runtime(
        Cli::try_parse_from([
            "sshw",
            "get",
            "--policy",
            "server-alpha",
            "/etc/secret",
            temp.path().join("out").to_str().unwrap(),
        ])
        .unwrap(),
        &path,
        &store,
        &ssh,
        &mut FakePrompter::default(),
    );
    assert_eq!(get.exit_code, 7);
    assert!(get.stderr.contains("blocked by policy"));
}

#[test]
fn policy_disabled_in_file_allows_everything_without_flag() {
    let temp = tempfile::tempdir().unwrap();
    let path = temp.path().join("servers.json");
    save_config(&path, &sample_config()).unwrap();
    write_policy(
        temp.path(),
        r#"{"enabled":false,"allow_commands":["uptime"]}"#,
    );
    let store = FakeCredentialStore::default();
    store
        .set_password("sshw:server-alpha", "deploy", "YOUR_PASSWORD")
        .unwrap();
    let ssh = FakeSshClient::default();
    let mut prompter = FakePrompter::default();

    // whoami is not in the allowlist, but enforcement is off (no --policy,
    // file enabled=false), so it runs.
    let out = execute(
        Cli::try_parse_from(["sshw", "run", "server-alpha", "whoami"]).unwrap(),
        &path,
        &store,
        &ssh,
        &mut prompter,
    )
    .unwrap();
    assert_eq!(out.stdout, "ok\n");
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
        default: Some("server-alpha".to_string()),
        servers,
        ..SshwConfig::default()
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
    stdout: Option<String>,
    stderr: String,
}

impl FakeSshClient {
    fn with_stderr(stderr: &str) -> Self {
        Self {
            stderr: stderr.to_string(),
            ..Self::default()
        }
    }

    fn with_stdout(stdout: &str) -> Self {
        Self {
            stdout: Some(stdout.to_string()),
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
            stdout: self.stdout.clone().unwrap_or_else(|| "ok\n".to_string()),
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
