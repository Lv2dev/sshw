use clap::Parser;
use sshw::audit::FileAuditSink;
use sshw::cli::{
    AuthArg, Cli, Command, ExecContext, Prompter, execute, execute_for_runtime, execute_with,
};
use sshw::config::{
    AccountConfig, AuthConfig, PrivilegeConfig, PrivilegeMethod, ServerConfig, SshwConfig,
    load_config, save_config,
};
use sshw::credentials::session_store::SessionOnlyStore;
use sshw::credentials::{AuthMaterial, CredentialStore, CredentialStoreHealth};
use sshw::home::{CredentialNamespace, CredentialPurpose, ResolvedHome};
use sshw::ssh::{HostKeyInfo, RunResult, SshClient, SshTarget, TransferResult};
use std::cell::RefCell;
use std::collections::BTreeMap;
use std::path::Path;

#[test]
fn transfer_help_documents_remote_absolute_literal() {
    for command in ["put", "get"] {
        let help = Cli::try_parse_from(["sshw", command, "--help"])
            .unwrap_err()
            .to_string();
        assert!(
            help.contains("remote:/path"),
            "{command} help did not document the remote literal: {help}"
        );
    }
}

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
fn parses_add_with_password_stdin() {
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
        "--password-stdin",
    ])
    .unwrap();

    let Command::Add(args) = cli.command else {
        panic!("expected add command");
    };

    assert!(args.password_stdin);
    assert_eq!(args.auth, AuthArg::Password);
}

#[test]
fn parses_privilege_set_and_run_as_root() {
    let cli = Cli::try_parse_from([
        "sshw",
        "privilege",
        "set",
        "server-alpha",
        "--method",
        "sudo",
        "--password-stdin",
    ])
    .unwrap();

    let Command::Privilege(args) = cli.command else {
        panic!("expected privilege command");
    };
    let sshw::cli::PrivilegeCommand::Set(args) = args.command else {
        panic!("expected privilege set command");
    };
    assert_eq!(args.name, "server-alpha");
    assert_eq!(args.method, sshw::cli::PrivilegeMethodArg::Sudo);
    assert_eq!(args.user, "root");
    assert!(args.password_stdin);

    let cli = Cli::try_parse_from([
        "sshw",
        "run",
        "server-alpha",
        "id -u",
        "--as-root",
        "--json",
    ])
    .unwrap();
    let Command::Run(args) = cli.command else {
        panic!("expected run command");
    };
    assert!(args.as_root);
    assert!(args.json);
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
    save_config(&path, &sample_config(&path)).unwrap();
    let store = FakeCredentialStore::default();
    store
        .set_password(
            &login_credential(&path, "server-alpha"),
            "deploy",
            "YOUR_PASSWORD",
        )
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
    assert!(output.stdout.contains(&format!(
        "\"credential\":\"{}\"",
        login_credential(&path, "server-alpha")
    )));
    assert!(!output.stdout.contains("YOUR_PASSWORD"));
}

#[test]
fn unknown_server_returns_actionable_error() {
    let temp = tempfile::tempdir().unwrap();
    let path = temp.path().join("servers.json");
    save_config(&path, &sample_config(&path)).unwrap();
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
fn foreign_credential_reference_is_rejected_before_secret_or_ssh_access() {
    let temp = tempfile::tempdir().unwrap();
    let path = temp.path().join("servers.json");
    let foreign_credential =
        CredentialNamespace::profile("foreign").legacy_credential_key("server-alpha");
    let mut config = SshwConfig {
        default: Some("server-alpha".to_string()),
        ..SshwConfig::default()
    };
    config.servers.insert(
        "server-alpha".to_string(),
        ServerConfig::single_account(
            "192.0.2.10",
            22,
            "deploy",
            AuthConfig::Password {
                credential: foreign_credential.clone(),
            },
        ),
    );
    save_config(&path, &config).unwrap();
    let store = FakeCredentialStore::default();
    store
        .set_password(&foreign_credential, "deploy", "FOREIGN_PASSWORD")
        .unwrap();
    let ssh = FakeSshClient::default();
    let mut prompter = FakePrompter::default();

    let err = execute(
        Cli::try_parse_from(["sshw", "run", "server-alpha", "whoami"]).unwrap(),
        &path,
        &store,
        &ssh,
        &mut prompter,
    )
    .unwrap_err();

    assert!(err.to_string().contains("active home"));
    assert!(store.requested.borrow().is_empty());
    assert!(ssh.run_commands.borrow().is_empty());

    let err = execute(
        Cli::try_parse_from(["sshw", "remove", "server-alpha", "--yes"]).unwrap(),
        &path,
        &store,
        &ssh,
        &mut prompter,
    )
    .unwrap_err();
    assert!(err.to_string().contains("active home"));
    assert!(store.deleted.borrow().is_empty());
}

#[test]
fn orphan_privilege_blocks_add_before_alias_rebinding() {
    let temp = tempfile::tempdir().unwrap();
    let path = temp.path().join("servers.json");
    let namespace = ResolvedHome::from_config_path(&path).namespace;
    let original = format!(
        r#"{{
            "version": 1,
            "default": null,
            "servers": {{}},
            "privileges": {{
                "web": {{
                    "method": "sudo",
                    "user": "root",
                    "credential": "{}"
                }}
            }}
        }}"#,
        namespace.legacy_privilege_credential_key("web")
    );
    std::fs::write(&path, &original).unwrap();
    let store = FakeCredentialStore::default();
    let ssh = FakeSshClient::default();

    let err = execute(
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
            "--auth",
            "agent",
        ])
        .unwrap(),
        &path,
        &store,
        &ssh,
        &mut FakePrompter::default(),
    )
    .unwrap_err();

    assert!(err.to_string().contains("has no matching server"));
    assert_eq!(std::fs::read_to_string(&path).unwrap(), original);
    assert!(store.values.borrow().is_empty());
    assert!(ssh.run_commands.borrow().is_empty());
}

#[test]
fn active_home_v1_credential_reference_remains_compatible() {
    let temp = tempfile::tempdir().unwrap();
    let path = temp.path().join("servers.json");
    let home = ResolvedHome::from_config_path(&path);
    let credential = home.namespace.legacy_credential_key("server-alpha");
    let mut config = SshwConfig {
        default: Some("server-alpha".to_string()),
        ..SshwConfig::default()
    };
    config.servers.insert(
        "server-alpha".to_string(),
        ServerConfig::single_account(
            "192.0.2.10",
            22,
            "deploy",
            AuthConfig::Password {
                credential: credential.clone(),
            },
        ),
    );
    save_config(&path, &config).unwrap();
    let store = FakeCredentialStore::default();
    store
        .set_password(&credential, "deploy", "YOUR_PASSWORD")
        .unwrap();
    let ssh = FakeSshClient::default();
    let mut prompter = FakePrompter::default();

    let output = execute(
        Cli::try_parse_from(["sshw", "run", "server-alpha", "whoami"]).unwrap(),
        &path,
        &store,
        &ssh,
        &mut prompter,
    )
    .unwrap();

    assert_eq!(output.exit_code, 0);
    assert_eq!(store.requested.borrow().len(), 1);
    assert_eq!(ssh.run_commands.borrow().as_slice(), ["whoami"]);
}

#[test]
fn json_run_unknown_server_returns_structured_error() {
    let temp = tempfile::tempdir().unwrap();
    let path = temp.path().join("servers.json");
    save_config(&path, &sample_config(&path)).unwrap();
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
fn dynamic_unknown_server_text_cannot_change_config_error_kind() {
    let temp = tempfile::tempdir().unwrap();
    let path = temp.path().join("servers.json");
    save_config(&path, &sample_config(&path)).unwrap();

    let output = execute_for_runtime(
        Cli::try_parse_from(["sshw", "run", "blocked by policy", "hostname", "--json"]).unwrap(),
        &path,
        &FakeCredentialStore::default(),
        &FakeSshClient::default(),
        &mut FakePrompter::default(),
    );

    let json: serde_json::Value = serde_json::from_str(output.stdout.trim()).unwrap();
    assert_eq!(output.exit_code, 3);
    assert_eq!(json["error"]["kind"], "config");
}

#[test]
fn add_json_failure_uses_error_envelope() {
    let temp = tempfile::tempdir().unwrap();
    let path = temp.path().join("servers.json");
    save_config(&path, &SshwConfig::default()).unwrap();
    let store = FakeCredentialStore::default();
    let ssh = FakeSshClient::default();
    let mut prompter = FakePrompter {
        confirm: false,
        confirm_error: None,
        password: Some(String::new()),
        password_stdin: None,
    };

    let output = execute_for_runtime(
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
            "--json",
        ])
        .unwrap(),
        &path,
        &store,
        &ssh,
        &mut prompter,
    );

    assert_json_error(output, 4, "auth", "password cannot be empty");
    assert!(store.values.borrow().is_empty());
}

#[test]
fn trust_json_failure_uses_error_envelope() {
    let temp = tempfile::tempdir().unwrap();
    let path = temp.path().join("servers.json");
    save_config(&path, &SshwConfig::default()).unwrap();
    let store = FakeCredentialStore::default();
    let ssh = FakeSshClient::default();
    let mut prompter = FakePrompter::default();

    let output = execute_for_runtime(
        Cli::try_parse_from(["sshw", "trust", "missing", "--yes", "--json"]).unwrap(),
        &path,
        &store,
        &ssh,
        &mut prompter,
    );

    assert_json_error(output, 3, "config", "unknown server 'missing'");
}

#[test]
fn remove_json_failure_uses_error_envelope() {
    let temp = tempfile::tempdir().unwrap();
    let path = temp.path().join("servers.json");
    save_config(&path, &SshwConfig::default()).unwrap();
    let store = FakeCredentialStore::default();
    let ssh = FakeSshClient::default();
    let mut prompter = FakePrompter::default();

    let output = execute_for_runtime(
        Cli::try_parse_from(["sshw", "remove", "missing", "--yes", "--json"]).unwrap(),
        &path,
        &store,
        &ssh,
        &mut prompter,
    );

    assert_json_error(output, 3, "config", "unknown server 'missing'");
}

#[test]
fn privilege_set_json_failure_uses_error_envelope() {
    let temp = tempfile::tempdir().unwrap();
    let path = temp.path().join("servers.json");
    save_config(&path, &sample_config(&path)).unwrap();
    let store = FakeCredentialStore::default();
    let ssh = FakeSshClient::default();
    let mut prompter = FakePrompter {
        confirm: false,
        confirm_error: None,
        password: None,
        password_stdin: Some(String::new()),
    };

    let output = execute_for_runtime(
        Cli::try_parse_from([
            "sshw",
            "privilege",
            "set",
            "server-alpha",
            "--password-stdin",
            "--json",
        ])
        .unwrap(),
        &path,
        &store,
        &ssh,
        &mut prompter,
    );

    assert_json_error(output, 4, "auth", "password cannot be empty");
    assert!(store.values.borrow().is_empty());
}

#[test]
fn privilege_clear_json_failure_uses_error_envelope() {
    let temp = tempfile::tempdir().unwrap();
    let path = temp.path().join("servers.json");
    save_config(&path, &sample_config(&path)).unwrap();
    let store = FakeCredentialStore::default();
    let ssh = FakeSshClient::default();
    let mut prompter = FakePrompter::default();

    let output = execute_for_runtime(
        Cli::try_parse_from([
            "sshw",
            "privilege",
            "clear",
            "server-alpha",
            "--yes",
            "--json",
        ])
        .unwrap(),
        &path,
        &store,
        &ssh,
        &mut prompter,
    );

    assert_json_error(output, 3, "config", "privilege configuration missing");
}

#[test]
fn add_json_success_reports_state_change_without_secret() {
    let temp = tempfile::tempdir().unwrap();
    let path = temp.path().join("servers.json");
    save_config(&path, &SshwConfig::default()).unwrap();
    let store = FakeCredentialStore::default();
    let ssh = FakeSshClient::default();
    let mut prompter = FakePrompter {
        confirm: false,
        confirm_error: None,
        password: Some("SSH_PASSWORD".to_string()),
        password_stdin: None,
    };

    let output = execute(
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
            "--json",
        ])
        .unwrap(),
        &path,
        &store,
        &ssh,
        &mut prompter,
    )
    .unwrap();

    let json: serde_json::Value = serde_json::from_str(output.stdout.trim()).unwrap();
    assert_eq!(json["ok"], true);
    assert_eq!(json["action"], "added");
    assert_eq!(json["server"], "server-alpha");
    assert!(!output.stdout.contains("SSH_PASSWORD"));
}

#[test]
fn add_json_update_reports_updated_action_and_session_warning() {
    let temp = tempfile::tempdir().unwrap();
    let path = temp.path().join("servers.json");
    save_config(&path, &sample_config(&path)).unwrap();
    let store = SessionOnlyStore::new();
    let ssh = FakeSshClient::default();
    let mut prompter = FakePrompter {
        confirm: false,
        confirm_error: None,
        password: None,
        password_stdin: Some("UPDATED_PASSWORD".to_string()),
    };

    let output = execute(
        Cli::try_parse_from([
            "sshw",
            "add",
            "server-alpha",
            "--host",
            "192.0.2.20",
            "--port",
            "2022",
            "--user",
            "deploy",
            "--password-stdin",
            "--force",
            "--json",
        ])
        .unwrap(),
        &path,
        &store,
        &ssh,
        &mut prompter,
    )
    .unwrap();

    let json: serde_json::Value = serde_json::from_str(output.stdout.trim()).unwrap();
    assert_eq!(json["ok"], true);
    assert_eq!(json["action"], "updated");
    assert_eq!(json["server"], "server-alpha");
    assert!(
        json["warning"]
            .as_str()
            .is_some_and(|warning| warning.contains("does not persist passwords")),
        "expected session-only persistence warning, got: {json}"
    );
    assert!(!output.stdout.contains("UPDATED_PASSWORD"));
}

#[test]
fn trust_json_success_reports_state_change() {
    let temp = tempfile::tempdir().unwrap();
    let path = temp.path().join("servers.json");
    save_config(&path, &sample_config(&path)).unwrap();
    let store = FakeCredentialStore::default();
    let ssh = FakeSshClient {
        host_key_fingerprint: "SHA256:displayed".to_string(),
        ..FakeSshClient::default()
    };
    let mut prompter = FakePrompter::default();

    let output = execute(
        Cli::try_parse_from(["sshw", "trust", "server-alpha", "--yes", "--json"]).unwrap(),
        &path,
        &store,
        &ssh,
        &mut prompter,
    )
    .unwrap();

    let json: serde_json::Value = serde_json::from_str(output.stdout.trim()).unwrap();
    assert_eq!(json["ok"], true);
    assert_eq!(json["server"], "server-alpha");
    assert_eq!(json["algorithm"], "ssh-ed25519");
    assert_eq!(json["fingerprint_sha256"], "SHA256:displayed");
}

#[test]
fn remove_json_success_reports_state_change() {
    let temp = tempfile::tempdir().unwrap();
    let path = temp.path().join("servers.json");
    save_config(&path, &sample_config(&path)).unwrap();
    let store = FakeCredentialStore::default();
    let ssh = FakeSshClient::default();
    let mut prompter = FakePrompter::default();

    let output = execute(
        Cli::try_parse_from(["sshw", "remove", "server-alpha", "--yes", "--json"]).unwrap(),
        &path,
        &store,
        &ssh,
        &mut prompter,
    )
    .unwrap();

    let json: serde_json::Value = serde_json::from_str(output.stdout.trim()).unwrap();
    assert_eq!(json["ok"], true);
    assert_eq!(json["action"], "removed");
    assert_eq!(json["server"], "server-alpha");
}

#[test]
fn remove_json_delete_failure_uses_error_envelope_after_config_removal() {
    let temp = tempfile::tempdir().unwrap();
    let path = temp.path().join("servers.json");
    save_config(&path, &sample_config(&path)).unwrap();
    let store = FakeCredentialStore {
        delete_error: Some("credential backend unavailable: delete denied".to_string()),
        ..FakeCredentialStore::default()
    };
    let ssh = FakeSshClient::default();
    let mut prompter = FakePrompter::default();

    let output = execute_for_runtime(
        Cli::try_parse_from(["sshw", "remove", "server-alpha", "--yes", "--json"]).unwrap(),
        &path,
        &store,
        &ssh,
        &mut prompter,
    );

    assert_json_error(output, 4, "auth", "credential backend unavailable");
    let config = load_config(&path).unwrap();
    assert!(
        !config.servers.contains_key("server-alpha"),
        "config must not keep references after durable removal"
    );
}

#[test]
fn privilege_set_json_success_reports_state_change_without_secret() {
    let temp = tempfile::tempdir().unwrap();
    let path = temp.path().join("servers.json");
    save_config(&path, &sample_config(&path)).unwrap();
    let store = FakeCredentialStore::default();
    let ssh = FakeSshClient::default();
    let mut prompter = FakePrompter {
        confirm: false,
        confirm_error: None,
        password: None,
        password_stdin: Some("ROOT_PASSWORD".to_string()),
    };

    let output = execute(
        Cli::try_parse_from([
            "sshw",
            "privilege",
            "set",
            "server-alpha",
            "--method",
            "sudo",
            "--password-stdin",
            "--json",
        ])
        .unwrap(),
        &path,
        &store,
        &ssh,
        &mut prompter,
    )
    .unwrap();

    let json: serde_json::Value = serde_json::from_str(output.stdout.trim()).unwrap();
    assert_eq!(json["ok"], true);
    assert_eq!(json["server"], "server-alpha");
    assert_eq!(json["method"], "sudo");
    assert_eq!(json["user"], "root");
    assert!(!output.stdout.contains("ROOT_PASSWORD"));
}

#[test]
fn privilege_set_session_warning_names_privilege_environment_variable() {
    let temp = tempfile::tempdir().unwrap();
    let path = temp.path().join("servers.json");
    save_config(&path, &sample_config(&path)).unwrap();
    let store = SessionOnlyStore::new();
    let ssh = FakeSshClient::default();
    let mut prompter = FakePrompter {
        confirm: false,
        confirm_error: None,
        password: None,
        password_stdin: Some("ROOT_PASSWORD".to_string()),
    };

    let output = execute(
        Cli::try_parse_from([
            "sshw",
            "privilege",
            "set",
            "server-alpha",
            "--method",
            "sudo",
            "--password-stdin",
            "--json",
        ])
        .unwrap(),
        &path,
        &store,
        &ssh,
        &mut prompter,
    )
    .unwrap();

    let json: serde_json::Value = serde_json::from_str(output.stdout.trim()).unwrap();
    assert!(
        json["warning"]
            .as_str()
            .unwrap()
            .contains("SSHW_PRIVILEGE_PASSWORD")
    );
}

#[test]
fn privilege_clear_json_success_reports_state_change() {
    let temp = tempfile::tempdir().unwrap();
    let path = temp.path().join("servers.json");
    let mut config = sample_config(&path);
    set_default_privilege(
        &mut config,
        "server-alpha",
        PrivilegeConfig {
            method: PrivilegeMethod::Sudo,
            user: "root".to_string(),
            credential: privilege_credential(&path, "server-alpha"),
        },
    );
    save_config(&path, &config).unwrap();
    let store = FakeCredentialStore::default();
    let ssh = FakeSshClient::default();
    let mut prompter = FakePrompter::default();

    let output = execute(
        Cli::try_parse_from([
            "sshw",
            "privilege",
            "clear",
            "server-alpha",
            "--yes",
            "--json",
        ])
        .unwrap(),
        &path,
        &store,
        &ssh,
        &mut prompter,
    )
    .unwrap();

    let json: serde_json::Value = serde_json::from_str(output.stdout.trim()).unwrap();
    assert_eq!(json["ok"], true);
    assert_eq!(json["action"], "cleared");
    assert_eq!(json["server"], "server-alpha");
}

#[test]
fn dangerous_run_is_blocked_before_ssh() {
    let temp = tempfile::tempdir().unwrap();
    let path = temp.path().join("servers.json");
    save_config(&path, &sample_config(&path)).unwrap();
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
    save_config(&path, &sample_config(&path)).unwrap();
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
    save_config(&path, &sample_config(&path)).unwrap();
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
fn show_json_success_includes_ok_true() {
    let temp = tempfile::tempdir().unwrap();
    let path = temp.path().join("servers.json");
    save_config(&path, &sample_config(&path)).unwrap();
    let store = FakeCredentialStore::default();
    let ssh = FakeSshClient::default();
    let mut prompter = FakePrompter::default();

    let output = execute(
        Cli::try_parse_from(["sshw", "show", "server-alpha", "--json"]).unwrap(),
        &path,
        &store,
        &ssh,
        &mut prompter,
    )
    .unwrap();

    let json: serde_json::Value = serde_json::from_str(output.stdout.trim()).unwrap();
    assert_eq!(json["ok"], true);
    assert_eq!(json["name"], "server-alpha");
    assert_eq!(json["is_default"], true);
}

#[test]
fn remove_requires_confirmation_unless_yes() {
    let temp = tempfile::tempdir().unwrap();
    let path = temp.path().join("servers.json");
    save_config(&path, &sample_config(&path)).unwrap();
    let store = FakeCredentialStore::default();
    let ssh = FakeSshClient::default();
    let mut prompter = FakePrompter {
        confirm: false,
        confirm_error: None,
        password: None,
        password_stdin: None,
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
fn remove_deletes_privilege_metadata_and_password() {
    let temp = tempfile::tempdir().unwrap();
    let path = temp.path().join("servers.json");
    let namespace = ResolvedHome::from_config_path(&path).namespace;
    let ops_login = namespace.credential_key_v3(
        CredentialPurpose::Login,
        "server-alpha",
        "ops",
        "0000000000000001",
    );
    let ops_privilege = namespace.credential_key_v3(
        CredentialPurpose::Privilege,
        "server-alpha",
        "ops",
        "0000000000000002",
    );
    let mut config = sample_config(&path);
    set_default_privilege(
        &mut config,
        "server-alpha",
        PrivilegeConfig {
            method: PrivilegeMethod::Sudo,
            user: "root".to_string(),
            credential: privilege_credential(&path, "server-alpha"),
        },
    );
    config
        .servers
        .get_mut("server-alpha")
        .unwrap()
        .accounts
        .insert(
            "ops".to_string(),
            AccountConfig {
                auth: AuthConfig::Password {
                    credential: ops_login.clone(),
                },
                privilege: Some(PrivilegeConfig {
                    method: PrivilegeMethod::Sudo,
                    user: "admin".to_string(),
                    credential: ops_privilege.clone(),
                }),
            },
        );
    save_config(&path, &config).unwrap();
    let store = FakeCredentialStore::default();
    let ssh = FakeSshClient::default();

    let output = execute(
        Cli::try_parse_from(["sshw", "remove", "server-alpha", "--yes"]).unwrap(),
        &path,
        &store,
        &ssh,
        &mut FakePrompter::default(),
    )
    .unwrap();

    assert!(output.stdout.contains("removed server-alpha"));
    let config = load_config(&path).unwrap();
    assert!(!config.servers.contains_key("server-alpha"));
    assert!(default_privilege(&config, "server-alpha").is_none());
    let deleted = store.deleted.borrow();
    assert!(deleted.contains(&(
        login_credential(&path, "server-alpha"),
        "deploy".to_string()
    )));
    assert!(deleted.contains(&(
        privilege_credential(&path, "server-alpha"),
        "root".to_string()
    )));
    assert!(deleted.contains(&(ops_login, "ops".to_string())));
    assert!(deleted.contains(&(ops_privilege, "admin".to_string())));
}

#[test]
fn confirmation_failure_is_reported_as_config_error() {
    let temp = tempfile::tempdir().unwrap();
    let path = temp.path().join("servers.json");
    save_config(&path, &sample_config(&path)).unwrap();
    let store = FakeCredentialStore::default();
    let ssh = FakeSshClient::default();
    let mut prompter = FakePrompter {
        confirm: false,
        confirm_error: Some(
            "confirmation requires an interactive terminal; rerun with --yes to confirm"
                .to_string(),
        ),
        password: None,
        password_stdin: None,
    };

    let output = execute_for_runtime(
        Cli::try_parse_from(["sshw", "remove", "server-alpha"]).unwrap(),
        &path,
        &store,
        &ssh,
        &mut prompter,
    );

    assert_eq!(output.exit_code, 3);
    assert_eq!(output.stdout, "");
    assert!(output.stderr.contains("interactive terminal"));
}

#[test]
fn trust_passes_displayed_fingerprint_to_storage() {
    let temp = tempfile::tempdir().unwrap();
    let path = temp.path().join("servers.json");
    save_config(&path, &sample_config(&path)).unwrap();
    let store = FakeCredentialStore::default();
    let ssh = FakeSshClient {
        host_key_fingerprint: "SHA256:displayed".to_string(),
        ..FakeSshClient::default()
    };
    let mut prompter = FakePrompter {
        confirm: true,
        confirm_error: None,
        password: None,
        password_stdin: None,
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
    save_config(&path, &sample_config(&path)).unwrap();
    let local = temp.path().join("existing.txt");
    std::fs::write(&local, "keep").unwrap();
    let store = FakeCredentialStore::default();
    store
        .set_password(
            &login_credential(&path, "server-alpha"),
            "deploy",
            "YOUR_PASSWORD",
        )
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
    save_config(&path, &sample_config(&path)).unwrap();
    let local = temp.path().join("existing.txt");
    std::fs::write(&local, "keep").unwrap();
    let store = FakeCredentialStore::default();
    store
        .set_password(
            &login_credential(&path, "server-alpha"),
            "deploy",
            "YOUR_PASSWORD",
        )
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
fn dynamic_local_path_text_cannot_change_io_error_kind() {
    let temp = tempfile::tempdir().unwrap();
    let path = temp.path().join("servers.json");
    save_config(&path, &sample_config(&path)).unwrap();
    let local = temp.path().join("requires --yes.txt");
    std::fs::write(&local, "keep").unwrap();

    let output = execute_for_runtime(
        Cli::try_parse_from([
            "sshw",
            "get",
            "server-alpha",
            "/tmp/remote.txt",
            local.to_str().unwrap(),
            "--json",
        ])
        .unwrap(),
        &path,
        &FakeCredentialStore::default(),
        &FakeSshClient::default(),
        &mut FakePrompter::default(),
    );

    let json: serde_json::Value = serde_json::from_str(output.stdout.trim()).unwrap();
    assert_eq!(output.exit_code, 6);
    assert_eq!(json["error"]["kind"], "io");
}

#[test]
fn get_existing_local_file_with_yes_allows_overwrite() {
    let temp = tempfile::tempdir().unwrap();
    let path = temp.path().join("servers.json");
    save_config(&path, &sample_config(&path)).unwrap();
    let local = temp.path().join("existing.txt");
    std::fs::write(&local, "replace").unwrap();
    let store = FakeCredentialStore::default();
    store
        .set_password(
            &login_credential(&path, "server-alpha"),
            "deploy",
            "YOUR_PASSWORD",
        )
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
    save_config(&path, &sample_config(&path)).unwrap();
    let store = FakeCredentialStore::default();
    store
        .set_password(
            &login_credential(&path, "server-alpha"),
            "deploy",
            "YOUR_PASSWORD",
        )
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
        [(
            login_credential(&path, "server-alpha"),
            "deploy".to_string()
        )]
    );
}

#[test]
fn add_update_removes_stale_privilege_metadata_and_password() {
    let temp = tempfile::tempdir().unwrap();
    let path = temp.path().join("servers.json");
    let namespace = ResolvedHome::from_config_path(&path).namespace;
    let ops_login = namespace.credential_key_v3(
        CredentialPurpose::Login,
        "server-alpha",
        "ops",
        "0000000000000001",
    );
    let ops_privilege = namespace.credential_key_v3(
        CredentialPurpose::Privilege,
        "server-alpha",
        "ops",
        "0000000000000002",
    );
    let mut config = sample_config(&path);
    set_default_privilege(
        &mut config,
        "server-alpha",
        PrivilegeConfig {
            method: PrivilegeMethod::Sudo,
            user: "root".to_string(),
            credential: privilege_credential(&path, "server-alpha"),
        },
    );
    config
        .servers
        .get_mut("server-alpha")
        .unwrap()
        .accounts
        .insert(
            "ops".to_string(),
            AccountConfig {
                auth: AuthConfig::Password {
                    credential: ops_login.clone(),
                },
                privilege: Some(PrivilegeConfig {
                    method: PrivilegeMethod::Sudo,
                    user: "admin".to_string(),
                    credential: ops_privilege.clone(),
                }),
            },
        );
    save_config(&path, &config).unwrap();
    let store = FakeCredentialStore::default();
    store
        .set_password(
            &login_credential(&path, "server-alpha"),
            "deploy",
            "YOUR_PASSWORD",
        )
        .unwrap();
    store
        .set_password(&ops_login, "ops", "OPS_PASSWORD")
        .unwrap();
    store
        .set_password(&ops_privilege, "admin", "OPS_ROOT_PASSWORD")
        .unwrap();
    store
        .set_password(
            &privilege_credential(&path, "server-alpha"),
            "root",
            "OLD_ROOT_PASSWORD",
        )
        .unwrap();
    let ssh = FakeSshClient::default();
    let mut prompter = FakePrompter::default();

    execute(
        Cli::try_parse_from([
            "sshw",
            "add",
            "server-alpha",
            "--host",
            "192.0.2.20",
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

    let config = load_config(&path).unwrap();
    assert!(default_privilege(&config, "server-alpha").is_none());
    let deleted = store.deleted.borrow();
    assert!(deleted.contains(&(
        login_credential(&path, "server-alpha"),
        "deploy".to_string()
    )));
    assert!(deleted.contains(&(
        privilege_credential(&path, "server-alpha"),
        "root".to_string()
    )));
    assert!(deleted.contains(&(ops_login, "ops".to_string())));
    assert!(deleted.contains(&(ops_privilege, "admin".to_string())));
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
        confirm_error: None,
        password: Some(String::new()),
        password_stdin: None,
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
fn add_password_stdin_stores_namespaced_credential_key() {
    let temp = tempfile::tempdir().unwrap();
    let path = temp.path().join("servers.json");
    save_config(&path, &SshwConfig::default()).unwrap();
    let store = FakeCredentialStore::default();
    let ssh = FakeSshClient::default();
    let mut prompter = FakePrompter {
        confirm: false,
        confirm_error: None,
        password: Some("PROMPT_PASSWORD".to_string()),
        password_stdin: Some("STDIN_PASSWORD".to_string()),
    };

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
            "--password-stdin",
        ])
        .unwrap(),
        &path,
        &store,
        &ssh,
        &mut prompter,
    )
    .unwrap();

    let values = store.values.borrow();
    assert_eq!(values.len(), 1);
    let ((credential, user), password) = values.iter().next().unwrap();
    assert_eq!(user, "deploy");
    assert_eq!(password, "STDIN_PASSWORD");
    let namespace = &ResolvedHome::from_config_path(&path).namespace;
    assert!(namespace.account_credential_key_matches(
        CredentialPurpose::Login,
        "server-alpha",
        "deploy",
        credential,
    ));
    assert_ne!(credential, &namespace.legacy_credential_key("server-alpha"));
}

#[test]
fn add_password_stdin_rejects_agent_auth() {
    let temp = tempfile::tempdir().unwrap();
    let path = temp.path().join("servers.json");
    save_config(&path, &SshwConfig::default()).unwrap();
    let store = FakeCredentialStore::default();
    let ssh = FakeSshClient::default();
    let mut prompter = FakePrompter {
        confirm: false,
        confirm_error: None,
        password: None,
        password_stdin: Some("STDIN_PASSWORD".to_string()),
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
            "--auth",
            "agent",
            "--password-stdin",
        ])
        .unwrap(),
        &path,
        &store,
        &ssh,
        &mut prompter,
    )
    .unwrap_err();

    assert!(err.to_string().contains("--password-stdin"));
    assert!(err.to_string().contains("--auth agent"));
    assert!(store.values.borrow().is_empty());
}

#[test]
fn privilege_set_stores_root_password_outside_config() {
    let temp = tempfile::tempdir().unwrap();
    let path = temp.path().join("servers.json");
    save_config(&path, &sample_config(&path)).unwrap();
    let store = FakeCredentialStore::default();
    let ssh = FakeSshClient::default();
    let mut prompter = FakePrompter {
        confirm: false,
        confirm_error: None,
        password: Some("PROMPT_ROOT_PASSWORD".to_string()),
        password_stdin: Some("ROOT_PASSWORD".to_string()),
    };

    let output = execute(
        Cli::try_parse_from([
            "sshw",
            "privilege",
            "set",
            "server-alpha",
            "--method",
            "sudo",
            "--password-stdin",
        ])
        .unwrap(),
        &path,
        &store,
        &ssh,
        &mut prompter,
    )
    .unwrap();

    assert!(output.stdout.contains("privilege set for server-alpha"));
    let config = load_config(&path).unwrap();
    let privilege = default_privilege(&config, "server-alpha").unwrap();
    assert_eq!(privilege.method, PrivilegeMethod::Sudo);
    assert_eq!(privilege.user, "root");
    let namespace = &ResolvedHome::from_config_path(&path).namespace;
    assert!(namespace.account_credential_key_matches(
        CredentialPurpose::Privilege,
        "server-alpha",
        "deploy",
        &privilege.credential
    ));
    assert_ne!(
        privilege.credential,
        namespace.legacy_privilege_credential_key("server-alpha")
    );

    let stored = store
        .values
        .borrow()
        .get(&(privilege.credential.clone(), "root".to_string()))
        .cloned()
        .unwrap();
    assert_eq!(stored, "ROOT_PASSWORD");
    let config_text = std::fs::read_to_string(&path).unwrap();
    assert!(!config_text.contains("ROOT_PASSWORD"));
    assert!(!config_text.contains("PROMPT_ROOT_PASSWORD"));
}

#[test]
fn privilege_set_rejects_newline_or_cr_passwords() {
    for password in ["ROOT_PASSWORD\nEXTRA", "ROOT_PASSWORD\rEXTRA"] {
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("servers.json");
        save_config(&path, &sample_config(&path)).unwrap();
        let store = FakeCredentialStore::default();
        let ssh = FakeSshClient::default();
        let mut prompter = FakePrompter {
            confirm: false,
            confirm_error: None,
            password: None,
            password_stdin: Some(password.to_string()),
        };

        let err = execute(
            Cli::try_parse_from([
                "sshw",
                "privilege",
                "set",
                "server-alpha",
                "--method",
                "sudo",
                "--password-stdin",
            ])
            .unwrap(),
            &path,
            &store,
            &ssh,
            &mut prompter,
        )
        .unwrap_err();

        assert!(err.to_string().contains("single line"));
        assert!(store.values.borrow().is_empty());
        assert!(privileges_are_empty(&load_config(&path).unwrap()));
    }
}

#[test]
fn privilege_show_redacts_secret_material() {
    let temp = tempfile::tempdir().unwrap();
    let path = temp.path().join("servers.json");
    let mut config = sample_config(&path);
    set_default_privilege(
        &mut config,
        "server-alpha",
        PrivilegeConfig {
            method: PrivilegeMethod::Sudo,
            user: "root".to_string(),
            credential: privilege_credential(&path, "server-alpha"),
        },
    );
    save_config(&path, &config).unwrap();
    let store = FakeCredentialStore::default();
    store
        .set_password(
            &privilege_credential(&path, "server-alpha"),
            "root",
            "ROOT_PASSWORD",
        )
        .unwrap();
    let ssh = FakeSshClient::default();
    let mut prompter = FakePrompter::default();

    let output = execute(
        Cli::try_parse_from(["sshw", "privilege", "show", "server-alpha"]).unwrap(),
        &path,
        &store,
        &ssh,
        &mut prompter,
    )
    .unwrap();

    assert!(output.stdout.contains("method: sudo"));
    assert!(output.stdout.contains("user: root"));
    assert!(output.stdout.contains(&format!(
        "credential: {}",
        privilege_credential(&path, "server-alpha")
    )));
    assert!(!output.stdout.contains("ROOT_PASSWORD"));
}

#[test]
fn privilege_show_json_success_includes_ok_true() {
    let temp = tempfile::tempdir().unwrap();
    let path = temp.path().join("servers.json");
    let mut config = sample_config(&path);
    set_default_privilege(
        &mut config,
        "server-alpha",
        PrivilegeConfig {
            method: PrivilegeMethod::Sudo,
            user: "root".to_string(),
            credential: privilege_credential(&path, "server-alpha"),
        },
    );
    save_config(&path, &config).unwrap();
    let store = FakeCredentialStore::default();
    let ssh = FakeSshClient::default();
    let mut prompter = FakePrompter::default();

    let output = execute(
        Cli::try_parse_from(["sshw", "privilege", "show", "server-alpha", "--json"]).unwrap(),
        &path,
        &store,
        &ssh,
        &mut prompter,
    )
    .unwrap();

    let json: serde_json::Value = serde_json::from_str(output.stdout.trim()).unwrap();
    assert_eq!(json["ok"], true);
    assert_eq!(json["server"], "server-alpha");
    assert_eq!(json["method"], "sudo");
    assert_eq!(json["user"], "root");
}

#[test]
fn privilege_clear_removes_metadata_and_stored_password() {
    let temp = tempfile::tempdir().unwrap();
    let path = temp.path().join("servers.json");
    let mut config = sample_config(&path);
    set_default_privilege(
        &mut config,
        "server-alpha",
        PrivilegeConfig {
            method: PrivilegeMethod::Sudo,
            user: "root".to_string(),
            credential: privilege_credential(&path, "server-alpha"),
        },
    );
    save_config(&path, &config).unwrap();
    let store = FakeCredentialStore::default();
    let ssh = FakeSshClient::default();
    let mut prompter = FakePrompter::default();

    let output = execute(
        Cli::try_parse_from(["sshw", "privilege", "clear", "server-alpha", "--yes"]).unwrap(),
        &path,
        &store,
        &ssh,
        &mut prompter,
    )
    .unwrap();

    assert!(output.stdout.contains("privilege cleared for server-alpha"));
    let config = load_config(&path).unwrap();
    assert!(default_privilege(&config, "server-alpha").is_none());
    assert_eq!(
        store.deleted.borrow().as_slice(),
        [(
            privilege_credential(&path, "server-alpha"),
            "root".to_string()
        )]
    );
}

#[test]
fn privilege_clear_removes_metadata_when_password_delete_fails() {
    let temp = tempfile::tempdir().unwrap();
    let path = temp.path().join("servers.json");
    let mut config = sample_config(&path);
    set_default_privilege(
        &mut config,
        "server-alpha",
        PrivilegeConfig {
            method: PrivilegeMethod::Sudo,
            user: "root".to_string(),
            credential: privilege_credential(&path, "server-alpha"),
        },
    );
    save_config(&path, &config).unwrap();
    let store = FakeCredentialStore {
        delete_error: Some("keyring delete failed".to_string()),
        ..FakeCredentialStore::default()
    };
    let ssh = FakeSshClient::default();
    let mut prompter = FakePrompter::default();

    let err = execute(
        Cli::try_parse_from(["sshw", "privilege", "clear", "server-alpha", "--yes"]).unwrap(),
        &path,
        &store,
        &ssh,
        &mut prompter,
    )
    .unwrap_err();

    assert!(err.to_string().contains("keyring delete failed"));
    assert!(default_privilege(&load_config(&path).unwrap(), "server-alpha").is_none());
}

#[test]
fn privilege_set_update_deletes_previous_user_credential() {
    let temp = tempfile::tempdir().unwrap();
    let path = temp.path().join("servers.json");
    let mut config = sample_config(&path);
    set_default_privilege(
        &mut config,
        "server-alpha",
        PrivilegeConfig {
            method: PrivilegeMethod::Sudo,
            user: "root".to_string(),
            credential: privilege_credential(&path, "server-alpha"),
        },
    );
    save_config(&path, &config).unwrap();
    let store = FakeCredentialStore::default();
    store
        .set_password(
            &privilege_credential(&path, "server-alpha"),
            "root",
            "OLD_ROOT_PASSWORD",
        )
        .unwrap();
    let ssh = FakeSshClient::default();
    let mut prompter = FakePrompter {
        confirm: false,
        confirm_error: None,
        password: None,
        password_stdin: Some("NEW_ADMIN_PASSWORD".to_string()),
    };

    let output = execute(
        Cli::try_parse_from([
            "sshw",
            "privilege",
            "set",
            "server-alpha",
            "--method",
            "sudo",
            "--user",
            "admin",
            "--password-stdin",
            "--force",
        ])
        .unwrap(),
        &path,
        &store,
        &ssh,
        &mut prompter,
    )
    .unwrap();

    assert!(output.stdout.contains("privilege set for server-alpha"));
    let config = load_config(&path).unwrap();
    let privilege = default_privilege(&config, "server-alpha").unwrap();
    assert_eq!(privilege.user, "admin");
    assert_eq!(
        store.deleted.borrow().as_slice(),
        [(
            privilege_credential(&path, "server-alpha"),
            "root".to_string()
        )]
    );
    assert!(
        store
            .values
            .borrow()
            .contains_key(&(privilege.credential.clone(), "admin".to_string()))
    );
}

#[test]
fn privilege_set_update_surfaces_previous_credential_delete_failure() {
    // set-update stores the new credential and config first, then deletes the
    // previous user's credential. If that cleanup delete fails it is surfaced as
    // an error (not swallowed): the new credential and config are already in
    // place, and the previous credential remains as an orphan in the backend.
    // Pin that behavior so a future change cannot silently drop the failure.
    let temp = tempfile::tempdir().unwrap();
    let path = temp.path().join("servers.json");
    let mut config = sample_config(&path);
    set_default_privilege(
        &mut config,
        "server-alpha",
        PrivilegeConfig {
            method: PrivilegeMethod::Sudo,
            user: "root".to_string(),
            credential: privilege_credential(&path, "server-alpha"),
        },
    );
    save_config(&path, &config).unwrap();
    let store = FakeCredentialStore {
        delete_error: Some("keyring delete failed".to_string()),
        ..FakeCredentialStore::default()
    };
    store
        .set_password(
            &privilege_credential(&path, "server-alpha"),
            "root",
            "OLD_ROOT_PASSWORD",
        )
        .unwrap();
    let ssh = FakeSshClient::default();
    let mut prompter = FakePrompter {
        confirm: false,
        confirm_error: None,
        password: None,
        password_stdin: Some("NEW_ADMIN_PASSWORD".to_string()),
    };

    let err = execute(
        Cli::try_parse_from([
            "sshw",
            "privilege",
            "set",
            "server-alpha",
            "--method",
            "sudo",
            "--user",
            "admin",
            "--password-stdin",
            "--force",
        ])
        .unwrap(),
        &path,
        &store,
        &ssh,
        &mut prompter,
    )
    .unwrap_err();

    // The cleanup failure is surfaced, not swallowed.
    assert!(err.to_string().contains("keyring delete failed"));
    // The new credential and updated config were committed before cleanup ran.
    let config = load_config(&path).unwrap();
    let privilege = default_privilege(&config, "server-alpha").unwrap();
    assert_eq!(privilege.user, "admin");
    assert!(
        store
            .values
            .borrow()
            .contains_key(&(privilege.credential.clone(), "admin".to_string()))
    );
    // The previous user's credential remains an orphan because delete failed.
    assert!(store.values.borrow().contains_key(&(
        privilege_credential(&path, "server-alpha"),
        "root".to_string()
    )));
}

#[test]
fn put_to_system_path_requires_yes_before_ssh() {
    let temp = tempfile::tempdir().unwrap();
    let path = temp.path().join("servers.json");
    save_config(&path, &sample_config(&path)).unwrap();
    let local = temp.path().join("app");
    std::fs::write(&local, "binary").unwrap();
    let store = FakeCredentialStore::default();
    store
        .set_password(
            &login_credential(&path, "server-alpha"),
            "deploy",
            "YOUR_PASSWORD",
        )
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
    save_config(&path, &sample_config(&path)).unwrap();
    let local = temp.path().join("app");
    std::fs::write(&local, "binary").unwrap();
    let store = FakeCredentialStore::default();
    store
        .set_password(
            &login_credential(&path, "server-alpha"),
            "deploy",
            "YOUR_PASSWORD",
        )
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
    save_config(&path, &sample_config(&path)).unwrap();
    let store = FakeCredentialStore::default();
    store
        .set_password(
            &login_credential(&path, "server-alpha"),
            "deploy",
            "YOUR_PASSWORD",
        )
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
    save_config(&path, &sample_config(&path)).unwrap();
    let store = FakeCredentialStore::default();
    store
        .set_password(
            &login_credential(&path, "server-alpha"),
            "deploy",
            "YOUR_PASSWORD",
        )
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
    save_config(&path, &sample_config(&path)).unwrap();
    let store = FakeCredentialStore::default();
    store
        .set_password(
            &login_credential(&path, "server-alpha"),
            "deploy",
            "YOUR_PASSWORD",
        )
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
    let mut config = sample_config(&path);
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
    assert!(err.to_string().contains("sshw default <name>"));
    assert!(ssh.run_commands.borrow().is_empty());
}

#[test]
fn run_as_root_without_privilege_config_fails_closed() {
    let temp = tempfile::tempdir().unwrap();
    let path = temp.path().join("servers.json");
    save_config(&path, &sample_config(&path)).unwrap();
    let store = FakeCredentialStore::default();
    store
        .set_password(
            &login_credential(&path, "server-alpha"),
            "deploy",
            "YOUR_PASSWORD",
        )
        .unwrap();
    let ssh = FakeSshClient::default();
    let mut prompter = FakePrompter::default();

    let err = execute(
        Cli::try_parse_from(["sshw", "run", "server-alpha", "id -u", "--as-root", "--yes"])
            .unwrap(),
        &path,
        &store,
        &ssh,
        &mut prompter,
    )
    .unwrap_err();

    assert!(err.to_string().contains("privilege configuration"));
    assert!(err.to_string().contains("sshw privilege set"));
    assert!(ssh.run_commands.borrow().is_empty());
}

#[test]
fn run_as_root_requires_yes_before_ssh() {
    let temp = tempfile::tempdir().unwrap();
    let path = temp.path().join("servers.json");
    save_config(&path, &sample_config(&path)).unwrap();
    let store = FakeCredentialStore::default();
    store
        .set_password(
            &login_credential(&path, "server-alpha"),
            "deploy",
            "YOUR_PASSWORD",
        )
        .unwrap();
    let ssh = FakeSshClient::default();
    let mut prompter = FakePrompter::default();

    let err = execute(
        Cli::try_parse_from(["sshw", "run", "server-alpha", "id -u", "--as-root"]).unwrap(),
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
fn run_as_root_uses_sudo_stdin_and_redacts_privilege_secret() {
    let temp = tempfile::tempdir().unwrap();
    let path = temp.path().join("servers.json");
    let mut config = sample_config(&path);
    set_default_privilege(
        &mut config,
        "server-alpha",
        PrivilegeConfig {
            method: PrivilegeMethod::Sudo,
            user: "root".to_string(),
            credential: privilege_credential(&path, "server-alpha"),
        },
    );
    save_config(&path, &config).unwrap();
    let store = FakeCredentialStore::default();
    store
        .set_password(
            &login_credential(&path, "server-alpha"),
            "deploy",
            "YOUR_PASSWORD",
        )
        .unwrap();
    store
        .set_password(
            &privilege_credential(&path, "server-alpha"),
            "root",
            "ROOT_PASSWORD",
        )
        .unwrap();
    let ssh = FakeSshClient::with_stdout("ROOT_PASSWORD\nok\n");
    let mut prompter = FakePrompter::default();

    let output = execute(
        Cli::try_parse_from(["sshw", "run", "server-alpha", "id -u", "--as-root", "--yes"])
            .unwrap(),
        &path,
        &store,
        &ssh,
        &mut prompter,
    )
    .unwrap();

    assert_eq!(output.stdout, "<redacted>\nok\n");
    assert!(!output.stdout.contains("ROOT_PASSWORD"));
    let commands = ssh.run_commands.borrow();
    assert_eq!(commands.len(), 1);
    assert!(commands[0].starts_with("sh -c "));
    assert!(commands[0].contains("IFS= read -r sshw_sudo_password"));
    assert!(commands[0].contains("sudo -S"));
    assert!(commands[0].contains("-v"));
    assert!(commands[0].contains("sudo -n"));
    assert!(commands[0].contains("sh -lc"));
    assert!(commands[0].contains("id -u"));
    assert!(commands[0].contains("root"));
    assert!(commands[0].contains("< /dev/null"));
    assert!(!commands[0].contains("ROOT_PASSWORD"));
    assert_eq!(
        ssh.run_stdin.borrow().as_slice(),
        [Some("ROOT_PASSWORD\n".to_string())]
    );
}

#[test]
fn session_passwords_are_selected_by_typed_login_and_privilege_purpose() {
    let temp = tempfile::tempdir().unwrap();
    let path = temp.path().join("servers.json");
    let mut config = sample_config(&path);
    set_default_privilege(
        &mut config,
        "server-alpha",
        PrivilegeConfig {
            method: PrivilegeMethod::Sudo,
            user: "root".to_string(),
            credential: privilege_credential(&path, "server-alpha"),
        },
    );
    save_config(&path, &config).unwrap();
    let store = SessionOnlyStore::with_session_passwords(
        Some("LOGIN_PASSWORD".to_string()),
        Some("ROOT_PASSWORD".to_string()),
    );
    let ssh = FakeSshClient::default();

    execute(
        Cli::try_parse_from(["sshw", "run", "server-alpha", "id -u", "--as-root", "--yes"])
            .unwrap(),
        &path,
        &store,
        &ssh,
        &mut FakePrompter::default(),
    )
    .unwrap();

    assert_eq!(
        ssh.run_stdin.borrow().as_slice(),
        [Some("ROOT_PASSWORD\n".to_string())]
    );
}

#[test]
fn run_as_root_rejects_stored_multiline_privilege_password_before_ssh() {
    let temp = tempfile::tempdir().unwrap();
    let path = temp.path().join("servers.json");
    let mut config = sample_config(&path);
    set_default_privilege(
        &mut config,
        "server-alpha",
        PrivilegeConfig {
            method: PrivilegeMethod::Sudo,
            user: "root".to_string(),
            credential: privilege_credential(&path, "server-alpha"),
        },
    );
    save_config(&path, &config).unwrap();
    let store = FakeCredentialStore::default();
    store
        .set_password(
            &login_credential(&path, "server-alpha"),
            "deploy",
            "YOUR_PASSWORD",
        )
        .unwrap();
    store
        .set_password(
            &privilege_credential(&path, "server-alpha"),
            "root",
            "ROOT_PASSWORD\nEXTRA",
        )
        .unwrap();
    let ssh = FakeSshClient::default();
    let mut prompter = FakePrompter::default();

    let err = execute(
        Cli::try_parse_from(["sshw", "run", "server-alpha", "id -u", "--as-root", "--yes"])
            .unwrap(),
        &path,
        &store,
        &ssh,
        &mut prompter,
    )
    .unwrap_err();

    assert!(err.to_string().contains("single line"));
    assert!(ssh.run_commands.borrow().is_empty());
}

#[test]
fn run_as_root_su_injects_password_over_pty_without_leaking_it() {
    let temp = tempfile::tempdir().unwrap();
    let path = temp.path().join("servers.json");
    let mut config = sample_config(&path);
    set_default_privilege(
        &mut config,
        "server-alpha",
        PrivilegeConfig {
            method: PrivilegeMethod::Su,
            user: "root".to_string(),
            credential: privilege_credential(&path, "server-alpha"),
        },
    );
    save_config(&path, &config).unwrap();
    let store = FakeCredentialStore::default();
    store
        .set_password(
            &login_credential(&path, "server-alpha"),
            "deploy",
            "YOUR_PASSWORD",
        )
        .unwrap();
    store
        .set_password(
            &privilege_credential(&path, "server-alpha"),
            "root",
            "ROOT_SU_PASSWORD",
        )
        .unwrap();
    let ssh = FakeSshClient::with_stdout("0\n");
    let mut prompter = FakePrompter::default();

    let output = execute(
        Cli::try_parse_from(["sshw", "run", "server-alpha", "id -u", "--as-root", "--yes"])
            .unwrap(),
        &path,
        &store,
        &ssh,
        &mut prompter,
    )
    .unwrap();

    let commands = ssh.run_commands.borrow();
    assert_eq!(commands.len(), 1);
    // su reads its password from the PTY (no -S/stdin trick); the command is
    // wrapped in BEGIN/END output markers so the backend extracts the command
    // output and exit code without prompt-line heuristics.
    assert!(
        commands[0].contains("LC_ALL=C su - 'root' -c"),
        "got: {}",
        commands[0]
    );
    // The output framing markers embed the per-execution nonce that is also
    // handed to the backend, so a command's own stdout cannot forge the END
    // marker and spoof the exit code.
    let nonces = ssh.run_pty_nonces.borrow();
    assert_eq!(nonces.len(), 1);
    let nonce = &nonces[0];
    assert!(!nonce.is_empty(), "a marker nonce should be generated");
    assert!(
        commands[0].contains(&format!("__SSHW_BEGIN_{nonce}__")),
        "got: {}",
        commands[0]
    );
    assert!(
        commands[0].contains(&format!("__SSHW_END_{nonce}_")),
        "got: {}",
        commands[0]
    );
    // The password must never appear in the command string.
    assert!(!commands[0].contains("ROOT_SU_PASSWORD"));
    // It is delivered via the dedicated PTY-password path instead.
    assert_eq!(
        ssh.run_pty_passwords.borrow().as_slice(),
        ["ROOT_SU_PASSWORD".to_string()]
    );
    assert_eq!(output.exit_code, 0);
}

#[test]
fn json_run_without_name_reports_default_hint() {
    let temp = tempfile::tempdir().unwrap();
    let path = temp.path().join("servers.json");
    let mut config = sample_config(&path);
    config.default = None;
    save_config(&path, &config).unwrap();
    let store = FakeCredentialStore::default();
    let ssh = FakeSshClient::default();
    let mut prompter = FakePrompter::default();

    let output = execute_for_runtime(
        Cli::try_parse_from(["sshw", "run", "hostname", "--json"]).unwrap(),
        &path,
        &store,
        &ssh,
        &mut prompter,
    );

    assert_eq!(output.exit_code, 3);
    assert_eq!(output.stderr, "");
    let json: serde_json::Value = serde_json::from_str(output.stdout.trim()).unwrap();
    assert_eq!(json["error"]["kind"], "config");
    assert!(
        json["error"]["message"]
            .as_str()
            .unwrap()
            .contains("sshw default <name>")
    );
    assert!(ssh.run_commands.borrow().is_empty());
}

#[test]
fn put_uses_default_server_when_name_is_omitted() {
    let temp = tempfile::tempdir().unwrap();
    let path = temp.path().join("servers.json");
    save_config(&path, &sample_config(&path)).unwrap();
    let local = temp.path().join("app");
    std::fs::write(&local, "binary").unwrap();
    let store = FakeCredentialStore::default();
    store
        .set_password(
            &login_credential(&path, "server-alpha"),
            "deploy",
            "YOUR_PASSWORD",
        )
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
fn put_json_reports_transfer_result() {
    let temp = tempfile::tempdir().unwrap();
    let path = temp.path().join("servers.json");
    save_config(&path, &sample_config(&path)).unwrap();
    let local = temp.path().join("app");
    std::fs::write(&local, "binary").unwrap();
    let store = FakeCredentialStore::default();
    store
        .set_password(
            &login_credential(&path, "server-alpha"),
            "deploy",
            "YOUR_PASSWORD",
        )
        .unwrap();
    let ssh = FakeSshClient::default();
    let mut prompter = FakePrompter::default();

    let output = execute(
        Cli::try_parse_from([
            "sshw",
            "put",
            "server-alpha",
            local.to_str().unwrap(),
            "/tmp/app",
            "--json",
        ])
        .unwrap(),
        &path,
        &store,
        &ssh,
        &mut prompter,
    )
    .unwrap();

    assert_eq!(output.stderr, "");
    let json: serde_json::Value = serde_json::from_str(output.stdout.trim()).unwrap();
    assert_eq!(json["ok"], true);
    assert_eq!(json["server"], "server-alpha");
    assert_eq!(json["local"], local.display().to_string());
    assert_eq!(json["remote"], "/tmp/app");
    assert_eq!(json["bytes"], 1);
}

#[test]
fn put_json_failure_uses_error_envelope() {
    let temp = tempfile::tempdir().unwrap();
    let path = temp.path().join("servers.json");
    save_config(&path, &sample_config(&path)).unwrap();
    let local = temp.path().join("app");
    std::fs::write(&local, "binary").unwrap();
    let store = FakeCredentialStore::default();
    let ssh = FakeSshClient::default();
    let mut prompter = FakePrompter::default();

    let output = execute_for_runtime(
        Cli::try_parse_from([
            "sshw",
            "put",
            local.to_str().unwrap(),
            "/usr/bin/app",
            "--json",
        ])
        .unwrap(),
        &path,
        &store,
        &ssh,
        &mut prompter,
    );

    assert_eq!(output.exit_code, 2);
    assert_eq!(output.stderr, "");
    let json: serde_json::Value = serde_json::from_str(output.stdout.trim()).unwrap();
    assert_eq!(json["ok"], false);
    assert_eq!(json["error"]["kind"], "safety");
    assert_eq!(json["error"]["exit_code"], 2);
    assert!(ssh.put_calls.borrow().is_empty());
}

#[test]
fn get_uses_default_server_when_name_is_omitted() {
    let temp = tempfile::tempdir().unwrap();
    let path = temp.path().join("servers.json");
    save_config(&path, &sample_config(&path)).unwrap();
    let local = temp.path().join("download.txt");
    let store = FakeCredentialStore::default();
    store
        .set_password(
            &login_credential(&path, "server-alpha"),
            "deploy",
            "YOUR_PASSWORD",
        )
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
fn get_json_reports_transfer_result() {
    let temp = tempfile::tempdir().unwrap();
    let path = temp.path().join("servers.json");
    save_config(&path, &sample_config(&path)).unwrap();
    let local = temp.path().join("download.txt");
    let store = FakeCredentialStore::default();
    store
        .set_password(
            &login_credential(&path, "server-alpha"),
            "deploy",
            "YOUR_PASSWORD",
        )
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
            "--json",
        ])
        .unwrap(),
        &path,
        &store,
        &ssh,
        &mut prompter,
    )
    .unwrap();

    assert_eq!(output.stderr, "");
    let json: serde_json::Value = serde_json::from_str(output.stdout.trim()).unwrap();
    assert_eq!(json["ok"], true);
    assert_eq!(json["server"], "server-alpha");
    assert_eq!(json["remote"], "/tmp/remote.txt");
    assert_eq!(json["local"], local.display().to_string());
    assert_eq!(json["bytes"], 1);
}

#[test]
fn remote_absolute_literal_is_decoded_for_put_and_get() {
    let temp = tempfile::tempdir().unwrap();
    let path = temp.path().join("servers.json");
    save_config(&path, &sample_config(&path)).unwrap();
    let upload = temp.path().join("upload.bin");
    let download = temp.path().join("download.bin");
    std::fs::write(&upload, "binary").unwrap();
    let store = FakeCredentialStore::default();
    store
        .set_password(
            &login_credential(&path, "server-alpha"),
            "deploy",
            "YOUR_PASSWORD",
        )
        .unwrap();
    let ssh = FakeSshClient::default();

    let put = execute(
        Cli::try_parse_from([
            "sshw",
            "put",
            "server-alpha",
            upload.to_str().unwrap(),
            "remote:/tmp/upload.bin",
            "--json",
        ])
        .unwrap(),
        &path,
        &store,
        &ssh,
        &mut FakePrompter::default(),
    )
    .unwrap();
    let put_json: serde_json::Value = serde_json::from_str(put.stdout.trim()).unwrap();
    assert_eq!(put_json["remote"], "/tmp/upload.bin");
    assert_eq!(ssh.put_calls.borrow().as_slice(), ["/tmp/upload.bin"]);

    let get = execute(
        Cli::try_parse_from([
            "sshw",
            "get",
            "server-alpha",
            "remote:/var/log/app.log",
            download.to_str().unwrap(),
            "--json",
        ])
        .unwrap(),
        &path,
        &store,
        &ssh,
        &mut FakePrompter::default(),
    )
    .unwrap();
    let get_json: serde_json::Value = serde_json::from_str(get.stdout.trim()).unwrap();
    assert_eq!(get_json["remote"], "/var/log/app.log");
    assert_eq!(
        ssh.get_remote_calls.borrow().as_slice(),
        ["/var/log/app.log"]
    );
}

#[test]
fn remote_absolute_literal_rejects_empty_and_relative_paths_before_ssh() {
    let temp = tempfile::tempdir().unwrap();
    let path = temp.path().join("servers.json");
    save_config(&path, &sample_config(&path)).unwrap();
    let upload = temp.path().join("upload.bin");
    std::fs::write(&upload, "binary").unwrap();
    let ssh = FakeSshClient::default();

    let put = execute_for_runtime(
        Cli::try_parse_from([
            "sshw",
            "put",
            "server-alpha",
            upload.to_str().unwrap(),
            "remote:relative/file",
            "--json",
        ])
        .unwrap(),
        &path,
        &FakeCredentialStore::default(),
        &ssh,
        &mut FakePrompter::default(),
    );
    let put_json: serde_json::Value = serde_json::from_str(put.stdout.trim()).unwrap();
    assert_eq!(put.exit_code, 3);
    assert_eq!(put_json["error"]["kind"], "config");

    let get = execute_for_runtime(
        Cli::try_parse_from([
            "sshw",
            "get",
            "server-alpha",
            "remote:",
            temp.path().join("download.bin").to_str().unwrap(),
            "--json",
        ])
        .unwrap(),
        &path,
        &FakeCredentialStore::default(),
        &ssh,
        &mut FakePrompter::default(),
    );
    let get_json: serde_json::Value = serde_json::from_str(get.stdout.trim()).unwrap();
    assert_eq!(get.exit_code, 3);
    assert_eq!(get_json["error"]["kind"], "config");
    assert!(ssh.put_calls.borrow().is_empty());
    assert!(ssh.get_remote_calls.borrow().is_empty());
}

#[test]
fn remote_absolute_literal_cannot_bypass_safety_or_policy() {
    let temp = tempfile::tempdir().unwrap();
    let path = temp.path().join("servers.json");
    save_config(&path, &sample_config(&path)).unwrap();
    let upload = temp.path().join("upload.bin");
    std::fs::write(&upload, "binary").unwrap();
    let ssh = FakeSshClient::default();

    let safety = execute_for_runtime(
        Cli::try_parse_from([
            "sshw",
            "put",
            "server-alpha",
            upload.to_str().unwrap(),
            "remote:/usr/bin/app",
            "--json",
        ])
        .unwrap(),
        &path,
        &FakeCredentialStore::default(),
        &ssh,
        &mut FakePrompter::default(),
    );
    let safety_json: serde_json::Value = serde_json::from_str(safety.stdout.trim()).unwrap();
    assert_eq!(safety.exit_code, 2);
    assert_eq!(safety_json["error"]["kind"], "safety");

    write_policy(
        temp.path(),
        r#"{"enabled":true,"allow_put_paths":["/srv/app"],"allow_get_paths":["/var/log"]}"#,
    );
    let store = FakeCredentialStore::default();
    store
        .set_password(
            &login_credential(&path, "server-alpha"),
            "deploy",
            "YOUR_PASSWORD",
        )
        .unwrap();

    execute(
        Cli::try_parse_from([
            "sshw",
            "put",
            "--policy",
            "server-alpha",
            upload.to_str().unwrap(),
            "remote:/srv/app/upload.bin",
        ])
        .unwrap(),
        &path,
        &store,
        &ssh,
        &mut FakePrompter::default(),
    )
    .unwrap();
    execute(
        Cli::try_parse_from([
            "sshw",
            "get",
            "--policy",
            "server-alpha",
            "remote:/var/log/app.log",
            temp.path().join("download.bin").to_str().unwrap(),
        ])
        .unwrap(),
        &path,
        &store,
        &ssh,
        &mut FakePrompter::default(),
    )
    .unwrap();

    let traversal = execute_for_runtime(
        Cli::try_parse_from([
            "sshw",
            "put",
            "--policy",
            "--yes",
            "server-alpha",
            upload.to_str().unwrap(),
            "remote:/srv/app/../../etc/passwd",
            "--json",
        ])
        .unwrap(),
        &path,
        &store,
        &ssh,
        &mut FakePrompter::default(),
    );
    let traversal_json: serde_json::Value = serde_json::from_str(traversal.stdout.trim()).unwrap();
    assert_eq!(traversal.exit_code, 7);
    assert_eq!(traversal_json["error"]["kind"], "policy");
    assert_eq!(ssh.put_calls.borrow().as_slice(), ["/srv/app/upload.bin"]);
    assert_eq!(
        ssh.get_remote_calls.borrow().as_slice(),
        ["/var/log/app.log"]
    );
}

#[test]
fn remote_absolute_literal_audit_records_the_decoded_path() {
    let temp = tempfile::tempdir().unwrap();
    let path = temp.path().join("servers.json");
    save_config(&path, &sample_config(&path)).unwrap();
    let upload = temp.path().join("upload.bin");
    std::fs::write(&upload, "binary").unwrap();
    let store = FakeCredentialStore::default();
    store
        .set_password(
            &login_credential(&path, "server-alpha"),
            "deploy",
            "YOUR_PASSWORD",
        )
        .unwrap();
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
        Cli::try_parse_from([
            "sshw",
            "put",
            "server-alpha",
            upload.to_str().unwrap(),
            "remote:/tmp/upload.bin",
        ])
        .unwrap(),
        &ctx,
        &store,
        &FakeSshClient::default(),
        &mut FakePrompter::default(),
    )
    .unwrap();

    let error = execute_with(
        Cli::try_parse_from([
            "sshw",
            "get",
            "server-alpha",
            "remote:relative/file",
            temp.path().join("download.bin").to_str().unwrap(),
        ])
        .unwrap(),
        &ctx,
        &store,
        &FakeSshClient::default(),
        &mut FakePrompter::default(),
    )
    .unwrap_err();
    assert!(error.to_string().contains("must contain an absolute path"));

    let records: Vec<serde_json::Value> = std::fs::read_to_string(audit_path)
        .unwrap()
        .lines()
        .map(|line| serde_json::from_str(line).unwrap())
        .collect();
    assert_eq!(records.len(), 2);
    assert_eq!(records[0]["action"], "put");
    assert_eq!(records[0]["detail"], "/tmp/upload.bin");
    assert_eq!(records[0]["status"], "ok");
    assert_eq!(records[1]["action"], "get");
    assert_eq!(records[1]["detail"], "remote:relative/file");
    assert_eq!(records[1]["status"], "error");
    assert_eq!(records[1]["exit_code"], 3);
}

#[test]
fn get_json_failure_uses_error_envelope() {
    let temp = tempfile::tempdir().unwrap();
    let path = temp.path().join("servers.json");
    save_config(&path, &sample_config(&path)).unwrap();
    let local = temp.path().join("download.txt");
    std::fs::write(&local, "existing").unwrap();
    let store = FakeCredentialStore::default();
    let ssh = FakeSshClient::default();
    let mut prompter = FakePrompter::default();

    let output = execute_for_runtime(
        Cli::try_parse_from([
            "sshw",
            "get",
            "/tmp/remote.txt",
            local.to_str().unwrap(),
            "--json",
        ])
        .unwrap(),
        &path,
        &store,
        &ssh,
        &mut prompter,
    );

    assert_eq!(output.exit_code, 6);
    assert_eq!(output.stderr, "");
    let json: serde_json::Value = serde_json::from_str(output.stdout.trim()).unwrap();
    assert_eq!(json["ok"], false);
    assert_eq!(json["error"]["kind"], "io");
    assert_eq!(json["error"]["exit_code"], 6);
    assert!(ssh.get_calls.borrow().is_empty());
}

#[test]
fn default_command_prints_and_updates_default_server() {
    let temp = tempfile::tempdir().unwrap();
    let path = temp.path().join("servers.json");
    let mut config = sample_config(&path);
    config.servers.insert(
        "server-beta".to_string(),
        ServerConfig::single_account("192.0.2.11", 22, "deploy", AuthConfig::Agent),
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
    save_config(&path, &sample_config(&path)).unwrap();
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
    assert_eq!(json["ok"], true);
    assert_eq!(json["credential_backend"], "fake");
    assert_eq!(json["credential_available"], true);
    assert_eq!(
        json["missing_credentials"],
        serde_json::json!(["server-alpha/deploy"])
    );
    assert!(!output.stdout.contains("YOUR_PASSWORD"));
}

#[test]
fn doctor_json_reports_runtime_ssh_library_versions() {
    let temp = tempfile::tempdir().unwrap();
    let path = temp.path().join("servers.json");
    save_config(&path, &SshwConfig::default()).unwrap();
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
    assert!(
        json["libssh2_version"]
            .as_str()
            .is_some_and(|version| !version.is_empty())
    );
    assert!(
        json["openssl_version"]
            .as_str()
            .is_some_and(|version| !version.is_empty())
    );
}

#[test]
fn doctor_human_reports_runtime_ssh_library_versions() {
    let temp = tempfile::tempdir().unwrap();
    let path = temp.path().join("servers.json");
    save_config(&path, &SshwConfig::default()).unwrap();
    let store = FakeCredentialStore::default();
    let ssh = FakeSshClient::default();
    let mut prompter = FakePrompter::default();

    let output = execute(
        Cli::try_parse_from(["sshw", "doctor"]).unwrap(),
        &path,
        &store,
        &ssh,
        &mut prompter,
    )
    .unwrap();

    assert!(output.stdout.contains("libssh2 version: "));
    assert!(output.stdout.contains("openssl version: "));
}

#[test]
fn doctor_reports_corrupt_config_without_failing() {
    let temp = tempfile::tempdir().unwrap();
    let path = temp.path().join("servers.json");
    std::fs::write(&path, "{").unwrap();

    let output = execute(
        Cli::try_parse_from(["sshw", "doctor", "--json"]).unwrap(),
        &path,
        &FakeCredentialStore::default(),
        &FakeSshClient::default(),
        &mut FakePrompter::default(),
    )
    .expect("doctor must remain available for config recovery");

    let json: serde_json::Value = serde_json::from_str(output.stdout.trim()).unwrap();
    assert_eq!(json["ok"], true);
    assert_eq!(json["config_valid"], false);
    assert!(
        json["config_message"]
            .as_str()
            .is_some_and(|message| message.contains("failed to load config"))
    );
    assert_eq!(json["missing_credentials"], serde_json::json!([]));
}

#[test]
fn doctor_reports_invalid_profile_registry_without_failing() {
    let temp = tempfile::tempdir().unwrap();
    let path = temp.path().join("servers.json");
    save_config(&path, &SshwConfig::default()).unwrap();
    let registry = serde_json::json!({
        "version": 1,
        "default": "legacy",
        "profiles": {
            "legacy": { "id": "p_legacy", "home": "relative/home" }
        }
    });
    std::fs::write(
        temp.path().join("profiles.json"),
        serde_json::to_vec(&registry).unwrap(),
    )
    .unwrap();

    let output = execute(
        Cli::try_parse_from(["sshw", "doctor", "--json"]).unwrap(),
        &path,
        &FakeCredentialStore::default(),
        &FakeSshClient::default(),
        &mut FakePrompter::default(),
    )
    .expect("doctor must remain available for registry recovery");

    let json: serde_json::Value = serde_json::from_str(output.stdout.trim()).unwrap();
    assert_eq!(json["ok"], true);
    assert_eq!(json["registry_valid"], false);
    assert!(
        json["registry_message"]
            .as_str()
            .is_some_and(|message| message.contains("home must be absolute"))
    );
}

#[test]
fn profile_list_recovers_when_active_config_is_corrupt() {
    let temp = tempfile::tempdir().unwrap();
    let path = temp.path().join("servers.json");
    std::fs::write(&path, "{").unwrap();

    let output = execute(
        Cli::try_parse_from(["sshw", "profile", "list", "--json"]).unwrap(),
        &path,
        &FakeCredentialStore::default(),
        &FakeSshClient::default(),
        &mut FakePrompter::default(),
    )
    .expect("profile commands must not load the active server config");

    assert_eq!(output.exit_code, 0);
    assert_eq!(
        serde_json::from_str::<serde_json::Value>(output.stdout.trim()).unwrap(),
        serde_json::json!([])
    );
}

#[test]
fn home_mutation_waits_for_exclusive_lock() {
    let temp = tempfile::tempdir().unwrap();
    let path = temp.path().join("servers.json");
    save_config(&path, &SshwConfig::default()).unwrap();
    let lock = sshw::storage::acquire_exclusive_lock(&temp.path().join(".sshw.lock")).unwrap();
    let (sender, receiver) = std::sync::mpsc::channel();
    let thread_path = path.clone();

    let worker = std::thread::spawn(move || {
        let result = execute(
            Cli::try_parse_from([
                "sshw",
                "add",
                "server-alpha",
                "--host",
                "192.0.2.10",
                "--port",
                "22",
                "--user",
                "deploy",
                "--auth",
                "agent",
            ])
            .unwrap(),
            &thread_path,
            &FakeCredentialStore::default(),
            &FakeSshClient::default(),
            &mut FakePrompter::default(),
        );
        sender.send(result.map(|output| output.exit_code)).unwrap();
    });

    assert!(
        receiver
            .recv_timeout(std::time::Duration::from_millis(150))
            .is_err(),
        "mutation completed while another process held the home lock"
    );
    drop(lock);
    assert_eq!(
        receiver
            .recv_timeout(std::time::Duration::from_secs(5))
            .unwrap()
            .unwrap(),
        0
    );
    worker.join().unwrap();
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
fn parses_global_timeout_flag() {
    let cli = Cli::try_parse_from(["sshw", "--timeout", "30", "run", "uptime"]).unwrap();
    assert_eq!(cli.timeout, Some(30));

    let without = Cli::try_parse_from(["sshw", "run", "uptime"]).unwrap();
    assert_eq!(without.timeout, None);
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
        confirm_error: None,
        password: Some("secret-pw".to_string()),
        password_stdin: None,
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
    let namespace = &ResolvedHome::from_config_path(&path).namespace;
    assert!(namespace.account_credential_key_matches(
        CredentialPurpose::Login,
        "web",
        "deploy",
        credential,
    ));
    assert_ne!(credential, &namespace.legacy_credential_key("web"));
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
    assert!(
        removed
            .stdout
            .contains("re-adding creates a fresh credential namespace")
    );

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
fn legacy_relative_profile_can_only_be_removed_for_recovery() {
    let temp = tempfile::tempdir().unwrap();
    let path = temp.path().join("servers.json");
    save_config(&path, &SshwConfig::default()).unwrap();
    let registry_path = temp.path().join("profiles.json");
    let registry = serde_json::json!({
        "version": 1,
        "default": "legacy",
        "profiles": {
            "legacy": { "id": "p_legacy", "home": "relative/home" }
        }
    });
    std::fs::write(&registry_path, serde_json::to_vec(&registry).unwrap()).unwrap();

    let list_error = execute(
        Cli::try_parse_from(["sshw", "profile", "list"]).unwrap(),
        &path,
        &FakeCredentialStore::default(),
        &FakeSshClient::default(),
        &mut FakePrompter::default(),
    )
    .unwrap_err();
    assert!(list_error.to_string().contains("home must be absolute"));

    let removed = execute(
        Cli::try_parse_from(["sshw", "profile", "remove", "legacy"]).unwrap(),
        &path,
        &FakeCredentialStore::default(),
        &FakeSshClient::default(),
        &mut FakePrompter::default(),
    )
    .expect("the invalid legacy entry must be removable without resolving its home");
    assert!(removed.stdout.contains("removed profile legacy"));

    let registry = sshw::profile::load_registry(&registry_path).unwrap();
    assert!(registry.profiles.is_empty());
    assert_eq!(registry.default, None);
}

#[test]
fn profile_json_success_contracts_are_stable() {
    let temp = tempfile::tempdir().unwrap();
    let path = temp.path().join("servers.json");
    save_config(&path, &SshwConfig::default()).unwrap();
    let store = FakeCredentialStore::default();
    let ssh = FakeSshClient::default();
    let prod_home = temp.path().join("prod-home");
    let prod_home = prod_home.to_str().unwrap();

    execute(
        Cli::try_parse_from(["sshw", "profile", "add", "prod", "--home", prod_home]).unwrap(),
        &path,
        &store,
        &ssh,
        &mut FakePrompter::default(),
    )
    .unwrap();

    let listed = execute(
        Cli::try_parse_from(["sshw", "profile", "list", "--json"]).unwrap(),
        &path,
        &store,
        &ssh,
        &mut FakePrompter::default(),
    )
    .unwrap();
    let entries: serde_json::Value = serde_json::from_str(listed.stdout.trim()).unwrap();
    let entries = entries.as_array().expect("profile list stays a bare array");
    assert_eq!(entries.len(), 1);
    assert_eq!(entries[0]["name"], "prod");
    assert_eq!(entries[0]["is_default"], true);
    assert!(
        entries[0].get("ok").is_none(),
        "profile list is intentionally not wrapped"
    );

    let shown = execute(
        Cli::try_parse_from(["sshw", "profile", "show", "prod", "--json"]).unwrap(),
        &path,
        &store,
        &ssh,
        &mut FakePrompter::default(),
    )
    .unwrap();
    let json: serde_json::Value = serde_json::from_str(shown.stdout.trim()).unwrap();
    assert_eq!(json["ok"], true);
    assert_eq!(json["name"], "prod");
    assert_eq!(json["is_default"], true);
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
fn profile_force_same_home_preserves_namespace_and_control_names_are_rejected() {
    let temp = tempfile::tempdir().unwrap();
    let path = temp.path().join("servers.json");
    save_config(&path, &SshwConfig::default()).unwrap();
    let home = temp.path().join("prod-home");
    let home_text = home.to_str().unwrap();

    execute(
        Cli::try_parse_from(["sshw", "profile", "add", "prod", "--home", home_text]).unwrap(),
        &path,
        &FakeCredentialStore::default(),
        &FakeSshClient::default(),
        &mut FakePrompter::default(),
    )
    .unwrap();
    let registry_path = temp.path().join("profiles.json");
    let first_id = sshw::profile::load_registry(&registry_path)
        .unwrap()
        .profiles["prod"]
        .id
        .clone();
    std::fs::create_dir_all(&home).unwrap();

    execute(
        Cli::try_parse_from([
            "sshw", "profile", "add", "prod", "--home", home_text, "--force",
        ])
        .unwrap(),
        &path,
        &FakeCredentialStore::default(),
        &FakeSshClient::default(),
        &mut FakePrompter::default(),
    )
    .unwrap();
    let second_id = sshw::profile::load_registry(&registry_path)
        .unwrap()
        .profiles["prod"]
        .id
        .clone();
    assert_eq!(second_id, first_id);

    let err = execute(
        Cli::try_parse_from([
            "sshw",
            "profile",
            "add",
            "bad\nname",
            "--home",
            temp.path().join("bad-home").to_str().unwrap(),
        ])
        .unwrap(),
        &path,
        &FakeCredentialStore::default(),
        &FakeSshClient::default(),
        &mut FakePrompter::default(),
    )
    .unwrap_err();
    assert!(
        err.to_string()
            .contains("profile name must not contain control")
    );
}

#[test]
fn profile_add_persists_relative_home_as_absolute() {
    let temp = tempfile::tempdir().unwrap();
    let path = temp.path().join("servers.json");
    save_config(&path, &SshwConfig::default()).unwrap();
    let store = FakeCredentialStore::default();
    let ssh = FakeSshClient::default();
    let relative = format!("sshw-relative-profile-home-{}", std::process::id());
    let expected = std::path::absolute(&relative).unwrap();

    execute(
        Cli::try_parse_from(["sshw", "--home", &relative, "profile", "add", "prod"]).unwrap(),
        &path,
        &store,
        &ssh,
        &mut FakePrompter::default(),
    )
    .unwrap();

    let registry = sshw::profile::load_registry(&temp.path().join("profiles.json")).unwrap();
    assert_eq!(registry.profiles["prod"].home, expected);
}

#[test]
fn run_redacts_secrets_in_output() {
    let temp = tempfile::tempdir().unwrap();
    let path = temp.path().join("servers.json");
    save_config(&path, &sample_config(&path)).unwrap();
    let store = FakeCredentialStore::default();
    store
        .set_password(
            &login_credential(&path, "server-alpha"),
            "deploy",
            "YOUR_PASSWORD",
        )
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

#[test]
fn run_redacts_the_exact_login_password_from_remote_output() {
    let temp = tempfile::tempdir().unwrap();
    let path = temp.path().join("servers.json");
    save_config(&path, &sample_config(&path)).unwrap();
    let login_password = "LOGIN-EXACT-7x4Q";
    let store = FakeCredentialStore::default();
    store
        .set_password(
            &login_credential(&path, "server-alpha"),
            "deploy",
            login_password,
        )
        .unwrap();
    let ssh = FakeSshClient {
        stdout: Some(format!("stdout echoed {login_password}\n")),
        stderr: format!("stderr echoed {login_password}\n"),
        ..FakeSshClient::default()
    };

    let output = execute(
        Cli::try_parse_from(["sshw", "run", "server-alpha", "hostname"]).unwrap(),
        &path,
        &store,
        &ssh,
        &mut FakePrompter::default(),
    )
    .unwrap();

    assert!(!output.stdout.contains(login_password));
    assert!(!output.stderr.contains(login_password));
    assert!(output.stdout.contains("<redacted>"));
    assert!(output.stderr.contains("<redacted>"));

    let json_output = execute(
        Cli::try_parse_from([
            "sshw",
            "run",
            "server-alpha",
            &format!("printf {login_password}"),
            "--json",
        ])
        .unwrap(),
        &path,
        &store,
        &ssh,
        &mut FakePrompter::default(),
    )
    .unwrap();
    let json: serde_json::Value = serde_json::from_str(json_output.stdout.trim()).unwrap();
    assert!(!json_output.stdout.contains(login_password));
    assert_eq!(json["command"], "printf <redacted>");
}

#[test]
fn run_redacts_overlapping_login_and_privilege_secrets_longest_first() {
    let temp = tempfile::tempdir().unwrap();
    let path = temp.path().join("servers.json");
    let mut config = sample_config(&path);
    set_default_privilege(
        &mut config,
        "server-alpha",
        PrivilegeConfig {
            method: PrivilegeMethod::Sudo,
            user: "root".to_string(),
            credential: privilege_credential(&path, "server-alpha"),
        },
    );
    save_config(&path, &config).unwrap();

    let store = FakeCredentialStore::default();
    store
        .set_password(&login_credential(&path, "server-alpha"), "deploy", "abc")
        .unwrap();
    store
        .set_password(
            &privilege_credential(&path, "server-alpha"),
            "root",
            "abcdef",
        )
        .unwrap();
    let ssh = FakeSshClient {
        stdout: Some("abcdef|abc\n".to_string()),
        stderr: "abcdef|abc\n".to_string(),
        ..FakeSshClient::default()
    };

    let human = execute(
        Cli::try_parse_from(["sshw", "run", "server-alpha", "id -u", "--as-root", "--yes"])
            .unwrap(),
        &path,
        &store,
        &ssh,
        &mut FakePrompter::default(),
    )
    .unwrap();
    assert_eq!(human.stdout, "<redacted>|<redacted>\n");
    assert_eq!(human.stderr, "<redacted>|<redacted>\n");

    let json_output = execute(
        Cli::try_parse_from([
            "sshw",
            "run",
            "server-alpha",
            "printf abcdef abc",
            "--as-root",
            "--yes",
            "--json",
        ])
        .unwrap(),
        &path,
        &store,
        &ssh,
        &mut FakePrompter::default(),
    )
    .unwrap();
    let json: serde_json::Value = serde_json::from_str(json_output.stdout.trim()).unwrap();
    assert_eq!(json["command"], "printf <redacted> <redacted>");
    assert_eq!(json["stdout"], "<redacted>|<redacted>\n");
    assert_eq!(json["stderr"], "<redacted>|<redacted>\n");
}

fn write_policy(dir: &Path, contents: &str) {
    std::fs::write(dir.join("policy.json"), contents).unwrap();
}

#[test]
fn policy_setup_failure_is_audited() {
    let temp = tempfile::tempdir().unwrap();
    let path = temp.path().join("servers.json");
    save_config(&path, &sample_config(&path)).unwrap();
    write_policy(temp.path(), "{");
    let store = FakeCredentialStore::default();
    store
        .set_password(
            &login_credential(&path, "server-alpha"),
            "deploy",
            "YOUR_PASSWORD",
        )
        .unwrap();
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

    let err = execute_with(
        Cli::try_parse_from(["sshw", "run", "server-alpha", "uptime"]).unwrap(),
        &ctx,
        &store,
        &FakeSshClient::default(),
        &mut FakePrompter::default(),
    )
    .unwrap_err();

    assert!(err.to_string().contains("policy"));
    let record: serde_json::Value =
        serde_json::from_str(std::fs::read_to_string(audit_path).unwrap().trim()).unwrap();
    assert_eq!(record["action"], "run");
    assert_eq!(record["status"], "error");
    assert_eq!(record["exit_code"], 7);
}

#[test]
fn profile_mutation_success_and_failure_are_audited() {
    let temp = tempfile::tempdir().unwrap();
    let path = temp.path().join("active").join("servers.json");
    let profile_home = temp.path().join("profile-home");
    std::fs::create_dir_all(&profile_home).unwrap();
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

    let profile_add = || {
        Cli::try_parse_from([
            "sshw",
            "--home",
            profile_home.to_str().unwrap(),
            "profile",
            "add",
            "prod",
        ])
        .unwrap()
    };
    execute_with(
        profile_add(),
        &ctx,
        &FakeCredentialStore::default(),
        &FakeSshClient::default(),
        &mut FakePrompter::default(),
    )
    .unwrap();
    execute_with(
        profile_add(),
        &ctx,
        &FakeCredentialStore::default(),
        &FakeSshClient::default(),
        &mut FakePrompter::default(),
    )
    .unwrap_err();

    let records: Vec<serde_json::Value> = std::fs::read_to_string(audit_path)
        .unwrap()
        .lines()
        .map(|line| serde_json::from_str(line).unwrap())
        .collect();
    assert_eq!(records.len(), 2);
    assert_eq!(records[0]["action"], "profile");
    assert_eq!(records[0]["detail"], "add:prod");
    assert_eq!(records[0]["status"], "ok");
    assert_eq!(records[1]["action"], "profile");
    assert_eq!(records[1]["detail"], "add:prod");
    assert_eq!(records[1]["status"], "error");
    assert_eq!(records[1]["exit_code"], 3);
}

#[test]
fn run_audit_records_program_name_not_arguments() {
    let temp = tempfile::tempdir().unwrap();
    let path = temp.path().join("servers.json");
    let mut config = sample_config(&path);
    config
        .servers
        .get_mut("server-alpha")
        .unwrap()
        .accounts
        .insert(
            "ops".to_string(),
            AccountConfig {
                auth: AuthConfig::Agent,
                privilege: None,
            },
        );
    save_config(&path, &config).unwrap();
    let store = FakeCredentialStore::default();
    store
        .set_password(
            &login_credential(&path, "server-alpha"),
            "deploy",
            "YOUR_PASSWORD",
        )
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
        Cli::try_parse_from([
            "sshw",
            "run",
            "server-alpha",
            "mysql --password=hunter2",
            "--user",
            "ops",
        ])
        .unwrap(),
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
    assert_eq!(rec["user"], "ops");
    assert_eq!(rec["status"], "ok");
    // Only the program name is recorded; inline arguments (and any secret in
    // them) are never persisted.
    assert_eq!(rec["detail"], "mysql");
    assert!(!log.contains("hunter2"), "secret leaked into audit log");
    assert!(
        !log.contains("--password"),
        "arguments leaked into audit log"
    );
}

#[test]
fn run_audit_skips_leading_environment_assignments() {
    let temp = tempfile::tempdir().unwrap();
    let path = temp.path().join("servers.json");
    save_config(&path, &sample_config(&path)).unwrap();
    let store = FakeCredentialStore::default();
    store
        .set_password(
            &login_credential(&path, "server-alpha"),
            "deploy",
            "YOUR_PASSWORD",
        )
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
        Cli::try_parse_from([
            "sshw",
            "run",
            "server-alpha",
            "GENERIC_VAR=synthetic-audit-secret env OTHER=value /usr/bin/printf ok",
        ])
        .unwrap(),
        &ctx,
        &store,
        &ssh,
        &mut FakePrompter::default(),
    )
    .unwrap();

    let log = std::fs::read_to_string(&audit_path).unwrap();
    let rec: serde_json::Value = serde_json::from_str(log.trim()).unwrap();
    assert_eq!(rec["detail"], "printf");
    assert!(!log.contains("GENERIC_VAR"));
    assert!(!log.contains("synthetic-audit-secret"));
    assert!(!log.contains("OTHER=value"));
}

#[test]
fn run_as_root_audit_records_privilege_marker_without_secret() {
    let temp = tempfile::tempdir().unwrap();
    let path = temp.path().join("servers.json");
    let mut config = sample_config(&path);
    set_default_privilege(
        &mut config,
        "server-alpha",
        PrivilegeConfig {
            method: PrivilegeMethod::Sudo,
            user: "root".to_string(),
            credential: privilege_credential(&path, "server-alpha"),
        },
    );
    save_config(&path, &config).unwrap();
    let store = FakeCredentialStore::default();
    store
        .set_password(
            &login_credential(&path, "server-alpha"),
            "deploy",
            "YOUR_PASSWORD",
        )
        .unwrap();
    store
        .set_password(
            &privilege_credential(&path, "server-alpha"),
            "root",
            "ROOT_PASSWORD",
        )
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
        Cli::try_parse_from([
            "sshw",
            "run",
            "server-alpha",
            "id -u --password=hunter2",
            "--as-root",
            "--yes",
        ])
        .unwrap(),
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
    assert_eq!(rec["detail"], "as-root:sudo:root:id");
    assert!(!log.contains("ROOT_PASSWORD"));
    assert!(!log.contains("hunter2"));
    assert!(!log.contains("--password"));
}

#[test]
fn run_remote_nonzero_exit_maps_to_dedicated_exit_code() {
    let temp = tempfile::tempdir().unwrap();
    let path = temp.path().join("servers.json");
    save_config(&path, &sample_config(&path)).unwrap();
    let store = FakeCredentialStore::default();
    store
        .set_password(
            &login_credential(&path, "server-alpha"),
            "deploy",
            "YOUR_PASSWORD",
        )
        .unwrap();
    let ssh = FakeSshClient::with_exit_status(5);
    let mut prompter = FakePrompter::default();

    let output = execute_for_runtime(
        Cli::try_parse_from(["sshw", "run", "server-alpha", "false"]).unwrap(),
        &path,
        &store,
        &ssh,
        &mut prompter,
    );

    // A remote status of 5 must not surface as sshw's ssh exit code (5); it
    // maps to the dedicated remote-non-zero code instead.
    assert_eq!(output.exit_code, sshw::output::REMOTE_NONZERO_EXIT_CODE);
    assert!(
        output
            .stderr
            .contains("remote command exited with status 5"),
        "human mode should note the real remote status; got: {:?}",
        output.stderr
    );
}

#[test]
fn run_remote_nonzero_note_starts_on_a_new_line() {
    let temp = tempfile::tempdir().unwrap();
    let path = temp.path().join("servers.json");
    save_config(&path, &sample_config(&path)).unwrap();
    let store = FakeCredentialStore::default();
    store
        .set_password(
            &login_credential(&path, "server-alpha"),
            "deploy",
            "YOUR_PASSWORD",
        )
        .unwrap();
    let ssh = FakeSshClient {
        stderr: "remote warning without newline".to_string(),
        run_exit_status: 5,
        ..FakeSshClient::default()
    };

    let output = execute_for_runtime(
        Cli::try_parse_from(["sshw", "run", "server-alpha", "false"]).unwrap(),
        &path,
        &store,
        &ssh,
        &mut FakePrompter::default(),
    );

    assert_eq!(
        output.stderr,
        "remote warning without newline\nnote: remote command exited with status 5\n"
    );
}

#[test]
fn run_remote_nonzero_json_reports_real_status_and_dedicated_exit() {
    let temp = tempfile::tempdir().unwrap();
    let path = temp.path().join("servers.json");
    save_config(&path, &sample_config(&path)).unwrap();
    let store = FakeCredentialStore::default();
    store
        .set_password(
            &login_credential(&path, "server-alpha"),
            "deploy",
            "YOUR_PASSWORD",
        )
        .unwrap();
    let ssh = FakeSshClient::with_exit_status(3);
    let mut prompter = FakePrompter::default();

    let output = execute_for_runtime(
        Cli::try_parse_from(["sshw", "run", "server-alpha", "test -f /x", "--json"]).unwrap(),
        &path,
        &store,
        &ssh,
        &mut prompter,
    );

    assert_eq!(output.exit_code, sshw::output::REMOTE_NONZERO_EXIT_CODE);
    assert_eq!(output.stderr, "", "JSON mode must not add the human note");
    let body: serde_json::Value = serde_json::from_str(output.stdout.trim()).unwrap();
    assert_eq!(
        body["exit_status"], 3,
        "JSON carries the real remote status"
    );
}

#[test]
fn run_remote_zero_exit_stays_zero() {
    let temp = tempfile::tempdir().unwrap();
    let path = temp.path().join("servers.json");
    save_config(&path, &sample_config(&path)).unwrap();
    let store = FakeCredentialStore::default();
    store
        .set_password(
            &login_credential(&path, "server-alpha"),
            "deploy",
            "YOUR_PASSWORD",
        )
        .unwrap();
    let ssh = FakeSshClient::with_exit_status(0);
    let mut prompter = FakePrompter::default();

    let output = execute_for_runtime(
        Cli::try_parse_from(["sshw", "run", "server-alpha", "true"]).unwrap(),
        &path,
        &store,
        &ssh,
        &mut prompter,
    );

    assert_eq!(output.exit_code, 0);
    assert!(!output.stderr.contains("remote command exited"));
}

#[test]
fn run_remote_nonzero_audit_records_real_status() {
    let temp = tempfile::tempdir().unwrap();
    let path = temp.path().join("servers.json");
    save_config(&path, &sample_config(&path)).unwrap();
    let store = FakeCredentialStore::default();
    store
        .set_password(
            &login_credential(&path, "server-alpha"),
            "deploy",
            "YOUR_PASSWORD",
        )
        .unwrap();
    let ssh = FakeSshClient::with_exit_status(5);
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

    let output = execute_with(
        Cli::try_parse_from(["sshw", "run", "server-alpha", "false"]).unwrap(),
        &ctx,
        &store,
        &ssh,
        &mut FakePrompter::default(),
    )
    .unwrap();

    // User-facing exit is the dedicated code, but the audit log preserves the
    // real remote status for diagnostics.
    assert_eq!(output.exit_code, sshw::output::REMOTE_NONZERO_EXIT_CODE);
    let rec: serde_json::Value =
        serde_json::from_str(std::fs::read_to_string(&audit_path).unwrap().trim()).unwrap();
    assert_eq!(rec["action"], "run");
    assert_eq!(rec["status"], "ok");
    assert_eq!(rec["exit_code"], 5);
}

#[test]
fn ssh_boundary_type_beats_dynamic_error_text() {
    let temp = tempfile::tempdir().unwrap();
    let path = temp.path().join("servers.json");
    save_config(&path, &sample_config(&path)).unwrap();
    let store = FakeCredentialStore::default();
    store
        .set_password(
            &login_credential(&path, "server-alpha"),
            "deploy",
            "YOUR_PASSWORD",
        )
        .unwrap();
    let ssh = FakeSshClient::with_run_error("blocked by policy and requires --yes");
    let mut prompter = FakePrompter::default();

    let output = execute_for_runtime(
        Cli::try_parse_from(["sshw", "run", "server-alpha", "hostname", "--json"]).unwrap(),
        &path,
        &store,
        &ssh,
        &mut prompter,
    );

    assert_eq!(output.exit_code, 5);
    let json: serde_json::Value = serde_json::from_str(output.stdout.trim()).unwrap();
    assert_eq!(json["error"]["kind"], "ssh");
}

#[test]
fn transfer_boundaries_type_backend_errors_as_ssh() {
    let temp = tempfile::tempdir().unwrap();
    let path = temp.path().join("servers.json");
    save_config(&path, &sample_config(&path)).unwrap();
    let store = FakeCredentialStore::default();
    store
        .set_password(
            &login_credential(&path, "server-alpha"),
            "deploy",
            "YOUR_PASSWORD",
        )
        .unwrap();
    let ssh = FakeSshClient::with_transfer_error("blocked by policy and requires --yes");

    for cli in [
        Cli::try_parse_from([
            "sshw",
            "put",
            "server-alpha",
            "fixture.txt",
            "/srv/app/fixture.txt",
            "--json",
        ])
        .unwrap(),
        Cli::try_parse_from([
            "sshw",
            "get",
            "server-alpha",
            "/var/log/app.log",
            temp.path().join("download.log").to_str().unwrap(),
            "--json",
        ])
        .unwrap(),
    ] {
        let output = execute_for_runtime(cli, &path, &store, &ssh, &mut FakePrompter::default());
        let json: serde_json::Value = serde_json::from_str(output.stdout.trim()).unwrap();

        assert_eq!(output.exit_code, 5);
        assert_eq!(json["error"]["kind"], "ssh");
    }
}

#[test]
fn add_password_under_session_backend_warns_not_persisted() {
    let temp = tempfile::tempdir().unwrap();
    let path = temp.path().join("servers.json");
    save_config(&path, &SshwConfig::default()).unwrap();
    let store = SessionOnlyStore::new();
    let ssh = FakeSshClient::default();
    let mut prompter = FakePrompter {
        confirm: false,
        confirm_error: None,
        password: Some("secret-pw".to_string()),
        password_stdin: None,
    };

    let output = execute(
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

    assert!(output.stdout.contains("added web"));
    assert!(
        output.stdout.contains("does not persist"),
        "expected a non-persistent backend warning, got: {}",
        output.stdout
    );
}

#[test]
fn failed_run_is_audited_with_error_status() {
    let temp = tempfile::tempdir().unwrap();
    let path = temp.path().join("servers.json");
    save_config(&path, &sample_config(&path)).unwrap();
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
    save_config(&path, &sample_config(&path)).unwrap();
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
    execute_with(
        Cli::try_parse_from(["sshw", "account", "list", "server-alpha"]).unwrap(),
        &ctx,
        &store,
        &ssh,
        &mut FakePrompter::default(),
    )
    .unwrap();
    execute_with(
        Cli::try_parse_from(["sshw", "account", "show", "server-alpha", "deploy"]).unwrap(),
        &ctx,
        &store,
        &ssh,
        &mut FakePrompter::default(),
    )
    .unwrap();

    assert!(
        !audit_path.exists(),
        "read-only list/account commands should not write an audit record"
    );
}

#[test]
fn policy_allows_listed_command_and_blocks_others() {
    let temp = tempfile::tempdir().unwrap();
    let path = temp.path().join("servers.json");
    save_config(&path, &sample_config(&path)).unwrap();
    write_policy(
        temp.path(),
        r#"{"version":1,"enabled":true,"allow_commands":["uptime"]}"#,
    );
    let store = FakeCredentialStore::default();
    store
        .set_password(
            &login_credential(&path, "server-alpha"),
            "deploy",
            "YOUR_PASSWORD",
        )
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
    save_config(&path, &sample_config(&path)).unwrap();
    let store = FakeCredentialStore::default();
    store
        .set_password(
            &login_credential(&path, "server-alpha"),
            "deploy",
            "YOUR_PASSWORD",
        )
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
    save_config(&path, &sample_config(&path)).unwrap();
    write_policy(
        temp.path(),
        r#"{"enabled":true,"allow_put_paths":["/srv/app"],"allow_get_paths":["/var/log"]}"#,
    );
    let store = FakeCredentialStore::default();
    store
        .set_password(
            &login_credential(&path, "server-alpha"),
            "deploy",
            "YOUR_PASSWORD",
        )
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
    save_config(&path, &sample_config(&path)).unwrap();
    write_policy(
        temp.path(),
        r#"{"enabled":true,"allow_put_paths":["/srv/app"],"allow_get_paths":["/var/log"]}"#,
    );
    let store = FakeCredentialStore::default();
    store
        .set_password(
            &login_credential(&path, "server-alpha"),
            "deploy",
            "YOUR_PASSWORD",
        )
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
    save_config(&path, &sample_config(&path)).unwrap();
    write_policy(
        temp.path(),
        r#"{"enabled":false,"allow_commands":["uptime"]}"#,
    );
    let store = FakeCredentialStore::default();
    store
        .set_password(
            &login_credential(&path, "server-alpha"),
            "deploy",
            "YOUR_PASSWORD",
        )
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

fn assert_json_error(
    output: sshw::cli::CommandOutput,
    exit_code: i32,
    kind: &str,
    message_part: &str,
) {
    assert_eq!(output.exit_code, exit_code);
    assert_eq!(output.stderr, "");
    let json: serde_json::Value = serde_json::from_str(output.stdout.trim()).unwrap();
    assert_eq!(json["ok"], false);
    assert_eq!(json["error"]["kind"], kind);
    assert_eq!(json["error"]["exit_code"], exit_code);
    assert!(
        json["error"]["message"]
            .as_str()
            .unwrap()
            .contains(message_part)
    );
}

fn login_credential(path: &Path, name: &str) -> String {
    ResolvedHome::from_config_path(path)
        .namespace
        .legacy_credential_key(name)
}

fn privilege_credential(path: &Path, name: &str) -> String {
    ResolvedHome::from_config_path(path)
        .namespace
        .legacy_privilege_credential_key(name)
}

fn sample_config(path: &Path) -> SshwConfig {
    let mut servers = BTreeMap::new();
    servers.insert(
        "server-alpha".to_string(),
        ServerConfig::single_account(
            "192.0.2.10",
            2222,
            "deploy",
            AuthConfig::Password {
                credential: login_credential(path, "server-alpha"),
            },
        ),
    );

    SshwConfig {
        default: Some("server-alpha".to_string()),
        servers,
        ..SshwConfig::default()
    }
}

#[test]
fn doctor_reports_missing_credentials_per_server_and_user() {
    let temp = tempfile::tempdir().unwrap();
    let path = temp.path().join("servers.json");
    let namespace = ResolvedHome::from_config_path(&path).namespace;
    let ops_credential = namespace.credential_key_v3(
        CredentialPurpose::Login,
        "server-alpha",
        "ops",
        "0000000000000001",
    );
    let mut config = sample_config(&path);
    config
        .servers
        .get_mut("server-alpha")
        .unwrap()
        .accounts
        .insert(
            "ops".to_string(),
            AccountConfig {
                auth: AuthConfig::Password {
                    credential: ops_credential,
                },
                privilege: None,
            },
        );
    save_config(&path, &config).unwrap();
    let store = FakeCredentialStore::default();
    store
        .set_password(
            &login_credential(&path, "server-alpha"),
            "deploy",
            "DEPLOY_PASSWORD",
        )
        .unwrap();

    let output = execute(
        Cli::try_parse_from(["sshw", "doctor", "--json"]).unwrap(),
        &path,
        &store,
        &FakeSshClient::default(),
        &mut FakePrompter::default(),
    )
    .unwrap();
    let json: serde_json::Value = serde_json::from_str(output.stdout.trim()).unwrap();
    assert_eq!(
        json["missing_credentials"],
        serde_json::json!(["server-alpha/ops"])
    );
}

#[test]
fn parses_account_management_commands() {
    let cli = Cli::try_parse_from([
        "sshw",
        "account",
        "add",
        "server-alpha",
        "ops",
        "--auth",
        "agent",
        "--json",
    ])
    .unwrap();
    let Command::Account(args) = cli.command else {
        panic!("expected account command");
    };
    let sshw::cli::AccountCommand::Add(args) = args.command else {
        panic!("expected account add command");
    };
    assert_eq!(args.name, "server-alpha");
    assert_eq!(args.user, "ops");
    assert_eq!(args.auth, AuthArg::Agent);
    assert!(args.json);

    for command in ["list", "show", "default", "remove"] {
        let mut argv = vec!["sshw", "account", command, "server-alpha"];
        if command != "list" {
            argv.push("ops");
        }
        Cli::try_parse_from(argv).unwrap();
    }
}

#[test]
fn parses_explicit_user_for_run_put_and_get() {
    let run =
        Cli::try_parse_from(["sshw", "run", "server-alpha", "whoami", "--user", "ops"]).unwrap();
    let Command::Run(run) = run.command else {
        panic!("expected run command");
    };
    assert_eq!(run.user.as_deref(), Some("ops"));

    let put = Cli::try_parse_from([
        "sshw",
        "put",
        "server-alpha",
        "local.txt",
        "/tmp/remote.txt",
        "--user",
        "ops",
    ])
    .unwrap();
    let Command::Put(put) = put.command else {
        panic!("expected put command");
    };
    assert_eq!(put.user.as_deref(), Some("ops"));

    let get = Cli::try_parse_from([
        "sshw",
        "get",
        "server-alpha",
        "/tmp/remote.txt",
        "local.txt",
        "--user",
        "ops",
    ])
    .unwrap();
    let Command::Get(get) = get.command else {
        panic!("expected get command");
    };
    assert_eq!(get.user.as_deref(), Some("ops"));
}

#[test]
fn run_uses_registered_explicit_user_and_reports_it_in_json() {
    let temp = tempfile::tempdir().unwrap();
    let path = temp.path().join("servers.json");
    let namespace = ResolvedHome::from_config_path(&path).namespace;
    let credential = namespace.credential_key_v3(
        CredentialPurpose::Login,
        "server-alpha",
        "ops",
        "0000000000000001",
    );
    let mut config = sample_config(&path);
    config
        .servers
        .get_mut("server-alpha")
        .unwrap()
        .accounts
        .insert(
            "ops".to_string(),
            AccountConfig {
                auth: AuthConfig::Password {
                    credential: credential.clone(),
                },
                privilege: None,
            },
        );
    save_config(&path, &config).unwrap();
    let store = FakeCredentialStore::default();
    store
        .set_password(&credential, "ops", "OPS_PASSWORD")
        .unwrap();
    let ssh = FakeSshClient::default();
    let mut prompter = FakePrompter::default();

    let output = execute(
        Cli::try_parse_from([
            "sshw",
            "run",
            "server-alpha",
            "whoami",
            "--user",
            "ops",
            "--json",
        ])
        .unwrap(),
        &path,
        &store,
        &ssh,
        &mut prompter,
    )
    .unwrap();

    let json: serde_json::Value = serde_json::from_str(output.stdout.trim()).unwrap();
    assert_eq!(json["server"], "server-alpha");
    assert_eq!(json["user"], "ops");
    assert_eq!(ssh.selected_users.borrow().as_slice(), ["ops"]);
    assert_eq!(
        store.requested.borrow().as_slice(),
        [(credential, "ops".to_string())]
    );
}

#[test]
fn unknown_explicit_user_fails_before_credential_or_ssh_access() {
    let temp = tempfile::tempdir().unwrap();
    let path = temp.path().join("servers.json");
    save_config(&path, &sample_config(&path)).unwrap();
    let store = FakeCredentialStore::default();
    let ssh = FakeSshClient::default();

    let err = execute(
        Cli::try_parse_from(["sshw", "run", "server-alpha", "whoami", "--user", "missing"])
            .unwrap(),
        &path,
        &store,
        &ssh,
        &mut FakePrompter::default(),
    )
    .unwrap_err();

    assert!(
        err.to_string()
            .contains("unknown account 'server-alpha/missing'")
    );
    assert!(store.requested.borrow().is_empty());
    assert!(ssh.selected_users.borrow().is_empty());
}

#[test]
fn put_and_get_use_the_same_registered_explicit_user() {
    let temp = tempfile::tempdir().unwrap();
    let path = temp.path().join("servers.json");
    let local_source = temp.path().join("source.txt");
    let local_destination = temp.path().join("destination.txt");
    std::fs::write(&local_source, "payload").unwrap();
    let mut config = sample_config(&path);
    config
        .servers
        .get_mut("server-alpha")
        .unwrap()
        .accounts
        .insert(
            "ops".to_string(),
            AccountConfig {
                auth: AuthConfig::Agent,
                privilege: None,
            },
        );
    save_config(&path, &config).unwrap();
    let store = FakeCredentialStore::default();
    let ssh = FakeSshClient::default();
    let mut prompter = FakePrompter::default();

    let put = execute(
        Cli::try_parse_from([
            "sshw",
            "put",
            "server-alpha",
            local_source.to_str().unwrap(),
            "/tmp/source.txt",
            "--user",
            "ops",
            "--json",
        ])
        .unwrap(),
        &path,
        &store,
        &ssh,
        &mut prompter,
    )
    .unwrap();
    let put: serde_json::Value = serde_json::from_str(put.stdout.trim()).unwrap();
    assert_eq!(put["user"], "ops");

    let get = execute(
        Cli::try_parse_from([
            "sshw",
            "get",
            "server-alpha",
            "/tmp/source.txt",
            local_destination.to_str().unwrap(),
            "--user",
            "ops",
            "--json",
        ])
        .unwrap(),
        &path,
        &store,
        &ssh,
        &mut prompter,
    )
    .unwrap();
    let get: serde_json::Value = serde_json::from_str(get.stdout.trim()).unwrap();
    assert_eq!(get["user"], "ops");
    assert_eq!(ssh.selected_users.borrow().as_slice(), ["ops", "ops"]);
}

#[test]
fn explicit_user_works_when_run_put_and_get_omit_the_default_server() {
    let temp = tempfile::tempdir().unwrap();
    let path = temp.path().join("servers.json");
    let local_source = temp.path().join("source.txt");
    let local_destination = temp.path().join("destination.txt");
    std::fs::write(&local_source, "payload").unwrap();
    let mut config = sample_config(&path);
    config
        .servers
        .get_mut("server-alpha")
        .unwrap()
        .accounts
        .insert(
            "ops".to_string(),
            AccountConfig {
                auth: AuthConfig::Agent,
                privilege: None,
            },
        );
    save_config(&path, &config).unwrap();
    let store = FakeCredentialStore::default();
    let ssh = FakeSshClient::default();
    let mut prompter = FakePrompter::default();

    execute(
        Cli::try_parse_from(["sshw", "run", "whoami", "--user", "ops"]).unwrap(),
        &path,
        &store,
        &ssh,
        &mut prompter,
    )
    .unwrap();
    execute(
        Cli::try_parse_from([
            "sshw",
            "put",
            local_source.to_str().unwrap(),
            "/tmp/source.txt",
            "--user",
            "ops",
        ])
        .unwrap(),
        &path,
        &store,
        &ssh,
        &mut prompter,
    )
    .unwrap();
    execute(
        Cli::try_parse_from([
            "sshw",
            "get",
            "/tmp/source.txt",
            local_destination.to_str().unwrap(),
            "--user",
            "ops",
        ])
        .unwrap(),
        &path,
        &store,
        &ssh,
        &mut prompter,
    )
    .unwrap();

    assert_eq!(
        ssh.selected_users.borrow().as_slice(),
        ["ops", "ops", "ops"]
    );
}

#[test]
fn privilege_configuration_is_scoped_to_the_selected_login_account() {
    let temp = tempfile::tempdir().unwrap();
    let path = temp.path().join("servers.json");
    let mut config = sample_config(&path);
    config
        .servers
        .get_mut("server-alpha")
        .unwrap()
        .accounts
        .insert(
            "ops".to_string(),
            AccountConfig {
                auth: AuthConfig::Agent,
                privilege: None,
            },
        );
    save_config(&path, &config).unwrap();
    let store = FakeCredentialStore::default();
    store
        .set_password(
            &login_credential(&path, "server-alpha"),
            "deploy",
            "DEPLOY_PASSWORD",
        )
        .unwrap();
    let ssh = FakeSshClient::default();
    let mut prompter = FakePrompter::default();

    execute(
        Cli::try_parse_from([
            "sshw",
            "privilege",
            "set",
            "server-alpha",
            "--account",
            "ops",
            "--user",
            "root",
            "--force",
        ])
        .unwrap(),
        &path,
        &store,
        &ssh,
        &mut prompter,
    )
    .unwrap();

    let config = load_config(&path).unwrap();
    let privilege = config.servers["server-alpha"].accounts["ops"]
        .privilege
        .as_ref()
        .unwrap();
    assert!(
        ResolvedHome::from_config_path(&path)
            .namespace
            .account_credential_key_matches(
                CredentialPurpose::Privilege,
                "server-alpha",
                "ops",
                &privilege.credential,
            )
    );
    assert!(
        config.servers["server-alpha"].accounts["deploy"]
            .privilege
            .is_none()
    );

    execute(
        Cli::try_parse_from([
            "sshw",
            "run",
            "server-alpha",
            "id -u",
            "--user",
            "ops",
            "--as-root",
            "--yes",
        ])
        .unwrap(),
        &path,
        &store,
        &ssh,
        &mut prompter,
    )
    .unwrap();
    assert_eq!(ssh.selected_users.borrow().as_slice(), ["ops"]);
    assert_eq!(ssh.run_stdin.borrow().len(), 1);

    let err = execute(
        Cli::try_parse_from(["sshw", "run", "server-alpha", "id -u", "--as-root", "--yes"])
            .unwrap(),
        &path,
        &store,
        &ssh,
        &mut prompter,
    )
    .unwrap_err();
    assert!(
        err.to_string()
            .contains("privilege configuration missing for account 'server-alpha/deploy'")
    );
}

#[test]
fn policy_requires_exact_allowlist_for_non_default_account() {
    let temp = tempfile::tempdir().unwrap();
    let path = temp.path().join("servers.json");
    let mut config = sample_config(&path);
    config
        .servers
        .get_mut("server-alpha")
        .unwrap()
        .accounts
        .insert(
            "ops".to_string(),
            AccountConfig {
                auth: AuthConfig::Agent,
                privilege: None,
            },
        );
    save_config(&path, &config).unwrap();
    write_policy(
        temp.path(),
        r#"{"version":1,"enabled":true,"allow_commands":["whoami"]}"#,
    );
    let store = FakeCredentialStore::default();
    let ssh = FakeSshClient::default();
    let mut prompter = FakePrompter::default();

    let err = execute(
        Cli::try_parse_from(["sshw", "run", "server-alpha", "whoami", "--user", "ops"]).unwrap(),
        &path,
        &store,
        &ssh,
        &mut prompter,
    )
    .unwrap_err();
    assert!(
        err.to_string()
            .contains("account 'server-alpha/ops' is blocked by policy")
    );
    assert!(ssh.selected_users.borrow().is_empty());

    write_policy(
        temp.path(),
        r#"{
            "version":2,
            "enabled":true,
            "allow_commands":["whoami"],
            "allow_accounts":[{"server":"server-alpha","user":"ops"}]
        }"#,
    );
    execute(
        Cli::try_parse_from(["sshw", "run", "server-alpha", "whoami", "--user", "ops"]).unwrap(),
        &path,
        &store,
        &ssh,
        &mut prompter,
    )
    .unwrap();
    assert_eq!(ssh.selected_users.borrow().as_slice(), ["ops"]);
}

#[test]
fn account_add_list_show_and_default_round_trip() {
    let temp = tempfile::tempdir().unwrap();
    let path = temp.path().join("servers.json");
    save_config(&path, &sample_config(&path)).unwrap();
    let store = FakeCredentialStore::default();
    let ssh = FakeSshClient::default();
    let mut prompter = FakePrompter::default();

    let added = execute(
        Cli::try_parse_from([
            "sshw",
            "account",
            "add",
            "server-alpha",
            "ops",
            "--auth",
            "agent",
            "--json",
        ])
        .unwrap(),
        &path,
        &store,
        &ssh,
        &mut prompter,
    )
    .unwrap();
    let added: serde_json::Value = serde_json::from_str(added.stdout.trim()).unwrap();
    assert_eq!(added["action"], "added");
    assert_eq!(added["server"], "server-alpha");
    assert_eq!(added["user"], "ops");

    let listed = execute(
        Cli::try_parse_from(["sshw", "account", "list", "server-alpha", "--json"]).unwrap(),
        &path,
        &store,
        &ssh,
        &mut prompter,
    )
    .unwrap();
    let listed: serde_json::Value = serde_json::from_str(listed.stdout.trim()).unwrap();
    assert_eq!(listed.as_array().unwrap().len(), 2);
    assert_eq!(listed[0]["user"], "deploy");
    assert_eq!(listed[0]["is_default"], true);
    assert_eq!(listed[1]["user"], "ops");
    assert_eq!(listed[1]["auth"]["type"], "agent");

    execute(
        Cli::try_parse_from(["sshw", "account", "default", "server-alpha", "ops"]).unwrap(),
        &path,
        &store,
        &ssh,
        &mut prompter,
    )
    .unwrap();

    let shown = execute(
        Cli::try_parse_from(["sshw", "account", "show", "server-alpha", "ops", "--json"]).unwrap(),
        &path,
        &store,
        &ssh,
        &mut prompter,
    )
    .unwrap();
    let shown: serde_json::Value = serde_json::from_str(shown.stdout.trim()).unwrap();
    assert_eq!(shown["ok"], true);
    assert_eq!(shown["server"], "server-alpha");
    assert_eq!(shown["user"], "ops");
    assert_eq!(shown["is_default"], true);
    assert_eq!(
        load_config(&path).unwrap().servers["server-alpha"].default_user,
        "ops"
    );
}

#[test]
fn account_json_failure_uses_standard_config_envelope() {
    let temp = tempfile::tempdir().unwrap();
    let path = temp.path().join("servers.json");
    save_config(&path, &sample_config(&path)).unwrap();

    let output = execute_for_runtime(
        Cli::try_parse_from([
            "sshw",
            "account",
            "show",
            "server-alpha",
            "missing",
            "--json",
        ])
        .unwrap(),
        &path,
        &FakeCredentialStore::default(),
        &FakeSshClient::default(),
        &mut FakePrompter::default(),
    );

    assert_json_error(
        output,
        3,
        "config",
        "unknown account 'server-alpha/missing'",
    );
}

#[test]
fn account_password_uses_v3_key_and_remove_cleans_only_that_account() {
    let temp = tempfile::tempdir().unwrap();
    let path = temp.path().join("servers.json");
    save_config(&path, &sample_config(&path)).unwrap();
    let store = FakeCredentialStore::default();
    let ssh = FakeSshClient::default();
    let mut prompter = FakePrompter::default();

    execute(
        Cli::try_parse_from([
            "sshw",
            "account",
            "add",
            "server-alpha",
            "ops",
            "--auth",
            "password",
        ])
        .unwrap(),
        &path,
        &store,
        &ssh,
        &mut prompter,
    )
    .unwrap();

    let config = load_config(&path).unwrap();
    let AuthConfig::Password { credential } = &config.servers["server-alpha"].accounts["ops"].auth
    else {
        panic!("ops account must use password auth");
    };
    let namespace = ResolvedHome::from_config_path(&path).namespace;
    assert!(namespace.account_credential_key_matches(
        CredentialPurpose::Login,
        "server-alpha",
        "ops",
        credential,
    ));
    assert!(
        store
            .values
            .borrow()
            .contains_key(&(credential.clone(), "ops".to_string()))
    );

    let default_error = execute(
        Cli::try_parse_from([
            "sshw",
            "account",
            "remove",
            "server-alpha",
            "deploy",
            "--yes",
        ])
        .unwrap(),
        &path,
        &store,
        &ssh,
        &mut prompter,
    )
    .unwrap_err();
    assert!(
        default_error
            .to_string()
            .contains("cannot remove default account")
    );

    execute(
        Cli::try_parse_from(["sshw", "account", "remove", "server-alpha", "ops", "--yes"]).unwrap(),
        &path,
        &store,
        &ssh,
        &mut prompter,
    )
    .unwrap();

    let config = load_config(&path).unwrap();
    assert!(!config.servers["server-alpha"].accounts.contains_key("ops"));
    assert_eq!(
        store.deleted.borrow().as_slice(),
        [(credential.clone(), "ops".to_string())]
    );
}

#[test]
fn account_mutations_are_audited_with_the_affected_user() {
    let temp = tempfile::tempdir().unwrap();
    let path = temp.path().join("servers.json");
    save_config(&path, &sample_config(&path)).unwrap();
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
    let mut prompter = FakePrompter::default();

    execute_with(
        Cli::try_parse_from([
            "sshw",
            "account",
            "add",
            "server-alpha",
            "ops",
            "--auth",
            "agent",
        ])
        .unwrap(),
        &ctx,
        &store,
        &ssh,
        &mut prompter,
    )
    .unwrap();
    execute_with(
        Cli::try_parse_from(["sshw", "account", "remove", "server-alpha", "ops", "--yes"]).unwrap(),
        &ctx,
        &store,
        &ssh,
        &mut prompter,
    )
    .unwrap();

    let records: Vec<serde_json::Value> = std::fs::read_to_string(&audit_path)
        .unwrap()
        .lines()
        .map(|line| serde_json::from_str(line).unwrap())
        .collect();
    assert_eq!(records.len(), 2);
    assert_eq!(records[0]["action"], "account");
    assert_eq!(records[0]["server"], "server-alpha");
    assert_eq!(records[0]["user"], "ops");
    assert_eq!(records[0]["detail"], "add:ops");
    assert_eq!(records[1]["user"], "ops");
    assert_eq!(records[1]["detail"], "remove:ops");
}

#[test]
fn first_account_mutation_persists_v2_without_losing_legacy_default_credential() {
    let temp = tempfile::tempdir().unwrap();
    let path = temp.path().join("servers.json");
    let namespace = ResolvedHome::from_config_path(&path).namespace;
    let legacy_credential = namespace.legacy_credential_key("server-alpha");
    let v1 = format!(
        r#"{{
            "version": 1,
            "default": "server-alpha",
            "servers": {{
                "server-alpha": {{
                    "host": "192.0.2.10",
                    "port": 2222,
                    "user": "deploy",
                    "auth": {{
                        "type": "password",
                        "credential": "{legacy_credential}"
                    }}
                }}
            }}
        }}"#
    );
    std::fs::write(&path, v1).unwrap();
    let store = FakeCredentialStore::default();
    store
        .set_password(&legacy_credential, "deploy", "LEGACY_PASSWORD")
        .unwrap();
    let ssh = FakeSshClient::default();
    let mut prompter = FakePrompter::default();

    execute(
        Cli::try_parse_from([
            "sshw",
            "account",
            "add",
            "server-alpha",
            "ops",
            "--auth",
            "agent",
        ])
        .unwrap(),
        &path,
        &store,
        &ssh,
        &mut prompter,
    )
    .unwrap();

    let raw: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(&path).unwrap()).unwrap();
    assert_eq!(raw["version"], 2);
    assert_eq!(raw["servers"]["server-alpha"]["default_user"], "deploy");
    assert_eq!(
        raw["servers"]["server-alpha"]["accounts"]["deploy"]["auth"]["credential"],
        legacy_credential
    );

    execute(
        Cli::try_parse_from(["sshw", "run", "server-alpha", "whoami"]).unwrap(),
        &path,
        &store,
        &ssh,
        &mut prompter,
    )
    .unwrap();
    assert_eq!(ssh.selected_users.borrow().as_slice(), ["deploy"]);
}

#[test]
fn account_auth_update_preserves_privilege_and_deletes_only_stale_login_secret() {
    let temp = tempfile::tempdir().unwrap();
    let path = temp.path().join("servers.json");
    let namespace = ResolvedHome::from_config_path(&path).namespace;
    let login = namespace.credential_key_v3(
        CredentialPurpose::Login,
        "server-alpha",
        "ops",
        "0000000000000001",
    );
    let privilege = namespace.credential_key_v3(
        CredentialPurpose::Privilege,
        "server-alpha",
        "ops",
        "0000000000000002",
    );
    let mut config = sample_config(&path);
    config
        .servers
        .get_mut("server-alpha")
        .unwrap()
        .accounts
        .insert(
            "ops".to_string(),
            AccountConfig {
                auth: AuthConfig::Password {
                    credential: login.clone(),
                },
                privilege: Some(PrivilegeConfig {
                    method: PrivilegeMethod::Sudo,
                    user: "root".to_string(),
                    credential: privilege.clone(),
                }),
            },
        );
    save_config(&path, &config).unwrap();
    let store = FakeCredentialStore::default();
    store.set_password(&login, "ops", "LOGIN_PASSWORD").unwrap();
    store
        .set_password(&privilege, "root", "PRIVILEGE_PASSWORD")
        .unwrap();

    execute(
        Cli::try_parse_from([
            "sshw",
            "account",
            "add",
            "server-alpha",
            "ops",
            "--auth",
            "agent",
            "--force",
        ])
        .unwrap(),
        &path,
        &store,
        &FakeSshClient::default(),
        &mut FakePrompter::default(),
    )
    .unwrap();

    let config = load_config(&path).unwrap();
    let account = &config.servers["server-alpha"].accounts["ops"];
    assert!(matches!(account.auth, AuthConfig::Agent));
    assert_eq!(account.privilege.as_ref().unwrap().credential, privilege);
    assert_eq!(
        store.deleted.borrow().as_slice(),
        [(login, "ops".to_string())]
    );
    assert!(
        store
            .values
            .borrow()
            .contains_key(&(privilege, "root".to_string()))
    );
}

fn set_default_privilege(config: &mut SshwConfig, server: &str, privilege: PrivilegeConfig) {
    let server = config.servers.get_mut(server).unwrap();
    let user = server.default_user.clone();
    server.account_mut(&user).unwrap().privilege = Some(privilege);
}

fn default_privilege<'a>(config: &'a SshwConfig, server: &str) -> Option<&'a PrivilegeConfig> {
    let server = config.servers.get(server)?;
    server
        .account(&server.default_user)
        .and_then(|account| account.privilege.as_ref())
}

fn privileges_are_empty(config: &SshwConfig) -> bool {
    config
        .servers
        .values()
        .flat_map(|server| server.accounts.values())
        .all(|account| account.privilege.is_none())
}

#[derive(Default)]
struct FakeCredentialStore {
    values: RefCell<BTreeMap<(String, String), String>>,
    requested: RefCell<Vec<(String, String)>>,
    deleted: RefCell<Vec<(String, String)>>,
    delete_error: Option<String>,
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
        self.requested
            .borrow_mut()
            .push((credential.to_string(), user.to_string()));
        self.values
            .borrow()
            .get(&(credential.to_string(), user.to_string()))
            .cloned()
            .ok_or_else(|| anyhow::anyhow!("missing credential"))
    }

    fn delete_password(&self, credential: &str, user: &str) -> anyhow::Result<()> {
        if let Some(message) = &self.delete_error {
            return Err(anyhow::anyhow!(message.clone()));
        }
        self.deleted
            .borrow_mut()
            .push((credential.to_string(), user.to_string()));
        self.values
            .borrow_mut()
            .remove(&(credential.to_string(), user.to_string()));
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
    selected_users: RefCell<Vec<String>>,
    run_commands: RefCell<Vec<String>>,
    run_stdin: RefCell<Vec<Option<String>>>,
    run_pty_passwords: RefCell<Vec<String>>,
    run_pty_nonces: RefCell<Vec<String>>,
    trusted_expected_fingerprints: RefCell<Vec<String>>,
    put_calls: RefCell<Vec<String>>,
    get_calls: RefCell<Vec<bool>>,
    get_remote_calls: RefCell<Vec<String>>,
    host_key_fingerprint: String,
    stdout: Option<String>,
    stderr: String,
    run_error: Option<String>,
    transfer_error: Option<String>,
    run_exit_status: i32,
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

    fn with_run_error(message: &str) -> Self {
        Self {
            run_error: Some(message.to_string()),
            ..Self::default()
        }
    }

    fn with_transfer_error(message: &str) -> Self {
        Self {
            transfer_error: Some(message.to_string()),
            ..Self::default()
        }
    }

    fn with_exit_status(exit_status: i32) -> Self {
        Self {
            run_exit_status: exit_status,
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
        target: &SshTarget<'_>,
        _auth: &AuthMaterial,
        command: &str,
    ) -> anyhow::Result<RunResult> {
        self.selected_users
            .borrow_mut()
            .push(target.user.to_string());
        self.run_commands.borrow_mut().push(command.to_string());
        self.run_stdin.borrow_mut().push(None);
        if let Some(message) = &self.run_error {
            return Err(anyhow::anyhow!("{message}"));
        }
        Ok(RunResult {
            exit_status: self.run_exit_status,
            stdout: self.stdout.clone().unwrap_or_else(|| "ok\n".to_string()),
            stderr: self.stderr.clone(),
            duration_ms: 1,
        })
    }

    fn run_with_stdin(
        &self,
        target: &SshTarget<'_>,
        _auth: &AuthMaterial,
        command: &str,
        stdin: &str,
    ) -> anyhow::Result<RunResult> {
        self.selected_users
            .borrow_mut()
            .push(target.user.to_string());
        self.run_commands.borrow_mut().push(command.to_string());
        self.run_stdin.borrow_mut().push(Some(stdin.to_string()));
        if let Some(message) = &self.run_error {
            return Err(anyhow::anyhow!("{message}"));
        }
        Ok(RunResult {
            exit_status: self.run_exit_status,
            stdout: self.stdout.clone().unwrap_or_else(|| "ok\n".to_string()),
            stderr: self.stderr.clone(),
            duration_ms: 1,
        })
    }

    fn run_with_pty_password(
        &self,
        target: &SshTarget<'_>,
        _auth: &AuthMaterial,
        command: &str,
        password: &str,
        marker_nonce: &str,
    ) -> anyhow::Result<RunResult> {
        self.selected_users
            .borrow_mut()
            .push(target.user.to_string());
        self.run_commands.borrow_mut().push(command.to_string());
        self.run_pty_passwords
            .borrow_mut()
            .push(password.to_string());
        self.run_pty_nonces
            .borrow_mut()
            .push(marker_nonce.to_string());
        if let Some(message) = &self.run_error {
            return Err(anyhow::anyhow!("{message}"));
        }
        Ok(RunResult {
            exit_status: self.run_exit_status,
            stdout: self.stdout.clone().unwrap_or_else(|| "ok\n".to_string()),
            stderr: self.stderr.clone(),
            duration_ms: 1,
        })
    }

    fn put(
        &self,
        target: &SshTarget<'_>,
        _auth: &AuthMaterial,
        local: &Path,
        remote: &str,
    ) -> anyhow::Result<TransferResult> {
        self.selected_users
            .borrow_mut()
            .push(target.user.to_string());
        self.put_calls.borrow_mut().push(remote.to_string());
        if let Some(message) = &self.transfer_error {
            return Err(anyhow::anyhow!(message.clone()));
        }
        Ok(TransferResult {
            bytes: 1,
            source: local.display().to_string(),
            destination: remote.to_string(),
        })
    }

    fn get(
        &self,
        target: &SshTarget<'_>,
        _auth: &AuthMaterial,
        remote: &str,
        local: &Path,
        overwrite: bool,
    ) -> anyhow::Result<TransferResult> {
        self.selected_users
            .borrow_mut()
            .push(target.user.to_string());
        self.get_calls.borrow_mut().push(overwrite);
        self.get_remote_calls.borrow_mut().push(remote.to_string());
        if let Some(message) = &self.transfer_error {
            return Err(anyhow::anyhow!(message.clone()));
        }
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
    confirm_error: Option<String>,
    password: Option<String>,
    password_stdin: Option<String>,
}

impl Prompter for FakePrompter {
    fn confirm(&mut self, _prompt: &str) -> anyhow::Result<bool> {
        if let Some(message) = &self.confirm_error {
            return Err(anyhow::anyhow!(message.clone()));
        }
        Ok(self.confirm)
    }

    fn password(&mut self, _prompt: &str) -> anyhow::Result<String> {
        Ok(self
            .password
            .clone()
            .unwrap_or_else(|| "YOUR_PASSWORD".to_string()))
    }

    fn password_stdin(&mut self) -> anyhow::Result<String> {
        Ok(self
            .password_stdin
            .clone()
            .unwrap_or_else(|| "YOUR_STDIN_PASSWORD".to_string()))
    }
}
