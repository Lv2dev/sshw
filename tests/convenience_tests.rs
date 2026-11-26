use serde_json::{Value, json};
use std::io::Write;
use std::path::Path;
use std::process::{Command, Output, Stdio};

fn fixture() -> tempfile::TempDir {
    let temp = tempfile::Builder::new()
        .prefix("sshw convenience ")
        .tempdir()
        .unwrap();
    let mut servers = serde_json::Map::new();
    for (name, host) in [
        ("prod", "Example.COM"),
        ("prod space", "192.0.2.10"),
        ("prod'quote", "192.0.2.11"),
        ("prod;$(throw 'must-not-run')", "192.0.2.12"),
        ("-production", "192.0.2.13"),
        ("개발 서버", "DEV.example.com"),
    ] {
        servers.insert(name.into(), json!({"host":host,"port":22,"default_user":"deploy","accounts":{"deploy":{"auth":{"type":"agent"}},"ops account":{"auth":{"type":"agent"}}}}));
    }
    std::fs::write(
        temp.path().join("servers.json"),
        json!({"version":2,"credential_backend":"session_only","default":"prod","servers":servers})
            .to_string(),
    )
    .unwrap();
    temp
}

fn run(home: &Path, args: &[&str], input: &str) -> Output {
    let mut child = Command::new(env!("CARGO_BIN_EXE_sshw"))
        .env("SSHW_HOME", home)
        .env_remove("SSHW_PASSWORD")
        .env_remove("SSHW_PRIVILEGE_PASSWORD")
        .args(args)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    child
        .stdin
        .take()
        .unwrap()
        .write_all(input.as_bytes())
        .unwrap();
    child.wait_with_output().unwrap()
}

#[test]
fn server_filter_matches_names_and_hosts_literally_and_preserves_array_default_and_files() {
    let home = fixture();
    let path = home.path().join("servers.json");
    let bytes = std::fs::read(&path).unwrap();
    let mtime = std::fs::metadata(&path).unwrap().modified().unwrap();
    for (filter, expected) in [
        ("EXAMPLE.com", vec!["prod", "개발 서버"]),
        ("개발", vec!["개발 서버"]),
        ("prod space", vec!["prod space"]),
        ("192.0.2.11", vec!["prod'quote"]),
        (".*", vec![]),
        (
            "",
            vec![
                "-production",
                "prod",
                "prod space",
                "prod'quote",
                "prod;$(throw 'must-not-run')",
                "개발 서버",
            ],
        ),
    ] {
        let output = run(home.path(), &["list", "--filter", filter, "--json"], "");
        assert!(output.status.success());
        let rows: Vec<Value> = serde_json::from_slice(&output.stdout).unwrap();
        assert_eq!(
            rows.iter()
                .map(|row| row["name"].as_str().unwrap())
                .collect::<Vec<_>>(),
            expected
        );
        for row in rows {
            assert_eq!(row["is_default"], row["name"] == "prod");
        }
    }
    let output = run(home.path(), &["list", "--filter", "absent"], "");
    assert!(
        String::from_utf8(output.stdout)
            .unwrap()
            .contains("no matching servers")
    );
    let output = run(home.path(), &["list", "--filter", "Example"], "");
    assert!(
        String::from_utf8(output.stdout)
            .unwrap()
            .contains("* prod ")
    );
    assert_eq!(std::fs::read(&path).unwrap(), bytes);
    assert_eq!(std::fs::metadata(&path).unwrap().modified().unwrap(), mtime);
    assert!(!home.path().join("audit.jsonl").exists());
    assert!(!home.path().join(".sshw.lock").exists());
}

#[test]
fn password_cli_rotates_existing_account_without_confirmation_and_masks_input() {
    let home = fixture();
    let output = run(
        home.path(),
        &[
            "account",
            "add",
            "prod",
            "ops account",
            "--force",
            "--password-stdin",
            "--json",
        ],
        "old-fixture\n",
    );
    assert!(output.status.success());
    let output = run(
        home.path(),
        &[
            "password",
            "prod",
            "--user",
            "ops account",
            "--password-stdin",
            "--json",
        ],
        "new-fixture\n",
    );
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let body: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(body["action"], "password_updated");
    assert_eq!(body["user"], "ops account");
    assert!(
        body["warning"]
            .as_str()
            .unwrap()
            .contains("does not persist")
    );
    let config: Value =
        serde_json::from_slice(&std::fs::read(home.path().join("servers.json")).unwrap()).unwrap();
    assert_eq!(config["servers"]["prod"]["default_user"], "deploy");
    let audit = std::fs::read_to_string(home.path().join("audit.jsonl")).unwrap();
    let last: Value = serde_json::from_str(audit.lines().last().unwrap()).unwrap();
    assert_eq!(last["action"], "password");
    assert_eq!(last["server"], "prod");
    assert_eq!(last["user"], "ops account");
    for text in [String::from_utf8(output.stdout).unwrap(), audit] {
        assert!(!text.contains("new-fixture"));
    }
    let rejected = run(
        home.path(),
        &["password", "prod", "--password-stdin", "--json"],
        "unused\n",
    );
    assert_eq!(rejected.status.code(), Some(3));
    let usage = run(home.path(), &["password", "--json"], "");
    assert_eq!(usage.status.code(), Some(9));
}

#[test]
fn privilege_password_cli_keeps_agent_login_target_and_audit_purpose() {
    let home = fixture();
    let configured = run(
        home.path(),
        &[
            "privilege",
            "set",
            "prod",
            "--account",
            "ops account",
            "--method",
            "su",
            "--user",
            "service",
            "--password-stdin",
            "--json",
        ],
        "old-privilege\n",
    );
    assert!(configured.status.success());
    let output = run(
        home.path(),
        &[
            "password",
            "prod",
            "--user",
            "ops account",
            "--privilege",
            "--password-stdin",
            "--json",
        ],
        "new-privilege\n",
    );
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let result: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(result["action"], "privilege_password_updated");
    assert_eq!(result["purpose"], "privilege");
    assert_eq!(result["user"], "ops account");
    assert_eq!(result["target_user"], "service");
    assert!(
        result["warning"]
            .as_str()
            .unwrap()
            .contains("SSHW_PRIVILEGE_PASSWORD")
    );
    let config: Value =
        serde_json::from_slice(&std::fs::read(home.path().join("servers.json")).unwrap()).unwrap();
    assert_eq!(
        config["servers"]["prod"]["accounts"]["ops account"]["auth"]["type"],
        "agent"
    );
    assert_eq!(
        config["servers"]["prod"]["accounts"]["ops account"]["privilege"]["method"],
        "su"
    );
    assert_eq!(config["servers"]["prod"]["default_user"], "deploy");
    let audit = std::fs::read_to_string(home.path().join("audit.jsonl")).unwrap();
    let last: Value = serde_json::from_str(audit.lines().last().unwrap()).unwrap();
    assert_eq!(last["action"], "password");
    assert_eq!(last["user"], "ops account");
    assert_eq!(last["detail"], "privilege");
    assert!(
        !String::from_utf8(output.stdout)
            .unwrap()
            .contains("new-privilege")
    );
    assert!(!audit.contains("new-privilege"));
}

#[test]
fn removal_clears_grants_before_name_reuse_and_named_doctor_has_scoped_json() {
    for account_scope in [false, true] {
        let home = fixture();
        for args in [
            vec!["policy", "init"],
            vec!["policy", "allow", "account", "prod", "ops account"],
            vec!["policy", "allow", "command", "uptime"],
            vec!["policy", "enable"],
        ] {
            assert!(run(home.path(), &args, "").status.success());
        }
        assert!(
            run(
                home.path(),
                &[
                    "policy",
                    "check",
                    "prod",
                    "uptime",
                    "--user",
                    "ops account",
                    "--json"
                ],
                ""
            )
            .status
            .success()
        );
        let command = if account_scope {
            vec![
                "account",
                "remove",
                "prod",
                "ops account",
                "--yes",
                "--json",
            ]
        } else {
            vec!["remove", "prod", "--yes", "--json"]
        };
        let removed = run(home.path(), &command, "");
        assert!(removed.status.success());
        let value: Value = serde_json::from_slice(&removed.stdout).unwrap();
        assert_eq!(value["policy_rules_removed"], 1);
        assert_eq!(value["policy_changed"], true);
        let reuse = if account_scope {
            vec!["account", "add", "prod", "ops account", "--auth", "agent"]
        } else {
            vec!["rename", "prod space", "prod"]
        };
        assert!(run(home.path(), &reuse, "").status.success());
        let check = run(
            home.path(),
            &[
                "policy",
                "check",
                "prod",
                "uptime",
                "--user",
                "ops account",
                "--json",
            ],
            "",
        );
        assert_eq!(check.status.code(), Some(7));
        let diagnostic = run(home.path(), &["doctor", "prod", "--json"], "");
        assert!(diagnostic.status.success());
        let diagnostic: Value = serde_json::from_slice(&diagnostic.stdout).unwrap();
        assert_eq!(diagnostic["server"], "prod");
        assert_eq!(diagnostic["host_trust"].as_array().unwrap().len(), 1);
        assert_eq!(diagnostic["connection_tested"], false);
    }
}

#[test]
fn show_includes_all_account_settings_without_secret_or_policy_access_and_keeps_existing_json_fields()
 {
    let home = fixture();
    let path = home.path().join("servers.json");
    let mut config: Value = serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
    let resolved = sshw::home::ResolvedHome::ad_hoc(home.path(), "fixture".into());
    let key = resolved.namespace.new_account_credential_key(
        sshw::home::CredentialPurpose::Privilege,
        "prod",
        "ops account",
    );
    config["servers"]["prod"]["accounts"]["ops account"]["privilege"] =
        json!({"method":"su","user":"service","credential":key});
    config["servers"]["prod"]["accounts"]["deploy"]["privilege"] =
        json!({"method":"sudo","user":"daemon","no_password":true});
    config["servers"]["prod"]["accounts"]["token=account-marker"] = json!({"auth":{"type":"agent"},"privilege":{"method":"sudo","user":"password=target-marker","no_password":true}});
    std::fs::write(&path, config.to_string()).unwrap();
    let policy = home.path().join("policy.json");
    let trust = home.path().join("known_hosts");
    std::fs::write(&policy, "invalid policy is not queried").unwrap();
    std::fs::write(&trust, "invalid host approval is not queried").unwrap();
    let before = std::fs::read(&path).unwrap();
    let mtime = std::fs::metadata(&path).unwrap().modified().unwrap();
    let output = run(home.path(), &["show", "prod"], "");
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let human = String::from_utf8(output.stdout).unwrap();
    assert!(human.contains("* deploy auth=agent privilege=sudo -> daemon (no password)"));
    assert!(human.contains("ops account auth=agent privilege=su -> service (password)"));
    assert!(human.contains("<redacted> auth=agent privilege=sudo -> <redacted> (no password)"));
    assert!(!human.contains("account-marker"));
    assert!(!human.contains("target-marker"));
    assert!(!human.contains(&key));
    let output = run(home.path(), &["show", "prod", "--json"], "");
    assert!(output.status.success());
    let mut shown: Value = serde_json::from_slice(&output.stdout).unwrap();
    let accounts = shown.as_object_mut().unwrap().remove("accounts").unwrap();
    let listed = run(home.path(), &["account", "list", "prod", "--json"], "");
    assert_eq!(
        accounts,
        serde_json::from_slice::<Value>(&listed.stdout).unwrap()
    );
    shown.as_object_mut().unwrap().remove("ok");
    let listed = run(
        home.path(),
        &["list", "--filter", "Example.COM", "--json"],
        "",
    );
    let rows: Vec<Value> = serde_json::from_slice(&listed.stdout).unwrap();
    assert_eq!(
        shown,
        *rows.iter().find(|row| row["name"] == "prod").unwrap()
    );
    assert_eq!(std::fs::read(&path).unwrap(), before);
    assert_eq!(std::fs::metadata(&path).unwrap().modified().unwrap(), mtime);
    assert_eq!(
        std::fs::read_to_string(&policy).unwrap(),
        "invalid policy is not queried"
    );
    assert_eq!(
        std::fs::read_to_string(&trust).unwrap(),
        "invalid host approval is not queried"
    );
    assert!(!home.path().join("audit.jsonl").exists());
    assert!(!home.path().join(".sshw.lock").exists());
}

#[test]
fn completion_script_is_available_without_a_valid_home_or_config_and_queries_are_bounded_data() {
    use base64::{Engine, engine::general_purpose::STANDARD};
    let temp = tempfile::tempdir().unwrap();
    let missing = temp.path().join("missing home");
    let output = run(&missing, &["completions", "powershell"], "");
    assert!(output.status.success());
    assert!(
        String::from_utf8(output.stdout)
            .unwrap()
            .contains("Register-ArgumentCompleter -Native")
    );
    let encoded = STANDARD.encode(json!({"words":[],"word":"pa"}).to_string());
    let output = run(
        &missing,
        &["completions", "powershell", "--query"],
        &encoded,
    );
    assert!(output.status.success());
    let values: Vec<Value> = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(values[0]["value"], "password");
    assert!(!missing.exists());
    for input in ["not base64".to_owned(), "x".repeat(65537)] {
        assert!(
            !run(&missing, &["completions", "powershell", "--query"], &input)
                .status
                .success()
        );
    }
}

#[test]
#[cfg(windows)]
fn actual_powershell_tab_completion_preserves_quoted_values_exit_status_and_read_only_state() {
    let home = fixture();
    let path = home.path().join("servers.json");
    let before = std::fs::read(&path).unwrap();
    for shell in ["pwsh", "powershell"] {
        let output = Command::new(shell)
            .args([
                "-NoProfile",
                "-NonInteractive",
                "-ExecutionPolicy",
                "Bypass",
                "-File",
            ])
            .arg(
                Path::new(env!("CARGO_MANIFEST_DIR"))
                    .join("tests/fixtures/powershell_completion.ps1"),
            )
            .arg(env!("CARGO_BIN_EXE_sshw"))
            .arg(home.path())
            .env_remove("SSHW_HOME")
            .env_remove("SSHW_PASSWORD")
            .env_remove("SSHW_PRIVILEGE_PASSWORD")
            .stdin(Stdio::null())
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "{shell}: {}\n{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
        assert_eq!(std::fs::read(&path).unwrap(), before);
        assert!(!home.path().join("audit.jsonl").exists());
        assert!(!home.path().join(".sshw.lock").exists());
    }
}
