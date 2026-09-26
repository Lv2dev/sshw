use serde_json::{Value, json};
use std::io::Write;
use std::path::Path;
use std::process::{Command, Output, Stdio};

fn home() -> tempfile::TempDir {
    let home = tempfile::tempdir().unwrap();
    std::fs::write(
        home.path().join("servers.json"),
        json!({"version":2,"default":null,"servers":{},"credential_backend":"session_only"})
            .to_string(),
    )
    .unwrap();
    home
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

fn successful(home: &Path, args: &[&str], input: &str) -> Output {
    let result = run(home, args, input);
    assert!(
        result.status.success(),
        "args={args:?}, stdout={}, stderr={}",
        String::from_utf8_lossy(&result.stdout),
        String::from_utf8_lossy(&result.stderr)
    );
    result
}

fn add(home: &Path) {
    successful(
        home,
        &[
            "add",
            "web",
            "--host",
            "127.0.0.1",
            "--port",
            "2222",
            "--user",
            "deploy",
            "--auth",
            "agent",
        ],
        "",
    );
}

#[test]
fn explicit_profile_cannot_be_silently_shadowed_by_environment() {
    let home = home();
    add(home.path());
    let result = run(
        home.path(),
        &[
            "--profile",
            "nonexistent-usability-profile",
            "show",
            "web",
            "--json",
        ],
        "",
    );
    assert_eq!(result.status.code(), Some(3));
    let error: Value = serde_json::from_slice(&result.stdout).unwrap();
    assert!(
        error["error"]["message"]
            .as_str()
            .unwrap()
            .contains("SSHW_HOME")
    );
}

#[test]
fn same_endpoint_update_preserves_other_accounts_and_privilege() {
    let home = home();
    add(home.path());
    successful(
        home.path(),
        &["account", "add", "web", "auditor", "--auth", "agent"],
        "",
    );
    successful(
        home.path(),
        &["privilege", "set", "web", "--password-stdin"],
        "fixture-only\n",
    );
    let path = home.path().join("servers.json");
    let before: Value = serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
    successful(
        home.path(),
        &[
            "add",
            "web",
            "--host",
            "127.0.0.1",
            "--port",
            "2222",
            "--user",
            "deploy",
            "--auth",
            "agent",
            "--force",
        ],
        "",
    );
    let after: Value = serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
    assert_eq!(
        before["servers"]["web"]["accounts"],
        after["servers"]["web"]["accounts"]
    );
}

#[test]
fn endpoint_change_requires_explicit_replacement_before_mutation() {
    let home = home();
    add(home.path());
    let path = home.path().join("servers.json");
    let before = std::fs::read(&path).unwrap();
    let result = run(
        home.path(),
        &[
            "add",
            "web",
            "--host",
            "127.0.0.2",
            "--port",
            "2222",
            "--user",
            "deploy",
            "--auth",
            "agent",
            "--force",
            "--json",
        ],
        "",
    );
    assert_eq!(result.status.code(), Some(3));
    assert_eq!(before, std::fs::read(&path).unwrap());
    assert!(String::from_utf8_lossy(&result.stdout).contains("--replace"));
}

#[test]
fn update_confirmation_names_the_option_that_command_accepts() {
    let home = home();
    add(home.path());
    let args = [
        "add",
        "web",
        "--host",
        "127.0.0.1",
        "--port",
        "2222",
        "--user",
        "deploy",
        "--auth",
        "agent",
    ];
    let result = run(home.path(), &args, "");
    assert_eq!(result.status.code(), Some(3));
    let message = String::from_utf8_lossy(&result.stderr);
    assert!(message.contains("--force"), "{message}");
    assert!(!message.contains("--yes"), "{message}");
    let mut confirmed = args.to_vec();
    confirmed.push("--force");
    successful(home.path(), &confirmed, "");
}

#[test]
fn first_use_has_default_port_and_next_steps_without_changing_json_list() {
    let home = home();
    let empty = successful(home.path(), &["list"], "");
    assert!(String::from_utf8_lossy(&empty.stdout).contains("sshw add"));
    let json_list = successful(home.path(), &["list", "--json"], "");
    assert_eq!(
        serde_json::from_slice::<Value>(&json_list.stdout).unwrap(),
        json!([])
    );
    let added = successful(
        home.path(),
        &[
            "add",
            "web",
            "--host",
            "127.0.0.1",
            "--user",
            "deploy",
            "--auth",
            "agent",
        ],
        "",
    );
    assert!(String::from_utf8_lossy(&added.stdout).contains("sshw trust"));
    let shown = successful(home.path(), &["show", "web", "--json"], "");
    assert_eq!(
        serde_json::from_slice::<Value>(&shown.stdout).unwrap()["port"],
        22
    );
}

#[test]
fn policy_management_and_checks_need_no_connection_or_credentials() {
    let home = home();
    add(home.path());
    successful(home.path(), &["policy", "init", "--json"], "");
    successful(
        home.path(),
        &["policy", "allow", "command", "echo", "--json"],
        "",
    );
    successful(
        home.path(),
        &["policy", "allow", "command", "echo", "--json"],
        "",
    );
    successful(home.path(), &["policy", "enable", "--json"], "");
    let allowed = successful(
        home.path(),
        &["policy", "check", "web", "echo hello", "--json"],
        "",
    );
    let value: Value = serde_json::from_slice(&allowed.stdout).unwrap();
    assert_eq!(value["allowed"], true);
    assert_eq!(value["connection_tested"], false);
    let denied = run(
        home.path(),
        &["policy", "check", "web", "echo hello | cat", "--json"],
        "",
    );
    assert_eq!(denied.status.code(), Some(7));
    let show = successful(home.path(), &["policy", "show", "--json"], "");
    assert_eq!(
        serde_json::from_slice::<Value>(&show.stdout).unwrap()["policy"]["allow_commands"],
        json!(["echo"])
    );
    successful(
        home.path(),
        &["policy", "remove", "command", "echo", "--json"],
        "",
    );
    assert_eq!(
        run(
            home.path(),
            &["policy", "check", "web", "echo hello", "--json"],
            ""
        )
        .status
        .code(),
        Some(7)
    );
    successful(home.path(), &["policy", "disable", "--json"], "");
    successful(
        home.path(),
        &["policy", "check", "web", "echo hello", "--json"],
        "",
    );
    let audit = std::fs::read_to_string(home.path().join("audit.jsonl")).unwrap();
    assert!(!audit.contains("echo hello"));
    assert!(audit.contains("\"action\":\"policy\""));
    for kind in ["put", "get"] {
        successful(
            home.path(),
            &["policy", "allow", kind, "remote:/srv/app"],
            "",
        );
        let shown = successful(home.path(), &["policy", "show", "--json"], "");
        let shown: Value = serde_json::from_slice(&shown.stdout).unwrap();
        assert_eq!(
            shown["policy"][format!("allow_{kind}_paths")],
            json!(["/srv/app"])
        );
        assert_eq!(
            run(
                home.path(),
                &["policy", "allow", kind, "remote:/srv/../etc", "--json"],
                ""
            )
            .status
            .code(),
            Some(7)
        );
        successful(
            home.path(),
            &["policy", "remove", kind, "remote:/srv/app"],
            "",
        );
    }
}

#[test]
fn policy_mutation_rejects_corruption_and_preserves_existing_file() {
    let home = home();
    let path = home.path().join("policy.json");
    let contents = r#"{"enabled":false,"allow_comands":[]}"#;
    std::fs::write(&path, contents).unwrap();
    for command in ["init", "enable", "disable"] {
        assert_eq!(
            run(home.path(), &["policy", command, "--json"], "")
                .status
                .code(),
            Some(7)
        );
        assert_eq!(std::fs::read_to_string(&path).unwrap(), contents);
    }
}

#[test]
fn policy_checks_all_restrictions_and_validates_account_entries() {
    let home = home();
    add(home.path());
    successful(
        home.path(),
        &["account", "add", "web", "auditor", "--auth", "agent"],
        "",
    );
    successful(home.path(), &["policy", "init"], "");
    successful(home.path(), &["policy", "allow", "command", "rm"], "");
    successful(home.path(), &["policy", "enable"], "");
    let blocked = run(
        home.path(),
        &[
            "policy",
            "check",
            "web",
            "rm -rf /tmp/fixture",
            "--user",
            "auditor",
            "--json",
        ],
        "",
    );
    assert_eq!(blocked.status.code(), Some(2));
    assert_eq!(
        serde_json::from_slice::<Value>(&blocked.stdout).unwrap()["reasons"]
            .as_array()
            .unwrap()
            .len(),
        2
    );
    assert_eq!(
        run(
            home.path(),
            &["policy", "allow", "account", "web", "missing", "--json"],
            ""
        )
        .status
        .code(),
        Some(3)
    );
    successful(
        home.path(),
        &["policy", "allow", "account", "web", "auditor"],
        "",
    );
    successful(
        home.path(),
        &[
            "policy",
            "check",
            "web",
            "rm -rf /tmp/fixture",
            "--user",
            "auditor",
            "--yes",
            "--json",
        ],
        "",
    );
}

#[test]
fn policy_json_remains_valid_when_redacting_a_rule() {
    let home = home();
    successful(home.path(), &["policy", "init"], "");
    let result = successful(
        home.path(),
        &[
            "policy",
            "allow",
            "command",
            "echo password=fixture-secret",
            "--json",
        ],
        "",
    );
    let value: Value = serde_json::from_slice(&result.stdout).unwrap();
    assert_eq!(value["ok"], true);
    assert!(!String::from_utf8_lossy(&result.stdout).contains("fixture-secret"));
}

#[test]
fn doctor_distinguishes_diagnostic_success_from_local_readiness() {
    let home = home();
    std::fs::write(home.path().join("policy.json"), "{invalid").unwrap();
    let result = successful(home.path(), &["doctor", "--json"], "");
    let value: Value = serde_json::from_slice(&result.stdout).unwrap();
    assert_eq!(value["ok"], true);
    assert_eq!(value["local_checks_passed"], false);
    assert_eq!(value["connection_tested"], false);
    assert!(
        value["policy_message"]
            .as_str()
            .unwrap()
            .contains("invalid policy file")
    );
    assert!(
        value["issues"]
            .as_array()
            .unwrap()
            .iter()
            .any(|issue| issue["kind"] == "policy" && issue["next_step"].is_string())
    );
}

#[test]
fn defaults_offer_json_and_unknown_target_explains_quoting() {
    let home = home();
    add(home.path());
    for args in [
        vec!["default", "web", "--json"],
        vec!["default", "--json"],
        vec!["account", "default", "web", "deploy", "--json"],
    ] {
        let result = successful(home.path(), &args, "");
        assert_eq!(
            serde_json::from_slice::<Value>(&result.stdout).unwrap()["ok"],
            true
        );
    }
    let result = run(home.path(), &["run", "echo", "hello", "--json"], "");
    assert_eq!(result.status.code(), Some(3));
    assert!(String::from_utf8_lossy(&result.stdout).contains("Quote the whole remote command"));
}

#[test]
fn upload_modes_and_passwordless_elevation_reject_invalid_combinations() {
    let home = home();
    for mode in ["7777", "888", "755;echo", "-1"] {
        assert_eq!(
            run(
                home.path(),
                &["put", "web", "file", "/tmp/file", "--mode", mode, "--json"],
                ""
            )
            .status
            .code(),
            Some(9)
        );
    }
    assert_eq!(
        run(
            home.path(),
            &["run", "web", "id", "--no-password", "--json"],
            ""
        )
        .status
        .code(),
        Some(9)
    );
    add(home.path());
    successful(
        home.path(),
        &[
            "policy",
            "check",
            "web",
            "id",
            "--as-root",
            "--no-password",
            "--json",
        ],
        "",
    );
    successful(
        home.path(),
        &[
            "privilege",
            "set",
            "web",
            "--method",
            "su",
            "--password-stdin",
        ],
        "fixture-only\n",
    );
    assert_eq!(
        run(
            home.path(),
            &["run", "web", "id", "--as-root", "--no-password", "--json"],
            ""
        )
        .status
        .code(),
        Some(3)
    );
}
