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
fn upload_diagnostics_reject_missing_files_and_directories_locally() {
    let home = home();
    add(home.path());
    let missing = home.path().join("missing.txt");
    for (local, message) in [
        (missing.as_path(), "local file not found"),
        (home.path(), "not a regular file"),
    ] {
        for prefix in [vec!["put"], vec!["policy", "check-put"]] {
            let mut args = prefix;
            args.extend(["web", local.to_str().unwrap(), "/tmp/file", "--json"]);
            let output = run(home.path(), &args, "");
            assert_eq!(
                output.status.code(),
                Some(6),
                "{args:?}: {}",
                String::from_utf8_lossy(&output.stdout)
            );
            assert!(String::from_utf8_lossy(&output.stdout).contains(message));
            if args[0] == "policy" {
                let value: Value = serde_json::from_slice(&output.stdout).unwrap();
                assert_eq!(value["access_allowed"], true);
                assert_eq!(value["allowed"], false);
                assert_eq!(value["local_file_checked"], true);
                assert_eq!(value["local_file_ready"], false);
            }
        }
    }
}

#[test]
fn transfer_preflight_and_execution_choose_the_same_first_failure() {
    let home = home();
    add(home.path());
    successful(home.path(), &["policy", "init"], "");
    successful(home.path(), &["policy", "allow", "get", "/allowed"], "");
    successful(home.path(), &["policy", "enable"], "");
    let existing = home.path().join("existing");
    std::fs::write(&existing, "original").unwrap();
    for (operation, check, operands, expected) in [
        ("put", "check-put", ["missing-local", "/blocked/file"], 7),
        (
            "get",
            "check-get",
            ["/blocked/file", existing.to_str().unwrap()],
            7,
        ),
        (
            "get",
            "check-get",
            ["/allowed/file", existing.to_str().unwrap()],
            6,
        ),
    ] {
        for mut prefix in [vec![operation], vec!["policy", check]] {
            prefix.extend([
                "web",
                operands[0],
                operands[1],
                "--user",
                "missing-user",
                "--json",
            ]);
            let output = run(home.path(), &prefix, "");
            assert_eq!(
                output.status.code(),
                Some(expected),
                "{prefix:?}: {}",
                String::from_utf8_lossy(&output.stdout)
            );
        }
    }
}

#[test]
fn transfer_preflight_checks_the_same_paths_without_connecting() {
    let home = home();
    add(home.path());
    successful(home.path(), &["policy", "init"], "");
    successful(home.path(), &["policy", "allow", "put", "/srv/app"], "");
    successful(home.path(), &["policy", "allow", "get", "/var/log/app"], "");
    successful(home.path(), &["policy", "enable"], "");
    let local = home.path().join("input.txt");
    std::fs::write(&local, "fixture").unwrap();
    let result = successful(
        home.path(),
        &[
            "policy",
            "check-put",
            "web",
            local.to_str().unwrap(),
            "remote:/srv/app/file",
            "--json",
        ],
        "",
    );
    let value: Value = serde_json::from_slice(&result.stdout).unwrap();
    assert_eq!(value["allowed"], true);
    assert_eq!(value["local_file_checked"], true);
    assert_eq!(value["local_file_ready"], true);
    assert_eq!(value["connection_tested"], false);
    assert_eq!(value["credentials_checked"], false);
    for command in [vec!["policy", "check-put"], vec!["put"]] {
        let mut args = command;
        args.extend(["web", local.to_str().unwrap(), "/blocked/file", "--json"]);
        let result = run(home.path(), &args, "");
        assert_eq!(result.status.code(), Some(7));
    }
    let result = run(
        home.path(),
        &[
            "policy",
            "check-get",
            "web",
            "/var/log/app/file",
            local.to_str().unwrap(),
            "--json",
        ],
        "",
    );
    assert_eq!(result.status.code(), Some(6));
    successful(
        home.path(),
        &[
            "policy",
            "check-get",
            "web",
            "/var/log/app/file",
            local.to_str().unwrap(),
            "--yes",
            "--json",
        ],
        "",
    );
}

#[test]
fn streaming_json_is_rejected_before_running_a_command() {
    let home = home();
    let result = run(
        home.path(),
        &["run", "web", "uptime", "--stream", "--json"],
        "",
    );
    assert_eq!(result.status.code(), Some(9));
    let value: Value = serde_json::from_slice(&result.stdout).unwrap();
    assert!(
        value["error"]["message"]
            .as_str()
            .unwrap()
            .contains("cannot be used")
    );
}

#[test]
fn atomic_upload_still_obeys_path_policy_before_connecting() {
    let home = home();
    add(home.path());
    successful(home.path(), &["policy", "init"], "");
    successful(home.path(), &["policy", "enable"], "");
    let result = run(
        home.path(),
        &[
            "put",
            "web",
            "missing.txt",
            "/tmp/file",
            "--atomic",
            "--json",
        ],
        "",
    );
    assert_eq!(result.status.code(), Some(7));
}

#[test]
fn atomic_preflight_requires_parent_directory_and_preserves_existing_policy() {
    let home = home();
    add(home.path());
    let local = home.path().join("file");
    std::fs::write(&local, "fixture").unwrap();
    successful(home.path(), &["policy", "init"], "");
    successful(
        home.path(),
        &["policy", "allow", "put", "/srv/app/file"],
        "",
    );
    successful(home.path(), &["policy", "enable"], "");
    successful(
        home.path(),
        &[
            "policy",
            "check-put",
            "web",
            local.to_str().unwrap(),
            "/srv/app/file",
            "--json",
        ],
        "",
    );
    for args in [vec!["policy", "check-put"], vec!["put"]] {
        let mut args = args;
        args.extend([
            "web",
            local.to_str().unwrap(),
            "/srv/app/file",
            "--atomic",
            "--json",
        ]);
        let output = run(home.path(), &args, "");
        assert_eq!(output.status.code(), Some(7));
        assert!(String::from_utf8_lossy(&output.stdout).contains("parent-directory"));
    }
    successful(home.path(), &["policy", "allow", "put", "/srv/app"], "");
    successful(
        home.path(),
        &[
            "policy",
            "check-put",
            "web",
            local.to_str().unwrap(),
            "/srv/app/file",
            "--atomic",
            "--json",
        ],
        "",
    );
}

#[test]
fn streaming_su_is_rejected_without_loading_privilege_credentials() {
    let home = home();
    add(home.path());
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
    let output = run(
        home.path(),
        &["run", "web", "uptime", "--as-root", "--stream"],
        "",
    );
    assert_eq!(output.status.code(), Some(9));
    assert!(String::from_utf8_lossy(&output.stderr).contains("su PTY"));
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
fn passwordless_privilege_cli_needs_no_stdin_and_rejects_conflicting_options() {
    let home = home();
    add(home.path());
    let path = home.path().join("servers.json");
    let initial = std::fs::read(&path).unwrap();
    for flags in [vec!["--method", "su"], vec!["--password-stdin"]] {
        let mut args = vec!["privilege", "set", "web", "--no-password", "--json"];
        args.extend(flags);
        let output = run(home.path(), &args, "");
        assert_eq!(output.status.code(), Some(9));
        assert_eq!(std::fs::read(&path).unwrap(), initial);
    }
    let output = successful(
        home.path(),
        &[
            "privilege",
            "set",
            "web",
            "--user",
            "service",
            "--no-password",
            "--json",
        ],
        "",
    );
    let value: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(value["no_password"], true);
    assert!(
        value.get("warning").is_none(),
        "passwordless settings need no password environment variable"
    );
    assert!(value["credential"].is_null());
    let stored: Value = serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
    assert!(
        stored["servers"]["web"]["accounts"]["deploy"]["privilege"]
            .get("credential")
            .is_none()
    );
    successful(home.path(), &["privilege", "clear", "web", "--yes"], "");
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
