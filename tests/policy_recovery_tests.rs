use serde_json::{Value, json};
use std::path::Path;
use std::process::{Command, Output};

fn cli(home: &Path, args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_sshw"))
        .env("SSHW_HOME", home)
        .env_remove("SSHW_PASSWORD")
        .args(args)
        .output()
        .unwrap()
}
fn run_copy(command: &str) -> Output {
    let binary = Path::new(env!("CARGO_BIN_EXE_sshw"));
    let mut paths = vec![binary.parent().unwrap().to_path_buf()];
    paths.extend(std::env::split_paths(
        &std::env::var_os("PATH").unwrap_or_default(),
    ));
    let mut shell = if cfg!(windows) {
        let mut c = Command::new("powershell");
        c.args(["-NoProfile", "-NonInteractive", "-Command", command]);
        c
    } else {
        let mut c = Command::new("sh");
        c.args(["-c", command]);
        c
    };
    shell
        .env("PATH", std::env::join_paths(paths).unwrap())
        .env_remove("SSHW_HOME")
        .output()
        .unwrap()
}
fn fixture() -> tempfile::TempDir {
    let home = tempfile::Builder::new()
        .prefix("sshw policy's $scope; ")
        .tempdir()
        .unwrap();
    std::fs::write(home.path().join("servers.json"),json!({"version":2,"credential_backend":"session_only","default":"web","servers":{"web":{"host":"192.0.2.10","port":22,"default_user":"deploy","accounts":{"deploy":{"auth":{"type":"agent"}},"ops account":{"auth":{"type":"agent"}}}}}}).to_string()).unwrap();
    std::fs::write(home.path().join("source"), "payload").unwrap();
    home
}

#[test]
fn copyable_policy_recovery_grants_only_on_explicit_execution_then_preflight_passes() {
    for (category, value, scope) in [
        ("command", "uptime", "whole program"),
        ("command", "echo 'a b;$(whoami)'", "exact full command"),
        ("put", "/tmp/app's file", "descendants"),
        ("get", "/tmp/app's file", "descendants"),
        ("get", "C:\\Deploy\\app's file", "descendants"),
        ("get", "\\\\host\\share\\app's file", "descendants"),
        ("account", "ops account", "registered server/login"),
    ] {
        let home = fixture();
        let policy = home.path().join("policy.json");
        std::fs::write(&policy,json!({"version":2,"enabled":true,"allow_commands":if category=="account" {vec!["uptime"]} else {vec![]}}).to_string()).unwrap();
        let local = home.path().join("source");
        let downloaded = home.path().join("download");
        let args = match category {
            "put" => vec![
                "policy",
                "--json",
                "check-put",
                "web",
                local.to_str().unwrap(),
                value,
            ],
            "get" => vec![
                "policy",
                "--json",
                "check-get",
                "web",
                value,
                downloaded.to_str().unwrap(),
            ],
            "account" => vec![
                "policy", "--json", "check", "web", "uptime", "--user", value,
            ],
            _ => vec!["policy", "--json", "check", "web", value],
        };
        let before = std::fs::read(&policy).unwrap();
        let blocked = cli(home.path(), &args);
        assert_eq!(blocked.status.code(), Some(7), "{blocked:?}");
        let json: Value = serde_json::from_slice(&blocked.stdout).unwrap();
        assert_eq!(json["allowed"], false);
        assert_eq!(json["suggestions"][0]["kind"], category);
        assert!(
            json["suggestions"][0]["scope"]
                .as_str()
                .unwrap()
                .contains(scope)
        );
        let command = json["suggestions"][0]["command"].as_str().unwrap();
        assert!(command.contains("--home="));
        assert!(command.contains(" -- "));
        assert_eq!(std::fs::read(&policy).unwrap(), before);
        assert!(!home.path().join("audit.jsonl").exists());
        let applied = run_copy(command);
        assert!(
            applied.status.success(),
            "command={command}, stderr={}",
            String::from_utf8_lossy(&applied.stderr)
        );
        let allowed = cli(home.path(), &args);
        assert_eq!(
            allowed.status.code(),
            Some(0),
            "{}",
            String::from_utf8_lossy(&allowed.stdout)
        );
        let json: Value = serde_json::from_slice(&allowed.stdout).unwrap();
        assert_eq!(json["allowed"], true);
        assert!(json.get("suggestions").is_none());
        let saved: Value = serde_json::from_slice(&std::fs::read(policy).unwrap()).unwrap();
        assert_eq!(saved["enabled"], true);
        assert_eq!(
            saved[match category {
                "command" => "allow_commands",
                "put" => "allow_put_paths",
                "get" => "allow_get_paths",
                _ => "allow_accounts",
            }]
            .as_array()
            .unwrap()
            .len(),
            1
        );
    }
}

#[test]
#[cfg(target_os = "linux")]
fn copied_global_policy_grant_targets_the_same_policy_from_a_project() {
    let temp = fixture();
    let binary = Path::new(env!("CARGO_BIN_EXE_sshw"));
    let config = std::fs::read(temp.path().join("servers.json")).unwrap();
    let config_dir = temp.path().join("config");
    let base = config_dir.join("sshw");
    let project_dir = temp.path().join("project");
    let project = project_dir.join(".sshw");
    let project_policy = project.join("policy.json");
    std::fs::create_dir_all(&project).unwrap();
    std::fs::write(project.join("servers.json"), &config).unwrap();
    std::fs::write(
        project.join("project.json"),
        r#"{"version":1,"servers":"local","policy":"local"}"#,
    )
    .unwrap();
    std::fs::write(
        &project_policy,
        r#"{"enabled":true,"allow_commands":["whoami"]}"#,
    )
    .unwrap();
    let project_before = std::fs::read(&project_policy).unwrap();
    let call = |mut cmd: Command| {
        cmd.current_dir(&project_dir)
            .env("XDG_CONFIG_HOME", &config_dir)
            .env("SSHW_HOME", &project)
            .env_remove("SSHW_PASSWORD")
            .output()
            .unwrap()
    };
    for explicit_default in [false, true] {
        let global = if explicit_default {
            temp.path().join("named home")
        } else {
            base.join("profiles/default")
        };
        std::fs::create_dir_all(&global).unwrap();
        if explicit_default {
            std::fs::write(base.join("profiles.json"), json!({"version":1,"default":"named","profiles":{"named":{"id":"p_named","home":global}}}).to_string()).unwrap();
        }
        std::fs::write(global.join("servers.json"), &config).unwrap();
        let policy = global.join("policy.json");
        std::fs::write(
            &policy,
            r#"{"enabled":false,"allow_commands":["hostname"]}"#,
        )
        .unwrap();
        let before = std::fs::read(&policy).unwrap();
        let invoke = |args: &[&str]| {
            let mut cmd = Command::new(binary);
            cmd.args(["--global", "--policy"]).args(args);
            call(cmd)
        };
        for args in [
            ["run", "uptime", "--json"].as_slice(),
            ["policy", "check", "uptime", "--json"].as_slice(),
        ] {
            let denied = invoke(args);
            assert_eq!(denied.status.code(), Some(7), "{denied:?}");
            let body: Value = serde_json::from_slice(&denied.stdout).unwrap();
            assert_eq!(
                body["suggestions"][0]["command"],
                "sshw --global --policy policy allow command -- 'uptime'"
            );
            assert_eq!(std::fs::read(&policy).unwrap(), before);
        }
        let mut shell = Command::new("sh");
        shell.env(
            "PATH",
            std::env::join_paths(
                std::iter::once(binary.parent().unwrap().to_path_buf()).chain(
                    std::env::split_paths(&std::env::var_os("PATH").unwrap_or_default()),
                ),
            )
            .unwrap(),
        );
        let denied = invoke(&["policy", "check", "uptime", "--json"]);
        let body: Value = serde_json::from_slice(&denied.stdout).unwrap();
        shell.args(["-c", body["suggestions"][0]["command"].as_str().unwrap()]);
        let applied = call(shell);
        assert!(applied.status.success(), "{applied:?}");
        let value: Value = serde_json::from_slice(&std::fs::read(&policy).unwrap()).unwrap();
        assert_eq!(value["allow_commands"], json!(["hostname", "uptime"]));
        assert_eq!(value["enabled"], false);
        assert_eq!(std::fs::read(&project_policy).unwrap(), project_before);
        assert!(
            invoke(&["policy", "check", "uptime", "--json"])
                .status
                .success()
        );
        assert!(!global.join("known_hosts").exists());
        assert!(!project.join("audit.jsonl").exists());
    }
}

#[test]
fn execution_denials_have_recovery_but_safety_invalid_policy_and_sensitive_values_do_not_offer_grants()
 {
    let home = fixture();
    let path = home.path().join("policy.json");
    std::fs::write(&path, r#"{"version":2,"enabled":true}"#).unwrap();
    let blocked = cli(home.path(), &["run", "web", "uptime", "--json"]);
    assert_eq!(blocked.status.code(), Some(7));
    let json: Value = serde_json::from_slice(&blocked.stdout).unwrap();
    assert_eq!(json["suggestions"][0]["kind"], "command");
    assert!(
        json["error"]["message"]
            .as_str()
            .unwrap()
            .contains("permission scope")
    );
    let local = home.path().join("source");
    for args in [
        vec!["run", "web", "rm -rf /tmp/x", "--json"],
        vec!["put", "web", local.to_str().unwrap(), "/etc/x", "--json"],
    ] {
        let result = cli(home.path(), &args);
        assert_eq!(result.status.code(), Some(2));
        let json: Value = serde_json::from_slice(&result.stdout).unwrap();
        assert!(json.get("suggestions").is_none());
    }
    for value in [
        "echo token=private-marker",
        "echo a\nb",
        "echo end\n",
        "\tuptime",
        "*",
    ] {
        let result = cli(home.path(), &["policy", "--json", "check", "web", value]);
        let json: Value = serde_json::from_slice(&result.stdout).unwrap();
        assert!(json["suggestions"][0]["command"].is_null());
        assert!(!String::from_utf8_lossy(&result.stdout).contains("private-marker"));
    }
    for path_value in ["/", "/tmp/../etc/x", " /tmp/x "] {
        let result = cli(
            home.path(),
            &["policy", "--json", "check-get", "web", path_value, "unused"],
        );
        let json: Value = serde_json::from_slice(&result.stdout).unwrap();
        assert!(json["suggestions"][0]["command"].is_null());
    }
    std::fs::write(&path, "{broken").unwrap();
    let result = cli(home.path(), &["run", "web", "uptime", "--json"]);
    assert_eq!(result.status.code(), Some(7));
    let json: Value = serde_json::from_slice(&result.stdout).unwrap();
    assert!(json.get("suggestions").is_none());
}
