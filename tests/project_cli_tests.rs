use sshw::config::{AuthConfig, ServerConfig, SshwConfig, save_config};
use std::collections::BTreeMap;
use std::path::Path;
use std::process::{Command, Output};

fn run(cwd: &Path, args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_sshw"))
        .current_dir(cwd)
        .args(args)
        .env_remove("SSHW_HOME")
        .env_remove("SSHW_PASSWORD")
        .env_remove("SSHW_PRIVILEGE_PASSWORD")
        .output()
        .unwrap()
}
fn local_fixture(cwd: &Path) {
    let root = cwd.join(".sshw");
    std::fs::create_dir_all(&root).unwrap();
    save_config(
        &root.join("servers.json"),
        &SshwConfig {
            credential_backend: sshw::config::CredentialBackend::SessionOnly,
            default: Some("local".into()),
            servers: BTreeMap::from([(
                "local".into(),
                ServerConfig::single_account("192.0.2.10", 22, "deploy", AuthConfig::Agent),
            )]),
            ..Default::default()
        },
    )
    .unwrap();
    std::fs::write(
        root.join("policy.json"),
        r#"{"enabled":true,"allow_commands":["uptime"]}"#,
    )
    .unwrap();
    std::fs::write(
        root.join("project.json"),
        r#"{"version":1,"servers":"local","policy":"local"}"#,
    )
    .unwrap();
}

#[test]
fn missing_project_recovery_keeps_the_explicit_directory_instead_of_cwd() {
    let temp = tempfile::Builder::new()
        .prefix("sshw project's $scope; ")
        .tempdir()
        .unwrap();
    let target = temp.path().join("app");
    let elsewhere = temp.path().join("elsewhere");
    std::fs::create_dir(&target).unwrap();
    std::fs::create_dir(&elsewhere).unwrap();
    let output = run(
        &elsewhere,
        &["--project-dir", target.to_str().unwrap(), "list", "--json"],
    );
    assert_eq!(output.status.code(), Some(3));
    let body: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    let message = body["error"]["message"].as_str().unwrap();
    assert!(message.contains("sshw --project-dir="), "{message}");
    assert!(message.contains(" project init"), "{message}");
    assert!(message.contains("app"), "{message}");
    assert_eq!(std::fs::read_dir(&target).unwrap().count(), 0);
    assert_eq!(std::fs::read_dir(&elsewhere).unwrap().count(), 0);
}

fn copy_from(cwd: &Path, command: &str) -> Output {
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
        .current_dir(cwd)
        .env("PATH", std::env::join_paths(paths).unwrap())
        .env("SSHW_HOME", cwd.join("unused"))
        .env_remove("SSHW_PASSWORD")
        .env_remove("SSHW_PRIVILEGE_PASSWORD")
        .output()
        .unwrap()
}

#[test]
fn missing_default_recovery_keeps_the_selected_project_from_another_directory() {
    let temp = tempfile::Builder::new()
        .prefix("default's $scope; ")
        .tempdir()
        .unwrap();
    let target = temp.path().join("target");
    let elsewhere = temp.path().join("elsewhere");
    local_fixture(&target);
    local_fixture(&elsewhere);
    let path = target.join(".sshw/servers.json");
    let decoy = elsewhere.join(".sshw/servers.json");
    let decoy_before = std::fs::read(&decoy).unwrap();
    let mut config = sshw::config::load_config(&path).unwrap();
    config.default = None;
    save_config(&path, &config).unwrap();
    let before = std::fs::read(&path).unwrap();
    let mut default_command = None;
    for tail in [
        &["default", "--json"][..],
        &["run", "uptime", "--json"][..],
        &["policy", "check", "uptime", "--json"][..],
    ] {
        let mut args = vec!["--project-dir", target.to_str().unwrap(), "--policy"];
        args.extend_from_slice(tail);
        let output = run(&elsewhere, &args);
        assert_eq!(output.status.code(), Some(3), "{output:?}");
        let body: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
        let msg = body["error"]["message"].as_str().unwrap();
        let list = msg
            .split('`')
            .find(|part| part.ends_with(" --policy list"))
            .unwrap_or_else(|| panic!("{msg}"));
        let command = msg
            .split('`')
            .find(|part| part.contains(" --policy default -- "))
            .unwrap_or_else(|| panic!("{msg}"));
        assert!(list.starts_with("sshw --project-dir="));
        assert!(command.starts_with("sshw --project-dir="));
        let listed = copy_from(&elsewhere, &format!("{list} --json"));
        assert!(listed.status.success(), "{listed:?}");
        let entries: serde_json::Value = serde_json::from_slice(&listed.stdout).unwrap();
        assert_eq!(entries[0]["is_default"], false);
        assert_eq!(std::fs::read(&path).unwrap(), before);
        default_command = Some(command.replace("<registered-server>", "local"));
    }
    let applied = copy_from(&elsewhere, &default_command.unwrap());
    assert!(applied.status.success(), "{applied:?}");
    assert_eq!(
        sshw::config::load_config(&path).unwrap().default.as_deref(),
        Some("local")
    );
    assert_eq!(std::fs::read(decoy).unwrap(), decoy_before);
    assert!(!target.join(".sshw/known_hosts").exists());
    assert!(!elsewhere.join("unused").exists());
}

#[test]
fn missing_local_server_list_suggests_initializing_the_selected_project_only() {
    let temp = tempfile::Builder::new()
        .prefix("repair project's $scope; ")
        .tempdir()
        .unwrap();
    let target = temp.path().join("target");
    let elsewhere = temp.path().join("elsewhere");
    local_fixture(&target);
    local_fixture(&elsewhere);
    let root = target.join(".sshw");
    let policy = root.join("policy.json");
    let before = std::fs::read(&policy).unwrap();
    let decoy = elsewhere.join(".sshw/servers.json");
    let decoy_before = std::fs::read(&decoy).unwrap();
    std::fs::remove_file(root.join("servers.json")).unwrap();
    let args = ["--project-dir", target.to_str().unwrap(), "list", "--json"];
    let output = run(&elsewhere, &args);
    assert_eq!(output.status.code(), Some(3), "{output:?}");
    let body: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    let message = body["error"]["message"].as_str().unwrap();
    let command = message
        .split('`')
        .find(|part| part.contains(" project init "))
        .unwrap_or_else(|| panic!("{message}"));
    assert!(command.starts_with("sshw --project-dir="));
    assert!(command.ends_with(" --servers-source local"));
    assert!(message.contains("empty server list"));
    assert!(!root.join("servers.json").exists());
    assert!(!root.join(".sshw.lock").exists());

    let initialized = copy_from(&elsewhere, command);
    assert!(initialized.status.success(), "{initialized:?}; {command}");
    let listed = run(&elsewhere, &args);
    assert!(listed.status.success(), "{listed:?}");
    assert_eq!(listed.stdout, b"[]\n");
    assert_eq!(std::fs::read(policy).unwrap(), before);
    assert_eq!(std::fs::read(decoy).unwrap(), decoy_before);
    assert!(!elsewhere.join("unused").exists());
}

#[test]
fn missing_policy_recovery_preserves_an_explicit_project_baseline() {
    let temp = tempfile::tempdir().unwrap();
    let project = temp.path().join("project");
    local_fixture(&project);
    let local_path = project.join(".sshw/policy.json");
    std::fs::remove_file(&local_path).unwrap();
    let baseline = temp.path().join("baseline");
    std::fs::create_dir(&baseline).unwrap();
    let policy = baseline.join("policy.json");
    let original = r#"{"enabled":true,"allow_commands":["hostname"]}"#;
    std::fs::write(&policy, original).unwrap();
    let output = run(
        &project,
        &[
            "--home",
            baseline.to_str().unwrap(),
            "project",
            "status",
            "--json",
        ],
    );
    assert_eq!(output.status.code(), Some(3), "{output:?}");
    let response: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    let message = response["error"]["message"].as_str().unwrap();
    assert!(
        message.contains("--policy-source local")
            && message.contains("same home/profile selection"),
        "{message}"
    );
    assert!(!message.contains("sshw --project-dir"), "{message}");
    assert!(!local_path.exists());
    assert!(!project.join(".sshw/audit.jsonl").exists());

    let initialized = run(
        &project,
        &[
            "--home",
            baseline.to_str().unwrap(),
            "project",
            "init",
            "--policy-source",
            "local",
            "--json",
        ],
    );
    assert!(initialized.status.success(), "{initialized:?}");
    let actual: sshw::policy::PolicyFile =
        serde_json::from_slice(&std::fs::read(&local_path).unwrap()).unwrap();
    assert_eq!(actual, serde_json::from_str(original).unwrap());
    assert_eq!(std::fs::read_to_string(policy).unwrap(), original);
}

#[test]
fn empty_doctor_reuses_list_registration_guidance_from_another_directory() {
    let temp = tempfile::Builder::new()
        .prefix("empty doctor's $scope; ")
        .tempdir()
        .unwrap();
    let target = temp.path().join("target");
    let elsewhere = temp.path().join("elsewhere");
    local_fixture(&target);
    local_fixture(&elsewhere);
    let settings = target.join(".sshw");
    let config = settings.join("servers.json");
    let decoy = elsewhere.join(".sshw/servers.json");
    let decoy_before = std::fs::read(&decoy).unwrap();
    for (selector, path) in [("--project-dir", &target), ("--home", &settings)] {
        save_config(
            &config,
            &SshwConfig {
                credential_backend: sshw::config::CredentialBackend::SessionOnly,
                ..Default::default()
            },
        )
        .unwrap();
        let before = std::fs::read(&config).unwrap();
        let path = path.to_str().unwrap();
        let output = run(
            &elsewhere,
            &[selector, path, "--policy", "doctor", "--json"],
        );
        assert!(output.status.success(), "{output:?}");
        let report: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
        let setup = report["issues"]
            .as_array()
            .unwrap()
            .iter()
            .find(|issue| issue["kind"] == "setup")
            .unwrap();
        let listing = run(&elsewhere, &[selector, path, "--policy", "list"]);
        assert!(listing.status.success(), "{listing:?}");
        let guidance = setup["next_step"].as_str().unwrap();
        let summary = setup["message"].as_str().unwrap();
        assert_eq!(
            format!("{summary}\n{guidance}"),
            String::from_utf8_lossy(&listing.stdout).trim_end()
        );
        assert_eq!(std::fs::read(&config).unwrap(), before);

        let registration = &guidance[guidance.find("sshw ").unwrap()..];
        assert!(registration.starts_with(&format!("sshw {selector}=")));
        assert!(registration.contains(" --policy add "));
        let registration = registration
            .replace("<host>", "192.0.2.10")
            .replace("<login-user>", "deploy")
            .replacen(" -- ", " --auth agent -- ", 1);
        let output = copy_from(&elsewhere, &registration);
        assert!(output.status.success(), "{output:?}; {registration}");
        assert!(
            sshw::config::load_config(&config)
                .unwrap()
                .servers
                .contains_key("web")
        );
        assert_eq!(std::fs::read(&decoy).unwrap(), decoy_before);
        assert!(!elsewhere.join("unused").exists());
        assert!(!settings.join("known_hosts").exists());
    }
}

#[test]
fn doctor_and_account_lookup_recovery_keep_the_project_when_copied_elsewhere() {
    let temp = tempfile::Builder::new()
        .prefix("diagnostic's $scope; ")
        .tempdir()
        .unwrap();
    let target = temp.path().join("target");
    let other = temp.path().join("elsewhere");
    local_fixture(&target);
    local_fixture(&other);
    let home = sshw::home::ResolvedHome::ad_hoc(&target.join(".sshw"), "target".into());
    let mut config = sshw::config::load_config(&home.config_path).unwrap();
    config
        .servers
        .get_mut("local")
        .unwrap()
        .accounts
        .get_mut("deploy")
        .unwrap()
        .auth = AuthConfig::Password {
        credential: home.namespace.new_account_credential_key(
            sshw::home::CredentialPurpose::Login,
            "local",
            "deploy",
        ),
    };
    save_config(&home.config_path, &config).unwrap();
    let before = std::fs::read(&home.config_path).unwrap();
    let decoy = other.join(".sshw/servers.json");
    let mut config = sshw::config::load_config(&decoy).unwrap();
    config.servers.insert(
        "local".into(),
        ServerConfig::single_account("192.0.2.99", 10022, "decoy", AuthConfig::Agent),
    );
    save_config(&decoy, &config).unwrap();
    let diagnosed = run(
        &other,
        &[
            "--project-dir",
            target.to_str().unwrap(),
            "doctor",
            "local",
            "--json",
        ],
    );
    assert!(diagnosed.status.success(), "{diagnosed:?}");
    let body: serde_json::Value = serde_json::from_slice(&diagnosed.stdout).unwrap();
    let hint = body["issues"]
        .as_array()
        .unwrap()
        .iter()
        .find(|issue| issue["kind"] == "host_trust")
        .unwrap()["next_step"]
        .as_str()
        .unwrap();
    assert!(hint.contains("--project-dir="), "{hint}");
    let shown = copy_from(&other, &hint.replacen(" trust -- ", " show --json -- ", 1));
    assert!(shown.status.success(), "{shown:?}; {hint}");
    let body: serde_json::Value = serde_json::from_slice(&shown.stdout).unwrap();
    assert_eq!(body["host"], "192.0.2.10");
    let failed = run(
        &other,
        &[
            "--project-dir",
            target.to_str().unwrap(),
            "account",
            "show",
            "local",
            "missing",
            "--json",
        ],
    );
    assert_eq!(failed.status.code(), Some(3));
    let body: serde_json::Value = serde_json::from_slice(&failed.stdout).unwrap();
    let message = body["error"]["message"].as_str().unwrap();
    let hint = message
        .split('`')
        .find(|text| text.contains(" account list "))
        .unwrap();
    assert!(hint.contains("--project-dir="), "{hint}");
    let listed = copy_from(
        &other,
        &hint.replacen(" account list -- ", " account list --json -- ", 1),
    );
    assert!(listed.status.success(), "{listed:?}; {hint}");
    let body: serde_json::Value = serde_json::from_slice(&listed.stdout).unwrap();
    assert_eq!(body[0]["user"], "deploy");
    assert_eq!(std::fs::read(&home.config_path).unwrap(), before);
    assert!(!home.known_hosts_path.exists());
    assert!(!home.audit_path.exists());
    assert!(!other.join("unused").exists());
}

#[test]
fn registration_followups_keep_home_environment_and_project_selection_from_another_directory() {
    let temp = tempfile::Builder::new()
        .prefix("sshw guidance's $scope; ")
        .tempdir()
        .unwrap();
    let elsewhere = temp.path().join("elsewhere");
    std::fs::create_dir(&elsewhere).unwrap();
    local_fixture(&elsewhere);
    for selection in ["home", "environment", "project"] {
        let directory = temp.path().join(selection);
        std::fs::create_dir(&directory).unwrap();
        let home = directory.join("settings");
        if selection == "project" {
            local_fixture(&directory);
        }
        let name = "web' $scope; literal";
        let mut child = Command::new(env!("CARGO_BIN_EXE_sshw"));
        child
            .current_dir(&elsewhere)
            .env_remove("SSHW_HOME")
            .env_remove("SSHW_PASSWORD")
            .env_remove("SSHW_PRIVILEGE_PASSWORD");
        match selection {
            "home" => {
                child.args(["--home", home.to_str().unwrap()]);
            }
            "environment" => {
                child.env("SSHW_HOME", &home);
            }
            _ => {
                child.args(["--project-dir", directory.to_str().unwrap()]);
            }
        }
        let output = child
            .args([
                "--policy",
                "add",
                name,
                "--host",
                "192.0.2.10",
                "--user",
                "deploy",
                "--auth",
                "agent",
            ])
            .output()
            .unwrap();
        assert!(output.status.success(), "{output:?}");
        let text = String::from_utf8(output.stdout).unwrap();
        let next = text
            .lines()
            .find_map(|line| line.strip_prefix("next: "))
            .unwrap();
        let then = text
            .lines()
            .find_map(|line| line.strip_prefix("then: "))
            .unwrap();
        let selector = if selection == "project" {
            "--project-dir="
        } else {
            "--home="
        };
        assert!(next.contains(selector), "{selection}: {text}");
        assert!(then.contains(selector), "{selection}: {text}");
        assert!(then.contains("--policy"), "{then}");
        // Exercise the exact generated selector/name with read-only metadata;
        // host approval and remote command execution remain explicit user actions.
        let probe = next.replacen(" trust -- ", " show --json -- ", 1);
        let output = copy_from(&elsewhere, &probe);
        assert!(output.status.success(), "{output:?}; {probe}");
        let shown: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
        assert_eq!(shown["name"], name);
        assert_eq!(shown["host"], "192.0.2.10");
        assert!(!elsewhere.join("unused").exists());
        let root = if selection == "project" {
            directory.join(".sshw")
        } else {
            home
        };
        assert!(!root.join("known_hosts").exists());
    }
}

#[test]
fn empty_selected_list_and_filter_miss_keep_the_home_and_remain_read_only() {
    let temp = tempfile::tempdir().unwrap();
    let home = temp.path().join("empty home");
    let output = run(temp.path(), &["--home", home.to_str().unwrap(), "list"]);
    assert!(output.status.success(), "{output:?}");
    let text = String::from_utf8(output.stdout).unwrap();
    assert!(text.contains("--home="), "{text}");
    assert!(text.contains(" add --host "), "{text}");
    assert!(!home.exists());
    let output = run(
        temp.path(),
        &["--home", home.to_str().unwrap(), "list", "--json"],
    );
    assert_eq!(output.stdout, b"[]\n");
    assert!(!home.exists());
    let output = run(
        temp.path(),
        &[
            "--home",
            home.to_str().unwrap(),
            "add",
            "web",
            "--host",
            "192.0.2.10",
            "--user",
            "deploy",
            "--auth",
            "agent",
        ],
    );
    assert!(output.status.success(), "{output:?}");
    let before = std::fs::read(home.join("servers.json")).unwrap();
    let audit = std::fs::read(home.join("audit.jsonl")).unwrap();
    let output = run(
        temp.path(),
        &[
            "--home",
            home.to_str().unwrap(),
            "list",
            "--filter",
            "missing",
        ],
    );
    let text = String::from_utf8(output.stdout).unwrap();
    assert!(text.contains("no matching servers"), "{text}");
    assert!(text.contains("--home="), "{text}");
    let command = text.split('`').nth(1).unwrap();
    let elsewhere = tempfile::tempdir().unwrap();
    let output = copy_from(elsewhere.path(), command);
    assert!(output.status.success(), "{output:?}; {command}");
    assert!(String::from_utf8(output.stdout).unwrap().contains("web"));
    assert_eq!(std::fs::read(home.join("servers.json")).unwrap(), before);
    assert_eq!(std::fs::read(home.join("audit.jsonl")).unwrap(), audit);
    assert!(!elsewhere.path().join("unused").exists());
}

#[test]
fn add_address_conflict_recommends_a_scoped_endpoint_and_preserves_accounts_and_trust() {
    let temp = tempfile::Builder::new()
        .prefix("endpoint's $scope; ")
        .tempdir()
        .unwrap();
    local_fixture(temp.path());
    let root = temp.path().join(".sshw");
    let path = root.join("servers.json");
    let mut config = sshw::config::load_config(&path).unwrap();
    config.servers.get_mut("local").unwrap().accounts.insert(
        "ops".into(),
        sshw::config::AccountConfig {
            auth: AuthConfig::Agent,
            privilege: Some(sshw::config::PrivilegeConfig {
                method: sshw::config::PrivilegeMethod::Sudo,
                user: "root".into(),
                credential: None,
                no_password: true,
            }),
        },
    );
    save_config(&path, &config).unwrap();
    std::fs::write(root.join("known_hosts"), "old approved keys preserved").unwrap();
    let before = std::fs::read(&path).unwrap();
    let policy = std::fs::read(root.join("policy.json")).unwrap();
    let output = run(
        temp.path(),
        &[
            "add",
            "local",
            "--host",
            "192.0.2.20",
            "--port",
            "10022",
            "--user",
            "deploy",
            "--auth",
            "agent",
            "--force",
            "--json",
        ],
    );
    assert_eq!(output.status.code(), Some(3));
    let body: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    let message = body["error"]["message"].as_str().unwrap();
    assert!(message.contains("endpoint"), "{message}");
    assert!(message.contains("--replace"), "{message}");
    let command = message.split('`').nth(1).unwrap();
    assert!(command.contains("--project-dir="), "{command}");
    assert!(command.contains("--host="), "{command}");
    assert!(command.contains("--port=10022"), "{command}");
    assert_eq!(std::fs::read(&path).unwrap(), before);
    let elsewhere = tempfile::tempdir().unwrap();
    let applied = copy_from(
        elsewhere.path(),
        &command.replacen(" endpoint ", " endpoint --yes ", 1),
    );
    assert!(applied.status.success(), "{applied:?}; {command}");
    config.servers.get_mut("local").unwrap().host = "192.0.2.20".into();
    config.servers.get_mut("local").unwrap().port = 10022;
    assert_eq!(sshw::config::load_config(&path).unwrap(), config);
    assert_eq!(std::fs::read(root.join("policy.json")).unwrap(), policy);
    assert_eq!(
        std::fs::read_to_string(root.join("known_hosts")).unwrap(),
        "old approved keys preserved"
    );
    assert!(!elsewhere.path().join("unused").exists());
}

#[test]
fn project_policy_status_distinguishes_saved_forced_and_blocked_and_enable_targets_local_policy() {
    let temp = tempfile::Builder::new()
        .prefix("sshw project's $scope; ")
        .tempdir()
        .unwrap();
    local_fixture(temp.path());
    let root = temp.path().join(".sshw");
    let policy = root.join("policy.json");
    std::fs::write(&policy, r#"{"enabled":false,"allow_commands":["uptime"]}"#).unwrap();
    let before = std::fs::read(&policy).unwrap();
    let output = run(temp.path(), &["project", "status", "--json"]);
    assert!(output.status.success(), "{output:?}");
    let body: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    let state = &body["policy_status"];
    assert_eq!(state["saved_enabled"], false);
    assert_eq!(state["enforced"], false);
    assert_eq!(state["forced"], false);
    assert_eq!(state["state"], "off");
    let command = state["enable_command"].as_str().unwrap();
    assert!(command.contains("--project-dir="));
    let human = run(temp.path(), &["project", "status"]);
    let human = String::from_utf8(human.stdout).unwrap();
    assert!(human.contains("saved enabled: false"), "{human}");
    assert!(human.contains("policy enforcement: off"), "{human}");
    let forced = run(temp.path(), &["--policy", "project", "status", "--json"]);
    let forced: serde_json::Value = serde_json::from_slice(&forced.stdout).unwrap();
    assert_eq!(forced["policy_status"]["saved_enabled"], false);
    assert_eq!(forced["policy_status"]["forced"], true);
    assert_eq!(forced["policy_status"]["enforced"], true);
    assert_eq!(std::fs::read(&policy).unwrap(), before);
    assert!(!root.join("audit.jsonl").exists());
    assert!(!root.join(".sshw.lock").exists());
    let elsewhere = tempfile::tempdir().unwrap();
    let applied = copy_from(elsewhere.path(), command);
    assert!(applied.status.success(), "{applied:?}; {command}");
    assert!(!elsewhere.path().join("unused").exists());
    assert!(!elsewhere.path().join(".sshw").exists());
    let saved: serde_json::Value =
        serde_json::from_slice(&std::fs::read(&policy).unwrap()).unwrap();
    assert_eq!(saved["enabled"], true);
    assert_eq!(saved["allow_commands"], serde_json::json!(["uptime"]));
    let output = run(temp.path(), &["project", "status", "--json"]);
    let body: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(body["policy_status"]["state"], "on");
    assert!(body["policy_status"]["enable_command"].is_null());
    std::fs::write(&policy, "invalid policy").unwrap();
    let output = run(temp.path(), &["project", "status", "--json"]);
    assert!(output.status.success(), "{output:?}");
    let body: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(body["policy_status"]["state"], "blocked");
    assert_eq!(body["policy_status"]["valid"], false);
    assert!(body["policy_status"]["saved_enabled"].is_null());
    assert!(body["policy_status"]["enforced"].is_null());
    assert!(body["policy_status"]["enable_command"].is_null());
}

#[test]
fn cwd_project_cli_preflight_and_completion_use_local_only_without_writes() {
    use base64::{Engine, engine::general_purpose::STANDARD};
    let temp = tempfile::tempdir().unwrap();
    local_fixture(temp.path());
    let root = temp.path().join(".sshw");
    let before = std::fs::read(root.join("servers.json")).unwrap();
    let output = run(temp.path(), &["list", "--json"]);
    assert!(output.status.success(), "{output:?}");
    let body: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(body[0]["name"], "local");
    assert_eq!(body.as_array().unwrap().len(), 1);
    let output = run(temp.path(), &["policy", "check", "uptime", "--json"]);
    assert!(output.status.success(), "{output:?}");
    let body: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(body["allowed"], true);
    assert_eq!(
        body["policy"]["settings_sources"]["servers"]["scope"],
        "local"
    );
    let payload = STANDARD.encode(serde_json::json!({"words":["run"],"word":"loc"}).to_string());
    let mut child = Command::new(env!("CARGO_BIN_EXE_sshw"))
        .current_dir(temp.path())
        .args(["completions", "powershell", "--query"])
        .env_remove("SSHW_HOME")
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .spawn()
        .unwrap();
    use std::io::Write;
    child
        .stdin
        .take()
        .unwrap()
        .write_all(payload.as_bytes())
        .unwrap();
    let output = child.wait_with_output().unwrap();
    let body: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(body[0]["value"], "local");
    assert_eq!(
        run(temp.path(), &["show", "global", "--json"])
            .status
            .code(),
        Some(3)
    );
    assert_eq!(std::fs::read(root.join("servers.json")).unwrap(), before);
    assert!(!root.join("audit.jsonl").exists());
    assert!(!root.join(".sshw.lock").exists());
    let status = run(temp.path(), &["project", "status", "--json"]);
    assert!(status.status.success(), "{status:?}");
    let body: serde_json::Value = serde_json::from_slice(&status.stdout).unwrap();
    assert_eq!(body["sources"]["servers"]["scope"], "local");
    assert_eq!(body["sources"]["policy"]["scope"], "local");
}

#[test]
fn project_policy_recovery_command_reproduces_selection_from_another_directory() {
    let temp = tempfile::Builder::new()
        .prefix("sshw project's $scope; ")
        .tempdir()
        .unwrap();
    local_fixture(temp.path());
    let output = run(temp.path(), &["policy", "check", "date", "--json"]);
    assert_eq!(output.status.code(), Some(7));
    let body: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    let command = body["suggestions"][0]["command"].as_str().unwrap();
    assert!(command.contains("--project-dir="));
    let elsewhere = tempfile::tempdir().unwrap();
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
    let output = shell
        .current_dir(elsewhere.path())
        .env("PATH", std::env::join_paths(paths).unwrap())
        // --project-dir must reproduce the source despite ambient SSHW_HOME.
        .env("SSHW_HOME", elsewhere.path().join("unused"))
        .output()
        .unwrap();
    assert!(output.status.success(), "{output:?}; {command}");
    assert!(
        run(temp.path(), &["policy", "check", "date", "--json"])
            .status
            .success()
    );
    assert!(!elsewhere.path().join("unused").exists());
}

#[test]
fn project_init_cli_copies_policy_without_global_data_or_credentials_and_is_repeatable() {
    let temp = tempfile::tempdir().unwrap();
    let cwd = temp.path().join("work");
    let global = temp.path().join("global");
    std::fs::create_dir(&cwd).unwrap();
    std::fs::create_dir(&global).unwrap();
    std::fs::write(
        global.join("policy.json"),
        r#"{"version":2,"enabled":true,"allow_commands":["uptime"],"allow_accounts":[]}"#,
    )
    .unwrap();
    let global_policy = std::fs::read(global.join("policy.json")).unwrap();
    let args = [
        "--home",
        global.to_str().unwrap(),
        "project",
        "init",
        "--servers-source",
        "local",
        "--policy-source",
        "local",
        "--json",
    ];
    let output = run(&cwd, &args);
    assert!(output.status.success(), "{output:?}");
    let body: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(body["servers_created"], true);
    assert_eq!(body["policy_created"], true);
    assert_eq!(body["policy_status"]["saved_enabled"], true);
    assert_eq!(body["policy_status"]["state"], "on");
    let root = cwd.join(".sshw");
    let config = sshw::config::load_config(&root.join("servers.json")).unwrap();
    assert!(config.servers.is_empty());
    assert!(config.default.is_none());
    let policy: serde_json::Value =
        serde_json::from_slice(&std::fs::read(root.join("policy.json")).unwrap()).unwrap();
    assert_eq!(policy["enabled"], true);
    assert_eq!(policy["allow_commands"], serde_json::json!(["uptime"]));
    let before = std::fs::read(root.join("project.json")).unwrap();
    let modified = std::fs::metadata(root.join("project.json"))
        .unwrap()
        .modified()
        .unwrap();
    let output = run(&cwd, &args);
    assert!(output.status.success());
    let body: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(body["changed"], false);
    assert_eq!(std::fs::read(root.join("project.json")).unwrap(), before);
    assert_eq!(
        std::fs::metadata(root.join("project.json"))
            .unwrap()
            .modified()
            .unwrap(),
        modified
    );
    assert_eq!(
        std::fs::read(global.join("policy.json")).unwrap(),
        global_policy
    );
    assert_eq!(std::fs::read_dir(&global).unwrap().count(), 1);
    let output = run(
        &cwd,
        &[
            "add",
            "local",
            "--host",
            "192.0.2.20",
            "--user",
            "deploy",
            "--auth",
            "agent",
            "--json",
        ],
    );
    assert!(output.status.success(), "{output:?}");
    assert!(
        sshw::config::load_config(&root.join("servers.json"))
            .unwrap()
            .servers
            .contains_key("local")
    );
}

#[test]
fn project_init_reports_disabled_policy_and_missing_forced_status_without_enabling_or_writing_it() {
    let temp = tempfile::tempdir().unwrap();
    let cwd = temp.path().join("work");
    let global = temp.path().join("global");
    std::fs::create_dir(&cwd).unwrap();
    std::fs::create_dir(&global).unwrap();
    let output = run(
        &cwd,
        &[
            "--home",
            global.to_str().unwrap(),
            "project",
            "init",
            "--servers-source",
            "local",
            "--json",
        ],
    );
    assert!(output.status.success(), "{output:?}");
    let body: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(body["policy_status"]["saved_enabled"], false);
    assert_eq!(body["policy_status"]["state"], "off");
    assert!(
        body["policy_status"]["enable_command"]
            .as_str()
            .unwrap()
            .contains("--project-dir=")
    );
    let root = cwd.join(".sshw");
    let before = std::fs::read(root.join("policy.json")).unwrap();
    let output = run(
        &cwd,
        &["--home", global.to_str().unwrap(), "project", "init"],
    );
    assert!(output.status.success(), "{output:?}");
    let text = String::from_utf8(output.stdout).unwrap();
    assert!(text.contains("saved enabled: false"), "{text}");
    assert!(text.contains("policy enforcement: off"), "{text}");
    assert!(text.contains(" policy enable`"), "{text}");
    assert_eq!(std::fs::read(root.join("policy.json")).unwrap(), before);
    let empty_cwd = temp.path().join("other");
    std::fs::create_dir(&empty_cwd).unwrap();
    for forced in [false, true] {
        let mut args = vec!["--home", global.to_str().unwrap()];
        if forced {
            args.push("--policy");
        }
        args.extend(["project", "status", "--json"]);
        let output = run(&empty_cwd, &args);
        assert!(output.status.success(), "{output:?}");
        let body: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
        let state = &body["policy_status"];
        assert_eq!(state["present"], false);
        assert_eq!(state["valid"], true);
        assert!(state["saved_enabled"].is_null());
        assert_eq!(state["forced"], forced);
        assert_eq!(state["state"], if forced { "blocked" } else { "off" });
        if forced {
            assert!(state["enforced"].is_null());
        } else {
            assert_eq!(state["enforced"], false);
        }
        assert!(state["enable_command"].is_null());
    }
    assert_eq!(std::fs::read_dir(global).unwrap().count(), 0);
    assert_eq!(std::fs::read_dir(empty_cwd).unwrap().count(), 0);
}

#[test]
fn policy_diagnostics_agree_when_enforcement_is_blocked() {
    let temp = tempfile::tempdir().unwrap();
    local_fixture(temp.path());
    let root = temp.path().join(".sshw");
    let policy = root.join("policy.json");
    save_config(
        &root.join("servers.json"),
        &SshwConfig {
            credential_backend: sshw::config::CredentialBackend::SessionOnly,
            ..Default::default()
        },
    )
    .unwrap();
    std::fs::remove_file(&policy).unwrap();
    let elsewhere = temp.path().join("elsewhere");
    std::fs::create_dir(&elsewhere).unwrap();
    for malformed in [false, true] {
        if malformed {
            std::fs::write(&policy, "not JSON").unwrap();
        }
        let before = std::fs::read(&policy).ok();
        let call = |command: &[&str]| {
            let mut args = vec!["--policy"];
            // A project explicitly requiring a missing local resource cannot resolve.
            // Exercise missing policy through a home and malformed policy in the project.
            let cwd = if malformed {
                temp.path()
            } else {
                args.extend(["--home", root.to_str().unwrap()]);
                &elsewhere
            };
            args.extend_from_slice(command);
            run(cwd, &args)
        };
        let status = call(&["project", "status", "--json"]);
        let doctor = call(&["doctor", "--json"]);
        assert!(
            status.status.success() && doctor.status.success(),
            "{status:?}\n{doctor:?}"
        );
        let status: serde_json::Value = serde_json::from_slice(&status.stdout).unwrap();
        let doctor: serde_json::Value = serde_json::from_slice(&doctor.stdout).unwrap();
        let snapshot = &doctor["policy_status"];
        assert_eq!(snapshot["valid"], !malformed);
        assert_eq!(snapshot["present"], malformed);
        assert_eq!(snapshot["forced"], true);
        assert!(snapshot["saved_enabled"].is_null());
        assert_eq!(snapshot["state"], "blocked");
        assert!(snapshot["enforced"].is_null());
        for key in [
            "present",
            "valid",
            "saved_enabled",
            "forced",
            "state",
            "enforced",
        ] {
            assert_eq!(snapshot[key], status["policy_status"][key], "{key}");
        }
        let show = call(&["policy", "show", "--json"]);
        let show_body: serde_json::Value = serde_json::from_slice(&show.stdout).unwrap();
        if malformed {
            assert_eq!(show.status.code(), Some(7));
            assert_eq!(show_body["error"]["kind"], "policy");
            assert!(
                show_body["error"]["message"]
                    .as_str()
                    .unwrap()
                    .contains("policy enforcement: blocked")
            );
        } else {
            assert!(show.status.success());
            assert_eq!(&show_body["policy_status"], snapshot);
            let setup = doctor["issues"]
                .as_array()
                .unwrap()
                .iter()
                .find(|issue| issue["kind"] == "policy")
                .unwrap()["next_step"]
                .as_str()
                .unwrap();
            assert!(
                setup.contains("--home=") && setup.contains(" --policy policy init"),
                "{setup}"
            );
        }
        let text = call(&["doctor"]);
        assert!(text.status.success());
        assert!(String::from_utf8_lossy(&text.stdout).contains("policy enforcement: blocked"));
        let check = call(&["policy", "check", "uptime", "--json"]);
        assert_eq!(check.status.code(), Some(7));
        assert_eq!(std::fs::read(&policy).ok(), before);
        assert!(!root.join("audit.jsonl").exists());
    }
}

#[test]
fn invalid_project_data_fails_closed_and_explicit_home_bypasses_it() {
    let temp = tempfile::tempdir().unwrap();
    local_fixture(temp.path());
    let root = temp.path().join(".sshw");
    std::fs::write(root.join("servers.json"), "broken local servers").unwrap();
    assert_eq!(run(temp.path(), &["list", "--json"]).status.code(), Some(3));
    std::fs::remove_file(root.join("servers.json")).unwrap();
    assert_eq!(run(temp.path(), &["list", "--json"]).status.code(), Some(3));
    std::fs::write(root.join("project.json"), "broken project metadata").unwrap();
    let explicit = temp.path().join("explicit");
    std::fs::create_dir(&explicit).unwrap();
    let output = run(
        temp.path(),
        &["--home", explicit.to_str().unwrap(), "list", "--json"],
    );
    assert!(output.status.success(), "{output:?}");
    assert_eq!(output.stdout, b"[]\n");
    assert!(!root.join("audit.jsonl").exists());
    assert!(!root.join(".sshw.lock").exists());
}
