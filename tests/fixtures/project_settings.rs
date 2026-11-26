use super::*;
use sshw::project::{ProjectSettings, ResourceMode};

struct Fixture {
    _temp: tempfile::TempDir,
    base: std::path::PathBuf,
    cwd: std::path::PathBuf,
    global: ResolvedHome,
    local: ResolvedHome,
    store: FakeCredentialStore,
    ssh: FakeSshClient,
}
impl Fixture {
    fn new(servers: ResourceMode, policy: ResourceMode) -> Self {
        let temp = tempfile::tempdir().unwrap();
        let base = temp.path().join("base");
        let cwd = temp.path().join("work");
        let global = ResolvedHome::profile(
            temp.path().join("global"),
            "p_global",
            "default profile prod".into(),
        );
        let local = ResolvedHome::ad_hoc(&cwd.join(".sshw"), "local".into());
        std::fs::create_dir_all(&local.root).unwrap();
        save_registry(
            &base.join("profiles.json"),
            &ProfileRegistry {
                default: Some("prod".into()),
                profiles: BTreeMap::from([(
                    "prod".into(),
                    ProfileEntry {
                        id: "p_global".into(),
                        home: global.root.clone(),
                    },
                )]),
                ..Default::default()
            },
        )
        .unwrap();
        let store = FakeCredentialStore::default();
        for (home, name, user) in [(&global, "global", "deploy"), (&local, "local", "ops")] {
            let key =
                home.namespace
                    .new_account_credential_key(CredentialPurpose::Login, name, user);
            store.set_password(&key, user, "SYNTHETIC_SECRET").unwrap();
            save_config(
                &home.config_path,
                &SshwConfig {
                    default: Some(name.into()),
                    servers: BTreeMap::from([(
                        name.into(),
                        ServerConfig::single_account(
                            "192.0.2.10",
                            22,
                            user,
                            AuthConfig::Password { credential: key },
                        ),
                    )]),
                    ..Default::default()
                },
            )
            .unwrap();
            std::fs::write(&home.known_hosts_path, "trust fixture retained").unwrap();
            std::fs::write(&home.policy_path,serde_json::json!({"version":2,"enabled":true,"allow_commands":[format!("{name}-command")],"allow_accounts":[]}).to_string()).unwrap();
        }
        std::fs::write(
            local.root.join("project.json"),
            serde_json::to_string(&ProjectSettings {
                version: 1,
                servers,
                policy,
            })
            .unwrap(),
        )
        .unwrap();
        Self {
            _temp: temp,
            base,
            cwd,
            global,
            local,
            store,
            ssh: FakeSshClient::default(),
        }
    }
    fn call(&self, tail: &[&str]) -> sshw::cli::CommandOutput {
        let mut args = vec!["sshw"];
        args.extend_from_slice(tail);
        let cli = Cli::try_parse_from(args).unwrap();
        let (home, registry) =
            sshw::cli::resolve_runtime_at(&cli, &self.base, None, &self.cwd).unwrap();
        let audit = FileAuditSink::new(home.audit_path.clone())
            .with_settings(sshw::project::sources(&home));
        sshw::cli::execute_for_runtime_with(
            cli,
            &ExecContext {
                home: &home,
                registry_path: &registry,
                policy_forced: false,
                audit: &audit,
            },
            &self.store,
            &self.ssh,
            &mut NoPasswordPrompter { prompts: vec![] },
        )
    }
}

#[test]
fn trust_confirmation_identifies_the_actual_endpoint_and_project_settings_without_changing_approval()
 {
    struct Confirmation {
        prompts: Vec<String>,
        approve: bool,
    }
    impl Prompter for Confirmation {
        fn confirm(&mut self, question: &str) -> anyhow::Result<bool> {
            self.prompts.push(question.into());
            Ok(self.approve)
        }
        fn password(&mut self, _: &str) -> anyhow::Result<String> {
            panic!("trust never reads passwords")
        }
        fn password_stdin(&mut self) -> anyhow::Result<String> {
            panic!("trust never reads stdin")
        }
    }
    for (approve, host, port, endpoint) in [
        (false, "192.0.2.10", 22, "192.0.2.10:22"),
        (true, "192.0.2.10", 22, "192.0.2.10:22"),
        (false, "2001:db8::10", 10022, "[2001:db8::10]:10022"),
        (true, "2001:db8::10", 10022, "[2001:db8::10]:10022"),
    ] {
        let mut f = Fixture::new(ResourceMode::Local, ResourceMode::Global);
        f.ssh.host_key_fingerprint = "SHA256:context-visible".into();
        let mut config = load_config(&f.local.config_path).unwrap();
        config.servers.get_mut("local").unwrap().host = host.into();
        config.servers.get_mut("local").unwrap().port = port;
        save_config(&f.local.config_path, &config).unwrap();
        let cli = Cli::try_parse_from([
            "sshw",
            "--project-dir",
            f.cwd.to_str().unwrap(),
            "trust",
            "local",
            "--json",
        ])
        .unwrap();
        let (home, registry) = sshw::cli::resolve_runtime_at(&cli, &f.base, None, &f.cwd).unwrap();
        let mut input = Confirmation {
            prompts: vec![],
            approve,
        };
        let output = sshw::cli::execute_for_runtime_with(
            cli,
            &ExecContext {
                home: &home,
                registry_path: &registry,
                policy_forced: false,
                audit: &sshw::audit::NoopAudit,
            },
            &f.store,
            &f.ssh,
            &mut input,
        );
        assert_eq!(output.exit_code, if approve { 0 } else { 3 }, "{output:?}");
        assert_eq!(input.prompts.len(), 1);
        let question = &input.prompts[0];
        assert!(question.contains(endpoint), "{question}");
        assert!(question.contains("project local"), "{question}");
        assert!(
            question.contains(&f.local.config_path.display().to_string()),
            "{question}"
        );
        assert!(
            question.contains(&f.local.known_hosts_path.display().to_string()),
            "{question}"
        );
        assert!(question.contains(&f.ssh.host_key_fingerprint), "{question}");
        assert!(f.store.requested.borrow().is_empty());
        assert_eq!(
            f.ssh.trusted_expected_fingerprints.borrow().len(),
            usize::from(approve)
        );
        if approve {
            assert_eq!(
                f.ssh.trusted_expected_fingerprints.borrow()[0],
                f.ssh.host_key_fingerprint
            );
        }
    }
}

#[test]
fn diagnostic_and_lookup_writes_make_inherited_global_intent_explicit_without_mutation() {
    for servers in [ResourceMode::Local, ResourceMode::Global] {
        let f = Fixture::new(servers, ResourceMode::Local);
        f.store.values.borrow_mut().clear();
        let name = if servers == ResourceMode::Local {
            "local"
        } else {
            "global"
        };
        let home = if servers == ResourceMode::Local {
            &f.local
        } else {
            &f.global
        };
        let before = std::fs::read(&home.config_path).unwrap();
        let trust = std::fs::read(&home.known_hosts_path).unwrap();
        let output = f.call(&["doctor", name, "--json"]);
        assert_eq!(output.exit_code, 0, "{output:?}");
        let body: serde_json::Value = serde_json::from_str(&output.stdout).unwrap();
        let credential = body["credential_checks"][0]["next_step"].as_str().unwrap();
        let host = body["issues"]
            .as_array()
            .unwrap()
            .iter()
            .find(|issue| issue["kind"] == "host_trust")
            .unwrap()["next_step"]
            .as_str()
            .unwrap();
        let unknown = f.call(&["account", "show", name, "missing", "--json"]);
        assert_eq!(unknown.exit_code, 3);
        let unknown: serde_json::Value = serde_json::from_str(&unknown.stdout).unwrap();
        let message = unknown["error"]["message"].as_str().unwrap();
        assert!(
            message.contains("--project-dir=") && message.contains(" account list -- "),
            "{message}"
        );
        if servers == ResourceMode::Global {
            assert!(
                credential.contains("sshw --global account add"),
                "{credential}"
            );
            assert!(host.contains("sshw --global trust"), "{host}");
            assert!(host.contains("intentional global approval"), "{host}");
            assert!(
                message.contains("sshw --global account add") && message.contains("intentionally"),
                "{message}"
            );
            assert!(
                message
                    .split('`')
                    .filter(|s| s.contains(" account add "))
                    .all(|s| s.starts_with("sshw --global"))
            );
        } else {
            assert!(
                credential.contains("--project-dir=") && credential.contains(" account add "),
                "{credential}"
            );
            assert!(
                host.contains("--project-dir=") && host.contains(" trust -- "),
                "{host}"
            );
        }
        assert_eq!(std::fs::read(&home.config_path).unwrap(), before);
        assert_eq!(std::fs::read(&home.known_hosts_path).unwrap(), trust);
        assert!(f.store.values.borrow().is_empty());
        assert_eq!(*f.ssh.host_key_calls.borrow(), 0);
        assert!(f.ssh.trusted_expected_fingerprints.borrow().is_empty());
        assert!(!home.root.join(".sshw.lock").exists());
    }
}

#[test]
fn missing_inherited_default_scopes_list_and_requires_explicit_global_write() {
    let f = Fixture::new(ResourceMode::Global, ResourceMode::Local);
    let mut config = load_config(&f.global.config_path).unwrap();
    config.default = None;
    save_config(&f.global.config_path, &config).unwrap();
    let global = std::fs::read(&f.global.config_path).unwrap();
    let local = std::fs::read(&f.local.config_path).unwrap();
    let output = f.call(&["default", "--json"]);
    assert_eq!(output.exit_code, 3, "{output:?}");
    let body: serde_json::Value = serde_json::from_str(&output.stdout).unwrap();
    let message = body["error"]["message"].as_str().unwrap();
    assert!(
        message
            .split('`')
            .any(|part| part.starts_with("sshw --project-dir=") && part.ends_with(" list")),
        "{message}"
    );
    assert!(
        message.contains("`sshw --global default -- '<registered-server>'`"),
        "{message}"
    );
    assert!(
        message.contains("intentionally targets global"),
        "{message}"
    );
    assert_eq!(std::fs::read(&f.global.config_path).unwrap(), global);
    assert_eq!(std::fs::read(&f.local.config_path).unwrap(), local);
    assert!(!f.global.root.join(".sshw.lock").exists());
    assert!(f.store.requested.borrow().is_empty());
}

#[test]
fn missing_local_policy_uses_the_selected_initialization_baseline() {
    let f = Fixture::new(ResourceMode::Local, ResourceMode::Local);
    let servers = std::fs::read(&f.local.config_path).unwrap();
    let policy = std::fs::read(&f.global.policy_path).unwrap();
    std::fs::remove_file(&f.local.policy_path).unwrap();
    let path = f.cwd.to_str().unwrap();
    let args = Cli::try_parse_from(["sshw", "--project-dir", path, "doctor"]).unwrap();
    let error = sshw::cli::resolve_runtime_at(&args, &f.base, None, &f.cwd).unwrap_err();
    assert_eq!(sshw::output::classify_error(&error).exit_code(), 3);
    let message = error.to_string();
    assert!(
        message
            .split('`')
            .any(|part| part.starts_with("sshw --project-dir=")
                && part.ends_with(" project init --policy-source local")),
        "{message}"
    );
    assert!(
        message.contains("copies the selected global policy"),
        "{message}"
    );

    assert!(!f.local.policy_path.exists());
    assert!(!f.local.root.join(".sshw.lock").exists());

    let init = f.call(&[
        "--project-dir",
        path,
        "project",
        "init",
        "--policy-source",
        "local",
        "--json",
    ]);
    assert_eq!(init.exit_code, 0, "{init:?}");
    let body: serde_json::Value = serde_json::from_str(&init.stdout).unwrap();
    assert_eq!(body["servers_created"], false);
    assert_eq!(body["policy_created"], true);
    let saved: sshw::policy::PolicyFile =
        serde_json::from_slice(&std::fs::read(&f.local.policy_path).unwrap()).unwrap();
    let from_global: sshw::policy::PolicyFile = serde_json::from_slice(&policy).unwrap();
    assert_eq!(saved, from_global);
    assert_eq!(std::fs::read(&f.local.config_path).unwrap(), servers);
    assert_eq!(std::fs::read(&f.global.policy_path).unwrap(), policy);
    assert!(f.store.requested.borrow().is_empty());
}

#[test]
fn empty_inherited_server_list_offers_global_registration_and_project_local_initialization() {
    let f = Fixture::new(ResourceMode::Global, ResourceMode::Local);
    save_config(&f.global.config_path, &SshwConfig::default()).unwrap();
    let before = std::fs::read(&f.global.config_path).unwrap();
    let output = f.call(&["list"]);
    assert_eq!(output.exit_code, 0, "{output:?}");
    assert!(output.stdout.contains("inherited global"), "{output:?}");
    assert!(output.stdout.contains("sshw --global"), "{output:?}");
    assert!(output.stdout.contains("--project-dir="), "{output:?}");
    assert!(
        output.stdout.contains("--servers-source local"),
        "{output:?}"
    );
    let json = f.call(&["list", "--json"]);
    assert_eq!(json.stdout, "[]\n");
    let diagnostic = f.call(&["doctor", "--json"]);
    assert_eq!(diagnostic.exit_code, 0, "{diagnostic:?}");
    let diagnostic: serde_json::Value = serde_json::from_str(&diagnostic.stdout).unwrap();
    let setup = diagnostic["issues"]
        .as_array()
        .unwrap()
        .iter()
        .find(|issue| issue["kind"] == "setup")
        .unwrap();
    assert_eq!(
        format!(
            "{}\n{}",
            setup["message"].as_str().unwrap(),
            setup["next_step"].as_str().unwrap()
        ),
        output.stdout.trim_end()
    );
    assert_eq!(
        f.call(&[
            "add",
            "web",
            "--host",
            "192.0.2.10",
            "--user",
            "deploy",
            "--auth",
            "agent",
            "--json"
        ])
        .exit_code,
        3
    );
    assert_eq!(std::fs::read(&f.global.config_path).unwrap(), before);
    assert!(f.store.requested.borrow().is_empty());
    assert!(!f.local.root.join("audit.jsonl").exists());
    assert!(!f.global.root.join(".sshw.lock").exists());
    let no_default = f.call(&["default", "--json"]);
    assert_eq!(no_default.exit_code, 3, "{no_default:?}");
    let no_default: serde_json::Value = serde_json::from_str(&no_default.stdout).unwrap();
    let message = no_default["error"]["message"].as_str().unwrap();
    assert!(message.contains(output.stdout.trim_end()), "{message}");
    assert!(!message.contains(" default -- "), "{message}");
    assert_eq!(std::fs::read(&f.global.config_path).unwrap(), before);
}

#[test]
fn registration_followups_keep_registered_profile_namespace_without_switching_to_home() {
    let f = Fixture::new(ResourceMode::Local, ResourceMode::Local);
    let credentials = f.store.values.borrow().clone();
    let output = f.call(&[
        "--profile",
        "prod",
        "add",
        "named",
        "--host",
        "192.0.2.10",
        "--user",
        "deploy",
        "--auth",
        "agent",
    ]);
    assert_eq!(output.exit_code, 0, "{output:?}");
    let next = output
        .stdout
        .lines()
        .find(|line| line.starts_with("next: "))
        .unwrap();
    let then = output
        .stdout
        .lines()
        .find(|line| line.starts_with("then: "))
        .unwrap();
    assert!(next.contains("--profile="), "{next}");
    assert!(then.contains("--profile="), "{then}");
    assert!(!next.contains("--home="));
    assert!(!then.contains("--home="));
    assert_eq!(f.store.values.borrow().clone(), credentials);
    assert!(f.store.requested.borrow().is_empty());
    assert_eq!(
        std::fs::read_to_string(&f.global.known_hosts_path).unwrap(),
        "trust fixture retained"
    );
    let global = f.call(&[
        "--global",
        "add",
        "global-new",
        "--host",
        "192.0.2.11",
        "--user",
        "deploy",
        "--auth",
        "agent",
    ]);
    assert_eq!(global.exit_code, 0, "{global:?}");
    assert!(
        global.stdout.contains("next: sshw --global trust"),
        "{global:?}"
    );
    assert!(
        global.stdout.contains("then: sshw --global run"),
        "{global:?}"
    );
}

#[test]
fn project_runtime_matrix_keeps_sources_credentials_policy_and_no_server_fallback_aligned() {
    for servers in [ResourceMode::Local, ResourceMode::Global] {
        for policy in [ResourceMode::Local, ResourceMode::Global] {
            let f = Fixture::new(servers, policy);
            let name = if servers == ResourceMode::Local {
                "local"
            } else {
                "global"
            };
            let user = if servers == ResourceMode::Local {
                "ops"
            } else {
                "deploy"
            };
            let command = if policy == ResourceMode::Local {
                "local-command"
            } else {
                "global-command"
            };
            let config_path = if servers == ResourceMode::Local {
                &f.local.config_path
            } else {
                &f.global.config_path
            };
            let policy_path = if policy == ResourceMode::Local {
                &f.local.policy_path
            } else {
                &f.global.policy_path
            };
            let selected = sshw::project::resolve_automatic(&f.cwd, &f.base)
                .unwrap()
                .unwrap();
            assert_eq!(&selected.config_path, config_path);
            assert_eq!(&selected.policy_path, policy_path);
            let output = f.call(&["list", "--json"]);
            assert_eq!(output.exit_code, 0);
            let list: serde_json::Value = serde_json::from_str(&output.stdout).unwrap();
            assert_eq!(list.as_array().unwrap().len(), 1);
            assert_eq!(list[0]["name"], name);
            let output = f.call(&["policy", "check", command, "--json"]);
            assert_eq!(output.exit_code, 0, "{output:?}");
            let body: serde_json::Value = serde_json::from_str(&output.stdout).unwrap();
            assert_eq!(body["policy"]["path"], policy_path.to_str().unwrap());
            assert!(f.store.requested.borrow().is_empty());
            let output = f.call(&["run", command, "--json"]);
            assert_eq!(output.exit_code, 0, "{output:?}");
            let body: serde_json::Value = serde_json::from_str(&output.stdout).unwrap();
            assert_eq!(body["server"], name);
            assert_eq!(body["user"], user);
            let expected_home = if servers == ResourceMode::Local {
                &f.local
            } else {
                &f.global
            };
            let config = load_config(config_path).unwrap();
            let AuthConfig::Password { credential } = &config.servers[name].accounts[user].auth
            else {
                panic!()
            };
            assert_eq!(
                *f.store.requested.borrow(),
                vec![(credential.clone(), user.into())]
            );
            assert!(expected_home.namespace.account_credential_key_matches(
                CredentialPurpose::Login,
                name,
                user,
                credential
            ));
            let wrong = if command == "local-command" {
                "global-command"
            } else {
                "local-command"
            };
            let reads = f.store.requested.borrow().len();
            assert_eq!(f.call(&["run", wrong, "--json"]).exit_code, 7);
            assert_eq!(f.store.requested.borrow().len(), reads);
            let missing = if name == "local" { "global" } else { "local" };
            assert_eq!(f.call(&["show", missing, "--json"]).exit_code, 3);
            let records = std::fs::read_to_string(f.local.root.join("audit.jsonl")).unwrap();
            let record: serde_json::Value =
                serde_json::from_str(records.lines().next().unwrap()).unwrap();
            assert_eq!(
                record["settings"]["servers"]["path"],
                config_path.to_str().unwrap()
            );
            let output = f.call(&["doctor", name, "--json"]);
            assert_eq!(output.exit_code, 0, "{output:?}");
            let body: serde_json::Value = serde_json::from_str(&output.stdout).unwrap();
            assert_eq!(
                body["settings_sources"]["servers"]["path"],
                config_path.to_str().unwrap()
            );
            assert_eq!(
                body["settings_sources"]["policy"]["path"],
                policy_path.to_str().unwrap()
            );
            let denied = f.call(&["policy", "check", wrong, "--json"]);
            let body: serde_json::Value = serde_json::from_str(&denied.stdout).unwrap();
            if policy == ResourceMode::Global {
                assert!(body["suggestions"][0]["command"].is_null());
                assert!(
                    body["suggestions"][0]["scope"]
                        .as_str()
                        .unwrap()
                        .contains("inherited")
                );
            } else {
                assert!(
                    body["suggestions"][0]["command"]
                        .as_str()
                        .unwrap()
                        .contains("--project-dir=")
                );
            }
        }
    }
}

#[test]
fn project_inherited_writes_are_blocked_but_explicit_global_and_local_edits_work() {
    let f = Fixture::new(ResourceMode::Global, ResourceMode::Local);
    let before = std::fs::read(&f.global.config_path).unwrap();
    for args in [
        vec!["remove", "global", "--yes", "--json"],
        vec!["endpoint", "global", "--port", "10022", "--yes", "--json"],
        vec!["default", "--clear", "--json"],
        vec!["password", "global", "--json"],
        vec!["trust", "global", "--yes", "--json"],
    ] {
        let output = f.call(&args);
        assert_eq!(output.exit_code, 3, "{output:?}");
        assert!(output.stdout.contains("--global"));
        let body: serde_json::Value = serde_json::from_str(&output.stdout).unwrap();
        let message = body["error"]["message"].as_str().unwrap();
        assert!(message.contains("sshw --project-dir="), "{message}");
        assert!(message.contains("--servers-source local"), "{message}");
    }
    assert_eq!(std::fs::read(&f.global.config_path).unwrap(), before);
    assert!(f.store.requested.borrow().is_empty());
    assert!(!f.global.root.join(".sshw.lock").exists());
    assert_eq!(
        f.call(&[
            "--global", "endpoint", "global", "--port", "10022", "--yes", "--json"
        ])
        .exit_code,
        0
    );
    assert_eq!(
        load_config(&f.global.config_path).unwrap().servers["global"].port,
        10022
    );
    assert_eq!(
        f.call(&["policy", "allow", "command", "id", "--json"])
            .exit_code,
        0
    );
    let local_policy = std::fs::read(&f.local.policy_path).unwrap();
    assert!(String::from_utf8(local_policy).unwrap().contains("id"));
    let f = Fixture::new(ResourceMode::Local, ResourceMode::Global);
    let before = std::fs::read(&f.global.policy_path).unwrap();
    assert_eq!(
        f.call(&["policy", "allow", "command", "id", "--json"])
            .exit_code,
        3
    );
    assert_eq!(std::fs::read(&f.global.policy_path).unwrap(), before);
    assert_eq!(
        f.call(&["endpoint", "local", "--port", "10022", "--yes", "--json"])
            .exit_code,
        0
    );
}

#[test]
fn project_local_initialization_preserves_global_rules_and_protects_inherited_cleanup() {
    let f = Fixture::new(ResourceMode::Local, ResourceMode::Global);
    std::fs::write(&f.global.policy_path,r#"{"version":2,"enabled":true,"allow_commands":["global-command"],"allow_accounts":[{"server":"local","user":"ops"}]}"#).unwrap();
    let global_policy = std::fs::read(&f.global.policy_path).unwrap();
    let config = std::fs::read(&f.local.config_path).unwrap();
    let secrets = f.store.values.borrow().clone();
    let blocked = f.call(&["remove", "local", "--yes", "--json"]);
    assert_eq!(blocked.exit_code, 3);
    let blocked: serde_json::Value = serde_json::from_str(&blocked.stdout).unwrap();
    let message = blocked["error"]["message"].as_str().unwrap();
    assert!(message.contains("sshw --project-dir="), "{message}");
    assert!(message.contains("--policy-source local"), "{message}");
    assert_eq!(
        f.call(&["rename", "local", "renamed", "--json"]).exit_code,
        3
    );
    assert_eq!(std::fs::read(&f.local.config_path).unwrap(), config);
    assert_eq!(f.store.values.borrow().clone(), secrets);
    // Existing local data is kept; remove the previously unselected file to test copying.
    std::fs::remove_file(&f.local.policy_path).unwrap();
    let directory = f.cwd.to_str().unwrap();
    let output = f.call(&[
        "project",
        "init",
        "--policy-source",
        "local",
        "--project-dir",
        directory,
        "--json",
    ]);
    assert_eq!(output.exit_code, 0, "{output:?}");
    let selected: sshw::policy::PolicyFile =
        serde_json::from_slice(&std::fs::read(&f.local.policy_path).unwrap()).unwrap();
    assert!(selected.enabled);
    assert_eq!(selected.allow_accounts.len(), 1);
    let before = std::fs::read(f.local.root.join("project.json")).unwrap();
    let modified = std::fs::metadata(f.local.root.join("project.json"))
        .unwrap()
        .modified()
        .unwrap();
    let output = f.call(&["project", "init", "--project-dir", directory, "--json"]);
    assert_eq!(output.exit_code, 0);
    let body: serde_json::Value = serde_json::from_str(&output.stdout).unwrap();
    assert_eq!(body["changed"], false);
    assert_eq!(
        std::fs::read(f.local.root.join("project.json")).unwrap(),
        before
    );
    assert_eq!(
        std::fs::metadata(f.local.root.join("project.json"))
            .unwrap()
            .modified()
            .unwrap(),
        modified
    );
    assert_eq!(f.call(&["remove", "local", "--yes", "--json"]).exit_code, 0);
    assert_eq!(std::fs::read(&f.global.policy_path).unwrap(), global_policy);
    assert!(
        load_config(&f.global.config_path)
            .unwrap()
            .servers
            .contains_key("global")
    );
}

#[test]
fn project_explicit_selectors_bypass_discovery_and_unused_global_or_local_corruption() {
    let f = Fixture::new(ResourceMode::Local, ResourceMode::Local);
    std::fs::write(f.base.join("profiles.json"), "broken registry").unwrap();
    std::fs::write(&f.global.config_path, "broken global config").unwrap();
    assert_eq!(f.call(&["run", "local-command", "--json"]).exit_code, 0);
    let cli =
        Cli::try_parse_from(["sshw", "--home", f.local.root.to_str().unwrap(), "list"]).unwrap();
    let (home, _) = sshw::cli::resolve_runtime_at(&cli, &f.base, None, &f.cwd).unwrap();
    assert!(home.project.is_none());
    assert_eq!(home.namespace, f.local.namespace);
    let f = Fixture::new(ResourceMode::Global, ResourceMode::Global);
    std::fs::write(&f.local.config_path, "bad unused local").unwrap();
    std::fs::write(&f.local.policy_path, "bad unused local").unwrap();
    assert_eq!(f.call(&["run", "global-command", "--json"]).exit_code, 0);
    std::fs::write(f.local.root.join("project.json"), "broken project").unwrap();
    let cli = Cli::try_parse_from(["sshw", "--global", "list"]).unwrap();
    let (home, _) =
        sshw::cli::resolve_runtime_at(&cli, &f.base, Some(f.local.root.as_os_str()), &f.cwd)
            .unwrap();
    assert_eq!(home.namespace, f.global.namespace);
    assert!(home.project.is_none());
    let cli = Cli::try_parse_from(["sshw", "list"]).unwrap();
    assert!(sshw::cli::resolve_runtime_at(&cli, &f.base, None, &f.cwd).is_err());
}

#[test]
fn fully_local_project_initialization_ignores_an_unused_invalid_global_registry() {
    let f = Fixture::new(ResourceMode::Local, ResourceMode::Local);
    std::fs::write(f.base.join("profiles.json"), "broken unused registry").unwrap();
    std::fs::write(&f.global.config_path, "broken unused global config").unwrap();
    let manifest = f.local.root.join("project.json");
    let before = std::fs::read(&manifest).unwrap();
    let modified = std::fs::metadata(&manifest).unwrap().modified().unwrap();
    let policy = std::fs::read(&f.local.policy_path).unwrap();
    let credentials = f.store.values.borrow().clone();
    let output = f.call(&[
        "--project-dir",
        f.cwd.to_str().unwrap(),
        "project",
        "init",
        "--json",
    ]);
    assert_eq!(output.exit_code, 0, "{output:?}");
    let body: serde_json::Value = serde_json::from_str(&output.stdout).unwrap();
    assert_eq!(body["changed"], false);
    assert_eq!(std::fs::read(&manifest).unwrap(), before);
    assert_eq!(
        std::fs::metadata(&manifest).unwrap().modified().unwrap(),
        modified
    );
    assert_eq!(std::fs::read(&f.local.policy_path).unwrap(), policy);
    assert_eq!(f.store.values.borrow().clone(), credentials);
    assert!(f.store.requested.borrow().is_empty());
    assert_eq!(
        std::fs::read_to_string(f.base.join("profiles.json")).unwrap(),
        "broken unused registry"
    );
}

#[test]
fn local_initialization_plans_auto_new_lists_and_required_global_sources_independently() {
    for manifest_present in [false, true] {
        let f = Fixture::new(ResourceMode::Auto, ResourceMode::Auto);
        let manifest = f.local.root.join("project.json");
        if !manifest_present {
            std::fs::remove_file(&manifest).unwrap();
        }
        std::fs::write(f.base.join("profiles.json"), "broken unused registry").unwrap();
        let config = std::fs::read(&f.local.config_path).unwrap();
        let policy = std::fs::read(&f.local.policy_path).unwrap();
        let output = f.call(&[
            "--project-dir",
            f.cwd.to_str().unwrap(),
            "project",
            "init",
            "--json",
        ]);
        assert_eq!(output.exit_code, 0, "{output:?}");
        assert_eq!(std::fs::read(&f.local.config_path).unwrap(), config);
        assert_eq!(std::fs::read(&f.local.policy_path).unwrap(), policy);
        assert!(f.store.requested.borrow().is_empty());
        let body: serde_json::Value = serde_json::from_str(&output.stdout).unwrap();
        assert_eq!(body["changed"], !manifest_present);
        assert!(body["policy_copied_from"].is_null());
    }
    let f = Fixture::new(ResourceMode::Global, ResourceMode::Local);
    std::fs::remove_file(&f.local.config_path).unwrap();
    std::fs::write(f.base.join("profiles.json"), "broken unused registry").unwrap();
    let global = std::fs::read(&f.global.config_path).unwrap();
    let policy = std::fs::read(&f.local.policy_path).unwrap();
    let output = f.call(&[
        "--project-dir",
        f.cwd.to_str().unwrap(),
        "project",
        "init",
        "--servers-source",
        "local",
        "--json",
    ]);
    assert_eq!(output.exit_code, 0, "{output:?}");
    let body: serde_json::Value = serde_json::from_str(&output.stdout).unwrap();
    assert_eq!(body["servers_created"], true);
    assert_eq!(body["policy_created"], false);
    assert_eq!(f.call(&["list", "--json"]).stdout, "[]\n");
    assert_eq!(std::fs::read(&f.global.config_path).unwrap(), global);
    assert_eq!(std::fs::read(&f.local.policy_path).unwrap(), policy);
    let before = std::fs::read(f.local.root.join("project.json")).unwrap();
    for tail in [
        vec!["project", "init", "--policy-source", "global"],
        vec!["--global", "project", "init"],
        vec!["--profile", "prod", "project", "init"],
    ] {
        let cli = Cli::try_parse_from(std::iter::once("sshw").chain(tail)).unwrap();
        assert!(sshw::cli::resolve_runtime_at(&cli, &f.base, None, &f.cwd).is_err());
    }
    std::fs::remove_file(&f.local.policy_path).unwrap();
    let cli = Cli::try_parse_from(["sshw", "project", "init"]).unwrap();
    assert!(sshw::cli::resolve_runtime_at(&cli, &f.base, None, &f.cwd).is_err());
    assert!(!f.local.policy_path.exists());
    assert_eq!(
        std::fs::read(f.local.root.join("project.json")).unwrap(),
        before
    );
}
