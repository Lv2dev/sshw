use super::*;

#[derive(Default)]
struct Input {
    confirmations: Vec<String>,
    passwords: Vec<String>,
    stdin_calls: usize,
    cancel: bool,
}

impl Prompter for Input {
    fn confirm(&mut self, prompt: &str) -> anyhow::Result<bool> {
        self.confirmations.push(prompt.into());
        Ok(!self.cancel)
    }
    fn password(&mut self, prompt: &str) -> anyhow::Result<String> {
        self.passwords.push(prompt.into());
        Ok("SYNTHETIC_INPUT".into())
    }
    fn password_stdin(&mut self) -> anyhow::Result<String> {
        self.stdin_calls += 1;
        Ok("SYNTHETIC_INPUT".into())
    }
}

struct Fixture {
    _temp: tempfile::TempDir,
    home: ResolvedHome,
    registry: std::path::PathBuf,
    store: FakeCredentialStore,
    ssh: FakeSshClient,
}

impl Fixture {
    fn new() -> Self {
        let temp = tempfile::tempdir().unwrap();
        let home = ResolvedHome::from_config_path(&temp.path().join("servers.json"));
        let mut config = SshwConfig {
            default: Some("old".into()),
            ..Default::default()
        };
        let store = FakeCredentialStore::default();
        for (index, name) in ["old", "a-fallback", "z-chosen"].iter().enumerate() {
            let key =
                home.namespace
                    .new_account_credential_key(CredentialPurpose::Login, name, "ops");
            store.set_password(&key, "ops", "SYNTHETIC_LOGIN").unwrap();
            config.servers.insert(
                (*name).into(),
                ServerConfig::single_account(
                    "192.0.2.10",
                    2200 + index as u16,
                    "ops",
                    AuthConfig::Password { credential: key },
                ),
            );
        }
        save_config(&home.config_path, &config).unwrap();
        std::fs::write(&home.known_hosts_path, "preserved trust").unwrap();
        std::fs::write(&home.policy_path, r#"{"version":2,"enabled":true,"allow_commands":["id"],"allow_accounts":[{"server":"old","user":"ops"},{"server":"z-chosen","user":"ops"}]}"#).unwrap();
        let registry = temp.path().join("profiles.json");
        let profiles = ["old", "a-fallback", "z-chosen"]
            .into_iter()
            .map(|name| {
                let target = temp.path().join(name);
                std::fs::create_dir(&target).unwrap();
                std::fs::write(target.join("known_hosts"), "keep profile files").unwrap();
                (
                    name.into(),
                    ProfileEntry {
                        id: format!("p_{}", name.replace('-', "_")),
                        home: target,
                    },
                )
            })
            .collect();
        save_registry(
            &registry,
            &ProfileRegistry {
                default: Some("old".into()),
                profiles,
                ..Default::default()
            },
        )
        .unwrap();
        Self {
            _temp: temp,
            home,
            registry,
            store,
            ssh: FakeSshClient::default(),
        }
    }
    fn call(&self, args: Vec<&str>, input: &mut Input) -> sshw::cli::CommandOutput {
        let audit = FileAuditSink::new(self.home.audit_path.clone());
        sshw::cli::execute_for_runtime_with(
            Cli::try_parse_from(args).unwrap(),
            &ExecContext {
                home: &self.home,
                registry_path: &self.registry,
                policy_forced: false,
                audit: &audit,
            },
            &self.store,
            &self.ssh,
            input,
        )
    }
}

#[test]
fn removal_selects_or_clears_defaults_and_preserves_other_registrations() {
    for profile in [false, true] {
        for mode in [
            "switch",
            "clear",
            "automatic",
            "non-default",
            "unselected",
            "last",
        ] {
            for json in [false, true] {
                let f = Fixture::new();
                let mut config = load_config(&f.home.config_path).unwrap();
                let mut registry = load_registry(&f.registry).unwrap();
                if mode == "unselected" {
                    config.default = None;
                    registry.default = None;
                }
                if mode == "last" {
                    config.servers.retain(|name, _| name == "old");
                    registry.profiles.retain(|name, _| name == "old");
                }
                save_config(&f.home.config_path, &config).unwrap();
                save_registry(&f.registry, &registry).unwrap();
                let target = if mode == "non-default" {
                    "a-fallback"
                } else {
                    "old"
                };
                let mut args = vec!["sshw"];
                if profile {
                    args.push("profile");
                }
                args.extend(["remove", target]);
                if mode == "switch" {
                    args.extend(["--switch-default", "z-chosen"]);
                }
                if mode == "clear" || mode == "last" {
                    args.push("--clear-default");
                }
                if json {
                    args.push("--json");
                }
                let expected = match mode {
                    "switch" => Some("z-chosen"),
                    "clear" | "unselected" | "last" => None,
                    "non-default" => Some("old"),
                    _ => Some("a-fallback"),
                };
                let policy = std::fs::read(&f.home.policy_path).unwrap();
                let mut input = Input::default();
                let output = f.call(args, &mut input);
                assert_eq!(output.exit_code, 0, "{profile}/{mode}/{json}: {output:?}");
                let saved_config = load_config(&f.home.config_path).unwrap();
                let saved_registry = load_registry(&f.registry).unwrap();
                if profile {
                    registry.profiles.remove(target);
                    registry.default = expected.map(str::to_string);
                    assert_eq!(saved_registry, registry);
                    assert_eq!(saved_config, config);
                    assert!(f.store.deleted.borrow().is_empty());
                    assert_eq!(std::fs::read(&f.home.policy_path).unwrap(), policy);
                    assert!(input.confirmations.is_empty());
                } else {
                    config.servers.remove(target);
                    config.default = expected.map(str::to_string);
                    assert_eq!(saved_config, config);
                    assert_eq!(saved_registry, registry);
                    assert_eq!(f.store.deleted.borrow().len(), 1);
                    assert_eq!(input.confirmations.len(), 1);
                    if mode == "switch" {
                        assert!(
                            input.confirmations[0].contains("switch default server to 'z-chosen'")
                        );
                    }
                    if mode == "clear" {
                        assert!(
                            input.confirmations[0].contains("clear the default server selection")
                        );
                    }
                    let policy: serde_json::Value =
                        serde_json::from_slice(&std::fs::read(&f.home.policy_path).unwrap())
                            .unwrap();
                    assert_eq!(policy["enabled"], true);
                    assert_eq!(policy["allow_commands"], serde_json::json!(["id"]));
                    assert!(
                        policy["allow_accounts"]
                            .as_array()
                            .unwrap()
                            .iter()
                            .all(|grant| grant["server"] != target)
                    );
                }
                assert_eq!(
                    std::fs::read(&f.home.known_hosts_path).unwrap(),
                    b"preserved trust"
                );
                for entry in saved_registry.profiles.values() {
                    assert_eq!(
                        std::fs::read(entry.home.join("known_hosts")).unwrap(),
                        b"keep profile files"
                    );
                }
                assert!(f.store.requested.borrow().is_empty());
                assert!(f.ssh.selected_users.borrow().is_empty());
                assert!(input.passwords.is_empty());
                let records = std::fs::read_to_string(&f.home.audit_path).unwrap();
                let record: serde_json::Value =
                    serde_json::from_str(records.lines().last().unwrap()).unwrap();
                if mode == "switch" {
                    assert!(
                        record["detail"]
                            .as_str()
                            .unwrap()
                            .ends_with("switch-default:z-chosen")
                    );
                }
                if mode == "clear" || mode == "last" {
                    assert!(
                        record["detail"]
                            .as_str()
                            .unwrap()
                            .ends_with("clear-default")
                    );
                }
                if json {
                    let body: serde_json::Value = serde_json::from_str(&output.stdout).unwrap();
                    if matches!(mode, "non-default" | "unselected") {
                        assert!(body.get("default_change").is_none());
                    } else {
                        assert_eq!(body["default_change"]["previous"], "old");
                        assert_eq!(
                            body["default_change"]["current"],
                            serde_json::json!(expected)
                        );
                    }
                }
            }
        }
    }
}

#[test]
fn removal_rejects_invalid_default_selection_before_confirmation_or_writes() {
    for profile in [false, true] {
        for (target, flags, cancel) in [
            ("old", vec!["--switch-default", "missing"], false),
            ("old", vec!["--switch-default", "old"], false),
            ("a-fallback", vec!["--switch-default", "z-chosen"], false),
            ("a-fallback", vec!["--clear-default"], false),
            ("missing", vec!["--clear-default"], false),
            ("old", vec!["--switch-default", "z-chosen"], true),
        ] {
            if profile && cancel {
                continue;
            }
            let f = Fixture::new();
            let paths = [
                &f.home.config_path,
                &f.registry,
                &f.home.policy_path,
                &f.home.known_hosts_path,
            ];
            let before: Vec<_> = paths
                .iter()
                .map(|p| {
                    (
                        std::fs::read(p).unwrap(),
                        std::fs::metadata(p).unwrap().modified().unwrap(),
                    )
                })
                .collect();
            let secrets = f.store.values.borrow().clone();
            let mut args = vec!["sshw"];
            if profile {
                args.push("profile");
            }
            args.extend(["remove", target]);
            args.extend(flags);
            args.push("--json");
            let mut input = Input {
                cancel,
                ..Default::default()
            };
            let output = f.call(args, &mut input);
            assert_eq!(output.exit_code, 3, "{output:?}");
            let body: serde_json::Value = serde_json::from_str(&output.stdout).unwrap();
            assert_eq!(body["error"]["kind"], "config");
            assert!(body.get("mutation").is_none());
            for (path, (bytes, modified)) in paths.iter().zip(before) {
                assert_eq!(std::fs::read(path).unwrap(), bytes);
                assert_eq!(
                    std::fs::metadata(path).unwrap().modified().unwrap(),
                    modified
                );
            }
            assert_eq!(f.store.values.borrow().clone(), secrets);
            assert!(f.store.deleted.borrow().is_empty());
            assert_eq!(input.confirmations.len(), usize::from(cancel));
            assert!(input.passwords.is_empty());
        }
        for flags in [
            vec!["--switch-default"],
            vec!["--switch-default", "z-chosen", "--clear-default"],
        ] {
            let mut args = vec!["sshw"];
            if profile {
                args.push("profile");
            }
            args.extend(["remove", "old"]);
            args.extend(flags);
            assert!(Cli::try_parse_from(args).is_err());
        }
    }
}

#[test]
fn profile_removal_validates_explicit_replacement_and_recovers_broken_removed_home() {
    let f = Fixture::new();
    let mut registry = load_registry(&f.registry).unwrap();
    let chosen_home = registry.profiles["z-chosen"].home.clone();
    std::fs::write(chosen_home.join("servers.json"), "broken config").unwrap();
    let before = std::fs::read(&f.registry).unwrap();
    let output = f.call(
        vec![
            "sshw",
            "profile",
            "remove",
            "old",
            "--switch-default",
            "z-chosen",
            "--json",
        ],
        &mut Input::default(),
    );
    assert_eq!(output.exit_code, 3);
    assert_eq!(std::fs::read(&f.registry).unwrap(), before);
    std::fs::remove_file(chosen_home.join("servers.json")).unwrap();
    // Recovery of a legacy relative home still works; it is never resolved against cwd.
    registry.profiles.get_mut("old").unwrap().home = "legacy-relative-home".into();
    std::fs::write(&f.registry, serde_json::to_string(&registry).unwrap()).unwrap();
    let output = f.call(
        vec![
            "sshw",
            "profile",
            "remove",
            "old",
            "--switch-default",
            "z-chosen",
            "--json",
        ],
        &mut Input::default(),
    );
    assert_eq!(output.exit_code, 0, "{output:?}");
    assert_eq!(
        load_registry(&f.registry).unwrap().default.as_deref(),
        Some("z-chosen")
    );
    assert!(!Path::new("legacy-relative-home").exists());
}

#[test]
fn hidden_password_prompts_identify_selected_login_and_privilege_target() {
    let f = Fixture::new();
    let mut input = Input::default();
    for (args, expected) in [
        (
            vec![
                "sshw",
                "add",
                "web",
                "--host",
                "192.0.2.10",
                "--user",
                "deploy",
            ],
            "SSH password for 'web/deploy': ",
        ),
        (
            vec!["sshw", "account", "add", "web", "ops"],
            "SSH password for 'web/ops': ",
        ),
        (
            vec!["sshw", "password", "web"],
            "SSH password for 'web/deploy': ",
        ),
        (
            vec!["sshw", "password", "web", "--user", "ops"],
            "SSH password for 'web/ops': ",
        ),
        (
            vec![
                "sshw",
                "privilege",
                "set",
                "web",
                "--account",
                "ops",
                "--method",
                "su",
                "--user",
                "root",
            ],
            "Privilege password for 'web/ops' (su target: root): ",
        ),
        (
            vec!["sshw", "password", "web", "--user", "ops", "--privilege"],
            "Privilege password for 'web/ops' (su target: root): ",
        ),
        (
            vec![
                "sshw",
                "privilege",
                "set",
                "web",
                "--account",
                "deploy",
                "--method",
                "sudo",
                "--user",
                "service",
            ],
            "Privilege password for 'web/deploy' (sudo target: service): ",
        ),
        (
            vec!["sshw", "password", "web", "--privilege"],
            "Privilege password for 'web/deploy' (sudo target: service): ",
        ),
    ] {
        let count = input.passwords.len();
        let output = f.call(args, &mut input);
        assert_eq!(output.exit_code, 0, "{output:?}");
        assert_eq!(input.passwords.len(), count + 1);
        assert_eq!(input.passwords.last().unwrap(), expected);
        assert!(!output.stdout.contains("SYNTHETIC_INPUT"));
    }
    let count = input.passwords.len();
    for args in [
        vec![
            "sshw",
            "add",
            "stdin-web",
            "--host",
            "192.0.2.20",
            "--user",
            "ops",
            "--password-stdin",
        ],
        vec![
            "sshw",
            "account",
            "add",
            "stdin-web",
            "deploy",
            "--password-stdin",
        ],
        vec!["sshw", "password", "stdin-web", "--password-stdin"],
        vec![
            "sshw",
            "privilege",
            "set",
            "stdin-web",
            "--method",
            "su",
            "--password-stdin",
        ],
        vec![
            "sshw",
            "password",
            "stdin-web",
            "--privilege",
            "--password-stdin",
        ],
    ] {
        assert_eq!(f.call(args, &mut input).exit_code, 0);
    }
    assert_eq!(input.passwords.len(), count);
    assert_eq!(input.stdin_calls, 5);
    assert!(f.store.requested.borrow().is_empty());
    assert!(f.ssh.selected_users.borrow().is_empty());
}

#[test]
fn hidden_password_targets_are_masked_individually() {
    let f = Fixture::new();
    let mut input = Input::default();
    for args in [
        vec![
            "sshw",
            "add",
            "password=server-private",
            "--host",
            "192.0.2.10",
            "--user",
            "token=login-private",
        ],
        vec![
            "sshw",
            "privilege",
            "set",
            "password=server-private",
            "--method",
            "su",
            "--user",
            "secret=target-private",
        ],
        vec!["sshw", "password", "password=server-private", "--privilege"],
    ] {
        assert_eq!(f.call(args, &mut input).exit_code, 0);
        let prompt = input.passwords.last().unwrap();
        for private in ["server-private", "login-private", "target-private"] {
            assert!(!prompt.contains(private), "{prompt}");
        }
        assert!(prompt.contains("<redacted>"));
    }
    assert!(input.passwords[1].contains("su target:"));
}
