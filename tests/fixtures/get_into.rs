use super::*;

#[test]
fn get_into_and_preflight_resolve_the_same_basename_user_and_audit_source() {
    for explicit in [false, true] {
        for preflight in [false, true] {
            for (remote, decoded) in [
                ("/logs/app.log", "/logs/app.log"),
                ("remote:/logs/app.log", "/logs/app.log"),
                (r"remote:C:\logs\app.log", r"C:\logs\app.log"),
                (r"remote:\\srv\share\app.log", r"\\srv\share\app.log"),
                ("/logs/개발 ' log.txt", "/logs/개발 ' log.txt"),
            ] {
                let temp = tempfile::tempdir().unwrap();
                let path = temp.path().join("servers.json");
                let home = ResolvedHome::from_config_path(&path);
                let mut server =
                    ServerConfig::single_account("192.0.2.10", 22, "deploy", AuthConfig::Agent);
                server.accounts.insert(
                    "ops".into(),
                    AccountConfig {
                        auth: AuthConfig::Agent,
                        privilege: None,
                    },
                );
                save_config(
                    &path,
                    &SshwConfig {
                        default: Some("web".into()),
                        servers: BTreeMap::from([("web".into(), server)]),
                        ..Default::default()
                    },
                )
                .unwrap();
                let before = std::fs::read(&path).unwrap();
                let registry = temp.path().join("profiles.json");
                let audit = FileAuditSink::new(home.audit_path.clone());
                let ctx = ExecContext {
                    home: &home,
                    registry_path: &registry,
                    policy_forced: false,
                    audit: &audit,
                };
                let into = temp.path().join("missing folder").join("downloads");
                let mut args = vec!["sshw"];
                if preflight {
                    args.extend(["policy", "check-get"]);
                } else {
                    args.push("get");
                }
                if explicit {
                    args.push("web");
                }
                args.extend([
                    remote,
                    "--into",
                    into.to_str().unwrap(),
                    "--user",
                    "ops",
                    "--json",
                ]);
                let store = FakeCredentialStore::default();
                let ssh = FakeSshClient::default();
                let output = execute_with(
                    Cli::try_parse_from(args).unwrap(),
                    &ctx,
                    &store,
                    &ssh,
                    &mut NoPasswordPrompter { prompts: vec![] },
                )
                .unwrap();
                let body: serde_json::Value = serde_json::from_str(&output.stdout).unwrap();
                let basename = if decoded.starts_with("/logs/개발") {
                    "개발 ' log.txt"
                } else {
                    "app.log"
                };
                assert_eq!(body["local"], into.join(basename).to_str().unwrap());
                assert_eq!(body["remote"], decoded);
                assert_eq!(body["server"], "web");
                assert_eq!(body["user"], "ops");
                assert!(
                    !into.exists(),
                    "preflight/fake transfer must not create directories"
                );
                assert_eq!(std::fs::read(&path).unwrap(), before);
                assert!(store.requested.borrow().is_empty());
                if preflight {
                    assert_eq!(body["allowed"], true);
                    assert!(ssh.get_calls.borrow().is_empty());
                    assert!(!home.audit_path.exists());
                } else {
                    assert_eq!(*ssh.get_remote_calls.borrow(), vec![decoded]);
                    assert_eq!(*ssh.selected_users.borrow(), vec!["ops"]);
                    let records = std::fs::read_to_string(&home.audit_path).unwrap();
                    let record: serde_json::Value =
                        serde_json::from_str(records.lines().last().unwrap()).unwrap();
                    assert_eq!(record["action"], "get");
                    assert_eq!(record["server"], "web");
                    assert_eq!(record["user"], "ops");
                    assert_eq!(record["detail"], decoded);
                }
            }
        }
    }
}

#[test]
fn get_into_preserves_overwrite_parent_policy_and_invalid_basename_guards() {
    for preflight in [false, true] {
        for case in [
            "existing",
            "directory",
            "parent-file",
            "denied",
            "traversal",
            "empty-name",
            "dot-name",
            "control-name",
        ] {
            let temp = tempfile::tempdir().unwrap();
            let path = temp.path().join("servers.json");
            save_config(
                &path,
                &SshwConfig {
                    default: Some("web".into()),
                    servers: BTreeMap::from([(
                        "web".into(),
                        ServerConfig::single_account("192.0.2.10", 22, "deploy", AuthConfig::Agent),
                    )]),
                    ..Default::default()
                },
            )
            .unwrap();
            std::fs::write(
                temp.path().join("policy.json"),
                r#"{"enabled":true,"allow_get_paths":["/logs"]}"#,
            )
            .unwrap();
            let into = temp.path().join("downloads");
            if case == "parent-file" {
                std::fs::write(&into, "original parent").unwrap();
            } else {
                std::fs::create_dir(&into).unwrap();
            }
            let destination = into.join("app.log");
            if case == "existing" {
                std::fs::write(&destination, "original file").unwrap();
            }
            if case == "directory" {
                std::fs::create_dir(&destination).unwrap();
            }
            let remote = match case {
                "denied" => "/private/app.log",
                "traversal" => "/logs/../app.log",
                "empty-name" => "/logs/",
                "dot-name" => "/logs/..",
                "control-name" => "/logs/bad\nname",
                _ => "/logs/app.log",
            };
            let store = FakeCredentialStore::default();
            let ssh = FakeSshClient::default();
            let mut args = vec!["sshw"];
            if preflight {
                args.extend(["policy", "check-get"]);
            } else {
                args.push("get");
            }
            args.extend(["web", remote, "--into", into.to_str().unwrap(), "--json"]);
            let output = execute_for_runtime(
                Cli::try_parse_from(args.clone()).unwrap(),
                &path,
                &store,
                &ssh,
                &mut NoPasswordPrompter { prompts: vec![] },
            );
            let expected = match case {
                "denied" | "traversal" => 7,
                "empty-name" | "dot-name" | "control-name" => 9,
                _ => 6,
            };
            assert_eq!(output.exit_code, expected, "{case}: {output:?}");
            assert!(ssh.get_calls.borrow().is_empty());
            assert!(store.requested.borrow().is_empty());
            if case == "existing" {
                assert_eq!(std::fs::read(&destination).unwrap(), b"original file");
                args.push("--yes");
                let output = execute_for_runtime(
                    Cli::try_parse_from(args).unwrap(),
                    &path,
                    &store,
                    &ssh,
                    &mut NoPasswordPrompter { prompts: vec![] },
                );
                assert_eq!(output.exit_code, 0, "{output:?}");
                assert_eq!(std::fs::read(&destination).unwrap(), b"original file");
                if !preflight {
                    assert_eq!(*ssh.get_calls.borrow(), vec![true]);
                }
            }
            if case == "directory" {
                assert!(destination.is_dir());
            }
            if case == "parent-file" {
                assert_eq!(std::fs::read(&into).unwrap(), b"original parent");
            }
        }
    }
}
