use sshw::policy::{Policy, describe_policy, resolve_policy};
use std::fs;

fn write_policy(dir: &std::path::Path, contents: &str) -> std::path::PathBuf {
    let path = dir.join("policy.json");
    fs::write(&path, contents).unwrap();
    path
}

#[test]
fn missing_file_without_force_is_disabled() {
    let temp = tempfile::tempdir().unwrap();
    let path = temp.path().join("policy.json");

    assert_eq!(resolve_policy(&path, false).unwrap(), Policy::Disabled);
}

#[test]
fn missing_file_with_force_fails_closed() {
    let temp = tempfile::tempdir().unwrap();
    let path = temp.path().join("policy.json");

    let err = resolve_policy(&path, true).unwrap_err();

    assert!(err.to_string().contains("no policy file"));
}

#[test]
fn invalid_file_fails_closed_even_without_force() {
    let temp = tempfile::tempdir().unwrap();
    let path = write_policy(temp.path(), "{ this is not json");

    let err = resolve_policy(&path, false).unwrap_err();

    assert!(err.to_string().contains("invalid policy file"));
}

#[test]
fn policy_rejects_unknown_fields_and_future_versions() {
    let unknown_dir = tempfile::tempdir().unwrap();
    let unknown = write_policy(
        unknown_dir.path(),
        r#"{"version":1,"enable":true,"allow_commands":["ls"]}"#,
    );
    let err = resolve_policy(&unknown, false).unwrap_err();
    assert!(err.to_string().contains("unknown field"));

    let future_dir = tempfile::tempdir().unwrap();
    let future = write_policy(
        future_dir.path(),
        r#"{"version":3,"enabled":true,"allow_commands":["ls"]}"#,
    );
    let err = resolve_policy(&future, false).unwrap_err();
    assert!(err.to_string().contains("unsupported policy version 3"));
    assert!(err.to_string().contains("supported versions are 1 and 2"));

    let nested_dir = tempfile::tempdir().unwrap();
    let nested = write_policy(
        nested_dir.path(),
        r#"{
            "version":2,
            "enabled":true,
            "allow_accounts":[{"server":"web","user":"ops","unexpected":true}]
        }"#,
    );
    let err = resolve_policy(&nested, false).unwrap_err();
    assert!(err.to_string().contains("unknown field"));
}

#[cfg(unix)]
#[test]
fn dangling_policy_symlink_fails_closed() {
    use std::os::unix::fs::symlink;

    let temp = tempfile::tempdir().unwrap();
    let path = temp.path().join("policy.json");
    symlink(temp.path().join("missing-policy.json"), &path).unwrap();

    let err = resolve_policy(&path, false).unwrap_err();

    assert!(err.to_string().contains("failed to read policy file"));
    let status = describe_policy(&path, false);
    assert!(status.present);
    assert!(!status.valid);
}

#[test]
fn valid_enabled_file_enforces_allowlist() {
    let temp = tempfile::tempdir().unwrap();
    let path = write_policy(
        temp.path(),
        r#"{"version":1,"enabled":true,"allow_commands":["ls"]}"#,
    );

    match resolve_policy(&path, false).unwrap() {
        Policy::Enabled(rules) => {
            assert!(rules.allows_command("ls -la"));
            assert!(!rules.allows_command("rm -rf /"));
            assert!(rules.allows_account("web", "deploy", true));
            assert!(!rules.allows_account("web", "ops", false));
        }
        Policy::Disabled => panic!("expected enabled policy"),
    }
}

#[test]
fn policy_v2_allows_only_exact_registered_non_default_accounts() {
    let temp = tempfile::tempdir().unwrap();
    let path = write_policy(
        temp.path(),
        r#"{
            "version": 2,
            "enabled": true,
            "allow_commands": ["whoami"],
            "allow_accounts": [
                { "server": "web", "user": "ops" },
                { "server": "db", "user": "reader" }
            ]
        }"#,
    );

    match resolve_policy(&path, false).unwrap() {
        Policy::Enabled(rules) => {
            assert!(rules.allows_account("web", "deploy", true));
            assert!(rules.allows_account("web", "ops", false));
            assert!(rules.allows_account("db", "reader", false));
            assert!(!rules.allows_account("web", "reader", false));
            assert!(!rules.allows_account("db", "ops", false));
        }
        Policy::Disabled => panic!("expected enabled policy"),
    }
}

#[test]
fn valid_disabled_file_without_force_is_disabled() {
    let temp = tempfile::tempdir().unwrap();
    let path = write_policy(temp.path(), r#"{"enabled":false,"allow_commands":["ls"]}"#);

    assert_eq!(resolve_policy(&path, false).unwrap(), Policy::Disabled);
}

#[test]
fn force_flag_overrides_disabled_file() {
    let temp = tempfile::tempdir().unwrap();
    let path = write_policy(temp.path(), r#"{"enabled":false,"allow_commands":["ls"]}"#);

    match resolve_policy(&path, true).unwrap() {
        Policy::Enabled(rules) => assert!(rules.allows_command("ls")),
        Policy::Disabled => panic!("expected --policy to force enforcement"),
    }
}

#[test]
fn glob_star_entry_does_not_match_everything() {
    let temp = tempfile::tempdir().unwrap();
    let path = write_policy(temp.path(), r#"{"enabled":true,"allow_commands":["*"]}"#);

    match resolve_policy(&path, false).unwrap() {
        Policy::Enabled(rules) => {
            assert!(!rules.allows_command("rm -rf /home"));
            assert!(!rules.allows_command("whoami"));
        }
        Policy::Disabled => panic!("expected enabled policy"),
    }
}

#[test]
fn empty_path_entry_does_not_allow_everything() {
    let temp = tempfile::tempdir().unwrap();
    let path = write_policy(temp.path(), r#"{"enabled":true,"allow_get_paths":[""]}"#);

    match resolve_policy(&path, false).unwrap() {
        Policy::Enabled(rules) => assert!(!rules.allows_get("/etc/passwd")),
        Policy::Disabled => panic!("expected enabled policy"),
    }
}

#[test]
fn trailing_slash_path_entry_matches_children() {
    let temp = tempfile::tempdir().unwrap();
    let path = write_policy(
        temp.path(),
        r#"{"enabled":true,"allow_put_paths":["/srv/app/"]}"#,
    );

    match resolve_policy(&path, false).unwrap() {
        Policy::Enabled(rules) => {
            assert!(rules.allows_put("/srv/app/bin/run"));
            assert!(!rules.allows_put("/etc/passwd"));
        }
        Policy::Disabled => panic!("expected enabled policy"),
    }
}

#[test]
fn command_allowlist_rejects_metacharacter_bypass_samples() {
    let temp = tempfile::tempdir().unwrap();
    let path = write_policy(
        temp.path(),
        r#"{"enabled":true,"allow_commands":["ls","uptime","systemctl status *"]}"#,
    );

    match resolve_policy(&path, false).unwrap() {
        Policy::Enabled(rules) => {
            assert!(rules.allows_command("ls -la /srv"));
            assert!(rules.allows_command("uptime"));
            assert!(rules.allows_command("systemctl status nginx"));

            for command in [
                "ls; whoami",
                "ls && whoami",
                "ls | sh",
                "ls $(whoami)",
                "ls `whoami`",
                "ls > /tmp/out",
                "ls\nwhoami",
                "/bin/ls && rm -rf /",
                "uptime || reboot",
                "systemctl status nginx && reboot",
                "systemctl status nginx; reboot",
            ] {
                assert!(
                    !rules.allows_command(command),
                    "metacharacter sample was allowed: {command:?}"
                );
            }
        }
        Policy::Disabled => panic!("expected enabled policy"),
    }
}

#[test]
fn transfer_allowlist_rejects_sibling_and_traversal_samples() {
    let temp = tempfile::tempdir().unwrap();
    let path = write_policy(
        temp.path(),
        r#"{"enabled":true,"allow_put_paths":["/srv/app"],"allow_get_paths":["/var/log"]}"#,
    );

    match resolve_policy(&path, false).unwrap() {
        Policy::Enabled(rules) => {
            assert!(rules.allows_put("/srv/app"));
            assert!(rules.allows_put("/srv/app/bin/run"));
            assert!(rules.allows_get("/var/log"));
            assert!(rules.allows_get("/var/log/syslog"));

            for path in [
                "/srv/app2",
                "/srv/application",
                "/srv/app../secret",
                "/srv/app/../secret",
                "/srv/app/../../etc/passwd",
                "/srv/app\\..\\secret",
                "/srv/app\\..\\..\\etc\\passwd",
            ] {
                assert!(
                    !rules.allows_put(path),
                    "put path sample was allowed: {path:?}"
                );
            }

            for path in [
                "/var/logs",
                "/var/login",
                "/var/log../secret",
                "/var/log/../secret",
                "/var/log/../../root/.ssh/id_rsa",
                "/var/log\\..\\secret",
                "/var/log\\..\\..\\root\\.ssh\\id_rsa",
            ] {
                assert!(
                    !rules.allows_get(path),
                    "get path sample was allowed: {path:?}"
                );
            }
        }
        Policy::Disabled => panic!("expected enabled policy"),
    }
}

#[test]
fn unreadable_policy_file_classifies_as_policy() {
    let temp = tempfile::tempdir().unwrap();
    // A directory named policy.json cannot be read as a file.
    let path = temp.path().join("policy.json");
    std::fs::create_dir(&path).unwrap();

    let err = resolve_policy(&path, false).unwrap_err();

    assert!(err.to_string().contains("policy file"), "err was {err}");
}

#[test]
fn describe_policy_reports_status_without_erroring() {
    let temp = tempfile::tempdir().unwrap();
    let missing = temp.path().join("policy.json");
    let status = describe_policy(&missing, false);
    assert!(!status.present);
    assert!(status.valid);
    assert!(!status.enabled);

    let valid = write_policy(temp.path(), r#"{"enabled":true,"allow_commands":["ls"]}"#);
    let status = describe_policy(&valid, false);
    assert!(status.present);
    assert!(status.valid);
    assert!(status.enabled);

    let invalid_dir = tempfile::tempdir().unwrap();
    let invalid = write_policy(invalid_dir.path(), "nope");
    let status = describe_policy(&invalid, false);
    assert!(status.present);
    assert!(!status.valid);
}
