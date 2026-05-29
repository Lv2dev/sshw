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
