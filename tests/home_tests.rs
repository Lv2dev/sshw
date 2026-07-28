use sshw::home::{CredentialNamespace, CredentialPurpose, ResolvedHome, validate_server_name};
use sshw::profile::{ProfileRegistry, resolve_home_with_registry};
use std::ffi::OsStr;
use std::path::{Path, PathBuf};

/// Resolve a home with an empty registry and no `--profile`, exercising the
/// `--home`/`SSHW_HOME`/built-in-default tail of the resolution chain. This is
/// the home-model invariant surface; profile/registry priority lives in
/// `profile_tests`.
fn resolve_home(home_flag: Option<&Path>, env_home: Option<&OsStr>, base: &Path) -> ResolvedHome {
    resolve_home_with_registry(home_flag, env_home, None, &ProfileRegistry::default(), base)
        .expect("empty registry without --profile never errors")
}

#[test]
fn default_home_resolves_under_profiles_default() {
    let base = PathBuf::from("/base/sshw");
    let resolved = resolve_home(None, None, &base);

    let home = base.join("profiles").join("default");
    assert_eq!(resolved.root, home);
    assert_eq!(resolved.config_path, home.join("servers.json"));
    assert_eq!(resolved.known_hosts_path, home.join("known_hosts"));
    assert_eq!(resolved.policy_path, home.join("policy.json"));
    assert_eq!(resolved.audit_path, home.join("audit.jsonl"));
    assert_eq!(resolved.namespace.token(), "default");
}

#[test]
fn home_flag_takes_priority_over_env() {
    let base = PathBuf::from("/base/sshw");
    let home = PathBuf::from("/project/.sshw");
    let env = PathBuf::from("/env/home");

    let resolved = resolve_home(Some(&home), Some(env.as_os_str()), &base);

    assert_eq!(resolved.root, home);
    assert_eq!(resolved.config_path, home.join("servers.json"));
    assert_eq!(resolved.known_hosts_path, home.join("known_hosts"));
}

#[test]
fn env_home_used_when_no_flag() {
    let base = PathBuf::from("/base/sshw");
    let env = PathBuf::from("/env/home");

    let resolved = resolve_home(None, Some(env.as_os_str()), &base);

    assert_eq!(resolved.root, env);
    assert_eq!(resolved.config_path, env.join("servers.json"));
}

#[test]
fn different_homes_produce_distinct_credential_namespaces() {
    let base = PathBuf::from("/base/sshw");
    let a = resolve_home(Some(Path::new("/home/a")), None, &base);
    let b = resolve_home(Some(Path::new("/home/b")), None, &base);

    assert_ne!(a.namespace.token(), b.namespace.token());
    assert_ne!(
        a.namespace.credential_key("web"),
        b.namespace.credential_key("web")
    );
}

#[test]
fn credential_keys_are_always_namespaced() {
    let base = PathBuf::from("/base/sshw");

    let default = resolve_home(None, None, &base);
    assert_eq!(default.namespace.credential_key("web"), "sshw:default:web");

    let adhoc = resolve_home(Some(Path::new("/home/a")), None, &base);
    let key = adhoc.namespace.credential_key("web");
    assert!(key.starts_with("sshw:home_"), "key was {key}");
    assert!(key.ends_with(":web"), "key was {key}");
    assert_ne!(key, "sshw:web");
}

#[test]
fn equivalent_home_paths_share_one_credential_namespace() {
    let base = PathBuf::from("/base/sshw");
    let dotted = resolve_home(Some(Path::new("/srv/data/../prod")), None, &base);
    let plain = resolve_home(Some(Path::new("/srv/prod")), None, &base);

    assert_eq!(dotted.namespace.token(), plain.namespace.token());
    assert_eq!(
        dotted.namespace.credential_key("web"),
        plain.namespace.credential_key("web")
    );
}

#[test]
fn from_config_path_treats_parent_directory_as_home() {
    let resolved = ResolvedHome::from_config_path(Path::new("/tmp/x/servers.json"));

    assert_eq!(resolved.config_path, PathBuf::from("/tmp/x/servers.json"));
    assert_eq!(
        resolved.known_hosts_path,
        PathBuf::from("/tmp/x/known_hosts")
    );
    assert_eq!(resolved.policy_path, PathBuf::from("/tmp/x/policy.json"));
    assert_eq!(resolved.audit_path, PathBuf::from("/tmp/x/audit.jsonl"));
    assert!(resolved.namespace.token().starts_with("home_"));
}

#[test]
fn v2_credential_keys_are_typed_and_delimiter_safe() {
    let namespace = CredentialNamespace::profile("default");

    let login = namespace.credential_key_v2(
        CredentialPurpose::Login,
        "privilege:web",
        "0000000000000001",
    );
    let privilege =
        namespace.credential_key_v2(CredentialPurpose::Privilege, "web", "0000000000000001");

    assert_ne!(login, privilege);
    assert!(!login.contains(":privilege:web:"));
    assert!(namespace.credential_key_matches(CredentialPurpose::Login, "privilege:web", &login));
    assert!(namespace.credential_key_matches(CredentialPurpose::Privilege, "web", &privilege));
}

#[test]
fn v2_credential_keys_are_injective_across_alias_and_purpose_pairs() {
    let namespace = CredentialNamespace::profile("profile:with:delimiters");
    let aliases = ["web", "db", "a:b", "privilege:web", "server-alpha"];
    let purposes = [CredentialPurpose::Login, CredentialPurpose::Privilege];

    for left_alias in aliases {
        for left_purpose in purposes {
            let left = namespace.credential_key_v2(left_purpose, left_alias, "0000000000000001");
            for right_alias in aliases {
                for right_purpose in purposes {
                    let right =
                        namespace.credential_key_v2(right_purpose, right_alias, "0000000000000001");
                    assert_eq!(
                        left == right,
                        left_alias == right_alias && left_purpose == right_purpose,
                        "left={left_purpose:?}:{left_alias}, right={right_purpose:?}:{right_alias}"
                    );
                }
            }
        }
    }
}

#[test]
fn v2_credential_key_validation_rejects_cross_boundary_references() {
    let namespace = CredentialNamespace::profile("profile-a");
    let other = CredentialNamespace::profile("profile-b");
    let key = namespace.credential_key_v2(CredentialPurpose::Login, "web", "0000000000000001");

    assert!(!other.credential_key_matches(CredentialPurpose::Login, "web", &key));
    assert!(!namespace.credential_key_matches(CredentialPurpose::Privilege, "web", &key));
    assert!(!namespace.credential_key_matches(CredentialPurpose::Login, "db", &key));
    assert!(!namespace.credential_key_matches(CredentialPurpose::Login, "web", "sshw:v2:broken"));
}

#[test]
fn legacy_credential_keys_are_accepted_only_for_the_expected_owner() {
    let namespace = CredentialNamespace::profile("default");
    let login = namespace.legacy_credential_key("web");
    let privilege = namespace.legacy_privilege_credential_key("web");

    assert!(namespace.credential_key_matches(CredentialPurpose::Login, "web", &login));
    assert!(namespace.credential_key_matches(CredentialPurpose::Privilege, "web", &privilege));
    assert!(!namespace.credential_key_matches(CredentialPurpose::Login, "db", &login));
}

#[test]
fn generated_credential_keys_use_distinct_generations() {
    let namespace = CredentialNamespace::profile("default");

    let first = namespace.new_credential_key(CredentialPurpose::Login, "web");
    let second = namespace.new_credential_key(CredentialPurpose::Login, "web");

    assert_ne!(first, second);
    assert!(namespace.credential_key_matches(CredentialPurpose::Login, "web", &first));
    assert!(namespace.credential_key_matches(CredentialPurpose::Login, "web", &second));
}

#[test]
fn server_names_reject_empty_control_and_reserved_forms() {
    assert!(validate_server_name("web").is_ok());
    assert!(validate_server_name("서버-alpha").is_ok());
    assert!(validate_server_name("").is_err());
    assert!(validate_server_name("privilege:web").is_err());
    assert!(validate_server_name("line\nbreak").is_err());
    assert!(validate_server_name("carriage\rreturn").is_err());
    assert!(validate_server_name("nul\0byte").is_err());
}
