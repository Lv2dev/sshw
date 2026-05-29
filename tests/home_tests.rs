use sshw::home::{ResolvedHome, resolve_home};
use std::path::{Path, PathBuf};

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
