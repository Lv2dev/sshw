use sshw::profile::{
    ProfileEntry, ProfileRegistry, load_registry, load_registry_with_revision,
    resolve_home_with_registry, save_registry, save_registry_if_unchanged,
};
use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};

fn registry_with(name: &str, id: &str, home: &str) -> ProfileRegistry {
    let mut profiles = BTreeMap::new();
    profiles.insert(
        name.to_string(),
        ProfileEntry {
            id: id.to_string(),
            home: PathBuf::from(home),
        },
    );
    ProfileRegistry {
        version: 1,
        default: None,
        profiles,
    }
}

#[test]
fn registry_round_trips_and_defaults_to_empty() {
    let temp = tempfile::tempdir().unwrap();
    let path = temp.path().join("profiles.json");

    assert_eq!(load_registry(&path).unwrap(), ProfileRegistry::default());

    let home = temp.path().join("prod-home");
    let mut registry = registry_with("prod", "p_prod", &home.to_string_lossy());
    registry.default = Some("prod".to_string());
    save_registry(&path, &registry).unwrap();

    assert_eq!(load_registry(&path).unwrap(), registry);
}

#[test]
fn stale_registry_revision_cannot_overwrite_external_change() {
    let temp = tempfile::tempdir().unwrap();
    let path = temp.path().join("profiles.json");
    save_registry(&path, &ProfileRegistry::default()).unwrap();

    let (mut stale, revision) = load_registry_with_revision(&path).unwrap();
    let external_home = temp.path().join("external");
    let mut external = registry_with("external", "p_external", &external_home.to_string_lossy());
    external.default = Some("external".to_string());
    save_registry(&path, &external).unwrap();

    stale.profiles.insert(
        "stale".to_string(),
        ProfileEntry {
            id: "p_stale".to_string(),
            home: temp.path().join("stale"),
        },
    );
    let err = save_registry_if_unchanged(&path, &stale, &revision).unwrap_err();

    assert!(err.to_string().contains("changed concurrently"));
    assert_eq!(load_registry(&path).unwrap(), external);
}

#[test]
fn registry_rejects_unknown_fields_and_future_versions() {
    let temp = tempfile::tempdir().unwrap();
    let path = temp.path().join("profiles.json");
    fs::write(
        &path,
        r#"{"version":1,"default":null,"profiles":{},"unexpected":true}"#,
    )
    .unwrap();
    assert!(
        load_registry(&path)
            .unwrap_err()
            .to_string()
            .contains("unknown field")
    );

    let nested = serde_json::json!({
        "version": 1,
        "default": null,
        "profiles": {
            "prod": {
                "id": "p_prod",
                "home": temp.path().join("prod"),
                "unexpected": true
            }
        }
    });
    fs::write(&path, serde_json::to_vec(&nested).unwrap()).unwrap();
    assert!(
        load_registry(&path)
            .unwrap_err()
            .to_string()
            .contains("unknown field")
    );

    fs::write(&path, r#"{"version":2,"default":null,"profiles":{}}"#).unwrap();
    let err = load_registry(&path).unwrap_err();
    assert!(
        err.to_string()
            .contains("unsupported profile registry version 2")
    );
    assert!(err.to_string().contains("supported version is 1"));
}

#[test]
fn registry_rejects_relative_homes_and_duplicate_ids() {
    let temp = tempfile::tempdir().unwrap();
    let path = temp.path().join("profiles.json");
    let relative = serde_json::json!({
        "version": 1,
        "default": "prod",
        "profiles": {
            "prod": { "id": "p_prod", "home": "relative/home" }
        }
    });
    fs::write(&path, serde_json::to_vec(&relative).unwrap()).unwrap();
    let err = load_registry(&path).unwrap_err();
    assert!(err.to_string().contains("home must be absolute"));

    let duplicate = serde_json::json!({
        "version": 1,
        "default": "prod",
        "profiles": {
            "prod": { "id": "p_shared", "home": temp.path().join("prod") },
            "stage": { "id": "p_shared", "home": temp.path().join("stage") }
        }
    });
    fs::write(&path, serde_json::to_vec(&duplicate).unwrap()).unwrap();
    let err = load_registry(&path).unwrap_err();
    assert!(
        err.to_string()
            .contains("duplicate credential namespace id")
    );

    let forged = serde_json::json!({
        "version": 1,
        "default": "prod",
        "profiles": {
            "prod": { "id": "p_prod:stage", "home": temp.path().join("prod") }
        }
    });
    fs::write(&path, serde_json::to_vec(&forged).unwrap()).unwrap();
    let err = load_registry(&path).unwrap_err();
    assert!(
        err.to_string().contains("invalid credential namespace id"),
        "error was: {err:#}"
    );
}

#[cfg(unix)]
#[test]
fn dangling_registry_symlink_is_not_treated_as_missing() {
    use std::os::unix::fs::symlink;

    let temp = tempfile::tempdir().unwrap();
    let path = temp.path().join("profiles.json");
    symlink(temp.path().join("missing-profiles.json"), &path).unwrap();

    let err = load_registry(&path).unwrap_err();

    assert!(err.to_string().contains("failed to load profile registry"));
}

#[test]
fn home_flag_beats_everything() {
    let base = PathBuf::from("/base/sshw");
    let registry = {
        let mut r = registry_with("prod", "p_prod", "/homes/prod");
        r.default = Some("prod".to_string());
        r
    };

    let resolved = resolve_home_with_registry(
        Some(Path::new("/explicit")),
        Some(std::ffi::OsStr::new("/env")),
        None,
        &registry,
        &base,
    )
    .unwrap();

    assert_eq!(resolved.root, PathBuf::from("/explicit"));
}

#[test]
fn env_beats_profile_and_default() {
    let base = PathBuf::from("/base/sshw");
    let mut registry = registry_with("prod", "p_prod", "/homes/prod");
    registry.default = Some("prod".to_string());

    let resolved = resolve_home_with_registry(
        None,
        Some(std::ffi::OsStr::new("/env")),
        Some("prod"),
        &registry,
        &base,
    )
    .unwrap();

    assert_eq!(resolved.root, PathBuf::from("/env"));
}

#[test]
fn profile_flag_beats_registry_default() {
    let base = PathBuf::from("/base/sshw");
    let mut registry = registry_with("prod", "p_prod", "/homes/prod");
    registry.profiles.insert(
        "stage".to_string(),
        ProfileEntry {
            id: "p_stage".to_string(),
            home: PathBuf::from("/homes/stage"),
        },
    );
    registry.default = Some("prod".to_string());

    let resolved = resolve_home_with_registry(None, None, Some("stage"), &registry, &base).unwrap();

    assert_eq!(resolved.root, PathBuf::from("/homes/stage"));
    assert_eq!(resolved.namespace.token(), "p_stage");
}

#[test]
fn registry_default_used_when_no_flag_or_env() {
    let base = PathBuf::from("/base/sshw");
    let mut registry = registry_with("prod", "p_prod", "/homes/prod");
    registry.default = Some("prod".to_string());

    let resolved = resolve_home_with_registry(None, None, None, &registry, &base).unwrap();

    assert_eq!(resolved.root, PathBuf::from("/homes/prod"));
    assert_eq!(resolved.namespace.token(), "p_prod");
}

#[test]
fn builtin_default_used_when_registry_empty() {
    let base = PathBuf::from("/base/sshw");
    let registry = ProfileRegistry::default();

    let resolved = resolve_home_with_registry(None, None, None, &registry, &base).unwrap();

    assert_eq!(resolved.root, base.join("profiles").join("default"));
    assert_eq!(resolved.namespace.token(), "default");
}

#[test]
fn home_and_profile_together_is_an_error() {
    let base = PathBuf::from("/base/sshw");
    let registry = registry_with("prod", "p_prod", "/homes/prod");

    let err = resolve_home_with_registry(
        Some(Path::new("/explicit")),
        None,
        Some("prod"),
        &registry,
        &base,
    )
    .unwrap_err();

    assert!(err.to_string().contains("cannot use --home and --profile"));
}

#[test]
fn unknown_profile_is_an_error() {
    let base = PathBuf::from("/base/sshw");
    let registry = ProfileRegistry::default();

    let err =
        resolve_home_with_registry(None, None, Some("missing"), &registry, &base).unwrap_err();

    assert!(err.to_string().contains("unknown profile 'missing'"));
}

#[test]
fn reserved_profile_id_is_rejected() {
    let base = PathBuf::from("/base/sshw");
    // A registry whose entry reuses the built-in default token must not be
    // silently honored (it would share the credential namespace).
    let registry = registry_with("prod", "default", "/homes/prod");

    let err = resolve_home_with_registry(None, None, Some("prod"), &registry, &base).unwrap_err();

    assert!(err.to_string().contains("reserved id"));
}

#[test]
fn distinct_profiles_never_collide_on_paths_or_credentials() {
    let base = PathBuf::from("/base/sshw");
    let mut registry = registry_with("prod", "p_prod", "/homes/prod");
    registry.profiles.insert(
        "stage".to_string(),
        ProfileEntry {
            id: "p_stage".to_string(),
            home: PathBuf::from("/homes/stage"),
        },
    );

    let prod = resolve_home_with_registry(None, None, Some("prod"), &registry, &base).unwrap();
    let stage = resolve_home_with_registry(None, None, Some("stage"), &registry, &base).unwrap();

    // Same server name, different profiles -> no collision anywhere.
    assert_ne!(prod.config_path, stage.config_path);
    assert_ne!(prod.known_hosts_path, stage.known_hosts_path);
    assert_ne!(
        prod.namespace.credential_key("web"),
        stage.namespace.credential_key("web")
    );
    assert_eq!(prod.namespace.credential_key("web"), "sshw:p_prod:web");
    assert_eq!(stage.namespace.credential_key("web"), "sshw:p_stage:web");
}
