use sshw::error::ResultErrorKindExt;
use sshw::home::ResolvedHome;
use sshw::output::{ErrorKind, ErrorResponse};
use sshw::profile::{ProfileEntry, ProfileRegistry, resolve_home_with_registry};
use std::path::Path;

#[test]
fn home_readiness_rejects_files_for_every_home_source_and_preserves_the_cause() {
    let temp = tempfile::tempdir().unwrap();
    let file = temp.path().join("file");
    std::fs::write(&file, "preserve").unwrap();
    let modified = std::fs::metadata(&file).unwrap().modified().unwrap();
    for path in [&file, &file.join("child").join("home")] {
        let mut registry = ProfileRegistry {
            default: Some("prod".into()),
            ..Default::default()
        };
        registry.profiles.insert(
            "prod".into(),
            ProfileEntry {
                id: "p_prod".into(),
                home: path.clone(),
            },
        );
        let failures = [
            resolve_home_with_registry(Some(path), None, None, &registry, temp.path()),
            resolve_home_with_registry(None, Some(path.as_os_str()), None, &registry, temp.path()),
            resolve_home_with_registry(None, None, Some("prod"), &registry, temp.path()),
            resolve_home_with_registry(None, None, None, &registry, temp.path()),
            resolve_home_with_registry(None, None, None, &ProfileRegistry::default(), path),
        ];
        for failure in failures {
            let error = failure.with_error_kind(ErrorKind::Config).unwrap_err();
            assert!(error.to_string().contains("requires a directory"));
            assert!(error.to_string().contains("--home/SSHW_HOME"));
            let io = error
                .chain()
                .find_map(|cause| cause.downcast_ref::<std::io::Error>())
                .unwrap();
            assert_eq!(io.kind(), std::io::ErrorKind::NotADirectory);
            let response = ErrorResponse::from_error(&error);
            assert_eq!(response.error.kind, ErrorKind::Config);
            assert_eq!(response.error.exit_code, 3);
        }
    }
    assert_eq!(std::fs::read(&file).unwrap(), b"preserve");
    assert_eq!(
        std::fs::metadata(&file).unwrap().modified().unwrap(),
        modified
    );
}

#[test]
fn home_readiness_preserves_relative_selection_missing_directories_and_conflict_priority() {
    let temp = tempfile::tempdir_in(".").unwrap();
    let home = Path::new(".")
        .join(temp.path().file_name().unwrap())
        .join("missing")
        .join("home");
    assert!(!home.is_absolute());
    let registry = ProfileRegistry::default();
    let resolved =
        resolve_home_with_registry(Some(&home), None, None, &registry, temp.path()).unwrap();
    assert_eq!(
        resolved,
        ResolvedHome::ad_hoc(&home, format!("--home {}", home.display()))
    );
    assert!(!home.exists());
    let current =
        resolve_home_with_registry(Some(Path::new(".")), None, None, &registry, temp.path())
            .unwrap();
    assert_eq!(current.root, Path::new("."));
    let file = temp.path().join("file");
    std::fs::write(&file, "preserve").unwrap();
    let error =
        resolve_home_with_registry(Some(&file), None, Some("unknown"), &registry, temp.path())
            .unwrap_err();
    assert!(
        error
            .to_string()
            .contains("cannot use --home and --profile")
    );
    let error = resolve_home_with_registry(
        None,
        Some(file.as_os_str()),
        Some("unknown"),
        &registry,
        temp.path(),
    )
    .unwrap_err();
    assert!(
        error
            .to_string()
            .contains("cannot use --profile while SSHW_HOME is set")
    );
    let selected = resolve_home_with_registry(
        Some(temp.path()),
        Some(file.as_os_str()),
        None,
        &registry,
        temp.path(),
    )
    .unwrap();
    assert_eq!(selected.root, temp.path());
}

#[test]
fn home_readiness_masks_sensitive_paths_without_losing_recovery_or_source() {
    let temp = tempfile::tempdir().unwrap();
    let file = temp.path().join("password=synthetic-home-marker");
    std::fs::write(&file, "preserve").unwrap();
    let error = resolve_home_with_registry(
        Some(&file),
        None,
        None,
        &ProfileRegistry::default(),
        temp.path(),
    )
    .with_error_kind(ErrorKind::Config)
    .unwrap_err();
    let message = error.to_string();
    assert!(message.contains("<redacted>") && message.contains("--home/SSHW_HOME"));
    assert!(!message.contains("synthetic-home-marker"));
    let json = serde_json::to_string(&ErrorResponse::from_error(&error)).unwrap();
    assert!(!json.contains("synthetic-home-marker"));
    assert!(
        error
            .chain()
            .any(|cause| cause.downcast_ref::<std::io::Error>().is_some())
    );
}

#[cfg(unix)]
#[test]
fn home_readiness_accepts_directory_symlinks_and_rejects_file_symlinks() {
    let temp = tempfile::tempdir().unwrap();
    let directory = temp.path().join("directory");
    let file = temp.path().join("file");
    std::fs::create_dir(&directory).unwrap();
    std::fs::write(&file, "preserve").unwrap();
    let registry = ProfileRegistry::default();
    for (target, name) in [(&directory, "dir-link"), (&file, "file-link")] {
        let link = temp.path().join(name);
        std::os::unix::fs::symlink(target, &link).unwrap();
        for home in [&link, &link.join("missing")] {
            let result = resolve_home_with_registry(Some(home), None, None, &registry, temp.path());
            assert_eq!(result.is_ok(), target == &directory);
        }
    }
}
