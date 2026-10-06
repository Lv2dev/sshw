use sshw::audit::{AuditRecord, AuditSink, AuditStatus, FileAuditSink, NoopAudit, is_writable};

fn record(action: &str, detail: Option<&str>, status: AuditStatus, exit_code: i32) -> AuditRecord {
    AuditRecord {
        action: action.to_string(),
        server: Some("web".to_string()),
        user: Some("ops".to_string()),
        detail: detail.map(str::to_string),
        status,
        exit_code,
    }
}

#[test]
fn file_sink_appends_jsonl_and_redacts_detail() {
    let temp = tempfile::tempdir().unwrap();
    let path = temp.path().join("audit.jsonl");
    let sink = FileAuditSink::new(path.clone());

    sink.record(&record(
        "run",
        Some("mysql --password=hunter2"),
        AuditStatus::Ok,
        0,
    ))
    .unwrap();
    sink.record(&record("get", Some("/etc/passwd"), AuditStatus::Error, 7))
        .unwrap();

    let contents = std::fs::read_to_string(&path).unwrap();
    let lines: Vec<&str> = contents.lines().collect();
    assert_eq!(lines.len(), 2);

    let first: serde_json::Value = serde_json::from_str(lines[0]).unwrap();
    assert_eq!(first["action"], "run");
    assert_eq!(first["server"], "web");
    assert_eq!(first["user"], "ops");
    assert_eq!(first["status"], "ok");
    assert_eq!(first["exit_code"], 0);
    assert!(first["time_ms"].is_number());
    assert!(first["detail"].as_str().unwrap().contains("<redacted>"));
    assert!(
        !contents.contains("hunter2"),
        "secret leaked into audit log"
    );

    let second: serde_json::Value = serde_json::from_str(lines[1]).unwrap();
    assert_eq!(second["action"], "get");
    assert_eq!(second["status"], "error");
    assert_eq!(second["exit_code"], 7);
}

#[test]
fn audit_record_gives_up_promptly_when_record_lock_is_busy() {
    let temp = tempfile::tempdir().unwrap();
    let path = temp.path().join("audit.jsonl");
    std::fs::write(&path, "").unwrap();
    let lock = sshw::storage::acquire_exclusive_lock(&path).unwrap();
    let thread_path = path.clone();
    let (sender, receiver) = std::sync::mpsc::channel();

    let worker = std::thread::spawn(move || {
        let sink = FileAuditSink::new(thread_path);
        let result = sink.record(&AuditRecord {
            action: "run".to_string(),
            server: Some("server-alpha".to_string()),
            user: Some("deploy".to_string()),
            detail: Some("printf".to_string()),
            status: AuditStatus::Ok,
            exit_code: 0,
        });
        sender.send(result).unwrap();
    });

    let result = receiver
        .recv_timeout(std::time::Duration::from_secs(2))
        .expect("best-effort audit must not wait indefinitely for its lock");
    let err = result.expect_err("busy audit lock should skip the record");
    assert!(err.to_string().contains("timed out waiting for lock"));
    drop(lock);
    worker.join().unwrap();

    assert!(std::fs::read_to_string(path).unwrap().is_empty());
}

#[test]
fn noop_sink_records_nothing() {
    NoopAudit
        .record(&record("run", None, AuditStatus::Ok, 0))
        .unwrap();
}

#[cfg(unix)]
#[test]
fn file_sink_is_owner_only() {
    use std::os::unix::fs::PermissionsExt;

    let temp = tempfile::tempdir().unwrap();
    let path = temp.path().join("audit.jsonl");
    FileAuditSink::new(path.clone())
        .record(&record("run", None, AuditStatus::Ok, 0))
        .unwrap();

    let mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
    assert_eq!(mode, 0o600);
}

#[test]
fn is_writable_requires_existing_parent() {
    let temp = tempfile::tempdir().unwrap();
    assert!(is_writable(&temp.path().join("audit.jsonl")));
    assert!(!is_writable(
        &temp.path().join("missing").join("audit.jsonl")
    ));
}

#[test]
fn default_audit_readiness_preserves_logs_and_does_not_create_missing_parents() {
    let temp = tempfile::tempdir().unwrap();
    let blocker = temp.path().join("blocker");
    std::fs::write(&blocker, "file").unwrap();
    assert!(!is_writable(&blocker.join("audit.jsonl")));
    assert!(!is_writable(&temp.path().join("missing/audit.jsonl")));
    assert!(!temp.path().join("missing").exists());
    let path = temp.path().join("audit.jsonl");
    let before: Vec<_> = std::fs::read_dir(temp.path())
        .unwrap()
        .map(|entry| entry.unwrap().file_name())
        .collect();
    assert!(is_writable(&path));
    assert!(!path.exists());
    let after: Vec<_> = std::fs::read_dir(temp.path())
        .unwrap()
        .map(|entry| entry.unwrap().file_name())
        .collect();
    assert_eq!(before, after);
    std::fs::write(&path, "existing audit data\n").unwrap();
    let modified = std::fs::metadata(&path).unwrap().modified().unwrap();
    assert!(is_writable(&path));
    assert_eq!(
        std::fs::read_to_string(&path).unwrap(),
        "existing audit data\n"
    );
    assert_eq!(
        std::fs::metadata(&path).unwrap().modified().unwrap(),
        modified
    );
    #[cfg(unix)]
    {
        let link = temp.path().join("dangling");
        std::os::unix::fs::symlink(temp.path().join("nonexistent"), &link).unwrap();
        assert!(!is_writable(&link));
        assert!(!temp.path().join("nonexistent").exists());
    }
}

#[cfg(unix)]
#[test]
fn default_audit_readiness_checks_creation_permission_in_a_readonly_parent() {
    use std::os::unix::fs::PermissionsExt;
    let temp = tempfile::tempdir().unwrap();
    let parent = temp.path().join("parent");
    std::fs::create_dir(&parent).unwrap();
    std::fs::set_permissions(&parent, std::fs::Permissions::from_mode(0o555)).unwrap();
    let result = std::panic::catch_unwind(|| {
        let marker = parent.join("direct-creation-control");
        let writable = match std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&marker)
        {
            Ok(file) => {
                drop(file);
                std::fs::remove_file(&marker).unwrap();
                true
            }
            Err(error) => {
                assert_eq!(error.kind(), std::io::ErrorKind::PermissionDenied);
                false
            }
        };
        assert_eq!(is_writable(&parent.join("audit.jsonl")), writable);
        assert!(std::fs::read_dir(&parent).unwrap().next().is_none());
    });
    std::fs::set_permissions(&parent, std::fs::Permissions::from_mode(0o700)).unwrap();
    if let Err(error) = result {
        std::panic::resume_unwind(error);
    }
}

#[cfg(windows)]
#[test]
fn default_audit_readiness_checks_windows_directory_acl_and_keeps_append_access() {
    let temp = tempfile::tempdir().unwrap();
    let parent = temp.path().join("audit-home");
    std::fs::create_dir(&parent).unwrap();
    let existing = parent.join("existing.jsonl");
    std::fs::write(&existing, "existing audit data\n").unwrap();
    let saved_acl = temp.path().join("audit-acl.txt");
    let invoke = |args: &[&std::ffi::OsStr]| {
        let mut command = std::process::Command::new("icacls.exe");
        command.args(args);
        let output = command.output().unwrap();
        assert!(
            output.status.success(),
            "{}{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
    };
    let identity = std::process::Command::new("whoami.exe")
        .args(["/user", "/fo", "csv", "/nh"])
        .output()
        .unwrap();
    assert!(identity.status.success());
    let identity = String::from_utf8_lossy(&identity.stdout);
    let sid = identity
        .trim()
        .rsplit(',')
        .next()
        .unwrap()
        .trim_matches('"');
    assert!(sid.starts_with("S-1-"));
    let deny = format!("*{sid}:(WD)");
    invoke(&[
        parent.as_os_str(),
        std::ffi::OsStr::new("/save"),
        saved_acl.as_os_str(),
        std::ffi::OsStr::new("/q"),
    ]);
    invoke(&[
        parent.as_os_str(),
        std::ffi::OsStr::new("/deny"),
        std::ffi::OsStr::new(&deny),
        std::ffi::OsStr::new("/q"),
    ]);
    let result = std::panic::catch_unwind(|| {
        assert!(!is_writable(&parent.join("audit.jsonl")));
        assert!(is_writable(&existing));
        assert_eq!(
            std::fs::read_to_string(&existing).unwrap(),
            "existing audit data\n"
        );
        assert!(!parent.join("audit.jsonl").exists());
        assert_eq!(std::fs::read_dir(&parent).unwrap().count(), 1);
    });
    let remove = format!("*{sid}");
    invoke(&[
        parent.as_os_str(),
        std::ffi::OsStr::new("/remove:d"),
        std::ffi::OsStr::new(&remove),
        std::ffi::OsStr::new("/q"),
    ]);
    let restored_acl = temp.path().join("restored-acl.txt");
    invoke(&[
        parent.as_os_str(),
        std::ffi::OsStr::new("/save"),
        restored_acl.as_os_str(),
        std::ffi::OsStr::new("/q"),
    ]);
    assert_eq!(
        std::fs::read(saved_acl).unwrap(),
        std::fs::read(restored_acl).unwrap()
    );
    if let Err(error) = result {
        std::panic::resume_unwind(error);
    }
}
