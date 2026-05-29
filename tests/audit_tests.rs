use sshw::audit::{AuditRecord, AuditSink, AuditStatus, FileAuditSink, NoopAudit, is_writable};

fn record(action: &str, detail: Option<&str>, status: AuditStatus, exit_code: i32) -> AuditRecord {
    AuditRecord {
        action: action.to_string(),
        server: Some("web".to_string()),
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
