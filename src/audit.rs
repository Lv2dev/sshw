use crate::output::redact_secrets;
use anyhow::{Context, Result};
use serde::Serialize;
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuditStatus {
    Ok,
    Error,
}

impl AuditStatus {
    fn as_str(self) -> &'static str {
        match self {
            Self::Ok => "ok",
            Self::Error => "error",
        }
    }
}

/// A single auditable operation outcome. Secrets in `server`/`detail` are
/// redacted by the sink before they are written.
#[derive(Debug, Clone)]
pub struct AuditRecord {
    pub action: String,
    pub server: Option<String>,
    pub user: Option<String>,
    pub detail: Option<String>,
    pub status: AuditStatus,
    pub exit_code: i32,
}

pub trait AuditSink {
    fn record(&self, record: &AuditRecord) -> Result<()>;
}

/// Discards all records. Used when auditing is not wired (tests, facade).
pub struct NoopAudit;

impl AuditSink for NoopAudit {
    fn record(&self, _record: &AuditRecord) -> Result<()> {
        Ok(())
    }
}

/// Appends one JSON object per line to `<home>/audit.jsonl`. Owner-only on
/// platforms that support it. Secret-bearing fields are redacted on a
/// best-effort basis before writing (see `redact_secrets`); the `run` action
/// records only the program name, not its arguments, to avoid persisting
/// secrets passed inline.
pub struct FileAuditSink {
    path: PathBuf,
}

impl FileAuditSink {
    pub fn new(path: PathBuf) -> Self {
        Self { path }
    }
}

#[derive(Serialize)]
struct AuditLine<'a> {
    time_ms: u128,
    action: &'a str,
    #[serde(skip_serializing_if = "Option::is_none")]
    server: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    user: Option<String>,
    status: &'a str,
    exit_code: i32,
    #[serde(skip_serializing_if = "Option::is_none")]
    detail: Option<String>,
}

impl AuditSink for FileAuditSink {
    fn record(&self, record: &AuditRecord) -> Result<()> {
        if let Some(parent) = self.path.parent() {
            fs::create_dir_all(parent)?;
        }

        let line = AuditLine {
            time_ms: epoch_millis(),
            action: &record.action,
            server: record.server.as_deref().map(redact_secrets),
            user: record.user.as_deref().map(redact_secrets),
            status: record.status.as_str(),
            exit_code: record.exit_code,
            detail: record.detail.as_deref().map(redact_secrets),
        };
        let json = serde_json::to_string(&line)?;

        let mut lock = crate::storage::acquire_exclusive_lock_with_timeout(
            &self.path,
            Duration::from_millis(100),
        )?;
        let mut record_bytes = json.into_bytes();
        record_bytes.push(b'\n');
        let file = lock.file_mut();
        file.write_all(&record_bytes)?;
        file.flush()?;
        Ok(())
    }
}

/// Best-effort audit readiness check. Does not create the audit log or missing
/// parents; a missing log uses a private empty sibling probe, removed before success.
pub fn is_writable(path: &Path) -> bool {
    check_writable(path).is_ok()
}

/// Check audit append/creation readiness without writing an audit record.
/// This is a point-in-time check, not a guarantee about a later record or lock.
pub fn check_writable(path: &Path) -> Result<()> {
    let open_context = || {
        format!(
            "cannot open existing audit log for append at {}",
            path.display()
        )
    };
    match fs::symlink_metadata(path) {
        Ok(_) => {
            let metadata = fs::metadata(path).with_context(open_context)?;
            if !metadata.is_file() {
                return Err(anyhow::anyhow!(
                    "{}: expected a regular file",
                    open_context()
                ));
            }
            OpenOptions::new()
                .append(true)
                .open(path)
                .with_context(open_context)?;
            return Ok(());
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => {
            return Err(error)
                .with_context(|| format!("cannot inspect audit log at {}", path.display()));
        }
    }
    let parent = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    let metadata = fs::metadata(parent)
        .with_context(|| format!("cannot inspect audit parent directory {}", parent.display()))?;
    if !metadata.is_dir() {
        return Err(anyhow::anyhow!(
            "cannot create audit log at {}: parent {} is not a directory",
            path.display(),
            parent.display()
        ));
    }
    let probe = tempfile::Builder::new()
        .prefix(".sshw-audit-check-")
        .tempfile_in(parent)
        .with_context(|| {
            format!(
                "cannot create audit log at {}: creation probe in parent directory {} failed",
                path.display(),
                parent.display()
            )
        })?;
    let probe_path = probe.path().to_path_buf();
    probe.close().with_context(|| {
        format!(
            "cannot remove private audit readiness probe at {}",
            probe_path.display()
        )
    })
}

fn epoch_millis() -> u128 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_millis())
        .unwrap_or_default()
}
