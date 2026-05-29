use crate::output::redact_secrets;
use anyhow::Result;
use serde::Serialize;
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

#[cfg(unix)]
use std::os::unix::fs::OpenOptionsExt;

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
/// platforms that support it. Never records secrets.
pub struct FileAuditSink {
    path: PathBuf,
}

impl FileAuditSink {
    pub fn new(path: PathBuf) -> Self {
        Self { path }
    }

    pub fn path(&self) -> &Path {
        &self.path
    }
}

#[derive(Serialize)]
struct AuditLine<'a> {
    time_ms: u128,
    action: &'a str,
    #[serde(skip_serializing_if = "Option::is_none")]
    server: Option<String>,
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
            status: record.status.as_str(),
            exit_code: record.exit_code,
            detail: record.detail.as_deref().map(redact_secrets),
        };
        let json = serde_json::to_string(&line)?;

        let mut options = OpenOptions::new();
        options.create(true).append(true);
        #[cfg(unix)]
        options.mode(0o600);

        let mut file = options.open(&self.path)?;
        writeln!(file, "{json}")?;
        Ok(())
    }
}

/// Best-effort, non-destructive check of whether the audit log can be written,
/// for `doctor`. Does not create the file or its parent directory.
pub fn is_writable(path: &Path) -> bool {
    let parent_exists = path.parent().map(Path::exists).unwrap_or(false);
    if !parent_exists {
        return false;
    }
    if path.exists() {
        OpenOptions::new().append(true).open(path).is_ok()
    } else {
        true
    }
}

fn epoch_millis() -> u128 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_millis())
        .unwrap_or_default()
}
