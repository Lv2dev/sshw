use crate::error::{ResultErrorKindExt, app_error};
use crate::output::ErrorKind;
use anyhow::Result;
use std::fmt;
use std::fs;
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

#[cfg(unix)]
use std::os::unix::fs::OpenOptionsExt;

/// Process-wide/cross-process advisory exclusive lock backed by the platform's
/// native whole-file lock. The default acquisition waits at most five seconds,
/// and the lock is released when this guard is dropped.
#[derive(Debug)]
pub struct ExclusiveFileLock {
    file: fs::File,
}

impl ExclusiveFileLock {
    pub(crate) fn file_mut(&mut self) -> &mut fs::File {
        &mut self.file
    }
}

/// Signals that the atomic rename completed but syncing the containing
/// directory failed. Callers that coordinate another store (such as the OS
/// keyring) must not compensate by deleting data now referenced by the
/// published file.
#[derive(Debug)]
struct PublishedWriteError {
    path: PathBuf,
    source: anyhow::Error,
}

impl fmt::Display for PublishedWriteError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "state at {} was published, but parent directory durability could not be confirmed: {}",
            self.path.display(),
            self.source
        )
    }
}

impl std::error::Error for PublishedWriteError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        Some(self.source.as_ref())
    }
}

pub(crate) fn write_was_published(error: &anyhow::Error) -> bool {
    error
        .chain()
        .any(|cause| cause.downcast_ref::<PublishedWriteError>().is_some())
}

impl Drop for ExclusiveFileLock {
    fn drop(&mut self) {
        let _ = self.file.unlock();
    }
}

pub fn acquire_exclusive_lock(path: &Path) -> Result<ExclusiveFileLock> {
    acquire_exclusive_lock_with_timeout(path, Duration::from_secs(5))
}

pub fn acquire_exclusive_lock_with_timeout(
    path: &Path,
    timeout: Duration,
) -> Result<ExclusiveFileLock> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }

    let mut options = fs::OpenOptions::new();
    options.read(true).write(true).append(true).create(true);
    #[cfg(unix)]
    options.mode(0o600);

    let file = options.open(path)?;
    set_owner_only(path)?;
    let started = Instant::now();
    loop {
        match file.try_lock() {
            Ok(()) => break,
            Err(fs::TryLockError::WouldBlock) => {
                if started.elapsed() >= timeout {
                    return Err(anyhow::anyhow!(
                        "timed out waiting for lock at {} after {} milliseconds",
                        path.display(),
                        timeout.as_millis()
                    ));
                }
                std::thread::sleep(Duration::from_millis(5));
            }
            Err(fs::TryLockError::Error(err)) => return Err(err.into()),
        }
    }
    Ok(ExclusiveFileLock { file })
}

/// Atomically write `contents` to `path`, creating parent directories and
/// applying owner-only permissions on platforms that support them.
///
/// The write goes to a sibling temp file which is then atomically persisted
/// over the destination, so an interrupted write never leaves a truncated or
/// missing destination. Permissions and temp-file data are finalized before
/// publish; the parent directory is synced afterward where supported. A failed
/// post-publish directory sync returns a detectable `PublishedWriteError`.
/// On Windows the permission and directory-sync steps are best-effort no-ops
/// (NTFS ACLs already restrict the per-user config directory).
pub fn write_owner_only_atomic(path: &Path, contents: &str) -> Result<()> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }

    let temp_path = temp_sibling_path(path);
    write_temp(&temp_path, contents)?;
    set_owner_only(&temp_path)?;
    fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open(&temp_path)?
        .sync_all()?;
    replace_atomic(&temp_path, path)?;
    if let Err(source) = sync_parent_directory(path) {
        return Err(anyhow::Error::new(PublishedWriteError {
            path: path.to_path_buf(),
            source,
        }));
    }
    Ok(())
}

fn temp_sibling_path(path: &Path) -> PathBuf {
    let file_name = path
        .file_name()
        .map(|name| name.to_string_lossy())
        .unwrap_or_else(|| "sshw.tmp".into());
    let suffix = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_nanos())
        .unwrap_or_default();
    path.with_file_name(format!(
        ".{file_name}.{}.{}.tmp",
        std::process::id(),
        suffix
    ))
}

fn write_temp(path: &Path, contents: &str) -> Result<()> {
    let mut options = fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    options.mode(0o600);

    let mut file = options.open(path)?;
    file.write_all(contents.as_bytes())?;
    file.sync_all()?;
    Ok(())
}

fn replace_atomic(temp_path: &Path, path: &Path) -> Result<()> {
    tempfile::TempPath::try_from_path(temp_path)?.persist(path)?;
    Ok(())
}

#[cfg(unix)]
fn set_owner_only(path: &Path) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;

    fs::set_permissions(path, fs::Permissions::from_mode(0o600))?;
    Ok(())
}

#[cfg(not(unix))]
fn set_owner_only(_path: &Path) -> Result<()> {
    Ok(())
}

/// Atomically write all bytes from `reader` to `path`, mirroring
/// [`write_owner_only_atomic`] for an arbitrary stream (e.g. an SCP download).
///
/// The stream is written to a sibling temp file and persisted over the
/// destination only after the copy + fsync succeed, so a failed or interrupted
/// download never truncates or replaces an existing file. When `overwrite` is
/// false, an existing destination is refused without being touched.
///
/// When `expected_len` is `Some(n)`, the copied byte count is verified to equal
/// `n` *before* the temp file is persisted; a short transfer fails closed (with
/// an ssh-classified error) and leaves the destination untouched, so a truncated
/// download is never reported as a success. SCP downloads pass the remote size
/// here; callers without an authoritative size pass `None`.
pub fn write_stream_owner_only_atomic(
    path: &Path,
    reader: &mut dyn Read,
    overwrite: bool,
    expected_len: Option<u64>,
) -> Result<u64> {
    stage_stream_owner_only(path, reader, overwrite, expected_len)?.persist()
}

/// A complete local stream that is durable in a sibling temporary file but is
/// not yet visible at its final destination. Dropping it removes the temporary
/// file; [`persist`](Self::persist) is the only operation that publishes it.
pub struct StagedStreamWrite {
    temp: tempfile::NamedTempFile,
    destination: PathBuf,
    overwrite: bool,
    bytes: u64,
}

impl StagedStreamWrite {
    pub fn bytes(&self) -> u64 {
        self.bytes
    }

    pub fn persist(self) -> Result<u64> {
        self.persist_inner().with_error_kind(ErrorKind::Io)
    }

    fn persist_inner(self) -> Result<u64> {
        let Self {
            temp,
            destination,
            overwrite,
            bytes,
        } = self;
        set_owner_only(temp.path())?;

        let persisted = if overwrite {
            temp.persist(&destination)
        } else {
            temp.persist_noclobber(&destination)
        };
        match persisted {
            Ok(file) => drop(file),
            Err(err) => {
                let tempfile::PersistError { error, file } = err;
                let already_exists = !overwrite
                    && (error.kind() == std::io::ErrorKind::AlreadyExists
                        || destination.try_exists().is_ok_and(|exists| exists));
                drop(file);
                if already_exists {
                    return Err(already_exists_error(&destination));
                }
                return Err(anyhow::Error::new(error).context(format!(
                    "failed to persist staged file at {}",
                    destination.display()
                )));
            }
        }
        sync_parent_directory(&destination)?;
        Ok(bytes)
    }
}

pub fn stage_stream_owner_only(
    path: &Path,
    reader: &mut dyn Read,
    overwrite: bool,
    expected_len: Option<u64>,
) -> Result<StagedStreamWrite> {
    stage_stream_owner_only_inner(path, reader, overwrite, expected_len)
        .with_error_kind(ErrorKind::Io)
}

fn stage_stream_owner_only_inner(
    path: &Path,
    reader: &mut dyn Read,
    overwrite: bool,
    expected_len: Option<u64>,
) -> Result<StagedStreamWrite> {
    if !overwrite && path.try_exists()? {
        return Err(already_exists_error(path));
    }

    let parent = parent_directory(path);
    fs::create_dir_all(parent)?;
    let mut temp = tempfile::Builder::new()
        .prefix(".sshw-download-")
        .suffix(".tmp")
        .tempfile_in(parent)?;

    let bytes = std::io::copy(reader, temp.as_file_mut())?;
    temp.as_file_mut().flush()?;
    temp.as_file().sync_all()?;

    if let Some(expected) = expected_len
        && bytes != expected
    {
        return Err(incomplete_transfer_error(expected, bytes));
    }

    Ok(StagedStreamWrite {
        temp,
        destination: path.to_path_buf(),
        overwrite,
        bytes,
    })
}

fn parent_directory(path: &Path) -> &Path {
    path.parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."))
}

fn sync_parent_directory(path: &Path) -> Result<()> {
    #[cfg(test)]
    if FAIL_NEXT_PARENT_SYNC.with(|fail| fail.replace(false)) {
        return Err(anyhow::anyhow!("simulated parent directory sync failure"));
    }
    sync_parent_directory_platform(path)
}

#[cfg(unix)]
fn sync_parent_directory_platform(path: &Path) -> Result<()> {
    fs::File::open(parent_directory(path))?.sync_all()?;
    Ok(())
}

#[cfg(not(unix))]
fn sync_parent_directory_platform(_path: &Path) -> Result<()> {
    Ok(())
}

#[cfg(test)]
thread_local! {
    static FAIL_NEXT_PARENT_SYNC: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
}

#[cfg(test)]
pub(crate) fn fail_next_parent_sync() {
    FAIL_NEXT_PARENT_SYNC.with(|fail| fail.set(true));
}

fn already_exists_error(path: &Path) -> anyhow::Error {
    app_error(
        ErrorKind::Io,
        format!(
            "local file already exists: {}; pass --yes to overwrite",
            path.display()
        ),
    )
}

fn incomplete_transfer_error(expected: u64, actual: u64) -> anyhow::Error {
    app_error(
        ErrorKind::Ssh,
        format!(
            "ssh transfer aborted: incomplete download (expected {expected} bytes, wrote {actual})"
        ),
    )
}

#[cfg(all(test, windows))]
mod tests {
    use super::replace_atomic;
    use std::fs;

    #[test]
    fn windows_replace_preserves_destination_when_rename_fails() {
        let temp = tempfile::tempdir().unwrap();
        let destination = temp.path().join("servers.json");
        let missing_temp = temp.path().join("missing.tmp");
        fs::write(&destination, "original").unwrap();

        let _err = replace_atomic(&missing_temp, &destination).unwrap_err();

        assert_eq!(fs::read_to_string(destination).unwrap(), "original");
    }
}

#[cfg(test)]
mod stream_tests {
    use super::{
        acquire_exclusive_lock, acquire_exclusive_lock_with_timeout, stage_stream_owner_only,
        write_stream_owner_only_atomic,
    };
    use std::fs;
    use std::io::{self, Read};

    /// Reader that yields `remaining` bytes, then fails — simulates a download
    /// that dies partway (network drop, timeout, disk full).
    struct FailingReader {
        remaining: usize,
    }

    impl Read for FailingReader {
        fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
            if self.remaining == 0 {
                return Err(io::Error::other("simulated download failure"));
            }
            let n = buf.len().min(self.remaining);
            buf[..n].fill(b'x');
            self.remaining -= n;
            Ok(n)
        }
    }

    fn count_temp_files(dir: &std::path::Path) -> usize {
        fs::read_dir(dir)
            .unwrap()
            .filter_map(|entry| entry.ok())
            .filter(|entry| entry.file_name().to_string_lossy().ends_with(".tmp"))
            .count()
    }

    #[test]
    fn failed_stream_preserves_existing_destination_and_leaves_no_temp() {
        let dir = tempfile::tempdir().unwrap();
        let dest = dir.path().join("data.txt");
        fs::write(&dest, "ORIGINAL").unwrap();

        let mut reader = FailingReader { remaining: 8 };
        let err = write_stream_owner_only_atomic(&dest, &mut reader, true, None).unwrap_err();

        assert!(err.to_string().contains("simulated download failure"));
        assert_eq!(fs::read_to_string(&dest).unwrap(), "ORIGINAL");
        assert_eq!(
            count_temp_files(dir.path()),
            0,
            "temp file leaked after failure"
        );
    }

    #[test]
    fn successful_stream_overwrites_destination() {
        let dir = tempfile::tempdir().unwrap();
        let dest = dir.path().join("data.txt");
        fs::write(&dest, "ORIGINAL").unwrap();

        let mut reader = &b"NEWDATA"[..];
        let bytes = write_stream_owner_only_atomic(&dest, &mut reader, true, None).unwrap();

        assert_eq!(bytes, 7);
        assert_eq!(fs::read_to_string(&dest).unwrap(), "NEWDATA");
        assert_eq!(count_temp_files(dir.path()), 0);
    }

    #[test]
    fn competing_lock_attempt_has_a_bounded_wait() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("state.lock");
        let _held = acquire_exclusive_lock(&path).unwrap();
        let started = std::time::Instant::now();

        let err = acquire_exclusive_lock_with_timeout(&path, std::time::Duration::from_millis(25))
            .unwrap_err();

        assert!(
            err.to_string().contains("timed out waiting for lock"),
            "error was: {err:#}"
        );
        assert!(started.elapsed() < std::time::Duration::from_secs(1));
    }

    #[test]
    fn staged_stream_is_invisible_until_persisted() {
        let dir = tempfile::tempdir().unwrap();
        let dest = dir.path().join("data.txt");
        fs::write(&dest, "ORIGINAL").unwrap();
        let mut reader = &b"NEWDATA"[..];

        let staged = stage_stream_owner_only(&dest, &mut reader, true, Some(7)).unwrap();

        assert_eq!(staged.bytes(), 7);
        assert_eq!(fs::read_to_string(&dest).unwrap(), "ORIGINAL");
        assert_eq!(count_temp_files(dir.path()), 1);

        let bytes = staged.persist().unwrap();
        assert_eq!(bytes, 7);
        assert_eq!(fs::read_to_string(&dest).unwrap(), "NEWDATA");
        assert_eq!(count_temp_files(dir.path()), 0);
    }

    #[test]
    fn dropping_staged_stream_preserves_existing_destination() {
        let dir = tempfile::tempdir().unwrap();
        let dest = dir.path().join("data.txt");
        fs::write(&dest, "ORIGINAL").unwrap();
        let mut reader = &b"NEWDATA"[..];

        let staged = stage_stream_owner_only(&dest, &mut reader, true, Some(7)).unwrap();
        drop(staged);

        assert_eq!(fs::read_to_string(&dest).unwrap(), "ORIGINAL");
        assert_eq!(count_temp_files(dir.path()), 0);
    }

    #[test]
    fn no_clobber_persist_rejects_destination_created_after_stage() {
        let dir = tempfile::tempdir().unwrap();
        let dest = dir.path().join("data.txt");
        let mut reader = &b"NEWDATA"[..];
        let staged = stage_stream_owner_only(&dest, &mut reader, false, Some(7)).unwrap();
        fs::write(&dest, "COMPETING").unwrap();

        let err = staged.persist().unwrap_err();

        assert!(err.to_string().contains("already exists"));
        assert_eq!(fs::read_to_string(&dest).unwrap(), "COMPETING");
        assert_eq!(count_temp_files(dir.path()), 0);
    }

    #[test]
    fn rejects_incomplete_stream_and_preserves_destination() {
        let dir = tempfile::tempdir().unwrap();
        let dest = dir.path().join("data.txt");
        fs::write(&dest, "ORIGINAL").unwrap();

        // Reader yields 4 bytes but the caller expects 8 (a truncated download).
        let mut reader = &b"NEWD"[..];
        let err = write_stream_owner_only_atomic(&dest, &mut reader, true, Some(8)).unwrap_err();

        // Fail closed: the existing destination is untouched and no temp leaks.
        assert!(err.to_string().contains("ssh transfer aborted"));
        assert_eq!(fs::read_to_string(&dest).unwrap(), "ORIGINAL");
        assert_eq!(count_temp_files(dir.path()), 0);
    }

    #[test]
    fn refuses_existing_destination_without_overwrite() {
        let dir = tempfile::tempdir().unwrap();
        let dest = dir.path().join("data.txt");
        fs::write(&dest, "ORIGINAL").unwrap();

        let mut reader = &b"NEW"[..];
        let err = write_stream_owner_only_atomic(&dest, &mut reader, false, None).unwrap_err();

        assert!(err.to_string().contains("already exists"));
        assert_eq!(fs::read_to_string(&dest).unwrap(), "ORIGINAL");
    }

    #[cfg(unix)]
    #[test]
    fn creates_destination_owner_only() {
        use std::os::unix::fs::PermissionsExt;

        let dir = tempfile::tempdir().unwrap();
        let dest = dir.path().join("data.txt");

        let mut reader = &b"DATA"[..];
        write_stream_owner_only_atomic(&dest, &mut reader, false, None).unwrap();

        let mode = fs::metadata(&dest).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600);
    }
}
