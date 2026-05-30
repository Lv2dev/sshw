use anyhow::Result;
use std::fs;
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

#[cfg(unix)]
use std::os::unix::fs::OpenOptionsExt;

/// Atomically write `contents` to `path`, creating parent directories and
/// applying owner-only permissions on platforms that support them.
///
/// The write goes to a sibling temp file which is then atomically persisted
/// over the destination, so an interrupted write never leaves a truncated or
/// missing destination. On Windows the permission step is a best-effort no-op
/// (NTFS ACLs already restrict the per-user config directory).
pub fn write_owner_only_atomic(path: &Path, contents: &str) -> Result<()> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }

    let temp_path = temp_sibling_path(path);
    write_temp(&temp_path, contents)?;
    replace_atomic(&temp_path, path)?;
    set_owner_only(path)?;
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
    if !overwrite && path.exists() {
        return Err(already_exists_error(path));
    }
    if let Some(parent) = path.parent()
        && !parent.as_os_str().is_empty()
    {
        fs::create_dir_all(parent)?;
    }

    let temp_path = temp_sibling_path(path);
    let bytes = match copy_stream_to_temp(&temp_path, reader) {
        Ok(bytes) => bytes,
        Err(err) => {
            // The destination was never touched; drop the partial temp file.
            let _ = fs::remove_file(&temp_path);
            return Err(err);
        }
    };

    // Fail closed on a short transfer before persisting, so a truncated download
    // never overwrites or creates the destination.
    if let Some(expected) = expected_len
        && bytes != expected
    {
        let _ = fs::remove_file(&temp_path);
        return Err(incomplete_transfer_error(expected, bytes));
    }

    // Re-check in case the destination appeared during the download.
    if !overwrite && path.exists() {
        let _ = fs::remove_file(&temp_path);
        return Err(already_exists_error(path));
    }

    replace_atomic(&temp_path, path)?;
    set_owner_only(path)?;
    Ok(bytes)
}

fn copy_stream_to_temp(temp_path: &Path, reader: &mut dyn Read) -> Result<u64> {
    let mut options = fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    options.mode(0o600);

    let mut file = options.open(temp_path)?;
    let bytes = std::io::copy(reader, &mut file)?;
    file.flush()?;
    file.sync_all()?;
    Ok(bytes)
}

fn already_exists_error(path: &Path) -> anyhow::Error {
    anyhow::anyhow!(
        "local file already exists: {}; pass --yes to overwrite",
        path.display()
    )
}

fn incomplete_transfer_error(expected: u64, actual: u64) -> anyhow::Error {
    anyhow::anyhow!(
        "ssh transfer aborted: incomplete download (expected {expected} bytes, wrote {actual})"
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
    use super::write_stream_owner_only_atomic;
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
