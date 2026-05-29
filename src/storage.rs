use anyhow::Result;
use std::fs;
use std::io::Write;
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
