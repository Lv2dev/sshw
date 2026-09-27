//! Same-directory SFTP staging with an explicit POSIX atomic rename.
use super::ssh2_client::{OperationDeadline, timeout_millis};
use crate::error::{ResultErrorKindExt, app_error};
use crate::output::ErrorKind;
use anyhow::Context;
use libssh2_sys as raw;
use ssh2::{FileStat, OpenFlags, OpenType, Session};
use std::ffi::{CString, c_char, c_int};
use std::io::{Read, Write};

// Present in the official bundled libssh2 >= 1.11.0, but not declared by the
// current Rust bindings. This declaration does not change the native library.
unsafe extern "C" {
    fn libssh2_sftp_posix_rename_ex(
        sftp: *mut raw::LIBSSH2_SFTP,
        source: *const c_char,
        source_len: usize,
        destination: *const c_char,
        destination_len: usize,
    ) -> c_int;
}

pub(crate) fn parent_path(remote: &str) -> anyhow::Result<&str> {
    if remote.contains(['\0', '\\']) {
        return Err(app_error(
            ErrorKind::Config,
            "atomic upload requires an SFTP path with forward slashes and no NUL",
        ));
    }
    let (parent, name) = remote.rsplit_once('/').unwrap_or((".", remote));
    if name.is_empty() || matches!(name, "." | "..") {
        return Err(app_error(
            ErrorKind::Config,
            "atomic upload requires a destination filename",
        ));
    }
    Ok(if parent.is_empty() { "/" } else { parent })
}

pub(super) fn upload<R: Read>(
    session: &Session,
    source: &mut R,
    size: u64,
    remote: &str,
    mode: u32,
    deadline: &OperationDeadline,
) -> anyhow::Result<u64> {
    let parent = parent_path(remote)?;
    // tempfile supplies an OS-random name. Remote CREATE|EXCLUSIVE ensures a
    // collision can never overwrite somebody else's staging file or symlink.
    let nonce = tempfile::Builder::new()
        .prefix(".sshw-upload-")
        .rand_bytes(24)
        .tempfile()
        .with_error_kind(ErrorKind::Io)?;
    let name = nonce
        .path()
        .file_name()
        .and_then(|name| name.to_str())
        .context("cannot name upload temporary file")?;
    let temporary = format!("{}/{name}", parent.trim_end_matches('/'));
    deadline.apply(session)?;
    let sftp = session
        .sftp()
        .context("atomic upload requires an SFTP subsystem")?;
    deadline.apply(session)?;
    let mut file = sftp
        .open_mode(
            std::path::Path::new(&temporary),
            OpenFlags::WRITE | OpenFlags::CREATE | OpenFlags::EXCLUSIVE,
            0o600,
            OpenType::File,
        )
        .context("cannot create exclusive upload temporary file")?;
    let mut rename_started = false;
    let result = (|| {
        let mut sent = 0;
        let mut buffer = [0u8; 32 * 1024];
        while sent < size {
            deadline.apply(session)?;
            let limit = (size - sent).min(buffer.len() as u64) as usize;
            let count = source
                .read(&mut buffer[..limit])
                .with_error_kind(ErrorKind::Io)?;
            if count == 0 {
                return Err(app_error(
                    ErrorKind::Ssh,
                    "atomic upload aborted: local file shrank during transfer",
                ));
            }
            deadline.apply(session)?;
            file.write_all(&buffer[..count])
                .context("atomic upload write failed")?;
            sent += count as u64;
        }
        deadline.apply(session)?;
        let stat = file.stat().context("cannot verify staged upload size")?;
        if stat.size != Some(size) {
            return Err(app_error(
                ErrorKind::Ssh,
                "staged upload size does not match the source",
            ));
        }
        deadline.apply(session)?;
        file.setstat(FileStat {
            size: None,
            uid: None,
            gid: None,
            perm: Some(mode),
            atime: None,
            mtime: None,
        })
        .context("cannot set staged upload mode")?;
        deadline.apply(session)?;
        file.close().context("cannot confirm staged upload close")?;
        deadline.apply(session)?;
        rename_started = true;
        posix_rename(session, &temporary, remote, deadline)?;
        Ok(sent)
    })();
    if result.is_err() {
        // Only our exclusively-created sibling is removed. Never remove or
        // truncate the destination, including after an unconfirmed rename.
        session.set_timeout(100);
        drop(file);
        let cleaned = sftp.unlink(std::path::Path::new(&temporary)).is_ok();
        let phase = if rename_started {
            "replacement was not confirmed; inspect the destination before retrying"
        } else {
            "replacement was not attempted; the existing destination was preserved"
        };
        return result.with_context(|| {
            format!(
                "atomic upload failed: {phase}; temporary file {} at {temporary}",
                if cleaned { "removed" } else { "may remain" }
            )
        });
    }
    Ok(size)
}

fn posix_rename(
    session: &Session,
    source: &str,
    destination: &str,
    deadline: &OperationDeadline,
) -> anyhow::Result<()> {
    let source = CString::new(source)?;
    let destination = CString::new(destination)?;
    deadline.apply(session)?;
    // Hold ssh2's session mutex for every raw call, and shut down this dedicated
    // SFTP handle before releasing it. No pointer escapes or aliases a Rust
    // Sftp/File handle. Other SFTP operations have finished before this call.
    let mut guard = session.raw();
    let session_ptr: *mut raw::LIBSSH2_SESSION = &mut *guard;
    unsafe {
        let sftp = raw::libssh2_sftp_init(session_ptr);
        if sftp.is_null() {
            return Err(app_error(
                ErrorKind::Ssh,
                "cannot initialize atomic rename subsystem",
            ));
        }
        let result = (|| {
            let timeout = deadline.remaining()?.map(timeout_millis).unwrap_or(0);
            raw::libssh2_session_set_timeout(
                session_ptr,
                timeout.min(i32::MAX as u32) as std::ffi::c_long,
            );
            let code = libssh2_sftp_posix_rename_ex(
                sftp,
                source.as_ptr(),
                source.as_bytes().len(),
                destination.as_ptr(),
                destination.as_bytes().len(),
            );
            if code != 0 {
                return Err(app_error(
                    ErrorKind::Ssh,
                    format!(
                        "atomic SFTP rename failed (code {code}); server must support posix-rename@openssh.com; no non-atomic fallback was used"
                    ),
                ));
            }
            Ok(())
        })();
        raw::libssh2_session_set_timeout(session_ptr, 100);
        raw::libssh2_sftp_shutdown(sftp);
        result
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn staging_uses_remote_path_semantics_on_every_client_os() {
        assert_eq!(parent_path("/srv/app/file").unwrap(), "/srv/app");
        assert_eq!(parent_path("/file").unwrap(), "/");
        assert_eq!(parent_path("file").unwrap(), ".");
        for path in ["", "/", "/srv/..", "a\\b", "a\0b"] {
            assert!(parent_path(path).is_err());
        }
    }
}
