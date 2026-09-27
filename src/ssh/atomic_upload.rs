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
    if let Err(error) = &result {
        let failure = error.to_string();
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
                "atomic upload failed: {failure}; {phase}; temporary file {} at {temporary}",
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
            return Err(rename_error(
                raw::libssh2_session_last_errno(session_ptr),
                None,
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
                // SFTP status is meaningful for protocol failures only. Read
                // it before shutdown/cleanup can overwrite the last error.
                let status = (code == raw::LIBSSH2_ERROR_SFTP_PROTOCOL)
                    .then(|| raw::libssh2_sftp_last_error(sftp) as u64);
                return Err(rename_error(code, status));
            }
            Ok(())
        })();
        raw::libssh2_session_set_timeout(session_ptr, 100);
        raw::libssh2_sftp_shutdown(sftp);
        result
    }
}

fn rename_error(code: c_int, status: Option<u64>) -> anyhow::Error {
    let (label, hint) = if code == raw::LIBSSH2_FX_OP_UNSUPPORTED {
        // libssh2 1.11.x returns the positive SFTP constant directly when the
        // extension was not advertised; last_errno is not set on that path.
        (
            "OP_UNSUPPORTED",
            "server does not support posix-rename@openssh.com; use a server with atomic rename support",
        )
    } else if code == raw::LIBSSH2_ERROR_SFTP_PROTOCOL {
        match status.and_then(|value| c_int::try_from(value).ok()) {
            Some(raw::LIBSSH2_FX_OP_UNSUPPORTED) => (
                "OP_UNSUPPORTED",
                "server rejected the atomic rename extension; check server extension support",
            ),
            Some(raw::LIBSSH2_FX_PERMISSION_DENIED) => (
                "PERMISSION_DENIED",
                "server denied replacement; check parent-directory permissions and SFTP request restrictions",
            ),
            Some(raw::LIBSSH2_FX_NO_SUCH_FILE | raw::LIBSSH2_FX_NO_SUCH_PATH) => (
                "MISSING_PATH",
                "check that the staging file and destination directory still exist",
            ),
            Some(
                raw::LIBSSH2_FX_FILE_ALREADY_EXISTS
                | raw::LIBSSH2_FX_DIR_NOT_EMPTY
                | raw::LIBSSH2_FX_NOT_A_DIRECTORY,
            ) => (
                "DESTINATION_CONFLICT",
                "check the destination path and its file/directory type",
            ),
            Some(raw::LIBSSH2_FX_WRITE_PROTECT) => {
                ("WRITE_PROTECT", "the remote filesystem is read-only")
            }
            Some(raw::LIBSSH2_FX_NO_SPACE_ON_FILESYSTEM | raw::LIBSSH2_FX_QUOTA_EXCEEDED) => {
                ("STORAGE_LIMIT", "check remote free space and quota")
            }
            Some(raw::LIBSSH2_FX_NO_CONNECTION | raw::LIBSSH2_FX_CONNECTION_LOST) => (
                "CONNECTION_LOST",
                "connection was lost; inspect the destination before retrying",
            ),
            Some(raw::LIBSSH2_FX_FAILURE) => (
                "FAILURE",
                "server rejected replacement without a specific cause; check destination type, directory permissions, filesystem constraints and server logs",
            ),
            _ => (
                "SFTP_ERROR",
                "check the SFTP server response and server logs",
            ),
        }
    } else {
        match code {
            raw::LIBSSH2_ERROR_SOCKET_TIMEOUT | raw::LIBSSH2_ERROR_TIMEOUT => (
                "TIMEOUT",
                "rename response timed out; inspect the destination before retrying",
            ),
            raw::LIBSSH2_ERROR_SOCKET_SEND
            | raw::LIBSSH2_ERROR_SOCKET_RECV
            | raw::LIBSSH2_ERROR_SOCKET_DISCONNECT => (
                "CONNECTION_ERROR",
                "SSH transport failed; inspect connection state and the destination before retrying",
            ),
            _ => ("SSH_ERROR", "check the SSH connection and server logs"),
        }
    };
    let detail = if code == raw::LIBSSH2_ERROR_SFTP_PROTOCOL {
        status
            .map(|status| format!(", SFTP status {status}"))
            .unwrap_or_default()
    } else {
        String::new()
    };
    app_error(
        ErrorKind::Ssh,
        format!(
            "atomic SFTP rename failed: {label} (native code {code}{detail}); {hint}; no non-atomic fallback was used"
        ),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn rename_errors_distinguish_native_transport_and_sftp_status() {
        for (code, status, expected) in [
            (raw::LIBSSH2_FX_OP_UNSUPPORTED, None, "OP_UNSUPPORTED"),
            (raw::LIBSSH2_ERROR_SFTP_PROTOCOL, Some(8), "OP_UNSUPPORTED"),
            (
                raw::LIBSSH2_ERROR_SFTP_PROTOCOL,
                Some(3),
                "PERMISSION_DENIED",
            ),
            (raw::LIBSSH2_ERROR_SFTP_PROTOCOL, Some(4), "FAILURE"),
            (raw::LIBSSH2_ERROR_SFTP_PROTOCOL, Some(10), "MISSING_PATH"),
            (
                raw::LIBSSH2_ERROR_SFTP_PROTOCOL,
                Some(18),
                "DESTINATION_CONFLICT",
            ),
            (raw::LIBSSH2_ERROR_SFTP_PROTOCOL, Some(12), "WRITE_PROTECT"),
            (raw::LIBSSH2_ERROR_SFTP_PROTOCOL, Some(15), "STORAGE_LIMIT"),
            (raw::LIBSSH2_ERROR_SFTP_PROTOCOL, Some(7), "CONNECTION_LOST"),
            (
                raw::LIBSSH2_ERROR_SFTP_PROTOCOL,
                Some(u64::MAX),
                "SFTP_ERROR",
            ),
            (raw::LIBSSH2_ERROR_SOCKET_TIMEOUT, Some(3), "TIMEOUT"),
            (raw::LIBSSH2_ERROR_SOCKET_RECV, Some(8), "CONNECTION_ERROR"),
        ] {
            let error = rename_error(code, status);
            assert!(error.to_string().contains(expected), "{error}");
            assert!(error.to_string().contains("no non-atomic fallback"));
            assert_eq!(crate::output::classify_error(&error), ErrorKind::Ssh);
            if code != raw::LIBSSH2_ERROR_SFTP_PROTOCOL {
                assert!(!error.to_string().contains("SFTP status"));
            }
        }
    }
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
