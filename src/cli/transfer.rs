//! File transfer subcommand handlers.

use super::transfer_progress::ProgressDisplay;
use super::{
    CommandOutput, GetArgs, PutArgs, get_server, ok, resolve_auth, resolve_target_server,
    select_account, split_target,
};
use crate::config::{AccountConfig, ServerConfig, SshwConfig};
use crate::credentials::CredentialStore;
use crate::error::{ResultErrorKindExt, app_error};
use crate::local_command::display_value;
use crate::output::{ErrorKind, classify_error, redact_secrets};
use crate::safety::{SafetyDecision, classify_remote_write_path};
use crate::sandbox::{Sandbox, SandboxDecision};
use crate::ssh::{SshClient, SshTarget, UploadOptions};
use serde_json::json;
use std::path::PathBuf;

const MSYS_REMOTE_PATH_HINT: &str = "Git Bash/MSYS may have converted the remote path into a Windows path; prefix the remote absolute path with 'remote:' (for example remote:/tmp/file), or retry with MSYS2_ARG_CONV_EXCL='*'";
const REMOTE_PATH_LITERAL_PREFIX: &str = "remote:";

#[derive(Debug)]
pub(super) struct RemotePath {
    pub(super) value: String,
    explicit_literal: bool,
}

pub(super) fn put_file<C, S>(
    args: PutArgs,
    sandbox: &dyn Sandbox,
    credentials: &C,
    ssh: &S,
    config: &SshwConfig,
) -> anyhow::Result<CommandOutput>
where
    C: CredentialStore,
    S: SshClient,
{
    let PutArgs {
        target,
        user,
        mode,
        atomic,
        yes,
        progress,
        json,
    } = args;
    let (server_name, local, remote) = resolve_put_target(target, config)?;

    let (server, login_user, account) = check_put_access(
        &server_name,
        user.as_deref(),
        &remote.value,
        yes,
        atomic,
        sandbox,
        config,
    )?;
    check_put_source(&local)?;
    let auth = resolve_auth(&server_name, account, login_user, credentials)?;
    let ssh_target = SshTarget::new(server, login_user);
    let mut display = progress.then(|| ProgressDisplay::stderr("upload"));
    let result = with_msys_remote_path_hint(
        if let Some(display) = display.as_mut() {
            ssh.put_with_progress(
                &ssh_target,
                &auth,
                &local,
                &remote.value,
                UploadOptions { mode, atomic },
                &mut |event| display.update(event),
            )
        } else if atomic {
            ssh.put_atomic(&ssh_target, &auth, &local, &remote.value, mode)
        } else {
            match mode {
                Some(mode) => ssh.put_with_mode(&ssh_target, &auth, &local, &remote.value, mode),
                None => ssh.put(&ssh_target, &auth, &local, &remote.value),
            }
        }
        .with_error_kind(ErrorKind::Ssh),
        &remote.value,
        windows_msys_argument_conversion_active() && !remote.explicit_literal,
    );
    if let Some(display) = display.as_mut() {
        display.finish(result.is_ok());
    }
    let result = result?;
    if json {
        let output = json!({
            "ok": true,
            "server": redact_secrets(&server_name),
            "user": redact_secrets(login_user),
            "local": redact_secrets(&result.source),
            "remote": redact_secrets(&result.destination),
            "bytes": result.bytes,
        });
        return Ok(ok(format!("{}\n", serde_json::to_string(&output)?)));
    }

    Ok(ok(format!(
        "uploaded {} bytes from {} to {}\n",
        result.bytes,
        display_value(&result.source),
        display_value(&result.destination)
    )))
}

pub(super) fn get_file<C, S>(
    args: GetArgs,
    sandbox: &dyn Sandbox,
    credentials: &C,
    ssh: &S,
    config: &SshwConfig,
) -> anyhow::Result<CommandOutput>
where
    C: CredentialStore,
    S: SshClient,
{
    let GetArgs {
        target,
        into,
        user,
        yes,
        progress,
        json,
    } = args;
    let (server_name, remote, local) = resolve_get_target(target, into.as_deref(), config)?;

    let (server, login_user, account) = check_get_access(
        &server_name,
        user.as_deref(),
        &remote.value,
        sandbox,
        config,
        || crate::storage::check_download_destination(&local, yes),
    )?;
    let auth = resolve_auth(&server_name, account, login_user, credentials)?;
    let ssh_target = SshTarget::new(server, login_user);
    let mut display = progress.then(|| ProgressDisplay::stderr("download"));
    let result = with_msys_remote_path_hint(
        if let Some(display) = display.as_mut() {
            ssh.get_with_progress(
                &ssh_target,
                &auth,
                &remote.value,
                &local,
                yes,
                &mut |event| display.update(event),
            )
        } else {
            ssh.get(&ssh_target, &auth, &remote.value, &local, yes)
        }
        .with_error_kind(ErrorKind::Ssh),
        &remote.value,
        windows_msys_argument_conversion_active() && !remote.explicit_literal,
    );
    if let Some(display) = display.as_mut() {
        display.finish(result.is_ok());
    }
    let result = result?;
    if json {
        let output = json!({
            "ok": true,
            "server": redact_secrets(&server_name),
            "user": redact_secrets(login_user),
            "remote": redact_secrets(&result.source),
            "local": redact_secrets(&result.destination),
            "bytes": result.bytes,
        });
        return Ok(ok(format!("{}\n", serde_json::to_string(&output)?)));
    }

    Ok(ok(format!(
        "downloaded {} bytes from {} to {}\n",
        result.bytes,
        display_value(&result.source),
        display_value(&result.destination)
    )))
}

// Execution and preflight use these ordered prerequisites. Keep the operation's
// existing first-error precedence, including combinations of invalid inputs.
pub(super) fn check_put_access<'a>(
    name: &str,
    user: Option<&str>,
    remote: &str,
    yes: bool,
    atomic: bool,
    sandbox: &dyn Sandbox,
    config: &'a SshwConfig,
) -> anyhow::Result<(&'a ServerConfig, &'a str, &'a AccountConfig)> {
    check_put_path(remote, yes, atomic, sandbox)?;
    checked_account(name, user, get_server(config, name)?, sandbox)
}

pub(super) fn check_put_source(local: &std::path::Path) -> anyhow::Result<()> {
    // This checks readiness now. The transfer still opens, validates and keeps
    // its own handle so later path replacements cannot change what it sends.
    crate::ssh::ssh2_client::open_regular_local_file(local).map(|_| ())
}

pub(super) fn check_get_access<'a>(
    name: &str,
    user: Option<&str>,
    remote: &str,
    sandbox: &dyn Sandbox,
    config: &'a SshwConfig,
    check_destination: impl FnOnce() -> anyhow::Result<()>,
) -> anyhow::Result<(&'a ServerConfig, &'a str, &'a AccountConfig)> {
    let server = get_server(config, name)?;
    check_get_path(remote, sandbox)?;
    check_destination()?;
    checked_account(name, user, server, sandbox)
}

fn checked_account<'a>(
    name: &str,
    user: Option<&str>,
    server: &'a ServerConfig,
    sandbox: &dyn Sandbox,
) -> anyhow::Result<(&'a ServerConfig, &'a str, &'a AccountConfig)> {
    let (user, account) = select_account(name, server, user)?;
    if let SandboxDecision::Deny { reason } =
        sandbox.check_account(name, user, user == server.default_user)
    {
        return Err(super::policy_recovery::denial(
            reason,
            super::policy_recovery::Rule::Account(name.into(), user.into()),
        ));
    }
    Ok((server, user, account))
}

fn check_put_path(
    remote: &str,
    yes: bool,
    atomic: bool,
    sandbox: &dyn Sandbox,
) -> anyhow::Result<()> {
    if let SafetyDecision::Block { reason } = classify_remote_write_path(remote, yes) {
        return Err(app_error(ErrorKind::Safety, reason));
    }
    if let SandboxDecision::Deny { reason } = sandbox.check_put(remote) {
        return Err(super::policy_recovery::denial(
            reason,
            super::policy_recovery::Rule::Path {
                value: remote.into(),
                upload: true,
            },
        ));
    }
    if atomic {
        let parent = crate::ssh::atomic_upload::parent_path(remote)?;
        if let SandboxDecision::Deny { reason } = sandbox.check_put(parent) {
            return Err(super::policy_recovery::denial(
                format!(
                    "atomic upload needs parent-directory permission for its temporary file: {reason}"
                ),
                super::policy_recovery::Rule::Path {
                    value: parent.into(),
                    upload: true,
                },
            ));
        }
    }
    Ok(())
}

fn check_get_path(remote: &str, sandbox: &dyn Sandbox) -> anyhow::Result<()> {
    if let SandboxDecision::Deny { reason } = sandbox.check_get(remote) {
        return Err(super::policy_recovery::denial(
            reason,
            super::policy_recovery::Rule::Path {
                value: remote.into(),
                upload: false,
            },
        ));
    }
    Ok(())
}

pub(super) fn resolve_put_target(
    target: Vec<String>,
    config: &SshwConfig,
) -> anyhow::Result<(String, PathBuf, RemotePath)> {
    // target is `[name] <local> <remote>`.
    let (name, rest) = split_target(&target, 2)
        .ok_or_else(|| app_error(ErrorKind::Config, "put expects [name] <local> <remote>"))?;
    let server = resolve_target_server(name, config)?;
    let remote = decode_transfer_remote_path(&rest[1], "put")?;
    let local = decode_transfer_local_path(&rest[0], "put")?;
    Ok((server, local, remote))
}

pub(super) fn resolve_get_target(
    target: Vec<String>,
    into: Option<&std::path::Path>,
    config: &SshwConfig,
) -> anyhow::Result<(String, RemotePath, PathBuf)> {
    // target is `[name] <remote> <local>`.
    let (name, rest) =
        split_target(&target, if into.is_some() { 1 } else { 2 }).ok_or_else(|| {
            app_error(
                ErrorKind::Usage,
                "get expects [name] <remote> <local>, or [name] <remote> --into <directory>",
            )
        })?;
    let server = resolve_target_server(name, config)?;
    let remote = decode_transfer_remote_path(&rest[0], "get")?;
    let local = if let Some(directory) = into {
        directory.join(download_file_name(&remote.value)?)
    } else {
        decode_transfer_local_path(&rest[1], "get")?
    };
    Ok((server, remote, local))
}

fn download_file_name(remote: &str) -> anyhow::Result<&str> {
    // Interpret explicit drive/UNC paths as Windows paths even on Unix clients.
    // Other remote paths use POSIX separators, preserving literal backslashes.
    let name = if is_windows_drive_absolute(remote) || remote.starts_with(r"\\") {
        remote.rsplit(['/', '\\']).next().unwrap_or_default()
    } else {
        remote.rsplit('/').next().unwrap_or_default()
    };
    let mut components = std::path::Path::new(name).components();
    let safe_component = matches!(components.next(), Some(std::path::Component::Normal(_)))
        && components.next().is_none();
    if !safe_component || name.chars().any(char::is_control) || !valid_local_file_name(name) {
        return Err(app_error(
            ErrorKind::Usage,
            "cannot derive a local filename for --into from this remote path; use a regular remote file path or specify the local filename explicitly",
        ));
    }
    Ok(name)
}

#[cfg(not(windows))]
fn valid_local_file_name(_: &str) -> bool {
    true
}

#[cfg(windows)]
fn valid_local_file_name(name: &str) -> bool {
    if name.ends_with(['.', ' ']) || name.contains(['<', '>', ':', '"', '/', '\\', '|', '?', '*']) {
        return false;
    }
    let stem = name
        .split('.')
        .next()
        .unwrap_or_default()
        .to_ascii_uppercase();
    !matches!(
        stem.as_str(),
        "CON" | "PRN" | "AUX" | "NUL" | "CLOCK$" | "CONIN$" | "CONOUT$"
    ) && !["COM", "LPT"].iter().any(|prefix| {
        stem.strip_prefix(prefix).is_some_and(|suffix| {
            matches!(
                suffix,
                "1" | "2" | "3" | "4" | "5" | "6" | "7" | "8" | "9" | "¹" | "²" | "³"
            )
        })
    })
}

pub(super) fn policy_remote_path(path: &str) -> anyhow::Result<String> {
    decode_remote_path(path).map(|remote| remote.value)
}

fn decode_transfer_local_path(path: &str, operation: &str) -> anyhow::Result<PathBuf> {
    if path.is_empty() {
        let (label, target) = if operation == "put" {
            ("source", "<local> <remote>")
        } else {
            ("destination", "<remote> <local>")
        };
        return Err(app_error(
            ErrorKind::Usage,
            format!(
                "local {label} path cannot be empty; check the local path variable, for example sshw {operation} <server> {target}"
            ),
        ));
    }
    Ok(PathBuf::from(path))
}

fn decode_transfer_remote_path(path: &str, operation: &str) -> anyhow::Result<RemotePath> {
    if path.is_empty() {
        let target = if operation == "put" {
            "<local> <remote>"
        } else {
            "<remote> <local>"
        };
        return Err(app_error(
            ErrorKind::Usage,
            format!(
                "remote path cannot be empty; check the remote path variable, for example sshw {operation} <server> {target}"
            ),
        ));
    }
    decode_remote_path(path)
}

fn decode_remote_path(path: &str) -> anyhow::Result<RemotePath> {
    let Some(value) = path.strip_prefix(REMOTE_PATH_LITERAL_PREFIX) else {
        return Ok(RemotePath {
            value: path.to_string(),
            explicit_literal: false,
        });
    };
    if !is_remote_absolute(value) {
        return Err(app_error(
            ErrorKind::Config,
            "remote path literal must contain an absolute path after 'remote:'",
        ));
    }
    Ok(RemotePath {
        value: value.to_string(),
        explicit_literal: true,
    })
}

pub(super) fn remote_path_for_audit(path: &str) -> String {
    decode_remote_path(path)
        .map(|remote| remote.value)
        .unwrap_or_else(|_| path.to_string())
}

fn is_remote_absolute(path: &str) -> bool {
    path.starts_with('/') || path.starts_with(r"\\") || is_windows_drive_absolute(path)
}

fn with_msys_remote_path_hint<T>(
    result: anyhow::Result<T>,
    remote: &str,
    argument_conversion_active: bool,
) -> anyhow::Result<T> {
    result.map_err(|error| {
        if argument_conversion_active
            && is_windows_drive_absolute(remote)
            && classify_error(&error) == ErrorKind::Ssh
        {
            error.context(MSYS_REMOTE_PATH_HINT)
        } else {
            error
        }
    })
}

fn is_windows_drive_absolute(path: &str) -> bool {
    let bytes = path.as_bytes();
    bytes.len() >= 3
        && bytes[0].is_ascii_alphabetic()
        && bytes[1] == b':'
        && matches!(bytes[2], b'/' | b'\\')
}

fn windows_msys_argument_conversion_active() -> bool {
    if !cfg!(windows) || std::env::var_os("MSYSTEM").is_none() {
        return false;
    }
    if std::env::var("MSYS_NO_PATHCONV").as_deref() == Ok("1") {
        return false;
    }
    !std::env::var("MSYS2_ARG_CONV_EXCL").is_ok_and(|value| {
        value
            .split(';')
            .any(|excluded_prefix| excluded_prefix == "*")
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::output::ErrorResponse;

    fn transfer_error(kind: ErrorKind) -> anyhow::Error {
        Err::<(), _>(anyhow::anyhow!("synthetic transfer failure"))
            .with_error_kind(kind)
            .unwrap_err()
    }

    #[test]
    fn msys_remote_path_hint_preserves_ssh_contract_for_human_and_json() {
        let error = with_msys_remote_path_hint::<()>(
            Err(transfer_error(ErrorKind::Ssh)),
            "C:/Users/example/AppData/Local/Temp/artifact",
            true,
        )
        .unwrap_err();

        assert_eq!(classify_error(&error), ErrorKind::Ssh);
        assert_eq!(error.to_string(), MSYS_REMOTE_PATH_HINT);
        let response = ErrorResponse::from_error(&error);
        assert_eq!(response.error.kind, ErrorKind::Ssh);
        assert_eq!(response.error.exit_code, 5);
        assert_eq!(response.error.message, MSYS_REMOTE_PATH_HINT);
        assert!(
            response
                .error
                .causes
                .iter()
                .any(|cause| cause.contains("synthetic transfer failure"))
        );
    }

    #[test]
    fn msys_remote_path_hint_does_not_change_success_or_unrelated_failures() {
        assert_eq!(
            with_msys_remote_path_hint(Ok(7), "C:/remote/file", true).unwrap(),
            7
        );

        for (remote, conversion_active, kind) in [
            ("C:/remote/file", false, ErrorKind::Ssh),
            ("/tmp/remote-file", true, ErrorKind::Ssh),
            ("C:/remote/file", true, ErrorKind::Io),
        ] {
            let error = with_msys_remote_path_hint::<()>(
                Err(transfer_error(kind)),
                remote,
                conversion_active,
            )
            .unwrap_err();
            assert_eq!(error.to_string(), "synthetic transfer failure");
            assert_eq!(classify_error(&error), kind);
        }
    }

    #[test]
    fn windows_drive_detection_requires_an_absolute_drive_prefix() {
        assert!(is_windows_drive_absolute("C:/remote/file"));
        assert!(is_windows_drive_absolute(r"C:\remote\file"));
        assert!(!is_windows_drive_absolute("C:relative"));
        assert!(!is_windows_drive_absolute("/tmp/remote-file"));
        assert!(!is_windows_drive_absolute("remote-file"));
    }

    #[test]
    fn remote_literal_accepts_posix_windows_and_unc_absolute_paths() {
        for (input, expected) in [
            ("remote:/tmp/file", "/tmp/file"),
            ("remote:C:/Data/file", "C:/Data/file"),
            (r"remote:C:\Data\file", r"C:\Data\file"),
            (r"remote:\\server\share\file", r"\\server\share\file"),
        ] {
            let decoded = decode_remote_path(input).unwrap();
            assert_eq!(decoded.value, expected);
            assert!(decoded.explicit_literal);
        }
    }

    #[test]
    fn remote_literal_rejects_non_absolute_values_and_preserves_raw_paths() {
        for input in ["remote:", "remote:relative/file", "remote:C:relative"] {
            let error = decode_remote_path(input).unwrap_err();
            assert_eq!(classify_error(&error), ErrorKind::Config);
        }

        for input in [
            "/tmp/file",
            "relative/file",
            "./remote:relative/file",
            "C:/Data/file",
        ] {
            let decoded = decode_remote_path(input).unwrap();
            assert_eq!(decoded.value, input);
            assert!(!decoded.explicit_literal);
        }
    }
}
#[test]
fn into_filename_preserves_platform_names_without_allowing_local_path_components() {
    for (remote, expected) in [
        ("/var/log/app.log", "app.log"),
        (r"C:\logs\app.log", "app.log"),
        (r"\\server\share\app.log", "app.log"),
        ("../parent/app.log", "app.log"),
        ("/logs/개발 'log.txt", "개발 'log.txt"),
    ] {
        assert_eq!(download_file_name(remote).unwrap(), expected);
    }
    for remote in [
        "/",
        ".",
        "..",
        "/logs/.",
        "/logs/..",
        "/logs/",
        "/logs/bad\nname",
        "/logs/bad\0name",
        r"C:\logs\",
    ] {
        assert_eq!(
            classify_error(&download_file_name(remote).unwrap_err()),
            ErrorKind::Usage,
            "{remote:?}"
        );
    }
    #[cfg(windows)]
    for remote in [
        "/logs/NUL",
        "/logs/con.txt",
        "/logs/COM1",
        "/logs/LPT³.log",
        "/logs/file:stream",
        "/logs/trailing.",
        "/logs/trailing ",
        r"/logs/file\name",
    ] {
        assert!(download_file_name(remote).is_err(), "{remote:?}");
    }
    #[cfg(not(windows))]
    assert_eq!(
        download_file_name(r"/logs/file\name").unwrap(),
        r"file\name"
    );
}
