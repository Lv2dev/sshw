//! File transfer subcommand handlers.

use super::{
    CommandOutput, GetArgs, PutArgs, get_server, ok, resolve_auth, resolve_target_server,
    split_target,
};
use crate::config::SshwConfig;
use crate::credentials::CredentialStore;
use crate::error::{ResultErrorKindExt, app_error};
use crate::output::{ErrorKind, classify_error, redact_secrets};
use crate::safety::{SafetyDecision, classify_remote_write_path};
use crate::sandbox::{Sandbox, SandboxDecision};
use crate::ssh::SshClient;
use serde_json::json;
use std::path::PathBuf;

const MSYS_REMOTE_PATH_HINT: &str = "Git Bash/MSYS may have converted the remote path into a Windows path; retry with MSYS2_ARG_CONV_EXCL='*' and pass the local path in Windows form (for example C:/path/file)";

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
    let PutArgs { target, yes, json } = args;
    let (server_name, local, remote) = resolve_put_target(target, config)?;

    match classify_remote_write_path(&remote, yes) {
        SafetyDecision::Allow => {}
        SafetyDecision::Block { reason } => return Err(app_error(ErrorKind::Safety, reason)),
    }

    if let SandboxDecision::Deny { reason } = sandbox.check_put(&remote) {
        return Err(app_error(ErrorKind::Policy, reason));
    }

    let server = get_server(config, &server_name)?;
    let auth = resolve_auth(server, credentials)?;
    let result = with_msys_remote_path_hint(
        ssh.put(server, &auth, &local, &remote)
            .with_error_kind(ErrorKind::Ssh),
        &remote,
        windows_msys_argument_conversion_active(),
    )?;
    if json {
        let output = json!({
            "ok": true,
            "server": redact_secrets(&server_name),
            "local": redact_secrets(&result.source),
            "remote": redact_secrets(&result.destination),
            "bytes": result.bytes,
        });
        return Ok(ok(format!("{}\n", serde_json::to_string(&output)?)));
    }

    Ok(ok(format!(
        "uploaded {} bytes from {} to {}\n",
        result.bytes, result.source, result.destination
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
    let GetArgs { target, yes, json } = args;
    let (server_name, remote, local) = resolve_get_target(target, config)?;

    let server = get_server(config, &server_name)?;
    if let SandboxDecision::Deny { reason } = sandbox.check_get(&remote) {
        return Err(app_error(ErrorKind::Policy, reason));
    }

    if local.try_exists().with_error_kind(ErrorKind::Io)? && !yes {
        return Err(app_error(
            ErrorKind::Io,
            format!(
                "local file already exists: {}; pass --yes to overwrite",
                local.display()
            ),
        ));
    }

    let auth = resolve_auth(server, credentials)?;
    let result = with_msys_remote_path_hint(
        ssh.get(server, &auth, &remote, &local, yes)
            .with_error_kind(ErrorKind::Ssh),
        &remote,
        windows_msys_argument_conversion_active(),
    )?;
    if json {
        let output = json!({
            "ok": true,
            "server": redact_secrets(&server_name),
            "remote": redact_secrets(&result.source),
            "local": redact_secrets(&result.destination),
            "bytes": result.bytes,
        });
        return Ok(ok(format!("{}\n", serde_json::to_string(&output)?)));
    }

    Ok(ok(format!(
        "downloaded {} bytes from {} to {}\n",
        result.bytes, result.source, result.destination
    )))
}

fn resolve_put_target(
    target: Vec<String>,
    config: &SshwConfig,
) -> anyhow::Result<(String, PathBuf, String)> {
    // target is `[name] <local> <remote>`.
    let (name, rest) = split_target(&target, 2)
        .ok_or_else(|| app_error(ErrorKind::Config, "put expects [name] <local> <remote>"))?;
    let server = resolve_target_server(name, config)?;
    Ok((server, PathBuf::from(&rest[0]), rest[1].clone()))
}

fn resolve_get_target(
    target: Vec<String>,
    config: &SshwConfig,
) -> anyhow::Result<(String, String, PathBuf)> {
    // target is `[name] <remote> <local>`.
    let (name, rest) = split_target(&target, 2)
        .ok_or_else(|| app_error(ErrorKind::Config, "get expects [name] <remote> <local>"))?;
    let server = resolve_target_server(name, config)?;
    Ok((server, rest[0].clone(), PathBuf::from(&rest[1])))
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
}
