//! File transfer subcommand handlers.

use super::{
    CommandOutput, GetArgs, PutArgs, get_server, ok, resolve_auth, resolve_target_server,
    select_account, split_target,
};
use crate::config::SshwConfig;
use crate::credentials::CredentialStore;
use crate::error::{ResultErrorKindExt, app_error};
use crate::output::{ErrorKind, classify_error, redact_secrets};
use crate::safety::{SafetyDecision, classify_remote_write_path};
use crate::sandbox::{Sandbox, SandboxDecision};
use crate::ssh::{SshClient, SshTarget};
use serde_json::json;
use std::path::PathBuf;

const MSYS_REMOTE_PATH_HINT: &str = "Git Bash/MSYS may have converted the remote path into a Windows path; prefix the remote absolute path with 'remote:' (for example remote:/tmp/file), or retry with MSYS2_ARG_CONV_EXCL='*'";
const REMOTE_PATH_LITERAL_PREFIX: &str = "remote:";

#[derive(Debug)]
struct RemotePath {
    value: String,
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
        yes,
        json,
    } = args;
    let (server_name, local, remote) = resolve_put_target(target, config)?;

    match classify_remote_write_path(&remote.value, yes) {
        SafetyDecision::Allow => {}
        SafetyDecision::Block { reason } => return Err(app_error(ErrorKind::Safety, reason)),
    }

    if let SandboxDecision::Deny { reason } = sandbox.check_put(&remote.value) {
        return Err(app_error(ErrorKind::Policy, reason));
    }

    let server = get_server(config, &server_name)?;
    let (login_user, account) = select_account(&server_name, server, user.as_deref())?;
    if let SandboxDecision::Deny { reason } =
        sandbox.check_account(&server_name, login_user, login_user == server.default_user)
    {
        return Err(app_error(ErrorKind::Policy, reason));
    }
    let auth = resolve_auth(account, login_user, credentials)?;
    let ssh_target = SshTarget::new(server, login_user);
    let result = with_msys_remote_path_hint(
        ssh.put(&ssh_target, &auth, &local, &remote.value)
            .with_error_kind(ErrorKind::Ssh),
        &remote.value,
        windows_msys_argument_conversion_active() && !remote.explicit_literal,
    )?;
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
    let GetArgs {
        target,
        user,
        yes,
        json,
    } = args;
    let (server_name, remote, local) = resolve_get_target(target, config)?;

    let server = get_server(config, &server_name)?;
    if let SandboxDecision::Deny { reason } = sandbox.check_get(&remote.value) {
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

    let (login_user, account) = select_account(&server_name, server, user.as_deref())?;
    if let SandboxDecision::Deny { reason } =
        sandbox.check_account(&server_name, login_user, login_user == server.default_user)
    {
        return Err(app_error(ErrorKind::Policy, reason));
    }
    let auth = resolve_auth(account, login_user, credentials)?;
    let ssh_target = SshTarget::new(server, login_user);
    let result = with_msys_remote_path_hint(
        ssh.get(&ssh_target, &auth, &remote.value, &local, yes)
            .with_error_kind(ErrorKind::Ssh),
        &remote.value,
        windows_msys_argument_conversion_active() && !remote.explicit_literal,
    )?;
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
        result.bytes, result.source, result.destination
    )))
}

fn resolve_put_target(
    target: Vec<String>,
    config: &SshwConfig,
) -> anyhow::Result<(String, PathBuf, RemotePath)> {
    // target is `[name] <local> <remote>`.
    let (name, rest) = split_target(&target, 2)
        .ok_or_else(|| app_error(ErrorKind::Config, "put expects [name] <local> <remote>"))?;
    let server = resolve_target_server(name, config)?;
    Ok((
        server,
        PathBuf::from(&rest[0]),
        decode_remote_path(&rest[1])?,
    ))
}

fn resolve_get_target(
    target: Vec<String>,
    config: &SshwConfig,
) -> anyhow::Result<(String, RemotePath, PathBuf)> {
    // target is `[name] <remote> <local>`.
    let (name, rest) = split_target(&target, 2)
        .ok_or_else(|| app_error(ErrorKind::Config, "get expects [name] <remote> <local>"))?;
    let server = resolve_target_server(name, config)?;
    Ok((
        server,
        decode_remote_path(&rest[0])?,
        PathBuf::from(&rest[1]),
    ))
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
