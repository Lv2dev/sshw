//! File transfer subcommand handlers.

use super::{
    CommandOutput, GetArgs, PutArgs, get_server, ok, resolve_auth, resolve_target_server,
    split_target,
};
use crate::config::SshwConfig;
use crate::credentials::CredentialStore;
use crate::output::redact_secrets;
use crate::safety::{SafetyDecision, classify_remote_write_path};
use crate::sandbox::{Sandbox, SandboxDecision};
use crate::ssh::SshClient;
use serde_json::json;
use std::path::PathBuf;

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
        SafetyDecision::Block { reason } => return Err(anyhow::anyhow!("{reason}")),
    }

    if let SandboxDecision::Deny { reason } = sandbox.check_put(&remote) {
        return Err(anyhow::anyhow!("{reason}"));
    }

    let server = get_server(config, &server_name)?;
    let auth = resolve_auth(server, credentials)?;
    let result = ssh.put(server, &auth, &local, &remote)?;
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
        return Err(anyhow::anyhow!("{reason}"));
    }

    if local.exists() && !yes {
        return Err(anyhow::anyhow!(
            "local file already exists: {}; pass --yes to overwrite",
            local.display()
        ));
    }

    let auth = resolve_auth(server, credentials)?;
    let result = ssh.get(server, &auth, &remote, &local, yes)?;
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
        .ok_or_else(|| anyhow::anyhow!("put expects [name] <local> <remote>"))?;
    let server = resolve_target_server(name, config)?;
    Ok((server, PathBuf::from(&rest[0]), rest[1].clone()))
}

fn resolve_get_target(
    target: Vec<String>,
    config: &SshwConfig,
) -> anyhow::Result<(String, String, PathBuf)> {
    // target is `[name] <remote> <local>`.
    let (name, rest) = split_target(&target, 2)
        .ok_or_else(|| anyhow::anyhow!("get expects [name] <remote> <local>"))?;
    let server = resolve_target_server(name, config)?;
    Ok((server, rest[0].clone(), PathBuf::from(&rest[1])))
}
