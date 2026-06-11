//! Server management subcommand handlers.
//!
//! These operate on the per-home `SshwConfig`: add/list/show/default/trust/remove.

use super::{
    AddArgs, AuthArg, CommandOutput, DefaultArgs, ListArgs, Prompter, RemoveArgs, ShowArgs,
    TrustArgs, get_server, no_default_server_error, ok, unknown_server,
};
use crate::config::{AuthConfig, PrivilegeConfig, ServerConfig, SshwConfig, save_config};
use crate::credentials::CredentialStore;
use crate::home::CredentialNamespace;
use crate::output::ServerOutput;
use crate::ssh::SshClient;
use serde_json::json;
use std::path::Path;

pub(super) fn add_server<C, P>(
    args: AddArgs,
    config_path: &Path,
    namespace: &CredentialNamespace,
    credentials: &C,
    prompter: &mut P,
    config: &mut SshwConfig,
) -> anyhow::Result<CommandOutput>
where
    C: CredentialStore,
    P: Prompter,
{
    let previous_server = config.servers.get(&args.name).cloned();
    if previous_server.is_some()
        && !args.force
        && !prompter.confirm(&format!("update existing server '{}'? [y/N] ", args.name))?
    {
        return Err(anyhow::anyhow!("add cancelled"));
    }

    let auth = match args.auth {
        AuthArg::Password => {
            let credential = namespace.credential_key(&args.name);
            let password = if args.password_stdin {
                prompter.password_stdin()?
            } else {
                prompter.password("SSH password: ")?
            };
            if password.is_empty() {
                return Err(anyhow::anyhow!("password cannot be empty"));
            }
            credentials.set_password(&credential, &args.user, &password)?;
            AuthConfig::Password { credential }
        }
        AuthArg::Agent => {
            if args.password_stdin {
                return Err(anyhow::anyhow!(
                    "--password-stdin cannot be used with --auth agent"
                ));
            }
            AuthConfig::Agent
        }
    };

    let new_server = ServerConfig {
        host: args.host,
        port: args.port,
        user: args.user,
        auth,
    };
    let stale_credential = stale_password_credential(previous_server.as_ref(), &new_server);
    let stale_privilege = previous_server
        .as_ref()
        .and_then(|_| config.privileges.get(&args.name).cloned());
    config.servers.insert(args.name.clone(), new_server);
    if previous_server.is_some() {
        config.privileges.remove(&args.name);
    }

    if config.default.is_none() {
        config.default = Some(args.name.clone());
    }

    save_config(config_path, config)?;
    if let Some((credential, user)) = stale_credential {
        credentials.delete_password(&credential, &user)?;
    }
    if let Some(privilege) = stale_privilege {
        delete_privilege_password(credentials, &privilege)?;
    }

    let action = if previous_server.is_some() {
        "updated"
    } else {
        "added"
    };
    let warning = if matches!(args.auth, AuthArg::Password) && !credentials.is_persistent() {
        Some("this credential backend does not persist passwords; supply SSHW_PASSWORD at run time")
    } else {
        None
    };

    if args.json {
        let mut output = json!({
            "ok": true,
            "action": action,
            "server": args.name,
        });
        if let (Some(map), Some(warning)) = (output.as_object_mut(), warning) {
            map.insert(
                "warning".to_string(),
                serde_json::Value::String(warning.to_string()),
            );
        }
        return Ok(ok(format!("{}\n", serde_json::to_string(&output)?)));
    }

    let mut message = format!("{action} {}\n", args.name);
    if let Some(warning) = warning {
        message.push_str(&format!("warning: {warning}\n"));
    }
    Ok(ok(message))
}

pub(super) fn list_servers(args: ListArgs, config: &SshwConfig) -> anyhow::Result<CommandOutput> {
    let servers = server_outputs(config);
    if args.json {
        return Ok(ok(format!("{}\n", serde_json::to_string(&servers)?)));
    }

    let mut stdout = String::new();
    for server in servers {
        let marker = if server.is_default { "*" } else { " " };
        stdout.push_str(&format!(
            "{marker} {} {}:{} user={} auth={}\n",
            server.name,
            server.host,
            server.port,
            server.user,
            auth_label(&server.auth)
        ));
    }
    Ok(ok(stdout))
}

pub(super) fn show_server(args: ShowArgs, config: &SshwConfig) -> anyhow::Result<CommandOutput> {
    let server = get_server(config, &args.name)?;
    let output = ServerOutput::from_config(
        &args.name,
        server,
        config.default.as_deref() == Some(args.name.as_str()),
    );

    if args.json {
        // `show` returns a single object, so add the `ok` discriminator without
        // touching `ServerOutput` (which `list` serializes as bare array items).
        let mut value = serde_json::to_value(&output)?;
        if let Some(map) = value.as_object_mut() {
            map.insert("ok".to_string(), serde_json::Value::Bool(true));
        }
        return Ok(ok(format!("{}\n", serde_json::to_string(&value)?)));
    }

    Ok(ok(format!(
        "{}\n  host: {}\n  port: {}\n  user: {}\n  auth: {}\n",
        output.name,
        output.host,
        output.port,
        output.user,
        auth_label(&output.auth)
    )))
}

pub(super) fn default_server(
    args: DefaultArgs,
    config_path: &Path,
    config: &mut SshwConfig,
) -> anyhow::Result<CommandOutput> {
    let Some(name) = args.name else {
        let name = config
            .default
            .as_ref()
            .ok_or_else(no_default_server_error)?;
        return Ok(ok(format!("{name}\n")));
    };

    if !config.servers.contains_key(&name) {
        return Err(unknown_server(&name));
    }

    config.default = Some(name.clone());
    save_config(config_path, config)?;
    Ok(ok(format!("default set to {name}\n")))
}

pub(super) fn trust_server<S, P>(
    args: TrustArgs,
    ssh: &S,
    prompter: &mut P,
    config: &SshwConfig,
) -> anyhow::Result<CommandOutput>
where
    S: SshClient,
    P: Prompter,
{
    let server = get_server(config, &args.name)?;
    let host_key = ssh.host_key(server)?;
    let prompt = format!(
        "trust {} {} {}? [y/N] ",
        args.name, host_key.algorithm, host_key.fingerprint_sha256
    );
    if !args.yes && !prompter.confirm(&prompt)? {
        return Err(anyhow::anyhow!("trust cancelled"));
    }

    let trusted = ssh.trust_host(&args.name, server, &host_key.fingerprint_sha256)?;
    if args.json {
        let output = json!({
            "ok": true,
            "server": args.name,
            "algorithm": trusted.algorithm,
            "fingerprint_sha256": trusted.fingerprint_sha256,
        });
        return Ok(ok(format!("{}\n", serde_json::to_string(&output)?)));
    }

    Ok(ok(format!(
        "trusted {} {} {}\n",
        args.name, trusted.algorithm, trusted.fingerprint_sha256
    )))
}

pub(super) fn remove_server<C, P>(
    args: RemoveArgs,
    config_path: &Path,
    credentials: &C,
    prompter: &mut P,
    config: &mut SshwConfig,
) -> anyhow::Result<CommandOutput>
where
    C: CredentialStore,
    P: Prompter,
{
    let server = get_server(config, &args.name)?.clone();
    let privilege = config.privileges.get(&args.name).cloned();
    if !args.yes && !prompter.confirm(&format!("remove server '{}'? [y/N] ", args.name))? {
        return Err(anyhow::anyhow!("removal cancelled"));
    }

    if let Some(privilege) = &privilege {
        delete_privilege_password(credentials, privilege)?;
    }
    if let AuthConfig::Password { credential } = &server.auth {
        credentials.delete_password(credential, &server.user)?;
    }

    config.servers.remove(&args.name);
    config.privileges.remove(&args.name);
    if config.default.as_deref() == Some(args.name.as_str()) {
        config.default = config.servers.keys().next().cloned();
    }

    save_config(config_path, config)?;
    if args.json {
        let output = json!({
            "ok": true,
            "action": "removed",
            "server": args.name,
        });
        return Ok(ok(format!("{}\n", serde_json::to_string(&output)?)));
    }

    Ok(ok(format!("removed {}\n", args.name)))
}

fn server_outputs(config: &SshwConfig) -> Vec<ServerOutput> {
    config
        .servers
        .iter()
        .map(|(name, server)| {
            ServerOutput::from_config(name, server, config.default.as_deref() == Some(name))
        })
        .collect()
}

fn stale_password_credential(
    previous_server: Option<&ServerConfig>,
    new_server: &ServerConfig,
) -> Option<(String, String)> {
    let previous = previous_server?;
    let AuthConfig::Password {
        credential: previous_credential,
    } = &previous.auth
    else {
        return None;
    };

    match &new_server.auth {
        AuthConfig::Password { credential }
            if credential == previous_credential && new_server.user == previous.user =>
        {
            None
        }
        _ => Some((previous_credential.clone(), previous.user.clone())),
    }
}

fn delete_privilege_password<C>(credentials: &C, privilege: &PrivilegeConfig) -> anyhow::Result<()>
where
    C: CredentialStore,
{
    credentials.delete_password(&privilege.credential, &privilege.user)
}

fn auth_label(auth: &crate::output::AuthOutput) -> &'static str {
    match auth {
        crate::output::AuthOutput::Password { .. } => "password",
        crate::output::AuthOutput::Agent => "agent",
    }
}
