//! Privilege escalation metadata handlers.

use super::{
    CommandOutput, PrivilegeClearArgs, PrivilegeMethodArg, PrivilegeSetArgs, PrivilegeShowArgs,
    Prompter, get_server, ok, unknown_server,
};
use crate::config::{PrivilegeConfig, PrivilegeMethod, SshwConfig, save_config};
use crate::credentials::CredentialStore;
use crate::home::CredentialNamespace;
use serde_json::json;
use std::path::Path;

pub(super) fn set_privilege<C, P>(
    args: PrivilegeSetArgs,
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
    get_server(config, &args.name)?;
    if config.privileges.contains_key(&args.name)
        && !args.force
        && !prompter.confirm(&format!(
            "update privilege configuration for '{}'? [y/N] ",
            args.name
        ))?
    {
        return Err(anyhow::anyhow!("privilege update cancelled"));
    }

    let password = if args.password_stdin {
        prompter.password_stdin()?
    } else {
        prompter.password("Privilege password: ")?
    };
    if password.is_empty() {
        return Err(anyhow::anyhow!("password cannot be empty"));
    }

    let privilege = PrivilegeConfig {
        method: map_method(args.method),
        user: args.user,
        credential: namespace.privilege_credential_key(&args.name),
    };
    credentials.set_password(&privilege.credential, &privilege.user, &password)?;
    config.privileges.insert(args.name.clone(), privilege);
    save_config(config_path, config)?;

    let mut message = format!("privilege set for {}\n", args.name);
    if !credentials.is_persistent() {
        message.push_str(
            "warning: this credential backend does not persist privilege passwords; supply SSHW_PASSWORD at run time\n",
        );
    }
    Ok(ok(message))
}

pub(super) fn show_privilege(
    args: PrivilegeShowArgs,
    config: &SshwConfig,
) -> anyhow::Result<CommandOutput> {
    get_server(config, &args.name)?;
    let privilege = config
        .privileges
        .get(&args.name)
        .ok_or_else(|| missing_privilege(&args.name))?;

    if args.json {
        let output = json!({
            "ok": true,
            "server": args.name,
            "method": privilege.method,
            "user": privilege.user,
            "credential": privilege.credential,
        });
        return Ok(ok(format!("{}\n", serde_json::to_string(&output)?)));
    }

    Ok(ok(format!(
        "{}\n  method: {}\n  user: {}\n  credential: {}\n",
        args.name,
        method_label(privilege.method),
        privilege.user,
        privilege.credential
    )))
}

pub(super) fn clear_privilege<C, P>(
    args: PrivilegeClearArgs,
    config_path: &Path,
    credentials: &C,
    prompter: &mut P,
    config: &mut SshwConfig,
) -> anyhow::Result<CommandOutput>
where
    C: CredentialStore,
    P: Prompter,
{
    if !config.servers.contains_key(&args.name) {
        return Err(unknown_server(&args.name));
    }
    let privilege = config
        .privileges
        .get(&args.name)
        .cloned()
        .ok_or_else(|| missing_privilege(&args.name))?;

    if !args.yes
        && !prompter.confirm(&format!(
            "clear privilege configuration for '{}'? [y/N] ",
            args.name
        ))?
    {
        return Err(anyhow::anyhow!("privilege clear cancelled"));
    }

    config.privileges.remove(&args.name);
    save_config(config_path, config)?;
    credentials.delete_password(&privilege.credential, &privilege.user)?;
    Ok(ok(format!("privilege cleared for {}\n", args.name)))
}

pub(super) fn missing_privilege(server: &str) -> anyhow::Error {
    anyhow::anyhow!(
        "privilege configuration missing for server '{server}'; run 'sshw privilege set {server} --method sudo' first"
    )
}

pub(super) fn method_label(method: PrivilegeMethod) -> &'static str {
    match method {
        PrivilegeMethod::Sudo => "sudo",
        PrivilegeMethod::Su => "su",
    }
}

fn map_method(method: PrivilegeMethodArg) -> PrivilegeMethod {
    match method {
        PrivilegeMethodArg::Sudo => PrivilegeMethod::Sudo,
        PrivilegeMethodArg::Su => PrivilegeMethod::Su,
    }
}
