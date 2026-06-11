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
    validate_privilege_password(&password)?;

    let previous_privilege = config.privileges.get(&args.name).cloned();
    let privilege = PrivilegeConfig {
        method: map_method(args.method),
        user: args.user,
        credential: namespace.privilege_credential_key(&args.name),
    };
    let output_method = privilege.method;
    let output_user = privilege.user.clone();
    let output_credential = privilege.credential.clone();
    credentials.set_password(&privilege.credential, &privilege.user, &password)?;
    config.privileges.insert(args.name.clone(), privilege);
    save_config(config_path, config)?;
    if let Some(previous) = previous_privilege {
        let current = config
            .privileges
            .get(&args.name)
            .expect("privilege just set");
        if previous.credential != current.credential || previous.user != current.user {
            credentials.delete_password(&previous.credential, &previous.user)?;
        }
    }

    let warning = if !credentials.is_persistent() {
        Some(
            "this credential backend does not persist privilege passwords; supply SSHW_PASSWORD at run time",
        )
    } else {
        None
    };

    if args.json {
        let mut output = json!({
            "ok": true,
            "server": args.name,
            "method": output_method,
            "user": output_user,
            "credential": output_credential,
        });
        if let (Some(map), Some(warning)) = (output.as_object_mut(), warning) {
            map.insert(
                "warning".to_string(),
                serde_json::Value::String(warning.to_string()),
            );
        }
        return Ok(ok(format!("{}\n", serde_json::to_string(&output)?)));
    }

    let mut message = format!("privilege set for {}\n", args.name);
    if let Some(warning) = warning {
        message.push_str(&format!("warning: {warning}\n"));
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

    credentials.delete_password(&privilege.credential, &privilege.user)?;
    config.privileges.remove(&args.name);
    save_config(config_path, config)?;
    if args.json {
        let output = json!({
            "ok": true,
            "action": "cleared",
            "server": args.name,
        });
        return Ok(ok(format!("{}\n", serde_json::to_string(&output)?)));
    }

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

pub(super) fn validate_privilege_password(password: &str) -> anyhow::Result<()> {
    if password.is_empty() {
        return Err(anyhow::anyhow!("password cannot be empty"));
    }
    if password.contains(['\n', '\r']) {
        return Err(anyhow::anyhow!("privilege password must be a single line"));
    }
    Ok(())
}

fn map_method(method: PrivilegeMethodArg) -> PrivilegeMethod {
    match method {
        PrivilegeMethodArg::Sudo => PrivilegeMethod::Sudo,
        PrivilegeMethodArg::Su => PrivilegeMethod::Su,
    }
}
