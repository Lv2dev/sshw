//! Policy management and local execution checks; never connects to SSH.
use super::{
    CommandOutput, ExecContext, build_sandbox, get_server, load_active_config, ok, select_account,
};
use crate::error::{ResultErrorKindExt, app_error};
use crate::output::{ErrorKind, redact_secrets};
use crate::policy::{AccountRule, PolicyFile, load_policy_with_revision, save_policy_if_unchanged};
use crate::safety::{SafetyDecision, classify_command};
use crate::sandbox::SandboxDecision;
use clap::{Args, Subcommand};
use serde_json::json;

#[derive(Debug, Args)]
pub struct PolicyArgs {
    /// Emit JSON, including local check results.
    #[arg(long, global = true)]
    pub json: bool,
    #[command(subcommand)]
    pub command: PolicyCommand,
}

#[derive(Debug, Subcommand)]
pub enum PolicyCommand {
    /// Create a disabled, empty policy without replacing an existing file.
    Init,
    /// Show the active home's policy and how command rules are interpreted.
    Show,
    /// Enable the configured allowlist. Empty lists deny operations.
    Enable,
    /// Disable allowlist enforcement (safety checks still apply).
    Disable,
    /// Add an allowlist entry. This does not enable the policy automatically.
    Allow(PolicyRuleArgs),
    /// Remove an exact entry; other matching rules can still allow the operation.
    Remove(PolicyRuleArgs),
    /// Explain run safety, account and policy checks without SSH or credentials.
    Check(PolicyCheckArgs),
}

#[derive(Debug, Args)]
pub struct PolicyRuleArgs {
    #[command(subcommand)]
    pub rule: PolicyRule,
}

#[derive(Debug, Subcommand)]
pub enum PolicyRule {
    /// Allow a program, exact command, or trailing-* prefix. Never include secrets.
    Command { value: String },
    /// Allow uploads under a remote path prefix.
    Put { path: String },
    /// Allow downloads under a remote path prefix.
    Get { path: String },
    /// Allow a registered non-default login account.
    Account { server: String, user: String },
}

#[derive(Debug, Args)]
pub struct PolicyCheckArgs {
    /// Registered server name.
    pub name: String,
    /// Entire remote command, quoted as one argument.
    pub command: String,
    /// Registered login account (default: server default).
    #[arg(long)]
    pub user: Option<String>,
    /// Evaluate the explicit safety confirmation used by run --yes.
    #[arg(long)]
    pub yes: bool,
    /// Evaluate the configured privilege path as well.
    #[arg(long, visible_alias = "elevate")]
    pub as_root: bool,
    /// Evaluate sudo -n without stored privilege credentials.
    #[arg(long, requires = "as_root")]
    pub no_password: bool,
}

pub(super) fn run_policy(args: PolicyArgs, ctx: &ExecContext<'_>) -> anyhow::Result<CommandOutput> {
    if let PolicyCommand::Check(check) = args.command {
        return check_run(check, args.json, ctx);
    }
    let action = match &args.command {
        PolicyCommand::Init => "init",
        PolicyCommand::Show => "show",
        PolicyCommand::Enable => "enable",
        PolicyCommand::Disable => "disable",
        PolicyCommand::Allow(_) => "allow",
        PolicyCommand::Remove(_) => "remove",
        PolicyCommand::Check(_) => unreachable!(),
    };
    let mutating = action != "show";
    let _lock = if mutating {
        Some(
            crate::storage::acquire_exclusive_lock(&ctx.home.root.join(".sshw.lock"))
                .with_error_kind(ErrorKind::Policy)?,
        )
    } else {
        None
    };
    let result = (|| {
        let (existing, revision) =
            load_policy_with_revision(&ctx.home.policy_path).with_error_kind(ErrorKind::Policy)?;
        if action == "init" && existing.is_some() {
            return Err(app_error(
                ErrorKind::Policy,
                "policy file already exists; use 'sshw policy show' to inspect it",
            ));
        }
        if existing.is_none() && !matches!(args.command, PolicyCommand::Init | PolicyCommand::Show)
        {
            return Err(app_error(
                ErrorKind::Policy,
                "policy file is missing; run 'sshw policy init' first",
            ));
        }
        let present = existing.is_some();
        let mut file = existing.unwrap_or_default();
        match &args.command {
            PolicyCommand::Enable => file.enabled = true,
            PolicyCommand::Disable => file.enabled = false,
            PolicyCommand::Allow(rule) | PolicyCommand::Remove(rule) => {
                let adding = matches!(&args.command, PolicyCommand::Allow(_));
                change_rule(&mut file, &rule.rule, adding, ctx)?;
            }
            _ => {}
        }
        if mutating {
            save_policy_if_unchanged(&ctx.home.policy_path, &file, &revision)
                .with_error_kind(ErrorKind::Policy)?;
        }
        let mut value = json!({"ok":true,"action":action,"path":ctx.home.policy_path,
            "present":present || mutating,"policy":file,"enforced":file.enabled || ctx.policy_forced});
        if args.json {
            redact_json(&mut value);
            return Ok(ok(format!("{value}\n")));
        }
        Ok(ok(format!(
            "policy {action}: {}\n{}\nBare program rules allow that program's arguments and subprocesses. Shell metacharacters require an exact full-command rule. Default accounts are implicitly allowed.\nCheck a command: sshw policy check <server> \"<command>\"\n",
            ctx.home.policy_path.display(),
            redact_secrets(&serde_json::to_string_pretty(&file)?)
        )))
    })();
    if mutating {
        // Never log rule contents: exact commands can contain sensitive arguments.
        super::record_audit_result(
            ctx.audit,
            Some(("policy", None, None, Some(action.to_string()))),
            &result,
        );
    }
    result
}

fn change_rule(
    file: &mut PolicyFile,
    rule: &PolicyRule,
    adding: bool,
    ctx: &ExecContext<'_>,
) -> anyhow::Result<()> {
    if let PolicyRule::Account { server, user } = rule {
        if adding {
            let config = load_active_config(ctx.home)?;
            let selected = get_server(&config, server)?;
            select_account(server, selected, Some(user))?;
        }
        let entry = AccountRule {
            server: server.clone(),
            user: user.clone(),
        };
        if adding && !file.allow_accounts.contains(&entry) {
            file.allow_accounts.push(entry);
        } else if !adding {
            file.allow_accounts.retain(|value| value != &entry);
        }
        return Ok(());
    }
    let (entries, value) = match rule {
        PolicyRule::Command { value } => (&mut file.allow_commands, value.clone()),
        PolicyRule::Put { path } => (
            &mut file.allow_put_paths,
            super::transfer::policy_remote_path(path)?,
        ),
        PolicyRule::Get { path } => (
            &mut file.allow_get_paths,
            super::transfer::policy_remote_path(path)?,
        ),
        PolicyRule::Account { .. } => unreachable!(),
    };
    if adding && (value.trim().is_empty() || value.trim() == "*") {
        return Err(app_error(
            ErrorKind::Policy,
            "empty and '*' policy entries do not grant access; specify a program, exact command, or path",
        ));
    }
    if adding
        && !matches!(rule, PolicyRule::Command { .. })
        && value.split(['/', '\\']).any(|part| part == "..")
    {
        return Err(app_error(
            ErrorKind::Policy,
            "policy paths containing '..' cannot grant access; use a normalized remote path",
        ));
    }
    if adding && !entries.contains(&value) {
        entries.push(value.clone());
    } else if !adding {
        entries.retain(|entry| entry != &value);
    }
    Ok(())
}

fn check_run(
    args: PolicyCheckArgs,
    json_output: bool,
    ctx: &ExecContext<'_>,
) -> anyhow::Result<CommandOutput> {
    let config = load_active_config(ctx.home)?;
    let server = get_server(&config, &args.name)?;
    let (user, account) = select_account(&args.name, server, args.user.as_deref())?;
    let sandbox = build_sandbox(&ctx.home.policy_path, ctx.policy_forced)?;
    let mut reasons = Vec::new();
    let mut exit_code = 0;
    if let SafetyDecision::Block { reason } = classify_command(&args.command, args.yes) {
        reasons.push(reason);
        exit_code = ErrorKind::Safety.exit_code();
    }
    for decision in [
        sandbox.check_command(&args.command),
        sandbox.check_account(&args.name, user, user == server.default_user),
    ] {
        if let SandboxDecision::Deny { reason } = decision {
            reasons.push(reason);
            if exit_code == 0 {
                exit_code = ErrorKind::Policy.exit_code();
            }
        }
    }
    if args.as_root && !args.no_password && account.privilege.is_none() {
        reasons.push(format!(
            "privilege is not configured; run 'sshw privilege set {} --account {}'",
            args.name, user
        ));
        if exit_code == 0 {
            exit_code = ErrorKind::Config.exit_code();
        }
    }
    if args.no_password
        && account
            .privilege
            .as_ref()
            .is_some_and(|p| p.method != crate::config::PrivilegeMethod::Sudo)
    {
        reasons.push(
            "--no-password requires a sudo privilege path; this account is configured for su"
                .to_string(),
        );
        if exit_code == 0 {
            exit_code = ErrorKind::Config.exit_code();
        }
    }
    let mut value = json!({"ok":true,"allowed":reasons.is_empty(),"home":ctx.home.root,
        "home_source":ctx.home.description,"server":args.name,"user":user,"reasons":reasons,
        "connection_tested":false,"credentials_checked":false});
    redact_json(&mut value);
    let stdout = if json_output {
        format!("{value}\n")
    } else {
        format!(
            "home: {}\nserver/account: {}/{}\nlocal checks: {}\n{}\nSSH and credentials were not tested.\n",
            ctx.home.root.display(),
            args.name,
            user,
            if reasons.is_empty() {
                "allowed"
            } else {
                "blocked"
            },
            redact_secrets(&reasons.join("\n"))
        )
    };
    Ok(CommandOutput {
        stdout,
        stderr: String::new(),
        exit_code,
    })
}

fn redact_json(value: &mut serde_json::Value) {
    match value {
        serde_json::Value::String(text) => *text = redact_secrets(text),
        serde_json::Value::Array(values) => values.iter_mut().for_each(redact_json),
        serde_json::Value::Object(values) => values.values_mut().for_each(redact_json),
        _ => {}
    }
}
