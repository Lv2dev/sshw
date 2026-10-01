//! Policy management and local execution checks; never connects to SSH.
use super::{
    CommandOutput, ExecContext, get_server, load_active_config, ok, sandbox_from_policy,
    select_account,
};
use crate::error::{ResultErrorKindExt, app_error};
use crate::output::{ErrorKind, redact_secrets};
use crate::policy::{
    AccountRule, Policy, PolicyExplanation, PolicyFile, load_policy_with_revision, resolve_policy,
    save_policy_if_unchanged,
};
use clap::{Args, Subcommand};
use serde_json::json;
use std::collections::BTreeMap;

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
    /// Enable the saved allowlist. Empty lists deny operations.
    Enable,
    /// Disable the saved allowlist; --policy still forces enforcement.
    /// Safety checks still apply.
    Disable,
    /// Add an allowlist entry. This does not enable the policy automatically.
    Allow(PolicyRuleArgs),
    /// Remove an exact entry; other matching rules can still allow the operation.
    Remove(PolicyRuleArgs),
    /// Explain run safety, account and policy checks without SSH or credentials.
    Check(PolicyCheckArgs),
    /// Check upload rules and local file readability, without SSH or credentials.
    CheckPut(PolicyTransferCheckArgs),
    /// Check download path/account rules and local overwrite confirmation.
    CheckGet(PolicyTransferCheckArgs),
}

#[derive(Debug, Args)]
pub struct PolicyTransferCheckArgs {
    /// Same target order as put/get: [server] <source> <destination>.
    #[arg(value_name = "TARGET", num_args = 2..=3, required = true)]
    pub target: Vec<String>,
    /// Registered login account (default: server default).
    #[arg(long)]
    pub user: Option<String>,
    /// Evaluate the safety/overwrite confirmation used by put/get --yes.
    #[arg(long)]
    pub yes: bool,
    /// For check-put, also check permission for the sibling staging file.
    #[arg(long)]
    pub atomic: bool,
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
    /// Same target order as run: [server] <command>. With one value, use the
    /// default server. Quote the entire remote command as one argument.
    #[arg(value_name = "TARGET", num_args = 1..=2, required = true)]
    pub target: Vec<String>,
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
    if let PolicyCommand::CheckPut(check) = args.command {
        return check_transfer(check, true, args.json, ctx);
    }
    if let PolicyCommand::CheckGet(check) = args.command {
        return check_transfer(check, false, args.json, ctx);
    }
    let action = match &args.command {
        PolicyCommand::Init => "init",
        PolicyCommand::Show => "show",
        PolicyCommand::Enable => "enable",
        PolicyCommand::Disable => "disable",
        PolicyCommand::Allow(_) => "allow",
        PolicyCommand::Remove(_) => "remove",
        PolicyCommand::Check(_) | PolicyCommand::CheckPut(_) | PolicyCommand::CheckGet(_) => {
            unreachable!()
        }
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
        let before = file.clone();
        match &args.command {
            PolicyCommand::Enable => file.enabled = true,
            PolicyCommand::Disable => file.enabled = false,
            PolicyCommand::Allow(rule) | PolicyCommand::Remove(rule) => {
                let adding = matches!(&args.command, PolicyCommand::Allow(_));
                change_rule(&mut file, &rule.rule, adding, ctx)?;
            }
            _ => {}
        }
        let changed = action == "init" || file != before;
        let change = match &args.command {
            PolicyCommand::Init => "created",
            PolicyCommand::Allow(_) if changed => "added",
            PolicyCommand::Allow(_) => "already_present",
            PolicyCommand::Remove(_) if changed => "removed",
            PolicyCommand::Remove(_) => "not_found",
            _ if changed => "updated",
            _ => "unchanged",
        };
        if mutating && changed {
            save_policy_if_unchanged(&ctx.home.policy_path, &file, &revision)
                .with_error_kind(ErrorKind::Policy)?;
        }
        let file_present = present || mutating;
        let enforced = file.enabled || ctx.policy_forced;
        let mut value = json!({"ok":true,"action":action,"path":ctx.home.policy_path,
            "present":file_present,"policy":file,"enforced":enforced,"forced":ctx.policy_forced});
        if mutating {
            value["changed"] = json!(changed);
            value["change"] = json!(change);
        }
        if args.json {
            redact_json(&mut value);
            return Ok(ok(format!("{value}\n")));
        }
        let outcome = if mutating {
            format!("result: {}\n", change.replace('_', " "))
        } else {
            String::new()
        };
        let saved_enabled = if file_present {
            file.enabled.to_string()
        } else {
            "not configured".to_string()
        };
        let reason = if ctx.policy_forced {
            "forced by --policy"
        } else if !file_present {
            "policy file missing"
        } else if file.enabled {
            "enabled in policy file"
        } else {
            "disabled in policy file"
        };
        let mut status = format!(
            "policy file: {}\nsaved enabled: {saved_enabled}\npolicy enforcement: {} ({reason})\n",
            if file_present { "present" } else { "missing" },
            if enforced { "on" } else { "off" }
        );
        if !file_present {
            status.push_str("next: using the same home/profile selection, run `sshw policy init` to create the policy file\n");
            if ctx.policy_forced {
                status.push_str(
                    "--policy requires a policy file; operations fail closed until it exists\n",
                );
            }
        } else if ctx.policy_forced && !file.enabled {
            status.push_str("next: remove --policy from the invocation to use the saved disabled setting; keep the same home/profile selection\n");
        }
        Ok(ok(format!(
            "policy {action}: {}\n{outcome}{status}{}\nBare program rules allow that program's arguments and subprocesses. Shell metacharacters require an exact full-command rule. Default accounts are implicitly allowed.\nCheck a command: sshw policy check <server> \"<command>\"\n",
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
    // Match run's loading and target-resolution order before evaluating checks.
    let policy = resolve_policy(&ctx.home.policy_path, ctx.policy_forced)
        .with_error_kind(ErrorKind::Policy)?;
    let sandbox = sandbox_from_policy(policy.clone());
    let (name, command) = super::resolve_run_target(args.target, &config)?;
    let mut errors = Vec::new();
    let checked = super::check_run_access(
        &name,
        &command,
        args.user.as_deref(),
        args.yes,
        sandbox.as_ref(),
        &config,
        |error| {
            errors.push(error);
            Ok(())
        },
    );
    match checked {
        Ok((_, user, account)) => {
            if let Err(error) =
                super::check_run_privilege(&name, user, account, args.as_root, args.no_password)
            {
                errors.push(error);
            }
        }
        // Preserve the error envelope when account resolution is the first
        // failure; an earlier safety/policy denial remains the primary result.
        Err(error) if errors.is_empty() => return Err(error),
        Err(error) => errors.push(error),
    }
    let exit_code = errors
        .first()
        .map(|error| crate::output::classify_error(error).exit_code())
        .unwrap_or(0);
    let reasons: Vec<_> = errors
        .iter()
        .map(|error| redact_secrets(&error.to_string()))
        .collect();
    let user = args
        .user
        .as_deref()
        .or_else(|| {
            config
                .servers
                .get(&name)
                .map(|server| server.default_user.as_str())
        })
        .unwrap_or("unresolved");
    let mut value = json!({"ok":true,"allowed":reasons.is_empty(),"home":ctx.home.root,
        "home_source":ctx.home.description,"server":name,"user":user,"reasons":reasons,
        "connection_tested":false,"credentials_checked":false});
    let mut checks = BTreeMap::from([("command", policy.explain_command(&command))]);
    add_account_explanation(&mut checks, &policy, &config, &name, Some(user));
    value["policy"] = policy_report(ctx, &policy, checks);
    redact_json(&mut value);
    let stdout = if json_output {
        format!("{value}\n")
    } else {
        format!(
            "home: {}\nserver/account: {}/{}\nlocal checks: {}\n{}\n{}SSH and credentials were not tested.\n",
            ctx.home.root.display(),
            name,
            user,
            if reasons.is_empty() {
                "allowed"
            } else {
                "blocked"
            },
            redact_secrets(&reasons.join("\n")),
            human_policy_report(&value["policy"])
        )
    };
    Ok(CommandOutput {
        stdout,
        stderr: String::new(),
        exit_code,
    })
}

fn check_transfer(
    args: PolicyTransferCheckArgs,
    upload: bool,
    json_output: bool,
    ctx: &ExecContext<'_>,
) -> anyhow::Result<CommandOutput> {
    use super::transfer;
    if !upload && args.atomic {
        return Err(app_error(
            ErrorKind::Usage,
            "--atomic is only supported by check-put",
        ));
    }
    let config = load_active_config(ctx.home)?;
    let policy = resolve_policy(&ctx.home.policy_path, ctx.policy_forced)
        .with_error_kind(ErrorKind::Policy)?;
    let sandbox = sandbox_from_policy(policy.clone());
    let (name, local, remote) = if upload {
        transfer::resolve_put_target(args.target, &config)?
    } else {
        let (name, remote, local) = transfer::resolve_get_target(args.target, &config)?;
        (name, local, remote)
    };
    let access = if upload {
        transfer::check_put_access(
            &name,
            args.user.as_deref(),
            &remote.value,
            args.yes,
            args.atomic,
            sandbox.as_ref(),
            &config,
        )
    } else {
        transfer::check_get_access(
            &name,
            args.user.as_deref(),
            &remote.value,
            &local,
            args.yes,
            sandbox.as_ref(),
            &config,
        )
    };
    let access_allowed = access.is_ok();
    let user = access
        .as_ref()
        .ok()
        .map(|(_, user, _)| *user)
        .or(args.user.as_deref())
        .or_else(|| {
            config
                .servers
                .get(&name)
                .map(|server| server.default_user.as_str())
        });
    let local_file_checked = upload && access_allowed;
    let validation = access.and_then(|_| {
        if upload {
            // Readability at this instant, without reading contents. Actual
            // transfer still opens and checks its own retained file handle.
            transfer::check_put_source(&local)?;
        }
        Ok(())
    });
    let local_file_ready = local_file_checked.then(|| validation.is_ok());
    let mut reasons = Vec::new();
    let mut exit_code = 0;
    if let Err(error) = validation {
        let kind = crate::output::classify_error(&error);
        if kind == ErrorKind::Config {
            return Err(error);
        }
        exit_code = kind.exit_code();
        let diagnostic = crate::output::ErrorResponse::from_error(&error);
        let mut reason = diagnostic.error.message;
        // Each cause is already redacted and consecutive wrapper duplicates
        // are removed. A path diagnostic may also include its OS cause inline.
        for cause in diagnostic.error.causes {
            if !reason.ends_with(&format!(": {cause}")) {
                reason.push_str(": ");
                reason.push_str(&cause);
            }
        }
        reasons.push(reason);
    }
    let operation = if upload { "put" } else { "get" };
    let mut value = json!({"ok":true,"allowed":reasons.is_empty(),"operation":operation,
        "server":name,"user":user,"local":local,"remote":remote.value,"reasons":reasons,
        "access_allowed":access_allowed,"local_file_checked":local_file_checked,"local_file_ready":local_file_ready,
        "connection_tested":false,"credentials_checked":false,"remote_permissions_checked":false});
    let mut checks = BTreeMap::from([(operation, policy.explain_path(&remote.value, upload))]);
    if upload
        && args.atomic
        && let Ok(parent) = crate::ssh::atomic_upload::parent_path(&remote.value)
    {
        checks.insert("atomic_parent", policy.explain_path(parent, true));
    }
    add_account_explanation(&mut checks, &policy, &config, &name, user);
    value["policy"] = policy_report(ctx, &policy, checks);
    redact_json(&mut value);
    let stdout = if json_output {
        format!("{value}\n")
    } else {
        redact_secrets(&format!(
            "operation: {operation}\nserver/account: {name}/{}\nlocal: {}\nremote: {}\nlocal checks: {}\n{}\n{}SSH, credentials and remote filesystem permissions were not tested. Local readiness is a point-in-time check. --yes confirms a local guardrail; it does not grant remote write permission.\n",
            user.unwrap_or("unresolved"),
            local.display(),
            remote.value,
            if reasons.is_empty() {
                "allowed"
            } else {
                "blocked"
            },
            reasons.join("\n"),
            human_policy_report(&value["policy"])
        ))
    };
    Ok(CommandOutput {
        stdout,
        stderr: String::new(),
        exit_code,
    })
}

fn add_account_explanation(
    checks: &mut BTreeMap<&'static str, PolicyExplanation>,
    policy: &Policy,
    config: &super::SshwConfig,
    name: &str,
    user: Option<&str>,
) {
    if let Some(server) = config.servers.get(name)
        && let Some(user) = user
        && server.accounts.contains_key(user)
    {
        checks.insert(
            "account",
            policy.explain_account(name, user, user == server.default_user),
        );
    }
}

fn policy_report(
    ctx: &ExecContext<'_>,
    policy: &Policy,
    checks: BTreeMap<&'static str, PolicyExplanation>,
) -> serde_json::Value {
    json!({"path":ctx.home.policy_path,"enforced":matches!(policy, Policy::Enabled(_)),
        "forced":ctx.policy_forced,"checks":checks})
}

fn human_policy_report(value: &serde_json::Value) -> String {
    let state = if value["forced"] == true {
        "enforced by --policy"
    } else if value["enforced"] == true {
        "enabled"
    } else {
        "disabled"
    };
    let mut text = format!(
        "policy: {state}\npolicy path: {}\n",
        value["path"].as_str().unwrap_or("")
    );
    if let Some(checks) = value["checks"].as_object() {
        for (name, decision) in checks {
            let detail = match decision["reason"].as_str().unwrap_or("") {
                "matched_rule" => format!(
                    "allowed by {} rule '{}'",
                    decision["match_type"].as_str().unwrap_or(""),
                    decision["matched_rule"].as_str().unwrap_or("")
                ),
                "policy_disabled" => "allowed because policy disabled".to_string(),
                "default_account" => "allowed as the default account".to_string(),
                "exact_command_required" => {
                    "blocked: shell syntax requires an exact full-command rule".to_string()
                }
                "parent_traversal" => {
                    "blocked: parent traversal ('..') cannot match a path rule".to_string()
                }
                _ => "blocked: no matching rule".to_string(),
            };
            text.push_str(&format!("policy {name}: {detail}\n"));
        }
    }
    text.push_str(
        "Policy decisions are separate from safety, account existence and local file checks.\n",
    );
    redact_secrets(&text)
}

fn redact_json(value: &mut serde_json::Value) {
    match value {
        serde_json::Value::String(text) => *text = redact_secrets(text),
        serde_json::Value::Array(values) => values.iter_mut().for_each(redact_json),
        serde_json::Value::Object(values) => values.values_mut().for_each(redact_json),
        _ => {}
    }
}
