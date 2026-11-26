//! Server management subcommand handlers.
//!
//! These operate on the per-home `SshwConfig`: add/list/show/default/trust/remove.

use super::{
    AddArgs, AuthArg, CommandOutput, DefaultArgs, ExecContext, ListArgs, Prompter, RemoveArgs,
    ShowArgs, TrustArgs, get_server, no_default_server_error, ok, unknown_server,
};
use crate::config::{
    AccountConfig, AuthConfig, ConfigRevision, ServerConfig, SshwConfig, save_config_if_unchanged,
    validate_account_user, validate_server_endpoint,
};
use crate::credentials::CredentialStore;
use crate::error::{ResultErrorKindExt, app_error, credential_cleanup_error};
use crate::home::{CredentialPurpose, validate_server_name};
use crate::local_command::display_value as trust_display;
use crate::output::{DefaultChange, ErrorKind, ServerOutput, redact_secrets};
use crate::ssh::SshClient;
use serde_json::json;
use std::path::Path;

pub(super) fn add_server<C, P>(
    args: AddArgs,
    revision: &ConfigRevision,
    ctx: &ExecContext<'_>,
    global_selection: bool,
    credentials: &C,
    prompter: &mut P,
    config: &mut SshwConfig,
) -> anyhow::Result<CommandOutput>
where
    C: CredentialStore,
    P: Prompter,
{
    let config_path = &ctx.home.config_path;
    let namespace = &ctx.home.namespace;
    validate_server_name(&args.name).with_error_kind(ErrorKind::Config)?;
    validate_account_user(&args.user).with_error_kind(ErrorKind::Config)?;
    validate_server_endpoint(&args.name, &args.host, args.port)
        .with_error_kind(ErrorKind::Config)?;

    let previous_server = config.servers.get(&args.name).cloned();
    let default_change = previous_server.as_ref().and_then(|previous| {
        DefaultChange::between(
            "account",
            Some(previous.default_user.clone()),
            Some(args.user.clone()),
        )
    });
    let account_notice = default_change
        .as_ref()
        .map(|change| {
            format!(
                "; default login account will change: {} -> {}",
                super::hints::redacted_argument(change.previous.as_deref().unwrap_or("none")),
                super::hints::redacted_argument(change.current.as_deref().unwrap_or("none"))
            )
        })
        .unwrap_or_default();
    let action = if previous_server.is_some() {
        "updated"
    } else {
        "added"
    };
    if let Some(previous) = &previous_server
        && (previous.host != args.host || previous.port != args.port)
        && !args.replace
    {
        return Err(app_error(
            ErrorKind::Config,
            format!(
                "{}. Changing a server address through add requires --replace, which removes its existing accounts and privilege settings; use it only for a full replacement. Use a new server name to keep the old endpoint available",
                super::hints::endpoint_update(
                    ctx,
                    global_selection,
                    &args.name,
                    (previous.host != args.host).then_some(args.host.as_str()),
                    (previous.port != args.port).then_some(args.port)
                )
            ),
        ));
    }
    super::check_registration_auth(args.auth, args.password_stdin)?;
    let prompt = if args.replace {
        format!(
            "replace server '{}' and remove its existing accounts and privilege settings{account_notice}? [y/N] ",
            super::hints::redacted_argument(&args.name)
        )
    } else {
        format!(
            "update account '{}/{}' (other accounts and privilege settings are preserved{account_notice})? [y/N] ",
            super::hints::redacted_argument(&args.name),
            super::hints::redacted_argument(&args.user)
        )
    };
    if previous_server.is_some()
        && !args.force
        && !prompter
            .confirm_with_option(&prompt, "--force")
            .with_error_kind(ErrorKind::Config)?
    {
        return Err(app_error(ErrorKind::Config, "add cancelled"));
    }

    let before = config.clone();
    let mut new_password_credential = None;
    let auth = match args.auth {
        AuthArg::Password => {
            let credential = namespace.new_account_credential_key(
                CredentialPurpose::Login,
                &args.name,
                &args.user,
            );
            let password = if args.password_stdin {
                prompter.password_stdin().with_error_kind(ErrorKind::Auth)?
            } else {
                prompter
                    .password(&super::prompt::login_password_prompt(
                        &args.name, &args.user,
                    ))
                    .with_error_kind(ErrorKind::Auth)?
            };
            if password.is_empty() {
                return Err(app_error(ErrorKind::Auth, "password cannot be empty"));
            }
            credentials
                .set_password_for(CredentialPurpose::Login, &credential, &args.user, &password)
                .with_error_kind(ErrorKind::Auth)?;
            new_password_credential = Some((credential.clone(), args.user.clone()));
            AuthConfig::Password { credential }
        }
        AuthArg::Agent => AuthConfig::Agent,
    };

    let mut accounts = previous_server
        .as_ref()
        .filter(|_| !args.replace)
        .map(|server| server.accounts.clone())
        .unwrap_or_default();
    let privilege = accounts
        .get(&args.user)
        .and_then(|account| account.privilege.clone());
    accounts.insert(args.user.clone(), AccountConfig { auth, privilege });
    let new_server = ServerConfig {
        host: args.host,
        port: args.port,
        default_user: args.user,
        accounts,
    };
    let retained_credentials = stored_credentials(&new_server);
    let stale_credentials = previous_server
        .as_ref()
        .map(stored_credentials)
        .unwrap_or_default()
        .into_iter()
        .filter(|entry| !retained_credentials.contains(entry));
    config.servers.insert(args.name.clone(), new_server);

    if config.default.is_none() && before.servers.is_empty() {
        config.default = Some(args.name.clone());
    }

    let changed = matches!(args.auth, AuthArg::Password) || *config != before;
    if changed
        && let Err(err) = save_config_if_unchanged(config_path, config, revision)
            .with_error_kind(ErrorKind::Config)
    {
        if !crate::storage::write_was_published(&err)
            && let Some((credential, user)) = new_password_credential.as_ref()
        {
            let _ = credentials.delete_password_for(CredentialPurpose::Login, credential, user);
        }
        return Err(err);
    }
    let mut cleanup_error = None;
    for (purpose, credential, user) in stale_credentials {
        if let Err(err) = credentials.delete_password_for(purpose, &credential, &user) {
            cleanup_error.get_or_insert(err);
        }
    }
    if let Some(err) = cleanup_error {
        return Err(credential_cleanup_error(
            err,
            action,
            &args.name,
            None,
            default_change,
        ));
    }

    let warning = if matches!(args.auth, AuthArg::Password) && !credentials.is_persistent() {
        Some("this credential backend does not persist passwords; supply SSHW_PASSWORD at run time")
    } else {
        None
    };

    if args.json {
        let mut output = json!({
            "ok": true,
            "action": action,
            "server": redact_secrets(&args.name),
            "user": redact_secrets(&config.servers[&args.name].default_user),
            "changed": changed,
            "change": if changed { action } else { "unchanged" },
        });
        if let Some(change) = default_change {
            output["default_change"] = serde_json::to_value(change.redacted())?;
        }
        if let (Some(map), Some(warning)) = (output.as_object_mut(), warning) {
            map.insert(
                "warning".to_string(),
                serde_json::Value::String(warning.to_string()),
            );
        }
        return Ok(ok(format!("{}\n", serde_json::to_string(&output)?)));
    }

    let mut message = if changed {
        format!("{action} {}\n", super::hints::redacted_argument(&args.name))
    } else {
        format!(
            "server {} (unchanged)\n",
            super::hints::redacted_argument(&args.name)
        )
    };
    if let Some(change) = default_change {
        message.push_str(&change.human_message());
    }
    if previous_server.is_none() || args.replace {
        message.push_str(&super::hints::registration_followups(
            ctx,
            global_selection,
            &args.name,
        ));
    }
    if let Some(warning) = warning {
        message.push_str(&format!("warning: {warning}\n"));
    }
    Ok(ok(message))
}

pub(super) fn list_servers(
    args: ListArgs,
    config: &SshwConfig,
    ctx: &ExecContext<'_>,
    global_selection: bool,
) -> anyhow::Result<CommandOutput> {
    let filter = args.filter.as_ref().map(|text| text.to_lowercase());
    let mut servers = server_outputs(config);
    if let Some(filter) = &filter {
        servers.retain(|server| {
            // Match the configured values, before display redaction.
            let original = &config.servers[&server.name];
            server.name.to_lowercase().contains(filter)
                || original.host.to_lowercase().contains(filter)
        });
    }
    if args.json {
        return Ok(ok(format!("{}\n", serde_json::to_string(&servers)?)));
    }

    if servers.is_empty() {
        if args.filter.is_some() && !config.servers.is_empty() {
            return Ok(ok(super::hints::no_matching_servers(ctx, global_selection)));
        }
        let (summary, guidance) = super::hints::empty_server_list(ctx, global_selection);
        return Ok(ok(format!("{summary}\n{guidance}\n")));
    }

    let mut stdout = String::new();
    for server in servers {
        let marker = if server.is_default { "*" } else { " " };
        stdout.push_str(&format!(
            "{marker} {} {}:{} user={} auth={} accounts={}\n",
            server.name,
            server.host,
            server.port,
            server.user,
            auth_label(&server.auth),
            server.account_count,
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
            map.insert(
                "accounts".to_string(),
                serde_json::to_value(
                    server
                        .accounts
                        .iter()
                        .map(|(user, account)| {
                            super::account::account_json(
                                user,
                                account,
                                user == &server.default_user,
                            )
                        })
                        .collect::<Vec<_>>(),
                )?,
            );
        }
        return Ok(ok(format!("{}\n", serde_json::to_string(&value)?)));
    }

    let mut message = format!(
        "{}\n  host: {}\n  port: {}\n  user: {}\n  auth: {}\n  default: {}\n  accounts: {}\n",
        super::hints::redacted_argument(&output.name),
        super::hints::redacted_argument(&output.host),
        output.port,
        super::hints::redacted_argument(&output.user),
        auth_label(&output.auth),
        output.is_default,
        output.account_count,
    );
    for (user, account) in &server.accounts {
        let marker = if user == &server.default_user {
            "*"
        } else {
            " "
        };
        message.push_str(&format!(
            "    {marker} {} auth={} privilege={}\n",
            super::hints::redacted_argument(user),
            super::account::auth_label(&account.auth),
            super::account::privilege_label(account),
        ));
    }
    Ok(ok(message))
}

pub(super) fn default_server(
    args: DefaultArgs,
    config_path: &Path,
    revision: &ConfigRevision,
    config: &mut SshwConfig,
) -> anyhow::Result<CommandOutput> {
    if args.clear {
        let previous = config.default.take();
        let changed = previous.is_some();
        let default_change = DefaultChange::between("server", previous, None);
        if changed {
            save_config_if_unchanged(config_path, config, revision)
                .with_error_kind(ErrorKind::Config)
                .map_err(|error| {
                    if crate::storage::write_was_published(&error) {
                        error.context("default server was cleared, but save durability could not be confirmed; inspect `sshw default` before retrying")
                    } else { error }
                })?;
        }
        if args.json {
            let mut output = json!({"ok":true,"action":"default","server":null,"changed":changed,
                "change":if changed { "cleared" } else { "unchanged" }});
            if let Some(change) = default_change {
                output["default_change"] = serde_json::to_value(change.redacted())?;
            }
            return Ok(ok(format!("{output}\n")));
        }
        return Ok(ok(format!(
            "{}; specify the server explicitly for run/put/get\n",
            if changed {
                "default server cleared"
            } else {
                "no default server configured (unchanged)"
            }
        )));
    }
    let Some(name) = args.name else {
        let name = config
            .default
            .as_ref()
            .ok_or_else(|| no_default_server_error(config))?;
        if args.json {
            return Ok(ok(format!("{}\n", json!({"ok":true,"server":name}))));
        }
        return Ok(ok(format!("{name}\n")));
    };

    if !config.servers.contains_key(&name) {
        return Err(unknown_server(&name));
    }

    let changed = config.default.as_deref() != Some(name.as_str());
    if changed {
        config.default = Some(name.clone());
        save_config_if_unchanged(config_path, config, revision)
            .with_error_kind(ErrorKind::Config)?;
    }
    if args.json {
        return Ok(ok(format!(
            "{}\n",
            json!({"ok":true,"action":"default","server":name,"changed":changed,
                "change":if changed { "updated" } else { "unchanged" }})
        )));
    }
    Ok(ok(if changed {
        format!("default set to {name}\n")
    } else {
        format!("default already set to {name} (unchanged)\n")
    }))
}

pub(super) fn trust_server<S, P>(
    args: TrustArgs,
    ssh: &S,
    prompter: &mut P,
    config: &SshwConfig,
    ctx: &ExecContext<'_>,
    global_selection: bool,
) -> anyhow::Result<CommandOutput>
where
    S: SshClient,
    P: Prompter,
{
    let server = get_server(config, &args.name)?;
    if !args.yes {
        prompter
            .ensure_confirmation_available("--yes")
            .with_error_kind(ErrorKind::Config)?;
    }
    let host_key = ssh.host_key(server).with_error_kind(ErrorKind::Ssh)?;
    let host = trust_display(&server.host);
    let endpoint = if host.contains(':') && !host.starts_with('[') {
        format!("[{host}]:{}", server.port)
    } else {
        format!("{host}:{}", server.port)
    };
    let source = if let Some(project) = &ctx.home.project {
        if project.servers == crate::project::ResourceSource::Local {
            "project local".into()
        } else {
            "inherited global".into()
        }
    } else if global_selection {
        format!("global ({})", trust_display(&ctx.home.description))
    } else {
        trust_display(&ctx.home.description)
    };
    let prompt = format!(
        "trust {} at {endpoint}\nserver settings: {source}\nconfig: {}\nknown_hosts: {}\nhost key: {} {}\napprove this host key? [y/N] ",
        trust_display(&args.name),
        trust_path(&ctx.home.config_path),
        trust_path(&ctx.home.known_hosts_path),
        trust_display(&host_key.algorithm),
        trust_display(&host_key.fingerprint_sha256)
    );
    if !args.yes
        && !prompter
            .confirm(&prompt)
            .with_error_kind(ErrorKind::Config)?
    {
        return Err(app_error(ErrorKind::Config, "trust cancelled"));
    }

    let trusted = ssh
        .trust_host(&args.name, server, &host_key.fingerprint_sha256)
        .with_error_kind(ErrorKind::Ssh)?;
    if args.json {
        let output = json!({
            "ok": true,
            "server": redact_secrets(&args.name),
            "algorithm": redact_secrets(&trusted.algorithm),
            "fingerprint_sha256": redact_secrets(&trusted.fingerprint_sha256),
        });
        return Ok(ok(format!("{}\n", serde_json::to_string(&output)?)));
    }

    Ok(ok(format!(
        "trusted {} {} {}\n",
        trust_display(&args.name),
        trust_display(&trusted.algorithm),
        trust_display(&trusted.fingerprint_sha256)
    )))
}

fn trust_path(path: &Path) -> String {
    let path = std::path::absolute(path).unwrap_or_else(|_| path.to_path_buf());
    trust_display(&path.display().to_string())
}

pub(super) fn remove_server<C, P>(
    args: RemoveArgs,
    config_path: &Path,
    policy_path: &Path,
    revision: &ConfigRevision,
    credentials: &C,
    prompter: &mut P,
    config: &mut SshwConfig,
) -> anyhow::Result<CommandOutput>
where
    C: CredentialStore,
    P: Prompter,
{
    let server = get_server(config, &args.name)?.clone();
    let explicit_default = args.switch_default.is_some() || args.clear_default;
    if explicit_default && config.default.as_deref() != Some(args.name.as_str()) {
        return Err(app_error(
            ErrorKind::Config,
            "--switch-default and --clear-default are only for removing the current default server; omit them to remove another server",
        ));
    }
    if args.clear_default && args.switch_default.is_some() {
        return Err(app_error(
            ErrorKind::Usage,
            "--switch-default conflicts with --clear-default",
        ));
    }
    if let Some(replacement) = &args.switch_default {
        if replacement == &args.name {
            return Err(app_error(
                ErrorKind::Config,
                "--switch-default must select a different registered server",
            ));
        }
        get_server(config, replacement)?;
    }
    let notice = if let Some(replacement) = &args.switch_default {
        format!(
            " and switch default server to '{}'",
            super::hints::redacted_argument(replacement)
        )
    } else if args.clear_default {
        " and clear the default server selection".into()
    } else {
        String::new()
    };
    if !args.yes
        && !prompter
            .confirm(&format!(
                "remove server '{}'{notice}? [y/N] ",
                super::hints::redacted_argument(&args.name)
            ))
            .with_error_kind(ErrorKind::Config)?
    {
        return Err(app_error(ErrorKind::Config, "removal cancelled"));
    }

    let previous_default = config.default.clone();
    let policy = super::removal_policy::RemovalPolicy::prepare(policy_path, &args.name, None)?;
    policy.verify_unchanged()?;
    config.servers.remove(&args.name);
    if config.default.as_deref() == Some(args.name.as_str()) {
        config.default = if args.clear_default {
            None
        } else {
            args.switch_default
                .or_else(|| config.servers.keys().next().cloned())
        };
    }

    let default_change = DefaultChange::between("server", previous_default, config.default.clone());
    save_config_if_unchanged(config_path, config, revision)
        .with_error_kind(ErrorKind::Config)
        .map_err(|error| policy.config_error(error, default_change.clone()))?;
    let policy_result = policy.save();
    let mut cleanup_error = None;
    for (purpose, credential, user) in stored_credentials(&server) {
        if let Err(err) = credentials.delete_password_for(purpose, &credential, &user) {
            cleanup_error.get_or_insert(err);
        }
    }
    policy.finish(policy_result, cleanup_error, default_change.clone())?;

    if args.json {
        let mut output = json!({
            "ok": true,
            "action": "removed",
            "server": redact_secrets(&args.name),
            "policy_changed": policy.rules_removed > 0,
            "policy_rules_removed": policy.rules_removed,
        });
        if let Some(change) = default_change {
            output["default_change"] = serde_json::to_value(change.redacted())?;
        }
        return Ok(ok(format!("{}\n", serde_json::to_string(&output)?)));
    }

    let mut message = format!("removed {}\n", super::hints::redacted_argument(&args.name));
    if policy.rules_removed > 0 {
        message.push_str(&format!(
            "account policy: removed {} rule(s)\n",
            policy.rules_removed
        ));
    }
    if let Some(change) = default_change {
        message.push_str(&change.human_message());
    }
    Ok(ok(message))
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

fn stored_credentials(server: &ServerConfig) -> Vec<(CredentialPurpose, String, String)> {
    let mut stored = Vec::new();
    for (user, account) in &server.accounts {
        if let AuthConfig::Password { credential } = &account.auth {
            stored.push((CredentialPurpose::Login, credential.clone(), user.clone()));
        }
        if let Some(privilege) = &account.privilege
            && let Some(credential) = &privilege.credential
        {
            stored.push((
                CredentialPurpose::Privilege,
                credential.clone(),
                privilege.user.clone(),
            ));
        }
    }
    stored
}

fn auth_label(auth: &crate::output::AuthOutput) -> &'static str {
    match auth {
        crate::output::AuthOutput::Password { .. } => "password",
        crate::output::AuthOutput::Agent => "agent",
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{PrivilegeConfig, PrivilegeMethod};
    use crate::credentials::CredentialStoreHealth;
    use crate::home::{CredentialNamespace, ResolvedHome};
    use clap::Parser;
    use std::cell::RefCell;
    use std::collections::BTreeMap;
    use std::fs;

    #[test]
    fn trust_display_masks_sensitive_values_and_escapes_terminal_controls() {
        assert_eq!(trust_display("token=marker"), "<redacted>");
        let text = trust_display("project\nknown_hosts:\t\u{1b}[31m");
        assert!(!text.chars().any(char::is_control));
        assert!(text.contains("\\n") && text.contains("\\t"));
        assert_eq!(trust_display("2001:db8::10"), "2001:db8::10");
    }

    #[test]
    fn default_clear_checks_cas_and_reports_post_publication_durability() {
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("servers.json");
        let mut config = SshwConfig {
            default: Some("web".into()),
            ..Default::default()
        };
        config.servers.insert(
            "web".into(),
            ServerConfig::single_account("192.0.2.10", 22, "deploy", AuthConfig::Agent),
        );
        crate::config::save_config(&path, &config).unwrap();
        let (mut snapshot, revision) = crate::config::load_config_with_revision(&path).unwrap();
        config.servers.get_mut("web").unwrap().port = 2222;
        crate::config::save_config(&path, &config).unwrap();
        let args = || match super::super::Cli::try_parse_from(["sshw", "default", "--clear"])
            .unwrap()
            .command
        {
            super::super::Command::Default(args) => args,
            _ => unreachable!(),
        };
        let error = default_server(args(), &path, &revision, &mut snapshot).unwrap_err();
        assert!(!crate::storage::write_was_published(&error));
        assert_eq!(crate::config::load_config(&path).unwrap(), config);
        let (mut snapshot, revision) = crate::config::load_config_with_revision(&path).unwrap();
        crate::storage::fail_next_parent_sync();
        let error = default_server(args(), &path, &revision, &mut snapshot).unwrap_err();
        assert!(crate::storage::write_was_published(&error));
        assert!(error.to_string().contains("was cleared"));
        let actual = crate::config::load_config(&path).unwrap();
        assert!(actual.default.is_none());
        assert_eq!(actual.servers, config.servers);
    }

    #[derive(Default)]
    struct RecordingStore {
        values: RefCell<BTreeMap<(String, String), String>>,
        deleted: RefCell<Vec<(String, String)>>,
    }

    impl CredentialStore for RecordingStore {
        fn set_password(&self, credential: &str, user: &str, password: &str) -> anyhow::Result<()> {
            self.values.borrow_mut().insert(
                (credential.to_string(), user.to_string()),
                password.to_string(),
            );
            Ok(())
        }

        fn get_password(&self, credential: &str, user: &str) -> anyhow::Result<String> {
            self.values
                .borrow()
                .get(&(credential.to_string(), user.to_string()))
                .cloned()
                .ok_or_else(|| anyhow::anyhow!("missing credential"))
        }

        fn delete_password(&self, credential: &str, user: &str) -> anyhow::Result<()> {
            self.deleted
                .borrow_mut()
                .push((credential.to_string(), user.to_string()));
            self.values
                .borrow_mut()
                .remove(&(credential.to_string(), user.to_string()));
            Ok(())
        }

        fn health_check(&self) -> anyhow::Result<CredentialStoreHealth> {
            Ok(CredentialStoreHealth {
                backend: "recording".to_string(),
                available: true,
                message: "ok".to_string(),
            })
        }
    }

    struct TestPrompter;

    impl Prompter for TestPrompter {
        fn confirm(&mut self, _prompt: &str) -> anyhow::Result<bool> {
            Ok(true)
        }

        fn password(&mut self, _prompt: &str) -> anyhow::Result<String> {
            Ok("NEW_PASSWORD".to_string())
        }

        fn password_stdin(&mut self) -> anyhow::Result<String> {
            Ok("NEW_STDIN_PASSWORD".to_string())
        }
    }

    fn sample_config() -> SshwConfig {
        let mut config = SshwConfig {
            default: Some("web".to_string()),
            ..SshwConfig::default()
        };
        config.servers.insert(
            "web".to_string(),
            ServerConfig::single_account(
                "192.0.2.10",
                22,
                "deploy",
                AuthConfig::Password {
                    credential: "sshw:default:web".to_string(),
                },
            ),
        );
        config
            .servers
            .get_mut("web")
            .unwrap()
            .accounts
            .get_mut("deploy")
            .unwrap()
            .privilege = Some(PrivilegeConfig {
            method: PrivilegeMethod::Sudo,
            user: "root".to_string(),
            credential: Some("sshw:default:privilege:web".to_string()),
            no_password: false,
        });
        config
    }

    #[test]
    fn remove_does_not_delete_credentials_when_config_save_fails() {
        let mut config = sample_config();
        let store = RecordingStore::default();
        let mut prompter = TestPrompter;
        let temp = tempfile::tempdir().unwrap();
        let file_parent = temp.path().join("not-a-directory");
        fs::write(&file_parent, "not a directory").unwrap();
        let config_path = file_parent.join("servers.json");

        let err = remove_server(
            RemoveArgs {
                switch_default: None,
                clear_default: false,
                name: "web".to_string(),
                yes: true,
                json: false,
            },
            &config_path,
            &temp.path().join("policy.json"),
            &ConfigRevision::missing(),
            &store,
            &mut prompter,
            &mut config,
        )
        .unwrap_err();

        assert!(err.to_string().contains("failed to save config"));
        assert!(
            store.deleted.borrow().is_empty(),
            "credentials must not be deleted before config removal is durable"
        );
    }

    #[test]
    fn add_cleans_new_password_when_config_save_fails() {
        let mut config = SshwConfig::default();
        let store = RecordingStore::default();
        let mut prompter = TestPrompter;
        let temp = tempfile::tempdir().unwrap();
        let file_parent = temp.path().join("not-a-directory");
        fs::write(&file_parent, "not a directory").unwrap();
        let config_path = file_parent.join("servers.json");
        let namespace = CredentialNamespace::profile("default");

        let err = add_server(
            AddArgs {
                name: "web".to_string(),
                host: "192.0.2.10".to_string(),
                port: 22,
                user: "deploy".to_string(),
                auth: AuthArg::Password,
                force: false,
                replace: false,
                password_stdin: false,
                json: false,
            },
            &ConfigRevision::missing(),
            &ExecContext {
                home: &ResolvedHome {
                    namespace: namespace.clone(),
                    ..ResolvedHome::from_config_path(&config_path)
                },
                registry_path: &temp.path().join("profiles.json"),
                policy_forced: false,
                audit: &crate::audit::NoopAudit,
            },
            false,
            &store,
            &mut prompter,
            &mut config,
        )
        .unwrap_err();

        assert!(err.to_string().contains("failed to save config"));
        assert!(
            store.values.borrow().is_empty(),
            "new credential must be cleaned up when config save fails"
        );
        let deleted = store.deleted.borrow();
        assert_eq!(deleted.len(), 1);
        assert_eq!(deleted[0].1, "deploy");
        assert!(namespace.account_credential_key_matches(
            crate::home::CredentialPurpose::Login,
            "web",
            "deploy",
            &deleted[0].0
        ));
        assert_ne!(deleted[0].0, namespace.legacy_credential_key("web"));
    }

    #[test]
    fn add_preserves_previous_password_when_config_save_fails() {
        let mut config = sample_config();
        let store = RecordingStore::default();
        let namespace = CredentialNamespace::profile("default");
        let previous_credential = namespace.legacy_credential_key("web");
        store.values.borrow_mut().insert(
            (previous_credential.clone(), "deploy".to_string()),
            "OLD_PASSWORD".to_string(),
        );
        let mut prompter = TestPrompter;
        let temp = tempfile::tempdir().unwrap();
        let file_parent = temp.path().join("not-a-directory");
        fs::write(&file_parent, "not a directory").unwrap();
        let config_path = file_parent.join("servers.json");

        let err = add_server(
            AddArgs {
                name: "web".to_string(),
                host: "192.0.2.20".to_string(),
                port: 22,
                user: "deploy".to_string(),
                auth: AuthArg::Password,
                force: true,
                replace: true,
                password_stdin: false,
                json: false,
            },
            &ConfigRevision::missing(),
            &ExecContext {
                home: &ResolvedHome {
                    namespace: namespace.clone(),
                    ..ResolvedHome::from_config_path(&config_path)
                },
                registry_path: &temp.path().join("profiles.json"),
                policy_forced: false,
                audit: &crate::audit::NoopAudit,
            },
            false,
            &store,
            &mut prompter,
            &mut config,
        )
        .unwrap_err();

        assert!(err.to_string().contains("failed to save config"));
        assert_eq!(
            store
                .values
                .borrow()
                .get(&(previous_credential.clone(), "deploy".to_string()))
                .map(String::as_str),
            Some("OLD_PASSWORD")
        );
        let deleted = store.deleted.borrow();
        assert_eq!(deleted.len(), 1);
        assert_ne!(deleted[0].0, previous_credential);
        assert!(namespace.account_credential_key_matches(
            crate::home::CredentialPurpose::Login,
            "web",
            "deploy",
            &deleted[0].0
        ));
    }

    #[test]
    fn add_keeps_new_password_when_config_was_published_but_parent_sync_failed() {
        let mut config = SshwConfig::default();
        let store = RecordingStore::default();
        let mut prompter = TestPrompter;
        let temp = tempfile::tempdir().unwrap();
        let config_path = temp.path().join("servers.json");
        let namespace = CredentialNamespace::profile("default");
        crate::storage::fail_next_parent_sync();

        let err = add_server(
            AddArgs {
                name: "web".to_string(),
                host: "192.0.2.10".to_string(),
                port: 22,
                user: "deploy".to_string(),
                auth: AuthArg::Password,
                force: false,
                replace: false,
                password_stdin: false,
                json: false,
            },
            &ConfigRevision::missing(),
            &ExecContext {
                home: &ResolvedHome {
                    namespace: namespace.clone(),
                    ..ResolvedHome::from_config_path(&config_path)
                },
                registry_path: &temp.path().join("profiles.json"),
                policy_forced: false,
                audit: &crate::audit::NoopAudit,
            },
            false,
            &store,
            &mut prompter,
            &mut config,
        )
        .unwrap_err();

        assert!(
            format!("{err:#}").contains("published"),
            "error was: {err:#}"
        );
        let saved = crate::config::load_config(&config_path).unwrap();
        let AuthConfig::Password { credential } = &saved.servers["web"].accounts["deploy"].auth
        else {
            panic!("published server must retain password authentication");
        };
        assert!(
            store
                .values
                .borrow()
                .contains_key(&(credential.clone(), "deploy".to_string())),
            "a published config must not point at a compensating-deleted credential"
        );
        assert!(store.deleted.borrow().is_empty());
    }
}
