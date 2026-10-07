//! Privilege escalation metadata handlers.

use super::{
    CommandOutput, PrivilegeClearArgs, PrivilegeMethodArg, PrivilegeSetArgs, PrivilegeShowArgs,
    Prompter, get_server, ok, unknown_server,
};
use crate::config::{
    ConfigRevision, PrivilegeConfig, PrivilegeMethod, SshwConfig, save_config_if_unchanged,
    validate_account_user,
};
use crate::credentials::CredentialStore;
use crate::error::{ResultErrorKindExt, app_error, credential_cleanup_error};
use crate::home::{CredentialNamespace, CredentialPurpose, validate_server_name};
use crate::output::ErrorKind;
use anyhow::Context;
use serde_json::json;
use std::path::Path;

pub(super) fn set_privilege<C, P>(
    args: PrivilegeSetArgs,
    config_path: &Path,
    revision: &ConfigRevision,
    namespace: &CredentialNamespace,
    credentials: &C,
    prompter: &mut P,
    config: &mut SshwConfig,
) -> anyhow::Result<CommandOutput>
where
    C: CredentialStore,
    P: Prompter,
{
    if args.no_password && (args.password_stdin || matches!(args.method, PrivilegeMethodArg::Su)) {
        return Err(app_error(
            ErrorKind::Usage,
            "--no-password requires sudo and cannot be combined with --password-stdin",
        ));
    }
    validate_server_name(&args.name).with_error_kind(ErrorKind::Config)?;
    validate_account_user(&args.user)
        .context("invalid privilege target user")
        .with_error_kind(ErrorKind::Config)?;
    let server = get_server(config, &args.name)?;
    let login_user = args
        .account
        .clone()
        .unwrap_or_else(|| server.default_user.clone());
    if server.account(&login_user).is_none() {
        return Err(super::account::unknown_account(&args.name, &login_user));
    }
    let previous_privilege = get_server(config, &args.name)?
        .account(&login_user)
        .and_then(|account| account.privilege.clone());
    if let Some(previous) = &previous_privilege
        && !args.force
        && !prompter
            .confirm_with_option(
                &format!(
                    "update privilege configuration for '{}/{}' ({} target: {} -> {} target: {}; authentication: {} -> {})? [y/N] ",
                    args.name, login_user, method_label(previous.method), previous.user,
                    method_label(map_method(args.method)), args.user,
                    authentication_label(previous.no_password), authentication_label(args.no_password)
                ),
                "--force",
            )
            .with_error_kind(ErrorKind::Config)?
    {
        return Err(app_error(ErrorKind::Config, "privilege update cancelled"));
    }

    let before = config.clone();
    let privilege = PrivilegeConfig {
        method: map_method(args.method),
        user: args.user,
        credential: (!args.no_password).then(|| {
            namespace.new_account_credential_key(
                CredentialPurpose::Privilege,
                &args.name,
                &login_user,
            )
        }),
        no_password: args.no_password,
    };
    let output_method = privilege.method;
    let output_user = privilege.user.clone();
    let output_credential = privilege.credential.clone();
    let stored_credential = if let Some(credential) = &privilege.credential {
        let password = zeroize::Zeroizing::new(if args.password_stdin {
            prompter.password_stdin().with_error_kind(ErrorKind::Auth)?
        } else {
            prompter
                .password("Privilege password: ")
                .with_error_kind(ErrorKind::Auth)?
        });
        validate_privilege_password(&password)?;
        credentials
            .set_password_for(
                CredentialPurpose::Privilege,
                credential,
                &privilege.user,
                &password,
            )
            .with_error_kind(ErrorKind::Auth)?;
        Some((credential.clone(), privilege.user.clone()))
    } else {
        None
    };
    config
        .servers
        .get_mut(&args.name)
        .and_then(|server| server.accounts.get_mut(&login_user))
        .expect("validated default account")
        .privilege = Some(privilege);
    let changed = !args.no_password || *config != before;
    let change = if !changed {
        "unchanged"
    } else if previous_privilege.is_some() {
        "updated"
    } else {
        "added"
    };
    if changed
        && let Err(err) = save_config_if_unchanged(config_path, config, revision)
            .with_error_kind(ErrorKind::Config)
    {
        if !crate::storage::write_was_published(&err)
            && let Some((credential, user)) = &stored_credential
        {
            let _ = credentials.delete_password_for(CredentialPurpose::Privilege, credential, user);
        }
        return Err(err);
    }
    if let Some(previous) = previous_privilege {
        let current = config
            .servers
            .get(&args.name)
            .and_then(|server| server.account(&login_user))
            .and_then(|account| account.privilege.as_ref())
            .expect("privilege just set");
        if (previous.credential != current.credential || previous.user != current.user)
            && let Some(credential) = &previous.credential
        {
            credentials
                .delete_password_for(CredentialPurpose::Privilege, credential, &previous.user)
                .map_err(|err| {
                    credential_cleanup_error(err, "set", &args.name, Some(&login_user), None)
                })?;
        }
    }

    let warning = if !args.no_password && !credentials.is_persistent() {
        Some(
            "this credential backend does not persist privilege passwords; supply SSHW_PRIVILEGE_PASSWORD at run time",
        )
    } else {
        None
    };

    if args.json {
        let mut output = json!({
            "ok": true,
            "server": args.name,
            "account": login_user,
            "method": output_method,
            "user": output_user,
            "credential": output_credential,
            "no_password": args.no_password,
            "changed": changed,
            "change": change,
        });
        if let (Some(map), Some(warning)) = (output.as_object_mut(), warning) {
            map.insert(
                "warning".to_string(),
                serde_json::Value::String(warning.to_string()),
            );
        }
        return Ok(ok(format!("{}\n", serde_json::to_string(&output)?)));
    }

    let mut message = format!(
        "privilege set for {}/{}{}\n  login account: {}\n  method: {}\n  target user: {}\n  authentication: {}\n",
        args.name,
        login_user,
        if changed { "" } else { " (unchanged)" },
        login_user,
        method_label(output_method),
        output_user,
        authentication_label(args.no_password)
    );
    if let Some(warning) = warning {
        message.push_str(&format!("warning: {warning}\n"));
    }
    Ok(ok(message))
}

pub(super) fn show_privilege(
    args: PrivilegeShowArgs,
    config: &SshwConfig,
) -> anyhow::Result<CommandOutput> {
    let server = get_server(config, &args.name)?;
    let login_user = args.account.as_deref().unwrap_or(&server.default_user);
    let account = server
        .account(login_user)
        .ok_or_else(|| super::account::unknown_account(&args.name, login_user))?;
    let privilege = account
        .privilege
        .as_ref()
        .ok_or_else(|| missing_privilege(&args.name, login_user))?;

    if args.json {
        let output = json!({
            "ok": true,
            "server": args.name,
            "account": login_user,
            "method": privilege.method,
            "user": privilege.user,
            "credential": privilege.credential,
            "no_password": privilege.no_password,
        });
        return Ok(ok(format!("{}\n", serde_json::to_string(&output)?)));
    }

    Ok(ok(format!(
        "{}/{}\n  login account: {}\n  method: {}\n  target user: {}\n  authentication: {}\n  credential: {}\n",
        args.name,
        login_user,
        login_user,
        method_label(privilege.method),
        privilege.user,
        authentication_label(privilege.no_password),
        privilege.credential.as_deref().unwrap_or("none")
    )))
}

pub(super) fn clear_privilege<C, P>(
    args: PrivilegeClearArgs,
    config_path: &Path,
    revision: &ConfigRevision,
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
    let login_user = args
        .account
        .clone()
        .unwrap_or_else(|| config.servers[&args.name].default_user.clone());
    let account = config.servers[&args.name]
        .account(&login_user)
        .ok_or_else(|| super::account::unknown_account(&args.name, &login_user))?;
    let Some(privilege) = account.privilege.clone() else {
        if args.json {
            return Ok(ok(format!(
                "{}\n",
                json!({"ok":true,"action":"cleared","server":args.name,"account":login_user,
                "changed":false,"change":"unchanged"})
            )));
        }
        return Ok(ok(format!(
            "privilege already cleared for {}/{} (unchanged)\n",
            args.name, login_user
        )));
    };

    if !args.yes
        && !prompter
            .confirm(&format!(
                "clear privilege configuration for '{}/{}' ({} target: {}; authentication: {})? [y/N] ",
                args.name, login_user, method_label(privilege.method), privilege.user,
                authentication_label(privilege.no_password)
            ))
            .with_error_kind(ErrorKind::Config)?
    {
        return Err(app_error(ErrorKind::Config, "privilege clear cancelled"));
    }

    config
        .servers
        .get_mut(&args.name)
        .and_then(|server| server.accounts.get_mut(&login_user))
        .expect("validated default account")
        .privilege = None;
    save_config_if_unchanged(config_path, config, revision).with_error_kind(ErrorKind::Config)?;
    if let Some(credential) = &privilege.credential {
        credentials
            .delete_password_for(CredentialPurpose::Privilege, credential, &privilege.user)
            .map_err(|err| {
                credential_cleanup_error(err, "cleared", &args.name, Some(&login_user), None)
            })?;
    }
    if args.json {
        let output = json!({
            "ok": true,
            "action": "cleared",
            "server": args.name,
            "account": login_user,
            "changed": true,
            "change": "removed",
        });
        return Ok(ok(format!("{}\n", serde_json::to_string(&output)?)));
    }

    Ok(ok(format!(
        "privilege cleared for {}/{} ({} target: {})\n",
        args.name,
        login_user,
        method_label(privilege.method),
        privilege.user
    )))
}

fn authentication_label(no_password: bool) -> &'static str {
    if no_password {
        "no password (sudo -n)"
    } else {
        "password"
    }
}

pub(super) fn missing_privilege(server: &str, login_user: &str) -> anyhow::Error {
    let command = super::hints::privilege_set(server, login_user, PrivilegeMethod::Sudo, None);
    app_error(
        ErrorKind::Config,
        format!(
            "privilege configuration missing for account '{server}/{login_user}'\nusing the same home/profile selection, run `{command}` first"
        ),
    )
}

pub(super) fn method_label(method: PrivilegeMethod) -> &'static str {
    match method {
        PrivilegeMethod::Sudo => "sudo",
        PrivilegeMethod::Su => "su",
    }
}

pub(super) fn recovery_step(
    server: &str,
    login_user: &str,
    privilege: &PrivilegeConfig,
    persistent: bool,
) -> String {
    let method = method_label(privilege.method);
    if !persistent {
        return format!(
            "supply SSHW_PRIVILEGE_PASSWORD at run time for login account {} ({method} target {}); session-only passwords are not persisted. Keep the same home/profile selection and never put the password in arguments",
            super::hints::quote_local_argument(login_user),
            super::hints::quote_local_argument(&privilege.user)
        );
    }
    let command =
        super::hints::privilege_set(server, login_user, privilege.method, Some(&privilege.user));
    format!(
        "using the same home/profile selection, run `{command}` to register the privilege password again; confirm the update, or insert --force and --password-stdin before -- for non-interactive secret-manager input"
    )
}

pub(super) fn validate_privilege_password(password: &str) -> anyhow::Result<()> {
    if password.is_empty() {
        return Err(app_error(ErrorKind::Auth, "password cannot be empty"));
    }
    if password.contains(['\n', '\r']) {
        return Err(app_error(
            ErrorKind::Auth,
            "privilege password must be a single line",
        ));
    }
    Ok(())
}

fn map_method(method: PrivilegeMethodArg) -> PrivilegeMethod {
    match method {
        PrivilegeMethodArg::Sudo => PrivilegeMethod::Sudo,
        PrivilegeMethodArg::Su => PrivilegeMethod::Su,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{AuthConfig, ServerConfig};
    use crate::credentials::CredentialStoreHealth;
    use std::cell::RefCell;
    use std::collections::BTreeMap;
    use std::fs;

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
    fn clear_does_not_delete_password_when_config_save_fails() {
        let mut config = sample_config();
        let store = RecordingStore::default();
        let mut prompter = TestPrompter;
        let temp = tempfile::tempdir().unwrap();
        let file_parent = temp.path().join("not-a-directory");
        fs::write(&file_parent, "not a directory").unwrap();
        let config_path = file_parent.join("servers.json");

        let err = clear_privilege(
            PrivilegeClearArgs {
                name: "web".to_string(),
                account: None,
                yes: true,
                json: false,
            },
            &config_path,
            &ConfigRevision::missing(),
            &store,
            &mut prompter,
            &mut config,
        )
        .unwrap_err();

        assert!(err.to_string().contains("failed to save config"));
        assert!(
            store.deleted.borrow().is_empty(),
            "privilege password must not be deleted before config removal is durable"
        );
    }

    #[test]
    fn set_cleans_new_password_when_config_save_fails() {
        let mut config = sample_config();
        config
            .servers
            .get_mut("web")
            .unwrap()
            .accounts
            .get_mut("deploy")
            .unwrap()
            .privilege = None;
        let store = RecordingStore::default();
        let mut prompter = TestPrompter;
        let temp = tempfile::tempdir().unwrap();
        let file_parent = temp.path().join("not-a-directory");
        fs::write(&file_parent, "not a directory").unwrap();
        let config_path = file_parent.join("servers.json");
        let namespace = CredentialNamespace::profile("default");

        let err = set_privilege(
            PrivilegeSetArgs {
                name: "web".to_string(),
                account: None,
                method: PrivilegeMethodArg::Sudo,
                user: "root".to_string(),
                password_stdin: false,
                no_password: false,
                force: false,
                json: false,
            },
            &config_path,
            &ConfigRevision::missing(),
            &namespace,
            &store,
            &mut prompter,
            &mut config,
        )
        .unwrap_err();

        assert!(err.to_string().contains("failed to save config"));
        assert!(
            store.values.borrow().is_empty(),
            "new privilege credential must be cleaned up when config save fails"
        );
        let deleted = store.deleted.borrow();
        assert_eq!(deleted.len(), 1);
        assert_eq!(deleted[0].1, "root");
        assert!(namespace.account_credential_key_matches(
            crate::home::CredentialPurpose::Privilege,
            "web",
            "deploy",
            &deleted[0].0
        ));
        assert_ne!(
            deleted[0].0,
            namespace.legacy_privilege_credential_key("web")
        );
    }

    #[test]
    fn set_preserves_previous_password_when_config_save_fails() {
        let mut config = sample_config();
        let store = RecordingStore::default();
        let namespace = CredentialNamespace::profile("default");
        let previous_credential = namespace.legacy_privilege_credential_key("web");
        store.values.borrow_mut().insert(
            (previous_credential.clone(), "root".to_string()),
            "OLD_PASSWORD".to_string(),
        );
        let mut prompter = TestPrompter;
        let temp = tempfile::tempdir().unwrap();
        let file_parent = temp.path().join("not-a-directory");
        fs::write(&file_parent, "not a directory").unwrap();
        let config_path = file_parent.join("servers.json");

        let err = set_privilege(
            PrivilegeSetArgs {
                name: "web".to_string(),
                account: None,
                method: PrivilegeMethodArg::Su,
                user: "root".to_string(),
                password_stdin: false,
                no_password: false,
                force: true,
                json: false,
            },
            &config_path,
            &ConfigRevision::missing(),
            &namespace,
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
                .get(&(previous_credential.clone(), "root".to_string()))
                .map(String::as_str),
            Some("OLD_PASSWORD")
        );
        let deleted = store.deleted.borrow();
        assert_eq!(deleted.len(), 1);
        assert_ne!(deleted[0].0, previous_credential);
        assert!(namespace.account_credential_key_matches(
            crate::home::CredentialPurpose::Privilege,
            "web",
            "deploy",
            &deleted[0].0
        ));
    }

    #[test]
    fn set_keeps_new_password_when_config_was_published_but_parent_sync_failed() {
        let mut config = sample_config();
        config
            .servers
            .get_mut("web")
            .unwrap()
            .accounts
            .get_mut("deploy")
            .unwrap()
            .privilege = None;
        let store = RecordingStore::default();
        let mut prompter = TestPrompter;
        let temp = tempfile::tempdir().unwrap();
        let config_path = temp.path().join("servers.json");
        let namespace = CredentialNamespace::profile("default");
        crate::storage::fail_next_parent_sync();

        let err = set_privilege(
            PrivilegeSetArgs {
                name: "web".to_string(),
                account: None,
                method: PrivilegeMethodArg::Sudo,
                user: "root".to_string(),
                password_stdin: false,
                no_password: false,
                force: false,
                json: false,
            },
            &config_path,
            &ConfigRevision::missing(),
            &namespace,
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
        let privilege = saved.servers["web"].accounts["deploy"]
            .privilege
            .as_ref()
            .unwrap();
        assert!(
            store.values.borrow().contains_key(&(
                privilege.credential.as_ref().unwrap().clone(),
                "root".to_string()
            )),
            "a published privilege config must retain its credential"
        );
        assert!(store.deleted.borrow().is_empty());
    }

    #[test]
    fn passwordless_transition_keeps_previous_secret_on_save_errors() {
        for published in [false, true] {
            let mut config = sample_config();
            let store = RecordingStore::default();
            let old = config.servers["web"].accounts["deploy"]
                .privilege
                .as_ref()
                .unwrap()
                .credential
                .clone()
                .unwrap();
            store
                .set_password(&old, "root", "OLD_FIXTURE_PASSWORD")
                .unwrap();
            let temp = tempfile::tempdir().unwrap();
            let path = temp.path().join("servers.json");
            crate::config::save_config(&path, &config).unwrap();
            let (_, revision) = crate::config::load_config_with_revision(&path).unwrap();
            let revision = if published {
                crate::storage::fail_next_parent_sync();
                revision
            } else {
                ConfigRevision::missing() // stale revision: no write may occur
            };
            let error = set_privilege(
                PrivilegeSetArgs {
                    name: "web".into(),
                    account: None,
                    method: PrivilegeMethodArg::Sudo,
                    user: "service".into(),
                    password_stdin: false,
                    no_password: true,
                    force: true,
                    json: false,
                },
                &path,
                &revision,
                &CredentialNamespace::profile("default"),
                &store,
                &mut TestPrompter,
                &mut config,
            )
            .unwrap_err();
            assert_eq!(crate::storage::write_was_published(&error), published);
            let persisted = crate::config::load_config(&path).unwrap();
            assert_eq!(
                persisted.servers["web"].accounts["deploy"]
                    .privilege
                    .as_ref()
                    .unwrap()
                    .no_password,
                published
            );
            assert_eq!(store.values.borrow().len(), 1);
            assert!(store.values.borrow().contains_key(&(old, "root".into())));
            assert!(
                store.deleted.borrow().is_empty(),
                "cleanup requires a successful config save"
            );
        }
    }
}
