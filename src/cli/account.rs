//! Login account management for configured server endpoints.

use super::{
    AccountAddArgs, AccountDefaultArgs, AccountListArgs, AccountRemoveArgs, AccountShowArgs,
    AuthArg, CommandOutput, Prompter, get_server, ok,
};
use crate::config::{
    AccountConfig, AuthConfig, ConfigRevision, PrivilegeMethod, SshwConfig,
    save_config_if_unchanged, validate_account_user,
};
use crate::credentials::CredentialStore;
use crate::error::{ResultErrorKindExt, app_error, classified_error};
use crate::home::{CredentialNamespace, CredentialPurpose, validate_server_name};
use crate::output::ErrorKind;
use serde_json::{Value, json};
use std::path::Path;

pub(super) fn add_account<C, P>(
    args: AccountAddArgs,
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
    validate_server_name(&args.name).with_error_kind(ErrorKind::Config)?;
    validate_account_user(&args.user).with_error_kind(ErrorKind::Config)?;
    let previous = get_server(config, &args.name)?.account(&args.user).cloned();
    if previous.is_some()
        && !args.force
        && !prompter
            .confirm(&format!(
                "update account '{}/{}'? [y/N] ",
                args.name, args.user
            ))
            .with_error_kind(ErrorKind::Config)?
    {
        return Err(app_error(ErrorKind::Config, "account update cancelled"));
    }

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
                    .password("SSH password: ")
                    .with_error_kind(ErrorKind::Auth)?
            };
            if password.is_empty() {
                return Err(app_error(ErrorKind::Auth, "password cannot be empty"));
            }
            credentials
                .set_password_for(CredentialPurpose::Login, &credential, &args.user, &password)
                .with_error_kind(ErrorKind::Auth)?;
            new_password_credential = Some(credential.clone());
            AuthConfig::Password { credential }
        }
        AuthArg::Agent => {
            if args.password_stdin {
                return Err(app_error(
                    ErrorKind::Config,
                    "--password-stdin cannot be used with --auth agent",
                ));
            }
            AuthConfig::Agent
        }
    };

    let account = AccountConfig {
        auth,
        privilege: previous
            .as_ref()
            .and_then(|account| account.privilege.clone()),
    };
    config
        .servers
        .get_mut(&args.name)
        .expect("server validated above")
        .accounts
        .insert(args.user.clone(), account);

    if let Err(err) =
        save_config_if_unchanged(config_path, config, revision).with_error_kind(ErrorKind::Config)
    {
        if !crate::storage::write_was_published(&err)
            && let Some(credential) = new_password_credential.as_ref()
        {
            let _ =
                credentials.delete_password_for(CredentialPurpose::Login, credential, &args.user);
        }
        return Err(err);
    }

    if let Some(AuthConfig::Password { credential }) =
        previous.as_ref().map(|account| &account.auth)
    {
        let current = &config.servers[&args.name].accounts[&args.user].auth;
        if !matches!(current, AuthConfig::Password { credential: current } if current == credential)
        {
            credentials
                .delete_password_for(CredentialPurpose::Login, credential, &args.user)
                .with_error_kind(ErrorKind::Auth)?;
        }
    }

    let action = if previous.is_some() {
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
            "user": args.user,
        });
        if let (Some(map), Some(warning)) = (output.as_object_mut(), warning) {
            map.insert("warning".to_string(), Value::String(warning.to_string()));
        }
        return Ok(ok(format!("{}\n", serde_json::to_string(&output)?)));
    }

    let mut message = format!("account {action} {}/{}\n", args.name, args.user);
    if let Some(warning) = warning {
        message.push_str(&format!("warning: {warning}\n"));
    }
    Ok(ok(message))
}

pub(super) fn list_accounts(
    args: AccountListArgs,
    config: &SshwConfig,
) -> anyhow::Result<CommandOutput> {
    let server = get_server(config, &args.name)?;
    let accounts: Vec<Value> = server
        .accounts
        .iter()
        .map(|(user, account)| account_json(user, account, user == &server.default_user))
        .collect();
    if args.json {
        return Ok(ok(format!("{}\n", serde_json::to_string(&accounts)?)));
    }

    let mut output = String::new();
    for (user, account) in &server.accounts {
        let marker = if user == &server.default_user {
            "*"
        } else {
            " "
        };
        output.push_str(&format!(
            "{marker} {user} auth={} privilege={}\n",
            auth_label(&account.auth),
            privilege_label(account),
        ));
    }
    Ok(ok(output))
}

pub(super) fn show_account(
    args: AccountShowArgs,
    config: &SshwConfig,
) -> anyhow::Result<CommandOutput> {
    let server = get_server(config, &args.name)?;
    let account = server
        .account(&args.user)
        .ok_or_else(|| unknown_account(&args.name, &args.user))?;
    if args.json {
        let mut output = account_json(&args.user, account, args.user == server.default_user);
        output
            .as_object_mut()
            .expect("account JSON is an object")
            .insert("ok".to_string(), Value::Bool(true));
        output
            .as_object_mut()
            .expect("account JSON is an object")
            .insert("server".to_string(), Value::String(args.name));
        return Ok(ok(format!("{}\n", serde_json::to_string(&output)?)));
    }

    Ok(ok(format!(
        "{}/{}\n  default: {}\n  auth: {}\n  privilege: {}\n",
        args.name,
        args.user,
        args.user == server.default_user,
        auth_label(&account.auth),
        privilege_label(account),
    )))
}

pub(super) fn default_account(
    args: AccountDefaultArgs,
    config_path: &Path,
    revision: &ConfigRevision,
    config: &mut SshwConfig,
) -> anyhow::Result<CommandOutput> {
    let server = config
        .servers
        .get_mut(&args.name)
        .ok_or_else(|| super::unknown_server(&args.name))?;
    if !server.accounts.contains_key(&args.user) {
        return Err(unknown_account(&args.name, &args.user));
    }
    server.default_user = args.user.clone();
    save_config_if_unchanged(config_path, config, revision).with_error_kind(ErrorKind::Config)?;
    Ok(ok(format!(
        "default account for {} set to {}\n",
        args.name, args.user
    )))
}

pub(super) fn remove_account<C, P>(
    args: AccountRemoveArgs,
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
    let server = get_server(config, &args.name)?;
    if server.default_user == args.user {
        return Err(app_error(
            ErrorKind::Config,
            format!(
                "cannot remove default account '{}/{}'; set another default account first",
                args.name, args.user
            ),
        ));
    }
    let account = server
        .account(&args.user)
        .cloned()
        .ok_or_else(|| unknown_account(&args.name, &args.user))?;
    if !args.yes
        && !prompter
            .confirm(&format!(
                "remove account '{}/{}'? [y/N] ",
                args.name, args.user
            ))
            .with_error_kind(ErrorKind::Config)?
    {
        return Err(app_error(ErrorKind::Config, "account removal cancelled"));
    }

    config
        .servers
        .get_mut(&args.name)
        .expect("server validated above")
        .accounts
        .remove(&args.user);
    save_config_if_unchanged(config_path, config, revision).with_error_kind(ErrorKind::Config)?;

    let mut cleanup_error = None;
    if let AuthConfig::Password { credential } = &account.auth
        && let Err(err) =
            credentials.delete_password_for(CredentialPurpose::Login, credential, &args.user)
    {
        cleanup_error = Some(err);
    }
    if let Some(privilege) = &account.privilege
        && let Err(err) = credentials.delete_password_for(
            CredentialPurpose::Privilege,
            &privilege.credential,
            &privilege.user,
        )
    {
        cleanup_error.get_or_insert(err);
    }
    if let Some(err) = cleanup_error {
        return Err(classified_error(ErrorKind::Auth, err));
    }

    if args.json {
        let output = json!({
            "ok": true,
            "action": "removed",
            "server": args.name,
            "user": args.user,
        });
        return Ok(ok(format!("{}\n", serde_json::to_string(&output)?)));
    }
    Ok(ok(format!("account removed {}/{}\n", args.name, args.user)))
}

fn account_json(user: &str, account: &AccountConfig, is_default: bool) -> Value {
    let auth = match &account.auth {
        AuthConfig::Password { credential } => json!({
            "type": "password",
            "credential": credential,
        }),
        AuthConfig::Agent => json!({ "type": "agent" }),
    };
    let privilege = account.privilege.as_ref().map(|privilege| {
        json!({
            "method": privilege.method,
            "user": privilege.user,
            "credential": privilege.credential,
        })
    });
    json!({
        "user": user,
        "is_default": is_default,
        "auth": auth,
        "privilege": privilege,
    })
}

fn auth_label(auth: &AuthConfig) -> &'static str {
    match auth {
        AuthConfig::Password { .. } => "password",
        AuthConfig::Agent => "agent",
    }
}

fn privilege_label(account: &AccountConfig) -> &'static str {
    match account.privilege.as_ref().map(|privilege| privilege.method) {
        Some(PrivilegeMethod::Sudo) => "sudo",
        Some(PrivilegeMethod::Su) => "su",
        None => "none",
    }
}

pub(super) fn unknown_account(server: &str, user: &str) -> anyhow::Error {
    app_error(
        ErrorKind::Config,
        format!("unknown account '{server}/{user}'"),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::ServerConfig;
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
            ServerConfig::single_account("192.0.2.10", 22, "deploy", AuthConfig::Agent),
        );
        config
    }

    #[test]
    fn add_cleans_new_password_when_config_save_fails() {
        let mut config = sample_config();
        let store = RecordingStore::default();
        let mut prompter = TestPrompter;
        let temp = tempfile::tempdir().unwrap();
        let file_parent = temp.path().join("not-a-directory");
        fs::write(&file_parent, "not a directory").unwrap();
        let config_path = file_parent.join("servers.json");
        let namespace = CredentialNamespace::profile("default");

        let err = add_account(
            AccountAddArgs {
                name: "web".to_string(),
                user: "ops".to_string(),
                auth: AuthArg::Password,
                password_stdin: false,
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
        assert!(store.values.borrow().is_empty());
        let deleted = store.deleted.borrow();
        assert_eq!(deleted.len(), 1);
        assert_eq!(deleted[0].1, "ops");
        assert!(namespace.account_credential_key_matches(
            CredentialPurpose::Login,
            "web",
            "ops",
            &deleted[0].0,
        ));
    }

    #[test]
    fn remove_does_not_delete_credentials_when_config_save_fails() {
        let mut config = sample_config();
        let namespace = CredentialNamespace::profile("default");
        let credential =
            namespace.credential_key_v3(CredentialPurpose::Login, "web", "ops", "0000000000000001");
        config.servers.get_mut("web").unwrap().accounts.insert(
            "ops".to_string(),
            AccountConfig {
                auth: AuthConfig::Password {
                    credential: credential.clone(),
                },
                privilege: None,
            },
        );
        let store = RecordingStore::default();
        store
            .values
            .borrow_mut()
            .insert((credential, "ops".to_string()), "OLD_PASSWORD".to_string());
        let mut prompter = TestPrompter;
        let temp = tempfile::tempdir().unwrap();
        let file_parent = temp.path().join("not-a-directory");
        fs::write(&file_parent, "not a directory").unwrap();
        let config_path = file_parent.join("servers.json");

        let err = remove_account(
            AccountRemoveArgs {
                name: "web".to_string(),
                user: "ops".to_string(),
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
        assert!(store.deleted.borrow().is_empty());
    }

    #[test]
    fn add_keeps_new_password_when_config_was_published_but_parent_sync_failed() {
        let mut config = sample_config();
        let store = RecordingStore::default();
        let mut prompter = TestPrompter;
        let temp = tempfile::tempdir().unwrap();
        let config_path = temp.path().join("servers.json");
        let namespace = CredentialNamespace::profile("default");
        crate::storage::fail_next_parent_sync();

        let err = add_account(
            AccountAddArgs {
                name: "web".to_string(),
                user: "ops".to_string(),
                auth: AuthArg::Password,
                password_stdin: false,
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

        assert!(format!("{err:#}").contains("published"));
        let saved = crate::config::load_config(&config_path).unwrap();
        let AuthConfig::Password { credential } = &saved.servers["web"].accounts["ops"].auth else {
            panic!("published account must retain password auth");
        };
        assert!(
            store
                .values
                .borrow()
                .contains_key(&(credential.clone(), "ops".to_string()))
        );
        assert!(store.deleted.borrow().is_empty());
    }
}
