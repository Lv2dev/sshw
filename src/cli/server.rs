//! Server management subcommand handlers.
//!
//! These operate on the per-home `SshwConfig`: add/list/show/default/trust/remove.

use super::{
    AddArgs, AuthArg, CommandOutput, DefaultArgs, ListArgs, Prompter, RemoveArgs, ShowArgs,
    TrustArgs, get_server, no_default_server_error, ok, unknown_server,
};
use crate::config::{
    AccountConfig, AuthConfig, ConfigRevision, ServerConfig, SshwConfig, save_config_if_unchanged,
    validate_account_user,
};
use crate::credentials::CredentialStore;
use crate::error::{ResultErrorKindExt, app_error};
use crate::home::{CredentialNamespace, CredentialPurpose, validate_server_name};
use crate::output::{ErrorKind, ServerOutput};
use crate::ssh::SshClient;
use serde_json::json;
use std::collections::BTreeMap;
use std::path::Path;

pub(super) fn add_server<C, P>(
    args: AddArgs,
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

    let previous_server = config.servers.get(&args.name).cloned();
    if previous_server.is_some()
        && !args.force
        && !prompter
            .confirm(&format!("update existing server '{}'? [y/N] ", args.name))
            .with_error_kind(ErrorKind::Config)?
    {
        return Err(app_error(ErrorKind::Config, "add cancelled"));
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
            new_password_credential = Some((credential.clone(), args.user.clone()));
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

    let mut accounts = BTreeMap::new();
    accounts.insert(
        args.user.clone(),
        AccountConfig {
            auth,
            privilege: None,
        },
    );
    let new_server = ServerConfig {
        host: args.host,
        port: args.port,
        default_user: args.user,
        accounts,
    };
    let stale_credentials = previous_server
        .as_ref()
        .map(stored_credentials)
        .unwrap_or_default();
    config.servers.insert(args.name.clone(), new_server);

    if config.default.is_none() {
        config.default = Some(args.name.clone());
    }

    if let Err(err) =
        save_config_if_unchanged(config_path, config, revision).with_error_kind(ErrorKind::Config)
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
        return Err(crate::error::classified_error(ErrorKind::Auth, err));
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
        }
        return Ok(ok(format!("{}\n", serde_json::to_string(&value)?)));
    }

    Ok(ok(format!(
        "{}\n  host: {}\n  port: {}\n  user: {}\n  auth: {}\n  accounts: {}\n",
        output.name,
        output.host,
        output.port,
        output.user,
        auth_label(&output.auth),
        output.account_count,
    )))
}

pub(super) fn default_server(
    args: DefaultArgs,
    config_path: &Path,
    revision: &ConfigRevision,
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
    save_config_if_unchanged(config_path, config, revision).with_error_kind(ErrorKind::Config)?;
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
    let host_key = ssh.host_key(server).with_error_kind(ErrorKind::Ssh)?;
    let prompt = format!(
        "trust {} {} {}? [y/N] ",
        args.name, host_key.algorithm, host_key.fingerprint_sha256
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
    if !args.yes
        && !prompter
            .confirm(&format!("remove server '{}'? [y/N] ", args.name))
            .with_error_kind(ErrorKind::Config)?
    {
        return Err(app_error(ErrorKind::Config, "removal cancelled"));
    }

    config.servers.remove(&args.name);
    if config.default.as_deref() == Some(args.name.as_str()) {
        config.default = config.servers.keys().next().cloned();
    }

    save_config_if_unchanged(config_path, config, revision).with_error_kind(ErrorKind::Config)?;
    let mut cleanup_error = None;
    for (purpose, credential, user) in stored_credentials(&server) {
        if let Err(err) = credentials.delete_password_for(purpose, &credential, &user) {
            cleanup_error.get_or_insert(err);
        }
    }
    if let Some(err) = cleanup_error {
        return Err(crate::error::classified_error(ErrorKind::Auth, err));
    }

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

fn stored_credentials(server: &ServerConfig) -> Vec<(CredentialPurpose, String, String)> {
    let mut stored = Vec::new();
    for (user, account) in &server.accounts {
        if let AuthConfig::Password { credential } = &account.auth {
            stored.push((CredentialPurpose::Login, credential.clone(), user.clone()));
        }
        if let Some(privilege) = &account.privilege {
            stored.push((
                CredentialPurpose::Privilege,
                privilege.credential.clone(),
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
            credential: "sshw:default:privilege:web".to_string(),
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
                name: "web".to_string(),
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
                password_stdin: false,
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
                password_stdin: false,
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
                password_stdin: false,
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
