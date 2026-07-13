//! Privilege escalation metadata handlers.

use super::{
    CommandOutput, PrivilegeClearArgs, PrivilegeMethodArg, PrivilegeSetArgs, PrivilegeShowArgs,
    Prompter, get_server, ok, unknown_server,
};
use crate::config::{
    ConfigRevision, PrivilegeConfig, PrivilegeMethod, SshwConfig, save_config_if_unchanged,
};
use crate::credentials::CredentialStore;
use crate::error::{ResultErrorKindExt, app_error};
use crate::home::{CredentialNamespace, CredentialPurpose, validate_server_name};
use crate::output::ErrorKind;
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
    validate_server_name(&args.name).with_error_kind(ErrorKind::Config)?;
    get_server(config, &args.name)?;
    if config.privileges.contains_key(&args.name)
        && !args.force
        && !prompter
            .confirm(&format!(
                "update privilege configuration for '{}'? [y/N] ",
                args.name
            ))
            .with_error_kind(ErrorKind::Config)?
    {
        return Err(app_error(ErrorKind::Config, "privilege update cancelled"));
    }

    let password = if args.password_stdin {
        prompter.password_stdin().with_error_kind(ErrorKind::Auth)?
    } else {
        prompter
            .password("Privilege password: ")
            .with_error_kind(ErrorKind::Auth)?
    };
    validate_privilege_password(&password)?;

    let previous_privilege = config.privileges.get(&args.name).cloned();
    let privilege = PrivilegeConfig {
        method: map_method(args.method),
        user: args.user,
        credential: namespace.new_credential_key(CredentialPurpose::Privilege, &args.name),
    };
    let output_method = privilege.method;
    let output_user = privilege.user.clone();
    let output_credential = privilege.credential.clone();
    credentials
        .set_password_for(
            CredentialPurpose::Privilege,
            &privilege.credential,
            &privilege.user,
            &password,
        )
        .with_error_kind(ErrorKind::Auth)?;
    let stored_credential = (privilege.credential.clone(), privilege.user.clone());
    config.privileges.insert(args.name.clone(), privilege);
    if let Err(err) =
        save_config_if_unchanged(config_path, config, revision).with_error_kind(ErrorKind::Config)
    {
        if !crate::storage::write_was_published(&err) {
            let _ = credentials.delete_password_for(
                CredentialPurpose::Privilege,
                &stored_credential.0,
                &stored_credential.1,
            );
        }
        return Err(err);
    }
    if let Some(previous) = previous_privilege {
        let current = config
            .privileges
            .get(&args.name)
            .expect("privilege just set");
        if previous.credential != current.credential || previous.user != current.user {
            credentials
                .delete_password_for(
                    CredentialPurpose::Privilege,
                    &previous.credential,
                    &previous.user,
                )
                .with_error_kind(ErrorKind::Auth)?;
        }
    }

    let warning = if !credentials.is_persistent() {
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
    let privilege = config
        .privileges
        .get(&args.name)
        .cloned()
        .ok_or_else(|| missing_privilege(&args.name))?;

    if !args.yes
        && !prompter
            .confirm(&format!(
                "clear privilege configuration for '{}'? [y/N] ",
                args.name
            ))
            .with_error_kind(ErrorKind::Config)?
    {
        return Err(app_error(ErrorKind::Config, "privilege clear cancelled"));
    }

    config.privileges.remove(&args.name);
    save_config_if_unchanged(config_path, config, revision).with_error_kind(ErrorKind::Config)?;
    credentials
        .delete_password_for(
            CredentialPurpose::Privilege,
            &privilege.credential,
            &privilege.user,
        )
        .with_error_kind(ErrorKind::Auth)?;
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
    app_error(
        ErrorKind::Config,
        format!(
            "privilege configuration missing for server '{server}'; run 'sshw privilege set {server} --method sudo' first"
        ),
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
            ServerConfig {
                host: "192.0.2.10".to_string(),
                port: 22,
                user: "deploy".to_string(),
                auth: AuthConfig::Password {
                    credential: "sshw:default:web".to_string(),
                },
            },
        );
        config.privileges.insert(
            "web".to_string(),
            PrivilegeConfig {
                method: PrivilegeMethod::Sudo,
                user: "root".to_string(),
                credential: "sshw:default:privilege:web".to_string(),
            },
        );
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
        config.privileges.clear();
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
                method: PrivilegeMethodArg::Sudo,
                user: "root".to_string(),
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
        assert!(
            store.values.borrow().is_empty(),
            "new privilege credential must be cleaned up when config save fails"
        );
        let deleted = store.deleted.borrow();
        assert_eq!(deleted.len(), 1);
        assert_eq!(deleted[0].1, "root");
        assert!(namespace.credential_key_matches(
            crate::home::CredentialPurpose::Privilege,
            "web",
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
                method: PrivilegeMethodArg::Su,
                user: "root".to_string(),
                password_stdin: false,
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
        assert!(namespace.credential_key_matches(
            crate::home::CredentialPurpose::Privilege,
            "web",
            &deleted[0].0
        ));
    }

    #[test]
    fn set_keeps_new_password_when_config_was_published_but_parent_sync_failed() {
        let mut config = sample_config();
        config.privileges.clear();
        let store = RecordingStore::default();
        let mut prompter = TestPrompter;
        let temp = tempfile::tempdir().unwrap();
        let config_path = temp.path().join("servers.json");
        let namespace = CredentialNamespace::profile("default");
        crate::storage::fail_next_parent_sync();

        let err = set_privilege(
            PrivilegeSetArgs {
                name: "web".to_string(),
                method: PrivilegeMethodArg::Sudo,
                user: "root".to_string(),
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

        assert!(
            format!("{err:#}").contains("published"),
            "error was: {err:#}"
        );
        let saved = crate::config::load_config(&config_path).unwrap();
        let privilege = &saved.privileges["web"];
        assert!(
            store
                .values
                .borrow()
                .contains_key(&(privilege.credential.clone(), "root".to_string())),
            "a published privilege config must retain its credential"
        );
        assert!(store.deleted.borrow().is_empty());
    }
}
