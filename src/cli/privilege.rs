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
    let stored_credential = (privilege.credential.clone(), privilege.user.clone());
    let overwrote_previous = previous_privilege.as_ref().is_some_and(|previous| {
        previous.credential == stored_credential.0 && previous.user == stored_credential.1
    });
    config.privileges.insert(args.name.clone(), privilege);
    if let Err(err) = save_config(config_path, config) {
        if !overwrote_previous {
            let _ = credentials.delete_password(&stored_credential.0, &stored_credential.1);
        }
        return Err(err);
    }
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

    config.privileges.remove(&args.name);
    save_config(config_path, config)?;
    credentials.delete_password(&privilege.credential, &privilege.user)?;
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
        assert_eq!(
            store.deleted.borrow().as_slice(),
            [("sshw:default:privilege:web".to_string(), "root".to_string())]
        );
    }
}
