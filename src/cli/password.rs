//! Rotate an existing login or privilege password, preserving its other settings.

use super::{CommandOutput, PasswordArgs, Prompter, get_server, ok, select_account};
use crate::config::{AuthConfig, ConfigRevision, SshwConfig, save_config_if_unchanged};
use crate::credentials::CredentialStore;
use crate::error::{
    ResultErrorKindExt, app_error, credential_cleanup_error, redacted_error_detail,
    saved_mutation_error,
};
use crate::home::{CredentialPurpose, ResolvedHome};
use crate::output::{ConfigMutationOutput, ErrorKind};
use serde_json::json;
use zeroize::Zeroizing;

pub(super) fn update_password<C: CredentialStore, P: Prompter>(
    args: PasswordArgs,
    home: &ResolvedHome,
    revision: &ConfigRevision,
    credentials: &C,
    prompter: &mut P,
    config: &SshwConfig,
) -> anyhow::Result<CommandOutput> {
    let server = get_server(config, &args.name)?;
    let (user, account) = select_account(&args.name, server, args.user.as_deref())?;
    let (purpose, previous, backend_user) = if args.privilege {
        let privilege = account
            .privilege
            .as_ref()
            .ok_or_else(|| super::privilege::missing_privilege(&args.name, user))?;
        if privilege.no_password {
            return Err(app_error(
                ErrorKind::Config,
                "this account uses passwordless privilege escalation; use privilege set to explicitly change to password-based sudo or su before updating its password",
            ));
        }
        let previous = privilege.credential.as_deref().ok_or_else(|| {
            app_error(ErrorKind::Config, "the privilege configuration has no password reference; inspect privilege show and repair it with privilege set")
        })?;
        (
            CredentialPurpose::Privilege,
            previous,
            privilege.user.as_str(),
        )
    } else {
        let AuthConfig::Password { credential } = &account.auth else {
            return Err(app_error(
                ErrorKind::Config,
                "this account uses SSH-agent authentication; password only updates existing password accounts. Use account add --auth password to explicitly change its authentication method",
            ));
        };
        (CredentialPurpose::Login, credential.as_str(), user)
    };
    let purpose_label = if args.privilege { "privilege" } else { "login" };
    let action = if args.privilege {
        "privilege_password_updated"
    } else {
        "password_updated"
    };
    let password = Zeroizing::new(if args.password_stdin {
        prompter.password_stdin().with_error_kind(ErrorKind::Auth)?
    } else {
        let prompt = if args.privilege {
            let privilege = account.privilege.as_ref().expect("validated privilege");
            super::prompt::privilege_password_prompt(
                &args.name,
                user,
                privilege.method,
                &privilege.user,
            )
        } else {
            super::prompt::login_password_prompt(&args.name, user)
        };
        prompter
            .password(&prompt)
            .with_error_kind(ErrorKind::Auth)?
    });
    if password.is_empty() {
        return Err(app_error(ErrorKind::Auth, "password cannot be empty"));
    }
    if args.privilege {
        super::privilege::validate_privilege_password(&password)?;
    }
    let new = home
        .namespace
        .new_account_credential_key(purpose, &args.name, user);
    let mut next = config.clone();
    let updated_account = next
        .servers
        .get_mut(&args.name)
        .expect("validated server")
        .accounts
        .get_mut(user)
        .expect("validated account");
    if args.privilege {
        updated_account
            .privilege
            .as_mut()
            .expect("validated privilege")
            .credential = Some(new.clone());
    } else {
        updated_account.auth = AuthConfig::Password {
            credential: new.clone(),
        };
    }
    let prepared = credentials
        .set_password_for(purpose, &new, backend_user, &password)
        .with_error_kind(ErrorKind::Auth)
        .and_then(|()| {
            save_config_if_unchanged(&home.config_path, &next, revision)
                .with_error_kind(ErrorKind::Config)
        });
    if let Err(error) = prepared {
        if crate::storage::write_was_published(&error) {
            return Err(saved_mutation_error(ErrorKind::Config,
                error.context(format!("the updated {purpose_label} password reference was published but durability confirmation failed; inspect the account using the same home/profile before retrying; both credential generations were retained")),
                ConfigMutationOutput { config_applied: true, failed_stage: "config_save", action, server: args.name, account: Some(user.into()), default_change: None }));
        }
        return Err(
            match delete_if_present(credentials, purpose, &new, backend_user) {
                Ok(()) => error,
                Err(cleanup) => error.context(format!(
                    "password update was not applied; temporary credential cleanup also failed: {}",
                    redacted_error_detail(&cleanup)
                )),
            },
        );
    }
    delete_if_present(credentials, purpose, previous, backend_user)
        .map_err(|error| credential_cleanup_error(error, action, &args.name, Some(user), None))?;
    let warning = (!credentials.is_persistent()).then_some(if args.privilege {
        "this credential backend does not persist passwords; supply SSHW_PRIVILEGE_PASSWORD at run time"
    } else {
        "this credential backend does not persist passwords; supply SSHW_PASSWORD at run time"
    });
    let name = super::hints::redacted_argument(&args.name);
    let user = super::hints::redacted_argument(user);
    if args.json {
        let mut value = json!({"ok":true,"action":action,"purpose":purpose_label,"server":name,"user":user,"changed":true,"change":"updated"});
        if args.privilege {
            value["target_user"] = super::hints::redacted_argument(backend_user).into();
        }
        if let Some(warning) = warning {
            value["warning"] = warning.into();
        }
        return Ok(ok(format!("{value}\n")));
    }
    let target = if args.privilege {
        format!(
            " (target '{}')",
            super::hints::redacted_argument(backend_user)
        )
    } else {
        String::new()
    };
    let mut message =
        format!("saved {purpose_label} password updated for '{name}/{user}'{target}\n");
    if let Some(warning) = warning {
        message.push_str(&format!("warning: {warning}\n"));
    }
    Ok(ok(message))
}

fn delete_if_present<C: CredentialStore>(
    store: &C,
    purpose: CredentialPurpose,
    key: &str,
    user: &str,
) -> anyhow::Result<()> {
    match store.delete_password_for(purpose, key, user) {
        Err(error)
            if error.chain().any(|cause| {
                matches!(
                    cause.downcast_ref::<keyring_core::Error>(),
                    Some(keyring_core::Error::NoEntry)
                )
            }) =>
        {
            Ok(())
        }
        result => result,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{
        AccountConfig, PrivilegeConfig, PrivilegeMethod, ServerConfig, load_config,
        load_config_with_revision, save_config,
    };
    use crate::credentials::CredentialStoreHealth;
    use crate::output::ErrorResponse;
    use std::cell::{Cell, RefCell};
    use std::collections::BTreeMap;

    #[derive(Default)]
    struct Store {
        values: RefCell<BTreeMap<(String, String), String>>,
        fail_set: Cell<bool>,
        fail_delete: Cell<bool>,
        set_hook: RefCell<Option<Box<dyn FnOnce()>>>,
    }
    impl CredentialStore for Store {
        fn get_password(&self, _: &str, _: &str) -> anyhow::Result<String> {
            panic!("password rotation must not read old secrets")
        }
        fn set_password(&self, key: &str, user: &str, value: &str) -> anyhow::Result<()> {
            self.values
                .borrow_mut()
                .insert((key.into(), user.into()), value.into());
            if let Some(hook) = self.set_hook.borrow_mut().take() {
                hook();
            }
            if self.fail_set.get() {
                anyhow::bail!("backend failed after storing token=set-marker");
            }
            Ok(())
        }
        fn delete_password(&self, key: &str, user: &str) -> anyhow::Result<()> {
            if self.fail_delete.get() {
                anyhow::bail!("delete failed token=delete-marker");
            }
            self.values
                .borrow_mut()
                .remove(&(key.into(), user.into()))
                .map(|_| ())
                .ok_or_else(|| keyring_core::Error::NoEntry.into())
        }
        fn health_check(&self) -> anyhow::Result<CredentialStoreHealth> {
            unreachable!()
        }
        fn is_persistent(&self) -> bool {
            false
        }
    }
    struct Prompt {
        calls: usize,
        value: String,
    }
    impl Prompter for Prompt {
        fn confirm(&mut self, _: &str) -> anyhow::Result<bool> {
            panic!("explicit password update must not ask to confirm")
        }
        fn password(&mut self, _: &str) -> anyhow::Result<String> {
            self.calls += 1;
            Ok(self.value.clone())
        }
        fn password_stdin(&mut self) -> anyhow::Result<String> {
            self.calls += 1;
            Ok(self.value.clone())
        }
    }
    fn fixture(home: &ResolvedHome, store: &Store) -> SshwConfig {
        let login =
            home.namespace
                .new_account_credential_key(CredentialPurpose::Login, "web", "deploy");
        let privilege = home.namespace.new_account_credential_key(
            CredentialPurpose::Privilege,
            "web",
            "deploy",
        );
        store
            .values
            .borrow_mut()
            .insert((login.clone(), "deploy".into()), "old-login".into());
        store.values.borrow_mut().insert(
            (privilege.clone(), "root".into()),
            "privilege-fixture".into(),
        );
        let mut server = ServerConfig::single_account(
            "192.0.2.10",
            2222,
            "deploy",
            AuthConfig::Password { credential: login },
        );
        server.accounts.get_mut("deploy").unwrap().privilege = Some(PrivilegeConfig {
            method: PrivilegeMethod::Su,
            user: "root".into(),
            credential: Some(privilege),
            no_password: false,
        });
        server
            .accounts
            .insert("ops".into(), server.accounts["deploy"].clone());
        let ops = home
            .namespace
            .new_account_credential_key(CredentialPurpose::Login, "web", "ops");
        store
            .values
            .borrow_mut()
            .insert((ops.clone(), "ops".into()), "ops-fixture".into());
        server.accounts.get_mut("ops").unwrap().auth = AuthConfig::Password { credential: ops };
        server.accounts.get_mut("ops").unwrap().privilege = None;
        server.accounts.insert(
            "agent".into(),
            AccountConfig {
                auth: AuthConfig::Agent,
                privilege: None,
            },
        );
        let config = SshwConfig {
            default: Some("web".into()),
            servers: BTreeMap::from([("web".into(), server)]),
            ..Default::default()
        };
        save_config(&home.config_path, &config).unwrap();
        std::fs::write(&home.known_hosts_path, "unchanged approval").unwrap();
        std::fs::write(&home.policy_path, "unchanged policy bytes").unwrap();
        config
    }
    fn args(user: Option<&str>, stdin: bool) -> PasswordArgs {
        PasswordArgs {
            name: "web".into(),
            user: user.map(str::to_owned),
            privilege: false,
            password_stdin: stdin,
            json: true,
        }
    }

    #[test]
    fn privilege_password_preserves_method_target_login_and_profile_namespace() {
        for (method, user, target, agent) in [
            (PrivilegeMethod::Sudo, "deploy", "root", false),
            (PrivilegeMethod::Su, "ops", "service", true),
        ] {
            let temp = tempfile::tempdir().unwrap();
            let home = ResolvedHome::profile(temp.path().into(), "p_privilege", "fixture".into());
            let store = Store::default();
            let mut config = fixture(&home, &store);
            let previous = home.namespace.new_account_credential_key(
                CredentialPurpose::Privilege,
                "web",
                user,
            );
            store
                .values
                .borrow_mut()
                .insert((previous.clone(), target.into()), "old-privilege".into());
            let account = config
                .servers
                .get_mut("web")
                .unwrap()
                .accounts
                .get_mut(user)
                .unwrap();
            account.privilege = Some(PrivilegeConfig {
                method,
                user: target.into(),
                credential: Some(previous.clone()),
                no_password: false,
            });
            if agent {
                account.auth = AuthConfig::Agent;
            }
            save_config(&home.config_path, &config).unwrap();
            let (_, revision) = load_config_with_revision(&home.config_path).unwrap();
            let mut expected_values = store.values.borrow().clone();
            let mut input = Prompt {
                calls: 0,
                value: "new-privilege-fixture".into(),
            };
            let mut request = args(Some(user), agent);
            request.privilege = true;
            let output =
                update_password(request, &home, &revision, &store, &mut input, &config).unwrap();
            let saved = load_config(&home.config_path).unwrap();
            let new = saved.servers["web"].accounts[user]
                .privilege
                .as_ref()
                .unwrap()
                .credential
                .as_ref()
                .unwrap();
            assert!(home.namespace.account_credential_key_matches(
                CredentialPurpose::Privilege,
                "web",
                user,
                new
            ));
            expected_values.remove(&(previous, target.into()));
            expected_values.insert((new.clone(), target.into()), "new-privilege-fixture".into());
            assert_eq!(*store.values.borrow(), expected_values);
            config
                .servers
                .get_mut("web")
                .unwrap()
                .accounts
                .get_mut(user)
                .unwrap()
                .privilege
                .as_mut()
                .unwrap()
                .credential = Some(new.clone());
            assert_eq!(saved, config);
            assert_eq!(input.calls, 1);
            let result: serde_json::Value = serde_json::from_str(&output.stdout).unwrap();
            assert_eq!(result["action"], "privilege_password_updated");
            assert_eq!(result["purpose"], "privilege");
            assert_eq!(result["user"], user);
            assert_eq!(result["target_user"], target);
            assert!(
                result["warning"]
                    .as_str()
                    .unwrap()
                    .contains("SSHW_PRIVILEGE_PASSWORD")
            );
            assert!(!output.stdout.contains("new-privilege-fixture"));
            assert_eq!(
                std::fs::read_to_string(&home.known_hosts_path).unwrap(),
                "unchanged approval"
            );
            assert_eq!(
                std::fs::read_to_string(&home.policy_path).unwrap(),
                "unchanged policy bytes"
            );
        }
    }

    #[test]
    fn privilege_password_rejects_unconfigured_passwordless_and_multiline_input_without_mutation() {
        for (user, passwordless, input, calls) in [
            ("ops", false, "fixture", 0),
            ("agent", false, "fixture", 0),
            ("deploy", true, "fixture", 0),
            ("deploy", false, "first\nsecond", 1),
            ("deploy", false, "first\rsecond", 1),
            ("deploy", false, "", 1),
        ] {
            let temp = tempfile::tempdir().unwrap();
            let home = ResolvedHome::ad_hoc(temp.path(), "fixture".into());
            let store = Store::default();
            let mut config = fixture(&home, &store);
            if passwordless {
                let privilege = config
                    .servers
                    .get_mut("web")
                    .unwrap()
                    .accounts
                    .get_mut("deploy")
                    .unwrap()
                    .privilege
                    .as_mut()
                    .unwrap();
                privilege.method = PrivilegeMethod::Sudo;
                privilege.no_password = true;
                privilege.credential = None;
                save_config(&home.config_path, &config).unwrap();
            }
            let before = std::fs::read(&home.config_path).unwrap();
            let values = store.values.borrow().clone();
            let (_, revision) = load_config_with_revision(&home.config_path).unwrap();
            let mut prompt = Prompt {
                calls: 0,
                value: input.into(),
            };
            let mut request = args(Some(user), true);
            request.privilege = true;
            let error = update_password(request, &home, &revision, &store, &mut prompt, &config)
                .unwrap_err();
            assert_eq!(
                ErrorResponse::from_error(&error).error.kind,
                if calls == 0 {
                    ErrorKind::Config
                } else {
                    ErrorKind::Auth
                }
            );
            assert_eq!(prompt.calls, calls);
            assert_eq!(std::fs::read(&home.config_path).unwrap(), before);
            assert_eq!(*store.values.borrow(), values);
        }
    }

    #[test]
    fn privilege_password_failure_paths_keep_login_secret_and_report_correct_applied_action() {
        for failure in ["set", "revision", "cleanup", "published", "missing"] {
            let temp = tempfile::tempdir().unwrap();
            let home = ResolvedHome::ad_hoc(temp.path(), "fixture".into());
            let store = Store::default();
            let config = fixture(&home, &store);
            let privilege = config.servers["web"].accounts["deploy"]
                .privilege
                .as_ref()
                .unwrap();
            let old = privilege.credential.as_ref().unwrap();
            let AuthConfig::Password { credential: login } =
                &config.servers["web"].accounts["deploy"].auth
            else {
                panic!()
            };
            let login_value = store.values.borrow()[&(login.clone(), "deploy".into())].clone();
            let mut before = std::fs::read(&home.config_path).unwrap();
            let (_, revision) = load_config_with_revision(&home.config_path).unwrap();
            match failure {
                "set" => store.fail_set.set(true),
                "cleanup" => store.fail_delete.set(true),
                "published" => crate::storage::fail_next_parent_sync(),
                "missing" => {
                    store
                        .values
                        .borrow_mut()
                        .remove(&(old.clone(), "root".into()));
                }
                "revision" => {
                    before.push(b'\n');
                    let path = home.config_path.clone();
                    let contents = before.clone();
                    *store.set_hook.borrow_mut() =
                        Some(Box::new(move || std::fs::write(path, contents).unwrap()));
                }
                _ => unreachable!(),
            }
            let values = store.values.borrow().clone();
            let mut request = args(None, false);
            request.privilege = true;
            let mut prompt = Prompt {
                calls: 0,
                value: "new-privilege-fixture".into(),
            };
            let result = update_password(request, &home, &revision, &store, &mut prompt, &config);
            let applied = matches!(failure, "cleanup" | "published" | "missing");
            if failure == "missing" {
                result.unwrap();
            } else {
                let response = ErrorResponse::from_error(&result.unwrap_err());
                assert_eq!(
                    response.error.kind,
                    if matches!(failure, "revision" | "published") {
                        ErrorKind::Config
                    } else {
                        ErrorKind::Auth
                    }
                );
                assert!(
                    !serde_json::to_string(&response)
                        .unwrap()
                        .contains("set-marker")
                );
                if applied {
                    let mutation = response.mutation.unwrap();
                    assert!(mutation.config_applied);
                    assert_eq!(mutation.action, "privilege_password_updated");
                    assert_eq!(mutation.account.as_deref(), Some("deploy"));
                    assert_eq!(
                        mutation.failed_stage,
                        if failure == "cleanup" {
                            "credential_cleanup"
                        } else {
                            "config_save"
                        }
                    );
                } else {
                    assert!(response.mutation.is_none());
                }
            }
            assert_eq!(
                store.values.borrow()[&(login.clone(), "deploy".into())],
                login_value
            );
            if applied {
                let saved = load_config(&home.config_path).unwrap();
                let new = saved.servers["web"].accounts["deploy"]
                    .privilege
                    .as_ref()
                    .unwrap()
                    .credential
                    .as_ref()
                    .unwrap();
                assert_eq!(
                    store.values.borrow()[&(new.clone(), "root".into())],
                    "new-privilege-fixture"
                );
                assert_eq!(
                    store
                        .values
                        .borrow()
                        .contains_key(&(old.clone(), "root".into())),
                    failure != "missing"
                );
            } else {
                assert_eq!(std::fs::read(&home.config_path).unwrap(), before);
                assert_eq!(*store.values.borrow(), values);
            }
        }
    }

    #[test]
    fn password_rotates_only_selected_login_preserving_privilege_default_and_namespace() {
        for user in [None, Some("ops")] {
            let temp = tempfile::tempdir().unwrap();
            let home = ResolvedHome::profile(temp.path().into(), "p_password", "fixture".into());
            let store = Store::default();
            let config = fixture(&home, &store);
            let (_, revision) = load_config_with_revision(&home.config_path).unwrap();
            let mut prompt = Prompt {
                calls: 0,
                value: "new-login-fixture".into(),
            };
            let output = update_password(
                args(user, user.is_some()),
                &home,
                &revision,
                &store,
                &mut prompt,
                &config,
            )
            .unwrap();
            assert_eq!(prompt.calls, 1);
            let saved = load_config(&home.config_path).unwrap();
            let target = user.unwrap_or("deploy");
            let AuthConfig::Password { credential: key } =
                &saved.servers["web"].accounts[target].auth
            else {
                panic!()
            };
            assert!(home.namespace.account_credential_key_matches(
                CredentialPurpose::Login,
                "web",
                target,
                key
            ));
            assert_eq!(
                store.values.borrow()[&(key.clone(), target.into())],
                "new-login-fixture"
            );
            let mut expected = config.clone();
            expected
                .servers
                .get_mut("web")
                .unwrap()
                .accounts
                .get_mut(target)
                .unwrap()
                .auth = saved.servers["web"].accounts[target].auth.clone();
            assert_eq!(saved, expected);
            assert_eq!(store.values.borrow().len(), 3);
            assert_eq!(
                std::fs::read_to_string(&home.known_hosts_path).unwrap(),
                "unchanged approval"
            );
            assert_eq!(
                std::fs::read_to_string(&home.policy_path).unwrap(),
                "unchanged policy bytes"
            );
            assert!(!output.stdout.contains("new-login-fixture"));
        }
    }

    #[test]
    fn password_validates_before_input_and_empty_input_never_changes_state() {
        for (name, user, password, calls) in [
            ("missing", None, "fixture", 0),
            ("web", Some("missing"), "fixture", 0),
            ("web", Some("agent"), "fixture", 0),
            ("web", None, "", 1),
        ] {
            let temp = tempfile::tempdir().unwrap();
            let home = ResolvedHome::ad_hoc(temp.path(), "fixture".into());
            let store = Store::default();
            let config = fixture(&home, &store);
            let values = store.values.borrow().clone();
            let before = std::fs::read(&home.config_path).unwrap();
            let (_, revision) = load_config_with_revision(&home.config_path).unwrap();
            let mut prompt = Prompt {
                calls: 0,
                value: password.into(),
            };
            let mut args = args(user, false);
            args.name = name.into();
            let error =
                update_password(args, &home, &revision, &store, &mut prompt, &config).unwrap_err();
            assert_eq!(
                ErrorResponse::from_error(&error).error.kind,
                if calls == 0 {
                    ErrorKind::Config
                } else {
                    ErrorKind::Auth
                }
            );
            assert_eq!(prompt.calls, calls);
            assert_eq!(std::fs::read(&home.config_path).unwrap(), before);
            assert_eq!(*store.values.borrow(), values);
        }
    }

    #[test]
    fn password_rolls_back_even_a_partially_stored_secret_and_preserves_external_revision() {
        for failure in ["set", "revision"] {
            let temp = tempfile::tempdir().unwrap();
            let home = ResolvedHome::ad_hoc(temp.path(), "fixture".into());
            let store = Store::default();
            let config = fixture(&home, &store);
            let values = store.values.borrow().clone();
            let mut before = std::fs::read(&home.config_path).unwrap();
            let (_, revision) = load_config_with_revision(&home.config_path).unwrap();
            if failure == "set" {
                store.fail_set.set(true);
            } else {
                before.push(b'\n');
                let contents = before.clone();
                let path = home.config_path.clone();
                *store.set_hook.borrow_mut() =
                    Some(Box::new(move || std::fs::write(path, contents).unwrap()));
            }
            let mut prompt = Prompt {
                calls: 0,
                value: "new-login-fixture".into(),
            };
            let error = update_password(
                args(None, false),
                &home,
                &revision,
                &store,
                &mut prompt,
                &config,
            )
            .unwrap_err();
            let response = ErrorResponse::from_error(&error);
            assert!(response.mutation.is_none());
            assert_eq!(
                response.error.kind,
                if failure == "set" {
                    ErrorKind::Auth
                } else {
                    ErrorKind::Config
                }
            );
            assert_eq!(std::fs::read(&home.config_path).unwrap(), before);
            assert_eq!(*store.values.borrow(), values);
            assert!(
                !serde_json::to_string(&response)
                    .unwrap()
                    .contains("set-marker")
            );
        }
    }

    #[test]
    fn password_recovers_a_missing_old_secret_and_reports_obsolete_cleanup_failure() {
        for fail_cleanup in [false, true] {
            let temp = tempfile::tempdir().unwrap();
            let home = ResolvedHome::ad_hoc(temp.path(), "fixture".into());
            let store = Store::default();
            let config = fixture(&home, &store);
            let AuthConfig::Password { credential: old } =
                &config.servers["web"].accounts["deploy"].auth
            else {
                panic!()
            };
            if !fail_cleanup {
                store
                    .values
                    .borrow_mut()
                    .remove(&(old.clone(), "deploy".into()));
            }
            store.fail_delete.set(fail_cleanup);
            let (_, revision) = load_config_with_revision(&home.config_path).unwrap();
            let mut prompt = Prompt {
                calls: 0,
                value: "new-login-fixture".into(),
            };
            let result = update_password(
                args(None, false),
                &home,
                &revision,
                &store,
                &mut prompt,
                &config,
            );
            if fail_cleanup {
                let response = ErrorResponse::from_error(&result.unwrap_err());
                assert_eq!(response.error.kind, ErrorKind::Auth);
                let mutation = response.mutation.unwrap();
                assert!(mutation.config_applied);
                assert_eq!(mutation.failed_stage, "credential_cleanup");
                assert_eq!(mutation.account.as_deref(), Some("deploy"));
            } else {
                result.unwrap();
            }
            let saved = load_config(&home.config_path).unwrap();
            let AuthConfig::Password { credential: new } =
                &saved.servers["web"].accounts["deploy"].auth
            else {
                panic!()
            };
            assert_eq!(
                store.values.borrow()[&(new.clone(), "deploy".into())],
                "new-login-fixture"
            );
        }
    }

    #[test]
    fn password_retains_both_generations_after_publication_durability_failure() {
        let temp = tempfile::tempdir().unwrap();
        let home = ResolvedHome::ad_hoc(temp.path(), "fixture".into());
        let store = Store::default();
        let config = fixture(&home, &store);
        let (_, revision) = load_config_with_revision(&home.config_path).unwrap();
        let mut prompt = Prompt {
            calls: 0,
            value: "new-login-fixture".into(),
        };
        crate::storage::fail_next_parent_sync();
        let error = update_password(
            args(None, false),
            &home,
            &revision,
            &store,
            &mut prompt,
            &config,
        )
        .unwrap_err();
        let response = ErrorResponse::from_error(&error);
        assert_eq!(response.error.kind, ErrorKind::Config);
        let mutation = response.mutation.unwrap();
        assert!(mutation.config_applied);
        assert_eq!(mutation.failed_stage, "config_save");
        assert_eq!(mutation.action, "password_updated");
        assert_eq!(store.values.borrow().len(), 4);
        assert_ne!(load_config(&home.config_path).unwrap(), config);
    }
}
