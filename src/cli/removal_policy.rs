//! Remove only account grants tied to an explicitly removed server/account.

use crate::error::{
    ResultErrorKindExt, app_error, credential_cleanup_error, redacted_error_detail,
    saved_mutation_error,
};
use crate::output::{ConfigMutationOutput, DefaultChange, ErrorKind};
use crate::policy::{PolicyFile, load_policy_with_revision, save_policy_if_unchanged};
use std::path::{Path, PathBuf};

pub(super) struct RemovalPolicy {
    path: PathBuf,
    file: Option<PolicyFile>,
    revision: Option<String>,
    server: String,
    account: Option<String>,
    pub rules_removed: usize,
}

impl RemovalPolicy {
    pub fn prepare(path: &Path, server: &str, account: Option<&str>) -> anyhow::Result<Self> {
        let (mut file, revision) =
            load_policy_with_revision(path).with_error_kind(ErrorKind::Policy)?;
        let mut rules_removed = 0;
        if let Some(file) = file.as_mut() {
            let before = file.allow_accounts.len();
            file.allow_accounts.retain(|rule| {
                rule.server != server || account.is_some_and(|user| rule.user != user)
            });
            rules_removed = before - file.allow_accounts.len();
        }
        Ok(Self {
            path: path.into(),
            file,
            revision,
            server: server.into(),
            account: account.map(str::to_owned),
            rules_removed,
        })
    }

    pub fn verify_unchanged(&self) -> anyhow::Result<()> {
        let (_, revision) =
            load_policy_with_revision(&self.path).with_error_kind(ErrorKind::Policy)?;
        if revision != self.revision {
            return Err(app_error(
                ErrorKind::Policy,
                "policy file changed concurrently; inspect it and retry the removal",
            ));
        }
        Ok(())
    }

    pub fn save(&self) -> anyhow::Result<()> {
        if self.rules_removed == 0 {
            return Ok(());
        }
        save_policy_if_unchanged(
            &self.path,
            self.file.as_ref().expect("changed policy exists"),
            &self.revision,
        )
        .with_error_kind(ErrorKind::Policy)
    }

    pub fn config_error(
        &self,
        error: anyhow::Error,
        default_change: Option<DefaultChange>,
    ) -> anyhow::Error {
        if crate::storage::write_was_published(&error) {
            saved_mutation_error(ErrorKind::Config,
                error.context("the removal was published but durability confirmation failed; credentials and policy were retained. Inspect the saved configuration and policy using the same home/profile before retrying or reusing the removed name"),
                self.mutation("config_save", default_change))
        } else {
            error
        }
    }

    pub fn finish(
        &self,
        policy_result: anyhow::Result<()>,
        cleanup_error: Option<anyhow::Error>,
        default_change: Option<DefaultChange>,
    ) -> anyhow::Result<()> {
        if let Err(error) = policy_result {
            let mut error = error.context("the removal is already applied; inspect sshw policy show using the same home/profile and remove any remaining allow_accounts entries for the removed server/account before reusing that name; repeating remove cannot clean up entries for an absent target");
            if let Some(cleanup) = cleanup_error {
                error = error.context(format!(
                    "obsolete credential cleanup also failed: {}",
                    redacted_error_detail(&cleanup)
                ));
            }
            return Err(saved_mutation_error(
                ErrorKind::Policy,
                error,
                self.mutation("policy_update", default_change),
            ));
        }
        if let Some(error) = cleanup_error {
            return Err(credential_cleanup_error(
                error,
                "removed",
                &self.server,
                self.account.as_deref(),
                default_change,
            ));
        }
        Ok(())
    }

    fn mutation(
        &self,
        stage: &'static str,
        default_change: Option<DefaultChange>,
    ) -> ConfigMutationOutput {
        ConfigMutationOutput {
            config_applied: true,
            failed_stage: stage,
            action: "removed",
            server: self.server.clone(),
            account: self.account.clone(),
            default_change,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cli::{AccountRemoveArgs, Prompter, RemoveArgs, account, server};
    use crate::config::{
        AuthConfig, PrivilegeConfig, PrivilegeMethod, ServerConfig, SshwConfig, load_config,
        load_config_with_revision, save_config,
    };
    use crate::credentials::{
        CredentialStore, CredentialStoreHealth, session_store::SessionOnlyStore,
    };
    use crate::home::{CredentialPurpose, ResolvedHome};
    use crate::output::ErrorResponse;
    use std::cell::Cell;
    use std::collections::BTreeMap;
    use std::fs;

    #[derive(Default)]
    struct Store {
        inner: SessionOnlyStore,
        fail_delete: Cell<bool>,
        deletes: Cell<usize>,
    }
    impl CredentialStore for Store {
        fn get_password(&self, _: &str, _: &str) -> anyhow::Result<String> {
            panic!("removal must not read secrets")
        }
        fn set_password(&self, _: &str, _: &str, _: &str) -> anyhow::Result<()> {
            panic!("removal must not store secrets")
        }
        fn delete_password(&self, _: &str, _: &str) -> anyhow::Result<()> {
            unreachable!()
        }
        fn delete_password_for(
            &self,
            purpose: CredentialPurpose,
            key: &str,
            user: &str,
        ) -> anyhow::Result<()> {
            self.deletes.set(self.deletes.get() + 1);
            if self.fail_delete.get() {
                anyhow::bail!("cleanup failed token=cleanup-marker");
            }
            self.inner.delete_password_for(purpose, key, user)
        }
        fn health_check(&self) -> anyhow::Result<CredentialStoreHealth> {
            unreachable!()
        }
    }
    struct Prompt(bool);
    impl Prompter for Prompt {
        fn confirm(&mut self, _: &str) -> anyhow::Result<bool> {
            Ok(self.0)
        }
        fn password(&mut self, _: &str) -> anyhow::Result<String> {
            panic!("no password input")
        }
        fn password_stdin(&mut self) -> anyhow::Result<String> {
            panic!("no stdin input")
        }
    }
    fn fixture(home: &ResolvedHome, store: &Store) -> SshwConfig {
        let login =
            home.namespace
                .new_account_credential_key(CredentialPurpose::Login, "web", "ops");
        let privilege =
            home.namespace
                .new_account_credential_key(CredentialPurpose::Privilege, "web", "ops");
        store
            .inner
            .set_password_for(CredentialPurpose::Login, &login, "ops", "fixture-login")
            .unwrap();
        store
            .inner
            .set_password_for(
                CredentialPurpose::Privilege,
                &privilege,
                "root",
                "fixture-privilege",
            )
            .unwrap();
        let mut web = ServerConfig::single_account("192.0.2.10", 22, "deploy", AuthConfig::Agent);
        web.accounts.insert(
            "ops".into(),
            crate::config::AccountConfig {
                auth: AuthConfig::Password { credential: login },
                privilege: Some(PrivilegeConfig {
                    method: PrivilegeMethod::Su,
                    user: "root".into(),
                    credential: Some(privilege),
                    no_password: false,
                }),
            },
        );
        let config = SshwConfig {
            default: Some("web".into()),
            servers: BTreeMap::from([
                ("web".into(), web),
                (
                    "other".into(),
                    ServerConfig::single_account("192.0.2.11", 22, "deploy", AuthConfig::Agent),
                ),
            ]),
            ..Default::default()
        };
        save_config(&home.config_path, &config).unwrap();
        fs::write(&home.policy_path,r#"{"version":2,"enabled":true,"allow_commands":["id"],"allow_put_paths":["/srv"],"allow_get_paths":["/var/log"],"allow_accounts":[{"server":"web","user":"ops"},{"server":"web","user":"ops"},{"server":"web","user":"deploy"},{"server":"web","user":"ghost"},{"server":"other","user":"ops"}]}"#).unwrap();
        config
    }
    fn remove(
        home: &ResolvedHome,
        store: &Store,
        account_scope: bool,
        config: &mut SshwConfig,
        revision: &crate::config::ConfigRevision,
    ) -> anyhow::Result<crate::cli::CommandOutput> {
        if account_scope {
            account::remove_account(
                AccountRemoveArgs {
                    switch_default: None,
                    name: "web".into(),
                    user: "ops".into(),
                    yes: true,
                    json: true,
                },
                &home.config_path,
                &home.policy_path,
                revision,
                store,
                &mut Prompt(true),
                config,
            )
        } else {
            server::remove_server(
                RemoveArgs {
                    switch_default: None,
                    clear_default: false,
                    name: "web".into(),
                    yes: true,
                    json: true,
                },
                &home.config_path,
                &home.policy_path,
                revision,
                store,
                &mut Prompt(true),
                config,
            )
        }
    }

    #[test]
    fn removal_cleans_only_matching_grants_in_enabled_and_disabled_policies() {
        for account_scope in [false, true] {
            for enabled in [false, true] {
                let temp = tempfile::tempdir().unwrap();
                let home = ResolvedHome::ad_hoc(temp.path(), "fixture".into());
                let store = Store::default();
                let mut config = fixture(&home, &store);
                let (file, _) = load_policy_with_revision(&home.policy_path).unwrap();
                let mut expected = file.unwrap();
                expected.enabled = enabled;
                fs::write(&home.policy_path, serde_json::to_string(&expected).unwrap()).unwrap();
                expected
                    .allow_accounts
                    .retain(|r| r.server != "web" || account_scope && r.user != "ops");
                let (_, revision) = load_config_with_revision(&home.config_path).unwrap();
                let output = remove(&home, &store, account_scope, &mut config, &revision).unwrap();
                let (saved, _) = load_policy_with_revision(&home.policy_path).unwrap();
                assert_eq!(saved.unwrap(), expected);
                let json: serde_json::Value = serde_json::from_str(&output.stdout).unwrap();
                assert_eq!(json["policy_changed"], true);
                assert_eq!(
                    json["policy_rules_removed"],
                    if account_scope { 2 } else { 4 }
                );
                assert_eq!(store.deletes.get(), 2);
                if account_scope {
                    assert_eq!(
                        load_config(&home.config_path).unwrap().default.as_deref(),
                        Some("web")
                    );
                } else {
                    assert_eq!(json["default_change"]["current"], "other");
                }
            }
        }
    }

    #[test]
    fn removal_keeps_missing_legacy_and_no_match_policy_bytes_and_mtime() {
        for policy in [
            None,
            Some(r#"{ "version":1, "enabled":false, "allow_commands":["id"] }"#),
            Some(r#"{ "version":2, "allow_accounts":[{"server":"other","user":"ops"}] }"#),
        ] {
            let temp = tempfile::tempdir().unwrap();
            let home = ResolvedHome::ad_hoc(temp.path(), "fixture".into());
            let store = Store::default();
            let mut config = fixture(&home, &store);
            if let Some(text) = policy {
                fs::write(&home.policy_path, text).unwrap();
            } else {
                fs::remove_file(&home.policy_path).unwrap();
            }
            let mtime = fs::metadata(&home.policy_path)
                .ok()
                .map(|m| m.modified().unwrap());
            let (_, revision) = load_config_with_revision(&home.config_path).unwrap();
            let output = remove(&home, &store, false, &mut config, &revision).unwrap();
            let json: serde_json::Value = serde_json::from_str(&output.stdout).unwrap();
            assert_eq!(json["policy_changed"], false);
            assert_eq!(
                fs::read_to_string(&home.policy_path).ok().as_deref(),
                policy
            );
            assert_eq!(
                fs::metadata(&home.policy_path)
                    .ok()
                    .map(|m| m.modified().unwrap()),
                mtime
            );
        }
    }

    #[test]
    fn invalid_policy_cancellation_and_revision_conflicts_preserve_unpublished_state() {
        for mode in ["invalid", "cancel", "config-revision", "policy-revision"] {
            let temp = tempfile::tempdir().unwrap();
            let home = ResolvedHome::ad_hoc(temp.path(), "fixture".into());
            let store = Store::default();
            let mut config = fixture(&home, &store);
            let (_, revision) = load_config_with_revision(&home.config_path).unwrap();
            let mut before = fs::read(&home.config_path).unwrap();
            if matches!(mode, "invalid" | "cancel") {
                fs::write(&home.policy_path, "invalid policy").unwrap();
            }
            if mode == "config-revision" {
                before.push(b'\n');
                fs::write(&home.config_path, &before).unwrap();
            }
            let policy_before = fs::read(&home.policy_path).unwrap();
            let error = if mode == "cancel" {
                server::remove_server(
                    RemoveArgs {
                        switch_default: None,
                        clear_default: false,
                        name: "web".into(),
                        yes: false,
                        json: true,
                    },
                    &home.config_path,
                    &home.policy_path,
                    &revision,
                    &store,
                    &mut Prompt(false),
                    &mut config,
                )
                .unwrap_err()
            } else if mode == "policy-revision" {
                let prepared = RemovalPolicy::prepare(&home.policy_path, "web", None).unwrap();
                let mut changed = policy_before.clone();
                changed.push(b'\n');
                fs::write(&home.policy_path, &changed).unwrap();
                assert!(prepared.verify_unchanged().is_err());
                let error = prepared.save().unwrap_err();
                assert_eq!(fs::read(&home.policy_path).unwrap(), changed);
                error
            } else {
                remove(&home, &store, false, &mut config, &revision).unwrap_err()
            };
            let response = ErrorResponse::from_error(&error);
            assert!(response.mutation.is_none());
            assert_eq!(
                response.error.kind,
                if matches!(mode, "invalid" | "policy-revision") {
                    ErrorKind::Policy
                } else {
                    ErrorKind::Config
                }
            );
            assert_eq!(fs::read(&home.config_path).unwrap(), before);
            assert_eq!(store.deletes.get(), 0);
            if mode != "policy-revision" {
                assert_eq!(fs::read(&home.policy_path).unwrap(), policy_before);
            }
        }
    }

    #[test]
    fn removal_publication_failure_reports_applied_target_and_retains_policy_and_secrets() {
        for account_scope in [false, true] {
            let temp = tempfile::tempdir().unwrap();
            let home = ResolvedHome::ad_hoc(temp.path(), "fixture".into());
            let store = Store::default();
            let mut config = fixture(&home, &store);
            let policy = fs::read(&home.policy_path).unwrap();
            let (_, revision) = load_config_with_revision(&home.config_path).unwrap();
            crate::storage::fail_next_parent_sync();
            let error = remove(&home, &store, account_scope, &mut config, &revision).unwrap_err();
            assert!(crate::storage::write_was_published(&error));
            let response = ErrorResponse::from_error(&error);
            assert_eq!(response.error.kind, ErrorKind::Config);
            let mutation = response.mutation.unwrap();
            assert!(mutation.config_applied);
            assert_eq!(mutation.failed_stage, "config_save");
            assert_eq!(mutation.account.as_deref(), account_scope.then_some("ops"));
            assert_eq!(store.deletes.get(), 0);
            assert_eq!(fs::read(&home.policy_path).unwrap(), policy);
        }
    }

    #[test]
    fn switch_default_removal_preserves_transition_on_save_policy_and_cleanup_failures() {
        for scope in ["account", "server-switch", "server-clear"] {
            for stage in [
                "ok",
                "stale",
                "config_save",
                "policy_update",
                "credential_cleanup",
                "both",
            ] {
                let temp = tempfile::tempdir().unwrap();
                let policy_temp = tempfile::tempdir().unwrap();
                let mut home = ResolvedHome::ad_hoc(temp.path(), "fixture".into());
                home.policy_path = policy_temp.path().join("policy.json");
                let store = Store::default();
                let mut config = fixture(&home, &store);
                config.servers.get_mut("web").unwrap().default_user = "ops".into();
                save_config(&home.config_path, &config).unwrap();
                let policy_before = fs::read(&home.policy_path).unwrap();
                let (_, revision) = load_config_with_revision(&home.config_path).unwrap();
                if stage == "stale" {
                    let mut external = config.clone();
                    external.servers.get_mut("web").unwrap().port = 2222;
                    save_config(&home.config_path, &external).unwrap();
                }
                #[cfg(windows)]
                let guarded = home.policy_path.clone();
                #[cfg(unix)]
                let guarded = policy_temp.path().to_owned();
                let original = fs::metadata(&guarded).unwrap().permissions();
                struct Guard(PathBuf, fs::Permissions);
                impl Drop for Guard {
                    fn drop(&mut self) {
                        let _ = fs::set_permissions(&self.0, self.1.clone());
                    }
                }
                let _restore = Guard(guarded.clone(), original.clone());
                if matches!(stage, "policy_update" | "both") {
                    let mut permissions = original;
                    #[cfg(windows)]
                    permissions.set_readonly(true);
                    #[cfg(unix)]
                    {
                        use std::os::unix::fs::PermissionsExt;
                        permissions.set_mode(0o500);
                    }
                    fs::set_permissions(&guarded, permissions).unwrap();
                }
                store
                    .fail_delete
                    .set(matches!(stage, "credential_cleanup" | "both"));
                if stage == "config_save" {
                    crate::storage::fail_next_parent_sync();
                }
                let result = if scope == "account" {
                    account::remove_account(
                        AccountRemoveArgs {
                            name: "web".into(),
                            user: "ops".into(),
                            switch_default: Some("deploy".into()),
                            yes: true,
                            json: true,
                        },
                        &home.config_path,
                        &home.policy_path,
                        &revision,
                        &store,
                        &mut Prompt(true),
                        &mut config,
                    )
                } else {
                    server::remove_server(
                        RemoveArgs {
                            name: "web".into(),
                            switch_default: (scope == "server-switch").then(|| "other".into()),
                            clear_default: scope == "server-clear",
                            yes: true,
                            json: true,
                        },
                        &home.config_path,
                        &home.policy_path,
                        &revision,
                        &store,
                        &mut Prompt(true),
                        &mut config,
                    )
                };
                let saved = load_config(&home.config_path).unwrap();
                if stage == "stale" {
                    let error = result.unwrap_err();
                    assert!(ErrorResponse::from_error(&error).mutation.is_none());
                    assert_eq!(saved.servers["web"].default_user, "ops");
                    assert_eq!(saved.servers["web"].port, 2222);
                    assert_eq!(store.deletes.get(), 0);
                    assert_eq!(fs::read(&home.policy_path).unwrap(), policy_before);
                    continue;
                }
                let (resource, previous, current) = if scope == "account" {
                    assert_eq!(saved.servers["web"].default_user, "deploy");
                    assert!(!saved.servers["web"].accounts.contains_key("ops"));
                    ("account", "ops", Some("deploy"))
                } else {
                    assert!(!saved.servers.contains_key("web"));
                    let current = (scope == "server-switch").then_some("other");
                    assert_eq!(saved.default.as_deref(), current);
                    ("server", "web", current)
                };
                if stage == "ok" {
                    let value: serde_json::Value =
                        serde_json::from_str(&result.unwrap().stdout).unwrap();
                    assert_eq!(
                        value["default_change"]["current"],
                        serde_json::json!(current)
                    );
                } else {
                    let error = result.unwrap_err();
                    let response = ErrorResponse::from_error(&error);
                    let mutation = response.mutation.unwrap();
                    assert_eq!(
                        mutation.failed_stage,
                        if stage == "both" {
                            "policy_update"
                        } else {
                            stage
                        }
                    );
                    let change = mutation.default_change.unwrap();
                    assert_eq!(change.resource, resource);
                    assert_eq!(change.previous.as_deref(), Some(previous));
                    assert_eq!(change.current.as_deref(), current);
                    assert_eq!(
                        response.error.kind,
                        match stage {
                            "config_save" => ErrorKind::Config,
                            "credential_cleanup" => ErrorKind::Auth,
                            _ => ErrorKind::Policy,
                        }
                    );
                }
                assert_eq!(
                    store.deletes.get(),
                    if stage == "config_save" { 0 } else { 2 }
                );
                if matches!(stage, "config_save" | "policy_update" | "both") {
                    assert_eq!(fs::read(&home.policy_path).unwrap(), policy_before);
                }
            }
        }
    }

    #[test]
    fn applied_policy_and_credential_failures_report_each_stage_and_keep_default_change() {
        for account_scope in [false, true] {
            for policy_failure in [false, true] {
                for credential_failure in [false, true] {
                    let temp = tempfile::tempdir().unwrap();
                    let policy_temp = tempfile::tempdir().unwrap();
                    let mut home = ResolvedHome::ad_hoc(temp.path(), "fixture".into());
                    home.policy_path = policy_temp.path().join("policy.json");
                    let store = Store::default();
                    let mut config = fixture(&home, &store);
                    let policy_before = fs::read(&home.policy_path).unwrap();
                    #[cfg(windows)]
                    let guarded = home.policy_path.clone();
                    #[cfg(unix)]
                    let guarded = policy_temp.path().to_owned();
                    let original = fs::metadata(&guarded).unwrap().permissions();
                    struct Guard(PathBuf, fs::Permissions);
                    impl Drop for Guard {
                        fn drop(&mut self) {
                            let _ = fs::set_permissions(&self.0, self.1.clone());
                        }
                    }
                    let _restore = Guard(guarded.clone(), original.clone());
                    if policy_failure {
                        let mut permissions = original;
                        #[cfg(windows)]
                        permissions.set_readonly(true);
                        #[cfg(unix)]
                        {
                            use std::os::unix::fs::PermissionsExt;
                            permissions.set_mode(0o500);
                        }
                        fs::set_permissions(&guarded, permissions).unwrap();
                    }
                    store.fail_delete.set(credential_failure);
                    let (_, revision) = load_config_with_revision(&home.config_path).unwrap();
                    let result = remove(&home, &store, account_scope, &mut config, &revision);
                    assert_eq!(store.deletes.get(), 2);
                    if policy_failure || credential_failure {
                        let error = result.unwrap_err();
                        let response = ErrorResponse::from_error(&error);
                        assert_eq!(
                            response.error.kind,
                            if policy_failure {
                                ErrorKind::Policy
                            } else {
                                ErrorKind::Auth
                            }
                        );
                        let mutation = response.mutation.unwrap();
                        assert!(mutation.config_applied);
                        assert_eq!(
                            mutation.failed_stage,
                            if policy_failure {
                                "policy_update"
                            } else {
                                "credential_cleanup"
                            }
                        );
                        assert_eq!(mutation.action, "removed");
                        if !account_scope {
                            assert_eq!(
                                mutation.default_change.unwrap().current.as_deref(),
                                Some("other")
                            );
                        }
                        if policy_failure && credential_failure {
                            assert!(error.to_string().contains("cleanup also failed"));
                            assert!(!error.to_string().contains("cleanup-marker"));
                        }
                    } else {
                        result.unwrap();
                    }
                    if policy_failure {
                        assert_eq!(fs::read(&home.policy_path).unwrap(), policy_before);
                    } else {
                        assert_ne!(fs::read(&home.policy_path).unwrap(), policy_before);
                    }
                    let saved = load_config(&home.config_path).unwrap();
                    if account_scope {
                        assert!(!saved.servers["web"].accounts.contains_key("ops"));
                    } else {
                        assert!(!saved.servers.contains_key("web"));
                    }
                }
            }
        }
    }
}
