use clap::Parser;
use sshw::audit::{AuditSink, FileAuditSink, NoopAudit};
use sshw::cli::{Cli, CommandOutput, ExecContext, Prompter, execute_with};
use sshw::config::{
    AccountConfig, AuthConfig, PrivilegeConfig, PrivilegeMethod, ServerConfig, SshwConfig,
    load_config, save_config, validate_config_credential_references,
};
use sshw::credentials::{AuthMaterial, CredentialStore, CredentialStoreHealth};
use sshw::home::{CredentialPurpose, ResolvedHome};
use sshw::output::{ErrorKind, ErrorResponse};
use sshw::policy::PolicyFile;
use sshw::ssh::{HostKeyInfo, RunResult, SshClient, SshTarget, TransferResult};
use std::cell::{Cell, RefCell};
use std::collections::BTreeMap;
use std::fs;
use std::path::Path;

#[derive(Default)]
struct Store {
    values: RefCell<BTreeMap<(String, String), String>>,
    gets: Cell<usize>,
    sets: Cell<usize>,
    fail_get: Cell<Option<usize>>,
    fail_set: Cell<Option<usize>>,
    fail_delete: Cell<bool>,
    get_hook: RefCell<Option<Box<dyn FnOnce()>>>,
}

impl CredentialStore for Store {
    fn get_password(&self, key: &str, user: &str) -> anyhow::Result<String> {
        let count = self.gets.get() + 1;
        self.gets.set(count);
        if let Some(hook) = self.get_hook.borrow_mut().take() {
            hook();
        }
        if self.fail_get.get() == Some(count) {
            anyhow::bail!("credential read failed: token=read-marker");
        }
        self.values
            .borrow()
            .get(&(key.into(), user.into()))
            .cloned()
            .ok_or_else(|| anyhow::Error::new(keyring_core::Error::NoEntry))
    }
    fn set_password(&self, key: &str, user: &str, password: &str) -> anyhow::Result<()> {
        let count = self.sets.get() + 1;
        self.sets.set(count);
        if self.fail_set.get() == Some(count) {
            anyhow::bail!("credential write failed: token=write-marker");
        }
        self.values
            .borrow_mut()
            .insert((key.into(), user.into()), password.into());
        Ok(())
    }
    fn delete_password(&self, key: &str, user: &str) -> anyhow::Result<()> {
        if self.fail_delete.get() {
            anyhow::bail!("credential delete failed: token=delete-marker");
        }
        self.values
            .borrow_mut()
            .remove(&(key.into(), user.into()))
            .map(|_| ())
            .ok_or_else(|| anyhow::Error::new(keyring_core::Error::NoEntry))
    }
    fn health_check(&self) -> anyhow::Result<CredentialStoreHealth> {
        unreachable!("rename must not run doctor")
    }
}

struct NoPrompts;
impl Prompter for NoPrompts {
    fn confirm(&mut self, _: &str) -> anyhow::Result<bool> {
        panic!("explicit rename must not prompt")
    }
    fn password(&mut self, _: &str) -> anyhow::Result<String> {
        panic!("rename must copy existing secrets")
    }
    fn password_stdin(&mut self) -> anyhow::Result<String> {
        panic!("rename must not read stdin")
    }
}

struct NoNetwork;
impl SshClient for NoNetwork {
    fn host_key(&self, _: &ServerConfig) -> anyhow::Result<HostKeyInfo> {
        panic!("rename must not connect")
    }
    fn trust_host(&self, _: &str, _: &ServerConfig, _: &str) -> anyhow::Result<HostKeyInfo> {
        panic!("rename must preserve trust")
    }
    fn run(&self, _: &SshTarget<'_>, _: &AuthMaterial, _: &str) -> anyhow::Result<RunResult> {
        panic!("rename must not run SSH")
    }
    fn put(
        &self,
        _: &SshTarget<'_>,
        _: &AuthMaterial,
        _: &Path,
        _: &str,
    ) -> anyhow::Result<TransferResult> {
        panic!("rename must not upload")
    }
    fn get(
        &self,
        _: &SshTarget<'_>,
        _: &AuthMaterial,
        _: &str,
        _: &Path,
        _: bool,
    ) -> anyhow::Result<TransferResult> {
        panic!("rename must not download")
    }
}

fn fixture(home: &ResolvedHome, store: &Store) -> SshwConfig {
    let login = home.namespace.legacy_credential_key("old");
    let ops = home
        .namespace
        .credential_key_v3(CredentialPurpose::Login, "old", "ops", "01");
    let privilege =
        home.namespace
            .credential_key_v3(CredentialPurpose::Privilege, "old", "ops", "02");
    for (key, user, password) in [
        (&login, "deploy", "fixture-login"),
        (&ops, "ops", "fixture-ops"),
        (&privilege, "root", "fixture-privilege"),
    ] {
        store
            .values
            .borrow_mut()
            .insert((key.clone(), user.into()), password.into());
    }
    let mut server = ServerConfig::single_account(
        "192.0.2.10",
        2222,
        "deploy",
        AuthConfig::Password { credential: login },
    );
    server.accounts.insert(
        "ops".into(),
        AccountConfig {
            auth: AuthConfig::Password { credential: ops },
            privilege: Some(PrivilegeConfig {
                method: PrivilegeMethod::Sudo,
                user: "root".into(),
                credential: Some(privilege),
                no_password: false,
            }),
        },
    );
    server.accounts.insert(
        "agent".into(),
        AccountConfig {
            auth: AuthConfig::Agent,
            privilege: Some(PrivilegeConfig {
                method: PrivilegeMethod::Sudo,
                user: "root".into(),
                credential: None,
                no_password: true,
            }),
        },
    );
    let config = SshwConfig {
        default: Some("old".into()),
        servers: BTreeMap::from([
            ("old".into(), server),
            (
                "other".into(),
                ServerConfig::single_account("192.0.2.11", 22, "other-user", AuthConfig::Agent),
            ),
        ]),
        ..SshwConfig::default()
    };
    save_config(&home.config_path, &config).unwrap();
    fs::write(
        &home.known_hosts_path,
        "# unchanged host approval fixture\n",
    )
    .unwrap();
    fs::write(&home.policy_path, r#"{"version":2,"enabled":true,"allow_commands":["uptime"],"allow_accounts":[{"server":"old","user":"ops"},{"server":"other","user":"some-user"}]}"#).unwrap();
    config
}

fn rename<C: CredentialStore>(
    home: &ResolvedHome,
    store: &C,
    old: &str,
    new: &str,
    audit: &dyn AuditSink,
) -> anyhow::Result<CommandOutput> {
    let registry = home.root.join("test-profiles.json");
    let ctx = ExecContext {
        home,
        registry_path: &registry,
        policy_forced: false,
        audit,
    };
    execute_with(
        Cli::try_parse_from(["sshw", "rename", old, new, "--json"]).unwrap(),
        &ctx,
        store,
        &NoNetwork,
        &mut NoPrompts,
    )
}

fn assert_new_credentials(config: &SshwConfig, home: &ResolvedHome, store: &Store, new: &str) {
    validate_config_credential_references(config, &home.namespace).unwrap();
    let server = &config.servers[new];
    for (user, password) in [("deploy", "fixture-login"), ("ops", "fixture-ops")] {
        let AuthConfig::Password { credential } = &server.accounts[user].auth else {
            panic!()
        };
        assert!(home.namespace.account_credential_key_matches(
            CredentialPurpose::Login,
            new,
            user,
            credential
        ));
        assert_eq!(
            store.values.borrow()[&(credential.clone(), user.into())],
            password
        );
    }
    let privilege = server.accounts["ops"].privilege.as_ref().unwrap();
    let key = privilege.credential.as_ref().unwrap();
    assert!(home.namespace.account_credential_key_matches(
        CredentialPurpose::Privilege,
        new,
        "ops",
        key
    ));
    assert_eq!(
        store.values.borrow()[&(key.clone(), "root".into())],
        "fixture-privilege"
    );
}

#[test]
fn rename_preserves_accounts_credentials_default_policy_and_host_trust() {
    let temp = tempfile::tempdir().unwrap();
    let home = ResolvedHome::ad_hoc(temp.path(), "fixture".into());
    let store = Store::default();
    let original = fixture(&home, &store);
    let old_secrets = store.values.borrow().clone();
    let trusted = fs::read(&home.known_hosts_path).unwrap();
    let output = rename(&home, &store, "old", "production 서버", &NoopAudit).unwrap();
    let json: serde_json::Value = serde_json::from_str(&output.stdout).unwrap();
    assert_eq!(json["server"], "production 서버");
    assert_eq!(json["previous_server"], "old");
    assert_eq!(json["policy_changed"], true);
    assert_eq!(json["default_change"]["current"], "production 서버");
    let saved = load_config(&home.config_path).unwrap();
    assert_eq!(saved.default.as_deref(), Some("production 서버"));
    assert!(!saved.servers.contains_key("old"));
    assert_eq!(saved.servers["other"], original.servers["other"]);
    let new_server = &saved.servers["production 서버"];
    assert_eq!(
        (&new_server.host, new_server.port, &new_server.default_user),
        (&original.servers["old"].host, 2222, &"deploy".to_owned())
    );
    assert_eq!(
        new_server.accounts["agent"],
        original.servers["old"].accounts["agent"]
    );
    assert_eq!(
        new_server.accounts["ops"]
            .privilege
            .as_ref()
            .unwrap()
            .method,
        PrivilegeMethod::Sudo
    );
    assert_new_credentials(&saved, &home, &store, "production 서버");
    for old_key in old_secrets.keys() {
        assert!(!store.values.borrow().contains_key(old_key));
    }
    assert_eq!(store.values.borrow().len(), 3);
    let policy: PolicyFile = serde_json::from_slice(&fs::read(&home.policy_path).unwrap()).unwrap();
    assert!(policy.enabled);
    assert_eq!(policy.allow_commands, ["uptime"]);
    assert_eq!(policy.allow_accounts[0].server, "production 서버");
    assert_eq!(policy.allow_accounts[1].server, "other");
    assert_eq!(fs::read(&home.known_hosts_path).unwrap(), trusted);
    for password in old_secrets.values() {
        assert!(!output.stdout.contains(password));
    }
}

#[test]
fn rename_uses_profile_namespace_and_keeps_other_home_and_default() {
    let a = tempfile::tempdir().unwrap();
    let b = tempfile::tempdir().unwrap();
    let home = ResolvedHome::profile(a.path().to_owned(), "profile-one", "fixture".into());
    let other = ResolvedHome::profile(b.path().to_owned(), "profile-two", "fixture".into());
    let store = Store::default();
    let mut config = fixture(&home, &store);
    let first_home_values = store.values.borrow().clone();
    fixture(&other, &store);
    config.default = Some("other".into());
    save_config(&home.config_path, &config).unwrap();
    let other_bytes = fs::read(&other.config_path).unwrap();
    let other_values: BTreeMap<_, _> = store
        .values
        .borrow()
        .iter()
        .filter(|(key, _)| !first_home_values.contains_key(*key))
        .map(|(key, value)| (key.clone(), value.clone()))
        .collect();
    let output = rename(&home, &store, "old", "new", &NoopAudit).unwrap();
    let saved = load_config(&home.config_path).unwrap();
    assert_eq!(saved.default.as_deref(), Some("other"));
    assert_new_credentials(&saved, &home, &store, "new");
    assert!(!output.stdout.contains("default_change"));
    assert_eq!(fs::read(&other.config_path).unwrap(), other_bytes);
    assert_eq!(other_values.len(), 3);
    for (key, password) in other_values {
        assert_eq!(store.values.borrow().get(&key), Some(&password));
    }
}

#[test]
fn rename_rejects_collisions_invalid_names_and_bad_policy_without_secret_io() {
    for (old, new, policy, kind) in [
        ("missing", "new", None, ErrorKind::Config),
        ("old", "other", None, ErrorKind::Config),
        ("old", " ", None, ErrorKind::Config),
        ("old", "bad\nname", None, ErrorKind::Config),
        ("old", "privilege:reserved", None, ErrorKind::Config),
        (
            "old",
            "new",
            Some(r#"{"version":2,"allow_accounts":[{"server":"new","user":"ops"}]}"#),
            ErrorKind::Policy,
        ),
        (
            "old",
            "new",
            Some(r#"{"enabled":false,"unknown":true}"#),
            ErrorKind::Policy,
        ),
    ] {
        let temp = tempfile::tempdir().unwrap();
        let home = ResolvedHome::ad_hoc(temp.path(), "fixture".into());
        let store = Store::default();
        fixture(&home, &store);
        if let Some(policy) = policy {
            fs::write(&home.policy_path, policy).unwrap();
        }
        let before = fs::read(&home.config_path).unwrap();
        let policy = fs::read(&home.policy_path).unwrap();
        let values = store.values.borrow().clone();
        let error = rename(&home, &store, old, new, &NoopAudit).unwrap_err();
        assert_eq!(
            ErrorResponse::from_error(&error).error.kind,
            kind,
            "{error:#}"
        );
        assert_eq!(fs::read(&home.config_path).unwrap(), before);
        assert_eq!(fs::read(&home.policy_path).unwrap(), policy);
        assert_eq!(*store.values.borrow(), values);
        assert_eq!(store.gets.get(), 0);
        assert_eq!(store.sets.get(), 0);
    }
    for args in [vec!["sshw", "rename"], vec!["sshw", "rename", "old"]] {
        assert!(Cli::try_parse_from(args).is_err());
    }
}

#[test]
fn rename_same_name_preserves_legacy_bytes_mtime_and_skips_secrets_and_policy() {
    let temp = tempfile::tempdir().unwrap();
    let home = ResolvedHome::ad_hoc(temp.path(), "fixture".into());
    let store = Store::default();
    let legacy = serde_json::json!({"version":1,"default":"old","servers":{"old":{"host":"192.0.2.10","port":22,"user":"deploy","auth":{"type":"password","credential":home.namespace.legacy_credential_key("old")}}}}).to_string();
    fs::write(&home.config_path, &legacy).unwrap();
    fs::write(&home.policy_path, "invalid policy remains untouched").unwrap();
    let mtime = fs::metadata(&home.config_path).unwrap().modified().unwrap();
    let output = rename(&home, &store, "old", "old", &NoopAudit).unwrap();
    let output: serde_json::Value = serde_json::from_str(&output.stdout).unwrap();
    assert_eq!(output["changed"], false);
    assert_eq!(output["change"], "unchanged");
    assert_eq!(store.gets.get(), 0);
    assert_eq!(store.sets.get(), 0);
    assert_eq!(fs::read_to_string(&home.config_path).unwrap(), legacy);
    assert_eq!(
        fs::metadata(&home.config_path).unwrap().modified().unwrap(),
        mtime
    );
    assert_eq!(
        fs::read_to_string(&home.policy_path).unwrap(),
        "invalid policy remains untouched"
    );
}

#[test]
fn rename_migrates_legacy_login_and_su_password_but_keeps_legacy_policy_bytes() {
    let temp = tempfile::tempdir().unwrap();
    let home = ResolvedHome::ad_hoc(temp.path(), "fixture".into());
    let store = Store::default();
    let login = home.namespace.legacy_credential_key("old");
    let privilege = home.namespace.legacy_privilege_credential_key("old");
    let legacy = serde_json::json!({"version":1,"default":"old","servers":{"old":{"host":"192.0.2.10","port":22,"user":"deploy","auth":{"type":"password","credential":login}}},"privileges":{"old":{"method":"su","user":"root","credential":privilege}}}).to_string();
    fs::write(&home.config_path, legacy).unwrap();
    let policy = r#"{ "version":1, "enabled":false, "allow_commands":["uptime"] }"#;
    fs::write(&home.policy_path, policy).unwrap();
    let policy_mtime = fs::metadata(&home.policy_path).unwrap().modified().unwrap();
    store
        .values
        .borrow_mut()
        .insert((login.clone(), "deploy".into()), "legacy-login".into());
    store
        .values
        .borrow_mut()
        .insert((privilege.clone(), "root".into()), "legacy-su".into());
    let output = rename(&home, &store, "old", "new", &NoopAudit).unwrap();
    let output: serde_json::Value = serde_json::from_str(&output.stdout).unwrap();
    assert_eq!(output["policy_changed"], false);
    assert_eq!(fs::read_to_string(&home.policy_path).unwrap(), policy);
    assert_eq!(
        fs::metadata(&home.policy_path).unwrap().modified().unwrap(),
        policy_mtime
    );
    let saved = load_config(&home.config_path).unwrap();
    validate_config_credential_references(&saved, &home.namespace).unwrap();
    let account = &saved.servers["new"].accounts["deploy"];
    let AuthConfig::Password { credential } = &account.auth else {
        panic!()
    };
    assert_eq!(
        store.values.borrow()[&(credential.clone(), "deploy".into())],
        "legacy-login"
    );
    let privilege = account.privilege.as_ref().unwrap();
    assert_eq!(privilege.method, PrivilegeMethod::Su);
    assert_eq!(
        store.values.borrow()[&(privilege.credential.clone().unwrap(), "root".into())],
        "legacy-su"
    );
    assert_eq!(store.values.borrow().len(), 2);
    let raw: serde_json::Value =
        serde_json::from_slice(&fs::read(&home.config_path).unwrap()).unwrap();
    assert_eq!(raw["version"], 2);
}

#[test]
fn rename_rolls_back_new_secrets_on_copy_failures_and_revision_conflicts() {
    for failure in ["read", "write", "config-conflict", "policy-conflict"] {
        let temp = tempfile::tempdir().unwrap();
        let home = ResolvedHome::ad_hoc(temp.path(), "fixture".into());
        let store = Store::default();
        fixture(&home, &store);
        let mut config_bytes = fs::read(&home.config_path).unwrap();
        let mut policy_bytes = fs::read(&home.policy_path).unwrap();
        let values = store.values.borrow().clone();
        match failure {
            "read" => store.fail_get.set(Some(2)),
            "write" => store.fail_set.set(Some(2)),
            "config-conflict" | "policy-conflict" => {
                let (path, bytes) = if failure == "config-conflict" {
                    (&home.config_path, &mut config_bytes)
                } else {
                    (&home.policy_path, &mut policy_bytes)
                };
                bytes.push(b'\n');
                let path = path.clone();
                let contents = bytes.clone();
                *store.get_hook.borrow_mut() =
                    Some(Box::new(move || fs::write(path, contents).unwrap()));
            }
            _ => unreachable!(),
        }
        let error = rename(&home, &store, "old", "new", &NoopAudit).unwrap_err();
        let response = ErrorResponse::from_error(&error);
        assert_eq!(
            response.error.kind,
            match failure {
                "config-conflict" => ErrorKind::Config,
                "policy-conflict" => ErrorKind::Policy,
                _ => ErrorKind::Auth,
            }
        );
        assert!(response.mutation.is_none());
        assert_eq!(fs::read(&home.config_path).unwrap(), config_bytes);
        assert_eq!(fs::read(&home.policy_path).unwrap(), policy_bytes);
        assert_eq!(*store.values.borrow(), values);
        let rendered = serde_json::to_string(&response).unwrap();
        for secret in [
            "fixture-login",
            "fixture-ops",
            "fixture-privilege",
            "read-marker",
            "write-marker",
        ] {
            assert!(!rendered.contains(secret));
        }
    }
}

#[test]
fn rename_cleanup_failure_reports_applied_name_and_keeps_usable_new_secrets() {
    let temp = tempfile::tempdir().unwrap();
    let home = ResolvedHome::ad_hoc(temp.path(), "fixture".into());
    let store = Store::default();
    fixture(&home, &store);
    store.fail_delete.set(true);
    let error = rename(&home, &store, "old", "new", &NoopAudit).unwrap_err();
    let response = ErrorResponse::from_error(&error);
    assert_eq!(response.error.kind, ErrorKind::Auth);
    let mutation = response.mutation.unwrap();
    assert!(mutation.config_applied);
    assert_eq!(mutation.failed_stage, "credential_cleanup");
    assert_eq!(mutation.action, "renamed");
    assert_eq!(mutation.server, "new");
    assert_eq!(
        mutation.default_change.unwrap().current.as_deref(),
        Some("new")
    );
    let saved = load_config(&home.config_path).unwrap();
    assert_new_credentials(&saved, &home, &store, "new");
    assert_eq!(store.values.borrow().len(), 6);
    let policy: PolicyFile = serde_json::from_slice(&fs::read(&home.policy_path).unwrap()).unwrap();
    assert_eq!(policy.allow_accounts[0].server, "new");
    assert!(!error.to_string().contains("delete-marker"));
}

#[test]
fn rename_records_old_and_new_alias_in_audit_without_displaying_sensitive_values() {
    let temp = tempfile::tempdir().unwrap();
    let home = ResolvedHome::ad_hoc(temp.path(), "fixture".into());
    let store = Store::default();
    fixture(&home, &store);
    let audit = FileAuditSink::new(home.audit_path.clone());
    let output = rename(&home, &store, "old", "token=rename-marker", &audit).unwrap();
    assert!(!output.stdout.contains("rename-marker"));
    let line: serde_json::Value =
        serde_json::from_str(&fs::read_to_string(&home.audit_path).unwrap()).unwrap();
    assert_eq!(line["action"], "rename");
    assert_eq!(line["server"], "old");
    assert_eq!(line["status"], "ok");
    assert!(!line.to_string().contains("rename-marker"));
    assert!(line["detail"].as_str().unwrap().contains("redacted"));
}

#[test]
fn rename_policy_save_failure_reports_config_applied_and_preserves_policy() {
    let temp = tempfile::tempdir().unwrap();
    let policy_temp = tempfile::tempdir().unwrap();
    let mut home = ResolvedHome::ad_hoc(temp.path(), "fixture".into());
    home.policy_path = policy_temp.path().join("policy.json");
    let store = Store::default();
    fixture(&home, &store);
    let before = fs::read(&home.policy_path).unwrap();
    #[cfg(windows)]
    let guarded_path = home.policy_path.clone();
    #[cfg(unix)]
    let guarded_path = policy_temp.path().to_owned();
    let original = fs::metadata(&guarded_path).unwrap().permissions();
    struct PermissionsGuard(std::path::PathBuf, fs::Permissions);
    impl Drop for PermissionsGuard {
        fn drop(&mut self) {
            let _ = fs::set_permissions(&self.0, self.1.clone());
        }
    }
    let _restore = PermissionsGuard(guarded_path.clone(), original.clone());
    let mut read_only = original;
    #[cfg(windows)]
    read_only.set_readonly(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        read_only.set_mode(0o500);
    }
    fs::set_permissions(&guarded_path, read_only).unwrap();
    let error = rename(&home, &store, "old", "new", &NoopAudit).unwrap_err();
    let response = ErrorResponse::from_error(&error);
    assert_eq!(response.error.kind, ErrorKind::Policy, "{error:#}");
    let mutation = response.mutation.unwrap();
    assert!(mutation.config_applied);
    assert_eq!(mutation.failed_stage, "policy_update");
    assert_eq!(mutation.server, "new");
    assert!(error.to_string().contains("rename is already applied"));
    assert_eq!(fs::read(&home.policy_path).unwrap(), before);
    let saved = load_config(&home.config_path).unwrap();
    assert_new_credentials(&saved, &home, &store, "new");
    assert_eq!(store.values.borrow().len(), 3);
}
