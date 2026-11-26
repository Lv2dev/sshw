use clap::Parser;
use serde_json::Value;
use sshw::audit::FileAuditSink;
use sshw::cli::{Cli, ExecContext, Prompter, execute_for_runtime_with};
use sshw::config::{
    AccountConfig, AuthConfig, PrivilegeConfig, PrivilegeMethod, ServerConfig, SshwConfig,
    save_config,
};
use sshw::credentials::{AuthMaterial, CredentialStore};
use sshw::home::{CredentialPurpose, ResolvedHome};
use sshw::ssh::{HostKeyInfo, RunResult, SshClient, SshTarget, TransferResult};
use std::cell::RefCell;
use std::collections::BTreeMap;
use std::path::Path;

struct Store {
    reads: RefCell<Vec<(String, String)>>,
    secret: String,
}
impl CredentialStore for Store {
    fn health_check(&self) -> anyhow::Result<sshw::credentials::CredentialStoreHealth> {
        panic!("no global backend health probe")
    }
    fn set_password(&self, _: &str, _: &str, _: &str) -> anyhow::Result<()> {
        panic!("connection test must not store credentials")
    }
    fn delete_password(&self, _: &str, _: &str) -> anyhow::Result<()> {
        panic!("connection test must not delete credentials")
    }
    fn get_password(&self, key: &str, user: &str) -> anyhow::Result<String> {
        self.reads.borrow_mut().push((key.into(), user.into()));
        Ok(self.secret.clone())
    }
}
struct NoPrompts;
impl Prompter for NoPrompts {
    fn confirm(&mut self, _: &str) -> anyhow::Result<bool> {
        panic!("no prompts")
    }
    fn password(&mut self, _: &str) -> anyhow::Result<String> {
        panic!("no password prompt")
    }
    fn password_stdin(&mut self) -> anyhow::Result<String> {
        panic!("no stdin")
    }
}
#[derive(Default)]
struct Probe {
    calls: RefCell<Vec<(String, bool)>>,
    fail: bool,
}
impl SshClient for Probe {
    fn test_connection(
        &self,
        target: &SshTarget<'_>,
        auth: &AuthMaterial,
    ) -> anyhow::Result<HostKeyInfo> {
        self.calls.borrow_mut().push((
            target.user.into(),
            matches!(auth, AuthMaterial::Password(_)),
        ));
        if self.fail {
            return Err(sshw::error::classified_error(
                sshw::output::ErrorKind::Auth,
                anyhow::anyhow!("authentication rejected"),
            ));
        }
        Ok(HostKeyInfo {
            algorithm: "ssh-ed25519".into(),
            fingerprint_sha256: "SHA256:test".into(),
        })
    }
    fn host_key(&self, _: &ServerConfig) -> anyhow::Result<HostKeyInfo> {
        panic!("no unverified host probe")
    }
    fn trust_host(&self, _: &str, _: &ServerConfig, _: &str) -> anyhow::Result<HostKeyInfo> {
        panic!("no auto trust")
    }
    fn run(&self, _: &SshTarget<'_>, _: &AuthMaterial, _: &str) -> anyhow::Result<RunResult> {
        panic!("no remote exec")
    }
    fn put(
        &self,
        _: &SshTarget<'_>,
        _: &AuthMaterial,
        _: &Path,
        _: &str,
    ) -> anyhow::Result<TransferResult> {
        panic!("no upload")
    }
    fn get(
        &self,
        _: &SshTarget<'_>,
        _: &AuthMaterial,
        _: &str,
        _: &Path,
        _: bool,
    ) -> anyhow::Result<TransferResult> {
        panic!("no download")
    }
}

#[test]
fn connection_test_selects_only_login_credentials_preserves_files_and_audits_without_exec() {
    let temp = tempfile::tempdir().unwrap();
    let home = ResolvedHome::ad_hoc(temp.path(), "test".into());
    let registry = temp.path().join("profiles.json");
    let audit = FileAuditSink::new(home.audit_path.clone());
    let ctx = ExecContext {
        home: &home,
        registry_path: &registry,
        policy_forced: false,
        audit: &audit,
    };
    let login = home.namespace.credential_key_v3(
        CredentialPurpose::Login,
        "web",
        "ops",
        "0000000000000001",
    );
    let privilege = home.namespace.credential_key_v3(
        CredentialPurpose::Privilege,
        "web",
        "ops",
        "0000000000000002",
    );
    let mut server = ServerConfig::single_account("192.0.2.10", 2222, "deploy", AuthConfig::Agent);
    server.accounts.insert(
        "ops".into(),
        AccountConfig {
            auth: AuthConfig::Password {
                credential: login.clone(),
            },
            privilege: Some(PrivilegeConfig {
                method: PrivilegeMethod::Su,
                user: "root".into(),
                credential: Some(privilege),
                no_password: false,
            }),
        },
    );
    let config = SshwConfig {
        default: None,
        servers: BTreeMap::from([("web".into(), server)]),
        ..Default::default()
    };
    save_config(&home.config_path, &config).unwrap();
    std::fs::write(&home.known_hosts_path, "preserved").unwrap();
    std::fs::write(
        &home.policy_path,
        r#"{"version":2,"enabled":true,"allow_accounts":[{"server":"web","user":"ops"}]}"#,
    )
    .unwrap();
    let paths = [&home.config_path, &home.known_hosts_path, &home.policy_path];
    let before: Vec<_> = paths
        .iter()
        .map(|p| {
            (
                std::fs::read(p).unwrap(),
                std::fs::metadata(p).unwrap().modified().unwrap(),
            )
        })
        .collect();
    let store = Store {
        reads: RefCell::new(vec![]),
        secret: "connection-test-secret".into(),
    };
    let probe = Probe::default();
    for user in [None, Some("ops")] {
        let mut args = vec!["sshw", "test", "web", "--json"];
        if let Some(user) = user {
            args.extend(["--user", user]);
        }
        let output = execute_for_runtime_with(
            Cli::try_parse_from(args).unwrap(),
            &ctx,
            &store,
            &probe,
            &mut NoPrompts,
        );
        assert_eq!(output.exit_code, 0, "{output:?}");
        let json: Value = serde_json::from_str(&output.stdout).unwrap();
        for field in [
            "ok",
            "connection_tested",
            "host_key_verified",
            "authenticated",
        ] {
            assert_eq!(json[field], true);
        }
        assert_eq!(json["command_executed"], false);
        assert_eq!(json["user"], user.unwrap_or("deploy"));
        assert_eq!(json["fingerprint_sha256"], "SHA256:test");
        assert!(!output.stdout.contains("connection-test-secret"));
    }
    assert_eq!(
        *probe.calls.borrow(),
        vec![("deploy".into(), false), ("ops".into(), true)]
    );
    assert_eq!(*store.reads.borrow(), vec![(login, "ops".into())]);
    for (p, before) in paths.iter().zip(before) {
        assert_eq!(
            (
                std::fs::read(p).unwrap(),
                std::fs::metadata(p).unwrap().modified().unwrap()
            ),
            before
        );
    }
    assert!(!home.root.join(".sshw.lock").exists());
    let records = std::fs::read_to_string(&home.audit_path).unwrap();
    assert_eq!(records.lines().count(), 2);
    for record in records.lines() {
        let v: Value = serde_json::from_str(record).unwrap();
        assert_eq!(v["action"], "test");
        assert_eq!(v["status"], "ok");
    }
}

#[test]
fn connection_test_rejects_unknown_targets_policy_and_authentication_without_remote_exec() {
    let temp = tempfile::tempdir().unwrap();
    let home = ResolvedHome::ad_hoc(temp.path(), "test".into());
    let registry = temp.path().join("profiles.json");
    let audit = FileAuditSink::new(home.audit_path.clone());
    let ctx = ExecContext {
        home: &home,
        registry_path: &registry,
        policy_forced: false,
        audit: &audit,
    };
    let mut server = ServerConfig::single_account("192.0.2.10", 22, "deploy", AuthConfig::Agent);
    server.accounts.insert(
        "ops".into(),
        AccountConfig {
            auth: AuthConfig::Agent,
            privilege: None,
        },
    );
    save_config(
        &home.config_path,
        &SshwConfig {
            default: Some("web".into()),
            servers: BTreeMap::from([("web".into(), server)]),
            ..Default::default()
        },
    )
    .unwrap();
    std::fs::write(&home.policy_path, r#"{"version":2,"enabled":true}"#).unwrap();
    let store = Store {
        reads: RefCell::new(vec![]),
        secret: "unused".into(),
    };
    let probe = Probe::default();
    for (args, exit) in [
        (vec!["sshw", "test", "absent", "--json"], 3),
        (vec!["sshw", "test", "web", "--user", "absent", "--json"], 3),
        (vec!["sshw", "test", "web", "--user", "ops", "--json"], 7),
    ] {
        let output = execute_for_runtime_with(
            Cli::try_parse_from(args).unwrap(),
            &ctx,
            &store,
            &probe,
            &mut NoPrompts,
        );
        assert_eq!(output.exit_code, exit, "{output:?}");
        if exit == 7 {
            let json: Value = serde_json::from_str(&output.stdout).unwrap();
            assert_eq!(json["suggestions"][0]["kind"], "account");
        }
    }
    assert!(probe.calls.borrow().is_empty());
    assert!(store.reads.borrow().is_empty());
    let fail = Probe {
        fail: true,
        ..Default::default()
    };
    let output = execute_for_runtime_with(
        Cli::try_parse_from(["sshw", "test", "web", "--json"]).unwrap(),
        &ctx,
        &store,
        &fail,
        &mut NoPrompts,
    );
    assert_eq!(output.exit_code, 4);
    let json: Value = serde_json::from_str(&output.stdout).unwrap();
    assert_eq!(json["error"]["kind"], "auth");
    assert!(Cli::try_parse_from(["sshw", "test"]).is_err());
}
