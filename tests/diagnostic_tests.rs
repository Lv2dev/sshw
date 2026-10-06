use clap::Parser;
use sshw::cli::{Cli, Prompter, execute, execute_for_runtime};
use sshw::config::{
    AccountConfig, AuthConfig, PrivilegeConfig, PrivilegeMethod, ServerConfig, SshwConfig,
    load_config, save_config,
};
use sshw::credentials::{AuthMaterial, CredentialStore, CredentialStoreHealth};
use sshw::home::{CredentialPurpose, ResolvedHome};
use sshw::ssh::{HostKeyInfo, RunResult, SshClient, SshTarget, TransferResult};
use std::cell::Cell;
use std::collections::BTreeMap;
use std::path::Path;

const KEY: &str =
    "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIB9zU1OEQ2tzYhrXq4/DEjvRNvKv6cU4Xar6gghj1p7D";

struct Store {
    persistent: bool,
    error: Option<&'static str>,
    reads: Cell<usize>,
}

impl CredentialStore for Store {
    fn set_password(&self, _: &str, _: &str, _: &str) -> anyhow::Result<()> {
        panic!("diagnostics must not store passwords")
    }
    fn delete_password(&self, _: &str, _: &str) -> anyhow::Result<()> {
        panic!("diagnostics must not delete passwords")
    }
    fn get_password(&self, _: &str, _: &str) -> anyhow::Result<String> {
        self.reads.set(self.reads.get() + 1);
        match self.error {
            Some(message) => Err(anyhow::Error::new(std::io::Error::new(
                std::io::ErrorKind::PermissionDenied,
                message,
            ))
            .context("backend could not read the credential")),
            None => Ok("disposable-password".into()),
        }
    }
    fn health_check(&self) -> anyhow::Result<CredentialStoreHealth> {
        Ok(CredentialStoreHealth {
            backend: "fixture".into(),
            available: true,
            message: "ok".into(),
        })
    }
    fn is_persistent(&self) -> bool {
        self.persistent
    }
}

struct NoNetwork;
impl SshClient for NoNetwork {
    fn host_key(&self, _: &ServerConfig) -> anyhow::Result<HostKeyInfo> {
        panic!("unexpected network connection")
    }
    fn trust_host(&self, _: &str, _: &ServerConfig, _: &str) -> anyhow::Result<HostKeyInfo> {
        panic!("unexpected host trust change")
    }
    fn run(&self, _: &SshTarget<'_>, _: &AuthMaterial, _: &str) -> anyhow::Result<RunResult> {
        panic!("unexpected network connection")
    }
    fn put(
        &self,
        _: &SshTarget<'_>,
        _: &AuthMaterial,
        _: &Path,
        _: &str,
    ) -> anyhow::Result<TransferResult> {
        panic!("unexpected network connection")
    }
    fn get(
        &self,
        _: &SshTarget<'_>,
        _: &AuthMaterial,
        _: &str,
        _: &Path,
        _: bool,
    ) -> anyhow::Result<TransferResult> {
        panic!("unexpected network connection")
    }
}

struct NoPrompts;
impl Prompter for NoPrompts {
    fn confirm(&mut self, _: &str) -> anyhow::Result<bool> {
        panic!("unexpected confirmation")
    }
    fn password(&mut self, _: &str) -> anyhow::Result<String> {
        panic!("unexpected password prompt")
    }
    fn password_stdin(&mut self) -> anyhow::Result<String> {
        panic!("unexpected stdin read")
    }
}

#[test]
fn clear_persistence_lock_errors_report_path_stage_recovery_and_io_source() {
    let temp = tempfile::tempdir().unwrap();
    let path = temp.path().join("servers.json");
    config(&path, "example.test", 2222, "web", "deploy");
    let lock = temp.path().join(".sshw.lock");
    std::fs::create_dir(&lock).unwrap();
    let before = std::fs::read(&path).unwrap();
    let store = Store {
        persistent: true,
        error: Some("must not query"),
        reads: Cell::new(0),
    };
    for json_output in [false, true] {
        let mut args = vec!["sshw", "privilege", "clear", "web"];
        if json_output {
            args.push("--json");
        }
        let output = execute_for_runtime(
            Cli::try_parse_from(args).unwrap(),
            &path,
            &store,
            &NoNetwork,
            &mut NoPrompts,
        );
        assert_eq!(output.exit_code, 3);
        let message = if json_output {
            serde_json::from_str::<serde_json::Value>(&output.stdout).unwrap()["error"]["message"]
                .as_str()
                .unwrap()
                .to_string()
        } else {
            output.stderr
        };
        assert!(
            message.contains(".sshw.lock")
                && message.contains("open lock file")
                && message.contains("next:"),
            "{message}"
        );
        assert_eq!(std::fs::read(&path).unwrap(), before);
    }
    let error = sshw::storage::acquire_exclusive_lock(&lock).unwrap_err();
    assert!(
        error
            .chain()
            .any(|cause| cause.downcast_ref::<std::io::Error>().is_some())
    );
    assert_eq!(store.reads.get(), 0);
}

#[test]
fn clear_persistence_config_registry_save_errors_report_atomic_stage_and_keep_source() {
    for registry in [false, true] {
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("state-destination");
        std::fs::create_dir(&path).unwrap();
        std::fs::write(path.join("keep"), "original").unwrap();
        let error = if registry {
            sshw::profile::save_registry(&path, &sshw::profile::ProfileRegistry::default())
                .unwrap_err()
        } else {
            save_config(&path, &SshwConfig::default()).unwrap_err()
        };
        let message = error.to_string();
        assert!(
            message.contains("state-destination")
                && message.contains("replace state file atomically")
                && message.contains("next:"),
            "{message}"
        );
        assert!(message.contains(if registry {
            "save profile registry"
        } else {
            "save config"
        }));
        assert!(
            error
                .chain()
                .any(|cause| cause.downcast_ref::<std::io::Error>().is_some())
        );
        assert_eq!(
            std::fs::read_to_string(path.join("keep")).unwrap(),
            "original"
        );
        assert_eq!(std::fs::read_dir(&path).unwrap().count(), 1);
    }
}

#[cfg(unix)]
#[test]
fn clear_persistence_readonly_save_has_the_os_cause_in_human_and_json_messages() {
    use std::os::unix::fs::PermissionsExt;
    let temp = tempfile::tempdir().unwrap();
    let home = temp.path().join("home");
    std::fs::create_dir(&home).unwrap();
    let path = home.join("servers.json");
    config(&path, "example.test", 2222, "web", "deploy");
    let mut file = load_config(&path).unwrap();
    let mut server = file.servers["web"].clone();
    server.accounts.get_mut("deploy").unwrap().auth = AuthConfig::Agent;
    file.servers.insert("other".into(), server);
    save_config(&path, &file).unwrap();
    let lock = home.join(".sshw.lock");
    std::fs::write(&lock, "").unwrap();
    let before = std::fs::read(&path).unwrap();
    std::fs::set_permissions(&home, std::fs::Permissions::from_mode(0o555)).unwrap();
    let result = std::panic::catch_unwind(|| {
        for json_output in [false, true] {
            let store = Store {
                persistent: true,
                error: Some("must not query"),
                reads: Cell::new(0),
            };
            let mut args = vec!["sshw", "default", "other"];
            if json_output {
                args.push("--json");
            }
            let output = execute_for_runtime(
                Cli::try_parse_from(args).unwrap(),
                &path,
                &store,
                &NoNetwork,
                &mut NoPrompts,
            );
            let denied = std::fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(home.join("permission-control"));
            if denied.is_ok() {
                std::fs::remove_file(home.join("permission-control")).unwrap();
                assert_eq!(output.exit_code, 0);
                continue;
            }
            assert_eq!(output.exit_code, 3);
            let message = if json_output {
                serde_json::from_str::<serde_json::Value>(&output.stdout).unwrap()["error"]["message"].as_str().unwrap().to_string()
            } else {
                output.stderr
            };
            assert!(
                message.contains("Permission denied")
                    && message.contains("servers.json")
                    && message.contains("temporary state file")
                    && message.contains("next:"),
                "{message}"
            );
            assert_eq!(std::fs::read(&path).unwrap(), before);
            assert_eq!(store.reads.get(), 0);
        }
    });
    std::fs::set_permissions(&home, std::fs::Permissions::from_mode(0o700)).unwrap();
    if let Err(error) = result {
        std::panic::resume_unwind(error);
    }
}

#[test]
fn default_audit_doctor_reports_path_causes_and_preserves_existing_metadata() {
    for kind in ["missing", "file", "directory"] {
        for json_output in [false, true] {
            let temp = tempfile::tempdir().unwrap();
            let path = temp.path().join("servers.json");
            config(&path, "example.test", 2222, "web", "deploy");
            std::fs::write(
                temp.path().join("known_hosts"),
                format!("[example.test]:2222 {KEY}\n"),
            )
            .unwrap();
            let audit = temp.path().join("audit.jsonl");
            if kind == "file" {
                std::fs::write(&audit, "existing audit data\n").unwrap();
            }
            if kind == "directory" {
                std::fs::create_dir(&audit).unwrap();
            }
            let before = std::fs::read(&path).unwrap();
            let store = Store {
                persistent: true,
                error: None,
                reads: Cell::new(0),
            };
            let mut args = vec!["sshw", "doctor"];
            if json_output {
                args.push("--json");
            }
            let output = execute_for_runtime(
                Cli::try_parse_from(args).unwrap(),
                &path,
                &store,
                &NoNetwork,
                &mut NoPrompts,
            );
            assert_eq!(output.exit_code, 0);
            if kind == "directory" {
                assert!(output.stdout.contains("cannot open existing audit log"));
                assert!(output.stdout.contains("parent directory"));
                if json_output {
                    let body: serde_json::Value = serde_json::from_str(&output.stdout).unwrap();
                    assert_eq!(body["audit_writable"], false);
                    assert_eq!(body["local_checks_passed"], false);
                    assert!(
                        body["audit_message"]
                            .as_str()
                            .unwrap()
                            .contains("audit.jsonl")
                    );
                }
            } else if json_output {
                let body: serde_json::Value = serde_json::from_str(&output.stdout).unwrap();
                assert_eq!(body["audit_writable"], true);
                assert_eq!(body["local_checks_passed"], true);
                assert!(body["audit_message"].is_null());
            }
            assert_eq!(std::fs::read(&path).unwrap(), before);
            if kind == "file" {
                assert_eq!(
                    std::fs::read_to_string(&audit).unwrap(),
                    "existing audit data\n"
                );
            }
            if kind == "missing" {
                assert!(!audit.exists());
            }
            assert!(std::fs::read_dir(temp.path()).unwrap().all(|entry| {
                !entry
                    .unwrap()
                    .file_name()
                    .to_string_lossy()
                    .starts_with(".sshw-audit-check-")
            }));
        }
    }
}

#[test]
fn empty_diagnostics_blank_commands_fail_before_credentials_and_match_preflight() {
    for command in ["", "   ", "\t\r\n", "\u{2003}"] {
        for explicit in [false, true] {
            for json_output in [false, true] {
                let temp = tempfile::tempdir().unwrap();
                let path = temp.path().join("servers.json");
                config(&path, "example.test", 2222, "web", "deploy");
                let before = std::fs::read(&path).unwrap();
                let store = Store {
                    persistent: true,
                    error: Some("must not query"),
                    reads: Cell::new(0),
                };
                for preflight in [false, true] {
                    let mut args = vec!["sshw"];
                    if preflight {
                        args.extend(["policy", "check"]);
                    } else {
                        args.push("run");
                    }
                    if explicit {
                        args.push("web");
                    }
                    args.push(command);
                    if json_output {
                        args.push("--json");
                    }
                    let output = execute_for_runtime(
                        Cli::try_parse_from(args).unwrap(),
                        &path,
                        &store,
                        &NoNetwork,
                        &mut NoPrompts,
                    );
                    assert_eq!(output.exit_code, 9, "{}{}", output.stdout, output.stderr);
                    let rendered = format!("{}{}", output.stdout, output.stderr);
                    assert!(rendered.contains("remote command cannot be empty or whitespace"));
                    assert!(rendered.contains("sshw run"));
                    if json_output {
                        let body: serde_json::Value = serde_json::from_str(&output.stdout).unwrap();
                        assert_eq!(body["error"]["kind"], "usage");
                        assert!(body.get("allowed").is_none());
                    }
                }
                assert_eq!(store.reads.get(), 0);
                assert_eq!(std::fs::read(&path).unwrap(), before);
            }
        }
    }
    let temp = tempfile::tempdir().unwrap();
    let path = temp.path().join("servers.json");
    config(&path, "example.test", 2222, "web", "deploy");
    let store = Store {
        persistent: true,
        error: Some("must not query"),
        reads: Cell::new(0),
    };
    for args in [
        vec!["sshw", "run", "missing", "", "--json"],
        vec!["sshw", "policy", "check", "missing", "", "--json"],
    ] {
        let output = execute_for_runtime(
            Cli::try_parse_from(args).unwrap(),
            &path,
            &store,
            &NoNetwork,
            &mut NoPrompts,
        );
        assert_eq!(output.exit_code, 3);
        assert!(output.stdout.contains("unknown server"));
    }
    for preflight in [false, true] {
        let args = if preflight {
            vec!["sshw", "--policy", "policy", "check", "web", "", "--json"]
        } else {
            vec!["sshw", "--policy", "run", "web", "", "--json"]
        };
        assert_eq!(
            execute_for_runtime(
                Cli::try_parse_from(args).unwrap(),
                &path,
                &store,
                &NoNetwork,
                &mut NoPrompts
            )
            .exit_code,
            7
        );
    }
    std::fs::write(&path, "{broken").unwrap();
    for args in [
        vec!["sshw", "run", "web", "", "--json"],
        vec!["sshw", "policy", "check", "web", "", "--json"],
    ] {
        assert_eq!(
            execute_for_runtime(
                Cli::try_parse_from(args).unwrap(),
                &path,
                &store,
                &NoNetwork,
                &mut NoPrompts
            )
            .exit_code,
            3
        );
    }
    assert_eq!(store.reads.get(), 0);
}

#[test]
fn empty_diagnostics_remote_paths_fail_before_local_io_and_preserve_literal_spaces() {
    for operation in ["put", "get"] {
        for explicit in [false, true] {
            for json_output in [false, true] {
                let temp = tempfile::tempdir().unwrap();
                let path = temp.path().join("servers.json");
                config(&path, "example.test", 2222, "web", "deploy");
                let local = temp.path().join("local");
                let store = Store {
                    persistent: true,
                    error: Some("must not query"),
                    reads: Cell::new(0),
                };
                for preflight in [false, true] {
                    let mut args = vec!["sshw"];
                    if preflight {
                        args.push("policy");
                    }
                    let check = format!("check-{operation}");
                    args.push(if preflight { &check } else { operation });
                    if explicit {
                        args.push("web");
                    }
                    if operation == "put" {
                        args.extend([local.to_str().unwrap(), ""]);
                    } else {
                        args.extend(["", local.to_str().unwrap()]);
                    }
                    if json_output {
                        args.push("--json");
                    }
                    let output = execute_for_runtime(
                        Cli::try_parse_from(args).unwrap(),
                        &path,
                        &store,
                        &NoNetwork,
                        &mut NoPrompts,
                    );
                    assert_eq!(output.exit_code, 9, "{}{}", output.stdout, output.stderr);
                    assert!(
                        format!("{}{}", output.stdout, output.stderr)
                            .contains("remote path cannot be empty")
                    );
                }
                assert!(!local.exists());
                assert_eq!(store.reads.get(), 0);
                if operation == "put" {
                    std::fs::write(&local, "payload").unwrap();
                }
                let mut args = vec!["sshw", "policy"];
                let check = format!("check-{operation}");
                args.extend([&check, "web"]);
                if operation == "put" {
                    args.extend([local.to_str().unwrap(), "   "]);
                } else {
                    args.extend(["   ", local.to_str().unwrap()]);
                }
                args.push("--json");
                let output = execute_for_runtime(
                    Cli::try_parse_from(args).unwrap(),
                    &path,
                    &store,
                    &NoNetwork,
                    &mut NoPrompts,
                );
                assert_eq!(output.exit_code, 0);
                let body: serde_json::Value = serde_json::from_str(&output.stdout).unwrap();
                assert_eq!(body["allowed"], true);
                assert_eq!(body["remote"], "   ");
            }
        }
    }
}

#[test]
fn empty_diagnostics_doctor_uses_the_execution_privilege_password_validator() {
    for password in [
        "",
        "disposable-first\ndisposable-second",
        "disposable-first\rdisposable-second",
        "disposable-valid",
    ] {
        for json_output in [false, true] {
            let temp = tempfile::tempdir().unwrap();
            let path = temp.path().join("servers.json");
            privilege_config(&path, "web", "deploy", "service", PrivilegeMethod::Sudo);
            std::fs::write(
                temp.path().join("known_hosts"),
                format!("[example.test]:2222 {KEY}\n"),
            )
            .unwrap();
            let mut saved = load_config(&path).unwrap();
            saved
                .servers
                .get_mut("web")
                .unwrap()
                .accounts
                .get_mut("deploy")
                .unwrap()
                .auth = AuthConfig::Password {
                credential: ResolvedHome::from_config_path(&path)
                    .namespace
                    .new_account_credential_key(CredentialPurpose::Login, "web", "deploy"),
            };
            saved.servers.get_mut("web").unwrap().host = "example.test".into();
            saved.servers.get_mut("web").unwrap().port = 2222;
            save_config(&path, &saved).unwrap();
            let before = std::fs::read(&path).unwrap();
            let store = sshw::credentials::session_store::SessionOnlyStore::with_session_passwords(
                Some("disposable-login".into()),
                Some(password.into()),
            );
            let mut args = vec!["sshw", "doctor"];
            if json_output {
                args.push("--json");
            }
            let output = execute_for_runtime(
                Cli::try_parse_from(args).unwrap(),
                &path,
                &store,
                &NoNetwork,
                &mut NoPrompts,
            );
            assert_eq!(output.exit_code, 0);
            assert!(!output.stdout.contains("disposable-"));
            let valid = password == "disposable-valid";
            if json_output {
                let body: serde_json::Value = serde_json::from_str(&output.stdout).unwrap();
                assert_eq!(body["ok"], true);
                assert_eq!(body["local_checks_passed"], valid);
                assert_eq!(body["connection_tested"], false);
                let check = body["credential_checks"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .find(|value| value["purpose"] == "privilege")
                    .unwrap();
                assert_eq!(check["status"], if valid { "ready" } else { "invalid" });
                if !valid {
                    assert!(
                        check["next_step"]
                            .as_str()
                            .unwrap()
                            .contains("SSHW_PRIVILEGE_PASSWORD")
                    );
                }
            } else {
                assert!(output.stdout.contains(if valid {
                    "local checks: passed"
                } else {
                    "local checks: action required"
                }));
                if !valid {
                    assert!(output.stdout.contains("invalid privilege credential"));
                }
            }
            assert_eq!(std::fs::read(&path).unwrap(), before);
        }
    }
}

struct DiagnosticLookupStore {
    mode: &'static str,
    reads: Cell<usize>,
}

impl CredentialStore for DiagnosticLookupStore {
    fn set_password(&self, _: &str, _: &str, _: &str) -> anyhow::Result<()> {
        panic!("unexpected store mutation")
    }
    fn delete_password(&self, _: &str, _: &str) -> anyhow::Result<()> {
        panic!("unexpected store mutation")
    }
    fn get_password(&self, _: &str, _: &str) -> anyhow::Result<String> {
        self.reads.set(self.reads.get() + 1);
        match self.mode {
            "missing" => Err(anyhow::Error::new(keyring_core::Error::NoEntry).context("entry not found")),
            "ready" => Ok("disposable-valid".into()),
            _ => Err(anyhow::Error::new(std::io::Error::new(
                if self.mode == "not_found" { std::io::ErrorKind::NotFound } else { std::io::ErrorKind::PermissionDenied },
                "store locked token=lookup-secret\n-----BEGIN PRIVATE KEY-----\nlookup-private-key\n-----END PRIVATE KEY-----"))
                .context("cannot reach the credential service")),
        }
    }
    fn health_check(&self) -> anyhow::Result<CredentialStoreHealth> {
        Ok(CredentialStoreHealth {
            backend: "fixture".into(),
            available: self.mode != "unavailable",
            message: "fixture backend health".into(),
        })
    }
}

#[test]
fn empty_diagnostics_doctor_distinguishes_typed_absence_from_unavailable_lookups() {
    for mode in ["missing", "unavailable", "not_found", "ready"] {
        for json_output in [false, true] {
            let temp = tempfile::tempdir().unwrap();
            let path = temp.path().join("servers.json");
            privilege_config(
                &path,
                "-stage west",
                "operator's $literal",
                "-service's $literal",
                PrivilegeMethod::Su,
            );
            let mut saved = load_config(&path).unwrap();
            saved
                .servers
                .get_mut("-stage west")
                .unwrap()
                .accounts
                .get_mut("operator's $literal")
                .unwrap()
                .auth = AuthConfig::Password {
                credential: ResolvedHome::from_config_path(&path)
                    .namespace
                    .new_account_credential_key(
                        CredentialPurpose::Login,
                        "-stage west",
                        "operator's $literal",
                    ),
            };
            save_config(&path, &saved).unwrap();
            let before = std::fs::read(&path).unwrap();
            let store = DiagnosticLookupStore {
                mode,
                reads: Cell::new(0),
            };
            let mut args = vec!["sshw", "doctor"];
            if json_output {
                args.push("--json");
            }
            let output = execute_for_runtime(
                Cli::try_parse_from(args).unwrap(),
                &path,
                &store,
                &NoNetwork,
                &mut NoPrompts,
            );
            assert_eq!(output.exit_code, 0);
            let status = if mode == "missing" {
                "missing"
            } else if mode == "ready" {
                "ready"
            } else {
                "unavailable"
            };
            assert!(
                !output.stdout.contains("lookup-secret")
                    && !output.stdout.contains("lookup-private-key")
            );
            if json_output {
                let body: serde_json::Value = serde_json::from_str(&output.stdout).unwrap();
                assert_eq!(
                    body["missing_credentials"],
                    if mode == "missing" {
                        serde_json::json!(["-stage west/operator's $literal"])
                    } else {
                        serde_json::json!([])
                    }
                );
                let checks = body["credential_checks"].as_array().unwrap();
                assert_eq!(checks.len(), 2);
                for check in checks {
                    assert_eq!(check["status"], status);
                    assert_eq!(check["user"], "operator's $literal");
                    if status == "unavailable" {
                        assert!(
                            check["message"]
                                .as_str()
                                .unwrap()
                                .contains("cannot reach the credential service")
                        );
                        assert!(
                            check["next_step"]
                                .as_str()
                                .unwrap()
                                .contains("rerun sshw doctor")
                        );
                        assert!(
                            !check["next_step"]
                                .as_str()
                                .unwrap()
                                .contains("privilege set")
                        );
                    }
                }
            } else if status == "unavailable" {
                assert!(
                    output.stdout.contains("cannot read login credential")
                        && output.stdout.contains("cannot read privilege credential")
                );
                assert!(
                    !output.stdout.contains("missing login credential")
                        && !output.stdout.contains("missing privilege credential")
                );
                assert!(
                    output
                        .stdout
                        .contains("cannot reach the credential service")
                );
            }
            assert_eq!(store.reads.get(), 2);
            assert_eq!(std::fs::read(&path).unwrap(), before);
        }
    }
}

fn config(path: &Path, host: &str, port: u16, name: &str, user: &str) {
    let namespace = ResolvedHome::from_config_path(path).namespace;
    save_config(
        path,
        &SshwConfig {
            default: Some(name.into()),
            servers: BTreeMap::from([(
                name.into(),
                ServerConfig {
                    host: host.into(),
                    port,
                    default_user: user.into(),
                    accounts: BTreeMap::from([(
                        user.into(),
                        AccountConfig {
                            auth: AuthConfig::Password {
                                credential: namespace.new_account_credential_key(
                                    CredentialPurpose::Login,
                                    name,
                                    user,
                                ),
                            },
                            privilege: None,
                        },
                    )]),
                },
            )]),
            ..SshwConfig::default()
        },
    )
    .unwrap();
}

#[test]
fn doctor_checks_known_hosts_contents_without_connections_or_file_changes() {
    for (content, expected) in [
        (None, None),
        (Some("".into()), Some(false)),
        (Some("# comment only\n".into()), Some(false)),
        (Some("this is not a known_hosts entry\n".into()), None),
        (Some(format!("unrelated.test {KEY}\n")), Some(false)),
        (Some(format!("[example.test]:2222 {KEY}\n")), Some(true)),
    ] {
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("servers.json");
        config(&path, "example.test", 2222, "web", "deploy");
        let known = temp.path().join("known_hosts");
        if let Some(content) = &content {
            std::fs::write(&known, content).unwrap();
        }
        let before = std::fs::read(&path).unwrap();
        let store = Store {
            persistent: true,
            error: None,
            reads: Cell::new(0),
        };
        let output = execute_for_runtime(
            Cli::try_parse_from(["sshw", "doctor", "--json"]).unwrap(),
            &path,
            &store,
            &NoNetwork,
            &mut NoPrompts,
        );
        assert_eq!(output.exit_code, 0, "{output:?}");
        let value: serde_json::Value = serde_json::from_str(&output.stdout).unwrap();
        assert_eq!(value["ok"], true);
        assert_eq!(value["connection_tested"], false);
        assert_eq!(
            value["local_checks_passed"],
            expected == Some(true),
            "{value}"
        );
        assert_eq!(
            value["host_trust"][0]["entry_present"],
            serde_json::json!(expected)
        );
        assert_eq!(value["host_trust"][0]["key_match_checked"], false);
        assert_eq!(
            value["issues"]
                .as_array()
                .unwrap()
                .iter()
                .any(|issue| issue["kind"] == "host_trust"),
            expected != Some(true)
        );
        let human = execute_for_runtime(
            Cli::try_parse_from(["sshw", "doctor"]).unwrap(),
            &path,
            &store,
            &NoNetwork,
            &mut NoPrompts,
        );
        assert!(
            human.stdout.contains("remote key not checked"),
            "{}",
            human.stdout
        );
        assert_eq!(std::fs::read(&path).unwrap(), before);
        assert_eq!(std::fs::read_to_string(&known).ok(), content);
        assert!(!temp.path().join("audit.jsonl").exists());
    }
}

#[test]
fn doctor_keeps_host_entries_separate_and_distinguishes_ports() {
    let temp = tempfile::tempdir().unwrap();
    let path = temp.path().join("servers.json");
    config(&path, "example.test", 2222, "web", "deploy");
    let mut file = load_config(&path).unwrap();
    let namespace = ResolvedHome::from_config_path(&path).namespace;
    for (name, host, port) in [("ipv6", "2001:db8::1", 2222), ("other", "other.test", 22)] {
        let mut server = file.servers["web"].clone();
        server.host = host.into();
        server.port = port;
        server.accounts.get_mut("deploy").unwrap().auth = AuthConfig::Password {
            credential: namespace.new_account_credential_key(
                CredentialPurpose::Login,
                name,
                "deploy",
            ),
        };
        file.servers.insert(name.into(), server);
    }
    save_config(&path, &file).unwrap();
    let hashed = "|1|MDEyMzQ1Njc4OTAxMjM0NTY3ODk=|fV91fVHrhuYFIPiFJeEhE3eNSjs=";
    std::fs::write(
        temp.path().join("known_hosts"),
        format!("[example.test]:22 {KEY}\n{hashed} {KEY}\nother.test {KEY}\n"),
    )
    .unwrap();
    let store = Store {
        persistent: true,
        error: None,
        reads: Cell::new(0),
    };
    let output = execute_for_runtime(
        Cli::try_parse_from(["sshw", "doctor", "--json"]).unwrap(),
        &path,
        &store,
        &NoNetwork,
        &mut NoPrompts,
    );
    let value: serde_json::Value = serde_json::from_str(&output.stdout).unwrap();
    let entries = value["host_trust"].as_array().unwrap();
    assert_eq!(entries.len(), 3);
    for entry in entries {
        assert_eq!(entry["entry_present"], entry["server"] != "web");
        assert_eq!(entry["key_match_checked"], false);
    }
    assert_eq!(value["local_checks_passed"], false);
    assert_eq!(value["issues"].as_array().unwrap().len(), 1);
    assert!(
        value["issues"][0]["message"]
            .as_str()
            .unwrap()
            .contains("web")
    );
}

#[test]
fn login_errors_preserve_the_cause_and_backend_specific_recovery() {
    for persistent in [false, true] {
        for operation in ["run", "put", "get"] {
            for json in [false, true] {
                let temp = tempfile::tempdir().unwrap();
                let path = temp.path().join("servers.json");
                config(&path, "example.test", 2222, "web", "deploy");
                let local = temp.path().join("local.txt");
                std::fs::write(&local, "upload fixture").unwrap();
                let local = local.to_str().unwrap();
                let mut args = match operation {
                    "run" => vec!["sshw", "run", "web", "hostname"],
                    "put" => vec!["sshw", "put", "web", local, "/tmp/file"],
                    _ => vec!["sshw", "get", "web", "/tmp/file", local, "--yes"],
                };
                if json {
                    args.push("--json");
                }
                let before = std::fs::read(&path).unwrap();
                let store = Store {
                    persistent,
                    error: Some("credential store locked; permission denied"),
                    reads: Cell::new(0),
                };
                let output = execute_for_runtime(
                    Cli::try_parse_from(args).unwrap(),
                    &path,
                    &store,
                    &NoNetwork,
                    &mut NoPrompts,
                );
                assert_eq!(output.exit_code, 4, "{output:?}");
                let rendered = format!("{}{}", output.stdout, output.stderr);
                assert!(
                    rendered.contains("credential store locked; permission denied"),
                    "{rendered}"
                );
                assert!(
                    rendered.contains("web")
                        && rendered.contains("deploy")
                        && rendered.contains("same home/profile"),
                    "{rendered}"
                );
                assert!(
                    rendered.contains(if persistent {
                        "sshw doctor"
                    } else {
                        "SSHW_PASSWORD"
                    }),
                    "{rendered}"
                );
                if persistent {
                    assert!(
                        rendered.contains("account add")
                            && rendered.contains("--force")
                            && rendered.contains("--password-stdin")
                    );
                }
                assert!(!rendered.contains("missing credential entry for"));
                if json {
                    let value: serde_json::Value = serde_json::from_str(&output.stdout).unwrap();
                    assert_eq!(value["error"]["kind"], "auth");
                    assert!(
                        value["error"]["causes"]
                            .as_array()
                            .unwrap()
                            .iter()
                            .any(|cause| cause
                                .as_str()
                                .unwrap()
                                .contains("credential store locked; permission denied"))
                    );
                }
                assert_eq!(store.reads.get(), 1);
                assert_eq!(std::fs::read(&path).unwrap(), before);
            }
        }
    }
}

#[test]
fn login_error_redacts_separate_causes_and_preserves_quoted_recovery_arguments() {
    let temp = tempfile::tempdir().unwrap();
    let path = temp.path().join("servers.json");
    let name = "-stage west";
    let user = "operator's $literal";
    config(&path, "example.test", 2222, name, user);
    let store = Store {
        persistent: true,
        error: Some(
            "token=disposable-token\n-----BEGIN PRIVATE KEY-----\ndisposable-key\n-----END PRIVATE KEY-----\nbackend unavailable",
        ),
        reads: Cell::new(0),
    };
    for json in [false, true] {
        let mut args = vec!["sshw", "run"];
        if json {
            args.push("--json");
        }
        args.extend(["--", name, "hostname"]);
        let output = execute_for_runtime(
            Cli::try_parse_from(args).unwrap(),
            &path,
            &store,
            &NoNetwork,
            &mut NoPrompts,
        );
        let rendered = format!("{}{}", output.stdout, output.stderr);
        assert_eq!(output.exit_code, 4);
        assert!(
            !rendered.contains("disposable-token")
                && !rendered.contains("disposable-key")
                && !rendered.contains("BEGIN PRIVATE KEY")
        );
        let message = if json {
            serde_json::from_str::<serde_json::Value>(&output.stdout).unwrap()["error"]["message"]
                .as_str()
                .unwrap()
                .to_owned()
        } else {
            output.stderr
        };
        assert!(
            message.contains("backend unavailable")
                && message.contains("sshw doctor")
                && message.contains("--password-stdin")
        );
        assert!(message.contains("-- '-stage west'"));
        assert!(message.contains(if cfg!(windows) {
            "'operator''s $literal'"
        } else {
            "'operator'\"'\"'s $literal'"
        }));
    }
}

fn privilege_config(path: &Path, name: &str, login: &str, target: &str, method: PrivilegeMethod) {
    config(path, "example.test", 2222, name, login);
    let mut file = load_config(path).unwrap();
    let account = file
        .servers
        .get_mut(name)
        .unwrap()
        .accounts
        .get_mut(login)
        .unwrap();
    account.auth = AuthConfig::Agent;
    account.privilege = Some(PrivilegeConfig {
        method,
        user: target.into(),
        no_password: false,
        credential: Some(
            ResolvedHome::from_config_path(path)
                .namespace
                .new_account_credential_key(CredentialPurpose::Privilege, name, login),
        ),
    });
    save_config(path, &file).unwrap();
}

#[test]
fn privilege_lookup_errors_show_the_cause_and_backend_specific_recovery() {
    for method in [PrivilegeMethod::Sudo, PrivilegeMethod::Su] {
        for persistent in [false, true] {
            let temp = tempfile::tempdir().unwrap();
            let path = temp.path().join("servers.json");
            privilege_config(&path, "web", "deploy", "service", method);
            let before = std::fs::read(&path).unwrap();
            let store = Store {
                persistent,
                error: Some("credential store locked; permission denied"),
                reads: Cell::new(0),
            };
            for json in [false, true] {
                let mut args = vec!["sshw", "run", "web", "whoami", "--as-root"];
                if json {
                    args.push("--json");
                }
                let output = execute_for_runtime(
                    Cli::try_parse_from(args).unwrap(),
                    &path,
                    &store,
                    &NoNetwork,
                    &mut NoPrompts,
                );
                assert_eq!(output.exit_code, 4, "{output:?}");
                let value = json
                    .then(|| serde_json::from_str::<serde_json::Value>(&output.stdout).unwrap());
                let message = value
                    .as_ref()
                    .map(|v| v["error"]["message"].as_str().unwrap())
                    .unwrap_or(&output.stderr);
                assert!(
                    message.contains("credential store locked; permission denied"),
                    "{message}"
                );
                assert!(
                    message.contains("web")
                        && message.contains("deploy")
                        && message.contains("service")
                );
                assert!(message.contains(if method == PrivilegeMethod::Sudo {
                    "sudo"
                } else {
                    "su"
                }));
                assert!(message.contains("same home/profile"));
                if persistent {
                    assert!(
                        message.contains("sshw doctor")
                            && message.contains("if the entry is missing")
                            && message.contains("privilege set")
                    );
                    assert!(message.contains("--force") && message.contains("--password-stdin"));
                } else {
                    assert!(message.contains("SSHW_PRIVILEGE_PASSWORD"));
                }
                assert!(!message.contains("missing credential entry for"));
                if let Some(value) = value {
                    assert_eq!(value["error"]["kind"], "auth");
                    assert!(
                        value["error"]["causes"]
                            .as_array()
                            .unwrap()
                            .iter()
                            .any(|c| c
                                .as_str()
                                .unwrap()
                                .contains("credential store locked; permission denied"))
                    );
                }
            }
            assert_eq!(store.reads.get(), 2);
            let error = execute(
                Cli::try_parse_from(["sshw", "run", "web", "whoami", "--as-root"]).unwrap(),
                &path,
                &store,
                &NoNetwork,
                &mut NoPrompts,
            )
            .unwrap_err();
            assert!(error.chain().any(|cause| {
                cause
                    .downcast_ref::<std::io::Error>()
                    .is_some_and(|error| error.kind() == std::io::ErrorKind::PermissionDenied)
            }));
            assert_eq!(std::fs::read(&path).unwrap(), before);
        }
    }
}

#[test]
fn privilege_lookup_error_redacts_causes_and_keeps_quoted_recovery_targets() {
    let temp = tempfile::tempdir().unwrap();
    let path = temp.path().join("servers.json");
    privilege_config(
        &path,
        "-stage west",
        "operator's $literal",
        "-service's $target",
        PrivilegeMethod::Su,
    );
    let store = Store {
        persistent: true,
        error: Some(
            "token=disposable-token\n-----BEGIN PRIVATE KEY-----\ndisposable-key\n-----END PRIVATE KEY-----\nbackend unavailable",
        ),
        reads: Cell::new(0),
    };
    for json in [false, true] {
        let mut args = vec!["sshw", "run", "--as-root"];
        if json {
            args.push("--json");
        }
        args.extend(["--", "-stage west", "whoami"]);
        let output = execute_for_runtime(
            Cli::try_parse_from(args).unwrap(),
            &path,
            &store,
            &NoNetwork,
            &mut NoPrompts,
        );
        assert_eq!(output.exit_code, 4);
        let rendered = format!("{}{}", output.stdout, output.stderr);
        assert!(
            !rendered.contains("disposable-token")
                && !rendered.contains("disposable-key")
                && !rendered.contains("BEGIN PRIVATE KEY")
        );
        let message = if json {
            serde_json::from_str::<serde_json::Value>(&output.stdout).unwrap()["error"]["message"]
                .as_str()
                .unwrap()
                .to_owned()
        } else {
            output.stderr
        };
        assert!(
            message.contains("backend unavailable")
                && message.contains("--password-stdin")
                && message.contains("--method su")
        );
        assert!(message.contains("-- '-stage west'"));
        assert!(message.contains(if cfg!(windows) {
            "--account='operator''s $literal'"
        } else {
            "--account='operator'\"'\"'s $literal'"
        }));
        assert!(message.contains(if cfg!(windows) {
            "--user='-service''s $target'"
        } else {
            "--user='-service'\"'\"'s $target'"
        }));
    }
}

#[test]
fn policy_management_reports_file_saved_and_forced_state_without_mutation() {
    for enabled in [None, Some(false), Some(true)] {
        for forced in [false, true] {
            let temp = tempfile::tempdir().unwrap();
            let path = temp.path().join("servers.json");
            config(&path, "example.test", 2222, "web", "deploy");
            let policy = temp.path().join("policy.json");
            if let Some(enabled) = enabled {
                std::fs::write(
                    &policy,
                    format!("{{\"version\":2,\"enabled\":{enabled}}}\n"),
                )
                .unwrap();
            }
            let before = std::fs::read(&policy).ok();
            let store = Store {
                persistent: false,
                error: None,
                reads: Cell::new(0),
            };
            for json in [false, true] {
                let mut args = vec!["sshw"];
                if forced {
                    args.push("--policy");
                }
                args.extend(["policy", "show"]);
                if json {
                    args.push("--json");
                }
                let output = execute_for_runtime(
                    Cli::try_parse_from(args).unwrap(),
                    &path,
                    &store,
                    &NoNetwork,
                    &mut NoPrompts,
                );
                assert_eq!(output.exit_code, 0, "{output:?}");
                let enforced = enabled.unwrap_or(false) || forced;
                if json {
                    let value: serde_json::Value = serde_json::from_str(&output.stdout).unwrap();
                    assert_eq!(value["present"], enabled.is_some());
                    assert_eq!(value["policy"]["enabled"], enabled.unwrap_or(false));
                    assert_eq!(value["enforced"], enforced);
                    assert_eq!(value["forced"], forced);
                } else {
                    assert!(
                        output.stdout.contains(if enabled.is_some() {
                            "policy file: present"
                        } else {
                            "policy file: missing"
                        }),
                        "{}",
                        output.stdout
                    );
                    assert!(output.stdout.contains(&format!(
                            "saved enabled: {}",
                            enabled
                                .map(|v| v.to_string())
                                .unwrap_or_else(|| "not configured".into())
                        )));
                    assert!(output.stdout.contains(if enforced {
                        "policy enforcement: on"
                    } else {
                        "policy enforcement: off"
                    }));
                    assert_eq!(output.stdout.contains("forced by --policy"), forced);
                    if enabled.is_none() {
                        assert!(
                            output.stdout.contains("sshw policy init")
                                && output.stdout.contains("same home/profile")
                        );
                    }
                }
            }
            assert_eq!(std::fs::read(&policy).ok(), before);
            assert_eq!(store.reads.get(), 0);
        }
    }
}

#[test]
fn policy_disable_reports_force_and_preserves_unchanged_file() {
    let temp = tempfile::tempdir().unwrap();
    let path = temp.path().join("servers.json");
    config(&path, "example.test", 2222, "web", "deploy");
    let policy = temp.path().join("policy.json");
    std::fs::write(&policy, "{ \"version\":1, \"enabled\":true }\n").unwrap();
    let store = Store {
        persistent: false,
        error: None,
        reads: Cell::new(0),
    };
    let output = execute_for_runtime(
        Cli::try_parse_from(["sshw", "--policy", "policy", "disable"]).unwrap(),
        &path,
        &store,
        &NoNetwork,
        &mut NoPrompts,
    );
    assert_eq!(output.exit_code, 0);
    assert!(
        output.stdout.contains("saved enabled: false")
            && output
                .stdout
                .contains("policy enforcement: on (forced by --policy)")
    );
    assert!(
        output
            .stdout
            .contains("remove --policy from the invocation")
    );
    let before = std::fs::read(&policy).unwrap();
    for forced in [false, true] {
        let mut args = vec!["sshw"];
        if forced {
            args.push("--policy");
        }
        args.extend(["policy", "disable", "--json"]);
        let output = execute_for_runtime(
            Cli::try_parse_from(args).unwrap(),
            &path,
            &store,
            &NoNetwork,
            &mut NoPrompts,
        );
        assert_eq!(output.exit_code, 0);
        let value: serde_json::Value = serde_json::from_str(&output.stdout).unwrap();
        assert_eq!(value["changed"], false);
        assert_eq!(value["change"], "unchanged");
        assert_eq!(value["enforced"], forced);
        assert_eq!(value["forced"], forced);
        assert_eq!(value["policy"]["enabled"], false);
        assert_eq!(std::fs::read(&policy).unwrap(), before);
    }
    assert_eq!(store.reads.get(), 0);
}
