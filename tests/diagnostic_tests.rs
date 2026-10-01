use clap::Parser;
use sshw::cli::{Cli, Prompter, execute_for_runtime};
use sshw::config::{AccountConfig, AuthConfig, ServerConfig, SshwConfig, load_config, save_config};
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
