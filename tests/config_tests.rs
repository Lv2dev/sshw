use sshw::config::{
    AccountConfig, AuthConfig, CredentialBackend, PrivilegeConfig, PrivilegeMethod, ServerConfig,
    SshwConfig, load_config, load_config_with_revision, save_config, save_config_if_unchanged,
    validate_config_credential_references,
};
use sshw::home::{CredentialNamespace, CredentialPurpose};
use std::fs;

#[test]
fn new_config_starts_empty() {
    let config = SshwConfig::default();

    assert_eq!(config.version, 2);
    assert!(config.default.is_none());
    assert!(config.servers.is_empty());
}

#[test]
fn config_serializes_password_and_agent_auth_without_secrets() {
    let mut config = SshwConfig::default();
    config.servers.insert(
        "server-alpha".to_string(),
        ServerConfig::single_account(
            "192.0.2.10",
            2222,
            "deploy",
            AuthConfig::Password {
                credential: "sshw:server-alpha".to_string(),
            },
        ),
    );
    config.servers.insert(
        "server-beta".to_string(),
        ServerConfig::single_account("192.0.2.11", 2222, "deploy", AuthConfig::Agent),
    );
    config
        .servers
        .get_mut("server-alpha")
        .unwrap()
        .account_mut("deploy")
        .unwrap()
        .privilege = Some(PrivilegeConfig {
        method: PrivilegeMethod::Sudo,
        user: "root".to_string(),
        credential: Some("sshw:default:privilege:server-alpha".to_string()),
        no_password: false,
    });

    let json = serde_json::to_string_pretty(&config).unwrap();

    assert!(json.contains("\"type\": \"password\""));
    assert!(json.contains("\"credential\": \"sshw:server-alpha\""));
    assert!(json.contains("\"type\": \"agent\""));
    assert!(json.contains("\"method\": \"sudo\""));
    assert!(json.contains("\"user\": \"root\""));
    assert!(json.contains("\"credential\": \"sshw:default:privilege:server-alpha\""));
    assert!(!json.contains("YOUR_PASSWORD"));
    assert!(!json.contains("ROOT_PASSWORD"));
    assert!(!json.contains("passphrase"));
    assert!(!json.contains("private_key"));
}

#[test]
fn missing_config_loads_default() {
    let temp = tempfile::tempdir().unwrap();
    let path = temp.path().join("missing").join("servers.json");

    let config = load_config(&path).unwrap();

    assert_eq!(config, SshwConfig::default());
}

#[test]
fn config_defaults_to_native_backend_and_round_trips_session() {
    assert_eq!(
        SshwConfig::default().credential_backend,
        CredentialBackend::Native
    );

    // A config file without the field loads as native (backward compatible).
    let legacy: SshwConfig =
        serde_json::from_str(r#"{"version":1,"default":null,"servers":{}}"#).unwrap();
    assert_eq!(legacy.credential_backend, CredentialBackend::Native);
    assert_eq!(legacy.version, 2);

    let temp = tempfile::tempdir().unwrap();
    let path = temp.path().join("servers.json");
    let config = SshwConfig {
        credential_backend: CredentialBackend::SessionOnly,
        ..SshwConfig::default()
    };
    save_config(&path, &config).unwrap();

    assert_eq!(
        load_config(&path).unwrap().credential_backend,
        CredentialBackend::SessionOnly
    );
}

#[test]
fn corrupt_config_reports_config_error() {
    let temp = tempfile::tempdir().unwrap();
    let path = temp.path().join("servers.json");
    std::fs::write(&path, "{ not valid json").unwrap();

    let err = load_config(&path).unwrap_err();

    assert!(err.to_string().contains("failed to load config"));
}

#[test]
fn config_rejects_unknown_fields_at_root_and_nested_levels() {
    let temp = tempfile::tempdir().unwrap();
    let path = temp.path().join("servers.json");
    fs::write(
        &path,
        r#"{
            "version": 1,
            "default": null,
            "servers": {},
            "credentials_backend": "session_only"
        }"#,
    )
    .unwrap();

    let root_err = load_config(&path).unwrap_err();
    assert!(root_err.to_string().contains("unknown field"));

    fs::write(
        &path,
        r#"{
            "version": 1,
            "default": "web",
            "servers": {
                "web": {
                    "host": "192.0.2.10",
                    "port": 22,
                    "user": "deploy",
                    "auth": { "type": "agent", "unexpected": true }
                }
            }
        }"#,
    )
    .unwrap();
    let nested_err = load_config(&path).unwrap_err();
    assert!(nested_err.to_string().contains("unknown field"));

    fs::write(
        &path,
        r#"{
            "version": 1,
            "default": "web",
            "servers": {
                "web": {
                    "host": "192.0.2.10",
                    "port": 22,
                    "user": "deploy",
                    "auth": { "type": "agent" },
                    "unexpected": true
                }
            },
            "privileges": {
                "web": {
                    "method": "sudo",
                    "user": "root",
                    "credential": "synthetic",
                    "unexpected": true
                }
            }
        }"#,
    )
    .unwrap();
    let nested_err = load_config(&path).unwrap_err();
    assert!(nested_err.to_string().contains("unknown field"));

    fs::write(
        &path,
        r#"{
            "version": 1,
            "default": "web",
            "servers": {
                "web": {
                    "host": "192.0.2.10",
                    "port": 22,
                    "user": "deploy",
                    "auth": { "type": "agent" }
                }
            },
            "privileges": {
                "web": {
                    "method": "sudo",
                    "user": "root",
                    "credential": "synthetic",
                    "unexpected": true
                }
            }
        }"#,
    )
    .unwrap();
    let privilege_err = load_config(&path).unwrap_err();
    assert!(privilege_err.to_string().contains("unknown field"));

    fs::write(
        &path,
        r#"{
            "version": 2,
            "default": "web",
            "servers": {
                "web": {
                    "host": "192.0.2.10",
                    "port": 22,
                    "default_user": "deploy",
                    "accounts": {
                        "deploy": {
                            "auth": { "type": "agent" },
                            "unexpected": true
                        }
                    }
                }
            }
        }"#,
    )
    .unwrap();
    let account_err = load_config(&path).unwrap_err();
    assert!(account_err.to_string().contains("unknown field"));
}

#[test]
fn config_rejects_unsupported_future_version() {
    let temp = tempfile::tempdir().unwrap();
    let path = temp.path().join("servers.json");
    fs::write(
        &path,
        r#"{
            "version": 3,
            "default": null,
            "servers": {}
        }"#,
    )
    .unwrap();

    let err = load_config(&path).unwrap_err();

    assert!(err.to_string().contains("unsupported config version 3"));
    assert!(err.to_string().contains("supported versions are 1 and 2"));
}

#[cfg(unix)]
#[test]
fn dangling_config_symlink_is_not_treated_as_missing() {
    use std::os::unix::fs::symlink;

    let temp = tempfile::tempdir().unwrap();
    let path = temp.path().join("servers.json");
    symlink(temp.path().join("missing-servers.json"), &path).unwrap();

    let err = load_config(&path).unwrap_err();

    assert!(err.to_string().contains("failed to load config"));
}

#[test]
fn config_saves_and_loads_round_trip() {
    let temp = tempfile::tempdir().unwrap();
    let path = temp.path().join("nested").join("servers.json");
    let mut servers = std::collections::BTreeMap::new();
    servers.insert(
        "server-alpha".to_string(),
        ServerConfig::single_account(
            "192.0.2.10",
            2222,
            "deploy",
            AuthConfig::Password {
                credential: "sshw:server-alpha".to_string(),
            },
        ),
    );
    let config = SshwConfig {
        default: Some("server-alpha".to_string()),
        servers,
        ..SshwConfig::default()
    };

    save_config(&path, &config).unwrap();
    let loaded = load_config(&path).unwrap();

    assert_eq!(loaded, config);
}

#[test]
fn stale_config_revision_cannot_overwrite_external_change() {
    let temp = tempfile::tempdir().unwrap();
    let path = temp.path().join("servers.json");
    save_config(&path, &SshwConfig::default()).unwrap();

    let (mut stale, revision) = load_config_with_revision(&path).unwrap();
    let external = SshwConfig {
        default: Some("external".to_string()),
        ..SshwConfig::default()
    };
    save_config(&path, &external).unwrap();

    stale.default = Some("stale".to_string());
    let err = save_config_if_unchanged(&path, &stale, &revision).unwrap_err();

    assert!(err.to_string().contains("changed concurrently"));
    assert_eq!(load_config(&path).unwrap(), external);
}

#[test]
fn credential_references_accept_expected_legacy_and_v2_keys() {
    let namespace = CredentialNamespace::profile("default");
    let mut config = SshwConfig::default();
    config.servers.insert(
        "legacy".to_string(),
        ServerConfig::single_account(
            "192.0.2.10",
            22,
            "deploy",
            AuthConfig::Password {
                credential: namespace.legacy_credential_key("legacy"),
            },
        ),
    );
    config.servers.insert(
        "modern".to_string(),
        ServerConfig::single_account(
            "192.0.2.11",
            22,
            "deploy",
            AuthConfig::Password {
                credential: namespace.credential_key_v2(
                    CredentialPurpose::Login,
                    "modern",
                    "0000000000000001",
                ),
            },
        ),
    );
    config
        .servers
        .get_mut("modern")
        .unwrap()
        .account_mut("deploy")
        .unwrap()
        .privilege = Some(PrivilegeConfig {
        method: PrivilegeMethod::Sudo,
        user: "root".to_string(),
        credential: Some(namespace.credential_key_v2(
            CredentialPurpose::Privilege,
            "modern",
            "0000000000000002",
        )),
        no_password: false,
    });

    validate_config_credential_references(&config, &namespace).unwrap();
}

#[test]
fn privilege_modes_preserve_legacy_shape_and_roundtrip_passwordless_settings() {
    let legacy = serde_json::json!({"method":"sudo","user":"root","credential":"existing-key"});
    let parsed: PrivilegeConfig = serde_json::from_value(legacy.clone()).unwrap();
    assert!(!parsed.no_password);
    assert_eq!(parsed.credential.as_deref(), Some("existing-key"));
    assert_eq!(serde_json::to_value(parsed).unwrap(), legacy);

    let passwordless = serde_json::json!({"method":"sudo","user":"service","no_password":true});
    let parsed: PrivilegeConfig = serde_json::from_value(passwordless.clone()).unwrap();
    assert!(parsed.no_password);
    assert_eq!(parsed.credential, None);
    assert_eq!(serde_json::to_value(&parsed).unwrap(), passwordless);
    let mut config = SshwConfig::default();
    let mut server = ServerConfig::single_account("localhost", 22, "ops", AuthConfig::Agent);
    server.account_mut("ops").unwrap().privilege = Some(parsed);
    config.servers.insert("web".into(), server);
    validate_config_credential_references(&config, &CredentialNamespace::profile("default"))
        .unwrap();
    let serialized = serde_json::to_string(&config).unwrap();
    assert_eq!(
        serde_json::from_str::<SshwConfig>(&serialized).unwrap(),
        config
    );
}

#[test]
fn privilege_modes_reject_ambiguous_or_unsupported_authentication() {
    for value in [
        serde_json::json!({"method":"sudo"}),
        serde_json::json!({"method":"su","no_password":true}),
        serde_json::json!({"method":"sudo","credential":"key","no_password":true}),
        serde_json::json!({"method":"sudo","credential":"","no_password":true}),
        serde_json::json!({"method":"sudo","no_password":false}),
        serde_json::json!({"method":"sudo","no_password":"true"}),
        serde_json::json!({"method":"sudo","no_password":true,"future_auth":true}),
    ] {
        assert!(
            serde_json::from_value::<PrivilegeConfig>(value.clone()).is_err(),
            "{value}"
        );
    }
}

#[test]
fn privilege_target_validation_rejects_empty_and_control_users_in_all_formats() {
    for user in ["", "   ", "service\nextra", "service\r", "service\0"] {
        for (method, no_password) in [("sudo", false), ("su", false), ("sudo", true)] {
            let mut value = serde_json::json!({"method":method,"user":user});
            if no_password {
                value["no_password"] = serde_json::json!(true);
            } else {
                value["credential"] = serde_json::json!("existing-key");
            }
            assert!(serde_json::from_value::<PrivilegeConfig>(value.clone()).is_err());
            for config in [
                serde_json::json!({"version":1,"default":"web","servers":{"web":{"host":"localhost","port":22,"user":"deploy","auth":{"type":"agent"}}},"privileges":{"web":value}}),
                serde_json::json!({"version":2,"default":"web","servers":{"web":{"host":"localhost","port":22,"default_user":"deploy","accounts":{"deploy":{"auth":{"type":"agent"},"privilege":value}}}}}),
            ] {
                assert!(serde_json::from_value::<SshwConfig>(config).is_err());
            }
            let mut privilege = PrivilegeConfig {
                method: PrivilegeMethod::Sudo,
                user: user.into(),
                credential: None,
                no_password: true,
            };
            assert!(privilege.validate().is_err());
            privilege.user = "service's $literal".into();
            privilege.validate().unwrap();
        }
    }
}

#[test]
fn config_relationships_reject_dangling_server_and_user_defaults() {
    let namespace = CredentialNamespace::profile("default");
    let mut config = SshwConfig {
        default: Some("missing".to_string()),
        ..SshwConfig::default()
    };

    let dangling_default = validate_config_credential_references(&config, &namespace).unwrap_err();
    assert!(
        dangling_default
            .to_string()
            .contains("default server 'missing' is not present")
    );

    config.default = Some("web".to_string());
    config.servers.insert(
        "web".to_string(),
        ServerConfig::single_account("192.0.2.10", 22, "deploy", AuthConfig::Agent),
    );
    config.servers.get_mut("web").unwrap().default_user = "missing".to_string();

    let dangling_user = validate_config_credential_references(&config, &namespace).unwrap_err();
    assert!(
        dangling_user
            .to_string()
            .contains("default user 'missing' is not registered for server 'web'")
    );
}

#[test]
fn credential_references_reject_cross_namespace_keys() {
    let namespace = CredentialNamespace::profile("default");
    let other = CredentialNamespace::profile("other");
    let mut config = SshwConfig::default();
    config.servers.insert(
        "web".to_string(),
        ServerConfig::single_account(
            "192.0.2.10",
            22,
            "deploy",
            AuthConfig::Password {
                credential: other.credential_key_v2(
                    CredentialPurpose::Login,
                    "web",
                    "0000000000000001",
                ),
            },
        ),
    );

    let err = validate_config_credential_references(&config, &namespace).unwrap_err();

    let message = err.to_string();
    assert!(message.contains("does not belong to account 'web/deploy'"));
    assert!(message.contains("active home"));
}

#[test]
fn credential_references_reject_legacy_reserved_alias_collisions() {
    let namespace = CredentialNamespace::profile("default");
    let shared = namespace.legacy_credential_key("privilege:web");
    assert_eq!(shared, namespace.legacy_privilege_credential_key("web"));
    let mut config = SshwConfig::default();
    config.servers.insert(
        "privilege:web".to_string(),
        ServerConfig::single_account(
            "192.0.2.10",
            22,
            "deploy",
            AuthConfig::Password {
                credential: shared.clone(),
            },
        ),
    );

    let err = validate_config_credential_references(&config, &namespace).unwrap_err();

    assert!(err.to_string().contains("reserved 'privilege:' prefix"));
}

#[test]
fn credential_references_reject_control_characters_in_aliases() {
    let namespace = CredentialNamespace::profile("default");
    let mut config = SshwConfig::default();
    config.servers.insert(
        "web\ninjected".to_string(),
        ServerConfig::single_account("192.0.2.10", 22, "deploy", AuthConfig::Agent),
    );

    let err = validate_config_credential_references(&config, &namespace).unwrap_err();

    assert!(err.to_string().contains("invalid server name"));
}

#[cfg(unix)]
#[test]
fn config_save_uses_owner_only_permissions() {
    use std::os::unix::fs::PermissionsExt;

    let temp = tempfile::tempdir().unwrap();
    let path = temp.path().join("servers.json");

    save_config(&path, &SshwConfig::default()).unwrap();

    let mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
    assert_eq!(mode, 0o600);
}

#[test]
fn v1_config_loads_as_v2_accounts_without_rewriting_the_file() {
    let temp = tempfile::tempdir().unwrap();
    let path = temp.path().join("servers.json");
    let original = r#"{
        "version": 1,
        "default": "web",
        "servers": {
            "web": {
                "host": "192.0.2.10",
                "port": 22,
                "user": "deploy",
                "auth": { "type": "password", "credential": "sshw:default:web" }
            }
        },
        "privileges": {
            "web": {
                "method": "sudo",
                "user": "root",
                "credential": "sshw:default:privilege:web"
            }
        }
    }"#;
    fs::write(&path, original).unwrap();

    let config = load_config(&path).unwrap();

    assert_eq!(config.version, 2);
    let server = &config.servers["web"];
    assert_eq!(server.default_user, "deploy");
    assert_eq!(server.accounts.len(), 1);
    let account = &server.accounts["deploy"];
    assert!(matches!(account.auth, AuthConfig::Password { .. }));
    assert_eq!(account.privilege.as_ref().unwrap().user, "root");
    assert_eq!(fs::read_to_string(&path).unwrap(), original);
}

#[test]
fn v2_config_round_trip_preserves_multiple_accounts() {
    let temp = tempfile::tempdir().unwrap();
    let path = temp.path().join("servers.json");
    let namespace = CredentialNamespace::profile("default");
    let mut accounts = std::collections::BTreeMap::new();
    accounts.insert(
        "deploy".to_string(),
        AccountConfig {
            auth: AuthConfig::Agent,
            privilege: None,
        },
    );
    accounts.insert(
        "ops".to_string(),
        AccountConfig {
            auth: AuthConfig::Password {
                credential: namespace.credential_key_v3(
                    CredentialPurpose::Login,
                    "web",
                    "ops",
                    "0000000000000001",
                ),
            },
            privilege: Some(PrivilegeConfig {
                method: PrivilegeMethod::Sudo,
                user: "root".to_string(),
                credential: Some(namespace.credential_key_v3(
                    CredentialPurpose::Privilege,
                    "web",
                    "ops",
                    "0000000000000002",
                )),
                no_password: false,
            }),
        },
    );
    let mut config = SshwConfig {
        default: Some("web".to_string()),
        ..SshwConfig::default()
    };
    config.servers.insert(
        "web".to_string(),
        ServerConfig {
            host: "192.0.2.10".to_string(),
            port: 22,
            default_user: "deploy".to_string(),
            accounts,
        },
    );

    save_config(&path, &config).unwrap();

    let loaded = load_config(&path).unwrap();
    assert_eq!(loaded, config);
    validate_config_credential_references(&loaded, &namespace).unwrap();
}

#[test]
fn account_relationships_and_credentials_fail_closed() {
    let namespace = CredentialNamespace::profile("default");
    let mut accounts = std::collections::BTreeMap::new();
    accounts.insert(
        "ops".to_string(),
        AccountConfig {
            auth: AuthConfig::Password {
                credential: namespace.credential_key_v3(
                    CredentialPurpose::Login,
                    "web",
                    "deploy",
                    "0000000000000001",
                ),
            },
            privilege: None,
        },
    );
    let mut config = SshwConfig::default();
    config.servers.insert(
        "web".to_string(),
        ServerConfig {
            host: "192.0.2.10".to_string(),
            port: 22,
            default_user: "missing".to_string(),
            accounts,
        },
    );

    let err = validate_config_credential_references(&config, &namespace).unwrap_err();
    assert!(err.to_string().contains("default user 'missing'"));

    config.servers.get_mut("web").unwrap().default_user = "ops".to_string();
    let err = validate_config_credential_references(&config, &namespace).unwrap_err();
    assert!(
        err.to_string()
            .contains("does not belong to account 'web/ops'")
    );
}
