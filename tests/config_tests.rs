use sshw::config::{
    AuthConfig, CredentialBackend, PrivilegeConfig, PrivilegeMethod, ServerConfig, SshwConfig,
    load_config, save_config,
};

#[test]
fn new_config_starts_empty() {
    let config = SshwConfig::default();

    assert_eq!(config.version, 1);
    assert!(config.default.is_none());
    assert!(config.servers.is_empty());
    assert!(config.privileges.is_empty());
}

#[test]
fn config_serializes_password_and_agent_auth_without_secrets() {
    let mut config = SshwConfig::default();
    config.servers.insert(
        "server-alpha".to_string(),
        ServerConfig {
            host: "192.0.2.10".to_string(),
            port: 2222,
            user: "deploy".to_string(),
            auth: AuthConfig::Password {
                credential: "sshw:server-alpha".to_string(),
            },
        },
    );
    config.servers.insert(
        "server-beta".to_string(),
        ServerConfig {
            host: "192.0.2.11".to_string(),
            port: 2222,
            user: "deploy".to_string(),
            auth: AuthConfig::Agent,
        },
    );
    config.privileges.insert(
        "server-alpha".to_string(),
        PrivilegeConfig {
            method: PrivilegeMethod::Sudo,
            user: "root".to_string(),
            credential: "sshw:default:privilege:server-alpha".to_string(),
        },
    );

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
    assert!(legacy.privileges.is_empty());

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
fn config_saves_and_loads_round_trip() {
    let temp = tempfile::tempdir().unwrap();
    let path = temp.path().join("nested").join("servers.json");
    let mut servers = std::collections::BTreeMap::new();
    servers.insert(
        "server-alpha".to_string(),
        ServerConfig {
            host: "192.0.2.10".to_string(),
            port: 2222,
            user: "deploy".to_string(),
            auth: AuthConfig::Password {
                credential: "sshw:server-alpha".to_string(),
            },
        },
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
