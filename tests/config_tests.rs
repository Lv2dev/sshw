use sshw::config::{
    AuthConfig, ServerConfig, SshwConfig, default_config_path, load_config, save_config,
};

#[test]
fn new_config_starts_empty() {
    let config = SshwConfig::default();

    assert_eq!(config.version, 1);
    assert!(config.default.is_none());
    assert!(config.servers.is_empty());
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

    let json = serde_json::to_string_pretty(&config).unwrap();

    assert!(json.contains("\"type\": \"password\""));
    assert!(json.contains("\"credential\": \"sshw:server-alpha\""));
    assert!(json.contains("\"type\": \"agent\""));
    assert!(!json.contains("YOUR_PASSWORD"));
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
fn config_saves_and_loads_round_trip() {
    let temp = tempfile::tempdir().unwrap();
    let path = temp.path().join("nested").join("servers.json");
    let mut config = SshwConfig::default();
    config.default = Some("server-alpha".to_string());
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

    save_config(&path, &config).unwrap();
    let loaded = load_config(&path).unwrap();

    assert_eq!(loaded, config);
}

#[test]
fn default_config_path_uses_sshw_servers_json() {
    let path = default_config_path().unwrap();

    assert_eq!(path.file_name().unwrap(), "servers.json");
    assert_eq!(path.parent().unwrap().file_name().unwrap(), "sshw");
}
