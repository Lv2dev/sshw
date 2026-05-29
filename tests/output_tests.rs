use sshw::config::{AuthConfig, ServerConfig};
use sshw::output::{RunOutput, ServerOutput, filter_startup_stderr_noise};

#[test]
fn run_output_serializes_for_agents() {
    let output = RunOutput {
        server: "server-alpha".to_string(),
        command: "hostname".to_string(),
        exit_status: 0,
        stdout: "server\n".to_string(),
        stderr: String::new(),
        duration_ms: 12,
    };

    let json = serde_json::to_string(&output).unwrap();

    assert!(json.contains("\"server\":\"server-alpha\""));
    assert!(json.contains("\"exit_status\":0"));
    assert!(!json.contains("password"));
}

#[test]
fn server_output_includes_metadata_without_secrets() {
    let server = ServerConfig {
        host: "192.0.2.10".to_string(),
        port: 2222,
        user: "deploy".to_string(),
        auth: AuthConfig::Password {
            credential: "sshw:server-alpha".to_string(),
        },
    };

    let output = ServerOutput::from_config("server-alpha", &server, true);
    let json = serde_json::to_string(&output).unwrap();

    assert!(json.contains("\"name\":\"server-alpha\""));
    assert!(json.contains("\"credential\":\"sshw:server-alpha\""));
    assert!(!json.contains("YOUR_PASSWORD"));
    assert!(!json.contains("private_key"));
    assert!(!json.contains("passphrase"));
}

#[test]
fn filters_known_noninteractive_stty_startup_noise() {
    let stderr = "stty: 'standard input': Inappropriate ioctl for device\nactual warning\n";

    let filtered = filter_startup_stderr_noise(stderr);

    assert_eq!(filtered, "actual warning\n");
}

#[test]
fn preserves_unrelated_stderr_lines() {
    let stderr = "permission denied\nstty: unexpected option\n";

    let filtered = filter_startup_stderr_noise(stderr);

    assert_eq!(filtered, stderr);
}
