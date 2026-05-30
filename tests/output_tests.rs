use sshw::config::{AuthConfig, ServerConfig};
use sshw::output::{
    ErrorKind, RunOutput, ServerOutput, classify_error, filter_startup_stderr_noise, redact_secrets,
};

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
fn classifies_ssh_connection_errors_for_stable_exit_codes() {
    let err = anyhow::anyhow!("failed to connect to 192.0.2.10:22 within 15 seconds");

    let kind = classify_error(&err);

    assert_eq!(kind, ErrorKind::Ssh);
    assert_eq!(kind.exit_code(), 5);
}

#[test]
fn classifies_profile_and_registry_errors_as_config() {
    for message in [
        "cannot use --home and --profile together",
        "unknown profile 'prod'",
        "profile 'prod' already exists; pass --force to overwrite",
        "profile add requires --home <path>",
        "default profile 'prod' is not present in the registry",
    ] {
        let kind = classify_error(&anyhow::anyhow!("{message}"));
        assert_eq!(kind, ErrorKind::Config, "message: {message}");
        assert_eq!(kind.exit_code(), 3);
    }
}

#[test]
fn filters_known_noninteractive_stty_startup_noise() {
    let stderr = "stty: 'standard input': Inappropriate ioctl for device\nactual warning\n";

    let filtered = filter_startup_stderr_noise(stderr);

    assert_eq!(filtered, "actual warning\n");
}

#[test]
fn classifies_ssh_session_and_transfer_errors_as_ssh() {
    for message in [
        "ssh session error: channel failure",
        "ssh transfer error: scp protocol error",
    ] {
        let kind = classify_error(&anyhow::anyhow!("{message}"));
        assert_eq!(kind, ErrorKind::Ssh, "message: {message}");
        assert_eq!(kind.exit_code(), 5);
    }
}

#[test]
fn classifies_raw_ssh2_library_errors_as_ssh() {
    // ssh2 errors (handshake/kex/known_hosts) carry no classification keyword
    // and are not io::Error, so message matching alone misses them. They must
    // still map to the stable ssh exit code (5), not unknown (1).
    let err = anyhow::Error::new(ssh2::Error::unknown());

    let kind = classify_error(&err);

    assert_eq!(kind, ErrorKind::Ssh);
    assert_eq!(kind.exit_code(), 5);
}

#[test]
fn classifies_policy_errors_with_exit_code_7() {
    for message in [
        "command blocked by policy: 'rm' is not in the allowlist",
        "upload blocked by policy: '/tmp' is not in the allowed paths",
        "invalid policy file at /x/policy.json: expected value",
        "policy enforcement requested (--policy) but no policy file at /x/policy.json",
    ] {
        let kind = classify_error(&anyhow::anyhow!("{message}"));
        assert_eq!(kind, ErrorKind::Policy, "message: {message}");
        assert_eq!(kind.exit_code(), 7);
    }
}

#[test]
fn classifies_safety_rail_errors_with_exit_code_2() {
    for message in [
        "'rm -rf /tmp/x' requires --yes to run a destructive command",
        "writing to system path '/etc/hosts' requires --yes",
    ] {
        let kind = classify_error(&anyhow::anyhow!("{message}"));
        assert_eq!(kind, ErrorKind::Safety, "message: {message}");
        assert_eq!(kind.exit_code(), 2);
    }
}

#[test]
fn classifies_auth_errors_with_exit_code_4() {
    for message in [
        "missing credential entries for server 'web'",
        "credential store unavailable",
        "SSH authentication failed",
        "password cannot be empty",
    ] {
        let kind = classify_error(&anyhow::anyhow!("{message}"));
        assert_eq!(kind, ErrorKind::Auth, "message: {message}");
        assert_eq!(kind.exit_code(), 4);
    }
}

#[test]
fn classifies_unknown_server_and_confirmation_errors_as_config() {
    for message in [
        "unknown server 'missing'",
        "no default server configured; run 'sshw default <name>' to set one",
        "failed to load config",
        "confirmation requires an interactive terminal; rerun with --yes to confirm",
        "confirmation input ended before a response; rerun with --yes to confirm",
    ] {
        let kind = classify_error(&anyhow::anyhow!("{message}"));
        assert_eq!(kind, ErrorKind::Config, "message: {message}");
        assert_eq!(kind.exit_code(), 3);
    }
}

#[test]
fn classifies_existing_local_file_as_io() {
    let err = anyhow::anyhow!("local file already exists: ./out; pass --yes to overwrite");
    let kind = classify_error(&err);
    assert_eq!(kind, ErrorKind::Io);
    assert_eq!(kind.exit_code(), 6);
}

#[test]
fn redacts_pem_private_key_block() {
    let input = "before\n-----BEGIN OPENSSH PRIVATE KEY-----\nb3BlbnNzaC1rZXk\nAAAA\n-----END OPENSSH PRIVATE KEY-----\nafter\n";

    let out = redact_secrets(input);

    assert!(out.contains("[redacted private key]"));
    assert!(!out.contains("b3BlbnNzaC1rZXk"));
    assert!(!out.contains("AAAA"));
    assert!(out.contains("before\n"));
    assert!(out.contains("after\n"));
}

#[test]
fn redacts_keyword_assignments() {
    assert_eq!(redact_secrets("password=hunter2"), "password=<redacted>");
    assert_eq!(redact_secrets("PASSWORD: hunter2"), "PASSWORD: <redacted>");

    let api = redact_secrets("api_key = \"abc123\"");
    assert!(api.starts_with("api_key = "));
    assert!(!api.contains("abc123"));

    let token = redact_secrets("export TOKEN=abcdef\n");
    assert!(token.contains("TOKEN=<redacted>"));
    assert!(!token.contains("abcdef"));
}

#[test]
fn redacts_bearer_token() {
    let out = redact_secrets("Authorization: Bearer abc.def.ghi");

    assert!(out.contains("Bearer <redacted>"));
    assert!(!out.contains("abc.def.ghi"));
}

#[test]
fn redacts_json_embedded_secrets() {
    let compact = redact_secrets("{\"password\":\"hunter2\",\"region\":\"us\"}\n");
    assert!(!compact.contains("hunter2"), "compact was {compact}");
    assert!(compact.contains("<redacted>"));

    let pretty = redact_secrets("  \"api_key\": \"AKIAEXAMPLEKEY\"\n");
    assert!(!pretty.contains("AKIAEXAMPLEKEY"), "pretty was {pretty}");

    let aws = redact_secrets("AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMIabcd\n");
    assert!(!aws.contains("wJalrXUtnFEMIabcd"), "aws was {aws}");
    assert!(aws.contains("<redacted>"));
}

#[test]
fn leaves_ordinary_output_and_identifiers_untouched() {
    assert_eq!(redact_secrets("ok\n"), "ok\n");
    assert_eq!(
        redact_secrets("the password is in the vault"),
        "the password is in the vault"
    );
    assert_eq!(redact_secrets("sshw:p_abc123:web"), "sshw:p_abc123:web");
    assert_eq!(
        redact_secrets("hostname\nuptime 3 days\n"),
        "hostname\nuptime 3 days\n"
    );
}

#[test]
fn redaction_is_idempotent() {
    let once = redact_secrets("password=hunter2\nAuthorization: Bearer xyz\nok\n");
    let twice = redact_secrets(&once);

    assert_eq!(once, twice);
    assert!(!once.contains("hunter2"));
    assert!(!once.contains("xyz"));
}

#[test]
fn preserves_unrelated_stderr_lines() {
    let stderr = "permission denied\nstty: unexpected option\n";

    let filtered = filter_startup_stderr_noise(stderr);

    assert_eq!(filtered, stderr);
}
