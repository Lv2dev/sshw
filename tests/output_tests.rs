use sshw::config::{AuthConfig, ServerConfig};
use sshw::output::{
    ErrorKind, RunOutput, ServerOutput, classify_error, filter_startup_stderr_noise, redact_secrets,
};
use sshw::profile::load_registry;
use sshw::safety::{SafetyDecision, classify_command, classify_remote_write_path};

#[test]
fn run_output_serializes_for_agents() {
    let output = RunOutput {
        ok: true,
        server: "server-alpha".to_string(),
        command: "hostname".to_string(),
        exit_status: 0,
        stdout: "server\n".to_string(),
        stderr: String::new(),
        duration_ms: 12,
    };

    let json = serde_json::to_string(&output).unwrap();

    assert!(json.contains("\"ok\":true"));
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
        "ssh session error: remote command terminated by signal TERM",
        "ssh transfer error: scp protocol error",
        "ssh transfer error: remote scp exited with status 1",
        // ssh2_client::extract_su_output when the su END marker never arrives.
        "su output ended before the completion marker",
        // ssh2_client::extract_su_output when the END marker is incomplete.
        "su output ended with a malformed completion marker",
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
    // Drive classification with the *actual* reasons `safety` produces, so a
    // change that drops the "requires --yes" marker fails here instead of
    // silently reclassifying the block to Unknown.
    let mut reasons = Vec::new();
    for command in [
        "rm -rf /tmp/x",
        "sudo systemctl restart svc",
        "chmod -R 777 /srv",
    ] {
        match classify_command(command, false) {
            SafetyDecision::Block { reason } => reasons.push(reason),
            SafetyDecision::Allow => panic!("expected '{command}' to be blocked"),
        }
    }
    match classify_remote_write_path("/etc/hosts", false) {
        SafetyDecision::Block { reason } => reasons.push(reason),
        SafetyDecision::Allow => panic!("expected '/etc/hosts' write to be blocked"),
    }

    for reason in reasons {
        let kind = classify_error(&anyhow::anyhow!("{reason}"));
        assert_eq!(kind, ErrorKind::Safety, "message: {reason}");
        assert_eq!(kind.exit_code(), 2);
    }
}

#[test]
fn classifies_auth_errors_with_exit_code_4() {
    // Use the exact messages the cli/credential paths produce so the markers
    // stay anchored to real output, not paraphrases.
    for message in [
        "missing credential entries: server-alpha",
        "missing credential entry for sshw:server-alpha and user deploy",
        "credential backend unavailable: backend offline. Run `sshw doctor` for setup details",
        "SSH authentication failed",
        "password cannot be empty",
        // privilege::validate_privilege_password rejects a multiline secret.
        "privilege password must be a single line",
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
        "no default server configured; run 'sshw default <name>' to set one or pass an explicit server name",
        "failed to load config",
        "confirmation requires an interactive terminal; rerun with --yes to confirm",
    ] {
        let kind = classify_error(&anyhow::anyhow!("{message}"));
        assert_eq!(kind, ErrorKind::Config, "message: {message}");
        assert_eq!(kind.exit_code(), 3);
    }
}

#[test]
fn classifies_state_change_cancellations_as_config() {
    for message in [
        "add cancelled",
        "trust cancelled",
        "removal cancelled",
        "privilege update cancelled",
        "privilege clear cancelled",
    ] {
        let kind = classify_error(&anyhow::anyhow!("{message}"));
        assert_eq!(kind, ErrorKind::Config, "message: {message}");
        assert_eq!(kind.exit_code(), 3);
    }
}

#[test]
fn classifies_password_stdin_with_agent_as_config() {
    let message = "--password-stdin cannot be used with --auth agent";

    let kind = classify_error(&anyhow::anyhow!("{message}"));

    assert_eq!(kind, ErrorKind::Config);
    assert_eq!(kind.exit_code(), 3);
}

#[test]
fn classifies_corrupt_profile_registry_load_as_config() {
    let temp = tempfile::tempdir().unwrap();
    let path = temp.path().join("profiles.json");
    std::fs::write(&path, "{").unwrap();
    let err = load_registry(&path).unwrap_err();

    let kind = classify_error(&err);

    assert_eq!(kind, ErrorKind::Config);
    assert_eq!(kind.exit_code(), 3);
}

#[test]
fn classifies_io_errors_with_exit_code_6() {
    for message in [
        "local file already exists: ./out; pass --yes to overwrite",
        // ssh2_client::put rejects a non-file local path (e.g. a directory).
        "local path is not a regular file: ./somedir",
    ] {
        let kind = classify_error(&anyhow::anyhow!("{message}"));
        assert_eq!(kind, ErrorKind::Io, "message: {message}");
        assert_eq!(kind.exit_code(), 6);
    }
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
fn redacts_crlf_terminated_secret_and_preserves_line_ending() {
    let out = redact_secrets("password=hunter2\r\nok\r\n");
    assert!(!out.contains("hunter2"), "secret survived: {out:?}");
    assert!(
        out.contains("password=<redacted>\r\n"),
        "CRLF line ending not preserved: {out:?}"
    );
    assert!(out.contains("ok\r\n"));
}

#[test]
fn redacts_secrets_across_mixed_crlf_and_lf_lines() {
    let out = redact_secrets("api_key=ABC123\r\nAuthorization: Bearer XYZ789\nplain text\n");
    assert!(!out.contains("ABC123"), "CRLF secret survived: {out:?}");
    assert!(!out.contains("XYZ789"), "LF bearer survived: {out:?}");
    assert!(out.contains("plain text\n"));
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
fn redaction_samples_remove_sensitive_values() {
    for (input, secret) in [
        ("password=hunter2", "hunter2"),
        ("PASSWORD: swordfish", "swordfish"),
        ("  \"password\":\"json-secret\"", "json-secret"),
        ("api_key = \"AKIAEXAMPLEKEY\"", "AKIAEXAMPLEKEY"),
        (
            "AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMIabcd",
            "wJalrXUtnFEMIabcd",
        ),
        ("refresh_token: r1.r2.r3", "r1.r2.r3"),
        ("auth_token='quoted-secret'", "quoted-secret"),
        ("Authorization: Bearer abc.def.ghi", "abc.def.ghi"),
    ] {
        let once = redact_secrets(input);
        let twice = redact_secrets(&once);

        assert!(
            once.contains("<redacted>"),
            "sample was not redacted: {input}"
        );
        assert!(!once.contains(secret), "secret leaked for sample: {input}");
        assert_eq!(once, twice, "redaction was not idempotent: {input}");
    }
}

#[test]
fn redaction_samples_keep_non_secret_text() {
    for input in [
        "ok\n",
        "token bucket capacity is normal",
        "the password is in the vault",
        "credential name sshw:p_abc123:web",
        "sshw:p_abc123:web",
        "authentication succeeded",
        "private_key material is not shown here",
    ] {
        assert_eq!(redact_secrets(input), input, "sample changed: {input}");
    }
}

#[test]
fn preserves_unrelated_stderr_lines() {
    let stderr = "permission denied\nstty: unexpected option\n";

    let filtered = filter_startup_stderr_noise(stderr);

    assert_eq!(filtered, stderr);
}
