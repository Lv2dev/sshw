use super::*;

#[test]
fn add_address_change_recovery_precedes_confirmation_and_credentials_without_mutation() {
    let temp = tempfile::tempdir().unwrap();
    let path = temp.path().join("servers.json");
    save_config(&path, &sample_config(&path)).unwrap();
    let before = std::fs::read(&path).unwrap();
    let store = FakeCredentialStore::default();
    let mut input = NoPasswordPrompter { prompts: vec![] };
    let output = execute_for_runtime(
        Cli::try_parse_from([
            "sshw",
            "add",
            "server-alpha",
            "--host",
            "192.0.2.77",
            "--port",
            "10022",
            "--user",
            "deploy",
            "--json",
        ])
        .unwrap(),
        &path,
        &store,
        &FakeSshClient::default(),
        &mut input,
    );
    assert_eq!(output.exit_code, 3, "{output:?}");
    let body: serde_json::Value = serde_json::from_str(&output.stdout).unwrap();
    let message = body["error"]["message"].as_str().unwrap();
    assert!(message.find("endpoint").unwrap() < message.find("--replace").unwrap());
    assert!(message.contains("--home="), "{message}");
    assert!(input.prompts.is_empty());
    assert!(store.requested.borrow().is_empty());
    assert!(store.values.borrow().is_empty());
    assert_eq!(std::fs::read(&path).unwrap(), before);
}

#[test]
fn endpoint_changes_only_host_port_and_keeps_secrets_policy_defaults_and_trust() {
    let temp = tempfile::tempdir().unwrap();
    let path = temp.path().join("servers.json");
    let home = ResolvedHome::from_config_path(&path);
    let mut config = sample_config(&path);
    let original = config.servers["server-alpha"].clone();
    config
        .servers
        .get_mut("server-alpha")
        .unwrap()
        .accounts
        .insert(
            "ops".into(),
            AccountConfig {
                auth: AuthConfig::Agent,
                privilege: Some(PrivilegeConfig {
                    method: PrivilegeMethod::Su,
                    user: "root".into(),
                    credential: Some(home.namespace.new_account_credential_key(
                        CredentialPurpose::Privilege,
                        "server-alpha",
                        "ops",
                    )),
                    no_password: false,
                }),
            },
        );
    save_config(&path, &config).unwrap();
    std::fs::write(&home.policy_path, "invalid unused policy preserved").unwrap();
    std::fs::write(&home.known_hosts_path, "old approved endpoint preserved").unwrap();
    let store = FakeCredentialStore::default();
    let key = login_credential(&path, "server-alpha");
    store
        .set_password(&key, "deploy", "SYNTHETIC_LOGIN")
        .unwrap();
    let secrets = store.values.borrow().clone();
    let ssh = FakeSshClient::default();
    let audit = FileAuditSink::new(home.audit_path.clone());
    let registry = temp.path().join("profiles.json");
    let ctx = ExecContext {
        home: &home,
        registry_path: &registry,
        policy_forced: false,
        audit: &audit,
    };
    let mut input = NoPasswordPrompter { prompts: vec![] };
    let output = execute_with(
        Cli::try_parse_from([
            "sshw",
            "endpoint",
            "server-alpha",
            "--port",
            "10022",
            "--json",
        ])
        .unwrap(),
        &ctx,
        &store,
        &ssh,
        &mut input,
    )
    .unwrap();
    let body: serde_json::Value = serde_json::from_str(&output.stdout).unwrap();
    assert_eq!(body["changed"], true);
    assert_eq!(body["port"], 10022);
    assert_eq!(body["host"], original.host);
    assert_eq!(body["credentials_changed"], false);
    assert_eq!(body["host_key_verified"], false);
    assert!(
        input.prompts[0].contains("10022")
            && input.prompts[0].contains("accounts and passwords are preserved")
    );
    config.servers.get_mut("server-alpha").unwrap().port = 10022;
    assert_eq!(load_config(&path).unwrap(), config);
    let output = execute_with(
        Cli::try_parse_from([
            "sshw",
            "endpoint",
            "server-alpha",
            "--host",
            "192.0.2.77",
            "--yes",
        ])
        .unwrap(),
        &ctx,
        &store,
        &ssh,
        &mut input,
    )
    .unwrap();
    assert_eq!(output.exit_code, 0);
    config.servers.get_mut("server-alpha").unwrap().host = "192.0.2.77".into();
    assert_eq!(load_config(&path).unwrap(), config);
    let before = std::fs::read(&path).unwrap();
    let modified = std::fs::metadata(&path).unwrap().modified().unwrap();
    let output = execute_with(
        Cli::try_parse_from([
            "sshw",
            "endpoint",
            "server-alpha",
            "--host",
            "192.0.2.77",
            "--json",
        ])
        .unwrap(),
        &ctx,
        &store,
        &ssh,
        &mut input,
    )
    .unwrap();
    let body: serde_json::Value = serde_json::from_str(&output.stdout).unwrap();
    assert_eq!(body["changed"], false);
    assert_eq!(input.prompts.len(), 1);
    assert_eq!(std::fs::read(&path).unwrap(), before);
    assert_eq!(
        std::fs::metadata(&path).unwrap().modified().unwrap(),
        modified
    );
    assert_eq!(store.values.borrow().clone(), secrets);
    assert!(store.requested.borrow().is_empty());
    assert!(store.deleted.borrow().is_empty());
    assert!(ssh.selected_users.borrow().is_empty());
    assert_eq!(*ssh.host_key_calls.borrow(), 0);
    assert_eq!(
        std::fs::read(&home.policy_path).unwrap(),
        b"invalid unused policy preserved"
    );
    assert_eq!(
        std::fs::read(&home.known_hosts_path).unwrap(),
        b"old approved endpoint preserved"
    );
    let audit = std::fs::read_to_string(&home.audit_path).unwrap();
    assert!(audit.lines().all(
        |line| serde_json::from_str::<serde_json::Value>(line).unwrap()["action"] == "endpoint"
    ));
}

#[test]
fn endpoint_rejects_invalid_or_cancelled_edits_without_writes_or_secret_access() {
    let temp = tempfile::tempdir().unwrap();
    let path = temp.path().join("servers.json");
    save_config(&path, &sample_config(&path)).unwrap();
    let before = std::fs::read(&path).unwrap();
    let store = FakeCredentialStore::default();
    let ssh = FakeSshClient::default();
    for args in [
        vec!["sshw", "endpoint", "server-alpha", "--port", "0"],
        vec!["sshw", "endpoint", "server-alpha", "--host", "  "],
        vec!["sshw", "endpoint", "missing", "--port", "22"],
        vec!["sshw", "endpoint", "server-alpha", "--host", "192.0.2.90"],
    ] {
        let output = execute_for_runtime(
            Cli::try_parse_from(args).unwrap(),
            &path,
            &store,
            &ssh,
            &mut FakePrompter::default(),
        );
        assert_eq!(output.exit_code, 3);
        assert_eq!(std::fs::read(&path).unwrap(), before);
    }
    assert!(Cli::try_parse_from(["sshw", "endpoint", "server-alpha"]).is_err());
    assert!(store.requested.borrow().is_empty());
    assert!(store.deleted.borrow().is_empty());
    assert!(ssh.selected_users.borrow().is_empty());
}
