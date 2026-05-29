use sshw::safety::{SafetyDecision, classify_command};

#[test]
fn allows_basic_diagnostics() {
    assert_eq!(
        classify_command("hostname && whoami && pwd", false),
        SafetyDecision::Allow
    );
}

#[test]
fn blocks_rm_rf_without_yes() {
    assert!(matches!(
        classify_command("rm -rf /home/deploy/app", false),
        SafetyDecision::Block { .. }
    ));
}

#[test]
fn blocks_service_and_permission_commands_without_yes() {
    for command in [
        "sudo systemctl restart app",
        "chmod -R 755 /srv/app",
        "chown -R deploy:deploy /srv/app",
        "pm2 delete app",
    ] {
        assert!(
            matches!(
                classify_command(command, false),
                SafetyDecision::Block { .. }
            ),
            "{command} should be blocked"
        );
    }
}

#[test]
fn blocks_writes_to_etc_without_yes() {
    for command in [
        "echo x > /etc/app.conf",
        "echo x >> /etc/app.conf",
        "cat file >/etc/app.conf",
    ] {
        assert!(
            matches!(
                classify_command(command, false),
                SafetyDecision::Block { .. }
            ),
            "{command} should be blocked"
        );
    }
}

#[test]
fn allows_dangerous_command_with_yes() {
    assert_eq!(
        classify_command("sudo systemctl restart app", true),
        SafetyDecision::Allow
    );
}
