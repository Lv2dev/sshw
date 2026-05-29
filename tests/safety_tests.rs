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
    for command in [
        "rm -rf /home/deploy/app",
        "rm -fr /home/deploy/app",
        "rm -r -f /home/deploy/app",
        "rm -f -r /home/deploy/app",
        "/bin/rm -rf /home/deploy/app",
        "/usr/bin/rm -rf /home/deploy/app",
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
fn blocks_service_and_permission_commands_without_yes() {
    for command in [
        "sudo systemctl restart app",
        "sudo\t systemctl restart app",
        "/usr/bin/sudo systemctl restart app",
        "chmod -R 755 /srv/app",
        "/bin/chmod -R 755 /srv/app",
        "chmod --recursive 755 /srv/app",
        "chown -R deploy:deploy /srv/app",
        "/usr/bin/chown -R deploy:deploy /srv/app",
        "chown --recursive deploy:deploy /srv/app",
        "pm2 delete app",
        "/usr/bin/pm2 delete app",
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
        "cat file >\t/etc/app.conf",
        "tee /etc/app.conf",
        "cp app.conf /etc/app.conf",
        "mv app.conf /etc/app.conf",
        "dd if=app.conf of=/etc/app.conf",
        "install app.conf /etc/app.conf",
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
