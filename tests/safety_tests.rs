use sshw::safety::{SafetyDecision, classify_command, classify_remote_write_path};

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
        "echo x > /etc",
        "echo x >> /etc/app.conf",
        "cat file >/etc/app.conf",
        "cat file >\t/etc/app.conf",
        "cat file >/etc",
        "tee /etc/app.conf",
        "tee /etc",
        "cp app.conf /etc/app.conf",
        "mv app.conf /etc/app.conf",
        "dd if=app.conf of=/etc/app.conf",
        "dd if=app.conf of=/etc",
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

#[test]
fn blocks_remote_writes_to_system_paths_without_yes() {
    for path in [
        "/etc/app.conf",
        "/usr/bin/app",
        "/bin/app",
        "/sbin/app",
        "/lib/system.so",
        "/lib64/system.so",
        "/boot/loader",
        "/root/secret",
    ] {
        assert!(
            matches!(
                classify_remote_write_path(path, false),
                SafetyDecision::Block { .. }
            ),
            "{path} should require --yes"
        );
    }
}

#[test]
fn allows_remote_system_write_with_yes() {
    assert_eq!(
        classify_remote_write_path("/usr/bin/app", true),
        SafetyDecision::Allow
    );
}

#[test]
fn allows_remote_write_to_user_path_without_yes() {
    assert_eq!(
        classify_remote_write_path("/home/deploy/app", false),
        SafetyDecision::Allow
    );
}
