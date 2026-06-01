#![no_main]

use libfuzzer_sys::fuzz_target;
use sshw::policy::{Policy, PolicyFile, resolve_policy};
use std::collections::hash_map::DefaultHasher;
use std::fs;
use std::hash::{Hash, Hasher};
use std::path::{Path, PathBuf};

fuzz_target!(|data: &[u8]| {
    let Ok(input) = std::str::from_utf8(data) else {
        return;
    };

    let Ok(policy_file) = serde_json::from_str::<PolicyFile>(input) else {
        return;
    };

    let serialized = serde_json::to_string(&policy_file).expect("PolicyFile should serialize");
    let reparsed = serde_json::from_str::<PolicyFile>(&serialized)
        .expect("serialized PolicyFile should parse");
    assert_eq!(policy_file, reparsed);

    let path = policy_path(data);
    if fs::write(&path, input).is_ok() {
        exercise_resolved_policy(&path, false);
        exercise_resolved_policy(&path, true);
        let _ = fs::remove_file(&path);
    }
});

fn policy_path(data: &[u8]) -> PathBuf {
    let mut hasher = DefaultHasher::new();
    data.hash(&mut hasher);

    std::env::temp_dir().join(format!(
        "sshw-policy-fuzz-{}-{:016x}.json",
        std::process::id(),
        hasher.finish()
    ))
}

fn exercise_resolved_policy(path: &Path, force_enable: bool) {
    let Ok(Policy::Enabled(rules)) = resolve_policy(path, force_enable) else {
        return;
    };

    for command in [
        "",
        "ls",
        "/bin/ls -la /srv/app",
        "ls && rm -rf /",
        "systemctl status sshd",
        "systemctl status sshd; reboot",
        "cat /etc/passwd",
    ] {
        let _ = rules.allows_command(command);
    }

    for remote_path in [
        "",
        "/srv/app",
        "/srv/app/bin/run",
        "/srv/application",
        "/srv/app/../secret",
        "/srv/app\\..\\secret",
    ] {
        let _ = rules.allows_put(remote_path);
    }

    for remote_path in [
        "",
        "/var/log",
        "/var/log/syslog",
        "/var/logs",
        "/var/log/../../root/.ssh/id_rsa",
        "/var/log\\..\\secret",
    ] {
        let _ = rules.allows_get(remote_path);
    }
}
