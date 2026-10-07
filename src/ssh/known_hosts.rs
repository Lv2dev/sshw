//! Local known_hosts parsing shared by diagnostics and connection verification.

use crate::error::settings_error;
use base64::Engine;
use ssh2::{CheckResult, KnownHostFileKind, KnownHosts, Session};
use std::fs;
use std::path::Path;

pub(crate) struct LocalKnownHosts(KnownHosts);

impl LocalKnownHosts {
    /// Allocate a parser without opening a socket or starting an SSH handshake.
    pub(crate) fn load(path: &Path) -> anyhow::Result<Self> {
        let session = Session::new()?;
        let mut hosts = session.known_hosts()?;
        read_known_hosts_file(&mut hosts, path)?;
        // libssh2 also accepts opaque text for unknown/legacy key formats.
        // Report unreadable key data as unverified instead of a usable entry.
        for host in hosts.hosts()? {
            base64::engine::general_purpose::STANDARD
                .decode(host.key())
                .map_err(|error| settings_error(error.into(), "invalid host key data in known_hosts file", path,
                    "repair the reported known_hosts key data; use sshw doctor with the same home/profile to inspect local trust entries"))?;
        }
        Ok(Self(hosts))
    }

    pub(crate) fn has_entry(&self, host: &str, port: u16) -> anyhow::Result<bool> {
        // check_port uses the same plain/hashed host and port matching as a
        // connection. A mismatch with this fixed nonempty probe also means an
        // endpoint entry exists; it says nothing about the remote server's key.
        match self.0.check_port(host, port, b"sshw local endpoint lookup") {
            CheckResult::Match | CheckResult::Mismatch => Ok(true),
            CheckResult::NotFound => Ok(false),
            CheckResult::Failure => Err(anyhow::anyhow!(
                "failed to inspect the local known_hosts entry for {host}:{port}"
            )),
        }
    }
}

pub(crate) fn read_known_hosts_file(hosts: &mut KnownHosts, path: &Path) -> anyhow::Result<()> {
    let content = fs::read_to_string(path)
        .map_err(|error| settings_error(error.into(), "failed to read known_hosts file", path,
            "check read access and UTF-8/OpenSSH format at the reported known_hosts path; use sshw doctor with the same home/profile to inspect local trust entries"))?;
    for (index, line) in content.lines().enumerate() {
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }
        let mut entry = String::with_capacity(line.len() + 1);
        entry.push_str(line);
        entry.push('\n');
        hosts
            .read_str(&entry, KnownHostFileKind::OpenSSH)
            .map_err(|error| settings_error(error.into(), &format!("failed to parse known_hosts file at line {}", index + 1), path,
                "repair the reported known_hosts line in OpenSSH format; verify the server identity before explicitly trusting a replacement key"))?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    #[test]
    fn known_hosts_read_failure_shows_masked_path_cause_and_keeps_io_source() {
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("token=path-marker");
        std::fs::create_dir(&path).unwrap();
        let error = super::LocalKnownHosts::load(&path).err().unwrap();
        let response = crate::output::ErrorResponse::from_error(&error);
        assert!(
            response.error.message.contains("caused by:")
                && response.error.message.contains("next:")
                && response.error.message.contains("known_hosts")
        );
        assert!(!response.error.message.contains("path-marker"));
        assert!(
            error
                .chain()
                .any(|cause| cause.downcast_ref::<std::io::Error>().is_some())
        );
        assert!(path.is_dir());
    }
}
