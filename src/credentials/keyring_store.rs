use super::{CredentialStore, CredentialStoreHealth};
use crate::error::ResultErrorKindExt;
use crate::output::ErrorKind;
use anyhow::Context;
use std::sync::OnceLock;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

#[cfg(target_os = "linux")]
use std::collections::HashMap;

#[derive(Debug, Default, Clone)]
pub struct KeyringCredentialStore;

impl CredentialStore for KeyringCredentialStore {
    fn set_password(&self, credential: &str, user: &str, password: &str) -> anyhow::Result<()> {
        ensure_native_store().with_error_kind(ErrorKind::Auth)?;
        let entry = keyring_core::Entry::new(credential, user).with_error_kind(ErrorKind::Auth)?;
        entry
            .set_password(password)
            .with_error_kind(ErrorKind::Auth)?;
        Ok(())
    }

    fn get_password(&self, credential: &str, user: &str) -> anyhow::Result<String> {
        ensure_native_store().with_error_kind(ErrorKind::Auth)?;
        let entry = keyring_core::Entry::new(credential, user).with_error_kind(ErrorKind::Auth)?;
        entry.get_password().with_error_kind(ErrorKind::Auth)
    }

    fn delete_password(&self, credential: &str, user: &str) -> anyhow::Result<()> {
        ensure_native_store().with_error_kind(ErrorKind::Auth)?;
        let entry = keyring_core::Entry::new(credential, user).with_error_kind(ErrorKind::Auth)?;
        match entry.delete_credential() {
            Ok(()) => Ok(()),
            Err(keyring_core::Error::NoEntry) => Ok(()),
            Err(err) => Err(err).with_error_kind(ErrorKind::Auth),
        }
    }

    fn health_check(&self) -> anyhow::Result<CredentialStoreHealth> {
        ensure_native_store().with_error_kind(ErrorKind::Auth)?;
        let backend = backend_name().to_string();
        let probe = new_health_probe();
        let entry = keyring_core::Entry::new(&probe.credential, probe.user)
            .with_error_kind(ErrorKind::Auth)?;
        entry
            .set_password(&probe.secret)
            .with_error_kind(ErrorKind::Auth)?;
        let value = entry.get_password();
        cleanup_health_probe(entry.delete_credential()).with_error_kind(ErrorKind::Auth)?;
        let value = value.with_error_kind(ErrorKind::Auth)?;
        let available = value == probe.secret;

        Ok(CredentialStoreHealth {
            backend,
            available,
            message: if available {
                "credential store read/write/cleanup succeeded".to_string()
            } else {
                "credential store read/write mismatch".to_string()
            },
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct HealthProbe {
    credential: String,
    user: &'static str,
    secret: String,
}

fn new_health_probe() -> HealthProbe {
    let nonce = health_nonce();
    HealthProbe {
        credential: format!("sshw:doctor:{nonce}"),
        user: "doctor",
        secret: format!("sshw-health-secret:{nonce}"),
    }
}

fn health_nonce() -> String {
    static COUNTER: AtomicU64 = AtomicU64::new(0);
    let counter = COUNTER.fetch_add(1, Ordering::Relaxed);
    let timestamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_nanos())
        .unwrap_or_default();
    format!("{}-{timestamp:x}-{counter:x}", std::process::id())
}

fn cleanup_health_probe(result: keyring_core::Result<()>) -> anyhow::Result<()> {
    result.context("credential health cleanup failed")
}

fn ensure_native_store() -> anyhow::Result<()> {
    static INIT: OnceLock<Result<(), String>> = OnceLock::new();
    let result = INIT.get_or_init(|| select_native_store().map_err(|err| err.to_string()));

    match result {
        Ok(()) => Ok(()),
        Err(message) => Err(anyhow::anyhow!(
            "credential backend unavailable: {message}. Run `sshw doctor` for setup details"
        )),
    }
}

fn select_native_store() -> keyring_core::Result<()> {
    #[cfg(target_os = "windows")]
    {
        keyring_core::set_default_store(windows_native_keyring_store::Store::new()?);
        Ok(())
    }
    #[cfg(target_os = "macos")]
    {
        keyring_core::set_default_store(apple_native_keyring_store::keychain::Store::new()?);
        Ok(())
    }
    #[cfg(target_os = "linux")]
    {
        keyring_core::set_default_store(
            dbus_secret_service_keyring_store::Store::new_with_configuration(&HashMap::new())?,
        );
        Ok(())
    }
    #[cfg(not(any(target_os = "windows", target_os = "macos", target_os = "linux")))]
    {
        Err(keyring_core::Error::NotSupportedByStore(format!(
            "{} is not supported by sshw password auth",
            std::env::consts::OS
        )))
    }
}

fn backend_name() -> &'static str {
    #[cfg(target_os = "windows")]
    {
        "windows-credential-manager"
    }
    #[cfg(target_os = "macos")]
    {
        "macos-keychain"
    }
    #[cfg(target_os = "linux")]
    {
        "secret-service"
    }
    #[cfg(not(any(target_os = "windows", target_os = "macos", target_os = "linux")))]
    {
        "unsupported"
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn health_probe_uses_unique_nonce_and_non_fixed_secret() {
        let first = super::new_health_probe();
        let second = super::new_health_probe();

        assert_ne!(first.credential, second.credential);
        assert_ne!(first.secret, second.secret);
        assert_ne!(first.secret, "doctor-secret");
        assert!(first.credential.starts_with("sshw:doctor:"));
        assert_eq!(first.user, "doctor");
    }

    #[test]
    fn health_probe_cleanup_failure_is_reported() {
        let err = super::cleanup_health_probe(Err(keyring_core::Error::NotSupportedByStore(
            "cleanup failed".to_string(),
        )))
        .unwrap_err();

        assert!(err.to_string().contains("credential health cleanup failed"));
    }
}
