use super::{CredentialStore, CredentialStoreHealth};
use std::sync::OnceLock;

#[derive(Debug, Default, Clone)]
pub struct KeyringCredentialStore;

impl CredentialStore for KeyringCredentialStore {
    fn set_password(&self, credential: &str, user: &str, password: &str) -> anyhow::Result<()> {
        ensure_native_store()?;
        let entry = keyring_core::Entry::new(credential, user)?;
        entry.set_password(password)?;
        Ok(())
    }

    fn get_password(&self, credential: &str, user: &str) -> anyhow::Result<String> {
        ensure_native_store()?;
        let entry = keyring_core::Entry::new(credential, user)?;
        Ok(entry.get_password()?)
    }

    fn delete_password(&self, credential: &str, user: &str) -> anyhow::Result<()> {
        ensure_native_store()?;
        let entry = keyring_core::Entry::new(credential, user)?;
        match entry.delete_credential() {
            Ok(()) => Ok(()),
            Err(keyring_core::Error::NoEntry) => Ok(()),
            Err(err) => Err(err.into()),
        }
    }

    fn health_check(&self) -> anyhow::Result<CredentialStoreHealth> {
        ensure_native_store()?;
        let backend = backend_name().to_string();
        let credential = "sshw:doctor";
        let user = "doctor";
        let entry = keyring_core::Entry::new(credential, user)?;
        entry.set_password("doctor-secret")?;
        let value = entry.get_password()?;
        let _ = entry.delete_credential();

        Ok(CredentialStoreHealth {
            backend,
            available: value == "doctor-secret",
            message: "credential store read/write succeeded".to_string(),
        })
    }
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
        keyring::use_named_store("windows")
    }
    #[cfg(target_os = "macos")]
    {
        keyring::use_named_store("keychain")
    }
    #[cfg(target_os = "linux")]
    {
        keyring::use_named_store("secret-service")
    }
    #[cfg(any(target_os = "freebsd", target_os = "openbsd"))]
    {
        keyring::use_named_store("secret-service")
    }
    #[cfg(not(any(
        target_os = "windows",
        target_os = "macos",
        target_os = "linux",
        target_os = "freebsd",
        target_os = "openbsd"
    )))]
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
    #[cfg(any(target_os = "freebsd", target_os = "openbsd"))]
    {
        "secret-service"
    }
    #[cfg(not(any(
        target_os = "windows",
        target_os = "macos",
        target_os = "linux",
        target_os = "freebsd",
        target_os = "openbsd"
    )))]
    {
        "unsupported"
    }
}
