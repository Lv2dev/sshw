use super::{CredentialStore, CredentialStoreHealth};
use std::cell::RefCell;
use std::collections::HashMap;
use zeroize::Zeroizing;

/// In-memory credential store that never touches the OS keyring. Useful for
/// ephemeral/CI contexts where secrets must not be persisted. A password may
/// be supplied for the invocation via the `SSHW_PASSWORD` environment
/// variable; anything stored with `set_password` lives only for this process.
/// Held secrets are zeroized on drop.
#[derive(Default)]
pub struct SessionOnlyStore {
    session_password: Option<Zeroizing<String>>,
    values: RefCell<HashMap<(String, String), Zeroizing<String>>>,
}

impl SessionOnlyStore {
    pub fn new() -> Self {
        Self::default()
    }

    /// Seed the session password from `SSHW_PASSWORD` (empty is treated as
    /// unset), then remove the variable from this process environment to
    /// reduce how long the secret is exposed to later code or child processes.
    pub fn from_env() -> Self {
        let session_password = std::env::var("SSHW_PASSWORD")
            .ok()
            .filter(|value| !value.is_empty())
            .map(Zeroizing::new);
        // SAFETY: sshw calls this during single-threaded CLI startup before it
        // spawns child processes. Clearing the variable after reading narrows
        // the exposure window for this opt-in secret transport.
        unsafe {
            std::env::remove_var("SSHW_PASSWORD");
        }
        Self {
            session_password,
            values: RefCell::new(HashMap::new()),
        }
    }

    pub fn with_session_password(password: Option<String>) -> Self {
        Self {
            session_password: password.map(Zeroizing::new),
            values: RefCell::new(HashMap::new()),
        }
    }
}

impl CredentialStore for SessionOnlyStore {
    fn set_password(&self, credential: &str, user: &str, password: &str) -> anyhow::Result<()> {
        self.values.borrow_mut().insert(
            (credential.to_string(), user.to_string()),
            Zeroizing::new(password.to_string()),
        );
        Ok(())
    }

    fn get_password(&self, credential: &str, user: &str) -> anyhow::Result<String> {
        if let Some(value) = self
            .values
            .borrow()
            .get(&(credential.to_string(), user.to_string()))
        {
            return Ok(value.as_str().to_string());
        }
        if !allows_session_password_fallback(credential) {
            return Err(anyhow::anyhow!(
                "session-only credential backend has no explicit password for {credential}; set the privilege password for this session or use the native backend"
            ));
        }
        self.session_password
            .as_ref()
            .map(|password| password.as_str().to_string())
            .ok_or_else(|| {
                anyhow::anyhow!(
                    "session-only credential backend has no password for {credential}; set SSHW_PASSWORD or use the native backend"
                )
            })
    }

    fn delete_password(&self, credential: &str, user: &str) -> anyhow::Result<()> {
        self.values
            .borrow_mut()
            .remove(&(credential.to_string(), user.to_string()));
        Ok(())
    }

    fn health_check(&self) -> anyhow::Result<CredentialStoreHealth> {
        let message = if self.session_password.is_some() {
            "session password provided via SSHW_PASSWORD".to_string()
        } else {
            "in-memory only; no SSHW_PASSWORD set".to_string()
        };
        Ok(CredentialStoreHealth {
            backend: "session-only".to_string(),
            available: true,
            message,
        })
    }

    fn is_persistent(&self) -> bool {
        false
    }
}

fn allows_session_password_fallback(credential: &str) -> bool {
    !credential.contains(":privilege:")
}
