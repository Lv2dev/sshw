use super::{CredentialStore, CredentialStoreHealth};
use std::cell::RefCell;
use std::collections::HashMap;

/// In-memory credential store that never touches the OS keyring. Useful for
/// ephemeral/CI contexts where secrets must not be persisted. A password may
/// be supplied for the invocation via the `SSHW_PASSWORD` environment
/// variable; anything stored with `set_password` lives only for this process.
#[derive(Debug, Default)]
pub struct SessionOnlyStore {
    session_password: Option<String>,
    values: RefCell<HashMap<(String, String), String>>,
}

impl SessionOnlyStore {
    pub fn new() -> Self {
        Self::default()
    }

    /// Seed the session password from `SSHW_PASSWORD` (empty is treated as
    /// unset).
    pub fn from_env() -> Self {
        let session_password = std::env::var("SSHW_PASSWORD")
            .ok()
            .filter(|value| !value.is_empty());
        Self {
            session_password,
            values: RefCell::new(HashMap::new()),
        }
    }

    pub fn with_session_password(password: Option<String>) -> Self {
        Self {
            session_password: password,
            values: RefCell::new(HashMap::new()),
        }
    }
}

impl CredentialStore for SessionOnlyStore {
    fn set_password(&self, credential: &str, user: &str, password: &str) -> anyhow::Result<()> {
        self.values.borrow_mut().insert(
            (credential.to_string(), user.to_string()),
            password.to_string(),
        );
        Ok(())
    }

    fn get_password(&self, credential: &str, user: &str) -> anyhow::Result<String> {
        if let Some(value) = self
            .values
            .borrow()
            .get(&(credential.to_string(), user.to_string()))
        {
            return Ok(value.clone());
        }
        self.session_password.clone().ok_or_else(|| {
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
}
