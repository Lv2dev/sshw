pub mod keyring_store;
pub mod session_store;

use std::fmt;
use zeroize::Zeroize;

#[derive(Clone)]
pub enum AuthMaterial {
    Password(String),
    Agent,
}

impl fmt::Debug for AuthMaterial {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Password(_) => formatter
                .debug_tuple("Password")
                .field(&"<redacted>")
                .finish(),
            Self::Agent => formatter.write_str("Agent"),
        }
    }
}

impl Drop for AuthMaterial {
    fn drop(&mut self) {
        if let Self::Password(password) = self {
            password.zeroize();
        }
    }
}

#[derive(Debug, Clone)]
pub struct CredentialStoreHealth {
    pub backend: String,
    pub available: bool,
    pub message: String,
}

/// Abstraction over a credential backend. Implemented by the native OS keyring
/// (`keyring_store`) and the in-memory `session_store`; an external-helper
/// backend (shelling out to a user-provided program that prints the secret) is
/// a planned extension behind this same trait.
pub trait CredentialStore {
    fn set_password(&self, credential: &str, user: &str, password: &str) -> anyhow::Result<()>;
    fn get_password(&self, credential: &str, user: &str) -> anyhow::Result<String>;
    fn delete_password(&self, credential: &str, user: &str) -> anyhow::Result<()>;
    fn health_check(&self) -> anyhow::Result<CredentialStoreHealth>;

    fn set_password_for(
        &self,
        _purpose: crate::home::CredentialPurpose,
        credential: &str,
        user: &str,
        password: &str,
    ) -> anyhow::Result<()> {
        self.set_password(credential, user, password)
    }

    fn get_password_for(
        &self,
        _purpose: crate::home::CredentialPurpose,
        credential: &str,
        user: &str,
    ) -> anyhow::Result<String> {
        self.get_password(credential, user)
    }

    fn delete_password_for(
        &self,
        _purpose: crate::home::CredentialPurpose,
        credential: &str,
        user: &str,
    ) -> anyhow::Result<()> {
        self.delete_password(credential, user)
    }

    /// Whether `set_password` durably persists the secret across invocations.
    /// Non-persistent backends (e.g. session-only) let the CLI warn that a
    /// stored password will not survive the process.
    fn is_persistent(&self) -> bool {
        true
    }
}
