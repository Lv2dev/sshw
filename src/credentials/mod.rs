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
}
