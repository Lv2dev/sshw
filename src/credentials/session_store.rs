use super::{CredentialStore, CredentialStoreHealth};
use crate::error::app_error;
use crate::home::CredentialPurpose;
use crate::output::ErrorKind;
use std::cell::RefCell;
use std::collections::HashMap;
use zeroize::Zeroizing;

/// In-memory credential store that never touches the OS keyring. Useful for
/// ephemeral/CI contexts where secrets must not be persisted. Login and
/// privilege passwords may be supplied for the invocation via
/// `SSHW_PASSWORD` and `SSHW_PRIVILEGE_PASSWORD`; anything stored with
/// `set_password` lives only for this process. Held secrets are zeroized on
/// drop.
#[derive(Default)]
pub struct SessionOnlyStore {
    session_password: Option<Zeroizing<String>>,
    privilege_password: Option<Zeroizing<String>>,
    values: RefCell<HashMap<(u8, String, String), Zeroizing<String>>>,
}

impl SessionOnlyStore {
    pub fn new() -> Self {
        Self::default()
    }

    /// Seed purpose-specific session passwords from the environment (empty is
    /// treated as unset), then remove both variables from this process to
    /// reduce how long the secrets are exposed to later code or child
    /// processes.
    pub fn from_env() -> Self {
        let session_password = std::env::var("SSHW_PASSWORD")
            .ok()
            .filter(|value| !value.is_empty())
            .map(Zeroizing::new);
        let privilege_password = std::env::var("SSHW_PRIVILEGE_PASSWORD")
            .ok()
            .filter(|value| !value.is_empty())
            .map(Zeroizing::new);
        // SAFETY: sshw calls this during single-threaded CLI startup before it
        // spawns child processes. Clearing both variables after reading narrows
        // the exposure window for this opt-in secret transport.
        unsafe {
            std::env::remove_var("SSHW_PASSWORD");
            std::env::remove_var("SSHW_PRIVILEGE_PASSWORD");
        }
        Self {
            session_password,
            privilege_password,
            values: RefCell::new(HashMap::new()),
        }
    }

    pub fn with_session_password(password: Option<String>) -> Self {
        Self::with_session_passwords(password, None)
    }

    pub fn with_session_passwords(
        password: Option<String>,
        privilege_password: Option<String>,
    ) -> Self {
        Self {
            session_password: password.map(Zeroizing::new),
            privilege_password: privilege_password.map(Zeroizing::new),
            values: RefCell::new(HashMap::new()),
        }
    }
}

impl CredentialStore for SessionOnlyStore {
    fn set_password(&self, credential: &str, user: &str, password: &str) -> anyhow::Result<()> {
        self.set_password_for(CredentialPurpose::Login, credential, user, password)
    }

    fn get_password(&self, credential: &str, user: &str) -> anyhow::Result<String> {
        self.get_password_for(CredentialPurpose::Login, credential, user)
    }

    fn delete_password(&self, credential: &str, user: &str) -> anyhow::Result<()> {
        self.delete_password_for(CredentialPurpose::Login, credential, user)
    }

    fn set_password_for(
        &self,
        purpose: CredentialPurpose,
        credential: &str,
        user: &str,
        password: &str,
    ) -> anyhow::Result<()> {
        self.values.borrow_mut().insert(
            (
                purpose_tag(purpose),
                credential.to_string(),
                user.to_string(),
            ),
            Zeroizing::new(password.to_string()),
        );
        Ok(())
    }

    fn get_password_for(
        &self,
        purpose: CredentialPurpose,
        credential: &str,
        user: &str,
    ) -> anyhow::Result<String> {
        if let Some(value) = self.values.borrow().get(&(
            purpose_tag(purpose),
            credential.to_string(),
            user.to_string(),
        )) {
            return Ok(value.as_str().to_string());
        }
        let (fallback, environment) = match purpose {
            CredentialPurpose::Login => (&self.session_password, "SSHW_PASSWORD"),
            CredentialPurpose::Privilege => (&self.privilege_password, "SSHW_PRIVILEGE_PASSWORD"),
        };
        fallback
            .as_ref()
            .map(|password| password.as_str().to_string())
            .ok_or_else(|| {
                app_error(
                    ErrorKind::Auth,
                    format!(
                        "session-only credential backend has no password for {credential}; set {environment} or use the native backend"
                    ),
                )
            })
    }

    fn delete_password_for(
        &self,
        purpose: CredentialPurpose,
        credential: &str,
        user: &str,
    ) -> anyhow::Result<()> {
        self.values.borrow_mut().remove(&(
            purpose_tag(purpose),
            credential.to_string(),
            user.to_string(),
        ));
        Ok(())
    }

    fn health_check(&self) -> anyhow::Result<CredentialStoreHealth> {
        let message = match (
            self.session_password.is_some(),
            self.privilege_password.is_some(),
        ) {
            (true, true) => {
                "session passwords provided via SSHW_PASSWORD and SSHW_PRIVILEGE_PASSWORD"
                    .to_string()
            }
            (true, false) => "session password provided via SSHW_PASSWORD".to_string(),
            (false, true) => "privilege password provided via SSHW_PRIVILEGE_PASSWORD".to_string(),
            (false, false) => {
                "in-memory only; no SSHW_PASSWORD or SSHW_PRIVILEGE_PASSWORD set".to_string()
            }
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

fn purpose_tag(purpose: CredentialPurpose) -> u8 {
    match purpose {
        CredentialPurpose::Login => 0,
        CredentialPurpose::Privilege => 1,
    }
}
