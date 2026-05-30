use sshw::credentials::session_store::SessionOnlyStore;
use sshw::credentials::{AuthMaterial, CredentialStore, CredentialStoreHealth};
use std::cell::RefCell;
use std::collections::BTreeMap;
use std::sync::Mutex;

static ENV_LOCK: Mutex<()> = Mutex::new(());

#[derive(Default)]
struct FakeCredentialStore {
    values: RefCell<BTreeMap<(String, String), String>>,
}

impl CredentialStore for FakeCredentialStore {
    fn set_password(&self, credential: &str, user: &str, password: &str) -> anyhow::Result<()> {
        self.values.borrow_mut().insert(
            (credential.to_string(), user.to_string()),
            password.to_string(),
        );
        Ok(())
    }

    fn get_password(&self, credential: &str, user: &str) -> anyhow::Result<String> {
        self.values
            .borrow()
            .get(&(credential.to_string(), user.to_string()))
            .cloned()
            .ok_or_else(|| anyhow::anyhow!("missing credential"))
    }

    fn delete_password(&self, credential: &str, user: &str) -> anyhow::Result<()> {
        self.values
            .borrow_mut()
            .remove(&(credential.to_string(), user.to_string()));
        Ok(())
    }

    fn health_check(&self) -> anyhow::Result<CredentialStoreHealth> {
        Ok(CredentialStoreHealth {
            backend: "fake".to_string(),
            available: true,
            message: "ok".to_string(),
        })
    }
}

#[test]
fn credential_store_trait_supports_password_lifecycle() {
    let store = FakeCredentialStore::default();

    store
        .set_password("sshw:server-alpha", "deploy", "YOUR_PASSWORD")
        .unwrap();
    assert_eq!(
        store.get_password("sshw:server-alpha", "deploy").unwrap(),
        "YOUR_PASSWORD"
    );

    store
        .delete_password("sshw:server-alpha", "deploy")
        .unwrap();
    assert!(store.get_password("sshw:server-alpha", "deploy").is_err());
}

#[test]
fn session_only_store_keeps_secrets_in_memory() {
    let store = SessionOnlyStore::new();

    // Nothing stored and no session password -> error, never persisted.
    assert!(store.get_password("sshw:default:web", "deploy").is_err());

    store
        .set_password("sshw:default:web", "deploy", "in-mem")
        .unwrap();
    assert_eq!(
        store.get_password("sshw:default:web", "deploy").unwrap(),
        "in-mem"
    );

    store.delete_password("sshw:default:web", "deploy").unwrap();
    assert!(store.get_password("sshw:default:web", "deploy").is_err());
}

#[test]
fn session_only_store_falls_back_to_session_password() {
    let store = SessionOnlyStore::with_session_password(Some("from-env".to_string()));

    // Any server without an explicit entry resolves to the session password.
    assert_eq!(
        store.get_password("sshw:default:web", "deploy").unwrap(),
        "from-env"
    );

    let health = store.health_check().unwrap();
    assert_eq!(health.backend, "session-only");
    assert!(health.available);
}

#[test]
fn session_only_store_from_env_removes_password_from_environment_after_reading() {
    let _guard = ENV_LOCK.lock().unwrap();
    unsafe {
        std::env::set_var("SSHW_PASSWORD", "from-env");
    }

    let store = SessionOnlyStore::from_env();

    assert_eq!(
        store.get_password("sshw:default:web", "deploy").unwrap(),
        "from-env"
    );
    assert!(std::env::var_os("SSHW_PASSWORD").is_none());
}

#[test]
fn session_only_store_is_not_persistent() {
    assert!(!SessionOnlyStore::new().is_persistent());
    // The default trait method (used by the native keyring) is persistent.
    assert!(FakeCredentialStore::default().is_persistent());
}

#[test]
fn session_only_store_without_password_reports_unavailable_secret() {
    let store = SessionOnlyStore::with_session_password(None);
    let err = store
        .get_password("sshw:default:web", "deploy")
        .unwrap_err();
    assert!(err.to_string().contains("session-only"));
}

#[test]
fn auth_material_debug_redacts_password() {
    let auth = AuthMaterial::Password("YOUR_PASSWORD".to_string());
    let debug = format!("{auth:?}");

    assert!(debug.contains("<redacted>"));
    assert!(!debug.contains("YOUR_PASSWORD"));
}
