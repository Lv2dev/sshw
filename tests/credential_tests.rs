use sshw::credentials::{AuthMaterial, CredentialStore, CredentialStoreHealth};
use std::cell::RefCell;
use std::collections::BTreeMap;

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
fn auth_material_debug_redacts_password() {
    let auth = AuthMaterial::Password("YOUR_PASSWORD".to_string());
    let debug = format!("{auth:?}");

    assert!(debug.contains("<redacted>"));
    assert!(!debug.contains("YOUR_PASSWORD"));
}
