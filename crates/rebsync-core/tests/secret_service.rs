//! The Secret Service sealer against a real Secret Service (GNOME Keyring).
//! Needs a D-Bus session with an unlocked keyring, so it is ignored by
//! default; scripts/with-secret-service.sh provides one and CI runs it:
//!   scripts/with-secret-service.sh cargo test -p rebsync-core \
//!     --features secret-service --test secret_service -- --ignored
#![cfg(all(feature = "secret-service", target_os = "linux"))]

use rebsync_core::credentials::files::{FileStore, Sealer};
use rebsync_core::credentials::secret_service::{SEALER_ID, SecretServiceSealer};
use rebsync_core::credentials::{
    Audience, CredentialKind, CredentialStore, Descriptor, Scope, Secret, StoreError,
};
use std::sync::Arc;

fn descriptor(id: &str) -> Descriptor {
    Descriptor {
        id: id.into(),
        kind: CredentialKind::DashBearer,
        audience: Audience {
            endpoint: format!("https://dash.example/api/rbq/{id}"),
            account_id: "https://dash.example".into(),
            repository_id: "repository".into(),
        },
        scopes: vec![Scope::Read],
        created_at: 100,
        expires_at: u64::MAX,
        disabled: false,
    }
}

#[test]
#[ignore = "needs a Secret Service: run under scripts/with-secret-service.sh"]
fn credentials_are_sealed_by_a_key_in_the_secret_service() {
    let root = tempfile::tempdir().unwrap();
    let dir = root.path().join("credentials");
    let plain = FileStore::open(&dir).unwrap();
    let sealer: Arc<dyn Sealer> = Arc::new(SecretServiceSealer::for_store(&dir).unwrap());
    assert_eq!(sealer.id(), SEALER_ID);
    let store = plain.clone().with_sealer(sealer);
    let entry = descriptor("key-ss");
    store
        .create(entry.clone(), Secret::new(b"rbs_in_the_keyring".to_vec()))
        .unwrap();

    let file = std::fs::read_to_string(dir.join("key-ss.json")).unwrap();
    assert!(!file.contains("rbs_in_the_keyring"), "ciphertext on disk");
    assert!(file.contains(SEALER_ID));

    // A second process (a new sealer for the same directory) finds the same key.
    let again = plain
        .clone()
        .with_sealer(Arc::new(SecretServiceSealer::for_store(&dir).unwrap()));
    assert_eq!(
        again
            .use_secret("key-ss", &entry.audience, &Scope::Read, 200)
            .unwrap()
            .expose(),
        b"rbs_in_the_keyring"
    );
    // Without the keyring the secret stays shut.
    assert_eq!(
        plain
            .use_secret("key-ss", &entry.audience, &Scope::Read, 200)
            .map(|_| ()),
        Err(StoreError::Locked)
    );
    // Another directory has another key, so its sealer cannot open this one.
    let elsewhere = root.path().join("elsewhere");
    FileStore::open(&elsewhere).unwrap();
    let stranger = plain.with_sealer(Arc::new(
        SecretServiceSealer::for_store(&elsewhere).unwrap(),
    ));
    assert_eq!(
        stranger
            .use_secret("key-ss", &entry.audience, &Scope::Read, 200)
            .map(|_| ()),
        Err(StoreError::Invalid)
    );
}
