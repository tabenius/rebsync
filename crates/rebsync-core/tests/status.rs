#![cfg(feature = "storage-object-store")]

use rebsync_core::{Config, FsObjectStorage, status};

#[test]
fn status_read_does_not_create_private_state() -> anyhow::Result<()> {
    let home = tempfile::tempdir()?;
    let mut config = Config::defaults(home.path().to_path_buf());
    config.storage.root = home.path().join("objects");
    let storage = FsObjectStorage::open(&config.storage.root)?;

    let value = status::collect(&config, &storage, 2)?;

    assert_eq!(value["schema"], "rbq.status.v1");
    assert_eq!(value["overall"]["state"], "disabled");
    assert!(!home.path().join(".rebeqah").exists());
    assert!(
        value["layers"]
            .as_array()
            .is_some_and(|layers| !layers.is_empty())
    );
    Ok(())
}
