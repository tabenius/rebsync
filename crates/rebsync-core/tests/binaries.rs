//! The binaries layer against a local object store; no restic or R2 required.
#![cfg(all(unix, feature = "storage-object-store"))]

use anyhow::Result;
use rebsync_core::{Config, FsObjectStorage, binaries, journal::Journal, layer};
use serde_json::Value;
use std::{
    fs,
    os::unix::fs::PermissionsExt,
    path::{Path, PathBuf},
};

fn config(home: &Path) -> Config {
    let mut config = Config::defaults(home.to_path_buf());
    fs::create_dir_all(home.join("empty")).unwrap();
    config.scan.roots = vec![home.join("empty")];
    config.storage.root = home.join("objects");
    config.binaries.label = "local".into();
    config.binaries.chunk_bytes = 8;
    config.binaries.restic = false;
    config
}

fn executable(path: &Path, bytes: &[u8]) -> PathBuf {
    fs::write(path, bytes).unwrap();
    fs::set_permissions(path, fs::Permissions::from_mode(0o755)).unwrap();
    path.to_path_buf()
}

fn spec(path: &Path, tool: &str, version: &str) -> binaries::BinarySpec {
    binaries::BinarySpec {
        tool: tool.into(),
        version: version.into(),
        path: path.to_path_buf(),
        target: Some("x86_64-unknown-linux-gnu".into()),
        source: Some("src/ragbaz/rebsync".into()),
        build_command: Some("cargo install --path crates/rebsync-cli --locked".into()),
        install_path: Some(PathBuf::from("/home/xyzzy/.cargo/bin/rbq")),
        note: Some("integration fixture".into()),
    }
}

fn first_chunk_path(storage_root: &Path, manifest: &layer::SnapshotManifest) -> PathBuf {
    let digest = &manifest.files[0].chunks[0].sha256;
    storage_root.join(layer::chunk_key("binaries/v1", digest).unwrap().as_str())
}

#[test]
fn publish_list_verify_restore_and_fetch_roundtrip() -> Result<()> {
    let home = tempfile::tempdir()?;
    let config = config(home.path());
    let storage = FsObjectStorage::open(&config.storage.root)?;
    let mut journal = Journal::open(home.path())?;
    let source = executable(
        &home.path().join("rbq-fixture"),
        &(0..64).map(|n| n as u8).collect::<Vec<_>>(),
    );

    let outcome = binaries::publish(
        &config,
        &storage,
        &[spec(&source, "rbq", "0.2.4")],
        &mut journal,
    )?;
    assert_eq!(outcome.files, 1);
    assert_eq!(outcome.bytes, 64);
    assert!(
        outcome.chunks > 1,
        "chunking should produce several objects"
    );
    assert!(outcome.restic_snapshot.is_none());

    let listed: Vec<Value> = binaries::list(&storage, Some("local"))?;
    assert_eq!(listed.len(), 1);
    assert_eq!(listed[0]["tools"][0]["tool"], "rbq");
    assert_eq!(listed[0]["tools"][0]["version"], "0.2.4");

    let verified = binaries::verify(&config, &storage, &outcome.id, &mut journal)?;
    assert_eq!(verified["bytes"], 64);
    assert_eq!(
        verified["tools"][0]["sha256"],
        listed[0]["tools"][0]["sha256"]
    );

    let restored = home.path().join("restored-rbq");
    let report = binaries::restore(
        &config,
        &storage,
        &outcome.id,
        "rbq",
        &restored,
        &mut journal,
    )?;
    assert_eq!(report["restored_to"].as_str(), restored.to_str());
    assert_eq!(fs::read(&restored)?, fs::read(&source)?);
    assert_eq!(
        fs::metadata(&restored)?.permissions().mode() & 0o111,
        0o111,
        "restored binaries must stay executable"
    );
    assert_eq!(
        report["build_command"],
        "cargo install --path crates/rebsync-cli --locked"
    );

    let fetched = home.path().join("fetched-rbq");
    let report = binaries::fetch(&config, &storage, "rbq", None, &fetched, &mut journal)?;
    assert_eq!(report["tool"], "rbq");
    assert_eq!(fs::read(&fetched)?, fs::read(&source)?);
    Ok(())
}

#[test]
fn tampered_and_missing_chunks_are_refused() -> Result<()> {
    let home = tempfile::tempdir()?;
    let config = config(home.path());
    let storage = FsObjectStorage::open(&config.storage.root)?;
    let mut journal = Journal::open(home.path())?;
    let source = executable(
        &home.path().join("rbq-fixture"),
        &(0..64).map(|n| n as u8).collect::<Vec<_>>(),
    );
    let outcome = binaries::publish(
        &config,
        &storage,
        &[spec(&source, "rbq", "0.2.4")],
        &mut journal,
    )?;
    let manifest = layer::load(&storage, binaries::LAYER, &outcome.id)?;
    let chunk = first_chunk_path(&config.storage.root, &manifest);

    fs::write(&chunk, b"corrupt!")?;
    assert!(binaries::verify(&config, &storage, &outcome.id, &mut journal).is_err());
    let target = home.path().join("should-not-exist");
    assert!(binaries::fetch(&config, &storage, "rbq", None, &target, &mut journal).is_err());
    assert!(
        !target.exists(),
        "a failed fetch must not leave a partial binary"
    );

    fs::remove_file(&chunk)?;
    assert!(binaries::verify(&config, &storage, &outcome.id, &mut journal).is_err());
    assert!(binaries::fetch(&config, &storage, "rbq", None, &target, &mut journal).is_err());
    assert!(!target.exists());

    assert!(
        binaries::fetch(
            &config,
            &storage,
            "unknown-tool",
            None,
            &target,
            &mut journal
        )
        .is_err()
    );
    assert!(!target.exists());
    Ok(())
}

#[test]
fn restore_never_overwrites_an_existing_path() -> Result<()> {
    let home = tempfile::tempdir()?;
    let config = config(home.path());
    let storage = FsObjectStorage::open(&config.storage.root)?;
    let mut journal = Journal::open(home.path())?;
    let source = executable(&home.path().join("rbq-fixture"), b"verified payload");
    let outcome = binaries::publish(
        &config,
        &storage,
        &[spec(&source, "rbq", "0.2.4")],
        &mut journal,
    )?;

    let existing = home.path().join("existing");
    fs::write(&existing, b"keep me")?;
    assert!(
        binaries::restore(
            &config,
            &storage,
            &outcome.id,
            "rbq",
            &existing,
            &mut journal
        )
        .is_err()
    );
    assert_eq!(fs::read(&existing)?, b"keep me");
    Ok(())
}
