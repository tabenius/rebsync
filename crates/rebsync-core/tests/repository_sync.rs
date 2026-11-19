#![cfg(all(feature = "peer-http", feature = "storage-object-store"))]
use anyhow::{Result, ensure};
use rebsync_core::{
    FsObjectStorage, ObjectKey, ObjectStorage, layer,
    repository_sync::{self, RepositoryApi, Source},
};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::{cell::RefCell, collections::BTreeMap};

#[derive(Default)]
struct Memory {
    objects: RefCell<BTreeMap<String, Vec<u8>>>,
    writes: RefCell<Vec<String>>,
    fail_write: RefCell<Option<usize>>,
    hostile_listing: RefCell<Option<Value>>,
}
impl RepositoryApi for Memory {
    fn describe(&self) -> Result<Value> {
        Ok(json!({"private":true}))
    }
    fn list(&self, prefix: &str, after: Option<&str>, limit: usize) -> Result<Value> {
        if let Some(value) = &*self.hostile_listing.borrow() {
            return Ok(value.clone());
        }
        let objects = self.objects.borrow();
        // Small pages ensure cursor handling is exercised on every test.
        let limit = limit.min(2);
        let all: Vec<_> = objects
            .iter()
            .filter(|(key, _)| {
                key.starts_with(prefix) && after.is_none_or(|after| key.as_str() > after)
            })
            .collect();
        let entries: Vec<_> = all.iter().take(limit).map(|(key, bytes)| json!({"key":key,"sha256":format!("{:x}",Sha256::digest(bytes)),"size_bytes":bytes.len()})).collect();
        Ok(
            json!({"objects":entries,"next_after":if all.len() > limit { entries.last().map(|entry| entry["key"].clone()) } else { None }}),
        )
    }
    fn read(&self, key: &str) -> Result<Vec<u8>> {
        self.objects
            .borrow()
            .get(key)
            .cloned()
            .ok_or_else(|| anyhow::anyhow!("missing object"))
    }
    fn append(&self, key: &str, bytes: &[u8]) -> Result<Value> {
        ensure!(
            self.fail_write
                .borrow()
                .is_none_or(|at| self.writes.borrow().len() != at),
            "simulated interrupted transfer"
        );
        let mut objects = self.objects.borrow_mut();
        let created = !objects.contains_key(key);
        if let Some(prior) = objects.get(key) {
            ensure!(prior == bytes, "immutable conflict");
        } else {
            objects.insert(key.into(), bytes.into());
        }
        self.writes.borrow_mut().push(key.into());
        Ok(json!({"created":created}))
    }
}

fn snapshot(
    storage: &dyn ObjectStorage,
    dir: &std::path::Path,
    content: &[u8],
) -> layer::PublishOutcome {
    std::fs::write(dir.join("data.txt"), content).unwrap();
    layer::publish_files(
        storage,
        "frog",
        "local",
        65536,
        dir,
        &["data.txt".into()],
        json!({"fixture":true}),
        None,
    )
    .unwrap()
}

#[test]
fn push_and_pull_roundtrip_is_additive_hash_checked_and_source_scoped() {
    let dir = tempfile::tempdir().unwrap();
    let source = FsObjectStorage::open(dir.path().join("local")).unwrap();
    let outcome = snapshot(&source, dir.path(), &vec![b'x'; 150000]);
    let remote = Memory::default();
    let laptop = Source::new("laptop-uuid", "Laptop").unwrap();
    let layers = vec!["frog".into()];
    let pushed = repository_sync::push(&remote, &source, &laptop, &layers).unwrap();
    assert!(pushed.complete);
    assert!(pushed.transferred >= 3);
    assert_eq!(pushed.verified_snapshots, 1);
    let writes = remote.writes.borrow();
    assert!(writes.last().unwrap().contains("/snapshots/"));
    drop(writes);
    let retried = repository_sync::push(&remote, &source, &laptop, &layers).unwrap();
    assert!(retried.complete);
    assert_eq!(retried.transferred, 0);
    assert!(retried.already_present >= 3);
    // Same content and native snapshot ID still have separate upstream scope.
    repository_sync::push(
        &remote,
        &source,
        &Source::new("phone-uuid", "Phone").unwrap(),
        &layers,
    )
    .unwrap();
    let listed = repository_sync::sources(&remote).unwrap();
    assert_eq!(listed.len(), 2);
    let destination = FsObjectStorage::open(dir.path().join("download")).unwrap();
    let pulled = repository_sync::pull(&remote, &destination, "laptop-uuid", &layers).unwrap();
    assert!(pulled.complete);
    assert_eq!(pulled.transferred, pushed.transferred);
    assert_eq!(
        repository_sync::pull(&remote, &destination, "laptop-uuid", &layers)
            .unwrap()
            .transferred,
        0
    );
    assert!(destination.list_prefix("frog/", 0).unwrap().is_empty());
    let scoped =
        FsObjectStorage::open(dir.path().join("download/sources/v1/laptop-uuid/objects")).unwrap();
    assert!(layer::check_snapshot(&scoped, "frog", &outcome.manifest_key).ok);
    assert!(
        repository_sync::pull(&remote, &destination, "phone-uuid", &layers)
            .unwrap()
            .complete
    );
    assert_eq!(
        destination.list_prefix("sources/v1/", 0).unwrap().len(),
        2 * (pushed.transferred + 1)
    );
}

#[test]
fn interrupted_transfer_can_resume_without_overwriting_or_republishing_bad_manifests() {
    let dir = tempfile::tempdir().unwrap();
    let local = FsObjectStorage::open(dir.path().join("local")).unwrap();
    snapshot(&local, dir.path(), &vec![b'y'; 150000]);
    let remote = Memory::default();
    *remote.fail_write.borrow_mut() = Some(2);
    let source = Source::new("usb-source", "USB").unwrap();
    let layers = vec!["frog".into()];
    assert!(repository_sync::push(&remote, &local, &source, &layers).is_err());
    assert!(
        !remote
            .objects
            .borrow()
            .keys()
            .any(|key| key.contains("/snapshots/"))
    );
    *remote.fail_write.borrow_mut() = None;
    assert!(
        repository_sync::push(&remote, &local, &source, &layers)
            .unwrap()
            .complete
    );
    assert!(
        repository_sync::push(
            &remote,
            &local,
            &Source::new("usb-source", "Different device").unwrap(),
            &layers
        )
        .is_err()
    );
}

#[test]
fn incomplete_remote_snapshots_never_become_visible_locally() {
    let dir = tempfile::tempdir().unwrap();
    let local = FsObjectStorage::open(dir.path().join("local")).unwrap();
    snapshot(&local, dir.path(), b"private source");
    let remote = Memory::default();
    let source = Source::new("original", "Original").unwrap();
    let layers = vec!["frog".into()];
    repository_sync::push(&remote, &local, &source, &layers).unwrap();
    remote
        .objects
        .borrow_mut()
        .retain(|key, _| !key.contains("/chunks/"));
    let destination = FsObjectStorage::open(dir.path().join("download")).unwrap();
    let pulled = repository_sync::pull(&remote, &destination, "original", &layers).unwrap();
    assert!(!pulled.complete);
    assert!(!pulled.rejected.is_empty());
    assert!(
        !destination
            .list_prefix("sources/v1/", 0)
            .unwrap()
            .iter()
            .any(|meta| meta.key.contains("/snapshots/"))
    );
}

#[test]
fn equal_size_conflicting_bytes_are_not_mistaken_for_already_present() {
    let dir = tempfile::tempdir().unwrap();
    let local = FsObjectStorage::open(dir.path().join("local")).unwrap();
    snapshot(&local, dir.path(), b"original");
    let remote = Memory::default();
    let source = Source::new("original", "Original").unwrap();
    let layers = vec!["frog".into()];
    repository_sync::push(&remote, &local, &source, &layers).unwrap();
    let chunk = remote
        .objects
        .borrow()
        .keys()
        .find(|key| key.contains("/chunks/"))
        .unwrap()
        .clone();
    remote
        .objects
        .borrow_mut()
        .insert(chunk.clone(), b"conflict".to_vec());
    let pushed = repository_sync::push(&remote, &local, &source, &layers).unwrap();
    assert!(!pushed.complete);
    assert_eq!(pushed.conflicts.len(), 1);
    assert_eq!(remote.objects.borrow()[&chunk], b"conflict");
    let destination = FsObjectStorage::open(dir.path().join("download")).unwrap();
    // Corrupt chunk is rejected by its content-address, regardless of HTTP hash.
    let pulled = repository_sync::pull(&remote, &destination, "original", &layers).unwrap();
    assert!(!pulled.complete);
    assert!(pulled.rejected.len() >= 2);
}

#[test]
fn invalid_or_oversized_local_objects_abort_before_any_remote_write() {
    let dir = tempfile::tempdir().unwrap();
    let local = FsObjectStorage::open(dir.path().join("local")).unwrap();
    local
        .put_if_absent(
            &ObjectKey::parse("frog/v1/not-a-layer-object").unwrap(),
            b"bad",
        )
        .unwrap();
    let remote = Memory::default();
    let pushed = repository_sync::push(
        &remote,
        &local,
        &Source::new("laptop", "Laptop").unwrap(),
        &["frog".into()],
    )
    .unwrap();
    assert!(!pushed.complete);
    assert!(remote.objects.borrow().is_empty());
    assert!(Source::new("../escape", "Name").is_err());
    assert!(Source::new("safe", "\u{001b} Name").is_err());
}

#[test]
fn out_of_scope_and_nonadvancing_pagination_are_rejected() {
    let remote = Memory::default();
    *remote.hostile_listing.borrow_mut() = Some(json!({"objects":[],"next_after":"repeat"}));
    assert!(repository_sync::sources(&remote).is_err());
    *remote.hostile_listing.borrow_mut() = Some(
        json!({"objects":[{"key":"foreign/key","sha256":"a".repeat(64),"size_bytes":1}],"next_after":null}),
    );
    assert!(repository_sync::sources(&remote).is_err());
}
