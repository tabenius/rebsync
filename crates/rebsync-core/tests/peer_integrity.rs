//! Synthetic three-store recovery, not phone hardware or remote cloud testing.
#![cfg(feature = "storage-object-store")]
use anyhow::Result;
use rebsync_core::{
    Config, FsObjectStorage, ObjectKey, ObjectStorage, PutOutcome,
    journal::Journal,
    layer, mneme,
    peer::{self, PeerApi},
    storage::{ObjectMeta, StorageCapabilities, StorageError},
};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::{collections::BTreeMap, fs, ops::Range, path::Path};

struct Carrier<'a>(&'a FsObjectStorage);
impl PeerApi for Carrier<'_> {
    fn base(&self) -> &str {
        "synthetic-carrier"
    }
    fn status(&self) -> Result<Value> {
        Ok(json!({"protocol":"fixture"}))
    }
    fn list(&self, prefix: &str) -> Result<BTreeMap<String, u64>> {
        Ok(self
            .0
            .list_prefix(prefix, 0)?
            .into_iter()
            .map(|m| (m.key, m.size))
            .collect())
    }
    fn get(&self, key: &str) -> Result<Vec<u8>> {
        Ok(self.0.get(&ObjectKey::parse(key)?)?)
    }
    fn put(&self, key: &str, bytes: &[u8]) -> Result<bool> {
        Ok(matches!(
            self.0.put_if_absent(&ObjectKey::parse(key)?, bytes)?,
            PutOutcome::Created(_)
        ))
    }
}

fn publish(store: &dyn ObjectStorage, dir: &Path) -> Result<layer::PublishOutcome> {
    fs::create_dir_all(dir)?;
    fs::write(dir.join("sample.txt"), b"immutable portable bytes")?;
    layer::publish_files(
        store,
        "agenda",
        "fixture",
        4096,
        dir,
        &["sample.txt".into()],
        json!({"fixture":true}),
        None,
    )
}

#[test]
fn producer_carrier_recipient_recovers_without_producer_and_repeats_cleanly() -> Result<()> {
    let t = tempfile::tempdir()?;
    let producer = FsObjectStorage::open(t.path().join("producer"))?;
    let carrier = FsObjectStorage::open(t.path().join("carrier"))?;
    let recipient = FsObjectStorage::open(t.path().join("recipient"))?;
    let snapshot = publish(&producer, &t.path().join("export"))?;
    let mut journal = Journal::open(t.path())?;
    let peer = Carrier(&carrier);
    let selection = ["agenda/".into()];
    assert!(peer::push(&producer, &peer, &selection, &mut journal)?.clean());
    let repeat = peer::push(&producer, &peer, &selection, &mut journal)?;
    assert!(repeat.clean());
    assert_eq!(repeat.transferred, 0);
    drop(producer);
    let pulled = peer::pull(&recipient, &peer, &selection, &mut journal)?;
    assert!(pulled.clean(), "{pulled:?}");
    assert_eq!(pulled.verified.len(), 1);
    let repeat = peer::pull(&recipient, &peer, &selection, &mut journal)?;
    assert!(repeat.clean());
    assert_eq!(repeat.transferred, 0);
    let manifest = layer::load(&recipient, "agenda", &snapshot.id)?;
    layer::assemble(&recipient, &manifest, &t.path().join("restored"))?;
    assert_eq!(
        fs::read(t.path().join("restored/sample.txt"))?,
        b"immutable portable bytes"
    );
    Ok(())
}

#[test]
fn same_length_corrupt_replicas_are_not_copies_or_published_snapshots() -> Result<()> {
    let t = tempfile::tempdir()?;
    let producer = FsObjectStorage::open(t.path().join("producer"))?;
    let carrier = FsObjectStorage::open(t.path().join("carrier"))?;
    let snapshot = publish(&producer, &t.path().join("export"))?;
    let manifest = layer::load(&producer, "agenda", &snapshot.id)?;
    let key = layer::chunk_key("agenda/v1", &manifest.files[0].chunks[0].sha256)?;
    let original = producer.get(&key)?;
    let mut corrupt = original.clone();
    corrupt[0] ^= 1;
    carrier.put(&key, &corrupt)?;
    let mut journal = Journal::open(t.path())?;
    let peer = Carrier(&carrier);
    let selection = ["agenda/".into()];
    let report = peer::push(&producer, &peer, &selection, &mut journal)?;
    assert!(!report.clean());
    assert!(!report.conflicts.is_empty());
    assert!(carrier.list_prefix("agenda/v1/snapshots/", 0)?.is_empty());
    let report = peer::pull(&producer, &peer, &selection, &mut journal)?;
    assert!(!report.clean());
    assert!(!report.rejected.is_empty());
    assert_eq!(producer.get(&key)?, original);
    assert_eq!(carrier.get(&key)?, corrupt);
    Ok(())
}

#[test]
fn missing_chunks_prevent_manifest_publication_in_both_directions() -> Result<()> {
    let t = tempfile::tempdir()?;
    let producer = FsObjectStorage::open(t.path().join("producer"))?;
    let carrier = FsObjectStorage::open(t.path().join("carrier"))?;
    let recipient = FsObjectStorage::open(t.path().join("recipient"))?;
    let snapshot = publish(&producer, &t.path().join("export"))?;
    let manifest = layer::load(&producer, "agenda", &snapshot.id)?;
    producer.delete(&layer::chunk_key(
        "agenda/v1",
        &manifest.files[0].chunks[0].sha256,
    )?)?;
    let mut journal = Journal::open(t.path())?;
    let selection = ["agenda/".into()];
    let report = peer::push(&producer, &Carrier(&carrier), &selection, &mut journal)?;
    assert!(!report.clean());
    assert!(carrier.list_prefix("agenda/v1/snapshots/", 0)?.is_empty());
    let report = peer::pull(&recipient, &Carrier(&producer), &selection, &mut journal)?;
    assert!(!report.clean());
    assert!(!report.verification_failed.is_empty());
    assert!(recipient.list_prefix("agenda/v1/snapshots/", 0)?.is_empty());
    Ok(())
}

#[test]
fn mneme_reuses_the_verified_chunk_path() -> Result<()> {
    let t = tempfile::tempdir()?;
    let store = FsObjectStorage::open(t.path().join("objects"))?;
    let mut config = Config::defaults(t.path().into());
    config.mneme.chunk_bytes = 4096;
    let bytes = b"synthetic owner export";
    let path = t.path().join("export.sqlite");
    fs::write(&path, bytes)?;
    let digest = format!("{:x}", Sha256::digest(bytes));
    let key = layer::chunk_key("mneme/v1", &digest)?;
    store.put(&key, &vec![0; bytes.len()])?;
    let error = mneme::publish_file(
        &config,
        &store,
        &path,
        json!({"sha256":digest,"bytes":bytes.len()}),
        None,
    )
    .unwrap_err();
    assert!(
        error.to_string().contains("digest or size mismatch"),
        "{error:#}"
    );
    assert!(store.list_prefix("mneme/v1/snapshots/", 0)?.is_empty());
    Ok(())
}

/// Deterministic competing writer: HEAD reports missing, create loses to bad
/// bytes of the correct length. No threads/timing required to exercise the race.
struct CompetingStore(FsObjectStorage);
impl ObjectStorage for CompetingStore {
    fn capabilities(&self) -> StorageCapabilities {
        self.0.capabilities()
    }
    fn put(&self, k: &ObjectKey, b: &[u8]) -> Result<ObjectMeta, StorageError> {
        self.0.put(k, b)
    }
    fn put_if_absent(&self, k: &ObjectKey, b: &[u8]) -> Result<PutOutcome, StorageError> {
        self.0.put(k, &vec![0; b.len()])?;
        Ok(PutOutcome::AlreadyExists(self.0.head(k)?))
    }
    fn get(&self, k: &ObjectKey) -> Result<Vec<u8>, StorageError> {
        self.0.get(k)
    }
    fn get_range(&self, k: &ObjectKey, r: Range<u64>) -> Result<Vec<u8>, StorageError> {
        self.0.get_range(k, r)
    }
    fn head(&self, k: &ObjectKey) -> Result<ObjectMeta, StorageError> {
        Err(StorageError::NotFound(k.to_string()))
    }
    fn list_prefix(&self, p: &str, n: usize) -> Result<Vec<ObjectMeta>, StorageError> {
        self.0.list_prefix(p, n)
    }
    fn delete(&self, k: &ObjectKey) -> Result<(), StorageError> {
        self.0.delete(k)
    }
}

#[test]
fn corrupt_existing_chunk_and_competing_create_are_rejected_without_overwrite() -> Result<()> {
    let t = tempfile::tempdir()?;
    let store = FsObjectStorage::open(t.path().join("existing"))?;
    let original = b"correct immutable bytes";
    let (chunk, _) = layer::put_chunk(&store, "agenda/v1", original)?;
    let key = layer::chunk_key("agenda/v1", &chunk.sha256)?;
    store.put(&key, &vec![0; original.len()])?;
    assert!(layer::put_chunk(&store, "agenda/v1", original).is_err());
    assert_eq!(store.get(&key)?, vec![0; original.len()]);
    let race = CompetingStore(FsObjectStorage::open(t.path().join("race"))?);
    assert!(layer::put_chunk(&race, "agenda/v1", original).is_err());
    assert_eq!(race.get(&key)?, vec![0; original.len()]);
    Ok(())
}
