//! Additive Dash repository exchange. Each upstream source has an explicit,
//! stable ID/name; replicas never collapse sources by local IDs or equal bytes.
use crate::{
    layer, peer,
    repository::{MAX_OBJECT_BYTES, Repository},
    storage::{
        ObjectKey, ObjectMeta, ObjectStorage, PutOutcome, StorageCapabilities, StorageError,
    },
};
use anyhow::{Context, Result, ensure};
use serde::{Deserialize, Serialize};
use std::{collections::BTreeMap, ops::Range};

const MAX_KEYS: usize = 10000;

/// Narrow immutable transport seam; transfer policy is shared by HTTP and tests.
pub trait RepositoryApi {
    fn describe(&self) -> Result<serde_json::Value>;
    fn list(&self, prefix: &str, after: Option<&str>, limit: usize) -> Result<serde_json::Value>;
    fn read(&self, key: &str) -> Result<Vec<u8>>;
    fn append(&self, key: &str, bytes: &[u8]) -> Result<serde_json::Value>;
}
impl RepositoryApi for Repository {
    fn describe(&self) -> Result<serde_json::Value> {
        Repository::describe(self)
    }
    fn list(&self, prefix: &str, after: Option<&str>, limit: usize) -> Result<serde_json::Value> {
        Repository::list(self, prefix, after, limit)
    }
    fn read(&self, key: &str) -> Result<Vec<u8>> {
        Repository::read(self, key)
    }
    fn append(&self, key: &str, bytes: &[u8]) -> Result<serde_json::Value> {
        Repository::append(self, key, bytes)
    }
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Source {
    pub schema: String,
    pub id: String,
    pub name: String,
}

impl Source {
    pub fn new(id: &str, name: &str) -> Result<Self> {
        ensure!(
            !id.is_empty() && id.len() <= 128 && !id.contains('/'),
            "source ID must be a single safe key segment, at most 128 bytes"
        );
        ObjectKey::parse(id)?;
        ensure!(
            !name.trim().is_empty()
                && name.chars().count() <= 200
                && !name.chars().any(char::is_control),
            "source name must be 1..200 printable characters"
        );
        Ok(Self {
            schema: "rbq.source.v1".into(),
            id: id.into(),
            name: name.into(),
        })
    }
    fn prefix(&self) -> String {
        format!("sources/v1/{}/", self.id)
    }
    fn descriptor_key(&self) -> String {
        format!("{}source.json", self.prefix())
    }
    fn objects_prefix(&self) -> String {
        format!("{}objects/", self.prefix())
    }
}

#[derive(Clone, Deserialize)]
struct Entry {
    key: String,
    sha256: String,
    size_bytes: u64,
}

#[derive(Default, Debug, Serialize)]
pub struct Report {
    pub direction: String,
    pub source_id: String,
    pub source_name: String,
    pub transferred: usize,
    pub transferred_bytes: u64,
    pub already_present: usize,
    pub conflicts: Vec<String>,
    pub rejected: Vec<String>,
    pub verified_snapshots: usize,
    pub complete: bool,
}

fn hash(bytes: &[u8]) -> String {
    crate::wire::sha256_hex(bytes)
}

fn inventory(repository: &dyn RepositoryApi, prefix: &str) -> Result<BTreeMap<String, Entry>> {
    let mut entries = BTreeMap::new();
    let mut after: Option<String> = None;
    for _ in 0..=MAX_KEYS / 100 {
        let value = repository.list(prefix, after.as_deref(), 100)?;
        ensure!(
            value.get("next_after").is_some(),
            "repository omitted pagination state"
        );
        let page = value["objects"]
            .as_array()
            .context("repository omitted objects page")?;
        ensure!(page.len() <= 100, "repository returned too many entries");
        let mut previous = after.clone();
        for value in page {
            let entry: Entry =
                serde_json::from_value(value.clone()).context("invalid repository entry")?;
            ObjectKey::parse(&entry.key)?;
            ensure!(
                entry.key.starts_with(prefix)
                    && previous.as_ref().is_none_or(|key| entry.key > *key)
                    && layer::valid_sha256(&entry.sha256)
                    && entry.size_bytes <= MAX_OBJECT_BYTES as u64,
                "invalid, out-of-scope or unordered repository listing"
            );
            previous = Some(entry.key.clone());
            entries.insert(entry.key.clone(), entry);
            ensure!(
                entries.len() <= MAX_KEYS,
                "repository inventory exceeds key limit"
            );
        }
        match &value["next_after"] {
            serde_json::Value::Null => return Ok(entries),
            serde_json::Value::String(next) => {
                ensure!(
                    !page.is_empty() && Some(next) == previous.as_ref(),
                    "invalid repository pagination cursor"
                );
                after = Some(next.clone());
            }
            _ => anyhow::bail!("invalid repository pagination cursor"),
        }
    }
    anyhow::bail!("repository pagination did not terminate")
}

fn check_layers(layers: &[String]) -> Result<()> {
    ensure!(
        !layers.is_empty()
            && layers
                .iter()
                .all(|name| layer::LAYERS.contains(&name.as_str())),
        "select one or more supported layers"
    );
    let unique: std::collections::BTreeSet<_> = layers.iter().collect();
    ensure!(unique.len() == layers.len(), "duplicate layer selection");
    Ok(())
}

pub fn sources(repository: &dyn RepositoryApi) -> Result<Vec<Source>> {
    let mut sources = Vec::new();
    for entry in inventory(repository, "sources/v1/")?.into_values() {
        if entry.key.ends_with("/source.json") {
            let source: Source = serde_json::from_slice(&repository.read(&entry.key)?)?;
            ensure!(
                source == Source::new(&source.id, &source.name)?
                    && source.descriptor_key() == entry.key,
                "invalid source descriptor"
            );
            sources.push(source);
        }
    }
    Ok(sources)
}

fn read_source(repository: &dyn RepositoryApi, id: &str) -> Result<Source> {
    let candidate = Source::new(id, "validate")?;
    let source: Source = serde_json::from_slice(&repository.read(&candidate.descriptor_key())?)?;
    ensure!(
        source == Source::new(id, &source.name)?,
        "source identity or schema mismatch"
    );
    Ok(source)
}

fn report(direction: &str, source: &Source) -> Report {
    Report {
        direction: direction.into(),
        source_id: source.id.clone(),
        source_name: source.name.clone(),
        ..Default::default()
    }
}

/// Re-runnable, source-scoped transfer. Local store is read-only. A preflight
/// verifies every candidate manifest before any remote publication.
pub fn push(
    repository: &dyn RepositoryApi,
    storage: &dyn ObjectStorage,
    source: &Source,
    layers: &[String],
) -> Result<Report> {
    ensure!(
        *source == Source::new(&source.id, &source.name)?,
        "unsupported source schema"
    );
    check_layers(layers)?;
    repository.describe()?;
    let mut result = report("push", source);
    let remote = inventory(repository, &source.prefix())?;
    let descriptor = serde_json::to_vec(source)?;
    if let Some(entry) = remote.get(&source.descriptor_key()) {
        // Preserve an upstream source's stable ID/name. Never silently rename or
        // merge a different source into an existing namespace.
        let prior: Source = serde_json::from_slice(&repository.read(&entry.key)?)?;
        ensure!(
            prior == *source,
            "source ID already has a different name or schema"
        );
    }
    let mut objects = Vec::new();
    for name in layers {
        for meta in storage.list_prefix(&format!("{name}/v1/"), MAX_KEYS + 1)? {
            ensure!(
                objects.len() < MAX_KEYS,
                "local inventory exceeds repository key limit"
            );
            if meta.size > MAX_OBJECT_BYTES as u64 {
                result.rejected.push(format!(
                    "{}: exceeds Dash's 256 KiB object limit; use smaller owner-export chunks",
                    meta.key
                ));
                continue;
            }
            let bytes = storage.get(&ObjectKey::parse(&meta.key)?)?;
            ObjectKey::parse(&format!("{}{}", source.objects_prefix(), meta.key))?;
            ensure!(
                bytes.len() <= MAX_OBJECT_BYTES,
                "local object grew beyond transfer size limit"
            );
            if let Err(error) = peer::validate_received_object(&meta.key, &bytes) {
                result.rejected.push(format!("{}: {error}", meta.key));
                continue;
            }
            if meta.key.contains("/snapshots/") {
                let check = layer::check_snapshot_bytes(storage, name, &meta.key, &bytes);
                if !check.ok {
                    result.rejected.push(format!(
                        "{}: incomplete or corrupt local snapshot",
                        meta.key
                    ));
                    continue;
                }
                result.verified_snapshots += 1;
            }
            objects.push((meta.key, meta.size));
        }
    }
    if !result.rejected.is_empty() {
        return Ok(result);
    }
    objects.sort_by_key(|(key, _)| (key.contains("/snapshots/"), key.clone()));
    repository.append(&source.descriptor_key(), &descriptor)?;
    for (key, _) in objects {
        let bytes = storage.get(&ObjectKey::parse(&key)?)?;
        peer::validate_received_object(&key, &bytes)?;
        // Recheck the dependency closure after chunks transfer; a concurrent
        // local prune must not cause a manifest to be advertised as complete.
        if key.contains("/snapshots/") {
            let name = key.split('/').next().unwrap_or_default();
            ensure!(
                layer::check_snapshot_bytes(storage, name, &key, &bytes).ok,
                "local snapshot changed during push"
            );
        }
        let remote_key = format!("{}{key}", source.objects_prefix());
        if let Some(entry) = remote.get(&remote_key) {
            // Same size is NOT enough. The server verifies its stored bytes on
            // read, so compare both the listing digest and actual content.
            if entry.size_bytes == bytes.len() as u64
                && entry.sha256 == hash(&bytes)
                && repository.read(&remote_key)? == bytes
            {
                result.already_present += 1;
            } else {
                result.conflicts.push(key);
            }
        } else {
            let ack = repository.append(&remote_key, &bytes)?;
            if ack["created"] == true {
                result.transferred += 1;
                result.transferred_bytes += bytes.len() as u64;
            } else {
                result.already_present += 1;
            }
        }
        // Do not publish manifests after any chunk conflict.
        if !result.conflicts.is_empty() {
            return Ok(result);
        }
    }
    result.complete = true;
    Ok(result)
}

/// Pull into `<destination>/sources/v1/<id>/objects`, never flattening an
/// upstream source into the destination's own layer namespace. Manifests are
/// checked against destination chunks BEFORE immutable publication.
pub fn pull(
    repository: &dyn RepositoryApi,
    destination: &dyn ObjectStorage,
    id: &str,
    layers: &[String],
) -> Result<Report> {
    check_layers(layers)?;
    repository.describe()?;
    ensure!(
        destination.capabilities().atomic_create_if_absent,
        "pull requires atomic create-if-absent storage; no unsafe single-writer fallback"
    );
    ensure!(
        destination.capabilities().owner_only_permissions,
        "private repository pull requires an owner-only destination (chmod 700)"
    );
    let source = read_source(repository, id)?;
    let mut result = report("pull", &source);
    let descriptor_key = ObjectKey::parse(&source.descriptor_key())?;
    let descriptor = serde_json::to_vec(&source)?;
    if let PutOutcome::AlreadyExists(_) = destination.put_if_absent(&descriptor_key, &descriptor)? {
        let prior: Source = serde_json::from_slice(&destination.get(&descriptor_key)?)?;
        ensure!(
            prior == source,
            "destination source ID already has different metadata"
        );
    }
    let scoped = ScopedStorage {
        storage: destination,
        prefix: source.objects_prefix(),
    };
    let remote = inventory(repository, &source.objects_prefix())?;
    let mut selected = Vec::new();
    for entry in remote.into_values() {
        let key = entry
            .key
            .strip_prefix(&source.objects_prefix())
            .context("invalid source scope")?
            .to_owned();
        let name = key.split('/').next().unwrap_or_default();
        if !layers.iter().any(|layer| layer == name) {
            continue;
        }
        if peer::validate_peer_key(&key).is_err() {
            result
                .rejected
                .push(format!("{key}: not a supported layer object"));
            continue;
        }
        selected.push((key, entry));
    }
    selected.sort_by_key(|(key, _)| (key.contains("/snapshots/"), key.clone()));
    for (key, entry) in selected {
        let object_key = ObjectKey::parse(&key)?;
        let bytes = repository.read(&entry.key)?;
        ensure!(
            hash(&bytes) == entry.sha256 && bytes.len() as u64 == entry.size_bytes,
            "repository listing/content mismatch"
        );
        if let Err(error) = peer::validate_received_object(&key, &bytes) {
            result.rejected.push(format!("{key}: {error}"));
            continue;
        }
        if key.contains("/snapshots/") {
            let name = key.split('/').next().unwrap_or_default();
            if !layer::check_snapshot_bytes(&scoped, name, &key, &bytes).ok {
                result.rejected.push(format!(
                    "{key}: missing or corrupt destination chunks; manifest not published"
                ));
                continue;
            }
            result.verified_snapshots += 1;
        }
        match scoped.put_if_absent(&object_key, &bytes)? {
            PutOutcome::Created(_) => {
                result.transferred += 1;
                result.transferred_bytes += bytes.len() as u64;
            }
            PutOutcome::AlreadyExists(_) => {
                if scoped.get(&object_key)? == bytes {
                    result.already_present += 1;
                } else {
                    result.conflicts.push(key);
                }
            }
        }
    }
    result.complete = result.conflicts.is_empty() && result.rejected.is_empty();
    Ok(result)
}

struct ScopedStorage<'a> {
    storage: &'a dyn ObjectStorage,
    prefix: String,
}
impl ScopedStorage<'_> {
    fn key(&self, key: &ObjectKey) -> Result<ObjectKey, StorageError> {
        ObjectKey::parse(&format!("{}{key}", self.prefix))
    }
}
impl ObjectStorage for ScopedStorage<'_> {
    fn capabilities(&self) -> StorageCapabilities {
        self.storage.capabilities()
    }
    fn put(&self, _: &ObjectKey, _: &[u8]) -> Result<ObjectMeta, StorageError> {
        Err(StorageError::Unsupported("immutable source scope".into()))
    }
    fn delete(&self, _: &ObjectKey) -> Result<(), StorageError> {
        Err(StorageError::Unsupported("immutable source scope".into()))
    }
    fn put_if_absent(&self, key: &ObjectKey, data: &[u8]) -> Result<PutOutcome, StorageError> {
        self.storage.put_if_absent(&self.key(key)?, data)
    }
    fn get(&self, key: &ObjectKey) -> Result<Vec<u8>, StorageError> {
        self.storage.get(&self.key(key)?)
    }
    fn get_range(&self, key: &ObjectKey, range: Range<u64>) -> Result<Vec<u8>, StorageError> {
        self.storage.get_range(&self.key(key)?, range)
    }
    fn head(&self, key: &ObjectKey) -> Result<ObjectMeta, StorageError> {
        self.storage.head(&self.key(key)?)
    }
    fn list_prefix(&self, prefix: &str, limit: usize) -> Result<Vec<ObjectMeta>, StorageError> {
        crate::storage::validate_prefix(prefix)?;
        self.storage
            .list_prefix(&format!("{}{prefix}", self.prefix), limit)
    }
}
