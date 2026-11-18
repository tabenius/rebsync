//! Shared machinery for owner-exported data layers (Mneme, Frog, agenda).
//!
//! A layer snapshot is one or more files that the data's *owner* exported and
//! that were validated before publication. Files are split into fixed-size,
//! content-addressed chunks under `<layer>/v1/chunks/sha256/<aa>/<sha256>`,
//! written create-if-absent before an immutable manifest at
//! `<layer>/v1/snapshots/<label>/<stamp>-<digest12>.json`. A manifest's
//! presence therefore implies its chunks were published. Nothing is ever
//! overwritten or deleted.
//!
//! Manifests may arrive from peers, so everything read back is treated as
//! untrusted: keys, relative paths, sizes and digests are re-validated, and
//! reassembly checks every chunk and every whole file.

use crate::{
    config::Config,
    storage::{ObjectKey, ObjectStorage, PutOutcome, StorageError},
    sync,
};
use anyhow::{Context, Result, bail, ensure};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::{
    fs::File,
    io::{Read, Write},
    path::{Component, Path},
};

pub const SNAPSHOT_SCHEMA: &str = "rbq.layer.snapshot.v1";
/// Layers whose objects Rebeqah publishes and exchanges with peers.
pub const LAYERS: &[&str] = &["mneme", "frog", "agenda", "git", "binaries"];

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Chunk {
    pub sha256: String,
    pub size: u64,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LayerFile {
    /// Relative path inside the snapshot, `/`-separated.
    pub path: String,
    pub sha256: String,
    pub bytes: u64,
    pub chunks: Vec<Chunk>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SnapshotManifest {
    pub schema: String,
    pub layer: String,
    /// `<label>/<stamp>-<digest12>`.
    pub id: String,
    pub label: String,
    pub created_at: DateTime<Utc>,
    pub run_id: Option<String>,
    pub chunk_bytes: u64,
    /// SHA-256 over the sorted `path\0sha256\n` lines: identifies the content.
    pub digest: String,
    pub files: Vec<LayerFile>,
    /// What the owner (or Rebeqah's validator) reported about the export.
    pub owner: Value,
}

impl SnapshotManifest {
    pub fn bytes(&self) -> u64 {
        self.files.iter().map(|f| f.bytes).sum()
    }
}

#[derive(Debug, Serialize)]
pub struct PublishOutcome {
    pub layer: String,
    pub id: String,
    pub manifest_key: String,
    pub digest: String,
    pub files: usize,
    pub bytes: u64,
    pub chunks: usize,
    pub new_chunks: usize,
    pub reused_chunks: usize,
    pub new_bytes: u64,
    pub restic_snapshot: Option<String>,
}

#[derive(Debug, Default, Serialize)]
pub struct LayerStats {
    pub layer: String,
    pub snapshots: usize,
    pub latest_id: Option<String>,
    pub latest_created_at: Option<DateTime<Utc>>,
    pub logical_bytes: u64,
    pub stored_chunks: usize,
    pub stored_bytes: u64,
    pub orphan_chunks: usize,
    pub orphan_bytes: u64,
    pub missing_chunks: usize,
    /// Referenced bytes whose chunks are absent; the transfer still required
    /// for this layer to be complete.
    pub missing_bytes: u64,
}

pub fn validate_label(label: &str) -> Result<()> {
    ensure!(
        !label.is_empty()
            && label.len() <= 64
            && label != "."
            && label != ".."
            && label
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'-' | b'_')),
        "label must be 1..64 of ASCII letters, digits, '.', '-' or '_'"
    );
    Ok(())
}

fn validate_layer(layer: &str) -> Result<()> {
    ensure!(LAYERS.contains(&layer), "unknown layer {layer:?}");
    Ok(())
}

pub fn valid_sha256(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
}

/// A relative path from an untrusted manifest: plain segments of safe ASCII.
pub fn validate_relative_path(path: &str) -> Result<()> {
    ensure!(
        !path.is_empty() && path.len() <= 512,
        "file path must be 1..512 bytes"
    );
    for component in Path::new(path).components() {
        match component {
            Component::Normal(segment) => {
                let segment = segment.to_str().context("non-UTF-8 path")?;
                ensure!(
                    !segment.starts_with('.') || segment == ".rbq-keep",
                    "hidden path segment {segment:?}"
                );
                ensure!(
                    segment
                        .bytes()
                        .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'-' | b'_')),
                    "unsupported character in {segment:?}"
                );
            }
            _ => bail!("path {path:?} must be relative without '.' or '..'"),
        }
    }
    ensure!(!path.contains('\\'), "backslash in path");
    Ok(())
}

pub fn chunk_key(prefix: &str, sha256: &str) -> Result<ObjectKey> {
    ensure!(valid_sha256(sha256), "invalid chunk digest");
    Ok(ObjectKey::parse(&format!(
        "{prefix}/chunks/sha256/{}/{sha256}",
        &sha256[..2]
    ))?)
}

fn prefix(layer: &str) -> String {
    format!("{layer}/v1")
}

pub fn manifest_key(layer: &str, id: &str) -> Result<ObjectKey> {
    validate_layer(layer)?;
    let (label, name) = id
        .split_once('/')
        .context("snapshot id must be <label>/<name>")?;
    validate_label(label)?;
    ensure!(
        !name.is_empty() && !name.contains('/'),
        "snapshot id must be <label>/<name>"
    );
    Ok(ObjectKey::parse(&format!(
        "{}/snapshots/{label}/{name}.json",
        prefix(layer)
    ))?)
}

pub fn read_full(file: &mut File, buffer: &mut [u8]) -> std::io::Result<usize> {
    let mut filled = 0;
    while filled < buffer.len() {
        match file.read(&mut buffer[filled..])? {
            0 => break,
            n => filled += n,
        }
    }
    Ok(filled)
}

pub fn hash_file(path: &Path) -> Result<(String, u64)> {
    let mut file = File::open(path).with_context(|| format!("open {}", path.display()))?;
    let mut hasher = Sha256::new();
    let mut buffer = vec![0_u8; 1 << 20];
    let mut total = 0;
    loop {
        let n = file.read(&mut buffer)?;
        if n == 0 {
            break;
        }
        hasher.update(&buffer[..n]);
        total += n as u64;
    }
    Ok((format!("{:x}", hasher.finalize()), total))
}

/// Private staging directory for one layer operation.
pub fn staging(config: &Config, layer: &str) -> Result<tempfile::TempDir> {
    let state = sync::state_dir(config)?;
    let parent = state.join(layer);
    sync::private_dir(&parent)?;
    Ok(tempfile::Builder::new()
        .prefix("stage-")
        .tempdir_in(parent)?)
}

/// Write one chunk unless an identical-size object already exists.
pub fn put_chunk(storage: &dyn ObjectStorage, prefix: &str, data: &[u8]) -> Result<(Chunk, bool)> {
    let sha256 = format!("{:x}", Sha256::digest(data));
    let key = chunk_key(prefix, &sha256)?;
    let size = data.len() as u64;
    // Most chunks of a republished snapshot exist already; HEAD avoids
    // rewriting them. put_if_absent still guards the race.
    match storage.head(&key) {
        Ok(meta) if meta.size == size => return Ok((Chunk { sha256, size }, false)),
        Ok(meta) => {
            return Err(StorageError::Corrupt(format!(
                "{key}: stored {} bytes, expected {size}",
                meta.size
            ))
            .into());
        }
        Err(StorageError::NotFound(_)) => {}
        Err(error) => return Err(error.into()),
    }
    let created = match storage.put_if_absent(&key, data)? {
        PutOutcome::Created(_) => true,
        PutOutcome::AlreadyExists(meta) => {
            if meta.size != size {
                return Err(StorageError::Corrupt(format!(
                    "{key}: stored {} bytes, expected {size}",
                    meta.size
                ))
                .into());
            }
            false
        }
    };
    Ok((Chunk { sha256, size }, created))
}

/// Chunk one file. Returns the file record plus (new chunks, new bytes).
pub fn chunk_file(
    storage: &dyn ObjectStorage,
    prefix: &str,
    path: &Path,
    relative: &str,
    chunk_bytes: u64,
) -> Result<(LayerFile, usize, u64)> {
    let mut file = File::open(path).with_context(|| format!("open {}", path.display()))?;
    let mut buffer = vec![0_u8; chunk_bytes as usize];
    let mut whole = Sha256::new();
    let (mut chunks, mut new_chunks, mut new_bytes, mut total) = (Vec::new(), 0, 0, 0_u64);
    loop {
        let n = read_full(&mut file, &mut buffer)?;
        if n == 0 {
            break;
        }
        whole.update(&buffer[..n]);
        total += n as u64;
        let (chunk, created) = put_chunk(storage, prefix, &buffer[..n])?;
        if created {
            new_chunks += 1;
            new_bytes += chunk.size;
        }
        chunks.push(chunk);
    }
    Ok((
        LayerFile {
            path: relative.to_owned(),
            sha256: format!("{:x}", whole.finalize()),
            bytes: total,
            chunks,
        },
        new_chunks,
        new_bytes,
    ))
}

fn content_digest(files: &[LayerFile]) -> String {
    let mut lines: Vec<String> = files
        .iter()
        .map(|f| format!("{}\0{}\n", f.path, f.sha256))
        .collect();
    lines.sort();
    format!("{:x}", Sha256::digest(lines.concat().as_bytes()))
}

/// Publish already-validated files from `dir` (relative paths) as a snapshot.
#[allow(clippy::too_many_arguments)]
pub fn publish_files(
    storage: &dyn ObjectStorage,
    layer: &str,
    label: &str,
    chunk_bytes: u64,
    dir: &Path,
    relative: &[String],
    owner: Value,
    run_id: Option<&str>,
) -> Result<PublishOutcome> {
    validate_layer(layer)?;
    validate_label(label)?;
    ensure!(!relative.is_empty(), "a snapshot needs at least one file");
    let prefix = prefix(layer);
    let mut files = Vec::new();
    let (mut new_chunks, mut new_bytes) = (0, 0);
    for path in relative {
        validate_relative_path(path)?;
        let (file, created, created_bytes) =
            chunk_file(storage, &prefix, &dir.join(path), path, chunk_bytes)?;
        new_chunks += created;
        new_bytes += created_bytes;
        files.push(file);
    }
    let digest = content_digest(&files);
    let created_at = Utc::now();
    let id = format!(
        "{label}/{}-{}",
        created_at.format("%Y%m%dT%H%M%S%.3fZ"),
        &digest[..12]
    );
    let manifest = SnapshotManifest {
        schema: SNAPSHOT_SCHEMA.into(),
        layer: layer.into(),
        id: id.clone(),
        label: label.into(),
        created_at,
        run_id: run_id.map(String::from),
        chunk_bytes,
        digest: digest.clone(),
        files,
        owner,
    };
    let key = manifest_key(layer, &id)?;
    match storage.put_if_absent(&key, &serde_json::to_vec_pretty(&manifest)?)? {
        PutOutcome::Created(_) => {}
        PutOutcome::AlreadyExists(_) => bail!("manifest {key} already exists; not overwriting"),
    }
    let chunks: usize = manifest.files.iter().map(|f| f.chunks.len()).sum();
    Ok(PublishOutcome {
        layer: layer.into(),
        id,
        manifest_key: key.to_string(),
        digest,
        files: manifest.files.len(),
        bytes: manifest.bytes(),
        chunks,
        new_chunks,
        reused_chunks: chunks - new_chunks,
        new_bytes,
        restic_snapshot: None,
    })
}

/// Validate a manifest read from storage (possibly written by a peer).
pub fn check_manifest(manifest: &SnapshotManifest, layer: &str, id: &str) -> Result<()> {
    ensure!(
        manifest.schema == SNAPSHOT_SCHEMA,
        "unsupported snapshot schema"
    );
    ensure!(manifest.layer == layer, "manifest belongs to another layer");
    ensure!(manifest.id == id, "manifest id does not match its key");
    ensure!(valid_sha256(&manifest.digest), "invalid manifest digest");
    ensure!(!manifest.files.is_empty(), "manifest lists no files");
    manifest
        .files
        .iter()
        .try_fold(0_u64, |sum, file| sum.checked_add(file.bytes))
        .context("manifest byte count overflows u64")?;
    let mut seen = std::collections::BTreeSet::new();
    for file in &manifest.files {
        validate_relative_path(&file.path)?;
        ensure!(seen.insert(&file.path), "duplicate path {}", file.path);
        ensure!(valid_sha256(&file.sha256), "invalid file digest");
        ensure!(
            file.chunks
                .iter()
                .try_fold(0_u64, |sum, c| sum.checked_add(c.size))
                == Some(file.bytes),
            "chunk sizes of {} do not add up",
            file.path
        );
        for chunk in &file.chunks {
            ensure!(valid_sha256(&chunk.sha256), "invalid chunk digest");
            ensure!(
                chunk.size > 0 && chunk.size <= 64 * 1024 * 1024,
                "invalid chunk size"
            );
        }
    }
    ensure!(
        content_digest(&manifest.files) == manifest.digest,
        "manifest digest does not match its file list"
    );
    Ok(())
}

pub fn load(storage: &dyn ObjectStorage, layer: &str, id: &str) -> Result<SnapshotManifest> {
    let key = manifest_key(layer, id)?;
    let manifest: SnapshotManifest = serde_json::from_slice(&storage.get(&key)?)
        .with_context(|| format!("unreadable manifest {key}"))?;
    check_manifest(&manifest, layer, id)?;
    Ok(manifest)
}

/// Published snapshots of a layer, oldest first.
pub fn list(
    storage: &dyn ObjectStorage,
    layer: &str,
    label: Option<&str>,
) -> Result<Vec<SnapshotManifest>> {
    validate_layer(layer)?;
    let base = format!("{}/snapshots/", prefix(layer));
    let wanted = match label {
        Some(label) => {
            validate_label(label)?;
            format!("{base}{label}/")
        }
        None => base,
    };
    let mut found = Vec::new();
    for meta in storage.list_prefix(&wanted, 0)? {
        let Some(id) = meta
            .key
            .strip_prefix(&format!("{}/snapshots/", prefix(layer)))
            .and_then(|rest| rest.strip_suffix(".json"))
        else {
            continue;
        };
        found.push(load(storage, layer, id)?);
    }
    found.sort_by(|a, b| a.created_at.cmp(&b.created_at).then(a.id.cmp(&b.id)));
    Ok(found)
}

/// Reassemble every file into `out` (which must not exist), checking every
/// chunk and every whole-file digest. Never writes outside `out`.
pub fn assemble(
    storage: &dyn ObjectStorage,
    manifest: &SnapshotManifest,
    out: &Path,
) -> Result<()> {
    check_manifest(manifest, &manifest.layer, &manifest.id)?;
    ensure!(
        std::fs::symlink_metadata(out).is_err(),
        "{} already exists; refusing to overwrite",
        out.display()
    );
    std::fs::create_dir_all(out)?;
    let prefix = prefix(&manifest.layer);
    for file in &manifest.files {
        let target = out.join(&file.path);
        if let Some(parent) = target.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let mut options = std::fs::OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        let mut output = options
            .open(&target)
            .with_context(|| format!("create {}", target.display()))?;
        let mut whole = Sha256::new();
        for (index, chunk) in file.chunks.iter().enumerate() {
            let data = storage.get(&chunk_key(&prefix, &chunk.sha256)?)?;
            ensure!(
                data.len() as u64 == chunk.size
                    && format!("{:x}", Sha256::digest(&data)) == chunk.sha256,
                "{}: chunk {index} ({}) is damaged",
                file.path,
                chunk.sha256
            );
            whole.update(&data);
            output.write_all(&data)?;
        }
        output.sync_all()?;
        ensure!(
            format!("{:x}", whole.finalize()) == file.sha256,
            "{}: reassembled digest does not match",
            file.path
        );
    }
    Ok(())
}

/// Read-only accounting for one layer.
pub fn stats(storage: &dyn ObjectStorage, layer: &str) -> Result<LayerStats> {
    use std::collections::BTreeMap;
    let manifests = list(storage, layer, None)?;
    let mut referenced = BTreeMap::new();
    for manifest in &manifests {
        for file in &manifest.files {
            for chunk in &file.chunks {
                referenced.insert(chunk.sha256.clone(), chunk.size);
            }
        }
    }
    let mut stored = BTreeMap::new();
    for meta in storage.list_prefix(&format!("{}/chunks/sha256/", prefix(layer)), 0)? {
        if let Some(digest) = meta.key.rsplit('/').next() {
            stored.insert(digest.to_owned(), meta.size);
        }
    }
    let orphans: Vec<u64> = stored
        .iter()
        .filter(|(d, _)| !referenced.contains_key(*d))
        .map(|(_, s)| *s)
        .collect();
    let missing_bytes = referenced
        .iter()
        .filter(|(digest, _)| !stored.contains_key(*digest))
        .map(|(_, size)| *size)
        .sum();
    let latest = manifests.last();
    Ok(LayerStats {
        layer: layer.into(),
        snapshots: manifests.len(),
        latest_id: latest.map(|m| m.id.clone()),
        latest_created_at: latest.map(|m| m.created_at),
        logical_bytes: manifests.iter().map(SnapshotManifest::bytes).sum(),
        stored_chunks: stored.len(),
        stored_bytes: stored.values().sum(),
        orphan_chunks: orphans.len(),
        orphan_bytes: orphans.iter().sum(),
        missing_chunks: referenced
            .keys()
            .filter(|d| !stored.contains_key(*d))
            .count(),
        missing_bytes,
    })
}

/// The `--apply` status vocabulary shared by all layers.
pub fn status_value(name: &str, result: Result<PublishOutcome>) -> Value {
    match result {
        Ok(outcome) => {
            let status = if outcome.restic_snapshot.is_some() {
                "backed-up"
            } else {
                "published-local"
            };
            serde_json::json!({"name": name, "kind": name, "status": status, "snapshot": outcome})
        }
        Err(error) => crate::migration::failure(name, &error),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn untrusted_paths_are_constrained() {
        for ok in ["AGENTS.db", "index.html", "a/b.json", "snapshot.json"] {
            assert!(validate_relative_path(ok).is_ok(), "{ok}");
        }
        for bad in [
            "",
            "/etc/passwd",
            "../x",
            "a/../b",
            "./a",
            ".hidden",
            "sp ace",
            "a\\b",
        ] {
            assert!(validate_relative_path(bad).is_err(), "{bad}");
        }
        assert!(manifest_key("frog", "local/x").is_ok());
        assert!(manifest_key("other", "local/x").is_err());
        assert!(manifest_key("agenda", "local/a/b").is_err());
    }
}

/// Exclusive per-layer lock: publish and prune never interleave locally.
/// (Peers are separate stores; pruning never reaches them.)
pub fn lock(config: &Config, layer: &str) -> Result<File> {
    use fs2::FileExt;
    let state = sync::state_dir(config)?;
    let file = std::fs::OpenOptions::new()
        .create(true)
        .truncate(false)
        .write(true)
        .open(state.join(format!("{layer}.lock")))?;
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(60);
    while file.try_lock_exclusive().is_err() {
        ensure!(
            std::time::Instant::now() < deadline,
            "another rbq is publishing or pruning the {layer} layer"
        );
        std::thread::sleep(std::time::Duration::from_millis(200));
    }
    Ok(file)
}

/// Shared per-layer lock for read-only observers such as `rbq status`.
///
/// Writers use `lock()` (exclusive), so a status snapshot cannot observe a
/// publish or prune halfway through. A missing state directory or lock file
/// means no writer has ever used this layer here; return `None` rather than
/// creating state from a read-only command.
pub fn read_lock(config: &Config, layer: &str) -> Result<Option<File>> {
    let state = config.rbq_home.join(".rebeqah/rbq");
    let path = match state.metadata() {
        Ok(metadata) if metadata.is_dir() => state.join(format!("{layer}.lock")),
        _ => return Ok(None),
    };
    if path.is_symlink() {
        bail!("refusing symlink lock file");
    }
    let file = match std::fs::OpenOptions::new().read(true).open(&path) {
        Ok(file) => file,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(error.into()),
    };
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(60);
    while file.try_lock_shared().is_err() {
        ensure!(
            std::time::Instant::now() < deadline,
            "another rbq is publishing or pruning the {layer} layer"
        );
        std::thread::sleep(std::time::Duration::from_millis(200));
    }
    Ok(Some(file))
}

#[derive(Clone, Debug)]
pub struct Retention {
    /// Newest snapshots kept per label; at least 1.
    pub keep_last: usize,
    /// Also keep everything created within this many days.
    pub keep_days: Option<u32>,
    pub label: Option<String>,
    /// Unreferenced chunks younger than this are left alone (an interrupted
    /// or concurrent publish may still reference them).
    pub grace: chrono::Duration,
}

#[derive(Debug, Default, Serialize)]
pub struct PruneReport {
    pub layer: String,
    pub dry_run: bool,
    pub snapshots_kept: Vec<String>,
    pub snapshots_removed: Vec<String>,
    pub chunks_removed: usize,
    pub bytes_freed: u64,
    pub chunks_deferred: usize,
    pub note: &'static str,
}

/// Chunk digests a manifest references, for both manifest formats: Mneme's
/// single-file `chunks` and the multi-file `files[].chunks`.
fn referenced_chunks(manifest: &Value) -> Result<Vec<String>> {
    let mut found = Vec::new();
    let mut take = |chunks: &Value| -> Result<()> {
        for chunk in chunks.as_array().context("chunks must be a list")? {
            let digest = chunk
                .get("sha256")
                .and_then(Value::as_str)
                .filter(|d| valid_sha256(d))
                .context("invalid chunk digest")?;
            found.push(digest.to_owned());
        }
        Ok(())
    };
    if let Some(chunks) = manifest.get("chunks") {
        take(chunks)?;
    }
    if let Some(files) = manifest.get("files").and_then(Value::as_array) {
        for file in files {
            take(file.get("chunks").context("file without chunks")?)?;
        }
    }
    // Mneme's optional sidecar chunks live in the same content-addressed
    // namespace but only in opaque owner JSON. Keep the strict record check
    // scoped to the mneme manifest schema; other layer schemas are untouched.
    if manifest.get("schema").and_then(Value::as_str) == Some(crate::mneme::LAYER_SCHEMA)
        && let Some(record) = crate::mneme::sidecar_owner_record(manifest.get("owner"))?
    {
        found.extend(record.chunks.into_iter().map(|chunk| chunk.sha256));
    }
    Ok(found)
}

/// Apply retention to one layer. Dry-run unless `apply`. Manifests go first,
/// then chunks no remaining manifest references (after the grace period).
/// A manifest that cannot be read stops the prune: its chunks might be
/// referenced, so nothing is swept on a partial view.
pub fn prune(
    storage: &dyn ObjectStorage,
    layer: &str,
    retention: &Retention,
    apply: bool,
) -> Result<PruneReport> {
    validate_layer(layer)?;
    ensure!(
        retention.keep_last >= 1,
        "keep at least one snapshot per label"
    );
    if let Some(label) = &retention.label {
        validate_label(label)?;
    }
    let base = format!("{}/snapshots/", prefix(layer));
    let mut by_label: std::collections::BTreeMap<String, Vec<(DateTime<Utc>, String, Value)>> =
        Default::default();
    for meta in storage.list_prefix(&base, 0)? {
        let Some(id) = meta
            .key
            .strip_prefix(&base)
            .and_then(|r| r.strip_suffix(".json"))
        else {
            continue;
        };
        let value: Value = serde_json::from_slice(&storage.get(&ObjectKey::parse(&meta.key)?)?)
            .with_context(|| format!("unreadable manifest {}; not pruning", meta.key))?;
        let created = value
            .get("created_at")
            .and_then(Value::as_str)
            .and_then(|t| DateTime::parse_from_rfc3339(t).ok())
            .map(|t| t.with_timezone(&Utc))
            .with_context(|| format!("{}: no created_at; not pruning", meta.key))?;
        referenced_chunks(&value).with_context(|| format!("{}; not pruning", meta.key))?;
        let label = id.split('/').next().unwrap_or_default().to_owned();
        by_label
            .entry(label)
            .or_default()
            .push((created, id.to_owned(), value));
    }
    let cutoff = retention
        .keep_days
        .map(|d| Utc::now() - chrono::Duration::days(i64::from(d)));
    let mut report = PruneReport {
        layer: layer.into(),
        dry_run: !apply,
        note: "Local only: peers keep their copies, and `rbq peer pull` would bring pruned snapshots back.",
        ..Default::default()
    };
    let mut remaining = Vec::new();
    let mut doomed = Vec::new();
    for (label, mut snapshots) in by_label {
        snapshots.sort_by(|a, b| b.0.cmp(&a.0).then(b.1.cmp(&a.1)));
        let selected = retention.label.as_deref().is_none_or(|l| l == label);
        for (rank, (created, id, value)) in snapshots.into_iter().enumerate() {
            let keep =
                !selected || rank < retention.keep_last || cutoff.is_some_and(|c| created >= c);
            if keep {
                report.snapshots_kept.push(id);
                remaining.push(value);
            } else {
                doomed.push(id);
            }
        }
    }
    // Incremental snapshots (git layer) depend on their `owner.base`: keep the
    // whole chain behind every kept snapshot, or the survivors cannot restore.
    let base_of = |value: &Value| {
        value
            .pointer("/owner/base")
            .and_then(Value::as_str)
            .map(str::to_owned)
    };
    let mut needed: Vec<String> = remaining.iter().filter_map(base_of).collect();
    while let Some(base) = needed.pop() {
        if let Some(position) = doomed.iter().position(|id| id == &base) {
            let id = doomed.remove(position);
            let key = manifest_key(layer, &id)?;
            let value: Value = serde_json::from_slice(&storage.get(&key)?)?;
            needed.extend(base_of(&value));
            report.snapshots_kept.push(id);
            remaining.push(value);
        }
    }
    let mut live = std::collections::BTreeSet::new();
    for value in &remaining {
        live.extend(referenced_chunks(value)?);
    }
    let now = Utc::now();
    let mut sweep = Vec::new();
    for meta in storage.list_prefix(&format!("{}/chunks/sha256/", prefix(layer)), 0)? {
        let digest = meta.key.rsplit('/').next().unwrap_or_default();
        if live.contains(digest) {
            continue;
        }
        let young = meta.last_modified.is_none_or(|t| now - t < retention.grace);
        if young {
            report.chunks_deferred += 1;
        } else {
            sweep.push(meta);
        }
    }
    if apply {
        for id in &doomed {
            storage.delete(&manifest_key(layer, id)?)?;
        }
        for meta in &sweep {
            storage.delete(&ObjectKey::parse(&meta.key)?)?;
        }
    }
    report.snapshots_removed = doomed;
    report.chunks_removed = sweep.len();
    report.bytes_freed = sweep.iter().map(|m| m.size).sum();
    Ok(report)
}

/// Result of checking one snapshot's structure and content.
#[derive(Debug, Serialize)]
pub struct SnapshotCheck {
    pub layer: String,
    pub key: String,
    pub ok: bool,
    pub files: usize,
    pub bytes: u64,
    pub error: Option<String>,
}

#[derive(Debug, Default, Serialize)]
pub struct FsckReport {
    pub snapshots_checked: usize,
    pub snapshots_ok: usize,
    pub failures: Vec<SnapshotCheck>,
    pub bytes_verified: u64,
    pub orphan_chunks: usize,
    pub note: &'static str,
}

/// Files of a manifest in either format: Mneme's single-file layout
/// (`sha256`, `bytes`, `chunks`) or the multi-file layer layout.
fn manifest_files(layer: &str, key: &str, value: &Value) -> Result<Vec<LayerFile>> {
    match value.get("schema").and_then(Value::as_str) {
        Some(SNAPSHOT_SCHEMA) => {
            let manifest: SnapshotManifest = serde_json::from_value(value.clone())?;
            let id = key
                .strip_prefix(&format!("{}/snapshots/", prefix(layer)))
                .and_then(|r| r.strip_suffix(".json"))
                .context("manifest key outside the layer")?;
            check_manifest(&manifest, layer, id)?;
            Ok(manifest.files)
        }
        Some("rbq.mneme.snapshot.v1") if layer == "mneme" => {
            let chunks: Vec<Chunk> = serde_json::from_value(
                value
                    .get("chunks")
                    .cloned()
                    .context("mneme manifest without chunks")?,
            )?;
            let file = LayerFile {
                path: "mneme-index.sqlite".into(),
                sha256: value
                    .get("sha256")
                    .and_then(Value::as_str)
                    .filter(|d| valid_sha256(d))
                    .context("mneme manifest without a valid sha256")?
                    .into(),
                bytes: value
                    .get("bytes")
                    .and_then(Value::as_u64)
                    .context("mneme manifest without bytes")?,
                chunks,
            };
            ensure!(
                file.chunks.iter().map(|c| c.size).sum::<u64>() == file.bytes,
                "chunk sizes do not add up"
            );
            let mut files = vec![file];
            if let Some(record) = crate::mneme::sidecar_owner_record(value.get("owner"))? {
                files.push(LayerFile {
                    path: record.path,
                    sha256: record.sha256,
                    bytes: record.bytes,
                    chunks: record
                        .chunks
                        .into_iter()
                        .map(|chunk| Chunk {
                            sha256: chunk.sha256,
                            size: chunk.bytes,
                        })
                        .collect(),
                });
            }
            Ok(files)
        }
        other => bail!("unsupported manifest schema {other:?}"),
    }
}

/// Stream every chunk of one snapshot and check chunk and whole-file digests.
/// Reads only; nothing is written.
pub fn check_snapshot(storage: &dyn ObjectStorage, layer: &str, key: &str) -> SnapshotCheck {
    let mut check = SnapshotCheck {
        layer: layer.into(),
        key: key.into(),
        ok: false,
        files: 0,
        bytes: 0,
        error: None,
    };
    let result = (|| -> Result<(usize, u64)> {
        let value: Value = serde_json::from_slice(&storage.get(&ObjectKey::parse(key)?)?)
            .context("manifest is not JSON")?;
        let files = manifest_files(layer, key, &value)?;
        let mut total = 0;
        for file in &files {
            let mut whole = Sha256::new();
            for (index, chunk) in file.chunks.iter().enumerate() {
                let data = storage
                    .get(&chunk_key(&prefix(layer), &chunk.sha256)?)
                    .with_context(|| format!("{}: chunk {index} missing", file.path))?;
                ensure!(
                    data.len() as u64 == chunk.size
                        && format!("{:x}", Sha256::digest(&data)) == chunk.sha256,
                    "{}: chunk {index} ({}) is damaged",
                    file.path,
                    chunk.sha256
                );
                whole.update(&data);
            }
            ensure!(
                format!("{:x}", whole.finalize()) == file.sha256,
                "{}: whole-file digest does not match",
                file.path
            );
            total += file.bytes;
        }
        Ok((files.len(), total))
    })();
    match result {
        Ok((files, bytes)) => {
            check.ok = true;
            check.files = files;
            check.bytes = bytes;
        }
        Err(error) => check.error = Some(format!("{error:#}")),
    }
    check
}

/// Check every snapshot of the given layers. Owner validation (SQLite
/// integrity, edition manifests) remains `rbq <layer> verify`.
pub fn fsck(storage: &dyn ObjectStorage, layers: &[&str]) -> Result<FsckReport> {
    let mut report = FsckReport {
        note: "Structural check: every chunk and file digest. Owner validation is `rbq <layer> verify ID`.",
        ..Default::default()
    };
    for layer in layers {
        validate_layer(layer)?;
        let mut live = std::collections::BTreeSet::new();
        for meta in storage.list_prefix(&format!("{}/snapshots/", prefix(layer)), 0)? {
            if !meta.key.ends_with(".json") {
                continue;
            }
            let check = check_snapshot(storage, layer, &meta.key);
            report.snapshots_checked += 1;
            if check.ok {
                report.snapshots_ok += 1;
                report.bytes_verified += check.bytes;
                if let Ok(value) =
                    serde_json::from_slice::<Value>(&storage.get(&ObjectKey::parse(&meta.key)?)?)
                {
                    live.extend(referenced_chunks(&value).unwrap_or_default());
                }
            } else {
                report.failures.push(check);
            }
        }
        if report.failures.iter().all(|f| f.layer != *layer) {
            report.orphan_chunks += storage
                .list_prefix(&format!("{}/chunks/sha256/", prefix(layer)), 0)?
                .iter()
                .filter(|m| !live.contains(m.key.rsplit('/').next().unwrap_or_default()))
                .count();
        }
    }
    Ok(report)
}
