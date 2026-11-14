//! The Mneme layer.
//!
//! Mneme's index is a live SQLite WAL database, which repository snapshots and
//! directory datasets deliberately refuse. Mneme is the owner of that format, so
//! this layer never copies the live files: it asks `mneme snapshot create` for a
//! consistent, integrity-checked export, re-hashes it independently, and
//! publishes it into [`ObjectStorage`] as:
//!
//! ```text
//! mneme/v1/chunks/sha256/<aa>/<sha256>          fixed-size content-addressed chunks
//! mneme/v1/snapshots/<label>/<stamp>-<sha12>.json immutable layer manifest
//! ```
//!
//! Chunks are written create-if-absent before the manifest, so a manifest's
//! presence implies its chunks were published. Nothing is overwritten or
//! deleted. Verification and restore reassemble the file, check every chunk and
//! the whole-file digest, and then hand the result back to Mneme's own
//! validator; Rebsync never claims a snapshot is sound on its own authority.
//!
//! The object store is local and plaintext (owner-only). Off-machine,
//! encrypted coverage comes from the optional restic step.

use crate::{
    config::Config,
    journal::Journal,
    process,
    storage::{ObjectKey, ObjectStorage, PutOutcome, StorageError},
    sync,
};
use anyhow::{Context, Result, bail, ensure};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::{
    fs::File,
    io::{Read, Write},
    path::{Path, PathBuf},
    process::Command,
};

pub const LAYER_SCHEMA: &str = "rebsync.mneme.snapshot.v1";
pub const OWNER_SCHEMA: &str = "mneme.snapshot.v1";
const PREFIX: &str = "mneme/v1";
const SNAPSHOT_FILE: &str = "mneme-index.sqlite";

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Chunk {
    pub sha256: String,
    pub size: u64,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LayerManifest {
    pub schema: String,
    /// `<label>/<stamp>-<sha12>`, unique per published snapshot.
    pub id: String,
    pub label: String,
    pub created_at: DateTime<Utc>,
    pub run_id: Option<String>,
    pub sha256: String,
    pub bytes: u64,
    pub chunk_bytes: u64,
    pub chunks: Vec<Chunk>,
    /// Mneme's own manifest: schema, generation, counts, sources, integrity.
    pub owner: Value,
}

#[derive(Debug, Serialize)]
pub struct PublishOutcome {
    pub id: String,
    pub manifest_key: String,
    pub sha256: String,
    pub bytes: u64,
    pub chunks: usize,
    pub new_chunks: usize,
    pub reused_chunks: usize,
    pub new_bytes: u64,
    pub restic_snapshot: Option<String>,
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
        "mneme.label must be 1..64 of ASCII letters, digits, '.', '-' or '_'"
    );
    Ok(())
}

fn valid_sha256(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
}

fn chunk_key(sha256: &str) -> Result<ObjectKey> {
    ensure!(valid_sha256(sha256), "invalid chunk digest");
    Ok(ObjectKey::parse(&format!(
        "{PREFIX}/chunks/sha256/{}/{sha256}",
        &sha256[..2]
    ))?)
}

fn manifest_key(id: &str) -> Result<ObjectKey> {
    let (label, name) = id
        .split_once('/')
        .context("snapshot id must be <label>/<name>")?;
    validate_label(label)?;
    ensure!(
        !name.is_empty() && !name.contains('/'),
        "snapshot id must be <label>/<name>"
    );
    Ok(ObjectKey::parse(&format!(
        "{PREFIX}/snapshots/{label}/{name}.json"
    ))?)
}

fn mneme(config: &Config, db: Option<&Path>) -> Command {
    let mut cmd = process::command(&config.mneme.binary.to_string_lossy());
    if let Some(db) = db.or(config.mneme.db.as_deref()) {
        cmd.arg("--db").arg(db);
    }
    // Avoid Rust backtraces in captured output; diagnostics are suppressed anyway.
    cmd.env_remove("RUST_BACKTRACE");
    cmd
}

fn owner_json(bytes: &[u8]) -> Result<Value> {
    let value: Value = serde_json::from_slice(bytes).context("mneme returned non-JSON output")?;
    ensure!(
        value.get("schema").and_then(Value::as_str) == Some(OWNER_SCHEMA),
        "mneme snapshot schema is not {OWNER_SCHEMA}; upgrade mneme"
    );
    ensure!(
        value.get("integrity").and_then(Value::as_str) == Some("ok"),
        "mneme did not report a passing integrity check"
    );
    Ok(value)
}

fn hash_file(path: &Path) -> Result<(String, u64)> {
    let mut file = File::open(path)?;
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

fn read_full(file: &mut File, buffer: &mut [u8]) -> std::io::Result<usize> {
    let mut filled = 0;
    while filled < buffer.len() {
        match file.read(&mut buffer[filled..])? {
            0 => break,
            n => filled += n,
        }
    }
    Ok(filled)
}

fn staging(config: &Config) -> Result<tempfile::TempDir> {
    let state = sync::state_dir(config)?;
    let parent = state.join("mneme");
    sync::private_dir(&parent)?;
    // tempfile creates directories owner-only on Unix.
    Ok(tempfile::Builder::new()
        .prefix("stage-")
        .tempdir_in(parent)?)
}

/// Ask Mneme for a consistent export into `dir`, then re-hash it here so the
/// digest is not taken on the exporter's word alone.
pub fn export(config: &Config, dir: &Path, journal: &mut Journal) -> Result<(PathBuf, Value)> {
    let out = dir.join(SNAPSHOT_FILE);
    let mut cmd = mneme(config, None);
    cmd.args(["snapshot", "create", "--out"]).arg(&out);
    let stdout = sync::checked(
        journal,
        dir,
        "mneme-snapshot-create",
        json!([
            "mneme",
            "--db",
            "<configured>",
            "snapshot",
            "create",
            "--out",
            out
        ]),
        &mut cmd,
        config.mneme.timeout_seconds,
    )?;
    let owner = owner_json(&stdout)?;
    let (sha256, bytes) = hash_file(&out)?;
    ensure!(
        owner.get("sha256").and_then(Value::as_str) == Some(sha256.as_str())
            && owner.get("bytes").and_then(Value::as_u64) == Some(bytes),
        "mneme-reported digest/size does not match the exported file"
    );
    Ok((out, owner))
}

fn put_chunk(storage: &dyn ObjectStorage, data: &[u8]) -> Result<(Chunk, bool)> {
    let sha256 = format!("{:x}", Sha256::digest(data));
    let key = chunk_key(&sha256)?;
    let size = data.len() as u64;
    let created = match storage.put_if_absent(&key, data)? {
        PutOutcome::Created(_) => true,
        PutOutcome::AlreadyExists(meta) => {
            // Same digest, same key: a size mismatch means damaged storage.
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

/// Chunk and publish an exported snapshot file. Chunks first, manifest last.
pub fn publish_file(
    config: &Config,
    storage: &dyn ObjectStorage,
    path: &Path,
    owner: Value,
    run_id: Option<&str>,
) -> Result<PublishOutcome> {
    let chunk_bytes = config.mneme.chunk_bytes;
    let mut file = File::open(path)?;
    let mut buffer = vec![0_u8; chunk_bytes as usize];
    let mut whole = Sha256::new();
    let mut chunks = Vec::new();
    let (mut new_chunks, mut new_bytes, mut total) = (0, 0, 0_u64);
    loop {
        let n = read_full(&mut file, &mut buffer)?;
        if n == 0 {
            break;
        }
        whole.update(&buffer[..n]);
        total += n as u64;
        let (chunk, created) = put_chunk(storage, &buffer[..n])?;
        if created {
            new_chunks += 1;
            new_bytes += chunk.size;
        }
        chunks.push(chunk);
    }
    let sha256 = format!("{:x}", whole.finalize());
    ensure!(
        owner.get("sha256").and_then(Value::as_str) == Some(sha256.as_str()),
        "snapshot changed while it was being published"
    );
    let created_at = Utc::now();
    let id = format!(
        "{}/{}-{}",
        config.mneme.label,
        created_at.format("%Y%m%dT%H%M%S%.3fZ"),
        &sha256[..12]
    );
    let manifest = LayerManifest {
        schema: LAYER_SCHEMA.into(),
        id: id.clone(),
        label: config.mneme.label.clone(),
        created_at,
        run_id: run_id.map(String::from),
        sha256: sha256.clone(),
        bytes: total,
        chunk_bytes,
        chunks,
        owner,
    };
    let key = manifest_key(&id)?;
    match storage.put_if_absent(&key, &serde_json::to_vec_pretty(&manifest)?)? {
        PutOutcome::Created(_) => {}
        PutOutcome::AlreadyExists(_) => bail!("manifest {key} already exists; not overwriting"),
    }
    Ok(PublishOutcome {
        id,
        manifest_key: key.to_string(),
        sha256,
        bytes: total,
        chunks: manifest.chunks.len(),
        new_chunks,
        reused_chunks: manifest.chunks.len() - new_chunks,
        new_bytes,
        restic_snapshot: None,
    })
}

/// Export, publish and optionally restic-encrypt one Mneme snapshot.
pub fn publish(
    config: &Config,
    storage: &dyn ObjectStorage,
    journal: &mut Journal,
) -> Result<PublishOutcome> {
    let stage = staging(config)?;
    let (path, owner) = export(config, stage.path(), journal)?;
    let run_id = journal.run_id.clone();
    let mut outcome = publish_file(config, storage, &path, owner, Some(&run_id))?;
    journal.event(
        "mneme-published",
        &outcome.manifest_key,
        json!({"id":outcome.id,"sha256":outcome.sha256,"bytes":outcome.bytes,"chunks":outcome.chunks,"new_chunks":outcome.new_chunks}),
    )?;
    if config.mneme.restic {
        // The staged directory holds only the verified export plus its manifest.
        let manifest = storage.get(&manifest_key(&outcome.id)?)?;
        process::write_private(&stage.path().join("rebsync-mneme-manifest.json"), &manifest)?;
        let tag = format!("rebsync-mneme:{}:{}", journal.run_id, config.mneme.label);
        outcome.restic_snapshot = Some(sync::restic_backup(config, stage.path(), &tag, journal)?);
    }
    Ok(outcome)
}

/// Entry point for `rebsync --apply`: never fails the run, reports status.
pub fn run_layer(config: &Config, journal: &mut Journal) -> Value {
    #[cfg(feature = "storage-object-store")]
    {
        if config.mneme.restic && config.backup.repository.is_none() {
            return json!({"name":"mneme","kind":"mneme","status":"blocked","reason":"mneme.restic requires backup.repository; set mneme.restic = false to publish locally only"});
        }
        let storage = match crate::storage::FsObjectStorage::open(&config.storage.root) {
            Ok(storage) => storage,
            Err(error) => {
                return json!({"name":"mneme","kind":"mneme","status":"failed","error":error.to_string()});
            }
        };
        match publish(config, &storage, journal) {
            Ok(outcome) => {
                // Local object storage shares this disk; only restic counts as backed up.
                let status = if outcome.restic_snapshot.is_some() {
                    "backed-up"
                } else {
                    "published-local"
                };
                json!({"name":"mneme","kind":"mneme","status":status,"snapshot":outcome})
            }
            Err(error) => {
                json!({"name":"mneme","kind":"mneme","status":"failed","error":format!("{error:#}")})
            }
        }
    }
    #[cfg(not(feature = "storage-object-store"))]
    {
        let _ = (config, journal);
        json!({"name":"mneme","kind":"mneme","status":"blocked","reason":"built without object storage support"})
    }
}

/// Published manifests, oldest first. Unparseable manifests are reported, not skipped.
pub fn list(storage: &dyn ObjectStorage, label: Option<&str>) -> Result<Vec<LayerManifest>> {
    let prefix = match label {
        Some(label) => {
            validate_label(label)?;
            format!("{PREFIX}/snapshots/{label}/")
        }
        None => format!("{PREFIX}/snapshots/"),
    };
    let mut found = Vec::new();
    for meta in storage.list_prefix(&prefix, 0)? {
        if !meta.key.ends_with(".json") {
            continue;
        }
        let bytes = storage.get(&ObjectKey::parse(&meta.key)?)?;
        let manifest: LayerManifest = serde_json::from_slice(&bytes)
            .with_context(|| format!("unreadable layer manifest {}", meta.key))?;
        found.push(manifest);
    }
    found.sort_by(|a, b| a.created_at.cmp(&b.created_at).then(a.id.cmp(&b.id)));
    Ok(found)
}

pub fn load(storage: &dyn ObjectStorage, id: &str) -> Result<LayerManifest> {
    let key = manifest_key(id)?;
    let manifest: LayerManifest = serde_json::from_slice(&storage.get(&key)?)
        .with_context(|| format!("unreadable layer manifest {key}"))?;
    ensure!(manifest.schema == LAYER_SCHEMA, "unsupported layer schema");
    ensure!(manifest.id == id, "manifest id does not match its key");
    ensure!(valid_sha256(&manifest.sha256), "invalid manifest digest");
    ensure!(
        manifest.chunks.iter().map(|c| c.size).sum::<u64>() == manifest.bytes,
        "chunk sizes do not add up to the snapshot size"
    );
    Ok(manifest)
}

/// Reassemble a snapshot into a new owner-only file, checking every chunk and
/// the whole-file digest. Refuses to overwrite.
pub fn assemble(storage: &dyn ObjectStorage, manifest: &LayerManifest, out: &Path) -> Result<()> {
    let mut opts = std::fs::OpenOptions::new();
    opts.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(0o600);
    }
    let mut file = opts
        .open(out)
        .with_context(|| format!("create {}", out.display()))?;
    let mut whole = Sha256::new();
    for (index, chunk) in manifest.chunks.iter().enumerate() {
        let data = storage.get(&chunk_key(&chunk.sha256)?)?;
        ensure!(
            data.len() as u64 == chunk.size
                && format!("{:x}", Sha256::digest(&data)) == chunk.sha256,
            "chunk {index} ({}) is damaged",
            chunk.sha256
        );
        whole.update(&data);
        file.write_all(&data)?;
    }
    file.sync_all()?;
    ensure!(
        format!("{:x}", whole.finalize()) == manifest.sha256,
        "reassembled snapshot digest does not match the manifest"
    );
    Ok(())
}

/// Reassemble and let Mneme validate the result. Writes nothing persistent.
pub fn verify(
    config: &Config,
    storage: &dyn ObjectStorage,
    id: &str,
    journal: &mut Journal,
) -> Result<Value> {
    let manifest = load(storage, id)?;
    let stage = staging(config)?;
    let path = stage.path().join(SNAPSHOT_FILE);
    assemble(storage, &manifest, &path)?;
    let mut cmd = mneme(config, None);
    cmd.args(["snapshot", "verify"])
        .arg(&path)
        .args(["--sha256", &manifest.sha256]);
    let stdout = sync::checked(
        journal,
        stage.path(),
        "mneme-snapshot-verify",
        json!([
            "mneme",
            "snapshot",
            "verify",
            path,
            "--sha256",
            manifest.sha256
        ]),
        &mut cmd,
        config.mneme.timeout_seconds,
    )?;
    let owner = owner_json(&stdout)?;
    Ok(
        json!({"id":manifest.id,"sha256":manifest.sha256,"bytes":manifest.bytes,"chunks":manifest.chunks.len(),"owner_verification":owner}),
    )
}

/// Restore into a *new* index at `target`; Mneme refuses existing indexes.
pub fn restore(
    config: &Config,
    storage: &dyn ObjectStorage,
    id: &str,
    target: &Path,
    journal: &mut Journal,
) -> Result<Value> {
    let manifest = load(storage, id)?;
    let stage = staging(config)?;
    let path = stage.path().join(SNAPSHOT_FILE);
    assemble(storage, &manifest, &path)?;
    let mut cmd = mneme(config, Some(target));
    cmd.args(["snapshot", "restore", "--from"])
        .arg(&path)
        .args(["--sha256", &manifest.sha256]);
    let stdout = sync::checked(
        journal,
        target,
        "mneme-snapshot-restore",
        json!([
            "mneme",
            "--db",
            target,
            "snapshot",
            "restore",
            "--from",
            path,
            "--sha256",
            manifest.sha256
        ]),
        &mut cmd,
        config.mneme.timeout_seconds,
    )?;
    let owner = owner_json(&stdout)?;
    Ok(
        json!({"id":manifest.id,"restored_to":target,"sha256":manifest.sha256,"owner_verification":owner}),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn keys_and_labels_are_constrained() {
        assert!(validate_label("local").is_ok());
        for bad in ["", ".", "..", "a/b", "sp ace", &"x".repeat(65)] {
            assert!(validate_label(bad).is_err(), "accepted {bad:?}");
        }
        assert!(manifest_key("local/20261114T000000.000Z-abc").is_ok());
        for bad in ["local", "local/", "local/a/b", "../x", "/x"] {
            assert!(manifest_key(bad).is_err(), "accepted id {bad:?}");
        }
        assert!(chunk_key("zz").is_err());
        assert_eq!(
            chunk_key(&"ab".repeat(32)).unwrap().as_str(),
            format!("mneme/v1/chunks/sha256/ab/{}", "ab".repeat(32))
        );
    }
}
