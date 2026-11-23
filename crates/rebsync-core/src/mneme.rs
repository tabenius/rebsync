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
//! validator; Rebeqah never claims a snapshot is sound on its own authority.
//!
//! The object store is local and plaintext (owner-only). Off-machine,
//! encrypted coverage comes from the optional restic step.

use crate::{
    config::Config,
    journal::Journal,
    process,
    storage::{ObjectKey, ObjectStorage, PutOutcome},
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

pub const LAYER_SCHEMA: &str = "rbq.mneme.snapshot.v1";
pub const OWNER_SCHEMA: &str = "mneme.snapshot.v1";
const PREFIX: &str = "mneme/v1";
const SNAPSHOT_FILE: &str = "mneme-index.sqlite";
const SIDECAR_SCHEMA: &str = "mneme.outputs-sidecar.v1";
const SIDECAR_FILE: &str = "mneme-outputs.sqlite";
const SIDECAR_OWNER_KEY: &str = "tool_output_sidecar";

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Chunk {
    pub sha256: String,
    pub size: u64,
}

/// Owner-nested metadata for the optional tool-output sidecar. This is not a
/// new layer manifest field: it lives only in the opaque owner JSON.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct SidecarChunk {
    pub(crate) sha256: String,
    pub(crate) bytes: u64,
    pub(crate) offset: u64,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct SidecarRecord {
    pub(crate) schema: String,
    pub(crate) path: String,
    pub(crate) sha256: String,
    pub(crate) bytes: u64,
    pub(crate) chunks: Vec<SidecarChunk>,
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

/// Parse and strictly validate a sidecar record from owner JSON or an owner
/// report. A malformed record is never ignored.
fn sidecar_record(value: &Value) -> Result<SidecarRecord> {
    let record: SidecarRecord =
        serde_json::from_value(value.clone()).context("malformed tool-output sidecar record")?;
    ensure!(
        record.schema == SIDECAR_SCHEMA,
        "unsupported tool-output sidecar schema"
    );
    ensure!(
        !record.path.is_empty()
            && record.path.len() <= 255
            && !record.path.starts_with('.')
            && !record.path.contains('/')
            && !record.path.contains('\\')
            && record
                .path
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'-' | b'_')),
        "unsafe tool-output sidecar path"
    );
    ensure!(
        valid_sha256(&record.sha256),
        "invalid tool-output sidecar digest"
    );
    ensure!(record.bytes > 0, "invalid tool-output sidecar size");
    ensure!(
        !record.chunks.is_empty(),
        "tool-output sidecar has no chunks"
    );
    let mut offset = 0_u64;
    for (index, chunk) in record.chunks.iter().enumerate() {
        ensure!(
            valid_sha256(&chunk.sha256),
            "invalid tool-output sidecar chunk {index} digest"
        );
        ensure!(
            chunk.bytes > 0 && chunk.bytes <= 64 * 1024 * 1024,
            "invalid tool-output sidecar chunk {index} size"
        );
        ensure!(
            chunk.offset == offset,
            "tool-output sidecar chunk {index} has a non-contiguous offset"
        );
        offset = offset
            .checked_add(chunk.bytes)
            .context("tool-output sidecar chunk offsets overflow")?;
    }
    ensure!(
        offset == record.bytes,
        "tool-output sidecar chunk sizes do not add up"
    );
    Ok(record)
}

/// The sidecar field is optional; when present it must be a valid record.
pub(crate) fn sidecar_owner_record(owner: Option<&Value>) -> Result<Option<SidecarRecord>> {
    let Some(value) = owner.and_then(|owner| owner.get(SIDECAR_OWNER_KEY)) else {
        return Ok(None);
    };
    sidecar_record(value).map(Some)
}

/// Owner verify/restore commands print the sidecar manifest. They may add an
/// `available` marker, which is not part of the stored record.
fn sidecar_manifest(stdout: &[u8]) -> Result<SidecarRecord> {
    let mut value: Value =
        serde_json::from_slice(stdout).context("mneme returned non-JSON sidecar report")?;
    if let Some(object) = value.as_object_mut() {
        object.remove("available");
        object.remove("reason");
    }
    sidecar_record(&value)
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
    crate::migration::require_schema("mneme", &value, OWNER_SCHEMA)?;
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

/// Subcommands the owner lists under `snapshot --help` (clap's "Commands:"
/// section). The help request itself must succeed: an owner that cannot even
/// describe itself is broken, not merely old.
fn snapshot_commands(config: &Config) -> Result<Vec<String>> {
    let mut cmd = mneme(config, None);
    cmd.args(["snapshot", "--help"]);
    let stdout = process::checked(&mut cmd, config.mneme.timeout_seconds)
        .context("mneme snapshot --help failed; cannot detect owner capabilities")?;
    Ok(listed_commands(&String::from_utf8_lossy(&stdout)))
}

fn listed_commands(help: &str) -> Vec<String> {
    help.lines()
        .skip_while(|line| line.trim_end() != "Commands:")
        .skip(1)
        .take_while(|line| line.starts_with("  "))
        .filter_map(|line| line.split_whitespace().next())
        .map(str::to_owned)
        .collect()
}

/// Ask the owner for an optional tool-output sidecar. Capability is detected
/// explicitly: an owner that does not list `create-sidecar` has no sidecar,
/// while any failure of an owner that does list it is propagated, never
/// mistaken for "no sidecar".
fn create_sidecar(
    config: &Config,
    dir: &Path,
    journal: &mut Journal,
    out: &Path,
) -> Result<Option<SidecarRecord>> {
    if !snapshot_commands(config)?
        .iter()
        .any(|command| command == "create-sidecar")
    {
        journal.event(
            "mneme-sidecar-unsupported",
            "mneme",
            json!({"reason": "owner does not list snapshot create-sidecar"}),
        )?;
        return Ok(None);
    }
    let mut cmd = mneme(config, None);
    cmd.args(["snapshot", "create-sidecar", "--out"]).arg(out);
    let stdout = sync::checked(
        journal,
        dir,
        "mneme-snapshot-create-sidecar",
        json!([
            "mneme",
            "--db",
            "<configured>",
            "snapshot",
            "create-sidecar",
            "--out",
            out
        ]),
        &mut cmd,
        config.mneme.timeout_seconds,
    )?;
    let report: Value =
        serde_json::from_slice(&stdout).context("mneme returned non-JSON sidecar report")?;
    ensure!(
        report.get("schema").and_then(Value::as_str) == Some(SIDECAR_SCHEMA),
        "unsupported tool-output sidecar report schema"
    );
    match report.get("available").and_then(Value::as_bool) {
        Some(false) => {
            ensure!(
                report.get("reason").and_then(Value::as_str) == Some("not_initialized"),
                "unexpected tool-output sidecar unavailability reason"
            );
            Ok(None)
        }
        Some(true) => sidecar_manifest(&stdout).map(Some),
        None => bail!("tool-output sidecar report did not state availability"),
    }
}

/// Ask Mneme for a consistent export into `dir`, then re-hash it here so the
/// digest is not taken on the exporter's word alone. An available tool-output
/// sidecar is chunked into the same namespace and recorded only in owner JSON.
pub fn export(
    config: &Config,
    storage: &dyn ObjectStorage,
    dir: &Path,
    journal: &mut Journal,
) -> Result<(PathBuf, Value)> {
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
    let sidecar_out = dir.join(SIDECAR_FILE);
    let Some(record) = create_sidecar(config, dir, journal, &sidecar_out)? else {
        return Ok((out, owner));
    };
    let (sidecar_sha256, sidecar_bytes) = hash_file(&sidecar_out)?;
    ensure!(
        sidecar_sha256 == record.sha256 && sidecar_bytes == record.bytes,
        "mneme-reported sidecar digest/size does not match the exported file"
    );
    let mut sidecar = File::open(&sidecar_out)?;
    for (index, chunk) in record.chunks.iter().enumerate() {
        let mut buffer = vec![0_u8; chunk.bytes as usize];
        let n = read_full(&mut sidecar, &mut buffer)?;
        ensure!(n == buffer.len(), "sidecar chunk {index} is short");
        let (published, _) = put_chunk(storage, &buffer)?;
        ensure!(
            published.sha256 == chunk.sha256,
            "sidecar chunk {index} digest does not match the exported file"
        );
    }
    let mut owner = owner;
    owner
        .as_object_mut()
        .context("mneme owner report is not an object")?
        .insert(SIDECAR_OWNER_KEY.into(), serde_json::to_value(&record)?);
    Ok((out, owner))
}

fn put_chunk(storage: &dyn ObjectStorage, data: &[u8]) -> Result<(Chunk, bool)> {
    let (chunk, created) = crate::layer::put_chunk(storage, PREFIX, data)?;
    Ok((
        Chunk {
            sha256: chunk.sha256,
            size: chunk.size,
        },
        created,
    ))
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
    let _lock = crate::layer::lock(config, "mneme")?;
    let stage = staging(config)?;
    let (path, owner) = export(config, storage, stage.path(), journal)?;
    let run_id = journal.run_id.clone();
    let mut outcome = publish_file(config, storage, &path, owner, Some(&run_id))?;
    journal.event(
        "mneme-published",
        &outcome.manifest_key,
        json!({"id":outcome.id,"sha256":outcome.sha256,"bytes":outcome.bytes,"chunks":outcome.chunks,"new_chunks":outcome.new_chunks}),
    )?;
    if config.mneme.restic {
        // The staged directory holds only the verified export(s) plus its manifest.
        let manifest = storage.get(&manifest_key(&outcome.id)?)?;
        process::write_private(&stage.path().join("rbq-mneme-manifest.json"), &manifest)?;
        let tag = format!("rbq-mneme:{}:{}", journal.run_id, config.mneme.label);
        outcome.restic_snapshot = Some(sync::restic_backup(config, stage.path(), &tag, journal)?);
    }
    Ok(outcome)
}

/// Entry point for `rbq --apply`: never fails the run, reports status.
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
            Err(error) => crate::migration::failure("mneme", &error),
        }
    }
    #[cfg(not(feature = "storage-object-store"))]
    {
        let _ = (config, journal);
        json!({"name":"mneme","kind":"mneme","status":"blocked","reason":"built without object storage support"})
    }
}

#[derive(Debug, Serialize)]
pub struct LayerStats {
    pub snapshots: usize,
    pub latest_id: Option<String>,
    pub latest_created_at: Option<DateTime<Utc>>,
    /// Sum of snapshot sizes: what storing every snapshot whole would cost.
    pub logical_bytes: u64,
    pub referenced_chunks: usize,
    pub referenced_bytes: u64,
    pub stored_chunks: usize,
    pub stored_bytes: u64,
    /// Chunks no manifest references, e.g. from an interrupted publish.
    /// Reported only; nothing is deleted.
    pub orphan_chunks: usize,
    pub orphan_bytes: u64,
    /// Referenced chunks that are missing from storage: restore would fail.
    pub missing_chunks: usize,
}

/// Read-only accounting of what the layer holds. Lists objects, reads manifests.
pub fn stats(storage: &dyn ObjectStorage) -> Result<LayerStats> {
    use std::collections::BTreeMap;
    let manifests = list(storage, None)?;
    let mut referenced = BTreeMap::new();
    for manifest in &manifests {
        for chunk in &manifest.chunks {
            referenced.insert(chunk.sha256.clone(), chunk.size);
        }
        // Sidecar chunks share the same object namespace but are not part of
        // the manifest's top-level `chunks`; they are still referenced.
        if let Some(record) = sidecar_owner_record(Some(&manifest.owner))? {
            for chunk in &record.chunks {
                referenced.insert(chunk.sha256.clone(), chunk.bytes);
            }
        }
    }
    let mut stored = BTreeMap::new();
    for meta in storage.list_prefix(&format!("{PREFIX}/chunks/sha256/"), 0)? {
        if let Some(digest) = meta.key.rsplit('/').next() {
            stored.insert(digest.to_owned(), meta.size);
        }
    }
    let orphans: Vec<u64> = stored
        .iter()
        .filter(|(digest, _)| !referenced.contains_key(*digest))
        .map(|(_, size)| *size)
        .collect();
    let latest = manifests.last();
    Ok(LayerStats {
        snapshots: manifests.len(),
        latest_id: latest.map(|m| m.id.clone()),
        latest_created_at: latest.map(|m| m.created_at),
        logical_bytes: manifests.iter().map(|m| m.bytes).sum(),
        referenced_chunks: referenced.len(),
        referenced_bytes: referenced.values().sum(),
        stored_chunks: stored.len(),
        stored_bytes: stored.values().sum(),
        orphan_chunks: orphans.len(),
        orphan_bytes: orphans.iter().sum(),
        missing_chunks: referenced
            .keys()
            .filter(|digest| !stored.contains_key(*digest))
            .count(),
    })
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
    check_manifest(&manifest, id)?;
    Ok(manifest)
}

pub fn check_manifest(manifest: &LayerManifest, id: &str) -> Result<()> {
    ensure!(manifest.schema == LAYER_SCHEMA, "unsupported layer schema");
    ensure!(manifest.id == id, "manifest id does not match its key");
    ensure!(valid_sha256(&manifest.sha256), "invalid manifest digest");
    ensure!(
        manifest
            .chunks
            .iter()
            .try_fold(0_u64, |sum, c| sum.checked_add(c.size))
            == Some(manifest.bytes),
        "chunk sizes do not add up to the snapshot size"
    );
    for chunk in &manifest.chunks {
        ensure!(
            valid_sha256(&chunk.sha256) && chunk.size > 0 && chunk.size <= 64 * 1024 * 1024,
            "invalid chunk address or size"
        );
    }
    // Old manifests have no sidecar field. A present field is part of the
    // opaque owner JSON and must be a complete, self-consistent record.
    sidecar_owner_record(Some(&manifest.owner))?;
    Ok(())
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

/// Reassemble the optional sidecar from its owner-nested chunk list, checking
/// each chunk and the whole-file digest before the owner sees it.
fn assemble_sidecar(storage: &dyn ObjectStorage, record: &SidecarRecord, out: &Path) -> Result<()> {
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
    for (index, chunk) in record.chunks.iter().enumerate() {
        let data = storage
            .get(&chunk_key(&chunk.sha256)?)
            .with_context(|| format!("sidecar chunk {index} missing"))?;
        ensure!(
            data.len() as u64 == chunk.bytes
                && format!("{:x}", Sha256::digest(&data)) == chunk.sha256,
            "sidecar chunk {index} ({}) is damaged",
            chunk.sha256
        );
        whole.update(&data);
        file.write_all(&data)?;
    }
    file.sync_all()?;
    ensure!(
        format!("{:x}", whole.finalize()) == record.sha256,
        "reassembled sidecar digest does not match the owner record"
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
    let sidecar = sidecar_owner_record(Some(&manifest.owner))?;
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
    if let Some(record) = sidecar {
        let sidecar_path = stage.path().join(&record.path);
        assemble_sidecar(storage, &record, &sidecar_path)?;
        let mut cmd = mneme(config, None);
        cmd.args(["snapshot", "verify-sidecar"])
            .arg(&sidecar_path)
            .args(["--sha256", &record.sha256]);
        let stdout = sync::checked(
            journal,
            stage.path(),
            "mneme-snapshot-verify-sidecar",
            json!([
                "mneme",
                "snapshot",
                "verify-sidecar",
                sidecar_path,
                "--sha256",
                record.sha256
            ]),
            &mut cmd,
            config.mneme.timeout_seconds,
        )?;
        let verified = sidecar_manifest(&stdout)?;
        ensure!(
            verified.sha256 == record.sha256 && verified.bytes == record.bytes,
            "owner sidecar verification disagrees with the manifest"
        );
    }
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
    // Ask the installed owner to validate compatibility before it can create
    // the destination. A migration refusal must not leave a restored index.
    verify(config, storage, id, journal)?;
    let manifest = load(storage, id)?;
    let sidecar = sidecar_owner_record(Some(&manifest.owner))?;
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
    if let Some(record) = sidecar {
        let sidecar_path = stage.path().join(&record.path);
        assemble_sidecar(storage, &record, &sidecar_path)?;
        let mut cmd = mneme(config, Some(target));
        cmd.args(["snapshot", "restore-sidecar", "--from"])
            .arg(&sidecar_path)
            .args(["--sha256", &record.sha256]);
        let stdout = sync::checked(
            journal,
            target,
            "mneme-snapshot-restore-sidecar",
            json!([
                "mneme",
                "--db",
                target,
                "snapshot",
                "restore-sidecar",
                "--from",
                sidecar_path,
                "--sha256",
                record.sha256
            ]),
            &mut cmd,
            config.mneme.timeout_seconds,
        )?;
        let restored = sidecar_manifest(&stdout)?;
        ensure!(
            restored.sha256 == record.sha256 && restored.bytes == record.bytes,
            "owner sidecar restore disagrees with the manifest"
        );
    }
    Ok(
        json!({"id":manifest.id,"restored_to":target,"sha256":manifest.sha256,"owner_verification":owner}),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn owner_schema_and_migration_refusals_are_typed() {
        for body in [
            br#"{"schema":"mneme.snapshot.v999","integrity":"ok"}"#.as_slice(),
            br#"{"schema":"mneme.snapshot.v1","integrity":"ok","migration":{"status":"required"}}"#
                .as_slice(),
        ] {
            let error = owner_json(body).unwrap_err();
            assert!(
                error
                    .downcast_ref::<crate::migration::MigrationBlocked>()
                    .is_some()
            );
        }
    }

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

    #[test]
    fn capability_parser_reads_only_the_commands_section() {
        let help = "Snapshot operations\n\nUsage: mneme snapshot <COMMAND>\n\nCommands:\n  create          Export\n  create-sidecar  Export outputs\n  help            Print this message\n\nOptions:\n  -h, --help  Print help\n";
        assert_eq!(listed_commands(help), ["create", "create-sidecar", "help"]);
        assert!(listed_commands("create-sidecar is mentioned in prose\n").is_empty());
    }

    fn test_record() -> Value {
        json!({
            "schema": SIDECAR_SCHEMA,
            "path": SIDECAR_FILE,
            "sha256": "ab".repeat(32),
            "bytes": 10,
            "chunks": [
                {"sha256": "cd".repeat(32), "bytes": 6, "offset": 0},
                {"sha256": "ef".repeat(32), "bytes": 4, "offset": 6}
            ]
        })
    }

    fn test_manifest(owner: Value) -> LayerManifest {
        LayerManifest {
            schema: LAYER_SCHEMA.into(),
            id: "local/x".into(),
            label: "local".into(),
            created_at: Utc::now(),
            run_id: None,
            sha256: "12".repeat(32),
            bytes: 8,
            chunk_bytes: 8,
            chunks: vec![Chunk {
                sha256: "34".repeat(32),
                size: 8,
            }],
            owner,
        }
    }

    #[test]
    fn sidecar_records_fail_closed_and_are_optional() {
        assert!(sidecar_record(&test_record()).is_ok());
        assert!(check_manifest(&test_manifest(json!({})), "local/x").is_ok());
        assert!(check_manifest(&test_manifest(test_record()), "local/x").is_ok());

        let mut bad = test_record();
        bad["schema"] = json!("mneme.outputs-sidecar.v999");
        assert!(sidecar_record(&bad).is_err());
        let mut bad = test_record();
        bad["path"] = json!("../escape");
        assert!(sidecar_record(&bad).is_err());
        let mut bad = test_record();
        bad["bytes"] = json!(11);
        assert!(sidecar_record(&bad).is_err());
        let mut bad = test_record();
        bad["chunks"][1]["offset"] = json!(7);
        assert!(sidecar_record(&bad).is_err());
        let mut bad = test_record();
        bad["chunks"][0]["sha256"] = json!("zz".repeat(32));
        assert!(sidecar_record(&bad).is_err());
        let mut bad = test_record();
        bad["chunks"][0]["bytes"] = json!(0);
        assert!(sidecar_record(&bad).is_err());
        let mut bad = test_record();
        bad["extra"] = json!(true);
        assert!(sidecar_record(&bad).is_err());

        assert!(
            check_manifest(
                &test_manifest(json!({"tool_output_sidecar": null})),
                "local/x"
            )
            .is_err()
        );
    }
}
