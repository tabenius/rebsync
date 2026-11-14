//! The agenda layer: whole Daily Agenda editions.
//!
//! The generator publishes each file atomically and commits `manifest.json`
//! (schema `ragbaz.daily-agenda-manifest.v1`) last, under an exclusive lock on
//! `.publish.lock`. That manifest *is* the owner's validator: it lists every
//! file with its SHA-256 and the edition's generation status.
//!
//! Export takes a shared lock on `.publish.lock` (so no edition is replaced
//! mid-copy), copies the listed files and the manifest into private staging,
//! and checks every digest. By default only `ready` editions are published;
//! degraded or running editions are reported, not claimed. Restore writes a
//! new directory and re-verifies it against the edition manifest.

use crate::{config::Config, journal::Journal, layer, process, storage::ObjectStorage, sync};
use anyhow::{Context, Result, bail, ensure};
use fs2::FileExt;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::{
    path::{Path, PathBuf},
    time::{Duration, Instant},
};

pub const LAYER: &str = "agenda";
pub const OWNER_SCHEMA: &str = "ragbaz.daily-agenda-manifest.v1";
const MANIFEST: &str = "manifest.json";

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AgendaConfig {
    pub enabled: bool,
    /// The generator's output directory (DAILY_AGENDA_OUTPUT).
    pub path: PathBuf,
    pub label: String,
    pub chunk_bytes: u64,
    pub restic: bool,
    /// Publish only editions whose generation status is `ready`.
    pub require_ready: bool,
}

impl Default for AgendaConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            path: PathBuf::from("/srv/ragbaz/reports/daily-agenda"),
            label: "local".into(),
            chunk_bytes: 64 * 1024,
            restic: true,
            require_ready: true,
        }
    }
}

/// Check a directory holding an edition against its own manifest.
/// Returns the owner summary and the relative file list (manifest last).
pub fn check_edition(dir: &Path, require_ready: bool) -> Result<(Value, Vec<String>)> {
    let manifest: Value = serde_json::from_slice(
        &std::fs::read(dir.join(MANIFEST)).context("edition has no manifest.json")?,
    )
    .context("edition manifest is not JSON")?;
    ensure!(
        manifest.get("schema").and_then(Value::as_str) == Some(OWNER_SCHEMA),
        "unsupported edition manifest schema; expected {OWNER_SCHEMA}"
    );
    let status = manifest
        .pointer("/generation/status")
        .and_then(Value::as_str)
        .unwrap_or("unknown")
        .to_owned();
    if require_ready && status != "ready" {
        bail!(
            "edition generation status is {status:?}, not ready; not publishing a degraded edition"
        );
    }
    let files = manifest
        .get("files")
        .and_then(Value::as_object)
        .context("edition manifest lists no files")?;
    ensure!(!files.is_empty(), "edition manifest lists no files");
    let mut names = Vec::new();
    for (name, entry) in files {
        layer::validate_relative_path(name)?;
        ensure!(name != MANIFEST, "manifest lists itself");
        let expected = entry
            .get("sha256")
            .and_then(Value::as_str)
            .filter(|d| layer::valid_sha256(d))
            .with_context(|| format!("{name}: missing digest"))?;
        let (digest, bytes) = layer::hash_file(&dir.join(name))
            .with_context(|| format!("{name}: listed in the manifest but unreadable"))?;
        ensure!(
            digest == expected,
            "{name}: digest does not match the edition manifest"
        );
        if let Some(size) = entry.get("bytes").and_then(Value::as_u64) {
            ensure!(
                size == bytes,
                "{name}: size does not match the edition manifest"
            );
        }
        names.push(name.clone());
    }
    names.sort();
    names.push(MANIFEST.into());
    let owner = json!({
        "schema": OWNER_SCHEMA,
        "edition_id": manifest.get("id"),
        "observed_at": manifest.get("observed_at"),
        "generated_at": manifest.get("generated_at"),
        "generation_status": status,
        "provider": manifest.pointer("/generation/provider"),
        "files_verified": names.len() - 1,
    });
    Ok((owner, names))
}

/// Copy the current edition into `dir` under a shared publish lock, then verify.
pub fn export(config: &Config, dir: &Path) -> Result<(Value, Vec<String>)> {
    let source = &config.agenda.path;
    ensure!(
        source.join(MANIFEST).is_file(),
        "no published edition at {}",
        source.display()
    );
    // The generator holds this exclusively while replacing files. Do not
    // create it: the owner's directory is not ours to write.
    let lock = std::fs::File::open(source.join(".publish.lock")).ok();
    if let Some(lock) = &lock {
        let deadline = Instant::now() + Duration::from_secs(60);
        while lock.try_lock_shared().is_err() {
            ensure!(
                Instant::now() < deadline,
                "edition is being published; try again later"
            );
            std::thread::sleep(Duration::from_millis(250));
        }
    }
    let (_, names) = check_edition(source, config.agenda.require_ready)?;
    for name in &names {
        let target = dir.join(name);
        if let Some(parent) = target.parent() {
            std::fs::create_dir_all(parent)?;
        }
        std::fs::copy(source.join(name), &target).with_context(|| format!("copy {name}"))?;
    }
    if let Some(lock) = &lock {
        let _ = FileExt::unlock(lock);
    }
    // Verify the private copy, not the live directory.
    check_edition(dir, config.agenda.require_ready)
}

pub fn publish(
    config: &Config,
    storage: &dyn ObjectStorage,
    journal: &mut Journal,
) -> Result<layer::PublishOutcome> {
    let stage = layer::staging(config, LAYER)?;
    let edition = stage.path().join("edition");
    std::fs::create_dir_all(&edition)?;
    let (owner, names) = export(config, &edition)?;
    let run_id = journal.run_id.clone();
    let mut outcome = layer::publish_files(
        storage,
        LAYER,
        &config.agenda.label,
        config.agenda.chunk_bytes,
        &edition,
        &names,
        owner,
        Some(&run_id),
    )?;
    journal.event(
        "agenda-published",
        &outcome.manifest_key,
        json!({"id":outcome.id,"files":outcome.files,"new_chunks":outcome.new_chunks}),
    )?;
    if config.agenda.restic {
        let manifest = storage.get(&layer::manifest_key(LAYER, &outcome.id)?)?;
        process::write_private(
            &stage.path().join("rebsync-agenda-manifest.json"),
            &manifest,
        )?;
        let tag = format!("rebsync-agenda:{}:{}", journal.run_id, config.agenda.label);
        outcome.restic_snapshot = Some(sync::restic_backup(config, stage.path(), &tag, journal)?);
    }
    Ok(outcome)
}

pub fn verify(config: &Config, storage: &dyn ObjectStorage, id: &str) -> Result<Value> {
    let manifest = layer::load(storage, LAYER, id)?;
    let stage = layer::staging(config, LAYER)?;
    let out = stage.path().join("assembled");
    layer::assemble(storage, &manifest, &out)?;
    // Degraded editions may have been published with require_ready = false.
    let (owner, names) = check_edition(&out, false)?;
    Ok(
        json!({"id": manifest.id, "files": names.len(), "bytes": manifest.bytes(), "edition": owner}),
    )
}

/// Restore an edition into a new directory and re-verify it there.
pub fn restore(storage: &dyn ObjectStorage, id: &str, into: &Path) -> Result<Value> {
    let manifest = layer::load(storage, LAYER, id)?;
    layer::assemble(storage, &manifest, into)?;
    let (owner, names) = check_edition(into, false)?;
    Ok(json!({"id": manifest.id, "restored_to": into, "files": names.len(), "edition": owner}))
}

pub fn run_layer(config: &Config, journal: &mut Journal) -> Value {
    if config.agenda.restic && config.backup.repository.is_none() {
        return json!({"name":"agenda","kind":"agenda","status":"blocked","reason":"agenda.restic requires backup.repository; set agenda.restic = false to publish locally only"});
    }
    #[cfg(feature = "storage-object-store")]
    {
        let storage = match crate::storage::FsObjectStorage::open(&config.storage.root) {
            Ok(storage) => storage,
            Err(error) => {
                return json!({"name":"agenda","kind":"agenda","status":"failed","error":error.to_string()});
            }
        };
        layer::status_value("agenda", publish(config, &storage, journal))
    }
    #[cfg(not(feature = "storage-object-store"))]
    {
        let _ = journal;
        json!({"name":"agenda","kind":"agenda","status":"blocked","reason":"built without object storage support"})
    }
}
