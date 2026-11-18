//! Self-built binary artifacts: tools compiled from our own sources, or that
//! cannot be obtained from cargo-binstall, preserved as a Rebeqah layer.
//!
//! A snapshot is one or more executables plus provenance (source revision,
//! build command, target triple, install path). Chunks and the manifest live in
//! the same content-addressed namespace as every other layer. An optional
//! restic repository in private R2 mirrors the objects so a peer with no local
//! copy can fetch a tool instead of rebuilding it. Rebuilding always remains
//! possible: the manifest records how.

use crate::{Config, journal::Journal, layer, process, storage::ObjectStorage};
use anyhow::{Context, Result, bail, ensure};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::{
    fs::File,
    io::Read,
    path::{Path, PathBuf},
    process::Command,
};

pub const LAYER: &str = "binaries";
pub const OWNER_SCHEMA: &str = "rbq.binaries.snapshot.v1";
const RESTIC_TAG_PREFIX: &str = "rbq-binaries";

/// One executable to publish, with enough provenance to rebuild or re-fetch it.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BinarySpec {
    /// Tool name; one object-key segment.
    pub tool: String,
    /// Version or source revision; one object-key segment.
    pub version: String,
    /// Local executable to preserve.
    pub path: PathBuf,
    /// Compilation target, e.g. x86_64-unknown-linux-gnu.
    #[serde(default)]
    pub target: Option<String>,
    /// Source checkout or crate that produced it.
    #[serde(default)]
    pub source: Option<String>,
    /// Exact command a peer can run when rebuilding instead of fetching.
    #[serde(default)]
    pub build_command: Option<String>,
    /// Where this binary is expected to be installed on a peer.
    #[serde(default)]
    pub install_path: Option<PathBuf>,
    /// Human note; never a secret.
    #[serde(default)]
    pub note: Option<String>,
}

impl BinarySpec {
    /// Safe, stable name inside a snapshot.
    pub fn artifact_name(&self) -> Result<String> {
        let target = self.target.as_deref().unwrap_or("unknown-target");
        let name = format!("{}-{}-{}", self.tool, self.version, target);
        layer::validate_relative_path(&name)?;
        Ok(name)
    }
}

/// Snapshot summary for humans and peers; the full digest inventory is in the manifest.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OwnerRecord {
    pub schema: String,
    pub tools: Vec<OwnerTool>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OwnerTool {
    pub tool: String,
    pub version: String,
    pub sha256: String,
    pub bytes: u64,
    #[serde(default)]
    pub target: Option<String>,
    #[serde(default)]
    pub source: Option<String>,
    #[serde(default)]
    pub build_command: Option<String>,
    #[serde(default)]
    pub install_path: Option<PathBuf>,
    #[serde(default)]
    pub note: Option<String>,
}

/// Configuration for the binaries layer.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BinariesConfig {
    /// Publish binaries during `--apply` runs (explicit specs still publish).
    pub enabled: bool,
    /// Names the publisher in object keys.
    pub label: String,
    pub chunk_bytes: u64,
    /// Mirror objects into this restic repository. If unset, use backup.repository.
    pub repository: Option<String>,
    /// Password file for that repository. If unset, use backup.password_file.
    pub password_file: Option<PathBuf>,
    /// Mirror published objects before reporting success.
    pub restic: bool,
    pub timeout_seconds: u64,
    /// Tools published automatically during `--apply`; usually empty.
    #[serde(default)]
    pub specs: Vec<BinarySpec>,
}

impl Default for BinariesConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            label: "local".into(),
            chunk_bytes: 1024 * 1024,
            repository: None,
            password_file: None,
            restic: true,
            timeout_seconds: 900,
            specs: Vec::new(),
        }
    }
}

pub fn validate_name(value: &str) -> Result<()> {
    layer::validate_label(value)
}

fn owner_json(records: &[OwnerTool]) -> Value {
    serde_json::to_value(OwnerRecord {
        schema: OWNER_SCHEMA.into(),
        tools: records.to_vec(),
    })
    .expect("owner record is serializable")
}

fn hash_and_size(path: &Path) -> Result<(String, u64)> {
    let mut file = File::open(path).with_context(|| format!("open {}", path.display()))?;
    let mut hasher = Sha256::new();
    let mut buffer = vec![0_u8; 1 << 20];
    let mut total = 0_u64;
    loop {
        let n = file.read(&mut buffer)?;
        if n == 0 {
            break;
        }
        hasher.update(&buffer[..n]);
        total += n as u64;
    }
    ensure!(total > 0, "{} is empty", path.display());
    Ok((format!("{:x}", hasher.finalize()), total))
}

fn repository(config: &Config) -> Result<(String, Option<PathBuf>)> {
    let repo = config
        .binaries
        .repository
        .clone()
        .or_else(|| config.backup.repository.clone())
        .context("no restic repository configured; set binaries.repository or backup.repository")?;
    let password = config
        .binaries
        .password_file
        .clone()
        .or_else(|| config.backup.password_file.clone());
    Ok((repo, password))
}

/// Restic mirroring is opt-out per snapshot and requires a repository. Keeping
/// this as one predicate means local-only tests and peers can fetch from an
/// already-populated object store without needing credentials.
fn mirror_enabled(config: &Config) -> bool {
    config.binaries.restic && repository(config).is_ok()
}

/// Restic command using the binaries repository, which may differ from the
/// general backup repository. Credentials stay in the environment/password file.
fn restic_command(config: &Config) -> Result<Command> {
    let (repo, password) = repository(config)?;
    let mut command = process::command("restic");
    command.args(["--repo", &repo, "--json"]);
    if let Some(path) = password {
        command.arg("--password-file").arg(path);
    }
    command.env_remove("RESTIC_PASSWORD_COMMAND");
    Ok(command)
}

/// Mirror objects into private R2. Only published objects are backed up; no
/// source checkouts or secrets are included.
pub fn mirror(config: &Config, journal: &mut Journal, run_id: &str) -> Result<String> {
    let _ = repository(config)?;
    let root = if config.storage.root.is_absolute() {
        config.storage.root.clone()
    } else {
        config.rbq_home.join(&config.storage.root)
    };
    ensure!(
        root.is_dir(),
        "object store root does not exist: {}",
        root.display()
    );
    let tag = format!("{RESTIC_TAG_PREFIX}:{run_id}:{}", config.binaries.label);
    let mut command = restic_command(config)?;
    command
        .arg("backup")
        .arg("--tag")
        .arg(&tag)
        .arg("--")
        .arg(&root);
    let bytes = process::checked(&mut command, config.command_timeout_seconds)?;
    let id = String::from_utf8(bytes)?
        .lines()
        .filter_map(|line| serde_json::from_str::<Value>(line).ok())
        .find(|v| v.get("message_type").and_then(Value::as_str) == Some("summary"))
        .and_then(|v| v["snapshot_id"].as_str().map(String::from))
        .context("restic returned no completed snapshot ID")?;
    // Fail closed if the new snapshot cannot be read back.
    let mut verify = restic_command(config)?;
    verify.args(["cat", "snapshot", &id]);
    let value: Value = serde_json::from_slice(&process::checked(
        &mut verify,
        config.command_timeout_seconds,
    )?)?;
    ensure!(
        value.get("tree").and_then(Value::as_str).is_some(),
        "restic snapshot has no tree"
    );
    // Repository URLs can carry inline credentials; never journal them.
    journal.event(
        "binaries-mirrored",
        &id,
        json!({"repository": "<configured>", "tag": tag}),
    )?;
    Ok(id)
}

/// If local objects are missing, restore the tagged mirror into private
/// staging and copy only the binaries layer objects into the object store.
pub fn restore_objects_from_r2(config: &Config, journal: &mut Journal) -> Result<usize> {
    let root = if config.storage.root.is_absolute() {
        config.storage.root.clone()
    } else {
        config.rbq_home.join(&config.storage.root)
    };
    let stage = layer::staging(config, LAYER)?;
    let mut command = restic_command(config)?;
    command
        .arg("restore")
        .arg("latest")
        .arg("--tag")
        .arg(RESTIC_TAG_PREFIX)
        .arg("--target")
        .arg(stage.path());
    process::checked(&mut command, config.command_timeout_seconds)?;
    // Restic recreates the absolute source path under its target.
    let nested = stage.path().join(root.strip_prefix("/").unwrap_or(&root));
    let source = if nested.is_dir() {
        nested
    } else {
        stage.path().to_path_buf()
    };
    let from = source.join(LAYER).join("v1");
    ensure!(
        from.is_dir(),
        "mirrored restore contains no binaries/v1 objects"
    );
    let to = root.join(LAYER).join("v1");
    std::fs::create_dir_all(&to)?;
    let mut copied = 0;
    for entry in walkdir::WalkDir::new(&from) {
        let entry = entry?;
        if !entry.file_type().is_file() {
            continue;
        }
        let relative = entry.path().strip_prefix(&from)?;
        let target = to.join(relative);
        if let Some(parent) = target.parent() {
            std::fs::create_dir_all(parent)?;
        }
        if !target.exists() {
            std::fs::copy(entry.path(), &target)?;
            copied += 1;
        }
    }
    journal.event(
        "binaries-restored-from-r2",
        LAYER,
        json!({"objects": copied}),
    )?;
    Ok(copied)
}

/// Publish executables. Chunks are written before the manifest; the optional
/// R2 mirror is written last so a failed mirror never leaves an unverified set.
pub fn publish(
    config: &Config,
    storage: &dyn ObjectStorage,
    specs: &[BinarySpec],
    journal: &mut Journal,
) -> Result<layer::PublishOutcome> {
    ensure!(!specs.is_empty(), "at least one binary is required");
    let _lock = layer::lock(config, LAYER)?;
    let stage = layer::staging(config, LAYER)?;
    let mut records = Vec::new();
    let mut relative = Vec::new();
    for spec in specs {
        validate_name(&spec.tool)?;
        validate_name(&spec.version)?;
        let name = spec.artifact_name()?;
        let meta = std::fs::metadata(&spec.path)
            .with_context(|| format!("stat {}", spec.path.display()))?;
        ensure!(
            meta.is_file(),
            "{} is not a regular file",
            spec.path.display()
        );
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            ensure!(
                meta.permissions().mode() & 0o111 != 0,
                "{} is not executable",
                spec.path.display()
            );
        }
        let (sha256, bytes) = hash_and_size(&spec.path)?;
        std::fs::copy(&spec.path, stage.path().join(&name))?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(
                stage.path().join(&name),
                std::fs::Permissions::from_mode(0o755),
            )?;
        }
        relative.push(name);
        records.push(OwnerTool {
            tool: spec.tool.clone(),
            version: spec.version.clone(),
            sha256,
            bytes,
            target: spec.target.clone(),
            source: spec.source.clone(),
            build_command: spec.build_command.clone(),
            install_path: spec.install_path.clone(),
            note: spec.note.clone(),
        });
    }
    let mut outcome = layer::publish_files(
        storage,
        LAYER,
        &config.binaries.label,
        config.binaries.chunk_bytes,
        stage.path(),
        &relative,
        owner_json(&records),
        Some(&journal.run_id),
    )?;
    journal.event(
        "binaries-published",
        &outcome.manifest_key,
        json!({"id": outcome.id, "bytes": outcome.bytes, "tools": records.iter().map(|r| &r.tool).collect::<Vec<_>>()}),
    )?;
    if config.binaries.restic {
        let run_id = journal.run_id.clone();
        outcome.restic_snapshot = Some(mirror(config, journal, &run_id)?);
    }
    Ok(outcome)
}

fn owner_tools(manifest: &layer::SnapshotManifest) -> Result<Vec<OwnerTool>> {
    ensure!(
        manifest.owner["schema"].as_str() == Some(OWNER_SCHEMA),
        "unsupported binaries owner schema"
    );
    let record: OwnerRecord = serde_json::from_value(manifest.owner.clone())?;
    ensure!(
        record.tools.len() == manifest.files.len(),
        "tools/files mismatch"
    );
    Ok(record.tools)
}

/// Read-only integrity check: digests and provenance, no installation.
pub fn verify(
    config: &Config,
    storage: &dyn ObjectStorage,
    id: &str,
    journal: &mut Journal,
) -> Result<Value> {
    let manifest = layer::load(storage, LAYER, id)?;
    let tools = owner_tools(&manifest)?;
    let stage = layer::staging(config, LAYER)?;
    let out = stage.path().join("assembled");
    layer::assemble(storage, &manifest, &out)?;
    for (file, tool) in manifest.files.iter().zip(&tools) {
        let (digest, _) = hash_and_size(&out.join(&file.path))?;
        ensure!(
            digest == tool.sha256,
            "{} does not match provenance",
            file.path
        );
    }
    journal.event("binaries-verified", id, json!({"bytes": manifest.bytes()}))?;
    Ok(json!({
        "id": manifest.id,
        "digest": manifest.digest,
        "bytes": manifest.bytes(),
        "tools": tools.iter().map(|t| json!({"tool": t.tool, "version": t.version, "sha256": t.sha256, "bytes": t.bytes})).collect::<Vec<_>>(),
    }))
}

/// Restore one tool from a snapshot to a new path (never overwrites).
pub fn restore(
    config: &Config,
    storage: &dyn ObjectStorage,
    id: &str,
    tool: &str,
    into: &Path,
    journal: &mut Journal,
) -> Result<Value> {
    ensure!(
        std::fs::symlink_metadata(into).is_err(),
        "{} already exists; restore only creates a new file",
        into.display()
    );
    let manifest = layer::load(storage, LAYER, id)?;
    let tools = owner_tools(&manifest)?;
    let index = tools
        .iter()
        .position(|t| t.tool == tool)
        .with_context(|| format!("snapshot {id} has no tool {tool:?}"))?;
    let file = &manifest.files[index];
    let stage = layer::staging(config, LAYER)?;
    let out = stage.path().join("assembled");
    layer::assemble(storage, &manifest, &out)?;
    if let Some(parent) = into.parent().filter(|p| !p.as_os_str().is_empty()) {
        std::fs::create_dir_all(parent)?;
    }
    let mut options = std::fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o755);
    }
    let mut target = options.open(into)?;
    std::io::copy(&mut File::open(out.join(&file.path))?, &mut target)?;
    target.sync_all()?;
    let (digest, bytes) = hash_and_size(into)?;
    ensure!(
        digest == tools[index].sha256,
        "restored binary failed its digest check"
    );
    journal.event(
        "binaries-restored",
        into,
        json!({"id": manifest.id, "tool": tool, "sha256": digest, "bytes": bytes}),
    )?;
    Ok(json!({
        "id": manifest.id,
        "tool": tool,
        "version": tools[index].version,
        "restored_to": into,
        "sha256": digest,
        "bytes": bytes,
        "source": tools[index].source,
        "build_command": tools[index].build_command,
        "note": "Verified from content-addressed chunks. No live binary was replaced.",
    }))
}

/// List snapshots, newest last, with a compact tool summary.
pub fn list(storage: &dyn ObjectStorage, label: Option<&str>) -> Result<Vec<Value>> {
    let manifests = layer::list(storage, LAYER, label)?;
    manifests
        .iter()
        .map(|manifest| {
            let tools = owner_tools(manifest)?;
            Ok(json!({
                "id": manifest.id,
                "created_at": manifest.created_at,
                "label": manifest.label,
                "digest": manifest.digest,
                "bytes": manifest.bytes(),
                "tools": tools.iter().map(|t| json!({"tool":t.tool,"version":t.version,"sha256":t.sha256})).collect::<Vec<_>>(),
            }))
        })
        .collect()
}

/// Find the newest snapshot containing `tool` (optionally a specific version).
pub fn find(
    storage: &dyn ObjectStorage,
    tool: &str,
    version: Option<&str>,
) -> Result<Option<(layer::SnapshotManifest, OwnerTool)>> {
    let manifests = layer::list(storage, LAYER, None)?;
    for manifest in manifests.into_iter().rev() {
        for record in owner_tools(&manifest)? {
            if record.tool == tool && version.is_none_or(|v| v == record.version) {
                return Ok(Some((manifest, record)));
            }
        }
    }
    Ok(None)
}

/// Ensure a tool is available locally. If the object store is incomplete, the
/// R2 mirror is restored first. This is the re-fetch path for peers and build
/// software; rebuilding from `build_command` remains the manual fallback.
pub fn fetch(
    config: &Config,
    storage: &dyn ObjectStorage,
    tool: &str,
    version: Option<&str>,
    into: &Path,
    journal: &mut Journal,
) -> Result<Value> {
    let mut found = find(storage, tool, version)?;
    if found.is_none() && mirror_enabled(config) {
        restore_objects_from_r2(config, journal)?;
        found = find(storage, tool, version)?;
    }
    let Some((manifest, _)) = found else {
        bail!("no published snapshot for tool {tool:?} (version {version:?})");
    };
    match restore(config, storage, &manifest.id, tool, into, journal) {
        Ok(value) => Ok(value),
        Err(first) if mirror_enabled(config) => {
            // A manifest can be present while its chunks are not.
            restore_objects_from_r2(config, journal)?;
            restore(config, storage, &manifest.id, tool, into, journal)
                .with_context(|| format!("first attempt failed: {first}"))
        }
        Err(error) => Err(error),
    }
}

/// `--apply` integration for explicitly configured automatic publications.
pub fn run_layer(config: &Config, journal: &mut Journal) -> Value {
    if config.binaries.restic && !mirror_enabled(config) {
        return json!({"name":"binaries","kind":"binaries","status":"blocked","reason":"binaries.restic requires binaries.repository or backup.repository"});
    }
    if config.binaries.specs.is_empty() {
        return json!({"name":"binaries","kind":"binaries","status":"skipped","reason":"no binaries.specs configured; publish explicitly with 'rbq binaries publish'"});
    }
    #[cfg(feature = "storage-object-store")]
    {
        let storage = match crate::storage::FsObjectStorage::open(&config.storage.root) {
            Ok(storage) => storage,
            Err(error) => {
                return json!({"name":"binaries","kind":"binaries","status":"failed","error":error.to_string()});
            }
        };
        layer::status_value(
            "binaries",
            publish(config, &storage, &config.binaries.specs, journal),
        )
    }
    #[cfg(not(feature = "storage-object-store"))]
    {
        let _ = journal;
        json!({"name":"binaries","kind":"binaries","status":"blocked","reason":"built without object storage support"})
    }
}

/// Human date formatter kept here so callers do not depend on chrono's Display.
pub fn created_at(manifest: &layer::SnapshotManifest) -> DateTime<Utc> {
    manifest.created_at
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn artifact_names_are_safe_and_stable() {
        let spec = BinarySpec {
            tool: "rbq".into(),
            version: "0.2.4".into(),
            path: PathBuf::from("/bin/true"),
            target: Some("x86_64-unknown-linux-gnu".into()),
            source: None,
            build_command: None,
            install_path: None,
            note: None,
        };
        assert_eq!(
            spec.artifact_name().unwrap(),
            "rbq-0.2.4-x86_64-unknown-linux-gnu"
        );
    }

    #[test]
    fn traversal_in_names_is_rejected() {
        assert!(validate_name("../escape").is_err());
        assert!(validate_name("ok.name-1").is_ok());
    }
}
