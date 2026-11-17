//! The Frog layer: the shared coordination database (`AGENTS.db`).
//!
//! Frog owns the export: `frog snapshot` copies the live database with
//! SQLite's online backup API, which is consistent under concurrent writers.
//! (It also records a `workspace.snapshot` event in AGENTS.db and keeps its
//! own `.last`/`.prev` rotation inside the destination, which Rebsync points
//! at a private staging directory.)
//!
//! Frog has no snapshot validator, so Rebsync checks the export itself before
//! publishing it, through Python's standard `sqlite3` module (present wherever
//! Frog runs): `PRAGMA integrity_check`, the core tables, applied migrations
//! and row counts. Restore writes a *new* file and never touches a live
//! database; replacing AGENTS.db is a deliberate, Frog-side operation.

use crate::{config::Config, journal::Journal, layer, process, storage::ObjectStorage, sync};
use anyhow::{Context, Result, bail, ensure};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::path::{Path, PathBuf};

pub const LAYER: &str = "frog";
const FILE: &str = "AGENTS.db";

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FrogConfig {
    pub enabled: bool,
    /// Frog CLI; a bare name is looked up on PATH.
    pub binary: PathBuf,
    /// Passed as `frog --db`; unset uses Frog's own default.
    pub db: Option<PathBuf>,
    /// Interpreter for the validator (Python 3 with the standard sqlite3 module).
    pub python: PathBuf,
    pub label: String,
    pub chunk_bytes: u64,
    pub restic: bool,
    pub timeout_seconds: u64,
}

impl Default for FrogConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            binary: PathBuf::from("frog"),
            db: None,
            python: PathBuf::from("python3"),
            label: "local".into(),
            chunk_bytes: 64 * 1024,
            restic: true,
            timeout_seconds: 600,
        }
    }
}

/// Read-only validator. Opens the copy immutable, so it can never write to it.
const VALIDATOR: &str = r#"
import json, sqlite3, sys
path = sys.argv[1]
with open(path, "rb") as f:
    header = f.read(16)
if header != b"SQLite format 3\x00":
    print(json.dumps({"ok": False, "error": "not an SQLite database"})); sys.exit(2)
c = sqlite3.connect("file:" + path + "?mode=ro&immutable=1", uri=True)
problems = [r[0] for r in c.execute("PRAGMA integrity_check(20)") if r[0] != "ok"]
tables = {r[0] for r in c.execute("SELECT name FROM sqlite_master WHERE type='table'")}
required = ["schema_migrations", "repos", "agents", "locks", "tasks", "event_log"]
missing = [t for t in required if t not in tables]
result = {"schema": "rebsync.frog.validation.v1", "ok": not problems and not missing,
          "integrity": "ok" if not problems else problems, "missing_tables": missing}
if not missing:
    result["migrations"] = sorted(r[0] for r in c.execute("SELECT name FROM schema_migrations"))
    result["counts"] = {t: c.execute(f"SELECT count(*) FROM {t}").fetchone()[0]
                        for t in ["repos", "agents", "locks", "tasks", "event_log"]}
print(json.dumps(result))
sys.exit(0 if result["ok"] else 3)
"#;

fn frog(config: &Config) -> std::process::Command {
    let mut cmd = process::command(&config.frog.binary.to_string_lossy());
    if let Some(db) = &config.frog.db {
        cmd.arg("--db").arg(db);
    }
    cmd
}

/// Validate a Frog database copy; returns the validator's report.
pub fn validate(config: &Config, path: &Path, journal: &mut Journal) -> Result<Value> {
    let mut cmd = process::command(&config.frog.python.to_string_lossy());
    cmd.args(["-I", "-c", VALIDATOR]).arg(path);
    let out = sync::execute(
        journal,
        path,
        "frog-validate",
        json!(["python3", "-I", "-c", "<validator>", path]),
        &mut cmd,
        config.frog.timeout_seconds,
        None,
    )?;
    let report: Value = serde_json::from_slice(&out.stdout)
        .context("validator produced no report (is python3 with sqlite3 available?)")?;
    if !out.success || report.get("ok") != Some(&Value::Bool(true)) {
        bail!("Frog database failed validation: {report}");
    }
    Ok(report)
}

/// Ask Frog for a consistent copy in `dir`, then validate it.
pub fn export(config: &Config, dir: &Path, journal: &mut Journal) -> Result<Value> {
    let dest = dir.join("frog-snapshot");
    let mut cmd = frog(config);
    cmd.args(["--json", "snapshot", "--dest"]).arg(&dest);
    let output = sync::execute(
        journal,
        dir,
        "frog-snapshot",
        json!([
            "frog",
            "--db",
            "<configured>",
            "--json",
            "snapshot",
            "--dest",
            dest
        ]),
        &mut cmd,
        config.frog.timeout_seconds,
        None,
    )?;
    let reply: Value =
        serde_json::from_slice(&output.stdout).context("frog returned non-JSON output")?;
    crate::migration::check_report(LAYER, &reply)?;
    ensure!(
        output.success && reply.get("ok") == Some(&Value::Bool(true)),
        "frog snapshot failed: {}",
        reply
            .get("error")
            .and_then(Value::as_str)
            .unwrap_or("unknown error")
    );
    let last = PathBuf::from(
        reply
            .get("last")
            .and_then(Value::as_str)
            .context("frog snapshot did not name its output")?,
    );
    // Only accept output inside our private staging directory.
    let last = last
        .canonicalize()
        .context("frog snapshot output missing")?;
    ensure!(
        last.starts_with(dest.canonicalize()?),
        "frog wrote its snapshot outside the staging directory"
    );
    std::fs::rename(&last, dir.join(FILE))?;
    let mut owner = validate(config, &dir.join(FILE), journal)?;
    owner["frog_reported_bytes"] = reply.get("bytes").cloned().unwrap_or(Value::Null);
    Ok(owner)
}

pub fn publish(
    config: &Config,
    storage: &dyn ObjectStorage,
    journal: &mut Journal,
) -> Result<layer::PublishOutcome> {
    let _lock = crate::layer::lock(config, LAYER)?;
    let stage = layer::staging(config, LAYER)?;
    let owner = export(config, stage.path(), journal)?;
    let run_id = journal.run_id.clone();
    let mut outcome = layer::publish_files(
        storage,
        LAYER,
        &config.frog.label,
        config.frog.chunk_bytes,
        stage.path(),
        &[FILE.to_owned()],
        owner,
        Some(&run_id),
    )?;
    journal.event(
        "frog-published",
        &outcome.manifest_key,
        json!({"id":outcome.id,"bytes":outcome.bytes,"new_chunks":outcome.new_chunks}),
    )?;
    if config.frog.restic {
        std::fs::remove_dir_all(stage.path().join("frog-snapshot")).ok();
        let manifest = storage.get(&layer::manifest_key(LAYER, &outcome.id)?)?;
        process::write_private(&stage.path().join("rebsync-frog-manifest.json"), &manifest)?;
        let tag = format!("rebsync-frog:{}:{}", journal.run_id, config.frog.label);
        outcome.restic_snapshot = Some(sync::restic_backup(config, stage.path(), &tag, journal)?);
    }
    Ok(outcome)
}

/// Reassemble, check every chunk, and run the validator. Writes nothing persistent.
pub fn verify(
    config: &Config,
    storage: &dyn ObjectStorage,
    id: &str,
    journal: &mut Journal,
) -> Result<Value> {
    let manifest = layer::load(storage, LAYER, id)?;
    let stage = layer::staging(config, LAYER)?;
    let out = stage.path().join("assembled");
    layer::assemble(storage, &manifest, &out)?;
    let report = validate(config, &out.join(FILE), journal)?;
    Ok(
        json!({"id": manifest.id, "digest": manifest.digest, "bytes": manifest.bytes(), "validation": report}),
    )
}

/// Restore to a *new* database file; refuses anything that already exists.
pub fn restore(
    config: &Config,
    storage: &dyn ObjectStorage,
    id: &str,
    into: &Path,
    journal: &mut Journal,
) -> Result<Value> {
    for suffix in ["", "-wal", "-shm", "-journal"] {
        let mut name = into.as_os_str().to_owned();
        name.push(suffix);
        ensure!(
            std::fs::symlink_metadata(PathBuf::from(&name)).is_err(),
            "{} already exists; restore only creates a new database",
            PathBuf::from(name).display()
        );
    }
    let manifest = layer::load(storage, LAYER, id)?;
    let stage = layer::staging(config, LAYER)?;
    let out = stage.path().join("assembled");
    layer::assemble(storage, &manifest, &out)?;
    let report = validate(config, &out.join(FILE), journal)?;
    if let Some(parent) = into.parent().filter(|p| !p.as_os_str().is_empty()) {
        std::fs::create_dir_all(parent)?;
    }
    // Copy (staging may be on another filesystem), then fsync.
    let mut options = std::fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut target = options.open(into)?;
    std::io::copy(&mut std::fs::File::open(out.join(FILE))?, &mut target)?;
    target.sync_all()?;
    let (digest, _) = layer::hash_file(into)?;
    ensure!(
        digest == manifest.files[0].sha256,
        "restored file does not match the snapshot"
    );
    journal.event("frog-restored", into, json!({"id": manifest.id}))?;
    Ok(
        json!({"id": manifest.id, "restored_to": into, "validation": report,
        "next": "Stop Frog agents and swap the file in deliberately; rebsync never replaces a live AGENTS.db."}),
    )
}

pub fn run_layer(config: &Config, journal: &mut Journal) -> Value {
    if config.frog.restic && config.backup.repository.is_none() {
        return json!({"name":"frog","kind":"frog","status":"blocked","reason":"frog.restic requires backup.repository; set frog.restic = false to publish locally only"});
    }
    #[cfg(feature = "storage-object-store")]
    {
        let storage = match crate::storage::FsObjectStorage::open(&config.storage.root) {
            Ok(storage) => storage,
            Err(error) => {
                return json!({"name":"frog","kind":"frog","status":"failed","error":error.to_string()});
            }
        };
        layer::status_value("frog", publish(config, &storage, journal))
    }
    #[cfg(not(feature = "storage-object-store"))]
    {
        let _ = journal;
        json!({"name":"frog","kind":"frog","status":"blocked","reason":"built without object storage support"})
    }
}
