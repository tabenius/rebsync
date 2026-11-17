//! Frog and agenda layers against owner-shaped fixtures.
#![cfg(all(unix, feature = "storage-object-store"))]

use anyhow::Result;
use rebsync_core::{
    Config, FsObjectStorage, RunOptions, agenda, frog, journal::Journal, layer, run,
};
use sha2::{Digest, Sha256};
use std::{fs, os::unix::fs::PermissionsExt, path::Path, process::Command};

fn frog_db(path: &Path, tasks: usize) {
    let script = format!(
        r#"
import sqlite3
c = sqlite3.connect({path:?})
c.executescript('''
CREATE TABLE IF NOT EXISTS schema_migrations(name TEXT PRIMARY KEY);
CREATE TABLE IF NOT EXISTS repos(id INTEGER PRIMARY KEY);
CREATE TABLE IF NOT EXISTS agents(id INTEGER PRIMARY KEY);
CREATE TABLE IF NOT EXISTS locks(id INTEGER PRIMARY KEY);
CREATE TABLE IF NOT EXISTS tasks(id INTEGER PRIMARY KEY, title TEXT);
CREATE TABLE IF NOT EXISTS event_log(id INTEGER PRIMARY KEY);
INSERT OR IGNORE INTO schema_migrations VALUES ('001_initial.sql'), ('015_audit_intent_limits.sql');
''')
c.executemany("INSERT INTO tasks(title) VALUES (?)", [("task %d" % i,) for i in range({tasks})])
c.commit()
"#,
        path = path.to_str().unwrap()
    );
    assert!(
        Command::new("python3")
            .args(["-c", &script])
            .status()
            .unwrap()
            .success()
    );
}

/// Mimics `frog --db DB --json snapshot --dest D`.
const FAKE_FROG: &str = r#"#!/bin/sh
set -e
db="$2"; dest="$6"
mkdir -p "$dest"
python3 -c "import sqlite3,sys; s=sqlite3.connect(sys.argv[1]); d=sqlite3.connect(sys.argv[2]); s.backup(d); d.close()" "$db" "$dest/AGENTS.db.last"
size=$(wc -c < "$dest/AGENTS.db.last" | tr -d ' ')
printf '{"ok": true, "last": "%s", "bytes": %s}\n' "$dest/AGENTS.db.last" "$size"
"#;

fn config(home: &Path) -> Config {
    let mut config = Config::defaults(home.to_path_buf());
    fs::create_dir_all(home.join("empty")).unwrap();
    config.scan.roots = vec![home.join("empty")];
    config.storage.root = home.join("objects");
    let script = home.join("fake-frog");
    fs::write(&script, FAKE_FROG).unwrap();
    fs::set_permissions(&script, fs::Permissions::from_mode(0o700)).unwrap();
    config.frog.binary = script;
    config.frog.db = Some(home.join("AGENTS.db"));
    config.frog.restic = false;
    config.agenda.path = home.join("daily-agenda");
    config.agenda.restic = false;
    config
}

#[test]
fn frog_pending_migration_is_blocked_without_publishing_or_changing_source() {
    let t = tempfile::tempdir().unwrap();
    let config = config(t.path());
    frog_db(config.frog.db.as_ref().unwrap(), 1);
    let before = fs::read(config.frog.db.as_ref().unwrap()).unwrap();
    fs::write(
        &config.frog.binary,
        "#!/bin/sh\nprintf '%s\\n' '{\"ok\":false,\"behind\":[\"016_repo_dep_kind.sql\"],\"fix\":\"frog db migrate\"}'\nexit 2\n",
    )
    .unwrap();
    let mut journal = Journal::open(t.path()).unwrap();
    let report = frog::run_layer(&config, &mut journal);
    assert_eq!(report["status"], "blocked", "{report}");
    assert_eq!(report["migration"]["status"], "required");
    assert_eq!(fs::read(config.frog.db.as_ref().unwrap()).unwrap(), before);
    let storage = FsObjectStorage::open(&config.storage.root).unwrap();
    assert!(layer::list(&storage, "frog", None).unwrap().is_empty());
}

#[test]
fn future_agenda_schema_signals_unavailable_migration() {
    let t = tempfile::tempdir().unwrap();
    fs::write(
        t.path().join("manifest.json"),
        r#"{"schema":"ragbaz.daily-agenda-manifest.v999"}"#,
    )
    .unwrap();
    let error = agenda::check_edition(t.path(), true).unwrap_err();
    let blocked = error
        .downcast_ref::<rebsync_core::migration::MigrationBlocked>()
        .unwrap();
    assert_eq!(blocked.status, "unavailable");
}

fn edition(dir: &Path, status: &str, html: &str) {
    fs::create_dir_all(dir).unwrap();
    let files = [
        ("index.html", html.to_owned()),
        ("snapshot.json", r#"{"errors":[]}"#.to_owned()),
        ("editorial.json", "{}".to_owned()),
    ];
    let mut listed = serde_json::Map::new();
    for (name, body) in &files {
        fs::write(dir.join(name), body).unwrap();
        listed.insert(
            (*name).into(),
            serde_json::json!({"sha256": format!("{:x}", Sha256::digest(body.as_bytes())), "bytes": body.len()}),
        );
    }
    let manifest = serde_json::json!({"schema": agenda::OWNER_SCHEMA, "id": "daily-agenda-2026-11-14T06:00:00+00:00",
        "observed_at": "2026-11-14T06:00:00+00:00", "generation": {"status": status, "provider": "local"}, "files": listed});
    fs::write(
        dir.join("manifest.json"),
        serde_json::to_vec_pretty(&manifest).unwrap(),
    )
    .unwrap();
}

#[test]
fn frog_layer_exports_validates_dedups_and_restores_to_new_files() -> Result<()> {
    let t = tempfile::tempdir()?;
    let config = config(t.path());
    frog_db(&t.path().join("AGENTS.db"), 200);
    let storage = FsObjectStorage::open(&config.storage.root)?;
    let mut journal = Journal::open(t.path())?;

    let first = frog::publish(&config, &storage, &mut journal)?;
    assert_eq!(first.files, 1);
    let listed = layer::list(&storage, "frog", None)?;
    assert_eq!(listed[0].owner["counts"]["tasks"], 200);
    assert_eq!(listed[0].owner["integrity"], "ok");
    assert!(listed[0].owner["migrations"].as_array().unwrap().len() == 2);

    std::thread::sleep(std::time::Duration::from_millis(5));
    let second = frog::publish(&config, &storage, &mut journal)?;
    assert_eq!(
        second.new_chunks, 0,
        "unchanged database should reuse every chunk"
    );

    let verified = frog::verify(&config, &storage, &first.id, &mut journal)?;
    assert_eq!(verified["validation"]["ok"], true);
    let into = t.path().join("restored/AGENTS.db");
    frog::restore(&config, &storage, &first.id, &into, &mut journal)?;
    assert!(frog::restore(&config, &storage, &first.id, &into, &mut journal).is_err());
    // The live database is never touched by restore.
    let live = t.path().join("AGENTS.db");
    assert!(frog::restore(&config, &storage, &first.id, &live, &mut journal).is_err());

    // A database missing Frog's tables is refused before publication.
    fs::remove_file(&live)?;
    assert!(
        Command::new("python3")
            .args([
                "-c",
                &format!(
                    "import sqlite3; sqlite3.connect({:?}).execute('CREATE TABLE x(y)')",
                    live.to_str().unwrap()
                )
            ])
            .status()?
            .success()
    );
    let error = frog::publish(&config, &storage, &mut journal).unwrap_err();
    assert!(
        format!("{error:#}").contains("failed validation"),
        "{error:#}"
    );
    assert_eq!(layer::list(&storage, "frog", None)?.len(), 2);
    Ok(())
}

#[test]
fn agenda_layer_publishes_only_verified_ready_editions() -> Result<()> {
    let t = tempfile::tempdir()?;
    let mut config = config(t.path());
    let source = t.path().join("daily-agenda");
    edition(&source, "ready", "<h1>Agenda</h1>");
    fs::write(source.join(".publish.lock"), b"")?;
    let storage = FsObjectStorage::open(&config.storage.root)?;
    let mut journal = Journal::open(t.path())?;

    let outcome = agenda::publish(&config, &storage, &mut journal)?;
    assert_eq!(outcome.files, 4, "three listed files plus the manifest");
    let verified = agenda::verify(&config, &storage, &outcome.id)?;
    assert_eq!(verified["edition"]["generation_status"], "ready");
    let into = t.path().join("restored-edition");
    agenda::restore(&storage, &outcome.id, &into)?;
    assert_eq!(
        fs::read_to_string(into.join("index.html"))?,
        "<h1>Agenda</h1>"
    );
    assert!(agenda::restore(&storage, &outcome.id, &into).is_err());

    // A file that no longer matches its manifest is refused.
    fs::write(source.join("index.html"), "tampered")?;
    let error = agenda::publish(&config, &storage, &mut journal).unwrap_err();
    assert!(
        format!("{error:#}").contains("digest does not match"),
        "{error:#}"
    );

    // Degraded editions are refused unless explicitly allowed.
    fs::remove_dir_all(&source)?;
    edition(&source, "degraded", "<h1>Partial</h1>");
    assert!(agenda::publish(&config, &storage, &mut journal).is_err());
    config.agenda.require_ready = false;
    agenda::publish(&config, &storage, &mut journal)?;
    assert_eq!(layer::list(&storage, "agenda", None)?.len(), 2);
    Ok(())
}

#[test]
fn apply_runs_report_layer_status() -> Result<()> {
    let t = tempfile::tempdir()?;
    let mut config = config(t.path());
    frog_db(&t.path().join("AGENTS.db"), 3);
    edition(&t.path().join("daily-agenda"), "ready", "x");
    config.frog.enabled = true;
    config.agenda.enabled = true;
    let applied = run(&config, RunOptions { apply: true })?;
    let status =
        |name: &str| applied.datasets.iter().find(|d| d["name"] == name).unwrap()["status"].clone();
    assert_eq!(status("frog"), "published-local");
    assert_eq!(status("agenda"), "published-local");
    config.frog.restic = true;
    let blocked = run(&config, RunOptions { apply: true })?;
    assert_eq!(
        blocked
            .datasets
            .iter()
            .find(|d| d["name"] == "frog")
            .unwrap()["status"],
        "blocked"
    );
    Ok(())
}

#[test]
fn prune_keeps_newest_respects_grace_and_never_breaks_survivors() -> Result<()> {
    use rebsync_core::{ObjectKey, ObjectStorage, chrono::Duration as Span, layer::Retention};
    let t = tempfile::tempdir()?;
    let config = config(t.path());
    let storage = FsObjectStorage::open(&config.storage.root)?;
    let mut journal = Journal::open(t.path())?;
    let mut ids = Vec::new();
    for round in 0..4 {
        frog_db(&t.path().join("AGENTS.db"), 50 + round * 400);
        ids.push(frog::publish(&config, &storage, &mut journal)?.id);
        std::thread::sleep(std::time::Duration::from_millis(5));
    }
    let keep_two = |grace| Retention {
        keep_last: 2,
        keep_days: None,
        label: None,
        grace,
    };
    let chunk_count = || storage.list_prefix("frog/v1/chunks/", 0).unwrap().len();
    let before = chunk_count();

    // Dry run: reports, deletes nothing.
    let dry = layer::prune(&storage, "frog", &keep_two(Span::zero()), false)?;
    assert_eq!(dry.snapshots_removed, vec![ids[1].clone(), ids[0].clone()]);
    assert!(dry.chunks_removed > 0);
    assert_eq!(layer::list(&storage, "frog", None)?.len(), 4);
    assert_eq!(chunk_count(), before);

    // Grace period: fresh unreferenced chunks are deferred, not deleted.
    let graced = layer::prune(&storage, "frog", &keep_two(Span::hours(1)), false)?;
    assert_eq!(graced.chunks_removed, 0);
    assert_eq!(graced.chunks_deferred, dry.chunks_removed);

    // keep_days keeps everything recent.
    let recent = Retention {
        keep_last: 1,
        keep_days: Some(1),
        label: None,
        grace: Span::zero(),
    };
    assert!(
        layer::prune(&storage, "frog", &recent, false)?
            .snapshots_removed
            .is_empty()
    );
    // A label filter leaves other labels untouched.
    let other = Retention {
        keep_last: 1,
        keep_days: None,
        label: Some("elsewhere".into()),
        grace: Span::zero(),
    };
    assert!(
        layer::prune(&storage, "frog", &other, false)?
            .snapshots_removed
            .is_empty()
    );

    let applied = layer::prune(&storage, "frog", &keep_two(Span::zero()), true)?;
    assert_eq!(applied.snapshots_removed.len(), 2);
    assert_eq!(chunk_count(), before - applied.chunks_removed);
    // Survivors still reassemble and validate completely.
    for id in &ids[2..] {
        frog::verify(&config, &storage, id, &mut journal)?;
    }
    assert!(layer::load(&storage, "frog", &ids[0]).is_err());
    // Idempotent.
    let again = layer::prune(&storage, "frog", &keep_two(Span::zero()), true)?;
    assert!(again.snapshots_removed.is_empty() && again.chunks_removed == 0);

    // keep_last 0 is refused; an unreadable manifest stops the prune.
    assert!(
        layer::prune(
            &storage,
            "frog",
            &Retention {
                keep_last: 0,
                keep_days: None,
                label: None,
                grace: Span::zero()
            },
            false
        )
        .is_err()
    );
    storage.put(
        &ObjectKey::parse("frog/v1/snapshots/local/broken.json")?,
        b"not json",
    )?;
    let error = layer::prune(&storage, "frog", &keep_two(Span::zero()), true).unwrap_err();
    assert!(format!("{error:#}").contains("not pruning"), "{error:#}");
    assert_eq!(chunk_count(), before - applied.chunks_removed);
    Ok(())
}

#[test]
fn fsck_finds_damaged_missing_and_unreadable_snapshots() -> Result<()> {
    use rebsync_core::{ObjectKey, ObjectStorage};
    let t = tempfile::tempdir()?;
    let config = config(t.path());
    frog_db(&t.path().join("AGENTS.db"), 6000);
    edition(&t.path().join("daily-agenda"), "ready", "<p>ok</p>");
    let storage = FsObjectStorage::open(&config.storage.root)?;
    let mut journal = Journal::open(t.path())?;
    let frog_id = frog::publish(&config, &storage, &mut journal)?.id;
    agenda::publish(&config, &storage, &mut journal)?;

    let clean = layer::fsck(&storage, layer::LAYERS)?;
    assert_eq!((clean.snapshots_checked, clean.snapshots_ok), (2, 2));
    assert!(clean.failures.is_empty() && clean.bytes_verified > 0);
    assert_eq!(clean.orphan_chunks, 0);

    let manifest = layer::load(&storage, "frog", &frog_id)?;
    let chunk_path = |digest: &str| {
        config
            .storage
            .root
            .join(format!("frog/v1/chunks/sha256/{}/{digest}", &digest[..2]))
    };
    let first = &manifest.files[0].chunks[0].sha256;
    let mut bytes = fs::read(chunk_path(first))?;
    bytes[0] ^= 0xff;
    fs::write(chunk_path(first), bytes)?;
    let damaged = layer::fsck(&storage, &["frog"])?;
    assert_eq!(damaged.failures.len(), 1);
    assert!(
        damaged.failures[0]
            .error
            .as_deref()
            .unwrap()
            .contains("damaged")
    );

    let second = &manifest.files[0].chunks[1].sha256;
    fs::remove_file(chunk_path(second))?;
    fs::remove_file(chunk_path(first))?;
    let missing = layer::fsck(&storage, &["frog"])?;
    assert!(
        missing.failures[0]
            .error
            .as_deref()
            .unwrap()
            .contains("missing")
    );

    storage.put(
        &ObjectKey::parse("agenda/v1/snapshots/local/broken.json")?,
        b"{",
    )?;
    let unreadable = layer::fsck(&storage, &["agenda"])?;
    assert_eq!((unreadable.snapshots_ok, unreadable.failures.len()), (1, 1));
    // fsck never writes: the agenda store is unchanged apart from our probe.
    assert!(
        storage
            .head(&ObjectKey::parse("agenda/v1/snapshots/local/broken.json")?)
            .is_ok()
    );
    Ok(())
}
