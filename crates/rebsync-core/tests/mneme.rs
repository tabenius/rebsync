//! The Mneme layer against a stand-in owner binary with the same CLI contract.
#![cfg(all(unix, feature = "storage-object-store"))]

use anyhow::Result;
use rebsync_core::{Config, FsObjectStorage, RunOptions, journal::Journal, mneme, run};
use std::{fs, os::unix::fs::PermissionsExt, path::Path};

const FAKE: &str = r#"#!/bin/sh
set -e
db=""
if [ "$1" = "--db" ]; then db="$2"; shift 2; fi
[ "$1" = snapshot ] || exit 9
case "$2" in
create) out="$4"; [ ! -e "$out" ]; cp "SOURCE" "$out" ;;
verify) out="$3"; want="$5" ;;
restore) out="$4"; want="$6"; [ ! -e "$db" ] || exit 3 ;;
*) exit 9 ;;
esac
sum=$(sha256sum "$out" | cut -d' ' -f1)
if [ -n "$want" ] && [ "$sum" != "$want" ]; then exit 4; fi
if [ "$2" = restore ]; then cp "$out" "$db"; fi
size=$(wc -c < "$out" | tr -d ' ')
printf '{"schema":"mneme.snapshot.v1","integrity":"ok","sha256":"%s","bytes":%s,"generation":7,"counts":{"messages":3}}\n' "$sum" "$size"
"#;

fn setup(home: &Path) -> Result<Config> {
    let source = home.join("source.sqlite");
    let data: Vec<u8> = (0..200 * 1024u32).map(|i| (i * 31 % 251) as u8).collect();
    fs::write(&source, data)?;
    let script = home.join("fake-mneme");
    fs::write(&script, FAKE.replace("SOURCE", source.to_str().unwrap()))?;
    fs::set_permissions(&script, fs::Permissions::from_mode(0o700))?;
    let mut config = Config::defaults(home.to_path_buf());
    config.scan.roots = vec![home.join("empty")];
    fs::create_dir_all(home.join("empty"))?;
    config.storage.root = home.join("objects");
    config.mneme.binary = script;
    config.mneme.chunk_bytes = 64 * 1024;
    config.mneme.restic = false;
    Ok(config)
}

#[test]
fn publish_dedups_lists_verifies_and_restores() -> Result<()> {
    let t = tempfile::tempdir()?;
    let config = setup(t.path())?;
    let storage = FsObjectStorage::open(&config.storage.root)?;
    let mut journal = Journal::open(t.path())?;

    let first = mneme::publish(&config, &storage, &mut journal)?;
    assert_eq!((first.chunks, first.new_chunks), (4, 4));
    assert_eq!(first.bytes, 200 * 1024);
    assert!(first.restic_snapshot.is_none());
    std::thread::sleep(std::time::Duration::from_millis(5));
    let second = mneme::publish(&config, &storage, &mut journal)?;
    assert_eq!((second.new_chunks, second.reused_chunks), (0, 4));
    assert_ne!(first.id, second.id);

    let listed = mneme::list(&storage, Some("local"))?;
    assert_eq!(listed.len(), 2);
    assert_eq!(listed[0].id, first.id);
    assert_eq!(listed[0].owner["generation"], 7);

    let verified = mneme::verify(&config, &storage, &first.id, &mut journal)?;
    assert_eq!(verified["sha256"], first.sha256);

    let target = t.path().join("restored/index.sqlite");
    fs::create_dir_all(target.parent().unwrap())?;
    mneme::restore(&config, &storage, &first.id, &target, &mut journal)?;
    assert_eq!(
        fs::read(&target)?,
        fs::read(t.path().join("source.sqlite"))?
    );
    assert!(mneme::restore(&config, &storage, &first.id, &target, &mut journal).is_err());

    // Damage one shared chunk: verification must notice before the owner runs.
    let chunk = &mneme::load(&storage, &first.id)?.chunks[1].sha256;
    let path = config
        .storage
        .root
        .join(format!("mneme/v1/chunks/sha256/{}/{chunk}", &chunk[..2]));
    let mut bytes = fs::read(&path)?;
    bytes[0] ^= 1;
    fs::write(&path, bytes)?;
    let error = mneme::verify(&config, &storage, &second.id, &mut journal).unwrap_err();
    assert!(format!("{error:#}").contains("damaged"), "{error:#}");
    assert!(mneme::verify(&config, &storage, "local/../x", &mut journal).is_err());
    Ok(())
}

#[test]
fn apply_run_reports_honest_layer_status() -> Result<()> {
    let t = tempfile::tempdir()?;
    let mut config = setup(t.path())?;
    config.mneme.enabled = true;

    let dry = run(&config, RunOptions { apply: false })?;
    assert_eq!(dry.datasets[0]["status"], "planned");

    let applied = run(&config, RunOptions { apply: true })?;
    // Local object storage is not off-machine protection.
    assert_eq!(applied.datasets[0]["status"], "published-local");
    assert!(applied.needs_attention());

    config.mneme.restic = true;
    let blocked = run(&config, RunOptions { apply: true })?;
    assert_eq!(blocked.datasets[0]["status"], "blocked");

    config.mneme.restic = false;
    config.mneme.binary = t.path().join("missing-mneme");
    let failed = run(&config, RunOptions { apply: true })?;
    assert_eq!(failed.datasets[0]["status"], "failed");
    Ok(())
}
