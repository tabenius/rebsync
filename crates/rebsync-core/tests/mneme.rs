//! The Mneme layer against a stand-in owner binary with the same CLI contract.
#![cfg(all(unix, feature = "storage-object-store"))]

use anyhow::Result;
use rebsync_core::{
    Config, FsObjectStorage, ObjectStorage, RunOptions, journal::Journal, mneme, run,
};
use std::{fs, os::unix::fs::PermissionsExt, path::Path};

const FAKE: &str = r#"#!/bin/sh
set -e
db=""
if [ "$1" = "--db" ]; then db="$2"; shift 2; fi
[ "$1" = snapshot ] || exit 9
case "$2" in
--help) printf 'Usage: mneme snapshot <COMMAND>\n\nCommands:\n  create   Export\n  verify   Check\n  restore  Restore\n\nOptions:\n  -h, --help  Print help\n'; exit 0 ;;
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

    let stats = mneme::stats(&storage)?;
    assert_eq!(stats.snapshots, 2);
    assert_eq!(stats.logical_bytes, 2 * 200 * 1024);
    assert_eq!(stats.stored_bytes, 200 * 1024);
    assert_eq!((stats.orphan_chunks, stats.missing_chunks), (0, 0));
    assert_eq!(stats.latest_id.as_deref(), Some(second.id.as_str()));

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
    // An orphan from an interrupted publish is reported, never deleted.
    let orphan = config
        .storage
        .root
        .join(format!("mneme/v1/chunks/sha256/00/{}", "0".repeat(64)));
    fs::create_dir_all(orphan.parent().unwrap())?;
    fs::write(&orphan, b"orphan")?;
    let stats = mneme::stats(&storage)?;
    assert_eq!((stats.orphan_chunks, stats.orphan_bytes), (1, 6));
    assert!(orphan.exists());
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

#[test]
fn prune_understands_mneme_manifests_and_shared_chunks() -> Result<()> {
    use rebsync_core::{chrono::Duration as Span, layer};
    let t = tempfile::tempdir()?;
    let config = setup(t.path())?;
    let storage = FsObjectStorage::open(&config.storage.root)?;
    let mut journal = Journal::open(t.path())?;
    let first = mneme::publish(&config, &storage, &mut journal)?;
    std::thread::sleep(std::time::Duration::from_millis(5));
    let second = mneme::publish(&config, &storage, &mut journal)?;
    let retention = layer::Retention {
        keep_last: 1,
        keep_days: None,
        label: None,
        grace: Span::zero(),
    };
    let report = layer::prune(&storage, "mneme", &retention, true)?;
    assert_eq!(report.snapshots_removed, vec![first.id.clone()]);
    // Identical content: every chunk is still referenced by the survivor.
    assert_eq!(report.chunks_removed, 0);
    mneme::verify(&config, &storage, &second.id, &mut journal)?;
    assert_eq!(mneme::list(&storage, None)?.len(), 1);
    Ok(())
}

#[test]
fn fsck_reads_mneme_manifests() -> Result<()> {
    use rebsync_core::layer;
    let t = tempfile::tempdir()?;
    let config = setup(t.path())?;
    let storage = FsObjectStorage::open(&config.storage.root)?;
    let mut journal = Journal::open(t.path())?;
    mneme::publish(&config, &storage, &mut journal)?;
    let report = layer::fsck(&storage, &["mneme"])?;
    assert_eq!((report.snapshots_checked, report.snapshots_ok), (1, 1));
    assert_eq!(report.bytes_verified, 200 * 1024);
    Ok(())
}

/// Owner fixture with the optional sidecar commands. The legacy `FAKE` above
/// stays untouched as the strict v1 regression fixture.
const FAKE_SIDECAR: &str = r#"#!/bin/sh
set -e
db=""
if [ "$1" = "--db" ]; then db="$2"; shift 2; fi
[ "$1" = snapshot ] || exit 9
case "$2" in
--help) printf 'Usage: mneme snapshot <COMMAND>\n\nCommands:\n  create           Export\n  create-sidecar   Export outputs\n  verify           Check\n  verify-sidecar   Check outputs\n  restore          Restore\n  restore-sidecar  Restore outputs\n'; exit 0 ;;
create) out="$4"; [ ! -e "$out" ]; cp "SOURCE" "$out" ;;
create-sidecar)
  out="$4"; [ ! -e "$out" ]
  if [ -e "CRASH_FILE" ]; then exit 7; fi
  if [ -e "BLOCK_FILE" ]; then
    printf '%s\n' '{"schema":"mneme.outputs-sidecar.v1","migration":{"status":"required"}}'
    exit 2
  fi
  if [ ! -f "SIDECAR_SOURCE" ]; then
    printf '%s\n' '{"schema":"mneme.outputs-sidecar.v1","available":false,"reason":"not_initialized"}'
    exit 0
  fi
  cp "SIDECAR_SOURCE" "$out"
  want=""
  ;;
verify) out="$3"; want="$5" ;;
verify-sidecar) out="$3"; want="$5" ;;
restore) out="$4"; want="$6"; [ ! -e "$db" ] || exit 3 ;;
restore-sidecar)
  out="$4"; want="$6"; [ -n "$db" ] || exit 9
  dest=$(dirname "$db")/mneme-outputs.sqlite
  [ ! -e "$dest" ] || exit 5
  cp "$out" "$dest"
  ;;
*) exit 9 ;;
esac
sum=$(sha256sum "$out" | cut -d' ' -f1)
if [ -n "$want" ] && [ "$sum" != "$want" ]; then exit 4; fi
if [ "$2" = restore ]; then cp "$out" "$db"; fi
case "$2" in
create-sidecar|verify-sidecar|restore-sidecar)
  python3 -c 'import hashlib,json,sys
p=sys.argv[1]
b=open(p,"rb").read()
n=65536
cs=[{"sha256":hashlib.sha256(b[i:i+n]).hexdigest(),"bytes":len(b[i:i+n]),"offset":i} for i in range(0,len(b),n)]
print(json.dumps({"schema":"mneme.outputs-sidecar.v1","available":True,"path":"mneme-outputs.sqlite","sha256":hashlib.sha256(b).hexdigest(),"bytes":len(b),"chunks":cs},separators=(",",":")))' "$out"
  ;;
*)
  size=$(wc -c < "$out" | tr -d ' ')
  printf '{"schema":"mneme.snapshot.v1","integrity":"ok","sha256":"%s","bytes":%s,"generation":7,"counts":{"messages":3}}\n' "$sum" "$size"
  ;;
esac
"#;

const SIDECAR_BYTES: u64 = 100 * 1024 + 123;

fn setup_sidecar(home: &Path) -> Result<Config> {
    let mut config = setup(home)?;
    let sidecar_source = home.join("source-outputs.sqlite");
    let data: Vec<u8> = (0..SIDECAR_BYTES as u32)
        .map(|i| (i * 17 % 251) as u8)
        .collect();
    fs::write(&sidecar_source, data)?;
    let script = home.join("fake-mneme-sidecar");
    let body = FAKE_SIDECAR
        .replace("SIDECAR_SOURCE", sidecar_source.to_str().unwrap())
        .replace("SOURCE", home.join("source.sqlite").to_str().unwrap())
        .replace("BLOCK_FILE", home.join("block-sidecar").to_str().unwrap())
        .replace("CRASH_FILE", home.join("crash-sidecar").to_str().unwrap());
    fs::write(&script, body)?;
    fs::set_permissions(&script, fs::Permissions::from_mode(0o700))?;
    config.mneme.binary = script;
    Ok(config)
}

fn sidecar_digests(manifest: &mneme::LayerManifest) -> Vec<String> {
    manifest.owner["tool_output_sidecar"]["chunks"]
        .as_array()
        .unwrap()
        .iter()
        .map(|chunk| chunk["sha256"].as_str().unwrap().to_owned())
        .collect()
}

fn chunk_path(config: &Config, digest: &str) -> std::path::PathBuf {
    config
        .storage
        .root
        .join(format!("mneme/v1/chunks/sha256/{}/{digest}", &digest[..2]))
}

#[test]
fn sidecar_is_chunked_owner_nested_verified_and_restored() -> Result<()> {
    use rebsync_core::ObjectKey;
    let t = tempfile::tempdir()?;
    let config = setup_sidecar(t.path())?;
    let storage = FsObjectStorage::open(&config.storage.root)?;
    let mut journal = Journal::open(t.path())?;

    let outcome = mneme::publish(&config, &storage, &mut journal)?;
    // The core contract is unchanged: top-level chunks still sum to bytes.
    assert_eq!(outcome.chunks, 4);
    let manifest = mneme::load(&storage, &outcome.id)?;
    assert_eq!(manifest.schema, mneme::LAYER_SCHEMA);
    assert_eq!(manifest.owner["schema"], mneme::OWNER_SCHEMA);
    assert_eq!(
        manifest.chunks.iter().map(|c| c.size).sum::<u64>(),
        manifest.bytes
    );
    assert_eq!(
        manifest.owner["tool_output_sidecar"]["schema"],
        "mneme.outputs-sidecar.v1"
    );
    assert_eq!(
        manifest.owner["tool_output_sidecar"]["path"],
        "mneme-outputs.sqlite"
    );
    assert_eq!(
        manifest.owner["tool_output_sidecar"]["bytes"],
        SIDECAR_BYTES
    );
    let digests = sidecar_digests(&manifest);
    assert_eq!(digests.len(), 2);
    for digest in &digests {
        assert!(
            storage
                .head(&ObjectKey::parse(&format!(
                    "mneme/v1/chunks/sha256/{}/{digest}",
                    &digest[..2]
                ))?)
                .is_ok()
        );
    }
    let stats = mneme::stats(&storage)?;
    assert_eq!((stats.referenced_chunks, stats.stored_chunks), (6, 6));
    assert_eq!((stats.orphan_chunks, stats.missing_chunks), (0, 0));
    // Sidecar bytes are not folded into the core logical snapshot bytes.
    assert_eq!(stats.logical_bytes, 200 * 1024);

    let verified = mneme::verify(&config, &storage, &outcome.id, &mut journal)?;
    assert_eq!(verified["sha256"], outcome.sha256);

    let target = t.path().join("restored/index.sqlite");
    fs::create_dir_all(target.parent().unwrap())?;
    mneme::restore(&config, &storage, &outcome.id, &target, &mut journal)?;
    assert_eq!(
        fs::read(&target)?,
        fs::read(t.path().join("source.sqlite"))?
    );
    assert_eq!(
        fs::read(target.parent().unwrap().join("mneme-outputs.sqlite"))?,
        fs::read(t.path().join("source-outputs.sqlite"))?
    );
    assert!(mneme::restore(&config, &storage, &outcome.id, &target, &mut journal).is_err());
    Ok(())
}

#[test]
fn unavailable_and_legacy_sidecars_keep_the_v1_manifest() -> Result<()> {
    let t = tempfile::tempdir()?;
    let config = setup_sidecar(t.path())?;
    fs::remove_file(t.path().join("source-outputs.sqlite"))?;
    let storage = FsObjectStorage::open(&config.storage.root)?;
    let mut journal = Journal::open(t.path())?;
    let outcome = mneme::publish(&config, &storage, &mut journal)?;
    let manifest = mneme::load(&storage, &outcome.id)?;
    assert!(manifest.owner.get("tool_output_sidecar").is_none());
    assert_eq!(manifest.chunks.len(), 4);
    mneme::verify(&config, &storage, &outcome.id, &mut journal)?;
    let target = t.path().join("legacy/index.sqlite");
    fs::create_dir_all(target.parent().unwrap())?;
    mneme::restore(&config, &storage, &outcome.id, &target, &mut journal)?;
    assert!(
        !target
            .parent()
            .unwrap()
            .join("mneme-outputs.sqlite")
            .exists()
    );
    Ok(())
}

#[test]
fn tampered_or_missing_sidecar_chunks_are_refused() -> Result<()> {
    use rebsync_core::layer;
    let t = tempfile::tempdir()?;
    let config = setup_sidecar(t.path())?;
    let storage = FsObjectStorage::open(&config.storage.root)?;
    let mut journal = Journal::open(t.path())?;
    let outcome = mneme::publish(&config, &storage, &mut journal)?;
    let digest = sidecar_digests(&mneme::load(&storage, &outcome.id)?)[0].clone();
    let path = chunk_path(&config, &digest);
    let original = fs::read(&path)?;

    let mut damaged = original.clone();
    damaged[0] ^= 1;
    fs::write(&path, damaged)?;
    let error = mneme::verify(&config, &storage, &outcome.id, &mut journal).unwrap_err();
    assert!(format!("{error:#}").contains("damaged"), "{error:#}");
    let report = layer::fsck(&storage, &["mneme"])?;
    assert_eq!(report.failures.len(), 1);
    assert!(
        report.failures[0]
            .error
            .as_deref()
            .unwrap()
            .contains("damaged")
    );

    fs::write(&path, &original)?;
    fs::remove_file(&path)?;
    let error = mneme::verify(&config, &storage, &outcome.id, &mut journal).unwrap_err();
    assert!(format!("{error:#}").contains("missing"), "{error:#}");
    let error = mneme::restore(
        &config,
        &storage,
        &outcome.id,
        &t.path().join("restored/index.sqlite"),
        &mut journal,
    )
    .unwrap_err();
    assert!(format!("{error:#}").contains("missing"), "{error:#}");
    Ok(())
}

#[test]
fn forged_sidecar_owner_metadata_is_refused() -> Result<()> {
    use rebsync_core::ObjectKey;
    use serde_json::{Value, json};
    let t = tempfile::tempdir()?;
    let config = setup_sidecar(t.path())?;
    let storage = FsObjectStorage::open(&config.storage.root)?;
    let mut journal = Journal::open(t.path())?;
    let outcome = mneme::publish(&config, &storage, &mut journal)?;
    let key = ObjectKey::parse(&format!("mneme/v1/snapshots/{}.json", outcome.id))?;
    let original = storage.get(&key)?;
    let manifest: Value = serde_json::from_slice(&original)?;

    let mut bad = manifest.clone();
    bad["owner"]["tool_output_sidecar"]["bytes"] = json!(SIDECAR_BYTES + 1);
    storage.put(&key, &serde_json::to_vec_pretty(&bad)?)?;
    assert!(mneme::load(&storage, &outcome.id).is_err());

    let mut bad = manifest.clone();
    bad["owner"]["tool_output_sidecar"]["sha256"] = json!("ab".repeat(32));
    storage.put(&key, &serde_json::to_vec_pretty(&bad)?)?;
    let error = mneme::verify(&config, &storage, &outcome.id, &mut journal).unwrap_err();
    assert!(
        format!("{error:#}").contains("reassembled sidecar digest"),
        "{error:#}"
    );

    let mut bad = manifest.clone();
    bad["owner"]["tool_output_sidecar"]["path"] = json!("../escape");
    storage.put(&key, &serde_json::to_vec_pretty(&bad)?)?;
    assert!(mneme::load(&storage, &outcome.id).is_err());

    let mut bad = manifest;
    bad["owner"]["tool_output_sidecar"]["unexpected"] = json!(true);
    storage.put(&key, &serde_json::to_vec_pretty(&bad)?)?;
    assert!(mneme::load(&storage, &outcome.id).is_err());

    storage.put(&key, &original)?;
    mneme::verify(&config, &storage, &outcome.id, &mut journal)?;
    Ok(())
}

#[test]
fn prune_and_fsck_retain_owner_nested_sidecar_chunks() -> Result<()> {
    use rebsync_core::{chrono::Duration as Span, layer};
    let t = tempfile::tempdir()?;
    let config = setup_sidecar(t.path())?;
    let storage = FsObjectStorage::open(&config.storage.root)?;
    let mut journal = Journal::open(t.path())?;
    let first = mneme::publish(&config, &storage, &mut journal)?;
    let shared_digests = sidecar_digests(&mneme::load(&storage, &first.id)?);
    // Only the index changes; the sidecar chunks are shared by both snapshots.
    let changed: Vec<u8> = (0..200 * 1024u32).map(|i| (i * 37 % 251) as u8).collect();
    fs::write(t.path().join("source.sqlite"), changed)?;
    std::thread::sleep(std::time::Duration::from_millis(5));
    let second = mneme::publish(&config, &storage, &mut journal)?;
    assert_eq!(
        shared_digests,
        sidecar_digests(&mneme::load(&storage, &second.id)?)
    );

    let report = layer::prune(
        &storage,
        "mneme",
        &layer::Retention {
            keep_last: 1,
            keep_days: None,
            label: None,
            grace: Span::zero(),
        },
        true,
    )?;
    assert_eq!(report.snapshots_removed, vec![first.id.clone()]);
    // Four core chunks from the old index are swept; shared sidecar chunks stay.
    assert_eq!(report.chunks_removed, 4);
    for digest in &shared_digests {
        assert!(
            storage
                .head(&rebsync_core::ObjectKey::parse(&format!(
                    "mneme/v1/chunks/sha256/{}/{digest}",
                    &digest[..2]
                ))?)
                .is_ok(),
            "sidecar chunk {digest} was pruned"
        );
    }
    mneme::verify(&config, &storage, &second.id, &mut journal)?;
    let fsck = layer::fsck(&storage, &["mneme"])?;
    assert_eq!((fsck.snapshots_checked, fsck.snapshots_ok), (1, 1));
    assert_eq!(fsck.orphan_chunks, 0);
    assert_eq!(fsck.bytes_verified, 200 * 1024 + SIDECAR_BYTES);
    Ok(())
}

#[test]
fn sidecar_migration_refusal_is_not_treated_as_unavailable() -> Result<()> {
    use rebsync_core::migration::MigrationBlocked;
    let t = tempfile::tempdir()?;
    let config = setup_sidecar(t.path())?;
    fs::write(t.path().join("block-sidecar"), b"")?;
    let storage = FsObjectStorage::open(&config.storage.root)?;
    let mut journal = Journal::open(t.path())?;
    let error = mneme::publish(&config, &storage, &mut journal).unwrap_err();
    assert!(
        error.downcast_ref::<MigrationBlocked>().is_some(),
        "{error:#}"
    );
    assert!(mneme::list(&storage, None)?.is_empty());
    Ok(())
}

#[test]
fn a_capable_owner_whose_sidecar_export_fails_fails_the_publish() -> Result<()> {
    let t = tempfile::tempdir()?;
    let config = setup_sidecar(t.path())?;
    fs::write(t.path().join("crash-sidecar"), b"")?;
    let storage = FsObjectStorage::open(&config.storage.root)?;
    let mut journal = Journal::open(t.path())?;
    // Before: any non-migration failure silently meant "no sidecar".
    assert!(mneme::publish(&config, &storage, &mut journal).is_err());
    assert!(mneme::list(&storage, None)?.is_empty());
    Ok(())
}

#[test]
fn an_owner_without_sidecar_commands_publishes_the_v1_snapshot_only() -> Result<()> {
    let t = tempfile::tempdir()?;
    let config = setup(t.path())?;
    let storage = FsObjectStorage::open(&config.storage.root)?;
    let mut journal = Journal::open(t.path())?;
    let outcome = mneme::publish(&config, &storage, &mut journal)?;
    assert!(
        mneme::load(&storage, &outcome.id)?
            .owner
            .get("tool_output_sidecar")
            .is_none()
    );
    Ok(())
}

#[test]
fn an_owner_that_cannot_describe_its_commands_is_an_error() -> Result<()> {
    let t = tempfile::tempdir()?;
    let mut config = setup(t.path())?;
    let script = t.path().join("broken-mneme");
    // Exports fine, but cannot describe its commands.
    fs::write(
        &script,
        format!(
            "#!/bin/sh\n[ \"$2\" = --help ] && exit 1\nexec {} \"$@\"\n",
            config.mneme.binary.display()
        ),
    )?;
    fs::set_permissions(&script, fs::Permissions::from_mode(0o700))?;
    config.mneme.binary = script;
    let storage = FsObjectStorage::open(&config.storage.root)?;
    let mut journal = Journal::open(t.path())?;
    let error = mneme::publish(&config, &storage, &mut journal).unwrap_err();
    assert!(format!("{error:#}").contains("capabilities"), "{error:#}");
    Ok(())
}
