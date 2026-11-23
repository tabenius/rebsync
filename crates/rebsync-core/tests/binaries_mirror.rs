//! The binaries R2 mirror against a fake `restic` on PATH. One test only: it
//! changes PATH for this test binary, which must not race other tests.
#![cfg(all(unix, feature = "storage-object-store"))]

use anyhow::Result;
use rebsync_core::{Config, FsObjectStorage, binaries, journal::Journal};
use std::{fs, os::unix::fs::PermissionsExt, path::Path};

/// Records argv and whether RESTIC_REPOSITORY was set, keeps the "repository"
/// as a plain directory copy, and restores it under --target the way restic
/// does (absolute source path recreated beneath the target).
const FAKE_RESTIC: &str = r#"#!/bin/sh
set -e
state="STATE"
printf 'ARGS %s\n' "$*" >> "$state/log"
printf 'REPO %s\n' "${RESTIC_REPOSITORY:-unset}" >> "$state/log"
for arg; do last="$arg"; done
case " $* " in
*" backup "*)
  rm -rf "$state/mirror"; mkdir -p "$state/mirror"
  cp -a "$last/." "$state/mirror/"
  printf '%s' "$last" > "$state/source"
  echo '{"message_type":"summary","snapshot_id":"abc123"}'
  ;;
*" cat snapshot "*) echo '{"tree":"t"}' ;;
*" restore "*)
  target=""; previous=""
  for arg; do [ "$previous" = "--target" ] && target="$arg"; previous="$arg"; done
  nested="$target$(cat "$state/source")"
  mkdir -p "$nested"
  cp -a "$state/mirror/." "$nested/"
  ;;
*) exit 9 ;;
esac
"#;

fn executable(path: &Path, bytes: &[u8]) {
    fs::write(path, bytes).unwrap();
    fs::set_permissions(path, fs::Permissions::from_mode(0o755)).unwrap();
}

#[test]
fn mirror_is_scoped_tagged_credential_free_and_imports_only_verified_objects() -> Result<()> {
    let home = tempfile::tempdir()?;
    let state = home.path().join("restic-state");
    let bin = home.path().join("bin");
    fs::create_dir_all(&state)?;
    fs::create_dir_all(&bin)?;
    executable(
        &bin.join("restic"),
        FAKE_RESTIC
            .replace("STATE", state.to_str().unwrap())
            .as_bytes(),
    );
    let path = format!(
        "{}:{}",
        bin.display(),
        std::env::var("PATH").unwrap_or_default()
    );
    // SAFETY: this test binary contains exactly one test, so nothing else
    // reads the environment concurrently.
    unsafe { std::env::set_var("PATH", path) };

    let mut config = Config::defaults(home.path().to_path_buf());
    fs::create_dir_all(home.path().join("empty"))?;
    config.scan.roots = vec![home.path().join("empty")];
    config.storage.root = home.path().join("objects");
    config.binaries.chunk_bytes = 8;
    config.binaries.restic = true;
    config.binaries.repository = Some("s3:https://user:SECRET@r2.invalid/private".into());
    let storage = FsObjectStorage::open(&config.storage.root)?;
    let mut journal = Journal::open(home.path())?;

    // Another layer's private object must never enter the binaries mirror.
    let other = config.storage.root.join("mneme/v1/private-index");
    fs::create_dir_all(other.parent().unwrap())?;
    fs::write(&other, b"not for the binaries repository")?;

    let source = home.path().join("rbq-fixture");
    executable(&source, &(0..64).map(|n| n as u8).collect::<Vec<_>>());
    let spec = binaries::BinarySpec {
        tool: "rbq".into(),
        version: "0.2.4".into(),
        path: source.clone(),
        target: Some("x86_64-unknown-linux-gnu".into()),
        source: None,
        build_command: None,
        install_path: None,
        note: None,
    };
    let outcome = binaries::publish(&config, &storage, &[spec], &mut journal)?;
    assert_eq!(outcome.restic_snapshot.as_deref(), Some("abc123"));

    let log = fs::read_to_string(state.join("log"))?;
    let backup = log.lines().find(|l| l.contains(" backup ")).unwrap();
    assert!(backup.ends_with("objects/binaries/v1"), "{backup}");
    assert!(
        backup.contains("--tag rbq-binaries --tag rbq-binaries:"),
        "{backup}"
    );
    // The repository (which may carry credentials) is never on the command line.
    assert!(
        log.lines()
            .filter(|l| l.starts_with("ARGS"))
            .all(|l| !l.contains("SECRET"))
    );
    assert!(
        log.lines()
            .filter(|l| l.starts_with("REPO"))
            .all(|l| l.contains("r2.invalid"))
    );
    assert!(!state.join("mirror/private-index").exists());
    assert!(
        walkdir::WalkDir::new(state.join("mirror"))
            .into_iter()
            .filter_map(Result::ok)
            .all(|entry| !entry.path().to_string_lossy().contains("mneme")),
        "the mirror must hold binaries objects only"
    );

    // Lose the local layer; fetch re-imports it from the mirror.
    fs::remove_dir_all(config.storage.root.join("binaries"))?;
    let fetched = home.path().join("fetched-rbq");
    binaries::fetch(&config, &storage, "rbq", None, &fetched, &mut journal)?;
    assert_eq!(fs::read(&fetched)?, fs::read(&source)?);
    let restore = log_after(&state, "restore");
    assert!(restore.contains("--tag rbq-binaries "), "{restore}");

    // A tampered mirrored chunk is refused and nothing is installed.
    let chunk = walkdir::WalkDir::new(state.join("mirror/chunks"))
        .into_iter()
        .filter_map(Result::ok)
        .find(|entry| entry.file_type().is_file())
        .unwrap()
        .into_path();
    fs::write(&chunk, b"tampered")?;
    fs::remove_dir_all(config.storage.root.join("binaries"))?;
    let refused = home.path().join("refused-rbq");
    let error =
        binaries::fetch(&config, &storage, "rbq", None, &refused, &mut journal).unwrap_err();
    assert!(
        format!("{error:#}").contains("does not match its digest"),
        "{error:#}"
    );
    assert!(!refused.exists());

    // An existing destination is refused before the mirror is touched.
    let restores_before = log_count(&state, " restore ");
    assert!(binaries::fetch(&config, &storage, "rbq", None, &fetched, &mut journal).is_err());
    assert_eq!(log_count(&state, " restore "), restores_before);
    Ok(())
}

fn log_after(state: &Path, word: &str) -> String {
    fs::read_to_string(state.join("log"))
        .unwrap()
        .lines()
        .rfind(|line| line.contains(word))
        .unwrap()
        .to_owned()
}

fn log_count(state: &Path, word: &str) -> usize {
    fs::read_to_string(state.join("log"))
        .unwrap()
        .lines()
        .filter(|line| line.contains(word))
        .count()
}
