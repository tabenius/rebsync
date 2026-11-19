//! Enrolled drives: identity by marker, refusal of unenrolled or same-device
//! targets, and exchange through the peer engine. Drives live on /dev/shm,
//! a separate filesystem from the local object store, where available.
#![cfg(all(unix, feature = "storage-object-store"))]

use rebsync_core::drive::{self, MARKER, STORE_DIR};
use rebsync_core::peer::{self, PeerApi};
use rebsync_core::{Config, FsObjectStorage, journal::Journal, layer};
use serde_json::json;
use std::path::{Path, PathBuf};

fn config(home: &Path) -> Config {
    let mut config = Config::defaults(home.to_path_buf());
    config.storage.root = home.join("objects");
    config
}

/// A directory on another filesystem than `home`, or None (tests then skip
/// the independence assertions instead of faking them).
fn other_filesystem() -> Option<tempfile::TempDir> {
    use std::os::unix::fs::MetadataExt;
    let shm = Path::new("/dev/shm");
    let tmp = std::env::temp_dir();
    let (a, b) = (std::fs::metadata(shm).ok()?, std::fs::metadata(&tmp).ok()?);
    (a.dev() != b.dev())
        .then(|| tempfile::tempdir_in(shm).ok())
        .flatten()
}

fn publish(config: &Config, content: &[u8]) -> layer::PublishOutcome {
    let storage = FsObjectStorage::open(&config.storage.root).unwrap();
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(dir.path().join("data.txt"), content).unwrap();
    layer::publish_files(
        &storage,
        "frog",
        "local",
        65536,
        dir.path(),
        &["data.txt".into()],
        json!({"fixture": true}),
        None,
    )
    .unwrap()
}

#[test]
fn enrollment_writes_a_marker_and_identity_follows_the_marker_not_the_path() {
    let Some(stick) = other_filesystem() else {
        return eprintln!("skipped: no second filesystem");
    };
    let home = tempfile::tempdir().unwrap();
    let config = config(home.path());
    let enrollment = drive::enroll(&config, stick.path(), "usb-a", false, false).unwrap();
    let marker: serde_json::Value =
        serde_json::from_slice(&std::fs::read(stick.path().join(MARKER)).unwrap()).unwrap();
    assert_eq!(marker["id"], enrollment.id);
    assert_eq!(marker["schema"], "rbq.drive/1");

    let status = drive::status(&config, &[]).unwrap();
    assert_eq!(status.len(), 1);
    assert!(status[0].present);
    assert_eq!(status[0].independent, Some(true));

    // The same drive mounted elsewhere is still found (by marker).
    let moved = tempfile::tempdir_in("/dev/shm").unwrap();
    std::fs::rename(stick.path().join(MARKER), moved.path().join(MARKER)).unwrap();
    let status = drive::status(&config, &[moved.path().to_path_buf()]).unwrap();
    assert_eq!(
        status[0].path.as_deref(),
        Some(std::fs::canonicalize(moved.path()).unwrap().as_path())
    );
    // Without its marker the old location is no longer this drive.
    let status = drive::status(&config, &[]).unwrap();
    assert!(
        !status[0].present,
        "a path without the marker is not the drive"
    );
    assert!(drive::open(&config, "usb-a", &[]).is_err());
}

#[test]
fn refusals_protect_against_wrong_and_unenrolled_targets() {
    let Some(stick) = other_filesystem() else {
        return eprintln!("skipped: no second filesystem");
    };
    let home = tempfile::tempdir().unwrap();
    let config = config(home.path());
    // Same device as the local store: refused unless explicitly allowed.
    let same = home.path().join("same-disk");
    std::fs::create_dir_all(&same).unwrap();
    let error = drive::enroll(&config, &same, "same", false, false)
        .unwrap_err()
        .to_string();
    assert!(error.contains("same device"), "{error}");
    drive::enroll(&config, &same, "same", false, true).unwrap();
    let status = drive::status(&config, &[]).unwrap();
    assert_eq!(
        status
            .iter()
            .find(|s| s.name == "same")
            .unwrap()
            .independent,
        Some(false)
    );

    // Names are validated and unique; a marked drive needs --adopt; one
    // drive cannot be enrolled twice.
    assert!(drive::enroll(&config, stick.path(), "Bad Name", false, false).is_err());
    drive::enroll(&config, stick.path(), "usb-a", false, false).unwrap();
    assert!(drive::enroll(&config, stick.path(), "usb-a", false, false).is_err());
    let error = drive::enroll(&config, stick.path(), "usb-b", false, false)
        .unwrap_err()
        .to_string();
    assert!(error.contains("--adopt"), "{error}");
    assert!(
        drive::enroll(&config, stick.path(), "usb-b", true, false).is_err(),
        "already enrolled under another name"
    );

    // Another machine adopts the drive with its identity.
    let other_home = tempfile::tempdir().unwrap();
    let other = drive::enroll(
        &self::config(other_home.path()),
        stick.path(),
        "travel",
        true,
        false,
    )
    .unwrap();
    assert_eq!(other.id, drive::enrolled(&config).unwrap()["usb-a"].id);

    // Unenrolled names are refused; forgetting leaves the drive's data alone.
    assert!(drive::open(&config, "nope", &[]).is_err());
    drive::forget(&config, "usb-a").unwrap();
    assert!(stick.path().join(MARKER).exists());
    assert!(drive::open(&config, "usb-a", &[]).is_err());
}

#[test]
fn push_and_pull_reuse_the_peer_engine_and_never_overwrite() {
    let Some(stick) = other_filesystem() else {
        return eprintln!("skipped: no second filesystem");
    };
    let (home_a, home_b) = (tempfile::tempdir().unwrap(), tempfile::tempdir().unwrap());
    let (a, b) = (config(home_a.path()), config(home_b.path()));
    let published = publish(&a, &vec![b'x'; 150_000]);

    drive::enroll(&a, stick.path(), "usb", false, false).unwrap();
    let prefixes: Vec<String> = vec!["frog/".into()];
    let peer_a = drive::open(&a, "usb", &[]).unwrap();
    assert_eq!(peer_a.status().unwrap()["independent"], true);
    let local_a = FsObjectStorage::open(&a.storage.root).unwrap();
    let pushed = peer::push(
        &local_a,
        &peer_a,
        &prefixes,
        &mut Journal::open(&a.rbq_home).unwrap(),
    )
    .unwrap();
    assert!(pushed.clean() && pushed.transferred >= 2, "{pushed:?}");
    assert!(
        stick
            .path()
            .join(STORE_DIR)
            .join(&published.manifest_key)
            .exists()
    );
    let again = peer::push(
        &local_a,
        &peer_a,
        &prefixes,
        &mut Journal::open(&a.rbq_home).unwrap(),
    )
    .unwrap();
    assert_eq!(again.transferred, 0);

    // Machine B adopts the same drive and pulls a verified snapshot.
    drive::enroll(&b, stick.path(), "usb", true, false).unwrap();
    let peer_b = drive::open(&b, "usb", &[]).unwrap();
    let local_b = FsObjectStorage::open(&b.storage.root).unwrap();
    let pulled = peer::pull(
        &local_b,
        &peer_b,
        &prefixes,
        &mut Journal::open(&b.rbq_home).unwrap(),
    )
    .unwrap();
    assert!(pulled.clean(), "{pulled:?}");
    assert_eq!(pulled.verified, vec![published.manifest_key.clone()]);
    assert!(layer::check_snapshot(&local_b, "frog", &published.manifest_key).ok);

    // A damaged object on the drive is reported, never copied over good data.
    let chunk = peer_b
        .list("frog/")
        .unwrap()
        .into_keys()
        .find(|k| k.contains("/chunks/"))
        .unwrap();
    let path: PathBuf = stick.path().join(STORE_DIR).join(&chunk);
    let mut bytes = std::fs::read(&path).unwrap();
    bytes.push(0);
    std::fs::write(&path, bytes).unwrap();
    let conflicted = peer::pull(
        &local_b,
        &peer_b,
        &prefixes,
        &mut Journal::open(&b.rbq_home).unwrap(),
    )
    .unwrap();
    assert!(!conflicted.clean());
    assert!(
        conflicted.conflicts.iter().any(|c| c.starts_with(&chunk)),
        "{conflicted:?}"
    );
    assert!(layer::check_snapshot(&local_b, "frog", &published.manifest_key).ok);
}
