//! Actual peer API three-store recovery exercise: producer → carrying peer → recipient.
//! This is NOT an Android hardware/network or remote-S3 test.
#![cfg(all(unix, feature = "storage-object-store"))]

use anyhow::Result;
use rebsync_core::{
    Config, FsObjectStorage, ObjectKey, ObjectStorage, PutOutcome,
    gitlayer, journal::Journal, layer, peer::{self, PeerApi},
};
use serde_json::{Value, json};
use std::{collections::BTreeMap, fs, path::Path, process::Command};

/// Models the Android carrying peer's object-store boundary without a network.
/// The production transport and Android lifecycle still need device tests.
struct CarryingPeer<'a> {
    store: &'a FsObjectStorage,
}
impl PeerApi for CarryingPeer<'_> {
    fn base(&self) -> &str { "synthetic-offline-carrying-peer" }
    fn status(&self) -> Result<Value> { Ok(json!({"protocol": "test-carrier"})) }
    fn list(&self, prefix: &str) -> Result<BTreeMap<String, u64>> {
        Ok(self.store.list_prefix(prefix, 0)?
            .into_iter().map(|meta| (meta.key, meta.size)).collect())
    }
    fn get(&self, key: &str) -> Result<Vec<u8>> {
        Ok(self.store.get(&ObjectKey::parse(key)?)?)
    }
    fn put(&self, key: &str, bytes: &[u8]) -> Result<bool> {
        Ok(matches!(
            self.store.put_if_absent(&ObjectKey::parse(key)?, bytes)?,
            PutOutcome::Created(_)
        ))
    }
}
fn config(home: &Path) -> Config {
    let mut cfg = Config::defaults(home.to_path_buf());
    cfg.storage.root = home.join("objects");
    cfg.scan.roots = vec![home.join("src")];
    cfg
}
fn git(repo: &Path, args: &[&str]) -> String {
    let out = Command::new("git")
        .current_dir(repo)
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .env("GIT_AUTHOR_NAME", "Test")
        .env("GIT_AUTHOR_EMAIL", "test@example.invalid")
        .env("GIT_COMMITTER_NAME", "Test")
        .env("GIT_COMMITTER_EMAIL", "test@example.invalid")
        .args(["-c", "core.hooksPath=/dev/null", "-c", "commit.gpgsign=false"])
        .args(args).output().unwrap();
    assert!(out.status.success(), "git {:?}: {}", args, String::from_utf8_lossy(&out.stderr));
    String::from_utf8(out.stdout).unwrap().trim().to_owned()
}

#[test]
fn three_store_peer_exchange_restores_git_and_other_layer_without_producer() -> Result<()> {
    let t = tempfile::tempdir()?;
    let (a, carrier, b) = (t.path().join("a"), t.path().join("phone"), t.path().join("b"));
    for home in [&a, &carrier, &b] { fs::create_dir_all(home)?; }
    let a_cfg = config(&a);
    let b_cfg = config(&b);
    let a_store = FsObjectStorage::open(&a_cfg.storage.root)?;
    let phone_store = FsObjectStorage::open(carrier.join("objects"))?;
    let b_store = FsObjectStorage::open(&b_cfg.storage.root)?;

    // Native Git owner exports its own bundle.
    let a_repo = a.join("src/project");
    fs::create_dir_all(&a_repo)?;
    git(&a_repo, &["init", "-qb", "main"]);
    fs::write(a_repo.join("README"), "immutable original\n")?;
    git(&a_repo, &["add", "README"]);
    git(&a_repo, &["commit", "-qm", "initial"]);
    let original = git(&a_repo, &["rev-parse", "HEAD"]);
    let mut a_journal = Journal::open(&a)?;
    let git_snapshot = gitlayer::publish_all(&a_cfg, &a_store, &mut a_journal)?;
    assert_eq!(git_snapshot.len(), 1);
    let git_id = git_snapshot[0].snapshot.as_ref().unwrap().id.clone();

    // Second layer confirms exchange is not just a Git special case.
    let sample = a.join("export");
    fs::create_dir_all(&sample)?;
    fs::write(sample.join("sample.txt"), "verified portable data\n")?;
    let edition = layer::publish_files(
        &a_store, "agenda", "synthetic", 4096,
        &sample, &["sample.txt".to_owned()], json!({"fixture": true}), None
    )?;

    let selection = vec!["git/".to_owned(), "agenda/".to_owned()];
    let phone = CarryingPeer { store: &phone_store };
    let sent = peer::push(&a_store, &phone, &selection, &mut a_journal)?;
    assert!(sent.clean(), "{sent:?}");
    assert!(sent.transferred > 0);
    assert!(layer::fsck(&phone_store, &["git", "agenda"])?.failures.is_empty());
    // An identical second push must not create additional objects.
    let repeated = peer::push(&a_store, &phone, &selection, &mut a_journal)?;
    assert!(repeated.clean());
    assert_eq!(repeated.transferred, 0);

    // Laptop A is not consulted again from here onward.
    let mut b_journal = Journal::open(&b)?;
    let received = peer::pull(&b_store, &phone, &selection, &mut b_journal)?;
    assert!(received.clean(), "{received:?}");
    assert_eq!(received.verified.len(), 2);
    assert!(layer::fsck(&b_store, &["git", "agenda"])?.failures.is_empty());
    gitlayer::verify(&b_cfg, &b_store, &git_id)?;
    let restored_repo = b.join("recovered-git");
    gitlayer::restore(&b_cfg, &b_store, &git_id, &restored_repo, &mut b_journal)?;
    assert_eq!(git(&restored_repo, &["rev-parse", "HEAD"]), original);
    assert_eq!(fs::read_to_string(restored_repo.join("README"))?, "immutable original\n");
    let manifest = layer::load(&b_store, "agenda", &edition.id)?;
    let restored_edition = b.join("recovered-edition");
    layer::assemble(&b_store, &manifest, &restored_edition)?;
    assert_eq!(fs::read_to_string(restored_edition.join("sample.txt"))?, "verified portable data\n");
    Ok(())
}

#[test]
fn incomplete_source_manifest_is_not_advertised_to_a_carrying_peer() -> Result<()> {
    let t = tempfile::tempdir()?;
    let cfg = config(t.path());
    let store = FsObjectStorage::open(&cfg.storage.root)?;
    let carrier = FsObjectStorage::open(t.path().join("phone-objects"))?;
    let data = t.path().join("export");
    fs::create_dir_all(&data)?;
    fs::write(data.join("sample.txt"), b"hello")?;
    let published = layer::publish_files(
        &store, "agenda", "synthetic", 4096, &data,
        &["sample.txt".to_owned()], json!({"fixture": true}), None
    )?;
    let manifest = layer::load(&store, "agenda", &published.id)?;
    let digest = &manifest.files[0].chunks[0].sha256;
    let chunk = layer::chunk_key("agenda/v1", digest)?;
    store.delete(&chunk)?;

    let mut journal = Journal::open(t.path())?;
    let phone = CarryingPeer { store: &carrier };
    let report = peer::push(&store, &phone, &["agenda/".to_owned()], &mut journal)?;
    assert!(!report.clean());
    assert!(report.rejected.iter().any(|message| message.contains("not recoverable")));
    assert!(carrier.list_prefix("agenda/v1/snapshots/", 0)?.is_empty());
    Ok(())
}
