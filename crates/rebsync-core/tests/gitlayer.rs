//! The git layer: publish on one machine, carry, fetch on another, offline.
#![cfg(all(unix, feature = "storage-object-store"))]

use anyhow::Result;
use rebsync_core::{
    Config, FsObjectStorage, ObjectKey, ObjectStorage, RunOptions, gitlayer, journal::Journal,
    layer, run,
};
use std::{fs, path::Path, process::Command};

fn git(path: &Path, args: &[&str]) -> String {
    let out = Command::new("git")
        .current_dir(path)
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .env("GIT_AUTHOR_NAME", "Test")
        .env("GIT_AUTHOR_EMAIL", "test@example.invalid")
        .env("GIT_COMMITTER_NAME", "Test")
        .env("GIT_COMMITTER_EMAIL", "test@example.invalid")
        .args([
            "-c",
            "core.hooksPath=/dev/null",
            "-c",
            "commit.gpgsign=false",
        ])
        .args(args)
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "git {args:?}: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    String::from_utf8(out.stdout).unwrap().trim().to_owned()
}

fn commit(repo: &Path, file: &str, body: &str) -> String {
    fs::write(repo.join(file), body).unwrap();
    git(repo, &["add", "."]);
    git(repo, &["commit", "-qm", file]);
    git(repo, &["rev-parse", "HEAD"])
}

fn config(home: &Path) -> Config {
    let mut config = Config::defaults(home.to_path_buf());
    config.scan.roots = vec![home.join("src")];
    config.storage.root = home.join("objects");
    config
}

#[test]
fn offline_exchange_publish_carry_fetch_without_touching_local_work() -> Result<()> {
    let t = tempfile::tempdir()?;
    // Laptop A.
    let a_home = t.path().join("a");
    let a_repo = a_home.join("src/project");
    fs::create_dir_all(&a_repo)?;
    git(&a_repo, &["init", "-qb", "main"]);
    let base = commit(&a_repo, "README", "one\n");
    git(&a_repo, &["tag", "v1"]);
    let a_cfg = config(&a_home);
    let a_store = FsObjectStorage::open(&a_cfg.storage.root)?;
    let mut journal = Journal::open(&a_home)?;

    let first = gitlayer::publish_all(&a_cfg, &a_store, &mut journal)?;
    assert_eq!(first.len(), 1);
    assert_eq!(first[0].status, "published");
    // Unchanged refs: nothing new is published.
    let again = gitlayer::publish_all(&a_cfg, &a_store, &mut journal)?;
    assert_eq!(again[0].status, "unchanged");
    // New work on A, published again.
    git(&a_repo, &["checkout", "-qb", "feature"]);
    let feature = commit(&a_repo, "feature.txt", "offline work\n");
    let second = gitlayer::publish_all(&a_cfg, &a_store, &mut journal)?;
    assert_eq!(second[0].status, "published");
    let id = second[0].snapshot.as_ref().unwrap().id.clone();
    gitlayer::verify(&a_cfg, &a_store, &id)?;

    // Carry the store (in real life: rbq peer push / pull via the phone).
    let b_home = t.path().join("b");
    let b_cfg = config(&b_home);
    fs::create_dir_all(&b_home)?;
    let b_store = FsObjectStorage::open(&b_cfg.storage.root)?;
    for meta in a_store.list_prefix("git/", 0)? {
        let key = ObjectKey::parse(&meta.key)?;
        b_store.put(&key, &a_store.get(&key)?)?;
    }
    assert!(layer::fsck(&b_store, &["git"])?.failures.is_empty());

    // Laptop B has its own diverged clone with local, uncommitted work.
    let b_repo = b_home.join("project");
    let mut b_journal = Journal::open(&b_home)?;
    gitlayer::restore(
        &b_cfg,
        &b_store,
        &first[0].snapshot.as_ref().unwrap().id,
        &b_repo,
        &mut b_journal,
    )?;
    assert_eq!(git(&b_repo, &["rev-parse", "HEAD"]), base);
    assert_eq!(
        git(&b_repo, &["remote"]),
        "",
        "temporary bundle remote removed"
    );
    let local = commit(&b_repo, "local.txt", "B's own work\n");
    git(&b_repo, &["tag", "-f", "v1"]);
    let b_tag = git(&b_repo, &["rev-parse", "v1"]);
    fs::write(b_repo.join("uncommitted.txt"), "draft")?;

    let fetched = gitlayer::fetch(
        &b_cfg,
        &b_store,
        &id,
        &b_repo,
        Some("laptop-a"),
        &mut b_journal,
    )?;
    assert_eq!(fetched["branches"], "refs/remotes/rbq-laptop-a/*");
    // A's work arrives in the rbq namespace...
    assert_eq!(
        git(&b_repo, &["rev-parse", "refs/remotes/rbq-laptop-a/feature"]),
        feature
    );
    assert_eq!(
        git(&b_repo, &["rev-parse", "refs/rbq/laptop-a/tags/v1"]),
        base
    );
    // ...and nothing of B's own changed.
    assert_eq!(git(&b_repo, &["rev-parse", "main"]), local);
    assert_eq!(git(&b_repo, &["rev-parse", "v1"]), b_tag);
    assert_eq!(fs::read_to_string(b_repo.join("uncommitted.txt"))?, "draft");
    assert!(git(&b_repo, &["status", "--porcelain"]).contains("uncommitted.txt"));

    // Restore never overwrites; fetch needs a real repository.
    assert!(gitlayer::restore(&b_cfg, &b_store, &id, &b_repo, &mut b_journal).is_err());
    assert!(
        gitlayer::fetch(
            &b_cfg,
            &b_store,
            &id,
            &b_home.join("objects"),
            None,
            &mut b_journal
        )
        .is_err()
    );
    Ok(())
}

#[test]
fn tampered_bundles_and_mismatched_heads_are_refused() -> Result<()> {
    let t = tempfile::tempdir()?;
    let repo = t.path().join("src/project");
    fs::create_dir_all(&repo)?;
    git(&repo, &["init", "-qb", "main"]);
    for i in 0..30 {
        commit(&repo, &format!("f{i}"), &"x".repeat(5000 + i));
    }
    let cfg = config(t.path());
    let store = FsObjectStorage::open(&cfg.storage.root)?;
    let mut journal = Journal::open(t.path())?;
    let id = gitlayer::publish_all(&cfg, &store, &mut journal)?[0]
        .snapshot
        .as_ref()
        .unwrap()
        .id
        .clone();
    let mut manifest = layer::load(&store, "git", &id)?;
    // Forge a manifest whose recorded heads differ from the bundle's.
    manifest.owner["heads"] =
        serde_json::json!([{"ref": "refs/heads/main", "oid": "0".repeat(40)}]);
    let forged = id.replacen(&id[id.len() - 4..], "beef", 1);
    manifest.id = forged.clone();
    store.put(
        &layer::manifest_key("git", &forged)?,
        &serde_json::to_vec(&manifest)?,
    )?;
    let error = gitlayer::verify(&cfg, &store, &forged).unwrap_err();
    assert!(
        format!("{error:#}").contains("heads do not match"),
        "{error:#}"
    );
    // A damaged chunk is caught before Git ever reads the bundle.
    let chunk = &manifest.files[0].chunks[0].sha256;
    let path = cfg
        .storage
        .root
        .join(format!("git/v1/chunks/sha256/{}/{chunk}", &chunk[..2]));
    let mut bytes = fs::read(&path)?;
    bytes[100] ^= 0xff;
    fs::write(&path, bytes)?;
    assert!(gitlayer::verify(&cfg, &store, &id).is_err());
    Ok(())
}

#[test]
fn apply_run_publishes_git_layer() -> Result<()> {
    let t = tempfile::tempdir()?;
    let repo = t.path().join("src/project");
    fs::create_dir_all(&repo)?;
    git(&repo, &["init", "-qb", "main"]);
    commit(&repo, "a", "a");
    let mut cfg = config(t.path());
    cfg.git.fetch = false;
    cfg.git.push = false;
    cfg.git.backup_required = false;
    cfg.git_layer.enabled = true;
    let summary = run(&cfg, RunOptions { apply: true })?;
    let git_layer = summary
        .datasets
        .iter()
        .find(|d| d["name"] == "git")
        .unwrap();
    assert_eq!(git_layer["status"], "published-local", "{git_layer}");
    assert_eq!(git_layer["repositories"][0]["status"], "published");
    Ok(())
}

#[test]
fn incremental_chains_are_small_complete_and_survive_prune() -> Result<()> {
    use rebsync_core::{chrono::Duration as Span, layer::Retention};
    let t = tempfile::tempdir()?;
    let repo = t.path().join("src/project");
    fs::create_dir_all(&repo)?;
    git(&repo, &["init", "-qb", "main"]);
    // A repository with some real history (incompressible content).
    for i in 0..40u32 {
        use sha2::{Digest, Sha256};
        let body: String = (0..200u32)
            .map(|j| format!("{:x}\n", Sha256::digest(format!("{i}-{j}").as_bytes())))
            .collect();
        commit(&repo, &format!("f{i}"), &body);
    }
    let mut cfg = config(t.path());
    cfg.git_layer.full_every = 3;
    let store = FsObjectStorage::open(&cfg.storage.root)?;
    let mut journal = Journal::open(t.path())?;
    let publish = |journal: &mut Journal| -> Result<gitlayer::RepoOutcome> {
        Ok(gitlayer::publish_all(&cfg, &store, journal)?.remove(0))
    };

    let full = publish(&mut journal)?;
    assert_eq!(full.kind.as_deref(), Some("full"));
    commit(&repo, "small", "one line\n");
    let inc1 = publish(&mut journal)?;
    assert_eq!(inc1.kind.as_deref(), Some("incremental"));
    let (full_bytes, inc_bytes) = (
        full.snapshot.as_ref().unwrap().bytes,
        inc1.snapshot.as_ref().unwrap().bytes,
    );
    assert!(
        inc_bytes * 20 < full_bytes,
        "incremental {inc_bytes} vs full {full_bytes}"
    );
    git(&repo, &["tag", "v2"]);
    let inc2 = publish(&mut journal)?;
    // Only a lightweight tag moved: a refs-only link, a few hundred bytes.
    assert_eq!(inc2.kind.as_deref(), Some("refs"));
    assert!(inc2.snapshot.as_ref().unwrap().bytes < 4096);
    // Chain length reached full_every: a new full bundle starts a new chain.
    commit(&repo, "later", "x\n");
    let full2 = publish(&mut journal)?;
    assert_eq!(full2.kind.as_deref(), Some("full"));

    let inc2_id = inc2.snapshot.as_ref().unwrap().id.clone();
    let verified = gitlayer::verify(&cfg, &store, &inc2_id)?;
    assert_eq!(verified["chain"].as_array().unwrap().len(), 3);
    let restored = t.path().join("restored");
    gitlayer::restore(&cfg, &store, &inc2_id, &restored, &mut journal)?;
    assert_eq!(git(&restored, &["log", "-1", "--format=%s"]), "small");
    assert_eq!(
        git(&restored, &["rev-parse", "v2"]),
        git(&repo, &["rev-parse", "v2"])
    );

    // Prune keeping only the newest two would orphan inc2's chain: the chain stays.
    let keep_two = Retention {
        keep_last: 2,
        keep_days: None,
        label: None,
        grace: Span::zero(),
    };
    let report = layer::prune(&store, "git", &keep_two, true)?;
    assert!(report.snapshots_removed.is_empty(), "{report:?}");
    gitlayer::verify(&cfg, &store, &inc2_id)?;
    // Keeping only the newest full bundle may drop the old chain entirely.
    let keep_one = Retention {
        keep_last: 1,
        keep_days: None,
        label: None,
        grace: Span::zero(),
    };
    let report = layer::prune(&store, "git", &keep_one, true)?;
    assert_eq!(report.snapshots_removed.len(), 3);
    gitlayer::verify(&cfg, &store, &full2.snapshot.as_ref().unwrap().id)?;

    // A broken chain names the missing link.
    commit(&repo, "after-prune", "y\n");
    let tip = publish(&mut journal)?.snapshot.unwrap().id;
    store.delete(&layer::manifest_key(
        "git",
        &full2.snapshot.as_ref().unwrap().id,
    )?)?;
    let error = gitlayer::verify(&cfg, &store, &tip).unwrap_err();
    assert!(
        format!("{error:#}").contains("pull it from a peer"),
        "{error:#}"
    );
    Ok(())
}
