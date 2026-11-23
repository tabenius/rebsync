#![cfg(feature = "storage-object-store")]

use rebsync_core::{Config, FsObjectStorage, status};

#[test]
fn status_read_does_not_create_private_state() -> anyhow::Result<()> {
    let home = tempfile::tempdir()?;
    let mut config = Config::defaults(home.path().to_path_buf());
    config.storage.root = home.path().join("objects");
    let storage = FsObjectStorage::open(&config.storage.root)?;

    let value = status::collect(&config, &storage, 2)?;

    assert_eq!(value["schema"], "rbq.status.v1");
    assert_eq!(value["overall"]["state"], "disabled");
    assert!(!home.path().join(".rebeqah").exists());
    assert!(
        value["layers"]
            .as_array()
            .is_some_and(|layers| !layers.is_empty())
    );
    Ok(())
}

#[test]
fn a_clone_in_step_with_its_upstream_reports_ahead_and_behind() -> anyhow::Result<()> {
    use std::process::Command;
    let home = tempfile::tempdir()?;
    let git = |dir: &std::path::Path, args: &[&str]| {
        let status = Command::new("git")
            .current_dir(dir)
            .args(["-c", "user.name=t", "-c", "user.email=t@example.invalid"])
            .args(args)
            .env("GIT_CONFIG_NOSYSTEM", "1")
            .env("HOME", home.path())
            .status()
            .unwrap();
        assert!(status.success(), "git {args:?}");
    };
    let origin = home.path().join("origin.git");
    let work = home.path().join("src/work");
    std::fs::create_dir_all(&work)?;
    git(
        home.path(),
        &[
            "init",
            "-q",
            "--bare",
            "-b",
            "main",
            origin.to_str().unwrap(),
        ],
    );
    git(&work, &["init", "-q", "-b", "main"]);
    git(&work, &["commit", "-q", "--allow-empty", "-m", "one"]);
    git(
        &work,
        &["remote", "add", "origin", origin.to_str().unwrap()],
    );
    git(&work, &["push", "-q", "-u", "origin", "main"]);

    let mut config = Config::defaults(home.path().to_path_buf());
    config.scan.roots = vec![home.path().join("src")];
    config.storage.root = home.path().join("objects");
    let storage = FsObjectStorage::open(&config.storage.root)?;
    let value = status::collect(&config, &storage, 0)?;
    let repo = &value["repositories"][0];
    // Before: the range was built as `HEAD...@origin/main`, which git rejects,
    // so every repository read "unknown".
    assert_eq!(repo["state"], "synced", "{repo}");
    assert_eq!(
        (repo["ahead"].as_u64(), repo["behind"].as_u64()),
        (Some(0), Some(0))
    );
    Ok(())
}
