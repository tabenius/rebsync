use anyhow::{Context, Result};
use rebsync_core::{Config, RunOptions, discover, run};
use std::{fs, path::Path, process::Command};

fn git(path: &Path, args: &[&str]) -> Result<String> {
    let out = Command::new("git")
        .current_dir(path)
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .env("GIT_AUTHOR_NAME", "Rebsync Test")
        .env("GIT_AUTHOR_EMAIL", "test@example.invalid")
        .env("GIT_COMMITTER_NAME", "Rebsync Test")
        .env("GIT_COMMITTER_EMAIL", "test@example.invalid")
        .args([
            "-c",
            "core.hooksPath=/dev/null",
            "-c",
            "commit.gpgsign=false",
        ])
        .args(args)
        .output()?;
    anyhow::ensure!(
        out.status.success(),
        "test git {:?}: {}",
        args,
        String::from_utf8_lossy(&out.stderr)
    );
    Ok(String::from_utf8(out.stdout)?.trim().into())
}
fn fixture(root: &Path) -> Result<std::path::PathBuf> {
    let repo = root.join("repo");
    fs::create_dir_all(&repo)?;
    git(&repo, &["init", "-b", "main"])?;
    fs::write(repo.join("tracked.txt"), "committed\n")?;
    fs::write(repo.join("deleted.txt"), "delete me\n")?;
    fs::write(repo.join(".gitignore"), "ignored-secret\n")?;
    git(&repo, &["add", "."])?;
    git(&repo, &["commit", "-m", "initial"])?;
    Ok(repo)
}

#[test]
fn discovers_nested_repositories_and_worktrees() -> Result<()> {
    let t = tempfile::tempdir()?;
    let repo = fixture(t.path())?;
    let nested = repo.join("nested");
    fs::create_dir(&nested)?;
    git(&nested, &["init", "-b", "main"])?;
    let linked = t.path().join("linked");
    git(
        &repo,
        &["worktree", "add", "-b", "linked", linked.to_str().unwrap()],
    )?;
    #[cfg(unix)]
    std::os::unix::fs::symlink(&repo, t.path().join("loop"))?;
    let found = discover(&Config::defaults(t.path().into()))?;
    assert!(found.errors.is_empty(), "{:?}", found.errors);
    assert_eq!(found.repositories.len(), 3);
    let linked_repo = found
        .repositories
        .iter()
        .find(|r| r.path == linked)
        .unwrap();
    let main_repo = found.repositories.iter().find(|r| r.path == repo).unwrap();
    assert_eq!(linked_repo.common_dir, main_repo.common_dir);
    Ok(())
}

#[test]
fn dry_run_is_non_mutating_and_missing_backup_blocks_apply() -> Result<()> {
    let t = tempfile::tempdir()?;
    let repo = fixture(t.path())?;
    git(
        &repo,
        &[
            "remote",
            "add",
            "origin",
            "https://github.com/tabenius/not-contacted-test.git",
        ],
    )?;
    fs::write(repo.join("tracked.txt"), "precious dirty work\n")?;
    let before = git(&repo, &["show-ref"])?;
    let mut config = Config::defaults(t.path().into());
    config.scan.roots = vec![repo.clone()];
    let dry = run(&config, RunOptions::default())?;
    assert_eq!(before, git(&repo, &["show-ref"])?);
    assert!(!t.path().join(".rebekah").exists());
    assert!(dry.dry_run);
    let applied = run(&config, RunOptions { apply: true })?;
    assert_eq!(before, git(&repo, &["show-ref"])?);
    assert_eq!(
        fs::read_to_string(repo.join("tracked.txt"))?,
        "precious dirty work\n"
    );
    assert!(
        applied.repositories[0]
            .issues
            .iter()
            .any(|s| s.contains("Git exchange blocked"))
    );
    let lines = fs::read_to_string(&applied.journal)?;
    assert!(!lines.contains("git-fetch"));
    for line in lines.lines() {
        let _: serde_json::Value = serde_json::from_str(line)?;
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(
            fs::metadata(&applied.journal)?.permissions().mode() & 0o777,
            0o600
        );
    }
    Ok(())
}

#[test]
fn remote_urls_with_secrets_are_not_reported() -> Result<()> {
    let t = tempfile::tempdir()?;
    let repo = fixture(t.path())?;
    git(
        &repo,
        &[
            "remote",
            "add",
            "secret",
            "https://top-secret-token@github.com/tabenius/project.git",
        ],
    )?;
    let mut config = Config::defaults(t.path().into());
    config.scan.roots = vec![repo];
    let inv = discover(&config)?;
    assert!(!serde_json::to_string(&inv)?.contains("top-secret-token"));
    assert!(!inv.repositories[0].remotes[0].permitted);
    Ok(())
}

#[test]
fn git_url_rewrites_cannot_bypass_destination_allowlist() -> Result<()> {
    let t = tempfile::tempdir()?;
    let repo = fixture(t.path())?;
    git(&repo, &["branch", "feature"])?;
    let server = t.path().join("server.git");
    git(
        t.path(),
        &[
            "clone",
            "--bare",
            repo.to_str().unwrap(),
            server.to_str().unwrap(),
        ],
    )?;
    let producer = t.path().join("producer");
    git(
        t.path(),
        &[
            "clone",
            server.to_str().unwrap(),
            producer.to_str().unwrap(),
        ],
    )?;
    git(&producer, &["checkout", "feature"])?;
    fs::write(producer.join("remote.txt"), "remote change\n")?;
    git(&producer, &["add", "."])?;
    git(&producer, &["commit", "-m", "remote change"])?;
    let remote_oid = git(&producer, &["rev-parse", "HEAD"])?;
    git(&producer, &["push", "origin", "feature"])?;
    git(&server, &["update-ref", "refs/heads/main", &remote_oid])?;
    git(
        &server,
        &["update-ref", "refs/heads/divergent", &remote_oid],
    )?;
    git(&repo, &["checkout", "-b", "divergent"])?;
    fs::write(repo.join("local.txt"), "different local change\n")?;
    git(&repo, &["add", "."])?;
    git(&repo, &["commit", "-m", "local divergence"])?;
    let local_divergent = git(&repo, &["rev-parse", "HEAD"])?;
    git(&repo, &["checkout", "main"])?;
    git(&repo, &["branch", "my-local-branch"])?;
    let main_before = git(&repo, &["rev-parse", "HEAD"])?;
    fs::write(repo.join("tracked.txt"), "operator dirty work\n")?;
    git(
        &repo,
        &[
            "remote",
            "add",
            "origin",
            "https://github.com/tabenius/rebsync-test.git",
        ],
    )?;
    // Effective get-url identities must reject this apparent GitHub destination:
    // Git rewrites it to an unapproved local server. No network is contacted.
    let rewrite = format!("url.file://{}.insteadOf", server.display());
    git(
        &repo,
        &[
            "config",
            &rewrite,
            "https://github.com/tabenius/rebsync-test.git",
        ],
    )?;
    for name in ["main", "feature", "divergent"] {
        git(
            &repo,
            &["config", &format!("branch.{name}.remote"), "origin"],
        )?;
        git(
            &repo,
            &[
                "config",
                &format!("branch.{name}.merge"),
                &format!("refs/heads/{name}"),
            ],
        )?;
    }
    let mut config = Config::defaults(t.path().into());
    config.scan.roots = vec![repo.clone()];
    // This test explicitly bypasses backup only for its disposable local fixture.
    config.git.backup_required = false;
    let summary = run(&config, RunOptions { apply: true })?;
    let outcome = &summary.repositories[0];
    assert_eq!(git(&repo, &["rev-parse", "feature"])?, main_before);
    assert_eq!(git(&repo, &["rev-parse", "main"])?, main_before);
    assert_eq!(git(&repo, &["rev-parse", "divergent"])?, local_divergent);
    assert_eq!(git(&server, &["rev-parse", "main"])?, remote_oid);
    assert_eq!(git(&server, &["rev-parse", "divergent"])?, remote_oid);
    assert!(
        !Command::new("git")
            .current_dir(&server)
            .args(["show-ref", "--verify", "refs/heads/my-local-branch"])
            .output()?
            .status
            .success()
    );
    assert_eq!(
        fs::read_to_string(repo.join("tracked.txt"))?,
        "operator dirty work\n"
    );
    assert!(
        outcome
            .issues
            .iter()
            .any(|s| s.contains("no permitted GitHub exchange destination"))
    );
    Ok(())
}

#[test]
fn encrypted_backup_can_restore_dirty_work_and_history() -> Result<()> {
    if Command::new("restic").arg("version").output().is_err() {
        eprintln!("restic absent; encrypted restore integration test skipped");
        return Ok(());
    }
    let t = tempfile::tempdir()?;
    let home = t.path().join("home");
    fs::create_dir(&home)?;
    // Put the journal/state inside the repo to exercise self-generated-file exclusions.
    let repo = fixture(&home)?;
    fs::write(repo.join("tracked.txt"), "staged\n")?;
    git(&repo, &["add", "tracked.txt"])?;
    fs::write(repo.join("tracked.txt"), "unstaged\n")?;
    fs::remove_file(repo.join("deleted.txt"))?;
    fs::write(repo.join("--hostile\nname.bin"), [0, 1, 255, 0])?;
    fs::write(repo.join("ignored-secret"), "not opted in\n")?;
    #[cfg(unix)]
    std::os::unix::fs::symlink("tracked.txt", repo.join("link"))?;
    let password = t.path().join("password");
    fs::write(&password, "TEST-ONLY-NOT-A-REAL-KEY\n")?;
    let backup = t.path().join("encrypted-backup");
    let mut config = Config::defaults(repo.clone());
    config.backup.repository = Some(backup.to_str().unwrap().into());
    config.backup.password_file = Some(password.clone());
    config.git.fetch = false;
    config.git.push = false;
    rebsync_core::sync::initialize_backup(&config)?;
    let summary = run(&config, RunOptions { apply: true })?;
    let outcome = &summary.repositories[0];
    let snapshot = outcome
        .backup_snapshot
        .as_ref()
        .with_context(|| format!("backup failed: {:?}", outcome.issues))?;
    let restored = t.path().join("restored");
    let output = Command::new("restic")
        .arg("--repo")
        .arg(&backup)
        .arg("--password-file")
        .arg(&password)
        .args(["restore", snapshot, "--target"])
        .arg(&restored)
        .output()?;
    anyhow::ensure!(
        output.status.success(),
        "restore failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let files: Vec<_> = walkdir::WalkDir::new(&restored)
        .into_iter()
        .filter_map(Result::ok)
        .collect();
    let bundle = files
        .iter()
        .find(|e| e.file_name() == "repository.bundle")
        .context("no bundle restored")?
        .path();
    let archive = files
        .iter()
        .find(|e| e.file_name() == "worktree.tar")
        .context("no worktree archive restored")?
        .path();
    let recovered = t.path().join("recovered");
    let output = Command::new("git")
        .args(["clone", "--quiet"])
        .arg(bundle)
        .arg(&recovered)
        .output()?;
    anyhow::ensure!(output.status.success(), "bundle clone failed");
    assert_eq!(
        git(&repo, &["rev-parse", "HEAD"])?,
        git(&recovered, &["rev-parse", "HEAD"])?
    );
    let extracted = t.path().join("extracted");
    fs::create_dir(&extracted)?;
    let status = Command::new("tar")
        .arg("--extract")
        .arg("--file")
        .arg(archive)
        .arg("--directory")
        .arg(&extracted)
        .status()?;
    assert!(status.success());
    assert_eq!(
        fs::read(extracted.join("--hostile\nname.bin"))?,
        [0, 1, 255, 0]
    );
    assert_eq!(
        fs::read_to_string(extracted.join("tracked.txt"))?,
        "unstaged\n"
    );
    assert!(!extracted.join("deleted.txt").exists());
    assert!(!extracted.join("ignored-secret").exists());
    assert!(!extracted.join(".rebekah").exists());
    assert!(files.iter().any(|e| e.file_name() == "staged.patch"));
    assert!(files.iter().any(|e| e.file_name() == "unstaged.patch"));
    let staging = repo.join(".rebekah/rebsync/staging");
    assert_eq!(fs::read_dir(staging)?.count(), 0);
    Ok(())
}
