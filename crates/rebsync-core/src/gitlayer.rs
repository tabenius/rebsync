//! The git layer: committed history as verified bundles, for offline exchange.
//!
//! Built for long stretches without GitHub (outage, blocking, months offline):
//! a machine publishes bundles into the object store, `rebsync peer push`
//! carries them to the Rebekah phone, another machine pulls and fetches them.
//!
//! Each discovered repository has one label (`<name>-<identity hash>`) and a
//! chain of snapshots. The first is a full bundle
//! (`git bundle create --branches --tags [HEAD]`). Later ones are incremental:
//! the same refs, but excluding everything the previous snapshot already
//! carried (`--not <previous heads>`), so a new commit costs kilobytes, not a
//! whole repository (a full rebuild re-packs and changes every chunk). Each
//! manifest records its `base` and `prerequisites`. A new full bundle starts a
//! fresh chain every `full_every` snapshots, or whenever an incremental cannot
//! be built (for example after history was rewritten and old heads are gone).
//! Refs that did not change publish nothing.
//!
//! Reading a snapshot reassembles its chain base-first into a throwaway bare
//! repository, running `git bundle verify` on every link before fetching it,
//! so prerequisites are proven, not assumed. `restore` clones that result into
//! a new directory; `fetch` brings branches into `refs/remotes/rebsync-<name>/`
//! and tags into `refs/rebsync/<name>/tags/` of an existing repository and
//! never touches its branches, tags or worktree. Git hooks are disabled for
//! every Git command Rebsync runs. Committed history only: uncommitted work and
//! stashes stay with the encrypted repository snapshots.

use crate::{
    config::Config,
    inventory::{self, Repository},
    journal::Journal,
    layer, process,
    storage::ObjectStorage,
    sync,
};
use anyhow::{Context, Result, ensure};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::path::{Path, PathBuf};

pub const LAYER: &str = "git";
pub const OWNER_SCHEMA: &str = "rebsync.git.bundle.v1";
const BUNDLE: &str = "repository.bundle";
/// A link that only moves refs (tags, deleted branches): no new objects.
const REFS_ONLY: &str = "refs.json";
const MAX_CHAIN: usize = 1000;

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GitLayerConfig {
    /// Publish bundles of discovered repositories during `--apply` runs.
    pub enabled: bool,
    pub chunk_bytes: u64,
    /// Skip a repository whose branch/tag refs match its latest snapshot.
    pub skip_unchanged: bool,
    /// Also publish repositories without a permitted GitHub remote.
    pub include_local_only: bool,
    /// Start a new full bundle after this many snapshots in a chain (1 = always full).
    pub full_every: usize,
}

impl Default for GitLayerConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            chunk_bytes: 64 * 1024,
            skip_unchanged: true,
            include_local_only: true,
            full_every: 20,
        }
    }
}

/// Stable, key-safe label: `<sanitized name>-<10 hex of identity>`.
pub fn label_for(repo: &Repository) -> String {
    let identity = repo
        .remotes
        .iter()
        .find_map(|r| r.github.clone())
        .unwrap_or_else(|| repo.common_dir.display().to_string());
    let name: String = repo
        .path
        .file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_default()
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || matches!(c, '-' | '_') {
                c
            } else {
                '_'
            }
        })
        .take(40)
        .collect();
    let name = if name.is_empty() { "repo".into() } else { name };
    let digest = format!("{:x}", Sha256::digest(identity.as_bytes()));
    format!("{name}-{}", &digest[..10])
}

type Refs = Vec<(String, String)>;

/// Branch and tag refs with their object IDs, sorted.
fn refs(repo: &Path, timeout: u64) -> Result<Refs> {
    let out = process::text(
        process::git(repo).args([
            "for-each-ref",
            "--format=%(objectname) %(refname)",
            "refs/heads",
            "refs/tags",
        ]),
        timeout,
    )?;
    let mut refs: Refs = out
        .lines()
        .filter_map(|l| l.split_once(' '))
        .map(|(oid, name)| (name.to_owned(), oid.to_owned()))
        .collect();
    refs.sort();
    Ok(refs)
}

fn refs_digest(refs: &Refs) -> String {
    let joined: String = refs.iter().map(|(n, o)| format!("{n} {o}\n")).collect();
    format!("{:x}", Sha256::digest(joined.as_bytes()))
}

fn list_heads(cwd: &Path, bundle: &Path, timeout: u64) -> Result<Refs> {
    let out = process::text(
        process::git(cwd).args(["bundle", "list-heads"]).arg(bundle),
        timeout,
    )?;
    let mut heads: Refs = out
        .lines()
        .filter_map(|l| l.split_once(' '))
        .map(|(oid, name)| (name.to_owned(), oid.to_owned()))
        .collect();
    heads.sort();
    Ok(heads)
}

fn recorded_heads(manifest: &layer::SnapshotManifest) -> Refs {
    let mut heads: Refs = manifest
        .owner
        .get("heads")
        .and_then(Value::as_array)
        .map(|a| {
            a.iter()
                .filter_map(|h| {
                    Some((
                        h.get("ref")?.as_str()?.to_owned(),
                        h.get("oid")?.as_str()?.to_owned(),
                    ))
                })
                .collect()
        })
        .unwrap_or_default();
    heads.sort();
    heads
}

/// The complete ref state recorded at publication.
fn recorded_refs(manifest: &layer::SnapshotManifest) -> Refs {
    let mut refs: Refs = manifest
        .owner
        .get("refs")
        .and_then(Value::as_array)
        .map(|a| {
            a.iter()
                .filter_map(|h| {
                    Some((
                        h.get("ref")?.as_str()?.to_owned(),
                        h.get("oid")?.as_str()?.to_owned(),
                    ))
                })
                .collect()
        })
        .unwrap_or_default();
    refs.sort();
    refs
}

fn chain_length(manifest: &layer::SnapshotManifest) -> usize {
    manifest
        .owner
        .get("chain_length")
        .and_then(Value::as_u64)
        .unwrap_or(1) as usize
}

#[derive(Debug, Serialize)]
pub struct RepoOutcome {
    pub path: PathBuf,
    pub label: String,
    /// published | unchanged | skipped | failed
    pub status: String,
    /// full | incremental, when published
    pub kind: Option<String>,
    pub snapshot: Option<layer::PublishOutcome>,
    pub detail: Option<String>,
}

fn eligible(config: &Config, repo: &Repository) -> Option<&'static str> {
    if repo.head.is_none() && repo.branches.is_empty() {
        return Some("no commits");
    }
    if !config.git_layer.include_local_only && !repo.remotes.iter().any(|r| r.permitted) {
        return Some("no permitted remote and include_local_only = false");
    }
    None
}

fn create_bundle(
    config: &Config,
    repo: &Repository,
    bundle: &Path,
    exclude: &[String],
    journal: &mut Journal,
) -> Result<()> {
    let _ = std::fs::remove_file(bundle);
    let mut create = process::git(&repo.path);
    create
        .args(["bundle", "create", "--quiet"])
        .arg(bundle)
        .args(["--branches", "--tags"]);
    if repo.head.is_some() {
        create.arg("HEAD");
    }
    if !exclude.is_empty() {
        create.arg("--not").args(exclude);
    }
    let mode = if exclude.is_empty() {
        "full"
    } else {
        "--not <previous heads>"
    };
    sync::checked(
        journal,
        &repo.path,
        "git-layer-bundle",
        json!([
            "git",
            "bundle",
            "create",
            BUNDLE,
            "--branches",
            "--tags",
            "HEAD-if-present",
            mode
        ]),
        &mut create,
        config.command_timeout_seconds,
    )?;
    sync::checked(
        journal,
        &repo.path,
        "git-layer-bundle-verify",
        json!(["git", "bundle", "verify", BUNDLE]),
        process::git(&repo.path)
            .args(["bundle", "verify", "--quiet"])
            .arg(bundle),
        config.command_timeout_seconds,
    )?;
    Ok(())
}

/// Export and publish one repository's committed history.
pub fn publish_repo(
    config: &Config,
    storage: &dyn ObjectStorage,
    repo: &Repository,
    journal: &mut Journal,
) -> Result<RepoOutcome> {
    let label = label_for(repo);
    let mut outcome = RepoOutcome {
        path: repo.path.clone(),
        label: label.clone(),
        status: "skipped".into(),
        kind: None,
        snapshot: None,
        detail: None,
    };
    if let Some(reason) = eligible(config, repo) {
        outcome.detail = Some(reason.into());
        return Ok(outcome);
    }
    let timeout = config.command_timeout_seconds;
    let current = refs(&repo.path, timeout)?;
    let digest = refs_digest(&current);
    let latest = layer::list(storage, LAYER, Some(&label))?.pop();
    if config.git_layer.skip_unchanged
        && latest
            .as_ref()
            .and_then(|m| m.owner.get("refs_digest"))
            .and_then(Value::as_str)
            == Some(digest.as_str())
    {
        outcome.status = "unchanged".into();
        outcome.detail = latest.map(|m| m.id);
        return Ok(outcome);
    }
    let stage = layer::staging(config, LAYER)?;
    let bundle = stage.path().join(BUNDLE);
    // Incremental against the latest snapshot when the chain allows it and
    // every previous head still exists here (rewritten history falls back).
    let mut base: Option<&layer::SnapshotManifest> = None;
    let mut prerequisites: Vec<String> = Vec::new();
    if let Some(previous) = latest.as_ref()
        && config.git_layer.full_every > 1
        && chain_length(previous) < config.git_layer.full_every
    {
        let mut oids: Vec<String> = recorded_heads(previous)
            .into_iter()
            .map(|(_, o)| o)
            .collect();
        oids.sort();
        oids.dedup();
        let all_present = oids.iter().all(|oid| {
            process::checked(
                process::git(&repo.path).args(["cat-file", "-e", &format!("{oid}^{{commit}}")]),
                timeout,
            )
            .is_ok()
        });
        if all_present && !oids.is_empty() {
            base = Some(previous);
            prerequisites = oids;
        }
    }
    // No new commits since the previous link (a tag or branch moved onto
    // existing history, or a branch was deleted): record refs only.
    let refs_only = base.is_some() && {
        let mut count = process::git(&repo.path);
        count.args(["rev-list", "--count"]);
        count.args(current.iter().map(|(_, oid)| oid.as_str()));
        count.arg("--not").args(&prerequisites);
        process::text(&mut count, timeout).is_ok_and(|n| n.trim() == "0")
    };
    let file = if refs_only {
        std::fs::write(
            stage.path().join(REFS_ONLY),
            serde_json::to_vec_pretty(&current)?,
        )?;
        REFS_ONLY
    } else {
        if base.is_some() && create_bundle(config, repo, &bundle, &prerequisites, journal).is_err()
        {
            // Git could not build the incremental: start a fresh full chain.
            base = None;
            prerequisites.clear();
        }
        if base.is_none() {
            create_bundle(config, repo, &bundle, &[], journal)?;
        }
        BUNDLE
    };
    let kind = match (refs_only, base.is_some()) {
        (true, _) => "refs",
        (false, true) => "incremental",
        (false, false) => "full",
    };
    let heads = if refs_only {
        Vec::new()
    } else {
        list_heads(&repo.path, &bundle, timeout)?
    };
    let owner = json!({
        "schema": OWNER_SCHEMA,
        "kind": kind,
        "base": base.map(|b| b.id.clone()),
        "prerequisites": prerequisites,
        "chain_length": base.map(|b| chain_length(b) + 1).unwrap_or(1),
        "name": repo.path.file_name().map(|n| n.to_string_lossy().into_owned()),
        "path": repo.path,
        "github": repo.remotes.iter().find_map(|r| r.github.clone()),
        "head": repo.head,
        "branch": repo.branch,
        "heads": heads.iter().map(|(r, o)| json!({"ref": r, "oid": o})).collect::<Vec<_>>(),
        // The complete branch/tag state. Incremental bundles omit refs whose
        // commits an earlier link already carried, so this is authoritative.
        "refs": current.iter().map(|(r, o)| json!({"ref": r, "oid": o})).collect::<Vec<_>>(),
        "refs_digest": digest,
        "contents": "Committed history (branches, tags, HEAD). Not uncommitted work, stashes or remote-tracking refs.",
    });
    let run_id = journal.run_id.clone();
    let snapshot = layer::publish_files(
        storage,
        LAYER,
        &label,
        config.git_layer.chunk_bytes,
        stage.path(),
        &[file.to_owned()],
        owner,
        Some(&run_id),
    )?;
    journal.event(
        "git-layer-published",
        &repo.path,
        json!({"id": snapshot.id, "kind": kind, "bytes": snapshot.bytes, "heads": heads.len()}),
    )?;
    outcome.status = "published".into();
    outcome.kind = Some(kind.into());
    outcome.snapshot = Some(snapshot);
    Ok(outcome)
}

/// Publish every discovered repository; one failure does not stop the rest.
pub fn publish_all(
    config: &Config,
    storage: &dyn ObjectStorage,
    journal: &mut Journal,
) -> Result<Vec<RepoOutcome>> {
    let _lock = layer::lock(config, LAYER)?;
    let found = inventory::discover(config)?;
    let mut outcomes = Vec::new();
    for repo in &found.repositories {
        match publish_repo(config, storage, repo, journal) {
            Ok(outcome) => outcomes.push(outcome),
            Err(error) => outcomes.push(RepoOutcome {
                path: repo.path.clone(),
                label: label_for(repo),
                status: "failed".into(),
                kind: None,
                snapshot: None,
                detail: Some(format!("{error:#}")),
            }),
        }
    }
    Ok(outcomes)
}

/// The snapshot's chain, base first, ending with `id`.
fn chain(storage: &dyn ObjectStorage, id: &str) -> Result<Vec<layer::SnapshotManifest>> {
    let mut links: Vec<layer::SnapshotManifest> = Vec::new();
    let mut next = Some(id.to_owned());
    while let Some(current) = next.take() {
        ensure!(
            links.len() < MAX_CHAIN,
            "bundle chain longer than {MAX_CHAIN}"
        );
        let manifest = layer::load(storage, LAYER, &current).with_context(|| {
            format!("chain is incomplete: {current} is missing here; pull it from a peer")
        })?;
        let refs_only = manifest.owner.get("kind").and_then(Value::as_str) == Some("refs");
        let expected = if refs_only { REFS_ONLY } else { BUNDLE };
        ensure!(
            manifest.files.len() == 1 && manifest.files[0].path == expected,
            "git snapshot must contain exactly {expected}"
        );
        ensure!(
            !refs_only || manifest.owner.get("base").is_some_and(Value::is_string),
            "a refs-only snapshot needs a base"
        );
        next = manifest
            .owner
            .get("base")
            .and_then(Value::as_str)
            .map(str::to_owned);
        if let Some(base) = &next {
            ensure!(
                base != &current && links.iter().all(|l| &l.id != base),
                "bundle chain has a cycle"
            );
        }
        links.push(manifest);
    }
    links.reverse();
    Ok(links)
}

/// Rebuild a snapshot's chain into a throwaway bare repository: every link is
/// reassembled, `git bundle verify`-ed against what is already there, its heads
/// compared with its manifest, and fetched. The final link's refs become the
/// repository's real refs, so it can be cloned.
fn materialize(
    config: &Config,
    storage: &dyn ObjectStorage,
    id: &str,
) -> Result<(tempfile::TempDir, PathBuf, Vec<layer::SnapshotManifest>)> {
    let links = chain(storage, id)?;
    let stage = layer::staging(config, LAYER)?;
    let timeout = config.command_timeout_seconds;
    let scratch = stage.path().join("chain.git");
    process::checked(
        process::git(stage.path())
            .args(["init", "--quiet", "--bare"])
            .arg(&scratch),
        timeout,
    )?;
    for (index, manifest) in links.iter().enumerate() {
        let out = stage.path().join(format!("link-{index}"));
        layer::assemble(storage, manifest, &out)?;
        if manifest.owner.get("kind").and_then(Value::as_str) == Some("refs") {
            // Nothing to fetch; the recorded ref state must match the file.
            let file: Refs = serde_json::from_slice(&std::fs::read(out.join(REFS_ONLY))?)
                .context("refs-only snapshot is not a ref list")?;
            ensure!(
                file == recorded_refs(manifest),
                "{}: refs.json does not match the manifest",
                manifest.id
            );
            continue;
        }
        let bundle = out.join(BUNDLE);
        process::checked(
            process::git(&scratch)
                .args(["bundle", "verify", "--quiet"])
                .arg(&bundle),
            timeout,
        )
        .with_context(|| format!("git bundle verify failed for {}", manifest.id))?;
        ensure!(
            list_heads(&scratch, &bundle, timeout)? == recorded_heads(manifest),
            "{}: bundle heads do not match the snapshot manifest",
            manifest.id
        );
        let (heads, tags) = (
            format!("+refs/heads/*:refs/chain/{index}/heads/*"),
            format!("+refs/tags/*:refs/chain/{index}/tags/*"),
        );
        process::checked(
            process::git(&scratch)
                .args(["fetch", "--quiet", "--no-tags", "--no-write-fetch-head"])
                .arg(&bundle)
                .args([&heads, &tags]),
            timeout,
        )
        .with_context(|| format!("fetch {} into the chain", manifest.id))?;
    }
    // Recreate exactly the recorded branch/tag state. Each ref is only set if
    // its commit arrived through the verified chain.
    let last = links.last().expect("non-empty chain");
    let state = recorded_refs(last);
    ensure!(!state.is_empty(), "{}: snapshot records no refs", last.id);
    for (name, oid) in &state {
        ensure!(
            (name.starts_with("refs/heads/") || name.starts_with("refs/tags/"))
                && !name.contains("..")
                && oid.len() >= 40
                && oid.bytes().all(|b| b.is_ascii_hexdigit()),
            "{}: invalid ref record {name}",
            last.id
        );
        process::checked(
            process::git(&scratch).args(["update-ref", name, oid]),
            timeout,
        )
        .with_context(|| format!("{name} points to {oid}, which the chain does not contain"))?;
    }
    // A fresh bare repository's HEAD names a default branch that may not
    // exist; point it where the source repository's HEAD was.
    let branch = last.owner.get("branch").and_then(Value::as_str);
    let head = last.owner.get("head").and_then(Value::as_str);
    let has = |name: &str| state.iter().any(|(r, _)| r == name);
    if let Some(branch) = branch.filter(|b| has(&format!("refs/heads/{b}"))) {
        process::checked(
            process::git(&scratch).args(["symbolic-ref", "HEAD", &format!("refs/heads/{branch}")]),
            timeout,
        )?;
    } else if let Some(oid) = head.filter(|h| h.len() >= 40) {
        process::checked(
            process::git(&scratch).args(["update-ref", "--no-deref", "HEAD", oid]),
            timeout,
        )?;
    }
    Ok((stage, scratch, links))
}

pub fn verify(config: &Config, storage: &dyn ObjectStorage, id: &str) -> Result<Value> {
    let (_stage, _scratch, links) = materialize(config, storage, id)?;
    let last = links.last().expect("non-empty chain");
    Ok(
        json!({"id": last.id, "chain": links.iter().map(|l| &l.id).collect::<Vec<_>>(),
        "bytes": links.iter().map(layer::SnapshotManifest::bytes).sum::<u64>(),
        "heads": last.owner.get("heads"), "git_bundle_verify": "ok"}),
    )
}

/// Clone a snapshot (and its chain) into a new directory.
pub fn restore(
    config: &Config,
    storage: &dyn ObjectStorage,
    id: &str,
    into: &Path,
    journal: &mut Journal,
) -> Result<Value> {
    ensure!(
        std::fs::symlink_metadata(into).is_err(),
        "{} already exists; restore only creates a new repository",
        into.display()
    );
    let (stage, scratch, links) = materialize(config, storage, id)?;
    let parent = into
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or(Path::new("."));
    std::fs::create_dir_all(parent)?;
    let timeout = config.command_timeout_seconds;
    sync::checked(
        journal,
        into,
        "git-layer-restore",
        json!(["git", "clone", "--no-local", "<verified chain>", into]),
        process::git(stage.path())
            .args(["clone", "--quiet", "--no-local"])
            .arg(&scratch)
            .arg(into),
        timeout,
    )?;
    // The scratch repository is about to vanish.
    process::checked(
        process::git(into).args(["remote", "remove", "origin"]),
        timeout,
    )?;
    let last = links.last().expect("non-empty chain");
    Ok(
        json!({"id": last.id, "restored_to": into, "chain_length": links.len(),
        "heads": last.owner.get("heads"),
        "next": "Add the real remote yourself; rebsync does not guess it."}),
    )
}

/// Fetch a snapshot's branches and tags into a rebsync-only namespace of an
/// existing repository. Never touches local branches, tags or the worktree.
pub fn fetch(
    config: &Config,
    storage: &dyn ObjectStorage,
    id: &str,
    repo: &Path,
    name: Option<&str>,
    journal: &mut Journal,
) -> Result<Value> {
    let timeout = config.command_timeout_seconds;
    process::checked(process::git(repo).args(["rev-parse", "--git-dir"]), timeout)
        .context("not a Git repository")?;
    let (_stage, scratch, links) = materialize(config, storage, id)?;
    let last = links.last().expect("non-empty chain");
    let name = name.unwrap_or(&last.label).to_owned();
    layer::validate_label(&name)?;
    let heads_spec = format!("+refs/heads/*:refs/remotes/rebsync-{name}/*");
    let tags_spec = format!("+refs/tags/*:refs/rebsync/{name}/tags/*");
    sync::checked(
        journal,
        repo,
        "git-layer-fetch",
        json!([
            "git",
            "fetch",
            "--no-tags",
            "<verified chain>",
            heads_spec,
            tags_spec
        ]),
        process::git(repo)
            .args(["fetch", "--quiet", "--no-tags", "--no-write-fetch-head"])
            .arg(&scratch)
            .args([&heads_spec, &tags_spec]),
        timeout,
    )?;
    Ok(
        json!({"id": last.id, "repository": repo, "chain_length": links.len(),
        "branches": format!("refs/remotes/rebsync-{name}/*"),
        "tags": format!("refs/rebsync/{name}/tags/*"),
        "note": "Local branches, tags and the worktree were not changed. Merge or check out deliberately."}),
    )
}

pub fn run_layer(config: &Config, journal: &mut Journal) -> Value {
    #[cfg(feature = "storage-object-store")]
    {
        let storage = match crate::storage::FsObjectStorage::open(&config.storage.root) {
            Ok(storage) => storage,
            Err(error) => {
                return json!({"name":"git","kind":"git","status":"failed","error":error.to_string()});
            }
        };
        match publish_all(config, &storage, journal) {
            Ok(outcomes) => {
                let failed = outcomes.iter().filter(|o| o.status == "failed").count();
                // Exchange copies on this disk, not off-machine protection.
                let status = if failed > 0 {
                    "failed"
                } else {
                    "published-local"
                };
                json!({"name":"git","kind":"git","status":status,"repositories":outcomes})
            }
            Err(error) => {
                json!({"name":"git","kind":"git","status":"failed","error":format!("{error:#}")})
            }
        }
    }
    #[cfg(not(feature = "storage-object-store"))]
    {
        let _ = (config, journal);
        json!({"name":"git","kind":"git","status":"blocked","reason":"built without object storage support"})
    }
}
