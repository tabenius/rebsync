//! Read-only status across object layers, private mirrors and Git remotes.
//!
//! Observers take the same per-layer lock that publishers hold exclusively,
//! so `rbq status` never reports a half-written snapshot. No journal or state
//! directory is created by a status read; if no lock file exists, the layer
//! has never been written by this home.

use crate::{Config, inventory, layer, process, storage::ObjectStorage};
use anyhow::Result;
use chrono::Utc;
use serde_json::{Value, json};
use std::{fs, io::BufRead, path::PathBuf};

pub fn enabled(config: &Config, name: &str) -> bool {
    match name {
        "binaries" => config.binaries.enabled,
        "mneme" => config.mneme.enabled,
        "frog" => config.frog.enabled,
        "agenda" => config.agenda.enabled,
        "git" => config.git_layer.enabled,
        _ => false,
    }
}

fn mirror_configured(config: &Config, name: &str) -> bool {
    match name {
        "binaries" => {
            config.binaries.restic
                && (config.binaries.repository.is_some() || config.backup.repository.is_some())
        }
        "mneme" => config.mneme.restic && config.backup.repository.is_some(),
        "frog" => config.frog.restic && config.backup.repository.is_some(),
        "agenda" => config.agenda.restic && config.backup.repository.is_some(),
        // The Git layer is for offline exchange; restic preservation belongs
        // to the enclosing repository backup, not to a bundle snapshot.
        _ => false,
    }
}

/// Most recent journal evidence that this layer was mirrored. Malformed or
/// partial lines are skipped; an append in progress cannot forge a result.
fn mirror_evidence(config: &Config, name: &str) -> Option<Value> {
    let entries = fs::read_dir(&config.rbq_home).ok()?;
    let mut paths: Vec<PathBuf> = entries
        .filter_map(Result::ok)
        .map(|entry| entry.path())
        .filter(|path| {
            path.file_name()
                .and_then(|name| name.to_str())
                .is_some_and(|name| name.starts_with("rbq_") && name.ends_with(".jsonl"))
        })
        .collect();
    paths.sort_by_key(|path| fs::metadata(path).and_then(|meta| meta.modified()).ok());
    paths.reverse();

    let tag = format!("rbq-{name}:");
    for path in paths.into_iter().take(32) {
        let file = match fs::File::open(&path) {
            Ok(file) => file,
            Err(_) => continue,
        };
        let lines: Vec<String> = std::io::BufReader::new(file)
            .lines()
            .map_while(Result::ok)
            .collect();
        for line in lines.into_iter().rev() {
            let Ok(event): Result<Value, _> = serde_json::from_str(&line) else {
                continue;
            };
            let kind = event["kind"].as_str().unwrap_or("");
            let matched = if name == "binaries" && kind == "binaries-mirrored" {
                true
            } else if kind == "restic-backup" {
                event["detail"].as_array().is_some_and(|parts| {
                    parts
                        .iter()
                        .any(|part| part.as_str().is_some_and(|value| value.starts_with(&tag)))
                })
            } else {
                false
            };
            if matched {
                return Some(json!({
                    "at": event["at"],
                    "run_id": event["run_id"],
                    "journal": path,
                }));
            }
        }
    }
    None
}

fn progress(logical_bytes: u64, missing_bytes: u64) -> f64 {
    if logical_bytes == 0 {
        return 100.0;
    }
    let done = logical_bytes.saturating_sub(missing_bytes.min(logical_bytes));
    (done as f64 / logical_bytes as f64) * 100.0
}

fn layer_status(
    enabled: bool,
    stats: Option<&layer::LayerStats>,
    mirror: &str,
) -> (&'static str, Option<String>) {
    if !enabled {
        return (
            "disabled",
            Some("layer is disabled in configuration".into()),
        );
    }
    let Some(stats) = stats else {
        return ("unavailable", Some("object store could not be read".into()));
    };
    if stats.missing_chunks > 0 {
        return (
            "incomplete",
            Some(format!(
                "{} chunk(s) missing; re-fetch from private R2",
                stats.missing_chunks
            )),
        );
    }
    if stats.snapshots == 0 {
        return ("empty", Some("no snapshot published yet".into()));
    }
    match mirror {
        "verified" => ("synced", None),
        "unverified" => (
            "mirror-pending",
            Some("mirror is configured but no verified snapshot is recorded".into()),
        ),
        _ => ("local-only", Some("no private mirror configured".into())),
    }
}

fn git_repo_state(
    repo: &inventory::Repository,
    config: &Config,
) -> (Option<u64>, Option<u64>, &'static str, Option<String>) {
    if repo.dirty {
        return (
            None,
            None,
            "attention",
            Some("uncommitted work exists; it is preserved, not exchanged".into()),
        );
    }
    let Some(branch) = repo.branch.as_deref() else {
        return (
            None,
            None,
            "attention",
            Some("detached or unborn HEAD".into()),
        );
    };
    let upstream = repo
        .branches
        .iter()
        .find(|candidate| candidate.name == branch)
        .and_then(|branch| branch.upstream.clone());
    let Some(upstream) = upstream else {
        return (
            None,
            None,
            "unshared",
            Some(format!("branch {branch} has no upstream")),
        );
    };
    // `@{upstream}` is git's own syntax for HEAD's configured upstream; the
    // name is only used for the message.
    let output = process::text(
        process::git(&repo.path).args([
            "rev-list",
            "--left-right",
            "--count",
            "HEAD...@{upstream}",
        ]),
        config.command_timeout_seconds,
    );
    let Ok(output) = output else {
        return (
            None,
            None,
            "unknown",
            Some("local upstream state unavailable".into()),
        );
    };
    let mut counts = output.split_whitespace();
    let ahead = counts.next().and_then(|value| value.parse::<u64>().ok());
    let behind = counts.next().and_then(|value| value.parse::<u64>().ok());
    match (ahead, behind) {
        (Some(0), Some(0)) => (ahead, behind, "synced", None),
        (Some(_), Some(_)) => (
            ahead,
            behind,
            "out-of-sync",
            Some(format!("ahead {ahead:?}, behind {behind:?} of {upstream}")),
        ),
        _ => (
            ahead,
            behind,
            "unknown",
            Some("could not parse git counts".into()),
        ),
    }
}

/// Collect a deterministic, JSON-safe status snapshot. The caller decides how
/// much of it to render; no secrets or repository URLs are included.
pub fn collect(config: &Config, storage: &dyn ObjectStorage, detail: u8) -> Result<Value> {
    collect_with(config, storage, detail, true)
}

/// Layer status only, without walking local Git repositories. `rbq serve`
/// uses this: a page that may be announced on the LAN must not list local
/// repository paths, and a request must not start Git subprocesses.
pub fn collect_layers(config: &Config, storage: &dyn ObjectStorage) -> Result<Value> {
    collect_with(config, storage, 0, false)
}

fn collect_with(
    config: &Config,
    storage: &dyn ObjectStorage,
    detail: u8,
    git: bool,
) -> Result<Value> {
    // Hold shared locks while reading every layer, then release before the
    // (potentially slower) Git inventory walk.
    let mut guards = Vec::new();
    for name in layer::LAYERS {
        if let Some(guard) = layer::read_lock(config, name)? {
            guards.push(guard);
        }
    }

    let mut layers = Vec::new();
    let mut occupied_bytes = 0_u64;
    let mut pending_bytes = 0_u64;
    let mut logical_bytes = 0_u64;
    let mut synced = 0_usize;
    let mut attention = 0_usize;
    let mut local_only = 0_usize;
    let mut disabled = 0_usize;

    for name in layer::LAYERS {
        let stats = layer::stats(storage, name).ok();
        // Hypomnema has no local publisher or switch: it counts as enabled
        // once a handoff is present.
        let is_enabled = enabled(config, name)
            || (*name == "hypomnema" && stats.as_ref().is_some_and(|s| s.snapshots > 0));
        let configured = mirror_configured(config, name);
        let evidence = if configured {
            mirror_evidence(config, name)
        } else {
            None
        };
        let mirror = if !configured {
            "not-configured"
        } else if evidence.is_some() {
            "verified"
        } else {
            "unverified"
        };
        let (state, mut reason) = layer_status(is_enabled, stats.as_ref(), mirror);
        if let Some(stats) = &stats {
            if stats.orphan_chunks > 0 && detail >= 2 {
                reason = Some(format!(
                    "{} orphan chunk(s), {} bytes reclaimable by prune",
                    stats.orphan_chunks, stats.orphan_bytes
                ));
            }
            // stored_bytes already includes orphan chunks; do not count them twice.
            occupied_bytes = occupied_bytes.saturating_add(stats.stored_bytes);
            pending_bytes = pending_bytes.saturating_add(stats.missing_bytes);
            logical_bytes = logical_bytes.saturating_add(stats.logical_bytes);
        }
        match state {
            "synced" => synced += 1,
            "disabled" => disabled += 1,
            "local-only" => local_only += 1,
            _ => attention += 1,
        }
        let stats_value = stats.as_ref().map(|stats| {
            json!({
                "snapshots": stats.snapshots,
                "logical_bytes": stats.logical_bytes,
                "stored_chunks": stats.stored_chunks,
                "stored_bytes": stats.stored_bytes,
                "orphan_chunks": stats.orphan_chunks,
                "orphan_bytes": stats.orphan_bytes,
                "missing_chunks": stats.missing_chunks,
                "missing_bytes": stats.missing_bytes,
                "latest": stats.latest_created_at,
            })
        });
        layers.push(json!({
            "layer": name,
            "enabled": is_enabled,
            "state": state,
            "reason": reason,
            "mirror": mirror,
            "mirror_evidence": if detail >= 2 { evidence } else { None::<Value> },
            "stats": stats_value,
            "progress": progress(
                stats.as_ref().map_or(0, |s| s.logical_bytes),
                stats.as_ref().map_or(0, |s| s.missing_bytes),
            ),
        }));
    }
    drop(guards);

    let inventory = if git {
        inventory::discover(config)?
    } else {
        inventory::Inventory::default()
    };
    let mut repositories = Vec::new();
    let mut git_attention = 0_usize;
    for repo in &inventory.repositories {
        let (ahead, behind, state, reason) = git_repo_state(repo, config);
        if state == "attention" || state == "out-of-sync" {
            git_attention += 1;
        }
        let warnings = if detail >= 1 {
            repo.warnings.clone()
        } else {
            Vec::new()
        };
        repositories.push(json!({
            "path": repo.path,
            "branch": repo.branch,
            "head": repo.head,
            "dirty": repo.dirty,
            "ahead": ahead,
            "behind": behind,
            "state": state,
            "reason": reason,
            "permitted_remote": repo.remotes.iter().any(|remote| remote.permitted),
            "warnings": warnings,
        }));
    }
    if git_attention > 0 {
        attention = attention.saturating_add(git_attention);
    }

    let overall_state = if attention > 0 {
        "attention"
    } else if synced > 0 && pending_bytes == 0 {
        "synced"
    } else if local_only > 0 {
        "local-only"
    } else if disabled == layer::LAYERS.len() {
        "disabled"
    } else {
        "empty"
    };

    Ok(json!({
        "schema": "rbq.status.v1",
        "generated_at": Utc::now().to_rfc3339(),
        "rbq_home": config.rbq_home,
        "storage_root": config.storage.root,
        "backup": if config.backup.repository.is_some() || config.binaries.repository.is_some() {
            "configured (redacted)"
        } else {
            "not configured"
        },
        "overall": {
            "state": overall_state,
            "synced": synced,
            "attention": attention,
            "local_only": local_only,
            "disabled": disabled,
            "occupied_bytes": occupied_bytes,
            "pending_bytes": pending_bytes,
            "logical_bytes": logical_bytes,
            "progress": progress(logical_bytes, pending_bytes),
        },
        "layers": layers,
        "repositories": repositories,
        "issues": inventory.errors,
        "note": "Read-only. Shared layer locks prevent half-written snapshots; repository URLs are never shown.",
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn progress_is_honest_for_empty_and_partial_data() {
        assert_eq!(progress(0, 0), 100.0);
        assert_eq!(progress(1000, 0), 100.0);
        assert_eq!(progress(1000, 250), 75.0);
        assert_eq!(progress(1000, 2000), 0.0);
    }

    #[test]
    fn disabled_layers_are_not_counted_as_synced() {
        let stats = layer::LayerStats {
            layer: "binaries".into(),
            snapshots: 1,
            latest_id: None,
            latest_created_at: None,
            logical_bytes: 100,
            stored_chunks: 1,
            stored_bytes: 100,
            orphan_chunks: 0,
            orphan_bytes: 0,
            missing_chunks: 0,
            missing_bytes: 0,
        };
        let (state, _) = layer_status(false, Some(&stats), "verified");
        assert_eq!(state, "disabled");
        let (state, _) = layer_status(true, Some(&stats), "unverified");
        assert_eq!(state, "mirror-pending");
    }
}
