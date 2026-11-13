use crate::{config::Config, process};
use anyhow::{Context, Result, bail};
use serde::Serialize;
use std::{
    collections::BTreeSet,
    fs,
    path::{Path, PathBuf},
};
use walkdir::WalkDir;

#[derive(Clone, Debug, Serialize)]
pub struct Branch {
    pub name: String,
    pub oid: String,
    pub upstream: Option<String>,
}
#[derive(Clone, Debug, Serialize)]
pub struct Remote {
    pub name: String,
    pub github: Option<String>,
    pub permitted: bool,
}
#[derive(Clone, Debug, Serialize)]
pub struct Repository {
    pub path: PathBuf,
    pub common_dir: PathBuf,
    pub bare: bool,
    pub dirty: bool,
    pub head: Option<String>,
    pub branch: Option<String>,
    pub branches: Vec<Branch>,
    pub remotes: Vec<Remote>,
    pub warnings: Vec<String>,
}
#[derive(Debug, Serialize)]
pub struct Inventory {
    pub repositories: Vec<Repository>,
    pub errors: Vec<String>,
}

/// Strict GitHub identities, never arbitrary URL-prefix matching.
pub fn github_identity(url: &str) -> Option<String> {
    let path = url
        .strip_prefix("git@github.com:")
        .or_else(|| url.strip_prefix("https://github.com/"))
        .or_else(|| url.strip_prefix("ssh://git@github.com/"))?;
    let path = path.strip_suffix(".git").unwrap_or(path);
    let parts: Vec<_> = path.split('/').collect();
    if parts.len() != 2
        || parts.iter().any(|part| {
            part.is_empty()
                || *part == "."
                || *part == ".."
                || !part
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b"-_.".contains(&b))
        })
    {
        return None;
    }
    Some(format!("github.com/{}/{}", parts[0], parts[1]))
}
pub fn permitted(identity: &str, prefixes: &[String]) -> bool {
    identity
        .rsplit_once('/')
        .is_some_and(|(owner, _)| prefixes.iter().any(|p| owner.eq_ignore_ascii_case(p)))
}
pub fn inspect(path: &Path, config: &Config) -> Result<Repository> {
    let timeout = config.command_timeout_seconds;
    let bare = process::text(
        process::git(path).args(["rev-parse", "--is-bare-repository"]),
        timeout,
    )? == "true";
    let common = process::text(
        process::git(path).args(["rev-parse", "--path-format=absolute", "--git-common-dir"]),
        timeout,
    )?;
    let head = process::text(
        process::git(path).args(["rev-parse", "--verify", "HEAD"]),
        timeout,
    )
    .ok();
    let branch = process::text(
        process::git(path).args(["symbolic-ref", "--quiet", "--short", "HEAD"]),
        timeout,
    )
    .ok();
    let dirty = !bare
        && !process::checked(
            process::git(path).args(["status", "--porcelain=v1", "-z", "--untracked-files=all"]),
            timeout,
        )?
        .is_empty();
    let refs = process::text(
        process::git(path).args([
            "for-each-ref",
            "--format=%(refname:strip=2)%09%(objectname)%09%(upstream)",
            "refs/heads/",
        ]),
        timeout,
    )?;
    let branches = refs
        .lines()
        .map(|line| {
            let mut parts = line.split('\t');
            let name = parts.next().unwrap_or("").to_string();
            let oid = parts.next().unwrap_or("").to_string();
            let upstream = parts.next().filter(|s| !s.is_empty()).map(String::from);
            Branch {
                name,
                oid,
                upstream,
            }
        })
        .collect();
    let names = process::text(process::git(path).arg("remote"), timeout)?;
    let mut remotes = vec![];
    for name in names.lines() {
        // Unknown URLs are deliberately absent from reports; they may contain credentials.
        let urls = process::text(
            process::git(path).args(["remote", "get-url", "--all", name]),
            timeout,
        )?;
        let pushes = process::text(
            process::git(path).args(["remote", "get-url", "--push", "--all", name]),
            timeout,
        )?;
        let fetch: Vec<_> = urls.lines().collect();
        let push: Vec<_> = pushes.lines().collect();
        let github = fetch.first().and_then(|url| github_identity(url));
        let allowed = fetch.len() == 1
            && push.len() == 1
            && github.as_ref().is_some_and(|id| {
                permitted(id, &config.git.remote_prefixes)
                    && github_identity(push[0]).as_ref() == Some(id)
            });
        remotes.push(Remote {
            name: name.into(),
            github,
            permitted: allowed,
        });
    }
    let mut warnings = vec![];
    if dirty {
        warnings.push(
            "uncommitted work exists; it will not be committed or rewritten automatically".into(),
        );
    }
    if head.is_none() {
        warnings.push("unborn HEAD: no commit history yet".into());
    }
    if branch.is_none() && !bare {
        warnings.push("detached HEAD: commits will be bundled, not assigned to a branch".into());
    }
    if remotes.iter().all(|r| !r.permitted) {
        warnings.push(
            "no permitted GitHub exchange destination; creation/mapping needs approval".into(),
        );
    }
    let git_path = process::text(
        process::git(path).args(["rev-parse", "--path-format=absolute", "--git-dir"]),
        timeout,
    )?;
    if [
        "MERGE_HEAD",
        "CHERRY_PICK_HEAD",
        "REVERT_HEAD",
        "rebase-merge",
        "rebase-apply",
        "sequencer",
    ]
    .iter()
    .any(|p| Path::new(&git_path).join(p).exists())
    {
        warnings.push("Git operation in progress: branch movement is blocked".into());
    }
    Ok(Repository {
        path: path.to_path_buf(),
        common_dir: fs::canonicalize(common)?,
        bare,
        dirty,
        head,
        branch,
        branches,
        remotes,
        warnings,
    })
}

pub fn discover(config: &Config) -> Result<Inventory> {
    let mut paths = BTreeSet::new();
    let mut errors = vec![];
    for root in config.roots() {
        if !root.is_dir() {
            errors.push(format!("missing scan root: {}", root.display()));
            continue;
        }
        let walker = WalkDir::new(&root)
            .follow_links(false)
            .max_depth(config.scan.max_depth)
            .into_iter()
            .filter_entry(|entry| {
                entry.depth() == 0
                    || !config
                        .scan
                        .exclude
                        .iter()
                        .any(|x| entry.file_name() == x.as_str())
            });
        for entry in walker {
            match entry {
                Ok(entry) if entry.file_type().is_dir() => {
                    let path = entry.path();
                    if path.join(".git").exists()
                        || (path.join("HEAD").is_file()
                            && path.join("objects").is_dir()
                            && path.join("refs").is_dir())
                    {
                        match fs::canonicalize(path) {
                            Ok(path) => {
                                paths.insert(path);
                            }
                            Err(e) => errors.push(e.to_string()),
                        }
                    }
                }
                Ok(_) => {}
                Err(e) => errors.push(e.to_string()),
            }
        }
    }
    let mut repositories = vec![];
    for path in paths {
        match inspect(&path, config).with_context(|| format!("inspect {}", path.display())) {
            Ok(repo) => repositories.push(repo),
            Err(e) => errors.push(format!("{e:#}")),
        }
    }
    if config.scan.max_depth == 0 {
        bail!("scan.max_depth must be greater than zero");
    }
    Ok(Inventory {
        repositories,
        errors,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn strict_github_urls() {
        assert_eq!(
            github_identity("git@github.com:tabenius/rebsync.git"),
            Some("github.com/tabenius/rebsync".into())
        );
        assert_eq!(
            github_identity("https://github.com/tabenius/rebsync"),
            Some("github.com/tabenius/rebsync".into())
        );
        for bad in [
            "https://github.com.evil/tabenius/x",
            "https://secret@github.com/tabenius/x",
            "https://github.com/tabenius/../x",
            "ext::evil",
            "https://github.com/tabenius/x?secret=y",
        ] {
            assert!(github_identity(bad).is_none());
        }
        assert!(!permitted(
            "github.com/tabenius-evil/x",
            &["github.com/tabenius".into()]
        ));
    }
}
