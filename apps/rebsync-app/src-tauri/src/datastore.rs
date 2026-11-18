//! Settings, the pairing token and moving the data root between volumes.
//!
//! A move never deletes before it can prove the copy: every file is copied to
//! a temporary name, fsynced, renamed, then re-read and compared by SHA-256
//! with the source. Only after all files verify does the data root switch
//! (settings are written atomically). Removing the source is optional and
//! happens last. Writes from peers are paused for the whole move.

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    fs,
    io::{Read, Write},
    path::{Path, PathBuf},
    sync::Mutex,
};

pub const DATA_DIR: &str = "rebeqah";

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Settings {
    /// Volume directory holding `rbq/objects`.
    pub volume: PathBuf,
    pub token: String,
    pub port: u16,
    pub sharing: bool,
}

impl Settings {
    pub fn objects(&self) -> PathBuf {
        self.volume.join(DATA_DIR).join("objects")
    }
}

pub fn new_token() -> String {
    let mut bytes = [0_u8; 24];
    getrandom::fill(&mut bytes).expect("system randomness");
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

pub fn load(path: &Path, internal: &Path) -> Settings {
    fs::read(path)
        .ok()
        .and_then(|bytes| serde_json::from_slice::<Settings>(&bytes).ok())
        .unwrap_or_else(|| Settings {
            volume: internal.to_path_buf(),
            token: new_token(),
            port: 8787,
            sharing: false,
        })
}

/// Write via a temporary file and rename, so a crash never leaves torn settings.
pub fn save(path: &Path, settings: &Settings) -> Result<(), String> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).map_err(|e| e.to_string())?;
    }
    let temp = path.with_extension("json.tmp");
    let mut file = fs::File::create(&temp).map_err(|e| e.to_string())?;
    file.write_all(&serde_json::to_vec_pretty(settings).map_err(|e| e.to_string())?)
        .and_then(|_| file.sync_all())
        .map_err(|e| e.to_string())?;
    fs::rename(&temp, path).map_err(|e| e.to_string())
}

#[derive(Clone, Debug, Default, Serialize)]
pub struct MoveStatus {
    /// idle | scanning | copying | verifying | switching | cleaning | done | failed
    pub phase: String,
    pub from: Option<PathBuf>,
    pub to: Option<PathBuf>,
    pub files_total: u64,
    pub files_done: u64,
    pub bytes_total: u64,
    pub bytes_done: u64,
    pub error: Option<String>,
    pub removed_source: bool,
}

fn hash(path: &Path) -> std::io::Result<String> {
    let mut file = fs::File::open(path)?;
    let mut hasher = Sha256::new();
    let mut buffer = vec![0_u8; 1 << 20];
    loop {
        let n = file.read(&mut buffer)?;
        if n == 0 {
            break;
        }
        hasher.update(&buffer[..n]);
    }
    Ok(format!("{:x}", hasher.finalize()))
}

/// Regular files under `root`, relative paths, skipping probes and temporaries.
pub fn inventory(root: &Path) -> std::io::Result<Vec<(PathBuf, u64)>> {
    let mut files = Vec::new();
    if !root.exists() {
        return Ok(files);
    }
    for entry in walkdir::WalkDir::new(root).follow_links(false) {
        let entry = entry.map_err(std::io::Error::other)?;
        if !entry.file_type().is_file() {
            continue;
        }
        let name = entry.file_name().to_string_lossy();
        if name.starts_with(".rbq-link-probe") || name.starts_with(".rebeqah-") {
            continue;
        }
        let relative = entry
            .path()
            .strip_prefix(root)
            .map_err(std::io::Error::other)?
            .to_path_buf();
        files.push((
            relative,
            entry.metadata().map_err(std::io::Error::other)?.len(),
        ));
    }
    files.sort();
    Ok(files)
}

/// Copy `from` to `to` and verify every file. Existing identical files at the
/// destination are kept (a resumed move); a differing one is an error.
pub fn copy_verified(
    from: &Path,
    to: &Path,
    status: &Mutex<MoveStatus>,
) -> Result<Vec<PathBuf>, String> {
    let set = |f: &dyn Fn(&mut MoveStatus)| {
        if let Ok(mut s) = status.lock() {
            f(&mut s);
        }
    };
    set(&|s| s.phase = "scanning".into());
    let files = inventory(from).map_err(|e| format!("scan source: {e}"))?;
    let total: u64 = files.iter().map(|(_, n)| n).sum();
    set(&|s| {
        s.files_total = files.len() as u64;
        s.bytes_total = total;
        s.phase = "copying".into();
    });
    fs::create_dir_all(to).map_err(|e| format!("create destination: {e}"))?;
    let mut copied = Vec::new();
    for (relative, size) in &files {
        let source = from.join(relative);
        let target = to.join(relative);
        let expected = hash(&source).map_err(|e| format!("read {}: {e}", relative.display()))?;
        if target.exists() {
            let present = hash(&target).map_err(|e| format!("read destination: {e}"))?;
            if present != expected {
                return Err(format!(
                    "{} already exists at the destination with different content; not overwriting",
                    relative.display()
                ));
            }
        } else {
            if let Some(parent) = target.parent() {
                fs::create_dir_all(parent).map_err(|e| format!("create directory: {e}"))?;
            }
            let temp = target.with_file_name(format!(
                ".rbq-move-{}",
                target.file_name().unwrap_or_default().to_string_lossy()
            ));
            {
                let mut input = fs::File::open(&source).map_err(|e| e.to_string())?;
                let mut output =
                    fs::File::create(&temp).map_err(|e| format!("write destination: {e}"))?;
                std::io::copy(&mut input, &mut output).map_err(|e| format!("copy: {e}"))?;
                output.sync_all().map_err(|e| format!("sync: {e}"))?;
            }
            fs::rename(&temp, &target).map_err(|e| format!("publish copy: {e}"))?;
            let written = hash(&target).map_err(|e| format!("re-read copy: {e}"))?;
            if written != expected {
                let _ = fs::remove_file(&target);
                return Err(format!("verification failed for {}", relative.display()));
            }
        }
        copied.push(relative.clone());
        set(&|s| {
            s.files_done += 1;
            s.bytes_done += size;
        });
    }
    set(&|s| s.phase = "verifying".into());
    // Final check: the destination holds every source file with equal size.
    let destination: std::collections::BTreeMap<_, _> = inventory(to)
        .map_err(|e| format!("scan destination: {e}"))?
        .into_iter()
        .collect();
    for (relative, size) in &files {
        if destination.get(relative) != Some(size) {
            return Err(format!("{} missing after copy", relative.display()));
        }
    }
    Ok(copied)
}

/// Delete the verified source files, then empty directories. Best effort.
pub fn remove_source(from: &Path, files: &[PathBuf]) {
    for relative in files {
        let _ = fs::remove_file(from.join(relative));
    }
    let mut directories: Vec<_> = walkdir::WalkDir::new(from)
        .into_iter()
        .flatten()
        .filter(|e| e.file_type().is_dir())
        .map(|e| e.path().to_path_buf())
        .collect();
    directories.sort_by_key(|d| std::cmp::Reverse(d.components().count()));
    for directory in directories {
        let _ = fs::remove_dir(directory);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn copies_verifies_resumes_and_refuses_conflicts() {
        let dir = tempfile::tempdir().unwrap();
        let from = dir.path().join("a/objects");
        let to = dir.path().join("b/objects");
        for (key, body) in [("mneme/v1/x", "one"), ("data/y", "two"), ("z", "three")] {
            let path = from.join(key);
            fs::create_dir_all(path.parent().unwrap()).unwrap();
            fs::write(path, body).unwrap();
        }
        fs::write(from.join(".rbq-link-probe-1"), "probe").unwrap();
        let status = Mutex::new(MoveStatus::default());
        let copied = copy_verified(&from, &to, &status).unwrap();
        assert_eq!(copied.len(), 3);
        assert_eq!(fs::read_to_string(to.join("mneme/v1/x")).unwrap(), "one");
        assert!(!to.join(".rbq-link-probe-1").exists());
        let s = status.lock().unwrap().clone();
        assert_eq!((s.files_done, s.bytes_done), (3, 11));
        // Resuming over identical content is fine.
        copy_verified(&from, &to, &Mutex::new(MoveStatus::default())).unwrap();
        // A conflicting destination file is never overwritten.
        fs::write(to.join("z"), "other").unwrap();
        assert!(copy_verified(&from, &to, &Mutex::new(MoveStatus::default())).is_err());
        assert_eq!(fs::read_to_string(to.join("z")).unwrap(), "other");
        remove_source(&from, &copied);
        assert!(
            inventory(&from)
                .unwrap()
                .iter()
                .all(|(p, _)| p.starts_with(".rbq"))
        );
    }

    #[test]
    fn settings_round_trip_and_tokens_are_random() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("settings.json");
        let settings = load(&path, dir.path());
        assert_eq!(settings.token.len(), 48);
        assert_ne!(settings.token, new_token());
        save(&path, &settings).unwrap();
        assert_eq!(load(&path, Path::new("/elsewhere")).token, settings.token);
    }
}
