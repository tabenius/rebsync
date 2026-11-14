//! Storage volumes the app can write to, and their free space.
//!
//! On Android, `MainActivity` asks the system for this app's directory on every
//! mounted volume (`getExternalFilesDirs`, which also creates them) and writes
//! the list to a small JSON file named by `REBSYNC_VOLUMES_FILE`. It rewrites
//! the file whenever media is mounted or removed, so a newly inserted SD card
//! or USB stick appears on the next refresh. Elsewhere (desktop development),
//! `REBSYNC_EXTRA_VOLUMES` may list extra directories, separated by `:`.
//!
//! Every app-specific directory is deleted by Android when the app is
//! uninstalled; the UI says so instead of implying permanence.

use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};

#[derive(Clone, Debug, Serialize)]
pub struct Volume {
    pub id: String,
    pub label: String,
    /// internal | shared | sd | usb | removable | detected
    pub kind: String,
    pub path: PathBuf,
    pub total_bytes: Option<u64>,
    pub free_bytes: Option<u64>,
    pub available_bytes: Option<u64>,
    pub writable: bool,
    pub removable: bool,
    pub current: bool,
    pub note: Option<String>,
}

#[derive(Debug, Deserialize)]
struct Reported {
    path: String,
    #[serde(default)]
    removable: bool,
    #[serde(default)]
    emulated: bool,
    #[serde(default)]
    primary: bool,
    #[serde(default)]
    state: Option<String>,
    #[serde(default)]
    description: Option<String>,
    #[serde(default)]
    uuid: Option<String>,
}

fn space(path: &Path) -> (Option<u64>, Option<u64>, Option<u64>) {
    (
        fs2::total_space(path).ok(),
        fs2::free_space(path).ok(),
        fs2::available_space(path).ok(),
    )
}

fn writable(path: &Path) -> bool {
    if std::fs::create_dir_all(path).is_err() {
        return false;
    }
    let probe = path.join(format!(".rebekah-write-probe-{}", std::process::id()));
    let ok = std::fs::write(&probe, b"probe").is_ok();
    let _ = std::fs::remove_file(&probe);
    ok
}

fn classify(r: &Reported) -> (String, String) {
    let description = r.description.clone().unwrap_or_default();
    let lower = description.to_lowercase();
    if !r.removable && (r.emulated || r.primary) {
        return ("shared".into(), "Phone storage (app folder)".into());
    }
    if lower.contains("usb") {
        let label = if description.is_empty() {
            "USB drive".into()
        } else {
            description
        };
        return ("usb".into(), label);
    }
    if lower.contains("sd") {
        let label = if description.is_empty() {
            "SD card".into()
        } else {
            description
        };
        return ("sd".into(), label);
    }
    let label = if description.is_empty() {
        "Removable storage".into()
    } else {
        description
    };
    ("removable".into(), label)
}

/// All volumes, the internal one first. `data_root` marks the current one.
pub fn list(internal: &Path, data_root: &Path) -> Vec<Volume> {
    let mut volumes = Vec::new();
    let mut seen = Vec::<PathBuf>::new();
    let mut push = |mut volume: Volume, seen: &mut Vec<PathBuf>| {
        if seen.iter().any(|p| p == &volume.path) {
            return;
        }
        volume.current = data_root.starts_with(&volume.path);
        seen.push(volume.path.clone());
        volumes.push(volume);
    };
    // Creating the directory first lets statvfs measure a fresh install.
    let internal_writable = writable(internal);
    let (total, free, available) = space(internal);
    push(
        Volume {
            id: "internal".into(),
            label: "Internal (private)".into(),
            kind: "internal".into(),
            path: internal.to_path_buf(),
            total_bytes: total,
            free_bytes: free,
            available_bytes: available,
            writable: internal_writable,
            removable: false,
            current: false,
            note: Some(
                "Private to Rebekah; not visible to other apps. Removed on uninstall.".into(),
            ),
        },
        &mut seen,
    );
    let reported: Vec<Reported> = std::env::var_os("REBSYNC_VOLUMES_FILE")
        .and_then(|file| std::fs::read(file).ok())
        .and_then(|bytes| serde_json::from_slice(&bytes).ok())
        .unwrap_or_default();
    for (index, r) in reported.iter().enumerate() {
        let path = PathBuf::from(&r.path);
        let mounted = r.state.as_deref().is_none_or(|s| s == "mounted");
        let (kind, label) = classify(r);
        let is_writable = mounted && writable(&path);
        let (total, free, available) = if mounted {
            space(&path)
        } else {
            (None, None, None)
        };
        let note = if !mounted {
            Some(format!(
                "Not mounted ({})",
                r.state.as_deref().unwrap_or("unknown")
            ))
        } else if r.removable {
            Some("Removable: data stays on the card or stick, but Android deletes this app folder on uninstall. Eject safely before removing.".into())
        } else {
            Some("App folder on shared storage. Removed on uninstall.".into())
        };
        push(
            Volume {
                id: r.uuid.clone().unwrap_or_else(|| format!("volume-{index}")),
                label,
                kind,
                writable: is_writable,
                path,
                total_bytes: total,
                free_bytes: free,
                available_bytes: available,
                removable: r.removable,
                current: false,
                note,
            },
            &mut seen,
        );
    }
    if let Some(extra) = std::env::var_os("REBSYNC_EXTRA_VOLUMES") {
        for (index, path) in std::env::split_paths(&extra).enumerate() {
            let (total, free, available) = space(&path);
            push(
                Volume {
                    id: format!("extra-{index}"),
                    label: path.display().to_string(),
                    kind: "removable".into(),
                    writable: writable(&path),
                    path,
                    total_bytes: total,
                    free_bytes: free,
                    available_bytes: available,
                    removable: true,
                    current: false,
                    note: None,
                },
                &mut seen,
            );
        }
    }
    // Volumes Android mounted but did not offer to this app (commonly USB
    // drives on some devices): show their space, but they are not targets.
    if let Ok(entries) = std::fs::read_dir("/storage") {
        for entry in entries.flatten() {
            let name = entry.file_name().to_string_lossy().into_owned();
            if matches!(name.as_str(), "emulated" | "self") {
                continue;
            }
            let root = entry.path();
            if reported
                .iter()
                .any(|r| Path::new(&r.path).starts_with(&root))
            {
                continue;
            }
            let (total, free, available) = space(&root);
            if total.is_none() {
                continue;
            }
            push(
                Volume {
                    id: name.clone(),
                    label: format!("Detected volume {name}"),
                    kind: "detected".into(),
                    path: root,
                    total_bytes: total,
                    free_bytes: free,
                    available_bytes: available,
                    writable: false,
                    removable: true,
                    current: false,
                    note: Some("Mounted, but Android has not given Rebekah a folder here. Reopen the app after inserting; some devices only expose USB drives through the file picker.".into()),
                },
                &mut seen,
            );
        }
    }
    volumes
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn classifies_reported_volumes() {
        let r = |removable, emulated, description: &str| Reported {
            path: "/x".into(),
            removable,
            emulated,
            primary: emulated,
            state: Some("mounted".into()),
            description: Some(description.into()),
            uuid: None,
        };
        assert_eq!(
            classify(&r(false, true, "Internal shared storage")).0,
            "shared"
        );
        assert_eq!(classify(&r(true, false, "SanDisk SD card")).0, "sd");
        assert_eq!(classify(&r(true, false, "Kingston USB drive")).0, "usb");
        assert_eq!(classify(&r(true, false, "")).1, "Removable storage");
    }

    #[test]
    fn lists_internal_and_marks_current() {
        let dir = tempfile::tempdir().unwrap();
        let internal = dir.path().join("internal");
        let list = list(&internal, &internal.join("rebekah/objects"));
        assert_eq!(list[0].kind, "internal");
        assert!(list[0].current && list[0].writable);
        assert!(list[0].total_bytes.unwrap() > 0);
    }
}
