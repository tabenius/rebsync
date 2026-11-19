//! Enrolled storage: removable drives (USB sticks, SD cards, external disks)
//! that rbq may exchange layer objects with.
//!
//! A drive is identified by a marker file written at enrollment, not by its
//! mount path, which changes between machines and boots. rbq never writes to a
//! drive that was not enrolled by name, and never to every removable drive it
//! happens to see. Where the system exposes it, the filesystem UUID recorded at
//! enrollment must also match, so a copied marker on another filesystem is
//! refused. A drive on the same device as the local object store is reported
//! as not independent: copying there does not protect against losing the disk.
//!
//! Exchange reuses the peer engine ([`crate::peer::push`] / [`crate::peer::pull`]):
//! additive, never overwriting, verifying received snapshots.
use crate::Config;
use crate::peer::PeerApi;
use crate::storage::{FsObjectStorage, ObjectKey, ObjectStorage, PutOutcome};
use anyhow::{Context, Result, bail, ensure};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

pub const MARKER: &str = ".rbq-drive.json";
pub const STORE_DIR: &str = "rbq-store";
const SCHEMA: &str = "rbq.drive/1";

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct Marker {
    pub schema: String,
    pub id: String,
    pub name: String,
    pub enrolled_at: String,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct Enrollment {
    pub id: String,
    pub name: String,
    /// Filesystem UUID at enrollment, when the system exposes one.
    pub filesystem_uuid: Option<String>,
    pub enrolled_at: String,
    /// The path used at enrollment (informational only; never trusted later).
    pub enrolled_path: PathBuf,
}

#[derive(Debug, Serialize)]
pub struct DriveStatus {
    pub name: String,
    pub id: String,
    /// Where the drive is mounted now, if found and verified.
    pub path: Option<PathBuf>,
    pub present: bool,
    /// False when the drive shares a device with the local object store.
    pub independent: Option<bool>,
    pub problem: Option<String>,
}

fn valid_name(name: &str) -> bool {
    (1..=32).contains(&name.len())
        && name
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
        && !name.starts_with('-')
}

fn new_id() -> Result<String> {
    let mut bytes = [0u8; 16];
    std::fs::File::open("/dev/urandom")
        .and_then(|mut f| std::io::Read::read_exact(&mut f, &mut bytes))
        .context("read random bytes for the drive id")?;
    Ok(bytes.iter().map(|b| format!("{b:02x}")).collect())
}

fn registry_path(config: &Config) -> Result<PathBuf> {
    Ok(crate::sync::state_dir(config)?.join("drives.json"))
}

/// Enrolled drives, by name.
pub fn enrolled(config: &Config) -> Result<BTreeMap<String, Enrollment>> {
    let path = registry_path(config)?;
    match std::fs::read(&path) {
        Ok(bytes) => serde_json::from_slice(&bytes).context("drives.json is not valid"),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(BTreeMap::new()),
        Err(error) => Err(error).context("read drives.json"),
    }
}

fn save(config: &Config, drives: &BTreeMap<String, Enrollment>) -> Result<()> {
    let path = registry_path(config)?;
    let mut temp = tempfile::NamedTempFile::new_in(path.parent().context("state dir")?)?;
    std::io::Write::write_all(&mut temp, &serde_json::to_vec_pretty(drives)?)?;
    temp.as_file().sync_all()?;
    temp.persist(&path).map_err(|e| e.error)?;
    Ok(())
}

fn read_marker(root: &Path) -> Result<Option<Marker>> {
    let path = root.join(MARKER);
    let metadata = match std::fs::symlink_metadata(&path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(error).context("inspect drive marker"),
    };
    ensure!(metadata.is_file(), "drive marker must be a regular file");
    let file = std::fs::File::open(&path)?;
    let bytes = crate::wire::read_bounded(file, 4096)?.context("drive marker exceeds 4 KiB")?;
    let marker: Marker = serde_json::from_slice(&bytes).context("drive marker is not valid")?;
    ensure!(marker.schema == SCHEMA, "unsupported drive marker schema");
    ensure!(
        marker.id.len() == 32 && marker.id.bytes().all(|b| b.is_ascii_hexdigit()),
        "drive marker id is malformed"
    );
    Ok(Some(marker))
}

/// Unescape a /proc/self/mountinfo field (`\040` etc.).
fn unescape(field: &str) -> String {
    let bytes = field.as_bytes();
    let (mut out, mut i) = (Vec::with_capacity(bytes.len()), 0);
    while i < bytes.len() {
        if bytes[i] == b'\\'
            && i + 3 < bytes.len()
            && let Ok(code) = u8::from_str_radix(&field[i + 1..i + 4], 8)
        {
            out.push(code);
            i += 4;
            continue;
        }
        out.push(bytes[i]);
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

/// Current mount points and their source devices.
fn mounts() -> Vec<(PathBuf, String)> {
    let Ok(text) = std::fs::read_to_string("/proc/self/mountinfo") else {
        return Vec::new();
    };
    text.lines()
        .filter_map(|line| {
            let fields: Vec<&str> = line.split(' ').collect();
            let mount_point = fields.get(4)?;
            let dash = fields.iter().position(|f| *f == "-")?;
            let source = fields.get(dash + 2)?;
            Some((PathBuf::from(unescape(mount_point)), unescape(source)))
        })
        .collect()
}

/// The filesystem UUID of the device mounted at `root`, where `/dev/disk/by-uuid` exists.
fn filesystem_uuid(root: &Path) -> Option<String> {
    let root = std::fs::canonicalize(root).ok()?;
    let source = mounts()
        .into_iter()
        .filter(|(mount, _)| root.starts_with(mount))
        .max_by_key(|(mount, _)| mount.as_os_str().len())?
        .1;
    let device = std::fs::canonicalize(&source).ok()?;
    std::fs::read_dir("/dev/disk/by-uuid")
        .ok()?
        .flatten()
        .find_map(|entry| {
            (std::fs::canonicalize(entry.path()).ok()? == device)
                .then(|| entry.file_name().to_string_lossy().into_owned())
        })
}

#[cfg(unix)]
fn device_of(path: &Path) -> Option<u64> {
    use std::os::unix::fs::MetadataExt;
    let mut probe = path.to_path_buf();
    loop {
        if let Ok(metadata) = std::fs::metadata(&probe) {
            return Some(metadata.dev());
        }
        probe = probe.parent()?.to_path_buf();
    }
}

#[cfg(not(unix))]
fn device_of(_: &Path) -> Option<u64> {
    None
}

fn independent(config: &Config, root: &Path) -> Option<bool> {
    Some(device_of(root)? != device_of(&config.storage.root)?)
}

/// Enroll the drive mounted at `root` under `name`.
///
/// Writes the marker (create-only). A drive that already carries a marker is
/// adopted only with `adopt`, keeping its identity (e.g. enrolled on another
/// machine). Refuses a drive on the same device as the local object store
/// unless `allow_same_device`.
pub fn enroll(
    config: &Config,
    root: &Path,
    name: &str,
    adopt: bool,
    allow_same_device: bool,
) -> Result<Enrollment> {
    ensure!(
        valid_name(name),
        "drive name must be 1-32 lowercase letters, digits or '-'"
    );
    let root =
        std::fs::canonicalize(root).with_context(|| format!("drive path {}", root.display()))?;
    ensure!(root.is_dir(), "drive path must be a directory");
    ensure!(
        root != Path::new("/"),
        "refusing to enroll the root filesystem"
    );
    if independent(config, &root) == Some(false) && !allow_same_device {
        bail!(
            "{} is on the same device as the local object store; copying there does not protect against losing this disk (use --allow-same-device to enroll anyway)",
            root.display()
        );
    }
    let mut drives = enrolled(config)?;
    ensure!(
        !drives.contains_key(name),
        "a drive named {name} is already enrolled"
    );
    let marker = match read_marker(&root)? {
        Some(marker) if adopt => marker,
        Some(marker) => bail!(
            "{} already carries rbq drive {} ({}); pass --adopt to enroll it here with that identity",
            root.display(),
            marker.name,
            marker.id
        ),
        None => {
            let marker = Marker {
                schema: SCHEMA.into(),
                id: new_id()?,
                name: name.into(),
                enrolled_at: chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Secs, true),
            };
            let mut options = std::fs::OpenOptions::new();
            options.write(true).create_new(true);
            let mut file = options
                .open(root.join(MARKER))
                .context("write drive marker")?;
            std::io::Write::write_all(&mut file, &serde_json::to_vec_pretty(&marker)?)?;
            file.sync_all()?;
            marker
        }
    };
    ensure!(
        !drives.values().any(|d| d.id == marker.id),
        "this drive is already enrolled under another name"
    );
    let enrollment = Enrollment {
        id: marker.id,
        name: name.into(),
        filesystem_uuid: filesystem_uuid(&root),
        enrolled_at: marker.enrolled_at,
        enrolled_path: root,
    };
    drives.insert(name.into(), enrollment.clone());
    save(config, &drives)?;
    Ok(enrollment)
}

/// Remove an enrollment. The marker and data on the drive are left alone.
pub fn forget(config: &Config, name: &str) -> Result<Enrollment> {
    let mut drives = enrolled(config)?;
    let enrollment = drives
        .remove(name)
        .with_context(|| format!("no drive named {name} is enrolled"))?;
    save(config, &drives)?;
    Ok(enrollment)
}

/// Where an enrolled drive is mounted now: scan mount points (and any extra
/// candidate paths) for its marker, then check the filesystem UUID.
fn locate(enrollment: &Enrollment, candidates: &[PathBuf]) -> std::result::Result<PathBuf, String> {
    let mut paths: Vec<PathBuf> = mounts().into_iter().map(|(mount, _)| mount).collect();
    paths.extend(candidates.iter().cloned());
    paths.push(enrollment.enrolled_path.clone());
    paths.sort();
    paths.dedup();
    let mut problem = None;
    for path in paths {
        match read_marker(&path) {
            Ok(Some(marker)) if marker.id == enrollment.id => {
                match (&enrollment.filesystem_uuid, filesystem_uuid(&path)) {
                    (Some(expected), Some(actual)) if *expected != actual => {
                        problem = Some(format!(
                            "{} carries this drive's marker but filesystem {actual} is not the enrolled {expected}",
                            path.display()
                        ));
                    }
                    // A UUID was recorded: one that cannot be read now (a copied
                    // marker on tmpfs, say) is not proof of identity.
                    (Some(expected), None) => {
                        problem = Some(format!(
                            "{} carries this drive's marker but its filesystem UUID cannot be read to confirm the enrolled {expected}",
                            path.display()
                        ));
                    }
                    _ => return Ok(path),
                }
            }
            _ => {}
        }
    }
    Err(problem.unwrap_or_else(|| "not mounted".into()))
}

/// Status of every enrolled drive.
pub fn status(config: &Config, candidates: &[PathBuf]) -> Result<Vec<DriveStatus>> {
    Ok(enrolled(config)?
        .into_values()
        .map(|enrollment| match locate(&enrollment, candidates) {
            Ok(path) => DriveStatus {
                independent: independent(config, &path),
                name: enrollment.name,
                id: enrollment.id,
                path: Some(path),
                present: true,
                problem: None,
            },
            Err(problem) => DriveStatus {
                name: enrollment.name,
                id: enrollment.id,
                path: None,
                present: false,
                independent: None,
                problem: Some(problem),
            },
        })
        .collect())
}

/// The drive's object store directory, refusing one that is a symlink or
/// resolves outside the drive: copies there would not be on the drive.
fn store_dir(root: &Path) -> Result<PathBuf> {
    let store = root.join(STORE_DIR);
    match std::fs::symlink_metadata(&store) {
        Ok(metadata) => {
            ensure!(
                metadata.is_dir() && !metadata.file_type().is_symlink(),
                "{} must be a directory on the drive, not a symlink",
                store.display()
            );
            let resolved = std::fs::canonicalize(&store)?;
            ensure!(
                resolved.starts_with(std::fs::canonicalize(root)?),
                "{} resolves outside the drive",
                store.display()
            );
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => return Err(error).context("inspect drive store"),
    }
    Ok(store)
}

/// Open an enrolled, present, verified drive's object store.
pub fn open(config: &Config, name: &str, candidates: &[PathBuf]) -> Result<DrivePeer> {
    let enrollment = enrolled(config)?.remove(name).with_context(|| {
        format!("no drive named {name} is enrolled (rbq drive enroll PATH --name {name})")
    })?;
    let root = locate(&enrollment, candidates)
        .map_err(|problem| anyhow::anyhow!("drive {name}: {problem}"))?;
    let storage = FsObjectStorage::open(store_dir(&root)?).map_err(|e| anyhow::anyhow!("{e}"))?;
    Ok(DrivePeer {
        base: format!("drive:{name}"),
        independent: independent(config, &root),
        root,
        storage: Box::new(storage),
    })
}

/// Which published layer objects have a copy on an enrolled drive. Read-only:
/// creates nothing, writes nothing, and only reads drives that are mounted,
/// verified and independent of the local store. Returns a summary and the
/// issues to report ("what remains unprotected").
pub fn coverage(config: &Config, prefixes: &[String]) -> Result<(Value, Vec<String>)> {
    if !config.storage.root.is_dir() {
        return Ok((Value::Null, Vec::new()));
    }
    let local_store = FsObjectStorage::open_read_only(&config.storage.root)
        .map_err(|e| anyhow::anyhow!("{e}"))?;
    let mut local = BTreeMap::new();
    for prefix in prefixes {
        for meta in local_store
            .list_prefix(prefix, 0)
            .map_err(|e| anyhow::anyhow!("{e}"))?
        {
            local.insert(meta.key, meta.size);
        }
    }
    if local.is_empty() {
        return Ok((Value::Null, Vec::new()));
    }
    let total_bytes: u64 = local.values().sum();
    let (mut drives, mut issues, mut covered) = (Vec::new(), Vec::new(), false);
    let enrollments = enrolled(config)?;
    for enrollment in enrollments.values() {
        let root = match locate(enrollment, &[]) {
            Ok(root) => root,
            Err(problem) => {
                drives.push(json!({"name": enrollment.name, "present": false, "problem": problem}));
                continue;
            }
        };
        let independent = independent(config, &root);
        let store = match store_dir(&root) {
            Ok(store) => store,
            Err(problem) => {
                issues.push(format!("drive {}: {problem}", enrollment.name));
                drives.push(json!({"name": enrollment.name, "present": true, "problem": problem.to_string()}));
                continue;
            }
        };
        let mut remote = BTreeMap::new();
        if store.is_dir() {
            let drive =
                FsObjectStorage::open_read_only(&store).map_err(|e| anyhow::anyhow!("{e}"))?;
            for prefix in prefixes {
                for meta in drive
                    .list_prefix(prefix, 0)
                    .map_err(|e| anyhow::anyhow!("{e}"))?
                {
                    remote.insert(meta.key, meta.size);
                }
            }
        }
        let (mut missing, mut missing_bytes, mut conflicts) = (0usize, 0u64, 0usize);
        for (key, size) in &local {
            match remote.get(key) {
                Some(other) if other == size => {}
                Some(_) => conflicts += 1,
                None => {
                    missing += 1;
                    missing_bytes += size;
                }
            }
        }
        if independent == Some(true) && missing == 0 && conflicts == 0 {
            covered = true;
        }
        if missing > 0 {
            issues.push(format!(
                "drive {}: {missing} layer objects ({missing_bytes} bytes) not yet copied; run rbq drive push {}",
                enrollment.name, enrollment.name
            ));
        }
        if conflicts > 0 {
            issues.push(format!(
                "drive {}: {conflicts} layer objects differ in size from the local copy; inspect before exchanging",
                enrollment.name
            ));
        }
        drives.push(json!({"name": enrollment.name, "present": true, "path": root, "independent": independent,
            "missing": missing, "missing_bytes": missing_bytes, "conflicts": conflicts}));
    }
    if !covered {
        issues.push(if enrollments.is_empty() {
            format!(
                "{} published layer objects ({total_bytes} bytes) are only in the local store; enroll a removable drive (rbq drive enroll PATH --name NAME) or exchange with a peer",
                local.len()
            )
        } else {
            format!(
                "no mounted, independent enrolled drive holds all {} published layer objects ({total_bytes} bytes); peer copies are not tracked",
                local.len()
            )
        });
    }
    Ok((
        json!({"objects": local.len(), "bytes": total_bytes, "covered_by_drive": covered, "drives": drives}),
        issues,
    ))
}

/// An enrolled drive seen through the peer interface, so push and pull reuse
/// the peer engine's ordering, conflict reporting and verification.
pub struct DrivePeer {
    base: String,
    pub root: PathBuf,
    pub independent: Option<bool>,
    storage: Box<dyn ObjectStorage>,
}

impl PeerApi for DrivePeer {
    fn base(&self) -> &str {
        &self.base
    }

    fn status(&self) -> Result<Value> {
        let capabilities = self.storage.capabilities();
        Ok(json!({
            "drive": self.base,
            "path": self.root,
            "independent": self.independent,
            "atomic_create_if_absent": capabilities.atomic_create_if_absent,
            "owner_only_permissions": capabilities.owner_only_permissions,
        }))
    }

    fn list(&self, prefix: &str) -> Result<BTreeMap<String, u64>> {
        Ok(self
            .storage
            .list_prefix(prefix, 0)
            .map_err(|e| anyhow::anyhow!("{e}"))?
            .into_iter()
            .map(|meta| (meta.key, meta.size))
            .collect())
    }

    fn get(&self, key: &str) -> Result<Vec<u8>> {
        self.storage
            .get(&ObjectKey::parse(key)?)
            .map_err(|e| anyhow::anyhow!("{e}"))
    }

    fn put(&self, key: &str, bytes: &[u8]) -> Result<bool> {
        match self
            .storage
            .put_if_absent(&ObjectKey::parse(key)?, bytes)
            .map_err(|e| anyhow::anyhow!("{e}"))?
        {
            PutOutcome::Created(_) => Ok(true),
            PutOutcome::AlreadyExists(_) => Ok(false),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn names_and_mountinfo_escapes() {
        assert!(valid_name("usb-1"));
        assert!(!valid_name("USB") && !valid_name("-x") && !valid_name("") && !valid_name("a/b"));
        assert_eq!(unescape("/media/me/My\\040Drive"), "/media/me/My Drive");
    }
}
