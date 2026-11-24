//! Owner-only credential files: the explicitly selected headless backend
//! (RBQ-SERVICE-PLAN.md §1, "Headless Linux").
//!
//! **This is not encryption at rest.** Anyone who can read the directory as
//! this user, or as root, can read the secrets. It is what a headless device
//! or an app's private storage offers; a keyring or platform keystore backend
//! can replace it behind the same [`CredentialStore`] trait.
//!
//! - The directory is `0700` and owned by this user; every entry is a `0600`
//!   regular file owned by this user. Anything else is refused, not repaired.
//! - One entry is one file holding the descriptor and the secret together, so
//!   creation is atomic: written to a temporary file, fsynced, then hard-linked
//!   into place, which never replaces an existing entry (no-clobber).
//! - Disabling rewrites the entry with `disabled: true` and renames it over the
//!   old one before reporting success, so no later use can see it enabled.
//! - Reads never follow symlinks and are bounded in size.
//! - [`CredentialStore::use_secret`] checks the stored descriptor, never the
//!   caller's.

use super::{Audience, CredentialStore, Descriptor, Scope, Secret, StoreError};
use base64::Engine;
use serde::{Deserialize, Serialize};
use std::fs;
use std::io::{Read, Write};
use std::path::{Path, PathBuf};

const SCHEMA: &str = "rbq.credential-file.v1";
const MAX_ENTRY: u64 = 64 * 1024;

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Entry {
    schema: String,
    descriptor: Descriptor,
    /// Base64 of the secret bytes.
    secret: String,
}

/// Credential ids name files: letters, digits, `-` and `_`, 1..=64 bytes.
pub fn valid_id(id: &str) -> bool {
    (1..=64).contains(&id.len())
        && id
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
}

/// An explicitly selected directory of owner-only credential files.
#[derive(Debug, Clone)]
pub struct FileStore {
    dir: PathBuf,
}

fn io_error(error: std::io::Error) -> StoreError {
    match error.kind() {
        std::io::ErrorKind::NotFound => StoreError::NotFound,
        std::io::ErrorKind::AlreadyExists => StoreError::Conflict,
        std::io::ErrorKind::PermissionDenied => StoreError::Denied,
        _ => StoreError::Unavailable,
    }
}

#[cfg(unix)]
fn owned_by_me(metadata: &fs::Metadata) -> bool {
    use std::os::unix::fs::MetadataExt;
    // SAFETY: geteuid takes no arguments and has no memory preconditions.
    metadata.uid() == unsafe { libc::geteuid() }
}

impl FileStore {
    /// Open (creating it owner-only if absent) the store in `dir`. An
    /// existing directory must already be a real directory owned by this user
    /// and closed to everyone else.
    pub fn open(dir: &Path) -> Result<Self, StoreError> {
        match fs::symlink_metadata(dir) {
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                let mut builder = fs::DirBuilder::new();
                builder.recursive(true);
                #[cfg(unix)]
                {
                    use std::os::unix::fs::DirBuilderExt;
                    builder.mode(0o700);
                }
                builder.create(dir).map_err(io_error)?;
            }
            Err(error) => return Err(io_error(error)),
            Ok(_) => {}
        }
        let metadata = fs::symlink_metadata(dir).map_err(io_error)?;
        if !metadata.is_dir() {
            return Err(StoreError::Invalid);
        }
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            if !owned_by_me(&metadata) || metadata.permissions().mode() & 0o077 != 0 {
                return Err(StoreError::Denied);
            }
        }
        Ok(Self {
            dir: dir.to_path_buf(),
        })
    }

    pub fn dir(&self) -> &Path {
        &self.dir
    }

    fn path(&self, id: &str) -> Result<PathBuf, StoreError> {
        if !valid_id(id) {
            return Err(StoreError::Invalid);
        }
        Ok(self.dir.join(format!("{id}.json")))
    }

    fn load(&self, id: &str) -> Result<Entry, StoreError> {
        let bytes = read_private(&self.path(id)?)?;
        let entry: Entry = serde_json::from_slice(&bytes).map_err(|_| StoreError::Invalid)?;
        if entry.schema != SCHEMA || entry.descriptor.id != id {
            return Err(StoreError::Invalid);
        }
        Ok(entry)
    }

    fn encode(descriptor: Descriptor, secret: &[u8]) -> Result<Vec<u8>, StoreError> {
        serde_json::to_vec_pretty(&Entry {
            schema: SCHEMA.into(),
            descriptor,
            secret: base64::engine::general_purpose::STANDARD.encode(secret),
        })
        .map_err(|_| StoreError::Invalid)
    }
}

/// Read an owner-only regular file without following symlinks, bounded.
pub(crate) fn read_private(path: &Path) -> Result<Vec<u8>, StoreError> {
    let mut options = fs::OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK);
    }
    let file = options
        .open(path)
        .map_err(|error| match error.raw_os_error() {
            // O_NOFOLLOW on a symlink.
            #[cfg(unix)]
            Some(libc::ELOOP) => StoreError::Denied,
            _ => io_error(error),
        })?;
    let metadata = file.metadata().map_err(io_error)?;
    if !metadata.is_file() {
        return Err(StoreError::Invalid);
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if !owned_by_me(&metadata) || metadata.permissions().mode() & 0o077 != 0 {
            return Err(StoreError::Denied);
        }
    }
    let mut bytes = Vec::new();
    file.take(MAX_ENTRY + 1)
        .read_to_end(&mut bytes)
        .map_err(io_error)?;
    if bytes.len() as u64 > MAX_ENTRY {
        return Err(StoreError::Invalid);
    }
    Ok(bytes)
}

/// A new owner-only temporary file next to `path`, written and fsynced.
fn write_temporary(dir: &Path, bytes: &[u8]) -> Result<PathBuf, StoreError> {
    let mut nonce = [0_u8; 8];
    getrandom::getrandom(&mut nonce).map_err(|_| StoreError::Unavailable)?;
    let name: String = nonce.iter().map(|b| format!("{b:02x}")).collect();
    let temporary = dir.join(format!(".{name}.tmp"));
    let mut options = fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600).custom_flags(libc::O_NOFOLLOW);
    }
    let mut file = options.open(&temporary).map_err(io_error)?;
    let written = file.write_all(bytes).and_then(|_| file.sync_all());
    if let Err(error) = written {
        let _ = fs::remove_file(&temporary);
        return Err(io_error(error));
    }
    Ok(temporary)
}

fn sync_dir(dir: &Path) {
    // Durability of the rename/link itself; best effort where unsupported.
    if let Ok(handle) = fs::File::open(dir) {
        let _ = handle.sync_all();
    }
}

/// Create `path` with `bytes`, owner-only, atomically and never replacing it.
pub(crate) fn create_private(path: &Path, bytes: &[u8]) -> Result<(), StoreError> {
    let dir = path.parent().ok_or(StoreError::Invalid)?;
    let temporary = write_temporary(dir, bytes)?;
    let linked = fs::hard_link(&temporary, path);
    let _ = fs::remove_file(&temporary);
    linked.map_err(io_error)?;
    sync_dir(dir);
    Ok(())
}

/// Replace `path` with `bytes`, owner-only and atomically.
pub(crate) fn replace_private(path: &Path, bytes: &[u8]) -> Result<(), StoreError> {
    let dir = path.parent().ok_or(StoreError::Invalid)?;
    let temporary = write_temporary(dir, bytes)?;
    if let Err(error) = fs::rename(&temporary, path) {
        let _ = fs::remove_file(&temporary);
        return Err(io_error(error));
    }
    sync_dir(dir);
    Ok(())
}

impl CredentialStore for FileStore {
    /// Descriptors of the readable, well-formed entries; anything else in the
    /// directory is skipped. Never returns secrets.
    fn list(&self) -> Result<Vec<Descriptor>, StoreError> {
        let mut list: Vec<Descriptor> = fs::read_dir(&self.dir)
            .map_err(io_error)?
            .filter_map(Result::ok)
            .filter_map(|entry| {
                let name = entry.file_name().into_string().ok()?;
                let id = name.strip_suffix(".json")?;
                self.load(id).ok().map(|entry| entry.descriptor)
            })
            .collect();
        list.sort_by(|a, b| a.id.cmp(&b.id));
        Ok(list)
    }

    fn create(&self, descriptor: Descriptor, secret: Secret) -> Result<(), StoreError> {
        let path = self.path(&descriptor.id)?;
        create_private(&path, &Self::encode(descriptor, secret.expose())?)
    }

    fn disable(&self, id: &str) -> Result<(), StoreError> {
        let mut entry = self.load(id)?;
        entry.descriptor.disabled = true;
        let secret = base64::engine::general_purpose::STANDARD
            .decode(&entry.secret)
            .map_err(|_| StoreError::Invalid)?;
        replace_private(&self.path(id)?, &Self::encode(entry.descriptor, &secret)?)
    }

    fn use_secret(
        &self,
        id: &str,
        audience: &Audience,
        scope: &Scope,
        now: u64,
    ) -> Result<Secret, StoreError> {
        let entry = self.load(id)?;
        if !entry.descriptor.permits(audience, scope, now) {
            return Err(StoreError::Denied);
        }
        base64::engine::general_purpose::STANDARD
            .decode(&entry.secret)
            .map(Secret::new)
            .map_err(|_| StoreError::Invalid)
    }
}

impl FileStore {
    /// The stored descriptor for `id` (no secret).
    pub fn descriptor(&self, id: &str) -> Result<Descriptor, StoreError> {
        self.load(id).map(|entry| entry.descriptor)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::credentials::CredentialKind;

    fn descriptor(id: &str) -> Descriptor {
        Descriptor {
            id: id.into(),
            kind: CredentialKind::DashBearer,
            audience: Audience {
                endpoint: "https://dash.example/api/rbq/x".into(),
                account_id: "https://dash.example".into(),
                repository_id: "repository".into(),
            },
            scopes: vec![Scope::Read],
            created_at: 100,
            expires_at: 200,
            disabled: false,
        }
    }

    fn store() -> (tempfile::TempDir, FileStore) {
        let root = tempfile::tempdir().unwrap();
        let store = FileStore::open(&root.path().join("credentials")).unwrap();
        (root, store)
    }

    #[test]
    fn create_is_atomic_no_clobber_and_secrets_stay_out_of_listings() {
        let (_root, store) = store();
        let entry = descriptor("key-1");
        store
            .create(entry.clone(), Secret::new(b"rbs_secret".to_vec()))
            .unwrap();
        assert_eq!(
            store.create(entry.clone(), Secret::new(b"other".to_vec())),
            Err(StoreError::Conflict)
        );
        let listed = store.list().unwrap();
        assert_eq!(listed, vec![entry.clone()]);
        assert!(
            !serde_json::to_string(&listed)
                .unwrap()
                .contains("rbs_secret")
        );
        let secret = store
            .use_secret("key-1", &entry.audience, &Scope::Read, 150)
            .unwrap();
        assert_eq!(secret.expose(), b"rbs_secret");
        // No temporary files left behind.
        let names: Vec<_> = fs::read_dir(store.dir())
            .unwrap()
            .map(|e| e.unwrap().file_name())
            .collect();
        assert_eq!(names, vec![std::ffi::OsString::from("key-1.json")]);
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = |p: &Path| fs::metadata(p).unwrap().permissions().mode() & 0o777;
            assert_eq!(mode(store.dir()), 0o700);
            assert_eq!(mode(&store.dir().join("key-1.json")), 0o600);
        }
    }

    #[test]
    fn use_checks_the_stored_grant_and_disable_is_durable() {
        let (_root, store) = store();
        let entry = descriptor("key-2");
        store
            .create(entry.clone(), Secret::new(b"s".to_vec()))
            .unwrap();
        for (scope, now) in [(Scope::Append, 150), (Scope::Read, 200), (Scope::Read, 99)] {
            assert_eq!(
                store
                    .use_secret("key-2", &entry.audience, &scope, now)
                    .map(|_| ()),
                Err(StoreError::Denied)
            );
        }
        let mut other = entry.audience.clone();
        other.repository_id = "elsewhere".into();
        assert!(
            store
                .use_secret("key-2", &other, &Scope::Read, 150)
                .is_err()
        );
        store.disable("key-2").unwrap();
        assert!(store.descriptor("key-2").unwrap().disabled);
        assert!(
            store
                .use_secret("key-2", &entry.audience, &Scope::Read, 150)
                .is_err()
        );
        assert_eq!(store.disable("missing"), Err(StoreError::NotFound));
        assert_eq!(store.disable("../escape"), Err(StoreError::Invalid));
    }

    #[cfg(unix)]
    #[test]
    fn open_permissions_symlinks_and_tampering_are_refused() {
        use std::os::unix::fs::PermissionsExt;
        let (root, store) = store();
        let entry = descriptor("key-3");
        store
            .create(entry.clone(), Secret::new(b"s".to_vec()))
            .unwrap();
        // A group-readable entry is refused, not used.
        let path = store.dir().join("key-3.json");
        fs::set_permissions(&path, fs::Permissions::from_mode(0o640)).unwrap();
        assert_eq!(
            store
                .use_secret("key-3", &entry.audience, &Scope::Read, 150)
                .map(|_| ()),
            Err(StoreError::Denied)
        );
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
        // A symlink standing in for an entry is refused.
        let outside = root.path().join("outside.json");
        fs::copy(&path, &outside).unwrap();
        fs::set_permissions(&outside, fs::Permissions::from_mode(0o600)).unwrap();
        std::os::unix::fs::symlink(&outside, store.dir().join("key-4.json")).unwrap();
        assert!(store.descriptor("key-4").is_err());
        // An entry whose id does not match its file name is refused.
        fs::copy(&path, store.dir().join("key-5.json")).unwrap();
        fs::set_permissions(
            store.dir().join("key-5.json"),
            fs::Permissions::from_mode(0o600),
        )
        .unwrap();
        assert_eq!(
            store.descriptor("key-5").map(|_| ()),
            Err(StoreError::Invalid)
        );
        assert_eq!(store.list().unwrap(), vec![entry]);
        // A directory open to others is refused.
        let open = root.path().join("open");
        fs::create_dir(&open).unwrap();
        fs::set_permissions(&open, fs::Permissions::from_mode(0o755)).unwrap();
        assert_eq!(FileStore::open(&open).map(|_| ()), Err(StoreError::Denied));
    }
}
