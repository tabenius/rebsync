//! A narrow storage contract for Rebsync-managed objects.
//!
//! This is the client-side interface, not an S3 or restic REST server. The
//! filesystem adapter publishes through Apache `object_store`, so publication,
//! durability and create-if-absent behavior are explicit and testable.
//!
//! Deletion exists because storage backends and administrative maintenance need
//! it, but no synchronization policy in this crate propagates deletions.

use chrono::{DateTime, Utc};
use std::fmt;
use std::ops::Range;

/// Largest key accepted by the storage boundary. S3 permits 1024 UTF-8 bytes.
pub const MAX_KEY_BYTES: usize = 1024;

/// A validated, slash-separated object key.
///
/// Keys are restricted to ASCII letters, digits, `.`, `-`, `_` and `/`. This is
/// deliberately narrower than S3. It keeps filesystem mapping predictable and
/// rejects traversal, empty segments and Windows-hostile separators at the
/// boundary rather than hoping every backend agrees.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ObjectKey(String);

impl ObjectKey {
    pub fn parse(value: &str) -> Result<Self, StorageError> {
        if value.is_empty() {
            return Err(StorageError::InvalidKey("key is empty".into()));
        }
        if value.len() > MAX_KEY_BYTES {
            return Err(StorageError::InvalidKey(format!(
                "key exceeds {MAX_KEY_BYTES} bytes"
            )));
        }
        if value.starts_with('/') || value.ends_with('/') {
            return Err(StorageError::InvalidKey(
                "key must not start or end with '/'".into(),
            ));
        }
        for segment in value.split('/') {
            validate_segment(segment)?;
        }
        Ok(Self(value.to_owned()))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for ObjectKey {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.0)
    }
}

/// Validate a raw-prefix query. A prefix may end mid-segment, but never contain
/// an empty or traversal segment.
pub fn validate_prefix(prefix: &str) -> Result<(), StorageError> {
    if prefix.is_empty() {
        return Ok(());
    }
    if prefix.len() > MAX_KEY_BYTES {
        return Err(StorageError::InvalidKey(format!(
            "prefix exceeds {MAX_KEY_BYTES} bytes"
        )));
    }
    if prefix.starts_with('/') {
        return Err(StorageError::InvalidKey(
            "prefix must not start with '/'".into(),
        ));
    }
    for segment in prefix.trim_end_matches('/').split('/') {
        validate_segment(segment)?;
    }
    Ok(())
}

fn validate_segment(segment: &str) -> Result<(), StorageError> {
    if segment.is_empty() {
        return Err(StorageError::InvalidKey("empty path segment".into()));
    }
    if segment == "." || segment == ".." {
        return Err(StorageError::InvalidKey(
            "path traversal segment is not allowed".into(),
        ));
    }
    if segment.len() > 255 {
        return Err(StorageError::InvalidKey(
            "path segment exceeds 255 bytes".into(),
        ));
    }
    if !segment
        .bytes()
        .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'-' | b'_'))
    {
        return Err(StorageError::InvalidKey(format!(
            "unsupported character in segment {segment:?}"
        )));
    }
    Ok(())
}

/// Metadata about a stored object. ETags are opaque backend validators and are
/// not content hashes; do not compare them across providers.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ObjectMeta {
    pub key: String,
    pub size: u64,
    pub last_modified: Option<DateTime<Utc>>,
    pub etag: Option<String>,
}

impl ObjectMeta {
    #[cfg(feature = "storage-object-store")]
    fn for_input(key: &ObjectKey, size: usize, etag: Option<String>) -> Self {
        Self {
            key: key.as_str().to_owned(),
            size: size as u64,
            last_modified: None,
            etag,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum PutOutcome {
    Created(ObjectMeta),
    AlreadyExists(ObjectMeta),
}

/// What a backend actually promises. Adapters must not claim more than they can
/// demonstrate; notably, `durable_publication` is a deployment property as much
/// as a library one.
#[derive(Clone, Copy, Debug)]
pub struct StorageCapabilities {
    /// False on filesystems without hard links (FAT/exFAT SD cards, USB
    /// sticks, Android shared storage): create-if-absent then degrades to
    /// check-then-rename, which is only safe with a single writer.
    pub atomic_create_if_absent: bool,
    /// False where the filesystem ignores or refuses Unix permissions.
    pub owner_only_permissions: bool,
    pub durable_publication: bool,
    pub range_reads: bool,
    pub raw_prefix_listing: bool,
    pub max_key_bytes: usize,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum StorageError {
    InvalidKey(String),
    NotFound(String),
    AlreadyExists(String),
    PermissionDenied(String),
    Unavailable(String),
    Corrupt(String),
    Unsupported(String),
    Backend(String),
}

impl fmt::Display for StorageError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidKey(message) => write!(formatter, "invalid object key: {message}"),
            Self::NotFound(key) => write!(formatter, "object not found: {key}"),
            Self::AlreadyExists(key) => write!(formatter, "object already exists: {key}"),
            Self::PermissionDenied(message) => write!(formatter, "permission denied: {message}"),
            Self::Unavailable(message) => write!(formatter, "storage unavailable: {message}"),
            Self::Corrupt(message) => write!(formatter, "storage integrity failure: {message}"),
            Self::Unsupported(message) => write!(formatter, "unsupported operation: {message}"),
            Self::Backend(message) => write!(formatter, "storage backend error: {message}"),
        }
    }
}

impl std::error::Error for StorageError {}

/// The operations Rebsync needs from an object store.
///
/// Methods are synchronous so the rest of the crate stays runtime-agnostic and
/// the CLI does not become an async program. Adapters may own an internal
/// runtime; they must not require callers to enter one.
pub trait ObjectStorage: Send + Sync {
    fn capabilities(&self) -> StorageCapabilities;

    /// Create or replace an object.
    fn put(&self, key: &ObjectKey, data: &[u8]) -> Result<ObjectMeta, StorageError>;

    /// Create only when absent, without a separate HEAD-then-PUT race.
    fn put_if_absent(&self, key: &ObjectKey, data: &[u8]) -> Result<PutOutcome, StorageError>;

    fn get(&self, key: &ObjectKey) -> Result<Vec<u8>, StorageError>;

    fn get_range(&self, key: &ObjectKey, range: Range<u64>) -> Result<Vec<u8>, StorageError>;

    fn head(&self, key: &ObjectKey) -> Result<ObjectMeta, StorageError>;

    /// Raw string-prefix listing, not path-segment listing. Results are sorted
    /// by key. `limit` of zero means "no explicit limit".
    fn list_prefix(&self, prefix: &str, limit: usize) -> Result<Vec<ObjectMeta>, StorageError>;

    /// Deletion is available to storage policy and administration. Callers must
    /// not use it to propagate repository deletions between peers.
    fn delete(&self, key: &ObjectKey) -> Result<(), StorageError>;
}

#[cfg(feature = "storage-object-store")]
mod object_store_fs {
    use super::*;
    use futures::TryStreamExt;
    use object_store::{
        ObjectStore, ObjectStoreExt, PutMode, PutOptions, local::LocalFileSystem,
        path::Path as StorePath,
    };
    use std::path::{Path, PathBuf};
    use std::sync::Arc;

    /// Filesystem adapter using `object_store::local::LocalFileSystem`.
    pub struct FsObjectStorage {
        root: PathBuf,
        store: Arc<dyn ObjectStore>,
        runtime: tokio::runtime::Runtime,
        hard_links: bool,
        owner_only: bool,
    }

    /// Hard links back object_store's create-if-absent. Probe once per open
    /// instead of failing every write on filesystems that lack them.
    fn probe_hard_links(root: &Path) -> bool {
        let nonce = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or_default();
        let source = root.join(format!(
            ".rebsync-link-probe-{}-{nonce}",
            std::process::id()
        ));
        let link = root.join(format!(
            ".rebsync-link-probe-{}-{nonce}.link",
            std::process::id()
        ));
        let supported =
            std::fs::write(&source, b"probe").is_ok() && std::fs::hard_link(&source, &link).is_ok();
        let _ = std::fs::remove_file(&link);
        let _ = std::fs::remove_file(&source);
        supported
    }

    impl FsObjectStorage {
        /// Open or create a dedicated object root. The root is created with
        /// owner-only permissions when this adapter creates it.
        pub fn open(root: impl AsRef<Path>) -> Result<Self, StorageError> {
            let requested = root.as_ref();
            if requested.as_os_str().is_empty() {
                return Err(StorageError::InvalidKey("storage root is empty".into()));
            }
            let created = !requested.exists();
            std::fs::create_dir_all(requested).map_err(|error| {
                StorageError::Unavailable(format!(
                    "create storage root {}: {error}",
                    requested.display()
                ))
            })?;
            #[cfg(unix)]
            let owner_only = {
                use std::os::unix::fs::PermissionsExt;
                if created {
                    // FAT/exFAT and Android shared storage refuse or ignore
                    // chmod; record that instead of refusing removable media.
                    let _ =
                        std::fs::set_permissions(requested, std::fs::Permissions::from_mode(0o700));
                }
                std::fs::metadata(requested)
                    .map(|meta| meta.permissions().mode() & 0o077 == 0)
                    .unwrap_or(false)
            };
            #[cfg(not(unix))]
            let owner_only = false;
            let canonical = std::fs::canonicalize(requested).map_err(|error| {
                StorageError::Unavailable(format!(
                    "resolve storage root {}: {error}",
                    requested.display()
                ))
            })?;
            let store = LocalFileSystem::new_with_prefix(&canonical)
                .map_err(map_object_store_error)?
                .with_fsync(true);
            let runtime = tokio::runtime::Builder::new_current_thread()
                .build()
                .map_err(|error| {
                    StorageError::Unavailable(format!("create storage runtime: {error}"))
                })?;
            let hard_links = probe_hard_links(&canonical);
            Ok(Self {
                root: canonical,
                store: Arc::new(store),
                runtime,
                hard_links,
                owner_only,
            })
        }

        /// Test hook: behave as on a filesystem without hard links.
        #[doc(hidden)]
        pub fn without_hard_links(mut self) -> Self {
            self.hard_links = false;
            self
        }

        pub fn root(&self) -> &Path {
            &self.root
        }

        fn path(key: &ObjectKey) -> Result<StorePath, StorageError> {
            StorePath::parse(key.as_str())
                .map_err(|error| StorageError::InvalidKey(format!("{}: {error}", key.as_str())))
        }

        fn guard(&self, key: &str) -> Result<(), StorageError> {
            ensure_no_symlink_components(&self.root, key)
        }

        fn block_on<F, T>(&self, future: F) -> Result<T, StorageError>
        where
            F: std::future::Future<Output = Result<T, object_store::Error>>,
        {
            self.runtime
                .block_on(future)
                .map_err(map_object_store_error)
        }
    }

    impl ObjectStorage for FsObjectStorage {
        fn capabilities(&self) -> StorageCapabilities {
            StorageCapabilities {
                atomic_create_if_absent: self.hard_links,
                owner_only_permissions: self.owner_only,
                durable_publication: true,
                range_reads: true,
                raw_prefix_listing: true,
                max_key_bytes: MAX_KEY_BYTES,
            }
        }

        fn put(&self, key: &ObjectKey, data: &[u8]) -> Result<ObjectMeta, StorageError> {
            self.guard(key.as_str())?;
            let path = Self::path(key)?;
            let result = self.block_on(self.store.put(&path, data.to_vec().into()))?;
            Ok(ObjectMeta::for_input(key, data.len(), result.e_tag))
        }

        fn put_if_absent(&self, key: &ObjectKey, data: &[u8]) -> Result<PutOutcome, StorageError> {
            self.guard(key.as_str())?;
            let path = Self::path(key)?;
            if !self.hard_links {
                // Check-then-rename: atomic publication (staged rename) but
                // not atomic against a concurrent creator. Single writer only.
                return match self.head(key) {
                    Ok(meta) => Ok(PutOutcome::AlreadyExists(meta)),
                    Err(StorageError::NotFound(_)) => Ok(PutOutcome::Created(self.put(key, data)?)),
                    Err(error) => Err(error),
                };
            }
            let options = PutOptions {
                mode: PutMode::Create,
                ..Default::default()
            };
            match self.block_on(self.store.put_opts(&path, data.to_vec().into(), options)) {
                Ok(result) => Ok(PutOutcome::Created(ObjectMeta::for_input(
                    key,
                    data.len(),
                    result.e_tag,
                ))),
                Err(StorageError::AlreadyExists(_)) => {
                    Ok(PutOutcome::AlreadyExists(self.head(key)?))
                }
                Err(error) => Err(error),
            }
        }

        fn get(&self, key: &ObjectKey) -> Result<Vec<u8>, StorageError> {
            self.guard(key.as_str())?;
            let path = Self::path(key)?;
            let bytes = self.block_on(async {
                let result = self.store.get(&path).await?;
                result.bytes().await
            })?;
            Ok(bytes.to_vec())
        }

        fn get_range(&self, key: &ObjectKey, range: Range<u64>) -> Result<Vec<u8>, StorageError> {
            self.guard(key.as_str())?;
            if range.start >= range.end {
                return Err(StorageError::InvalidKey(format!(
                    "empty or inverted range {}..{}",
                    range.start, range.end
                )));
            }
            let path = Self::path(key)?;
            let bytes = self
                .runtime
                .block_on(self.store.get_range(&path, range))
                .map_err(map_object_store_error)?;
            Ok(bytes.to_vec())
        }

        fn head(&self, key: &ObjectKey) -> Result<ObjectMeta, StorageError> {
            self.guard(key.as_str())?;
            let path = Self::path(key)?;
            let meta = self.block_on(self.store.head(&path))?;
            Ok(ObjectMeta {
                key: key.as_str().to_owned(),
                size: meta.size,
                last_modified: Some(meta.last_modified),
                etag: meta.e_tag,
            })
        }

        fn list_prefix(&self, prefix: &str, limit: usize) -> Result<Vec<ObjectMeta>, StorageError> {
            validate_prefix(prefix)?;
            self.guard(prefix.trim_end_matches('/'))?;
            let ancestor = prefix
                .trim_end_matches('/')
                .rsplit_once('/')
                .map(|(parent, _)| parent.to_owned())
                .unwrap_or_default();
            let base =
                if ancestor.is_empty() {
                    None
                } else {
                    Some(StorePath::parse(&ancestor).map_err(|error| {
                        StorageError::InvalidKey(format!("{ancestor}: {error}"))
                    })?)
                };
            let mut found = self.runtime.block_on(async {
                let mut stream = self.store.list(base.as_ref());
                let mut found = Vec::new();
                while let Some(meta) = stream.try_next().await.map_err(map_object_store_error)? {
                    if meta.location.as_ref().starts_with(prefix) {
                        found.push(ObjectMeta {
                            key: meta.location.to_string(),
                            size: meta.size,
                            last_modified: Some(meta.last_modified),
                            etag: meta.e_tag,
                        });
                    }
                }
                Ok::<_, StorageError>(found)
            })?;
            found.sort_by(|left, right| left.key.cmp(&right.key));
            if limit > 0 {
                found.truncate(limit);
            }
            Ok(found)
        }

        fn delete(&self, key: &ObjectKey) -> Result<(), StorageError> {
            self.guard(key.as_str())?;
            let path = Self::path(key)?;
            self.block_on(self.store.delete(&path))
        }
    }

    fn map_object_store_error(error: object_store::Error) -> StorageError {
        match error {
            object_store::Error::NotFound { path, .. } => StorageError::NotFound(path),
            object_store::Error::AlreadyExists { path, .. } => StorageError::AlreadyExists(path),
            object_store::Error::Precondition { path, .. } => StorageError::AlreadyExists(path),
            object_store::Error::NotSupported { source } => {
                StorageError::Unsupported(source.to_string())
            }
            object_store::Error::NotImplemented { operation, .. } => {
                StorageError::Unsupported(format!("{operation} is not implemented"))
            }
            other => StorageError::Backend(other.to_string()),
        }
    }

    /// Reject a symlink at any key component, including the leaf, so a hostile
    /// or accidental link cannot redirect storage outside the dedicated root.
    /// The leaf matters: `get`, `put` and `head` all follow it, and a link
    /// would otherwise read or write outside the root.
    fn ensure_no_symlink_components(root: &Path, key: &str) -> Result<(), StorageError> {
        let segments: Vec<&str> = key
            .split('/')
            .filter(|segment| !segment.is_empty())
            .collect();
        let mut current = root.to_path_buf();
        for segment in segments {
            current.push(segment);
            match std::fs::symlink_metadata(&current) {
                Ok(meta) if meta.file_type().is_symlink() => {
                    return Err(StorageError::PermissionDenied(format!(
                        "refusing symlinked path component {}",
                        current.display()
                    )));
                }
                Ok(_) => {}
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => break,
                Err(error) => {
                    return Err(StorageError::Unavailable(format!(
                        "inspect {}: {error}",
                        current.display()
                    )));
                }
            }
        }
        Ok(())
    }
}

#[cfg(feature = "storage-object-store")]
pub use object_store_fs::FsObjectStorage;

#[cfg(all(test, feature = "storage-object-store"))]
mod tests {
    use super::*;

    fn adapter() -> (tempfile::TempDir, FsObjectStorage) {
        let directory = tempfile::tempdir().unwrap();
        let storage = FsObjectStorage::open(directory.path().join("objects")).unwrap();
        (directory, storage)
    }

    #[test]
    fn rejects_unsafe_keys_and_prefixes() {
        for key in [
            "",
            "/absolute",
            "trailing/",
            "empty//segment",
            ".",
            "..",
            "a/../b",
            "a/./b",
            "back\\slash",
            "spaces here",
            "control\u{7}",
        ] {
            assert!(ObjectKey::parse(key).is_err(), "accepted key {key:?}");
        }
        for key in ["a", "a/b", ".hidden", "a-b_c.d/e"] {
            assert!(ObjectKey::parse(key).is_ok(), "rejected key {key:?}");
        }
        for prefix in ["..", "/absolute", "a//b", "a/../b"] {
            assert!(
                validate_prefix(prefix).is_err(),
                "accepted prefix {prefix:?}"
            );
        }
        for prefix in ["", "data/it", "data/"] {
            assert!(
                validate_prefix(prefix).is_ok(),
                "rejected prefix {prefix:?}"
            );
        }
    }

    #[test]
    fn round_trip_range_and_delete() {
        let (_directory, storage) = adapter();
        let key = ObjectKey::parse("data/item").unwrap();
        assert_eq!(storage.put(&key, b"abcdefghij").unwrap().size, 10);
        assert_eq!(storage.get(&key).unwrap(), b"abcdefghij");
        assert_eq!(storage.get_range(&key, 2..5).unwrap(), b"cde");
        assert_eq!(storage.head(&key).unwrap().size, 10);
        storage.delete(&key).unwrap();
        assert!(matches!(storage.get(&key), Err(StorageError::NotFound(_))));
        assert!(matches!(storage.head(&key), Err(StorageError::NotFound(_))));
        assert!(matches!(
            storage.get_range(&key, 2..2),
            Err(StorageError::InvalidKey(_))
        ));
    }

    #[test]
    fn listing_uses_raw_string_prefixes() {
        let (_directory, storage) = adapter();
        for key in ["data/item", "data/item-extra", "data/other", "data2/item"] {
            storage.put(&ObjectKey::parse(key).unwrap(), b"x").unwrap();
        }
        let keys = |prefix: &str, limit: usize| {
            storage
                .list_prefix(prefix, limit)
                .unwrap()
                .into_iter()
                .map(|meta| meta.key)
                .collect::<Vec<_>>()
        };
        assert_eq!(keys("data/item", 0), vec!["data/item", "data/item-extra"]);
        assert_eq!(
            keys("data/", 0),
            vec!["data/item", "data/item-extra", "data/other"]
        );
        assert_eq!(keys("", 0).len(), 4);
        assert_eq!(keys("data/", 1).len(), 1);
    }

    #[test]
    fn create_if_absent_does_not_replace_existing_data() {
        let (_directory, storage) = adapter();
        let key = ObjectKey::parse("claims/lease").unwrap();
        assert!(matches!(
            storage.put_if_absent(&key, b"first"),
            Ok(PutOutcome::Created(_))
        ));
        assert!(matches!(
            storage.put_if_absent(&key, b"second"),
            Ok(PutOutcome::AlreadyExists(meta)) if meta.size == 5
        ));
        assert_eq!(storage.get(&key).unwrap(), b"first");
    }

    #[test]
    fn create_if_absent_without_hard_links_still_never_replaces() {
        let directory = tempfile::tempdir().unwrap();
        let storage = FsObjectStorage::open(directory.path().join("objects"))
            .unwrap()
            .without_hard_links();
        assert!(!storage.capabilities().atomic_create_if_absent);
        let key = ObjectKey::parse("claims/lease").unwrap();
        assert!(matches!(
            storage.put_if_absent(&key, b"first"),
            Ok(PutOutcome::Created(_))
        ));
        assert!(matches!(
            storage.put_if_absent(&key, b"second"),
            Ok(PutOutcome::AlreadyExists(meta)) if meta.size == 5
        ));
        assert_eq!(storage.get(&key).unwrap(), b"first");
        // No probe files are left in the root.
        assert!(storage.list_prefix("", 0).unwrap().len() == 1);
    }

    #[test]
    fn normal_filesystems_report_atomic_create_and_owner_only() {
        let (_directory, storage) = adapter();
        let capabilities = storage.capabilities();
        assert!(capabilities.atomic_create_if_absent);
        #[cfg(unix)]
        assert!(capabilities.owner_only_permissions);
    }

    #[cfg(unix)]
    #[test]
    fn refuses_symlinked_ancestors() {
        let directory = tempfile::tempdir().unwrap();
        let outside = directory.path().join("outside");
        std::fs::create_dir(&outside).unwrap();
        let storage = FsObjectStorage::open(directory.path().join("objects")).unwrap();
        std::os::unix::fs::symlink(&outside, directory.path().join("objects/escape")).unwrap();
        let key = ObjectKey::parse("escape/secret").unwrap();
        assert!(matches!(
            storage.put(&key, b"x"),
            Err(StorageError::PermissionDenied(_))
        ));
        assert!(!outside.join("secret").exists());
    }

    #[cfg(unix)]
    #[test]
    fn refuses_symlinked_leaf() {
        let directory = tempfile::tempdir().unwrap();
        let outside = directory.path().join("outside");
        std::fs::create_dir(&outside).unwrap();
        let secret = outside.join("secret");
        std::fs::write(&secret, b"outside").unwrap();
        let storage = FsObjectStorage::open(directory.path().join("objects")).unwrap();
        std::os::unix::fs::symlink(&secret, storage.root().join("leaf")).unwrap();
        let key = ObjectKey::parse("leaf").unwrap();
        for result in [
            storage.put(&key, b"x").map(|_| ()),
            storage.put_if_absent(&key, b"x").map(|_| ()),
            storage.get(&key).map(|_| ()),
            storage.head(&key).map(|_| ()),
            storage.delete(&key),
        ] {
            assert!(
                matches!(result, Err(StorageError::PermissionDenied(_))),
                "followed symlinked leaf: {result:?}"
            );
        }
        assert_eq!(std::fs::read(&secret).unwrap(), b"outside");
    }
}
