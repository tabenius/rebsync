//! Staged, resumable uploads.
//!
//! A large `put` arrives in parts that are appended to a staging file on
//! disk, so the server holds one part in memory, not the object. If the link
//! breaks, the client asks how much is staged (`put_start`) and continues
//! from there. Nothing is visible in the store until `put_commit`, which
//! verifies the whole staged file (a chunk's SHA-256 against its address,
//! computed while reading; a manifest's full admission check) and then
//! creates the object if absent, from the file.
//!
//! One staging file per object key. Content-addressed chunks have one
//! possible content, so two clients uploading the same chunk at once write
//! the same bytes; anything that does not verify at commit is discarded and
//! never published. Staging is bounded in total bytes and stale uploads are
//! removed.

use super::super::{
    peer,
    storage::{ObjectKey, ObjectStorage, PutOutcome},
};
use anyhow::{Context, Result, bail, ensure};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    fs,
    io::{Read, Seek, SeekFrom, Write},
    path::{Path, PathBuf},
    sync::Mutex,
    time::{Duration, SystemTime},
};

/// Bytes all unfinished staged uploads may occupy together.
pub const STAGING_BUDGET: u64 = 1024 * 1024 * 1024;
/// A staged upload untouched for this long is removed.
const STALE: Duration = Duration::from_secs(24 * 3600);
/// Manifests are verified in memory; anything larger must be a chunk.
const MAX_IN_MEMORY_CHECK: u64 = 16 * 1024 * 1024;

#[derive(Serialize, Deserialize)]
struct Meta {
    key: String,
    size: u64,
}

/// Where `rbq peer serve` stages uploads: `staging/` under rbq's state
/// directory.
pub fn default_staging_dir(config: &crate::Config) -> Result<PathBuf> {
    Ok(crate::sync::state_dir(config)?.join("staging"))
}

/// The staging area of one server.
pub struct Staging {
    dir: PathBuf,
    lock: Mutex<()>,
}

/// Why a staged operation was refused, with the HTTP-like code to answer.
#[derive(Debug)]
pub struct Refusal {
    pub code: u16,
    pub message: String,
}

impl Refusal {
    fn new(code: u16, message: impl Into<String>) -> Self {
        Self {
            code,
            message: message.into(),
        }
    }
}

impl From<anyhow::Error> for Refusal {
    fn from(error: anyhow::Error) -> Self {
        Self::new(500, format!("{error:#}"))
    }
}

impl Staging {
    /// A staging area in `dir` (created owner-only).
    pub fn open(dir: &Path) -> Result<Self> {
        fs::create_dir_all(dir)
            .with_context(|| format!("create staging directory {}", dir.display()))?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(dir, fs::Permissions::from_mode(0o700))?;
        }
        Ok(Self {
            dir: dir.to_path_buf(),
            lock: Mutex::new(()),
        })
    }

    fn paths(&self, key: &str) -> (PathBuf, PathBuf) {
        let name = crate::wire::sha256_hex(key.as_bytes());
        (
            self.dir.join(format!("{name}.part")),
            self.dir.join(format!("{name}.meta")),
        )
    }

    fn guard(&self) -> Result<std::sync::MutexGuard<'_, ()>, Refusal> {
        self.lock
            .lock()
            .map_err(|_| Refusal::new(500, "staging lock poisoned"))
    }

    fn meta(path: &Path) -> Option<Meta> {
        serde_json::from_slice(&fs::read(path).ok()?).ok()
    }

    /// Remove stale uploads and return the bytes the rest may still grow to.
    fn reserved(&self, except: &Path) -> u64 {
        let mut reserved = 0;
        let Ok(entries) = fs::read_dir(&self.dir) else {
            return 0;
        };
        for entry in entries.filter_map(Result::ok) {
            let path = entry.path();
            if path.extension().is_none_or(|e| e != "meta") || path == except {
                continue;
            }
            let part = path.with_extension("part");
            let stale = fs::metadata(&part)
                .and_then(|m| m.modified())
                .ok()
                .and_then(|modified| SystemTime::now().duration_since(modified).ok())
                .is_none_or(|age| age > STALE);
            match Self::meta(&path) {
                Some(meta) if !stale => reserved += meta.size,
                _ => {
                    let _ = fs::remove_file(&part);
                    let _ = fs::remove_file(&path);
                }
            }
        }
        reserved
    }

    /// Begin or resume an upload of `size` bytes; returns the bytes already
    /// staged for it.
    pub fn start(&self, key: &str, size: u64) -> Result<u64, Refusal> {
        let _guard = self.guard()?;
        let (part, meta_path) = self.paths(key);
        if let Some(meta) = Self::meta(&meta_path)
            && meta.key == key
            && meta.size == size
            && let Ok(staged) = fs::metadata(&part)
            && staged.len() <= size
        {
            return Ok(staged.len());
        }
        if self.reserved(&meta_path) + size > STAGING_BUDGET {
            return Err(Refusal::new(
                503,
                "too many uploads in progress; retry later",
            ));
        }
        let start = || -> Result<()> {
            // A fresh, empty, owner-only part file, and the record of what it
            // is for (written last, so a part without a record is ignored).
            private_file(&part)?;
            let mut file = private_file(&meta_path)?;
            file.write_all(&serde_json::to_vec(&Meta {
                key: key.to_owned(),
                size,
            })?)?;
            Ok(())
        };
        start()?;
        Ok(0)
    }

    /// Append `bytes` at `offset`, which must be exactly what is staged.
    /// Returns the new staged length.
    pub fn append(&self, key: &str, offset: u64, bytes: &[u8]) -> Result<u64, Refusal> {
        let _guard = self.guard()?;
        let (part, meta_path) = self.paths(key);
        let meta = Self::meta(&meta_path)
            .filter(|meta| meta.key == key)
            .ok_or_else(|| Refusal::new(409, "no upload in progress; start again"))?;
        let mut file = fs::OpenOptions::new()
            .append(true)
            .open(&part)
            .map_err(|_| Refusal::new(409, "no upload in progress; start again"))?;
        let staged = file.metadata().map_err(anyhow::Error::from)?.len();
        if staged != offset {
            return Err(Refusal::new(
                409,
                format!("staged {staged} bytes, not {offset}; resume from {staged}"),
            ));
        }
        if offset + bytes.len() as u64 > meta.size {
            return Err(Refusal::new(400, "part runs past the declared size"));
        }
        file.write_all(bytes).map_err(anyhow::Error::from)?;
        Ok(offset + bytes.len() as u64)
    }

    /// Verify the complete staged upload and create the object if absent.
    pub fn commit(
        &self,
        key: &str,
        size: u64,
        storage: &dyn ObjectStorage,
    ) -> Result<PutOutcome, Refusal> {
        let _guard = self.guard()?;
        let (part, meta_path) = self.paths(key);
        let meta = Self::meta(&meta_path)
            .filter(|meta| meta.key == key && meta.size == size)
            .ok_or_else(|| Refusal::new(409, "no upload in progress; start again"))?;
        let discard = || {
            let _ = fs::remove_file(&part);
            let _ = fs::remove_file(&meta_path);
        };
        let staged = fs::metadata(&part)
            .map_err(|_| Refusal::new(409, "no upload in progress; start again"))?
            .len();
        if staged != meta.size {
            return Err(Refusal::new(
                409,
                format!("staged {staged} of {} bytes; send the rest", meta.size),
            ));
        }
        if let Err(error) = verify(key, &part, staged) {
            // Never publish what does not verify; the client starts over.
            discard();
            return Err(Refusal::new(400, format!("{error:#}")));
        }
        fs::File::open(&part)
            .and_then(|file| file.sync_all())
            .map_err(anyhow::Error::from)?;
        let object = ObjectKey::parse(key).map_err(|e| Refusal::new(400, e.to_string()))?;
        let outcome = storage
            .put_if_absent_file(&object, &part)
            .map_err(|e| Refusal::new(500, e.to_string()))?;
        discard();
        Ok(outcome)
    }
}

/// Create or truncate `path`, owner-only from the first byte.
fn private_file(path: &Path) -> std::io::Result<fs::File> {
    let mut options = fs::OpenOptions::new();
    options.write(true).create(true).truncate(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    options.open(path)
}

/// The checks `put` applies to a body, applied to a staged file. Chunks are
/// hashed while reading, so a 64 MiB chunk is never held in memory.
fn verify(key: &str, path: &Path, size: u64) -> Result<()> {
    peer::admissible_key(key)?;
    if let Some((_, address)) = key.rsplit_once("/chunks/sha256/") {
        let digest = address.rsplit('/').next().unwrap_or_default();
        let mut file = fs::File::open(path)?;
        file.seek(SeekFrom::Start(0))?;
        let mut hasher = Sha256::new();
        let mut buffer = vec![0_u8; 1024 * 1024];
        loop {
            let n = file.read(&mut buffer)?;
            if n == 0 {
                break;
            }
            hasher.update(&buffer[..n]);
        }
        ensure!(
            format!("{:x}", hasher.finalize()) == digest,
            "chunk content does not match its address"
        );
        return Ok(());
    }
    if size > MAX_IN_MEMORY_CHECK {
        bail!("only chunks may be larger than 16 MiB");
    }
    peer::admissible(key, &fs::read(path)?)
}
