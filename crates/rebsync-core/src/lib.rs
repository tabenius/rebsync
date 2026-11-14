//! Preservation-first orchestration. No terminal I/O belongs in this crate.
pub mod config;
pub mod inventory;
pub mod journal;
pub mod mneme;
pub mod process;
pub mod storage;
pub mod sync;

pub use config::{Config, ConfigOverrides, EffectiveConfig, load_config};
pub use inventory::{Inventory, Repository, discover};
#[cfg(feature = "storage-object-store")]
pub use storage::FsObjectStorage;
pub use storage::{
    MAX_KEY_BYTES, ObjectKey, ObjectMeta, ObjectStorage, PutOutcome, StorageCapabilities,
    StorageError,
};
pub use sync::{RunOptions, RunSummary, run};
