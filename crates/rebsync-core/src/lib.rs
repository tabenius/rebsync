//! Preservation-first orchestration. No terminal I/O belongs in this crate.
pub use chrono;
pub mod agenda;
pub mod config;
pub mod frog;
pub mod gitlayer;
pub mod inventory;
pub mod journal;
pub mod layer;
pub mod mneme;
pub mod peer;
pub mod process;
pub mod storage;
pub mod sync;
#[cfg(feature = "peer-transport")]
pub mod transport;

pub use config::{Config, ConfigOverrides, EffectiveConfig, load_config};
pub use inventory::{Inventory, Repository, discover};
#[cfg(feature = "storage-object-store")]
pub use storage::FsObjectStorage;
pub use storage::{
    MAX_KEY_BYTES, ObjectKey, ObjectMeta, ObjectStorage, PutOutcome, StorageCapabilities,
    StorageError,
};
pub use sync::{RunOptions, RunSummary, run};
