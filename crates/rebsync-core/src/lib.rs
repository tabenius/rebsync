//! Preservation-first orchestration. No terminal I/O belongs in this crate.
pub use chrono;
pub mod agenda;
#[cfg(feature = "peer-http")]
pub mod artifacts;
pub mod binaries;
pub mod config;
pub mod credentials;
#[cfg(feature = "storage-object-store")]
pub mod drive;
pub mod frog;
pub mod gift;
pub mod gitlayer;
pub mod inventory;
pub mod journal;
pub mod layer;
pub mod migration;
pub mod mneme;
#[cfg(feature = "peer-transport")]
pub mod overlay;
pub mod peer;
pub mod phone;
#[cfg(feature = "peer-http")]
mod private_http;
pub mod process;
pub mod rbq_contract;
#[cfg(feature = "peer-http")]
pub mod repository;
#[cfg(feature = "peer-http")]
pub mod repository_sync;
#[cfg(feature = "serve")]
pub mod restic_rest;
#[cfg(feature = "serve")]
pub mod serve;
pub mod status;
pub mod storage;
pub mod sync;
#[cfg(feature = "peer-transport")]
pub mod transport;
pub mod wire;

pub use config::{Config, ConfigOverrides, EffectiveConfig, load_config};
pub use inventory::{Inventory, Repository, discover};
#[cfg(feature = "storage-object-store")]
pub use storage::FsObjectStorage;
pub use storage::{
    MAX_KEY_BYTES, ObjectKey, ObjectMeta, ObjectStorage, PutOutcome, StorageCapabilities,
    StorageError,
};
pub use sync::{RunOptions, RunSummary, run};
