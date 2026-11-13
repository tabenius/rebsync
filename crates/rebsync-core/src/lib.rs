//! Preservation-first orchestration. No terminal I/O belongs in this crate.
pub mod config;
pub mod inventory;
pub mod journal;
pub mod process;
pub mod sync;

pub use config::{Config, ConfigOverrides, EffectiveConfig, load_config};
pub use inventory::{Inventory, Repository, discover};
pub use sync::{RunOptions, RunSummary, run};
