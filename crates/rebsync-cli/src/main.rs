use anyhow::{Result, bail};
use clap::{Args, Parser, Subcommand};
use rebsync_core::{ConfigOverrides, RunOptions, load_config};
use std::path::PathBuf;

#[derive(Parser)]
#[command(
    name = "rebsync",
    version,
    about = "Preserve work, safely exchange Git branches, report unresolved risks"
)]
struct Cli {
    /// Rebekah home; defaults to $HOME. Bare invocation is a dry-run.
    home: Option<PathBuf>,
    #[command(flatten)]
    common: Common,
    /// Execute the plan. Without this flag only inventory and journaling occur.
    #[arg(long, conflicts_with = "dry_run")]
    apply: bool,
    #[arg(long)]
    dry_run: bool,
    #[arg(long, global = true)]
    json: bool,
    #[command(subcommand)]
    command: Option<Action>,
}
#[derive(Args)]
struct Common {
    #[arg(long, global = true)]
    config: Option<PathBuf>,
    /// Restrict discovery to these roots (relative to Rebekah home).
    #[arg(long, global = true)]
    root: Vec<PathBuf>,
    #[arg(long, global = true)]
    no_fetch: bool,
    /// Explicitly enable/disable fetching, overriding configuration.
    #[arg(long, global = true, num_args = 0..=1, require_equals = true, default_missing_value = "true", conflicts_with = "no_fetch")]
    fetch: Option<bool>,
    #[arg(long, global = true)]
    no_push: bool,
    /// Explicitly enable/disable pushing, overriding configuration.
    #[arg(long, global = true, num_args = 0..=1, require_equals = true, default_missing_value = "true", conflicts_with = "no_push")]
    push: Option<bool>,
    #[arg(long, global = true)]
    no_fast_forward: bool,
    #[arg(long, global = true, num_args = 0..=1, require_equals = true, default_missing_value = "true", conflicts_with = "no_fast_forward")]
    fast_forward: Option<bool>,
    /// Existing restic repository, e.g. s3:https://ACCOUNT.r2.cloudflarestorage.com/BUCKET.
    #[arg(long, global = true)]
    backup_repository: Option<String>,
    #[arg(long, global = true)]
    password_file: Option<PathBuf>,
    /// Root for Rebsync-managed objects; relative paths resolve against Rebekah home.
    #[arg(long, global = true)]
    storage_root: Option<PathBuf>,
    /// Mneme index passed to `mneme --db`; relative paths resolve against Rebekah home.
    #[arg(long, global = true)]
    mneme_db: Option<PathBuf>,
}
#[derive(Subcommand)]
enum Action {
    /// Print effective configuration and field origins; does not run synchronization.
    Config {
        #[command(subcommand)]
        command: ConfigAction,
    },
    /// Explicitly initialize the configured encrypted restic repository.
    BackupInit {
        #[arg(long, required = true)]
        confirm: bool,
    },
    /// Inspect or verify the configured local object store.
    Storage {
        #[command(subcommand)]
        command: StorageAction,
    },
    /// Mneme session-history layer: owner-exported index snapshots in object storage.
    Mneme {
        #[command(subcommand)]
        command: MnemeAction,
    },
}
#[derive(Subcommand)]
enum MnemeAction {
    /// Export a consistent snapshot through mneme and publish it now.
    Publish,
    /// Read-only storage accounting: dedup ratio, orphan and missing chunks.
    Stats,
    /// List published snapshots, oldest first.
    List {
        #[arg(long)]
        label: Option<String>,
    },
    /// Reassemble a snapshot, check every chunk, and run mneme's validator.
    Verify { id: String },
    /// Restore a snapshot into a new index; never overwrites an existing one.
    Restore {
        id: String,
        #[arg(long)]
        into: PathBuf,
    },
}
#[derive(Subcommand)]
enum ConfigAction {
    Explain,
}
#[derive(Subcommand)]
enum StorageAction {
    /// Print the effective storage root.
    Path,
    /// Write, read, verify and delete a probe object.
    Check,
}

#[cfg(feature = "storage")]
fn storage_check(config: &rebsync_core::Config, json: bool) -> Result<i32> {
    use rebsync_core::{FsObjectStorage, ObjectKey, ObjectStorage, PutOutcome, StorageError};
    use std::time::{SystemTime, UNIX_EPOCH};

    let storage = FsObjectStorage::open(&config.storage.root)?;
    let capabilities = storage.capabilities();
    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|elapsed| elapsed.as_nanos())
        .unwrap_or_default();
    let key = ObjectKey::parse(&format!("_probes/check-{}-{nonce}", std::process::id()))?;
    let payload = b"rebsync storage probe";
    let created = matches!(
        storage.put_if_absent(&key, payload)?,
        PutOutcome::Created(_)
    );
    if storage.get(&key)? != payload {
        bail!("probe readback mismatch at {key}");
    }
    if storage.get_range(&key, 0..4)? != b"rebs" {
        bail!("probe range read mismatch at {key}");
    }
    let head = storage.head(&key)?;
    if head.size != payload.len() as u64 {
        bail!("probe size mismatch: {} != {}", head.size, payload.len());
    }
    if !storage
        .list_prefix("_probes/", 0)?
        .iter()
        .any(|meta| meta.key == key.as_str())
    {
        bail!("probe missing from raw-prefix listing");
    }
    storage.delete(&key)?;
    if !matches!(storage.head(&key), Err(StorageError::NotFound(_))) {
        bail!("probe still present after delete");
    }
    if json {
        println!(
            "{}",
            serde_json::to_string_pretty(&serde_json::json!({
                "storage_root": config.storage.root,
                "probe_key": key.as_str(),
                "created_if_absent": created,
                "bytes": head.size,
                "checks": ["create-if-absent", "readback", "range", "head", "raw-prefix-listing", "delete"],
                "capabilities": {
                    "atomic_create_if_absent": capabilities.atomic_create_if_absent,
                    "durable_publication": capabilities.durable_publication,
                    "range_reads": capabilities.range_reads,
                    "raw_prefix_listing": capabilities.raw_prefix_listing,
                    "max_key_bytes": capabilities.max_key_bytes,
                },
            }))?
        );
    } else {
        println!("Storage root: {}", config.storage.root.display());
        println!("Probe: {key} ({} bytes, created={created})", head.size);
        println!("Checks: create-if-absent, readback, range, head, listing, delete");
        println!(
            "Capabilities: atomic_create={}, durable_publication={}, range={}, raw_prefix_listing={}",
            capabilities.atomic_create_if_absent,
            capabilities.durable_publication,
            capabilities.range_reads,
            capabilities.raw_prefix_listing
        );
    }
    Ok(0)
}

#[cfg(feature = "storage")]
fn mneme_action(config: &rebsync_core::Config, action: MnemeAction, json: bool) -> Result<i32> {
    use rebsync_core::{FsObjectStorage, journal::Journal, mneme};

    let storage = FsObjectStorage::open(&config.storage.root)?;
    let value = match action {
        MnemeAction::List { label } => {
            let items: Vec<_> = mneme::list(&storage, label.as_deref())?
                .into_iter()
                .map(|m| {
                    serde_json::json!({
                        "id": m.id,
                        "created_at": m.created_at,
                        "bytes": m.bytes,
                        "chunks": m.chunks.len(),
                        "sha256": m.sha256,
                        "generation": m.owner.get("generation"),
                        "counts": m.owner.get("counts"),
                    })
                })
                .collect();
            if !json {
                for item in &items {
                    println!(
                        "{}  {} bytes  {} chunks",
                        item["id"].as_str().unwrap_or_default(),
                        item["bytes"],
                        item["chunks"]
                    );
                }
                return Ok(0);
            }
            serde_json::json!({ "snapshots": items })
        }
        MnemeAction::Stats => {
            let stats = mneme::stats(&storage)?;
            if !json {
                println!(
                    "{} snapshots, latest {}",
                    stats.snapshots,
                    stats.latest_id.as_deref().unwrap_or("none")
                );
                println!(
                    "logical {} bytes, stored {} bytes in {} chunks",
                    stats.logical_bytes, stats.stored_bytes, stats.stored_chunks
                );
                println!(
                    "orphan chunks {} ({} bytes), missing chunks {}",
                    stats.orphan_chunks, stats.orphan_bytes, stats.missing_chunks
                );
                return Ok(if stats.missing_chunks > 0 { 2 } else { 0 });
            }
            let code = if stats.missing_chunks > 0 { 2 } else { 0 };
            println!("{}", serde_json::to_string_pretty(&stats)?);
            return Ok(code);
        }
        MnemeAction::Publish => {
            if config.mneme.restic && config.backup.repository.is_none() {
                bail!(
                    "mneme.restic requires backup.repository; set mneme.restic = false to publish locally only"
                );
            }
            let mut journal = Journal::open(&config.rebekah_home)?;
            let outcome = mneme::publish(config, &storage, &mut journal)?;
            serde_json::to_value(outcome)?
        }
        MnemeAction::Verify { id } => {
            let mut journal = Journal::open(&config.rebekah_home)?;
            mneme::verify(config, &storage, &id, &mut journal)?
        }
        MnemeAction::Restore { id, into } => {
            let mut journal = Journal::open(&config.rebekah_home)?;
            let into = if into.is_absolute() {
                into
            } else {
                std::env::current_dir()?.join(into)
            };
            mneme::restore(config, &storage, &id, &into, &mut journal)?
        }
    };
    println!("{}", serde_json::to_string_pretty(&value)?);
    Ok(0)
}

#[cfg(not(feature = "storage"))]
fn mneme_action(_config: &rebsync_core::Config, _action: MnemeAction, _json: bool) -> Result<i32> {
    bail!("rebsync was built without the storage feature; rebuild with --features storage")
}

#[cfg(not(feature = "storage"))]
fn storage_check(_config: &rebsync_core::Config, _json: bool) -> Result<i32> {
    bail!("rebsync was built without the storage feature; rebuild with --features storage")
}

fn main() {
    match entry() {
        Ok(code) => std::process::exit(code),
        Err(error) => {
            eprintln!("rebsync: {error:#}");
            std::process::exit(1);
        }
    }
}
fn entry() -> Result<i32> {
    let cli = Cli::parse();
    let config = load_config(ConfigOverrides {
        rebekah_home: cli.home,
        config: cli.common.config,
        roots: (!cli.common.root.is_empty()).then_some(cli.common.root),
        fetch: cli.common.no_fetch.then_some(false).or(cli.common.fetch),
        push: cli.common.no_push.then_some(false).or(cli.common.push),
        fast_forward: cli
            .common
            .no_fast_forward
            .then_some(false)
            .or(cli.common.fast_forward),
        backup_repository: cli.common.backup_repository,
        password_file: cli.common.password_file,
        storage_root: cli.common.storage_root,
        mneme_db: cli.common.mneme_db,
    })?;
    match cli.command {
        Some(Action::Config { .. }) => {
            let mut value = serde_json::to_value(&config)?;
            // Repository URLs can contain inline credentials; don't expose them in explain output.
            if value["config"]["backup"]["repository"].is_string() {
                value["config"]["backup"]["repository"] = "<configured; redacted>".into();
            }
            println!("{}", serde_json::to_string_pretty(&value)?);
            return Ok(0);
        }
        Some(Action::BackupInit { confirm: _ }) => {
            rebsync_core::sync::initialize_backup(&config.config)?;
            println!("Encrypted backup repository initialized. Keep its recovery key separately.");
            return Ok(0);
        }
        Some(Action::Storage { command }) => match command {
            StorageAction::Path => {
                if cli.json {
                    println!(
                        "{}",
                        serde_json::to_string_pretty(&serde_json::json!({
                            "storage_root": config.config.storage.root,
                        }))?
                    );
                } else {
                    println!("{}", config.config.storage.root.display());
                }
                return Ok(0);
            }
            StorageAction::Check => return storage_check(&config.config, cli.json),
        },
        Some(Action::Mneme { command }) => return mneme_action(&config.config, command, cli.json),
        None => {}
    }
    let summary = rebsync_core::run(&config.config, RunOptions { apply: cli.apply })?;
    if cli.json {
        println!("{}", serde_json::to_string_pretty(&summary)?);
    } else {
        println!(
            "{} — {} repositories",
            if summary.dry_run { "DRY RUN" } else { "APPLY" },
            summary.repositories.len()
        );
        for repo in &summary.repositories {
            println!("\n{}", repo.path.display());
            if let Some(id) = &repo.backup_snapshot {
                println!("  encrypted backup: {id}");
            }
            for action in &repo.actions {
                println!("  {action}");
            }
            for issue in &repo.issues {
                println!("  ! {issue}");
            }
        }
        for issue in &summary.issues {
            println!("\n! {issue}");
        }
        for dataset in &summary.datasets {
            println!("\ndataset: {dataset}");
        }
        println!("\nJournal: {}", summary.journal.display());
    }
    Ok(if summary.needs_attention() { 2 } else { 0 })
}
