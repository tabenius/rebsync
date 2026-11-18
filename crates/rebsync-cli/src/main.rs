use anyhow::{Result, bail};
use clap::{Args, CommandFactory, Parser, Subcommand};
use rebsync_core::{ConfigOverrides, RunOptions, load_config};
use std::path::PathBuf;
mod artifacts_cli;
mod repository_cli;
mod ui;

#[derive(Parser)]
#[command(
    name = "rbq",
    version,
    styles = ui::styles(),
    about = "Preserve work, safely exchange Git branches, report unresolved risks"
)]
struct Cli {
    /// Rebeqah home; defaults to $HOME. Bare invocation is a dry-run.
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
    /// Terminal styling; JSON and completion scripts always remain uncolored.
    #[arg(long, global = true, value_enum, default_value = "auto")]
    color: ui::ColorMode,
    #[command(subcommand)]
    command: Option<Action>,
}
#[derive(Args)]
struct Common {
    #[arg(long, global = true)]
    config: Option<PathBuf>,
    /// Restrict discovery to these roots (relative to Rebeqah home).
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
    /// Root for Rebeqah-managed objects; relative paths resolve against Rebeqah home.
    #[arg(long, global = true)]
    storage_root: Option<PathBuf>,
    /// Mneme index passed to `mneme --db`; relative paths resolve against Rebeqah home.
    #[arg(long, global = true)]
    mneme_db: Option<PathBuf>,
}
#[derive(Subcommand)]
enum Action {
    /// Navigate authorized Dash artifacts using read-only private MCP tools (JSON).
    Artifacts(artifacts_cli::ArtifactArgs),
    /// Access your private Dash-hosted RBQ repository (JSON output, no local sync).
    Repository(repository_cli::RepositoryArgs),
    /// Generate a shell completion script on stdout, without reading configuration.
    Completions {
        #[arg(value_enum)]
        shell: clap_complete::Shell,
    },
    /// Read-only phone diagnostics and printable Linux/Chromebook connection guides.
    Phone {
        #[command(subcommand)]
        command: PhoneAction,
    },
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
    /// Explicit reviewed Hypomnema gzip exchange, separate from Mneme SQLite snapshots.
    Hypomnema {
        #[command(subcommand)]
        command: HypomnemaAction,
    },
    /// Frog coordination database (AGENTS.db) layer.
    Frog {
        #[command(subcommand)]
        command: LayerAction,
    },
    /// Daily Agenda edition layer.
    Agenda {
        #[command(subcommand)]
        command: LayerAction,
    },
    /// Git layer: committed history as verified bundles, for offline exchange.
    Git {
        #[command(subcommand)]
        command: GitAction,
    },
    /// Serve the object store as a restic REST repository (append-only).
    ///
    /// `restic -r rest:https://USER:PASSWORD@HOST:PORT/` can then init, back
    /// up, list, restore and check. Plain HTTP is accepted only on loopback.
    ResticServe(ResticServeArgs),
    /// Serve a read-only instructions and status page (HTTPS on localhost by
    /// default) and announce it via Avahi/mDNS and D-Bus where available.
    Serve {
        #[arg(long, default_value_t = 8790)]
        port: u16,
        /// Address to listen on; 0.0.0.0 shares the page on the local network.
        #[arg(long, default_value = "127.0.0.1")]
        bind: std::net::IpAddr,
        /// Serve plain HTTP instead of HTTPS with the self-signed certificate.
        #[arg(long)]
        plain_http: bool,
        /// Do not announce via zeroconf or D-Bus.
        #[arg(long)]
        no_announce: bool,
    },
    /// Exchange layer objects with a Rebeqah phone (rbq-peer/0).
    Peer {
        #[command(subcommand)]
        command: PeerAction,
    },
    /// Enrolled removable drives: identify by marker, then push/pull layers.
    Drive {
        #[command(subcommand)]
        command: DriveAction,
    },
}

#[derive(Subcommand)]
enum DriveAction {
    /// Enroll the drive mounted at PATH: writes .rbq-drive.json there.
    Enroll {
        path: PathBuf,
        #[arg(long)]
        name: String,
        /// Take over a drive already marked elsewhere, keeping its identity.
        #[arg(long)]
        adopt: bool,
        /// Enroll even on the local object store's device (not independent).
        #[arg(long)]
        allow_same_device: bool,
    },
    /// Enrolled drives: where each is mounted now, and whether it is independent.
    List {
        /// Extra directories to look in besides mount points.
        #[arg(long)]
        search: Vec<PathBuf>,
    },
    /// Copy local layer objects the drive lacks (never overwrites).
    Push {
        name: String,
        /// Layers (default: all).
        #[arg(long = "layer")]
        layers: Vec<String>,
        #[arg(long)]
        search: Vec<PathBuf>,
    },
    /// Copy the drive's layer objects this store lacks; verifies snapshots.
    Pull {
        name: String,
        #[arg(long = "layer")]
        layers: Vec<String>,
        #[arg(long)]
        search: Vec<PathBuf>,
    },
    /// Forget an enrollment; the drive's marker and data are left untouched.
    Forget { name: String },
}
#[derive(Subcommand)]
enum PhoneAction {
    /// Observe USB/network metadata; never enrolls a peer or transfers files.
    Diagnose {
        /// Open read-only MTP storage sessions using GIO (requires gvfs-backends).
        #[arg(long)]
        mtp: bool,
        /// Include USB serial numbers; omit when sharing a diagnostic report.
        #[arg(long)]
        include_identifiers: bool,
        /// Query IPs/free space on this explicitly selected, authorized ADB device.
        #[arg(long)]
        adb_serial: Option<String>,
        /// Probe only this explicit HTTP peer; never scans the network.
        #[arg(long)]
        peer: Option<String>,
        #[arg(long, requires = "peer")]
        token_file: Option<PathBuf>,
    },
    /// Print instructions only; USB, TCP/IP and Bluetooth/PAN limitations are explicit.
    Instructions {
        #[arg(long, value_parser = ["all", "usb", "tcp", "bluetooth"], default_value = "all")]
        transport: String,
        #[arg(long)]
        chromebook: bool,
    },
}

fn phone_action(action: &PhoneAction, json: bool) -> Result<i32> {
    use rebsync_core::phone;
    match action {
        PhoneAction::Instructions {
            transport,
            chromebook,
        } => {
            let guide = phone::instructions(transport, *chromebook)?;
            if json {
                println!(
                    "{}",
                    serde_json::json!({"schema":"rbq.phone.instructions.v1", "transport":transport, "chromebook":chromebook, "instructions":guide})
                );
            } else {
                print!("{guide}");
            }
            Ok(0)
        }
        PhoneAction::Diagnose {
            mtp,
            include_identifiers,
            adb_serial,
            peer,
            token_file,
        } => {
            let mut report = phone::diagnose(*mtp, *include_identifiers);
            if let Some(serial) = adb_serial {
                report.adb = Some(phone::probe_adb(serial, *include_identifiers)?);
            }
            if let Some(connection) = peer {
                #[cfg(feature = "peer")]
                {
                    let token = token_file
                        .as_ref()
                        .map(|path| rebsync_core::transport::read_token_file(path))
                        .transpose()?;
                    match phone::probe_peer(connection, token.as_deref()) {
                        Ok(peer) => report.peer = Some(peer),
                        Err(error) => report
                            .issues
                            .push(format!("Explicit peer probe failed: {error:#}")),
                    }
                }
                #[cfg(not(feature = "peer"))]
                {
                    let _ = (connection, token_file);
                    report
                        .issues
                        .push("Peer probing unavailable: built without the peer feature.".into());
                }
            }
            let incomplete = !report.issues.is_empty()
                || report
                    .adb
                    .as_ref()
                    .is_some_and(|adb| !adb.authorized || !adb.issues.is_empty())
                || report
                    .usb
                    .iter()
                    .filter_map(|device| device.mtp.as_ref())
                    .any(|mtp| mtp.status != "space_reported" || !mtp.issues.is_empty());
            if json {
                println!("{}", serde_json::to_string_pretty(&report)?);
            } else {
                println!("Phone diagnostics (observations only; physical-device match: unknown)");
                for device in &report.usb {
                    println!(
                        "USB {:03}:{:03} {}:{} {}{}",
                        device.bus,
                        device.device,
                        device.vendor_id,
                        device.product_id,
                        device.description,
                        if device.mtp_candidate {
                            " [MTP/PTP candidate]"
                        } else {
                            ""
                        }
                    );
                    if let Some(serial) = &device.serial {
                        println!("  USB serial (not authentication): {serial}");
                    }
                    if let Some(mtp) = &device.mtp {
                        println!("  MTP: {} ({})", mtp.status, mtp.uri);
                        for storage in &mtp.storages {
                            println!(
                                "  {}: capacity={} free={} bytes",
                                storage.uri,
                                storage
                                    .capacity_bytes
                                    .map(|v| v.to_string())
                                    .unwrap_or_else(|| "unknown".into()),
                                storage
                                    .free_bytes
                                    .map(|v| v.to_string())
                                    .unwrap_or_else(|| "unknown".into())
                            );
                        }
                        for issue in &mtp.issues {
                            println!("  ! {issue}");
                        }
                    }
                }
                for route in &report.network.default_routes {
                    println!(
                        "Default route: {} via {}",
                        route.interface,
                        route.gateway.as_deref().unwrap_or("unknown")
                    );
                }
                if report.network.crostini_gateway_observed {
                    println!(
                        "Crostini virtual gateway observed; this is not an identified phone address."
                    );
                }
                if let Some(peer) = &report.peer {
                    println!("Explicit peer: {peer}");
                }
                if let Some(adb) = &report.adb {
                    println!(
                        "Explicit ADB device: authorized={} phone_addresses={:?}",
                        adb.authorized, adb.phone_addresses
                    );
                    for storage in &adb.storages {
                        println!(
                            "  ADB df: capacity={:?} free={:?} bytes",
                            storage.capacity_bytes, storage.free_bytes
                        );
                    }
                    for issue in &adb.issues {
                        println!("  ! {issue}");
                    }
                }
                for issue in &report.issues {
                    println!("! {issue}");
                }
                for note in &report.safety {
                    println!("Note: {note}");
                }
                println!("Guide: rbq phone instructions --chromebook");
            }
            Ok(if incomplete { 2 } else { 0 })
        }
    }
}
#[derive(Args)]
struct PruneArgs {
    /// Newest snapshots to keep per label (at least 1).
    #[arg(long, default_value_t = 7)]
    keep_last: usize,
    /// Also keep every snapshot created within this many days.
    #[arg(long)]
    keep_days: Option<u32>,
    /// Only prune this label; others are kept untouched.
    #[arg(long)]
    label: Option<String>,
    /// Leave unreferenced chunks younger than this alone.
    #[arg(long, default_value_t = 60)]
    grace_minutes: u32,
    /// Delete. Without this flag prune only reports what it would remove.
    #[arg(long)]
    apply: bool,
}
#[derive(Subcommand)]
enum HypomnemaAction {
    /// Verify and publish an explicitly selected local gzip. No ambient scans or uploads.
    Publish {
        #[arg(long)] bundle: PathBuf,
        #[arg(long, default_value = "local")] label: String,
    },
    /// List immutable reviewed bundle snapshots.
    List,
    /// Reassemble and validate all bytes with the Mneme owner CLI.
    Verify { id: String },
    /// Recover into a new file; no overwrite, no execution of handoff instructions.
    Restore { id: String, #[arg(long)] into: PathBuf },
}

#[derive(Subcommand)]
enum LayerAction {
    /// Export through the owner, validate, and publish now.
    Publish,
    /// List published snapshots, oldest first.
    List {
        #[arg(long)]
        label: Option<String>,
    },
    /// Read-only storage accounting.
    Stats,
    /// Retention: drop old snapshots and unreferenced chunks (dry-run by default).
    Prune(PruneArgs),
    /// Reassemble, check every chunk and validate as the owner would.
    Verify { id: String },
    /// Restore into a new file (frog) or directory (agenda); never overwrites.
    Restore {
        id: String,
        #[arg(long)]
        into: PathBuf,
    },
}
#[derive(Subcommand)]
enum GitAction {
    /// Bundle every discovered repository whose refs changed and publish it.
    Publish,
    /// List published bundles, oldest first.
    List {
        #[arg(long)]
        label: Option<String>,
    },
    /// Read-only storage accounting.
    Stats,
    /// Retention: drop old bundles and unreferenced chunks (dry-run by default).
    Prune(PruneArgs),
    /// Reassemble, check chunks, run `git bundle verify`, compare heads.
    Verify { id: String },
    /// Clone a bundle into a new directory.
    Restore {
        id: String,
        #[arg(long)]
        into: PathBuf,
    },
    /// Fetch a bundle's branches/tags into refs/remotes/rbq-NAME/* of an
    /// existing repository; local branches, tags and the worktree are untouched.
    Fetch {
        id: String,
        #[arg(long)]
        repo: PathBuf,
        /// Namespace name; defaults to the snapshot's label.
        #[arg(long = "as")]
        name: Option<String>,
    },
}
#[derive(Args)]
struct PeerTargetArgs {
    /// Connection string from the app (rbq+http://HOST:PORT/v1?token=…);
    /// defaults to $RBQ_PEER so the token stays out of shell history.
    connection: Option<String>,
    /// File holding the token, when the connection has none.
    #[arg(long)]
    token_file: Option<PathBuf>,
    /// Additional HTTP attempts on transient connection/502/503/504/408 failures.
    #[arg(long, default_value_t = 3, value_parser = clap::value_parser!(u8).range(0..=6))]
    retries: u8,
    /// HTTP timeout per attempt, including body transfer (retry budget is bounded).
    #[arg(long, default_value_t = 60, value_parser = clap::value_parser!(u64).range(1..=300))]
    timeout_seconds: u64,
}
#[derive(Subcommand)]
enum PeerAction {
    /// Check the peer and show what it holds per layer.
    Status {
        #[command(flatten)]
        target: PeerTargetArgs,
    },
    /// Copy local layer objects the peer lacks (never overwrites).
    Push {
        #[command(flatten)]
        target: PeerTargetArgs,
        /// Restrict to these layers (mneme, frog, agenda); default all.
        #[arg(long = "layer")]
        layers: Vec<String>,
    },
    /// Copy the peer's layer objects this store lacks (never overwrites).
    Pull {
        #[command(flatten)]
        target: PeerTargetArgs,
        #[arg(long = "layer")]
        layers: Vec<String>,
    },
    /// Serve this store over local transports (rbq-peer/1).
    Serve(ServeArgs),
    /// Push, pull and verify a tiny snapshot over every local transport.
    Selftest,
}
#[derive(Args)]
struct ResticServeArgs {
    /// Address to listen on. Off loopback, TLS is required.
    #[arg(long, default_value = "127.0.0.1:8000")]
    listen: std::net::SocketAddr,
    /// HTTP Basic user name restic must present.
    #[arg(long, default_value = "rbq")]
    user: String,
    /// Owner-only file holding the HTTP password (at least 16 characters).
    /// This is not the repository encryption password.
    #[arg(long)]
    password_file: PathBuf,
    /// PEM certificate chain for TLS (with --tls-key).
    #[arg(long, requires = "tls_key", conflicts_with = "tls_self_signed")]
    tls_cert: Option<PathBuf>,
    /// PEM private key for TLS (with --tls-cert).
    #[arg(long, requires = "tls_cert")]
    tls_key: Option<PathBuf>,
    /// Use a self-signed certificate kept in rbq's private state directory;
    /// pass the printed path to `restic --cacert`.
    #[arg(long)]
    tls_self_signed: bool,
    /// Extra DNS name or IP address the self-signed certificate must cover
    /// (repeatable), e.g. the name clients use to reach this machine.
    #[arg(long, requires = "tls_self_signed")]
    tls_name: Vec<String>,
    /// Object store root; defaults to the configured storage root. Repository
    /// objects live under its `restic/` namespace.
    #[arg(long)]
    storage: Option<PathBuf>,
    /// Refuse uploads once the repository holds this many bytes.
    #[arg(long)]
    max_bytes: Option<u64>,
    /// Allow deleting snapshots, packs and indexes (forget/prune). Without it
    /// only locks can be removed.
    #[arg(long)]
    allow_delete: bool,
    /// Concurrent request handlers.
    #[arg(long, default_value_t = 4)]
    workers: usize,
}
#[derive(Args)]
struct ServeArgs {
    /// Listen address; repeat for several. tcp://HOST:PORT, unix:///path or
    /// unix-dgram:///path.
    #[arg(long = "listen", required = true)]
    listen: Vec<String>,
    /// File holding the shared token; must not be group- or world-readable.
    #[arg(long)]
    token_file: PathBuf,
    /// Remove an existing socket path. A live server is never replaced.
    #[arg(long)]
    replace_stale: bool,
}
#[derive(Subcommand)]
enum MnemeAction {
    /// Export a consistent snapshot through mneme and publish it now.
    Publish,
    /// Read-only storage accounting: dedup ratio, orphan and missing chunks.
    Stats,
    /// Retention: drop old snapshots and unreferenced chunks (dry-run by default).
    Prune(PruneArgs),
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
    /// Check every layer snapshot: chunk and whole-file digests (read-only).
    Fsck {
        /// Restrict to these layers (mneme, frog, agenda); default all.
        #[arg(long = "layer")]
        layers: Vec<String>,
    },
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
    let payload = b"rbq storage probe";
    // Run every check in a closure so a failure still reaches cleanup. A probe
    // left behind on an error path would masquerade as stored data.
    let checks = (|| -> Result<(bool, u64)> {
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
        Ok((created, head.size))
    })();
    let (created, size) = match checks {
        Ok(values) => values,
        Err(error) => {
            let _ = storage.delete(&key);
            return Err(error);
        }
    };
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
                "bytes": size,
                "checks": ["create-if-absent", "readback", "range", "head", "raw-prefix-listing", "delete"],
                "capabilities": {
                    "atomic_create_if_absent": capabilities.atomic_create_if_absent,
                    "owner_only_permissions": capabilities.owner_only_permissions,
                    "durable_publication": capabilities.durable_publication,
                    "range_reads": capabilities.range_reads,
                    "raw_prefix_listing": capabilities.raw_prefix_listing,
                    "max_key_bytes": capabilities.max_key_bytes,
                },
            }))?
        );
    } else {
        println!("Storage root: {}", config.storage.root.display());
        println!("Probe: {key} ({size} bytes, created={created})");
        println!("Checks: create-if-absent, readback, range, head, listing, delete");
        println!(
            "Capabilities: atomic_create={}, owner_only={}, durable_publication={}, range={}, raw_prefix_listing={}",
            capabilities.atomic_create_if_absent,
            capabilities.owner_only_permissions,
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
        MnemeAction::Prune(args) => return prune_layer(config, "mneme", args),
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
            let mut journal = Journal::open(&config.rbq_home)?;
            let outcome = mneme::publish(config, &storage, &mut journal)?;
            serde_json::to_value(outcome)?
        }
        MnemeAction::Verify { id } => {
            let mut journal = Journal::open(&config.rbq_home)?;
            mneme::verify(config, &storage, &id, &mut journal)?
        }
        MnemeAction::Restore { id, into } => {
            let mut journal = Journal::open(&config.rbq_home)?;
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

#[cfg(feature = "storage")]
fn hypomnema_action(config: &rebsync_core::Config, action: HypomnemaAction) -> Result<i32> {
    use rebsync_core::{FsObjectStorage, layer};
    use std::{fs, process::Command};
    const NAME: &str = "evac.bundle.json.gz";
    let storage = FsObjectStorage::open(&config.storage.root)?;
    let owner_verify = |path: &std::path::Path| -> Result<serde_json::Value> {
        let output = Command::new("mneme").args(["evac", "verify", "--bundle"]).arg(path).output()?;
        if !output.status.success() {
            bail!("Mneme rejected evacuation bundle (exit {:?}); contents not published", output.status.code());
        }
        let report: serde_json::Value = serde_json::from_slice(&output.stdout)?;
        if report["schema"] != "hypomnema.bundle.v1" || !report["sha256"].is_string() {
            bail!("invalid owner verification report");
        }
        Ok(report)
    };
    let verify_snapshot = |id: &str| -> Result<(tempfile::TempDir, serde_json::Value)> {
        let manifest = layer::load(&storage, "hypomnema", id)?;
        if manifest.files.len() != 1 || manifest.files[0].path != NAME {
            bail!("Hypomnema snapshot must contain exactly the named evacuation bundle");
        }
        let staging = layer::staging(config, "hypomnema")?;
        let output_dir = staging.path().join("recovered");
        layer::assemble(&storage, &manifest, &output_dir)?;
        let report = owner_verify(&output_dir.join(NAME))?;
        if report["sha256"].as_str() != Some(manifest.files[0].sha256.as_str()) {
            bail!("Mneme report differs from rbq manifest digest");
        }
        Ok((staging, report))
    };
    match action {
        HypomnemaAction::Publish { bundle, label } => {
            layer::validate_label(&label)?;
            let meta = fs::symlink_metadata(&bundle)?;
            if !meta.file_type().is_file() || meta.len() > 256 * 1024 {
                bail!("expected a regular, non-symlink reviewed gzip of at most 256 KiB");
            }
            let owner = owner_verify(&bundle)?;
            let _lock = layer::lock(config, "hypomnema")?;
            let staging = layer::staging(config, "hypomnema")?;
            fs::copy(&bundle, staging.path().join(NAME))?;
            let report = owner_verify(&staging.path().join(NAME))?;
            if owner["sha256"] != report["sha256"] {
                bail!("source bundle changed during staging");
            }
            let result = layer::publish_files(&storage, "hypomnema", &label, 65536,
                staging.path(), &[NAME.to_owned()], report, None)?;
            println!("{}", serde_json::to_string_pretty(&result)?);
        }
        HypomnemaAction::List => {
            let manifests = layer::list(&storage, "hypomnema", None)?;
            for m in manifests {
                println!("{}  {} bytes  {}", m.id, m.bytes(), m.owner["bundle_id"]);
            }
        }
        HypomnemaAction::Verify { id } => {
            let (_, report) = verify_snapshot(&id)?;
            println!("{}", serde_json::to_string_pretty(&report)?);
        }
        HypomnemaAction::Restore { id, into } => {
            let (staging, report) = verify_snapshot(&id)?;
            let source = staging.path().join("recovered").join(NAME);
            let mut dst = fs::OpenOptions::new();
            dst.write(true).create_new(true);
            #[cfg(unix)]
            {
                use std::os::unix::fs::OpenOptionsExt;
                dst.mode(0o600);
            }
            use std::io::Write;
            let mut output = dst.open(&into)?;
            output.write_all(&fs::read(source)?)?;
            output.sync_all()?;
            println!("{}", serde_json::to_string_pretty(&report)?);
        }
    }
    Ok(0)
}

#[cfg(not(feature = "storage"))]
fn hypomnema_action(_: &rebsync_core::Config, _: HypomnemaAction) -> Result<i32> {
    bail!("rbq was built without the storage feature")
}

#[cfg(feature = "storage")]
fn prune_layer(config: &rebsync_core::Config, layer: &str, args: PruneArgs) -> Result<i32> {
    use rebsync_core::{FsObjectStorage, journal::Journal, layer as layers};

    let storage = FsObjectStorage::open(&config.storage.root)?;
    let _lock = layers::lock(config, layer)?;
    let retention = layers::Retention {
        keep_last: args.keep_last,
        keep_days: args.keep_days,
        label: args.label,
        grace: rebsync_core::chrono::Duration::minutes(i64::from(args.grace_minutes)),
    };
    let report = layers::prune(&storage, layer, &retention, args.apply)?;
    if args.apply {
        let mut journal = Journal::open(&config.rbq_home)?;
        journal.event(
            "layer-pruned",
            layer,
            serde_json::json!({"removed": report.snapshots_removed, "chunks": report.chunks_removed, "bytes": report.bytes_freed}),
        )?;
    }
    println!("{}", serde_json::to_string_pretty(&report)?);
    Ok(0)
}

#[cfg(feature = "storage")]
fn layer_action(
    config: &rebsync_core::Config,
    layer: &str,
    action: LayerAction,
    json: bool,
) -> Result<i32> {
    use rebsync_core::{FsObjectStorage, agenda, frog, journal::Journal, layer as layers};

    let storage = FsObjectStorage::open(&config.storage.root)?;
    let restic = if layer == "frog" {
        config.frog.restic
    } else {
        config.agenda.restic
    };
    let value = match action {
        LayerAction::List { label } => {
            let items: Vec<_> = layers::list(&storage, layer, label.as_deref())?
                .into_iter()
                .map(|m| {
                    serde_json::json!({"id": m.id, "created_at": m.created_at, "files": m.files.len(),
                        "bytes": m.bytes(), "digest": m.digest, "owner": m.owner})
                })
                .collect();
            if !json {
                for item in &items {
                    println!(
                        "{}  {} files  {} bytes",
                        item["id"].as_str().unwrap_or_default(),
                        item["files"],
                        item["bytes"]
                    );
                }
                return Ok(0);
            }
            serde_json::json!({ "snapshots": items })
        }
        LayerAction::Prune(args) => return prune_layer(config, layer, args),
        LayerAction::Stats => {
            let stats = layers::stats(&storage, layer)?;
            let code = if stats.missing_chunks > 0 { 2 } else { 0 };
            println!("{}", serde_json::to_string_pretty(&stats)?);
            return Ok(code);
        }
        LayerAction::Publish => {
            if restic && config.backup.repository.is_none() {
                bail!(
                    "{layer}.restic requires backup.repository; set {layer}.restic = false to publish locally only"
                );
            }
            let mut journal = Journal::open(&config.rbq_home)?;
            let outcome = if layer == "frog" {
                frog::publish(config, &storage, &mut journal)?
            } else {
                agenda::publish(config, &storage, &mut journal)?
            };
            serde_json::to_value(outcome)?
        }
        LayerAction::Verify { id } => {
            if layer == "frog" {
                let mut journal = Journal::open(&config.rbq_home)?;
                frog::verify(config, &storage, &id, &mut journal)?
            } else {
                agenda::verify(config, &storage, &id)?
            }
        }
        LayerAction::Restore { id, into } => {
            let into = if into.is_absolute() {
                into
            } else {
                std::env::current_dir()?.join(into)
            };
            if layer == "frog" {
                let mut journal = Journal::open(&config.rbq_home)?;
                frog::restore(config, &storage, &id, &into, &mut journal)?
            } else {
                agenda::restore(&storage, &id, &into)?
            }
        }
    };
    println!("{}", serde_json::to_string_pretty(&value)?);
    Ok(0)
}

#[cfg(not(feature = "storage"))]
fn layer_action(_: &rebsync_core::Config, _: &str, _: LayerAction, _: bool) -> Result<i32> {
    bail!("rbq was built without the storage feature; rebuild with --features storage")
}

#[cfg(feature = "storage")]
fn git_action(config: &rebsync_core::Config, action: GitAction, json: bool) -> Result<i32> {
    use rebsync_core::{FsObjectStorage, gitlayer, journal::Journal, layer};
    let storage = FsObjectStorage::open(&config.storage.root)?;
    let absolute = |p: PathBuf| -> Result<PathBuf> {
        Ok(if p.is_absolute() {
            p
        } else {
            std::env::current_dir()?.join(p)
        })
    };
    let value = match action {
        GitAction::Publish => {
            let mut journal = Journal::open(&config.rbq_home)?;
            let outcomes = gitlayer::publish_all(config, &storage, &mut journal)?;
            let failed = outcomes.iter().any(|o| o.status == "failed");
            println!("{}", serde_json::to_string_pretty(&outcomes)?);
            return Ok(if failed { 2 } else { 0 });
        }
        GitAction::List { label } => {
            let items: Vec<_> = layer::list(&storage, gitlayer::LAYER, label.as_deref())?
                .into_iter()
                .map(|m| {
                    serde_json::json!({"id": m.id, "created_at": m.created_at, "bytes": m.bytes(),
                        "name": m.owner.get("name"), "github": m.owner.get("github"), "head": m.owner.get("head"),
                        "heads": m.owner.get("heads").and_then(|h| h.as_array()).map(Vec::len)})
                })
                .collect();
            if !json {
                for item in &items {
                    println!(
                        "{}  {} heads  {} bytes",
                        item["id"].as_str().unwrap_or_default(),
                        item["heads"],
                        item["bytes"]
                    );
                }
                return Ok(0);
            }
            serde_json::json!({ "snapshots": items })
        }
        GitAction::Stats => serde_json::to_value(layer::stats(&storage, gitlayer::LAYER)?)?,
        GitAction::Prune(args) => return prune_layer(config, gitlayer::LAYER, args),
        GitAction::Verify { id } => gitlayer::verify(config, &storage, &id)?,
        GitAction::Restore { id, into } => {
            let mut journal = Journal::open(&config.rbq_home)?;
            gitlayer::restore(config, &storage, &id, &absolute(into)?, &mut journal)?
        }
        GitAction::Fetch { id, repo, name } => {
            let mut journal = Journal::open(&config.rbq_home)?;
            gitlayer::fetch(
                config,
                &storage,
                &id,
                &absolute(repo)?,
                name.as_deref(),
                &mut journal,
            )?
        }
    };
    println!("{}", serde_json::to_string_pretty(&value)?);
    Ok(0)
}

#[cfg(not(feature = "storage"))]
fn git_action(_: &rebsync_core::Config, _: GitAction, _: bool) -> Result<i32> {
    bail!("rbq was built without the storage feature; rebuild with --features storage")
}

#[cfg(feature = "serve")]
fn serve(config: &rebsync_core::Config, options: rebsync_core::serve::ServeOptions) -> Result<i32> {
    use rebsync_core::FsObjectStorage;
    let storage = FsObjectStorage::open(&config.storage.root)?;
    let running = rebsync_core::serve::start(config, &options)?;
    eprintln!("rbq serving {}", running.url);
    if let Some(fingerprint) = &running.fingerprint {
        eprintln!("self-signed certificate SHA-256 {fingerprint}");
    }
    for a in &running.announcements {
        eprintln!(
            "  {} {}: {}",
            if a.ok { "✓" } else { "·" },
            a.mechanism,
            a.detail
        );
    }
    running.wait(config, &storage);
    Ok(0)
}

#[cfg(feature = "serve")]
fn restic_serve(config: &rebsync_core::Config, args: &ResticServeArgs) -> Result<i32> {
    use rebsync_core::restic_rest::{self, Repository, ResticOptions};
    use std::sync::Arc;
    let password = restic_rest::read_password_file(&args.password_file)?;
    let mut fingerprint = None;
    let tls = match (&args.tls_cert, &args.tls_key) {
        (Some(cert), Some(key)) => Some((std::fs::read(cert)?, std::fs::read(key)?)),
        _ if args.tls_self_signed => {
            let mut names = vec![
                "localhost".to_owned(),
                "127.0.0.1".to_owned(),
                "::1".to_owned(),
            ];
            // Clients verify the name they connect to: include explicit names,
            // the listen address, and this machine's name on wildcard listeners.
            names.extend(args.tls_name.iter().cloned());
            let ip = args.listen.ip();
            if ip.is_unspecified() {
                let host = rebsync_core::serve::hostname();
                names.push(format!("{host}.local"));
                names.push(host);
            } else if !ip.is_loopback() {
                names.push(ip.to_string());
            }
            names.sort();
            names.dedup();
            let (cert, key, path, print) = restic_rest::self_signed_certificate(config, names)?;
            fingerprint = Some((path, print));
            Some((cert, key))
        }
        _ => None,
    };
    let root = args.storage.as_ref().unwrap_or(&config.storage.root);
    let storage = Arc::new(rebsync_core::FsObjectStorage::open(root)?);
    let repository = Arc::new(Repository::new(
        storage,
        &args.user,
        &password,
        !args.allow_delete,
        args.max_bytes,
    )?);
    let options = ResticOptions {
        bind: args.listen,
        user: args.user.clone(),
        password,
        append_only: !args.allow_delete,
        max_bytes: args.max_bytes,
        tls,
    };
    let server = restic_rest::bind(&options)?;
    eprintln!("rbq restic REST repository at {}", server.url);
    eprintln!(
        "  storage: {} (namespace restic/), {} bytes stored",
        root.display(),
        repository.used_bytes()
    );
    eprintln!(
        "  {}{}",
        if args.allow_delete {
            "deletion allowed"
        } else {
            "append-only: only locks can be deleted"
        },
        args.max_bytes
            .map(|max| format!(", quota {max} bytes"))
            .unwrap_or_default()
    );
    if let Some((path, print)) = &fingerprint {
        eprintln!(
            "  self-signed certificate {} (SHA-256 {print})",
            path.display()
        );
        eprintln!(
            "  restic --cacert {} -r rest:{}",
            path.display(),
            server
                .url
                .replacen("://", &format!("://{}:PASSWORD@", args.user), 1)
        );
    } else {
        eprintln!(
            "  restic -r rest:{}",
            server
                .url
                .replacen("://", &format!("://{}:PASSWORD@", args.user), 1)
        );
    }
    server.serve(repository, args.workers);
    Ok(0)
}

#[cfg(not(feature = "serve"))]
fn restic_serve(_: &rebsync_core::Config, _: &ResticServeArgs) -> Result<i32> {
    bail!("restic-serve requires the serve feature; rebuild with --features serve")
}

#[cfg(not(feature = "serve"))]
fn serve(_: &rebsync_core::Config, _: ()) -> Result<i32> {
    bail!("rbq was built without the serve feature; rebuild with --features serve")
}

/// Object prefixes for the named layers (every layer when none are named).
#[cfg(feature = "peer")]
fn layer_prefixes(layers: &[String]) -> Result<Vec<String>> {
    use rebsync_core::{layer, peer};
    if layers.is_empty() {
        return Ok(peer::default_prefixes());
    }
    layers
        .iter()
        .map(|l| {
            if layer::LAYERS.contains(&l.as_str()) {
                Ok(format!("{l}/"))
            } else {
                bail!("unknown layer {l}; use mneme, frog, agenda or git")
            }
        })
        .collect()
}

#[cfg(feature = "peer")]
fn drive_action(config: &rebsync_core::Config, action: DriveAction, json: bool) -> Result<i32> {
    use rebsync_core::{FsObjectStorage, drive, journal::Journal, peer};
    let (value, code, report) = match action {
        DriveAction::Enroll {
            path,
            name,
            adopt,
            allow_same_device,
        } => {
            let enrollment = drive::enroll(config, &path, &name, adopt, allow_same_device)?;
            (serde_json::to_value(&enrollment)?, 0, false)
        }
        DriveAction::List { search } => (
            serde_json::to_value(drive::status(config, &search)?)?,
            0,
            false,
        ),
        DriveAction::Forget { name } => (
            serde_json::to_value(drive::forget(config, &name)?)?,
            0,
            false,
        ),
        DriveAction::Push {
            name,
            layers,
            search,
        } => {
            let target = drive::open(config, &name, &search)?;
            let storage = FsObjectStorage::open(&config.storage.root)?;
            let mut journal = Journal::open(&config.rbq_home)?;
            let report = peer::push(&storage, &target, &layer_prefixes(&layers)?, &mut journal)?;
            let code = if report.clean() { 0 } else { 2 };
            (serde_json::to_value(report)?, code, true)
        }
        DriveAction::Pull {
            name,
            layers,
            search,
        } => {
            let source = drive::open(config, &name, &search)?;
            let storage = FsObjectStorage::open(&config.storage.root)?;
            let mut journal = Journal::open(&config.rbq_home)?;
            let report = peer::pull(&storage, &source, &layer_prefixes(&layers)?, &mut journal)?;
            let code = if report.clean() { 0 } else { 2 };
            (serde_json::to_value(report)?, code, true)
        }
    };
    if json || !report {
        println!("{}", serde_json::to_string_pretty(&value)?);
    } else {
        ui::peer_report(&value, code);
    }
    Ok(code)
}

#[cfg(not(feature = "peer"))]
fn drive_action(_: &rebsync_core::Config, _: DriveAction, _: bool) -> Result<i32> {
    bail!("rbq was built without the peer feature; rebuild with --features peer")
}

#[cfg(feature = "peer")]
fn peer_action(config: &rebsync_core::Config, action: PeerAction, json: bool) -> Result<i32> {
    use rebsync_core::{FsObjectStorage, journal::Journal, peer, transport};
    use std::sync::{Arc, atomic::AtomicBool};

    let connection = |args: &PeerTargetArgs| -> Result<(String, Option<String>)> {
        let connection = args
            .connection
            .clone()
            .or_else(|| std::env::var("RBQ_PEER").ok())
            .ok_or_else(|| anyhow::anyhow!("give a connection target or set RBQ_PEER"))?;
        let token = args
            .token_file
            .as_ref()
            .map(|path| transport::read_token_file(path))
            .transpose()?;
        Ok((connection, token))
    };
    let remote = |args: &PeerTargetArgs| -> Result<Box<dyn peer::PeerApi>> {
        let (connection, token) = connection(args)?;
        let trimmed = connection.trim();
        let bare = trimmed.strip_prefix("rbq+").unwrap_or(trimmed);
        if bare.starts_with("http://") || bare.starts_with("https://") {
            let target = peer::parse_connection(&connection, token.as_deref())?;
            Ok(Box::new(
                peer::Peer::connect(target)
                    .with_retries(args.retries)
                    .with_timeout(std::time::Duration::from_secs(args.timeout_seconds)),
            ))
        } else {
            let (target, token) = transport::parse_connection(&connection, token.as_deref())?;
            Ok(Box::new(transport::TransportPeer::connect(&target, token)?))
        }
    };
    let prefixes = layer_prefixes;
    let (value, code) = match action {
        PeerAction::Status { target } => {
            let remote = remote(&target)?;
            let status = remote.status()?;
            let mut per_layer = serde_json::Map::new();
            for prefix in peer::default_prefixes() {
                let objects = remote.list(&prefix)?;
                per_layer.insert(
                    prefix.trim_end_matches('/').into(),
                    serde_json::json!({"objects": objects.len(), "bytes": objects.values().sum::<u64>(),
                        "snapshots": objects.keys().filter(|k| k.contains("/snapshots/")).count()}),
                );
            }
            (serde_json::json!({"peer": status, "layers": per_layer}), 0)
        }
        PeerAction::Push { target, layers } => {
            let storage = FsObjectStorage::open(&config.storage.root)?;
            let remote = remote(&target)?;
            let mut journal = Journal::open(&config.rbq_home)?;
            let report = peer::push(&storage, remote.as_ref(), &prefixes(&layers)?, &mut journal)?;
            let code = if report.clean() { 0 } else { 2 };
            (serde_json::to_value(report)?, code)
        }
        PeerAction::Pull { target, layers } => {
            let storage = FsObjectStorage::open(&config.storage.root)?;
            let remote = remote(&target)?;
            let mut journal = Journal::open(&config.rbq_home)?;
            let report = peer::pull(&storage, remote.as_ref(), &prefixes(&layers)?, &mut journal)?;
            let code = if report.clean() { 0 } else { 2 };
            (serde_json::to_value(report)?, code)
        }
        PeerAction::Serve(args) => {
            let storage = FsObjectStorage::open(&config.storage.root)?;
            let token = transport::read_token_file(&args.token_file)?;
            let service =
                transport::Service::new(Arc::new(storage), token, Arc::new(AtomicBool::new(false)));
            let mut servers = Vec::new();
            for listen in &args.listen {
                let target = transport::Target::parse(listen)?;
                if target.is_public() {
                    eprintln!(
                        "rbq: warning: {} is reachable beyond this host and is not encrypted",
                        target.describe()
                    );
                }
                servers.push(transport::Server::bind(
                    &target,
                    service.clone(),
                    args.replace_stale,
                )?);
            }
            let serving: Vec<String> = servers
                .iter()
                .map(|server| server.target.describe())
                .collect();
            println!(
                "{}",
                serde_json::to_string_pretty(&serde_json::json!({
                    "protocol": transport::PROTOCOL,
                    "serving": serving,
                    "note": "Additive only: create-if-absent, no overwrite and no delete.",
                }))?
            );
            loop {
                std::thread::park();
            }
        }
        PeerAction::Selftest => {
            let report = transport::selftest()?;
            let code = if report.ok { 0 } else { 2 };
            (serde_json::to_value(report)?, code)
        }
    };
    if json {
        println!("{}", serde_json::to_string_pretty(&value)?);
    } else {
        ui::peer_report(&value, code);
    }
    Ok(code)
}

#[cfg(not(feature = "peer"))]
fn peer_action(_: &rebsync_core::Config, _: PeerAction, _: bool) -> Result<i32> {
    bail!("rbq was built without the peer feature; rebuild with --features peer")
}

#[cfg(not(feature = "storage"))]
fn mneme_action(_config: &rebsync_core::Config, _action: MnemeAction, _json: bool) -> Result<i32> {
    bail!("rbq was built without the storage feature; rebuild with --features storage")
}

#[cfg(feature = "storage")]
fn storage_fsck(config: &rebsync_core::Config, layers: Vec<String>) -> Result<i32> {
    use rebsync_core::{FsObjectStorage, layer};
    let storage = FsObjectStorage::open(&config.storage.root)?;
    let selected: Vec<&str> = if layers.is_empty() {
        layer::LAYERS.to_vec()
    } else {
        layers.iter().map(String::as_str).collect()
    };
    let report = layer::fsck(&storage, &selected)?;
    println!("{}", serde_json::to_string_pretty(&report)?);
    Ok(if report.failures.is_empty() { 0 } else { 2 })
}

#[cfg(not(feature = "storage"))]
fn storage_fsck(_: &rebsync_core::Config, _: Vec<String>) -> Result<i32> {
    bail!("rbq was built without the storage feature; rebuild with --features storage")
}

#[cfg(not(feature = "storage"))]
fn storage_check(_config: &rebsync_core::Config, _json: bool) -> Result<i32> {
    bail!("rbq was built without the storage feature; rebuild with --features storage")
}

fn main() {
    match entry() {
        Ok(code) => std::process::exit(code),
        Err(error) => {
            if let Some(migration) =
                error.downcast_ref::<rebsync_core::migration::MigrationBlocked>()
            {
                if std::env::args().any(|arg| arg == "--json") {
                    println!(
                        "{}",
                        serde_json::json!({"status": "blocked", "migration": migration})
                    );
                } else {
                    eprintln!("rbq: {error:#}");
                }
                std::process::exit(2);
            }
            eprintln!("rbq: {error:#}");
            std::process::exit(1);
        }
    }
}
fn entry() -> Result<i32> {
    let cli = Cli::parse();
    ui::configure(
        cli.color,
        cli.json
            || matches!(
                cli.command,
                Some(Action::Completions { .. } | Action::Repository(_) | Action::Artifacts(_))
            ),
    );
    if let Some(Action::Completions { shell }) = &cli.command {
        if cli.json {
            bail!("completions emits shell code; omit --json");
        }
        clap_complete::generate(*shell, &mut Cli::command(), "rbq", &mut std::io::stdout());
        return Ok(0);
    }
    // Diagnostics/guides are independent of backup config and must not create
    // state directories, journals or object stores just to inspect a phone.
    if let Some(Action::Phone { command }) = &cli.command {
        return phone_action(command, cli.json);
    }
    if let Some(Action::Repository(args)) = &cli.command {
        return repository_cli::run(args);
    }
    if let Some(Action::Artifacts(args)) = &cli.command {
        return artifacts_cli::run(args);
    }
    let config = load_config(ConfigOverrides {
        rbq_home: cli.home,
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
        Some(Action::Completions { .. }) => {
            unreachable!("completions return before config loading")
        }
        Some(Action::Phone { .. }) => unreachable!("phone actions return before config loading"),
        Some(Action::Repository(_)) => {
            unreachable!("repository actions return before config loading")
        }
        Some(Action::Artifacts(_)) => unreachable!("artifact actions return before config loading"),
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
            StorageAction::Fsck { layers } => return storage_fsck(&config.config, layers),
        },
        Some(Action::Mneme { command }) => return mneme_action(&config.config, command, cli.json),
        Some(Action::Hypomnema { command }) => return hypomnema_action(&config.config, command),
        Some(Action::Frog { command }) => {
            return layer_action(&config.config, "frog", command, cli.json);
        }
        Some(Action::Agenda { command }) => {
            return layer_action(&config.config, "agenda", command, cli.json);
        }
        Some(Action::Peer { command }) => return peer_action(&config.config, command, cli.json),
        Some(Action::Drive { command }) => return drive_action(&config.config, command, cli.json),
        Some(Action::Git { command }) => return git_action(&config.config, command, cli.json),
        Some(Action::ResticServe(args)) => return restic_serve(&config.config, &args),
        Some(Action::Serve {
            port,
            bind,
            plain_http,
            no_announce,
        }) => {
            #[cfg(feature = "serve")]
            let options = rebsync_core::serve::ServeOptions {
                bind,
                port,
                tls: !plain_http,
                announce: !no_announce,
            };
            #[cfg(not(feature = "serve"))]
            let options = {
                let _ = (port, bind, plain_http, no_announce);
            };
            return serve(&config.config, options);
        }
        None => {}
    }
    let summary = rebsync_core::run(&config.config, RunOptions { apply: cli.apply })?;
    if cli.json {
        println!("{}", serde_json::to_string_pretty(&summary)?);
    } else {
        println!(
            "{}  {}",
            ui::heading("RBQ"),
            if summary.dry_run {
                ui::heading("PLAN / DRY RUN")
            } else {
                ui::warning("APPLY")
            }
        );
        println!(
            "  {} repositories  ·  {}",
            summary.repositories.len(),
            if summary.needs_attention() {
                ui::warning("attention required")
            } else {
                ui::good("checks complete")
            }
        );
        for repo in &summary.repositories {
            println!("\n{}", ui::heading(&repo.path.display().to_string()));
            if let Some(id) = &repo.backup_snapshot {
                println!("  {} {id}", ui::good("encrypted backup"));
            }
            for action in &repo.actions {
                println!("  {action}");
            }
            for issue in &repo.issues {
                println!("  {} {}", ui::warning("!"), ui::warning(issue));
            }
        }
        for issue in &summary.issues {
            println!("\n{} {}", ui::warning("!"), ui::warning(issue));
        }
        for dataset in &summary.datasets {
            println!("\ndataset: {dataset}");
        }
        println!("\n{} {}", ui::dim("Journal"), summary.journal.display());
    }
    Ok(if summary.needs_attention() { 2 } else { 0 })
}
