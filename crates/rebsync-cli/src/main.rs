use anyhow::Result;
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
    #[arg(long)]
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
}
#[derive(Subcommand)]
enum ConfigAction {
    Explain,
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
