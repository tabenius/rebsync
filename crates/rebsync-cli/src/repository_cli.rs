use anyhow::Result;
use clap::{Args, Subcommand};
use std::path::PathBuf;

#[derive(Args)]
pub struct RepositoryArgs {
    /// Token-free HTTPS endpoint returned by Dash's rbq_get_repository MCP tool.
    #[arg(long)]
    endpoint: String,
    /// Owner-only file containing the bearer token used for your Dash MCP URL.
    #[arg(long)]
    token_file: PathBuf,
    #[command(subcommand)]
    command: RepositoryAction,
}

#[derive(Subcommand)]
enum RepositoryAction {
    /// Resolve/provision your private account repository. Prints JSON, no token.
    Describe,
    /// List stable upstream source IDs and names; replicas remain separate.
    Sources,
    /// Push selected local layers into one immutable, named source namespace.
    Push {
        /// Existing local RBQ object-store root; read-only during transfer.
        #[arg(long)]
        store: PathBuf,
        /// Stable upstream source ID. Reuse it across retries and replicas.
        #[arg(long)]
        source_id: String,
        #[arg(long)]
        source_name: String,
        #[arg(long, value_parser = ["mneme", "frog", "agenda", "git"])]
        layer: Vec<String>,
    },
    /// Pull into STORE/sources/v1/SOURCE_ID/objects; no flattening or deletion.
    Pull {
        #[arg(long)]
        store: PathBuf,
        #[arg(long)]
        source_id: String,
        #[arg(long, value_parser = ["mneme", "frog", "agenda", "git"])]
        layer: Vec<String>,
    },
    /// List one bounded page; pass next_after as --after for another page.
    List {
        #[arg(long, default_value = "")]
        prefix: String,
        #[arg(long)]
        after: Option<String>,
        #[arg(long, default_value_t = 20)]
        limit: usize,
    },
    /// Download and hash-verify bytes into a NEW owner-only file; never overwrite.
    Read {
        key: String,
        #[arg(long)]
        output: PathBuf,
    },
    /// Append bytes under an immutable key (256 KiB maximum); identical retries succeed.
    Append {
        key: String,
        #[arg(long)]
        file: PathBuf,
    },
}

#[cfg(feature = "peer")]
pub fn run(args: &RepositoryArgs) -> Result<i32> {
    use rebsync_core::repository::{Repository, read_input, write_output};
    use rebsync_core::{FsObjectStorage, repository_sync};
    let repository = Repository::from_token_file(&args.endpoint, &args.token_file)?;
    let mut exit = 0;
    let value = match &args.command {
        RepositoryAction::Describe => repository.describe()?,
        RepositoryAction::Sources => {
            serde_json::json!({"sources":repository_sync::sources(&repository)?})
        }
        RepositoryAction::Push {
            store,
            source_id,
            source_name,
            layer,
        } => {
            anyhow::ensure!(
                store.is_dir(),
                "push requires an existing local object-store directory"
            );
            let storage = FsObjectStorage::open(store)?;
            let source = repository_sync::Source::new(source_id, source_name)?;
            let layers = selected_layers(layer);
            let report = repository_sync::push(&repository, &storage, &source, &layers)?;
            if !report.complete {
                exit = 2;
            }
            serde_json::to_value(report)?
        }
        RepositoryAction::Pull {
            store,
            source_id,
            layer,
        } => {
            let storage = FsObjectStorage::open(store)?;
            let layers = selected_layers(layer);
            let report = repository_sync::pull(&repository, &storage, source_id, &layers)?;
            if !report.complete {
                exit = 2;
            }
            serde_json::to_value(report)?
        }
        RepositoryAction::List {
            prefix,
            after,
            limit,
        } => repository.list(prefix, after.as_deref(), *limit)?,
        RepositoryAction::Append { key, file } => repository.append(key, &read_input(file)?)?,
        RepositoryAction::Read { key, output } => {
            let bytes = repository.read(key)?;
            write_output(output, &bytes)?;
            serde_json::json!({"key": key, "output": output, "size_bytes": bytes.len(), "verified": true})
        }
    };
    println!("{}", serde_json::to_string_pretty(&value)?);
    Ok(exit)
}

#[cfg(feature = "peer")]
fn selected_layers(layers: &[String]) -> Vec<String> {
    if layers.is_empty() {
        rebsync_core::layer::LAYERS
            .iter()
            .map(|name| (*name).into())
            .collect()
    } else {
        layers.to_vec()
    }
}

#[cfg(not(feature = "peer"))]
pub fn run(_args: &RepositoryArgs) -> Result<i32> {
    anyhow::bail!("repository access requires the peer feature; rebuild with --features peer")
}
