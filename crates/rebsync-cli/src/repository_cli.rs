use anyhow::Result;
use clap::{Args, Subcommand};
use std::path::PathBuf;

#[derive(Args)]
pub struct RepositoryArgs {
    /// Token-free HTTPS endpoint returned by Dash's rbq_get_repository MCP tool.
    #[arg(long, requires = "token_file", conflicts_with = "credential")]
    endpoint: Option<String>,
    /// Owner-only file containing the bearer token used for your Dash MCP URL.
    #[arg(long, requires = "endpoint")]
    token_file: Option<PathBuf>,
    /// A credential from `rbq dash pair`, by key id. Its stored grant must
    /// cover the command (describe, list, read or append).
    #[arg(
        long,
        requires = "credential_store",
        required_unless_present = "endpoint"
    )]
    credential: Option<String>,
    /// The credential store `rbq dash pair` wrote to.
    #[arg(long, env = "RBQ_CREDENTIAL_STORE")]
    credential_store: Option<PathBuf>,
    /// How that store is sealed (as for `rbq dash`).
    #[arg(
        long,
        env = "RBQ_CREDENTIAL_SEAL",
        value_enum,
        default_value = "secret-service"
    )]
    seal: crate::dash_cli::Seal,
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
        #[arg(long, default_value_t = rebsync_core::rbq_contract::LIST_LIMIT_DEFAULT)]
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
    let repository = match (
        &args.endpoint,
        &args.token_file,
        &args.credential,
        &args.credential_store,
    ) {
        (Some(endpoint), Some(token_file), None, _) => {
            Repository::from_token_file(endpoint, token_file)?
        }
        (None, None, Some(id), Some(dir)) => stored(dir, args.seal, id, scope_for(&args.command))?,
        _ => anyhow::bail!(
            "give --endpoint with --token-file, or --credential with --credential-store"
        ),
    };
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

/// The scope a command needs from a paired credential. Dash enforces each
/// request's own scope too; this refuses early, before the token is read.
#[cfg(feature = "peer")]
fn scope_for(action: &RepositoryAction) -> rebsync_core::credentials::Scope {
    use rebsync_core::credentials::Scope;
    match action {
        RepositoryAction::Describe => Scope::Describe,
        RepositoryAction::Sources | RepositoryAction::List { .. } => Scope::List,
        RepositoryAction::Read { .. } | RepositoryAction::Pull { .. } => Scope::Read,
        RepositoryAction::Append { .. } | RepositoryAction::Push { .. } => Scope::Append,
    }
}

/// Connect with a stored credential, after its stored grant allows `scope`.
#[cfg(feature = "peer")]
fn stored(
    dir: &std::path::Path,
    seal: crate::dash_cli::Seal,
    id: &str,
    scope: rebsync_core::credentials::Scope,
) -> Result<rebsync_core::repository::Repository> {
    use rebsync_core::credentials::CredentialStore;
    let store = crate::dash_cli::credential_store(dir, seal)?;
    let descriptor = store
        .descriptor(id)
        .map_err(|e| anyhow::anyhow!("no usable credential {id} ({e:?})"))?;
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or_default();
    let secret = store
        .use_secret(id, &descriptor.audience, &scope, now)
        .map_err(|error| {
            use rebsync_core::credentials::StoreError;
            match error {
                StoreError::Locked => anyhow::anyhow!(
                    "credential {id} is sealed with a key this run cannot use: unlock your keyring, \
                     or use the --seal it was stored with"
                ),
                StoreError::Invalid => anyhow::anyhow!(
                    "credential {id} does not open: it was sealed by another key, or altered"
                ),
                _ => anyhow::anyhow!(
                    "credential {id} does not allow {scope:?} now (expired, disabled or not granted)"
                ),
            }
        })?;
    let token = std::str::from_utf8(secret.expose())
        .map_err(|_| anyhow::anyhow!("credential {id} is unreadable"))?;
    rebsync_core::repository::Repository::connect(&descriptor.audience.endpoint, token)
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
