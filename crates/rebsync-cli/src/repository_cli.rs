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
    let repository = Repository::from_token_file(&args.endpoint, &args.token_file)?;
    let value = match &args.command {
        RepositoryAction::Describe => repository.describe()?,
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
    Ok(0)
}

#[cfg(not(feature = "peer"))]
pub fn run(_args: &RepositoryArgs) -> Result<i32> {
    anyhow::bail!("repository access requires the peer feature; rebuild with --features peer")
}
