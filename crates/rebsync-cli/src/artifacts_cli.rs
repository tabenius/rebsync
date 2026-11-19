use anyhow::Result;
use clap::{Args, Subcommand};
use std::path::PathBuf;

#[derive(Args)]
pub struct ArtifactArgs {
    /// Your token-free private Dash /mcp/ID endpoint; not /api/rbq/ID.
    #[arg(long)]
    endpoint: String,
    /// Owner-only bearer token file; enable artifact browsing in Dash first.
    #[arg(long)]
    token_file: PathBuf,
    #[command(subcommand)]
    command: ArtifactAction,
}

#[derive(Args)]
struct Reference {
    #[arg(long)]
    source: String,
    #[arg(long)]
    id: String,
}

#[derive(Subcommand)]
enum ArtifactAction {
    /// List authorized sources, capabilities and factory references.
    Sources,
    /// List a bounded page; preserve both source_id and id in every reference.
    List {
        #[arg(long)]
        source: Option<String>,
        #[arg(long, requires = "factory_source")]
        factory_id: Option<String>,
        #[arg(long, requires = "factory_id")]
        factory_source: Option<String>,
        #[arg(long, requires = "after_source")]
        after_id: Option<String>,
        #[arg(long, requires = "after_id")]
        after_source: Option<String>,
        #[arg(long, default_value_t = 20)]
        limit: usize,
    },
    /// Read artifact metadata and available navigation; does not read its content.
    Get(Reference),
    /// Inspect supplied provenance, not a new cryptographic verification claim.
    Provenance(Reference),
    /// Read an authorized Frog projection; never changes tasks or decisions.
    ReadFrog(Reference),
    /// Read a Unicode-code-point source slice, returned as JSON (not executed/rendered).
    ReadPiece {
        #[command(flatten)]
        reference: Reference,
        #[arg(long, default_value_t = 0)]
        offset: usize,
        #[arg(long, default_value_t = 4000)]
        limit: usize,
        #[arg(long)]
        expected_revision: Option<String>,
    },
}

#[cfg(feature = "peer")]
pub fn run(args: &ArtifactArgs) -> Result<i32> {
    use rebsync_core::artifacts::{Artifacts, SourceRef};
    let reference = |value: &Reference| SourceRef::new(value.source.clone(), value.id.clone());
    let mut client = Artifacts::from_token_file(&args.endpoint, &args.token_file)?;
    let value = match &args.command {
        ArtifactAction::Sources => client.sources()?,
        ArtifactAction::List {
            source,
            factory_id,
            factory_source,
            after_id,
            after_source,
            limit,
        } => {
            let pair = |source: &Option<String>, id: &Option<String>| match (source, id) {
                (Some(source), Some(id)) => SourceRef::new(source.clone(), id.clone()).map(Some),
                _ => Ok(None),
            };
            client.list(
                source.as_deref(),
                pair(factory_source, factory_id)?.as_ref(),
                pair(after_source, after_id)?.as_ref(),
                *limit,
            )?
        }
        ArtifactAction::Get(value) => client.get(&reference(value)?)?,
        ArtifactAction::Provenance(value) => client.provenance(&reference(value)?)?,
        ArtifactAction::ReadFrog(value) => client.read_frog(&reference(value)?)?,
        ArtifactAction::ReadPiece {
            reference: value,
            offset,
            limit,
            expected_revision,
        } => client.read_piece(
            &reference(value)?,
            *offset,
            *limit,
            expected_revision.as_deref(),
        )?,
    };
    println!("{}", serde_json::to_string_pretty(&value)?);
    Ok(0)
}

#[cfg(not(feature = "peer"))]
pub fn run(_args: &ArtifactArgs) -> Result<i32> {
    anyhow::bail!("artifact access requires the peer feature; rebuild with --features peer")
}
