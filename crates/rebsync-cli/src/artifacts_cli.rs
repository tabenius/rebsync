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
    /// Read a bounded page of arrivals; a read is not gift acceptance or approval.
    Arrivals {
        #[arg(long, default_value_t = 0)]
        after: u64,
        #[arg(long, default_value_t = 20)]
        limit: usize,
    },
    /// Poll arrivals as JSON lines. No content or notification permission is inferred.
    Watch {
        #[arg(long, default_value_t = 0)]
        after: u64,
        #[arg(long, default_value_t = 30, value_parser = clap::value_parser!(u64).range(5..=3600))]
        interval_seconds: u64,
        /// Zero watches until interrupted. A positive value bounds page fetches.
        #[arg(long, default_value_t = 0)]
        batches: u64,
        /// Explicitly request generic notify-send desktop notifications, no titles/content.
        #[arg(long)]
        notify: bool,
    },
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
    if let ArtifactAction::Watch {
        after,
        interval_seconds,
        batches,
        notify,
    } = &args.command
    {
        return watch(&mut client, *after, *interval_seconds, *batches, *notify);
    }
    let value = match &args.command {
        ArtifactAction::Arrivals { after, limit } => client.arrivals(*after, *limit)?,
        ArtifactAction::Watch { .. } => unreachable!("watch returns before one-page rendering"),
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

#[cfg(feature = "peer")]
fn watch(
    client: &mut rebsync_core::artifacts::Artifacts,
    mut after: u64,
    interval: u64,
    batches: u64,
    notify: bool,
) -> Result<i32> {
    use std::{io::Write, time::Duration};
    let mut fetched = 0;
    loop {
        let mut value = client.arrivals(after, 50)?;
        after = value["next_after"]
            .as_u64()
            .expect("arrival cursor validated by core");
        if notify
            && value["events"]
                .as_array()
                .is_some_and(|events| !events.is_empty())
        {
            // No authored text, URL, recipient keys or capability is passed to a
            // desktop helper. A notification never carries an approval action.
            let accepted = rebsync_core::process::run(
                rebsync_core::process::command("notify-send").args([
                    "--",
                    "RAGBAZ",
                    "New activity in your private inbox.",
                ]),
                5,
                None,
            )
            .is_ok_and(|output| output.success);
            value["desktop_notification"] = if accepted {
                "provider_accepted"
            } else {
                "unavailable_use_inbox"
            }
            .into();
        }
        println!("{}", serde_json::to_string(&value)?);
        std::io::stdout().flush()?;
        fetched += 1;
        if batches > 0 && fetched >= batches {
            return Ok(0);
        }
        // Drain pending pages promptly; only idle polling uses the interval.
        if value["has_more"] != true {
            std::thread::sleep(Duration::from_secs(interval));
        }
    }
}

#[cfg(not(feature = "peer"))]
pub fn run(_args: &ArtifactArgs) -> Result<i32> {
    anyhow::bail!("artifact access requires the peer feature; rebuild with --features peer")
}
