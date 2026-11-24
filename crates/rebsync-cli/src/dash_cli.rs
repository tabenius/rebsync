//! `rbq dash`: pair this device with Dash and manage its sync credentials.
//!
//! The credential store is selected explicitly (`--credential-store` or
//! `RBQ_CREDENTIAL_STORE`); there is no default location, so no command ever
//! writes a secret somewhere the user did not choose. Output is JSON on
//! stdout; human guidance goes to stderr. No command prints a token or nonce.
use anyhow::Result;
use clap::{Args, Subcommand, ValueEnum};
use std::path::PathBuf;

#[derive(Args)]
pub struct DashArgs {
    /// Directory of owner-only credential files (mode 0700). Not encrypted at
    /// rest: anyone who can read it as you can use the credentials in it.
    #[arg(long, env = "RBQ_CREDENTIAL_STORE")]
    credential_store: PathBuf,
    #[command(subcommand)]
    command: DashAction,
}

#[derive(Clone, Copy, ValueEnum)]
enum ScopeArg {
    Describe,
    List,
    Read,
    Append,
}

#[derive(Subcommand)]
enum DashAction {
    /// Ask Dash to pair this device, then wait for passkey approval in Dash
    /// and store the issued credential. Prints the matching code and approval
    /// URL first; compare the code with the one Dash shows before approving.
    Pair {
        /// Dash origin.
        #[arg(long, env = "RBQ_DASH", default_value = "https://dash.ragbaz.cc")]
        dash: String,
        /// How this device appears in Dash (default: the host name).
        #[arg(long)]
        label: Option<String>,
        /// Scopes to request; repeat. Default: describe, list, read, append.
        #[arg(long = "scope", value_enum)]
        scopes: Vec<ScopeArg>,
        /// Credential lifetime in days (1 hour minimum when 0; at most 90).
        #[arg(long, default_value_t = 30)]
        days: u64,
        /// Seconds to wait for approval (the request itself lasts 10 minutes).
        #[arg(long, default_value_t = 600)]
        timeout: u64,
        /// Only start the pairing; finish it later with `rbq dash wait`.
        #[arg(long)]
        no_wait: bool,
    },
    /// Wait for approval of a pairing started earlier, then claim and store it.
    Wait {
        pairing_id: String,
        #[arg(long, default_value_t = 600)]
        timeout: u64,
    },
    /// Cancel a pairing. If its credential was issued but never stored here
    /// (a lost response), this revokes it at Dash.
    Cancel { pairing_id: String },
    /// Pairings started here and not yet finished (no secrets).
    Pending,
    /// Credentials stored here (metadata only, never the token).
    Credentials,
    /// Stop using a stored credential on this device. Revoking it at Dash is
    /// done in Dash (signed in), which this device cannot do on its own.
    Disable { key_id: String },
}

#[cfg(feature = "peer")]
pub fn run(args: &DashArgs) -> Result<i32> {
    use anyhow::{anyhow, bail};
    use rebsync_core::credentials::{CredentialStore, Scope};
    use rebsync_core::dash_pairing::{self as pairing, Dash, Outcome, PendingStore};
    use std::time::Duration;

    let store = pairing::open_store(&args.credential_store)?;
    let pending_store = PendingStore::open(&store)?;
    let print = |value: serde_json::Value| -> Result<()> {
        println!("{}", serde_json::to_string_pretty(&value)?);
        Ok(())
    };
    let wait = |pending: &pairing::Pending, timeout: u64| -> Result<i32> {
        let dash = Dash::new(&pending.dash)?;
        eprintln!(
            "Approve in Dash: {}\nMatching code: {} (approve only if Dash shows the same code)",
            pending.approval_url, pending.matching_code
        );
        let mut last = None;
        let outcome = pairing::wait_and_claim(
            &dash,
            pending,
            &store,
            &pending_store,
            Duration::from_secs(3),
            Duration::from_secs(timeout),
            |state| {
                if last != Some(state) {
                    eprintln!("pairing {}: {state:?}", pending.pairing_id);
                    last = Some(state);
                }
            },
        )?;
        match outcome {
            Outcome::Stored(descriptor) => {
                print(serde_json::json!({ "paired": true, "credential": descriptor }))?;
                Ok(0)
            }
            Outcome::Ended(state) => {
                print(
                    serde_json::json!({ "paired": false, "pairing_id": pending.pairing_id, "state": state }),
                )?;
                Ok(2)
            }
            Outcome::StillPending => {
                print(
                    serde_json::json!({ "paired": false, "pairing_id": pending.pairing_id, "state": "pending",
                    "resume": format!("rbq dash wait {}", pending.pairing_id) }),
                )?;
                Ok(2)
            }
        }
    };

    match &args.command {
        DashAction::Pair {
            dash,
            label,
            scopes,
            days,
            timeout,
            no_wait,
        } => {
            let dash = Dash::new(dash)?;
            let label = match label {
                Some(label) => label.clone(),
                None => default_label(),
            };
            let scopes: Vec<Scope> = if scopes.is_empty() {
                vec![Scope::Describe, Scope::List, Scope::Read, Scope::Append]
            } else {
                scopes
                    .iter()
                    .map(|scope| match scope {
                        ScopeArg::Describe => Scope::Describe,
                        ScopeArg::List => Scope::List,
                        ScopeArg::Read => Scope::Read,
                        ScopeArg::Append => Scope::Append,
                    })
                    .collect()
            };
            if *days > 90 {
                bail!("a paired credential lives at most 90 days");
            }
            let lifetime = (days * 86_400).max(pairing::MIN_LIFETIME);
            let pending = pairing::begin(&dash, &label, &scopes, lifetime)?;
            pending_store.save(&pending)?;
            print(serde_json::to_value(pending.summary())?)?;
            if *no_wait {
                eprintln!(
                    "Approve in Dash: {}\nMatching code: {}\nThen run: rbq dash wait {}",
                    pending.approval_url, pending.matching_code, pending.pairing_id
                );
                return Ok(0);
            }
            wait(&pending, *timeout)
        }
        DashAction::Wait {
            pairing_id,
            timeout,
        } => wait(&pending_store.load(pairing_id)?, *timeout),
        DashAction::Cancel { pairing_id } => {
            let pending = pending_store.load(pairing_id)?;
            let state = pairing::cancel(&Dash::new(&pending.dash)?, &pending)?;
            pending_store.remove(pairing_id)?;
            print(serde_json::json!({ "pairing_id": pairing_id, "state": state }))?;
            Ok(0)
        }
        DashAction::Pending => {
            print(serde_json::json!({ "pending": pending_store.list() }))?;
            Ok(0)
        }
        DashAction::Credentials => {
            let list = store
                .list()
                .map_err(|e| anyhow!("credential store: {e:?}"))?;
            print(serde_json::json!({ "credentials": list }))?;
            Ok(0)
        }
        DashAction::Disable { key_id } => {
            store
                .disable(key_id)
                .map_err(|e| anyhow!("could not disable {key_id}: {e:?}"))?;
            eprintln!("Disabled here. Revoke it in Dash too, so it stops working everywhere.");
            print(serde_json::json!({ "key_id": key_id, "disabled": true }))?;
            Ok(0)
        }
    }
}

/// The host name as a Dash label, or a generic one.
#[cfg(feature = "peer")]
fn default_label() -> String {
    let name = std::fs::read_to_string("/etc/hostname")
        .ok()
        .or_else(|| std::env::var("HOSTNAME").ok())
        .unwrap_or_default();
    let name: String = name
        .trim()
        .chars()
        .filter(|c| !c.is_control())
        .take(64)
        .collect();
    if rebsync_core::dash_pairing::valid_label(&name) {
        name
    } else {
        "rbq device".into()
    }
}

#[cfg(not(feature = "peer"))]
pub fn run(_args: &DashArgs) -> Result<i32> {
    anyhow::bail!("Dash pairing requires the peer feature; rebuild with --features peer")
}
