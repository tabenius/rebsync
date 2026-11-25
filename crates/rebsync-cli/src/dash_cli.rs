//! `rbq dash`: pair this device with Dash and manage its sync credentials.
//!
//! The credential store is selected explicitly (`--credential-store` or
//! `RBQ_CREDENTIAL_STORE`); there is no default location, so no command ever
//! writes a secret somewhere the user did not choose. Output is JSON on
//! stdout; human guidance goes to stderr. No command prints a token or nonce.
use anyhow::Result;
use clap::{Args, Subcommand, ValueEnum};
use std::path::PathBuf;

/// How stored credentials are protected at rest.
#[derive(Clone, Copy, ValueEnum, PartialEq, Eq, Debug)]
pub enum Seal {
    /// Encrypt each credential with a key kept in the desktop's Secret
    /// Service (GNOME Keyring, KWallet, KeePassXC).
    SecretService,
    /// Owner-only files only, not encrypted at rest: for headless machines
    /// without a Secret Service, chosen explicitly.
    None,
}

#[derive(Args)]
pub struct DashArgs {
    /// Directory of owner-only credential files (mode 0700).
    #[arg(long, env = "RBQ_CREDENTIAL_STORE")]
    credential_store: PathBuf,
    /// Protection at rest: `secret-service` encrypts with a key in your
    /// desktop keyring; `none` (headless) leaves owner-only plaintext.
    #[arg(
        long,
        env = "RBQ_CREDENTIAL_SEAL",
        value_enum,
        default_value = "secret-service"
    )]
    seal: Seal,
    #[command(subcommand)]
    command: DashAction,
}

#[derive(Clone, Copy, ValueEnum)]
enum ScopeArg {
    Describe,
    List,
    Read,
    Append,
    Connector,
}

#[derive(Clone, Copy, ValueEnum)]
enum ConnectorActionArg {
    Pending,
    Push,
    Results,
}

#[derive(Subcommand)]
enum DashAction {
    /// Send one bounded connector request using a connector-only paired grant.
    /// Push/results read JSON from stdin. Output contains no credential.
    Connector {
        #[arg(long)]
        credential: String,
        /// Exact existing Dash instance; a mismatching grant is refused.
        #[arg(long)]
        instance: String,
        #[arg(long, env = "RBQ_DASH", default_value = "https://dash.ragbaz.cc")]
        dash: String,
        #[arg(value_enum)]
        action: ConnectorActionArg,
    },
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
    /// Make sure this device is paired, for unattended use (a systemd timer):
    /// does nothing if a usable credential for this Dash has at least
    /// --renew-days left; otherwise resumes a pairing still awaiting approval,
    /// or starts one, and waits for you to approve it in Dash. Exit 0 when
    /// paired, 2 when still awaiting approval (run again later).
    Ensure {
        /// Dash origin.
        #[arg(long, env = "RBQ_DASH", default_value = "https://dash.ragbaz.cc")]
        dash: String,
        /// How this device appears in Dash (default: the host name).
        #[arg(long, env = "RBQ_DASH_LABEL")]
        label: Option<String>,
        /// Scopes to require and request; repeat. Default: all four.
        #[arg(long = "scope", value_enum)]
        scopes: Vec<ScopeArg>,
        /// Credential lifetime in days when a new pairing is needed (1..90).
        #[arg(long, default_value_t = 30)]
        days: u64,
        /// Pair again when the current credential has fewer days left.
        #[arg(long, default_value_t = 7)]
        renew_days: u64,
        /// Seconds to wait for approval in this run.
        #[arg(long, default_value_t = 600)]
        timeout: u64,
        /// Also show the matching code and approval link as a desktop
        /// notification (notify-send), when a pairing awaits approval.
        #[arg(long)]
        notify: bool,
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
    use rebsync_core::credentials::CredentialStore;
    use rebsync_core::dash_pairing::{self as pairing, Dash, Outcome, PendingStore};
    use std::time::Duration;

    let store = credential_store(&args.credential_store, args.seal)?;
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
        DashAction::Connector {
            credential,
            instance,
            dash,
            action,
        } => {
            use pairing::ConnectorAction;
            use std::io::Read;
            let operation = match action {
                ConnectorActionArg::Pending => ConnectorAction::Pending,
                ConnectorActionArg::Push => ConnectorAction::Push,
                ConnectorActionArg::Results => ConnectorAction::Results,
            };
            let body = if matches!(action, ConnectorActionArg::Pending) {
                None
            } else {
                let mut raw = Vec::new();
                std::io::stdin()
                    .take(512 * 1024 + 1)
                    .read_to_end(&mut raw)?;
                anyhow::ensure!(
                    raw.len() <= 512 * 1024,
                    "connector request exceeds size limit"
                );
                Some(
                    serde_json::from_slice(&raw)
                        .map_err(|_| anyhow!("connector stdin must be JSON"))?,
                )
            };
            print(serde_json::to_value(pairing::connector_request(
                &store, credential, dash, instance, operation, body,
            )?)?)?;
            Ok(0)
        }
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
            let scopes = requested_scopes(scopes);
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
        DashAction::Ensure {
            dash,
            label,
            scopes,
            days,
            renew_days,
            timeout,
            notify,
        } => {
            let dash = Dash::new(dash)?;
            let scopes = requested_scopes(scopes);
            if *days == 0 || *days > 90 {
                bail!("a paired credential lives 1 to 90 days");
            }
            if *renew_days >= *days {
                bail!("--renew-days must be less than --days, or every run would pair again");
            }
            let now = now();
            // 1. Already paired, with enough life left: nothing to do.
            let current = store
                .list()
                .map_err(|e| anyhow!("credential store: {e:?}"))?
                .into_iter()
                .filter(|c| {
                    c.audience.account_id == dash.origin()
                        && c.kind == rebsync_core::credentials::CredentialKind::DashBearer
                        && c.created_at <= now
                        && !c.disabled
                        && scopes.iter().all(|s| c.scopes.contains(s))
                        && (!scopes.contains(&rebsync_core::credentials::Scope::Connector)
                            || c.scopes == [rebsync_core::credentials::Scope::Connector])
                        && c.expires_at > now + renew_days * 86_400
                })
                .max_by_key(|c| c.expires_at);
            if let Some(credential) = current {
                print(
                    serde_json::json!({ "paired": true, "action": "none", "credential": credential }),
                )?;
                return Ok(0);
            }
            // 2. A pairing for this Dash still awaiting approval: keep waiting
            //    on it, rather than piling up requests. Expired ones are gone
            //    at Dash; forget them here.
            let mut resumable = None;
            for summary in pending_store.list().into_iter().filter(|p| {
                p.dash == dash.origin()
                    && p.scopes.iter().all(|s| scopes.contains(s))
                    && scopes.iter().all(|s| p.scopes.contains(s))
            }) {
                if summary.expires_at > now + 30 && resumable.is_none() {
                    resumable = Some(pending_store.load(&summary.pairing_id)?);
                } else if summary.expires_at <= now {
                    pending_store.remove(&summary.pairing_id)?;
                }
            }
            // 3. Otherwise start one.
            let pending = match resumable {
                Some(pending) => pending,
                None => {
                    let label = label.clone().unwrap_or_else(default_label);
                    let pending = pairing::begin(&dash, &label, &scopes, days * 86_400)?;
                    pending_store.save(&pending)?;
                    pending
                }
            };
            print(serde_json::to_value(pending.summary())?)?;
            if *notify {
                notify_approval(&pending);
            }
            wait(&pending, *timeout)
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

/// The requested scopes, or all four by default.
#[cfg(feature = "peer")]
fn requested_scopes(scopes: &[ScopeArg]) -> Vec<rebsync_core::credentials::Scope> {
    use rebsync_core::credentials::Scope;
    if scopes.is_empty() {
        return vec![Scope::Describe, Scope::List, Scope::Read, Scope::Append];
    }
    scopes
        .iter()
        .map(|scope| match scope {
            ScopeArg::Describe => Scope::Describe,
            ScopeArg::List => Scope::List,
            ScopeArg::Read => Scope::Read,
            ScopeArg::Append => Scope::Append,
            ScopeArg::Connector => Scope::Connector,
        })
        .collect()
}

#[cfg(feature = "peer")]
fn now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or_default()
}

/// A desktop notification with what you need to approve: the matching code
/// and the approval link. Neither is a secret (the claim nonce stays here).
/// Best effort: no notification daemon is not an error.
#[cfg(feature = "peer")]
fn notify_approval(pending: &rebsync_core::dash_pairing::Pending) {
    let body = format!(
        "Approve '{}' in Dash if it shows code {}:\n{}",
        pending.device_label, pending.matching_code, pending.approval_url
    );
    let shown = rebsync_core::process::run(
        rebsync_core::process::command("notify-send").args([
            "--",
            "RAGBAZ: pair this device",
            &body,
        ]),
        5,
        None,
    )
    .is_ok_and(|output| output.success);
    if !shown {
        eprintln!("(no desktop notification: notify-send unavailable)");
    }
}

/// The credential store in `dir`, sealed as `seal` says. There is no
/// fallback: if the Secret Service is unavailable, say so and stop.
#[cfg(feature = "peer")]
pub fn credential_store(
    dir: &std::path::Path,
    seal: Seal,
) -> Result<rebsync_core::credentials::files::FileStore> {
    let store = rebsync_core::dash_pairing::open_store(dir)?;
    match seal {
        Seal::None => Ok(store),
        #[cfg(all(feature = "secret-service", target_os = "linux"))]
        Seal::SecretService => {
            use rebsync_core::credentials::secret_service::SecretServiceSealer;
            let sealer = SecretServiceSealer::for_store(store.dir()).map_err(|error| {
                anyhow::anyhow!(
                    "the Secret Service is unavailable or locked ({error:?}). Unlock your keyring, \
                     or on a headless machine pass --seal none (RBQ_CREDENTIAL_SEAL=none) to keep \
                     owner-only files that are not encrypted at rest"
                )
            })?;
            Ok(store.with_sealer(std::sync::Arc::new(sealer)))
        }
        #[cfg(not(all(feature = "secret-service", target_os = "linux")))]
        Seal::SecretService => anyhow::bail!(
            "this rbq has no Secret Service support; pass --seal none (RBQ_CREDENTIAL_SEAL=none) \
             to keep owner-only files that are not encrypted at rest"
        ),
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
