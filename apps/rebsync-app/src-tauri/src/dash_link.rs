//! Pairing this phone with Dash: the phone's own, passkey-approved credential
//! to the owner's private RBQ repository (rebsync `dash_pairing`).
//!
//! The phone starts a pairing and shows its matching code and Dash's approval
//! URL; the owner approves it in Dash with a passkey on any device; the phone
//! then collects the credential, once. No token or nonce ever reaches the web
//! view: commands return metadata only.
//!
//! Credentials live in the app's private storage (`dash-credentials/`, owner
//! only). On Android that is the app sandbox; it is **not** encrypted at rest
//! by the app. A platform-keystore backend can replace the file store behind
//! the same trait.

use rebsync_core::credentials::files::FileStore;
use rebsync_core::credentials::{CredentialStore, Descriptor, Scope};
use rebsync_core::dash_pairing::{
    self as pairing, Dash, Outcome, PendingStore, PendingSummary, State,
};
use serde::Serialize;
use std::path::Path;

/// The phone's link to Dash: its credential store and pending pairings.
pub struct DashLink {
    store: FileStore,
    pending: PendingStore,
}

/// One check of a pairing, for the web view to poll.
#[derive(Debug, Serialize)]
pub struct Progress {
    pub state: State,
    /// Set once the credential is stored (metadata only).
    pub credential: Option<Descriptor>,
}

fn now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or_default()
}

impl DashLink {
    /// The store in `internal/dash-credentials` (created owner-only).
    pub fn open(internal: &Path) -> Result<Self, String> {
        let store = pairing::open_store(&internal.join("dash-credentials"))
            .map_err(|e| format!("{e:#}"))?;
        let pending = PendingStore::open(&store).map_err(|e| format!("{e:#}"))?;
        Ok(Self { store, pending })
    }

    /// Ask `dash` to pair this phone as `label`; read-only leaves out
    /// `append`. Returns what to show: the matching code and approval URL.
    pub fn begin(
        &self,
        dash: &str,
        label: &str,
        read_only: bool,
        days: u64,
    ) -> Result<PendingSummary, String> {
        let dash = Dash::new(dash).map_err(|e| format!("{e:#}"))?;
        let mut scopes = vec![Scope::Describe, Scope::List, Scope::Read];
        if !read_only {
            scopes.push(Scope::Append);
        }
        if !(1..=90).contains(&days) {
            return Err("a paired credential lives 1 to 90 days".into());
        }
        let pending = pairing::begin(&dash, label.trim(), &scopes, days * 86_400)
            .map_err(|e| format!("{e:#}"))?;
        self.pending.save(&pending).map_err(|e| format!("{e:#}"))?;
        Ok(pending.summary())
    }

    /// Check a pairing once; if approved, collect and store the credential.
    pub fn poll(&self, pairing_id: &str) -> Result<Progress, String> {
        let pending = self
            .pending
            .load(pairing_id)
            .map_err(|e| format!("{e:#}"))?;
        let dash = Dash::new(&pending.dash).map_err(|e| format!("{e:#}"))?;
        let (state, outcome) = pairing::step(&dash, &pending, &self.store, &self.pending)
            .map_err(|e| format!("{e:#}"))?;
        Ok(Progress {
            state,
            credential: match outcome {
                Outcome::Stored(descriptor) => Some(descriptor),
                _ => None,
            },
        })
    }

    /// Cancel a pairing; revokes its credential if it was issued but lost.
    pub fn cancel(&self, pairing_id: &str) -> Result<State, String> {
        let pending = self
            .pending
            .load(pairing_id)
            .map_err(|e| format!("{e:#}"))?;
        let dash = Dash::new(&pending.dash).map_err(|e| format!("{e:#}"))?;
        let state = pairing::cancel(&dash, &pending).map_err(|e| format!("{e:#}"))?;
        self.pending
            .remove(pairing_id)
            .map_err(|e| format!("{e:#}"))?;
        Ok(state)
    }

    pub fn pending(&self) -> Vec<PendingSummary> {
        self.pending.list()
    }

    /// Stored credentials, metadata only.
    pub fn credentials(&self) -> Result<Vec<Descriptor>, String> {
        self.store
            .list()
            .map_err(|e| format!("credential store: {e:?}"))
    }

    /// Stop using a credential on this phone. Revoking it in Dash stops it
    /// everywhere; that needs the owner signed in to Dash.
    pub fn forget(&self, key_id: &str) -> Result<(), String> {
        self.store
            .disable(key_id)
            .map_err(|e| format!("could not disable {key_id}: {e:?}"))
    }

    /// Prove a stored credential works: describe the repository it reaches.
    pub fn check(&self, key_id: &str) -> Result<serde_json::Value, String> {
        let descriptor = self
            .store
            .descriptor(key_id)
            .map_err(|e| format!("no credential {key_id}: {e:?}"))?;
        let secret = self
            .store
            .use_secret(key_id, &descriptor.audience, &Scope::Describe, now())
            .map_err(|_| format!("credential {key_id} cannot be used now (expired or disabled)"))?;
        let token = std::str::from_utf8(secret.expose()).map_err(|_| "unreadable credential")?;
        let repository =
            rebsync_core::repository::Repository::connect(&descriptor.audience.endpoint, token)
                .map_err(|e| format!("{e:#}"))?;
        let described = repository.describe().map_err(|e| format!("{e:#}"))?;
        Ok(serde_json::json!({
            "key_id": key_id,
            "repository_id": described.get("repository_id"),
            "capabilities": described.get("capabilities"),
            "matches": described.get("repository_id").and_then(|v| v.as_str()) == Some(descriptor.audience.repository_id.as_str()),
        }))
    }
}
