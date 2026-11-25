//! Pairing this phone with Dash: the phone's own, passkey-approved credential
//! to the owner's private RBQ repository (rebsync `dash_pairing`).
//!
//! The phone starts a pairing and shows its matching code and Dash's approval
//! URL; the owner approves it in Dash with a passkey on any device; the phone
//! then collects the credential, once. No token or nonce ever reaches the web
//! view: commands return metadata only.
//!
//! Credentials live in the app's private storage (`dash-credentials/`, owner
//! only). On Android each secret is also sealed by a key in the Android
//! Keystore (`android_keystore.rs`), so the files hold ciphertext; elsewhere
//! (desktop builds, tests) the caller may pass no sealer.

use rebsync_core::credentials::files::{FileStore, Sealer};
use rebsync_core::credentials::{CredentialStore, Descriptor, Scope};
use rebsync_core::dash_pairing::{
    self as pairing, Dash, Outcome, PendingStore, PendingSummary, State,
};
use serde::Serialize;
use std::path::Path;

/// Where this phone's Dash source (id and name) is kept, next to its
/// credentials. Not a `.json` name, so the credential listing never reads it.
const SOURCE_FILE: &str = "phone-source";

#[derive(Serialize, serde::Deserialize)]
struct KeptSource {
    id: String,
    name: String,
}

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
    /// The store in `internal/dash-credentials` (created owner-only), its
    /// secrets sealed by `sealer` when given.
    pub fn open(
        internal: &Path,
        sealer: Option<std::sync::Arc<dyn Sealer>>,
    ) -> Result<Self, String> {
        let mut store = pairing::open_store(&internal.join("dash-credentials"))
            .map_err(|e| format!("{e:#}"))?;
        if let Some(sealer) = sealer {
            store = store.with_sealer(sealer);
        }
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

    /// Which sealer protects stored secrets, if any.
    pub fn sealer_id(&self) -> Option<&str> {
        self.store.sealer_id()
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

    /// The message for a failed Dash call. If Dash refused the credential
    /// (revoked, expired or unknown), it is disabled here so it is not tried
    /// again.
    fn refusal(&self, key_id: &str, error: anyhow::Error) -> String {
        if rebsync_core::is_unauthorized(&error) {
            let _ = self.forget(key_id);
            "Dash no longer accepts this phone's credential (revoked or expired). \
             It is forgotten here; pair again."
                .to_owned()
        } else {
            format!("{error:#}")
        }
    }

    /// Connect to the repository a stored credential reaches, after its
    /// stored grant allows `scope`.
    fn connect(
        &self,
        key_id: &str,
        scope: Scope,
    ) -> Result<(Descriptor, rebsync_core::repository::Repository), String> {
        let descriptor = self
            .store
            .descriptor(key_id)
            .map_err(|e| format!("no credential {key_id}: {e:?}"))?;
        let secret = self
            .store
            .use_secret(key_id, &descriptor.audience, &scope, now())
            .map_err(|error| match error {
                rebsync_core::credentials::StoreError::Locked => {
                    "this phone's key for the credential is unavailable (Android Keystore)".to_owned()
                }
                _ => format!(
                    "credential {key_id} cannot be used now for {scope:?} (expired, disabled or not granted)"
                ),
            })?;
        let token = std::str::from_utf8(secret.expose()).map_err(|_| "unreadable credential")?;
        let repository =
            rebsync_core::repository::Repository::connect(&descriptor.audience.endpoint, token)
                .map_err(|e| format!("{e:#}"))?;
        Ok((descriptor, repository))
    }

    /// Prove a stored credential works: describe the repository it reaches.
    pub fn check(&self, key_id: &str) -> Result<serde_json::Value, String> {
        let (descriptor, repository) = self.connect(key_id, Scope::Describe)?;
        let described = repository
            .describe()
            .map_err(|error| self.refusal(key_id, error))?;
        Ok(serde_json::json!({
            "key_id": key_id,
            "repository_id": described.get("repository_id"),
            "capabilities": described.get("capabilities"),
            "matches": described.get("repository_id").and_then(|v| v.as_str()) == Some(descriptor.audience.repository_id.as_str()),
        }))
    }

    /// This phone's source in Dash: chosen once (a random id and the name
    /// given the first time) and reused, as repository sources require.
    fn source(&self, name: &str) -> Result<rebsync_core::repository_sync::Source, String> {
        let path = self.store.dir().join(SOURCE_FILE);
        if let Ok(bytes) = std::fs::read(&path) {
            let kept: KeptSource =
                serde_json::from_slice(&bytes).map_err(|_| "unreadable phone source record")?;
            return rebsync_core::repository_sync::Source::new(&kept.id, &kept.name)
                .map_err(|e| format!("{e:#}"));
        }
        let mut random = [0_u8; 16];
        getrandom::fill(&mut random).map_err(|_| "no system randomness")?;
        let id = format!(
            "phone-{}",
            random
                .iter()
                .map(|b| format!("{b:02x}"))
                .collect::<String>()
        );
        let name = name.trim();
        let source =
            rebsync_core::repository_sync::Source::new(&id, name).map_err(|e| format!("{e:#}"))?;
        let bytes = serde_json::to_vec(&KeptSource {
            id,
            name: name.to_owned(),
        })
        .map_err(|e| e.to_string())?;
        let mut options = std::fs::OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        use std::io::Write;
        let written = options.open(&path).and_then(|mut file| {
            file.write_all(&bytes)?;
            file.sync_all()
        });
        match written {
            Ok(()) => Ok(source),
            // Another send made it first: use that one.
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => self.source(name),
            Err(error) => Err(format!("could not keep the phone's source: {error}")),
        }
    }

    /// Send this phone's snapshots to the owner's Dash repository, as this
    /// phone's source. Additive and resumable: objects already there are
    /// verified, never replaced; anything refused is listed in the report.
    pub fn send(
        &self,
        key_id: &str,
        storage: &dyn rebsync_core::ObjectStorage,
        name: &str,
    ) -> Result<rebsync_core::repository_sync::Report, String> {
        let (_, repository) = self.connect(key_id, Scope::Append)?;
        let source = self.source(name)?;
        let layers: Vec<String> = rebsync_core::layer::LAYERS
            .iter()
            .map(|l| (*l).to_owned())
            .collect();
        rebsync_core::repository_sync::push(&repository, storage, &source, &layers)
            .map_err(|error| self.refusal(key_id, error))
    }
}
