//! The device side of passkey-approved Dash pairing
//! (RBQ-SERVICE-PLAN.md §2; Dash `docs/RBQ-PAIRING.md`).
//!
//! 1. [`begin`]: this device makes a 128-bit pairing id and a 256-bit claim
//!    nonce, and sends Dash only the nonce's SHA-256 with the requested label,
//!    scopes and lifetime. The pending pairing, nonce included, is kept
//!    owner-only next to the credentials ([`PendingStore`]).
//! 2. A person opens the approval URL in Dash, compares the matching code with
//!    the one this device shows, and approves with a passkey.
//! 3. [`claim`]: this device presents the nonce once and receives an `rbs_`
//!    credential, which goes straight into the [`FileStore`] with its
//!    descriptor; only metadata is ever printed.
//!
//! Nothing Dash says is trusted that the device can check itself: the
//! matching code is computed here, the approval URL must be exactly
//! `{dash}/pair/{id}`, and an issued credential must have the requested id
//! form, a subset of the requested scopes and a future expiry. A claim whose
//! response is lost is never retried (Dash would refuse anyway): the pairing
//! is cancelled, which revokes the credential without knowing it.

use crate::credentials::files::{self, FileStore};
use crate::credentials::{Audience, CredentialKind, CredentialStore, Descriptor, Scope, Secret};
use crate::rbq_contract::{ENDPOINT_PATH_PREFIX, valid_endpoint_id};
use crate::wire::{self, http};
use anyhow::{Context, Result, anyhow, bail, ensure};
use base64::Engine;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

pub const PENDING_SCHEMA: &str = "rbq.dash-pairing.pending.v1";
/// Dash's bounds on a credential's lifetime.
pub const MIN_LIFETIME: u64 = 3600;
pub const MAX_LIFETIME: u64 = 90 * 24 * 3600;
const MAX_RESPONSE: u64 = 16 * 1024;

fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or_default()
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// The code both sides show: `SHA-256("rbq-pairing-v1\0" id "\0" nonce_sha256)`,
/// its first 8 hex digits as `XXXX-XXXX`.
pub fn matching_code(pairing_id: &str, nonce_sha256: &str) -> String {
    let digest = hex(&Sha256::digest(
        format!("rbq-pairing-v1\0{pairing_id}\0{nonce_sha256}").as_bytes(),
    ));
    format!("{}-{}", &digest[..4], &digest[4..8]).to_ascii_uppercase()
}

/// A device label as Dash accepts it: 1..=64 characters, no control or
/// format characters, no surrounding spaces.
pub fn valid_label(label: &str) -> bool {
    (1..=64).contains(&label.chars().count())
        && label.trim() == label
        && !label
            .chars()
            .any(|c| c.is_control() || matches!(c, '\u{200b}'..='\u{200f}' | '\u{202a}'..='\u{202e}' | '\u{2060}'..='\u{2064}' | '\u{feff}'))
}

/// A Dash origin: `https://host[:port]`, or `http://` on loopback for tests.
#[derive(Clone, Debug)]
pub struct Dash {
    origin: url::Url,
    agent: ureq::Agent,
}

impl Dash {
    pub fn new(origin: &str) -> Result<Self> {
        let url = url::Url::parse(origin).map_err(|_| anyhow!("invalid Dash URL"))?;
        let local = match url.host() {
            Some(url::Host::Domain("localhost")) => true,
            Some(url::Host::Ipv4(ip)) => ip.is_loopback(),
            Some(url::Host::Ipv6(ip)) => ip.is_loopback(),
            _ => false,
        };
        ensure!(
            url.scheme() == "https" || (url.scheme() == "http" && local),
            "Dash requires HTTPS (HTTP only on loopback for tests)"
        );
        ensure!(
            url.host().is_some()
                && url.username().is_empty()
                && url.password().is_none()
                && url.query().is_none()
                && url.fragment().is_none()
                && url.path() == "/",
            "give Dash as an origin only, such as https://dash.ragbaz.cc"
        );
        Ok(Self {
            origin: url,
            agent: http::agent(Duration::from_secs(10), Duration::from_secs(30)),
        })
    }

    /// `https://host[:port]`, without a trailing slash.
    pub fn origin(&self) -> String {
        self.origin.as_str().trim_end_matches('/').to_owned()
    }

    fn url(&self, path: &str) -> String {
        format!("{}{path}", self.origin())
    }

    fn post(&self, path: &str, body: serde_json::Value) -> Result<(u16, serde_json::Value), Lost> {
        let result = self
            .agent
            .post(&self.url(path))
            .set("User-Agent", concat!("rbq/", env!("CARGO_PKG_VERSION")))
            .send_json(body);
        Self::read(result)
    }

    fn get(&self, path: &str) -> Result<(u16, serde_json::Value), Lost> {
        let result = self
            .agent
            .get(&self.url(path))
            .set("User-Agent", concat!("rbq/", env!("CARGO_PKG_VERSION")))
            .call();
        Self::read(result)
    }

    /// Status and JSON body, bounded. A transport failure is [`Lost`]: the
    /// request may or may not have reached Dash.
    fn read(
        result: std::result::Result<ureq::Response, ureq::Error>,
    ) -> Result<(u16, serde_json::Value), Lost> {
        let response = match result {
            Ok(response) => response,
            Err(ureq::Error::Status(_, response)) => response,
            Err(ureq::Error::Transport(_)) => return Err(Lost),
        };
        let status = response.status();
        let body = wire::read_bounded(response.into_reader(), MAX_RESPONSE)
            .ok()
            .flatten()
            .and_then(|bytes| serde_json::from_slice(&bytes).ok())
            .unwrap_or(serde_json::Value::Null);
        Ok((status, body))
    }
}

/// A request whose outcome is unknown: it failed in transport.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Lost;

impl std::fmt::Display for Lost {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("could not reach Dash; check the network and the Dash URL")
    }
}

impl std::error::Error for Lost {}

/// Dash's error code, if the body names one; never the body itself.
fn error_code(body: &serde_json::Value) -> String {
    body.get("error")
        .and_then(|e| e.as_str())
        .filter(|e| e.len() <= 64 && e.bytes().all(|b| b.is_ascii_lowercase() || b == b'_'))
        .unwrap_or("unexpected_response")
        .to_owned()
}

/// A pairing this device started. Holds the claim nonce: keep it owner-only
/// ([`PendingStore`]), never print it. `Debug` redacts it.
#[derive(Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Pending {
    pub schema: String,
    pub dash: String,
    pub pairing_id: String,
    nonce: String,
    pub nonce_sha256: String,
    pub device_label: String,
    pub scopes: Vec<Scope>,
    pub lifetime_seconds: u64,
    pub expires_at: u64,
    pub matching_code: String,
    pub approval_url: String,
}

impl std::fmt::Debug for Pending {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Pending")
            .field("dash", &self.dash)
            .field("pairing_id", &self.pairing_id)
            .field("nonce", &"[REDACTED]")
            .field("matching_code", &self.matching_code)
            .finish_non_exhaustive()
    }
}

/// What a pending pairing may show: no nonce.
#[derive(Clone, Debug, Serialize, PartialEq, Eq)]
pub struct PendingSummary {
    pub dash: String,
    pub pairing_id: String,
    pub device_label: String,
    pub scopes: Vec<Scope>,
    pub lifetime_seconds: u64,
    pub expires_at: u64,
    pub matching_code: String,
    pub approval_url: String,
}

impl Pending {
    pub fn summary(&self) -> PendingSummary {
        PendingSummary {
            dash: self.dash.clone(),
            pairing_id: self.pairing_id.clone(),
            device_label: self.device_label.clone(),
            scopes: self.scopes.clone(),
            lifetime_seconds: self.lifetime_seconds,
            expires_at: self.expires_at,
            matching_code: self.matching_code.clone(),
            approval_url: self.approval_url.clone(),
        }
    }

    fn nonce_body(&self) -> serde_json::Value {
        serde_json::json!({ "nonce": self.nonce })
    }
}

/// Ask Dash to pair this device. Nothing is approved yet: show the person
/// [`Pending::matching_code`] and [`Pending::approval_url`].
pub fn begin(dash: &Dash, label: &str, scopes: &[Scope], lifetime_seconds: u64) -> Result<Pending> {
    ensure!(
        valid_label(label),
        "a device label is 1..64 characters, without control characters or surrounding spaces"
    );
    ensure!(!scopes.is_empty(), "request at least one scope");
    ensure!(
        (MIN_LIFETIME..=MAX_LIFETIME).contains(&lifetime_seconds),
        "a credential lives between 1 hour and 90 days"
    );
    let mut scopes = scopes.to_vec();
    scopes.sort_by_key(scope_order);
    scopes.dedup();
    let mut id = [0_u8; 16];
    let mut nonce = [0_u8; 32];
    getrandom::getrandom(&mut id).map_err(|_| anyhow!("no system randomness"))?;
    getrandom::getrandom(&mut nonce).map_err(|_| anyhow!("no system randomness"))?;
    let pairing_id = hex(&id);
    let nonce = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(nonce);
    let nonce_sha256 = wire::sha256_hex(nonce.as_bytes());
    let (status, body) = dash
        .post(
            "/api/rbq-pairing/requests",
            serde_json::json!({
                "pairing_id": pairing_id,
                "nonce_sha256": nonce_sha256,
                "device_label": label,
                "scopes": scopes,
                "lifetime_seconds": lifetime_seconds,
            }),
        )
        .map_err(anyhow::Error::from)?;
    ensure!(
        status == 201,
        "Dash refused the pairing request ({})",
        error_code(&body)
    );
    let code = matching_code(&pairing_id, &nonce_sha256);
    let approval_url = format!("{}/pair/{pairing_id}", dash.origin());
    // Dash must agree on what the person will compare and where they go.
    ensure!(
        body.get("pairing_id").and_then(|v| v.as_str()) == Some(pairing_id.as_str())
            && body.get("matching_code").and_then(|v| v.as_str()) == Some(code.as_str())
            && body.get("approval_url").and_then(|v| v.as_str()) == Some(approval_url.as_str()),
        "Dash answered for a different pairing; refusing it"
    );
    let expires_at = body
        .get("expires_at")
        .and_then(|v| v.as_u64())
        .filter(|&t| t > now() && t <= now() + 3600)
        .ok_or_else(|| anyhow!("Dash gave the pairing no plausible expiry"))?;
    Ok(Pending {
        schema: PENDING_SCHEMA.into(),
        dash: dash.origin(),
        pairing_id,
        nonce,
        nonce_sha256,
        device_label: label.to_owned(),
        scopes,
        lifetime_seconds,
        expires_at,
        matching_code: code,
        approval_url,
    })
}

fn scope_order(scope: &Scope) -> u8 {
    match scope {
        Scope::Describe => 0,
        Scope::List => 1,
        Scope::Read => 2,
        Scope::Append => 3,
    }
}

#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum State {
    Pending,
    Approved,
    Claimed,
    Cancelled,
    Revoked,
    Expired,
}

fn state_of(body: &serde_json::Value) -> Result<State> {
    serde_json::from_value(body.get("state").cloned().unwrap_or_default())
        .map_err(|_| anyhow!("Dash reported no pairing state"))
}

/// The pairing's state at Dash.
pub fn status(dash: &Dash, pending: &Pending) -> Result<State> {
    let (code, body) = dash
        .get(&format!("/api/rbq-pairing/requests/{}", pending.pairing_id))
        .map_err(anyhow::Error::from)?;
    ensure!(
        code == 200,
        "Dash could not report the pairing ({})",
        error_code(&body)
    );
    state_of(&body)
}

/// A credential Dash issued to this device. The token is a [`Secret`].
#[derive(Debug)]
pub struct Issued {
    pub key_id: String,
    pub token: Secret,
    pub scopes: Vec<Scope>,
    pub expires_at: u64,
    pub repository_id: String,
    pub device_label: String,
}

/// How a claim ended.
#[derive(Debug)]
pub enum Claim {
    Issued(Issued),
    /// Dash refused: not approved (yet), expired, cancelled or already claimed.
    Refused(String),
    /// The response was lost. The credential may exist; cancel to revoke it.
    Lost,
}

/// Claim the approved pairing's credential, once.
pub fn claim(dash: &Dash, pending: &Pending) -> Result<Claim> {
    let (status, body) = match dash.post(
        &format!("/api/rbq-pairing/requests/{}/claim", pending.pairing_id),
        pending.nonce_body(),
    ) {
        Ok(response) => response,
        Err(Lost) => return Ok(Claim::Lost),
    };
    if status != 201 {
        return Ok(Claim::Refused(error_code(&body)));
    }
    let text = |key: &str| body.get(key).and_then(|v| v.as_str()).map(str::to_owned);
    let token = text("token").filter(|t| {
        t.strip_prefix("rbs_").is_some_and(|hex| {
            hex.len() == 64 && hex.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
        })
    });
    let key_id = text("key_id").filter(|id| valid_endpoint_id(id));
    let repository_id = text("repository_id").filter(|id| valid_endpoint_id(id));
    let scopes: Option<Vec<Scope>> = body
        .get("scopes")
        .cloned()
        .and_then(|v| serde_json::from_value(v).ok());
    let expires_at = body.get("expires_at").and_then(|v| v.as_u64());
    let (Some(token), Some(key_id), Some(repository_id), Some(scopes), Some(expires_at)) =
        (token, key_id, repository_id, scopes, expires_at)
    else {
        // Something was issued, but not in a form this device can use or
        // check: treat it as lost, so the caller revokes it.
        return Ok(Claim::Lost);
    };
    if scopes.is_empty()
        || scopes.iter().any(|s| !pending.scopes.contains(s))
        || expires_at <= now()
        || expires_at > now() + MAX_LIFETIME + 300
    {
        return Ok(Claim::Lost);
    }
    Ok(Claim::Issued(Issued {
        key_id,
        token: Secret::new(token.into_bytes()),
        scopes,
        expires_at,
        repository_id,
        device_label: pending.device_label.clone(),
    }))
}

/// Cancel the pairing. If its credential was already issued (a lost claim
/// response), this revokes it. Returns the final state.
pub fn cancel(dash: &Dash, pending: &Pending) -> Result<State> {
    let (status, body) = dash
        .post(
            &format!("/api/rbq-pairing/requests/{}/cancel", pending.pairing_id),
            pending.nonce_body(),
        )
        .map_err(anyhow::Error::from)?;
    ensure!(
        status == 200,
        "Dash could not cancel the pairing ({})",
        error_code(&body)
    );
    state_of(&body)
}

/// The descriptor a stored credential carries. Dash does not tell devices
/// their account id, so the audience's `account_id` is the issuing Dash
/// origin; the repository id is Dash's.
pub fn descriptor_for(dash: &Dash, issued: &Issued, created_at: u64) -> Descriptor {
    Descriptor {
        id: issued.key_id.clone(),
        kind: CredentialKind::DashBearer,
        audience: audience_for(dash, &issued.key_id, &issued.repository_id),
        scopes: issued.scopes.clone(),
        created_at,
        expires_at: issued.expires_at,
        disabled: false,
    }
}

/// The audience of the credential `key_id` for `repository_id` at `dash`.
pub fn audience_for(dash: &Dash, key_id: &str, repository_id: &str) -> Audience {
    Audience {
        endpoint: format!("{}{ENDPOINT_PATH_PREFIX}{key_id}", dash.origin()),
        account_id: dash.origin(),
        repository_id: repository_id.to_owned(),
    }
}

/// Pending pairings, owner-only, in `pending/` under a credential store.
#[derive(Debug, Clone)]
pub struct PendingStore {
    dir: PathBuf,
}

impl PendingStore {
    pub fn open(store: &FileStore) -> Result<Self> {
        let dir = store.dir().join("pending");
        FileStore::open(&dir).map_err(|e| anyhow!("pending pairings directory: {e:?}"))?;
        Ok(Self { dir })
    }

    fn path(&self, pairing_id: &str) -> Result<PathBuf> {
        ensure!(
            pairing_id.len() == 32
                && pairing_id
                    .bytes()
                    .all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f')),
            "a pairing id is 32 lowercase hex digits"
        );
        Ok(self.dir.join(format!("{pairing_id}.json")))
    }

    pub fn save(&self, pending: &Pending) -> Result<()> {
        let bytes = serde_json::to_vec_pretty(pending)?;
        files::create_private(&self.path(&pending.pairing_id)?, &bytes)
            .map_err(|e| anyhow!("could not keep the pending pairing: {e:?}"))
    }

    pub fn load(&self, pairing_id: &str) -> Result<Pending> {
        let bytes = files::read_private(&self.path(pairing_id)?)
            .map_err(|e| anyhow!("no pending pairing {pairing_id} here ({e:?})"))?;
        let pending: Pending =
            serde_json::from_slice(&bytes).context("unreadable pending pairing")?;
        ensure!(
            pending.schema == PENDING_SCHEMA && pending.pairing_id == pairing_id,
            "unreadable pending pairing"
        );
        Ok(pending)
    }

    pub fn remove(&self, pairing_id: &str) -> Result<()> {
        match std::fs::remove_file(self.path(pairing_id)?) {
            Err(error) if error.kind() != std::io::ErrorKind::NotFound => Err(error.into()),
            _ => Ok(()),
        }
    }

    pub fn list(&self) -> Vec<PendingSummary> {
        let Ok(entries) = std::fs::read_dir(&self.dir) else {
            return Vec::new();
        };
        let mut list: Vec<PendingSummary> = entries
            .filter_map(Result::ok)
            .filter_map(|entry| {
                let name = entry.file_name().into_string().ok()?;
                self.load(name.strip_suffix(".json")?).ok()
            })
            .map(|pending| pending.summary())
            .collect();
        list.sort_by(|a, b| a.pairing_id.cmp(&b.pairing_id));
        list
    }
}

/// How waiting for approval ended.
#[derive(Debug)]
pub enum Outcome {
    /// Claimed and stored; the pending pairing is gone.
    Stored(Descriptor),
    /// Dash ended the pairing (cancelled, expired or revoked) before a claim.
    Ended(State),
    /// Still awaiting approval when the wait ran out; resume later.
    StillPending,
}

/// Check the pairing once: if Dash approved it, claim the credential and
/// store it. `Outcome::StillPending` means "not yet; ask again later" (also
/// when the check itself was lost in transport). A lost claim response, or a
/// credential that cannot be stored, is revoked by cancelling; that is
/// reported as an error, with the pending pairing kept if even the cancel
/// failed.
pub fn step(
    dash: &Dash,
    pending: &Pending,
    store: &FileStore,
    pending_store: &PendingStore,
) -> Result<(State, Outcome)> {
    let state = match status(dash, pending) {
        Ok(state) => state,
        // A dropped poll is harmless: nothing changed on our side.
        Err(error) if error.is::<Lost>() => return Ok((State::Pending, Outcome::StillPending)),
        Err(error) => return Err(error),
    };
    match state {
        State::Pending => return Ok((state, Outcome::StillPending)),
        State::Approved => {}
        ended => {
            pending_store.remove(&pending.pairing_id)?;
            return Ok((ended, Outcome::Ended(ended)));
        }
    }
    let issued = match claim(dash, pending)? {
        Claim::Issued(issued) => issued,
        Claim::Refused(code) => bail!("Dash refused the claim ({code})"),
        Claim::Lost => {
            return Err(revoke_lost(
                dash,
                pending,
                pending_store,
                "the claim's response was lost",
            ));
        }
    };
    let descriptor = descriptor_for(dash, &issued, now());
    if let Err(error) = store.create(descriptor.clone(), issued.token) {
        return Err(revoke_lost(
            dash,
            pending,
            pending_store,
            &format!("the credential could not be stored ({error:?})"),
        ));
    }
    pending_store.remove(&pending.pairing_id)?;
    Ok((State::Claimed, Outcome::Stored(descriptor)))
}

/// [`step`] every `poll` until the pairing is stored or ended, or `timeout`
/// passes. `tick` sees each state, for progress.
pub fn wait_and_claim(
    dash: &Dash,
    pending: &Pending,
    store: &FileStore,
    pending_store: &PendingStore,
    poll: Duration,
    timeout: Duration,
    mut tick: impl FnMut(State),
) -> Result<Outcome> {
    let deadline = Instant::now() + timeout;
    loop {
        let (state, outcome) = step(dash, pending, store, pending_store)?;
        tick(state);
        if !matches!(outcome, Outcome::StillPending) || Instant::now() + poll > deadline {
            return Ok(outcome);
        }
        std::thread::sleep(poll);
    }
}

fn revoke_lost(
    dash: &Dash,
    pending: &Pending,
    pending_store: &PendingStore,
    why: &str,
) -> anyhow::Error {
    match cancel(dash, pending) {
        Ok(state) => {
            let _ = pending_store.remove(&pending.pairing_id);
            anyhow!(
                "{why}; the pairing is now {state:?} at Dash, so no usable credential is left behind. Pair again."
            )
        }
        Err(_) => anyhow!(
            "{why}, and cancelling also failed. Run `rbq dash cancel {}` when Dash is reachable, to revoke any credential that was issued.",
            pending.pairing_id
        ),
    }
}

/// The credential store selected explicitly by path.
pub fn open_store(dir: &Path) -> Result<FileStore> {
    FileStore::open(dir).map_err(|e| {
        anyhow!(
            "credential store {} is unusable ({e:?}): it must be a directory owned by you with mode 0700",
            dir.display()
        )
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn matching_codes_follow_dashs_formula() {
        // The same vector Dash's matchingCode computes (see the Dash e2e
        // test); recomputed here from the formula.
        let id = "0123456789abcdef0123456789abcdef";
        let nonce_sha256 = "a".repeat(64);
        let expected = {
            let digest = hex(&Sha256::digest(
                format!("rbq-pairing-v1\0{id}\0{nonce_sha256}").as_bytes(),
            ));
            format!("{}-{}", &digest[..4], &digest[4..8]).to_uppercase()
        };
        let code = matching_code(id, &nonce_sha256);
        assert_eq!(code, expected);
        assert_eq!(code.len(), 9);
        assert!(
            code.bytes()
                .all(|b| b == b'-' || b.is_ascii_hexdigit() && !b.is_ascii_lowercase())
        );
    }

    #[test]
    fn dash_must_be_an_https_origin() {
        assert!(Dash::new("https://dash.ragbaz.cc").is_ok());
        assert!(Dash::new("https://dash.ragbaz.cc/").is_ok());
        assert!(Dash::new("http://127.0.0.1:8787").is_ok());
        for bad in [
            "http://dash.ragbaz.cc",
            "https://dash.ragbaz.cc/api",
            "https://user@dash.ragbaz.cc",
            "https://dash.ragbaz.cc/?x=1",
            "ftp://dash.ragbaz.cc",
            "dash.ragbaz.cc",
        ] {
            assert!(Dash::new(bad).is_err(), "{bad}");
        }
        assert_eq!(
            Dash::new("https://dash.ragbaz.cc/").unwrap().origin(),
            "https://dash.ragbaz.cc"
        );
    }

    #[test]
    fn labels_follow_dashs_rule() {
        assert!(valid_label("laptop"));
        assert!(valid_label("Tobias's phone"));
        for bad in ["", " pad", "pad ", "a\nb", "x\u{202e}y", &"x".repeat(65)] {
            assert!(!valid_label(bad), "{bad:?}");
        }
    }

    #[test]
    fn pending_pairings_never_show_the_nonce() {
        let pending = Pending {
            schema: PENDING_SCHEMA.into(),
            dash: "https://dash.example".into(),
            pairing_id: "0".repeat(32),
            nonce: "the-secret-nonce".into(),
            nonce_sha256: "a".repeat(64),
            device_label: "laptop".into(),
            scopes: vec![Scope::Read],
            lifetime_seconds: 3600,
            expires_at: 1,
            matching_code: "ABCD-1234".into(),
            approval_url: "https://dash.example/pair/0".into(),
        };
        assert!(!format!("{pending:?}").contains("the-secret-nonce"));
        assert!(
            !serde_json::to_string(&pending.summary())
                .unwrap()
                .contains("the-secret-nonce")
        );
        let root = tempfile::tempdir().unwrap();
        let store = FileStore::open(&root.path().join("c")).unwrap();
        let pendings = PendingStore::open(&store).unwrap();
        pendings.save(&pending).unwrap();
        assert!(pendings.save(&pending).is_err(), "never replaced");
        assert_eq!(pendings.load(&pending.pairing_id).unwrap(), pending);
        assert_eq!(pendings.list(), vec![pending.summary()]);
        // Pending pairings are not credentials.
        assert!(store.list().unwrap().is_empty());
        pendings.remove(&pending.pairing_id).unwrap();
        assert!(pendings.list().is_empty());
        assert!(pendings.load("../../etc/passwd").is_err());
    }
}
