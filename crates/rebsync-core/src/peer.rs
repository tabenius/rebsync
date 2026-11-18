//! Object exchange with a peer, independent of how the bytes travel.
//!
//! `push` copies local layer objects the peer lacks; `pull` copies the peer's
//! objects this store lacks. Both are additive: an object present on both
//! sides is never replaced, and a size mismatch is reported as a conflict.
//! Chunks travel before manifests, so an interrupted sync never leaves a
//! manifest whose chunks are missing. Everything received from a peer is
//! untrusted: content-addressed chunks are re-hashed, manifests must parse and
//! validate, and only layer prefixes are accepted.
//!
//! The sync logic talks to [`PeerApi`]. The Rebeqah app speaks
//! `rbq-peer/0` over HTTP ([`Peer`], feature `peer-http`); the local
//! transports in [`crate::transport`] speak `rbq-peer/1` over TCP, Unix
//! stream sockets or Unix datagram sockets.

use crate::{
    journal::Journal,
    layer,
    storage::{ObjectKey, ObjectStorage, PutOutcome},
};
use anyhow::{Context, Result, bail, ensure};
use serde::Serialize;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
#[cfg(feature = "peer-http")]
use std::{io::Read, time::Duration};

pub const PROTOCOL: &str = "rbq-peer/0";
#[cfg(feature = "peer-http")]
const PAGE: usize = 5000;
#[cfg(feature = "peer-http")]
const MAX_OBJECT: u64 = 64 * 1024 * 1024;

/// The operations `push` and `pull` need from any peer transport.
pub trait PeerApi {
    /// Human-readable, token-free description used in journals and reports.
    fn base(&self) -> &str;
    fn status(&self) -> Result<Value>;
    /// Every key under `prefix`, paged internally.
    fn list(&self, prefix: &str) -> Result<BTreeMap<String, u64>>;
    fn get(&self, key: &str) -> Result<Vec<u8>>;
    /// Create-if-absent on the peer. Returns true when created.
    fn put(&self, key: &str, bytes: &[u8]) -> Result<bool>;
}

#[cfg(feature = "peer-http")]
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Target {
    /// `http://host:port`, without a trailing slash.
    pub base: String,
    pub token: String,
}

/// Parse `rbq+http://host:port/v1?token=T` (as shown by the app) or a
/// plain `http://host:port` plus a separately supplied token.
#[cfg(feature = "peer-http")]
pub fn parse_connection(connection: &str, token: Option<&str>) -> Result<Target> {
    let raw = connection.trim();
    let raw = raw.strip_prefix("rbq+").unwrap_or(raw);
    ensure!(
        raw.starts_with("http://"),
        "peer connections are http://HOST:PORT (rbq-peer/0 has no TLS yet)"
    );
    let (location, query) = raw.split_once('?').unwrap_or((raw, ""));
    let location = location.trim_end_matches('/');
    let location = location.strip_suffix("/v1").unwrap_or(location);
    let host = &location["http://".len()..];
    ensure!(
        !host.is_empty() && !host.contains('/') && !host.contains('@'),
        "peer address must be HOST:PORT"
    );
    let from_query = query
        .split('&')
        .find_map(|pair| pair.strip_prefix("token="))
        .map(str::to_owned);
    let token = token
        .map(str::to_owned)
        .or(from_query)
        .context("no token: use the app's connection string or --token-file")?;
    ensure!(
        !token.is_empty() && token.bytes().all(|b| b.is_ascii_alphanumeric()),
        "token must be alphanumeric"
    );
    Ok(Target {
        base: location.to_owned(),
        token,
    })
}

#[cfg(feature = "peer-http")]
pub struct Peer {
    agent: ureq::Agent,
    target: Target,
    page: usize,
    retries: u8,
}

#[cfg(feature = "peer-http")]
struct AttemptError {
    error: anyhow::Error,
    transient: bool,
}

#[cfg(feature = "peer-http")]
impl From<ureq::Error> for AttemptError {
    fn from(error: ureq::Error) -> Self {
        let transient = match &error {
            ureq::Error::Status(code, _) => matches!(code, 408 | 502 | 503 | 504),
            ureq::Error::Transport(transport) => matches!(
                transport.kind(),
                ureq::ErrorKind::Dns | ureq::ErrorKind::ConnectionFailed | ureq::ErrorKind::Io
            ),
        };
        Self {
            error: describe(error),
            transient,
        }
    }
}

#[cfg(feature = "peer-http")]
impl From<std::io::Error> for AttemptError {
    fn from(error: std::io::Error) -> Self {
        let transient = matches!(
            error.kind(),
            std::io::ErrorKind::TimedOut
                | std::io::ErrorKind::UnexpectedEof
                | std::io::ErrorKind::ConnectionReset
                | std::io::ErrorKind::ConnectionAborted
                | std::io::ErrorKind::BrokenPipe
                | std::io::ErrorKind::Interrupted
                | std::io::ErrorKind::WouldBlock
        );
        Self {
            error: error.into(),
            transient,
        }
    }
}

#[cfg(feature = "peer-http")]
impl From<anyhow::Error> for AttemptError {
    fn from(error: anyhow::Error) -> Self {
        Self {
            error,
            transient: false,
        }
    }
}

#[cfg(feature = "peer-http")]
fn retry<T>(
    retries: u8,
    mut operation: impl FnMut() -> std::result::Result<T, AttemptError>,
    mut sleep: impl FnMut(Duration),
) -> Result<T> {
    for attempt in 0..=retries.min(6) {
        match operation() {
            Ok(value) => return Ok(value),
            Err(error) if error.transient && attempt < retries.min(6) => {
                let base = 250_u64.saturating_mul(1 << attempt).min(8000);
                // Jitter is scheduling noise, not a security primitive.
                let jitter = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .map(|d| d.subsec_nanos() as u64 % (base / 4 + 1))
                    .unwrap_or(0);
                sleep(Duration::from_millis(base + jitter));
            }
            Err(error) => {
                return Err(error.error.context(format!(
                    "peer request failed after {} attempt(s)",
                    attempt + 1
                )));
            }
        }
    }
    unreachable!("bounded retry loop always returns")
}

#[cfg(feature = "peer-http")]
fn encode(value: &str) -> String {
    value
        .bytes()
        .map(|b| match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' => (b as char).to_string(),
            _ => format!("%{b:02X}"),
        })
        .collect()
}

#[cfg(feature = "peer-http")]
impl Peer {
    pub fn connect(target: Target) -> Self {
        let agent = ureq::AgentBuilder::new()
            .timeout_connect(Duration::from_secs(10))
            .timeout(Duration::from_secs(300))
            .redirects(0)
            .build();
        Self {
            agent,
            target,
            page: PAGE,
            retries: 3,
        }
    }

    /// Smaller pages exercise pagination in tests; servers cap at 10 000.
    pub fn with_page_size(mut self, page: usize) -> Self {
        self.page = page.clamp(1, 10_000);
        self
    }

    /// Additional attempts (maximum six), only for transient HTTP/I/O errors.
    pub fn with_retries(mut self, retries: u8) -> Self {
        self.retries = retries.min(6);
        self
    }

    /// Bound explicit diagnostic probes without reducing bulk-transfer timeouts.
    pub fn with_timeout(mut self, timeout: Duration) -> Self {
        self.agent = ureq::AgentBuilder::new()
            .timeout_connect(timeout)
            .timeout(timeout)
            .redirects(0)
            .build();
        self
    }

    fn url(&self, path: &str) -> String {
        format!("{}{path}", self.target.base)
    }

    fn auth(&self, request: ureq::Request) -> ureq::Request {
        request
            .set("Authorization", &format!("Bearer {}", self.target.token))
            .set("User-Agent", concat!("rbq/", env!("CARGO_PKG_VERSION")))
    }

    fn json(&self, path: &str) -> Result<Value> {
        retry(
            self.retries,
            || {
                let response = self
                    .auth(self.agent.get(&self.url(path)))
                    .call()
                    .map_err(AttemptError::from)?;
                let mut bytes = Vec::new();
                const MAX_JSON: u64 = 16 * 1024 * 1024;
                response
                    .into_reader()
                    .take(MAX_JSON + 1)
                    .read_to_end(&mut bytes)?;
                if bytes.len() as u64 > MAX_JSON {
                    return Err(anyhow::anyhow!("peer JSON response exceeds 16 MiB").into());
                }
                serde_json::from_slice(&bytes)
                    .map_err(|e| AttemptError::from(anyhow::Error::from(e)))
            },
            std::thread::sleep,
        )
    }

    pub fn status(&self) -> Result<Value> {
        let status = self.json("/v1/status")?;
        ensure!(
            status.get("protocol").and_then(Value::as_str) == Some(PROTOCOL),
            "peer does not speak {PROTOCOL}"
        );
        Ok(status)
    }

    /// Every key under `prefix`, paging with `after`.
    pub fn list(&self, prefix: &str) -> Result<BTreeMap<String, u64>> {
        let mut found = BTreeMap::new();
        let mut after = String::new();
        loop {
            let page = self.json(&format!(
                "/v1/objects?prefix={}&limit={}&after={}",
                encode(prefix),
                self.page,
                encode(&after)
            ))?;
            let items = page
                .get("items")
                .and_then(Value::as_array)
                .context("malformed listing")?;
            ensure!(
                items.len() <= self.page,
                "peer exceeded the listing page limit"
            );
            let mut last = None;
            for item in items {
                let key = item
                    .get("key")
                    .and_then(Value::as_str)
                    .context("malformed listing")?;
                let size = item
                    .get("size")
                    .and_then(Value::as_u64)
                    .context("malformed listing")?;
                ensure!(
                    key > last.as_deref().unwrap_or(after.as_str()),
                    "peer ignored pagination; use Rebeqah 0.2.4 or later"
                );
                admissible_key(key)?;
                ensure!(
                    key.starts_with(prefix) && size <= MAX_OBJECT,
                    "out-of-scope or oversized listing entry"
                );
                ensure!(
                    found.len() < 100_000,
                    "peer inventory exceeds 100000 objects; narrow the layer filter"
                );
                found.insert(key.to_owned(), size);
                last = Some(key.to_owned());
            }
            match (
                page.get("truncated")
                    .and_then(Value::as_bool)
                    .context("peer omitted pagination flag; upgrade Rebeqah")?,
                last,
            ) {
                (true, Some(last)) => after = last,
                (true, None) => bail!("peer returned an empty truncated page"),
                (false, _) => break,
            }
        }
        Ok(found)
    }

    pub fn get(&self, key: &str) -> Result<Vec<u8>> {
        retry(
            self.retries,
            || {
                let response = self
                    .auth(
                        self.agent
                            .get(&self.url(&format!("/v1/objects/{}", encode_key(key)))),
                    )
                    .call()
                    .map_err(AttemptError::from)?;
                let mut bytes = Vec::new();
                response
                    .into_reader()
                    .take(MAX_OBJECT + 1)
                    .read_to_end(&mut bytes)?;
                if bytes.len() as u64 > MAX_OBJECT {
                    return Err(anyhow::anyhow!("{key}: object exceeds 64 MiB").into());
                }
                Ok(bytes)
            },
            std::thread::sleep,
        )
    }

    /// Create-if-absent on the peer. Returns true when created.
    pub fn put(&self, key: &str, bytes: &[u8]) -> Result<bool> {
        retry(
            self.retries,
            || {
                let response = self
                    .auth(
                        self.agent
                            .put(&self.url(&format!("/v1/objects/{}", encode_key(key)))),
                    )
                    .send_bytes(bytes)
                    .map_err(AttemptError::from)?;
                match response.status() {
                    201 => Ok(true),
                    200 => Ok(false),
                    code => Err(anyhow::anyhow!(
                        "unexpected create-if-absent response: HTTP {code}"
                    )
                    .into()),
                }
            },
            std::thread::sleep,
        )
    }
}

#[cfg(feature = "peer-http")]
impl PeerApi for Peer {
    fn base(&self) -> &str {
        &self.target.base
    }

    fn status(&self) -> Result<Value> {
        Peer::status(self)
    }

    fn list(&self, prefix: &str) -> Result<BTreeMap<String, u64>> {
        Peer::list(self, prefix)
    }

    fn get(&self, key: &str) -> Result<Vec<u8>> {
        Peer::get(self, key)
    }

    fn put(&self, key: &str, bytes: &[u8]) -> Result<bool> {
        Peer::put(self, key, bytes)
    }
}

#[cfg(feature = "peer-http")]
fn encode_key(key: &str) -> String {
    key.split('/').map(encode).collect::<Vec<_>>().join("/")
}

#[cfg(feature = "peer-http")]
fn describe(error: ureq::Error) -> anyhow::Error {
    match error {
        ureq::Error::Status(401, _) => anyhow::anyhow!("peer rejected the token (401)"),
        ureq::Error::Status(429, _) => {
            anyhow::anyhow!("peer is throttling after failed attempts; wait a minute")
        }
        ureq::Error::Status(503, _) => {
            anyhow::anyhow!("peer is moving its data; retry when the move finishes")
        }
        // Untrusted error pages can echo Authorization tokens or stream an
        // unbounded body. Do not read or publish them as diagnostic messages.
        ureq::Error::Status(code, _) => {
            anyhow::anyhow!("peer returned HTTP {code}; response body suppressed")
        }
        ureq::Error::Transport(transport) => anyhow::anyhow!("cannot reach peer: {transport}"),
    }
}

#[derive(Debug, Default, Serialize)]
pub struct SyncReport {
    pub direction: String,
    pub prefixes: Vec<String>,
    pub local_objects: usize,
    pub peer_objects: usize,
    pub transferred: usize,
    pub transferred_bytes: u64,
    pub already_present: usize,
    pub conflicts: Vec<String>,
    pub rejected: Vec<String>,
    /// Pull only: newly received snapshots whose chunks and digests check out.
    pub verified: Vec<String>,
    /// Pull only: newly received snapshots that are incomplete or damaged.
    pub verification_failed: Vec<String>,
    /// Pull only: damaged manifests removed again so they are never listed.
    pub quarantined: Vec<String>,
}

impl SyncReport {
    pub fn clean(&self) -> bool {
        self.conflicts.is_empty() && self.rejected.is_empty() && self.verification_failed.is_empty()
    }
}

/// Accept only layer objects, and check what can be checked before storing.
pub(crate) fn admissible(key: &str, bytes: &[u8]) -> Result<()> {
    admissible_key(key)?;
    let layer = key.split('/').next().unwrap_or_default();
    ensure!(
        layer::LAYERS.contains(&layer) && key.starts_with(&format!("{layer}/v1/")),
        "not a layer object"
    );
    if let Some((_, digest)) = key.rsplit_once("/chunks/sha256/") {
        let digest = digest.rsplit('/').next().unwrap_or_default();
        ensure!(
            layer::valid_sha256(digest) && format!("{:x}", Sha256::digest(bytes)) == digest,
            "chunk content does not match its address"
        );
    } else if key.contains("/snapshots/") {
        ensure!(key.ends_with(".json"), "unexpected snapshot object");
        let id = key
            .split_once("/snapshots/")
            .context("invalid snapshot key")?
            .1
            .strip_suffix(".json")
            .context("invalid snapshot extension")?;
        let value: Value = serde_json::from_slice(bytes).context("manifest is not JSON")?;
        if layer == "mneme" && value["schema"] == crate::mneme::LAYER_SCHEMA {
            crate::mneme::check_manifest(&serde_json::from_value(value)?, id)?;
        } else {
            layer::check_manifest(&serde_json::from_value(value)?, layer, id)?;
        }
    } else {
        bail!("unexpected object outside chunks/ and snapshots/");
    }
    Ok(())
}

/// Layer-only key check for reads; the content is not available yet.
pub(crate) fn admissible_key(key: &str) -> Result<()> {
    ObjectKey::parse(key)?;
    let layer = key.split('/').next().unwrap_or_default();
    ensure!(
        layer::LAYERS.contains(&layer) && key.starts_with(&format!("{layer}/v1/")),
        "not a layer object"
    );
    let rest = key
        .strip_prefix(&format!("{layer}/v1/"))
        .context("invalid layer key")?;
    if let Some(address) = rest.strip_prefix("chunks/sha256/") {
        let (shard, digest) = address.split_once('/').context("missing digest shard")?;
        ensure!(
            layer::valid_sha256(digest) && shard == &digest[..2],
            "invalid chunk address"
        );
    } else if let Some(id) = rest
        .strip_prefix("snapshots/")
        .and_then(|s| s.strip_suffix(".json"))
    {
        ensure!(
            layer::manifest_key(layer, id)?.as_str() == key,
            "invalid snapshot key"
        );
    } else {
        bail!("unexpected object outside chunks/ and snapshots/");
    }
    Ok(())
}

/// Receiver-side validation shared by the Android app and other peer servers.
pub fn validate_received_object(key: &str, bytes: &[u8]) -> Result<()> {
    admissible(key, bytes)
}

/// Restrict peer reads/listings to canonical layer object addresses.
pub fn validate_peer_key(key: &str) -> Result<()> {
    admissible_key(key)
}

/// Chunks first, manifests last, each group in key order.
fn ordered(keys: Vec<String>) -> Vec<String> {
    let (mut manifests, mut chunks): (Vec<_>, Vec<_>) =
        keys.into_iter().partition(|k| k.contains("/snapshots/"));
    chunks.sort();
    manifests.sort();
    chunks.extend(manifests);
    chunks
}

fn local_listing(storage: &dyn ObjectStorage, prefix: &str) -> Result<BTreeMap<String, u64>> {
    Ok(storage
        .list_prefix(prefix, 0)?
        .into_iter()
        .map(|m| (m.key, m.size))
        .collect())
}

pub fn push(
    storage: &dyn ObjectStorage,
    peer: &dyn PeerApi,
    prefixes: &[String],
    journal: &mut Journal,
) -> Result<SyncReport> {
    peer.status()?;
    let mut report = SyncReport {
        direction: "push".into(),
        prefixes: prefixes.to_vec(),
        ..Default::default()
    };
    for prefix in prefixes {
        let local = local_listing(storage, prefix)?;
        let remote = peer.list(prefix)?;
        report.local_objects += local.len();
        report.peer_objects += remote.len();
        let mut missing = Vec::new();
        for (key, size) in &local {
            match remote.get(key) {
                Some(remote_size) if remote_size == size => {
                    // An inventory is a size hint, not proof of byte identity.
                    // Even matching sizes must not conceal a damaged replica.
                    let source = storage.get(&ObjectKey::parse(key)?)?;
                    if source.len() as u64 != *size || admissible(key, &source).is_err() {
                        report.rejected.push(format!("{key}: local object integrity failure"));
                        continue;
                    }
                    if key.contains("/snapshots/") {
                        let layer_name = key.split('/').next().unwrap_or_default();
                        if !layer::check_snapshot(storage, layer_name, key).ok {
                            report.rejected.push(format!("{key}: local snapshot not recoverable"));
                            continue;
                        }
                    }
                    let replica = peer.get(key)?;
                    if replica == source {
                        report.already_present += 1;
                    } else {
                        report.conflicts.push(format!("{key}: existing peer object differs from source"));
                    }
                }
                Some(remote_size) => report.conflicts.push(format!(
                    "{key}: local {size} bytes, peer {remote_size} bytes"
                )),
                None => missing.push(key.clone()),
            }
        }
        for key in ordered(missing) {
            // Publishing a manifest promises that *all* of its chunks are
            // locally recoverable. Valid JSON alone is not enough. Never send
            // an incomplete manifest to a carrying peer (e.g. a phone).
            if key.contains("/snapshots/") {
                let layer_name = key.split('/').next().unwrap_or_default();
                let check = layer::check_snapshot(storage, layer_name, &key);
                if !check.ok {
                    report.rejected.push(format!(
                        "{key}: snapshot is not recoverable: {}",
                        check.error.unwrap_or_else(|| "unknown integrity error".to_owned())
                    ));
                    continue;
                }
            }
            let bytes = storage.get(&ObjectKey::parse(&key)?)?;
            if let Err(error) = admissible(&key, &bytes) {
                report.rejected.push(format!("{key}: {error}"));
                continue;
            }
            if peer.put(&key, &bytes)? {
                report.transferred += 1;
                report.transferred_bytes += bytes.len() as u64;
            } else {
                report.already_present += 1;
            }
        }
    }
    journal.event("peer-push", peer.base(), json!({"transferred":report.transferred,"bytes":report.transferred_bytes,"conflicts":report.conflicts.len(),"rejected":report.rejected.len()}))?;
    Ok(report)
}

pub fn pull(
    storage: &dyn ObjectStorage,
    peer: &dyn PeerApi,
    prefixes: &[String],
    journal: &mut Journal,
) -> Result<SyncReport> {
    peer.status()?;
    let mut report = SyncReport {
        direction: "pull".into(),
        prefixes: prefixes.to_vec(),
        ..Default::default()
    };
    let mut new_manifests = Vec::new();
    for prefix in prefixes {
        let local = local_listing(storage, prefix)?;
        let remote = peer.list(prefix)?;
        report.local_objects += local.len();
        report.peer_objects += remote.len();
        let mut missing = Vec::new();
        for (key, size) in &remote {
            if !key.starts_with(prefix) || admissible_key(key).is_err() {
                report
                    .rejected
                    .push(format!("{key}: invalid or out-of-scope listing entry"));
                continue;
            }
            match local.get(key) {
                Some(local_size) if local_size == size => {
                    // Never mistake matching object sizes for a verified copy.
                    // A peer may lie or be corrupted; inspect both byte strings.
                    let existing = storage.get(&ObjectKey::parse(key)?)?;
                    let incoming = peer.get(key)?;
                    if existing.len() as u64 != *size
                        || incoming.len() as u64 != *size
                        || admissible(key, &existing).is_err()
                        || admissible(key, &incoming).is_err()
                    {
                        report.rejected.push(format!("{key}: existing object fails integrity validation"));
                    } else if existing == incoming {
                        report.already_present += 1;
                    } else {
                        report.conflicts.push(format!("{key}: same-size local and peer objects differ"));
                    }
                }
                Some(local_size) => report.conflicts.push(format!(
                    "{key}: local {local_size} bytes, peer {size} bytes"
                )),
                None => missing.push(key.clone()),
            }
        }
        for key in ordered(missing) {
            let bytes = peer.get(&key)?;
            if bytes.len() as u64 != remote[&key] {
                report
                    .rejected
                    .push(format!("{key}: body size differs from listing"));
                continue;
            }
            if let Err(error) = admissible(&key, &bytes) {
                report.rejected.push(format!("{key}: {error}"));
                continue;
            }
            match storage.put_if_absent(&ObjectKey::parse(&key)?, &bytes)? {
                PutOutcome::Created(_) => {
                    report.transferred += 1;
                    report.transferred_bytes += bytes.len() as u64;
                    if key.contains("/snapshots/") {
                        new_manifests.push(key.clone());
                    }
                }
                PutOutcome::AlreadyExists(_) => report.already_present += 1,
            }
        }
    }
    // A pulled snapshot is only as good as its chunks: check each new one.
    for key in new_manifests {
        let layer_name = key.split('/').next().unwrap_or_default().to_owned();
        let check = layer::check_snapshot(storage, &layer_name, &key);
        if check.ok {
            report.verified.push(key);
        } else {
            let error = check.error.unwrap_or_default();
            // This manifest was created by this pull and did not exist locally
            // before. Removing it is not deletion propagation: it keeps a
            // damaged snapshot from being listed as if it were restorable.
            match storage.delete(&ObjectKey::parse(&key)?) {
                Ok(()) => {
                    report.quarantined.push(key.clone());
                    report
                        .verification_failed
                        .push(format!("{key}: {error} (manifest removed)"));
                }
                Err(delete_error) => report.verification_failed.push(format!(
                    "{key}: {error}; could not remove manifest: {delete_error}"
                )),
            }
        }
    }
    journal.event("peer-pull", peer.base(), json!({"transferred":report.transferred,"bytes":report.transferred_bytes,"conflicts":report.conflicts.len(),"rejected":report.rejected.len(),"verified":report.verified.len(),"quarantined":report.quarantined.len()}))?;
    Ok(report)
}

/// Default prefixes: every layer.
pub fn default_prefixes() -> Vec<String> {
    layer::LAYERS.iter().map(|l| format!("{l}/")).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(feature = "peer-http")]
    #[test]
    fn retry_backoff_is_exponential_bounded_and_fail_closed() {
        let mut attempts = 0;
        let mut delays = vec![];
        let value = retry(
            3,
            || {
                attempts += 1;
                if attempts < 4 {
                    Err(AttemptError {
                        error: anyhow::anyhow!("temporary"),
                        transient: true,
                    })
                } else {
                    Ok(7)
                }
            },
            |delay| delays.push(delay),
        )
        .unwrap();
        assert_eq!(value, 7);
        for (delay, base) in delays.iter().zip([250, 500, 1000]) {
            assert!(delay.as_millis() >= base && delay.as_millis() <= base + base / 4);
        }
        let mut attempts = 0;
        let failure = retry::<()>(
            6,
            || {
                attempts += 1;
                Err(AttemptError {
                    error: anyhow::anyhow!("permanent"),
                    transient: false,
                })
            },
            |_| panic!("permanent errors must not sleep"),
        );
        assert!(failure.is_err());
        assert_eq!(attempts, 1);
        let mut attempts = 0;
        assert!(
            retry::<()>(
                2,
                || {
                    attempts += 1;
                    Err(AttemptError {
                        error: anyhow::anyhow!("offline"),
                        transient: true,
                    })
                },
                |_| {}
            )
            .is_err()
        );
        assert_eq!(attempts, 3);
        for code in [400, 401, 403, 404, 409, 413, 429, 500] {
            let response = ureq::Response::new(code, "error", "untrusted").unwrap();
            assert!(!AttemptError::from(ureq::Error::Status(code, response)).transient);
        }
        for code in [408, 502, 503, 504] {
            let response = ureq::Response::new(code, "temporary", "untrusted").unwrap();
            assert!(AttemptError::from(ureq::Error::Status(code, response)).transient);
        }
    }

    #[cfg(feature = "peer-http")]
    #[test]
    fn http_error_pages_cannot_echo_credentials_into_reports() {
        let response = ureq::Response::new(500, "Error", "private-token-in-error-page").unwrap();
        let error = describe(ureq::Error::Status(500, response));
        assert!(error.to_string().contains("500"));
        assert!(!error.to_string().contains("private-token"));
    }

    #[cfg(feature = "storage-object-store")]
    #[test]
    fn pull_rejects_untrusted_listing_entries_before_fetching() {
        use std::cell::RefCell;

        struct ListedPeer {
            items: BTreeMap<String, u64>,
            fetched: RefCell<Vec<String>>,
        }

        impl PeerApi for ListedPeer {
            fn base(&self) -> &str {
                "test-peer"
            }
            fn status(&self) -> Result<Value> {
                Ok(json!({}))
            }
            fn list(&self, _: &str) -> Result<BTreeMap<String, u64>> {
                Ok(self.items.clone())
            }
            fn get(&self, key: &str) -> Result<Vec<u8>> {
                self.fetched.borrow_mut().push(key.into());
                Ok(b"chunk".to_vec())
            }
            fn put(&self, _: &str, _: &[u8]) -> Result<bool> {
                panic!("pull must not write to peer")
            }
        }

        let dir = tempfile::tempdir().unwrap();
        let storage = crate::FsObjectStorage::open(dir.path().join("objects")).unwrap();
        let mut journal = Journal::open(dir.path()).unwrap();
        let digest = format!("{:x}", Sha256::digest(b"chunk"));
        let key = format!("frog/v1/chunks/sha256/{}/{digest}", &digest[..2]);
        let peer = ListedPeer {
            items: BTreeMap::from([
                ("agenda/v1/snapshots/desk/x.json".into(), 5),
                ("frog/v1/stray".into(), 5),
                ("frog/../escape".into(), 5),
                (key.clone(), 99),
            ]),
            fetched: RefCell::new(Vec::new()),
        };
        let report = pull(&storage, &peer, &["frog/".into()], &mut journal).unwrap();
        assert_eq!(report.rejected.len(), 4, "{report:?}");
        assert_eq!(*peer.fetched.borrow(), vec![key]);
        assert_eq!(report.transferred, 0);
        assert!(!report.clean());
        assert!(storage.list_prefix("", 0).unwrap().is_empty());
    }

    #[cfg(feature = "peer-http")]
    #[test]
    fn parses_app_connection_strings() {
        let t = parse_connection("rbq+http://192.168.1.42:8787/v1?token=abc123", None).unwrap();
        assert_eq!(t.base, "http://192.168.1.42:8787");
        assert_eq!(t.token, "abc123");
        let t = parse_connection("http://[fe80::1]:8787/", Some("x9")).unwrap();
        assert_eq!(t.base, "http://[fe80::1]:8787");
        assert!(parse_connection("https://h:1", Some("x")).is_err());
        assert!(parse_connection("http://h:1", None).is_err());
        assert!(parse_connection("http://user@h:1", Some("x")).is_err());
        assert!(parse_connection("http://h:1?token=a%20b", None).is_err());
    }

    #[test]
    fn admits_only_verifiable_layer_objects() {
        let data = b"chunk";
        let digest = format!("{:x}", Sha256::digest(data));
        let key = format!("mneme/v1/chunks/sha256/{}/{digest}", &digest[..2]);
        assert!(admissible(&key, data).is_ok());
        assert!(admissible(&key, b"tampered").is_err());
        assert!(admissible("frog/v1/snapshots/local/x.json", br#"{"schema":"s"}"#).is_err());
        assert!(admissible("frog/v1/snapshots/local/x.json", b"not json").is_err());
        assert!(admissible("_probes/x", b"x").is_err());
        assert!(admissible("other/v1/chunks/sha256/aa/bb", b"x").is_err());
        assert!(admissible("agenda/v1/stray", b"x").is_err());
        assert_eq!(
            ordered(vec![
                "a/v1/snapshots/x.json".into(),
                "a/v1/chunks/sha256/b".into()
            ]),
            vec!["a/v1/chunks/sha256/b", "a/v1/snapshots/x.json"]
        );
    }
}
