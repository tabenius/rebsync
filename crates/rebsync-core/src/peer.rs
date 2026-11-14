//! Client for `rebsync-peer/0`, the object endpoint served by the Rebekah app.
//!
//! `push` copies local layer objects the peer lacks; `pull` copies the peer's
//! objects this store lacks. Both are additive: an object present on both
//! sides is never replaced, and a size mismatch is reported as a conflict.
//! Chunks travel before manifests, so an interrupted sync never leaves a
//! manifest whose chunks are missing. Everything received from a peer is
//! untrusted: content-addressed chunks are re-hashed, manifests must parse and
//! validate, and only layer prefixes are accepted.

use crate::{
    journal::Journal,
    layer,
    storage::{ObjectKey, ObjectStorage, PutOutcome},
};
use anyhow::{Context, Result, bail, ensure};
use serde::Serialize;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::{collections::BTreeMap, io::Read, time::Duration};

pub const PROTOCOL: &str = "rebsync-peer/0";
const PAGE: usize = 5000;
const MAX_OBJECT: u64 = 64 * 1024 * 1024;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Target {
    /// `http://host:port`, without a trailing slash.
    pub base: String,
    pub token: String,
}

/// Parse `rebsync+http://host:port/v1?token=T` (as shown by the app) or a
/// plain `http://host:port` plus a separately supplied token.
pub fn parse_connection(connection: &str, token: Option<&str>) -> Result<Target> {
    let raw = connection.trim();
    let raw = raw.strip_prefix("rebsync+").unwrap_or(raw);
    ensure!(
        raw.starts_with("http://"),
        "peer connections are http://HOST:PORT (rebsync-peer/0 has no TLS yet)"
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

pub struct Peer {
    agent: ureq::Agent,
    target: Target,
    page: usize,
}

fn encode(value: &str) -> String {
    value
        .bytes()
        .map(|b| match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' => (b as char).to_string(),
            _ => format!("%{b:02X}"),
        })
        .collect()
}

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
        }
    }

    /// Smaller pages exercise pagination in tests; servers cap at 10 000.
    pub fn with_page_size(mut self, page: usize) -> Self {
        self.page = page.clamp(1, 10_000);
        self
    }

    fn url(&self, path: &str) -> String {
        format!("{}{path}", self.target.base)
    }

    fn auth(&self, request: ureq::Request) -> ureq::Request {
        request
            .set("Authorization", &format!("Bearer {}", self.target.token))
            .set("User-Agent", concat!("rebsync/", env!("CARGO_PKG_VERSION")))
    }

    fn json(&self, path: &str) -> Result<Value> {
        let response = self
            .auth(self.agent.get(&self.url(path)))
            .call()
            .map_err(describe)?;
        Ok(response.into_json()?)
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
                    key > after.as_str(),
                    "peer ignored pagination; update the Rebekah app to 0.2.1 or later"
                );
                found.insert(key.to_owned(), size);
                last = Some(key.to_owned());
            }
            match (page.get("truncated").and_then(Value::as_bool), last) {
                (Some(true), Some(last)) => after = last,
                _ => break,
            }
        }
        Ok(found)
    }

    pub fn get(&self, key: &str) -> Result<Vec<u8>> {
        let response = self
            .auth(
                self.agent
                    .get(&self.url(&format!("/v1/objects/{}", encode_key(key)))),
            )
            .call()
            .map_err(describe)?;
        let mut bytes = Vec::new();
        response
            .into_reader()
            .take(MAX_OBJECT + 1)
            .read_to_end(&mut bytes)?;
        ensure!(
            bytes.len() as u64 <= MAX_OBJECT,
            "{key}: object exceeds 64 MiB"
        );
        Ok(bytes)
    }

    /// Create-if-absent on the peer. Returns true when created.
    pub fn put(&self, key: &str, bytes: &[u8]) -> Result<bool> {
        let response = self
            .auth(
                self.agent
                    .put(&self.url(&format!("/v1/objects/{}", encode_key(key)))),
            )
            .send_bytes(bytes)
            .map_err(describe)?;
        Ok(response.status() == 201)
    }
}

fn encode_key(key: &str) -> String {
    key.split('/').map(encode).collect::<Vec<_>>().join("/")
}

fn describe(error: ureq::Error) -> anyhow::Error {
    match error {
        ureq::Error::Status(401, _) => anyhow::anyhow!("peer rejected the token (401)"),
        ureq::Error::Status(429, _) => {
            anyhow::anyhow!("peer is throttling after failed attempts; wait a minute")
        }
        ureq::Error::Status(503, _) => {
            anyhow::anyhow!("peer is moving its data; retry when the move finishes")
        }
        ureq::Error::Status(code, response) => {
            let body = response.into_string().unwrap_or_default();
            anyhow::anyhow!(
                "peer returned {code}: {}",
                body.chars().take(200).collect::<String>()
            )
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
}

/// Accept only layer objects, and check what can be checked before storing.
fn admissible(key: &str, bytes: &[u8]) -> Result<()> {
    ObjectKey::parse(key)?;
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
        let value: Value = serde_json::from_slice(bytes).context("manifest is not JSON")?;
        ensure!(value.get("schema").is_some(), "manifest without schema");
    } else {
        bail!("unexpected object outside chunks/ and snapshots/");
    }
    Ok(())
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
    peer: &Peer,
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
                Some(remote_size) if remote_size == size => report.already_present += 1,
                Some(remote_size) => report.conflicts.push(format!(
                    "{key}: local {size} bytes, peer {remote_size} bytes"
                )),
                None => missing.push(key.clone()),
            }
        }
        for key in ordered(missing) {
            let bytes = storage.get(&ObjectKey::parse(&key)?)?;
            if let Err(error) = admissible(&key, &bytes) {
                report.rejected.push(format!("{key}: {error}"));
                continue;
            }
            peer.put(&key, &bytes)?;
            report.transferred += 1;
            report.transferred_bytes += bytes.len() as u64;
        }
    }
    journal.event("peer-push", &peer.target.base, json!({"transferred":report.transferred,"bytes":report.transferred_bytes,"conflicts":report.conflicts.len(),"rejected":report.rejected.len()}))?;
    Ok(report)
}

pub fn pull(
    storage: &dyn ObjectStorage,
    peer: &Peer,
    prefixes: &[String],
    journal: &mut Journal,
) -> Result<SyncReport> {
    peer.status()?;
    let mut report = SyncReport {
        direction: "pull".into(),
        prefixes: prefixes.to_vec(),
        ..Default::default()
    };
    for prefix in prefixes {
        let local = local_listing(storage, prefix)?;
        let remote = peer.list(prefix)?;
        report.local_objects += local.len();
        report.peer_objects += remote.len();
        let mut missing = Vec::new();
        for (key, size) in &remote {
            match local.get(key) {
                Some(local_size) if local_size == size => report.already_present += 1,
                Some(local_size) => report.conflicts.push(format!(
                    "{key}: local {local_size} bytes, peer {size} bytes"
                )),
                None => missing.push(key.clone()),
            }
        }
        for key in ordered(missing) {
            let bytes = peer.get(&key)?;
            if let Err(error) = admissible(&key, &bytes) {
                report.rejected.push(format!("{key}: {error}"));
                continue;
            }
            match storage.put_if_absent(&ObjectKey::parse(&key)?, &bytes)? {
                PutOutcome::Created(_) => {
                    report.transferred += 1;
                    report.transferred_bytes += bytes.len() as u64;
                }
                PutOutcome::AlreadyExists(_) => report.already_present += 1,
            }
        }
    }
    journal.event("peer-pull", &peer.target.base, json!({"transferred":report.transferred,"bytes":report.transferred_bytes,"conflicts":report.conflicts.len(),"rejected":report.rejected.len()}))?;
    Ok(report)
}

/// Default prefixes: every layer.
pub fn default_prefixes() -> Vec<String> {
    layer::LAYERS.iter().map(|l| format!("{l}/")).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_app_connection_strings() {
        let t = parse_connection("rebsync+http://192.168.1.42:8787/v1?token=abc123", None).unwrap();
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
        assert!(admissible("frog/v1/snapshots/local/x.json", br#"{"schema":"s"}"#).is_ok());
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
