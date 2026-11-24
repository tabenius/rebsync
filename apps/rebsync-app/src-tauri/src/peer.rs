//! A small, token-protected peer endpoint over the shared object store.
//!
//! Experimental `rbq-peer/0` protocol: list, read and create-if-absent.
//! There is no delete and no overwrite, matching the core's rule that
//! synchronization never propagates deletions. Served over HTTPS only, with
//! the phone's own key (the same one QUIC uses): a client pins it from the
//! connection string (`peer=`), so the token is never sent in clear and no
//! other device can pose as this phone.

use rebsync_core::{ObjectKey, ObjectStorage, PutOutcome, StorageError};
use serde::Serialize;
use sha2::{Digest, Sha256};
use std::{
    collections::BTreeMap,
    io::Read,
    net::SocketAddr,
    sync::{
        Arc, Mutex, RwLock,
        atomic::{AtomicBool, Ordering},
    },
    thread,
    time::{Duration, SystemTime, UNIX_EPOCH},
};
use tiny_http::{Header, Method, Request, Response, Server};

pub const PROTOCOL: &str = "rbq-peer/0";
/// Largest accepted object body; Mneme chunks are at most 64 MiB.
const MAX_BODY: u64 = 64 * 1024 * 1024;
const MAX_LIST: usize = 10_000;
const ACTIVE_MS: u64 = 60_000;

pub type SharedStorage = Arc<RwLock<Arc<dyn ObjectStorage>>>;

fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or_default()
}

#[derive(Clone, Debug, Default, Serialize)]
pub struct Client {
    pub address: String,
    pub first_seen_ms: u64,
    pub last_seen_ms: u64,
    pub requests: u64,
    pub rejected: u64,
    pub bytes_in: u64,
    pub bytes_out: u64,
    pub user_agent: Option<String>,
    pub last_request: String,
    pub authorized: bool,
    pub active: bool,
    /// How this client has reached the phone: `http` (plaintext) and/or
    /// `quic` (encrypted).
    pub transports: Vec<String>,
    #[serde(skip)]
    recent_failures: Vec<u64>,
}

#[derive(Default)]
pub struct Clients(Mutex<BTreeMap<String, Client>>);

impl Clients {
    pub fn snapshot(&self) -> Vec<Client> {
        let now = now_ms();
        let mut list: Vec<Client> = self
            .0
            .lock()
            .map(|map| map.values().cloned().collect())
            .unwrap_or_default();
        for client in &mut list {
            client.active = now.saturating_sub(client.last_seen_ms) < ACTIVE_MS;
        }
        list.sort_by_key(|c| std::cmp::Reverse(c.last_seen_ms));
        list
    }

    fn throttled(&self, address: &str) -> bool {
        let now = now_ms();
        self.0.lock().is_ok_and(|map| {
            map.get(address).is_some_and(|c| {
                c.recent_failures
                    .iter()
                    .filter(|t| now.saturating_sub(**t) < 60_000)
                    .count()
                    >= 10
            })
        })
    }

    #[allow(clippy::too_many_arguments)]
    fn record(
        &self,
        transport: &str,
        address: &str,
        user_agent: Option<String>,
        line: String,
        authorized: bool,
        rejected: bool,
        bytes_in: u64,
        bytes_out: u64,
    ) {
        let now = now_ms();
        if let Ok(mut map) = self.0.lock() {
            // Bound memory against address churn.
            if map.len() >= 256
                && !map.contains_key(address)
                && let Some(oldest) = map
                    .values()
                    .min_by_key(|c| c.last_seen_ms)
                    .map(|c| c.address.clone())
            {
                map.remove(&oldest);
            }
            let client = map.entry(address.to_owned()).or_insert_with(|| Client {
                address: address.to_owned(),
                first_seen_ms: now,
                ..Default::default()
            });
            client.last_seen_ms = now;
            client.requests += 1;
            if !client.transports.iter().any(|t| t == transport) {
                client.transports.push(transport.to_owned());
                client.transports.sort();
            }
            client.bytes_in += bytes_in;
            client.bytes_out += bytes_out;
            client.last_request = line;
            if user_agent.is_some() {
                client.user_agent = user_agent;
            }
            if rejected {
                client.rejected += 1;
                client.recent_failures.push(now);
                client
                    .recent_failures
                    .retain(|t| now.saturating_sub(*t) < 60_000);
            } else if authorized {
                client.authorized = true;
            }
        }
    }
}

/// The QUIC share reports its requests here too, so one list shows every
/// client however it connected, and the same failure throttle applies.
impl rebsync_core::transport::Observer for Clients {
    fn request(&self, record: &rebsync_core::transport::RequestRecord<'_>) {
        self.record(
            record.transport,
            record.peer,
            None,
            format!(
                "{} {}",
                record.transport.to_ascii_uppercase(),
                record.request
            ),
            record.authorized,
            record.rejected,
            record.bytes_in,
            record.bytes_out,
        );
    }

    fn admit(&self, peer: &str) -> bool {
        !self.throttled(peer)
    }
}

pub struct Peer {
    server: Arc<Server>,
    stop: Arc<AtomicBool>,
    pub port: u16,
    workers: Vec<thread::JoinHandle<()>>,
}

impl Peer {
    /// Serve over HTTPS as `identity` (the phone's long-term key).
    pub fn start(
        port: u16,
        token: String,
        storage: SharedStorage,
        clients: Arc<Clients>,
        writes_paused: Arc<AtomicBool>,
        identity: &rebsync_core::transport::quic::Identity,
    ) -> Result<Self, String> {
        let tls = || tiny_http::SslConfig {
            certificate: identity.certificate_pem().into_bytes(),
            private_key: identity.private_key_pem().into_bytes(),
        };
        let server = Server::https(("0.0.0.0", port), tls())
            .or_else(|_| Server::https(("0.0.0.0", 0), tls()))
            .map_err(|e| format!("cannot listen: {e}"))?;
        let port = server
            .server_addr()
            .to_ip()
            .map(|a| a.port())
            .ok_or("listener has no IP address")?;
        let server = Arc::new(server);
        let stop = Arc::new(AtomicBool::new(false));
        let token = Arc::new(token);
        let workers = (0..4)
            .map(|_| {
                let (server, stop, token, storage, clients, paused) = (
                    server.clone(),
                    stop.clone(),
                    token.clone(),
                    storage.clone(),
                    clients.clone(),
                    writes_paused.clone(),
                );
                thread::spawn(move || {
                    while !stop.load(Ordering::Relaxed) {
                        match server.recv_timeout(Duration::from_millis(500)) {
                            Ok(Some(request)) => {
                                handle(request, &token, &storage, &clients, &paused)
                            }
                            Ok(None) => {}
                            Err(_) => break,
                        }
                    }
                })
            })
            .collect();
        Ok(Self {
            server,
            stop,
            port,
            workers,
        })
    }

    pub fn stop(mut self) {
        self.stop.store(true, Ordering::Relaxed);
        self.server.unblock();
        for worker in self.workers.drain(..) {
            let _ = worker.join();
        }
        // Dropping the last handle closes the listener (on tiny_http's accept
        // thread, so it completes shortly after this returns).
        drop(self.server);
    }
}

fn json_header() -> Header {
    Header::from_bytes(&b"Content-Type"[..], &b"application/json"[..]).expect("static header")
}

fn header(request: &Request, name: &'static str) -> Option<String> {
    request
        .headers()
        .iter()
        .find(|h| h.field.equiv(name))
        .map(|h| h.value.as_str().to_owned())
}

/// Constant-time comparison so response timing does not leak the token.
fn same(a: &str, b: &str) -> bool {
    a.len() == b.len()
        && a.bytes()
            .zip(b.bytes())
            .fold(0_u8, |acc, (x, y)| acc | (x ^ y))
            == 0
}

fn split_query(url: &str) -> (&str, BTreeMap<String, String>) {
    let (path, query) = url.split_once('?').unwrap_or((url, ""));
    let params = query
        .split('&')
        .filter(|p| !p.is_empty())
        .filter_map(|p| {
            let (k, v) = p.split_once('=').unwrap_or((p, ""));
            Some((decode(k)?, decode(v)?))
        })
        .collect();
    (path, params)
}

fn decode(value: &str) -> Option<String> {
    let bytes = value.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        match bytes[i] {
            b'%' => {
                if i + 2 >= bytes.len() {
                    return None;
                }
                let hex = std::str::from_utf8(&bytes[i + 1..i + 3]).ok()?;
                out.push(u8::from_str_radix(hex, 16).ok()?);
                i += 3;
            }
            b'+' => {
                out.push(b' ');
                i += 1;
            }
            b => {
                out.push(b);
                i += 1;
            }
        }
    }
    String::from_utf8(out).ok()
}

fn status_of(error: &StorageError) -> u16 {
    match error {
        StorageError::InvalidKey(_) => 400,
        StorageError::NotFound(_) => 404,
        StorageError::AlreadyExists(_) => 409,
        StorageError::PermissionDenied(_) => 403,
        StorageError::Unavailable(_) => 503,
        StorageError::Unsupported(_) => 501,
        StorageError::Corrupt(_) | StorageError::Backend(_) => 500,
    }
}

fn handle(
    mut request: Request,
    token: &str,
    storage: &SharedStorage,
    clients: &Clients,
    writes_paused: &AtomicBool,
) {
    let address = request
        .remote_addr()
        .map(SocketAddr::ip)
        .map(|ip| ip.to_string())
        .unwrap_or_else(|| "unknown".into());
    let agent = header(&request, "User-Agent").map(|a| a.chars().take(120).collect());
    let method = request.method().clone();
    let url = request.url().to_owned();
    let (path, params) = split_query(&url);
    let path = path.to_owned();
    let line = format!("{method} {path}");

    let respond = |request: Request, status: u16, body: Vec<u8>, json: bool, authorized: bool| {
        let rejected = status == 401 || status == 429;
        let sent = body.len() as u64;
        let mut response = Response::from_data(body).with_status_code(status);
        if json {
            response = response.with_header(json_header());
        }
        let received = request.body_length().unwrap_or(0) as u64;
        let _ = request.respond(response);
        clients.record(
            "http",
            &address,
            agent.clone(),
            line.clone(),
            authorized,
            rejected,
            received,
            sent,
        );
    };
    let error = |message: &str| {
        serde_json::to_vec(&serde_json::json!({"error": message})).unwrap_or_default()
    };

    if path == "/v1/health" && method == Method::Get {
        let body = serde_json::to_vec(
            &serde_json::json!({"ok": true, "app": "rebeqah", "protocol": PROTOCOL}),
        )
        .unwrap_or_default();
        return respond(request, 200, body, true, false);
    }
    if clients.throttled(&address) {
        return respond(
            request,
            429,
            error("too many failed attempts; wait a minute"),
            true,
            false,
        );
    }
    let presented = header(&request, "Authorization")
        .and_then(|h| h.strip_prefix("Bearer ").map(str::to_owned))
        .or_else(|| params.get("token").cloned());
    if !presented.as_deref().is_some_and(|p| same(p, token)) {
        return respond(request, 401, error("missing or invalid token"), true, false);
    }
    let store = match storage.try_read() {
        Ok(guard) => guard.clone(),
        Err(std::sync::TryLockError::WouldBlock) => {
            return respond(request, 503, error("storage busy; retry later"), true, true);
        }
        Err(_) => return respond(request, 500, error("storage lock poisoned"), true, true),
    };

    match (method, path.as_str()) {
        (Method::Get, "/v1/status") => {
            let caps = store.capabilities();
            let body = serde_json::json!({
                "protocol": PROTOCOL,
                "app": "rebeqah",
                "version": env!("CARGO_PKG_VERSION"),
                "writes_paused": writes_paused.load(Ordering::Relaxed),
                "capabilities": {
                    "atomic_create_if_absent": caps.atomic_create_if_absent,
                    "owner_only_permissions": caps.owner_only_permissions,
                    "range_reads": caps.range_reads,
                    "max_key_bytes": caps.max_key_bytes,
                    "hashes": true,
                },
            });
            respond(
                request,
                200,
                serde_json::to_vec(&body).unwrap_or_default(),
                true,
                true,
            )
        }
        (Method::Get, "/v1/objects") => {
            let prefix = params.get("prefix").cloned().unwrap_or_default();
            let limit = params
                .get("limit")
                .and_then(|l| l.parse().ok())
                .unwrap_or(1000)
                .clamp(1, MAX_LIST);
            // Keyset pagination: keys strictly after `after`, in key order.
            let after = params.get("after").cloned().unwrap_or_default();
            match store.list_prefix(&prefix, 0) {
                Ok(items) => {
                    let mut page: Vec<_> = items
                        .into_iter()
                        .filter(|m| m.key.as_str() > after.as_str())
                        .filter(|m| rebsync_core::peer::validate_peer_key(&m.key).is_ok())
                        .take(limit + 1)
                        .map(|m| serde_json::json!({"key": m.key, "size": m.size}))
                        .collect();
                    let truncated = page.len() > limit;
                    page.truncate(limit);
                    let body = serde_json::json!({"items": page, "truncated": truncated});
                    respond(
                        request,
                        200,
                        serde_json::to_vec(&body).unwrap_or_default(),
                        true,
                        true,
                    )
                }
                Err(e) => respond(request, status_of(&e), error(&e.to_string()), true, true),
            }
        }
        // The SHA-256 of a stored object, so a client verifies a copy both
        // sides hold without downloading it. Read in 1 MiB windows.
        (Method::Get, p) if p.starts_with("/v1/hash/") => {
            let key = match decode(&p["/v1/hash/".len()..])
                .ok_or_else(|| StorageError::InvalidKey("bad percent-encoding".into()))
                .and_then(|k| ObjectKey::parse(&k))
            {
                Ok(key) => key,
                Err(e) => return respond(request, 400, error(&e.to_string()), true, true),
            };
            if rebsync_core::peer::validate_peer_key(key.as_str()).is_err() {
                return respond(
                    request,
                    400,
                    error("not a canonical layer object"),
                    true,
                    true,
                );
            }
            let hashed = store.head(&key).and_then(|meta| {
                let mut hasher = Sha256::new();
                let mut at = 0;
                while at < meta.size {
                    let next = (at + 1024 * 1024).min(meta.size);
                    hasher.update(store.get_range(&key, at..next)?);
                    at = next;
                }
                Ok((format!("{:x}", hasher.finalize()), meta.size))
            });
            match hashed {
                Ok((sha256, size)) => respond(
                    request,
                    200,
                    serde_json::to_vec(&serde_json::json!({"sha256": sha256, "size": size}))
                        .unwrap_or_default(),
                    true,
                    true,
                ),
                Err(e) => respond(request, status_of(&e), error(&e.to_string()), true, true),
            }
        }
        (method, p) if p.starts_with("/v1/objects/") => {
            let key = match decode(&p["/v1/objects/".len()..])
                .ok_or_else(|| StorageError::InvalidKey("bad percent-encoding".into()))
                .and_then(|k| ObjectKey::parse(&k))
            {
                Ok(key) => key,
                Err(e) => return respond(request, 400, error(&e.to_string()), true, true),
            };
            if rebsync_core::peer::validate_peer_key(key.as_str()).is_err() {
                return respond(
                    request,
                    400,
                    error("not a canonical layer object"),
                    true,
                    true,
                );
            }
            match method {
                Method::Get => match store.get(&key) {
                    Ok(bytes) => respond(request, 200, bytes, false, true),
                    Err(e) => respond(request, status_of(&e), error(&e.to_string()), true, true),
                },
                Method::Head => match store.head(&key) {
                    Ok(meta) => {
                        let len = Header::from_bytes(
                            &b"X-Object-Size"[..],
                            meta.size.to_string().as_bytes(),
                        )
                        .expect("numeric header");
                        let response = Response::empty(200).with_header(len);
                        let _ = request.respond(response);
                        clients.record("http", &address, agent, line, true, false, 0, 0);
                    }
                    Err(e) => respond(request, status_of(&e), Vec::new(), false, true),
                },
                Method::Put => {
                    if writes_paused.load(Ordering::Relaxed) {
                        return respond(
                            request,
                            503,
                            error("data is being moved; retry later"),
                            true,
                            true,
                        );
                    }
                    let expected = request.body_length();
                    if expected.is_none_or(|n| n as u64 > MAX_BODY) {
                        return respond(
                            request,
                            413,
                            error("Content-Length required, at most 64 MiB"),
                            true,
                            true,
                        );
                    }
                    let mut body = Vec::new();
                    if request
                        .as_reader()
                        .take(MAX_BODY + 1)
                        .read_to_end(&mut body)
                        .is_err()
                        || body.len() as u64 > MAX_BODY
                        || Some(body.len()) != expected
                    {
                        return respond(request, 400, error("could not read body"), true, true);
                    }
                    if rebsync_core::peer::validate_received_object(key.as_str(), &body).is_err() {
                        return respond(
                            request,
                            400,
                            error("invalid layer object or digest"),
                            true,
                            true,
                        );
                    }
                    // Synchronize with moves: a writer holds this guard through
                    // publication, and the mover takes the exclusive lock before copying.
                    let active = match storage.try_read() {
                        Ok(guard) => guard,
                        Err(_) => {
                            return respond(
                                request,
                                503,
                                error("storage busy; retry later"),
                                true,
                                true,
                            );
                        }
                    };
                    if writes_paused.load(Ordering::SeqCst) {
                        return respond(
                            request,
                            503,
                            error("data is being moved; retry later"),
                            true,
                            true,
                        );
                    }
                    let outcome = active.put_if_absent(&key, &body);
                    let incoming = Sha256::digest(&body);
                    let incoming_len = body.len() as u64;
                    drop(body);
                    match outcome {
                        Ok(PutOutcome::Created(_)) => respond(
                            request,
                            201,
                            br#"{"status":"created"}"#.to_vec(),
                            true,
                            true,
                        ),
                        Ok(PutOutcome::AlreadyExists(meta)) => {
                            if meta.size != incoming_len
                                || !active
                                    .get(&key)
                                    .is_ok_and(|bytes| Sha256::digest(&bytes) == incoming)
                            {
                                return respond(
                                    request,
                                    409,
                                    error("existing object differs; never overwritten"),
                                    true,
                                    true,
                                );
                            }
                            let body = serde_json::json!({"status": "exists", "size": meta.size});
                            respond(
                                request,
                                200,
                                serde_json::to_vec(&body).unwrap_or_default(),
                                true,
                                true,
                            )
                        }
                        Err(e) => {
                            respond(request, status_of(&e), error(&e.to_string()), true, true)
                        }
                    }
                }
                _ => respond(
                    request,
                    405,
                    error("only GET, HEAD and PUT (create-if-absent)"),
                    true,
                    true,
                ),
            }
        }
        _ => respond(request, 404, error("unknown endpoint"), true, true),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decoding_and_comparison() {
        assert_eq!(decode("a%2Fb+c").as_deref(), Some("a/b c"));
        assert_eq!(decode("%zz"), None);
        assert_eq!(decode("50%"), None);
        assert!(same("abc", "abc"));
        assert!(!same("abc", "abd"));
        assert!(!same("abc", "abcd"));
        let (path, params) = split_query("/v1/objects?prefix=mneme%2F&limit=5");
        assert_eq!(path, "/v1/objects");
        assert_eq!(params["prefix"], "mneme/");
    }
}
