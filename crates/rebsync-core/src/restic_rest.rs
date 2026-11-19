//! A restic REST server (protocol v1 and v2) over [`ObjectStorage`].
//!
//! Storage milestone 1: real `restic` can create, back up to, list, read and
//! check a repository held in an rbq object store. Policy, not convenience:
//!
//! - Every request needs HTTP Basic credentials; the password comes from an
//!   owner-only file and is compared in constant time.
//! - A listener off loopback requires TLS (or run it on loopback behind an
//!   authenticated tunnel such as SSH).
//! - One repository per server, in a dedicated key namespace (`restic/`).
//! - Uploads are verified: every object except `config` must be named by the
//!   SHA-256 of its bytes, as restic names them. Objects are created only if
//!   absent; an identical retry succeeds, nothing is ever replaced.
//! - Append-only (the default) refuses every deletion except locks, which a
//!   normal backup must remove. Pruning is a separate administrative act.
//! - An optional quota counts stored bytes; uploads beyond it get 507.
//! - Error responses never echo request data; logs are the caller's choice.
use crate::storage::{ObjectKey, ObjectStorage, PutOutcome, StorageError};
use crate::wire;
use anyhow::{Context, Result, bail, ensure};
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};

/// restic packs default to 16 MiB and can be configured up to 128 MiB.
pub const MAX_UPLOAD_BYTES: u64 = 128 * 1024 * 1024 + 1024 * 1024;
const NAMESPACE: &str = "restic";
const TYPES: [&str; 5] = ["data", "keys", "locks", "snapshots", "index"];
const V2: &str = "application/vnd.x.restic.rest.v2";
const V1: &str = "application/vnd.x.restic.rest.v1";

/// Server policy. `password` is the secret itself, read by the caller from an
/// owner-only file (see [`read_password_file`]).
pub struct ResticOptions {
    pub bind: SocketAddr,
    pub user: String,
    pub password: String,
    pub append_only: bool,
    pub max_bytes: Option<u64>,
    /// PEM certificate and key. Required unless `bind` is a loopback address.
    pub tls: Option<(Vec<u8>, Vec<u8>)>,
}

/// A parsed request, independent of the HTTP library.
pub struct Request<'a> {
    pub method: &'a str,
    pub path: &'a str,
    pub query: &'a str,
    pub authorization: Option<&'a str>,
    pub accept: Option<&'a str>,
    pub range: Option<&'a str>,
    pub body: &'a [u8],
}

#[derive(Debug, PartialEq, Eq)]
pub struct Reply {
    pub status: u16,
    pub headers: Vec<(&'static str, String)>,
    pub body: Vec<u8>,
    /// For HEAD: the length to announce without sending a body.
    pub head_length: Option<u64>,
}

impl Reply {
    fn empty(status: u16) -> Self {
        Self {
            status,
            headers: Vec::new(),
            body: Vec::new(),
            head_length: None,
        }
    }
    fn bytes(status: u16, content_type: &str, body: Vec<u8>) -> Self {
        Self {
            status,
            headers: vec![("Content-Type", content_type.to_owned())],
            body,
            head_length: None,
        }
    }
}

/// Repository state shared by request handlers.
pub struct Repository {
    storage: Arc<dyn ObjectStorage>,
    user_digest: [u8; 32],
    password_digest: [u8; 32],
    append_only: bool,
    max_bytes: Option<u64>,
    used: Mutex<u64>,
}

fn digest(text: &str) -> [u8; 32] {
    use sha2::{Digest, Sha256};
    Sha256::digest(text.as_bytes()).into()
}

/// Constant-time equality of two digests.
fn same(a: &[u8; 32], b: &[u8; 32]) -> bool {
    a.iter().zip(b).fold(0u8, |acc, (x, y)| acc | (x ^ y)) == 0
}

fn is_id(name: &str) -> bool {
    name.len() == 64 && name.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
}

fn object_key(kind: &str, name: &str) -> ObjectKey {
    // Fan data packs out like rest-server; names are validated hex IDs.
    let key = if kind == "data" {
        format!("{NAMESPACE}/data/{}/{name}", &name[..2])
    } else {
        format!("{NAMESPACE}/{kind}/{name}")
    };
    ObjectKey::parse(&key).expect("validated restic object key")
}

fn config_key() -> ObjectKey {
    ObjectKey::parse(&format!("{NAMESPACE}/config")).expect("static key")
}

fn storage_status(error: &StorageError) -> u16 {
    match error {
        StorageError::NotFound(_) => 404,
        StorageError::AlreadyExists(_) | StorageError::PermissionDenied(_) => 403,
        StorageError::InvalidKey(_) => 400,
        StorageError::Unsupported(_) => 501,
        _ => 500,
    }
}

/// `bytes=START-END` (inclusive) or `bytes=START-`, as restic sends them.
fn parse_range(header: &str, size: u64) -> Option<std::ops::Range<u64>> {
    let spec = header.strip_prefix("bytes=")?;
    let (start, end) = spec.split_once('-')?;
    let start: u64 = start.parse().ok()?;
    let end = if end.is_empty() {
        size.checked_sub(1)?
    } else {
        end.parse::<u64>().ok()?.min(size.checked_sub(1)?)
    };
    (start <= end && start < size).then_some(start..end + 1)
}

impl Repository {
    pub fn new(
        storage: Arc<dyn ObjectStorage>,
        user: &str,
        password: &str,
        append_only: bool,
        max_bytes: Option<u64>,
    ) -> Result<Self> {
        ensure!(
            !user.is_empty() && !user.contains(':'),
            "user must be non-empty and contain no ':'"
        );
        ensure!(
            password.len() >= 16,
            "password must be at least 16 characters"
        );
        let used = storage
            .list_prefix(&format!("{NAMESPACE}/"), 0)
            .map_err(|e| anyhow::anyhow!("{e}"))?
            .iter()
            .map(|meta| meta.size)
            .sum();
        Ok(Self {
            storage,
            user_digest: digest(user),
            password_digest: digest(password),
            append_only,
            max_bytes,
            used: Mutex::new(used),
        })
    }

    /// Bytes currently stored in the repository namespace.
    pub fn used_bytes(&self) -> u64 {
        *self.used.lock().expect("quota lock")
    }

    fn authorized(&self, header: Option<&str>) -> bool {
        let Some(encoded) = header.and_then(|h| h.strip_prefix("Basic ")) else {
            return false;
        };
        let Some(decoded) = wire::base64_decode(encoded.trim()) else {
            return false;
        };
        let Ok(text) = String::from_utf8(decoded) else {
            return false;
        };
        let Some((user, password)) = text.split_once(':') else {
            return false;
        };
        // Evaluate both comparisons so timing does not reveal which failed.
        let user_ok = same(&digest(user), &self.user_digest);
        let password_ok = same(&digest(password), &self.password_digest);
        user_ok & password_ok
    }

    pub fn handle(&self, request: &Request) -> Reply {
        if !self.authorized(request.authorization) {
            let mut reply = Reply::empty(401);
            reply
                .headers
                .push(("WWW-Authenticate", "Basic realm=\"rbq restic\"".into()));
            return reply;
        }
        let segments: Vec<&str> = request.path.trim_start_matches('/').split('/').collect();
        let head = request.method == "HEAD";
        match (request.method, segments.as_slice()) {
            ("POST", [""]) if request.query.split('&').any(|p| p == "create=true") => {
                Reply::empty(200)
            }
            ("HEAD" | "GET", ["config"]) => self.read(&config_key(), None, head),
            ("POST", ["config"]) => self.create(&config_key(), request.body, None),
            ("DELETE", ["config"]) => {
                if self.append_only {
                    Reply::empty(403)
                } else {
                    self.remove(&config_key())
                }
            }
            ("GET", [kind, ""]) | ("GET", [kind]) if TYPES.contains(kind) => {
                self.list(kind, request.accept)
            }
            (_, [kind, name]) if TYPES.contains(kind) && !name.is_empty() => {
                if !is_id(name) {
                    return Reply::empty(400);
                }
                let key = object_key(kind, name);
                match request.method {
                    "HEAD" | "GET" => self.read(&key, request.range, head),
                    "POST" => self.create(&key, request.body, Some(name)),
                    "DELETE" if self.append_only && *kind != "locks" => Reply::empty(403),
                    "DELETE" => self.remove(&key),
                    _ => Reply::empty(405),
                }
            }
            _ => Reply::empty(404),
        }
    }

    fn read(&self, key: &ObjectKey, range: Option<&str>, head: bool) -> Reply {
        let meta = match self.storage.head(key) {
            Ok(meta) => meta,
            Err(error) => return Reply::empty(storage_status(&error)),
        };
        if head {
            let mut reply = Reply::empty(200);
            reply.head_length = Some(meta.size);
            return reply;
        }
        let (status, result) = match range {
            Some(header) => match parse_range(header, meta.size) {
                Some(range) => (206, self.storage.get_range(key, range)),
                None => return Reply::empty(416),
            },
            None => (200, self.storage.get(key)),
        };
        match result {
            Ok(bytes) => Reply::bytes(status, "application/octet-stream", bytes),
            Err(error) => Reply::empty(storage_status(&error)),
        }
    }

    fn create(&self, key: &ObjectKey, body: &[u8], name: Option<&str>) -> Reply {
        if let Some(name) = name
            && wire::sha256_hex(body) != name
        {
            // restic names every object except config by its SHA-256.
            return Reply::empty(400);
        }
        // Reserve quota before writing so concurrent uploads cannot overshoot.
        {
            let mut used = self.used.lock().expect("quota lock");
            if let Some(max) = self.max_bytes
                && *used + body.len() as u64 > max
            {
                return Reply::empty(507);
            }
            *used += body.len() as u64;
        }
        let release = || *self.used.lock().expect("quota lock") -= body.len() as u64;
        match self.storage.put_if_absent(key, body) {
            Ok(PutOutcome::Created(_)) => Reply::empty(200),
            Ok(PutOutcome::AlreadyExists(meta)) => {
                release();
                // Identical retries succeed; nothing is ever replaced.
                let same_bytes = meta.size == body.len() as u64
                    && self.storage.get(key).is_ok_and(|existing| existing == body);
                Reply::empty(if same_bytes { 200 } else { 403 })
            }
            Err(error) => {
                release();
                Reply::empty(storage_status(&error))
            }
        }
    }

    fn remove(&self, key: &ObjectKey) -> Reply {
        let size = self.storage.head(key).map(|meta| meta.size).ok();
        match self.storage.delete(key) {
            Ok(()) => {
                if let Some(size) = size {
                    let mut used = self.used.lock().expect("quota lock");
                    *used = used.saturating_sub(size);
                }
                Reply::empty(200)
            }
            Err(error) => Reply::empty(storage_status(&error)),
        }
    }

    fn list(&self, kind: &str, accept: Option<&str>) -> Reply {
        let prefix = format!("{NAMESPACE}/{kind}/");
        let items = match self.storage.list_prefix(&prefix, 0) {
            Ok(items) => items,
            Err(error) => return Reply::empty(storage_status(&error)),
        };
        let entries: Vec<(String, u64)> = items
            .into_iter()
            .filter_map(|meta| {
                let name = meta.key.rsplit('/').next()?.to_owned();
                is_id(&name).then_some((name, meta.size))
            })
            .collect();
        if accept.is_some_and(|a| a.contains(V2)) {
            let value: Vec<_> = entries
                .iter()
                .map(|(name, size)| serde_json::json!({"name": name, "size": size}))
                .collect();
            Reply::bytes(200, V2, serde_json::to_vec(&value).expect("json"))
        } else {
            let names: Vec<_> = entries.into_iter().map(|(name, _)| name).collect();
            Reply::bytes(200, V1, serde_json::to_vec(&names).expect("json"))
        }
    }
}

/// Read the server password from a file that only its owner can read.
pub fn read_password_file(path: &std::path::Path) -> Result<String> {
    let file = std::fs::File::open(path)
        .with_context(|| format!("open password file {}", path.display()))?;
    wire::ensure_private_file(path, &file.metadata()?)?;
    let bytes = wire::read_bounded(file, 4096)?.context("password file exceeds 4 KiB")?;
    let text = String::from_utf8(bytes).context("password file must be UTF-8")?;
    Ok(text.trim_end_matches(['\n', '\r']).to_owned())
}

/// A self-signed certificate for the restic listener, kept in rbq's private
/// state directory. Returns PEM certificate, PEM key, the certificate path
/// (give it to `restic --cacert`) and its SHA-256 fingerprint.
pub fn self_signed_certificate(
    config: &crate::Config,
    names: Vec<String>,
) -> Result<(Vec<u8>, Vec<u8>, std::path::PathBuf, String)> {
    let dir = crate::sync::state_dir(config)?.join("tls-restic");
    let (certificate, key, fingerprint) = crate::serve::certificate(&dir, names)?;
    Ok((certificate, key, dir.join("localhost.crt.pem"), fingerprint))
}

/// A bound restic REST listener.
pub struct ResticServer {
    server: Arc<tiny_http::Server>,
    pub url: String,
    pub port: u16,
    pub tls: bool,
}

/// Bind the listener. Refuses plain HTTP off loopback.
pub fn bind(options: &ResticOptions) -> Result<ResticServer> {
    if options.tls.is_none() && !options.bind.ip().is_loopback() {
        bail!(
            "a restic REST listener off loopback requires TLS (or bind 127.0.0.1 behind an authenticated tunnel)"
        );
    }
    let server = match &options.tls {
        Some((certificate, private_key)) => tiny_http::Server::https(
            options.bind,
            tiny_http::SslConfig {
                certificate: certificate.clone(),
                private_key: private_key.clone(),
            },
        ),
        None => tiny_http::Server::http(options.bind),
    }
    .map_err(|e| anyhow::anyhow!("cannot listen on {}: {e}", options.bind))?;
    let port = server
        .server_addr()
        .to_ip()
        .map(|a| a.port())
        .context("listener has no IP address")?;
    let scheme = if options.tls.is_some() {
        "https"
    } else {
        "http"
    };
    let host = match options.bind.ip() {
        ip if ip.is_unspecified() || ip.is_loopback() => "localhost".to_owned(),
        std::net::IpAddr::V6(ip) => format!("[{ip}]"),
        ip => ip.to_string(),
    };
    Ok(ResticServer {
        server: Arc::new(server),
        url: format!("{scheme}://{host}:{port}/"),
        port,
        tls: options.tls.is_some(),
    })
}

impl ResticServer {
    /// Serve with `workers` threads until the process ends.
    pub fn serve(&self, repository: Arc<Repository>, workers: usize) {
        let handles: Vec<_> = (0..workers.max(1))
            .map(|_| {
                let server = Arc::clone(&self.server);
                let repository = Arc::clone(&repository);
                std::thread::spawn(move || {
                    for request in server.incoming_requests() {
                        respond(&repository, request);
                    }
                })
            })
            .collect();
        for handle in handles {
            let _ = handle.join();
        }
    }

    /// Stop accepting requests; `serve` returns once workers finish.
    pub fn unblock(&self) {
        self.server.unblock();
    }

    pub fn server(&self) -> Arc<tiny_http::Server> {
        Arc::clone(&self.server)
    }
}

fn header<'a>(request: &'a tiny_http::Request, name: &'static str) -> Option<&'a str> {
    request
        .headers()
        .iter()
        .find(|h| h.field.equiv(name))
        .map(|h| h.value.as_str())
}

/// Translate one tiny_http request: bound the body, then [`Repository::handle`].
pub fn respond(repository: &Repository, mut request: tiny_http::Request) {
    let method = request.method().as_str().to_owned();
    let url = request.url().to_owned();
    let (path, query) = url.split_once('?').unwrap_or((&url, ""));
    let declared = request.body_length().map(|n| n as u64);
    let mut body = Vec::new();
    if declared.is_some_and(|n| n > MAX_UPLOAD_BYTES) {
        let _ = request.respond(tiny_http::Response::empty(413));
        return;
    }
    if method == "POST" {
        match wire::read_bounded(request.as_reader(), MAX_UPLOAD_BYTES) {
            Ok(Some(bytes)) => body = bytes,
            Ok(None) => {
                let _ = request.respond(tiny_http::Response::empty(413));
                return;
            }
            Err(_) => {
                let _ = request.respond(tiny_http::Response::empty(400));
                return;
            }
        }
    }
    let reply = repository.handle(&Request {
        method: &method,
        path,
        query,
        authorization: header(&request, "Authorization"),
        accept: header(&request, "Accept"),
        range: header(&request, "Range"),
        body: &body,
    });
    let headers: Vec<tiny_http::Header> = reply
        .headers
        .iter()
        .filter_map(|(name, value)| {
            tiny_http::Header::from_bytes(name.as_bytes(), value.as_bytes()).ok()
        })
        .collect();
    let length = reply
        .head_length
        .map(|n| n as usize)
        .unwrap_or(reply.body.len());
    let response = tiny_http::Response::new(
        tiny_http::StatusCode(reply.status),
        headers,
        std::io::Cursor::new(reply.body),
        Some(length),
        None,
    );
    let _ = request.respond(response);
}
