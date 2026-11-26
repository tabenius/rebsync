//! Local transports for `rbq-peer/1`.
//!
//! The layer sync logic in [`crate::peer`] only needs a handful of operations:
//! status, list, get and create-if-absent put. `rbq-peer/0` carries those
//! over plain HTTP for the Rebeqah app. This module carries the same operations
//! over raw, length-prefixed frames and adds three local transports:
//!
//! * TCP (`tcp://HOST:PORT`), still token-protected but unencrypted;
//! * Unix stream sockets (`unix:///path`), for same-host or forwarded links;
//! * Unix datagram sockets (`unix-dgram:///path`), for a local bridge that
//!   cannot hold a stream open (for example an OSHI/Indra relay adapter).
//!
//! Datagrams are chunked and reassembled with explicit bounds. Everything is
//! additive: `put` is create-if-absent, there is no overwrite and no delete.
//! The server re-validates tokens, keys, sizes and chunk digests; a malformed
//! or hostile peer can waste bounded work but cannot write arbitrary objects.
//!
//! This is a transport contract, not an OSHI mesh integration. A bridge that
//! wants to carry rbq traffic must expose a Unix stream or datagram socket
//! speaking `rbq-peer/1`; rbq itself never talks to OSHI relays.

use crate::{
    journal::Journal,
    layer,
    peer::{self, PeerApi},
    storage::{ObjectKey, ObjectStorage, PutOutcome, StorageError, validate_prefix},
};
use anyhow::{Context, Result, bail, ensure};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};
#[cfg(unix)]
use std::os::unix::fs::FileTypeExt;
use std::{
    collections::BTreeMap,
    fs,
    io::{Read, Write},
    net::{Shutdown, TcpListener, TcpStream, ToSocketAddrs},
    path::{Path, PathBuf},
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, AtomicUsize, Ordering},
    },
    thread,
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

pub const PROTOCOL: &str = "rbq-peer/1";

#[cfg(feature = "peer-quic")]
pub mod pairing;
#[cfg(feature = "peer-quic")]
pub mod quic;
pub mod staging;
/// Metadata frames (a request/response envelope) are bounded independently
/// from object bodies. A 10 000-key listing with long keys needs a few MiB.
const MAX_CONTROL: usize = 8 * 1024 * 1024;
/// Largest object body, matching `rbq-peer/0` and Mneme chunks.
pub const MAX_OBJECT: u64 = 64 * 1024 * 1024;
const MAX_LIST: usize = 10_000;
const PAGE: usize = 5000;
/// Most objects a client accepts from one peer listing (as `rbq-peer/0`).
const MAX_INVENTORY: usize = 100_000;
/// A request envelope carries a token, an op and at most a key, prefix and
/// cursor. Servers read requests with this bound, so an unauthenticated peer
/// cannot make the server allocate the 8 MiB a response frame may need.
const MAX_REQUEST: usize = 64 * 1024;
const MAX_CONNECTIONS: usize = 8;
const IO_TIMEOUT: Duration = Duration::from_secs(120);
/// Total time a new connection has to deliver its first authenticated
/// request. Without it eight silent peers hold every slot for `IO_TIMEOUT`.
const AUTH_DEADLINE: Duration = Duration::from_secs(5);
const ACCEPT_POLL: Duration = Duration::from_millis(50);

// Datagram wire format: "RBQ1" | kind:u8 | id:u32 | seq:u32 | total:u32 | payload
const DATAGRAM_MAGIC: &[u8; 4] = b"RBQ1";
const DATAGRAM_HEADER: usize = 17;
const KIND_CONTROL: u8 = 0;
const KIND_CHUNK: u8 = 1;
/// Datagram payload size. 64 KiB is the usual platform limit; 32 KiB leaves
/// room for headers and keeps reassembly memory easy to reason about.
pub const CHUNK: usize = 32 * 1024;
const MAX_DATAGRAM: usize = 60 * 1024;
const DATAGRAM_PAGE: usize = 32;
const MAX_ASSEMBLIES: usize = 16;
/// Bytes all unfinished datagram uploads may reserve together. Sixteen
/// 64 MiB uploads would otherwise pin a gigabyte.
const ASSEMBLY_BUDGET: usize = 128 * 1024 * 1024;
const ASSEMBLY_TTL: Duration = Duration::from_secs(60);
const DATAGRAM_TIMEOUT: Duration = Duration::from_secs(30);
/// A reply that cannot be queued within this is dropped. Without a bound the
/// single serving thread blocks forever on a client that never reads, and
/// `Server::stop` cannot complete.
const DATAGRAM_SEND_TIMEOUT: Duration = Duration::from_millis(250);
const MAX_BODY_CHUNKS: u32 = (MAX_OBJECT as usize).div_ceil(CHUNK) as u32;

/// A parsed connection target. Tokens are carried separately so they never end
/// up in a display string, a journal subject or an error message.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Target {
    Tcp {
        host: String,
        port: u16,
    },
    /// `quic://HOST:PORT`: TLS 1.3 over UDP. A client must pin the server's
    /// key (`peer`, the hex SHA-256 of its public key, printed by
    /// `rbq peer serve`); a listener leaves it empty.
    #[cfg(feature = "peer-quic")]
    Quic {
        host: String,
        port: u16,
        peer: Option<String>,
    },
    #[cfg(unix)]
    Unix {
        path: PathBuf,
    },
    #[cfg(unix)]
    UnixDatagram {
        path: PathBuf,
    },
}

impl Target {
    pub fn parse(raw: &str) -> Result<Self> {
        let raw = raw.trim();
        ensure!(!raw.is_empty(), "connection target is empty");
        let (scheme, rest) = raw
            .split_once("://")
            .with_context(|| format!("connection target must be SCHEME://..., got {raw:?}"))?;
        match scheme {
            "tcp" => {
                let (host, port) = host_port(scheme, rest)?;
                Ok(Self::Tcp { host, port })
            }
            #[cfg(feature = "peer-quic")]
            "quic" => {
                let (host, port) = host_port(scheme, rest)?;
                Ok(Self::Quic {
                    host,
                    port,
                    peer: None,
                })
            }
            "unix" => unix_path(rest, false),
            "unix-dgram" | "unix+datagram" => unix_path(rest, true),
            "http" | "https" => {
                bail!("{scheme} targets use rbq-peer/0; keep using them with the HTTP peer client")
            }
            other => bail!("unsupported transport {other:?}; use tcp, quic, unix or unix-dgram"),
        }
    }

    pub fn describe(&self) -> String {
        let authority = |host: &str, port: u16| {
            if host.contains(':') {
                format!("[{host}]:{port}")
            } else {
                format!("{host}:{port}")
            }
        };
        match self {
            Self::Tcp { host, port } => format!("tcp://{}", authority(host, *port)),
            #[cfg(feature = "peer-quic")]
            Self::Quic { host, port, .. } => format!("quic://{}", authority(host, *port)),
            #[cfg(unix)]
            Self::Unix { path } => format!("unix://{}", path.display()),
            #[cfg(unix)]
            Self::UnixDatagram { path } => format!("unix-dgram://{}", path.display()),
        }
    }

    /// TCP listeners on a non-loopback address expose plaintext traffic to the
    /// local network. Callers should warn instead of silently pretending this
    /// is private. QUIC is encrypted, so it is never reported as exposed.
    /// Only a loopback address is private. The unspecified addresses
    /// (`0.0.0.0`, `::`) bind every interface and are the most exposed of all.
    pub fn is_public(&self) -> bool {
        match self {
            Self::Tcp { host, .. } => {
                let host = host.trim_start_matches('[').trim_end_matches(']');
                if host.eq_ignore_ascii_case("localhost") {
                    return false;
                }
                match host.parse::<std::net::IpAddr>() {
                    Ok(ip) => !ip.is_loopback(),
                    // A name may resolve anywhere; warn rather than assume.
                    Err(_) => true,
                }
            }
            #[cfg(feature = "peer-quic")]
            Self::Quic { .. } => false,
            #[cfg(unix)]
            _ => false,
        }
    }
}

/// `HOST:PORT` (IPv6 in brackets) for the network schemes.
fn host_port(scheme: &str, rest: &str) -> Result<(String, u16)> {
    let authority = rest.trim_end_matches('/');
    ensure!(!authority.is_empty(), "{scheme} target needs HOST:PORT");
    ensure!(
        !authority.contains('/') && !authority.contains('@'),
        "{scheme} target must be HOST:PORT"
    );
    let (host, port) = authority
        .rsplit_once(':')
        .with_context(|| format!("{scheme} target must be HOST:PORT"))?;
    ensure!(!host.is_empty(), "{scheme} host is empty");
    let port: u16 = port
        .parse()
        .with_context(|| format!("invalid {scheme} port"))?;
    Ok((
        host.trim_start_matches('[')
            .trim_end_matches(']')
            .to_owned(),
        port,
    ))
}

#[cfg(unix)]
fn unix_path(rest: &str, datagram: bool) -> Result<Target> {
    ensure!(!rest.is_empty(), "unix target needs an absolute path");
    let path = PathBuf::from(rest);
    ensure!(path.is_absolute(), "unix socket path must be absolute");
    ensure!(
        path.to_str().is_some_and(|p| !p.contains('\0')),
        "invalid unix socket path"
    );
    Ok(if datagram {
        Target::UnixDatagram { path }
    } else {
        Target::Unix { path }
    })
}

/// Parse `rbq+tcp://HOST:PORT?token=T`, `unix:///path?token=T` or
/// `unix-dgram:///path?token=T`, with the token optionally supplied separately.
pub fn parse_connection(connection: &str, token: Option<&str>) -> Result<(Target, String)> {
    let (target, token) = parse_target(connection, token)?;
    let token = token.context("no token: pass --token-file or include ?token=...")?;
    Ok((target, token))
}

/// Like [`parse_connection`], but the token is optional: a QUIC connection
/// from a paired device authenticates with its key instead.
pub fn parse_target(connection: &str, token: Option<&str>) -> Result<(Target, Option<String>)> {
    let raw = connection.trim();
    let raw = raw.strip_prefix("rbq+").unwrap_or(raw);
    let (location, query) = raw.split_once('?').unwrap_or((raw, ""));
    let from_query = query
        .split('&')
        .find_map(|pair| pair.strip_prefix("token="))
        .map(str::to_owned);
    let token = token.map(str::to_owned).or(from_query);
    if let Some(token) = &token {
        validate_token(token)?;
    }
    #[allow(unused_mut)]
    let mut target = Target::parse(location)?;
    #[cfg(feature = "peer-quic")]
    if let Target::Quic { peer, .. } = &mut target {
        let pin = query
            .split('&')
            .find_map(|pair| pair.strip_prefix("peer="))
            .context(
                "quic connections must pin the server: add &peer=<id printed by rbq peer serve>",
            )?;
        quic::validate_peer_id(pin)?;
        *peer = Some(pin.to_ascii_lowercase());
    }
    Ok((target, token))
}

pub fn validate_token(token: &str) -> Result<()> {
    ensure!(
        !token.is_empty() && token.len() <= 256 && token.bytes().all(|b| b.is_ascii_alphanumeric()),
        "token must be 1..256 ASCII letters or digits"
    );
    Ok(())
}

/// Read a token without accepting a group- or world-readable file.
pub fn read_token_file(path: &Path) -> Result<String> {
    let metadata =
        fs::metadata(path).with_context(|| format!("read token file {}", path.display()))?;
    crate::wire::ensure_private_file(path, &metadata)?;
    let token = fs::read_to_string(path)?.trim().to_owned();
    validate_token(&token)?;
    Ok(token)
}

/// Compare fixed-length SHA-256 digests in constant time, so neither the
/// position of the first wrong byte nor the token's length shows in timing.
fn same(a: &str, b: &str) -> bool {
    let (a, b) = (Sha256::digest(a.as_bytes()), Sha256::digest(b.as_bytes()));
    a.iter()
        .zip(b.iter())
        .fold(0_u8, |acc, (x, y)| acc | (x ^ y))
        == 0
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "op", rename_all = "snake_case")]
pub enum Request {
    Status,
    List {
        prefix: String,
        #[serde(default)]
        after: String,
        #[serde(default = "default_limit")]
        limit: usize,
    },
    Get {
        key: String,
    },
    /// Up to `length` bytes of an object from `offset`. The reply's `total`
    /// is the object's size, so a client can fetch a large object in
    /// windows and resume after a broken link.
    GetRange {
        key: String,
        offset: u64,
        length: u64,
    },
    Put {
        key: String,
        size: u64,
    },
    /// Begin or resume a staged upload of `size` bytes. Replies `staged`
    /// with the bytes already received (resume from there), or `stored` if
    /// the object already exists.
    PutStart {
        key: String,
        size: u64,
    },
    /// Append `length` bytes (the body that follows) at `offset`.
    PutPart {
        key: String,
        offset: u64,
        length: u64,
    },
    /// Verify the staged upload and create the object if absent.
    PutCommit {
        key: String,
        size: u64,
    },
    /// The SHA-256 of the stored object, computed by the server, so a copy
    /// both sides hold is verified without transferring it.
    Hash {
        key: String,
    },
    /// Redeem a one-time pairing secret (QUIC only): `card` is the client's
    /// self-signed card, whose key must be the one the TLS handshake proved.
    Pair {
        secret: String,
        card: Value,
    },
}

fn default_limit() -> usize {
    PAGE
}

/// A short, token-free description of a request for client lists.
fn describe_request(request: &Request) -> String {
    let short = |text: &str| text.chars().take(120).collect::<String>();
    match request {
        Request::Status => "status".into(),
        Request::List { prefix, .. } => format!("list {}", short(prefix)),
        Request::Get { key } => format!("get {}", short(key)),
        Request::GetRange {
            key,
            offset,
            length,
        } => format!("get {} [{offset}+{length}]", short(key)),
        Request::Put { key, size } => format!("put {} ({size} bytes)", short(key)),
        Request::PutStart { key, size } => format!("put {} ({size} bytes, staged)", short(key)),
        Request::PutPart {
            key,
            offset,
            length,
        } => format!("put {} [{offset}+{length}]", short(key)),
        Request::PutCommit { key, .. } => format!("put {} (commit)", short(key)),
        Request::Hash { key } => format!("hash {}", short(key)),
        Request::Pair { .. } => "pair (one-time secret)".into(),
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Item {
    pub key: String,
    pub size: u64,
}

#[derive(Clone, Debug, Serialize, Deserialize, Default)]
pub struct Capabilities {
    pub atomic_create_if_absent: bool,
    pub owner_only_permissions: bool,
    pub range_reads: bool,
    pub max_key_bytes: usize,
    pub max_object_bytes: u64,
    pub datagram_chunk_bytes: u64,
    /// The server answers `get_range` (absent from older servers).
    #[serde(default)]
    pub ranged_get: bool,
    /// The server accepts staged, resumable uploads.
    #[serde(default)]
    pub staged_put: bool,
    /// The server answers `hash`.
    #[serde(default)]
    pub hashes: bool,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Status {
    pub protocol: String,
    pub version: String,
    pub writes_paused: bool,
    pub capabilities: Capabilities,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(tag = "result", rename_all = "snake_case")]
pub enum Response {
    Status(Status),
    Listing {
        items: Vec<Item>,
        truncated: bool,
        next: Option<String>,
    },
    Object {
        /// Bytes in the body that follows.
        size: u64,
        /// For a range: the whole object's size.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        total: Option<u64>,
    },
    Stored {
        created: bool,
        size: u64,
    },
    /// Bytes of a staged upload received so far.
    Staged {
        offset: u64,
    },
    /// The stored object's SHA-256 (lowercase hex) and size.
    Hash {
        sha256: String,
        size: u64,
    },
    /// A redeemed pairing: the server's self-signed card.
    Paired {
        card: Value,
    },
    Error {
        code: u16,
        message: String,
    },
}

#[derive(Serialize, Deserialize)]
struct RequestEnvelope {
    schema: String,
    token: String,
    #[serde(flatten)]
    request: Request,
}

#[derive(Serialize, Deserialize)]
struct ResponseEnvelope {
    schema: String,
    #[serde(flatten)]
    response: Response,
}

/// The peer answered with an error (a "no", as opposed to a broken link):
/// retrying the same request will not help.
#[derive(Debug, Clone)]
pub struct PeerError {
    pub code: u16,
    pub message: String,
}

impl std::fmt::Display for PeerError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "peer error {}: {}", self.code, self.message)
    }
}

impl std::error::Error for PeerError {}

/// Largest part of a staged upload; a server holds one part in memory.
pub const MAX_PART: u64 = 8 * 1024 * 1024;

/// How many body bytes follow a request, if any. Servers read exactly this.
pub(crate) fn body_length(request: &Request) -> Option<u64> {
    match request {
        Request::Put { size, .. } => Some(*size),
        Request::PutPart { length, .. } => Some(*length),
        _ => None,
    }
}

/// The largest body a request may announce.
pub(crate) fn body_limit(request: &Request) -> u64 {
    match request {
        Request::PutPart { .. } => MAX_PART,
        _ => MAX_OBJECT,
    }
}

/// Largest range one `get_range` reply carries.
const MAX_RANGE: u64 = 16 * 1024 * 1024;
/// Window a server reads from storage while it writes an object body, so a
/// 64 MiB object never needs 64 MiB of server memory.
const STREAM_WINDOW: u64 = 1024 * 1024;
/// Window a client fetches large objects in; a broken link loses at most
/// this much.
const CLIENT_WINDOW: u64 = 4 * 1024 * 1024;
/// Attempts per window before a download gives up.
const WINDOW_ATTEMPTS: usize = 4;

/// An object body a server sends: in memory, or read from storage window by
/// window as it is written.
pub(crate) enum Body {
    Bytes(Vec<u8>),
    Stored {
        key: ObjectKey,
        offset: u64,
        length: u64,
    },
}

impl Body {
    pub(crate) fn len(&self) -> u64 {
        match self {
            Self::Bytes(bytes) => bytes.len() as u64,
            Self::Stored { length, .. } => *length,
        }
    }

    /// The whole body in memory (for transports that cannot stream).
    pub(crate) fn materialize(self, storage: &dyn ObjectStorage) -> Result<Vec<u8>> {
        match self {
            Self::Bytes(bytes) => Ok(bytes),
            Self::Stored {
                key,
                offset,
                length,
            } => Ok(storage.get_range(&key, offset..offset + length)?),
        }
    }

    /// Call `write` with consecutive pieces of at most [`STREAM_WINDOW`].
    pub(crate) fn for_each_window(
        &self,
        storage: &dyn ObjectStorage,
        mut write: impl FnMut(&[u8]) -> Result<()>,
    ) -> Result<()> {
        match self {
            Self::Bytes(bytes) => write(bytes),
            Self::Stored {
                key,
                offset,
                length,
            } => {
                let end = offset + length;
                let mut at = *offset;
                while at < end {
                    let next = (at + STREAM_WINDOW).min(end);
                    let window = storage.get_range(key, at..next)?;
                    ensure!(
                        window.len() as u64 == next - at,
                        "object changed size while it was read"
                    );
                    write(&window)?;
                    at = next;
                }
                Ok(())
            }
        }
    }
}

fn error_response(code: u16, message: impl Into<String>) -> Response {
    Response::Error {
        code,
        message: message.into(),
    }
}

fn storage_response(error: &StorageError) -> Response {
    let code = match error {
        StorageError::InvalidKey(_) => 400,
        StorageError::NotFound(_) => 404,
        StorageError::AlreadyExists(_) => 409,
        StorageError::PermissionDenied(_) => 403,
        StorageError::Unavailable(_) => 503,
        StorageError::Unsupported(_) => 501,
        StorageError::Corrupt(_) | StorageError::Backend(_) => 500,
    };
    error_response(code, error.to_string())
}

/// One request a server answered, as reported to an [`Observer`].
#[derive(Clone, Debug)]
pub struct RequestRecord<'a> {
    /// The peer's address without a port (an IP, or the transport name for
    /// local sockets), so one machine is one client across connections.
    pub peer: &'a str,
    /// `quic`, `tcp` or `unix`.
    pub transport: &'static str,
    /// What was asked, e.g. `get mneme/v1/chunks/...`. Never the token.
    pub request: String,
    /// The request carried the right token.
    pub authorized: bool,
    /// The request was refused for a wrong token.
    pub rejected: bool,
    pub bytes_in: u64,
    pub bytes_out: u64,
}

/// Watches a [`Service`]'s traffic, e.g. to list connected clients, and may
/// turn peers away (throttling repeated failures). Calls are made on serving
/// threads and must not block.
pub trait Observer: Send + Sync {
    /// Called after each answered request.
    fn request(&self, record: &RequestRecord<'_>);
    /// Whether to serve a new connection from `peer` at all.
    fn admit(&self, _peer: &str) -> bool {
        true
    }
}

/// A token-protected view of one object store. Cloneable so each connection and
/// datagram worker can hold it.
/// What a caller may do. A valid token grants both; a pairing grants what
/// its signed record says.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Scopes {
    pub read: bool,
    pub write: bool,
}

impl Scopes {
    pub const ALL: Self = Self {
        read: true,
        write: true,
    };

    pub fn allows(self, request: &Request) -> bool {
        match request {
            Request::Put { .. }
            | Request::PutStart { .. }
            | Request::PutPart { .. }
            | Request::PutCommit { .. } => self.write,
            Request::Status
            | Request::List { .. }
            | Request::Get { .. }
            | Request::GetRange { .. }
            | Request::Hash { .. } => self.read,
            // Pairing is decided by its secret, never by an existing grant.
            Request::Pair { .. } => false,
        }
    }
}

/// Redeems one-time pairing secrets: records the client's key and returns
/// this server's card (see `pairing`).
pub trait PairingAuthority: Send + Sync {
    fn redeem(&self, secret: &str, client_key: &str, card: &Value) -> Result<Value>;
}

/// Decides which proven peer keys may use a [`Service`] without a token,
/// e.g. the device's store of signed pairings.
pub trait PeerTrust: Send + Sync {
    /// Scopes granted to the peer whose key hashes to `peer_id`, if any.
    fn scopes(&self, peer_id: &str) -> Option<Scopes>;
}

#[derive(Clone)]
pub struct Service {
    storage: Arc<dyn ObjectStorage>,
    /// `None`: no token is accepted; only trusted peer keys get in.
    token: Option<Arc<String>>,
    trust: Option<Arc<dyn PeerTrust>>,
    pairing: Option<Arc<dyn PairingAuthority>>,
    staging: Option<Arc<staging::Staging>>,
    writes_paused: Arc<AtomicBool>,
    listing: Arc<Mutex<Option<CachedListing>>>,
    observer: Option<Arc<dyn Observer>>,
}

/// The full listing behind a paginated `list`. Without it every page re-read
/// the whole prefix: quadratic in the inventory, and with 32-entry datagram
/// pages a 10 000-object layer meant ~300 full storage walks. Objects are
/// immutable and only ever added, so cutting later pages from the listing
/// taken for the first page is a consistent snapshot; anything added
/// meanwhile is picked up by the next sync.
struct CachedListing {
    prefix: String,
    items: Arc<Vec<Item>>,
    at: Instant,
}

/// How long a cached listing serves follow-up pages.
const LISTING_TTL: Duration = Duration::from_secs(30);

impl Service {
    pub fn new(
        storage: Arc<dyn ObjectStorage>,
        token: String,
        writes_paused: Arc<AtomicBool>,
    ) -> Self {
        Self {
            storage,
            token: Some(Arc::new(token)),
            trust: None,
            pairing: None,
            staging: None,
            writes_paused,
            listing: Arc::default(),
            observer: None,
        }
    }

    /// A service no token can open: only peers trusted through
    /// [`Service::with_trust`] (paired keys over QUIC) are served.
    pub fn without_token(storage: Arc<dyn ObjectStorage>, writes_paused: Arc<AtomicBool>) -> Self {
        Self {
            token: None,
            ..Self::new(storage, String::new(), writes_paused)
        }
    }

    /// Let peers whose keys `trust` vouches for in without a token (QUIC).
    pub fn with_trust(mut self, trust: Arc<dyn PeerTrust>) -> Self {
        self.trust = Some(trust);
        self
    }

    /// Accept staged, resumable uploads, staged in `staging`.
    pub fn with_staging(mut self, staging: Arc<staging::Staging>) -> Self {
        self.staging = Some(staging);
        self
    }

    /// Accept one-time pairing secrets (QUIC) through `authority`.
    pub fn with_pairing(mut self, authority: Arc<dyn PairingAuthority>) -> Self {
        self.pairing = Some(authority);
        self
    }

    /// Redeem a pairing secret for the proven `client_key`.
    pub fn redeem(&self, secret: &str, client_key: &str, card: &Value) -> Result<Value> {
        self.pairing
            .as_ref()
            .context("this server does not accept pairing")?
            .redeem(secret, client_key, card)
    }

    /// Scopes a proven peer key is granted, if any.
    pub fn trusted(&self, peer_id: &str) -> Option<Scopes> {
        self.trust.as_ref().and_then(|trust| trust.scopes(peer_id))
    }

    /// Report every answered request to `observer` (QUIC, TCP and Unix
    /// stream servers).
    pub fn with_observer(mut self, observer: Arc<dyn Observer>) -> Self {
        self.observer = Some(observer);
        self
    }

    fn admit(&self, peer: &str) -> bool {
        self.observer
            .as_ref()
            .is_none_or(|observer| observer.admit(peer))
    }

    #[allow(clippy::too_many_arguments)]
    fn observe(
        &self,
        peer: &str,
        transport: &'static str,
        request: Option<&Request>,
        authorized: bool,
        rejected: bool,
        bytes_in: u64,
        bytes_out: u64,
    ) {
        if let Some(observer) = &self.observer {
            observer.request(&RequestRecord {
                peer,
                transport,
                request: request.map_or_else(|| "malformed".into(), describe_request),
                authorized,
                rejected,
                bytes_in,
                bytes_out,
            });
        }
    }

    /// Every item under `prefix`, sorted by key. A first page (`after` empty)
    /// always reads storage; follow-up pages reuse a fresh enough listing.
    fn listing(&self, prefix: &str, first_page: bool) -> Result<Arc<Vec<Item>>, StorageError> {
        if !first_page
            && let Ok(cache) = self.listing.lock()
            && let Some(cached) = cache.as_ref()
            && cached.prefix == prefix
            && cached.at.elapsed() < LISTING_TTL
        {
            return Ok(cached.items.clone());
        }
        let mut items: Vec<Item> = self
            .storage
            .list_prefix(prefix, 0)?
            .into_iter()
            .map(|item| Item {
                key: item.key,
                size: item.size,
            })
            .collect();
        items.sort_by(|a, b| a.key.cmp(&b.key));
        let items = Arc::new(items);
        if let Ok(mut cache) = self.listing.lock() {
            *cache = Some(CachedListing {
                prefix: prefix.to_owned(),
                items: items.clone(),
                at: Instant::now(),
            });
        }
        Ok(items)
    }

    pub fn authorize(&self, presented: &str) -> bool {
        self.token
            .as_ref()
            .is_some_and(|token| !presented.is_empty() && same(presented, token))
    }

    fn status(&self) -> Status {
        let caps = self.storage.capabilities();
        Status {
            protocol: PROTOCOL.into(),
            version: env!("CARGO_PKG_VERSION").into(),
            writes_paused: self.writes_paused.load(Ordering::Relaxed),
            capabilities: Capabilities {
                atomic_create_if_absent: caps.atomic_create_if_absent,
                owner_only_permissions: caps.owner_only_permissions,
                range_reads: caps.range_reads,
                max_key_bytes: caps.max_key_bytes,
                max_object_bytes: MAX_OBJECT,
                datagram_chunk_bytes: CHUNK as u64,
                ranged_get: true,
                staged_put: self.staging.is_some(),
                hashes: true,
            },
        }
    }

    /// Common checks for the staged-upload requests, then `step`.
    fn staged(
        &self,
        key: &str,
        size: u64,
        step: impl FnOnce(&staging::Staging) -> Result<Response, staging::Refusal>,
    ) -> (Response, Option<Body>) {
        let Some(staging) = &self.staging else {
            return (
                error_response(501, "this server does not stage uploads"),
                None,
            );
        };
        if self.writes_paused.load(Ordering::Relaxed) {
            return (
                error_response(503, "data is being moved; retry later"),
                None,
            );
        }
        if size > MAX_OBJECT {
            return (error_response(413, "object exceeds 64 MiB"), None);
        }
        if let Err(error) = peer::admissible_key(key) {
            return (error_response(400, format!("{error:#}")), None);
        }
        match step(staging) {
            Ok(response) => (response, None),
            Err(refusal) => (error_response(refusal.code, refusal.message), None),
        }
    }

    /// `length` bytes of `key` from `offset` (clamped to the object), and the
    /// object's size. Where storage reads ranges, the body is read window by
    /// window while it is sent instead of being loaded whole.
    fn object(&self, key: &str, offset: u64, length: u64) -> Result<(Body, u64), Response> {
        if let Err(error) = peer::admissible_key(key) {
            return Err(error_response(400, format!("{error:#}")));
        }
        let key = ObjectKey::parse(key).map_err(|error| storage_response(&error))?;
        if self.storage.capabilities().range_reads {
            let total = self
                .storage
                .head(&key)
                .map_err(|error| storage_response(&error))?
                .size;
            if offset > total {
                return Err(error_response(
                    416,
                    "range starts past the end of the object",
                ));
            }
            let length = length.min(total - offset);
            return Ok((
                Body::Stored {
                    key,
                    offset,
                    length,
                },
                total,
            ));
        }
        let bytes = self
            .storage
            .get(&key)
            .map_err(|error| storage_response(&error))?;
        let total = bytes.len() as u64;
        if offset > total {
            return Err(error_response(
                416,
                "range starts past the end of the object",
            ));
        }
        let end = offset + length.min(total - offset);
        Ok((
            Body::Bytes(bytes[offset as usize..end as usize].to_vec()),
            total,
        ))
    }

    pub(crate) fn storage(&self) -> &dyn ObjectStorage {
        self.storage.as_ref()
    }

    /// Handle one validated request. Returns an optional body for `get`.
    fn handle(&self, request: &Request, body: Option<&[u8]>) -> (Response, Option<Body>) {
        match request {
            Request::Pair { .. } => (
                error_response(400, "pairing is only offered over quic://"),
                None,
            ),
            Request::Status => (Response::Status(self.status()), None),
            Request::List {
                prefix,
                after,
                limit,
            } => {
                if let Err(error) = validate_prefix(prefix) {
                    return (error_response(400, error.to_string()), None);
                }
                let limit = (*limit).clamp(1, MAX_LIST);
                match self.listing(prefix, after.is_empty()) {
                    Ok(items) => {
                        // Sorted, so the page starts after a binary search.
                        let start =
                            items.partition_point(|item| item.key.as_str() <= after.as_str());
                        let rest = &items[start..];
                        let truncated = rest.len() > limit;
                        let page: Vec<Item> = rest[..rest.len().min(limit)].to_vec();
                        let next = if truncated {
                            page.last().map(|item| item.key.clone())
                        } else {
                            None
                        };
                        (
                            Response::Listing {
                                items: page,
                                truncated,
                                next,
                            },
                            None,
                        )
                    }
                    Err(error) => (storage_response(&error), None),
                }
            }
            Request::Get { key } => match self.object(key, 0, u64::MAX) {
                Ok((body, _)) => (
                    Response::Object {
                        size: body.len(),
                        total: None,
                    },
                    Some(body),
                ),
                Err(response) => (response, None),
            },
            Request::Hash { key } => match self.object(key, 0, u64::MAX) {
                Ok((body, size)) => {
                    let mut hasher = Sha256::new();
                    match body.for_each_window(self.storage.as_ref(), |window| {
                        hasher.update(window);
                        Ok(())
                    }) {
                        Ok(()) => (
                            Response::Hash {
                                sha256: format!("{:x}", hasher.finalize()),
                                size,
                            },
                            None,
                        ),
                        Err(error) => (error_response(500, format!("{error:#}")), None),
                    }
                }
                Err(response) => (response, None),
            },
            Request::GetRange {
                key,
                offset,
                length,
            } => match self.object(key, *offset, (*length).min(MAX_RANGE)) {
                Ok((body, total)) => (
                    Response::Object {
                        size: body.len(),
                        total: Some(total),
                    },
                    Some(body),
                ),
                Err(response) => (response, None),
            },
            Request::PutStart { key, size } => self.staged(key, *size, |staging| {
                if let Ok(object) = ObjectKey::parse(key)
                    && let Ok(meta) = self.storage.head(&object)
                {
                    return Ok(Response::Stored {
                        created: false,
                        size: meta.size,
                    });
                }
                Ok(Response::Staged {
                    offset: staging.start(key, *size)?,
                })
            }),
            Request::PutPart {
                key,
                offset,
                length,
            } => self.staged(key, 0, |staging| {
                let body = body.unwrap_or_default();
                if body.len() as u64 != *length || *length > MAX_PART {
                    return Err(staging::Refusal {
                        code: 400,
                        message: "part length does not match".into(),
                    });
                }
                Ok(Response::Staged {
                    offset: staging.append(key, *offset, body)?,
                })
            }),
            Request::PutCommit { key, size } => self.staged(key, *size, |staging| {
                Ok(match staging.commit(key, *size, self.storage.as_ref())? {
                    PutOutcome::Created(meta) => Response::Stored {
                        created: true,
                        size: meta.size,
                    },
                    PutOutcome::AlreadyExists(meta) => Response::Stored {
                        created: false,
                        size: meta.size,
                    },
                })
            }),
            Request::Put { key, size } => {
                let Some(body) = body else {
                    return (error_response(400, "put without a body"), None);
                };
                if *size > MAX_OBJECT {
                    return (error_response(413, "object exceeds 64 MiB"), None);
                }
                if body.len() as u64 != *size {
                    return (error_response(400, "body length does not match size"), None);
                }
                if self.writes_paused.load(Ordering::Relaxed) {
                    return (
                        error_response(503, "data is being moved; retry later"),
                        None,
                    );
                }
                if let Err(error) = peer::admissible(key, body) {
                    return (error_response(400, format!("{error:#}")), None);
                }
                match ObjectKey::parse(key).and_then(|key| self.storage.put_if_absent(&key, body)) {
                    Ok(PutOutcome::Created(meta)) => (
                        Response::Stored {
                            created: true,
                            size: meta.size,
                        },
                        None,
                    ),
                    Ok(PutOutcome::AlreadyExists(meta)) => (
                        Response::Stored {
                            created: false,
                            size: meta.size,
                        },
                        None,
                    ),
                    Err(error) => (storage_response(&error), None),
                }
            }
        }
    }
}

/// The operations a transport must carry. Each link owns its token so callers
/// can never accidentally send the sync report's token-free description in its
/// place.
pub trait Link: Send {
    fn describe(&self) -> String;
    /// Upper bound the transport can return in one listing page.
    fn list_limit(&self, requested: usize) -> usize;
    fn status(&mut self) -> Result<Status>;
    fn list(&mut self, prefix: &str, after: &str, limit: usize) -> Result<ListingPage>;
    fn get(&mut self, key: &str) -> Result<Vec<u8>>;
    fn put(&mut self, key: &str, bytes: &[u8]) -> Result<bool>;
    /// Up to `length` bytes of `key` from `offset`, and the object's size.
    /// Servers advertise support with `capabilities.ranged_get`.
    fn get_range(&mut self, key: &str, offset: u64, length: u64) -> Result<(Vec<u8>, u64)>;
    /// One request and its reply, for operations without a dedicated method
    /// (staged uploads).
    fn call(&mut self, request: Request, body: Option<&[u8]>) -> Result<Response>;
}

/// Shared by every link: decode a `get_range` exchange.
fn range_reply(reply: (Response, Option<Vec<u8>>), offset: u64) -> Result<(Vec<u8>, u64)> {
    match reply {
        (
            Response::Object {
                size,
                total: Some(total),
            },
            Some(body),
        ) => {
            ensure!(
                body.len() as u64 == size && offset.saturating_add(size) <= total,
                "peer returned an inconsistent range"
            );
            Ok((body, total))
        }
        _ => bail!("peer returned no range"),
    }
}

#[derive(Clone, Debug)]
pub struct ListingPage {
    pub items: Vec<Item>,
    pub truncated: bool,
    pub next: Option<String>,
}

/// Connect to a target with the transport its scheme names.
pub fn connect(target: &Target, token: String) -> Result<Box<dyn Link>> {
    validate_token(&token)?;
    connect_link(target, token)
}

/// Connect over QUIC presenting this device's key. A server that has paired
/// with the key serves it without a token, so `token` may be `None`.
#[cfg(feature = "peer-quic")]
pub fn connect_paired(
    target: &Target,
    token: Option<String>,
    identity: &quic::Identity,
) -> Result<Box<dyn Link>> {
    if let Some(token) = &token {
        validate_token(token)?;
    }
    let Target::Quic { host, port, peer } = target else {
        bail!("paired connections use quic://; other transports need a token");
    };
    let peer = peer
        .as_deref()
        .context("a quic connection needs the server's peer id (&peer=...)")?;
    Ok(Box::new(quic::QuicLink::connect_as(
        host,
        *port,
        peer,
        token.unwrap_or_default(),
        Some(identity),
    )?))
}

fn connect_link(target: &Target, token: String) -> Result<Box<dyn Link>> {
    match target {
        Target::Tcp { host, port } => Ok(Box::new(StreamLink::tcp(host, *port, token)?)),
        #[cfg(feature = "peer-quic")]
        Target::Quic { host, port, peer } => {
            let peer = peer
                .as_deref()
                .context("a quic connection needs the server's peer id (&peer=...)")?;
            Ok(Box::new(quic::QuicLink::connect(host, *port, peer, token)?))
        }
        #[cfg(unix)]
        Target::Unix { path } => Ok(Box::new(StreamLink::unix(path, token)?)),
        #[cfg(unix)]
        Target::UnixDatagram { path } => Ok(Box::new(DatagramLink::connect(path, token)?)),
    }
}

// ---------------------------------------------------------------------------
// Stream framing
// ---------------------------------------------------------------------------

fn write_frame<W: Write>(writer: &mut W, bytes: &[u8], max: usize) -> Result<()> {
    ensure!(
        bytes.len() <= max && bytes.len() <= u32::MAX as usize,
        "frame of {} bytes exceeds the {} byte limit",
        bytes.len(),
        max
    );
    writer.write_all(&(bytes.len() as u32).to_be_bytes())?;
    writer.write_all(bytes)?;
    writer.flush()?;
    Ok(())
}

fn read_frame<R: Read>(reader: &mut R, max: usize) -> Result<Option<Vec<u8>>> {
    let mut header = [0_u8; 4];
    let mut filled = 0;
    while filled < header.len() {
        match reader.read(&mut header[filled..]) {
            Ok(0) if filled == 0 => return Ok(None),
            Ok(0) => bail!("truncated frame header"),
            Ok(n) => filled += n,
            Err(error) if error.kind() == std::io::ErrorKind::Interrupted => {}
            Err(error) => return Err(error.into()),
        }
    }
    let length = u32::from_be_bytes(header) as usize;
    ensure!(
        length <= max,
        "frame of {length} bytes exceeds the {max} byte limit"
    );
    let mut body = vec![0_u8; length];
    reader.read_exact(&mut body)?;
    Ok(Some(body))
}

enum Stream {
    Tcp(TcpStream),
    #[cfg(unix)]
    Unix(std::os::unix::net::UnixStream),
}

impl Stream {
    fn set_timeouts(&self) -> Result<()> {
        match self {
            Self::Tcp(stream) => {
                stream.set_read_timeout(Some(IO_TIMEOUT))?;
                stream.set_write_timeout(Some(IO_TIMEOUT))?;
            }
            #[cfg(unix)]
            Self::Unix(stream) => {
                stream.set_read_timeout(Some(IO_TIMEOUT))?;
                stream.set_write_timeout(Some(IO_TIMEOUT))?;
            }
        }
        Ok(())
    }
}

impl Stream {
    fn set_read_timeout(&self, timeout: Duration) -> std::io::Result<()> {
        match self {
            Self::Tcp(stream) => stream.set_read_timeout(Some(timeout)),
            #[cfg(unix)]
            Self::Unix(stream) => stream.set_read_timeout(Some(timeout)),
        }
    }
}

/// Read one frame that must arrive completely before `deadline`. The socket
/// timeout is shortened before every read, so a peer trickling one byte at a
/// time cannot stretch a per-read timeout into an unbounded hold.
fn read_frame_before(
    stream: &mut Stream,
    max: usize,
    deadline: Instant,
) -> Result<Option<Vec<u8>>> {
    struct Deadline<'a> {
        stream: &'a mut Stream,
        deadline: Instant,
    }
    impl Read for Deadline<'_> {
        fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
            let remaining = self
                .deadline
                .checked_duration_since(Instant::now())
                .filter(|left| !left.is_zero())
                .ok_or_else(|| {
                    std::io::Error::new(std::io::ErrorKind::TimedOut, "request deadline passed")
                })?;
            self.stream.set_read_timeout(remaining)?;
            self.stream.read(buf)
        }
    }
    let frame = read_frame(&mut Deadline { stream, deadline }, max);
    stream.set_read_timeout(IO_TIMEOUT)?;
    frame
}

impl Read for Stream {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        match self {
            Self::Tcp(stream) => stream.read(buf),
            #[cfg(unix)]
            Self::Unix(stream) => stream.read(buf),
        }
    }
}

impl Write for Stream {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        match self {
            Self::Tcp(stream) => stream.write(buf),
            #[cfg(unix)]
            Self::Unix(stream) => stream.write(buf),
        }
    }

    fn flush(&mut self) -> std::io::Result<()> {
        match self {
            Self::Tcp(stream) => stream.flush(),
            #[cfg(unix)]
            Self::Unix(stream) => stream.flush(),
        }
    }
}

pub struct StreamLink {
    stream: Stream,
    token: String,
    description: String,
}

fn connect_tcp(host: &str, port: u16) -> Result<TcpStream> {
    let addresses: Vec<_> = (host, port)
        .to_socket_addrs()
        .with_context(|| format!("resolve {host}:{port}"))?
        .collect();
    ensure!(!addresses.is_empty(), "no address for {host}:{port}");
    let mut last = None;
    for address in addresses {
        match TcpStream::connect_timeout(&address, Duration::from_secs(10)) {
            Ok(stream) => return Ok(stream),
            Err(error) => last = Some(error),
        }
    }
    Err(last
        .map(anyhow::Error::from)
        .unwrap_or_else(|| anyhow::anyhow!("cannot connect to {host}:{port}")))
}

impl StreamLink {
    pub fn tcp(host: &str, port: u16, token: String) -> Result<Self> {
        let stream = connect_tcp(host, port)?;
        stream.set_nodelay(true)?;
        let link = Self {
            stream: Stream::Tcp(stream),
            token,
            description: Target::Tcp {
                host: host.into(),
                port,
            }
            .describe(),
        };
        link.stream.set_timeouts()?;
        Ok(link)
    }

    #[cfg(unix)]
    pub fn unix(path: &Path, token: String) -> Result<Self> {
        let stream = std::os::unix::net::UnixStream::connect(path)
            .with_context(|| format!("connect unix://{}", path.display()))?;
        let link = Self {
            stream: Stream::Unix(stream),
            token,
            description: Target::Unix {
                path: path.to_path_buf(),
            }
            .describe(),
        };
        link.stream.set_timeouts()?;
        Ok(link)
    }

    fn exchange(
        &mut self,
        request: Request,
        body: Option<&[u8]>,
    ) -> Result<(Response, Option<Vec<u8>>)> {
        let envelope = RequestEnvelope {
            schema: PROTOCOL.into(),
            token: self.token.clone(),
            request,
        };
        write_frame(
            &mut self.stream,
            &serde_json::to_vec(&envelope)?,
            MAX_CONTROL,
        )?;
        if let Some(body) = body {
            write_frame(&mut self.stream, body, MAX_OBJECT as usize)?;
        }
        let frame = read_frame(&mut self.stream, MAX_CONTROL)?
            .context("peer closed the connection without a response")?;
        let envelope: ResponseEnvelope =
            serde_json::from_slice(&frame).context("malformed response frame")?;
        ensure!(
            envelope.schema == PROTOCOL,
            "peer speaks {:?}, not {PROTOCOL}",
            envelope.schema
        );
        match envelope.response {
            Response::Object { size, total } => {
                ensure!(size <= MAX_OBJECT, "peer announced an oversized object");
                let body = read_frame(&mut self.stream, size as usize)?
                    .context("peer closed before sending the object body")?;
                ensure!(body.len() as u64 == size, "object body length mismatch");
                Ok((Response::Object { size, total }, Some(body)))
            }
            Response::Error { code, message } => Err(PeerError { code, message }.into()),
            other => Ok((other, None)),
        }
    }
}

impl Link for StreamLink {
    fn describe(&self) -> String {
        self.description.clone()
    }

    fn list_limit(&self, requested: usize) -> usize {
        requested.clamp(1, MAX_LIST)
    }

    fn status(&mut self) -> Result<Status> {
        match self.exchange(Request::Status, None)?.0 {
            Response::Status(status) => Ok(status),
            _ => bail!("peer returned an unexpected status reply"),
        }
    }

    fn list(&mut self, prefix: &str, after: &str, limit: usize) -> Result<ListingPage> {
        match self
            .exchange(
                Request::List {
                    prefix: prefix.into(),
                    after: after.into(),
                    limit,
                },
                None,
            )?
            .0
        {
            Response::Listing {
                items,
                truncated,
                next,
            } => Ok(ListingPage {
                items,
                truncated,
                next,
            }),
            _ => bail!("peer returned an unexpected listing reply"),
        }
    }

    fn get(&mut self, key: &str) -> Result<Vec<u8>> {
        match self.exchange(Request::Get { key: key.into() }, None)? {
            (Response::Object { .. }, Some(body)) => Ok(body),
            _ => bail!("peer returned no object body"),
        }
    }

    fn get_range(&mut self, key: &str, offset: u64, length: u64) -> Result<(Vec<u8>, u64)> {
        let reply = self.exchange(
            Request::GetRange {
                key: key.into(),
                offset,
                length,
            },
            None,
        )?;
        range_reply(reply, offset)
    }

    fn call(&mut self, request: Request, body: Option<&[u8]>) -> Result<Response> {
        Ok(self.exchange(request, body)?.0)
    }

    fn put(&mut self, key: &str, bytes: &[u8]) -> Result<bool> {
        match self
            .exchange(
                Request::Put {
                    key: key.into(),
                    size: bytes.len() as u64,
                },
                Some(bytes),
            )?
            .0
        {
            Response::Stored { created, size } => {
                ensure!(size == bytes.len() as u64, "peer stored a different size");
                Ok(created)
            }
            _ => bail!("peer returned an unexpected put reply"),
        }
    }
}

// ---------------------------------------------------------------------------
// Datagrams
// ---------------------------------------------------------------------------

#[cfg(unix)]
fn datagram(kind: u8, id: u32, seq: u32, total: u32, payload: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(DATAGRAM_HEADER + payload.len());
    out.extend_from_slice(DATAGRAM_MAGIC);
    out.push(kind);
    out.extend_from_slice(&id.to_be_bytes());
    out.extend_from_slice(&seq.to_be_bytes());
    out.extend_from_slice(&total.to_be_bytes());
    out.extend_from_slice(payload);
    out
}

#[cfg(unix)]
fn parse_datagram(bytes: &[u8]) -> Result<(u8, u32, u32, u32, &[u8])> {
    ensure!(bytes.len() >= DATAGRAM_HEADER, "short datagram");
    ensure!(&bytes[..4] == DATAGRAM_MAGIC, "not a rbq datagram");
    let kind = bytes[4];
    ensure!(
        kind == KIND_CONTROL || kind == KIND_CHUNK,
        "unknown datagram kind"
    );
    let id = u32::from_be_bytes(bytes[5..9].try_into().expect("4 bytes"));
    let seq = u32::from_be_bytes(bytes[9..13].try_into().expect("4 bytes"));
    let total = u32::from_be_bytes(bytes[13..17].try_into().expect("4 bytes"));
    Ok((kind, id, seq, total, &bytes[DATAGRAM_HEADER..]))
}

#[cfg(unix)]
pub struct DatagramLink {
    socket: std::os::unix::net::UnixDatagram,
    token: String,
    description: String,
    next_id: u32,
    _dir: tempfile::TempDir,
}

#[cfg(unix)]
impl DatagramLink {
    pub fn connect(path: &Path, token: String) -> Result<Self> {
        let dir = tempfile::tempdir().context("create datagram client directory")?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(dir.path(), fs::Permissions::from_mode(0o700))?;
        }
        let local = dir.path().join("s");
        let socket = std::os::unix::net::UnixDatagram::bind(&local)
            .with_context(|| format!("bind datagram client {}", local.display()))?;
        socket.set_read_timeout(Some(DATAGRAM_TIMEOUT))?;
        socket
            .connect(path)
            .with_context(|| format!("connect unix-dgram://{}", path.display()))?;
        Ok(Self {
            socket,
            token,
            description: Target::UnixDatagram {
                path: path.to_path_buf(),
            }
            .describe(),
            next_id: 1,
            _dir: dir,
        })
    }

    fn send_message(&mut self, request: &Request, body: Option<&[u8]>) -> Result<u32> {
        let envelope = RequestEnvelope {
            schema: PROTOCOL.into(),
            token: self.token.clone(),
            request: request.clone(),
        };
        let json = serde_json::to_vec(&envelope)?;
        ensure!(
            json.len() + DATAGRAM_HEADER <= MAX_DATAGRAM,
            "request envelope exceeds one datagram"
        );
        let id = self.next_id;
        self.next_id = self.next_id.wrapping_add(1).max(1);
        self.socket.send(&datagram(KIND_CONTROL, id, 0, 0, &json))?;
        if let Some(body) = body {
            let total = body.len().div_ceil(CHUNK);
            ensure!(total <= MAX_BODY_CHUNKS as usize, "body too large");
            for (seq, part) in body.chunks(CHUNK).enumerate() {
                self.socket
                    .send(&datagram(KIND_CHUNK, id, seq as u32, total as u32, part))?;
            }
        }
        Ok(id)
    }

    fn receive(&mut self, id: u32) -> Result<(Response, Option<Vec<u8>>)> {
        let mut response = None;
        let mut expected = None;
        let mut body = Vec::new();
        let mut next_seq = 0_u32;
        let mut buffer = vec![0_u8; MAX_DATAGRAM];
        let mut received = 0_usize;
        let mut attempts = 0_usize;
        loop {
            attempts += 1;
            ensure!(
                attempts <= MAX_BODY_CHUNKS as usize + 32,
                "too many datagrams"
            );
            let size = self.socket.recv(&mut buffer)?;
            let (kind, got_id, seq, got_total, payload) = parse_datagram(&buffer[..size])?;
            if got_id != id {
                continue;
            }
            received += size;
            ensure!(
                received <= MAX_OBJECT as usize + MAX_CONTROL + MAX_DATAGRAM,
                "response exceeds the reassembly bound"
            );
            match kind {
                KIND_CONTROL => {
                    ensure!(response.is_none(), "duplicate control datagram");
                    let envelope: ResponseEnvelope =
                        serde_json::from_slice(payload).context("malformed datagram response")?;
                    ensure!(
                        envelope.schema == PROTOCOL,
                        "peer speaks {:?}, not {PROTOCOL}",
                        envelope.schema
                    );
                    match envelope.response {
                        Response::Object {
                            size: announced,
                            total,
                        } => {
                            ensure!(announced <= MAX_OBJECT, "oversized object announcement");
                            expected = Some(announced as usize);
                            response = Some(Response::Object {
                                size: announced,
                                total,
                            });
                        }
                        Response::Error { code, message } => {
                            return Err(PeerError { code, message }.into());
                        }
                        other => return Ok((other, None)),
                    }
                    if expected == Some(0) {
                        return Ok((response.unwrap(), Some(Vec::new())));
                    }
                }
                KIND_CHUNK => {
                    let expected = expected.context("body chunk before control datagram")?;
                    ensure!(seq < got_total, "chunk sequence out of range");
                    ensure!(seq == next_seq, "out-of-order chunk");
                    ensure!(
                        got_total as usize == expected.div_ceil(CHUNK),
                        "wrong chunk count"
                    );
                    ensure!(payload.len() <= CHUNK, "oversized chunk");
                    ensure!(body.len() + payload.len() <= expected, "body overrun");
                    body.extend_from_slice(payload);
                    next_seq += 1;
                    if body.len() == expected {
                        ensure!(next_seq == got_total, "missing chunks");
                        return Ok((response.unwrap(), Some(body)));
                    }
                }
                _ => bail!("unknown datagram kind"),
            }
        }
    }

    fn exchange(
        &mut self,
        request: Request,
        body: Option<&[u8]>,
    ) -> Result<(Response, Option<Vec<u8>>)> {
        let id = self.send_message(&request, body)?;
        self.receive(id)
    }
}

#[cfg(unix)]
impl Link for DatagramLink {
    fn describe(&self) -> String {
        self.description.clone()
    }

    fn list_limit(&self, requested: usize) -> usize {
        requested.clamp(1, DATAGRAM_PAGE)
    }

    fn status(&mut self) -> Result<Status> {
        match self.exchange(Request::Status, None)?.0 {
            Response::Status(status) => Ok(status),
            _ => bail!("peer returned an unexpected status reply"),
        }
    }

    fn list(&mut self, prefix: &str, after: &str, limit: usize) -> Result<ListingPage> {
        match self
            .exchange(
                Request::List {
                    prefix: prefix.into(),
                    after: after.into(),
                    limit: self.list_limit(limit),
                },
                None,
            )?
            .0
        {
            Response::Listing {
                items,
                truncated,
                next,
            } => Ok(ListingPage {
                items,
                truncated,
                next,
            }),
            _ => bail!("peer returned an unexpected listing reply"),
        }
    }

    fn get(&mut self, key: &str) -> Result<Vec<u8>> {
        match self.exchange(Request::Get { key: key.into() }, None)? {
            (Response::Object { .. }, Some(body)) => Ok(body),
            _ => bail!("peer returned no object body"),
        }
    }

    fn get_range(&mut self, key: &str, offset: u64, length: u64) -> Result<(Vec<u8>, u64)> {
        let reply = self.exchange(
            Request::GetRange {
                key: key.into(),
                offset,
                length,
            },
            None,
        )?;
        range_reply(reply, offset)
    }

    fn call(&mut self, request: Request, body: Option<&[u8]>) -> Result<Response> {
        Ok(self.exchange(request, body)?.0)
    }

    fn put(&mut self, key: &str, bytes: &[u8]) -> Result<bool> {
        match self
            .exchange(
                Request::Put {
                    key: key.into(),
                    size: bytes.len() as u64,
                },
                Some(bytes),
            )?
            .0
        {
            Response::Stored { created, size } => {
                ensure!(size == bytes.len() as u64, "peer stored a different size");
                Ok(created)
            }
            _ => bail!("peer returned an unexpected put reply"),
        }
    }
}

// ---------------------------------------------------------------------------
// The peer adapter used by push/pull
// ---------------------------------------------------------------------------

/// Opens a fresh link to the same peer after the old one broke.
type Reconnect = Box<dyn Fn() -> Result<Box<dyn Link>> + Send + Sync>;

pub struct TransportPeer {
    link: Mutex<Box<dyn Link>>,
    description: String,
    reconnect: Option<Reconnect>,
    /// What the server supports (ranged gets, staged uploads), learned once.
    capabilities: std::sync::OnceLock<Capabilities>,
}

impl TransportPeer {
    pub fn connect(target: &Target, token: String) -> Result<Self> {
        let link = connect(target, token.clone())?;
        let target = target.clone();
        Ok(Self::from_link(
            link,
            Some(Box::new(move || connect(&target, token.clone()))),
        ))
    }

    /// Like [`connect`], presenting this device's key over QUIC; see
    /// [`connect_paired`].
    #[cfg(feature = "peer-quic")]
    pub fn connect_paired(
        target: &Target,
        token: Option<String>,
        identity: &quic::Identity,
    ) -> Result<Self> {
        let link = connect_paired(target, token.clone(), identity)?;
        let (target, identity) = (target.clone(), identity.clone());
        Ok(Self::from_link(
            link,
            Some(Box::new(move || {
                connect_paired(&target, token.clone(), &identity)
            })),
        ))
    }

    fn from_link(link: Box<dyn Link>, reconnect: Option<Reconnect>) -> Self {
        let description = link.describe();
        Self {
            link: Mutex::new(link),
            description,
            reconnect,
            capabilities: std::sync::OnceLock::new(),
        }
    }

    /// Run `operation` on the link. A broken link (any failure that is not
    /// the peer's own answer) is replaced by a fresh connection and the
    /// operation retried, a few times with backoff. A [`PeerError`] is the
    /// peer saying no and is never retried.
    fn with_retry<T>(&self, mut operation: impl FnMut(&mut dyn Link) -> Result<T>) -> Result<T> {
        let mut attempt = 0;
        loop {
            let result = operation(self.lock()?.as_mut());
            let error = match result {
                Ok(value) => return Ok(value),
                Err(error) => error,
            };
            attempt += 1;
            let Some(reconnect) = &self.reconnect else {
                return Err(error);
            };
            if error.downcast_ref::<PeerError>().is_some() || attempt >= WINDOW_ATTEMPTS {
                return Err(error);
            }
            thread::sleep(Duration::from_millis(250 << attempt.min(4)));
            // A failed reconnect counts as an attempt; the old link stays.
            if let Ok(link) = reconnect() {
                *self.lock()? = link;
            }
        }
    }

    fn capabilities(&self) -> Result<&Capabilities> {
        if let Some(capabilities) = self.capabilities.get() {
            return Ok(capabilities);
        }
        let capabilities = self.with_retry(|link| link.status())?.capabilities;
        Ok(self.capabilities.get_or_init(|| capabilities))
    }

    fn ranged(&self) -> Result<bool> {
        Ok(self.capabilities()?.ranged_get)
    }

    /// Upload in [`CLIENT_WINDOW`] parts that the server stages on disk. A
    /// broken link is replaced and the upload continues from what the
    /// server already has; nothing is published until the commit verifies.
    fn put_resumable(&self, key: &str, bytes: &[u8]) -> Result<bool> {
        let size = bytes.len() as u64;
        let start = || -> Result<Option<u64>> {
            match self.with_retry(|link| {
                link.call(
                    Request::PutStart {
                        key: key.into(),
                        size,
                    },
                    None,
                )
            })? {
                Response::Staged { offset } if offset <= size => Ok(Some(offset)),
                // Already stored: nothing to send.
                Response::Stored { .. } => Ok(None),
                _ => bail!("peer returned an unexpected upload reply"),
            }
        };
        let Some(mut offset) = start()? else {
            return Ok(false);
        };
        let mut resyncs = 0;
        while offset < size {
            let end = (offset + CLIENT_WINDOW.min(MAX_PART)).min(size);
            let part = &bytes[offset as usize..end as usize];
            let sent = self.with_retry(|link| {
                link.call(
                    Request::PutPart {
                        key: key.into(),
                        offset,
                        length: part.len() as u64,
                    },
                    Some(part),
                )
            });
            match sent {
                Ok(Response::Staged { offset: next }) if next > offset && next <= size => {
                    offset = next;
                }
                Ok(_) => bail!("peer returned an unexpected upload reply"),
                // The server has a different offset (a part landed but its
                // reply was lost, or the staging was reset): ask and resume.
                Err(error)
                    if error
                        .downcast_ref::<PeerError>()
                        .is_some_and(|e| e.code == 409)
                        && resyncs < WINDOW_ATTEMPTS =>
                {
                    resyncs += 1;
                    match start()? {
                        Some(staged) => offset = staged,
                        None => return Ok(false),
                    }
                }
                Err(error) => return Err(error),
            }
        }
        match self.with_retry(|link| {
            link.call(
                Request::PutCommit {
                    key: key.into(),
                    size,
                },
                None,
            )
        }) {
            Ok(Response::Stored {
                created,
                size: stored,
            }) => {
                ensure!(stored == size, "peer stored a different size");
                Ok(created)
            }
            Ok(_) => bail!("peer returned an unexpected commit reply"),
            // A commit that landed but whose reply was lost: the staging is
            // gone and the object exists.
            Err(error)
                if error
                    .downcast_ref::<PeerError>()
                    .is_some_and(|e| e.code == 409) =>
            {
                match start()? {
                    None => Ok(false),
                    Some(_) => Err(error),
                }
            }
            Err(error) => Err(error),
        }
    }

    /// Fetch an object in [`CLIENT_WINDOW`] pieces. If the link breaks
    /// mid-object (routine on a mesh or a mobile link), reconnect and resume
    /// from the bytes already received instead of starting over.
    fn get_resumable(&self, key: &str) -> Result<Vec<u8>> {
        let mut body: Vec<u8> = Vec::new();
        let mut total = None;
        loop {
            let offset = body.len() as u64;
            let (window, whole) =
                self.with_retry(|link| link.get_range(key, offset, CLIENT_WINDOW))?;
            match total {
                None => {
                    ensure!(whole <= MAX_OBJECT, "peer announced an oversized object");
                    total = Some(whole);
                    body.reserve_exact(whole as usize);
                }
                Some(total) => ensure!(total == whole, "object changed size during download"),
            }
            ensure!(
                !window.is_empty() || offset == whole,
                "peer returned an empty range before the end"
            );
            body.extend_from_slice(&window);
            if body.len() as u64 >= whole {
                ensure!(
                    body.len() as u64 == whole,
                    "peer returned more than the object"
                );
                return Ok(body);
            }
        }
    }

    fn lock(&self) -> Result<std::sync::MutexGuard<'_, Box<dyn Link>>> {
        self.link
            .lock()
            .map_err(|_| anyhow::anyhow!("peer link lock poisoned"))
    }
}

impl PeerApi for TransportPeer {
    fn base(&self) -> &str {
        &self.description
    }

    fn status(&self) -> Result<Value> {
        let status = self.with_retry(|link| link.status())?;
        let _ = self.capabilities.set(status.capabilities.clone());
        Ok(serde_json::json!({
            "protocol": status.protocol,
            "version": status.version,
            "writes_paused": status.writes_paused,
            "capabilities": status.capabilities,
        }))
    }

    fn list(&self, prefix: &str) -> Result<BTreeMap<String, u64>> {
        let mut found = BTreeMap::new();
        let mut after = String::new();
        let limit = self.lock()?.list_limit(PAGE);
        for _ in 0..10_000 {
            let page = self.with_retry(|link| link.list(prefix, &after, limit))?;
            // A hostile peer must not be able to grow this map without bound:
            // the same caps the HTTP peer client applies.
            ensure!(
                page.items.len() <= limit,
                "peer exceeded the listing page limit"
            );
            let mut last = after.clone();
            for item in &page.items {
                ensure!(
                    item.key.as_str() > last.as_str(),
                    "peer ignored pagination; refusing a repeated listing"
                );
                peer::admissible_key(&item.key)?;
                ensure!(
                    item.key.starts_with(prefix) && item.size <= MAX_OBJECT,
                    "out-of-scope or oversized listing entry"
                );
                ensure!(
                    found.len() < MAX_INVENTORY,
                    "peer inventory exceeds {MAX_INVENTORY} objects; narrow the layer filter"
                );
                found.insert(item.key.clone(), item.size);
                last.clone_from(&item.key);
            }
            if !page.truncated {
                return Ok(found);
            }
            let next = page
                .next
                .filter(|next| next.as_str() > after.as_str())
                .context("peer truncated a listing without a forward cursor")?;
            after = next;
        }
        bail!("peer listing did not terminate")
    }

    fn get(&self, key: &str) -> Result<Vec<u8>> {
        if self.ranged()? {
            self.get_resumable(key)
        } else {
            self.with_retry(|link| link.get(key))
        }
    }

    fn hash(&self, key: &str) -> Result<Option<String>> {
        if !self.capabilities()?.hashes {
            return Ok(None);
        }
        match self.with_retry(|link| link.call(Request::Hash { key: key.into() }, None))? {
            Response::Hash { sha256, .. }
                if sha256.len() == 64 && sha256.bytes().all(|b| b.is_ascii_hexdigit()) =>
            {
                Ok(Some(sha256.to_ascii_lowercase()))
            }
            _ => bail!("peer returned an unexpected hash reply"),
        }
    }

    /// Create-if-absent, so retrying after a lost reply is safe: a put that
    /// did land reports "already present" and push compares the bytes.
    fn put(&self, key: &str, bytes: &[u8]) -> Result<bool> {
        if bytes.len() as u64 > CLIENT_WINDOW && self.capabilities()?.staged_put {
            self.put_resumable(key, bytes)
        } else {
            self.with_retry(|link| link.put(key, bytes))
        }
    }
}

// ---------------------------------------------------------------------------
// Servers
// ---------------------------------------------------------------------------

pub struct Server {
    stop: Arc<AtomicBool>,
    joins: Vec<thread::JoinHandle<()>>,
    /// Unix socket paths to remove on stop.
    cleanup: Vec<PathBuf>,
    pub target: Target,
}

impl Server {
    pub fn bind(target: &Target, service: Service, replace_stale: bool) -> Result<Self> {
        match target {
            Target::Tcp { host, port } => Self::bind_tcp(host, *port, service),
            #[cfg(feature = "peer-quic")]
            Target::Quic { .. } => {
                bail!("a quic listener needs an identity; use Server::bind_quic")
            }
            #[cfg(unix)]
            Target::Unix { path } => Self::bind_unix(path, service, replace_stale),
            #[cfg(unix)]
            Target::UnixDatagram { path } => Self::bind_datagram(path, service, replace_stale),
        }
    }

    fn bind_tcp(host: &str, port: u16, service: Service) -> Result<Self> {
        let listener = TcpListener::bind((host, port))
            .with_context(|| format!("listen tcp://{host}:{port}"))?;
        let bound = listener
            .local_addr()
            .context("tcp listener has no address")?;
        listener.set_nonblocking(true)?;
        let stop = Arc::new(AtomicBool::new(false));
        let active = Arc::new(AtomicUsize::new(0));
        let join = {
            let stop = stop.clone();
            let active = active.clone();
            thread::spawn(move || {
                while !stop.load(Ordering::Relaxed) {
                    match listener.accept() {
                        Ok((stream, address)) => {
                            if active.fetch_add(1, Ordering::SeqCst) >= MAX_CONNECTIONS {
                                active.fetch_sub(1, Ordering::SeqCst);
                                let _ = stream.shutdown(Shutdown::Both);
                                continue;
                            }
                            let service = service.clone();
                            let stop = stop.clone();
                            let active = active.clone();
                            thread::spawn(move || {
                                let mut stream = Stream::Tcp(stream);
                                let _ = stream.set_timeouts();
                                serve_connection(
                                    &mut stream,
                                    &service,
                                    &stop,
                                    &address.ip().to_string(),
                                    "tcp",
                                );
                                active.fetch_sub(1, Ordering::SeqCst);
                            });
                        }
                        Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                            thread::sleep(ACCEPT_POLL);
                        }
                        Err(_) => break,
                    }
                }
            })
        };
        Ok(Self {
            stop,
            joins: vec![join],
            cleanup: Vec::new(),
            target: Target::Tcp {
                host: bound.ip().to_string(),
                port: bound.port(),
            },
        })
    }

    #[cfg(unix)]
    fn bind_unix(path: &Path, service: Service, replace_stale: bool) -> Result<Self> {
        prepare_socket_path(path, replace_stale)?;
        let listener = std::os::unix::net::UnixListener::bind(path)
            .with_context(|| format!("listen unix://{}", path.display()))?;
        set_socket_permissions(path)?;
        listener.set_nonblocking(true)?;
        let stop = Arc::new(AtomicBool::new(false));
        let active = Arc::new(AtomicUsize::new(0));
        let join = {
            let stop = stop.clone();
            let active = active.clone();
            thread::spawn(move || {
                while !stop.load(Ordering::Relaxed) {
                    match listener.accept() {
                        Ok((stream, _)) => {
                            if active.fetch_add(1, Ordering::SeqCst) >= MAX_CONNECTIONS {
                                active.fetch_sub(1, Ordering::SeqCst);
                                let _ = stream.shutdown(Shutdown::Both);
                                continue;
                            }
                            let service = service.clone();
                            let stop = stop.clone();
                            let active = active.clone();
                            thread::spawn(move || {
                                let mut stream = Stream::Unix(stream);
                                let _ = stream.set_timeouts();
                                serve_connection(&mut stream, &service, &stop, "local", "unix");
                                active.fetch_sub(1, Ordering::SeqCst);
                            });
                        }
                        Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                            thread::sleep(ACCEPT_POLL);
                        }
                        Err(_) => break,
                    }
                }
            })
        };
        Ok(Self {
            stop,
            joins: vec![join],
            cleanup: vec![path.to_path_buf()],
            target: Target::Unix {
                path: path.to_path_buf(),
            },
        })
    }

    #[cfg(unix)]
    fn bind_datagram(path: &Path, service: Service, replace_stale: bool) -> Result<Self> {
        prepare_socket_path(path, replace_stale)?;
        let socket = std::os::unix::net::UnixDatagram::bind(path)
            .with_context(|| format!("listen unix-dgram://{}", path.display()))?;
        set_socket_permissions(path)?;
        socket.set_read_timeout(Some(Duration::from_millis(200)))?;
        // One thread serves every client. A client that stops reading fills
        // its receive queue and would block `send_to` forever; give up on that
        // reply instead. This bounds the thread, not fairness: replies a client
        // has not read are charged to this socket's send buffer, so a same-user
        // process that floods requests and never reads can delay replies to
        // everyone until it reads or exits. The socket is owner-only (0600);
        // use `unix://` where clients must be isolated from each other.
        socket.set_write_timeout(Some(DATAGRAM_SEND_TIMEOUT))?;
        let stop = Arc::new(AtomicBool::new(false));
        let join = {
            let stop = stop.clone();
            thread::spawn(move || serve_datagrams(&socket, &service, &stop))
        };
        Ok(Self {
            stop,
            joins: vec![join],
            cleanup: vec![path.to_path_buf()],
            target: Target::UnixDatagram {
                path: path.to_path_buf(),
            },
        })
    }

    pub fn stop(self) {
        let _ = self.shutdown();
    }

    /// Stop, and report whether every serving thread ended cleanly (none
    /// panicked). `stop` discards this; tests assert on it.
    pub(crate) fn shutdown(mut self) -> bool {
        self.stop.store(true, Ordering::Relaxed);
        let mut clean = true;
        for join in self.joins.drain(..) {
            clean &= join.join().is_ok();
        }
        for path in &self.cleanup {
            if let Ok(metadata) = fs::symlink_metadata(path)
                && metadata.file_type().is_socket()
            {
                let _ = fs::remove_file(path);
            }
        }
        clean
    }
}

#[cfg(unix)]
fn set_socket_permissions(path: &Path) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;
    fs::set_permissions(path, fs::Permissions::from_mode(0o600))
        .with_context(|| format!("restrict socket permissions on {}", path.display()))?;
    Ok(())
}

#[cfg(unix)]
fn prepare_socket_path(path: &Path, replace_stale: bool) -> Result<()> {
    use std::os::unix::fs::FileTypeExt;
    if let Some(parent) = path.parent()
        && !parent.as_os_str().is_empty()
    {
        fs::create_dir_all(parent)
            .with_context(|| format!("create socket directory {}", parent.display()))?;
    }
    match fs::symlink_metadata(path) {
        Ok(metadata) => {
            ensure!(
                metadata.file_type().is_socket(),
                "refusing to replace {}: not a socket",
                path.display()
            );
            ensure!(
                replace_stale,
                "{} already exists; stop the other server or pass --replace-stale",
                path.display()
            );
            fs::remove_file(path)
                .with_context(|| format!("remove stale socket {}", path.display()))?;
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => {
            return Err(error).with_context(|| format!("inspect socket path {}", path.display()));
        }
    }
    Ok(())
}

fn serve_connection(
    stream: &mut Stream,
    service: &Service,
    stop: &AtomicBool,
    peer: &str,
    transport: &'static str,
) {
    if !service.admit(peer) {
        return;
    }
    let mut authenticated = false;
    let connected = Instant::now();
    while !stop.load(Ordering::Relaxed) {
        let frame = if authenticated {
            read_frame(stream, MAX_REQUEST)
        } else {
            read_frame_before(stream, MAX_REQUEST, connected + AUTH_DEADLINE)
        };
        let frame = match frame {
            Ok(Some(frame)) => frame,
            Ok(None) => return,
            Err(_) => return,
        };
        let envelope: RequestEnvelope = match serde_json::from_slice(&frame) {
            Ok(envelope) => envelope,
            Err(error) => {
                let _ = send_response(
                    stream,
                    None,
                    error_response(400, format!("malformed request: {error}")),
                );
                return;
            }
        };
        if envelope.schema != PROTOCOL {
            let _ = send_response(
                stream,
                None,
                error_response(400, format!("expected schema {PROTOCOL}")),
            );
            return;
        }
        if !service.authorize(&envelope.token) {
            let sent =
                send_response(stream, None, error_response(401, "invalid token")).unwrap_or(0);
            service.observe(
                peer,
                transport,
                Some(&envelope.request),
                false,
                true,
                frame.len() as u64,
                sent,
            );
            return;
        }
        authenticated = true;
        let body = match body_length(&envelope.request) {
            Some(size) => {
                if size > body_limit(&envelope.request) {
                    // The client has already written its body frame; the stream
                    // cannot be resynchronised, so answer and close.
                    let _ = send_response(stream, None, error_response(413, "body too large"));
                    return;
                }
                // The declared size bounds the read, not the protocol maximum:
                // a 10-byte put cannot make the server buffer 64 MiB.
                match read_frame(stream, size as usize) {
                    Ok(Some(body)) => Some(body),
                    _ => {
                        let _ = send_response(stream, None, error_response(400, "missing body"));
                        return;
                    }
                }
            }
            None => None,
        };
        let (response, out) = service.handle(&envelope.request, body.as_deref());
        let received = (frame.len() + body.as_ref().map_or(0, Vec::len)) as u64;
        let Ok(sent) = send_body(stream, out.as_ref(), response, service.storage()) else {
            return;
        };
        service.observe(
            peer,
            transport,
            Some(&envelope.request),
            true,
            false,
            received,
            sent,
        );
    }
}

/// Send a response whose body may be read from storage window by window as
/// it is written; returns the bytes written, frame headers included. A
/// storage failure mid-body ends the connection (the client sees a short
/// body), since a frame already announced cannot be taken back.
fn send_body(
    stream: &mut Stream,
    body: Option<&Body>,
    response: Response,
    storage: &dyn ObjectStorage,
) -> Result<u64> {
    let envelope = serde_json::to_vec(&ResponseEnvelope {
        schema: PROTOCOL.into(),
        response,
    })?;
    write_frame(stream, &envelope, MAX_CONTROL)?;
    let mut sent = 4 + envelope.len() as u64;
    if let Some(body) = body {
        let length = body.len();
        ensure!(length <= MAX_OBJECT, "object body exceeds the limit");
        stream.write_all(&(length as u32).to_be_bytes())?;
        body.for_each_window(storage, |window| Ok(stream.write_all(window)?))?;
        stream.flush()?;
        sent += 4 + length;
    }
    Ok(sent)
}

/// Send a response; returns the bytes written, frame headers included.
fn send_response(stream: &mut Stream, body: Option<&[u8]>, response: Response) -> Result<u64> {
    let envelope = ResponseEnvelope {
        schema: PROTOCOL.into(),
        response,
    };
    let json = serde_json::to_vec(&envelope)?;
    write_frame(stream, &json, MAX_CONTROL)?;
    let mut sent = 4 + json.len() as u64;
    if let Some(body) = body {
        write_frame(stream, body, MAX_OBJECT as usize)?;
        sent += 4 + body.len() as u64;
    }
    Ok(sent)
}

#[cfg(unix)]
struct Assembly {
    addr: std::os::unix::net::SocketAddr,
    id: u32,
    request: Request,
    expected: usize,
    total: u32,
    body: Vec<u8>,
    next_seq: u32,
    at: Instant,
}

#[cfg(unix)]
fn serve_datagrams(
    socket: &std::os::unix::net::UnixDatagram,
    service: &Service,
    stop: &AtomicBool,
) {
    let mut assemblies: std::collections::HashMap<PathBuf, Assembly> =
        std::collections::HashMap::new();
    let mut buffer = vec![0_u8; MAX_DATAGRAM];
    while !stop.load(Ordering::Relaxed) {
        let (size, addr) = match socket.recv_from(&mut buffer) {
            Ok(received) => received,
            Err(error)
                if matches!(
                    error.kind(),
                    std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
                ) =>
            {
                purge_assemblies(&mut assemblies);
                continue;
            }
            Err(_) => break,
        };
        // Replies go to the sender's bound path. An unnamed sender cannot get
        // one, and every unnamed address formats alike, so drop those before
        // they can share (and clobber) one reassembly slot.
        let Some(key) = addr.as_pathname().map(Path::to_path_buf) else {
            continue;
        };
        let (kind, id, seq, total, payload) = match parse_datagram(&buffer[..size]) {
            Ok(parsed) => parsed,
            Err(_) => continue,
        };
        purge_assemblies(&mut assemblies);
        match kind {
            KIND_CONTROL => {
                let envelope: RequestEnvelope = match serde_json::from_slice(payload) {
                    Ok(envelope) => envelope,
                    Err(error) => {
                        let _ = send_datagram(
                            socket,
                            &addr,
                            id,
                            error_response(400, format!("malformed request: {error}")),
                            None,
                        );
                        continue;
                    }
                };
                if envelope.schema != PROTOCOL {
                    let _ = send_datagram(
                        socket,
                        &addr,
                        id,
                        error_response(400, format!("expected schema {PROTOCOL}")),
                        None,
                    );
                    continue;
                }
                if !service.authorize(&envelope.token) {
                    let _ = send_datagram(
                        socket,
                        &addr,
                        id,
                        error_response(401, "invalid token"),
                        None,
                    );
                    continue;
                }
                if let Some(size) = body_length(&envelope.request) {
                    if size > body_limit(&envelope.request) {
                        let _ = send_datagram(
                            socket,
                            &addr,
                            id,
                            error_response(413, "body too large"),
                            None,
                        );
                        continue;
                    }
                    let expected = size as usize;
                    if expected == 0 {
                        let (response, out) = service.handle(&envelope.request, Some(&[]));
                        reply_body(socket, &addr, id, service, response, out);
                        continue;
                    }
                    let total = expected.div_ceil(CHUNK) as u32;
                    // An upload replacing this sender's own unfinished one
                    // frees that reservation first.
                    let reserved: usize = assemblies
                        .iter()
                        .filter(|(sender, _)| **sender != key)
                        .map(|(_, assembly)| assembly.expected)
                        .sum();
                    if reserved + expected > ASSEMBLY_BUDGET {
                        let _ = send_datagram(
                            socket,
                            &addr,
                            id,
                            error_response(503, "too many uploads in progress; retry later"),
                            None,
                        );
                        continue;
                    }
                    if assemblies.len() >= MAX_ASSEMBLIES
                        && let Some(oldest) = assemblies
                            .values()
                            .min_by_key(|assembly| assembly.at)
                            .and_then(|assembly| assembly.addr.as_pathname().map(Path::to_path_buf))
                    {
                        assemblies.remove(&oldest);
                    }
                    assemblies.insert(
                        key,
                        Assembly {
                            addr,
                            id,
                            request: envelope.request,
                            expected,
                            total,
                            body: Vec::with_capacity(expected.min(MAX_DATAGRAM)),
                            next_seq: 0,
                            at: Instant::now(),
                        },
                    );
                    continue;
                }
                let (response, out) = service.handle(&envelope.request, None);
                reply_body(socket, &addr, id, service, response, out);
            }
            KIND_CHUNK => {
                let Some(assembly) = assemblies.get_mut(&key) else {
                    continue;
                };
                let reject = if assembly.id != id {
                    Some("chunk for an unknown message")
                } else if total != assembly.total {
                    Some("wrong chunk count")
                } else if seq != assembly.next_seq {
                    Some("out-of-order chunk")
                } else if payload.len() > CHUNK {
                    Some("oversized chunk")
                } else if assembly.body.len() + payload.len() > assembly.expected {
                    Some("body overrun")
                } else if seq >= assembly.total {
                    Some("chunk sequence out of range")
                } else {
                    None
                };
                if let Some(message) = reject {
                    assemblies.remove(&key);
                    let _ = send_datagram(socket, &addr, id, error_response(400, message), None);
                    continue;
                }
                let assembly = assemblies.get_mut(&key).expect("checked above");
                assembly.body.extend_from_slice(payload);
                assembly.next_seq += 1;
                assembly.at = Instant::now();
                if assembly.body.len() == assembly.expected {
                    let assembly = assemblies.remove(&key).expect("checked above");
                    let (response, out) = service.handle(&assembly.request, Some(&assembly.body));
                    reply_body(socket, &addr, id, service, response, out);
                }
            }
            _ => {}
        }
    }
}

#[cfg(unix)]
fn purge_assemblies(assemblies: &mut std::collections::HashMap<PathBuf, Assembly>) {
    let now = Instant::now();
    assemblies.retain(|_, assembly| now.duration_since(assembly.at) < ASSEMBLY_TTL);
}

/// Datagram replies are assembled in memory (a local socket, and a body of at
/// most [`MAX_RANGE`] for ranges or [`MAX_OBJECT`] for whole objects).
#[cfg(unix)]
fn reply_body(
    socket: &std::os::unix::net::UnixDatagram,
    addr: &std::os::unix::net::SocketAddr,
    id: u32,
    service: &Service,
    response: Response,
    body: Option<Body>,
) {
    let (response, body) = match body
        .map(|body| body.materialize(service.storage()))
        .transpose()
    {
        Ok(body) => (response, body),
        Err(error) => (error_response(500, format!("read failed: {error:#}")), None),
    };
    let _ = send_datagram(socket, addr, id, response, body);
}

#[cfg(unix)]
fn send_datagram(
    socket: &std::os::unix::net::UnixDatagram,
    addr: &std::os::unix::net::SocketAddr,
    id: u32,
    response: Response,
    body: Option<Vec<u8>>,
) -> Result<()> {
    let envelope = ResponseEnvelope {
        schema: PROTOCOL.into(),
        response,
    };
    let json = serde_json::to_vec(&envelope)?;
    ensure!(
        json.len() + DATAGRAM_HEADER <= MAX_DATAGRAM,
        "response envelope exceeds one datagram"
    );
    let path = addr
        .as_pathname()
        .context("datagram client has no reply pathname")?;
    socket.send_to(&datagram(KIND_CONTROL, id, 0, 0, &json), path)?;
    if let Some(body) = body {
        let total = body.len().div_ceil(CHUNK);
        ensure!(total <= MAX_BODY_CHUNKS as usize, "response body too large");
        for (seq, part) in body.chunks(CHUNK).enumerate() {
            socket.send_to(
                &datagram(KIND_CHUNK, id, seq as u32, total as u32, part),
                path,
            )?;
        }
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Loopback self-test
// ---------------------------------------------------------------------------

#[derive(Debug, Serialize)]
pub struct TransportCheck {
    pub transport: String,
    pub protocol: String,
    pub pushed: usize,
    pub pulled: usize,
    pub verified: usize,
    pub bytes: u64,
    pub ok: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct SelftestReport {
    pub ok: bool,
    pub note: &'static str,
    pub transports: Vec<TransportCheck>,
}

/// Exercise every local transport against a temporary store: create valid
/// layer objects, push them over the transport, pull them into a fresh store
/// and verify the snapshot. Nothing outside the temporary directory is touched.
pub fn selftest() -> Result<SelftestReport> {
    let mut checks = Vec::new();
    checks.push(run_check(
        "tcp",
        Target::Tcp {
            host: "127.0.0.1".into(),
            port: 0,
        },
    ));
    #[cfg(feature = "peer-quic")]
    checks.push(run_check(
        "quic",
        Target::Quic {
            host: "127.0.0.1".into(),
            port: 0,
            peer: None,
        },
    ));
    #[cfg(unix)]
    {
        let base = tempfile::tempdir()?;
        checks.push(run_check(
            "unix",
            Target::Unix {
                path: base.path().join("stream.sock"),
            },
        ));
        checks.push(run_check(
            "unix-dgram",
            Target::UnixDatagram {
                path: base.path().join("dgram.sock"),
            },
        ));
    }
    Ok(SelftestReport {
        ok: checks.iter().all(|check| check.ok),
        note: "Loopback only: TCP and QUIC on 127.0.0.1, Unix stream and Unix datagram under a temporary directory.",
        transports: checks,
    })
}

fn run_check(name: &str, target: Target) -> TransportCheck {
    let mut check = TransportCheck {
        transport: name.into(),
        protocol: PROTOCOL.into(),
        pushed: 0,
        pulled: 0,
        verified: 0,
        bytes: 0,
        ok: false,
        error: None,
    };
    match check_transport(&target) {
        Ok((report, bytes)) => {
            check.pushed = report.0;
            check.pulled = report.1;
            check.verified = report.2;
            check.bytes = bytes;
            check.ok = true;
        }
        Err(error) => check.error = Some(format!("{error:#}")),
    }
    check
}

fn check_transport(target: &Target) -> Result<((usize, usize, usize), u64)> {
    let root = tempfile::tempdir()?;
    let source = crate::FsObjectStorage::open(root.path().join("source"))?;
    let peer_root = root.path().join("peer");
    let peer_store = crate::FsObjectStorage::open(&peer_root)?;
    let destination = crate::FsObjectStorage::open(root.path().join("destination"))?;
    let journal_home = root.path().join("journal");
    fs::create_dir_all(&journal_home)?;
    let mut journal = Journal::open(&journal_home)?;

    let (manifest_key, manifest_bytes) = write_fixture(&source, 200 * 1024)?;
    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_nanos())
        .unwrap_or_default();
    let token = format!("selftest{}{nonce}", std::process::id());

    let service = Service::new(
        Arc::new(peer_store),
        token.clone(),
        Arc::new(AtomicBool::new(false)),
    );
    let server = match target {
        #[cfg(feature = "peer-quic")]
        Target::Quic { host, port, .. } => {
            Server::bind_quic(host, *port, service, &quic::Identity::generate()?)?
        }
        _ => Server::bind(target, service, false)?,
    };
    let result = (|| -> Result<(usize, usize, usize, u64)> {
        let remote = TransportPeer::connect(&server.target, token)?;
        let pushed = peer::push(&source, &remote, &peer::default_prefixes(), &mut journal)?;
        ensure!(pushed.clean(), "push reported conflicts or rejections");
        let pulled = peer::pull(
            &destination,
            &remote,
            &peer::default_prefixes(),
            &mut journal,
        )?;
        ensure!(pulled.clean(), "pull reported conflicts or rejections");
        ensure!(
            pulled.verified.iter().any(|key| key == &manifest_key),
            "pulled snapshot did not verify"
        );
        let check = layer::check_snapshot(&destination, "mneme", &manifest_key);
        ensure!(
            check.ok,
            "destination snapshot failed verification: {:?}",
            check.error
        );
        Ok((
            pushed.transferred,
            pulled.transferred,
            pulled.verified.len(),
            manifest_bytes,
        ))
    })();
    server.stop();
    let (pushed, pulled, verified, bytes) = result?;
    Ok(((pushed, pulled, verified), bytes))
}

/// Writes one valid Mneme-shaped chunk and manifest, large enough that a
/// datagram transport must reassemble several chunks.
fn write_fixture(storage: &dyn ObjectStorage, size: usize) -> Result<(String, u64)> {
    let data: Vec<u8> = (0..size).map(|index| (index % 251) as u8).collect();
    let digest = crate::wire::sha256_hex(&data);
    let chunk = layer::Chunk {
        sha256: digest.clone(),
        size: data.len() as u64,
    };
    let file = layer::LayerFile {
        path: "selftest.bin".into(),
        sha256: digest.clone(),
        bytes: data.len() as u64,
        chunks: vec![chunk],
    };
    let created_at = crate::chrono::Utc::now();
    let stamp = created_at.format("%Y%m%dT%H%M%S%.9fZ").to_string();
    let content_digest = format!(
        "{:x}",
        Sha256::digest(format!("{}\0{}\n", file.path, file.sha256).as_bytes())
    );
    let id = format!("selftest/{stamp}-{}", &content_digest[..12]);
    let manifest = layer::SnapshotManifest {
        schema: layer::SNAPSHOT_SCHEMA.into(),
        layer: "mneme".into(),
        id: id.clone(),
        label: "selftest".into(),
        created_at,
        run_id: None,
        chunk_bytes: data.len() as u64,
        digest: content_digest,
        files: vec![file],
        owner: serde_json::json!({"selftest": true}),
    };
    let manifest_bytes = serde_json::to_vec(&manifest)?;
    let chunk_key = format!("mneme/v1/chunks/sha256/{}/{digest}", &digest[..2]);
    let manifest_key = format!("mneme/v1/snapshots/{id}.json");
    storage.put(&ObjectKey::parse(&chunk_key)?, &data)?;
    storage.put(&ObjectKey::parse(&manifest_key)?, &manifest_bytes)?;
    Ok((
        manifest_key,
        data.len() as u64 + manifest_bytes.len() as u64,
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn token() -> String {
        "abc123".into()
    }

    #[test]
    fn parses_local_targets_and_keeps_tokens_separate() {
        let (target, token) =
            parse_connection("rbq+tcp://127.0.0.1:8787?token=abc123", None).unwrap();
        assert_eq!(
            target,
            Target::Tcp {
                host: "127.0.0.1".into(),
                port: 8787
            }
        );
        assert_eq!(token, "abc123");
        let (target, _) = parse_connection("unix:///run/rbq.sock", Some("x9")).unwrap();
        assert_eq!(target.describe(), "unix:///run/rbq.sock");
        let (target, _) = parse_connection("unix-dgram:///run/rbq.dgram", Some("x9")).unwrap();
        assert_eq!(target.describe(), "unix-dgram:///run/rbq.dgram");
        assert!(parse_connection("http://h:1", Some("x9")).is_err());
        assert!(parse_connection("unix://relative.sock", Some("x9")).is_err());
        assert!(parse_connection("unix:///run/x", None).is_err());
        assert!(parse_connection("tcp://h:0", Some("has space")).is_err());
    }

    #[test]
    fn frame_codec_bounds_and_truncation() {
        let mut buffer = Vec::new();
        write_frame(&mut buffer, b"hello", 16).unwrap();
        assert_eq!(
            read_frame(&mut buffer.as_slice(), 16).unwrap().unwrap(),
            b"hello"
        );
        assert!(read_frame(&mut [0_u8, 0, 0, 20].as_slice(), 16).is_err());
        assert!(read_frame(&mut [0_u8, 0, 0, 5, b'a'].as_slice(), 16).is_err());
        assert!(read_frame(&mut [].as_slice(), 16).unwrap().is_none());
        assert!(write_frame(&mut Vec::new(), b"0123456789", 4).is_err());
    }

    #[cfg(unix)]
    #[test]
    fn datagram_codec_rejects_foreign_and_short_messages() {
        let packet = datagram(KIND_CHUNK, 7, 2, 3, b"payload");
        let (kind, id, seq, total, payload) = parse_datagram(&packet).unwrap();
        assert_eq!(
            (kind, id, seq, total, payload),
            (KIND_CHUNK, 7, 2, 3, b"payload".as_slice())
        );
        assert!(parse_datagram(b"RBQ1").is_err());
        let mut foreign = packet.clone();
        foreign[0] = b'X';
        assert!(parse_datagram(&foreign).is_err());
    }

    #[test]
    fn token_comparison_is_exact() {
        assert!(same("abc", "abc"));
        assert!(!same("abc", "abd"));
        assert!(!same("abc", "abcd"));
        assert!(!same("", "a"));
        assert!(!same("a", ""));
        assert!(validate_token("a1B2").is_ok());
        assert!(validate_token("").is_err());
        assert!(validate_token("a b").is_err());
    }

    #[test]
    fn only_loopback_listeners_count_as_private() {
        let tcp = |host: &str| Target::Tcp {
            host: host.into(),
            port: 1,
        };
        for private in ["127.0.0.1", "127.8.9.10", "::1", "[::1]", "localhost"] {
            assert!(!tcp(private).is_public(), "{private}");
        }
        for public in [
            "0.0.0.0",
            "::",
            "[::]",
            "192.168.1.4",
            "fd00::1",
            "peer.local",
        ] {
            assert!(tcp(public).is_public(), "{public}");
        }
    }

    fn tcp_server() -> (tempfile::TempDir, Server) {
        let root = tempfile::tempdir().unwrap();
        let storage = crate::FsObjectStorage::open(root.path().join("store")).unwrap();
        let service = Service::new(Arc::new(storage), token(), Arc::new(AtomicBool::new(false)));
        let server = Server::bind(
            &Target::Tcp {
                host: "127.0.0.1".into(),
                port: 0,
            },
            service,
            false,
        )
        .unwrap();
        (root, server)
    }

    fn raw_connect(server: &Server) -> TcpStream {
        let Target::Tcp { host, port } = &server.target else {
            unreachable!()
        };
        let stream = TcpStream::connect((host.as_str(), *port)).unwrap();
        stream
            .set_read_timeout(Some(Duration::from_secs(15)))
            .unwrap();
        stream
    }

    /// Read until the server closes. Returns how long that took.
    fn closed_within(mut stream: TcpStream) -> Duration {
        let started = Instant::now();
        let mut sink = [0_u8; 256];
        loop {
            match stream.read(&mut sink) {
                Ok(0) | Err(_) => return started.elapsed(),
                Ok(_) => {}
            }
        }
    }

    #[test]
    fn silent_and_trickling_peers_lose_their_slot_at_the_auth_deadline() {
        let (_root, server) = tcp_server();
        let silent = raw_connect(&server);
        let mut trickle = raw_connect(&server);
        let waiter = thread::spawn(move || closed_within(silent));
        // One header byte every second: each read is "fast", the request never ends.
        let started = Instant::now();
        for byte in [0_u8, 0, 0, 9, b'{'] {
            if trickle.write_all(&[byte]).is_err() {
                break;
            }
            thread::sleep(Duration::from_millis(1100));
        }
        let trickled = started.elapsed() + closed_within(trickle);
        let silent = waiter.join().unwrap();
        assert!(
            silent < AUTH_DEADLINE + Duration::from_secs(3),
            "{silent:?}"
        );
        assert!(
            trickled < AUTH_DEADLINE + Duration::from_secs(4),
            "{trickled:?}"
        );
        server.stop();
    }

    #[test]
    fn oversized_requests_are_refused_before_allocation() {
        let (_root, server) = tcp_server();
        let mut stream = raw_connect(&server);
        // Announce a request just over the request bound; send nothing else.
        stream
            .write_all(&((MAX_REQUEST + 1) as u32).to_be_bytes())
            .unwrap();
        assert!(closed_within(stream) < Duration::from_secs(2));
        server.stop();
    }

    #[test]
    fn put_body_is_bounded_by_its_declared_size() {
        let (_root, server) = tcp_server();
        let mut stream = Stream::Tcp(raw_connect(&server));
        let envelope = RequestEnvelope {
            schema: PROTOCOL.into(),
            token: token(),
            request: Request::Put {
                key: "mneme/v1/chunks/sha256/aa/".to_owned() + &"a".repeat(64),
                size: 4,
            },
        };
        write_frame(
            &mut stream,
            &serde_json::to_vec(&envelope).unwrap(),
            MAX_REQUEST,
        )
        .unwrap();
        // A body frame larger than declared: the server must not read it.
        stream.write_all(&(1024_u32).to_be_bytes()).unwrap();
        let reply = read_frame(&mut stream, MAX_CONTROL).unwrap().unwrap();
        let reply: ResponseEnvelope = serde_json::from_slice(&reply).unwrap();
        assert!(matches!(reply.response, Response::Error { code: 400, .. }));
        server.stop();
    }

    /// A link that answers every listing with whatever page it is given.
    struct FakeLink(ListingPage);

    impl Link for FakeLink {
        fn describe(&self) -> String {
            "fake".into()
        }
        fn list_limit(&self, requested: usize) -> usize {
            requested.clamp(1, 4)
        }
        fn status(&mut self) -> Result<Status> {
            bail!("unused")
        }
        fn list(&mut self, _: &str, _: &str, _: usize) -> Result<ListingPage> {
            Ok(self.0.clone())
        }
        fn get(&mut self, _: &str) -> Result<Vec<u8>> {
            bail!("unused")
        }
        fn put(&mut self, _: &str, _: &[u8]) -> Result<bool> {
            bail!("unused")
        }
        fn get_range(&mut self, _: &str, _: u64, _: u64) -> Result<(Vec<u8>, u64)> {
            bail!("unused")
        }
        fn call(&mut self, _: Request, _: Option<&[u8]>) -> Result<Response> {
            bail!("unused")
        }
    }

    fn listing(page: ListingPage) -> Result<BTreeMap<String, u64>> {
        TransportPeer::from_link(Box::new(FakeLink(page)), None).list("mneme/")
    }

    fn chunk_key(n: u8) -> String {
        let digest = format!("{n:02x}").repeat(32);
        format!("mneme/v1/chunks/sha256/{}/{digest}", &digest[..2])
    }

    #[test]
    fn hostile_listings_are_refused() {
        let page = |items: Vec<Item>| ListingPage {
            items,
            truncated: false,
            next: None,
        };
        let item = |key: String, size| Item { key, size };
        assert_eq!(listing(page(vec![item(chunk_key(1), 3)])).unwrap().len(), 1);
        // More items than the page limit the client asked for.
        assert!(listing(page((1..=5).map(|n| item(chunk_key(n), 1)).collect())).is_err());
        // Out of the requested prefix, not a layer key, or oversized.
        assert!(listing(page(vec![item(chunk_key(1).replace("mneme", "git"), 1)])).is_err());
        assert!(listing(page(vec![item("mneme/v1/notes.txt".into(), 1)])).is_err());
        assert!(listing(page(vec![item(chunk_key(1), MAX_OBJECT + 1)])).is_err());
        // Keys must strictly increase within a page too.
        assert!(listing(page(vec![item(chunk_key(2), 1), item(chunk_key(1), 1)])).is_err());
    }

    #[cfg(unix)]
    #[test]
    fn a_datagram_client_that_never_reads_cannot_wedge_the_server() {
        let root = tempfile::tempdir().unwrap();
        let storage = crate::FsObjectStorage::open(root.path().join("store")).unwrap();
        let service = Service::new(Arc::new(storage), token(), Arc::new(AtomicBool::new(false)));
        let path = root.path().join("dgram.sock");
        let server =
            Server::bind(&Target::UnixDatagram { path: path.clone() }, service, false).unwrap();
        // The hog asks for status over and over, never reads a reply, and
        // stays alive. Its unread replies fill its queue (and the server's
        // send buffer), so without a send timeout the serving thread blocks in
        // `send_to` forever and `stop` never returns.
        let hog = std::os::unix::net::UnixDatagram::bind(root.path().join("hog")).unwrap();
        hog.connect(&path).unwrap();
        hog.set_nonblocking(true).unwrap();
        let request = serde_json::to_vec(&RequestEnvelope {
            schema: PROTOCOL.into(),
            token: token(),
            request: Request::Status,
        })
        .unwrap();
        for id in 1..=4000 {
            let _ = hog.send(&datagram(KIND_CONTROL, id, 0, 0, &request));
        }
        thread::sleep(Duration::from_millis(500));
        let (done, stopped) = std::sync::mpsc::channel();
        thread::spawn(move || {
            server.stop();
            let _ = done.send(());
        });
        stopped
            .recv_timeout(Duration::from_secs(10))
            .expect("the serving thread must not block forever on a client that never reads");
        drop(hog);
    }

    /// Counts listings, delegating everything to a real store.
    struct CountingStore(crate::FsObjectStorage, AtomicUsize);

    impl ObjectStorage for CountingStore {
        fn capabilities(&self) -> crate::storage::StorageCapabilities {
            self.0.capabilities()
        }
        fn put(&self, k: &ObjectKey, d: &[u8]) -> Result<crate::storage::ObjectMeta, StorageError> {
            self.0.put(k, d)
        }
        fn put_if_absent(&self, k: &ObjectKey, d: &[u8]) -> Result<PutOutcome, StorageError> {
            self.0.put_if_absent(k, d)
        }
        fn get(&self, k: &ObjectKey) -> Result<Vec<u8>, StorageError> {
            self.0.get(k)
        }
        fn get_range(
            &self,
            k: &ObjectKey,
            r: std::ops::Range<u64>,
        ) -> Result<Vec<u8>, StorageError> {
            self.0.get_range(k, r)
        }
        fn head(&self, k: &ObjectKey) -> Result<crate::storage::ObjectMeta, StorageError> {
            self.0.head(k)
        }
        fn list_prefix(
            &self,
            p: &str,
            n: usize,
        ) -> Result<Vec<crate::storage::ObjectMeta>, StorageError> {
            self.1.fetch_add(1, Ordering::SeqCst);
            self.0.list_prefix(p, n)
        }
        fn delete(&self, k: &ObjectKey) -> Result<(), StorageError> {
            self.0.delete(k)
        }
    }

    #[test]
    fn pagination_lists_storage_once_per_listing() {
        let root = tempfile::tempdir().unwrap();
        let store = Arc::new(CountingStore(
            crate::FsObjectStorage::open(root.path().join("store")).unwrap(),
            AtomicUsize::new(0),
        ));
        for n in 0..100_u8 {
            store
                .put(&ObjectKey::parse(&chunk_key(n)).unwrap(), b"x")
                .unwrap();
        }
        let service = Service::new(store.clone(), token(), Arc::new(AtomicBool::new(false)));
        let mut after = String::new();
        let mut seen = Vec::new();
        loop {
            let (response, _) = service.handle(
                &Request::List {
                    prefix: "mneme/".into(),
                    after: after.clone(),
                    limit: 7,
                },
                None,
            );
            let Response::Listing {
                items,
                truncated,
                next,
            } = response
            else {
                panic!("expected a listing");
            };
            assert!(items.len() <= 7);
            seen.extend(items.into_iter().map(|item| item.key));
            if !truncated {
                break;
            }
            after = next.unwrap();
        }
        let mut expected: Vec<String> = (0..100_u8).map(chunk_key).collect();
        expected.sort();
        assert_eq!(seen, expected, "every key once, in order");
        assert_eq!(
            store.1.load(Ordering::SeqCst),
            1,
            "15 pages, one storage walk"
        );
        // A new listing (first page) always reads storage again.
        service.handle(
            &Request::List {
                prefix: "mneme/".into(),
                after: String::new(),
                limit: 7,
            },
            None,
        );
        assert_eq!(store.1.load(Ordering::SeqCst), 2);
    }

    #[cfg(unix)]
    #[test]
    fn unfinished_datagram_uploads_share_a_memory_budget() {
        let root = tempfile::tempdir().unwrap();
        let storage = crate::FsObjectStorage::open(root.path().join("store")).unwrap();
        let service = Service::new(Arc::new(storage), token(), Arc::new(AtomicBool::new(false)));
        let path = root.path().join("dgram.sock");
        let server =
            Server::bind(&Target::UnixDatagram { path: path.clone() }, service, false).unwrap();
        let start_upload = |name: &str| {
            let client = std::os::unix::net::UnixDatagram::bind(root.path().join(name)).unwrap();
            client.connect(&path).unwrap();
            client
                .set_read_timeout(Some(Duration::from_millis(500)))
                .unwrap();
            let request = serde_json::to_vec(&RequestEnvelope {
                schema: PROTOCOL.into(),
                token: token(),
                request: Request::Put {
                    key: chunk_key(1),
                    size: 60 * 1024 * 1024,
                },
            })
            .unwrap();
            client
                .send(&datagram(KIND_CONTROL, 1, 0, 0, &request))
                .unwrap();
            client
        };
        // Two 60 MiB uploads fit the 128 MiB budget and wait for chunks.
        let mut buffer = vec![0_u8; MAX_DATAGRAM];
        for name in ["a", "b"] {
            let client = start_upload(name);
            assert!(
                client.recv(&mut buffer).is_err(),
                "no reply until chunks arrive"
            );
        }
        // A third would exceed it and is refused instead of reserved.
        let client = start_upload("c");
        let size = client.recv(&mut buffer).expect("a refusal");
        let (_, _, _, _, payload) = parse_datagram(&buffer[..size]).unwrap();
        let reply: ResponseEnvelope = serde_json::from_slice(payload).unwrap();
        assert!(matches!(reply.response, Response::Error { code: 503, .. }));
        assert!(server.shutdown());
    }

    #[test]
    fn tcp_requests_are_reported_to_the_observer() {
        /// peer, transport, request, authorized, rejected
        type Row = (String, &'static str, String, bool, bool);
        #[derive(Default)]
        struct Count(Mutex<Vec<Row>>);
        impl Observer for Count {
            fn request(&self, r: &RequestRecord<'_>) {
                self.0.lock().unwrap().push((
                    r.peer.to_owned(),
                    r.transport,
                    r.request.clone(),
                    r.authorized,
                    r.rejected,
                ));
            }
        }
        let root = tempfile::tempdir().unwrap();
        let storage = crate::FsObjectStorage::open(root.path().join("store")).unwrap();
        let count = Arc::new(Count::default());
        let service = Service::new(Arc::new(storage), token(), Arc::new(AtomicBool::new(false)))
            .with_observer(count.clone());
        let server = Server::bind(
            &Target::Tcp {
                host: "127.0.0.1".into(),
                port: 0,
            },
            service,
            false,
        )
        .unwrap();
        let mut link = connect(&server.target, token()).unwrap();
        link.status().unwrap();
        drop(link);
        let mut bad = connect(&server.target, "wrong0".into()).unwrap();
        assert!(bad.status().is_err());
        drop(bad);
        server.stop();
        let seen = count.0.lock().unwrap().clone();
        assert_eq!(
            seen,
            vec![
                ("127.0.0.1".into(), "tcp", "status".into(), true, false),
                ("127.0.0.1".into(), "tcp", "status".into(), false, true),
            ]
        );
    }

    /// A valid, incompressible chunk of `size` bytes and its key.
    fn big_chunk(size: usize) -> (String, Vec<u8>) {
        let mut state = 0x9e37_79b9_7f4a_7c15_u64;
        let bytes: Vec<u8> = (0..size)
            .map(|_| {
                state ^= state << 13;
                state ^= state >> 7;
                state ^= state << 17;
                state as u8
            })
            .collect();
        let digest = crate::wire::sha256_hex(&bytes);
        (
            format!("mneme/v1/chunks/sha256/{}/{digest}", &digest[..2]),
            bytes,
        )
    }

    #[test]
    fn large_objects_stream_and_arrive_whole_over_every_transport() {
        let root = tempfile::tempdir().unwrap();
        let storage = Arc::new(crate::FsObjectStorage::open(root.path().join("store")).unwrap());
        let (key, bytes) = big_chunk(20 * 1024 * 1024 + 123);
        storage
            .put(&ObjectKey::parse(&key).unwrap(), &bytes)
            .unwrap();
        let mut targets = vec![Target::Tcp {
            host: "127.0.0.1".into(),
            port: 0,
        }];
        #[cfg(unix)]
        {
            targets.push(Target::Unix {
                path: root.path().join("s.sock"),
            });
            targets.push(Target::UnixDatagram {
                path: root.path().join("d.sock"),
            });
        }
        #[cfg(feature = "peer-quic")]
        targets.push(Target::Quic {
            host: "127.0.0.1".into(),
            port: 0,
            peer: None,
        });
        for target in targets {
            let service = Service::new(storage.clone(), token(), Arc::new(AtomicBool::new(false)));
            let server = match &target {
                #[cfg(feature = "peer-quic")]
                Target::Quic { host, port, .. } => {
                    Server::bind_quic(host, *port, service, &quic::Identity::generate().unwrap())
                        .unwrap()
                }
                _ => Server::bind(&target, service, false).unwrap(),
            };
            let peer = TransportPeer::connect(&server.target, token()).unwrap();
            assert!(peer.ranged().unwrap(), "{}", target.describe());
            assert!(peer.get(&key).unwrap() == bytes, "{}", target.describe());
            drop(peer);
            assert!(server.shutdown());
        }
    }

    /// A TCP relay that cuts its first connection after `cut_after` bytes in
    /// one direction (server to client, or client to server when `upload`),
    /// like a mesh link dropping mid-transfer. Returns the relay port and a
    /// count of connections it accepted.
    fn flaky_relay(upstream: u16, cut_after: usize, upload: bool) -> (u16, Arc<AtomicUsize>) {
        fn pump(mut from: TcpStream, mut to: TcpStream, cut: Option<usize>) {
            let mut buffer = [0_u8; 64 * 1024];
            let mut relayed = 0;
            loop {
                let n = match from.read(&mut buffer) {
                    Ok(0) | Err(_) => break,
                    Ok(n) => n,
                };
                if cut.is_some_and(|cut| relayed + n > cut) {
                    break;
                }
                if to.write_all(&buffer[..n]).is_err() {
                    break;
                }
                relayed += n;
            }
            let _ = from.shutdown(Shutdown::Both);
            let _ = to.shutdown(Shutdown::Both);
        }
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        let accepted = Arc::new(AtomicUsize::new(0));
        let count = accepted.clone();
        thread::spawn(move || {
            for client in listener.incoming() {
                let Ok(client) = client else { return };
                let first = count.fetch_add(1, Ordering::SeqCst) == 0;
                let server = TcpStream::connect(("127.0.0.1", upstream)).unwrap();
                let cut = first.then_some(cut_after);
                let (client_copy, server_copy) =
                    (client.try_clone().unwrap(), server.try_clone().unwrap());
                let (up_cut, down_cut) = if upload { (cut, None) } else { (None, cut) };
                thread::spawn(move || pump(client_copy, server_copy, up_cut));
                thread::spawn(move || pump(server, client, down_cut));
            }
        });
        (port, accepted)
    }

    #[test]
    fn a_download_resumes_after_the_link_breaks() {
        #[derive(Default)]
        struct Ranges(Mutex<Vec<String>>);
        impl Observer for Ranges {
            fn request(&self, r: &RequestRecord<'_>) {
                self.0.lock().unwrap().push(r.request.clone());
            }
        }
        let root = tempfile::tempdir().unwrap();
        let storage = Arc::new(crate::FsObjectStorage::open(root.path().join("store")).unwrap());
        let (key, bytes) = big_chunk(18 * 1024 * 1024);
        storage
            .put(&ObjectKey::parse(&key).unwrap(), &bytes)
            .unwrap();
        let ranges = Arc::new(Ranges::default());
        let service = Service::new(storage, token(), Arc::new(AtomicBool::new(false)))
            .with_observer(ranges.clone());
        let server = Server::bind(
            &Target::Tcp {
                host: "127.0.0.1".into(),
                port: 0,
            },
            service,
            false,
        )
        .unwrap();
        let Target::Tcp { port, .. } = server.target else {
            unreachable!()
        };
        // The relay drops the first connection 6 MiB into the download.
        let (relay, accepted) = flaky_relay(port, 6 * 1024 * 1024, false);
        let peer = TransportPeer::connect(
            &Target::Tcp {
                host: "127.0.0.1".into(),
                port: relay,
            },
            token(),
        )
        .unwrap();
        let fetched = peer.get(&key).unwrap();
        assert!(fetched == bytes, "resumed download must be byte-identical");
        assert_eq!(accepted.load(Ordering::SeqCst), 2, "one reconnect");
        let seen = ranges.0.lock().unwrap().clone();
        // Only the window in flight was fetched again, not the whole object.
        let windows = seen.iter().filter(|r| r.starts_with("get ")).count();
        assert!(
            (5..=7).contains(&windows),
            "18 MiB in 4 MiB windows plus one retried: {seen:?}"
        );
        // A peer's "no" is not a broken link: no reconnect for a missing object.
        let (missing, _) = big_chunk(10);
        assert!(peer.get(&missing).is_err());
        assert_eq!(accepted.load(Ordering::SeqCst), 2);
        drop(peer);
        server.stop();
    }

    fn staged_service(root: &Path) -> (Arc<crate::FsObjectStorage>, Service) {
        let storage = Arc::new(crate::FsObjectStorage::open(root.join("store")).unwrap());
        let staging = Arc::new(staging::Staging::open(&root.join("staging")).unwrap());
        let service = Service::new(storage.clone(), token(), Arc::new(AtomicBool::new(false)))
            .with_staging(staging);
        (storage, service)
    }

    fn staging_is_empty(root: &Path) -> bool {
        fs::read_dir(root.join("staging")).unwrap().next().is_none()
    }

    #[test]
    fn large_uploads_are_staged_and_arrive_whole_over_every_transport() {
        let (key, bytes) = big_chunk(20 * 1024 * 1024 + 77);
        let mut targets = vec![Target::Tcp {
            host: "127.0.0.1".into(),
            port: 0,
        }];
        #[cfg(unix)]
        {
            targets.push(Target::Unix {
                path: PathBuf::from("s.sock"),
            });
            targets.push(Target::UnixDatagram {
                path: PathBuf::from("d.sock"),
            });
        }
        #[cfg(feature = "peer-quic")]
        targets.push(Target::Quic {
            host: "127.0.0.1".into(),
            port: 0,
            peer: None,
        });
        for target in targets {
            let root = tempfile::tempdir().unwrap();
            let target = match target {
                #[cfg(unix)]
                Target::Unix { path } => Target::Unix {
                    path: root.path().join(path),
                },
                #[cfg(unix)]
                Target::UnixDatagram { path } => Target::UnixDatagram {
                    path: root.path().join(path),
                },
                other => other,
            };
            let (storage, service) = staged_service(root.path());
            let server = match &target {
                #[cfg(feature = "peer-quic")]
                Target::Quic { host, port, .. } => {
                    Server::bind_quic(host, *port, service, &quic::Identity::generate().unwrap())
                        .unwrap()
                }
                _ => Server::bind(&target, service, false).unwrap(),
            };
            let peer = TransportPeer::connect(&server.target, token()).unwrap();
            assert!(
                peer.capabilities().unwrap().staged_put,
                "{}",
                target.describe()
            );
            assert!(peer.put(&key, &bytes).unwrap(), "{}", target.describe());
            assert!(!peer.put(&key, &bytes).unwrap(), "create-if-absent");
            assert!(
                storage.get(&ObjectKey::parse(&key).unwrap()).unwrap() == bytes,
                "{}",
                target.describe()
            );
            assert!(staging_is_empty(root.path()), "{}", target.describe());
            drop(peer);
            assert!(server.shutdown());
        }
    }

    #[test]
    fn an_upload_resumes_after_the_link_breaks() {
        #[derive(Default)]
        struct Requests(Mutex<Vec<String>>);
        impl Observer for Requests {
            fn request(&self, r: &RequestRecord<'_>) {
                self.0.lock().unwrap().push(r.request.clone());
            }
        }
        let root = tempfile::tempdir().unwrap();
        let (storage, service) = staged_service(root.path());
        let requests = Arc::new(Requests::default());
        let server = Server::bind(
            &Target::Tcp {
                host: "127.0.0.1".into(),
                port: 0,
            },
            service.with_observer(requests.clone()),
            false,
        )
        .unwrap();
        let Target::Tcp { port, .. } = server.target else {
            unreachable!()
        };
        // The relay drops the first connection 6 MiB into the upload.
        let (relay, accepted) = flaky_relay(port, 6 * 1024 * 1024, true);
        let (key, bytes) = big_chunk(18 * 1024 * 1024);
        let peer = TransportPeer::connect(
            &Target::Tcp {
                host: "127.0.0.1".into(),
                port: relay,
            },
            token(),
        )
        .unwrap();
        assert!(peer.put(&key, &bytes).unwrap());
        assert!(storage.get(&ObjectKey::parse(&key).unwrap()).unwrap() == bytes);
        assert_eq!(accepted.load(Ordering::SeqCst), 2, "one reconnect");
        let seen = requests.0.lock().unwrap().clone();
        let parts = seen
            .iter()
            .filter(|r| r.contains("] ") || r.ends_with(']'))
            .count();
        // 18 MiB in 4 MiB parts is 5; after the break the client resumed from
        // the server's offset instead of starting over.
        assert!((5..=6).contains(&parts), "{seen:?}");
        assert!(seen.iter().any(|r| r.ends_with("(commit)")));
        assert!(staging_is_empty(root.path()));
        drop(peer);
        server.stop();
    }

    #[test]
    fn put_start_reports_what_is_already_staged() {
        let root = tempfile::tempdir().unwrap();
        let (storage, service) = staged_service(root.path());
        let (key, bytes) = big_chunk(3 * 1024 * 1024);
        let size = bytes.len() as u64;
        let call = |request: Request, body: Option<&[u8]>| service.handle(&request, body).0;
        let start = || {
            call(
                Request::PutStart {
                    key: key.clone(),
                    size,
                },
                None,
            )
        };
        assert!(matches!(start(), Response::Staged { offset: 0 }));
        let first = &bytes[..1024 * 1024];
        call(
            Request::PutPart {
                key: key.clone(),
                offset: 0,
                length: first.len() as u64,
            },
            Some(first),
        );
        // A client that lost the reply (or the link) asks again and resumes.
        assert!(matches!(start(), Response::Staged { offset } if offset == 1024 * 1024));
        let rest = &bytes[1024 * 1024..];
        call(
            Request::PutPart {
                key: key.clone(),
                offset: 1024 * 1024,
                length: rest.len() as u64,
            },
            Some(rest),
        );
        assert!(matches!(
            call(
                Request::PutCommit {
                    key: key.clone(),
                    size
                },
                None
            ),
            Response::Stored { created: true, .. }
        ));
        assert_eq!(
            storage.get(&ObjectKey::parse(&key).unwrap()).unwrap(),
            bytes
        );
        // Once stored, starting again says so instead of staging anew.
        assert!(matches!(start(), Response::Stored { created: false, .. }));
    }

    #[test]
    fn a_staged_upload_that_does_not_verify_is_never_published() {
        let root = tempfile::tempdir().unwrap();
        let (storage, service) = staged_service(root.path());
        let (key, bytes) = big_chunk(5 * 1024 * 1024);
        let size = bytes.len() as u64;
        let call = |request: Request, body: Option<&[u8]>| service.handle(&request, body).0;
        assert!(matches!(
            call(
                Request::PutStart {
                    key: key.clone(),
                    size
                },
                None
            ),
            Response::Staged { offset: 0 }
        ));
        let wrong = vec![0_u8; bytes.len()];
        assert!(matches!(
            call(
                Request::PutPart {
                    key: key.clone(),
                    offset: 0,
                    length: size
                },
                Some(&wrong)
            ),
            Response::Staged { .. }
        ));
        // A part at the wrong offset is refused with the real one.
        assert!(matches!(
            call(
                Request::PutPart {
                    key: key.clone(),
                    offset: 3,
                    length: 1
                },
                Some(b"x")
            ),
            Response::Error { code: 409, .. }
        ));
        assert!(matches!(
            call(
                Request::PutCommit {
                    key: key.clone(),
                    size
                },
                None
            ),
            Response::Error { code: 400, .. }
        ));
        assert!(storage.head(&ObjectKey::parse(&key).unwrap()).is_err());
        assert!(
            staging_is_empty(root.path()),
            "a failed upload is discarded"
        );
    }

    #[test]
    fn put_if_absent_file_never_replaces_an_object() {
        for hard_links in [true, false] {
            let root = tempfile::tempdir().unwrap();
            let mut storage = crate::FsObjectStorage::open(root.path().join("store")).unwrap();
            if !hard_links {
                storage = storage.without_hard_links();
            }
            let (key, bytes) = big_chunk(1000);
            let key = ObjectKey::parse(&key).unwrap();
            let file = root.path().join("upload");
            fs::write(&file, &bytes).unwrap();
            assert!(matches!(
                storage.put_if_absent_file(&key, &file).unwrap(),
                PutOutcome::Created(_)
            ));
            fs::write(&file, vec![1_u8; 1000]).unwrap();
            assert!(matches!(
                storage.put_if_absent_file(&key, &file).unwrap(),
                PutOutcome::AlreadyExists(_)
            ));
            assert_eq!(storage.get(&key).unwrap(), bytes);
            // No temporaries are left beside the object, or listed.
            assert_eq!(storage.list_prefix("mneme/", 0).unwrap().len(), 1);
        }
    }

    #[test]
    fn a_push_with_nothing_to_send_hashes_instead_of_downloading() {
        #[derive(Default)]
        struct Requests(Mutex<Vec<String>>);
        impl Observer for Requests {
            fn request(&self, r: &RequestRecord<'_>) {
                self.0.lock().unwrap().push(r.request.clone());
            }
        }
        let root = tempfile::tempdir().unwrap();
        let source = crate::FsObjectStorage::open(root.path().join("source")).unwrap();
        write_fixture(&source, 300 * 1024).unwrap();
        let requests = Arc::new(Requests::default());
        let service = Service::new(
            Arc::new(crate::FsObjectStorage::open(root.path().join("peer")).unwrap()),
            token(),
            Arc::new(AtomicBool::new(false)),
        )
        .with_observer(requests.clone());
        let server = Server::bind(
            &Target::Tcp {
                host: "127.0.0.1".into(),
                port: 0,
            },
            service,
            false,
        )
        .unwrap();
        let peer = TransportPeer::connect(&server.target, token()).unwrap();
        let mut journal = Journal::open(root.path()).unwrap();
        let prefixes = peer::default_prefixes();
        assert!(
            peer::push(&source, &peer, &prefixes, &mut journal)
                .unwrap()
                .clean()
        );
        requests.0.lock().unwrap().clear();
        let again = peer::push(&source, &peer, &prefixes, &mut journal).unwrap();
        assert!(again.clean() && again.transferred == 0 && again.already_present > 0);
        let seen = requests.0.lock().unwrap().clone();
        assert!(seen.iter().any(|r| r.starts_with("hash ")), "{seen:?}");
        assert!(
            !seen.iter().any(|r| r.starts_with("get ")),
            "nothing downloaded: {seen:?}"
        );
        // Distrusting the peer downloads the copies instead.
        requests.0.lock().unwrap().clear();
        assert!(
            peer::push(&source, &peer::Distrusting(&peer), &prefixes, &mut journal)
                .unwrap()
                .clean()
        );
        let seen = requests.0.lock().unwrap().clone();
        assert!(seen.iter().any(|r| r.starts_with("get ")), "{seen:?}");
        drop(peer);
        server.stop();
    }

    #[test]
    fn status_and_error_shapes_round_trip() {
        let response = Response::Status(Status {
            protocol: PROTOCOL.into(),
            version: "0".into(),
            writes_paused: false,
            capabilities: Capabilities::default(),
        });
        let envelope = ResponseEnvelope {
            schema: PROTOCOL.into(),
            response,
        };
        let json = serde_json::to_vec(&envelope).unwrap();
        let decoded: ResponseEnvelope = serde_json::from_slice(&json).unwrap();
        assert!(matches!(decoded.response, Response::Status(_)));
        let request = Request::List {
            prefix: "mneme/".into(),
            after: String::new(),
            limit: PAGE,
        };
        let envelope = RequestEnvelope {
            schema: PROTOCOL.into(),
            token: token(),
            request,
        };
        let json = serde_json::to_vec(&envelope).unwrap();
        let decoded: RequestEnvelope = serde_json::from_slice(&json).unwrap();
        assert!(matches!(decoded.request, Request::List { .. }));
    }
}
