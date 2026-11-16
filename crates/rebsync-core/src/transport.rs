//! Local transports for `rebsync-peer/1`.
//!
//! The layer sync logic in [`crate::peer`] only needs a handful of operations:
//! status, list, get and create-if-absent put. `rebsync-peer/0` carries those
//! over plain HTTP for the Rebekah app. This module carries the same operations
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
//! wants to carry rebsync traffic must expose a Unix stream or datagram socket
//! speaking `rebsync-peer/1`; rebsync itself never talks to OSHI relays.

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

pub const PROTOCOL: &str = "rebsync-peer/1";
/// Metadata frames (a request/response envelope) are bounded independently
/// from object bodies. A 10 000-key listing with long keys needs a few MiB.
const MAX_CONTROL: usize = 8 * 1024 * 1024;
/// Largest object body, matching `rebsync-peer/0` and Mneme chunks.
pub const MAX_OBJECT: u64 = 64 * 1024 * 1024;
const MAX_LIST: usize = 10_000;
const PAGE: usize = 5000;
const MAX_CONNECTIONS: usize = 8;
const IO_TIMEOUT: Duration = Duration::from_secs(120);
const ACCEPT_POLL: Duration = Duration::from_millis(50);

// Datagram wire format: "RSD1" | kind:u8 | id:u32 | seq:u32 | total:u32 | payload
const DATAGRAM_MAGIC: &[u8; 4] = b"RSD1";
const DATAGRAM_HEADER: usize = 17;
const KIND_CONTROL: u8 = 0;
const KIND_CHUNK: u8 = 1;
/// Datagram payload size. 64 KiB is the usual platform limit; 32 KiB leaves
/// room for headers and keeps reassembly memory easy to reason about.
pub const CHUNK: usize = 32 * 1024;
const MAX_DATAGRAM: usize = 60 * 1024;
const DATAGRAM_PAGE: usize = 32;
const MAX_ASSEMBLIES: usize = 16;
const ASSEMBLY_TTL: Duration = Duration::from_secs(60);
const DATAGRAM_TIMEOUT: Duration = Duration::from_secs(30);
const MAX_BODY_CHUNKS: u32 = (MAX_OBJECT as usize).div_ceil(CHUNK) as u32;

/// A parsed connection target. Tokens are carried separately so they never end
/// up in a display string, a journal subject or an error message.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Target {
    Tcp {
        host: String,
        port: u16,
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
                let authority = rest.trim_end_matches('/');
                ensure!(!authority.is_empty(), "tcp target needs HOST:PORT");
                ensure!(
                    !authority.contains('/') && !authority.contains('@'),
                    "tcp target must be HOST:PORT"
                );
                let (host, port) = authority
                    .rsplit_once(':')
                    .context("tcp target must be HOST:PORT")?;
                ensure!(!host.is_empty(), "tcp host is empty");
                let port: u16 = port.parse().context("invalid tcp port")?;
                Ok(Self::Tcp {
                    host: host
                        .trim_start_matches('[')
                        .trim_end_matches(']')
                        .to_owned(),
                    port,
                })
            }
            "unix" => unix_path(rest, false),
            "unix-dgram" | "unix+datagram" => unix_path(rest, true),
            "http" | "https" => bail!(
                "{scheme} targets use rebsync-peer/0; keep using them with the HTTP peer client"
            ),
            other => bail!("unsupported transport {other:?}; use tcp, unix or unix-dgram"),
        }
    }

    pub fn describe(&self) -> String {
        match self {
            Self::Tcp { host, port } => {
                if host.contains(':') {
                    format!("tcp://[{host}]:{port}")
                } else {
                    format!("tcp://{host}:{port}")
                }
            }
            #[cfg(unix)]
            Self::Unix { path } => format!("unix://{}", path.display()),
            #[cfg(unix)]
            Self::UnixDatagram { path } => format!("unix-dgram://{}", path.display()),
        }
    }

    /// TCP listeners on a non-loopback address expose plaintext traffic to the
    /// local network. Callers should warn instead of silently pretending this
    /// is private.
    pub fn is_public(&self) -> bool {
        match self {
            Self::Tcp { host, .. } => {
                !matches!(
                    host.as_str(),
                    "127.0.0.1" | "::1" | "localhost" | "0.0.0.0" | "[::]"
                ) && host != "::"
            }
            #[cfg(unix)]
            _ => false,
        }
    }
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

/// Parse `rebsync+tcp://HOST:PORT?token=T`, `unix:///path?token=T` or
/// `unix-dgram:///path?token=T`, with the token optionally supplied separately.
pub fn parse_connection(connection: &str, token: Option<&str>) -> Result<(Target, String)> {
    let raw = connection.trim();
    let raw = raw.strip_prefix("rebsync+").unwrap_or(raw);
    let (location, query) = raw.split_once('?').unwrap_or((raw, ""));
    let from_query = query
        .split('&')
        .find_map(|pair| pair.strip_prefix("token="))
        .map(str::to_owned);
    let token = token
        .map(str::to_owned)
        .or(from_query)
        .context("no token: pass --token-file or include ?token=...")?;
    validate_token(&token)?;
    Ok((Target::parse(location)?, token))
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
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        ensure!(
            metadata.permissions().mode() & 0o077 == 0,
            "token file {} must not be group- or world-readable (chmod 600)",
            path.display()
        );
    }
    let token = fs::read_to_string(path)?.trim().to_owned();
    validate_token(&token)?;
    Ok(token)
}

fn same(a: &str, b: &str) -> bool {
    a.len() == b.len()
        && a.bytes()
            .zip(b.bytes())
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
    Put {
        key: String,
        size: u64,
    },
}

fn default_limit() -> usize {
    PAGE
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
        size: u64,
    },
    Stored {
        created: bool,
        size: u64,
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

/// A token-protected view of one object store. Cloneable so each connection and
/// datagram worker can hold it.
#[derive(Clone)]
pub struct Service {
    storage: Arc<dyn ObjectStorage>,
    token: Arc<String>,
    writes_paused: Arc<AtomicBool>,
}

impl Service {
    pub fn new(
        storage: Arc<dyn ObjectStorage>,
        token: String,
        writes_paused: Arc<AtomicBool>,
    ) -> Self {
        Self {
            storage,
            token: Arc::new(token),
            writes_paused,
        }
    }

    pub fn authorize(&self, presented: &str) -> bool {
        same(presented, &self.token)
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
            },
        }
    }

    /// Handle one validated request. Returns an optional body for `get`.
    fn handle(&self, request: &Request, body: Option<&[u8]>) -> (Response, Option<Vec<u8>>) {
        match request {
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
                match self.storage.list_prefix(prefix, 0) {
                    Ok(items) => {
                        let mut page: Vec<Item> = items
                            .into_iter()
                            .filter(|item| item.key.as_str() > after.as_str())
                            .map(|item| Item {
                                key: item.key,
                                size: item.size,
                            })
                            .collect();
                        let truncated = page.len() > limit;
                        page.truncate(limit);
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
            Request::Get { key } => {
                if let Err(error) = peer::admissible_key(key) {
                    return (error_response(400, format!("{error:#}")), None);
                }
                match ObjectKey::parse(key).and_then(|key| self.storage.get(&key)) {
                    Ok(bytes) => (
                        Response::Object {
                            size: bytes.len() as u64,
                        },
                        Some(bytes),
                    ),
                    Err(error) => (storage_response(&error), None),
                }
            }
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
    match target {
        Target::Tcp { host, port } => Ok(Box::new(StreamLink::tcp(host, *port, token)?)),
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
            Response::Object { size } => {
                ensure!(size <= MAX_OBJECT, "peer announced an oversized object");
                let body = read_frame(&mut self.stream, MAX_OBJECT as usize)?
                    .context("peer closed before sending the object body")?;
                ensure!(body.len() as u64 == size, "object body length mismatch");
                Ok((Response::Object { size }, Some(body)))
            }
            Response::Error { code, message } => bail!("peer error {code}: {message}"),
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
    ensure!(&bytes[..4] == DATAGRAM_MAGIC, "not a rebsync datagram");
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
                        Response::Object { size: announced } => {
                            ensure!(announced <= MAX_OBJECT, "oversized object announcement");
                            expected = Some(announced as usize);
                        }
                        Response::Error { code, message } => {
                            bail!("peer error {code}: {message}")
                        }
                        other => return Ok((other, None)),
                    }
                    response = Some(Response::Object {
                        size: expected.unwrap() as u64,
                    });
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

pub struct TransportPeer {
    link: Mutex<Box<dyn Link>>,
    description: String,
}

impl TransportPeer {
    pub fn connect(target: &Target, token: String) -> Result<Self> {
        let link = connect(target, token)?;
        let description = link.describe();
        Ok(Self {
            link: Mutex::new(link),
            description,
        })
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
        let status = self.lock()?.status()?;
        Ok(serde_json::json!({
            "protocol": status.protocol,
            "version": status.version,
            "writes_paused": status.writes_paused,
            "capabilities": status.capabilities,
        }))
    }

    fn list(&self, prefix: &str) -> Result<BTreeMap<String, u64>> {
        let mut link = self.lock()?;
        let mut found = BTreeMap::new();
        let mut after = String::new();
        for _ in 0..10_000 {
            let page = link.list(prefix, &after, PAGE)?;
            for item in &page.items {
                ensure!(
                    item.key.as_str() > after.as_str(),
                    "peer ignored pagination; refusing a repeated listing"
                );
                found.insert(item.key.clone(), item.size);
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
        self.lock()?.get(key)
    }

    fn put(&self, key: &str, bytes: &[u8]) -> Result<bool> {
        self.lock()?.put(key, bytes)
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
                                    &address.to_string(),
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
                                serve_connection(&mut stream, &service, &stop, "unix");
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

    pub fn stop(mut self) {
        self.stop.store(true, Ordering::Relaxed);
        for join in self.joins.drain(..) {
            let _ = join.join();
        }
        for path in &self.cleanup {
            if let Ok(metadata) = fs::symlink_metadata(path)
                && metadata.file_type().is_socket()
            {
                let _ = fs::remove_file(path);
            }
        }
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

fn serve_connection(stream: &mut Stream, service: &Service, stop: &AtomicBool, peer: &str) {
    while !stop.load(Ordering::Relaxed) {
        let frame = match read_frame(stream, MAX_CONTROL) {
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
            let _ = send_response(stream, None, error_response(401, "invalid token"));
            return;
        }
        let body = match &envelope.request {
            Request::Put { size, .. } => {
                if *size > MAX_OBJECT {
                    let _ =
                        send_response(stream, None, error_response(413, "object exceeds 64 MiB"));
                    continue;
                }
                match read_frame(stream, MAX_OBJECT as usize) {
                    Ok(Some(body)) => Some(body),
                    _ => {
                        let _ = send_response(stream, None, error_response(400, "missing body"));
                        return;
                    }
                }
            }
            _ => None,
        };
        let (response, out) = service.handle(&envelope.request, body.as_deref());
        if send_response(stream, out.as_deref(), response).is_err() {
            return;
        }
        let _ = peer;
    }
}

fn send_response(stream: &mut Stream, body: Option<&[u8]>, response: Response) -> Result<()> {
    let envelope = ResponseEnvelope {
        schema: PROTOCOL.into(),
        response,
    };
    write_frame(stream, &serde_json::to_vec(&envelope)?, MAX_CONTROL)?;
    if let Some(body) = body {
        write_frame(stream, body, MAX_OBJECT as usize)?;
    }
    Ok(())
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
    let mut assemblies: std::collections::HashMap<String, Assembly> =
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
        let key = format!("{addr:?}");
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
                if let Request::Put { size, .. } = &envelope.request {
                    if *size > MAX_OBJECT {
                        let _ = send_datagram(
                            socket,
                            &addr,
                            id,
                            error_response(413, "object exceeds 64 MiB"),
                            None,
                        );
                        continue;
                    }
                    let expected = *size as usize;
                    if expected == 0 {
                        let (response, out) = service.handle(&envelope.request, Some(&[]));
                        let _ = send_datagram(socket, &addr, id, response, out);
                        continue;
                    }
                    let total = expected.div_ceil(CHUNK) as u32;
                    if assemblies.len() >= MAX_ASSEMBLIES
                        && let Some(oldest) = assemblies
                            .values()
                            .min_by_key(|assembly| assembly.at)
                            .map(|assembly| format!("{:?}", assembly.addr))
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
                let _ = send_datagram(socket, &addr, id, response, out);
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
                    let _ = send_datagram(socket, &addr, id, response, out);
                }
            }
            _ => {}
        }
    }
}

#[cfg(unix)]
fn purge_assemblies(assemblies: &mut std::collections::HashMap<String, Assembly>) {
    let now = Instant::now();
    assemblies.retain(|_, assembly| now.duration_since(assembly.at) < ASSEMBLY_TTL);
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
        note: "Loopback only: TCP on 127.0.0.1, Unix stream and Unix datagram under a temporary directory.",
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
    let server = Server::bind(target, service, false)?;
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
    let digest = format!("{:x}", Sha256::digest(&data));
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
            parse_connection("rebsync+tcp://127.0.0.1:8787?token=abc123", None).unwrap();
        assert_eq!(
            target,
            Target::Tcp {
                host: "127.0.0.1".into(),
                port: 8787
            }
        );
        assert_eq!(token, "abc123");
        let (target, _) = parse_connection("unix:///run/rebsync.sock", Some("x9")).unwrap();
        assert_eq!(target.describe(), "unix:///run/rebsync.sock");
        let (target, _) = parse_connection("unix-dgram:///run/rebsync.dgram", Some("x9")).unwrap();
        assert_eq!(target.describe(), "unix-dgram:///run/rebsync.dgram");
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
        assert!(parse_datagram(b"RSD1").is_err());
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
        assert!(validate_token("a1B2").is_ok());
        assert!(validate_token("").is_err());
        assert!(validate_token("a b").is_err());
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
