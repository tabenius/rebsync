//! `rbq-peer/1` over QUIC (`quic://HOST:PORT`).
//!
//! The TCP transport is token-protected but plaintext: anyone on the path
//! reads the token and every object. QUIC carries the same requests inside
//! TLS 1.3 to a server whose key the client has pinned:
//!
//! * **The server is a key, not a name.** `rbq peer serve` keeps a long-term
//!   [`Identity`] (a self-signed certificate and its private key, owner-only
//!   files) and prints its peer id: the hex SHA-256 of the certificate's
//!   public key. A connection string carries it as `&peer=...`; a server
//!   presenting any other key fails the TLS handshake. There is no CA and no
//!   hostname check: the pin is the trust decision.
//! * **The token still authorises.** TLS proves who the server is and hides
//!   the traffic; the shared token, now never on the wire in clear, decides
//!   which clients may read and create objects, exactly as on TCP.
//! * **One QUIC stream per request**, with the same length-prefixed frames as
//!   the stream transport, so a lost packet stalls one request, not the link.
//!   Requests are bounded the same way: [`super::MAX_REQUEST`] before the
//!   token is checked, an authentication deadline per connection, the
//!   declared size for a `put` body, and [`super::MAX_CONNECTIONS`].
//!
//! Over a mesh or a lossy relay, QUIC also brings what the datagram transport
//! lacks: retransmission, congestion control and connection migration.

use super::{
    AUTH_DEADLINE, IO_TIMEOUT, Link, ListingPage, MAX_CONNECTIONS, MAX_CONTROL, MAX_LIST,
    MAX_OBJECT, MAX_REQUEST, PROTOCOL, Request, RequestEnvelope, Response, ResponseEnvelope,
    Server, Service, Status, Target, error_response,
};
use anyhow::{Context, Result, bail, ensure};
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::crypto::{CryptoProvider, WebPkiSupportedAlgorithms};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer, ServerName, UnixTime};
use rustls::{DigitallySignedStruct, SignatureScheme};
use std::{
    fs,
    io::Write,
    net::{SocketAddr, ToSocketAddrs},
    path::Path,
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, AtomicUsize, Ordering},
    },
    thread,
    time::Duration,
};

/// TLS needs a server name; the key pin makes its value irrelevant.
const SERVER_NAME: &str = "rbq";
/// Requests one connection may have in flight. A client sends one at a
/// time, and each request may hold a 64 MiB object in memory, so one stream
/// per connection keeps the server's worst case at the stream transport's:
/// [`MAX_CONNECTIONS`] objects.
const MAX_STREAMS: u32 = 1;
const IDLE_TIMEOUT: Duration = Duration::from_secs(60);
const KEEP_ALIVE: Duration = Duration::from_secs(15);
const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);
const CERT_FILE: &str = "cert.der";
const KEY_FILE: &str = "key.pkcs8.der";

fn provider() -> Arc<CryptoProvider> {
    Arc::new(rustls::crypto::ring::default_provider())
}

fn alpn() -> Vec<Vec<u8>> {
    vec![PROTOCOL.as_bytes().to_vec()]
}

/// The peer id of whoever presents this certificate: the lowercase hex
/// SHA-256 of its DER SubjectPublicKeyInfo. Reissuing a certificate for the
/// same key keeps the id.
pub fn peer_id_of_certificate(der: &[u8]) -> Result<String> {
    let certificate = CertificateDer::from(der);
    let parsed = webpki::EndEntityCert::try_from(&certificate)
        .map_err(|error| anyhow::anyhow!("unreadable certificate: {error}"))?;
    Ok(crate::wire::sha256_hex(
        parsed.subject_public_key_info().as_ref(),
    ))
}

/// A peer id is 64 hexadecimal characters.
pub fn validate_peer_id(id: &str) -> Result<()> {
    ensure!(
        id.len() == 64 && id.bytes().all(|b| b.is_ascii_hexdigit()),
        "a peer id is 64 hexadecimal characters"
    );
    Ok(())
}

/// Where `rbq peer serve` keeps its QUIC identity unless told otherwise:
/// `quic-identity/` under rbq's state directory.
pub fn default_identity_dir(config: &crate::Config) -> Result<std::path::PathBuf> {
    Ok(crate::sync::state_dir(config)?.join("quic-identity"))
}

/// A server's long-term QUIC identity.
pub struct Identity {
    certificate: CertificateDer<'static>,
    key: PrivatePkcs8KeyDer<'static>,
    peer: String,
}

impl std::fmt::Debug for Identity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Never print the key.
        f.debug_struct("Identity")
            .field("peer", &self.peer)
            .finish_non_exhaustive()
    }
}

impl Identity {
    /// A fresh identity (ECDSA P-256), not stored anywhere.
    pub fn generate() -> Result<Self> {
        let generated = rcgen::generate_simple_self_signed(vec![SERVER_NAME.to_owned()])
            .context("generate a QUIC identity")?;
        Self::from_der(
            generated.cert.der().to_vec(),
            generated.signing_key.serialize_der(),
        )
    }

    /// Restore from a DER certificate and a PKCS#8 DER key; the pair is
    /// checked by building a TLS configuration from it.
    pub fn from_der(certificate: Vec<u8>, pkcs8_key: Vec<u8>) -> Result<Self> {
        let identity = Self {
            peer: peer_id_of_certificate(&certificate)?,
            certificate: CertificateDer::from(certificate),
            key: PrivatePkcs8KeyDer::from(pkcs8_key),
        };
        tls_server(&identity).context("certificate and key do not match")?;
        Ok(identity)
    }

    /// Load the identity kept in `dir`, creating it on first use. The
    /// directory is owner-only, the key file is refused if group- or
    /// world-readable, and an existing identity is never replaced.
    pub fn load_or_create(dir: &Path) -> Result<Self> {
        let (cert_path, key_path) = (dir.join(CERT_FILE), dir.join(KEY_FILE));
        if cert_path.exists() || key_path.exists() {
            let key_file = fs::File::open(&key_path)
                .with_context(|| format!("open QUIC key {}", key_path.display()))?;
            crate::wire::ensure_private_file(&key_path, &key_file.metadata()?)?;
            let key = crate::wire::read_bounded(key_file, 16 * 1024)?
                .context("QUIC key file is too large")?;
            let certificate = crate::wire::read_bounded(fs::File::open(&cert_path)?, 64 * 1024)?
                .context("QUIC certificate file is too large")?;
            return Self::from_der(certificate, key);
        }
        fs::create_dir_all(dir)
            .with_context(|| format!("create QUIC identity directory {}", dir.display()))?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(dir, fs::Permissions::from_mode(0o700))?;
        }
        let identity = Self::generate()?;
        write_new(&key_path, identity.private_key_der(), true)?;
        write_new(&cert_path, identity.certificate_der(), false)?;
        Ok(identity)
    }

    pub fn peer_id(&self) -> &str {
        &self.peer
    }

    pub fn certificate_der(&self) -> &[u8] {
        &self.certificate
    }

    /// The private key. Store it owner-only.
    pub fn private_key_der(&self) -> &[u8] {
        self.key.secret_pkcs8_der()
    }

    fn key(&self) -> PrivateKeyDer<'static> {
        PrivateKeyDer::Pkcs8(self.key.clone_key())
    }
}

/// Create a file that must not exist yet; private files are 0600 from the
/// first byte rather than restricted after writing.
fn write_new(path: &Path, bytes: &[u8], private: bool) -> Result<()> {
    let mut options = fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(if private { 0o600 } else { 0o644 });
    }
    #[cfg(not(unix))]
    let _ = private;
    let mut file = options
        .open(path)
        .with_context(|| format!("create {}", path.display()))?;
    file.write_all(bytes)?;
    file.sync_all()?;
    Ok(())
}

fn transport_config() -> Arc<quinn::TransportConfig> {
    let mut config = quinn::TransportConfig::default();
    config
        .max_concurrent_bidi_streams(quinn::VarInt::from_u32(MAX_STREAMS))
        .max_concurrent_uni_streams(quinn::VarInt::from_u32(0))
        .keep_alive_interval(Some(KEEP_ALIVE))
        .max_idle_timeout(Some(
            quinn::IdleTimeout::try_from(IDLE_TIMEOUT).expect("60 s fits a QUIC idle timeout"),
        ));
    Arc::new(config)
}

fn tls_server(identity: &Identity) -> Result<rustls::ServerConfig> {
    let mut tls = rustls::ServerConfig::builder_with_provider(provider())
        .with_protocol_versions(&[&rustls::version::TLS13])?
        .with_no_client_auth()
        .with_single_cert(vec![identity.certificate.clone()], identity.key())?;
    tls.alpn_protocols = alpn();
    Ok(tls)
}

/// Accepts exactly the pinned server key, and checks the handshake signature,
/// which proves the server holds that key.
#[derive(Debug)]
struct PinnedServer {
    expected: String,
    seen: Mutex<Option<String>>,
    algorithms: WebPkiSupportedAlgorithms,
}

impl ServerCertVerifier for PinnedServer {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        let presented = peer_id_of_certificate(end_entity).map_err(|_| {
            rustls::Error::InvalidCertificate(rustls::CertificateError::BadEncoding)
        })?;
        if let Ok(mut seen) = self.seen.lock() {
            *seen = Some(presented.clone());
        }
        if presented == self.expected {
            Ok(ServerCertVerified::assertion())
        } else {
            Err(rustls::Error::InvalidCertificate(
                rustls::CertificateError::ApplicationVerificationFailure,
            ))
        }
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        Err(rustls::Error::PeerIncompatible(
            rustls::PeerIncompatible::Tls12NotOffered,
        ))
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls13_signature(message, cert, dss, &self.algorithms)
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.algorithms.supported_schemes()
    }
}

// ---------------------------------------------------------------------------
// Framing over QUIC streams (the same frames as the stream transport)
// ---------------------------------------------------------------------------

async fn read_frame(recv: &mut quinn::RecvStream, max: usize) -> Result<Option<Vec<u8>>> {
    let mut header = [0_u8; 4];
    match recv.read_exact(&mut header).await {
        Ok(()) => {}
        Err(quinn::ReadExactError::FinishedEarly(0)) => return Ok(None),
        Err(quinn::ReadExactError::FinishedEarly(_)) => bail!("truncated frame header"),
        Err(error) => return Err(error.into()),
    }
    let length = u32::from_be_bytes(header) as usize;
    ensure!(
        length <= max,
        "frame of {length} bytes exceeds the {max} byte limit"
    );
    let mut body = vec![0_u8; length];
    recv.read_exact(&mut body)
        .await
        .context("truncated frame")?;
    Ok(Some(body))
}

async fn write_frame(send: &mut quinn::SendStream, bytes: &[u8], max: usize) -> Result<()> {
    ensure!(
        bytes.len() <= max && bytes.len() <= u32::MAX as usize,
        "frame of {} bytes exceeds the {max} byte limit",
        bytes.len()
    );
    send.write_all(&(bytes.len() as u32).to_be_bytes()).await?;
    send.write_all(bytes).await?;
    Ok(())
}

// ---------------------------------------------------------------------------
// Client
// ---------------------------------------------------------------------------

/// A client link. It owns a small runtime so the synchronous [`Link`] API
/// (used by push and pull) can drive QUIC.
pub struct QuicLink {
    runtime: tokio::runtime::Runtime,
    endpoint: quinn::Endpoint,
    conn: quinn::Connection,
    token: String,
    description: String,
}

impl QuicLink {
    pub fn connect(host: &str, port: u16, peer: &str, token: String) -> Result<Self> {
        validate_peer_id(peer)?;
        let addresses: Vec<SocketAddr> = (host, port)
            .to_socket_addrs()
            .with_context(|| format!("resolve {host}:{port}"))?
            .collect();
        ensure!(!addresses.is_empty(), "no address for {host}:{port}");
        let runtime = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(1)
            .thread_name("rbq-quic")
            .enable_all()
            .build()
            .context("start the QUIC runtime")?;
        let verifier = Arc::new(PinnedServer {
            expected: peer.to_ascii_lowercase(),
            seen: Mutex::new(None),
            algorithms: provider().signature_verification_algorithms,
        });
        let mut tls = rustls::ClientConfig::builder_with_provider(provider())
            .with_protocol_versions(&[&rustls::version::TLS13])?
            .dangerous()
            .with_custom_certificate_verifier(verifier.clone())
            .with_no_client_auth();
        tls.alpn_protocols = alpn();
        let crypto = quinn::crypto::rustls::QuicClientConfig::try_from(tls)?;
        let mut config = quinn::ClientConfig::new(Arc::new(crypto));
        config.transport_config(transport_config());

        let (endpoint, conn) = runtime
            .block_on(async {
                let mut last = None;
                for address in addresses {
                    let local: SocketAddr = if address.is_ipv6() {
                        "[::]:0".parse().expect("valid address")
                    } else {
                        "0.0.0.0:0".parse().expect("valid address")
                    };
                    let endpoint = quinn::Endpoint::client(local).context("open a UDP socket")?;
                    let attempt = async {
                        endpoint
                            .connect_with(config.clone(), address, SERVER_NAME)?
                            .await
                            .map_err(anyhow::Error::from)
                    };
                    match tokio::time::timeout(CONNECT_TIMEOUT, attempt).await {
                        Ok(Ok(conn)) => return Ok((endpoint, conn)),
                        Ok(Err(error)) => last = Some(error),
                        Err(_) => {
                            last = Some(anyhow::anyhow!(
                                "no QUIC handshake within {CONNECT_TIMEOUT:?}"
                            ))
                        }
                    }
                }
                Err(last.unwrap_or_else(|| anyhow::anyhow!("cannot connect")))
            })
            .map_err(|error| {
                // Say why the handshake failed when it was the pin.
                match verifier.seen.lock().ok().and_then(|seen| seen.clone()) {
                    Some(seen) if seen != verifier.expected => anyhow::anyhow!(
                        "quic://{host}:{port} presented peer {seen}, not the pinned {}; refusing",
                        verifier.expected
                    ),
                    _ => error.context(format!("connect quic://{host}:{port}")),
                }
            })?;
        Ok(Self {
            runtime,
            endpoint,
            conn,
            token,
            description: Target::Quic {
                host: host.into(),
                port,
                peer: None,
            }
            .describe(),
        })
    }

    fn exchange(
        &mut self,
        request: Request,
        body: Option<&[u8]>,
    ) -> Result<(Response, Option<Vec<u8>>)> {
        let envelope = serde_json::to_vec(&RequestEnvelope {
            schema: PROTOCOL.into(),
            token: self.token.clone(),
            request,
        })?;
        let conn = self.conn.clone();
        self.runtime.block_on(async move {
            tokio::time::timeout(IO_TIMEOUT, async {
                let (mut send, mut recv) = conn.open_bi().await?;
                write_frame(&mut send, &envelope, MAX_REQUEST).await?;
                if let Some(body) = body {
                    write_frame(&mut send, body, MAX_OBJECT as usize).await?;
                }
                send.finish()?;
                let frame = read_frame(&mut recv, MAX_CONTROL)
                    .await?
                    .context("peer closed the stream without a response")?;
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
                        let body = read_frame(&mut recv, size as usize)
                            .await?
                            .context("peer closed before sending the object body")?;
                        ensure!(body.len() as u64 == size, "object body length mismatch");
                        Ok((Response::Object { size }, Some(body)))
                    }
                    Response::Error { code, message } => bail!("peer error {code}: {message}"),
                    other => Ok((other, None)),
                }
            })
            .await
            .map_err(|_| anyhow::anyhow!("peer did not answer within {IO_TIMEOUT:?}"))?
        })
    }
}

impl Drop for QuicLink {
    fn drop(&mut self) {
        self.conn.close(quinn::VarInt::from_u32(0), b"done");
        // Let the close frame leave before the runtime goes away.
        let endpoint = self.endpoint.clone();
        self.runtime.block_on(async move {
            let _ = tokio::time::timeout(Duration::from_secs(1), endpoint.wait_idle()).await;
        });
    }
}

impl Link for QuicLink {
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
// Server
// ---------------------------------------------------------------------------

impl Server {
    /// Serve `service` on `quic://host:port` as `identity`. The returned
    /// target carries the peer id clients must pin.
    pub fn bind_quic(host: &str, port: u16, service: Service, identity: &Identity) -> Result<Self> {
        let address = (host, port)
            .to_socket_addrs()
            .with_context(|| format!("resolve {host}:{port}"))?
            .next()
            .with_context(|| format!("no address for {host}:{port}"))?;
        let crypto = quinn::crypto::rustls::QuicServerConfig::try_from(tls_server(identity)?)?;
        let mut config = quinn::ServerConfig::with_crypto(Arc::new(crypto));
        config.transport_config(transport_config());
        let runtime = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(2)
            .thread_name("rbq-quic-serve")
            .enable_all()
            .build()
            .context("start the QUIC runtime")?;
        let endpoint = {
            let _entered = runtime.enter();
            quinn::Endpoint::server(config, address)
                .with_context(|| format!("listen quic://{host}:{port}"))?
        };
        let bound = endpoint.local_addr()?;
        let stop = Arc::new(AtomicBool::new(false));
        let join = {
            let stop = stop.clone();
            thread::spawn(move || {
                // Storage may own a runtime of its own (object_store), and a
                // runtime must never be dropped inside async code. Keep the
                // last reference here, on a plain thread, until the QUIC
                // runtime and every task holding a clone are gone.
                let keep = service.clone();
                runtime.block_on(serve(endpoint, service, stop));
                drop(runtime);
                drop(keep);
            })
        };
        Ok(Self {
            stop,
            joins: vec![join],
            cleanup: Vec::new(),
            target: Target::Quic {
                host: bound.ip().to_string(),
                port: bound.port(),
                peer: Some(identity.peer_id().to_owned()),
            },
        })
    }
}

async fn serve(endpoint: quinn::Endpoint, service: Service, stop: Arc<AtomicBool>) {
    let active = Arc::new(AtomicUsize::new(0));
    let mut ticker = tokio::time::interval(Duration::from_millis(100));
    loop {
        tokio::select! {
            incoming = endpoint.accept() => {
                let Some(incoming) = incoming else { break };
                if active.fetch_add(1, Ordering::SeqCst) >= MAX_CONNECTIONS {
                    active.fetch_sub(1, Ordering::SeqCst);
                    incoming.refuse();
                    continue;
                }
                let (service, active) = (service.clone(), active.clone());
                tokio::spawn(async move {
                    if let Ok(Ok(conn)) = tokio::time::timeout(AUTH_DEADLINE, incoming).await {
                        serve_connection(conn, service).await;
                    }
                    active.fetch_sub(1, Ordering::SeqCst);
                });
            }
            _ = ticker.tick() => {
                if stop.load(Ordering::Relaxed) {
                    break;
                }
            }
        }
    }
    endpoint.close(quinn::VarInt::from_u32(0), b"server stopping");
    let _ = tokio::time::timeout(Duration::from_secs(1), endpoint.wait_idle()).await;
}

/// Serve one connection's requests. A connection must authenticate within
/// [`AUTH_DEADLINE`] of the handshake, and one bad token ends it.
async fn serve_connection(conn: quinn::Connection, service: Service) {
    let authenticated = Arc::new(AtomicBool::new(false));
    {
        let (conn, authenticated) = (conn.clone(), authenticated.clone());
        tokio::spawn(async move {
            tokio::time::sleep(AUTH_DEADLINE).await;
            if !authenticated.load(Ordering::SeqCst) {
                conn.close(quinn::VarInt::from_u32(1), b"no authenticated request");
            }
        });
    }
    while let Ok((send, recv)) = conn.accept_bi().await {
        let (conn, service, authenticated) = (conn.clone(), service.clone(), authenticated.clone());
        tokio::spawn(async move {
            match serve_stream(send, recv, service, &authenticated).await {
                Ok(true) => {}
                Ok(false) => conn.close(quinn::VarInt::from_u32(2), b"invalid token"),
                Err(_) => {}
            }
        });
    }
}

/// One request. `Ok(false)` means the token was wrong and the connection
/// should end.
async fn serve_stream(
    mut send: quinn::SendStream,
    mut recv: quinn::RecvStream,
    service: Service,
    authenticated: &AtomicBool,
) -> Result<bool> {
    let deadline = if authenticated.load(Ordering::SeqCst) {
        IO_TIMEOUT
    } else {
        AUTH_DEADLINE
    };
    let Some(frame) = tokio::time::timeout(deadline, read_frame(&mut recv, MAX_REQUEST))
        .await
        .context("request deadline passed")??
    else {
        return Ok(true);
    };
    let envelope: RequestEnvelope = match serde_json::from_slice(&frame) {
        Ok(envelope) => envelope,
        Err(error) => {
            respond(
                &mut send,
                error_response(400, format!("malformed request: {error}")),
                None,
            )
            .await?;
            return Ok(true);
        }
    };
    if envelope.schema != PROTOCOL {
        respond(
            &mut send,
            error_response(400, format!("expected schema {PROTOCOL}")),
            None,
        )
        .await?;
        return Ok(true);
    }
    if !service.authorize(&envelope.token) {
        let _ = respond(&mut send, error_response(401, "invalid token"), None).await;
        return Ok(false);
    }
    authenticated.store(true, Ordering::SeqCst);
    let body = match &envelope.request {
        Request::Put { size, .. } => {
            if *size > MAX_OBJECT {
                respond(
                    &mut send,
                    error_response(413, "object exceeds 64 MiB"),
                    None,
                )
                .await?;
                return Ok(true);
            }
            match tokio::time::timeout(IO_TIMEOUT, read_frame(&mut recv, *size as usize)).await {
                Ok(Ok(Some(body))) => Some(body),
                _ => {
                    respond(
                        &mut send,
                        error_response(400, "missing or oversized body"),
                        None,
                    )
                    .await?;
                    return Ok(true);
                }
            }
        }
        _ => None,
    };
    let request = envelope.request;
    // Storage is blocking I/O; keep it off the runtime's workers.
    let (response, out) =
        tokio::task::spawn_blocking(move || service.handle(&request, body.as_deref())).await?;
    respond(&mut send, response, out).await?;
    Ok(true)
}

async fn respond(
    send: &mut quinn::SendStream,
    response: Response,
    body: Option<Vec<u8>>,
) -> Result<()> {
    let envelope = serde_json::to_vec(&ResponseEnvelope {
        schema: PROTOCOL.into(),
        response,
    })?;
    tokio::time::timeout(IO_TIMEOUT, async {
        write_frame(send, &envelope, MAX_CONTROL).await?;
        if let Some(body) = body {
            write_frame(send, &body, MAX_OBJECT as usize).await?;
        }
        send.finish()?;
        // Wait until the peer has the whole reply (or gave up), so dropping
        // the stream cannot cut it short.
        let _ = send.stopped().await;
        Ok::<(), anyhow::Error>(())
    })
    .await
    .context("peer did not read the reply in time")?
}

#[cfg(test)]
mod tests {
    use super::*;

    fn token() -> String {
        "quicToken42".into()
    }

    fn server(root: &Path) -> (Server, String) {
        let storage = crate::FsObjectStorage::open(root.join("store")).unwrap();
        let service = Service::new(Arc::new(storage), token(), Arc::new(AtomicBool::new(false)));
        let identity = Identity::generate().unwrap();
        let server = Server::bind_quic("127.0.0.1", 0, service, &identity).unwrap();
        (server, identity.peer_id().to_owned())
    }

    fn port(server: &Server) -> u16 {
        match &server.target {
            Target::Quic { port, .. } => *port,
            _ => unreachable!(),
        }
    }

    #[test]
    fn identities_persist_owner_only_and_ids_are_key_hashes() {
        let root = tempfile::tempdir().unwrap();
        let dir = root.path().join("quic");
        let first = Identity::load_or_create(&dir).unwrap();
        let again = Identity::load_or_create(&dir).unwrap();
        assert_eq!(first.peer_id(), again.peer_id());
        validate_peer_id(first.peer_id()).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = fs::metadata(dir.join(KEY_FILE))
                .unwrap()
                .permissions()
                .mode();
            assert_eq!(mode & 0o077, 0, "key file must be owner-only");
            // A readable key is refused rather than used.
            fs::set_permissions(dir.join(KEY_FILE), fs::Permissions::from_mode(0o644)).unwrap();
            assert!(Identity::load_or_create(&dir).is_err());
        }
        // The id is the key's: a reissued certificate keeps it.
        let key = rcgen::KeyPair::try_from(first.private_key_der()).unwrap();
        let reissued = rcgen::CertificateParams::new(vec!["elsewhere".to_owned()])
            .unwrap()
            .self_signed(&key)
            .unwrap();
        assert_eq!(
            peer_id_of_certificate(reissued.der()).unwrap(),
            first.peer_id()
        );
        assert!(!format!("{first:?}").contains("key:"));
        assert!(validate_peer_id("abc").is_err());
    }

    #[test]
    fn status_put_get_and_list_over_quic() {
        let root = tempfile::tempdir().unwrap();
        let (server, peer) = server(root.path());
        let mut link = QuicLink::connect("127.0.0.1", port(&server), &peer, token()).unwrap();
        assert_eq!(link.status().unwrap().protocol, PROTOCOL);
        let digest = crate::wire::sha256_hex(b"hello");
        let key = format!("mneme/v1/chunks/sha256/{}/{digest}", &digest[..2]);
        assert!(link.put(&key, b"hello").unwrap());
        assert!(!link.put(&key, b"hello").unwrap(), "create-if-absent");
        assert_eq!(link.get(&key).unwrap(), b"hello");
        let page = link.list("mneme/", "", 10).unwrap();
        assert_eq!(page.items.len(), 1);
        assert!(
            link.put(&key.replace(&digest, &"0".repeat(64)), b"hello")
                .is_err()
        );
        drop(link);
        assert!(server.shutdown(), "the QUIC server thread must not panic");
    }

    #[test]
    fn a_server_with_another_key_is_refused() {
        let root = tempfile::tempdir().unwrap();
        let (server, _) = server(root.path());
        let impostor = Identity::generate().unwrap();
        let error = QuicLink::connect("127.0.0.1", port(&server), impostor.peer_id(), token())
            .err()
            .expect("a wrong pin must fail the handshake");
        assert!(format!("{error:#}").contains("not the pinned"), "{error:#}");
        assert!(server.shutdown(), "the QUIC server thread must not panic");
    }

    #[test]
    fn a_wrong_token_is_refused_and_ends_the_connection() {
        let root = tempfile::tempdir().unwrap();
        let (server, peer) = server(root.path());
        let mut link =
            QuicLink::connect("127.0.0.1", port(&server), &peer, "wrong".into()).unwrap();
        let error = link.status().expect_err("bad token");
        assert!(format!("{error:#}").contains("401"), "{error:#}");
        assert!(
            link.status().is_err(),
            "the connection is closed after a bad token"
        );
        drop(link);
        assert!(server.shutdown(), "the QUIC server thread must not panic");
    }

    #[test]
    fn an_idle_unauthenticated_connection_is_closed_at_the_deadline() {
        let root = tempfile::tempdir().unwrap();
        let (server, peer) = server(root.path());
        let link = QuicLink::connect("127.0.0.1", port(&server), &peer, token()).unwrap();
        let conn = link.conn.clone();
        let closed = link.runtime.block_on(async {
            tokio::time::timeout(AUTH_DEADLINE + Duration::from_secs(3), conn.closed()).await
        });
        assert!(
            closed.is_ok(),
            "the server must close a connection that never authenticates"
        );
        drop(link);
        assert!(server.shutdown(), "the QUIC server thread must not panic");
    }

    #[test]
    fn the_selftest_path_pushes_and_pulls_over_quic() {
        let check = super::super::run_check(
            "quic",
            Target::Quic {
                host: "127.0.0.1".into(),
                port: 0,
                peer: None,
            },
        );
        assert!(check.ok, "{:?}", check.error);
        assert!(check.verified > 0);
    }

    #[test]
    fn connection_strings_require_a_pin() {
        let peer = "ab".repeat(32);
        let (target, token) = crate::transport::parse_connection(
            &format!("rbq+quic://10.0.0.2:7000?token=t0k&peer={peer}"),
            None,
        )
        .unwrap();
        assert_eq!(token, "t0k");
        assert_eq!(
            target,
            Target::Quic {
                host: "10.0.0.2".into(),
                port: 7000,
                peer: Some(peer),
            }
        );
        assert!(
            crate::transport::parse_connection("quic://10.0.0.2:7000?token=t0k", None).is_err()
        );
        assert!(
            crate::transport::parse_connection("quic://10.0.0.2:7000?token=t0k&peer=xyz", None)
                .is_err()
        );
        assert!(!target.is_public());
    }
}
