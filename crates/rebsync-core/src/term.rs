//! Operator terminal: a login shell in the browser over the fleet mesh.
//!
//! `rbq term serve` listens on a NetBird/Tailscale address (100.64.0.0/10,
//! fd7a:115c:a1e0::/48) or, for local use, loopback. WireGuard encrypts and
//! authenticates the link; the caller's mesh identity (Tailscale login via
//! `tailscale whois`, NetBird peer name via `netbird status`) is checked
//! against `term.operators`. That list is the authorisation, so it works on the
//! free tiers of either mesh without their RBAC products.
//!
//! Sessions behave like mosh: the shell runs in a PTY that outlives the
//! connection, every output byte has an offset, and a client reconnects with
//! the offset it needs next. Nothing is lost while the buffer holds it, and
//! nothing is shown twice. Native `mosh`/`ssh` over the mesh remain the
//! terminal-client path; this is the browser path.
//!
//! Browser safety: the WebSocket requires an `Origin` equal to the page's own
//! origin and a `Host` that is this listener or a configured name, so another
//! site open in the operator's browser cannot ride the operator's mesh
//! identity (cross-site WebSocket hijacking, DNS rebinding).
use anyhow::{Context, Result, bail, ensure};
use serde_json::{Value, json};
use std::{
    collections::{HashMap, VecDeque},
    fs::File,
    io::{ErrorKind, Read, Write},
    net::{IpAddr, SocketAddr, TcpListener, TcpStream},
    os::fd::{AsRawFd, FromRawFd, OwnedFd},
    process::{Child, Command, Stdio},
    sync::{Arc, Condvar, Mutex},
    thread,
    time::{Duration, Instant},
};
use tungstenite::{
    Message, WebSocket,
    handshake::server::{ErrorResponse, Request, Response},
    http::StatusCode,
};

/// Output kept per session for resuming, in bytes.
pub const RING_BYTES: usize = 1 << 20;
const MAX_SESSIONS: usize = 32;
const MAX_SESSIONS_PER_IDENTITY: usize = 8;
const DETACHED_LIFETIME: Duration = Duration::from_secs(24 * 3600);
const EXITED_LINGER: Duration = Duration::from_secs(60);
const PING_EVERY: Duration = Duration::from_secs(15);
const MAX_INPUT_BYTES: usize = 64 * 1024;
const IDENTITY_TTL: Duration = Duration::from_secs(60);

pub use crate::config::TermConfig;

/// A caller's identity on the mesh, or None when it cannot be established.
pub trait Identify: Send + Sync {
    fn identify(&self, ip: IpAddr) -> Option<String>;
}

/// Ask the local Tailscale and NetBird daemons who a peer address belongs to.
pub struct MeshIdentity {
    timeout: u64,
    cache: Mutex<HashMap<IpAddr, (Instant, Option<String>)>>,
}

impl Default for MeshIdentity {
    fn default() -> Self {
        Self {
            timeout: 5,
            cache: Mutex::new(HashMap::new()),
        }
    }
}

impl Identify for MeshIdentity {
    fn identify(&self, ip: IpAddr) -> Option<String> {
        if let Some((at, found)) = self.cache.lock().ok()?.get(&ip)
            && at.elapsed() < IDENTITY_TTL
        {
            return found.clone();
        }
        let run = |program: &str, args: &[String]| {
            let mut cmd = crate::process::command(program);
            cmd.args(args);
            crate::process::checked(&mut cmd, self.timeout).ok()
        };
        let found = run(
            "tailscale",
            &["whois".into(), "--json".into(), ip.to_string()],
        )
        .and_then(|out| tailscale_identity(&out))
        .or_else(|| {
            run("netbird", &["status".into(), "--json".into()])
                .and_then(|out| netbird_identity(&out, ip))
        });
        if let Ok(mut cache) = self.cache.lock() {
            cache.insert(ip, (Instant::now(), found.clone()));
        }
        found
    }
}

/// `tailscale whois --json` → `tailscale:<UserProfile.LoginName>`. Tagged
/// devices have no user login and are not operators.
pub fn tailscale_identity(json: &[u8]) -> Option<String> {
    let value: Value = serde_json::from_slice(json).ok()?;
    let login = value.pointer("/UserProfile/LoginName")?.as_str()?;
    (!login.is_empty() && login != "tagged-devices").then(|| format!("tailscale:{login}"))
}

/// `netbird status --json` → `netbird:<fqdn>` of the peer with this address.
pub fn netbird_identity(json: &[u8], ip: IpAddr) -> Option<String> {
    let value: Value = serde_json::from_slice(json).ok()?;
    value
        .pointer("/peers/details")?
        .as_array()?
        .iter()
        .find(|peer| {
            peer.get("netbirdIp")
                .and_then(Value::as_str)
                .and_then(|text| text.split('/').next())
                .and_then(|text| text.parse::<IpAddr>().ok())
                == Some(ip)
        })
        .and_then(|peer| peer.get("fqdn")?.as_str())
        .filter(|fqdn| !fqdn.is_empty())
        .map(|fqdn| format!("netbird:{}", fqdn.trim_end_matches('.')))
}

/// Mesh (CGNAT 100.64.0.0/10, Tailscale fd7a:115c:a1e0::/48) or loopback.
pub fn bind_allowed(ip: IpAddr, allow_loopback: bool) -> bool {
    match ip {
        IpAddr::V4(v4) => {
            let [a, b, ..] = v4.octets();
            (a == 100 && (64..128).contains(&b)) || (allow_loopback && v4.is_loopback())
        }
        IpAddr::V6(v6) => {
            let s = v6.segments();
            (s[0] == 0xfd7a && s[1] == 0x115c && s[2] == 0xa1e0)
                || (allow_loopback && v6.is_loopback())
        }
    }
}

/// Output history with absolute byte offsets.
#[derive(Default)]
pub struct Ring {
    data: VecDeque<u8>,
    start: u64,
}

impl Ring {
    pub fn push(&mut self, bytes: &[u8]) {
        self.data.extend(bytes);
        let excess = self.data.len().saturating_sub(RING_BYTES);
        self.data.drain(..excess);
        self.start += excess as u64;
    }
    pub fn start(&self) -> u64 {
        self.start
    }
    pub fn end(&self) -> u64 {
        self.start + self.data.len() as u64
    }
    /// Up to `max` bytes from `offset`, which must lie in `start..=end`.
    pub fn read_from(&self, offset: u64, max: usize) -> Vec<u8> {
        let skip = (offset.saturating_sub(self.start)) as usize;
        self.data.iter().skip(skip).take(max).copied().collect()
    }
}

struct Shared {
    ring: Ring,
    exit: Option<i32>,
    attached: usize,
    detached_at: Instant,
}

pub struct Session {
    pub id: String,
    pub owner: String,
    master: File,
    child: Mutex<Child>,
    shared: Mutex<Shared>,
    changed: Condvar,
}

fn set_size(fd: &File, cols: u16, rows: u16) {
    let size = libc::winsize {
        ws_row: rows.clamp(2, 1000),
        ws_col: cols.clamp(2, 1000),
        ws_xpixel: 0,
        ws_ypixel: 0,
    };
    // SAFETY: TIOCSWINSZ reads one winsize from a valid pointer on a PTY fd.
    unsafe { libc::ioctl(fd.as_raw_fd(), libc::TIOCSWINSZ, &size) };
}

impl Session {
    /// Start a login shell on a new PTY, running as this process's user.
    pub fn spawn(
        id: String,
        owner: String,
        shell: &str,
        cols: u16,
        rows: u16,
    ) -> Result<Arc<Self>> {
        let (mut master, mut slave) = (0, 0);
        // SAFETY: openpty writes two fds; null name/termios/winsize are allowed.
        let rc = unsafe {
            libc::openpty(
                &mut master,
                &mut slave,
                std::ptr::null_mut(),
                std::ptr::null(),
                std::ptr::null(),
            )
        };
        ensure!(
            rc == 0,
            "openpty failed: {}",
            std::io::Error::last_os_error()
        );
        // SAFETY: both fds were just returned by openpty and are owned here.
        let (master, slave) = unsafe { (File::from_raw_fd(master), OwnedFd::from_raw_fd(slave)) };
        set_size(&master, cols, rows);
        let stdio = |fd: &OwnedFd| -> Result<Stdio> { Ok(Stdio::from(fd.try_clone()?)) };
        let mut command = Command::new(shell);
        command
            .arg("-l")
            .env("TERM", "xterm-256color")
            .env("COLORTERM", "truecolor")
            .env("RBQ_TERM_SESSION", &id)
            .stdin(stdio(&slave)?)
            .stdout(stdio(&slave)?)
            .stderr(stdio(&slave)?);
        if let Ok(home) = std::env::var("HOME") {
            command.current_dir(home);
        }
        {
            use std::os::unix::process::CommandExt;
            // SAFETY: only async-signal-safe calls between fork and exec.
            unsafe {
                command.pre_exec(|| {
                    if libc::setsid() < 0 || libc::ioctl(0, libc::TIOCSCTTY as _, 0) < 0 {
                        return Err(std::io::Error::last_os_error());
                    }
                    Ok(())
                });
            }
        }
        let child = command.spawn().with_context(|| format!("start {shell}"))?;
        drop(slave);
        let session = Arc::new(Self {
            id,
            owner,
            master,
            child: Mutex::new(child),
            shared: Mutex::new(Shared {
                ring: Ring::default(),
                exit: None,
                attached: 0,
                detached_at: Instant::now(),
            }),
            changed: Condvar::new(),
        });
        let reader = Arc::clone(&session);
        thread::spawn(move || reader.pump());
        Ok(session)
    }

    /// Copy PTY output into the ring until the shell side closes.
    fn pump(&self) {
        let mut master = match self.master.try_clone() {
            Ok(file) => file,
            Err(_) => return,
        };
        let mut buffer = [0_u8; 16 * 1024];
        loop {
            match master.read(&mut buffer) {
                Ok(0) => break,
                Ok(n) => {
                    if let Ok(mut shared) = self.shared.lock() {
                        shared.ring.push(&buffer[..n]);
                    }
                    self.changed.notify_all();
                }
                Err(error) if error.kind() == ErrorKind::Interrupted => continue,
                Err(_) => break, // EIO once every slave fd is closed
            }
        }
        let code = self
            .child
            .lock()
            .ok()
            .and_then(|mut child| child.wait().ok())
            .map_or(-1, |status| status.code().unwrap_or(-1));
        if let Ok(mut shared) = self.shared.lock() {
            shared.exit = Some(code);
            shared.detached_at = Instant::now();
        }
        self.changed.notify_all();
    }

    pub fn write_input(&self, bytes: &[u8]) -> std::io::Result<()> {
        (&self.master).write_all(bytes)
    }

    pub fn resize(&self, cols: u16, rows: u16) {
        set_size(&self.master, cols, rows);
    }

    fn kill(&self) {
        if let Ok(mut child) = self.child.lock() {
            let _ = child.kill();
        }
    }
}

/// All sessions of one server, keyed by id.
#[derive(Default)]
pub struct Sessions {
    map: Mutex<HashMap<String, Arc<Session>>>,
}

impl Sessions {
    fn get(&self, id: &str, owner: &str) -> Option<Arc<Session>> {
        self.map
            .lock()
            .ok()?
            .get(id)
            .filter(|s| s.owner == owner)
            .cloned()
    }

    fn create(&self, owner: &str, shell: &str, cols: u16, rows: u16) -> Result<Arc<Session>> {
        let mut map = self
            .map
            .lock()
            .map_err(|_| anyhow::anyhow!("session table poisoned"))?;
        ensure!(
            map.len() < MAX_SESSIONS,
            "too many terminal sessions on this host"
        );
        ensure!(
            map.values().filter(|s| s.owner == owner).count() < MAX_SESSIONS_PER_IDENTITY,
            "too many terminal sessions for {owner}"
        );
        let mut id = [0_u8; 16];
        File::open("/dev/urandom")?.read_exact(&mut id)?;
        let id: String = id.iter().map(|b| format!("{b:02x}")).collect();
        let session = Session::spawn(id.clone(), owner.to_owned(), shell, cols, rows)?;
        map.insert(id, Arc::clone(&session));
        Ok(session)
    }

    /// Drop exited sessions after a short linger, and kill shells left
    /// detached for a day.
    pub fn reap(&self) {
        let Ok(mut map) = self.map.lock() else { return };
        map.retain(|_, session| {
            let Ok(shared) = session.shared.lock() else {
                return false;
            };
            if shared.attached > 0 {
                return true;
            }
            if shared.exit.is_some() {
                return shared.detached_at.elapsed() < EXITED_LINGER;
            }
            if shared.detached_at.elapsed() > DETACHED_LIFETIME {
                session.kill();
            }
            true
        });
    }
}

pub struct ServeOptions {
    pub bind: SocketAddr,
    pub allow_loopback: bool,
}

pub struct Server {
    config: TermConfig,
    identify: Box<dyn Identify>,
    sessions: Sessions,
    host_names: Vec<String>,
    allow_loopback: bool,
}

const INDEX: &str = include_str!("../assets/term/index.html");
const CLIENT: &str = include_str!("../assets/term/client.js");
const XTERM_JS: &str = include_str!("../assets/term/xterm.js");
const XTERM_CSS: &str = include_str!("../assets/term/xterm.css");
const FIT_JS: &str = include_str!("../assets/term/addon-fit.js");

impl Server {
    pub fn new(
        config: TermConfig,
        identify: Box<dyn Identify>,
        options: &ServeOptions,
    ) -> Result<Self> {
        ensure!(
            bind_allowed(options.bind.ip(), options.allow_loopback),
            "rbq term binds only to a NetBird/Tailscale address (100.64.0.0/10, fd7a:115c:a1e0::/48){}",
            if options.allow_loopback {
                " or loopback"
            } else {
                "; pass --allow-loopback for local use"
            }
        );
        let mut host_names = vec![options.bind.to_string()];
        host_names.extend(
            config
                .hostnames
                .iter()
                .map(|name| format!("{name}:{}", options.bind.port())),
        );
        Ok(Self {
            config,
            identify,
            sessions: Sessions::default(),
            host_names,
            allow_loopback: options.allow_loopback,
        })
    }

    fn shell(&self) -> String {
        self.config
            .shell
            .clone()
            .or_else(|| std::env::var("SHELL").ok().filter(|s| !s.is_empty()))
            .unwrap_or_else(|| "/bin/sh".into())
    }

    /// Who is calling, and may they open a shell? Loopback callers are the
    /// local operator when loopback was explicitly allowed.
    fn authorise(&self, peer: IpAddr) -> Result<String, (StatusCode, String)> {
        if peer.is_loopback() {
            return if self.allow_loopback {
                Ok("local".into())
            } else {
                Err((StatusCode::FORBIDDEN, "loopback not enabled".into()))
            };
        }
        let identity = self.identify.identify(peer).ok_or((
            StatusCode::UNAUTHORIZED,
            "no mesh identity for this address".into(),
        ))?;
        if self
            .config
            .operators
            .iter()
            .any(|operator| operator == &identity)
        {
            Ok(identity)
        } else {
            Err((
                StatusCode::FORBIDDEN,
                format!("{identity} is not a term operator"),
            ))
        }
    }

    /// `Host` must be this listener (or a configured name) and, for the
    /// WebSocket, `Origin` must be the same origin.
    pub fn check_host_origin(
        &self,
        host: Option<&str>,
        origin: Option<&str>,
        websocket: bool,
    ) -> bool {
        let Some(host) = host else { return false };
        if !self.host_names.iter().any(|name| name == host) {
            return false;
        }
        if !websocket {
            return true;
        }
        origin.is_some_and(|origin| {
            origin == format!("http://{host}") || origin == format!("https://{host}")
        })
    }

    pub fn serve(self, options: &ServeOptions) -> Result<()> {
        let listener =
            TcpListener::bind(options.bind).with_context(|| format!("bind {}", options.bind))?;
        eprintln!(
            "rbq term: listening on http://{} ({} operator(s))",
            options.bind,
            self.config.operators.len()
        );
        self.serve_on(listener)
    }

    pub fn serve_on(self, listener: TcpListener) -> Result<()> {
        let server = Arc::new(self);
        let reaper = Arc::clone(&server);
        thread::spawn(move || {
            loop {
                thread::sleep(Duration::from_secs(30));
                reaper.sessions.reap();
            }
        });
        for stream in listener.incoming() {
            let Ok(stream) = stream else { continue };
            let server = Arc::clone(&server);
            thread::spawn(move || {
                if let Err(error) = server.handle(stream) {
                    eprintln!("rbq term: {error:#}");
                }
            });
        }
        Ok(())
    }

    fn handle(&self, stream: TcpStream) -> Result<()> {
        let peer = stream.peer_addr()?.ip();
        stream.set_read_timeout(Some(Duration::from_secs(10)))?;
        let mut head = [0_u8; 4096];
        let n = stream.peek(&mut head)?;
        let text = String::from_utf8_lossy(&head[..n]);
        let path = text
            .lines()
            .next()
            .and_then(|line| line.split_whitespace().nth(1))
            .unwrap_or("/")
            .to_owned();
        if path.starts_with("/ws?") || path == "/ws" {
            return self.websocket(stream, peer);
        }
        self.static_file(stream, peer, &path, &text)
    }

    fn static_file(
        &self,
        mut stream: TcpStream,
        peer: IpAddr,
        path: &str,
        head: &str,
    ) -> Result<()> {
        let mut request = [0_u8; 4096];
        let _ = stream.read(&mut request)?; // consume the peeked request
        let host = header(head, "host");
        let (status, body, kind): (&str, &str, &str) =
            if !self.check_host_origin(host.as_deref(), None, false) {
                ("421 Misdirected Request", "unknown host\n", "text/plain")
            } else if let Err((_, reason)) = self.authorise(peer) {
                (
                    "403 Forbidden",
                    if reason.is_empty() {
                        "forbidden\n"
                    } else {
                        "not authorised on this mesh\n"
                    },
                    "text/plain",
                )
            } else {
                match path.split('?').next().unwrap_or("/") {
                    "/" | "/index.html" => ("200 OK", INDEX, "text/html; charset=utf-8"),
                    "/client.js" => ("200 OK", CLIENT, "text/javascript; charset=utf-8"),
                    "/xterm.js" => ("200 OK", XTERM_JS, "text/javascript; charset=utf-8"),
                    "/addon-fit.js" => ("200 OK", FIT_JS, "text/javascript; charset=utf-8"),
                    "/xterm.css" => ("200 OK", XTERM_CSS, "text/css; charset=utf-8"),
                    _ => ("404 Not Found", "not found\n", "text/plain"),
                }
            };
        let host = host.unwrap_or_default();
        write!(
            stream,
            "HTTP/1.1 {status}\r\nContent-Type: {kind}\r\nContent-Length: {}\r\nCache-Control: no-store\r\n\
             Content-Security-Policy: default-src 'self'; connect-src 'self' ws://{host} wss://{host}; style-src 'self' 'unsafe-inline'; frame-ancestors 'none'; base-uri 'none'\r\n\
             X-Content-Type-Options: nosniff\r\nReferrer-Policy: no-referrer\r\nConnection: close\r\n\r\n{body}",
            body.len()
        )?;
        Ok(())
    }

    fn websocket(&self, stream: TcpStream, peer: IpAddr) -> Result<()> {
        let mut identity = None;
        let mut query = String::new();
        // tungstenite's callback signature fixes the large error type.
        #[allow(clippy::result_large_err)]
        let callback = |request: &Request, response: Response| -> Result<Response, ErrorResponse> {
            let get = |name: &str| request.headers().get(name).and_then(|v| v.to_str().ok());
            let reject = |status: StatusCode, reason: &str| {
                let mut error = ErrorResponse::new(Some(reason.to_owned()));
                *error.status_mut() = status;
                error
            };
            if !self.check_host_origin(get("host"), get("origin"), true) {
                return Err(reject(
                    StatusCode::FORBIDDEN,
                    "cross-origin terminal request refused",
                ));
            }
            match self.authorise(peer) {
                Ok(who) => identity = Some(who),
                Err((status, reason)) => return Err(reject(status, &reason)),
            }
            query = request.uri().query().unwrap_or_default().to_owned();
            Ok(response)
        };
        let socket = tungstenite::accept_hdr(stream, callback)
            .map_err(|e| anyhow::anyhow!("handshake: {e}"))?;
        let identity = identity.context("handshake without identity")?;
        self.run(socket, &identity, &query)
    }

    fn run(&self, mut socket: WebSocket<TcpStream>, identity: &str, query: &str) -> Result<()> {
        let param = |name: &str| {
            query.split('&').find_map(|pair| {
                pair.strip_prefix(name)?
                    .strip_prefix('=')
                    .map(str::to_owned)
            })
        };
        let number =
            |name: &str, default: u64| param(name).and_then(|v| v.parse().ok()).unwrap_or(default);
        let (cols, rows) = (number("cols", 80) as u16, number("rows", 24) as u16);
        let requested = param("session").filter(|id| id != "new");
        let session = match requested
            .as_deref()
            .and_then(|id| self.sessions.get(id, identity))
        {
            Some(session) => {
                session.resize(cols, rows);
                session
            }
            None if requested.is_some() => {
                let _ = socket.close(None);
                bail!("{identity} asked for a session it does not own or that ended");
            }
            None => {
                let session = self.sessions.create(identity, &self.shell(), cols, rows)?;
                eprintln!("rbq term: {identity} opened session {}", session.id);
                session
            }
        };
        let mut position = number("offset", 0);
        {
            let mut shared = session
                .shared
                .lock()
                .map_err(|_| anyhow::anyhow!("poisoned"))?;
            shared.attached += 1;
            let start = shared.ring.start();
            socket.send(Message::text(json!({"t":"hello","session":session.id,"offset":start.max(position.min(shared.ring.end())),"identity":identity}).to_string()))?;
            if position < start {
                socket.send(Message::text(json!({"t":"gap","from":start}).to_string()))?;
                position = start;
            }
            position = position.min(shared.ring.end());
        }
        let result = self.pump_connection(&mut socket, &session, position);
        if let Ok(mut shared) = session.shared.lock() {
            shared.attached -= 1;
            shared.detached_at = Instant::now();
        }
        result
    }

    fn pump_connection(
        &self,
        socket: &mut WebSocket<TcpStream>,
        session: &Session,
        mut position: u64,
    ) -> Result<()> {
        socket
            .get_mut()
            .set_read_timeout(Some(Duration::from_millis(30)))?;
        let mut last_ping = Instant::now();
        loop {
            match socket.read() {
                Ok(Message::Text(text)) => self.control(session, text.as_str())?,
                Ok(Message::Close(_)) => return Ok(()),
                Ok(_) => {}
                Err(tungstenite::Error::Io(error))
                    if matches!(error.kind(), ErrorKind::WouldBlock | ErrorKind::TimedOut) => {}
                Err(tungstenite::Error::ConnectionClosed | tungstenite::Error::AlreadyClosed) => {
                    return Ok(());
                }
                Err(error) => return Err(error.into()),
            }
            let (chunk, exit) = {
                let shared = session
                    .shared
                    .lock()
                    .map_err(|_| anyhow::anyhow!("poisoned"))?;
                let (shared, _) = session
                    .changed
                    .wait_timeout_while(shared, Duration::from_millis(20), |s| {
                        s.ring.end() <= position && s.exit.is_none()
                    })
                    .map_err(|_| anyhow::anyhow!("poisoned"))?;
                (shared.ring.read_from(position, 64 * 1024), shared.exit)
            };
            if !chunk.is_empty() {
                let mut frame = position.to_be_bytes().to_vec();
                frame.extend_from_slice(&chunk);
                socket.send(Message::binary(frame))?;
                position += chunk.len() as u64;
            } else if let Some(code) = exit {
                socket.send(Message::text(json!({"t":"exit","code":code}).to_string()))?;
                let _ = socket.close(None);
                let _ = socket.flush();
                return Ok(());
            }
            if last_ping.elapsed() > PING_EVERY {
                socket.send(Message::Ping(Vec::new()))?;
                last_ping = Instant::now();
            }
        }
    }

    fn control(&self, session: &Session, text: &str) -> Result<()> {
        ensure!(text.len() <= MAX_INPUT_BYTES, "input frame too large");
        let value: Value = serde_json::from_str(text).context("malformed control frame")?;
        match value.get("t").and_then(Value::as_str) {
            Some("i") => {
                let data = value
                    .get("d")
                    .and_then(Value::as_str)
                    .context("input without data")?;
                session.write_input(data.as_bytes())?;
            }
            Some("r") => {
                let get = |k| {
                    value
                        .get(k)
                        .and_then(Value::as_u64)
                        .map(|n| n.min(1000) as u16)
                };
                if let (Some(cols), Some(rows)) = (get("c"), get("r")) {
                    session.resize(cols, rows);
                }
            }
            _ => {}
        }
        Ok(())
    }
}

fn header(head: &str, name: &str) -> Option<String> {
    head.lines()
        .skip(1)
        .take_while(|line| !line.is_empty())
        .find_map(|line| {
            let (key, value) = line.split_once(':')?;
            key.trim()
                .eq_ignore_ascii_case(name)
                .then(|| value.trim().to_owned())
        })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn binds_only_to_mesh_or_explicit_loopback() {
        assert!(bind_allowed("100.64.0.1".parse().unwrap(), false));
        assert!(bind_allowed("100.127.255.254".parse().unwrap(), false));
        assert!(!bind_allowed("100.128.0.1".parse().unwrap(), false));
        assert!(!bind_allowed("192.168.1.10".parse().unwrap(), true));
        assert!(!bind_allowed("0.0.0.0".parse().unwrap(), true));
        assert!(bind_allowed("fd7a:115c:a1e0::1".parse().unwrap(), false));
        assert!(!bind_allowed("127.0.0.1".parse().unwrap(), false));
        assert!(bind_allowed("127.0.0.1".parse().unwrap(), true));
    }

    #[test]
    fn ring_keeps_offsets_across_eviction() {
        let mut ring = Ring::default();
        ring.push(&vec![b'a'; RING_BYTES]);
        ring.push(b"bc");
        assert_eq!(ring.start(), 2);
        assert_eq!(ring.end(), RING_BYTES as u64 + 2);
        assert_eq!(ring.read_from(ring.end() - 2, 10), b"bc");
    }

    #[test]
    fn mesh_identities_parse() {
        let ts = br#"{"Node":{"Name":"laptop.tail.ts.net."},"UserProfile":{"LoginName":"alice@github"}}"#;
        assert_eq!(
            tailscale_identity(ts).as_deref(),
            Some("tailscale:alice@github")
        );
        assert_eq!(
            tailscale_identity(br#"{"UserProfile":{"LoginName":"tagged-devices"}}"#),
            None
        );
        let nb = br#"{"peers":{"details":[{"fqdn":"kali.netbird.cloud","netbirdIp":"100.92.1.7/16"},{"fqdn":"x.netbird.cloud","netbirdIp":"100.92.1.8"}]}}"#;
        assert_eq!(
            netbird_identity(nb, "100.92.1.7".parse().unwrap()).as_deref(),
            Some("netbird:kali.netbird.cloud")
        );
        assert_eq!(netbird_identity(nb, "100.92.1.9".parse().unwrap()), None);
    }
}
