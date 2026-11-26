//! The operator terminal over loopback: real PTY, real WebSocket.
#![cfg(all(unix, feature = "term"))]
use rebsync_core::term::{Identify, ServeOptions, Server, TermConfig};
use std::{
    net::{IpAddr, TcpListener, TcpStream},
    time::{Duration, Instant},
};
use tungstenite::{Message, WebSocket, client::IntoClientRequest, stream::MaybeTlsStream};

struct Nobody;
impl Identify for Nobody {
    fn identify(&self, _: IpAddr) -> Option<String> {
        None
    }
}

fn start() -> String {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let bind = listener.local_addr().unwrap();
    let config = TermConfig {
        shell: Some("/bin/sh".into()),
        ..TermConfig::default()
    };
    let server = Server::new(
        config,
        Box::new(Nobody),
        &ServeOptions {
            bind,
            allow_loopback: true,
        },
    )
    .unwrap();
    std::thread::spawn(move || server.serve_on(listener));
    bind.to_string()
}

type Socket = WebSocket<MaybeTlsStream<TcpStream>>;

fn connect(host: &str, origin: &str, query: &str) -> Result<Socket, Box<tungstenite::Error>> {
    let mut request = format!("ws://{host}/ws?{query}")
        .into_client_request()
        .unwrap();
    request
        .headers_mut()
        .insert("Origin", origin.parse().unwrap());
    tungstenite::connect(request)
        .map(|(socket, _)| socket)
        .map_err(Box::new)
}

/// Read frames until `needle` appears in the output; returns (hello, output, next offset).
/// `from` is the stream position already reached on this connection (None for
/// a fresh connection, whose hello sets it).
fn read_until(
    socket: &mut Socket,
    needle: &str,
    from: Option<u64>,
) -> (serde_json::Value, String, u64) {
    let deadline = Instant::now() + Duration::from_secs(10);
    let (mut hello, mut output, mut next) =
        (serde_json::Value::Null, String::new(), from.unwrap_or(0));
    while Instant::now() < deadline && !output.contains(needle) {
        match socket.read().unwrap() {
            Message::Text(text) => {
                let value: serde_json::Value = serde_json::from_str(&text).unwrap();
                if value["t"] == "hello" {
                    next = value["offset"].as_u64().unwrap();
                    hello = value;
                }
            }
            Message::Binary(frame) => {
                let start = u64::from_be_bytes(frame[..8].try_into().unwrap());
                assert_eq!(start, next, "output is contiguous");
                output.push_str(&String::from_utf8_lossy(&frame[8..]));
                next = start + (frame.len() - 8) as u64;
            }
            _ => {}
        }
    }
    assert!(output.contains(needle), "missing {needle:?} in {output:?}");
    (hello, output, next)
}

fn input(socket: &mut Socket, text: &str) {
    socket
        .send(Message::text(
            serde_json::json!({"t":"i","d":text}).to_string(),
        ))
        .unwrap();
}

#[test]
fn a_dropped_connection_resumes_without_losing_or_repeating_output() {
    let host = start();
    let origin = format!("http://{host}");
    let mut socket = connect(&host, &origin, "session=new&offset=0&cols=100&rows=30").unwrap();
    input(&mut socket, "echo ready-$((40+2))\n");
    let (hello, _, offset) = read_until(&mut socket, "ready-42", None);
    let session = hello["session"].as_str().unwrap().to_owned();
    assert_eq!(hello["identity"], "local");

    // Start output that arrives while nobody is connected, then drop the link.
    input(&mut socket, "sleep 1; echo while-away-$((6*7))\n");
    drop(socket);
    std::thread::sleep(Duration::from_millis(1500));

    let mut resumed = connect(
        &host,
        &origin,
        &format!("session={session}&offset={offset}"),
    )
    .unwrap();
    let (hello, output, position) = read_until(&mut resumed, "while-away-42", None);
    assert_eq!(hello["session"], session.as_str());
    assert!(
        !output.contains("ready-42"),
        "already-seen output is not repeated: {output:?}"
    );

    // The shell is the same process: state set before the drop survives.
    input(&mut resumed, "X=kept; echo $X-$((1+1))\n");
    read_until(&mut resumed, "kept-2", Some(position));
    input(&mut resumed, "exit\n");
    let deadline = Instant::now() + Duration::from_secs(5);
    let mut exited = false;
    while Instant::now() < deadline && !exited {
        match resumed.read() {
            Ok(Message::Text(text)) => exited = text.contains("\"exit\""),
            Ok(_) => {}
            Err(_) => break,
        }
    }
    assert!(exited, "the client is told the shell exited");
}

#[test]
fn cross_origin_and_foreign_sessions_are_refused() {
    let host = start();
    // Another site in the operator's browser must not ride the operator's identity.
    assert!(connect(&host, "https://evil.example", "session=new").is_err());
    // A different Host (DNS rebinding) is refused even with a matching Origin.
    let mut request = format!("ws://{host}/ws?session=new")
        .into_client_request()
        .unwrap();
    request
        .headers_mut()
        .insert("Host", "rebound.example".parse().unwrap());
    request
        .headers_mut()
        .insert("Origin", "http://rebound.example".parse().unwrap());
    assert!(tungstenite::connect(request).is_err());
    // An unknown session id is not silently replaced by a new shell.
    let mut socket = connect(
        &host,
        &format!("http://{host}"),
        "session=00112233445566778899aabbccddeeff",
    )
    .unwrap();
    assert!(matches!(socket.read(), Ok(Message::Close(_)) | Err(_)));
}

#[test]
fn the_page_is_served_with_a_strict_policy_and_only_for_known_hosts() {
    use std::io::{Read, Write};
    let host = start();
    let get = |host_header: &str, path: &str| {
        let mut stream = TcpStream::connect(&host).unwrap();
        write!(stream, "GET {path} HTTP/1.1\r\nHost: {host_header}\r\n\r\n").unwrap();
        let mut response = String::new();
        stream.read_to_string(&mut response).unwrap();
        response
    };
    let page = get(&host, "/");
    assert!(page.starts_with("HTTP/1.1 200"), "{page}");
    assert!(page.contains("Content-Security-Policy: default-src 'self'"));
    assert!(page.contains("xterm.js"));
    assert!(get(&host, "/xterm.js").contains("Terminal"));
    assert!(get("rebound.example", "/").starts_with("HTTP/1.1 421"));
}
