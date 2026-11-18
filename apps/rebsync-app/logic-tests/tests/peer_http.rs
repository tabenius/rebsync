use rebeqah_logic_tests::peer::{Clients, Peer, SharedStorage};
use rebsync_core::{FsObjectStorage, ObjectStorage};
use sha2::{Digest, Sha256};
use std::{
    io::{Read, Write},
    net::TcpStream,
    sync::{
        Arc, RwLock,
        atomic::{AtomicBool, Ordering},
    },
};

fn request(port: u16, raw: &str, body: &[u8]) -> (u16, Vec<u8>) {
    let mut s = TcpStream::connect(("127.0.0.1", port)).unwrap();
    s.write_all(raw.as_bytes()).unwrap();
    s.write_all(body).unwrap();
    let mut out = Vec::new();
    s.read_to_end(&mut out).unwrap();
    let text = String::from_utf8_lossy(&out);
    let status = text[9..12].parse().unwrap();
    let split = out.windows(4).position(|w| w == b"\r\n\r\n").unwrap() + 4;
    (status, out[split..].to_vec())
}

fn get(port: u16, path: &str, token: Option<&str>) -> (u16, Vec<u8>) {
    let auth = token
        .map(|t| format!("Authorization: Bearer {t}\r\n"))
        .unwrap_or_default();
    request(
        port,
        &format!(
            "GET {path} HTTP/1.1\r\nHost: x\r\nUser-Agent: harness/1\r\n{auth}Connection: close\r\n\r\n"
        ),
        b"",
    )
}

fn put(port: u16, path: &str, token: &str, body: &[u8]) -> (u16, Vec<u8>) {
    request(
        port,
        &format!(
            "PUT {path} HTTP/1.1\r\nHost: x\r\nAuthorization: Bearer {token}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
            body.len()
        ),
        body,
    )
}

#[test]
fn peer_api_auth_create_if_absent_and_client_tracking() {
    let dir = tempfile::tempdir().unwrap();
    let store: Arc<dyn ObjectStorage> =
        Arc::new(FsObjectStorage::open(dir.path().join("objects")).unwrap());
    let storage: SharedStorage = Arc::new(RwLock::new(store));
    let clients = Arc::new(Clients::default());
    let paused = Arc::new(AtomicBool::new(false));
    let token = "t0ken".to_string();
    let peer = Peer::start(0, token.clone(), storage, clients.clone(), paused.clone()).unwrap();
    let port = peer.port;

    assert_eq!(get(port, "/v1/health", None).0, 200);
    assert_eq!(get(port, "/v1/status", None).0, 401);
    assert_eq!(get(port, "/v1/status", Some("wrong")).0, 401);
    let (code, body) = get(port, "/v1/status", Some(&token));
    assert_eq!(code, 200, "{}", String::from_utf8_lossy(&body));
    assert!(String::from_utf8_lossy(&body).contains("rbq-peer/0"));
    assert_eq!(get(port, &format!("/v1/status?token={token}"), None).0, 200);

    let digest = format!("{:x}", Sha256::digest(b"hello"));
    let key = format!("mneme/v1/chunks/sha256/{}/{digest}", &digest[..2]);
    let path = format!("/v1/objects/{key}");
    assert_eq!(put(port, &path, &token, b"hello").0, 201);
    // A lost reply can be retried safely with identical bytes.
    let (code, body) = put(port, &path, &token, b"hello");
    assert_eq!(code, 200);
    assert!(String::from_utf8_lossy(&body).contains("exists"));
    assert_eq!(
        get(port, &path, Some(&token)),
        (200, b"hello".to_vec())
    );
    assert_eq!(put(port, &path, &token, b"other").0, 400);
    assert_eq!(put(port, "/v1/objects/_probes/x", &token, b"x").0, 400);
    assert_eq!(get(port, &format!("/v1/objects/mneme/v1/chunks/sha256/00/{}", "0".repeat(64)), Some(&token)).0, 404);
    assert_eq!(get(port, "/v1/objects/..%2Fescape", Some(&token)).0, 400);
    let (code, body) = get(port, "/v1/objects?prefix=mneme%2F", Some(&token));
    assert_eq!(code, 200);
    assert!(String::from_utf8_lossy(&body).contains(&key));
    let (code, _) = request(
        port,
        &format!(
            "DELETE {path} HTTP/1.1\r\nHost: x\r\nAuthorization: Bearer {token}\r\nConnection: close\r\n\r\n"
        ),
        b"",
    );
    assert_eq!(code, 405);

    paused.store(true, Ordering::SeqCst);
    assert_eq!(put(port, &path, &token, b"hello").0, 503);
    paused.store(false, Ordering::SeqCst);

    // Brute force is throttled per address after ten failures in a minute.
    for _ in 0..10 {
        get(port, "/v1/status", Some("nope"));
    }
    assert_eq!(get(port, "/v1/status", Some(&token)).0, 429);

    let seen = clients.snapshot();
    assert_eq!(seen.len(), 1);
    let c = &seen[0];
    assert_eq!(c.address, "127.0.0.1");
    assert!(c.authorized && c.active);
    assert!(c.rejected >= 12);
    assert!(c.requests >= 20);
    assert!(c.bytes_in >= 10 && c.bytes_out >= 5);
    assert_eq!(c.user_agent.as_deref(), Some("harness/1"));
    peer.stop();
    let closed = (0..40).any(|_| {
        std::thread::sleep(std::time::Duration::from_millis(50));
        TcpStream::connect(("127.0.0.1", port)).is_err()
    });
    assert!(closed, "listener still open 2s after stop");
}
