//! `rbq serve`: HTTPS status page and zeroconf announcement.
#![cfg(all(unix, feature = "serve", feature = "storage-object-store"))]

use rebsync_core::{Config, FsObjectStorage, serve};
use std::time::{Duration, Instant};

#[test]
fn announces_on_the_network_and_is_discoverable_by_mdns() {
    let t = tempfile::tempdir().unwrap();
    let config = Config::defaults(t.path().to_path_buf());
    let options = serve::ServeOptions {
        bind: "0.0.0.0".parse().unwrap(),
        port: 0,
        tls: false,
        announce: true,
    };
    let running = serve::start(&config, &options).unwrap();
    let mdns = running
        .announcements
        .iter()
        .find(|a| a.ok && (a.mechanism == "mdns" || a.mechanism == "avahi"));
    let Some(mdns) = mdns else {
        eprintln!(
            "multicast unavailable here; announcements: {:?}",
            running.announcements
        );
        return;
    };
    assert!(mdns.detail.contains("_rbq._tcp"));
    let browser = mdns_sd::ServiceDaemon::new().unwrap();
    let events = browser.browse("_rbq._tcp.local.").unwrap();
    let deadline = Instant::now() + Duration::from_secs(10);
    let mut found = None;
    while Instant::now() < deadline {
        if let Ok(mdns_sd::ServiceEvent::ServiceResolved(info)) =
            events.recv_timeout(Duration::from_millis(500))
            && info.get_port() == running.port
        {
            found = Some(info);
            break;
        }
    }
    let info = found.expect("rbq service not discovered via mDNS");
    assert_eq!(info.get_property_val_str("path"), Some("/"));
    assert_eq!(info.get_property_val_str("scheme"), Some("http"));
    let _ = browser.shutdown();
}

#[test]
fn serves_page_and_status_without_secrets() {
    let t = tempfile::tempdir().unwrap();
    let mut config = Config::defaults(t.path().to_path_buf());
    config.backup.repository = Some("s3:https://KEY:TOPSECRET@example.invalid/b".into());
    config.storage.root = t.path().join("objects");
    let storage = FsObjectStorage::open(&config.storage.root).unwrap();
    let status = serve::status(&config, &storage);
    assert!(!status.to_string().contains("TOPSECRET"));
    assert_eq!(
        status["layers"].as_array().unwrap().len(),
        rebsync_core::layer::LAYERS.len()
    );
    let html = serve::page(&status);
    assert!(!html.contains("TOPSECRET") && html.contains("rbq peer push"));
    // The certificate is reused, owner-only, and its fingerprint is stable.
    let dir = t.path().join("tls");
    let (_, _, first) = serve::certificate(&dir, vec!["localhost".into()]).unwrap();
    let (_, _, second) = serve::certificate(&dir, vec!["localhost".into()]).unwrap();
    assert_eq!(first, second);
    use std::os::unix::fs::PermissionsExt;
    let mode = std::fs::metadata(dir.join("localhost.key.pem"))
        .unwrap()
        .permissions()
        .mode()
        & 0o777;
    assert_eq!(mode, 0o600);
}

#[test]
fn a_rebound_hostname_is_refused_and_an_ip_literal_is_served() {
    use std::io::{Read, Write};
    let t = tempfile::tempdir().unwrap();
    let mut config = Config::defaults(t.path().to_path_buf());
    config.storage.root = t.path().join("objects");
    let storage = FsObjectStorage::open(&config.storage.root).unwrap();
    let options = serve::ServeOptions {
        bind: "127.0.0.1".parse().unwrap(),
        port: 0,
        tls: false,
        announce: false,
    };
    let running = serve::start(&config, &options).unwrap();
    let ask = |host: &str| {
        let mut stream = std::net::TcpStream::connect(("127.0.0.1", running.port)).unwrap();
        write!(
            stream,
            "GET /v1/status HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n\r\n"
        )
        .unwrap();
        running.serve_one(&config, &storage).unwrap();
        let mut reply = String::new();
        stream.read_to_string(&mut reply).unwrap();
        reply
    };
    // A page on evil.example whose DNS now points at 127.0.0.1.
    let refused = ask("evil.example:8790");
    assert!(refused.starts_with("HTTP/1.1 421"), "{refused}");
    assert!(!refused.contains("storage_root"));
    let served = ask(&format!("127.0.0.1:{}", running.port));
    assert!(served.starts_with("HTTP/1.1 200"), "{served}");
}
