//! `rebsync serve`: HTTPS status page and zeroconf announcement.
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
        .find(|a| a.mechanism == "mdns" || a.mechanism == "avahi");
    let Some(mdns) = mdns.filter(|a| a.ok) else {
        eprintln!(
            "multicast unavailable here; announcements: {:?}",
            running.announcements
        );
        return;
    };
    assert!(mdns.detail.contains("_rebsync._tcp"));
    let browser = mdns_sd::ServiceDaemon::new().unwrap();
    let events = browser.browse("_rebsync._tcp.local.").unwrap();
    let deadline = Instant::now() + Duration::from_secs(10);
    let mut found = None;
    while Instant::now() < deadline {
        if let Ok(mdns_sd::ServiceEvent::ServiceResolved(info)) =
            events.recv_timeout(Duration::from_millis(500))
        {
            if info.get_port() == running.port {
                found = Some(info);
                break;
            }
        }
    }
    let info = found.expect("rebsync service not discovered via mDNS");
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
    assert!(!html.contains("TOPSECRET") && html.contains("rebsync peer push"));
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
