//! End to end: the real `rbq peer` client against the real app server.
use rebeqah_logic_tests::peer::{Clients, Peer as PhoneServer, SharedStorage};
use rebsync_core::{
    FsObjectStorage, ObjectKey, ObjectStorage,
    journal::Journal,
    layer,
    peer::{self, Peer},
};
use std::sync::{Arc, RwLock, atomic::AtomicBool};

fn publish(
    storage: &dyn ObjectStorage,
    dir: &std::path::Path,
    layer_name: &str,
    name: &str,
    body: &[u8],
) -> String {
    std::fs::write(dir.join(name), body).unwrap();
    layer::publish_files(
        storage,
        layer_name,
        "desk",
        4096,
        dir,
        &[name.to_owned()],
        serde_json::json!({"note": "fixture"}),
        None,
    )
    .unwrap()
    .id
}

#[test]
fn push_to_phone_then_pull_to_another_machine() {
    let t = tempfile::tempdir().unwrap();
    let desk = FsObjectStorage::open(t.path().join("desk")).unwrap();
    let laptop = FsObjectStorage::open(t.path().join("laptop")).unwrap();
    let phone: Arc<dyn ObjectStorage> =
        Arc::new(FsObjectStorage::open(t.path().join("phone")).unwrap());
    let shared: SharedStorage = Arc::new(RwLock::new(phone.clone()));
    let server = PhoneServer::start(
        0,
        "tok3n".into(),
        shared,
        Arc::new(Clients::default()),
        Arc::new(AtomicBool::new(false)),
    )
    .unwrap();
    let connection = format!("rbq+http://127.0.0.1:{}/v1?token=tok3n", server.port);
    let client =
        || Peer::connect(peer::parse_connection(&connection, None).unwrap()).with_page_size(7);
    let mut journal = Journal::open(t.path()).unwrap();

    // Two layers, enough chunks to need several listing pages.
    let src = t.path().join("src");
    std::fs::create_dir_all(&src).unwrap();
    let big: Vec<u8> = (0..60_000u32).map(|i| (i * 7 % 251) as u8).collect();
    let frog_id = publish(&desk, &src, "frog", "AGENTS.db", &big);
    let agenda_id = publish(&desk, &src, "agenda", "index.html", b"<h1>edition</h1>");
    // Stray objects are never exported.
    desk.put(&ObjectKey::parse("_probes/x").unwrap(), b"x")
        .unwrap();

    let pushed = peer::push(&desk, &client(), &peer::default_prefixes(), &mut journal).unwrap();
    assert!(pushed.transferred >= 17, "{pushed:?}");
    assert!(pushed.conflicts.is_empty() && pushed.rejected.is_empty());
    assert!(phone.head(&ObjectKey::parse("_probes/x").unwrap()).is_err());
    // Idempotent: nothing left to send.
    let again = peer::push(&desk, &client(), &peer::default_prefixes(), &mut journal).unwrap();
    assert_eq!(again.transferred, 0);
    assert_eq!(again.already_present, pushed.transferred);

    let pulled = peer::pull(&laptop, &client(), &peer::default_prefixes(), &mut journal).unwrap();
    assert_eq!(pulled.transferred, pushed.transferred);
    // Every newly pulled snapshot was checked chunk by chunk.
    assert_eq!(pulled.verified.len(), 2, "{pulled:?}");
    assert!(pulled.clean());
    // The laptop can reassemble both snapshots, byte for byte.
    let manifest = layer::load(&laptop, "frog", &frog_id).unwrap();
    let out = t.path().join("restored");
    layer::assemble(&laptop, &manifest, &out).unwrap();
    assert_eq!(std::fs::read(out.join("AGENTS.db")).unwrap(), big);
    assert!(layer::load(&laptop, "agenda", &agenda_id).is_ok());

    // Layer filter: only frog objects move.
    let only = peer::pull(
        &FsObjectStorage::open(t.path().join("frog-only")).unwrap(),
        &client(),
        &["frog/".into()],
        &mut journal,
    )
    .unwrap();
    assert!(only.transferred > 0 && only.prefixes == vec!["frog/".to_string()]);

    // A tampered chunk on the phone is rejected on pull, never stored.
    let chunk = &manifest.files[0].chunks[0].sha256;
    let key = format!("frog/v1/chunks/sha256/{}/{chunk}", &chunk[..2]);
    let fresh = FsObjectStorage::open(t.path().join("fresh")).unwrap();
    std::fs::write(
        t.path().join("phone").join(&key),
        vec![0u8; manifest.files[0].chunks[0].size as usize],
    )
    .unwrap();
    let report = peer::pull(&fresh, &client(), &["frog/".into()], &mut journal).unwrap();
    assert!(
        report.rejected.iter().any(|r| r.contains(chunk.as_str())),
        "{report:?}"
    );
    assert!(fresh.head(&ObjectKey::parse(&key).unwrap()).is_err());

    // A manifest whose chunks are missing is checked before publication so it
    // is never listed, even transiently, as a restorable snapshot.
    let damaged_chunk = &manifest.files[0].chunks[1].sha256;
    let damaged_path = format!(
        "frog/v1/chunks/sha256/{}/{damaged_chunk}",
        &damaged_chunk[..2]
    );
    std::fs::remove_file(t.path().join("phone").join(&damaged_path)).unwrap();
    let quarantine = FsObjectStorage::open(t.path().join("quarantine")).unwrap();
    let report = peer::pull(
        &quarantine,
        &client(),
        &["frog/".into()],
        &mut journal,
    )
    .unwrap();
    let manifest_key = layer::manifest_key("frog", &frog_id).unwrap();
    assert!(
        report
            .verification_failed
            .iter()
            .any(|line| line.contains(manifest_key.as_str())),
        "{report:?}"
    );
    assert!(report.quarantined.is_empty(), "{report:?}");
    assert!(quarantine.head(&manifest_key).is_err());
    assert!(!report.clean());

    // Wrong token is a clear error.
    let bad = Peer::connect(
        peer::parse_connection(&format!("http://127.0.0.1:{}", server.port), Some("nope")).unwrap(),
    );
    assert!(format!("{:#}", bad.status().unwrap_err()).contains("401"));
    server.stop();
}
