//! End to end: the real `rbq peer` QUIC client against the app's QUIC share.
use rebeqah_logic_tests::{peer::SharedStorage, quic_share};
use rebsync_core::{
    FsObjectStorage, ObjectStorage,
    journal::Journal,
    layer,
    peer::{self, PeerApi},
    transport::{self, TransportPeer},
};
use std::sync::{Arc, RwLock, atomic::AtomicBool};

const TOKEN: &str = "0123456789abcdef0123456789abcdef0123456789abcdef";

fn publish(storage: &dyn ObjectStorage, dir: &std::path::Path, body: &[u8]) -> String {
    std::fs::create_dir_all(dir).unwrap();
    std::fs::write(dir.join("AGENTS.db"), body).unwrap();
    layer::publish_files(
        storage,
        "frog",
        "desk",
        4096,
        dir,
        &["AGENTS.db".to_owned()],
        serde_json::json!({"note": "fixture"}),
        None,
    )
    .unwrap()
    .id
}

fn connect(share: &quic_share::QuicShare, peer_id: &str) -> TransportPeer {
    let pairing = quic_share::pairing("127.0.0.1", share.port, peer_id, TOKEN);
    let (target, token) = transport::parse_connection(&pairing, None).unwrap();
    TransportPeer::connect(&target, token).unwrap()
}

#[test]
fn push_to_the_phone_and_pull_elsewhere_over_quic() {
    let t = tempfile::tempdir().unwrap();
    let desk = FsObjectStorage::open(t.path().join("desk")).unwrap();
    let laptop = FsObjectStorage::open(t.path().join("laptop")).unwrap();
    let phone: Arc<dyn ObjectStorage> =
        Arc::new(FsObjectStorage::open(t.path().join("phone")).unwrap());
    let shared: SharedStorage = Arc::new(RwLock::new(phone));
    let share = quic_share::QuicShare::start(
        0,
        TOKEN.into(),
        shared.clone(),
        Arc::new(AtomicBool::new(false)),
        &t.path().join("identity"),
    )
    .unwrap();
    let mut journal = Journal::open(t.path()).unwrap();
    let big: Vec<u8> = (0..60_000u32).map(|i| (i * 7 % 251) as u8).collect();
    let id = publish(&desk, &t.path().join("src"), &big);

    let phone = connect(&share, &share.peer_id);
    let pushed = peer::push(&desk, &phone, &peer::default_prefixes(), &mut journal).unwrap();
    assert!(pushed.clean() && pushed.transferred > 10, "{pushed:?}");
    let pulled = peer::pull(&laptop, &phone, &peer::default_prefixes(), &mut journal).unwrap();
    assert!(pulled.clean(), "{pulled:?}");
    assert_eq!(pulled.transferred, pushed.transferred);
    let manifest = layer::load(&laptop, "frog", &id).unwrap();
    let out = t.path().join("restored");
    layer::assemble(&laptop, &manifest, &out).unwrap();
    assert_eq!(std::fs::read(out.join("AGENTS.db")).unwrap(), big);

    // During a volume move the store is write-locked: requests are refused
    // as busy, not blocked.
    {
        let _moving = shared.write().unwrap();
        let error = phone.list("frog/").unwrap_err();
        assert!(format!("{error:#}").contains("503"), "{error:#}");
    }
    // After the move the share follows the new data root.
    let moved: Arc<dyn ObjectStorage> =
        Arc::new(FsObjectStorage::open(t.path().join("sdcard")).unwrap());
    *shared.write().unwrap() = moved;
    assert!(phone.list("frog/").unwrap().is_empty());
    drop(phone);
    share.stop();
}

#[test]
fn the_phone_keeps_its_identity_and_refuses_a_wrong_pin() {
    let t = tempfile::tempdir().unwrap();
    let store: Arc<dyn ObjectStorage> =
        Arc::new(FsObjectStorage::open(t.path().join("phone")).unwrap());
    let shared: SharedStorage = Arc::new(RwLock::new(store));
    let start = || {
        quic_share::QuicShare::start(
            0,
            TOKEN.into(),
            shared.clone(),
            Arc::new(AtomicBool::new(false)),
            &t.path().join("identity"),
        )
        .unwrap()
    };
    let first = start();
    let id = first.peer_id.clone();
    first.stop();
    // A restart (or a token rotation, which restarts sharing) keeps the pin.
    let second = start();
    assert_eq!(second.peer_id, id);
    assert!(connect(&second, &id).status().is_ok());
    let wrong = "0".repeat(64);
    let pairing = quic_share::pairing("127.0.0.1", second.port, &wrong, TOKEN);
    let (target, token) = transport::parse_connection(&pairing, None).unwrap();
    let error = TransportPeer::connect(&target, token).err().expect("wrong pin");
    assert!(format!("{error:#}").contains("not the pinned"), "{error:#}");
    second.stop();
}
