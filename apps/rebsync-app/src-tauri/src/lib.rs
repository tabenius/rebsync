//! RAGBAZ Rebeqah: the rbq companion for Android.
//!
//! Holds a rbq object store on the phone (internal storage, SD card or USB
//! drive), shares it with peers on trusted local networks, and shows what is
//! connected and how much space remains.

mod datastore;
mod peer;
mod quic_share;
mod volumes;

use datastore::{MoveStatus, Settings};
use peer::{Clients, Peer, SharedStorage};
use rebsync_core::{FsObjectStorage, ObjectStorage};
use serde::Serialize;
use std::{
    path::{Path, PathBuf},
    sync::{
        Arc, Mutex, RwLock,
        atomic::{AtomicBool, Ordering},
    },
};
use tauri::{Manager, State};

struct App {
    internal: PathBuf,
    settings_path: PathBuf,
    settings: Arc<Mutex<Settings>>,
    storage: SharedStorage,
    peer: Mutex<Option<Peer>>,
    /// The encrypted QUIC share, running whenever sharing is on and it could
    /// start; `quic_error` says why not otherwise.
    quic: Mutex<Option<quic_share::QuicShare>>,
    quic_error: Mutex<Option<String>>,
    clients: Arc<Clients>,
    writes_paused: Arc<AtomicBool>,
    moving: Arc<Mutex<MoveStatus>>,
}

fn open_storage(settings: &Settings) -> Result<Arc<dyn ObjectStorage>, String> {
    let root = settings.objects();
    // Pre-create so removable filesystems that refuse chmod are still usable.
    std::fs::create_dir_all(&root).map_err(|e| format!("create {}: {e}", root.display()))?;
    Ok(Arc::new(
        FsObjectStorage::open(&root).map_err(|e| e.to_string())?,
    ))
}

#[derive(Serialize)]
struct Connection {
    interface: String,
    kind: String,
    address: String,
    url: String,
    /// Plaintext `rbq-peer/0` over HTTP, for older clients.
    pairing: String,
    /// Encrypted `rbq-peer/1` over QUIC, pinned to this phone's key. The QR
    /// code carries this one when it exists.
    quic_pairing: Option<String>,
    qr_svg: String,
}

fn interface_kind(name: &str) -> &'static str {
    match name {
        n if n.starts_with("wlan") => "Wi-Fi",
        n if n.starts_with("swlan") || n.starts_with("ap") || n.starts_with("softap") => "Hotspot",
        n if n.starts_with("rndis") || n.starts_with("usb") || n.starts_with("ncm") => {
            "USB tethering"
        }
        n if n.starts_with("eth") || n.starts_with("en") => "Ethernet",
        n if n.starts_with("bt-pan") || n.starts_with("bnep") => "Bluetooth tethering",
        n if n.starts_with("rmnet") || n.starts_with("ccmni") || n.starts_with("wwan") => {
            "Mobile data"
        }
        n if n.starts_with("tun") || n.starts_with("wg") => "VPN",
        _ => "Network",
    }
}

fn qr(text: &str) -> String {
    qrcode::QrCode::new(text.as_bytes())
        .map(|code| {
            code.render::<qrcode::render::svg::Color>()
                .min_dimensions(180, 180)
                .quiet_zone(true)
                .dark_color(qrcode::render::svg::Color("#0e1621"))
                .light_color(qrcode::render::svg::Color("#ffffff"))
                .build()
        })
        .unwrap_or_default()
}

fn connections(port: u16, token: &str, quic: Option<(u16, &str)>) -> Vec<Connection> {
    let mut list: Vec<Connection> = if_addrs::get_if_addrs()
        .unwrap_or_default()
        .into_iter()
        .filter(|i| !i.is_loopback())
        .filter_map(|i| {
            let ip = i.ip();
            let host = match ip {
                std::net::IpAddr::V4(v4) if !v4.is_link_local() => v4.to_string(),
                std::net::IpAddr::V6(v6)
                    if (v6.segments()[0] & 0xffc0) != 0xfe80 && !v6.is_unspecified() =>
                {
                    format!("[{v6}]")
                }
                _ => return None,
            };
            let url = format!("http://{host}:{port}");
            let pairing = format!("rbq+{url}/v1?token={token}");
            let quic_pairing =
                quic.map(|(quic_port, peer_id)| quic_share::pairing(&host, quic_port, peer_id, token));
            Some(Connection {
                kind: interface_kind(&i.name).into(),
                interface: i.name.clone(),
                address: host,
                qr_svg: qr(quic_pairing.as_deref().unwrap_or(&pairing)),
                url,
                pairing,
                quic_pairing,
            })
        })
        .collect();
    // Prefer local-network interfaces over mobile data, IPv4 first.
    let rank = |c: &Connection| {
        (
            match c.kind.as_str() {
                "Wi-Fi" => 0,
                "Hotspot" => 1,
                "USB tethering" => 2,
                "Ethernet" => 3,
                "Mobile data" => 9,
                _ => 5,
            },
            c.address.starts_with('['),
        )
    };
    list.sort_by_key(rank);
    list
}

#[derive(Serialize)]
struct Overview {
    app_version: &'static str,
    data_root: PathBuf,
    sharing: bool,
    port: u16,
    quic_port: Option<u16>,
    /// The phone's key fingerprint that QUIC clients pin.
    quic_peer_id: Option<String>,
    token_hint: String,
    connections: Vec<Connection>,
    clients: Vec<peer::Client>,
    capabilities: serde_json::Value,
    objects: u64,
    object_bytes: u64,
    objects_truncated: bool,
    mneme: Option<serde_json::Value>,
    layers: Vec<serde_json::Value>,
    moving: MoveStatus,
    warnings: Vec<String>,
}

#[tauri::command]
fn overview(app: State<'_, App>) -> Result<Overview, String> {
    let settings = app.settings.lock().map_err(|_| "settings lock")?.clone();
    let storage = app.storage.read().map_err(|_| "storage lock")?.clone();
    let caps = storage.capabilities();
    let listing = storage.list_prefix("", 50_000).unwrap_or_default();
    let peer_port = app
        .peer
        .lock()
        .ok()
        .and_then(|p| p.as_ref().map(|p| p.port));
    let quic = app
        .quic
        .lock()
        .ok()
        .and_then(|q| q.as_ref().map(|q| (q.port, q.peer_id.clone())));
    let mut warnings = Vec::new();
    if peer_port.is_some()
        && quic.is_none()
        && let Some(error) = app.quic_error.lock().ok().and_then(|e| e.clone())
    {
        warnings.push(format!(
            "Encrypted sharing (QUIC) could not start, so only plain HTTP is offered: {error}"
        ));
    }
    if !caps.atomic_create_if_absent {
        warnings.push("This volume has no hard links (typical for SD cards and USB drives): writes are safe with one writer at a time, which Rebeqah ensures.".into());
    }
    if !caps.owner_only_permissions {
        warnings.push("This volume does not enforce file permissions. Anyone with physical access to the card or stick can read the data; Mneme snapshots contain private transcripts.".into());
    }
    let mneme = rebsync_core::mneme::stats(storage.as_ref())
        .ok()
        .filter(|s| s.snapshots > 0)
        .and_then(|s| serde_json::to_value(s).ok());
    let layers: Vec<serde_json::Value> = ["frog", "agenda", "git"]
        .iter()
        .filter_map(|layer| rebsync_core::layer::stats(storage.as_ref(), layer).ok())
        .filter(|s| s.snapshots > 0)
        .filter_map(|s| serde_json::to_value(s).ok())
        .collect();
    Ok(Overview {
        app_version: env!("CARGO_PKG_VERSION"),
        data_root: settings.objects(),
        sharing: peer_port.is_some(),
        port: peer_port.unwrap_or(settings.port),
        quic_port: quic.as_ref().map(|(port, _)| *port),
        quic_peer_id: quic.as_ref().map(|(_, id)| id.clone()),
        token_hint: format!("{}…", &settings.token[..6]),
        connections: peer_port
            .map(|port| {
                connections(
                    port,
                    &settings.token,
                    quic.as_ref().map(|(port, id)| (*port, id.as_str())),
                )
            })
            .unwrap_or_default(),
        clients: app.clients.snapshot(),
        capabilities: serde_json::json!({
            "atomic_create_if_absent": caps.atomic_create_if_absent,
            "owner_only_permissions": caps.owner_only_permissions,
            "durable_publication": caps.durable_publication,
        }),
        objects: listing.len() as u64,
        object_bytes: listing.iter().map(|m| m.size).sum(),
        objects_truncated: listing.len() == 50_000,
        mneme,
        layers,
        moving: app.moving.lock().map(|m| m.clone()).unwrap_or_default(),
        warnings,
    })
}

#[tauri::command]
fn volumes(app: State<'_, App>) -> Result<Vec<volumes::Volume>, String> {
    let root = app.settings.lock().map_err(|_| "settings lock")?.objects();
    Ok(volumes::list(&app.internal, &root))
}

fn start_peer(app: &App, settings: &Settings) -> Result<u16, String> {
    let mut slot = app.peer.lock().map_err(|_| "peer lock")?;
    if let Some(peer) = slot.as_ref() {
        return Ok(peer.port);
    }
    let peer = Peer::start(
        settings.port,
        settings.token.clone(),
        app.storage.clone(),
        app.clients.clone(),
        app.writes_paused.clone(),
    )?;
    let port = peer.port;
    *slot = Some(peer);
    // Encrypted sharing next to HTTP, on the same port number over UDP. A
    // failure leaves HTTP running and is shown as a warning.
    let quic = quic_share::QuicShare::start(
        settings.port,
        settings.token.clone(),
        app.storage.clone(),
        app.writes_paused.clone(),
        &app.internal.join("quic-identity"),
    );
    if let (Ok(mut quic_slot), Ok(mut error)) = (app.quic.lock(), app.quic_error.lock()) {
        match quic {
            Ok(share) => {
                *quic_slot = Some(share);
                *error = None;
            }
            Err(message) => *error = Some(message),
        }
    }
    Ok(port)
}

fn stop_peer(app: &App) {
    if let Some(peer) = app.peer.lock().ok().and_then(|mut slot| slot.take()) {
        peer.stop();
    }
    if let Some(share) = app.quic.lock().ok().and_then(|mut slot| slot.take()) {
        share.stop();
    }
}

#[tauri::command]
fn set_sharing(app: State<'_, App>, enabled: bool) -> Result<bool, String> {
    let mut settings = app.settings.lock().map_err(|_| "settings lock")?.clone();
    if enabled {
        start_peer(&app, &settings)?;
    } else {
        stop_peer(&app);
    }
    settings.sharing = enabled;
    datastore::save(&app.settings_path, &settings)?;
    *app.settings.lock().map_err(|_| "settings lock")? = settings;
    Ok(enabled)
}

#[tauri::command]
fn reveal_token(app: State<'_, App>) -> Result<String, String> {
    Ok(app
        .settings
        .lock()
        .map_err(|_| "settings lock")?
        .token
        .clone())
}

/// New token; restarts sharing so the old one stops working immediately.
#[tauri::command]
fn rotate_token(app: State<'_, App>) -> Result<(), String> {
    let mut settings = app.settings.lock().map_err(|_| "settings lock")?.clone();
    settings.token = datastore::new_token();
    datastore::save(&app.settings_path, &settings)?;
    *app.settings.lock().map_err(|_| "settings lock")? = settings.clone();
    let was_sharing = app.peer.lock().map(|p| p.is_some()).unwrap_or(false);
    stop_peer(&app);
    if was_sharing {
        start_peer(&app, &settings)?;
    }
    Ok(())
}

#[tauri::command]
fn move_data(app: State<'_, App>, volume: PathBuf, remove_source: bool) -> Result<(), String> {
    let settings = app.settings.lock().map_err(|_| "settings lock")?.clone();
    let candidates = volumes::list(&app.internal, &settings.objects());
    let target = candidates
        .iter()
        .find(|v| v.path == volume)
        .ok_or("unknown volume")?;
    if !target.writable {
        return Err("Rebeqah cannot write to that volume".into());
    }
    if target.current {
        return Err("data already lives on that volume".into());
    }
    {
        let status = app.moving.lock().map_err(|_| "move lock")?;
        if matches!(
            status.phase.as_str(),
            "scanning" | "copying" | "verifying" | "switching" | "cleaning"
        ) {
            return Err("a move is already running".into());
        }
    }
    let from = settings.objects();
    let needed: u64 = datastore::inventory(&from)
        .map_err(|e| e.to_string())?
        .iter()
        .map(|(_, n)| n)
        .sum();
    let available = target.available_bytes.unwrap_or(0);
    if available < needed + needed / 20 + 16 * 1024 * 1024 {
        return Err(format!(
            "not enough space: need about {} MB, {} MB available",
            needed / 1_000_000 + 16,
            available / 1_000_000
        ));
    }
    let mut next = settings.clone();
    next.volume = target.path.clone();
    let to = next.objects();
    *app.moving.lock().map_err(|_| "move lock")? = MoveStatus {
        phase: "scanning".into(),
        from: Some(from.clone()),
        to: Some(to.clone()),
        ..Default::default()
    };
    // Clone what the worker needs; the State borrow cannot cross threads.
    let (moving, paused, storage, settings_path, shared_settings) = (
        app.moving.clone(),
        app.writes_paused.clone(),
        app.storage.clone(),
        app.settings_path.clone(),
        app.settings.clone(),
    );
    paused.store(true, Ordering::SeqCst);
    std::thread::spawn(move || {
        let result = (|| -> Result<bool, String> {
            // Drain already-started peer writes before copying; hold through
            // the root switch so no acknowledged object is stranded behind.
            let mut active_storage = storage.write().map_err(|_| "storage lock")?;
            let copied = datastore::copy_verified(&from, &to, &moving)?;
            if let Ok(mut s) = moving.lock() {
                s.phase = "switching".into();
            }
            let reopened = open_storage(&next)?;
            datastore::save(&settings_path, &next)?;
            *active_storage = reopened;
            if let Ok(mut s) = shared_settings.lock() {
                *s = next.clone();
            }
            if remove_source {
                if let Ok(mut s) = moving.lock() {
                    s.phase = "cleaning".into();
                }
                datastore::remove_source(&from, &copied);
            }
            Ok(remove_source)
        })();
        paused.store(false, Ordering::SeqCst);
        if let Ok(mut s) = moving.lock() {
            match result {
                Ok(removed) => {
                    s.phase = "done".into();
                    s.removed_source = removed;
                }
                Err(error) => {
                    s.phase = "failed".into();
                    s.error = Some(error);
                }
            }
        }
    });
    Ok(())
}

fn internal_dir(app: &tauri::AppHandle) -> PathBuf {
    std::env::var_os("RBQ_FILES_DIR")
        .map(PathBuf::from)
        .or_else(|| app.path().app_data_dir().ok())
        .unwrap_or_else(|| Path::new(".").to_path_buf())
}

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    tauri::Builder::default()
        .setup(|app| {
            if cfg!(debug_assertions) {
                app.handle().plugin(
                    tauri_plugin_log::Builder::default()
                        .level(log::LevelFilter::Info)
                        .build(),
                )?;
            }
            let internal = internal_dir(app.handle());
            std::fs::create_dir_all(&internal)?;
            let settings_path = internal.join("rbq-settings.json");
            let mut settings = datastore::load(&settings_path, &internal);
            // If the chosen volume vanished (card removed), fall back to internal
            // without forgetting the choice on disk.
            let storage = match open_storage(&settings) {
                Ok(storage) => storage,
                Err(_) => {
                    settings.volume = internal.clone();
                    open_storage(&settings).map_err(std::io::Error::other)?
                }
            };
            if !settings_path.exists() {
                datastore::save(&settings_path, &settings).map_err(std::io::Error::other)?;
            }
            let state = App {
                internal,
                settings_path,
                settings: Arc::new(Mutex::new(settings.clone())),
                storage: Arc::new(RwLock::new(storage)),
                peer: Mutex::new(None),
                quic: Mutex::new(None),
                quic_error: Mutex::new(None),
                clients: Arc::new(Clients::default()),
                writes_paused: Arc::new(AtomicBool::new(false)),
                moving: Arc::new(Mutex::new(MoveStatus {
                    phase: "idle".into(),
                    ..Default::default()
                })),
            };
            if settings.sharing {
                let _ = start_peer(&state, &settings);
            }
            app.manage(state);
            Ok(())
        })
        .invoke_handler(tauri::generate_handler![
            overview,
            volumes,
            set_sharing,
            reveal_token,
            rotate_token,
            move_data
        ])
        .run(tauri::generate_context!())
        .expect("error while building tauri application");
}
