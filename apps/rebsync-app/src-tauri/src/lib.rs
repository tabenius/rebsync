//! RAGBAZ Rebekah: the rebsync companion for Android.
//!
//! Holds a rebsync object store on the phone (internal storage, SD card or USB
//! drive), shares it with peers on trusted local networks, and shows what is
//! connected and how much space remains.

mod datastore;
mod peer;
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
    pairing: String,
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

fn connections(port: u16, token: &str) -> Vec<Connection> {
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
            let pairing = format!("rebsync+{url}/v1?token={token}");
            Some(Connection {
                kind: interface_kind(&i.name).into(),
                interface: i.name.clone(),
                address: host,
                qr_svg: qr(&pairing),
                url,
                pairing,
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
    let mut warnings = Vec::new();
    if !caps.atomic_create_if_absent {
        warnings.push("This volume has no hard links (typical for SD cards and USB drives): writes are safe with one writer at a time, which Rebekah ensures.".into());
    }
    if !caps.owner_only_permissions {
        warnings.push("This volume does not enforce file permissions. Anyone with physical access to the card or stick can read the data; Mneme snapshots contain private transcripts.".into());
    }
    let mneme = rebsync_core::mneme::stats(storage.as_ref())
        .ok()
        .filter(|s| s.snapshots > 0)
        .and_then(|s| serde_json::to_value(s).ok());
    let layers: Vec<serde_json::Value> = ["frog", "agenda"]
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
        token_hint: format!("{}…", &settings.token[..6]),
        connections: peer_port
            .map(|port| connections(port, &settings.token))
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
    Ok(port)
}

fn stop_peer(app: &App) {
    if let Some(peer) = app.peer.lock().ok().and_then(|mut slot| slot.take()) {
        peer.stop();
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
        return Err("Rebekah cannot write to that volume".into());
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
            let copied = datastore::copy_verified(&from, &to, &moving)?;
            if let Ok(mut s) = moving.lock() {
                s.phase = "switching".into();
            }
            let reopened = open_storage(&next)?;
            datastore::save(&settings_path, &next)?;
            *storage.write().map_err(|_| "storage lock")? = reopened;
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
    std::env::var_os("REBSYNC_FILES_DIR")
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
            let settings_path = internal.join("rebekah-settings.json");
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
