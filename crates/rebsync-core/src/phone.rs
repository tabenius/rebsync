//! Read-only Linux phone diagnostics. USB/MTP/network observations never enroll
//! a peer, establish ownership, or authorize synchronization.
use crate::process;
use anyhow::{Context, Result};
use serde::Serialize;
use serde_json::Value;
use std::path::Path;

const TIMEOUT: u64 = 5;
const MAX_DEVICES: usize = 32;
const MAX_MTP_DEVICES: usize = 4;
const MAX_STORAGES: usize = 8;

#[derive(Debug, Serialize)]
pub struct UsbDevice {
    pub bus: u16,
    pub device: u16,
    pub vendor_id: String,
    pub product_id: String,
    pub description: String,
    /// Imaging interfaces may be PTP-only; this is a hint, not MTP negotiation.
    pub mtp_candidate: bool,
    pub serial_available: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub serial: Option<String>,
    pub mtp: Option<MtpReport>,
}

impl UsbDevice {
    fn uri(&self) -> String {
        format!("mtp://[usb:{:03},{:03}]/", self.bus, self.device)
    }
}

#[derive(Debug, Serialize)]
pub struct MtpReport {
    pub uri: String,
    pub status: String,
    pub storages: Vec<StorageSpace>,
    pub issues: Vec<String>,
}

#[derive(Debug, Serialize)]
pub struct StorageSpace {
    pub uri: String,
    pub capacity_bytes: Option<u64>,
    pub free_bytes: Option<u64>,
}

#[derive(Debug, Default, Serialize)]
pub struct NetworkReport {
    pub crostini_gateway_observed: bool,
    pub interfaces: Vec<Interface>,
    pub default_routes: Vec<DefaultRoute>,
}

#[derive(Debug, Serialize)]
pub struct Interface {
    pub name: String,
    pub addresses: Vec<String>,
}

#[derive(Debug, Serialize)]
pub struct DefaultRoute {
    pub interface: String,
    pub gateway: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct PhoneReport {
    pub schema: &'static str,
    pub usb: Vec<UsbDevice>,
    pub network: NetworkReport,
    pub adb: Option<AdbReport>,
    pub peer: Option<Value>,
    pub same_physical_phone: &'static str,
    pub issues: Vec<String>,
    pub safety: Vec<&'static str>,
}

#[derive(Debug, Serialize)]
pub struct AdbReport {
    pub authorized: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub serial: Option<String>,
    pub phone_addresses: Vec<String>,
    pub storages: Vec<StorageSpace>,
    pub issues: Vec<String>,
}

fn adb_addresses(output: &str) -> Vec<String> {
    output
        .lines()
        .filter_map(|line| {
            let mut words = line.split_whitespace();
            if !matches!(words.next(), Some("inet" | "inet6")) {
                return None;
            }
            let ip = words.next()?.split('/').next()?;
            let address = ip.parse::<std::net::IpAddr>().ok()?;
            (!address.is_loopback() && !address.is_unspecified()).then(|| address.to_string())
        })
        .take(128)
        .collect()
}

fn adb_space(output: &str) -> Vec<StorageSpace> {
    output
        .lines()
        .filter_map(|line| {
            let words: Vec<_> = line.split_whitespace().collect();
            if words.len() < 6 || !words[4].ends_with('%') {
                return None;
            }
            let capacity = words[1].parse::<u64>().ok()?.checked_mul(1024)?;
            let free = words[3].parse::<u64>().ok()?.checked_mul(1024)?;
            if free > capacity {
                return None;
            }
            Some(StorageSpace {
                uri: format!("adb:df:{}", words[5]),
                capacity_bytes: Some(capacity),
                free_bytes: Some(free),
            })
        })
        .take(8)
        .collect()
}

/// Explicit, already-authorized ADB device only. Does not enable debugging,
/// pair, connect over TCP, forward ports or install software automatically.
pub fn probe_adb(serial: &str, include_identifiers: bool) -> Result<AdbReport> {
    anyhow::ensure!(
        !serial.is_empty()
            && serial.len() <= 256
            && !serial.starts_with('-')
            && serial
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b"._:-".contains(&b)),
        "invalid ADB serial; select the exact device shown by adb devices -l"
    );
    let mut report = AdbReport {
        authorized: false,
        serial: include_identifiers.then(|| serial.into()),
        phone_addresses: vec![],
        storages: vec![],
        issues: vec![],
    };
    if !matches!(text("adb", &["-s", serial, "get-state"]), Ok(state) if state.trim() == "device") {
        report.issues.push("ADB unavailable, offline or unauthorized. Install adb if wanted, share USB with Linux, and explicitly approve this computer on the phone. No authorization was bypassed.".into());
        return Ok(report);
    }
    report.authorized = true;
    match text("adb", &["-s", serial, "shell", "ip", "addr", "show"]) {
        Ok(output) => report.phone_addresses = adb_addresses(&output),
        Err(_) => report
            .issues
            .push("Authorized phone did not provide IP-address diagnostics.".into()),
    }
    match text(
        "adb",
        &[
            "-s",
            serial,
            "shell",
            "df",
            "-k",
            "/data",
            "/storage/emulated/0",
        ],
    ) {
        Ok(output) => {
            report.storages = adb_space(&output);
            if report.storages.is_empty() {
                report.issues.push(
                    "ADB returned no recognized free-space rows; space remains unknown.".into(),
                );
            }
        }
        Err(_) => report
            .issues
            .push("Authorized phone did not provide storage-space diagnostics.".into()),
    }
    Ok(report)
}

fn text(program: &str, args: &[&str]) -> Result<String> {
    let mut cmd = process::command(program);
    cmd.args(args).env("LC_ALL", "C");
    let bytes = process::checked(&mut cmd, TIMEOUT)?;
    String::from_utf8(bytes).context("diagnostic helper returned non-UTF-8 output")
}

fn parse_lsusb(output: &str) -> Vec<UsbDevice> {
    output
        .lines()
        .filter_map(|line| {
            let mut parts = line.split_whitespace();
            if parts.next()? != "Bus" {
                return None;
            }
            let bus = parts.next()?.parse::<u16>().ok()?;
            if parts.next()? != "Device" {
                return None;
            }
            let device = parts.next()?.strip_suffix(':')?.parse::<u16>().ok()?;
            if !(1..=999).contains(&bus) || !(1..=999).contains(&device) || parts.next()? != "ID" {
                return None;
            }
            let (vendor, product) = parts.next()?.split_once(':')?;
            if ![vendor, product]
                .iter()
                .all(|id| id.len() == 4 && id.bytes().all(|c| c.is_ascii_hexdigit()))
            {
                return None;
            }
            let description = parts.collect::<Vec<_>>().join(" ");
            if vendor == "1d6b" && description.contains("root hub") {
                return None;
            }
            Some(UsbDevice {
                bus,
                device,
                vendor_id: vendor.to_ascii_lowercase(),
                product_id: product.to_ascii_lowercase(),
                mtp_candidate: description.to_ascii_lowercase().contains("mtp"),
                description: description.chars().filter(|c| !c.is_control()).collect(),
                serial_available: false,
                serial: None,
                mtp: None,
            })
        })
        .take(MAX_DEVICES)
        .collect()
}

fn attribute(path: &Path, name: &str) -> Option<String> {
    let value = std::fs::read_to_string(path.join(name)).ok()?;
    let value = value.trim();
    (!value.is_empty() && value.len() <= 512 && !value.chars().any(char::is_control))
        .then(|| value.to_owned())
}

fn enrich_usb(devices: &mut [UsbDevice], sysfs: &Path, include_identifiers: bool) {
    let Ok(entries) = std::fs::read_dir(sysfs) else {
        return;
    };
    // Only metadata exported by the kernel; no USB commands or device writes.
    let paths: Vec<_> = entries.flatten().take(1024).map(|e| e.path()).collect();
    for device in devices {
        let Some(path) = paths.iter().find(|path| {
            attribute(path, "busnum").and_then(|s| s.parse().ok()) == Some(device.bus)
                && attribute(path, "devnum").and_then(|s| s.parse().ok()) == Some(device.device)
        }) else {
            continue;
        };
        let serial = attribute(path, "serial");
        device.serial_available = serial.is_some();
        if include_identifiers {
            device.serial = serial;
        }
        if let Some(name) = path.file_name().and_then(|n| n.to_str()) {
            device.mtp_candidate |= paths.iter().any(|interface| {
                interface
                    .file_name()
                    .and_then(|n| n.to_str())
                    .is_some_and(|n| {
                        n.starts_with(&format!("{name}:"))
                            && attribute(interface, "bInterfaceClass").as_deref() == Some("06")
                    })
            });
        }
    }
}

fn parse_space(uri: &str, output: &str) -> Option<StorageSpace> {
    let number = |key: &str| {
        output.lines().find_map(|line| {
            let (name, value) = line.trim().split_once(": ")?;
            (name == key)
                .then(|| value.trim().parse::<u64>().ok())
                .flatten()
        })
    };
    let capacity = number("filesystem::size");
    let free = number("filesystem::free");
    if capacity.is_none() && free.is_none()
        || matches!((capacity, free), (Some(c), Some(f)) if f > c)
    {
        return None;
    }
    Some(StorageSpace {
        uri: uri.into(),
        capacity_bytes: capacity,
        free_bytes: free,
    })
}

fn storage_uri(root: &str, uri: &str) -> bool {
    uri.strip_prefix(root).is_some_and(|name| {
        let name = name.strip_suffix('/').unwrap_or(name);
        let lower = name.to_ascii_lowercase();
        !name.is_empty()
            && name.len() <= 1024
            && !name.contains(['/', '?', '#'])
            && !["%2f", "%5c", "%2e", "%00"]
                .iter()
                .any(|encoded| lower.contains(encoded))
            && !name.chars().any(char::is_control)
            && !matches!(name, "." | "..")
    })
}

fn mtp(root: &str, run: &mut impl FnMut(&str, &[&str]) -> Result<String>) -> MtpReport {
    let mut report = MtpReport {
        uri: root.into(),
        status: "unavailable".into(),
        storages: vec![],
        issues: vec![],
    };
    // Try an already-mounted device first. With explicit --mtp, opening a GIO
    // mount is permitted; never unmount a session another application owns.
    let listing = match run("gio", &["list", "-u", root]) {
        Ok(listing) => listing,
        Err(_) => {
            if run("gio", &["mount", root]).is_err() {
                report.issues.push("MTP unavailable: install gvfs-backends, unlock the phone, select File transfer and check ChromeOS USB sharing/Linux USB permissions. Close competing MTP clients; no sudo or permission changes are performed.".into());
                return report;
            }
            match run("gio", &["list", "-u", root]) {
                Ok(listing) => listing,
                Err(_) => {
                    report
                        .issues
                        .push("MTP mount opened but storage enumeration failed.".into());
                    return report;
                }
            }
        }
    };
    report.status = "space_unknown".into();
    for uri in listing
        .lines()
        .filter(|uri| storage_uri(root, uri))
        .take(MAX_STORAGES)
    {
        if let Ok(output) = run(
            "gio",
            &["info", "-f", "-a", "filesystem::size,filesystem::free", uri],
        ) && let Some(space) = parse_space(uri, &output)
        {
            report.storages.push(space);
        }
    }
    if report.storages.is_empty() {
        report.issues.push("MTP connected, but the backend did not report storage capacity/free space; unknown is not zero.".into());
    } else {
        report.status = "space_reported".into();
    }
    report
}

fn network(addresses: &str, routes: &str) -> Result<NetworkReport> {
    let addresses: Vec<Value> = serde_json::from_str(addresses)?;
    let routes: Vec<Value> = serde_json::from_str(routes)?;
    let mut result = NetworkReport::default();
    for interface in addresses.iter().take(256) {
        if let Some(name) = interface["ifname"].as_str() {
            let addresses = interface["addr_info"]
                .as_array()
                .map(|items| {
                    items
                        .iter()
                        .filter_map(|item| item["local"].as_str().map(str::to_owned))
                        .collect()
                })
                .unwrap_or_default();
            result.interfaces.push(Interface {
                name: name.into(),
                addresses,
            });
        }
    }
    for route in routes
        .iter()
        .filter(|route| route["dst"] == "default")
        .take(64)
    {
        if let Some(interface) = route["dev"].as_str() {
            let gateway = route["gateway"].as_str().map(str::to_owned);
            result.crostini_gateway_observed |= gateway
                .as_deref()
                .is_some_and(|ip| ip.starts_with("100.115.92."));
            result.default_routes.push(DefaultRoute {
                interface: interface.into(),
                gateway,
            });
        }
    }
    Ok(result)
}

/// Enumerate local USB/network metadata. --mtp is opt-in because it opens a
/// device session. Neither mode reads phone files or writes to the object store.
pub fn diagnose(contact_mtp: bool, include_identifiers: bool) -> PhoneReport {
    let mut report = PhoneReport {
        schema: "rbq.phone.diagnostics.v1",
        usb: vec![],
        network: NetworkReport::default(),
        peer: None,
        adb: None,
        same_physical_phone: "unknown",
        issues: vec![],
        safety: vec![
            "USB bus/device numbers are ephemeral; VID/PID and USB serials are observations, not authentication.",
            "MTP is metadata-only here, not a safe database export or a Rebeqah synchronization transport.",
            "A default gateway or an answering peer does not establish that USB, hotspot and peer are the same phone.",
            "ChromeOS Phone Hub/Instant Tethering identity is not exposed by standard Crostini Linux APIs; inspect host settings and pair the peer explicitly.",
            "No LAN scanning, automatic peer enrollment, ADB activation, privilege escalation or file transfers are performed.",
        ],
    };
    if !cfg!(target_os = "linux") {
        report
            .issues
            .push("USB discovery currently supports Linux only.".into());
        return report;
    }
    match text("lsusb", &[]) {
        Ok(output) => report.usb = parse_lsusb(&output),
        Err(_) => report.issues.push(
            "USB inventory unavailable; install usbutils and check Linux USB sharing.".into(),
        ),
    }
    enrich_usb(
        &mut report.usb,
        Path::new("/sys/bus/usb/devices"),
        include_identifiers,
    );
    if contact_mtp {
        for device in report
            .usb
            .iter_mut()
            .filter(|d| d.mtp_candidate)
            .take(MAX_MTP_DEVICES)
        {
            device.mtp = Some(mtp(&device.uri(), &mut text));
        }
    }
    match (text("ip", &["-j", "address"]), text("ip", &["-j", "route"])) {
        (Ok(addresses), Ok(routes)) => match network(&addresses, &routes) {
            Ok(network) => report.network = network,
            Err(_) => report
                .issues
                .push("Network helper returned invalid JSON.".into()),
        },
        _ => report.issues.push(
            "Network inventory unavailable; install iproute2. No phone IP was inferred.".into(),
        ),
    }
    report
}

/// Contact only an explicitly selected HTTP endpoint. Status does not prove
/// that it is the observed USB device or the Chromebook's tethering provider.
#[cfg(feature = "peer-http")]
pub fn probe_peer(connection: &str, token: Option<&str>) -> Result<Value> {
    let target = crate::peer::parse_connection(connection, token)?;
    let endpoint = target.base.clone();
    let secret = target.token.clone();
    let status = crate::peer::Peer::connect(target)
        .with_retries(0)
        .with_timeout(std::time::Duration::from_secs(TIMEOUT))
        .status()?;
    // Never include arbitrary peer JSON or a connection-string token in reports.
    Ok(serde_json::json!({
        "endpoint": endpoint,
        "reachable": true,
        "protocol": status.get("protocol").and_then(Value::as_str),
        "version": status.get("version").and_then(Value::as_str).map(|s| s.replace(&secret, "<redacted>").chars().take(80).collect::<String>()),
        "identity_assurance": "unverified",
        "same_physical_phone": "unknown",
        "transport_encrypted": false,
    }))
}

/// Human instructions only. No commands are executed by rendering this guide.
pub fn instructions(transport: &str, chromebook: bool) -> Result<String> {
    anyhow::ensure!(
        ["all", "usb", "tcp", "bluetooth"].contains(&transport),
        "unknown phone transport"
    );
    let mut text = String::from(
        "Rebeqah phone connection guide\n\nKeep another copy of important phone data. Pair only a phone you control.\nNothing below is executed automatically; enabling ADB or changing connectivity requires your explicit approval.\n\n",
    );
    if chromebook {
        text.push_str("CHROMEBOOK / CROSTINI\n- Unlock the phone. In ChromeOS Settings > Developers > Linux development environment > Manage USB devices (wording varies), share the Android device with Linux if offered. Developer Mode is not required and is not recommended here.\n- ChromeOS Files/Phone Hub and Linux are different environments. The host may own the MTP session or Bluetooth adapter; close competing file-manager sessions. USB visibility does not imply read/write permission. Do not chmod device nodes or run rbq as root.\n- Inspect ChromeOS Settings > Network > the connected network for its actual gateway/IP. Inside Crostini, 100.115.92.x is a virtual gateway, not a discovered phone. Phone Hub identity is not a standard Linux API and does not authenticate a peer.\n\n");
    }
    if transport == "all" || transport == "usb" {
        text.push_str("USB: MTP STORAGE DIAGNOSTICS\n1. Use a data-capable cable, unlock Android, choose USB > File transfer / Android Auto (MTP).\n2. On Debian Linux, install helpers if wanted: sudo apt install usbutils libmtp-runtime gvfs-backends\n3. Run: lsusb\n   rbq phone diagnose --mtp\n   mtp-detect\n   gio mount -li\n   gio list -u 'mtp://[usb:001,002]/'\n   gio info -f -a filesystem::size,filesystem::free 'mtp://[usb:001,002]/Internal%20shared%20storage'\n   Substitute the CURRENT bus/device numbers and storage URI returned by gio; names vary. Capacity/free bytes may be unavailable; unknown is not zero.\nMTP is NOT a Rebeqah peer channel and does not safely export live databases.\n\nUSB: DIRECT PEER SYNC THROUGH AN APPROVED ADB TUNNEL\n1. Optional: sudo apt install adb\n2. Enable Android Developer options > USB debugging, then explicitly approve this computer's RSA prompt. ChromeOS may require USB sharing with Linux.\n3. Run: adb devices -l\n   Select the exact authorized SERIAL; do not guess if several devices are connected.\n4. Open Rebeqah and enable Sharing. Read its actual listening PORT (often 8787).\n5. Run: adb -s SERIAL forward --no-rebind tcp:18787 tcp:PORT\n   rbq peer status http://127.0.0.1:18787 --token-file /private/peer-token\n   rbq peer push http://127.0.0.1:18787 --token-file /private/peer-token\n6. Free-space check after ADB authorization:\n   adb -s SERIAL shell df -h /data /storage/emulated/0\n7. Remove only the tunnel you created:\n   adb -s SERIAL forward --remove tcp:18787\nDisable USB debugging/revoke debugging authorizations when finished if no longer needed. MTP mode does not authorize ADB. Never enable an unauthenticated ADB TCP listener for convenience.\n\n");
    }
    if transport == "all" || transport == "tcp" {
        text.push_str("TCP/IP: WIFI HOTSPOT, SHARED WIFI OR USB TETHERING\n1. Connect the Chromebook to the phone's hotspot, put both on trusted Wi-Fi, or enable Android USB tethering if supported by ChromeOS. USB tethering can change/replace MTP mode.\n2. Open Rebeqah, enable Sharing, and use the phone's displayed address and PORT. Do not assume that the Crostini gateway is the phone.\n3. Store the app's peer token in an owner-only file (chmod 600 /private/peer-token); avoid tokens in shell history. Use the connection string the app shows (it pins the phone's key with peer=ID). Then run:\n   rbq phone diagnose --peer 'https://PHONE_IP:PORT?peer=ID' --token-file /private/peer-token\n   rbq peer status 'https://PHONE_IP:PORT?peer=ID' --token-file /private/peer-token\n   rbq peer push 'https://PHONE_IP:PORT?peer=ID' --token-file /private/peer-token\n   rbq peer pull 'https://PHONE_IP:PORT?peer=ID' --token-file /private/peer-token\n4. If unreachable, check Sharing, host routes/firewall and hotspot client isolation. No scanning or firewall changes are automatic.\nRebeqah serves HTTPS (and QUIC) pinned to the phone's own key: copy the pin by QR code or compare the fingerprint the app shows. A successful status query does not bind the network endpoint to USB identity.\nOptional Android 11+ Wireless debugging is a separate ADB facility: pair using adb pair PHONE_IP:PAIRING_PORT, then adb connect PHONE_IP:DEBUG_PORT, approve on the phone, and use the explicit-device forward above. The two ports may differ; do not use legacy adb tcpip 5555 on an untrusted network.\n\n");
    }
    if transport == "all" || transport == "bluetooth" {
        text.push_str("BLUETOOTH: HOST PAIRING AND OPTIONAL IP TETHERING\n1. Pair phone and Chromebook in ChromeOS Bluetooth settings; confirm matching pairing codes on BOTH devices. Linux bluetoothctl may see no adapter because ChromeOS owns it.\n2. If Android offers Bluetooth tethering AND ChromeOS can join that phone's PAN/network, enable it through the host settings. Pairing/Phone Hub alone does not establish an IP route. Support varies by Chromebook/phone; if no PAN option exists, use USB or Wi-Fi instead.\n3. Only after a usable IP link exists, open Rebeqah Sharing and use the TCP/IP commands with the phone's reachable IP and actual port. Confirm reachability explicitly; do not equate a Bluetooth name, MAC, SSID or gateway with authenticated peer identity.\nRaw Bluetooth RFCOMM, BLE object exchange, OBEX file transfer and automatic PAN setup are NOT implemented by rbq. Bluetooth is supported as a possible host-provided IP carrier, not claimed as a native peer protocol.\n\n");
    }
    text.push_str("IDENTITY AND SAFETY\nUSB serials, Bluetooth MACs/names, randomized Wi-Fi MACs and IP addresses are different identifiers and may change or be spoofed. There is no universal standard ID linking them. Select the authorized ADB serial and the Rebeqah connection/token deliberately. Diagnostics never mark USB, tethering provider and peer as the same physical phone automatically. Read-only diagnostics do not enroll a peer or bypass encrypted-backup requirements for Git exchange.\n");
    Ok(text)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sysfs_serial_is_opt_in_not_implicit_enrollment() {
        let root = tempfile::tempdir().unwrap();
        let device = root.path().join("1-1");
        std::fs::create_dir(&device).unwrap();
        for (name, value) in [
            ("busnum", "1"),
            ("devnum", "2"),
            ("serial", "private-serial"),
        ] {
            std::fs::write(device.join(name), value).unwrap();
        }
        let mut devices = parse_lsusb("Bus 001 Device 002: ID 04e8:6860 Android MTP");
        enrich_usb(&mut devices, root.path(), false);
        assert!(devices[0].serial_available);
        assert!(devices[0].serial.is_none());
        assert!(
            !serde_json::to_string(&devices)
                .unwrap()
                .contains("private-serial")
        );
        enrich_usb(&mut devices, root.path(), true);
        assert_eq!(devices[0].serial.as_deref(), Some("private-serial"));
    }

    #[test]
    fn adb_diagnostics_parse_realistic_rows_without_inventing_space() {
        let addresses = adb_addresses(
            "inet 127.0.0.1/8 scope host lo\n inet 192.168.43.1/24 brd 192.168.43.255 scope global wlan0\ninet6 fe80::123/64 scope link\n",
        );
        assert_eq!(addresses, vec!["192.168.43.1", "fe80::123"]);
        let storages = adb_space(
            "Filesystem 1K-blocks Used Available Use% Mounted on\n/dev/block/dm-1 1000 250 750 25% /data\n",
        );
        assert_eq!(storages[0].capacity_bytes, Some(1024000));
        assert_eq!(storages[0].free_bytes, Some(768000));
        assert!(adb_space("Permission denied").is_empty());
        assert!(probe_adb("--arbitrary-option", false).is_err());
        assert!(probe_adb("serial;command", false).is_err());
    }

    #[test]
    fn printed_guides_cover_direct_connections_without_claiming_native_bluetooth() {
        for mode in ["all", "usb", "tcp", "bluetooth"] {
            let guide = instructions(mode, true).unwrap();
            assert!(guide.contains("CHROMEBOOK / CROSTINI"));
            assert!(guide.contains("IDENTITY AND SAFETY"));
        }
        assert!(
            instructions("usb", false)
                .unwrap()
                .contains("forward --no-rebind")
        );
        assert!(
            instructions("bluetooth", true)
                .unwrap()
                .contains("NOT implemented")
        );
        assert!(
            instructions("all", true)
                .unwrap()
                .contains("MTP is NOT a Rebeqah peer channel")
        );
        assert!(instructions("unsupported", true).is_err());
    }

    #[test]
    fn lsusb_candidates_are_observations_not_ids() {
        let devices = parse_lsusb(
            "Bus 001 Device 001: ID 1d6b:0002 Linux root hub\nBus 001 Device 002: ID 04e8:6860 Samsung (MTP mode)\nBus 002 Device 003: ID abcd:1234 Keyboard\nBus xyz Device 003: ID abcd:1234 invalid\n",
        );
        assert_eq!(devices.len(), 2);
        assert!(devices[0].mtp_candidate);
        assert_eq!(devices[0].uri(), "mtp://[usb:001,002]/");
        assert!(!devices[1].mtp_candidate);
        assert!(devices[0].serial.is_none());
    }

    #[test]
    fn space_is_optional_and_inconsistent_values_are_refused() {
        assert!(parse_space("mtp://x/", "filesystem::type: mtp").is_none());
        assert!(parse_space("mtp://x/", "filesystem::size: 20\nfilesystem::free: 30").is_none());
        let space = parse_space(
            "mtp://x/",
            "filesystem::size: 5000000000\nfilesystem::free: 0",
        )
        .unwrap();
        assert_eq!(space.capacity_bytes, Some(5_000_000_000));
        assert_eq!(space.free_bytes, Some(0));
    }

    #[test]
    fn mtp_enumeration_cannot_redirect_to_another_device_or_network() {
        let root = "mtp://[usb:001,002]/";
        assert!(storage_uri(root, "mtp://[usb:001,002]/Internal%20storage"));
        for bad in [
            "https://evil.invalid/x",
            "mtp://[usb:001,003]/x",
            "mtp://[usb:001,002]/../x",
            "mtp://[usb:001,002]/..",
            "mtp://[usb:001,002]/x?query",
            "mtp://[usb:001,002]/%2e%2e",
            "mtp://[usb:001,002]/Internal%2f..",
        ] {
            assert!(!storage_uri(root, bad));
        }
        let mut calls = vec![];
        let report = mtp(root, &mut |program, args| {
            calls.push((
                program.to_owned(),
                args.iter().map(|s| s.to_string()).collect::<Vec<_>>(),
            ));
            if args[0] == "list" {
                Ok(format!("https://evil.invalid/x\n{root}Internal\n"))
            } else {
                Ok("filesystem::size: 100\nfilesystem::free: 50".into())
            }
        });
        assert_eq!(report.status, "space_reported");
        assert_eq!(report.storages.len(), 1);
        assert_eq!(calls.len(), 2);
        assert_eq!(calls[1].1[0], "info");
    }

    #[test]
    fn unavailable_mtp_is_not_reported_as_a_full_or_empty_phone() {
        let report = mtp("mtp://[usb:001,002]/", &mut |_, _| {
            anyhow::bail!("backend missing")
        });
        assert_eq!(report.status, "unavailable");
        assert!(report.storages.is_empty());
        assert!(!report.issues.is_empty());
    }

    #[test]
    fn crostini_route_is_not_a_phone_address() {
        let report = network(
            r#"[{"ifname":"eth0","addr_info":[{"local":"100.115.92.26"}]}]"#,
            r#"[{"dst":"default","gateway":"100.115.92.25","dev":"eth0"}]"#,
        )
        .unwrap();
        assert!(report.crostini_gateway_observed);
        assert_eq!(
            report.default_routes[0].gateway.as_deref(),
            Some("100.115.92.25")
        );
    }
}
