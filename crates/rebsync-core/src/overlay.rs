//! Detect mesh VPN overlays (Tailscale, NetBird) this host is part of.
//!
//! An overlay gives peers a stable, WireGuard-encrypted path between devices
//! on different networks, which is often the simplest way to reach a phone or
//! a headless box. `rbq peer networks` reports what is present, and
//! `rbq peer serve` offers connection strings for overlay addresses.
//!
//! Detection is evidence, not authority:
//!
//! * **Interfaces** are the primary signal. `tailscale*` is Tailscale; `wt*`
//!   and `netbird*` are NetBird (its default Linux interface is `wt0`).
//! * **Address ranges** support it. Tailscale's IPv6 ULA `fd7a:115c:a1e0::/48`
//!   is specific to Tailscale. IPv4 `100.64.0.0/10` is shared by Tailscale,
//!   NetBird and carrier-grade NAT, so an address there on an unrecognised
//!   interface is reported as an unclassified overlay candidate, never
//!   guessed.
//! * **The overlay's own CLI** (`tailscale status --json`,
//!   `netbird status --json`), when installed, adds whether it is connected,
//!   this device's overlay name and how many peers it sees. It runs without a
//!   shell, with a short timeout, and its absence or failure is not an error.
//!
//! Being on an overlay does not make a peer trusted: rbq still pins keys and
//! checks tokens or pairings. The overlay only carries the packets.

use serde::Serialize;
use std::net::IpAddr;

/// An interface address as the operating system reports it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct InterfaceAddress {
    pub interface: String,
    pub address: IpAddr,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum OverlayKind {
    Tailscale,
    Netbird,
    /// An address in 100.64.0.0/10 on an interface we do not recognise:
    /// possibly an overlay, possibly carrier-grade NAT.
    Unclassified,
}

impl OverlayKind {
    pub fn label(self) -> &'static str {
        match self {
            Self::Tailscale => "Tailscale",
            Self::Netbird => "NetBird",
            Self::Unclassified => "100.64.0.0/10 (overlay or carrier NAT)",
        }
    }
}

#[derive(Clone, Debug, Serialize, PartialEq, Eq)]
pub struct OverlayAddress {
    pub kind: OverlayKind,
    pub interface: String,
    pub address: IpAddr,
    /// Why this address was classified so.
    pub evidence: String,
}

/// What an overlay's own CLI says about this device, when available.
#[derive(Clone, Debug, Default, Serialize, PartialEq)]
pub struct OverlayStatus {
    pub connected: Option<bool>,
    /// This device's name on the overlay (MagicDNS / NetBird FQDN).
    pub name: Option<String>,
    pub addresses: Vec<IpAddr>,
    pub peers: Option<usize>,
    pub peers_connected: Option<usize>,
}

#[derive(Clone, Debug, Serialize)]
pub struct OverlayReport {
    pub addresses: Vec<OverlayAddress>,
    pub tailscale: Option<OverlayStatus>,
    pub netbird: Option<OverlayStatus>,
    pub note: &'static str,
}

impl OverlayReport {
    pub fn any(&self) -> bool {
        !self.addresses.is_empty() || self.tailscale.is_some() || self.netbird.is_some()
    }
}

fn in_cgnat(ip: &IpAddr) -> bool {
    matches!(ip, IpAddr::V4(v4) if v4.octets()[0] == 100 && (v4.octets()[1] & 0xc0) == 64)
}

fn in_tailscale_ula(ip: &IpAddr) -> bool {
    matches!(ip, IpAddr::V6(v6) if v6.segments()[..3] == [0xfd7a, 0x115c, 0xa1e0])
}

fn interface_kind(name: &str) -> Option<OverlayKind> {
    let name = name.to_ascii_lowercase();
    if name.starts_with("tailscale") {
        Some(OverlayKind::Tailscale)
    } else if name.starts_with("netbird")
        || (name.starts_with("wt") && name[2..].bytes().all(|b| b.is_ascii_digit()))
    {
        Some(OverlayKind::Netbird)
    } else {
        None
    }
}

/// Classify interface addresses. Pure, so the rules are testable.
pub fn classify(interfaces: &[InterfaceAddress]) -> Vec<OverlayAddress> {
    let mut found = Vec::new();
    for entry in interfaces {
        let ip = entry.address;
        // Link-local addresses are not reachable across an overlay.
        let link_local = match ip {
            IpAddr::V4(v4) => v4.is_link_local(),
            IpAddr::V6(v6) => (v6.segments()[0] & 0xffc0) == 0xfe80,
        };
        if link_local || ip.is_loopback() {
            continue;
        }
        let (kind, evidence) = match (interface_kind(&entry.interface), ip) {
            (Some(kind), _) => (kind, format!("interface {}", entry.interface)),
            (None, ip) if in_tailscale_ula(&ip) => (
                OverlayKind::Tailscale,
                "address in Tailscale's fd7a:115c:a1e0::/48".to_owned(),
            ),
            (None, ip) if in_cgnat(&ip) => (
                OverlayKind::Unclassified,
                format!("address in 100.64.0.0/10 on {}", entry.interface),
            ),
            _ => continue,
        };
        found.push(OverlayAddress {
            kind,
            interface: entry.interface.clone(),
            address: ip,
            evidence,
        });
    }
    found
}

/// Parse `tailscale status --json`. Tolerant of fields being absent.
pub fn parse_tailscale_status(json: &[u8]) -> Option<OverlayStatus> {
    let value: serde_json::Value = serde_json::from_slice(json).ok()?;
    let me = value.get("Self");
    let addresses = me
        .and_then(|me| me.get("TailscaleIPs"))
        .and_then(|ips| ips.as_array())
        .map(|ips| {
            ips.iter()
                .filter_map(|ip| ip.as_str()?.parse().ok())
                .collect()
        })
        .unwrap_or_default();
    let peers = value.get("Peer").and_then(|peers| peers.as_object());
    Some(OverlayStatus {
        connected: value
            .get("BackendState")
            .and_then(|state| state.as_str())
            .map(|state| state == "Running"),
        name: me
            .and_then(|me| me.get("DNSName").or_else(|| me.get("HostName")))
            .and_then(|name| name.as_str())
            .map(|name| name.trim_end_matches('.').to_owned())
            .filter(|name| !name.is_empty()),
        addresses,
        peers: peers.map(|peers| peers.len()),
        peers_connected: peers.map(|peers| {
            peers
                .values()
                .filter(|peer| peer.get("Online").and_then(|o| o.as_bool()) == Some(true))
                .count()
        }),
    })
}

/// Parse `netbird status --json`. Tolerant of fields being absent.
pub fn parse_netbird_status(json: &[u8]) -> Option<OverlayStatus> {
    let value: serde_json::Value = serde_json::from_slice(json).ok()?;
    let address = value
        .get("netbirdIp")
        .and_then(|ip| ip.as_str())
        .and_then(|ip| ip.split('/').next()?.parse().ok());
    let peers = value.get("peers");
    Some(OverlayStatus {
        connected: value
            .get("management")
            .and_then(|m| m.get("connected"))
            .and_then(|c| c.as_bool()),
        name: value
            .get("fqdn")
            .and_then(|name| name.as_str())
            .map(|name| name.trim_end_matches('.').to_owned())
            .filter(|name| !name.is_empty()),
        addresses: address.into_iter().collect(),
        peers: peers
            .and_then(|p| p.get("total"))
            .and_then(|n| n.as_u64())
            .map(|n| n as usize),
        peers_connected: peers
            .and_then(|p| p.get("connected"))
            .and_then(|n| n.as_u64())
            .map(|n| n as usize),
    })
}

/// Addresses of this host's interfaces.
pub fn interfaces() -> Vec<InterfaceAddress> {
    if_addrs::get_if_addrs()
        .unwrap_or_default()
        .into_iter()
        .map(|interface| InterfaceAddress {
            address: interface.ip(),
            interface: interface.name,
        })
        .collect()
}

/// Run an overlay CLI's status command if it is installed. Bounded, no shell.
fn probe(program: &str, args: &[&str]) -> Option<Vec<u8>> {
    let mut command = crate::process::command(program);
    command.args(args);
    crate::process::checked(&mut command, 5).ok()
}

/// Inspect this host. `probe_clis` also asks `tailscale` and `netbird`
/// (when installed) for their status.
pub fn detect(probe_clis: bool) -> OverlayReport {
    let mut addresses = classify(&interfaces());
    let (mut tailscale, mut netbird) = (None, None);
    if probe_clis {
        tailscale = probe("tailscale", &["status", "--json"])
            .and_then(|json| parse_tailscale_status(&json));
        netbird =
            probe("netbird", &["status", "--json"]).and_then(|json| parse_netbird_status(&json));
        // A CLI naming an unclassified address settles which overlay it is.
        for entry in &mut addresses {
            if entry.kind != OverlayKind::Unclassified {
                continue;
            }
            let claimed = |status: &Option<OverlayStatus>| {
                status
                    .as_ref()
                    .is_some_and(|status| status.addresses.contains(&entry.address))
            };
            if claimed(&tailscale) {
                entry.kind = OverlayKind::Tailscale;
                entry.evidence = "tailscale status lists this address".into();
            } else if claimed(&netbird) {
                entry.kind = OverlayKind::Netbird;
                entry.evidence = "netbird status lists this address".into();
            }
        }
    }
    OverlayReport {
        addresses,
        tailscale,
        netbird,
        note: "An overlay carries packets between your devices; rbq still pins keys and checks tokens or pairings.",
    }
}

/// Which overlay addresses a server should start or stop listening on.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct ListenPlan {
    pub bind: Vec<OverlayAddress>,
    pub drop: Vec<IpAddr>,
}

/// Plan listeners for the Tailscale and NetBird addresses in `detected`,
/// given the overlay addresses already `bound` and whether a wildcard
/// listener on the same port already reaches IPv4 / IPv6 addresses.
/// Unclassified 100.64.0.0/10 addresses are never shared automatically: on a
/// phone or a mobile router that range is carrier NAT.
pub fn plan_listeners(
    detected: &[OverlayAddress],
    bound: &[IpAddr],
    wildcard_v4: bool,
    wildcard_v6: bool,
) -> ListenPlan {
    let wanted: Vec<&OverlayAddress> = detected
        .iter()
        .filter(|a| matches!(a.kind, OverlayKind::Tailscale | OverlayKind::Netbird))
        .filter(|a| match a.address {
            IpAddr::V4(_) => !wildcard_v4,
            IpAddr::V6(_) => !wildcard_v6,
        })
        .collect();
    let mut plan = ListenPlan::default();
    for address in &wanted {
        if !bound.contains(&address.address)
            && !plan.bind.iter().any(|b| b.address == address.address)
        {
            plan.bind.push((*address).clone());
        }
    }
    for address in bound {
        if !wanted.iter().any(|a| a.address == *address) {
            plan.drop.push(*address);
        }
    }
    plan
}

#[cfg(test)]
mod tests {
    use super::*;

    fn at(interface: &str, address: &str) -> InterfaceAddress {
        InterfaceAddress {
            interface: interface.into(),
            address: address.parse().unwrap(),
        }
    }

    #[test]
    fn interfaces_and_ranges_are_classified_conservatively() {
        let found = classify(&[
            at("lo", "127.0.0.1"),
            at("eth0", "192.168.1.4"),
            at("tailscale0", "100.101.102.103"),
            at("tailscale0", "fd7a:115c:a1e0::1234"),
            at("tailscale0", "fe80::1"),
            at("wt0", "100.88.0.7"),
            at("utun4", "fd7a:115c:a1e0:ab12::1"),
            at("rmnet0", "100.70.1.2"),
            at("wtf", "100.71.1.2"),
        ]);
        let kinds: Vec<(&str, OverlayKind)> = found
            .iter()
            .map(|f| (f.interface.as_str(), f.kind))
            .collect();
        assert_eq!(
            kinds,
            vec![
                ("tailscale0", OverlayKind::Tailscale),
                ("tailscale0", OverlayKind::Tailscale),
                ("wt0", OverlayKind::Netbird),
                ("utun4", OverlayKind::Tailscale),
                // Carrier NAT on mobile data looks the same: not guessed.
                ("rmnet0", OverlayKind::Unclassified),
                ("wtf", OverlayKind::Unclassified),
            ]
        );
    }

    #[test]
    fn overlay_cli_status_is_parsed_tolerantly() {
        let tailscale = parse_tailscale_status(
            br#"{"BackendState":"Running","Self":{"HostName":"box","DNSName":"box.tail1234.ts.net.","TailscaleIPs":["100.101.102.103","fd7a:115c:a1e0::1234"]},"Peer":{"a":{"Online":true},"b":{"Online":false}}}"#,
        )
        .unwrap();
        assert_eq!(tailscale.connected, Some(true));
        assert_eq!(tailscale.name.as_deref(), Some("box.tail1234.ts.net"));
        assert_eq!(tailscale.addresses.len(), 2);
        assert_eq!(
            (tailscale.peers, tailscale.peers_connected),
            (Some(2), Some(1))
        );

        let netbird = parse_netbird_status(
            br#"{"peers":{"total":3,"connected":2},"management":{"connected":true},"netbirdIp":"100.88.0.7/16","fqdn":"box.netbird.cloud"}"#,
        )
        .unwrap();
        assert_eq!(
            netbird.addresses,
            vec!["100.88.0.7".parse::<IpAddr>().unwrap()]
        );
        assert_eq!(netbird.name.as_deref(), Some("box.netbird.cloud"));
        assert_eq!((netbird.peers, netbird.peers_connected), (Some(3), Some(2)));

        assert_eq!(
            parse_tailscale_status(b"{}").unwrap(),
            OverlayStatus::default()
        );
        assert!(parse_netbird_status(b"not json").is_none());
    }

    #[test]
    fn listeners_follow_overlays_and_skip_what_is_covered_or_unclassified() {
        let found = classify(&[
            at("tailscale0", "100.101.102.103"),
            at("tailscale0", "fd7a:115c:a1e0::1234"),
            at("wt0", "100.88.0.7"),
            at("rmnet0", "100.70.1.2"),
        ]);
        let ip = |s: &str| s.parse::<IpAddr>().unwrap();
        let addresses = |plan: &ListenPlan| plan.bind.iter().map(|a| a.address).collect::<Vec<_>>();
        // Nothing bound yet: both overlays, both families; never carrier NAT.
        let plan = plan_listeners(&found, &[], false, false);
        assert_eq!(
            addresses(&plan),
            vec![
                ip("100.101.102.103"),
                ip("fd7a:115c:a1e0::1234"),
                ip("100.88.0.7")
            ]
        );
        assert!(plan.drop.is_empty());
        // A 0.0.0.0 listener on the same port already reaches IPv4 overlays.
        let plan = plan_listeners(&found, &[], true, false);
        assert_eq!(addresses(&plan), vec![ip("fd7a:115c:a1e0::1234")]);
        // Already bound: nothing to do. An overlay that went away is dropped.
        let bound = [ip("100.101.102.103"), ip("100.88.0.7"), ip("100.99.0.1")];
        let plan = plan_listeners(&found, &bound, false, true);
        assert!(plan.bind.is_empty());
        assert_eq!(plan.drop, vec![ip("100.99.0.1")]);
    }

    #[test]
    fn detection_runs_on_any_host_without_overlays() {
        // This host may or may not be on an overlay; detection must not fail
        // or hang when neither CLI is installed.
        let report = detect(true);
        assert!(report.addresses.iter().all(|a| !a.address.is_loopback()));
    }
}
