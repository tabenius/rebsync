//! `rbq serve`: a local, read-only instructions and status page.
//!
//! Serves HTTPS on localhost by default, with a self-signed certificate that is
//! generated once and kept owner-only under the private state directory (its
//! SHA-256 fingerprint is printed so a browser warning can be checked, not
//! clicked through blindly). Plain HTTP is available with `tls = false`.
//!
//! The page is built from the effective configuration and the object store:
//! enabled layers with snapshot counts and freshness, storage location,
//! phone-sync and offline-git recipes, and the journal location. It never
//! includes secrets: the backup repository URL is redacted, tokens and
//! password files are never read. Nothing can be changed through it.
//!
//! When the network allows, the service announces itself as
//! `_rbq._tcp` (and `_https._tcp` / `_http._tcp`), trying in order:
//! the system Avahi daemon (`avahi-publish-service`, which talks to Avahi
//! over D-Bus), then a built-in mDNS responder; and it posts a desktop
//! notification over the D-Bus session bus when one exists. Each mechanism
//! reports whether it worked; none is required.

use crate::{config::Config, storage::ObjectStorage};
use anyhow::{Context, Result};
use serde::Serialize;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::{
    net::{IpAddr, Ipv4Addr},
    path::{Path, PathBuf},
    process::Child,
};

pub const SERVICE_TYPE: &str = "_rbq._tcp";

#[derive(Clone, Debug)]
pub struct ServeOptions {
    pub bind: IpAddr,
    pub port: u16,
    pub tls: bool,
    pub announce: bool,
}

impl Default for ServeOptions {
    fn default() -> Self {
        Self {
            bind: IpAddr::V4(Ipv4Addr::LOCALHOST),
            port: 8790,
            tls: true,
            announce: true,
        }
    }
}

#[derive(Debug, Serialize)]
pub struct Announcement {
    pub mechanism: String,
    pub ok: bool,
    pub detail: String,
}

/// A running server; dropping it stops announcements (the server thread
/// stops with the process).
pub struct Running {
    pub url: String,
    pub port: u16,
    pub tls: bool,
    pub fingerprint: Option<String>,
    pub announcements: Vec<Announcement>,
    server: std::sync::Arc<tiny_http::Server>,
    avahi: Option<Child>,
    mdns: Option<mdns_sd::ServiceDaemon>,
}

impl Running {
    /// Serve until the process ends.
    pub fn wait(self, config: &Config, storage: &dyn ObjectStorage) {
        for request in self.server.incoming_requests() {
            handle(request, config, storage, self.tls);
        }
    }

    /// Handle at most one request (tests).
    pub fn serve_one(&self, config: &Config, storage: &dyn ObjectStorage) -> Result<()> {
        let request = self.server.recv()?;
        handle(request, config, storage, self.tls);
        Ok(())
    }
}

impl Drop for Running {
    fn drop(&mut self) {
        if let Some(mut child) = self.avahi.take() {
            let _ = child.kill();
            let _ = child.wait();
        }
        if let Some(daemon) = self.mdns.take() {
            let _ = daemon.shutdown();
        }
    }
}

fn private_file(path: &Path, bytes: &[u8]) -> Result<()> {
    let mut options = std::fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    use std::io::Write;
    options.open(path)?.write_all(bytes)?;
    Ok(())
}

/// Load or create the self-signed localhost certificate. Returns PEM cert,
/// PEM key and the certificate's SHA-256 fingerprint.
pub fn certificate(dir: &Path, names: Vec<String>) -> Result<(Vec<u8>, Vec<u8>, String)> {
    crate::sync::private_dir(dir)?;
    let (cert_path, key_path) = (dir.join("localhost.crt.pem"), dir.join("localhost.key.pem"));
    if !cert_path.exists() || !key_path.exists() {
        let _ = std::fs::remove_file(&cert_path);
        let _ = std::fs::remove_file(&key_path);
        let issued = rcgen::generate_simple_self_signed(names).context("generate certificate")?;
        private_file(&key_path, issued.signing_key.serialize_pem().as_bytes())?;
        private_file(&cert_path, issued.cert.pem().as_bytes())?;
    }
    let cert = std::fs::read(&cert_path)?;
    let key = std::fs::read(&key_path)?;
    let der = pem_body(&cert).context("certificate PEM is unreadable")?;
    let digest = Sha256::digest(&der);
    let fingerprint = digest
        .iter()
        .map(|b| format!("{b:02X}"))
        .collect::<Vec<_>>()
        .join(":");
    Ok((cert, key, fingerprint))
}

/// Decode the first PEM block (base64 body) without another dependency.
fn pem_body(pem: &[u8]) -> Option<Vec<u8>> {
    let text = std::str::from_utf8(pem).ok()?;
    let body: String = text
        .lines()
        .skip_while(|l| !l.starts_with("-----BEGIN"))
        .skip(1)
        .take_while(|l| !l.starts_with("-----END"))
        .collect();
    let mut out = Vec::new();
    let mut buffer = 0u32;
    let mut bits = 0;
    for c in body.bytes() {
        let value = match c {
            b'A'..=b'Z' => c - b'A',
            b'a'..=b'z' => c - b'a' + 26,
            b'0'..=b'9' => c - b'0' + 52,
            b'+' => 62,
            b'/' => 63,
            b'=' => break,
            _ => continue,
        } as u32;
        buffer = (buffer << 6) | value;
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            out.push((buffer >> bits) as u8);
            buffer &= (1 << bits) - 1;
        }
    }
    (!out.is_empty()).then_some(out)
}

fn hostname() -> String {
    std::fs::read_to_string("/etc/hostname")
        .ok()
        .map(|h| h.trim().to_owned())
        .filter(|h| !h.is_empty())
        .unwrap_or_else(|| "rbq".into())
}

fn which(program: &str) -> Option<PathBuf> {
    std::env::var_os("PATH").and_then(|paths| {
        std::env::split_paths(&paths)
            .map(|dir| dir.join(program))
            .find(|candidate| candidate.is_file())
    })
}

fn announce(
    options: &ServeOptions,
    port: u16,
    url: &str,
) -> (
    Vec<Announcement>,
    Option<Child>,
    Option<mdns_sd::ServiceDaemon>,
) {
    let mut report = Vec::new();
    let (mut avahi, mut mdns) = (None, None);
    let instance = format!("rbq on {}", hostname());
    let scheme = if options.tls { "https" } else { "http" };
    let loopback_only = options.bind.is_loopback();
    if loopback_only {
        report.push(Announcement {
            mechanism: "zeroconf".into(),
            ok: false,
            detail: "bound to localhost only; not advertised on the network (use --bind to share)"
                .into(),
        });
    } else if let Some(program) = which("avahi-publish-service") {
        // Avahi owns mDNS on most Linux desktops; publish through it (D-Bus).
        match std::process::Command::new(program)
            .args([
                &instance,
                SERVICE_TYPE,
                &port.to_string(),
                "path=/",
                &format!("scheme={scheme}"),
            ])
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .spawn()
        {
            Ok(child) => {
                avahi = Some(child);
                report.push(Announcement {
                    mechanism: "avahi".into(),
                    ok: true,
                    detail: format!("published {SERVICE_TYPE} via the system Avahi daemon"),
                });
            }
            Err(error) => report.push(Announcement {
                mechanism: "avahi".into(),
                ok: false,
                detail: format!("avahi-publish-service failed: {error}"),
            }),
        }
    }
    if !loopback_only && avahi.is_none() {
        let built_in = (|| -> Result<mdns_sd::ServiceDaemon> {
            let daemon = mdns_sd::ServiceDaemon::new()?;
            let host = format!("{}.local.", hostname());
            let properties = [("path", "/"), ("scheme", scheme)];
            let addresses = if options.bind.is_unspecified() {
                String::new()
            } else {
                options.bind.to_string()
            };
            let mut info = mdns_sd::ServiceInfo::new(
                &format!("{SERVICE_TYPE}.local."),
                &instance,
                &host,
                addresses.as_str(),
                port,
                &properties[..],
            )?;
            if options.bind.is_unspecified() {
                info = info.enable_addr_auto();
            }
            daemon.register(info)?;
            Ok(daemon)
        })();
        match built_in {
            Ok(daemon) => {
                mdns = Some(daemon);
                report.push(Announcement {
                    mechanism: "mdns".into(),
                    ok: true,
                    detail: format!("built-in mDNS responder advertising {SERVICE_TYPE}"),
                });
            }
            Err(error) => report.push(Announcement {
                mechanism: "mdns".into(),
                ok: false,
                detail: format!("multicast DNS unavailable: {error:#}"),
            }),
        }
    }
    // A desktop notification over the D-Bus session bus, when there is one.
    if std::env::var_os("DBUS_SESSION_BUS_ADDRESS").is_some()
        && let Some(gdbus) = which("gdbus")
    {
        let status = std::process::Command::new(gdbus)
            .args([
                "call",
                "--session",
                "--dest",
                "org.freedesktop.Notifications",
                "--object-path",
                "/org/freedesktop/Notifications",
                "--method",
                "org.freedesktop.Notifications.Notify",
                "rbq",
                "0",
                "",
                "rbq is serving instructions",
                url,
                "[]",
                "{}",
                "8000",
            ])
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .status();
        report.push(Announcement {
            mechanism: "dbus-notification".into(),
            ok: status.as_ref().is_ok_and(|s| s.success()),
            detail: match status {
                Ok(s) if s.success() => "desktop notification sent on the session bus".into(),
                _ => "no notification service answered on the session bus".into(),
            },
        });
    } else {
        report.push(Announcement {
            mechanism: "dbus-notification".into(),
            ok: false,
            detail: "no D-Bus session bus (or gdbus) available".into(),
        });
    }
    (report, avahi, mdns)
}

/// Bind, prepare TLS and announce. Serving starts with [`Running::wait`].
pub fn start(config: &Config, options: &ServeOptions) -> Result<Running> {
    let address = std::net::SocketAddr::new(options.bind, options.port);
    let (server, fingerprint) = if options.tls {
        let mut names = vec![
            "localhost".to_owned(),
            "127.0.0.1".to_owned(),
            "::1".to_owned(),
        ];
        names.push(format!("{}.local", hostname()));
        let (certificate, private_key, fingerprint) =
            certificate(&crate::sync::state_dir(config)?.join("tls"), names)?;
        let server = tiny_http::Server::https(
            address,
            tiny_http::SslConfig {
                certificate,
                private_key,
            },
        )
        .map_err(|e| anyhow::anyhow!("cannot listen on {address}: {e}"))?;
        (server, Some(fingerprint))
    } else {
        let server = tiny_http::Server::http(address)
            .map_err(|e| anyhow::anyhow!("cannot listen on {address}: {e}"))?;
        (server, None)
    };
    let port = server
        .server_addr()
        .to_ip()
        .map(|a| a.port())
        .context("listener has no IP address")?;
    let scheme = if options.tls { "https" } else { "http" };
    let host = if options.bind.is_loopback() || options.bind.is_unspecified() {
        "localhost".to_owned()
    } else {
        options.bind.to_string()
    };
    let url = format!("{scheme}://{host}:{port}/");
    let (announcements, avahi, mdns) = if options.announce {
        announce(options, port, &url)
    } else {
        (Vec::new(), None, None)
    };
    Ok(Running {
        url,
        port,
        tls: options.tls,
        fingerprint,
        announcements,
        server: std::sync::Arc::new(server),
        avahi,
        mdns,
    })
}

/// Machine-readable status; also the source of the HTML page.
///
/// This uses the same read-only collector as `rbq status`, including shared
/// layer locks, so a web request cannot observe a half-written snapshot. The
/// extra service fields are added here because they are specific to `rbq serve`.
pub fn status(config: &Config, storage: &dyn ObjectStorage) -> Value {
    let mut value = crate::status::collect(config, storage, 0).unwrap_or_else(|error| {
        json!({
            "schema": "rbq.status.v1",
            "generated_at": crate::chrono::Utc::now().to_rfc3339(),
            "rbq_home": config.rbq_home,
            "storage_root": config.storage.root,
            "backup": if config.backup.repository.is_some() || config.binaries.repository.is_some() {
                "configured (redacted)"
            } else {
                "not configured"
            },
            "overall": {
                "state": "unavailable",
                "synced": 0,
                "attention": 1,
                "local_only": 0,
                "disabled": 0,
                "occupied_bytes": 0,
                "pending_bytes": 0,
                "logical_bytes": 0,
                "progress": 0.0,
            },
            "layers": [],
            "repositories": [],
            "issues": [error.to_string()],
            "note": "Read-only. Secrets are never shown; repository URLs are redacted.",
        })
    });
    // Keep the older, flattened layer fields for the HTML table and peer tools.
    let layers: Vec<Value> = value["layers"]
        .as_array()
        .cloned()
        .unwrap_or_default()
        .into_iter()
        .map(|mut layer| {
            layer["snapshots"] = layer["stats"]["snapshots"].clone();
            layer["latest"] = layer["stats"]["latest"].clone();
            layer["stored_bytes"] = layer["stats"]["stored_bytes"].clone();
            layer["missing_chunks"] = layer["stats"]["missing_chunks"].clone();
            layer
        })
        .collect();
    value["layers"] = json!(layers);
    value["service"] = json!("rbq");
    value["version"] = json!(env!("CARGO_PKG_VERSION"));
    value["fleet_authority"] = json!(config.fleet.host);
    value
}

fn escape(text: &str) -> String {
    text.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
}

fn bytes(n: Option<u64>) -> String {
    match n {
        None => "–".into(),
        Some(n) if n >= 1_000_000_000 => format!("{:.1} GB", n as f64 / 1e9),
        Some(n) if n >= 1_000_000 => format!("{:.1} MB", n as f64 / 1e6),
        Some(n) if n >= 1_000 => format!("{:.1} KB", n as f64 / 1e3),
        Some(n) => format!("{n} B"),
    }
}

pub fn page(status: &Value) -> String {
    let rows: String = status["layers"]
        .as_array()
        .map(|layers| {
            layers
                .iter()
                .map(|l| {
                    format!(
                        "<tr><td><code>{}</code></td><td>{}</td><td>{}</td><td>{}</td><td>{}</td></tr>",
                        escape(l["layer"].as_str().unwrap_or("")),
                        if l["enabled"] == true { "enabled" } else { "off" },
                        l["snapshots"].as_u64().map(|n| n.to_string()).unwrap_or("–".into()),
                        escape(l["latest"].as_str().unwrap_or("never")),
                        bytes(l["stored_bytes"].as_u64()),
                    )
                })
                .collect()
        })
        .unwrap_or_default();
    let field = |key: &str| {
        escape(
            &status[key]
                .as_str()
                .map(str::to_owned)
                .unwrap_or_else(|| status[key].to_string()),
        )
    };
    format!(
        r#"<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<title>rbq</title>
<style>
:root {{ --ink:#0e1621; --paper:#f4efe6; --amber:#e8a33d; --muted:#6b7480; --line:#d9d2c5; }}
@media (prefers-color-scheme: dark) {{ :root {{ --ink:#f4efe6; --paper:#0e1621; --muted:#9aa6b6; --line:#2a3a50; }} }}
body {{ margin:0; background:var(--paper); color:var(--ink); font:16px/1.55 system-ui,sans-serif; }}
main {{ max-width:860px; margin:0 auto; padding:24px 16px 64px; }}
h1 {{ font-size:22px; margin:0 0 4px; }} h1 b {{ color:var(--amber); letter-spacing:.06em; }}
h2 {{ font-size:15px; text-transform:uppercase; letter-spacing:.08em; color:var(--amber); margin:32px 0 8px; }}
table {{ width:100%; border-collapse:collapse; font-size:14px; }} td,th {{ text-align:left; padding:6px 8px; border-bottom:1px solid var(--line); }}
code,pre {{ font-family:ui-monospace,Menlo,monospace; font-size:13px; }} pre {{ background:rgba(127,127,127,.12); padding:12px; border-radius:8px; overflow-x:auto; }}
.muted {{ color:var(--muted); font-size:14px; }}
</style></head><body><main>
<h1><b>RAGBAZ</b> rbq <span class="muted">{version}</span></h1>
<p class="muted">Preserve work, exchange it safely, report what remains at risk. This page is read-only and shows no secrets. <a href="/v1/status">JSON status</a></p>
<h2>This machine</h2>
<table><tr><th>Rebeqah home</th><td><code>{home}</code></td></tr>
<tr><th>Object store</th><td><code>{store}</code></td></tr>
<tr><th>Encrypted backup</th><td>{backup}</td></tr>
<tr><th>Fleet authority</th><td>{fleet}</td></tr></table>
<h2>Layers</h2>
<table><tr><th>Layer</th><th>--apply</th><th>Snapshots</th><th>Latest</th><th>Stored</th></tr>{rows}</table>
<h2>Everyday</h2>
<pre>rbq                      # dry run: what would be preserved and exchanged
rbq --apply              # preserve repositories, exchange branches, publish enabled layers
rbq storage fsck         # check every stored snapshot, chunk by chunk</pre>
<h2>Layers by hand</h2>
<pre>rbq mneme publish | list | verify ID | restore ID --into PATH
rbq frog publish  | agenda publish | git publish
rbq binaries publish PATH --tool NAME --version VERSION
rbq binaries list | verify ID | restore ID --tool NAME --into PATH
rbq binaries fetch --tool NAME --into PATH   # re-fetch from private R2
rbq &lt;layer&gt; prune --keep-last 7 [--apply]</pre>
<h2>Phone (Rebeqah app)</h2>
<pre>export RBQ_PEER='&lt;connection string from the app's Sharing card&gt;'
rbq peer status
rbq peer push            # this machine → phone
rbq peer pull            # phone → this machine (every snapshot is verified)</pre>
<h2>Offline Git (GitHub down, blocked or far away)</h2>
<pre>rbq git publish &amp;&amp; rbq peer push                  # laptop A
rbq peer pull --layer git                             # laptop B
rbq git fetch ID --repo ~/src/project --as laptop-a   # → refs/remotes/rbq-laptop-a/*</pre>
<p class="muted">Journals are written to the Rebeqah home as <code>rbq_*.jsonl</code>. Uncommitted work is covered by encrypted repository snapshots, not by the git layer.</p>
</main></body></html>"#,
        version = escape(status["version"].as_str().unwrap_or("")),
        home = field("rbq_home"),
        store = field("storage_root"),
        backup = field("backup"),
        fleet = field("fleet_authority"),
    )
}

fn handle(request: tiny_http::Request, config: &Config, storage: &dyn ObjectStorage, tls: bool) {
    let header = |name: &str, value: &str| {
        tiny_http::Header::from_bytes(name.as_bytes(), value.as_bytes()).expect("static header")
    };
    let path = request.url().split('?').next().unwrap_or("/").to_owned();
    let mut response = match (request.method(), path.as_str()) {
        (tiny_http::Method::Get, "/") => {
            tiny_http::Response::from_string(page(&status(config, storage)))
                .with_header(header("Content-Type", "text/html; charset=utf-8"))
        }
        (tiny_http::Method::Get, "/v1/status") => {
            tiny_http::Response::from_string(status(config, storage).to_string())
                .with_header(header("Content-Type", "application/json"))
        }
        (tiny_http::Method::Get, "/healthz") => tiny_http::Response::from_string("ok"),
        _ => tiny_http::Response::from_string("not found").with_status_code(404),
    };
    response.add_header(header(
        "Content-Security-Policy",
        "default-src 'none'; style-src 'unsafe-inline'",
    ));
    response.add_header(header("X-Content-Type-Options", "nosniff"));
    response.add_header(header("Cache-Control", "no-store"));
    if tls {
        response.add_header(header("Strict-Transport-Security", "max-age=300"));
    }
    let _ = request.respond(response);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pem_decoding_matches_der_length() {
        let issued = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
        let der = pem_body(issued.cert.pem().as_bytes()).unwrap();
        assert_eq!(der, issued.cert.der().to_vec());
    }

    #[test]
    fn page_escapes_paths() {
        let html = page(
            &json!({"version":"1","rbq_home":"/home/<x>","storage_root":"/s",
            "backup":"not configured","fleet_authority":"kali-1","layers":[]}),
        );
        assert!(html.contains("/home/&lt;x&gt;") && !html.contains("/home/<x>"));
    }
}
