# Operator terminal (`rbq term`)

A login shell in the browser on every fleet host, over the NetBird or
Tailscale mesh. No SSH keys to distribute, no public port, and no paid RBAC
tier: WireGuard authenticates the device, the mesh names its owner, and one
list in `rbq.toml` says who may log in.

```toml
[term]
# Who may open a shell: Tailscale logins or NetBird peer names.
operators = ["tailscale:you@github", "netbird:laptop.netbird.cloud"]
# Names the page may be loaded under besides the bind address (MagicDNS etc.).
hostnames = ["kali.tail1234.ts.net", "kali.netbird.cloud"]
# shell = "/bin/bash"   # default: $SHELL, then /bin/sh
```

```bash
rbq term serve --bind 100.92.1.7:7681     # this host's mesh address
rbq term whois 100.92.1.20                # who is that peer? operator?
```

Open `http://<mesh address>:7681/` from an operator device on the mesh.

## Sessions that survive the network

The shell runs in a PTY owned by `rbq term`, not by the connection. Every
output byte has an offset; the browser remembers the next one it needs and
asks for it when it reconnects, with backoff, at once when the network or the
tab returns. Typed input waits while offline and is delivered on reconnect.
Nothing is lost while the 1 MiB per-session buffer holds it (a gap is marked
if it no longer does) and nothing is shown twice. A reloaded page replays the
last 64 KiB, so the screen comes back the way tmux would show it. The session
ID is in the URL, so another tab or device of the same operator can attach.

Detached shells live for 24 hours; exited ones are dropped after a minute.
Each operator may hold 8 sessions, each host 32.

For terminal clients, the same mesh carries native mosh, whose UDP state sync
and local echo suit slow links best:

```bash
mosh --ssh="ssh -o StrictHostKeyChecking=accept-new" you@kali.netbird.cloud
tailscale ssh you@kali     # Tailscale SSH: login from the tailnet identity
netbird ssh kali           # NetBird SSH (enable with `netbird up --allow-server-ssh`)
```

## Running it on every host

A user unit, so the shell runs as that user and nothing needs root:

```ini
# ~/.config/systemd/user/rbq-term.service
[Unit]
Description=rbq operator terminal on the mesh
After=network-online.target

[Service]
ExecStart=%h/.cargo/bin/rbq term serve --bind 100.92.1.7:7681
Restart=always
RestartSec=5

[Install]
WantedBy=default.target
```

```bash
systemctl --user daemon-reload
systemctl --user enable --now rbq-term
loginctl enable-linger "$USER"    # keep it running without a login
```

The mesh address must already be up when the unit starts. `Restart=always`
retries until it is.

## Security model

- **Network**: the listener binds only to 100.64.0.0/10, fd7a:115c:a1e0::/48 or,
  with `--allow-loopback`, loopback; never to a LAN or public address. The link
  is the mesh's WireGuard tunnel.
- **Identity**: the peer address is resolved by the local daemon
  (`tailscale whois`, or the peer list of `netbird status`), cached for 60 s.
  Tagged Tailscale devices have no user and are never operators. NetBird
  identifies the peer device, not a person: list only devices that only you
  use.
- **Authorisation**: exact match against `[term].operators`. An empty list
  admits nobody; `rbq term serve` refuses to start without operators unless
  only loopback is wanted. A session belongs to the identity that opened it.
- **Browser**: the WebSocket requires `Origin` to equal the page's own
  origin and `Host` to be the bind address or a configured name, so another
  site in an operator's browser cannot use the operator's mesh identity, and
  DNS rebinding fails. The page is served with a strict CSP and xterm.js is
  bundled in the binary (`crates/rebsync-core/assets/term/VENDOR.md`).
- **Loopback** means "whoever can connect to this host locally", which is
  why it needs `--allow-loopback`. Use it behind an SSH tunnel, not on shared
  machines.
- The shell runs as the user running `rbq term`. Every operator gets that
  user; run one instance per account if operators need different users.

## Not yet

- No local echo prediction (mosh's typing-ahead on slow links); use native
  mosh for that.
- No audit trail beyond the `rbq term: <identity> opened session` log line.
- Operators are per host; a fleet-wide list is distributed with the rest of
  `rbq.toml` (or a future declarative provisioning contract).
