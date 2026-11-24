# Headless and unattended rbq peers

`rbq peer` never prompts. Every command takes its input from flags, files,
stdin or the environment, writes JSON on stdout (with `--json`, or always for
`peer id`, `peer pair add` and `peer pair invite`), and reports success with
its exit status. That makes it usable from systemd, containers, provisioning
tools and scripts on machines nobody is logged in to.

## Environment

| Variable | Used by | Meaning |
| --- | --- | --- |
| `RBQ_LISTEN` | `peer serve` | Listen addresses, comma-separated (`quic://0.0.0.0:8788,unix:///run/user/1000/rbq.sock`). Optional on a Tailscale/NetBird host. |
| `RBQ_NO_OVERLAYS` | `peer serve` | `true`: do not share over Tailscale/NetBird automatically. |
| `RBQ_OVERLAY_PORT` | `peer serve` | UDP port for overlay listeners (default: the first `quic://` port, else 8788). |
| `RBQ_TOKEN_FILE` | `peer serve`, `peer status/push/pull` | Owner-only file with the shared token. Optional for QUIC between paired devices. |
| `RBQ_QUIC_IDENTITY` | every `peer` command | Directory of this device's key. Its pairings are kept in `paired/` inside it. Default: `quic-identity/` and `paired/` under rbq's state directory. |
| `RBQ_PEER` | `peer status/push/pull` | Connection string or `paired:NAME`, so tokens and pins stay out of shell history. |

Use the same identity for `serve` and for `pair` commands: pairings only count
when this device's own key signed them.

## Exit status

`0` success; `2` a sync completed with conflicts, rejections or failed
verification (see the JSON report); `1` (or another non-zero code) the command
failed. `peer serve` exits `0` after SIGTERM, SIGINT or SIGHUP, having stopped
its servers cleanly.

## Run a server under systemd

[`examples/systemd/rbq-peer.service`](../examples/systemd/rbq-peer.service) is
a user unit configured by environment, with a clean stop and conservative
hardening. With no `RBQ_TOKEN_FILE`, only paired devices can connect.

## Provision pairings without anyone at the keyboard

Two ways, both non-interactive.

**Exchange signed cards** (works offline and ahead of time):

```bash
# On each machine, once:
rbq peer id --name backup-box --address quic://100.101.102.103:8788 > backup-box.card
rbq peer id --name laptop > laptop.card
# Move the cards over a channel you trust (provisioning, scp, a USB stick), then:
backup-box$ rbq peer pair add laptop.card --as client --expires-days 365
laptop$     rbq peer pair add backup-box.card --as server
laptop$     RBQ_PEER=paired:backup-box rbq peer push
```

**One-time invitation** (needs the server running):

```bash
backup-box$ rbq peer pair invite --name backup-box --minutes 30 | jq -r '.connect[].connection'
laptop$     rbq peer pair join 'rbq+quic://100.101.102.103:8788?peer=ID&pair=SECRET'
```

The invitation works once; a wrong or reused secret is refused and counts
towards the failure throttle. `rbq peer pair list` and
`rbq peer pair remove PEER` manage pairings; removal takes effect on the next
connection.

## Overlays

When this host is on Tailscale or NetBird, `rbq peer serve` shares over it
by itself: one QUIC listener per overlay address (unless a wildcard listener
on the same port already reaches it), re-checked every 30 seconds, so an
overlay that comes up after boot is picked up and one that goes away is
dropped (JSON lines on stderr say which). With no `RBQ_LISTEN` at all the
server is reachable *only* over the overlays, which is the private default
of the systemd unit. A plain `100.64.0.0/10` address on an unknown interface
is never shared automatically (carrier-grade NAT uses that range).

`rbq peer networks --json` shows what is detected (and, when their CLIs are
installed, connection state and peers). The overlay carries packets; rbq
still pins keys and checks pairings.
