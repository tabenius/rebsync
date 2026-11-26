# Linux CLI: private Dash repositories and artifacts

These commands require the CLI's default `peer` feature. They are explicit
operations, independent of backup configuration and bare `rbq`'s dry-run plan.
All successful output is JSON, even without `--json`. No command automatically
shares a piece, publishes an artifact, approves an invitation or exports a key.

## Credentials

Create/rotate a private MCP credential in Dash, with the appropriate explicit
opt-ins: **RBQ storage** for repository operations; **artifact browsing** for
read-only artifact tools. Older read-only tokens do not silently gain either.
Store the token in a regular, current-user-owned file with mode `0600` or `0400`.
Symlinks, sockets/devices and group/world-readable token files are refused.
Do not put bearer tokens in command arguments, URLs or shell history.

The repository contract accepts two token kinds: `rbm_` MCP credentials and
`rbs_` sync credentials. A sync credential comes from passkey-approved device
pairing in Dash; it is scoped (describe/list/read/append), bound to one
repository, and revocable on its own, and it carries no MCP or artifact access.
Its endpoint is `/api/rbq/<key_id>` for the credential's own key ID.

Repository operations use `https://dash.ragbaz.cc/api/rbq/ID`; artifact operations
use `https://dash.ragbaz.cc/mcp/ID`. The ID is the credential ID, not the stable
repository UUID. Rotation changes the URL/token, not the account repository.
Use the URL returned by Dash, not an invented account path. TLS is required;
plain HTTP is allowed only on loopback for tests. Redirects are never followed.
Server error bodies are suppressed. Transfers and MCP responses have size/time
bounds. Artifact data is returned with `trusted: false` and is never executed.

## Pairing this device (passkey-approved)

Instead of copying a token into a file, a device can ask Dash for its own
credential and have a person approve it with a passkey in Dash:

```sh
export RBQ_CREDENTIAL_STORE="$HOME/.config/rbq/credentials"   # chosen explicitly; no default
rbq dash pair --label laptop                # prints the matching code and approval URL, then waits
rbq dash credentials                        # metadata only: key id, endpoint, scopes, expiry
rbq repository --credential KEY_ID describe
rbq repository --credential KEY_ID push --store "$HOME/.rbq/objects" --source-id laptop --source-name Laptop
```

- **Approval.** Open the printed URL in Dash, check that Dash shows the same
  matching code as the device, and approve with your passkey. An email session
  alone cannot approve. The device computes the code itself and refuses a Dash
  whose code or approval URL disagrees.
- **What is requested.** `--scope describe|list|read|append` (repeatable;
  default all four) and `--days 1..90` (default 30). Dash cannot widen them.
  Each `rbq repository` command needs one: `describe`; `list` for `list` and
  `sources`; `read` for `read` and `pull`; `append` for `append` and `push`.
  The stored grant is checked before the token is read, and Dash checks again.
- **Waiting.** `rbq dash pair` waits up to `--timeout` seconds (default 600; the
  request lasts 10 minutes). `--no-wait` only starts it; finish with
  `rbq dash wait PAIRING_ID`. `rbq dash pending` lists unfinished pairings.
- **Lost responses.** A credential is issued once. If the claim's response is
  lost, or the credential cannot be stored, `rbq` cancels the pairing, which
  revokes the credential at Dash; pair again. If even that fails, run
  `rbq dash cancel PAIRING_ID` later.
- **Storage.** `$RBQ_CREDENTIAL_STORE` is a `0700` directory of `0600` files,
  one per credential, created atomically and never overwritten; symlinks and
  files open to others are refused. By default (`--seal secret-service`, or
  `RBQ_CREDENTIAL_SEAL`) each secret is encrypted with XChaCha20-Poly1305
  under a random key kept in your desktop's Secret Service (GNOME Keyring,
  KWallet, KeePassXC), one key per store directory, and bound to its
  credential id; the files hold ciphertext and readable metadata only. If the
  Secret Service is unavailable or locked, `rbq` stops and says so; on a
  headless machine pass `--seal none` to keep owner-only files that are **not
  encrypted at rest**. Plaintext entries are sealed the first time a sealing
  run uses them. Pending pairings (with their 10-minute claim nonces) are kept
  in `pending/`, owner-only and not sealed.
- **Stopping.** `rbq dash disable KEY_ID` stops this device from using it;
  revoke it in Dash too, which works everywhere at once. When Dash refuses a
  stored credential (revoked or expired: HTTP 401), `rbq repository` disables
  it on this device, says so, and asks you to pair again; it is not retried.
- Output is JSON on stdout. No command prints a token or nonce.

The credential's endpoint is `/api/rbq/KEY_ID`; it reaches only your account
repository, never MCP or artifacts.

## Pairing automatically (systemd)

`rbq dash ensure` keeps a device paired without anyone typing a command; a
person still approves each pairing in Dash with a passkey. Each run:

1. does nothing if the store holds a usable credential for this Dash, with
   the requested scopes and more than `--renew-days` (default 7) left;
2. otherwise resumes a pairing for this Dash still awaiting approval (it
   never piles up requests), or starts one;
3. waits up to `--timeout` seconds (default 600) for approval. `--notify`
   also shows the matching code and approval link as a desktop notification.

It exits `0` when paired and `2` while a request still awaits approval (run
it again later). Renewal pairs again before expiry, so the credential id
changes: use `rbq repository --credential auto`, which picks the newest usable
credential allowing the command.

`examples/systemd/` has a user service and timer that run it at login and
daily. For user `xyzzy` on host `kali`, with `rbq` in `~/.local/bin`:

```sh
mkdir -p ~/.config/systemd/user ~/.config/rbq
cp examples/systemd/rbq-dash-pair.service examples/systemd/rbq-dash-pair.timer ~/.config/systemd/user/
cp examples/systemd/rbq-dash.env ~/.config/rbq/dash.env   # RBQ_DASH_LABEL=xyzzy@kali
systemctl --user daemon-reload
systemctl --user enable --now rbq-dash-pair.timer
systemctl --user start rbq-dash-pair      # pair now instead of in 2 minutes
journalctl --user -u rbq-dash-pair -f     # the matching code and approval link
```

Open the link in Dash, check the code matches, approve with your passkey; the
service collects the credential. `RBQ_CREDENTIAL_SEAL=secret-service` needs an
unlocked keyring in that session (a desktop login); on a headless machine set
`none` in `dash.env` (owner-only files, not encrypted at rest) and run
`loginctl enable-linger xyzzy` so the timer runs without a login.

## Immutable object operations

```sh
rbq repository --endpoint "$RBQ_ENDPOINT" --token-file "$TOKEN_FILE" describe
rbq repository --endpoint "$RBQ_ENDPOINT" --token-file "$TOKEN_FILE" list --prefix notes/
rbq repository --endpoint "$RBQ_ENDPOINT" --token-file "$TOKEN_FILE" append notes/one --file note.txt
rbq repository --endpoint "$RBQ_ENDPOINT" --token-file "$TOKEN_FILE" read notes/one --output new-copy.txt
```

Read verifies the server's SHA-256 and creates a new owner-only file. Existing
downloads are never overwritten. Append accepts up to 256 KiB per object and
checks the acknowledged key, size and SHA-256. An identical append is a safe
retry; different bytes at the same key conflict. There is no overwrite/delete.
Dash's account quota is 64 MiB logical content and 10,000 reserved keys.
Privacy is account access control, **not end-to-end encryption**.

## Source-scoped push and pull

```sh
rbq repository --endpoint "$RBQ_ENDPOINT" --token-file "$TOKEN_FILE" push \
  --store "$HOME/.rbq/objects" --source-id laptop-stable-id --source-name Laptop
rbq repository --endpoint "$RBQ_ENDPOINT" --token-file "$TOKEN_FILE" sources
rbq repository --endpoint "$RBQ_ENDPOINT" --token-file "$TOKEN_FILE" pull \
  --store "$HOME/.rbq/received" --source-id laptop-stable-id --layer frog
```

`push` takes an **existing RBQ object store**, not an arbitrary directory of
working files. It selects Mneme, Frog, agenda and Git layer objects, or only the
repeated `--layer` selections. Use owner export commands to create snapshots
first; push never reads a live database or runs an owner's migration. Gifts are
not accepted as a layer before their owner protocol/verifier exists.

Choose a stable source ID once, retain it with the upstream source, and reuse
it when retrying or copying that source. Names describe a source; matching names,
remotes or hashes do not make two sources the same. Source IDs are structural
namespace identifiers, **not another Git repository identity scheme**. Do not
substitute path hashes or forge URLs for Frog repository identities.

Remote layout:

```text
sources/v1/SOURCE_ID/source.json
sources/v1/SOURCE_ID/objects/LAYER/v1/chunks/...
sources/v1/SOURCE_ID/objects/LAYER/v1/snapshots/...
```

The source descriptor binds its immutable ID/name. A different name for an
existing ID is refused rather than silently renamed. `pull` preserves this
layout beneath its destination root. It never merges remote sources into your
own local layer namespace. To inspect a received snapshot with an owner-layer
command, point `--storage-root` at
`DESTINATION/sources/v1/SOURCE_ID/objects`.

- Both directions are additive, with no replacement/deletion or prune propagation.
- Chunks transfer before manifests. Push preflights local snapshots; pull checks
  their complete chunk/file digest closure before publishing a manifest.
- Identical retries transfer zero objects. Same size alone is never sufficient:
  existing bytes are checked. Conflicts leave originals unchanged.
- A failed transfer can leave immutable chunks; retry the same command to resume.
  It does not claim an all-or-nothing multi-object transaction.
- Objects over 256 KiB are rejected before push writes anything. Configure the
  owner exporter with smaller chunks (64 KiB is suitable); no silent rewriting
  or rechunking of an existing signed/exported manifest occurs.
- Pull requires atomic create-if-absent and owner-only storage. FAT/exFAT's
  weaker single-writer fallback is not accepted for private repository pulls.
- Exit `0` means the selected transfer completed; exit `2` reports rejected
  objects/conflicts in JSON; transport/auth/protocol errors exit `1`.

## Read-only artifact navigation

Arrival events are a durable stream, independent of Web Push delivery:
The `arrivals` and `watch` commands require CLI 0.1.3 or newer; 0.1.2 contains
repository exchange and the earlier artifact navigation commands only.

```sh
rbq artifacts --endpoint "$MCP_ENDPOINT" --token-file "$TOKEN_FILE" arrivals --after 0
rbq artifacts --endpoint "$MCP_ENDPOINT" --token-file "$TOKEN_FILE" watch --after "$LAST_CURSOR"
rbq artifacts --endpoint "$MCP_ENDPOINT" --token-file "$TOKEN_FILE" watch --notify
```

`watch` emits one JSON line per bounded page and retains its cursor in memory;
persist the emitted `next_after` yourself and pass it back on restart. It does
not mark events read. `--batches 1` bounds a smoke test; zero watches until
interrupted. Polling is at least five seconds apart when idle. Transport errors
exit rather than pretending the stream is empty. `--notify` is explicit opt-in
to a fixed `notify-send` command with generic text only; it never sends private
subjects, gift contents, URLs or approval actions to the desktop. Missing desktop
notification support is reported in JSON without losing the arrival page.
Backfill pages coalesce desktop alerts to at most one attempt per polling
interval rather than opening a notification for each historical page.

Dash PWA Web Push and Tauri native notifications are delivery surfaces for the
same inbox, not alternative gift identities or authorization systems. Arrival
does not establish ownership, verify a signature, accept a gift or approve an
invitation. These commands need the corresponding deployed arrival MCP tool;
older Dash deployments refuse it explicitly.

```sh
rbq artifacts --endpoint "$MCP_ENDPOINT" --token-file "$TOKEN_FILE" sources
rbq artifacts --endpoint "$MCP_ENDPOINT" --token-file "$TOKEN_FILE" list --limit 20
rbq artifacts --endpoint "$MCP_ENDPOINT" --token-file "$TOKEN_FILE" get --source "$SOURCE_ID" --id "$ARTIFACT_ID"
rbq artifacts --endpoint "$MCP_ENDPOINT" --token-file "$TOKEN_FILE" provenance --source "$SOURCE_ID" --id "$ARTIFACT_ID"
rbq artifacts --endpoint "$MCP_ENDPOINT" --token-file "$TOKEN_FILE" read-piece \
  --source "$SOURCE_ID" --id "$ARTIFACT_ID" --offset 0 --limit 4000 --expected-revision "$REVISION"
rbq artifacts --endpoint "$MCP_ENDPOINT" --token-file "$TOKEN_FILE" read-frog --source "$SOURCE_ID" --id "$ARTIFACT_ID"
```

Preserve both `source_id` and `id` from discovery. A list can filter with
`--source`, or a pair `--factory-source`/`--factory-id`. For another page pass
both fields of `next_after` as `--after-source`/`--after-id`. A page has at most
50 artifacts. The server's `source_truncated` flag remains visible: pagination
does not magically recover a source inventory the provider did not supply.

Pieces reads return source JSON, not rendered HTML. Offsets count Unicode code
points, not bytes or UTF-16 units; each response includes `next_offset` and the
revision. Reuse `--expected-revision` to avoid mixing a changed manuscript's
pages. BOM, CRLF and Unicode are preserved in the returned string. A slice's
content digest describes the complete source, not just that slice.

Frog reads are projections with source/revision/stale metadata, not raw database
bytes or permission to change tasks. Current membership is rechecked by Dash.
Supplied signatures/attestations are inspection data: signature presence is not
cryptographic verification or ownership. Mouseion proof adapters, repository
file inventories and instance-specific RBQ inventories remain unavailable until
their owning services supply them. The CLI never substitutes arbitrary URL or
filesystem access, executes gift text or calls a signing/approval tool.

Only Dash's stateless JSON MCP endpoint is supported, not arbitrary stateful/SSE
servers. A server without the new artifact tools fails explicitly; no browser
session-cookie fallback is attempted.

## Validation

```sh
cargo test --workspace --locked
cargo clippy --workspace --all-targets --all-features --locked -- -D warnings
cargo check -p rebsync-cli --no-default-features --locked
RBQ_DASH_SOURCE=/path/to/tested/dash RBQ_BINARY=/path/to/built/rbq \
  node --test scripts/test_dash_cli.mjs
```

The last check is opt-in and runs the real Dash Worker, SQLite and local R2 with
synthetic accounts. It tests Unicode Pieces reads, provenance, revisions,
source-scoped push/pull, idempotency, cross-account refusal and credential
rotation. It does not access production accounts or prove live rollout.

## Remaining cross-product work

CLI repository and navigation support does not deploy Dash. Production use
needs the corresponding audited Dash migration/resources and artifact MCP
rollout. The gift signature format is decided (`ed25519-jcs-v1`, checked by
`rbq gift verify`), but a gift layer, HITL response authorization and
subscribed email/Telegram/Discord delivery still need verified key/identity
bindings and services. They are not silently added to
the peer registry or advertised as implemented by these commands.
