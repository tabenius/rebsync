# rbq

Preserve work, safely exchange Git branches, and report what remains at risk.

**Early milestone, not unattended fleet synchronization.** Bare invocation is a
dry-run. Execution requires `--apply`. Read the [Tufte plan](docs/plan.html) for the
broader design; this README describes what is actually implemented.

## Install

Requires Rust/Cargo, Git, and GNU tar. Encrypted backup additionally requires
[restic](https://restic.net/). GitHub exchange uses Git's existing credential setup.

```bash
cargo test --workspace
cargo install --path crates/rebsync-cli --locked
rbq --help
rbq --root src/ragbaz
rbq . --dry-run --json
```

`rbq .` sets Rebeqah home to the current directory. Otherwise it defaults to
`$HOME`. Relative scan roots, password-file and dataset paths resolve against that
home. Configuration values do not perform shell expansion; use an absolute path
instead of writing `$HOME` inside TOML/YAML.

## Configuration

### RAGBAZ component dependencies

[`ragbaz.component.json`](ragbaz.component.json) follows ragbaz-common's 0.2.0
component schema and Frog's typed dependency model (`install`, `runtime`,
`build`, `debug`), as adopted by WeftMark. Frog and Mneme are **optional runtime**
dependencies: their owner CLIs are needed only for the corresponding layers,
which are disabled by default. Installing or building Rebeqah does not install
either component. Tests use owner-CLI fixtures rather than sibling checkouts.

External packages remain in Cargo/npm manifests, not in this component graph.
Daily Agenda is an on-disk edition contract, not a declared component dependency
until its producer has a confirmed component identity. Repository/ref pins belong
in the catalog's `components.lock.json`, not dependency entries. This declaration
does not itself register edges in the authoritative fleet Frog database.

CI validates against the checksummed public schema snapshot from ragbaz-common
commit `f6f44e27ae7051968897080faf820c8ad6475147`, vendored in `schemas/` so
neither CI nor local validation needs access to a private repository. To validate:

```bash
python3 -m pip install jsonschema==4.23.0  # preferably in a virtual environment
sha256sum --check schemas/SHA256SUMS
python3 scripts/validate_component.py --schema schemas/ragbaz.component.schema.json
```

### Configuration precedence

Precedence, lowest first:

1. Built-in defaults.
2. `$XDG_CONFIG_HOME/rbq/config.toml`, `.yaml` or `.yml` (default config home:
   `$HOME/.config`).
3. `<rbq_home>/rbq.toml`, `.yaml` or `.yml`.
4. `--config PATH`.
5. Explicit CLI overrides.

Lists replace earlier lists. Unknown keys and competing formats at one layer are
errors. User/explicit configuration may set `rbq_home`; a home-local file may
not redirect it. Relative `rbq_home` resolves against the invoking directory.

```bash
rbq config explain
rbq --config examples/rbq.toml --no-push --dry-run
```

See [the working TOML example](examples/rbq.toml). YAML has the same structure.
Configuration explain redacts the backup repository URL, since URLs can contain
credentials. Never put secrets into configuration or source control.

## Encrypted preservation

Configure an **existing** restic repository and a separate password file (or
`RESTIC_PASSWORD` / `RESTIC_PASSWORD_FILE`). For Cloudflare R2:

```toml
[backup]
repository = "s3:https://ACCOUNT_ID.r2.cloudflarestorage.com/PRIVATE_BUCKET/rbq"
password_file = "/private/path/rbq-restic-password"
```

Supply bucket-scoped `AWS_ACCESS_KEY_ID` and `AWS_SECRET_ACCESS_KEY` in the
environment. Keep the password and an independently stored recovery copy outside
all source repositories. No Cloudflare resources or credentials are automatically
created or inferred.

Initialize only when deliberately creating a new repository:

```bash
rbq backup-init --confirm --config /path/to/rbq.toml
rbq --config /path/to/rbq.toml --apply
```

Each repository snapshot contains:

- A verified Git bundle of all reachable refs and HEAD, when commits exist.
- Staged and unstaged binary patches.
- A GNU tar archive of present tracked and nonignored untracked files, including
  their names and modes; deleted files are represented by patches.
- Repository identity, refs, sanitized remote identities, and warnings.

Private temporary staging directories are mode `0700`, journal files `0600`.
Staging is removed after the attempt; a failed backup does not leave a claimed
snapshot. Restic encrypts before uploading. Snapshot metadata is read back after
upload; this is **not** a full remote block-integrity check. Schedule `restic
check --read-data` and test restores separately. Git exchange is blocked by
default if preservation failed or is unconfigured.

Ignored files, Git LFS payloads, nested submodule contents, reflog-only objects,
external Git alternates and live databases need additional owner-specific backup
policies. Selected quiescent directories can be declared as `backup.datasets`.
Agenda editions and the Frog database have their own owner-validated layers (see below).

A filesystem restic repository may be useful for tests or an enrolled USB drive,
but rbq does not assert that it is independent of this machine. It never
prunes backups or propagates deletions.

## Local object storage

### Private Dash repository access

The separate `rbq repository` command accesses an opt-in, account-private
repository hosted by Dash. In Dash's **Your MCP link**, enable private RBQ
storage when creating/rotating a credential, then call `rbq_get_repository`
through that MCP client. It returns the token-free repository endpoint. Save
the same bearer token in an owner-only file using a private editor, not in a
URL or shell command:

```bash
chmod 600 ~/.config/rbq/dash.token
rbq repository --endpoint "$RBQ_ENDPOINT" --token-file ~/.config/rbq/dash.token describe
rbq repository --endpoint "$RBQ_ENDPOINT" --token-file ~/.config/rbq/dash.token append notes/first.mdoc --file ./first.mdoc
rbq repository --endpoint "$RBQ_ENDPOINT" --token-file ~/.config/rbq/dash.token list --prefix notes/
rbq repository --endpoint "$RBQ_ENDPOINT" --token-file ~/.config/rbq/dash.token read notes/first.mdoc --output ./downloaded.mdoc
```

Output is JSON. Reads verify SHA-256 and refuse to overwrite local files.
Appends are immutable (identical retries succeed); objects are limited to
256 KiB. Listing is paginated with `--limit` and `--after`. HTTPS is required;
redirects are refused (loopback HTTP is allowed for local development only).
Credential expiry/revocation applies to every request; rotation retains the
repository identity but changes its endpoint and token. Requires the `peer`
feature (enabled by default). This is not automatic peer synchronization or
an encrypted restic repository. Account isolation is **not** client-side
encryption: infrastructure administrators can access stored bytes.

### Local object store

`rbq` can publish Rebeqah-managed objects into a local filesystem root behind
a narrow `ObjectStorage` trait. This is the **client-side** contract for future
S3/R2 adapters, not an S3 server, not a restic REST server, and not a change to how
restic stores or encrypts existing snapshots.

The adapter is feature-gated. `rebsync-core` keeps `storage-object-store` off by
default; the CLI enables it through its default `storage` feature. Build the CLI
with `--no-default-features` to omit it. Restic-based backup and Git exchange do
not use this layer.

```toml
[storage]
# Relative paths resolve against rbq_home. Default shown.
root = ".rbq/objects"
```

`--storage-root PATH` overrides the file for one invocation, which is the easiest
way to keep experiments away from real home storage:

```bash
rbq storage path
rbq storage path --storage-root /mnt/backup/rbq --json
rbq storage check --storage-root /tmp/rbq-probe --json
```

`storage fsck [--layer L]` reads every layer snapshot (Mneme and multi-file
formats), streams each chunk and checks chunk and whole-file digests, and reports
damaged, missing or unreadable snapshots plus unreferenced chunks. It writes
nothing and exits `2` on any failure. It is a structural check; the owners'
validators run through `rbq <layer> verify ID`.

`storage check` writes a `_probes/check-*` object, verifies create-if-absent,
readback, range read, HEAD and raw-prefix listing, then deletes it. It never touches
the restic repository. Keys are limited to ASCII letters, digits, `.`, `-`, `_`
and `/`; empty segments, traversal, leading/trailing slashes and overlong keys are
rejected, and symlinks at any key component, including the leaf, are refused.
Filesystem publication is fsynced. Deletion exists for storage administration
only: no synchronization policy propagates repository deletions between peers.
A manifest received from a peer is removed only when its own snapshot check
fails, so damaged metadata is not advertised as restorable.

## Owner schemas and migrations

Frog, Mneme and Daily Agenda own their data formats and migration logic.
Rebeqah does **not** run SQL migrations, invoke `frog db migrate`, bypass
`FROG_ALLOW_SCHEMA_SKEW`, or change an existing/live database. Applied migration
names in a Frog snapshot are evidence of its history, not proof that the
installed owner can use it.

Owner export/validation JSON may include this optional extension:

```json
{"migration": {"status": "unavailable", "reason": "A compatible owner migrator is not installed"}}
```

`current` permits the remaining integrity checks; `required`, `unavailable`,
`unknown`, and unrecognized states block the operation. Rebeqah also understands
Frog's existing nonempty `behind` (migration required) and `ahead` (compatible
tooling unavailable) reports, including nonzero export exits. Unknown Mneme
snapshot or Agenda manifest schemas are migration/compatibility blockers, not
generic corruption. A normal apply run reports `status: blocked` with a
structured `migration` field; direct commands return exit `2` and `--json`
prints the blocker. Failed owner commands without such a signal remain failures.

Legacy owner reports without migration metadata retain existing behavior:
compatibility is **unknown**, not certified current. Frog's read-only SQLite
validator cannot discover migrations shipped by an arbitrary installed Frog
binary. Mneme restore now runs the installed owner's snapshot verifier before
invoking restore. A blocked migration must be resolved with compatible owner
tooling on an independently preserved copy; automatic staged migration is not
implemented. New converted data must be revalidated and published as a new
snapshot, never overwrite the old immutable objects.

## Mneme layer (session-history index)

[Mneme](https://github.com/tabenius/mneme)'s index is a live SQLite WAL database,
which repository snapshots and `directory` datasets refuse. This layer never
copies the live files. Mneme owns the format, so Rebeqah asks it to export and
to validate:

1. `mneme snapshot create` writes a consistent `VACUUM INTO` copy, runs
   `integrity_check`, and reports schema, generation, counts and SHA-256.
2. Rebeqah re-hashes the file itself and publishes it into the object store as
   fixed-size, content-addressed chunks plus an immutable manifest:

   ```text
   mneme/v1/chunks/sha256/<aa>/<sha256>
   mneme/v1/snapshots/<label>/<UTC stamp>-<sha12>.json
   ```

   Chunks are create-if-absent and written before the manifest. Nothing is
   overwritten or deleted. An unchanged index re-exports byte-identically and
   reuses every chunk.
3. With `mneme.restic = true` (the default) the verified export and its manifest
   are also backed up through the encrypted restic repository.

```toml
[mneme]
enabled = true            # publish during --apply runs
binary = "mneme"          # PATH lookup; paths resolve against rbq_home
# db = "/private/mneme/index.sqlite"   # else mneme's default / MNEME_DB
label = "local"           # one key segment naming this history store
chunk_bytes = 65536       # multiple of 4096, 4 KiB..64 MiB
restic = true             # requires backup.repository
timeout_seconds = 900
```

```bash
rbq mneme publish                 # export + publish now (journaled)
rbq mneme list [--label local] [--json]
rbq mneme stats [--json]          # read-only: dedup, orphan and missing chunks
rbq mneme verify local/20261114T112650.973Z-d7af0bf4f612
rbq mneme restore ID --into /private/new/index.sqlite
```

**Chunk size.** `VACUUM INTO` writes whole 4 KiB SQLite pages, so chunks that
are page multiples stay aligned when rows are inserted; that alignment, not
content-defined chunking, is what makes reuse work. Measured on a synthetic
10 MB index after adding 5% more sessions, the share of the second snapshot that
had to be uploaded:

| chunk | 4 KiB | 16 KiB | 64 KiB (default) | 256 KiB | 1 MiB | 4 MiB |
|---|---|---|---|---|---|---|
| uploaded | 10% | 21% | 25% | 31% | 69% | 100% |

Gear-hash content-defined chunking was measured too and did no better at 64 KiB
(23%) and worse at 1 MiB (94%), so it is not used. Smaller chunks trade object
count for transfer; 64 KiB keeps a 1 GB index near 16k objects.

`stats` is read-only. It reports logical versus stored bytes, chunks no
manifest references (for example from an interrupted publish; never deleted
automatically) and referenced chunks that are missing, which exits `2`.

`verify` reassembles into private staging, checks every chunk digest and the
whole-file digest, then runs `mneme snapshot verify --sha256`. `restore` does
the same and calls `mneme snapshot restore`, which refuses an existing index.

In `--apply` runs the layer reports `backed-up` only when restic succeeded.
`published-local` (object store only, same disk) and `blocked` (restic requested
but no repository) keep the exit code at `2`. The object store holds plaintext
transcripts owner-only (`0700`); treat it like the index itself. `--mneme-db`
overrides `mneme.db` for one invocation.

## Frog and agenda layers

The same owner-export pattern as the Mneme layer, stored under `frog/v1/…` and
`agenda/v1/…` (content-addressed chunks, then an immutable manifest).

**Frog (`AGENTS.db`).** `frog --db DB --json snapshot --dest <private staging>`
makes a consistent copy with SQLite's online backup API. (As always, Frog also
records a `workspace.snapshot` event in the live database.) Frog has no snapshot
validator, so Rebeqah checks the copy itself, through Python's standard `sqlite3`
module opened read-only and immutable:

- `PRAGMA integrity_check`;
- that Frog's core tables are present (`schema_migrations`, `repos`, `agents`,
  `locks`, `tasks`, `event_log`);
- the applied migrations and row counts are recorded in the manifest.

A copy that fails any check is never published. `restore` writes only a new
file and refuses an existing path, including the live database and its
`-wal`/`-shm` files. Swapping a restored database into place is a deliberate
step you take on the Frog side.

**Agenda editions.** The generator commits `manifest.json`
(`ragbaz.daily-agenda-manifest.v1`) last, under an exclusive `.publish.lock`, and
that manifest is the owner's validator. Rebeqah copies an edition as follows:

1. It takes a shared lock on `.publish.lock`, so an edition is never copied
   while it is being replaced.
2. It copies every listed file plus the manifest.
3. It re-verifies each SHA-256 and size on the private copy.

Only `ready` editions are published unless `require_ready = false`. `restore`
recreates the edition in a new directory and checks it again.

```toml
[frog]
enabled = true
# binary = "frog"           # PATH lookup
# db = "/data/src/AGENTS.db"
# python = "python3"        # runs the read-only validator
label = "local"
restic = true

[agenda]
enabled = true
path = "/srv/ragbaz/reports/daily-agenda"
label = "local"
restic = true
require_ready = true
```

```bash
rbq frog publish | list | stats | verify ID | restore ID --into /new/AGENTS.db
rbq agenda publish | list | stats | verify ID | restore ID --into /new/edition
```

In `--apply` runs these layers report `backed-up` (restic succeeded),
`published-local`, `blocked` or `failed`, exactly like Mneme. A
`backup.datasets` entry with `kind = "agenda"` now points to the `[agenda]`
layer instead.

## Instructions page (`rbq serve`)

```bash
rbq serve                        # https://localhost:8790/ (self-signed)
rbq serve --bind 0.0.0.0         # share the page on the local network and announce it
rbq serve --plain-http --port 8080 --no-announce
```

- **What it shows.** A read-only page with live status built from the
  effective configuration: Rebeqah home, object store, whether a backup is
  configured, and the fleet authority. Each layer appears with its `--apply`
  state, snapshot count, freshness and storage use, followed by everyday,
  phone-sync and offline-git recipes. `/v1/status` returns the same as JSON;
  `/healthz` is for probes.
- **No secrets.** The backup repository URL is redacted, and tokens and
  password files are never read. The page is served with
  `Content-Security-Policy: default-src 'none'`.
- **HTTPS.** HTTPS is the default. On first use rbq generates a
  self-signed certificate for `localhost`, `127.0.0.1`, `::1` and
  `<hostname>.local`, and stores it owner-only under `.rebeqah/rbq/tls/`.
  It prints the certificate's SHA-256 fingerprint, so you can check a
  browser's warning instead of clicking through it.
- **Announcement.** When bound beyond localhost, rbq advertises
  `_rbq._tcp` (TXT `path=/`, `scheme=https|http`). It tries the system
  Avahi daemon first (`avahi-publish-service`, which talks to Avahi over
  D-Bus), waiting up to three seconds for service establishment. A missing
  daemon, publisher exit or timeout falls back to a built-in mDNS responder;
  merely starting the Avahi executable is not reported as success. It also posts a
  desktop notification over the D-Bus session bus when one exists. Each
  mechanism reports `✓` or why not; none is required. Bound to localhost,
  it deliberately does not advertise on the network.
- **Path exposure.** On the network the page shows this machine's paths and
  layer status. Share it only where that is fine.

## Git layer (offline exchange)

For when GitHub is down, blocked, or out of reach for weeks or months. Each
discovered repository's committed history is published as Git bundles into the
object store, the phone carries them (`rbq peer push` / `pull`), and another
machine fetches them. No server and no network beyond the local link.

```bash
rbq git publish                         # every repository whose refs changed
rbq peer push                           # laptop A → phone
# … later, on laptop B …
rbq peer pull --layer git               # phone → laptop B
rbq git list
rbq git fetch ID --repo ~/src/project --as laptop-a
git log rbq-laptop-a/main               # review, then merge deliberately
rbq git restore ID --into ~/src/new-copy   # or clone a repository B never had
```

- **Owner export.** Git produces each bundle itself (`git bundle create`
  for branches, tags and HEAD), and rbq checks it with `git bundle verify`.
  Each repository gets a stable label, `<name>-<hash of its GitHub identity or
  path>`.
- **Incremental chains.** The first snapshot is a full bundle. Later ones
  carry only what is new since the previous snapshot (`--not <previous heads>`).
  Measured on a 200-commit repository, the full bundle was 720 KB and one
  further commit cost 680 bytes. Rebuilding a full bundle would re-pack and
  re-send everything, because Git packs share no chunks between builds. A
  change that only moves refs (a tag, a deleted branch) becomes a tiny
  refs-only link. Unchanged repositories publish nothing. A new full bundle
  starts a fresh chain every `full_every` snapshots (default 20), or when an
  incremental cannot be built, for example after history was rewritten.
- **Verified on the way back.** `verify`, `restore` and `fetch` rebuild the
  chain base-first in a throwaway repository. Each link must pass `git bundle
  verify` against what came before it and match its recorded heads. Then the
  exact recorded branch and tag state is applied, and any commit missing from
  the chain is an error, never a silent gap. A missing link is named, with a
  hint to pull it from a peer.
- **Never rewrites your work.** `fetch` writes branches to
  `refs/remotes/rbq-<name>/*` and tags to `refs/rbq/<name>/tags/*`
  only. Local branches, local tags and the worktree are untouched, which
  makes it safe when both sides kept committing offline. `restore` only
  creates a new directory and removes its temporary remote. Git hooks are
  disabled throughout.
- **Retention and checks.** `rbq git prune` keeps the entire chain behind
  every kept snapshot, so pruning cannot make a survivor unrestorable.
  `rbq storage fsck` checks git snapshots like any other layer.
- **Scope.** Committed history only. Uncommitted work and stashes are covered
  by the encrypted repository snapshots (restic), not by this layer. Bundles
  contain whatever history contains, including any secret ever committed; the
  object store and the phone are plaintext, so treat them like the repositories.

```toml
[git_layer]
enabled = true            # publish during --apply runs
skip_unchanged = true
include_local_only = true # also repositories without a permitted GitHub remote
full_every = 20
chunk_bytes = 65536
```

## Retention (`prune`)

Snapshots are kept until you prune them. Pruning matters after
`mneme erase`, because older snapshots still contain the erased sessions.

```bash
rbq mneme prune --keep-last 7                  # dry run: shows what would go
rbq frog prune --keep-last 3 --keep-days 14 --apply
rbq agenda prune --label local --keep-last 30 --apply
```

- **Dry-run by default.** `--apply` deletes, and the deletion is journaled.
- **What is kept.** For each label, the newest `--keep-last` snapshots (at least
  one) and anything newer than `--keep-days`. `--label` limits pruning to one
  label.
- **Order of deletion.** Manifests go first. Chunks go after them, and only
  chunks that no surviving snapshot references and that are older than
  `--grace-minutes` (default 60).
- **No partial views.** If any manifest can't be read, nothing is pruned,
  because its chunks might still be in use.
- **Locking.** Publish and prune take the same per-layer lock, so they never
  interleave.
- **Local only.** Peers keep their own copies, and `rbq peer pull` would
  bring pruned snapshots back. Prune the phone's copies separately, or don't
  pull from it afterwards. Restic snapshots of the same data are untouched;
  remove those with `restic forget --prune`.

## Terminal interface and shell completions

`rbq` uses color when attached to a terminal and honors `NO_COLOR`/`TERM=dumb`.
JSON, completion scripts and piped output stay uncolored and machine-readable.

```bash
rbq --color auto peer status           # default; detect terminal capability
rbq --color always peer status         # force styling
rbq --color never peer status          # plain text
rbq completions bash > ~/.local/share/bash-completion/completions/rbq
rbq completions fish > ~/.config/fish/completions/rbq.fish
rbq peer push --retries 5 --timeout-seconds 90
```

Peer commands retry only transient DNS/connection failures, timeouts and
`408/502/503/504` responses, with bounded exponential backoff and small jitter.
Authentication failures, validation errors, malformed responses and write
conflicts fail immediately. A lost create response is safe to retry: a second
identical `put` reports `already present` rather than transferring again.

## Phone diagnostics and Chromebook connections

```bash
rbq phone diagnose --json                 # local lsusb/sysfs + IP routes
rbq phone diagnose --mtp                  # opt in to MTP storage metadata
rbq phone diagnose --adb-serial SERIAL    # authorized phone's IPs + df
rbq phone diagnose --include-identifiers  # opt in to USB/ADB serial output
rbq phone instructions --chromebook       # print all connection guides
rbq phone instructions --chromebook --transport usb
rbq phone instructions --chromebook --transport tcp
rbq phone instructions --chromebook --transport bluetooth
```

Diagnostics/guides do not load backup configuration, create journals/object
stores, copy files, enable debugging, enroll peers, change permissions or scan
the LAN. These commands are also available without default Cargo features;
explicit HTTP peer probes require the `peer` feature. Missing helpers and
unknown space are reported, never converted into zero free bytes or a claim
that a device is trusted. Requested probes that are incomplete exit `2`.

- **Linux USB:** `usbutils` supplies `lsusb`. VID/PID/model/interface hints find
  MTP/PTP candidates; they do not prove the device is a phone. Bus/device numbers
  change when replugged. Serial numbers are omitted unless requested.
- **MTP:** install `gvfs-backends` (and optionally `libmtp-runtime` for
  `mtp-detect`), unlock Android and choose File transfer. `--mtp` may open a GIO
  mount but does not unmount somebody else's session. It enumerates storage
  roots and queries capacity/free bytes, not their contents. Backends, phone
  lock state, competing clients and USB permissions can prevent reporting.
  Helper calls time out; enumeration is bounded to 32 USB observations, four
  MTP candidates and eight storage roots each. MTP is not a synchronization or
  live-database-export transport.
- **USB peer sync:** the printed guide uses an explicitly authorized ADB device
  and a loopback `adb -s SERIAL forward --no-rebind` tunnel to Rebeqah Sharing.
  `--adb-serial SERIAL` only queries an already authorized device's `ip addr`
  and `df -k`; it never pairs, enables debugging or creates tunnels. ADB itself
  may start its local helper server. The data/emulated-storage rows can be views
  of the same underlying filesystem; do not sum them as independent disks.
- **TCP/IP:** use Rebeqah's displayed reachable IP/port on trusted Wi-Fi, a
  hotspot, USB tethering or another explicitly established link. To check only
  that endpoint: `rbq phone diagnose --peer http://PHONE_IP:PORT --token-file
  /private/peer-token`. HTTP peer JSON is size-bounded, error bodies are
  suppressed and connection tokens are not included in diagnostic output.
- **Bluetooth:** print the host pairing/PAN guide. If ChromeOS and Android offer
  Bluetooth tethering/PAN, an established IP link can carry the existing peer
  protocol. Pairing/Phone Hub alone does not establish that link. Native
  RFCOMM/BLE/OBEX exchange and automatic PAN setup are not implemented.
- **ChromeOS boundary:** share the Android USB device with Linux in host
  settings if offered. Crostini's `100.115.92.x` gateway is virtual, not a phone
  IP. Inspect the ChromeOS network settings for the host connection; there is
  no standard Linux API that authenticates Phone Hub identity or proves that
  USB, hotspot provider and Rebeqah peer are the same phone. Authorized ADB IP
  observations can help a person correlate them, but Rebeqah deliberately keeps
  `same_physical_phone: unknown` and does not enroll on that basis.

Guides are printed, not executed: read them, replace placeholders, approve
debugging/pairing on both devices and remove only tunnels you created. See
[Android's ADB documentation](https://developer.android.com/tools/adb) and
[ChromeOS Linux guidance](https://support.google.com/chromebook/answer/9145439).

## Phone sync (Rebeqah)

`rbq peer` exchanges layer objects with the Rebeqah Android app's
`rbq-peer/0` endpoint. Copy the connection string from the app's Sharing
card. Pass it through `RBQ_PEER` so the token stays out of shell history:

```bash
export RBQ_PEER='rbq+http://192.168.1.42:8787/v1?token=…'
rbq peer status                  # what the phone holds, per layer
rbq peer push                    # this machine → phone
rbq peer pull --layer frog       # phone → this machine, Frog only
```

- **Additive only.** An object present on both sides is never replaced. A size
  mismatch is reported as a conflict, and the command exits `2`. Nothing is
  ever deleted.
- **Chunks travel before manifests,** so an interrupted sync never leaves a
  snapshot whose data is missing. Running it again finishes the job; a repeat
  sync of an up-to-date phone transfers nothing.
- **Pulled data is untrusted:**
  - Each chunk is re-hashed against its address.
  - Manifests must parse.
  - Only `mneme/`, `frog/` and `agenda/` objects are accepted.
  - Rejected objects are listed and never stored.

  Each newly pulled snapshot is then checked chunk by chunk (`verified` /
  `verification_failed` in the report; failures exit `2`). A newly received
  manifest that fails this check is removed again (`quarantined`) so a damaged
  snapshot is never listed as if it were restorable. Owner validation
  (SQLite integrity, edition manifests) is still `rbq <layer> verify ID`.
- **Plain HTTP on the local network.** Use Wi-Fi you control, the phone's
  hotspot or USB tethering. Listings page with `after=`, which needs Rebeqah
  0.2.4 or later; Rebekah installs use an incompatible protocol and are refused.

### Local transports (`rbq-peer/1`)

For same-host or relayed links, `rbq peer` can also speak a frame protocol
over TCP, Unix stream sockets and Unix datagram sockets. The sync rules, layer
filtering and verification are identical; only the wire changes.

```bash
# Serve this object store to another local process.
rbq peer serve --listen unix:///run/user/1000/rbq.sock --token-file ~/.rbq/token
rbq peer serve --listen tcp://127.0.0.1:8787 --token-file ~/.rbq/token

# Point status/push/pull at a local transport.
export RBQ_PEER='rbq+tcp://127.0.0.1:8787?token=…'
rbq peer status

# Exercise TCP, Unix stream and Unix datagram loopback end to end.
rbq peer selftest
```

- **Authentication is one shared token.** It is compared in constant time and
  must be 1–256 ASCII letters or digits. `--token-file` refuses a group- or
  world-readable file; Unix sockets are created owner-only.
- **Encryption is the transport's job.** TCP is not encrypted. `serve` warns
  when a listen address is reachable beyond this host. Put a tunnel or a
  loopback-only bridge in front of a public path; rbq does not speak TLS.
- **Bounded and additive.** Frames, listings, datagrams and reassembly have
  explicit size and time limits. `put` is still create-if-absent, and the
  server re-checks keys and chunk digests before writing.
- **No mesh integration.** A relay must expose one of these sockets; rbq
  does not talk to OSHI or other mesh APIs directly.

## Android compile check

`apps/rebsync-app` is a small Tauri 2 shell that exercises the shared storage
boundary on Android. It is excluded from the root Cargo workspace, so the two
production crates remain `rebsync-core` and `rebsync-cli`. The app has no mobile
background sync, peer discovery or filesystem permissions yet; it is a build and
link check, not a phone transport.

With JDK 21, an Android SDK, NDK 27 and the Android Rust targets installed:

```bash
export ANDROID_HOME="$HOME/.local/android-sdk"
export NDK_HOME="$HOME/.local/android-sdk/ndk/27.2.12479018"
cd apps/rebsync-app
npx @tauri-apps/cli@^2 android build --debug --apk --target aarch64
```

The APK lands under `src-tauri/gen/android/app/build/outputs/apk/`. Tauri writes
its own `Cargo.lock` and Gradle files under the app directory; they are not part of
the production workspace. The first build downloads the Gradle wrapper and needs
network access. See [the plan](docs/plan.html#r2) for the still-planned phone
transport and peer protocol.

## Git safety

- Discovers nested repositories, bare repositories and linked worktrees without
  following directory symlinks. Discovery is depth-limited and excludes common
  caches/dependency directories, not an exhaustive disk inventory.
- Accepts normalized GitHub remotes only under `github.com/tabenius` and
  `github.com/RAGBAZ` by default. Non-GitHub sources are reported, not contacted.
- Uses explicit canonical HTTPS URLs, branch refspecs, no tags and no recursive
  submodule fetches. Existing Git credentials must work noninteractively.
- Pushes each local branch by observed object ID using nonforced refspecs.
  Push failure is explicit and does not prevent preserving other repositories.
- Fast-forwards only un-checked-out local branches with an upstream fetched in
  this run; compare-and-swap ref updates reject concurrent movement.
- **Never rewrites any checked-out worktree**, including a clean current branch.
  Fast-forwards for such branches are reported for review.
- No force pushes, default-branch assumptions, deletion propagation, stash/pop,
  remote rewrites, repository creation, or feature-branch-to-main merges.
- Disables Git hooks for its own operations. This is not a sandbox for malicious
  repositories or arbitrary Git configurations; run only on trusted local repos.

An advisory shared-Git-directory lock coordinates rbq instances. Ordinary
editors and Git commands do not honor that lock; keep repositories quiescent
during preservation. Fingerprints catch ordinary concurrent modifications but do
not promise an atomic filesystem snapshot.

## Journals and reconciliation

Writes `<rbq_home>/rbq_YYYY-MM-DD_HHMMSS.jsonl` in UTC, with collision-safe
filenames, action intents/results and before/after branch IDs. Dry-runs write a
journal but do not mutate repository refs, fetch, push or back up. Logs exclude
raw subprocess output and unknown remote URLs to avoid leaking credentials.

Applied runs leave reconciliation instructions under
`.rebeqah/rbq/reconcile/<repository-id>/<run-id>/rbq-repo-reconcile-merge.md`.
Automatic OpenCode execution and default-branch publication are not implemented.

The fleet authority is **kali-1**, not whichever GitHub tip is freshest. This
milestone records pending fleet reconciliation; it does not contact Kali, overwrite
Frog state or declare fleet convergence. The authoritative Frog database remains
`/srv/ragbaz/src/vendors/ragbaz/head/AGENTS.db` on Kali.

Exit codes: `0` completed without reported gaps; `1` fatal configuration/runtime
failure; `2` unresolved protection, synchronization or fleet gaps. This milestone
normally returns `2`, intentionally: unimplemented coverage is not success.

## Current boundaries / next work

- The revised [storage-stack plan](docs/plan.html#r2) covers S3/R2 client profiles,
  early restic REST serving, resumable multipart and peer capability negotiation.
  The [Rust abstraction evaluation](docs/STORAGE-EVALUATION.md) compares pinned
  object_store/OpenDAL candidates in an isolated workspace. A feature-gated
  `object_store` filesystem adapter now implements the production trait; S3/R2,
  multipart and peer negotiation are not implemented yet.
- R2 is supported through restic's existing S3 backend, but requires account setup
  and an actual off-machine restore test before being trusted.
- No automatic GitHub creation/forking, Frog discovery adapter, AI execution or
  resume engine. Peer sync is manual (`rbq peer`), local-network and
  unencrypted; it can use HTTP or the local TCP/Unix transports, but there is no
  discovery, scheduling or TLS yet.
- Retention is manual (`rbq <layer> prune`); there is no scheduled policy, and
  pruning is not propagated to peers or restic.
- No USB enrollment, Bluetooth or mesh autodiscovery. Phone sync remains a
  manual HTTP connection or an explicit local-transport bridge.
- No tags/LFS migration or automatic organization-wide repository creation.
- No claim that copying data to this same disk protects against laptop loss.

The core crate owns operational behavior; the clap CLI only parses/renders and
maps exit codes. No terminal printing or prompting is performed by the core.

## Install from the RAGBAZ package repositories

**Debian/Ubuntu (APT)**, signed with the RAGBAZ release OpenPGP key:

```bash
curl -fsSL https://ragbaz.cc/apt/ragbaz-archive-keyring.gpg | sudo tee /usr/share/keyrings/ragbaz-archive-keyring.gpg >/dev/null
echo "deb [signed-by=/usr/share/keyrings/ragbaz-archive-keyring.gpg] https://ragbaz.cc/apt stable main" | sudo tee /etc/apt/sources.list.d/ragbaz.list
sudo apt update && sudo apt install rbq
```

**Android (F-Droid)**: add `https://ragbaz.cc/fdroid/repo` in F-Droid's Repositories
settings. Compare the repository fingerprint with the one published next to it.

Maintainers build, sign, verify and upload both repositories with
`scripts/publish-repos.sh` (see its header). It runs on the owner's machine: APT
is signed by the local gpg-agent and the F-Droid index by a dedicated repo key.


## License

Copyright (C) 2026 Tobias Abenius.

Rebeqah (rbq) is free software: you can redistribute it and/or modify it under the
terms of the GNU General Public License as published by the Free Software
Foundation, either version 3 of the License, or (at your option) any later
version. It is distributed in the hope that it will be useful, but WITHOUT ANY
WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A
PARTICULAR PURPOSE. See [`LICENSE`](LICENSE) for the full text.

SPDX: `GPL-3.0-or-later`. Dependencies and vendored assets keep their own
licenses.
