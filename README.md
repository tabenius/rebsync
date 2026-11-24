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

To back up to another machine running `rbq restic-serve` (a restic REST
peer), name the user in the URL and keep the HTTP password in an owner-only file:

```toml
[backup]
repository = "rest:https://rbq@peer.local:8000/"
rest_password_file = "/private/path/restic-http.pw"   # chmod 600
cacert = "/private/path/peer-localhost.crt.pem"        # what restic-serve printed
password_file = "/private/path/rbq-restic-password"
```

rbq hands the repository to restic through its environment, never its
command line. A password written into `repository` itself is reported
as an issue.

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

## Serving a restic repository (`rbq restic-serve`)

`rbq restic-serve` exposes rbq's object store as a restic REST repository
(protocol v1 and v2), so another machine can back up *to* this one with plain
`restic`. It is storage milestone 1's restic REST interoperability, tested
against real restic: `init`, `backup`, `snapshots`, `restore`, `check
--read-data`, lock removal, and a refused `forget`.

```bash
umask 077; head -c 24 /dev/urandom | base64 > ~/.config/rbq/restic-http.pw
rbq restic-serve --password-file ~/.config/rbq/restic-http.pw --tls-self-signed --listen 0.0.0.0:8000
# prints the certificate path and the exact restic command, e.g.
restic --cacert ~/.rebeqah/rbq/tls-restic/localhost.crt.pem -r rest:https://rbq:PASSWORD@host:8000/ init
```

- **Authentication.** Every request needs HTTP Basic credentials. The password
  comes from an owner-only file (at least 16 characters) and is compared in
  constant time. It only guards the transport: restic still encrypts the data
  with its own repository password, which the server never sees.
- **Transport.** Plain HTTP is accepted only on loopback (for example behind
  `ssh -L`). Any other listener needs TLS: `--tls-cert/--tls-key`, or
  `--tls-self-signed` with the printed certificate pinned through `restic --cacert`.
- **Append-only by default.** Only locks can be deleted, which a normal backup
  needs. `forget`/`prune` are refused until the server is started with
  `--allow-delete` (do that only for an administrative session).
- **Verified, immutable uploads.** Every object except `config` must be named
  by the SHA-256 of its bytes. Objects are created only if absent: an identical
  retry succeeds and nothing is ever replaced.
- **Namespace and quota.** One repository per server, stored under the
  `restic/` namespace of the object store (`--storage DIR` picks a dedicated
  root). `--max-bytes` refuses uploads beyond a quota (HTTP 507); usage is
  recounted from storage at start.
- **Limits.** Each upload is held in memory, up to 129 MiB (restic packs
  default to 16 MiB). Bodies without `Content-Length` (restic sends its empty
  create request chunked) are accepted only up to 64 KiB; larger ones get 411. Bodies are read only after authentication. Each
  upload reserves twice its size, for the buffer plus the storage layer's
  copy, from a server-wide budget of two maximum uploads (about 258 MiB). An
  upload that can't get budget within 30 seconds gets 503 with `Retry-After`.
  Repository *format* compatibility is restic's: the server stores its objects
  opaquely. On a filesystem without hard links (FAT/exFAT), where atomic
  create-if-absent isn't available, the server serializes its own creates;
  don't run two servers on one such store.
- **Certificate names.** `--tls-self-signed` covers localhost, the listen
  address, this machine's name (`NAME` and `NAME.local`) when listening on a
  wildcard address, and every `--tls-name NAME`. Each set of names gets its
  own certificate path.
- **Failed logins** are throttled per client address. After 10 failures within
  60 seconds that address gets HTTP 429 (`Retry-After`), without its password
  being checked, until the window passes. Other clients are unaffected.

## Local object storage

For account-private Dash storage, source-preserving **push/pull**, and read-only
private artifact/Pieces/Frog/provenance navigation, see [the Linux Dash CLI
guide](docs/DASH-CLI.md). These commands are separate from bare `rbq`'s backup
plan and do not imply a production Dash rollout.

### Signed gifts

`rbq gift verify FILE [--recipient-key KEY]` checks a gift envelope signed in
the `ed25519-jcs-v1` format (a detached Ed25519 signature over RFC 8785
canonical JSON; specified in ragbaz-common `docs/GIFT-SIGNATURE.md`). It prints
JSON and exits `0` when valid, `2` with a stable reason (`malformed`,
`unsupported_format`, `invalid_key`, `not_yet_valid`, `expired`,
`not_a_recipient`, `bad_signature`) otherwise. Verification is strict and
agrees with the JavaScript verifier on the shared vectors vendored in
`contracts/vendor/`. A valid signature says only that the holder of the sender
key signed exactly this envelope for the listed recipients within its validity
window: it is not the sender's identity or authority, and not acceptance. rbq
holds no gift signing key, and there is no gift layer or delivery yet.

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

The wire contract (limits, key grammar, token and endpoint formats, headers,
response fields and conformance vectors) is
[`contracts/rbq-repository.v1.json`](contracts/rbq-repository.v1.json). This
repository owns it; Dash vendors a pinned copy and tests its server against the
same vectors (`crates/rebsync-core/tests/rbq_contract.rs` here).

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
Candidate manifests are checked against stored chunks before publication;
damaged metadata is never briefly advertised and then deleted by the pull path.

Existing same-sized chunks are SHA-256 verified before reuse, including a lost
create-only race. Peer push/pull compare actual existing bytes rather than
trusting inventory sizes. Push checks source and destination chunks before
publishing a manifest. Repeated exchanges therefore incur read I/O and network
traffic even when no new objects are written. Byte integrity is not identity
verification or owner-level validation.

## Self-built binaries (`rbq binaries`)

Some executables are built from our own sources (or cannot be obtained through
cargo-binstall) and are worth re-fetching instead of rebuilding. The binaries
layer stores each executable with provenance — tool, version, target, source,
build command, install path and SHA-256 — as content-addressed chunks and an
immutable manifest under `binaries/v1/…`. Rebuilding remains possible; the
manifest records how.

With `binaries.restic = true`, only the `binaries/v1` objects are mirrored
through the encrypted restic repository, tagged `rbq-binaries` (plus a
run/label tag). Other layers never enter that repository. `binaries.repository`
/ `binaries.password_file` may point at a repository separate from `[backup]`;
either may be omitted to fall back to `[backup]` (and only then do
`backup.cacert`/`backup.rest_password_file` apply). The repository is passed to
restic through the environment, never the command line. Private bucket names,
artifact names, manifests and tool inventories are never published to public
catalogs or the release registry.

```bash
rbq binaries publish /path/to/rbq --tool rbq --version 0.1.0 \
  --target x86_64-unknown-linux-gnu --source src/ragbaz/rebsync \
  --build-command 'cargo build --release -p rebsync-cli' \
  --install-path /usr/local/bin/rbq
rbq binaries list
rbq binaries stats --json
rbq binaries verify ID
rbq binaries restore ID --tool rbq --into /tmp/rbq-restored
rbq binaries fetch --tool rbq --into /tmp/rbq-restored
rbq binaries fetch --tool rbq --version 0.1.0 --into /tmp/rbq-restored
rbq binaries prune --keep-last 2 --apply
```

`fetch` finds the newest matching snapshot, restores missing objects from the
private mirror when needed, and reassembles the tool. Objects restored from the
mirror are untrusted until checked: a chunk is imported only if its bytes hash
to the digest in its key, and anything else but a manifest is refused.
`restore` and `fetch` check the tool's digest before writing, write through a
private temporary file, and link it into place only if the destination does
not exist, so a failed check never leaves an executable behind and no live
binary is replaced.

A manifest's provenance is the publisher's claim, not a signature. Peer
exchange therefore never includes the binaries layer by default: name it with
`--layer binaries` only for peers you would run executables from.
`[binaries].specs` can list tools published during `--apply`; explicit
`rbq binaries publish` works with an empty list. Restic snapshots of the same
data are removed only by deliberate `restic forget` / `restic prune`, never by
`rbq binaries prune`.

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
   reuses every chunk. An optional tool-output sidecar is described only inside
   the opaque owner JSON as `owner["tool_output_sidecar"]`; its chunks share the
   same namespace without changing the manifest's top-level `chunks`. Snapshots
   without that field remain valid `rbq.mneme.snapshot.v1` snapshots. rbq asks
   for a sidecar only when `mneme snapshot --help` lists `create-sidecar`; once
   the owner offers it, any failure to export it fails the publish.
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

## Status (`rbq status`)

`rbq status` is a read-only snapshot across all object layers, private mirror
evidence and discovered Git repositories. It shows occupied bytes, bytes still
to transfer, progress bars, per-layer state/mirror/storage, and ahead/behind
counts against each branch's upstream. `-v` adds reasons and freshness; `-vv`
adds mirror journal evidence and orphan-chunk accounting. `--json` emits the
same snapshot as `rbq.status.v1`.

```bash
rbq status
rbq status -v
rbq status -vv
rbq status --watch              # refresh every 2 seconds
rbq status --watch=5
rbq status --json
```

Observers take the same shared per-layer lock that publishers hold
exclusively, so a running publish or prune cannot produce a half-written
report. Status never creates state directories, lock files or journals, and
never prints repository URLs or tokens. `rbq serve` shows the layer part only:
it neither walks nor lists local Git repositories. `--watch` is human-only; use
plain `rbq status --json` from scripts. Exit code `2` means attention is needed
or bytes are still pending.

## Terminal interface and shell completions

`rbq` uses color when attached to a terminal and honors `NO_COLOR`/`TERM=dumb`.
JSON, completion scripts and piped output stay uncolored and machine-readable.

```bash
rbq --color auto peer status           # default; detect terminal capability
rbq --color always peer status         # force styling
rbq --color never peer status          # plain text
rbq completions bash > ~/.local/share/bash-completion/completions/rbq
rbq completions fish > ~/.config/fish/completions/rbq.fish
rbq completions install fish             # XDG user path + restart ritual
rbq completions install bash --dry-run   # show the plan without writing
rbq install-completions all --force      # replace installed scripts
rbq -v peer status                       # stderr traces; -vv for more
rbq --json status                        # machine-readable status
rbq peer push --retries 5 --timeout-seconds 90
```

Installed scripts are written through a temporary file and renamed into place,
so a symlink at the destination is replaced rather than followed. Empty or
relative `XDG_DATA_HOME`/`XDG_CONFIG_HOME` values are ignored, as the XDG spec
requires. Long human help uses `$RBQ_PAGER`, then `$PAGER`, then `less -FRX`
when attached to a terminal; the pager is run without a shell.
`RBQ_THEME=ragbaz` selects the printed (day) palette and `RBQ_THEME=ragbaz-night`
the dark-terminal colors. JSON and completion streams are always uncolored,
even with `--color always`; with `--json`, help, version and errors are JSON too.
Release builds strip debug symbols.

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

## Enrolled drives (`rbq drive`)

USB sticks, SD cards and external disks become destinations only after you
enroll them by name. rbq never writes to a removable drive it has not been
told about.

```bash
rbq drive enroll /media/$USER/STICK --name stick   # writes STICK/.rbq-drive.json
rbq drive push stick                                # layer objects → STICK/rbq-store
rbq drive list                                      # where each drive is mounted now
# on another machine:
rbq drive enroll /media/$USER/STICK --name stick --adopt
rbq drive pull stick                                # verifies received snapshots
```

- **The store must be on the drive.** An `rbq-store` that is a symlink, or
  that resolves outside the drive, is refused.
- **Identity is the marker, not the path.** Enrollment writes a random drive ID
  to `.rbq-drive.json` and records it, with the filesystem UUID where the
  system exposes one. The drive is found again by scanning mount points (and
  `--search DIR`) for that marker, wherever it is mounted. A copied marker on
  a different filesystem is refused, as is one whose filesystem UUID can't be
  read when a UUID was recorded at enrollment.
- **Independent or not.** A drive on the same device as the local object store
  is refused (`--allow-same-device` overrides it) and listed as
  `"independent": false`: copying there does not protect against losing the disk.
- **Exchange is the peer engine.** Push and pull use `rbq peer`'s additive,
  never-overwriting exchange. Size conflicts are reported rather than copied
  over, and pulled snapshots are verified before they are listed.
- **Another machine** adopts a marked drive with `--adopt` and keeps its
  identity. `rbq drive forget NAME` removes the enrollment but leaves the
  drive's marker and data alone.
- **What is still unprotected.** Every `rbq` run (dry-run included) compares
  published layer objects with each mounted, independent enrolled drive.
  It reports how many objects are not yet copied, with the `rbq drive push NAME`
  that fixes it, or that they exist only in the local store. This is read-only,
  and the JSON summary carries it as `layer_copies`. Copies on peers are not
  tracked.

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
  sync of an up-to-date phone writes no new objects but reads bytes to verify them.
- **Pulled data is untrusted:**
  - Each chunk is re-hashed against its address.
  - Manifests must parse.
   - Only canonical supported layer objects are accepted.
  - Rejected objects are listed and never stored.

  Each candidate snapshot is checked chunk by chunk **before** publication
  (`verified` / `verification_failed` in the report; failures exit `2`). Invalid
  manifests are not stored; the legacy `quarantined` report field remains empty.
  Owner validation
  (SQLite integrity, edition manifests) is still `rbq <layer> verify ID`.
- **Plain HTTP on the local network.** Use Wi-Fi you control, the phone's
  hotspot or USB tethering. Listings page with `after=`, which needs Rebeqah
  0.2.4 or later; Rebekah installs use an incompatible protocol and are refused.

### Local transports (`rbq-peer/1`)

`rbq peer` can also speak a frame protocol over QUIC, TCP, Unix stream
sockets and Unix datagram sockets. The sync rules, layer filtering and
verification are identical; only the wire changes.

```bash
# Serve this object store over the network, encrypted. The output includes
# quic_peer_id: the hash of this server's key, which clients must pin.
rbq peer serve --listen quic://0.0.0.0:8788 --token-file ~/.rbq/token

# Or to another local process.
rbq peer serve --listen unix:///run/user/1000/rbq.sock --token-file ~/.rbq/token
rbq peer serve --listen tcp://127.0.0.1:8787 --token-file ~/.rbq/token

# Point status/push/pull at a transport.
export RBQ_PEER='rbq+quic://192.168.1.42:8788?peer=<quic_peer_id>&token=…'
rbq peer status

# Exercise QUIC, TCP, Unix stream and Unix datagram loopback end to end.
rbq peer selftest
```

- **Authentication is one shared token.** It is compared in constant time and
  must be 1–256 ASCII letters or digits. `--token-file` refuses a group- or
  world-readable file; Unix sockets are created owner-only.
- **Use QUIC beyond this host.** QUIC runs TLS 1.3 to a server whose key the
  client pins (`peer=`, the SHA-256 of the server's public key): a server
  with any other key is refused, and the token never crosses the network in
  clear. There is no CA and no hostname check; the pin is the trust decision,
  so copy it from `rbq peer serve` over a channel you trust. The server keeps
  its key owner-only under rbq's state directory (`quic-identity/`, or
  `--quic-identity DIR`); deleting it creates a new identity and every client
  must re-pin. QUIC also retransmits and controls congestion, which a lossy
  relay or mesh link needs.
- **TCP is not encrypted.** `serve` warns when a TCP listen address is
  reachable beyond this host (including `0.0.0.0`); prefer `quic://`.
- **Bounded and additive.** Frames, listings, datagrams and reassembly have
  explicit size and time limits. `put` is still create-if-absent, and the
  server re-checks keys and chunk digests before writing.
- **Pair devices instead of sharing a token.** Every device has one key
  (the QUIC identity). Pairing means each side signs a record about the
  other's key, ahead of time and without prompts:

  ```bash
  # On each device: print its card (key, name, addresses), self-signed.
  rbq peer id --name phone --address quic://100.88.0.7:8788 > phone.card
  rbq peer id --name laptop > laptop.card
  # Carry the cards over a channel you trust, then on the server:
  rbq peer pair add laptop.card --as client            # or --read-only, --expires-days 90
  # and on the client:
  rbq peer pair add phone.card --as server
  # From then on the key authenticates; no token is needed or sent.
  rbq peer serve --listen quic://0.0.0.0:8788          # --token-file is optional now
  rbq peer push paired:phone
  ```

  Or let a device pair itself on first contact with a one-time secret:

  ```bash
  # On the server (with rbq peer serve running): valid 10 minutes, works once.
  rbq peer pair invite --name phone          # prints rbq+quic://HOST:8788?peer=ID&pair=SECRET
  # On the new device, either explicitly or on first use of any peer command:
  rbq peer pair join 'rbq+quic://100.88.0.7:8788?peer=ID&pair=SECRET'
  rbq peer push 'rbq+quic://100.88.0.7:8788?peer=ID&pair=SECRET'
  ```

  The client proves its key in the TLS handshake and sends its card; the
  server checks the card is for that key, spends the secret (atomically, so
  it works once; only its hash is stored), records the client and returns
  its own card, which the client checks against the pin and records. A wrong
  or reused secret ends the connection and counts towards the failure
  throttle.

  A server records which client keys may read (and write), optionally until
  a date; a client records a server's pin and addresses, so `paired:NAME`
  resolves both. A record only counts if this device's own key signed it and
  it has not expired; anything else in the directory is ignored, and
  `rbq peer pair remove PEER` revokes. A card proves its holder has the key,
  not who the holder is, so exchange cards like SSH host keys. Tokens still
  work for unpaired clients and for TCP and Unix sockets.
- **Tailscale and NetBird.** `rbq peer networks` shows whether this host is
  on either overlay (its interfaces; Tailscale's `fd7a:115c:a1e0::/48`; and,
  when installed, `tailscale status --json` / `netbird status --json` for the
  connection state, overlay name and peers) and suggests a QUIC listen
  address on it. A plain `100.64.0.0/10` address on an unknown interface is
  reported as unclassified: carrier-grade NAT uses that range too. When
  `serve` listens on all interfaces, its `connect` list includes one string
  per overlay address. The overlay carries packets; rbq still pins keys and
  checks tokens or pairings. Rebeqah labels overlay interfaces the same way.
- **No mesh integration.** A relay must carry one of these transports (QUIC
  over any IP path, including mesh overlays, or a local socket); rbq does not
  talk to OSHI or other mesh APIs directly.

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
  `object_store` filesystem adapter now implements the production trait, and
  `rbq restic-serve` serves it to restic over REST. S3/R2 adapters, resumable
  multipart, streaming uploads and peer negotiation are not implemented yet.
- R2 is supported through restic's existing S3 backend, but requires account setup
  and an actual off-machine restore test before being trusted.
- No automatic GitHub creation/forking, Frog discovery adapter, AI execution or
  resume engine. Peer sync is manual (`rbq peer`), local-network and
  unencrypted; it can use HTTP or the local TCP/Unix transports, but there is no
  discovery, scheduling or TLS yet.
- Retention is manual (`rbq <layer> prune`); there is no scheduled policy, and
  pruning is not propagated to peers or restic.
- Drives are enrolled and exchanged explicitly (`rbq drive`); there is no
  automatic exchange on insertion, and no Bluetooth or mesh autodiscovery.
  Phone sync remains a manual HTTP connection or an explicit local-transport
  bridge.
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
