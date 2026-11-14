# rebsync

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
rebsync --help
rebsync --root src/ragbaz
rebsync . --dry-run --json
```

`rebsync .` sets Rebekah home to the current directory. Otherwise it defaults to
`$HOME`. Relative scan roots, password-file and dataset paths resolve against that
home. Configuration values do not perform shell expansion; use an absolute path
instead of writing `$HOME` inside TOML/YAML.

## Configuration

Precedence, lowest first:

1. Built-in defaults.
2. `$XDG_CONFIG_HOME/rebsync/config.toml`, `.yaml` or `.yml` (default config home:
   `$HOME/.config`).
3. `<rebekah_home>/rebsync.toml`, `.yaml` or `.yml`.
4. `--config PATH`.
5. Explicit CLI overrides.

Lists replace earlier lists. Unknown keys and competing formats at one layer are
errors. User/explicit configuration may set `rebekah_home`; a home-local file may
not redirect it. Relative `rebekah_home` resolves against the invoking directory.

```bash
rebsync config explain
rebsync --config examples/rebsync.toml --no-push --dry-run
```

See [the working TOML example](examples/rebsync.toml). YAML has the same structure.
Configuration explain redacts the backup repository URL, since URLs can contain
credentials. Never put secrets into configuration or source control.

## Encrypted preservation

Configure an **existing** restic repository and a separate password file (or
`RESTIC_PASSWORD` / `RESTIC_PASSWORD_FILE`). For Cloudflare R2:

```toml
[backup]
repository = "s3:https://ACCOUNT_ID.r2.cloudflarestorage.com/PRIVATE_BUCKET/rebsync"
password_file = "/private/path/rebsync-restic-password"
```

Supply bucket-scoped `AWS_ACCESS_KEY_ID` and `AWS_SECRET_ACCESS_KEY` in the
environment. Keep the password and an independently stored recovery copy outside
all source repositories. No Cloudflare resources or credentials are automatically
created or inferred.

Initialize only when deliberately creating a new repository:

```bash
rebsync backup-init --confirm --config /path/to/rebsync.toml
rebsync --config /path/to/rebsync.toml --apply
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
but rebsync does not assert that it is independent of this machine. It never
prunes backups or propagates deletions.

## Local object storage

`rebsync` can publish Rebsync-managed objects into a local filesystem root behind
a narrow `ObjectStorage` trait. This is the **client-side** contract for future
S3/R2 adapters, not an S3 server, not a restic REST server, and not a change to how
restic stores or encrypts existing snapshots.

The adapter is feature-gated. `rebsync-core` keeps `storage-object-store` off by
default; the CLI enables it through its default `storage` feature. Build the CLI
with `--no-default-features` to omit it. Restic-based backup and Git exchange do
not use this layer.

```toml
[storage]
# Relative paths resolve against rebekah_home. Default shown.
root = ".rebsync/objects"
```

`--storage-root PATH` overrides the file for one invocation, which is the easiest
way to keep experiments away from real home storage:

```bash
rebsync storage path
rebsync storage path --storage-root /mnt/backup/rebsync --json
rebsync storage check --storage-root /tmp/rebsync-probe --json
```

`storage check` writes a `_probes/check-*` object, verifies create-if-absent,
readback, range read, HEAD and raw-prefix listing, then deletes it. It never touches
the restic repository. Keys are limited to ASCII letters, digits, `.`, `-`, `_`
and `/`; empty segments, traversal, leading/trailing slashes and overlong keys are
rejected, and symlinked path ancestors are refused. Filesystem publication is
fsynced. Deletion exists for storage administration only: no synchronization
policy propagates repository deletions between peers.

## Mneme layer (session-history index)

[Mneme](https://github.com/tabenius/mneme)'s index is a live SQLite WAL database,
which repository snapshots and `directory` datasets refuse. This layer never
copies the live files. Mneme owns the format, so Rebsync asks it to export and
to validate:

1. `mneme snapshot create` writes a consistent `VACUUM INTO` copy, runs
   `integrity_check`, and reports schema, generation, counts and SHA-256.
2. Rebsync re-hashes the file itself and publishes it into the object store as
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
binary = "mneme"          # PATH lookup; paths resolve against rebekah_home
# db = "/private/mneme/index.sqlite"   # else mneme's default / MNEME_DB
label = "local"           # one key segment naming this history store
chunk_bytes = 65536       # multiple of 4096, 4 KiB..64 MiB
restic = true             # requires backup.repository
timeout_seconds = 900
```

```bash
rebsync mneme publish                 # export + publish now (journaled)
rebsync mneme list [--label local] [--json]
rebsync mneme stats [--json]          # read-only: dedup, orphan and missing chunks
rebsync mneme verify local/20261114T112650.973Z-d7af0bf4f612
rebsync mneme restore ID --into /private/new/index.sqlite
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
validator, so Rebsync checks the copy itself, through Python's standard `sqlite3`
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
that manifest is the owner's validator. Rebsync copies an edition as follows:

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
rebsync frog publish | list | stats | verify ID | restore ID --into /new/AGENTS.db
rebsync agenda publish | list | stats | verify ID | restore ID --into /new/edition
```

In `--apply` runs these layers report `backed-up` (restic succeeded),
`published-local`, `blocked` or `failed`, exactly like Mneme. A
`backup.datasets` entry with `kind = "agenda"` now points to the `[agenda]`
layer instead.

## Phone sync (Rebekah)

`rebsync peer` exchanges layer objects with the Rebekah Android app's
`rebsync-peer/0` endpoint. Copy the connection string from the app's Sharing
card. Pass it through `REBSYNC_PEER` so the token stays out of shell history:

```bash
export REBSYNC_PEER='rebsync+http://192.168.1.42:8787/v1?token=…'
rebsync peer status                  # what the phone holds, per layer
rebsync peer push                    # this machine → phone
rebsync peer pull --layer frog       # phone → this machine, Frog only
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

  Run `rebsync <layer> verify ID` before relying on a pulled snapshot.
- **Plain HTTP on the local network.** Use Wi-Fi you control, the phone's
  hotspot or USB tethering. Listings page with `after=`, which needs Rebekah
  0.2.1 or later; older apps produce a clear error.

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

An advisory shared-Git-directory lock coordinates rebsync instances. Ordinary
editors and Git commands do not honor that lock; keep repositories quiescent
during preservation. Fingerprints catch ordinary concurrent modifications but do
not promise an atomic filesystem snapshot.

## Journals and reconciliation

Writes `<rebekah_home>/rebsync_YYYY-MM-DD_HHMMSS.jsonl` in UTC, with collision-safe
filenames, action intents/results and before/after branch IDs. Dry-runs write a
journal but do not mutate repository refs, fetch, push or back up. Logs exclude
raw subprocess output and unknown remote URLs to avoid leaking credentials.

Applied runs leave reconciliation instructions under
`.rebekah/rebsync/reconcile/<repository-id>/<run-id>/rebekah-repo-reconcile-merge.md`.
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
  resume engine. Peer sync is manual (`rebsync peer`), local-network and
  unencrypted; there is no discovery, scheduling or TLS yet.
- The Mneme layer has no retention policy or garbage collection yet; `rebsync
  mneme stats` reports orphans but nothing removes them.
- No USB enrollment, phone transport, Bluetooth or mesh autodiscovery yet.
- No tags/LFS migration or automatic organization-wide repository creation.
- No claim that copying data to this same disk protects against laptop loss.

The core crate owns operational behavior; the clap CLI only parses/renders and
maps exit codes. No terminal printing or prompting is performed by the core.
