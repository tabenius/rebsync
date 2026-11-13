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
Agenda editions are currently blocked pending an owner-validator adapter.

A filesystem restic repository may be useful for tests or an enrolled USB drive,
but rebsync does not assert that it is independent of this machine. It never
prunes backups or propagates deletions.

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

- R2 is supported through restic's existing S3 backend, but requires account setup
  and an actual off-machine restore test before being trusted.
- No automatic GitHub creation/forking, Frog discovery adapter, consistent remote
  SQLite export, agenda validator, AI execution, resume engine or peer protocol.
- No USB enrollment, phone transport, Bluetooth or mesh autodiscovery yet.
- No tags/LFS migration or automatic organization-wide repository creation.
- No claim that copying data to this same disk protects against laptop loss.

The core crate owns operational behavior; the clap CLI only parses/renders and
maps exit codes. No terminal printing or prompting is performed by the core.
