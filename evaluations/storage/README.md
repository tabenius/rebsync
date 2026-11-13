# Isolated storage evaluation

This is an unpublished experiment, not a third production crate and not part of
the root workspace. It does not change the installed `rebsync` command.

See [`docs/STORAGE-EVALUATION.md`](../../docs/STORAGE-EVALUATION.md) for the
comparison, semantics and decision gates.

## Run

Requires Python 3, Cargo/Rust (1.91 or newer for the OpenDAL candidate) and the
ordinary native build tools required by dependencies. The committed lockfile
fixes the dependency graph. Default probes build only filesystem functionality;
all exercised storage is temporary and local. Cloud client construction is a
separate opt-in build, not a prerequisite for the local semantic comparison.

```bash
python3 evaluations/storage/run.py
python3 evaluations/storage/run.py --resume
python3 evaluations/storage/run.py --cloud-build --resume
```

The runner checks formatting, executes both probes and saves JSON results. Resume
skips only successful results matching the probe source, manifest and lockfile
hash. A failing executable is never cached as success. To use an external build
cache, set `CARGO_TARGET_DIR` to a **disk-backed directory**, not a small `/tmp`
tmpfs. The default build concurrency is one job and can be overridden through
`CARGO_BUILD_JOBS`. Cloud/TLS builds can consume substantial space; the first
combined build exceeded this host's 1.4 GiB `/tmp` tmpfs.
The evaluation-only development profile disables debug info and incremental
artifacts to reduce build storage. Production build profiles are unchanged.

Individual probes:

```bash
cargo run --locked --manifest-path evaluations/storage/Cargo.toml \
  --features object-store --bin object-store-probe
cargo run --locked --manifest-path evaluations/storage/Cargo.toml \
  --features opendal --bin opendal-probe
```

With `--cloud-build`, builders use explicit dummy credentials and do not send provider requests.
Building can download crates. No AWS/R2 bucket is created, read or modified. The
local fixtures are removed on exit. Neither probe opens a server or reads actual
repository contents.

The saved `object-store-cloud-initial.json` predates the feature split. Its
manifest snapshot is alongside it; use the recorded Git revision for the probe
source and lockfile when checking its original input hash. Normal `--resume`
results use the current local-only or cloud-build recipe and do not reuse that
historical report.

Results distinguish observed behavior from untested features. In particular,
streaming writers do not prove restart-resumable multipart, metadata flags do not
prove atomic exclusion, and client construction does not prove cloud compatibility.

To let a long build survive OpenCode restarts, the same runner may be launched as
a user systemd service. This is an execution convenience, not a runtime dependency
of rebsync.
