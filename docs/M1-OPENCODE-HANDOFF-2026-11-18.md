# Rebeqah M1 implementation handoff and review — 2026-11-18

Status: **candidate code committed, CI and device recovery not yet green**. This document is an actionable local OpenCode/agent handoff, not an assertion of remote test execution. Fleet charter: [ragbaz-common PR #21](https://github.com/tabenius/ragbaz-common/pull/21). Rebeqah work: [PR #10](https://github.com/tabenius/rebsync/pull/10). Mneme owner verifier: [PR #4](https://github.com/tabenius/mneme/pull/4).

## Goal and invariants

Milestone 1 stays **owner-exported Rebeqah layers on laptop A → Android phone and/or encrypted S3 → independent owner-verified recovery on laptop B**. One proven path completes the initial milestone; target both. No public fleet coordinator required.

- Open standards first. Existing Git, restic/S3, Rust object storage and native owner exports remain authoritative.
- Chunks and snapshot manifests are immutable; no destructive auto-merge or remote deletion inference.
- Verify bytes, schemas, source ownership and independent restore separately.
- Hypomnema private evacuation bundles are opt-in peer transfers, not a default layer.
- No sensitive plaintext object sync to R2 by default; restic is the existing encrypted backup route.
- HTTP peer transport must remain restricted to explicitly trusted LAN/authorized loopback tunnel until authenticated encryption is implemented and audited.

## Current review findings and patches on `feat/hypomnema-opaque-layer`

1. **Default private layer leak risk fixed:** `peer::default_prefixes()` excludes Hypomnema. Explicit `--layer hypomnema` still selects it. Added regression test.
2. **Incomplete manifest advertisement fixed:** `peer::push()` now checks the full source snapshot before transmitting a missing manifest. A missing/corrupt chunk rejects that manifest. Existing remote manifests must still be independently checked for their completeness and authorization.
3. **Same-sized corrupted chunk reuse fixed:** `layer::put_chunk()` reads and SHA-256-checks an existing object before accepting it for deduplication (including a create-if-absent race). This intentionally costs additional read I/O; benchmark publish/dedup and consider a trusted verification cache only after proving safe invalidation.
4. **Three-store peer API test added:** `crates/rebsync-core/tests/peer_recovery.rs` exercises Git and another layer from producer through a separate carrying store to a recipient, including repeated sync and structural recovery. It is a **synthetic peer adapter**, not an Android device test.
5. **Additional corruption regression:** `crates/rebsync-core/tests/layers.rs` rejects same-sized corrupt dedup chunks.
6. **Runbook:** `docs/M1-RECOVERY-RUNBOOK.md` contains separate phone and restic/S3 restore trials, and explicit NOT RUN evidence placeholders.

## CI/review state

GitHub checks were reported **failing** on the branches reviewed 2026-11-18. Some newer workflow job logs returned BlobNotFound (no readable log), so do not diagnose those failures without a local build or new available logs. Earlier Mneme logs explicitly reported `cargo fmt --check` differences; those exact rustfmt changes were committed in `tabenius/mneme` branch `feat/hypomnema-rbq-interop-gate`, but a newer CI run also reported failure without readable logs. `ragbaz-common` PR #21 is documentation-only but its checks also reported failing; investigate independently.

**No CI green, merge, deployment, Android test or encrypted R2 restore is claimed.**

## P0 local OpenCode agent task list

### A. Validate Rust branches

```sh
git clone git@github.com:tabenius/rebsync.git
cd rebsync
git fetch origin
git switch feat/hypomnema-opaque-layer
cargo fmt --all --check
cargo test --workspace
cargo clippy --workspace --all-targets -- -D warnings
```

If formatting fails, run `cargo fmt --all`, review the exact diff and commit only mechanical formatting. If compilation fails, repair the smallest relevant source area, rerun the affected targeted test and then the full workspace suite.

Run specifically:
```sh
cargo test --package rebsync-core --features storage-object-store --test peer_recovery
cargo test --package rebsync-core --features storage-object-store --test layers
```

Check Cargo feature names against current manifests; do not interpret a test filtered out by `cfg` as executed.

### B. Validate Mneme owner CLI and Hypomnema

```sh
git clone git@github.com:tabenius/mneme.git
cd mneme
git fetch origin
git switch feat/hypomnema-rbq-interop-gate
cargo fmt --all --check
cargo clippy --locked --all-targets -- -D warnings
cargo test --locked --test evac
cargo test --locked
cargo run --locked -- evac verify --help
```

Test a real owner-built `hypomnema.bundle.v1` and malformed/trailing data, not synthetic metadata masquerading as valid bundle contents. Verify that the Rebeqah CLI can invoke the installed `mneme evac verify --bundle` command, parse its JSON, and reject source mutation, invalid hashes and unexpected formats. Confirm restore uses a new file and private permissions.

Review `MultiGzDecoder` trailing members behavior, decompression bounds, symlink/TOCTOU staging and permission handling. The owner verifier does not claim the handoff instructions are truthful or safe to execute.

### C. Confirm peer authorization boundaries

- `rbq peer push` and `rbq peer pull` with no `--layer` must not exchange Hypomnema.
- `rbq peer push --layer hypomnema` must do so only under an explicitly authorized peer connection; verify that the Android receiver actually supports the new layer namespace.
- Verify a remote listing that contains an existing but corrupt same-size object does not yield a false **verified/recoverable** claim. Investigate peer object integrity and immutable content conflicts.
- Test missing chunks, corrupt chunks, bad manifests, interrupted manifest publication and re-pull/re-push.
- Review `rbq-peer/0` bearer-token transport and avoid public interfaces until transport authentication/encryption work is finished.

### D. M1 recovery drills

Follow `docs/M1-RECOVERY-RUNBOOK.md`. First use an authorized Android app over trusted LAN or ADB loopback and physically disconnect laptop A/Internet. Then run an independent restic restore from a private S3/R2 repository on laptop B with key material supplied independently. Record source hashes and owner validator output; redact secrets and sensitive file paths. Do not merge device integration until the actual hardware test passes.

### E. S3 adapter only after encrypted restic path works

Do not turn a backup into an accidental plaintext replica. Native S3 `ObjectStorage` work needs vetted create-if-absent semantics on R2 and a second backend, integrity checks, bounded multipart/range reads, policy and encryption-before-upload. Preserve the current local trait and versioned manifests rather than inventing a new data model.

## Small next-PR decomposition

1. Rebeqah storage/peer correctness (same-size dedup verification, incomplete-manifest exclusion, three-store tests) — ideally a focused PR independent from unvalidated Hypomnema integration.
2. Mneme CLI verifier release gate — formatting, unit/integration tests and cargo build.
3. Hypomnema owner-backed import/export, scoped selection and Android namespace compatibility.
4. Android actual recovery-test evidence and transport hardening.
5. Encrypted restic/S3 independent restore evidence.
6. Native S3 layer adapter (separate, encryption/atomicity reviewed).

## Architectural boundaries not to conflate

- A new file in `ragbaz-common` does not mean a device can recover it.
- Git and native database snapshots do not replace backup of ignored files, uncommitted changes, LFS objects or live DB WAL.
- Content hashes cannot attest authorship or claims; Mouseion/Nostoi/WeftMark handle evidence/publication separately.
- Dash Hypomnema ingestion is another integration; it must not block M1. The historical Dash branch diverged and had incomplete trust validation; never claim production availability without a scoped real canary.
- A donor-supported interoperable library needs independent conformance fixtures and ownership boundaries, not a mandated cloud control plane.

## Definition of done for current branch

- Format, clippy, Rust tests and integration tests passed on a recorded commit.
- Layer-owner test fixtures genuinely validate source schemas.
- Default peer transfers do not include private handoffs.
- Published manifests cannot depend on already corrupted local chunks.
- At least one real independent phone or encrypted S3 recovery succeeds with laptop A unavailable.
- A human reviews security boundaries and only then reconciles the PR into main.
