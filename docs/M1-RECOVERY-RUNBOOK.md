# Milestone 1 recovery runbook: laptop → Android and/or encrypted S3

**Status:** Operator test specification, 2026-11-18. The end-to-end phone and independent cloud recovery experiments below are **not recorded as passed**. This runbook implements the P0 acceptance gate from [ragbaz-common's distributed-library roadmap](https://github.com/tabenius/ragbaz-common/blob/docs/federated-preservation-roadmap-20261118/docs/DISTRIBUTED-LIBRARY-ROADMAP.md).

## Rules and safety

- Work against disposable sample data and a dedicated Rebeqah storage root. Do not use personal data to explore a new transport or security feature.
- A local published object is not evidence of a second recoverable copy. Report locally-published, remotely-transferred, remotely-verified and owner-restorable separately.
- The filesystem object store can contain **plaintext**. Do not synchronize sensitive layers to cloud without separately validated client-side encryption.
- Use existing **restic encryption** for the first S3/R2 route. Native layer-object S3 is an independent future implementation.
- The current Android peer's `rbq-peer/0` HTTP channel is unencrypted. Use only explicitly trusted local networks or an authorized ADB loopback tunnel; never expose it on the public Internet. Do not paste tokens or account identifiers into reports.
- Hypomnema must be exchanged **only** with an explicit `--layer hypomnema`; its private handoffs are excluded from default peer prefixes on this feature branch.
- Imported content is untrusted and never executable automatically. No automatic destructive merge or deletion.

## Evidence sheet (fill after executing)

| Item | Result / evidence |
|---|---|
| Laptop A OS, commit, Rust/Cargo, `rbq --version` | NOT RUN |
| Android Rebeqah version/build and storage available | NOT RUN |
| Laptop B OS, fresh install/restore destination | NOT RUN |
| `cargo test --workspace` with actual exit status | NOT RUN |
| `rbq storage fsck` with actual exit status | NOT RUN |
| Git sample snapshot ID and owner-verified hash | NOT RUN |
| Mneme/Frog/Agenda sample snapshot ID and validation | NOT RUN |
| Phone object push, verified manifest inventory | NOT RUN |
| Phone restart, A disconnected, B pull and restore | NOT RUN |
| Interruption, retry, up-to-date retransmission | NOT RUN |
| S3 backend, restic snapshot/check/independent restore | NOT RUN |
| Any accepted loss of content, metadata or permissions | NOT ASSESSED |
| Credentials securely recoverable off Laptop A | NOT ASSESSED |

Never report an unchecked line as green.

## Track A — laptop → phone → independent laptop

### On laptop A

1. Build the checked-out branch in a disposable worktree: `cargo test --workspace`, then `cargo install --path crates/rebsync-cli --locked`.
2. Create a synthetic Git repo with a few commits and a disposable native owner snapshot. Use a storage root *separate from* your actual library.
3. Publish and verify selected layers. Example commands (replace ID and paths according to the installed CLI):

   ```sh
   rbq git publish
   rbq mneme publish
   rbq storage fsck
   rbq git list
   rbq mneme list
   ```

4. Pair the Android app using its Sharing card on an authorized, trusted link. Use `RBQ_PEER` or `--token-file` rather than typing a bearer token into a shell command. Be aware that process environment and connection strings may expose credentials; never enable shell tracing.
5. Use explicit layer selection for the trial; `rbq peer status`, then `rbq peer push --layer git` and `rbq peer push --layer mneme` (or another owner-validated sample). Do not include Hypomnema unless separately approved for the test.
6. Restart the app and inspect its actual preserved data, free space and verified inventory.

### On laptop B with laptop A offline

1. Connect to the phone through a trusted link using the application's current supported transport.
2. Run `rbq peer pull --layer git` and the corresponding non-Git pull; inspect reports and run `rbq storage fsck`.
3. Run `rbq git list`, `rbq git restore ID --into /new/recovered-repo`; verify refs and content with Git.
4. Run owner-specific `list` / `verify` / `restore --into` for the non-Git sample; compare reported native hashes, schema and counts with laptop A's recorded evidence.
5. Repeat after a second revision, interruption and reconnection. Check that no existing worktree or live DB is replaced, no corrupt manifest is marked recoverable and an up-to-date peer transfers no unnecessary objects.

**Track A passes only if laptop B restores owner-verified data with laptop A and the public Internet unavailable.**

## Track B — encrypted restic → S3-compatible storage → laptop B

1. Provision a dedicated private S3-compatible bucket and restricted credentials, plus a strong restic password held independently of laptop A. Do not commit either to Git, paste them into CI logs or upload them to Dash.
2. Configure the existing Rebeqah `[backup]` stanza (see root README). Initialize a **new** restic repository only after checking the destination; run an explicitly applied backup of disposable samples. Verify which layers and datasets are actually included.
3. On laptop B, independently supply the restricted S3 credentials and repository password. Use standard `restic snapshots`, `restic check` and `restic restore` to a **new directory**, checking the actual command exit statuses.
4. Validate recovered bytes and restored owner-format snapshots. Do not treat successful `restic snapshots` alone as a recovery drill.
5. Disconnect/reconnect during another upload; observe resumption and absence of misleading completeness claims.
6. Record the independent location of key-recovery instructions without recording the secret itself.

**Track B passes only if laptop B restores the encrypted remote copy without laptop A or a RAGBAZ service.**

## Explicit blockers and future work

- Native S3/R2 `ObjectStorage` remains to be implemented with create-if-absent, bounds, integrity, safe publication and encryption-by-default policy.
- Android automated synchronization and internet-safe encrypted/authenticated peer transport are not shown to be operational by this document.
- Hypomnema owner's `mneme evac verify` must compile and reject malformed real bundles before its Rebeqah adapter is considered ready.
- Device tests, recovery drills and CI results must be linked in a PR before merge/deployment claims.

## Escalation on failure

Preserve the original immutable objects and logs after redacting credentials and sensitive metadata. Do not prune or re-publish under a deceptively identical manifest ID. Diagnose source export, transfer, storage, hash, manifest, owner schema and key recovery as distinct failure classes. If uncertain, mark the outcome **not recoverable** until a new independent test passes.
