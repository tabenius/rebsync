# P0: Rebeqah storage layers → encrypted S3/R2 → independent recovery

Status: **implemented recovery operator workflow; real provider credentials and
two-machine recovery evidence are NOT yet available**. Nothing here claims a live
R2 transfer has been completed. The goal is specifically Rebeqah's existing
**content-addressed storage layers**, not a generic folder synchronizer.

This recovery path deliberately uses Rebeqah's **existing restic/S3 backend**,
rather than opening its plain content-addressed object store directly to R2.
Restic encrypts content client-side and can restore it without any RAGBAZ service.
This is a separate recovery exercise from Rebeqah's per-repository Git snapshots.

## What the operator script does

`scripts/rbq-s3-recovery.py` has two commands:
- **backup** (laptop A): inspect every regular object file, hash its bytes,
  run `rbq storage fsck`, back up the **whole Rebeqah object root** to an
  existing encrypted restic repository on S3/R2, require a completed snapshot
  ID and read-back, run `restic check --read-data` by default, and create a
  private, non-overwriting JSON receipt. It refuses a receipt if the source
  changed while being backed up.
- **restore** (laptop B): read a trusted transferred receipt, restore that
  *exact* snapshot into a new staging directory, compare **every restored
  file byte digest and size**, run `rbq storage fsck` against the restored
  object root, and only then atomically publish the recovery directory.
  Existing destinations are never overwritten.

It refuses symlinked or non-regular object paths and avoids shell execution,
implicit repository initialization, pruning and deletion. Both commands
are **preflight-only** without `--apply`.

**Important distinction:** restic's repository data check and Rebeqah structural
`fsck` do not establish that a native Git, Mneme, Frog or Agenda owner has
opened and verified its exported snapshot. Complete M1 acceptance also needs
the relevant owner-specific `rbq ... verify` and restore on laptop B.

## Prerequisites

Both machines: Python 3.10+, installed `restic`, installed compatible `rbq`
with its object-store storage feature. The source laptop must already have
published at least one owner-validated layer with a snapshot manifest.

Provision **an existing** private S3 bucket or Cloudflare R2 bucket, scoped
access credentials, and one restic repository initialized intentionally.
Use separate secret handling for each laptop: the restic password must be
recoverable without laptop A. Never put the password, access key, secret key
or a signed presigned URL in Git, the receipt, an issue or a CI report.

The operator script intentionally requires:
```text
RESTIC_REPOSITORY=s3:https://ACCOUNT_ID.r2.cloudflarestorage.com/PRIVATE_BUCKET/rbq-layers
AWS_ACCESS_KEY_ID=<from a private credential manager>
AWS_SECRET_ACCESS_KEY=<from a private credential manager>
RESTIC_PASSWORD_FILE=/private/path/to/owner-only-restic-password
```

This is an **example of variable names**, not a request to paste credentials.
Use private environment provision by an OS credential manager, non-logged
secret store, or an explicitly protected shell; avoid shell tracing. A password
file must have mode 0600 on Unix. S3/R2 must be reached over HTTPS.
Initialization is separate and explicitly approved by the bucket owner;
the script will **never** call `restic init`.

### Laptop A: publish, then send an encrypted snapshot

1. Check the local object store and publish a **synthetic** Git and another
   native owner-layer fixture; do not start with unreviewed personal data.
2. Confirm source structural integrity:

   ```sh
   rbq storage path
   rbq storage fsck
   ```

3. Set the credential environment privately (as above). Confirm
   `restic snapshots` can read the *existing* encrypted repository.
4. Run a read-only preflight:

   ```sh
   python3 scripts/rbq-s3-recovery.py backup \
     --storage-root "/absolute/path/from/rbq-storage-path" \
     --receipt "/private/transfer/m1-receipt.json"
   ```

5. Perform encrypted backup and full remote data verification:

   ```sh
   python3 scripts/rbq-s3-recovery.py backup \
     --storage-root "/absolute/path/from/rbq-storage-path" \
     --receipt "/private/transfer/m1-receipt.json" --apply
   ```

   Only a completed backup creates the receipt. `--skip-read-data` is
   provided for expensive repositories, but **does not satisfy the full P0
   remote-integrity gate** and is recorded as such.

6. Send the receipt to laptop B using an authenticated private channel.
   The receipt includes original source paths and file names: it is
   **sensitive metadata, not a public attestation**. A checksum alone does
   not authenticate a receipt received from a third party.

### Laptop B: source laptop and RAGBAZ services disconnected

1. Independently install `rbq` and `restic`; supply the separate S3 read
   credentials and the same restic repository password from independent
   recovery custody. Laptop A must be unavailable during this test.
2. Restore using the transferred private receipt (first omit `--apply`):

   ```sh
   python3 scripts/rbq-s3-recovery.py restore \
     --receipt "/private/transfer/m1-receipt.json" \
     --into "/private/new-empty-recovery-dir" --apply
   ```

3. The JSON success report contains `restored_storage_root`—use that
   absolute path for subsequent Rebeqah commands:

   ```sh
   rbq --storage-root "/path/from/restored_storage_root" storage fsck
   rbq --storage-root "/path/from/restored_storage_root" git list
   ```

4. Restore a specific Git snapshot into a **new** repository and compare
   branches and object content. Independently verify and restore at least one
   non-Git owner layer through its native CLI and content/schema validator.
   This must be a different laptop, VM or isolated recovery environment,
   not merely a successful local restic readback.
5. Record `rbq` commit, restic version, restic snapshot ID, object byte count,
   hashes and exact acceptance checks. Redact all private paths, repository
   URLs that contain identifiers, and credentials before publishing evidence.

## Acceptance gates (all distinct)

| Gate | Status until measured |
|---|---|
| Local owner export and Rebeqah structural verification | NOT RUN |
| Encrypted remote S3 backup and snapshot ID readback | NOT RUN |
| Full `restic check --read-data` | NOT RUN |
| Independent B restore and exact file-hash comparison | NOT RUN |
| B `rbq storage fsck` | NOT RUN |
| Git owner-level recovery on B | NOT RUN |
| At least one non-Git owner-level recovery on B | NOT RUN |
| Lost-source/password recovery drill | NOT RUN |

**The presence of this script, a receipt, a green mocked test, or a remote
snapshot listing must not change these statuses.** Real credentials and
a compatible remote repository have not been provided to this execution
environment, so the live recovery drill requires operator execution.

## Security and limitations

- The receipt is an inventory of file names and SHA-256 digests, **not signed
  provenance**; transfer it only over a trustworthy authenticated channel.
- Object-store snapshots are copies, not permissions or publication rights.
- A quiescent source is essential: the script compares source file contents
  before and after backup, but cannot rule out every concurrent filesystem
  race or owner database inconsistency. Publish from owner-validated exports.
- A compromised server could cause availability failures even while restic
  confidentiality and integrity protections hold. Independent key custody is
  crucial.
- `restic check --read-data` may be expensive for a large shared repository.
  Plan a dedicated repository for M1 and distinguish incomplete checks.
- This workflow does **not** introduce an S3-native `ObjectStorage` adapter,
  auto-upload new layers, peer discovery, pruning, or Cloudflare deployment.
- The CI test uses mocks of restic/rbq to verify the operator state machine;
  it is not a real S3/TLS/encryption integration test.

## Next implementation checkpoint

After an independently recorded real restore passes, integrate an optional
Rebeqah CLI command that reports four separate states: locally published,
encrypted remote snapshot present, remotely integrity-checked, and
independently owner-recoverable. Preserve a testable open protocol and explicit
opt-in replication. Add a native S3 `ObjectStorage` backend only as a
separate encrypted and capability-reviewed track.
