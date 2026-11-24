# RBQ service and credential store

Status: proposed architecture; credential boundary implementation started.
Existing CLI 0.1.3 behavior is unchanged. Pairing, keystore replication, a local
management API and a local MCP server are not implemented by this plan.

## Integration with the branch reconciliation

This is part of the 2026-11-23 Dash/Pieces/RBQ reconciliation, not an alternative
roadmap. The workspace review and branch dispositions are recorded at
`/srv/ragbaz/reports/dash-pieces-rbq-branch-review-2026-11-23/{REVIEW,BRANCHES}.md`.
Those machine-local reports are evidence, not portable dependencies of this repo.
Keep their selective-port decisions and refresh bases before every integration.

Execution order:

1. Port RBQ integrity fixes onto current main, including Mneme's duplicate chunk
   path; remediate Dash dependencies from current main, not the old lockfile.
2. Publish Pieces canonical navigation/catalogue source, then update Dash's pin.
3. Extract Dash's account repository service; layer its encrypted-keystore
   adapter onto that seam. Develop the native credential boundary separately
   but do not enable sync before this account-policy boundary is tested.
4. Specify and implement **opt-in** keystore exchange and cross-device recovery.
   Distinguish transfer of locked signing-key backups from API credential use.
5. Integrate editor, navigation and language ports with async-state regressions.
6. Repair inspector selection races, Worker routes/CSP and built-Worker tests;
   only then advertise them in Dash.
7. Salvage missing Hypomnema/sidecar/release-tool changes selectively. Never
   replay deployed/overlapping migration names or merge obsolete router copies.

Older two-party identity/workspace branches remain gated on an explicit product
and auth decision. Already represented CAD/registry/offline-security behavior
requires verification, not another merge. No dirty worktree or safety ref is
discarded as part of this plan.

## Direction

One Rust application service owns operations, policy and credential use. CLI,
Tauri commands, local HTTP and MCP are adapters, not separate implementations.
Use it in-process first; a daemon is optional, not required for every CLI call.

```text
CLI / Tauri invoke / local MCP / local HTTP
                    |
       RBQ service: authorize, execute, journal
                    |
       credential store + object store + sync engine
                    |
       phone peer adapter / Dash HTTPS adapter
```

These are separate trust boundaries:

| Deployment | Default | Authority |
|---|---|---|
| Same-host | In-process or owner-only Unix socket | Explicit local principal and capability policy; same UID is not human approval |
| Phone/Tauri remote peer | Disabled until enrolled; authenticated encrypted transport | Per-device grants, not a shared URL token |
| Dash sink | Outbound HTTPS only, no redirects | Account-bound, scoped, expiring Dash credential |

Do not expose the local management API by binding it to `0.0.0.0`. Remote object
exchange and remote management require distinct grants. A phone may be a peer
without being allowed to manage credentials or invoke shell commands. Restic
REST remains a specialized adapter with its existing append-only contract.

## 1. Credential store first

Separate a public-ish metadata catalog from a device-local secret backend.
"Public" means safe for authorized projections, not anonymously published:
labels, endpoint relationships and key inventories can still be private.

Each entry has a random stable credential ID, kind, issuer/account binding,
exact audience, scopes, creation/expiry, local status and backend reference.
IDs are not fingerprints, repository identities or evidence of ownership.
Metadata cannot grant authority: intersect it with backend policy and the
issuer's current authorization. Unknown remote revocation is not "active".

Kinds remain distinct:

- Dash bearer credential: secret usable for one account/repository audience.
- Peer credential: device enrollment and a bounded peer grant.
- Signing key: use a native signer/agent handle; do not extract private bytes.
- Wrapping/recovery key: separate from signing, authentication and VAPID keys.

`credentials.rs` starts the typed store interface, redacted non-serializable
secret container and grant checks. There is deliberately no default backend:
absence or a locked backend must fail, not select plaintext storage silently.

Backend order:

1. Linux desktop: OS secret service/keyring, explicit locked/unavailable states.
2. Android: platform keystore protecting a wrapping key; native Rust/plugin
   bridge. Hardware-backed capability is reported, never assumed.
3. Other Tauri desktops: OS keychain; share the service and metadata model.
4. Headless Linux: explicitly selected owner-only credential files, with a
   `0700` directory and `0600` files, bounded no-symlink reads, atomic no-clobber
   creation, fsync, locking and crash recovery. This is **not encryption at rest**.

Backend transactions must create metadata and secret together or leave a
recoverable orphan, never a usable entry missing its policy. Updates use a
generation/CAS boundary; rotation creates a new secret before retiring the old
one. Revocation is durable before success is reported; provider revocation and
local disabling have separate outcomes. No generic `get_secret` CLI/MCP/HTTP
operation. Trusted Rust adapters may obtain secret bytes for an authorized
request; minimize their lifetime and never put them in errors or Debug output.
Memory wiping is defense in depth, not a claim that process memory is protected.

## 2. Passkey-approved Dash enrollment

1. Local RBQ generates a high-entropy private claim nonce and pairing ID.
   Dash stores only a nonce hash, expiry and immutable requested parameters.
2. MCP may request/inspect the pairing using its public ID and receive an
   approval URL. Neither claim nonce nor bearer key appears in tool output.
3. Dash shows matching code, target account, device label, exact repository,
   scopes and expiry. A fresh passkey step-up approves those exact parameters;
   bind the approval server-side to the request/account and consume it once.
   A signed-in email session alone must not substitute for this approval.
4. RBQ claims over HTTPS with its nonce. A transaction consumes approval and
   issues one independently revocable credential. Never return the secret to
   MCP, put it in a URL or write it to browser storage.
5. RBQ persists it through the selected backend and prints metadata only.

Requests expire, are rate-limited, and cannot increase scopes during approval.
Claim races allow one winner. An ambiguous lost response requires revoke/reissue,
not plaintext retrieval. Define a public pairing-status/cancel recovery path so
an issued-but-lost credential can be revoked without knowing its secret. No
external callback URL, localhost listener or browser clipboard is required.

Existing `rbm_` MCP credentials and manually supplied token files continue to
work. Dedicated sync credentials need separate server-side validation and
revocation, without MCP/key-creation/signing authority. Preserve repository UUID
across rotation; do not use credential IDs as repository identities. Change the
owned repository contract and its vendored copy together if token syntax changes.

## 3. Keystore synchronization: three different operations

### Metadata replication

Sync authorized public keys, fingerprints, device IDs, credential descriptors,
expiry and issuer-signed revocation information through source-preserving RBQ
objects. Never sync backend handles, bearer tokens or private keys as metadata.
Keep upstream source IDs, exact source bytes and provenance. Imported metadata
is untrusted until its issuer/binding is verified; it cannot enroll a device or
resurrect a revoked key. Different credentials never merge because labels match.

### Per-device enrollment (the default)

Tauri/phone and Linux each generate or receive their own key and Dash grant.
Dash lists and revokes these independently. Sync is not token cloning. Platform
passkeys and non-exportable keys stay in their platform authenticators. A
reinstalled device enrolls afresh unless explicitly restored through recovery.

### Optional encrypted key backup/transfer (later, separately reviewed)

Only exportable keys with explicit per-key, per-recipient approval qualify.
Use an established authenticated-encryption/envelope format and library, not a
new cryptographic scheme. Bind version, key ID, purpose, issuer, recipients and
generation as authenticated data. Dash stores ciphertext and descriptors only;
recipient unwrap/recovery keys must not be stored alongside it in Dash.
An approved recipient-device binding is required before wrapping a key to it.

Evaluate the existing Pieces encrypted single-key backup format from the
reconciliation candidate before introducing another format. Its generic RBQ
append/read support is not automatic peer/sink synchronization. Preserve read
compatibility with `keystores/v1/pieces/` when adding source-scoped exchange;
explicitly select both legacy objects and future source-scoped descriptors, with
no silent relocation or identity inference from matching bytes.

Select the interoperable envelope format and recovery UX before new implementation. Define rollback
detection, durable revocation tombstones, concurrent updates, device loss,
recovery-key loss and restore validation. Offline clients cannot promise instant
revocation or remote erasure; issuer rejection is the authority for bearer keys.
Do not use the normal object replication path for plaintext credential files.
Dash's existing RBQ storage is account-private, **not E2EE**; only separately
encrypted envelopes can make the key-backup claim.

## 4. Service API and transports

Start with typed operations: status/capabilities, credential descriptors,
pairing begin/status/cancel, revoke, source/artifact list/read, explicit push/pull,
and arrivals/watch. Credentials are selected by ID and checked against a typed
operation and exact audience. Browser, peer and local grants are not interchangeable.

Mutations use bounded inputs, idempotency IDs and redacted audit events. Long
syncs return job IDs; typed events support cursors/cancellation/backpressure.
Notification, arrival or read receipt never approves a gift or grants authority.
Report storage/compute/production independently, including unknown/unsupported.

Local HTTP uses versioned JSON over an owner-only Unix socket initially. If a
browser bridge is needed, add explicit loopback authentication, Origin/Host
checks and CSRF protection; CORS alone is not authorization. Tauri invokes the
same Rust service directly. Local MCP wraps an allowlist of those operations,
with destructive/admin actions separated from read-only navigation. No shell
execution or secret-export escape hatch. GraphQL is deferred.

Remote peer transport uses TLS with verified enrollment/device bindings (or an
explicit secure tunnel); discovery is never trust. Keep current `rbq-peer/0`,
`rbq-peer/1` and restic compatibility adapters until replacement conformance
tests pass. Existing phone HTTP/token URLs are legacy compatibility, not a
suitable keystore-transfer channel.

## 5. Decrease duplication without a big-bang rewrite

| Current code | Refactor target |
|---|---|
| `private_http.rs`, transport token files, Tauri settings token | Shared credential references and backend policy; explicit import, no silent migration |
| `transport::Service` and Tauri `peer.rs` | Shared Rust object/policy service; separate socket/HTTP framing |
| CLI orchestration and Tauri commands | Same Rust application operations, no terminal I/O in core |
| TS/Rust validators and hand-kept DTOs | Owned versioned schema, generated types, shared accept/reject vectors |
| Dash Worker account/R2/D1/queue handlers | Keep JS/TS platform adapters and account authority |
| Browser presentation and native lifecycle | Keep React/TS UI; native Rust credential/signing boundary |

Most Tauri backend code is already Rust and already depends on `rebsync-core`.
Extract duplicated policy before rewriting languages. A Rust/WASM pure validator
is an option only if generated contracts/vectors prove insufficient; measure
bundle size, startup, compatibility and maintenance cost first. Do not port
Cloudflare auth, queues or D1 transactions just for language uniformity. Avoid
moving secrets into browser WASM; it does not provide a native-keystore boundary.

## Milestones and acceptance gates

1. **Credential boundary** (started): typed descriptors, redacted secret type,
   backend trait and exact grant tests. No production persistence claim yet.
2. **Linux backend + service integration**: keyring and explicit headless mode;
   replace direct token-file reads through an explicit compatibility adapter.
   Test permissions, symlinks, lock/unavailable, races, crash recovery and no
   serialization/log leakage. Retain source token files unless user removes them.
3. **Dash pairing + Tauri backend**: fresh passkey approval, one-time claim,
   independent revocation, native store integration. Test claim races, approval
   replay, wrong account/audience, expiry, lost delivery and compromised MCP.
   *Started:* `credentials::files::FileStore` (the explicit headless backend),
   `dash_pairing` (begin/status/claim/cancel, local matching code, revoke on a
   lost claim) and `rbq dash`, `rbq repository --credential`. Dash accepts the
   `rbs_` credential within its scopes. Tested end to end with the real CLI in
   Dash's `test/rbq-pairing-cli.test.mjs`. Still open: Dash's approval page,
   the production passkey adapter, the Tauri app and native keystores.
4. **Public registry sync**: verified device/account binding, source preservation,
   tombstones and conflict tests. No private material replicated.
5. **Unified service adapters**: migrate CLI/Tauri object handlers, then local
   API/MCP. Test capability parity, remote denial, cursor replay and cancellation.
6. **Encrypted backup/transfer**: reviewed format, recovery story and test vectors
   before shipping; tamper, wrong recipient, replay/rollback and recovery tests.

Each milestone is independently reviewable and preserves current push/pull and
historical source references. Production migrations/deployments and any native
key access need their own validated implementation, not authorization inferred
from this architecture plan.
