# Storage abstraction evaluation

Date: 2026-11-13. Status: **initial evaluation, not a production dependency decision**.

The browser-readable roadmap is [plan.html](plan.html#r2). Reproducible probes are
in [`evaluations/storage`](../evaluations/storage). The two production crates and
their dependency lockfile remain unchanged by this experiment.

## Decision to make

Choose the implementation beneath a small Rebsync-owned storage contract, not an
entire synchronization system. It must support filesystem storage and S3-family
clients, initially AWS S3 and Cloudflare R2. Incoming S3 and restic REST protocols
are separate server adapters. A client library is not a wire-protocol server.

Preserve the current restic CLI backup path while evaluating native adapters.
Restic continues to own encryption, repository encoding, backup locking and
restores. Do not reinterpret or rewrite its encrypted repository format.

## Candidates and verified package metadata

These versions were inspected using `cargo info` and the published crate source,
not inferred from older tutorials:

| Criterion | object_store 0.14.2 | Apache OpenDAL™ 0.59.5 |
| --- | --- | --- |
| License | MIT / Apache-2.0 | Apache-2.0 |
| Declared minimum Rust | 1.85 | 1.91 |
| Primary shape | Object-storage operations and typed object paths | Operator over many storage/service protocols |
| Initial backends | Filesystem, memory and S3-family clients | Filesystem, memory, S3 plus broader SFTP/WebDAV/consumer-cloud service options |
| Conditional writes | Explicit `PutMode::Create` / update mode; actual support depends on backend | Write options plus runtime capability flags; actual semantics still need testing |
| Durability control | Local `with_fsync(true)` synchronizes write publication; disabled by default | FS writer source synchronizes the file; directory publication durability must be separately established |
| Listing caveat | High-level prefixes match path segments, not arbitrary S3 string prefixes | High-level filesystem/directory listing must not be equated with S3 raw-prefix listing |
| Lower-level pagination | `PaginatedListStore`, including an S3 implementation | Operator listing can page internally; raw S3 continuation-token passthrough needs further investigation |
| Multipart | High-level upload handle; S3 also implements lower-level `MultipartStore` with upload/part IDs | Streaming writer; S3 multipart internals exist, but a public restart/resume interface is not established by this review |
| Server functionality | Not an S3 or restic REST server | Not an S3 or restic REST server |

The opendal 0.59.5 docs.rs API build was unavailable during inspection. The
published 0.59.5 crate sources, rather than silently substituted older API docs,
were used for its current behavior and build probes.

The isolated features enable only FS and S3 provider functionality, with the
runtime/TLS pieces needed to construct clients. They do not enable every backend
or import both abstractions into production.

## Contract and selection gates

### Storage milestone 1: reliable objects and restic interoperability

The internal contract needs put/get/head/list/delete, ranged reads, bounded-memory
streaming, typed errors, immutable-object creation and explicit durability and
consistency guarantees. Conditional replacement is a distinct capability; do not
pretend that a HEAD-then-PUT sequence is atomic.

The filesystem namespace must be dedicated to storage and safe for opaque keys.
Do not expose a source checkout directly as an S3 bucket. Library path validation
is not a complete security boundary against symlinks or external filesystem
mutation. Namespace mapping must address case sensitivity, traversal, reserved
paths and file/directory collisions. Early restic keys can use their constrained
layout; arbitrary S3 key compatibility needs its own explicit profile.

Use `ListObjectsV2` semantics at the S3 boundary. Never forward high-level
directory/segment listing as though it implemented arbitrary string prefixes or
stable, stateless continuation tokens. Bind server-issued cursors to the relevant
namespace and query, and document behavior under concurrent writes; pagination
does not imply a snapshot of an entire bucket.

Bring the established `rest-server` into an early supervised serving path, then
evaluate a native adapter. Conformance includes repository creation, config,
typed lists, API v1/v2 negotiation, object HEAD, ranged GET, POST, and authorized
DELETE. Basic object storage and restic REST protocol compatibility are not the
same thing. Normal backup needs lock removal even when old backup objects are
protected by append-only policy. Pruning/deletion privileges remain separate.

### Storage milestone 2: restart-safe transfers and S3 serving

Required operations: CreateMultipartUpload, UploadPart, CompleteMultipartUpload,
AbortMultipartUpload, ListParts and ListMultipartUploads. Persist upload identity,
receipts and completion state; handle lost acknowledgements and uncertain
completion. A streaming writer that works until the process exits is **not**
restart-resumable multipart.

`object_store::multipart::MultipartStore` exposes create/part/complete/abort with
explicit IDs, but does not itself provide ListParts or ListMultipartUploads.
Neither candidate is therefore selected as a complete milestone-2 solution.
Investigate provider-specific extensions or the AWS SDK for these gaps instead of
reimplementing signing and XML indiscriminately.

A server additionally needs SigV4 verification, canonical request handling,
HTTP/XML errors, bucket probes, ranges, conditionals, limits and addressing rules.
Validate signatures before internal path remapping changes signed request data.
Do not confuse an SDK's outbound signing with inbound verification.

### Storage milestone 3: authenticated peer capabilities

Advertise separately:

- Client access to a backend, versus an incoming protocol endpoint.
- Software support, current availability, caller permission and limits.
- Rebsync source/sink/hop roles and the supported protocol/profile versions.
- Receipt, local durability, verification and upstream replication state.

Do not serialize a dependency's entire capability structure as our permanent peer
protocol. Map verified behavior into our own versioned schema, bind it to enrolled
identity and freshness, and provide minimal anonymous discovery only.

Separate repositories or coordinated consistent replicas are required while
offline. Never merge disconnected writable restic replicas using generic object
directory synchronization. Restic-aware snapshot copy and pack/index/snapshot
ordering remain essential; independently pruning replicas cannot be reconciled by
blindly copying missing files afterward.

## Initial experiment

The probes use real temporary local filesystems and exercise:

1. Object write, full read, metadata and range read.
2. Directory-prefix listing and deletion.
3. Visibility before writer completion and abort cleanup.
4. Publication-time create-if-absent exclusion under competing writers.
5. AWS S3 and R2 client construction with explicit dummy credentials.

No provider requests are made by the probes. Client construction is not evidence
of AWS/R2 authentication, request compatibility or recovery. Downloads of Rust
dependencies during the build are distinct from storage-provider I/O.

`object_store` uses `with_fsync(true)` explicitly. OpenDAL uses a staging directory
on the same filesystem through `atomic_write_dir`; default direct writes are not
treated as atomic object publication. Its competing-writer experiment opens two
conditional writers before either publishes, then closes them in sequence. This
tests the publication boundary rather than merely rejecting a write after an
object is already visible.

Results are recorded as JSON under
[`evaluations/storage/results`](../evaluations/storage/results). Each result is
bound to the probe source, manifest and lockfile by SHA-256 and records the
compiler. An unexpected semantic observation is a finding, not an assertion that
the backend meets Rebsync's contract. Execution failures stop the runner.

### Findings and recommendation

Source review identifies important issues to verify with the local probes:

- `object_store` local durability is opt-in. Its high-level prefix listing has
  segment semantics, and its lower-level multipart interface does not fill every
  milestone-2 operation.
- In the inspected OpenDAL FS atomic-write path, create-if-absent checks occur at
  writer creation while publication uses rename. A competing-writer probe is
  required before treating the advertised flag as publication-time exclusion.
  File `sync_all` alone is not proof of parent-directory crash durability.
- Neither library supplies server authentication, a restic server, peer discovery
  or safe offline replication automatically.

**Provisional direction:** prefer `object_store` as the first FS/S3-focused
candidate behind a narrow Rebsync-owned interface if its semantic probes pass.
Keep OpenDAL on the shortlist for broader SFTP/WebDAV/consumer-cloud integration,
but do not silently weaken atomicity or durability to gain transport breadth.
Do not adopt both abstractions into production at this stage.

This is not a performance ranking. Shared build caches, different features and
the absence of real cloud tests do not support claims about comparative speed,
RAM use, binary size, availability or provider reliability.

## Still required before production adoption

- Review recorded observations and resolve failed atomicity/durability gates.
- Test conditional writes and pagination against a disposable local S3 service,
  then real AWS S3 and R2 buckets with dedicated credentials and cost limits.
- Exercise interruption, process restart, missing parts, aborted uploads and lost
  completion responses; implement missing low-level APIs explicitly.
- Run real restic backup/check/restore and lock-lifecycle tests against serving
  adapters, with append-only and administrative roles separated.
- Validate filesystem publication and deletion durability under crash injection;
  do not claim a power-loss test from a normal successful write.
- Test namespace escapes, symlinks, concurrent clients, full disks, quotas,
  authentication failures and capability downgrade attempts.
- Check Android/Termux target and TLS support, feature-minimized build footprint,
  dependency advisories and licenses before enabling on a phone.

## Sources

- [object_store 0.14.2](https://docs.rs/object_store/0.14.2/object_store/)
- [ObjectStore contract](https://docs.rs/object_store/0.14.2/object_store/trait.ObjectStore.html)
- [LocalFileSystem durability](https://docs.rs/object_store/0.14.2/object_store/local/struct.LocalFileSystem.html#method.with_fsync)
- [MultipartStore](https://docs.rs/object_store/0.14.2/object_store/multipart/trait.MultipartStore.html)
- [PaginatedListStore](https://docs.rs/object_store/0.14.2/object_store/list/trait.PaginatedListStore.html)
- [Apache OpenDAL 0.59.5 package](https://crates.io/crates/opendal/0.59.5)
- [OpenDAL capability source](https://docs.rs/crate/opendal-core/0.59.5/source/src/types/capability.rs)
- [OpenDAL filesystem writer source](https://docs.rs/crate/opendal-service-fs/0.59.5/source/src/writer.rs)
- [R2 S3 API compatibility](https://developers.cloudflare.com/r2/api/s3/api/)
- [Restic REST API and repository ordering](https://restic.readthedocs.io/en/stable/100_references.html)
- [rest-server](https://github.com/restic/rest-server)
