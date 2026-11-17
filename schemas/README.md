# Public component contract snapshot

`ragbaz.component.schema.json` is an unmodified copy downloaded from
<https://ragbaz.cc/schemas/ragbaz.component.schema.json> on 2026-11-18. Its bytes
were checked against ragbaz-common commit
`f6f44e27ae7051968897080faf820c8ad6475147` and the public website copy at
www.ragbaz commit `6ece4a1fc804f048f1e67c91b0f48170ab4d9ccc`.

SHA-256: `ef47a5a0614738329587fce87dcf01a3684bc02e08f6df3e9ea6609c154f0da9`.

The snapshot is test input, not a Rebsync-owned schema fork. Update it explicitly
from the public endpoint when adopting an upstream change; review the diff and
update provenance and `SHA256SUMS` together. CI uses this snapshot offline rather
than requesting access to the private upstream repository or trusting a mutable
network response on every build. No private upstream implementation is included.
