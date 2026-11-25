# Rebekah connector pairing

A Rebekah connector grant is **not** an object-storage grant. It uses the same
RBQ nonce, matching-code, fresh-passkey, claim-once and credential-store ceremony,
but requests exactly `connector`. Mixing that scope with repository scopes is
refused on both sides.

```sh
# Choose a store and its protection explicitly. On a desktop use secret-service;
# none is an explicit headless choice: private files, not encryption at rest.
export RBQ_CREDENTIAL_STORE=/path/to/private/credentials
export RBQ_CREDENTIAL_SEAL=none
rbq dash pair --label Rebekah --scope connector --no-wait
rbq dash wait PAIRING_ID
```

In Dash, compare the matching code, select an **existing** Rebekah instance you
have connector authority on, then approve with your passkey. No instance is
created and no existing manual push key is rotated. The connector is bound to
that instance, the approving account's live membership, and the credential's
expiry/revocation state.

The gateway delegates authenticated operations to RBQ; it never exports the
stored token. Only these operations are available:

```sh
rbq dash connector --credential KEY_ID --instance INSTANCE_ID pending
rbq dash connector --credential KEY_ID --instance INSTANCE_ID push < envelope.json
rbq dash connector --credential KEY_ID --instance INSTANCE_ID results < results.json
```

`--dash` pins the expected origin (default `https://dash.ragbaz.cc`). The
expected instance is sent as `X-Rebekah-Instance-Id`; Dash refuses a mismatch
**before** accepting views or returning commands. `--credential auto` selects
only an unexpired connector-only grant for that exact origin, never a repository
grant. If a different instance's grant is selected, the server refuses it.

Output is `{status, body, retry_after}` protocol data. Callers must check status;
HTTP refusal is not success merely because JSON was returned. A 401 durably
disables the credential locally. Requests are bounded to512KiB, responses to64KiB;
only pending/push/results paths are allowed, with verified TLS and no redirects.
No credential appears in argv or normal output. This is not a generic HTTP or
secret-export command.
