# RAGBAZ Rebeqah (rbq app)

Rebeqah is the Android companion for rbq. It keeps a rbq object
store on the phone, on internal storage, an SD card or a USB drive. It can
share that store with peers on a network you trust, and it shows who is
connected and how much space is left.

It is a Tauri 2 app. It is not part of the production Cargo workspace.

## What it does

- **Splash.** A native Android 12+ splash (`core-splashscreen`) shows the
  monogram, with a *RAGBAZ Rebeqah* wordmark on API 31+. It hands off to a
  matching in-app splash.
- **Sharing and connection strings.** A switch starts the experimental
  `rbq-peer/0` endpoint (port 8787, or a free port if 8787 is taken).
  - The endpoint offers read, list and create-if-absent. It has no overwrite
    and no delete.
  - Every network interface gets a URL, a QR code and a copyable connection
    string: `rbq+https://ADDRESS:PORT/v1?peer=ID&token=…`, served over HTTPS
    with the phone's own key, which `peer=` pins (no CA; `curl` users get a
    `--pinnedpubkey` command). Interfaces are Wi-Fi,
    hotspot, USB tethering, Ethernet and VPN; mobile data is listed last.
  - Requests need `Authorization: Bearer TOKEN`, or `?token=` in the URL. The
    token is 192 bits from the system RNG, compared in constant time and
    rotatable from the app.
  - **Encrypted sharing (QUIC).** Alongside HTTPS, the same object store is
    served as `rbq-peer/1` over QUIC on the same port number (UDP). Each
    interface also gets `rbq+quic://ADDRESS:PORT?peer=ID&token=…`, and the QR
    code carries it. `peer=` is this phone's key fingerprint, which the client
    pins: a device presenting another key is refused, and the token never
    crosses the network in clear. The key lives in the app's private storage
    (`quic-identity/`), so the fingerprint survives restarts and token
    rotation. Use `rbq peer status|push|pull` with either string. If QUIC
    cannot start, the app says why and keeps HTTPS running. **Pair a device** shows a one-time code (QR and
    string, 10 minutes, optionally read-only); `rbq peer pair join` on the
    other device redeems it, and from then on that device connects with its
    key alone, no token. Paired devices are listed with Remove (revocation).
    Tailscale and NetBird interfaces are labelled as such. QUIC clients are listed under Connected clients with
    HTTP ones, tagged by how they connected, and the same failure throttle
    applies: after ten wrong tokens in a minute an address cannot connect
    over either.
  - After ten failed attempts in a minute, an address is throttled.
- **Connected clients.** Each peer address shows when it was first and last
  seen, an active marker for the last 60 seconds, and request counts. It also
  shows rejected attempts, bytes in and out, its user agent and its last
  request.
- **Free space.** Space is measured with `statvfs` on every volume the app can
  write to:
  - internal (private);
  - the app folder on shared storage, SD cards and USB drives, which the system
    exposes through `getExternalFilesDirs`;
  - other mounted volumes. These are shown, but they can't be chosen.

  `MainActivity` refreshes the list whenever media is mounted, ejected or
  removed.
- **Move data.** Moves the store to another volume:
  - Every file is copied to a temporary name, fsynced, renamed, re-read and
    compared with the source by SHA-256.
  - The data root switches only after every file verifies.
  - Removing the old copy is an opt-in final step.
  - Peer writes pause during the move.
  - An interrupted move can be resumed. Identical files are kept, and a
    conflicting file is never overwritten.
- **Layer snapshots.** The app shows the count and storage use of Mneme, Frog
  and agenda snapshots, pushed with `rbq peer push` or pulled back with
  `rbq peer pull`.

## Limits, stated plainly

- **Uninstall deletes the data.** Android deletes the app's folders when
  Rebeqah is uninstalled, including on SD cards and USB drives. Keep another
  copy of anything that matters.
- **Check the key on first use.** Both HTTPS and QUIC are encrypted and pinned
  to the phone's key, but the pin is only as good as the channel you copied it
  over: scan the QR code or compare the fingerprint the app shows.
- **Removable media has fewer guarantees.** FAT and exFAT have no hard links
  and no Unix permissions, so the core falls back to check-then-rename. That is
  safe with one writer, and Rebeqah is the only writer. The app shows a warning
  for such volumes. Anyone holding the card can read it, and Mneme snapshots
  contain private transcripts.
- **Some USB drives aren't usable.** Some devices expose USB drives only through
  the system file picker, not as an app folder. Those drives appear as
  "detected", not as targets.
- **Background work is limited.** There is no background service. Sharing runs
  while the app is open.

## Build

You need JDK 21, an Android SDK with platform 37 and build-tools 37, NDK
27.2.12479018, and the Rust Android targets.

```bash
npm ci
export ANDROID_HOME="$HOME/.local/android-sdk"
export NDK_HOME="$ANDROID_HOME/ndk/27.2.12479018"
export JAVA_HOME=/usr/lib/jvm/java-21-openjdk-amd64
npx tauri android build --debug --apk --target aarch64
```

Release, as a universal APK for arm64, armv7 and x86_64:

```bash
export RBQ_KEYSTORE_PROPERTIES=/private/path/keystore.properties
npx tauri android build --apk --target aarch64 --target armv7 --target x86_64
```

`keystore.properties` contains `storeFile`, `storePassword`, `keyAlias` and
`keyPassword`. Gradle can also read `src-tauri/gen/android/keystore.properties`,
which is gitignored, or the variables `RBQ_STORE_FILE`,
`RBQ_STORE_PASSWORD`, `RBQ_KEY_ALIAS` and `RBQ_KEY_PASSWORD` for CI.
Never commit a keystore. Without one, the release APK is unsigned.

CI release: push an immutable tag `vX.Y.Z` (after bumping the app versions in
`src-tauri/tauri.conf.json`, `src-tauri/Cargo.toml`, `package.json` and its lock).
`.github/workflows/rebeqah-android.yml` builds, signs, verifies and publishes a
candidate release with the APK, SHA-256 inventory, Android metadata and an exact
`ragbaz.release/1` manifest signed using tag-bound GitHub Actions Sigstore OIDC.
Manual dispatch also requires that tag ref; releases are never replaced. It needs
the repository secrets `RBQ_KEYSTORE_B64`, `RBQ_STORE_PASSWORD`,
`RBQ_KEY_PASSWORD` and `RBQ_KEY_ALIAS`. Local builds may instead keep the
keystore entirely on the operator's machine. Never export a private GnuPG key or
store its passphrase in CI; optional OpenPGP signing uses the local gpg-agent.

The Rebeqah public signing identity is pinned in `release/android-signing.json` at
the repository root. It is **not compatible** with the previously documented
0.2.0 signing certificate (`60:24:5D:…:F9:A9`) or debug installs. The new APK
certificate SHA-256 is
`B0:93:A2:77:10:D4:E1:73:61:DE:BE:C5:B1:02:0A:AC:11:DE:FC:E0:30:2D:7A:5D:38:26:31:06:8C:E0:EF:4A`.
Existing installations signed with another key cannot be upgraded in place.
**Back up the object store before uninstalling**: uninstalling deletes app data.

### Verified direct-download inventory

From the repository root, after building the exact committed version tag and
following the [signing ceremony](../../docs/ANDROID-SIGNING.md), explicitly sign
the final APK with `scripts/sign_android_release.py`. Then prepare its inventory:

```bash
RELEASE_TAG=v0.2.7 python3 scripts/prepare_android_release.py \
  --apk /path/to/approved-final-release.apk \
  --dist /path/to/new-release-directory \
  --apksigner "$ANDROID_HOME/build-tools/37.0.0/apksigner" \
  --aapt "$ANDROID_HOME/build-tools/37.0.0/aapt" \
  --openpgp-sign
```

The optional last flag asks gpg-agent to sign `SHA256SUMS`; no passphrase file
or private-key export is used. The owner's existing ASCII-armored public key is
tracked in `release/keys/` and included in every prepared release. Fingerprint:
`266E9D54DD9C99B713C3743CB26A758A8EFD36F5`. This OpenPGP identity is separate
from the Android certificate and from the CI Sigstore identity. A locally
signed inventory alone does not satisfy the website's CI Sigstore gate.

The collector rejects debug builds, incorrect app versions/certificates and
incomplete ABI sets. `android.json` records package ID, versionCode, min/target
SDK, native ABIs, certificate digest, APK digest and source commit. No device
installation is claimed: releases remain candidates until separately tested.
The protected `www.ragbaz` publisher selects `tabenius/rebsync`, product
`rebeqah`, platform `android`, and the same `vX.Y.Z` tag.

### Future F-Droid and other channels

For a lighter-weight URL subscription after the first GitHub release is
published, [Obtainium](https://wiki.obtainium.imranr.dev/sources/#github) supports
adding `https://github.com/tabenius/rebsync` as a GitHub source. Enable
pre-releases to see our candidate channel and filter APK names with
`^rebeqah-.*-universal-release\.apk$`. This is a source configuration recipe,
not a claim that installation/background updates have been tested on a device.
Future apps can use their own source URLs without implementing an F-Droid index.

An APK URL is not a subscribable repository. `www.ragbaz` must additionally
publish a signed F-Droid index with its own stable repository key before we
advertise a single shared subscription URL for Rebeqah and future apps. The
Android inventory above gives a distributor the package/update identity without
coupling it to one download host. Keep versionCode increasing and retain the APK
signing key across direct-download/custom-repository releases. Google Play
onboarding (including its app-signing/upload-key choice) is a separate future
step; do not silently replace the existing Android signing identity. No F-Droid
feed or Play release is published by this workflow today.

The app logic (peer endpoint, volumes, move) is tested without Tauri or GTK:

```bash
cargo test --manifest-path logic-tests/Cargo.toml
```

## Peer API (`rbq-peer/0`, experimental)

| Request | Result |
|---|---|
| `GET /v1/health` | No auth needed; `{"ok":true,...}` |
| `GET /v1/status` | Protocol, version, storage capabilities, whether writes are paused |
| `GET /v1/objects?prefix=&limit=&after=` | Keys and sizes in key order, keys strictly after `after`; at most 10 000 per page; `truncated` signals more (0.2.1+) |
| `GET` or `HEAD /v1/objects/KEY` | Object bytes, or `X-Object-Size` |
| `PUT /v1/objects/KEY` | Create if absent: `201` created, `200` exists, `503` during a move; 64 MiB maximum |

```bash
curl -H "Authorization: Bearer $TOKEN" http://192.168.1.42:8787/v1/status
```

## Generated Android project

`src-tauri/gen/android/` is committed so the build is reproducible. Local
changes:

- In `app/build.gradle.kts`, `rootDirRel` is `../../../../`, so Gradle runs npm
  from this directory.
- Release signing is set up as described above.
- The splash library is added.
- `MainActivity.kt` publishes the volume list.
- There are splash themes and resources.

Re-check these if `tauri android init` regenerates the project.
