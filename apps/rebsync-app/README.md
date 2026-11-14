# RAGBAZ Rebekah (rebsync app)

Rebekah is the Android companion for rebsync. It keeps a rebsync object
store on the phone, on internal storage, an SD card or a USB drive. It can
share that store with peers on a network you trust, and it shows who is
connected and how much space is left.

It is a Tauri 2 app. It is not part of the production Cargo workspace.

## What it does

- **Splash.** A native Android 12+ splash (`core-splashscreen`) shows the
  monogram, with a *RAGBAZ Rebekah* wordmark on API 31+. It hands off to a
  matching in-app splash.
- **Sharing and connection strings.** A switch starts the experimental
  `rebsync-peer/0` endpoint (port 8787, or a free port if 8787 is taken).
  - The endpoint offers read, list and create-if-absent. It has no overwrite
    and no delete.
  - Every network interface gets a URL, a QR code and a copyable connection
    string: `rebsync+http://ADDRESS:PORT/v1?token=…`. Interfaces are Wi-Fi,
    hotspot, USB tethering, Ethernet and VPN; mobile data is listed last.
  - Requests need `Authorization: Bearer TOKEN`, or `?token=` in the URL. The
    token is 192 bits from the system RNG, compared in constant time and
    rotatable from the app.
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
- **Mneme snapshots.** If the store holds snapshots published by
  `rebsync mneme`, the app shows their count and storage use.

## Limits, stated plainly

- **Uninstall deletes the data.** Android deletes the app's folders when
  Rebekah is uninstalled, including on SD cards and USB drives. Keep another
  copy of anything that matters.
- **The connection is not encrypted.** Sharing uses plain HTTP, so anyone on
  the same network can read the token. Use networks you control, a hotspot or
  USB tethering.
- **Removable media has fewer guarantees.** FAT and exFAT have no hard links
  and no Unix permissions, so the core falls back to check-then-rename. That is
  safe with one writer, and Rebekah is the only writer. The app shows a warning
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
export REBEKAH_KEYSTORE_PROPERTIES=/private/path/keystore.properties
npx tauri android build --apk --target aarch64 --target armv7 --target x86_64
```

`keystore.properties` contains `storeFile`, `storePassword`, `keyAlias` and
`keyPassword`. Gradle can also read `src-tauri/gen/android/keystore.properties`,
which is gitignored, or the variables `REBEKAH_STORE_FILE`,
`REBEKAH_STORE_PASSWORD`, `REBEKAH_KEY_ALIAS` and `REBEKAH_KEY_PASSWORD` for CI.
Never commit a keystore. Without one, the release APK is unsigned.

CI release: push a tag `rebekah-vX.Y.Z` (after bumping `version` in
`src-tauri/tauri.conf.json`). `.github/workflows/rebekah-android.yml` then builds,
signs, verifies and publishes a pre-release with the APK and its SHA-256. It needs
the repository secrets `REBEKAH_KEYSTORE_B64`, `REBEKAH_STORE_PASSWORD`,
`REBEKAH_KEY_PASSWORD` and `REBEKAH_KEY_ALIAS`. Use the same keystore that signed
0.2.0 (certificate SHA-256 `60:24:5D:…:F9:A9`), or Android will refuse to update
an existing install.

The app logic (peer endpoint, volumes, move) is tested without Tauri or GTK:

```bash
cargo test --manifest-path logic-tests/Cargo.toml
```

## Peer API (`rebsync-peer/0`, experimental)

| Request | Result |
|---|---|
| `GET /v1/health` | No auth needed; `{"ok":true,...}` |
| `GET /v1/status` | Protocol, version, storage capabilities, whether writes are paused |
| `GET /v1/objects?prefix=&limit=` | Keys and sizes; at most 10 000 |
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
