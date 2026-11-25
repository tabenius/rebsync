# Android signing and release ceremony

## Separate the identities

`release/android-signing.json` pins the **APK** certificate for
`com.tabenius.rebeqah`. The F-Droid repository key signs an index, the OpenPGP
release key signs checksums, and CI's Sigstore identity signs the release
inventory. None substitutes for the APK key. Never upload an F-Droid/debug/other
app keystore as `RBQ_KEYSTORE_B64`, and never change the certificate pin just to
make a failing build pass: that breaks Android update identity.

## Before enrolling or changing CI secrets

Recover the existing approved APK keystore and its two passwords from the
owner's private custody. Keep the original and an encrypted independent recovery
copy; test recovery by comparing the public certificate fingerprint and proving
private-key access. This document does not assert a backup already exists.
Do not generate a replacement key, export a private key, or rotate identity as
part of routine release troubleshooting.

Supply `RBQ_STORE_PASSWORD`, `RBQ_KEY_PASSWORD`, and optionally `RBQ_KEY_ALIAS`
through a private environment/secret manager, not command-line password arguments,
history, logs, tracked properties files or issue comments. With a mode-0600
keystore, run:

```sh
python3 scripts/check_android_signing.py --keystore /private/path/rebeqah-release.jks
```

The check exports only the public certificate, compares its exact SHA-256 pin,
requires a private-key entry, and generates/discards a public CSR to prove key
password access. It does not change the keystore. Keytool raw diagnostics and
passwords are never printed. Only after this passes should the four repository
secrets be enrolled from the **same** checked keystore and credentials. Use
`gh secret set` through stdin or GitHub's secret UI, never `--body PASSWORD`.
The script does not upload secrets automatically.

## Before every expensive release build

Run `Rebeqah Android release` with `signing_preflight_only=true` at the reviewed
workflow ref. This tests actual CI secrets without the Android toolchain, APK
build, artifact upload or publication. The normal release workflow also performs
the same check before installing build toolchains. It writes a new runner-only
mode-0600 keystore and always removes it, including on failure.

Then dispatch the ordinary workflow on the immutable app version tag. The final
build output is explicitly signed with `apksigner` using that already-checked
key, rather than relying on implicit Gradle/Tauri signing behavior. Package,
version, non-debug state and universal ABI shape are checked **before** applying
the approved key. Existing output files are never overwritten; passwords are
passed to apksigner by environment-variable names, not their values.
The source
commit, tag, app version, package and APK certificate must all agree. The final
APK is verified again, independently of the preflight, before inventory,
Sigstore signing and candidate publication. Failed tags are not moved to smuggle
in workflow changes: use a new reviewed patch tag if the release source changes.
A secrets-only repair can retry the original immutable tag.

## If identity differs

Stop. Compare the public expected/observed fingerprints. Restore the approved
keystore/alias from custody; do not replace the pin with the observed digest or
reuse another application's key. If the original private key is unavailable,
identity recovery or an Android-supported key-rotation plan needs an explicit
owner decision. A new key with the old package name is not an ordinary update.

Signed/buildable is not device-validated or promoted: retain candidate status
until physical-device install/update checks and registry gates actually pass.
