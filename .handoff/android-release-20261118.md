# Rebeqah Android release handoff — 2026-11-18

For local agents releasing the Rebeqah APK. Read this before running a
release; it covers what has already been worked out. Format: the RAGBAZ fleet
handoff standard (tabenius/ragbaz-common#19). The machine-readable minimum is in
`.handoff/android-release.mvh.json`. Written by claude (Claude Code cloud
session).

## Resume target

- Repository `tabenius/rebsync`, branch `fix-ndk-home`, tabenius/rebsync#8
  (draft). The CLI release is on `rbq-sync-cli`, tabenius/rebsync#7.
- Release tag `v0.2.3` at `2061e4e`. It was never published.

## Next action

Find the keystore that holds the pinned Rebeqah certificate b093a277 (see "The local keystore"), then merge #8 and release the next version from main.

Queue:
1. Locate the b093a277 keystore on the host where `2061e4e` was made, or the
   repo secret `RBQ_KEYSTORE_B64`. If it is lost, the owner decides on a re-pin.
2. Merge tabenius/rebsync#8. Bump `version` in `tauri.conf.json` (0.2.4) and
   tag it from main.
3. `scripts/release-android.sh doctor`, then `all`, then `publish`; or let CI
   run on the tag.
4. Merge www.ragbaz `feat/rebeqah-release-signing` before promoting to R2.

## Decisions

- v0.2.3 is not released from its tag: its verifier cannot read apksigner 37
  output. The recommendation is the next version (owner to confirm).
- The release logic lives in `scripts/release-android.sh`; CI is a thin
  wrapper. Decided in #8 so local, GitHub and future Cloudflare runners
  behave the same.
- The pin in `release/android-signing.json` is only changed by a reviewed,
  owner-approved commit, never to get past an error.

## Blockers

- Which keystore holds b093a277 is unknown. The local `rebekah-release.jks`
  is the old key, 3a111387 (confirmed by the owner 2026-11-18).
- GitHub Actions minutes and artifact storage are exhausted. CI runs may fail
  for reasons that are not the code.

## Where things stand

- `main` is Rebeqah: package `com.tabenius.rebeqah`, app version 0.2.3
  (versionCode 2003), command `rbq`. The pinned release certificate in
  `release/android-signing.json` is SHA-256
  `b093a27710d4e17361debec5b1020aac11defce0302d7a5d382631068ce0ef4a`. A
  different key cannot update installed apps and is refused by
  `prepare_android_release.py`.
- Tag `v0.2.3` is on GitHub at `2061e4e`. Its CI run failed at "Build release
  APK" with `Android NDK invalid`. **No GitHub release exists for v0.2.3**:
  nothing was published or half-published. Cause:
  `NDK_HOME: ${{ env.ANDROID_HOME }}/ndk/…` expands to `/ndk/…`, because
  `${{ env.* }}` cannot see the runner's OS environment. Fixed in
  tabenius/rebsync#8. Every step before it passed, including the keystore
  secret.
- The tag is immutable and points at the broken workflow, so v0.2.3 is built
  and released locally. CI releases work again from the next version tag
  once #8 is merged.
- GitHub Actions minutes and artifact storage were exhausted around this
  date. Expect CI failures that are about GitHub, not about the code.

## v0.2.3 cannot pass its own verifier — read this first

`scripts/prepare_android_release.py` *at tag v0.2.3* only understands the
old apksigner line `Signer #1 certificate SHA-256 digest:`. build-tools
37.0.0 prints `V2 Signer: certificate SHA-256 digest:` (or `V3.0 Signer:`),
and for minSdk 24 it never adds a v1 signature, so re-signing does not
help. The tag's verifier finds no signer and refuses a **correctly signed**
APK with "APK signing certificate differs from the pinned release
identity". The message is misleading. Do not chase the keystore, and never edit
`android-signing.json` over it.

Confirmed on 2026-11-18 by a full local run with a throwaway key: the APK was
signed with exactly the pinned test cert and the tag's verifier still
refused it. Fixed in tabenius/rebsync#8. The parser accepts both formats,
counts one signer once across schemes, and names the digest it found.
`release-android.sh build` now also checks the signer straight after
Gradle (`check-signer`).

The verifier reads the repo it lives in and refuses tracked changes, so you
cannot drop the fixed copy into the tag checkout. Options, for the owner to
choose:
1. **Recommended:** merge #8 and release the next version from main (bump
   `version` in `tauri.conf.json`; v0.2.3 was never published, so nothing
   is lost). This also restores the CI path.
2. Publish v0.2.3 by hand without `prepare_android_release.py`, as the
   SIGN-AND-RELEASE.md route. This skips the inventory guard. Not recommended.

## The local keystore

- **Confirmed by the owner 2026-11-18:** `~/.config/rebekah-signing/rebekah-release.jks`
  holds one entry, alias `rebekah`, certificate `3A:11:13:87…:84:A6`. That is
  the key pinned at `8b342f5` for the *old* package `com.tabenius.rebsync`.
  **It is not the Rebeqah release key.** `2061e4e` ("create a new release
  signing identity") pinned `b093a277…` for `com.tabenius.rebeqah`, so a newer
  keystore was made at rename time, about 02:35 on Nov 18. Find it before
  building. List candidates, then check each with `keytool -list -v`; it
  prompts for the password, so do not pass one on the command line:

      find ~ -xdev \( -name '*.jks' -o -name '*.p12' -o -name '*.keystore' \
          -o -name 'keystore.properties' -o -name '*keystore*.txt' \) \
          -newermt 2026-11-18 2>/dev/null
      keytool -list -v -keystore FILE | grep -E 'Alias|SHA256:'

  Also check whether the repo secret `RBQ_KEYSTORE_B64` holds `b093a277…`:
  the next CI tag run prints it in `doctor`/`check-signer`. If the b093 key is
  lost and nothing was ever published under `com.tabenius.rebeqah` (true as of
  this date), the owner may re-pin a new key in a reviewed commit. That is a
  decision for the owner, never a fix made to get past an error.
- Old file name: `~/.config/rebekah-signing/rebekah-release.jks`. The directory
  and file keep the old *Rebekah* name.
- **Verify it is the Rebeqah key before building.** `doctor` compares the
  alias's certificate with the pinned one in seconds:
  - `b093a277…` (match): proceed.
  - `3a111387…`: the pre-rename Rebekah key for `com.tabenius.rebsync`. Wrong
    for this package.
  - `60245d83…`: the even older 0.2.0 test key. Wrong.

  Do not "fix" a mismatch by editing `release/android-signing.json`. Find the
  right key or ask the owner.
- Alias: Gradle and the script default to `rbq`, but the old keystore uses
  `rebekah`. If the keystore uses another
  alias, list the aliases without printing secrets and set `RBQ_KEY_ALIAS`:

      keytool -list -keystore ~/.config/rebekah-signing/rebekah-release.jks

- Never echo, log, commit or pass passwords as command-line arguments. Read
  them into the environment without echo:

      read -rs RBQ_STORE_PASSWORD && export RBQ_STORE_PASSWORD
      read -rs RBQ_KEY_PASSWORD && export RBQ_KEY_PASSWORD

## Release v0.2.3 locally

`scripts/release-android.sh` (tabenius/rebsync#8) holds the whole release.
Until #8 is merged, use it from that branch against the tag checkout. The
script only reads the repository it is run from, so copy it into the tag
checkout or run it from a #8 checkout with the tag checked out.

    git fetch origin --tags && git checkout v0.2.3
    export ANDROID_HOME=~/Android/Sdk          # or wherever the SDK lives
    export RBQ_STORE_FILE=~/.config/rebekah-signing/rebekah-release.jks
    export RBQ_KEY_ALIAS=rbq                   # or what keytool -list shows
    read -rs RBQ_STORE_PASSWORD && export RBQ_STORE_PASSWORD
    read -rs RBQ_KEY_PASSWORD && export RBQ_KEY_PASSWORD
    scripts/release-android.sh doctor          # fix everything it lists first
    scripts/release-android.sh all             # tests, build, verify, dist/
    scripts/release-android.sh publish         # gh release create v0.2.3 (needs gh auth)

- `doctor` lists every problem at once, each with its fix. It checks:
  - the tag against the app version and `HEAD`, and a clean tree;
  - the tools: Python 3.11+, JDK 17+ with keytool, Node 18+, cargo and the
    Rust Android targets;
  - the SDK: platform `android-37.0`, build-tools 37.0.0 and NDK
    27.2.12479018 (`install-sdk` installs exactly these);
  - free disk space (about 12 GB needed);
  - the keystore certificate.
- A local run cannot Sigstore-sign `release.json`, because that needs the
  GitHub OIDC identity. The script says so and continues. The www.ragbaz R2
  publisher requires that signature, so promotion to R2 waits for a CI-signed
  release.
- Local alternative without the script: SIGN-AND-RELEASE.md as sent in the
  session (sign an unsigned APK with `apksigner`, then run
  `prepare_android_release.py`). The script is preferred because it checks
  the key first.

## Known gaps

- The www.ragbaz `publish-signed-release.yml` allowlist on `master` names
  `tabenius/rebekah`, not `tabenius/rebsync`. The fix is commit `f7801a5` on
  branch `feat/rebeqah-release-signing`, not yet merged (checked 2026-11-18).
  Merge it before promoting any Rebeqah release to R2.
- The Gradle daemon can keep a stale lock after a build is interrupted, for
  example by a full disk. Run `./gradlew --stop` in
  `apps/rebsync-app/src-tauri/gen/android` and retry.
- Android release builds for three ABIs need about 12 GB free. `cargo clean`
  in old checkouts frees the most.

## Related, same day

- The `rbq` CLI ships as static Linux x86_64 and aarch64 tarballs, made by
  `scripts/build-cli-release.sh` with no CI (tabenius/rebsync#7). `install.sh`
  installs `rbq`, links the olden name `rebsync`, and refuses a tarball built
  for the wrong CPU.

## Verify

    git fetch origin && git checkout fix-ndk-home
    python3 -m unittest discover -s scripts -p 'test_android_release.py'
    scripts/release-android.sh doctor     # lists every missing tool or key, with fixes

## Do not

- Edit `release/android-signing.json` to match whatever key is at hand.
- Put keystore or key passwords in files, commits, chats or command lines.
  Use `read -rs`. If one was exposed, treat that keystore as compromised for
  any future use.
- Re-sign an APK with v1 enabled to satisfy the old verifier. apksigner 37
  drops v1 for minSdk 24 anyway.

## Refs

- tabenius/rebsync#8 (`5383dbe` NDK_HOME, `4bf1263` release script,
  `1635f54` verifier fix, `c50fc15` keystore finding)
- tabenius/rebsync#7 (rbq CLI tarballs)
- `2061e4e` (rename and new pin), `8b342f5` (old pin 3a111387)
- www.ragbaz `f7801a5` on `feat/rebeqah-release-signing`
