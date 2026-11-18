#!/usr/bin/env bash
# Rebeqah Android release, independent of any CI system.
#
# The same steps run on GitHub Actions, a self-hosted runner, a laptop or
# Chromebook, or another CI (e.g. Cloudflare) later. CI files only call this.
#
#   scripts/release-android.sh doctor          check everything, list every problem with its fix
#   scripts/release-android.sh sdk-packages    print the sdkmanager package list (single source of truth)
#   scripts/release-android.sh install-sdk     install those packages with sdkmanager
#   scripts/release-android.sh keystore-from-env   decode RBQ_KEYSTORE_B64 into a private temp file; prints its path
#   scripts/release-android.sh build           doctor, then the signed universal release APK
#   scripts/release-android.sh collect         verify the APK and write dist/ (prepare_android_release.py)
#   scripts/release-android.sh sign-inventory  Sigstore-sign dist/release.json when an OIDC identity exists
#   scripts/release-android.sh publish         create the GitHub candidate release from dist/ (needs gh + GH_TOKEN)
#   scripts/release-android.sh all [--publish] doctor, build, collect, sign-inventory [, publish]
#
# Inputs (environment):
#   RELEASE_TAG            vX.Y.Z; defaults to GITHUB_REF_NAME or the tag exactly at HEAD
#   ANDROID_HOME           Android SDK (falls back to ANDROID_SDK_ROOT, ~/Android/Sdk, ~/.local/android-sdk)
#   RBQ_STORE_FILE, RBQ_STORE_PASSWORD, RBQ_KEY_PASSWORD, RBQ_KEY_ALIAS (default rbq)
#     or RBQ_KEYSTORE_PROPERTIES naming a properties file (storeFile, storePassword, keyAlias, keyPassword)
#   RBQ_DIST               output directory (default dist)
#   RBQ_REQUIRE_SIGSTORE=1 fail instead of skipping when no Sigstore identity is available
#   RBQ_SKIP_TESTS=1       skip the logic/metadata tests in doctor (not recommended)
set -uo pipefail

# --- toolchain: the one place these versions live -------------------------
NDK_VERSION=27.2.12479018
BUILD_TOOLS=37.0.0
PLATFORM=android-37.0
RUST_TARGETS=(aarch64-linux-android armv7-linux-androideabi x86_64-linux-android)
TAURI_TARGETS=(aarch64 armv7 x86_64)
MIN_JAVA=17
MIN_NODE=18
MIN_FREE_GB=12

ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
APP="$ROOT/apps/rebsync-app"
APK_REL="src-tauri/gen/android/app/build/outputs/apk/universal/release/app-universal-release.apk"
DIST=${RBQ_DIST:-dist}
case "$DIST" in /*) ;; *) DIST="$ROOT/$DIST" ;; esac

# --- reporting: one line per problem, annotated on GitHub -----------------
problems=0
note() { echo "release-android: $*" >&2; }
problem() { # problem STEP "what is wrong" "how to fix it"
  problems=$((problems + 1))
  if [ -n "${GITHUB_ACTIONS:-}" ]; then
    echo "::error title=release-android $1::$2 — fix: $3"
  fi
  printf '  ✗ %s: %s\n      fix: %s\n' "$1" "$2" "$3" >&2
}
ok() { printf '  ✓ %s\n' "$*" >&2; }
die() { # die STEP "what" "fix"
  problem "$@"
  exit 1
}

# --- environment discovery -------------------------------------------------
sdk_root() {
  for candidate in "${ANDROID_HOME:-}" "${ANDROID_SDK_ROOT:-}" "$HOME/Android/Sdk" "$HOME/.local/android-sdk"; do
    if [ -n "$candidate" ] && [ -d "$candidate" ]; then
      echo "$candidate"
      return 0
    fi
  done
  return 1
}

json_get() { # json_get FILE KEY
  python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))[sys.argv[2]])' "$1" "$2"
}

app_version() { json_get "$APP/src-tauri/tauri.conf.json" version; }
pinned_cert() { json_get "$ROOT/release/android-signing.json" certificateSha256; }

release_tag() {
  if [ -n "${RELEASE_TAG:-}" ]; then echo "$RELEASE_TAG"; return; fi
  if [ "${GITHUB_REF_TYPE:-}" = tag ] && [ -n "${GITHUB_REF_NAME:-}" ]; then echo "$GITHUB_REF_NAME"; return; fi
  git -C "$ROOT" describe --tags --exact-match HEAD 2>/dev/null || true
}

# Resolve keystore inputs from RBQ_KEYSTORE_PROPERTIES / gen/android/keystore.properties
# into RBQ_STORE_FILE/RBQ_STORE_PASSWORD/RBQ_KEY_ALIAS, without printing secrets.
load_keystore() {
  local props=${RBQ_KEYSTORE_PROPERTIES:-}
  if [ -z "${RBQ_STORE_FILE:-}" ] && [ -z "$props" ] && [ -f "$APP/src-tauri/gen/android/keystore.properties" ]; then
    props="$APP/src-tauri/gen/android/keystore.properties"
  fi
  if [ -z "${RBQ_STORE_FILE:-}" ] && [ -n "$props" ] && [ -f "$props" ]; then
    RBQ_STORE_FILE=$(sed -n 's/^storeFile=//p' "$props")
    RBQ_STORE_PASSWORD=$(sed -n 's/^storePassword=//p' "$props")
    RBQ_KEY_ALIAS=$(sed -n 's/^keyAlias=//p' "$props")
    RBQ_KEY_PASSWORD=$(sed -n 's/^keyPassword=//p' "$props")
    export RBQ_STORE_FILE RBQ_STORE_PASSWORD RBQ_KEY_ALIAS RBQ_KEY_PASSWORD
  fi
  RBQ_KEY_ALIAS=${RBQ_KEY_ALIAS:-rbq}
  export RBQ_KEY_ALIAS
}

major() { sed -E 's/[^0-9]*([0-9]+).*/\1/' <<<"$1"; }

# --- doctor ----------------------------------------------------------------
doctor() {
  problems=0
  echo "release-android doctor ($(uname -sm))" >&2

  # Tag, version and tree.
  local version tag
  version=$(app_version 2>/dev/null) || die version "cannot read apps/rebsync-app/src-tauri/tauri.conf.json" "run from a rebsync checkout"
  tag=$(release_tag)
  if [ -z "$tag" ]; then
    problem tag "no release tag at HEAD (app version is $version)" "git tag -a v$version -m 'Rebeqah $version' && git checkout v$version, or set RELEASE_TAG=v$version"
  elif [ "$tag" != "v$version" ]; then
    problem tag "tag $tag does not match app version $version" "bump tauri.conf.json, src-tauri/Cargo.toml, package.json and its lock to ${tag#v}, or tag v$version"
  elif [ "$(git -C "$ROOT" rev-parse HEAD 2>/dev/null)" != "$(git -C "$ROOT" rev-parse "refs/tags/$tag^{commit}" 2>/dev/null)" ]; then
    problem tag "HEAD is not the commit tagged $tag" "git checkout $tag"
  else
    ok "tag $tag matches app version and HEAD"
  fi
  if [ -n "$(git -C "$ROOT" status --porcelain --untracked-files=no 2>/dev/null)" ]; then
    problem tree "tracked files have uncommitted changes" "commit or stash them; releases are built from the exact tag"
  else
    ok "clean working tree"
  fi

  # Tools.
  local v
  if command -v python3 >/dev/null && python3 -c 'import sys; sys.exit(sys.version_info < (3, 11))'; then
    ok "python3 $(python3 -c 'import platform; print(platform.python_version())')"
  else
    problem python "python3 3.11+ is required (hashlib.file_digest in prepare_android_release.py)" "install Python 3.11+ (actions/setup-python@v5 with 3.12 on GitHub)"
  fi
  if command -v java >/dev/null; then
    # Some environments print "Picked up JAVA_TOOL_OPTIONS" first; use the version line.
    v=$(java -version 2>&1 | grep -m1 ' version ')
    if [ "$(major "$(sed -E 's/.*version "([0-9]+).*/\1/' <<<"$v")")" -ge "$MIN_JAVA" ] 2>/dev/null; then ok "java: $v"; else problem java "JDK $MIN_JAVA+ required, found: $v" "install JDK 21 and set JAVA_HOME"; fi
  else
    problem java "java not found" "install JDK 21 (temurin) and put it on PATH"
  fi
  if command -v keytool >/dev/null; then :; else problem keytool "keytool not found (ships with the JDK)" "install a full JDK, not a JRE"; fi
  if command -v node >/dev/null && [ "$(major "$(node --version)")" -ge "$MIN_NODE" ]; then ok "node $(node --version)"; else problem node "Node $MIN_NODE+ required" "install Node 22 (actions/setup-node@v4 on GitHub)"; fi
  command -v npm >/dev/null || problem npm "npm not found" "install Node 22, which includes npm"
  if command -v cargo >/dev/null; then ok "$(cargo --version)"; else problem cargo "cargo not found" "install Rust via rustup"; fi
  if command -v rustup >/dev/null; then
    local installed missing=()
    installed=$(rustup target list --installed 2>/dev/null)
    for t in "${RUST_TARGETS[@]}"; do grep -qx "$t" <<<"$installed" || missing+=("$t"); done
    if [ ${#missing[@]} -eq 0 ]; then ok "rust android targets"; else problem rust-targets "missing Rust targets: ${missing[*]}" "rustup target add ${missing[*]}"; fi
  else
    note "rustup not found; cannot check Rust targets (${RUST_TARGETS[*]})"
  fi

  # Android SDK.
  local sdk
  if sdk=$(sdk_root); then
    export ANDROID_HOME="$sdk"
    ok "Android SDK at $sdk"
    [ -f "$sdk/ndk/$NDK_VERSION/source.properties" ] && ok "NDK $NDK_VERSION" \
      || problem ndk "NDK $NDK_VERSION missing at $sdk/ndk/$NDK_VERSION" "scripts/release-android.sh install-sdk (or sdkmanager 'ndk;$NDK_VERSION')"
    [ -d "$sdk/platforms/$PLATFORM" ] && ok "platform $PLATFORM" \
      || problem platform "SDK platform $PLATFORM missing" "scripts/release-android.sh install-sdk"
    if [ -x "$sdk/build-tools/$BUILD_TOOLS/apksigner" ] && [ -x "$sdk/build-tools/$BUILD_TOOLS/aapt" ]; then ok "build-tools $BUILD_TOOLS"
    else problem build-tools "build-tools $BUILD_TOOLS (apksigner, aapt) missing" "scripts/release-android.sh install-sdk"; fi
  else
    problem sdk "no Android SDK found (ANDROID_HOME, ANDROID_SDK_ROOT, ~/Android/Sdk, ~/.local/android-sdk)" "install the Android command-line tools and set ANDROID_HOME"
  fi

  # Signing key: catch a wrong key before a long build.
  load_keystore
  if [ -z "${RBQ_STORE_FILE:-}" ]; then
    problem keystore "no signing keystore configured" "set RBQ_STORE_FILE + RBQ_STORE_PASSWORD (+ RBQ_KEY_PASSWORD, RBQ_KEY_ALIAS), or RBQ_KEYSTORE_PROPERTIES; in CI decode RBQ_KEYSTORE_B64 with 'keystore-from-env'"
  elif [ ! -r "$RBQ_STORE_FILE" ]; then
    problem keystore "keystore file is not readable: $RBQ_STORE_FILE" "check the path; in CI the RBQ_KEYSTORE_B64 secret may be empty or truncated"
  elif [ -z "${RBQ_STORE_PASSWORD:-}" ]; then
    problem keystore "RBQ_STORE_PASSWORD is empty" "set the store password (CI secret RBQ_STORE_PASSWORD)"
  elif command -v keytool >/dev/null; then
    local listing actual expected
    if listing=$(keytool -list -v -keystore "$RBQ_STORE_FILE" -alias "$RBQ_KEY_ALIAS" -storepass:env RBQ_STORE_PASSWORD 2>&1); then
      actual=$(sed -n 's/^[[:space:]]*SHA256: //p' <<<"$listing" | head -1 | tr -d ':' | tr 'A-F' 'a-f')
      expected=$(pinned_cert)
      if [ "$actual" = "$expected" ]; then ok "keystore alias '$RBQ_KEY_ALIAS' matches the pinned certificate"
      else problem keystore "alias '$RBQ_KEY_ALIAS' certificate ${actual:0:16}… is not the pinned release certificate ${expected:0:16}…" "use the Rebeqah release keystore (release/android-signing.json); a different key cannot update installed apps"; fi
    else
      problem keystore "keytool could not open alias '$RBQ_KEY_ALIAS' (wrong password, alias or file)" "check RBQ_STORE_PASSWORD and RBQ_KEY_ALIAS; list aliases with: keytool -list -keystore FILE"
    fi
  fi

  # Disk.
  local free_gb
  free_gb=$(df -Pk "$ROOT" | awk 'NR==2 {print int($4/1024/1024)}')
  if [ "${free_gb:-0}" -ge "$MIN_FREE_GB" ]; then ok "${free_gb} GB free"
  else problem disk "only ${free_gb} GB free; three-ABI release builds need about $MIN_FREE_GB GB" "free space (cargo clean in old checkouts, remove stale Gradle/Tauri target dirs)"; fi

  if [ "$problems" -gt 0 ]; then
    note "$problems problem(s); nothing was built"
    return 1
  fi
  note "ready"
}

# --- steps -----------------------------------------------------------------
sdk_packages() { printf '%s\n' "platforms;$PLATFORM" "build-tools;$BUILD_TOOLS" "ndk;$NDK_VERSION"; }

install_sdk() {
  local sdk manager
  sdk=$(sdk_root) || die sdk "no Android SDK found" "install the Android command-line tools and set ANDROID_HOME"
  manager="$sdk/cmdline-tools/latest/bin/sdkmanager"
  [ -x "$manager" ] || die sdkmanager "sdkmanager not found at $manager" "install 'cmdline-tools;latest' into $sdk"
  yes 2>/dev/null | "$manager" --licenses >/dev/null || true
  mapfile -t packages < <(sdk_packages)
  "$manager" "${packages[@]}" >/dev/null || die sdkmanager "sdkmanager failed to install: ${packages[*]}" "rerun; check network access to dl.google.com"
  ok "installed ${packages[*]}"
}

keystore_from_env() {
  [ -n "${RBQ_KEYSTORE_B64:-}" ] || die keystore "RBQ_KEYSTORE_B64 is empty" "add the repository/environment secret RBQ_KEYSTORE_B64 (base64 -w0 rbq-release.jks)"
  local dir file
  dir=${RUNNER_TEMP:-${TMPDIR:-/tmp}}
  file=$(umask 077; mktemp "$dir/rbq-release.XXXXXX.jks")
  printf '%s' "$RBQ_KEYSTORE_B64" | base64 -d >"$file" 2>/dev/null \
    || { rm -f "$file"; die keystore "RBQ_KEYSTORE_B64 is not valid base64" "re-create it with: base64 -w0 rbq-release.jks"; }
  echo "$file"
}

build() {
  doctor || exit 1
  export NDK_HOME="$ANDROID_HOME/ndk/$NDK_VERSION"
  local args=()
  for t in "${TAURI_TARGETS[@]}"; do args+=(--target "$t"); done
  if [ -z "${RBQ_SKIP_TESTS:-}" ]; then
    note "tests: app logic and release metadata"
    cargo test --quiet --manifest-path "$APP/logic-tests/Cargo.toml" \
      || die tests "app logic tests failed" "run: cargo test --manifest-path apps/rebsync-app/logic-tests/Cargo.toml"
    python3 "$ROOT/scripts/test_android_release.py" \
      || die tests "release metadata tests failed" "run: python3 scripts/test_android_release.py"
  fi
  (cd "$APP" && npm ci --no-audit --no-fund) || die npm "npm ci failed in apps/rebsync-app" "check network access to registry.npmjs.org and package-lock.json"
  note "building universal release APK (${TAURI_TARGETS[*]}); this takes a while"
  (cd "$APP" && npx tauri android build --apk "${args[@]}") \
    || die build "tauri android build failed (see the Gradle/Cargo output above)" "rerun 'doctor'; if it passes, the error above is in the app build itself"
  [ -f "$APP/$APK_REL" ] || die build "build finished but $APK_REL is missing (unsigned?)" "the keystore was not applied: check RBQ_STORE_FILE/RBQ_KEYSTORE_PROPERTIES"
  ok "built $APK_REL"
}

collect() {
  local sdk tag
  sdk=$(sdk_root) || die sdk "no Android SDK found" "set ANDROID_HOME"
  tag=$(release_tag)
  [ -f "$APP/$APK_REL" ] || die collect "no release APK at $APK_REL" "run 'build' first"
  [ ! -e "$DIST" ] || die collect "$DIST already exists" "move it away; releases are never overwritten"
  RELEASE_TAG="$tag" python3 "$ROOT/scripts/prepare_android_release.py" --apk "$APP/$APK_REL" --dist "$DIST" \
    --apksigner "$sdk/build-tools/$BUILD_TOOLS/apksigner" --aapt "$sdk/build-tools/$BUILD_TOOLS/aapt" \
    ${RBQ_OPENPGP_SIGN:+--openpgp-sign} \
    || die collect "the APK failed release verification (message above)" "wrong certificate, version, debug build or missing ABI; fix the cause and rebuild"
  ok "verified inventory in $DIST"
}

sign_inventory() {
  [ -f "$DIST/release.json" ] || die sign "no $DIST/release.json" "run 'collect' first"
  if [ -n "${ACTIONS_ID_TOKEN_REQUEST_URL:-}" ] && command -v cosign >/dev/null; then
    cosign sign-blob --yes --bundle "$DIST/release.sigstore.json" "$DIST/release.json" >/dev/null \
      || die sign "cosign could not sign release.json" "the workflow needs 'permissions: id-token: write'"
    ok "Sigstore bundle written (CI identity bound to this tag)"
  elif [ -n "${RBQ_REQUIRE_SIGSTORE:-}" ]; then
    die sign "no Sigstore OIDC identity here (RBQ_REQUIRE_SIGSTORE=1)" "run in GitHub Actions with id-token: write, or unset RBQ_REQUIRE_SIGSTORE"
  else
    note "no Sigstore OIDC identity: inventory NOT Sigstore-signed. The www.ragbaz R2 publisher will refuse it until a CI run signs the same tag."
  fi
}

publish() {
  local tag
  tag=$(release_tag)
  [ -d "$DIST" ] || die publish "no $DIST" "run 'collect' first"
  command -v gh >/dev/null || die publish "gh CLI not found" "install GitHub CLI, or upload $DIST/* to the release by hand"
  [ -n "${GH_TOKEN:-${GITHUB_TOKEN:-}}" ] || gh auth status >/dev/null 2>&1 || die publish "gh is not authenticated" "set GH_TOKEN or run 'gh auth login'"
  if gh release view "$tag" >/dev/null 2>&1; then die publish "release $tag already exists" "releases are immutable; bump the version and tag a new one"; fi
  gh release create "$tag" "$DIST"/* --prerelease \
    --title "RAGBAZ Rebeqah ${tag#v} (Android candidate)" \
    --notes "Signed universal APK (arm64, armv7, x86_64; Android 7+). Candidate: installation on a physical device has not been verified. See android.json for the package/versionCode/signing identity and release.json (plus release.sigstore.json when CI-signed) for verification." \
    || die publish "gh release create failed" "check the token's contents:write permission; the tag must exist on GitHub"
  ok "published release $tag"
}

case "${1:-}" in
  doctor) doctor ;;
  sdk-packages) sdk_packages ;;
  install-sdk) install_sdk ;;
  keystore-from-env) keystore_from_env ;;
  build) build ;;
  collect) collect ;;
  sign-inventory) sign_inventory ;;
  publish) publish ;;
  all)
    build && collect && sign_inventory || exit 1
    if [ "${2:-}" = --publish ]; then publish; else note "built and verified; run 'publish' to create the release"; fi
    ;;
  *) sed -n '2,25p' "$0" >&2; exit 2 ;;
esac
