#!/usr/bin/env bash
# Build, sign, verify and (optionally) upload the RAGBAZ package repositories:
#
#   F-Droid  https://ragbaz.cc/fdroid/repo   signed index + Rebeqah APKs
#   APT      https://ragbaz.cc/apt           signed repository + rbq .debs
#
# Run on the owner's machine: the APT repository is signed by the local
# gpg-agent (the private key never leaves it) and the F-Droid index by the
# F-Droid repo key, which is NOT the APK signing key. Nothing is uploaded
# unless --upload is given.
#
#   scripts/publish-repos.sh init-fdroid-key        # once: create the repo key
#   scripts/publish-repos.sh init-apt-key           # once: create an APT archive key
#   scripts/publish-repos.sh build                   # collect, sign, verify -> dist/repos
#   scripts/publish-repos.sh build --upload          # ... then upload to R2
#
# Inputs are every published (non-draft) GitHub release of tabenius/rebsync:
# *.apk and rbq_*.deb assets, each checked against its release's SHA256SUMS.
# Extra local files: RBQ_EXTRA_APKS / RBQ_EXTRA_DEBS (directories).
#
# Environment (defaults in brackets):
#   APT_SIGNING_KEY      [aptOpenpgpFingerprint from release/android-signing.json]
#   APT_KEY_UID          [RAGBAZ APT archive signing <ragbaz@proton.me>]  for init-apt-key
#   APT_KEY_VOUCHED_BY   [unset]  fingerprint of a key that certifies the new APT key
#   FDROID_KEYSTORE      [~/.config/rebeqah-signing/fdroid-repo.jks]
#   FDROID_KEY_ALIAS     [ragbaz-fdroid]
#   FDROID_KEYSTORE_PASS, FDROID_KEY_PASS   [prompted, not echoed]
#   ANDROID_HOME         [~/Android/Sdk]  build-tools for apksigner/aapt
#   R2_BUCKET            [ragbaz-releases]  objects go under repos/
# Needs: gh, gpg, apt-ftparchive (apt-utils), dpkg-deb, keytool, fdroidserver,
# and for --upload: npx wrangler with CLOUDFLARE_API_TOKEN/ACCOUNT_ID.
set -euo pipefail
root=$(cd "$(dirname "$0")/.." && pwd)
here="$root/scripts/repos"
out="${RBQ_REPOS_OUT:-$root/dist/repos}"
repo=tabenius/rebsync
note() { printf '  · %s\n' "$*"; }
ok() { printf '  ✓ %s\n' "$*"; }
die() { printf '  ✗ %s\n' "$1" >&2; [ -n "${2:-}" ] && printf '      fix: %s\n' "$2" >&2; exit 1; }

: "${FDROID_KEYSTORE:=$HOME/.config/rebeqah-signing/fdroid-repo.jks}"
: "${FDROID_KEY_ALIAS:=ragbaz-fdroid}"
: "${ANDROID_HOME:=$HOME/Android/Sdk}"
: "${R2_BUCKET:=ragbaz-releases}"
: "${APT_SIGNING_KEY:=$(python3 -c "import json;print(json.load(open('$root/release/android-signing.json'))['aptOpenpgpFingerprint'])")}"
export FDROID_KEYSTORE FDROID_KEY_ALIAS ANDROID_HOME APT_SIGNING_KEY

ask() { # ask VAR prompt: read a secret without echo unless already set
  [ -n "${!1:-}" ] && return
  read -rsp "$2: " "$1"; echo; export "$1"
}

init_fdroid_key() {
  [ ! -e "$FDROID_KEYSTORE" ] || die "$FDROID_KEYSTORE already exists" "keep it: its fingerprint is what users pinned"
  mkdir -p "$(dirname "$FDROID_KEYSTORE")"; chmod 700 "$(dirname "$FDROID_KEYSTORE")"
  ask FDROID_KEYSTORE_PASS "New F-Droid repo keystore password"
  FDROID_KEY_PASS=$FDROID_KEYSTORE_PASS; export FDROID_KEY_PASS
  keytool -genkeypair -keystore "$FDROID_KEYSTORE" -storetype PKCS12 -alias "$FDROID_KEY_ALIAS" \
    -keyalg RSA -keysize 4096 -validity 10000 -dname "CN=RAGBAZ F-Droid repository" \
    -storepass:env FDROID_KEYSTORE_PASS -keypass:env FDROID_KEY_PASS 2>/dev/null
  chmod 600 "$FDROID_KEYSTORE"
  ok "created $FDROID_KEYSTORE (back it up offline; losing it forces every user to re-add the repo)"
  keytool -list -v -keystore "$FDROID_KEYSTORE" -alias "$FDROID_KEY_ALIAS" -storepass:env FDROID_KEYSTORE_PASS 2>/dev/null | sed -n 's/^\s*SHA256: /  fingerprint: /p'
}

init_apt_key() {
  # ed25519, sign-only, 3-year expiry (extend with: gpg --quick-set-expire FPR 3y), passphrase via pinentry.
  local uid=${APT_KEY_UID:-RAGBAZ APT archive signing <ragbaz@proton.me>} fpr
  gpg --list-keys "=$uid" >/dev/null 2>&1 && die "a key for \"$uid\" already exists" "keep it: its fingerprint is what users pinned"
  gpg --quick-gen-key "$uid" ed25519 sign 3y || die "gpg did not create the key"
  fpr=$(gpg --with-colons --list-keys "=$uid" | awk -F: '/^fpr:/{print $10; exit}')
  [ -n "$fpr" ] || die "cannot find the new key for \"$uid\""
  ok "created APT archive key $fpr (back it up offline: gpg --export-secret-keys --armor $fpr)"
  if [ -n "${APT_KEY_VOUCHED_BY:-}" ]; then
    gpg --batch --yes --default-key "$APT_KEY_VOUCHED_BY" --quick-sign-key "$fpr" || die "certification by $APT_KEY_VOUCHED_BY failed"
    ok "certified by $APT_KEY_VOUCHED_BY (exportable)"
  fi
  printf '\n  use it with: APT_SIGNING_KEY=%s scripts/publish-repos.sh build\n' "$fpr"
}

collect() { # collect DEST: download and verify release assets
  local dest=$1 tags t
  mkdir -p "$dest/apk" "$dest/deb" "$dest/dl"
  tags=$(gh api "repos/$repo/releases" --paginate --jq '.[] | select(.draft == false) | .tag_name')
  for t in $tags; do
    mkdir -p "$dest/dl/$t"
    gh release download "$t" -R "$repo" -D "$dest/dl/$t" -p '*.apk' -p 'rbq_*.deb' -p SHA256SUMS --clobber 2>/dev/null || true
    # A release may carry APKs, .debs or both; skip only one that has neither.
    shopt -s nullglob; local pkgs=("$dest/dl/$t"/*.apk "$dest/dl/$t"/rbq_*.deb); shopt -u nullglob
    [ ${#pkgs[@]} -gt 0 ] || continue
    [ -f "$dest/dl/$t/SHA256SUMS" ] || die "release $t has packages but no SHA256SUMS" "attach SHA256SUMS to the release"
    (cd "$dest/dl/$t" && sha256sum --check --ignore-missing --quiet SHA256SUMS) || die "checksum mismatch in release $t" "re-download or re-upload the release assets"
    cp "$dest/dl/$t"/*.apk "$dest/apk/" 2>/dev/null || true
    cp "$dest/dl/$t"/rbq_*.deb "$dest/deb/" 2>/dev/null || true
    ok "release $t verified"
  done
  [ -z "${RBQ_EXTRA_APKS:-}" ] || cp "$RBQ_EXTRA_APKS"/*.apk "$dest/apk/"
  [ -z "${RBQ_EXTRA_DEBS:-}" ] || cp "$RBQ_EXTRA_DEBS"/*.deb "$dest/deb/"
}

verify() {
  local tmp; tmp=$(mktemp -d)
  gpg --dearmor < "$out/apt/ragbaz-archive-keyring.asc" > "$tmp/k.gpg"
  gpgv --keyring "$tmp/k.gpg" "$out/apt/dists/stable/InRelease" 2>/dev/null || die "APT InRelease does not verify with the published keyring"
  ok "APT InRelease verifies with ragbaz-archive-keyring"
  (cd "$out/apt/dists/stable" && awk '/^SHA256:/{f=1;next} /^[A-Z]/{f=0} f{print $1"  "$3}' Release | sha256sum --check --quiet) || die "APT Release hashes do not match the index files"
  ok "APT index hashes match Release"
  jarsigner -verify "$out/fdroid/repo/entry.jar" 2>/dev/null | grep -q "jar verified" || die "F-Droid entry.jar signature does not verify"
  ok "F-Droid entry.jar signature verifies (index-v2)"
  rm -rf "$tmp"
}

upload() {
  local f rel type cache
  command -v npx >/dev/null || die "npx not found" "install Node.js; uploads use wrangler"
  put() { # put LOCAL KEY
    case "$1" in
      *.apk) type=application/vnd.android.package-archive ;; *.deb) type=application/vnd.debian.binary-package ;;
      *.json) type=application/json ;; *.jar) type=application/java-archive ;; *.png) type=image/png ;;
      *.gz) type=application/gzip ;; *.html) type="text/html; charset=utf-8" ;; *.xml) type=application/xml ;;
      */Release.gpg) type=application/pgp-signature ;; *.gpg) type=application/pgp-keys ;;
      *) type="text/plain; charset=utf-8" ;;
    esac
    npx --yes wrangler@4 r2 object put "$R2_BUCKET/$2" --file "$1" --content-type "$type" --remote >/dev/null \
      || die "upload of $2 failed" "re-run with --upload; packages are re-sent, indexes go last"
  }
  # Three phases, so a client never sees an index naming a file (or hash) that is not there yet:
  # 1 packages and other assets, 2 indexes, 3 the signed entry points that pin the indexes' hashes.
  phase() {
    case "$1" in
      */dists/*/InRelease|*/dists/*/Release|*/dists/*/Release.gpg|*/entry.jar|*/entry.json|*/index-v1.jar|*/index.jar) echo 3 ;;
      */dists/*|*/index-v*|*/index.xml|*/diff/*) echo 2 ;;
      *) echo 1 ;;
    esac
  }
  local p
  for p in 1 2 3; do
    while IFS= read -r f; do
      [ "$(phase "$f")" = "$p" ] || continue
      rel=${f#"$out/"}; put "$f" "repos/$rel"
    done < <(find "$out/apt" "$out/fdroid/repo" -type f | sort)
  done
  ok "uploaded to r2://$R2_BUCKET/repos/ (served at https://ragbaz.cc/apt and /fdroid/repo)"
}

build() {
  local upload_too=${1:-}
  [ ! -e "$out" ] || die "$out exists" "move it away; each build is fresh"
  for t in gh gpg gpgv apt-ftparchive dpkg-deb keytool jarsigner fdroid; do command -v $t >/dev/null || die "$t not found" "see the Needs: list at the top of this script"; done
  [ -f "$FDROID_KEYSTORE" ] || die "no F-Droid repo key at $FDROID_KEYSTORE" "run: scripts/publish-repos.sh init-fdroid-key"
  gpg --list-secret-keys "$APT_SIGNING_KEY" >/dev/null 2>&1 || die "no secret key $APT_SIGNING_KEY in your gpg keyring" "set APT_SIGNING_KEY to a key your gpg-agent holds"
  ask FDROID_KEYSTORE_PASS "F-Droid repo keystore password"
  [ -n "${FDROID_KEY_PASS:-}" ] || { FDROID_KEY_PASS=$FDROID_KEYSTORE_PASS; export FDROID_KEY_PASS; }
  local work; work=$(mktemp -d)
  note "collecting published releases of $repo"
  collect "$work"
  ls "$work/apk"/*.apk >/dev/null 2>&1 || die "no APKs found in published releases" "publish a release or set RBQ_EXTRA_APKS"
  ls "$work/deb"/*.deb >/dev/null 2>&1 || die "no rbq .deb found in published releases" "attach rbq_*.deb (scripts/build-cli-release.sh) or set RBQ_EXTRA_DEBS"
  mkdir -p "$out"
  "$here/build-apt-repo.sh" "$work/deb" "$out/apt"
  "$here/build-fdroid-repo.sh" "$work/apk" "$out/fdroid-work"
  mv "$out/fdroid-work" "$out/fdroid"; rm -rf "$out/fdroid/metadata" "$out/fdroid/tmp" "$out/fdroid/archive" "$out/fdroid/srclibs" "$out/fdroid/repo/status"
  rm -rf "$work"
  verify
  ok "repositories ready in $out"
  printf '\n  F-Droid: https://ragbaz.cc/fdroid/repo?fingerprint=%s\n' "$(cat "$out/fdroid/repo/FINGERPRINT.txt")"
  printf '  APT:     curl -fsSL https://ragbaz.cc/apt/ragbaz-archive-keyring.gpg | sudo tee /usr/share/keyrings/ragbaz-archive-keyring.gpg >/dev/null\n'
  printf '           echo "deb [signed-by=/usr/share/keyrings/ragbaz-archive-keyring.gpg] https://ragbaz.cc/apt stable main" | sudo tee /etc/apt/sources.list.d/ragbaz.list\n\n'
  [ "$upload_too" = --upload ] && upload || note "not uploaded (add --upload)"
}

case "${1:-}" in
  init-fdroid-key) init_fdroid_key ;;
  init-apt-key) init_apt_key ;;
  build) build "${2:-}" ;;
  verify) verify ;;
  upload) upload ;;
  *) sed -n '2,31p' "$0" | sed 's/^# \{0,1\}//'; exit 2 ;;
esac
