#!/usr/bin/env bash
# Build the signed F-Droid repository served at https://ragbaz.cc/fdroid/repo.
#
#   FDROID_KEYSTORE=/path/repo.jks FDROID_KEY_ALIAS=ragbaz-fdroid \
#   FDROID_KEYSTORE_PASS=… FDROID_KEY_PASS=… \
#     scripts/repos/build-fdroid-repo.sh APK_DIR OUT_DIR
#
# The F-Droid repo key signs only the index; it is NOT the APK signing key.
# Passwords are read from the environment (read -rs them), never from files
# written here. APK_DIR holds every APK to offer; OUT_DIR must not exist and
# receives repo/ (index-v1.jar, index-v2.json, entry.jar, APKs, icons).
# Needs fdroidserver (pip install fdroidserver) and Android build-tools
# (ANDROID_HOME) for apksigner/aapt.
set -euo pipefail
die() { echo "build-fdroid-repo: $*" >&2; exit 1; }
[ $# -eq 2 ] || die "usage: $0 APK_DIR OUT_DIR"
apks=$1; out=$2
here=$(cd "$(dirname "$0")" && pwd)
for v in FDROID_KEYSTORE FDROID_KEY_ALIAS FDROID_KEYSTORE_PASS FDROID_KEY_PASS; do [ -n "${!v:-}" ] || die "set $v"; done
[ -f "$FDROID_KEYSTORE" ] || die "keystore $FDROID_KEYSTORE not found"
[ -d "$apks" ] || die "no $apks"
[ ! -e "$out" ] || die "$out exists; build into a new directory"
command -v fdroid >/dev/null || die "fdroid not found (pip install fdroidserver)"
[ -n "${ANDROID_HOME:-}" ] || die "set ANDROID_HOME (build-tools with apksigner/aapt)"
shopt -s nullglob; files=("$apks"/*.apk); [ ${#files[@]} -gt 0 ] || die "no APKs in $apks"
mkdir -p "$out/repo" "$out/metadata"
cp "${files[@]}" "$out/repo/"
cp "$here"/fdroid-metadata/*.yml "$out/metadata/"
# Per-app graphics: fdroid-metadata/<appid>/<locale>/phoneScreenshots/*.png
for d in "$here"/fdroid-metadata/*/; do cp -R "$d" "$out/metadata/"; done
cat > "$out/config.yml" <<CONFIG
repo_url: https://ragbaz.cc/fdroid/repo
repo_name: RAGBAZ
repo_description: >-
  Apps from RAGBAZ, built from public GPL source. Rebeqah keeps your work safe
  and moves it between devices without needing the internet.
archive_older: 0
keystore: $FDROID_KEYSTORE
repo_keyalias: $FDROID_KEY_ALIAS
keystorepass: {env: FDROID_KEYSTORE_PASS}
keypass: {env: FDROID_KEY_PASS}
sdk_path: $ANDROID_HOME
CONFIG
chmod 0600 "$out/config.yml"
(cd "$out" && fdroid update --pretty --use-date-from-apk)
rm "$out/config.yml"
for f in index-v1.jar entry.jar index-v2.json; do [ -f "$out/repo/$f" ] || die "fdroid did not produce repo/$f"; done
fpr=$(keytool -list -v -keystore "$FDROID_KEYSTORE" -alias "$FDROID_KEY_ALIAS" -storepass:env FDROID_KEYSTORE_PASS 2>/dev/null | sed -n 's/^\s*SHA256: //p' | tr -d ':' | tr 'A-F' 'a-f')
echo "$fpr" > "$out/repo/FINGERPRINT.txt"
echo "built F-Droid repository in $out/repo; repo key fingerprint $fpr"
echo "add with: https://ragbaz.cc/fdroid/repo?fingerprint=$fpr"
