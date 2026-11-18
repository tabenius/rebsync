#!/bin/sh
# Build static rbq-sync release tarballs for Linux x86_64 and aarch64
# (Chromebook/Crostini, servers, Raspberry Pi) without CI.
#
# Needs: rustup targets x86_64-unknown-linux-musl and aarch64-unknown-linux-musl,
# cargo-zigbuild (cargo install cargo-zigbuild) and zig (pip install ziglang).
# Usage: scripts/build-cli-release.sh [DIST_DIR]
set -eu
root=$(cd "$(dirname "$0")/.." && pwd)
dist=${1:-"$root/dist/cli"}
cd "$root"
test -z "$(git status --porcelain --untracked-files=no)" || { echo "commit first: the tarballs name their source commit" >&2; exit 1; }
version=$(cargo metadata --no-deps --format-version 1 | python3 -c 'import json,sys; print([p["version"] for p in json.load(sys.stdin)["packages"] if p["name"]=="rebsync-cli"][0])')
commit=$(git rev-parse --short HEAD)
rm -rf "$dist"; mkdir -p "$dist"
for pair in "x86_64-unknown-linux-musl x86_64" "aarch64-unknown-linux-musl aarch64"; do
  set -- $pair
  cargo zigbuild --release --locked -p rebsync-cli --target "$1"
  bin="target/$1/release/rbq-sync"
  file "$bin" | grep -q "statically linked" || { echo "$bin is not static" >&2; exit 1; }
  name="rbq-sync-$version-linux-$2"
  mkdir -p "$dist/$name"
  cp "$bin" "$dist/$name/rbq-sync"
  install -m 0755 scripts/rbq-sync-install.sh "$dist/$name/install.sh"
  printf 'rbq-sync %s (source %s)\nStatic Linux %s build. Run ./install.sh, or copy rbq-sync onto your PATH.\nrebsync is the olden name; install.sh links it to rbq-sync.\n' "$version" "$commit" "$2" > "$dist/$name/README.txt"
  tar -C "$dist" -czf "$dist/$name.tar.gz" "$name"
  rm -rf "$dist/$name"
done
(cd "$dist" && sha256sum ./*.tar.gz | sed 's# \./# #' > SHA256SUMS && cat SHA256SUMS)
