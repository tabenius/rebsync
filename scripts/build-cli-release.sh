#!/bin/sh
# Build static rbq (rbq-sync) release tarballs and Debian packages for Linux
# x86_64 and aarch64 (Chromebook/Crostini, servers, Raspberry Pi) without CI.
# The .deb files feed the signed APT repository at https://ragbaz.cc/apt.
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

# One reproducible-ish .deb per architecture: /usr/bin/rbq, the olden name
# /usr/bin/rebsync as a symlink, and GPL copyright. Built with dpkg-deb only.
build_deb() {
  case "$2" in x86_64) debarch=amd64 ;; aarch64) debarch=arm64 ;; *) echo "unknown arch $2" >&2; exit 1 ;; esac
  pkg="$dist/deb-$debarch"
  rm -rf "$pkg"; mkdir -p "$pkg/DEBIAN" "$pkg/usr/bin" "$pkg/usr/share/doc/rbq"
  install -m 0755 "$1" "$pkg/usr/bin/rbq"
  ln -s rbq "$pkg/usr/bin/rebsync"
  install -m 0644 LICENSE "$pkg/usr/share/doc/rbq/copyright"
  cat > "$pkg/DEBIAN/control" <<CONTROL
Package: rbq
Version: $version
Architecture: $debarch
Maintainer: RAGBAZ <ragbaz@proton.me>
Section: utils
Priority: optional
Installed-Size: $(du -k "$pkg/usr" | tail -1 | cut -f1)
Homepage: https://github.com/tabenius/rebsync
Description: Rebeqah: preserve work and exchange Git branches without GitHub
 rbq keeps work safe and moves repositories between machines over USB, SD
 cards, a local network or a phone, and reports what remains at risk.
 Static build from source commit $commit. rebsync is the olden name.
CONTROL
  SOURCE_DATE_EPOCH=$(git log -1 --format=%ct) dpkg-deb --root-owner-group -Zxz --build "$pkg" "$dist/rbq_${version}_${debarch}.deb" >/dev/null
  rm -rf "$pkg"
  dpkg-deb --info "$dist/rbq_${version}_${debarch}.deb" | grep -E "Package|Version|Architecture" | tr -s ' '
}
for pair in "x86_64-unknown-linux-musl x86_64" "aarch64-unknown-linux-musl aarch64"; do
  set -- $pair
  cargo zigbuild --release --locked -p rebsync-cli --target "$1"
  bin="target/$1/release/rbq"
  file "$bin" | grep -q "statically linked" || { echo "$bin is not static" >&2; exit 1; }
  name="rbq-sync-$version-linux-$2"
  mkdir -p "$dist/$name"
  cp "$bin" "$dist/$name/rbq"
  install -m 0755 scripts/rbq-sync-install.sh "$dist/$name/install.sh"
  printf '%s\n' "$2" > "$dist/$name/ARCH"
  printf 'rbq-sync %s (source %s): the rbq command\nStatic Linux %s build. Run ./install.sh, or copy rbq onto your PATH.\nrebsync is the olden name; install.sh links it to rbq.\n' "$version" "$commit" "$2" > "$dist/$name/README.txt"
  tar -C "$dist" -czf "$dist/$name.tar.gz" "$name"
  rm -rf "$dist/$name"
  build_deb "$bin" "$2"
done
(cd "$dist" && sha256sum ./*.tar.gz ./*.deb | sed 's# \./# #' > SHA256SUMS && cat SHA256SUMS)
