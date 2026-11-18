#!/bin/sh
# Install rbq (rbq-sync; olden name rebsync) into ~/.local/bin.
# Static Linux binary: works in a Chromebook's Linux (Crostini) container as-is.
set -eu
here=$(cd "$(dirname "$0")" && pwd)
built_for=$(cat "$here/ARCH" 2>/dev/null || echo unknown)
machine=$(uname -m)
case "$machine" in arm64) machine=aarch64 ;; amd64) machine=x86_64 ;; esac
if [ "$built_for" != unknown ] && [ "$built_for" != "$machine" ]; then
  echo "This is the $built_for build, but this machine is $machine." >&2
  echo "Use rbq-sync-*-linux-$machine.tar.gz instead." >&2
  exit 1
fi
dest="${PREFIX:-$HOME/.local}/bin"
mkdir -p "$dest"
install -m 0755 "$here/rbq" "$dest/rbq"
ln -sf rbq "$dest/rebsync"
echo "installed $dest/rbq (and rebsync -> rbq)"
case ":$PATH:" in *":$dest:"*) ;; *) echo "add to PATH: export PATH=\"$dest:\$PATH\"";; esac
"$dest/rbq" --version
