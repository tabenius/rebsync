#!/bin/sh
# Install rbq (rbq-sync; olden name rebsync) into ~/.local/bin.
# Static Linux binary: works in a Chromebook's Linux (Crostini) container as-is.
set -eu
here=$(cd "$(dirname "$0")" && pwd)
dest="${PREFIX:-$HOME/.local}/bin"
mkdir -p "$dest"
install -m 0755 "$here/rbq" "$dest/rbq"
ln -sf rbq "$dest/rebsync"
echo "installed $dest/rbq (and rebsync -> rbq)"
case ":$PATH:" in *":$dest:"*) ;; *) echo "add to PATH: export PATH=\"$dest:\$PATH\"";; esac
"$dest/rbq" --version
