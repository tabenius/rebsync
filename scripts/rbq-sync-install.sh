#!/bin/sh
# Install rbq-sync (and its olden name, rebsync) into ~/.local/bin.
# Static Linux binary: works in a Chromebook's Linux (Crostini) container as-is.
set -eu
here=$(cd "$(dirname "$0")" && pwd)
dest="${PREFIX:-$HOME/.local}/bin"
mkdir -p "$dest"
install -m 0755 "$here/rbq-sync" "$dest/rbq-sync"
ln -sf rbq-sync "$dest/rebsync"
echo "installed $dest/rbq-sync (and rebsync -> rbq-sync)"
case ":$PATH:" in *":$dest:"*) ;; *) echo "add to PATH: export PATH=\"$dest:\$PATH\"";; esac
"$dest/rbq-sync" --version
