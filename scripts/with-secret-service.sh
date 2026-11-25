#!/usr/bin/env bash
# Run a command inside a throwaway D-Bus session with an unlocked GNOME
# Keyring, for tests of the Secret Service credential sealer. Needs
# dbus-run-session and gnome-keyring-daemon (Debian/Ubuntu: dbus,
# gnome-keyring). Nothing persists: the keyring lives in a temporary HOME.
set -euo pipefail
if [ -z "${RBQ_IN_SECRET_SERVICE:-}" ]; then
  export RBQ_IN_SECRET_SERVICE=1
  # Toolchains are found under HOME unless these say otherwise: pin them
  # before HOME moves to the throwaway keyring's directory.
  export RUSTUP_HOME="${RUSTUP_HOME:-$HOME/.rustup}" CARGO_HOME="${CARGO_HOME:-$HOME/.cargo}"
  HOME="$(mktemp -d)"
  export HOME
  exec dbus-run-session -- "$0" "$@"
fi
printf 'rbq-test' | gnome-keyring-daemon --unlock --components=secrets >/dev/null
exec "$@"
