#!/usr/bin/env bash
# Build the signed APT repository served at https://ragbaz.cc/apt.
#
#   APT_SIGNING_KEY=<OpenPGP fingerprint> scripts/repos/build-apt-repo.sh DEB_DIR OUT_DIR
#
# DEB_DIR holds every .deb the repository should offer (all versions). OUT_DIR
# must not exist; it receives pool/, dists/stable/ and the public keyring.
# Signing uses the local gpg-agent: the private key never leaves the agent and
# no passphrase is read from a file or argument. Needs apt-ftparchive
# (apt-utils), dpkg-deb and gpg.
set -euo pipefail
die() { echo "build-apt-repo: $*" >&2; exit 1; }
[ $# -eq 2 ] || die "usage: APT_SIGNING_KEY=FPR $0 DEB_DIR OUT_DIR"
debs=$1; out=$2; key=${APT_SIGNING_KEY:-}
[ -n "$key" ] || die "set APT_SIGNING_KEY to the archive key's fingerprint"
[ -d "$debs" ] || die "no $debs"
[ ! -e "$out" ] || die "$out exists; build into a new directory"
for t in apt-ftparchive dpkg-deb gpg; do command -v $t >/dev/null || die "$t not found (apt-utils, dpkg, gnupg)"; done
gpg --list-secret-keys "$key" >/dev/null 2>&1 || die "no secret key $key in the local keyring/agent"

suite=stable; comp=main
shopt -s nullglob; files=("$debs"/*.deb); [ ${#files[@]} -gt 0 ] || die "no .deb files in $debs"
archs=()
for f in "${files[@]}"; do
  pkg=$(dpkg-deb -f "$f" Package); arch=$(dpkg-deb -f "$f" Architecture)
  [[ $pkg =~ ^[a-z0-9][a-z0-9.+-]+$ ]] || die "bad package name in $f"
  dir="$out/pool/$comp/${pkg:0:1}/$pkg"; mkdir -p "$dir"; [ -e "$dir/$(basename "$f")" ] || cp "$f" "$dir/"
  [[ " ${archs[*]} " == *" $arch "* ]] || archs+=("$arch")
done
cd "$out"
for arch in "${archs[@]}"; do
  d="dists/$suite/$comp/binary-$arch"; mkdir -p "$d"
  apt-ftparchive --arch "$arch" packages pool > "$d/Packages"
  gzip -9nk "$d/Packages"
done
apt-ftparchive \
  -o APT::FTPArchive::Release::Origin=RAGBAZ \
  -o APT::FTPArchive::Release::Label=RAGBAZ \
  -o APT::FTPArchive::Release::Suite=$suite \
  -o APT::FTPArchive::Release::Codename=$suite \
  -o APT::FTPArchive::Release::Components=$comp \
  -o "APT::FTPArchive::Release::Architectures=${archs[*]}" \
  -o APT::FTPArchive::Release::Description="RAGBAZ packages (rbq)" \
  release "dists/$suite" > "Release.tmp"   # written outside dists/: it must not list itself
mv Release.tmp "dists/$suite/Release"
gpg --local-user "$key" --digest-algo SHA512 --clearsign -o "dists/$suite/InRelease" "dists/$suite/Release"
gpg --local-user "$key" --digest-algo SHA512 --armor --detach-sign -o "dists/$suite/Release.gpg" "dists/$suite/Release"
gpg --export "$key" > ragbaz-archive-keyring.gpg
gpg --armor --export "$key" > ragbaz-archive-keyring.asc
gpg --verify "dists/$suite/InRelease" 2>/dev/null || die "InRelease does not verify"
echo "built APT repository in $out for ${archs[*]}; signed by $key"
