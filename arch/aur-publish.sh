#!/usr/bin/env bash
# aur-publish.sh VERSION : put cfr2-bin VERSION on the AUR (first time creates the package).
# Run on a machine with the AUR ssh key and makepkg, after the GitHub release exists.
set -euo pipefail
VER=${1:?usage: aur-publish.sh VERSION (no leading v)}
HERE=$(cd "$(dirname "$0")" && pwd)
REPO=https://github.com/j4y-w4lk3r/cfr2
WORK=$(mktemp -d)
trap 'rm -rf "$WORK"' EXIT
git clone -q ssh://aur@aur.archlinux.org/cfr2-bin.git "$WORK/aur"
cd "$WORK/aur"
sha() { curl -fsSL "$1" | sha256sum | awk '{print $1}'; }
x86=$(sha "$REPO/releases/download/v$VER/cfr2_${VER}_linux_x86_64.tar.gz")
arm=$(sha "$REPO/releases/download/v$VER/cfr2_${VER}_linux_arm64.tar.gz")
sed -e "s/^pkgver=.*/pkgver=$VER/" -e "s/^pkgrel=.*/pkgrel=1/" \
    -e "s/^sha256sums_x86_64=.*/sha256sums_x86_64=('$x86')/" \
    -e "s/^sha256sums_aarch64=.*/sha256sums_aarch64=('$arm')/" "$HERE/PKGBUILD" > PKGBUILD
makepkg --printsrcinfo > .SRCINFO
git add PKGBUILD .SRCINFO
git -c user.name=j4y -c user.email="$(git -C "$HERE" config user.email)" commit -q -m "cfr2-bin: $VER"
git push -q origin HEAD:master
echo "cfr2-bin $VER is on the AUR: https://aur.archlinux.org/packages/cfr2-bin"
