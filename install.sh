#!/bin/sh
#
# Install vpnctl from its latest published release.
#
#   curl -fsSL https://raw.githubusercontent.com/nhatphat/vpn-router/main/install.sh | sh
#
# This downloads a binary, checks it against the checksum published beside it,
# and then runs "vpnctl install" with sudo — which is the step that asks for
# your password, and the only one that does. Everything it changes is listed
# by "vpnctl uninstall".
#
# Reading a script before piping it to a shell is a reasonable habit. This one
# is short on purpose.

set -eu

OWNER=nhatphat
REPO=vpn-router
API="https://api.github.com/repos/$OWNER/$REPO/releases/latest"

say()  { printf '%s\n' "$*"; }
die()  { printf 'error: %s\n' "$*" >&2; exit 1; }

os=$(uname -s)
arch=$(uname -m)

[ "$os" = "Darwin" ] || die "vpnctl is macOS only; this is $os."

case "$arch" in
  arm64) ;;
  x86_64)
    die "only Apple silicon is published so far.
On an Intel Mac, build it yourself:
  git clone https://github.com/$OWNER/$REPO && cd $REPO
  go build -trimpath -o vpnctl ./cmd/vpnctl && sudo ./vpnctl install"
    ;;
  *) die "unsupported architecture: $arch" ;;
esac

command -v curl >/dev/null 2>&1 || die "curl is required."
command -v shasum >/dev/null 2>&1 || die "shasum is required."

work=$(mktemp -d)
# Removed whatever happens next, including a failed checksum.
trap 'rm -rf "$work"' EXIT INT TERM

say "Looking up the latest release of $OWNER/$REPO..."

# The status code is read separately so that "there are no releases" and
# "the network is down" do not produce the same message. They call for
# entirely different things from the reader.
status=$(curl -sSL -o "$work/release.json" -w '%{http_code}' \
  -H 'Accept: application/vnd.github+json' "$API" 2>/dev/null) ||
  die "could not reach GitHub. Is the network up?"

case "$status" in
  200) ;;
  404) die "$OWNER/$REPO has no published releases yet.

Build it from source instead:
  git clone https://github.com/$OWNER/$REPO && cd $REPO
  go build -trimpath -o vpnctl ./cmd/vpnctl && sudo ./vpnctl install" ;;
  403) die "GitHub returned 403, which usually means a rate limit. Try again shortly." ;;
  *)   die "GitHub returned HTTP $status when asked for the latest release." ;;
esac

tag=$(sed -n 's/.*"tag_name"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p' "$work/release.json" | head -1)
[ -n "$tag" ] || die "could not read a tag from GitHub's answer."

version=${tag#v}
archive="vpnctl_${version}_darwin_arm64.tar.gz"
base="https://github.com/$OWNER/$REPO/releases/download/$tag"

say "Downloading $archive ($tag)..."
curl -fsSL -o "$work/$archive" "$base/$archive" ||
  die "could not download $archive.
$tag may not publish a build for Apple silicon."

curl -fsSL -o "$work/SHA256SUMS" "$base/SHA256SUMS" ||
  die "the release publishes no SHA256SUMS, so the download cannot be verified."

say "Verifying checksum..."
( cd "$work" && grep " \*\{0,1\}$archive\$" SHA256SUMS | shasum -a 256 -c - >/dev/null ) ||
  die "checksum mismatch. Nothing was installed."

tar -xzf "$work/$archive" -C "$work" || die "could not unpack $archive."
[ -x "$work/vpnctl" ] || die "the archive does not contain a vpnctl binary."

say ""
say "Installing. This is the step that needs your password:"
say ""
sudo "$work/vpnctl" install

say ""
say "Done. Try:  vpnctl status"
