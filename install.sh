#!/bin/sh
# doppelkey installer: downloads the release for this OS/CPU, verifies its checksum, and
# installs to ~/.local (bin/ and share/doppelkey/). Override with DOPPELKEY_PREFIX.
#   curl -fsSL https://raw.githubusercontent.com/KaiHongTan/doppelkey/main/install.sh | sh
set -eu
REPO="KaiHongTan/doppelkey"
PREFIX="${DOPPELKEY_PREFIX:-$HOME/.local}"
VERSION="${DOPPELKEY_VERSION:-latest}"

case "$(uname -s)-$(uname -m)" in
  Linux-x86_64) TARGET=x86_64-unknown-linux-gnu ;;
  Linux-aarch64|Linux-arm64) TARGET=aarch64-unknown-linux-gnu ;;
  Darwin-arm64) TARGET=aarch64-apple-darwin ;;
  Darwin-x86_64) TARGET=x86_64-apple-darwin ;;
  *) echo "doppelkey: no prebuilt binary for $(uname -s)-$(uname -m); build from source with cargo" >&2; exit 1 ;;
esac

if [ "$VERSION" = latest ]; then
  VERSION="$(curl -fsSL "https://api.github.com/repos/$REPO/releases/latest" | sed -n 's/.*"tag_name": *"v\{0,1\}\([^"]*\)".*/\1/p' | head -1)"
fi
NAME="doppelkey-$VERSION-$TARGET"
URL="https://github.com/$REPO/releases/download/v$VERSION/$NAME.tar.gz"
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT
echo "Downloading $NAME"
curl -fsSL "$URL" -o "$TMP/$NAME.tar.gz"
curl -fsSL "$URL.sha256" -o "$TMP/$NAME.tar.gz.sha256"
(cd "$TMP" && if command -v sha256sum >/dev/null; then sha256sum -c "$NAME.tar.gz.sha256"; else shasum -a 256 -c "$NAME.tar.gz.sha256"; fi) >/dev/null
tar xzf "$TMP/$NAME.tar.gz" -C "$TMP"
mkdir -p "$PREFIX/bin" "$PREFIX/share"
cp "$TMP/$NAME/bin/doppelkey" "$TMP/$NAME/bin/doppelkeyd" "$PREFIX/bin/"
rm -rf "$PREFIX/share/doppelkey" && cp -R "$TMP/$NAME/share/doppelkey" "$PREFIX/share/"
# The keeper binary should not be writable by tools running as you (see SECURITY.md); make it read-only.
chmod 0555 "$PREFIX/bin/doppelkeyd"
echo "Installed doppelkey $VERSION to $PREFIX/bin"
case ":$PATH:" in *":$PREFIX/bin:"*) ;; *) echo "Add $PREFIX/bin to your PATH." ;; esac
echo "Next: cd your-project && doppelkey init"
