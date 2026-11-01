#!/bin/sh
# Set the release version everywhere it appears, then commit and tag:
#   sh packaging/set-version.sh 0.2.0 && git commit -am "Release 0.2.0" && git tag v0.2.0
# The release workflow refuses a tag that doesn't match these files.
set -eu
V="${1:?usage: packaging/set-version.sh <version, e.g. 0.2.0>}"
cd "$(dirname "$0")/.."
sedi() { sed -i.bak "$@" && rm -f "$2.bak" 2>/dev/null || true; }
sedi "0,/^version = \".*\"/s//version = \"$V\"/" Cargo.toml
sedi "s/^version = \".*\"/version = \"$V\"/" shims/python/pyproject.toml
sedi "s/^__version__ = \".*\"/__version__ = \"$V\"/" shims/python/src/doppelkey/__init__.py
sedi "s/^  s.version = \".*\"/  s.version = \"$V\"/" shims/ruby/doppelkey.gemspec
sedi "s/^  VERSION = \".*\"/  VERSION = \"$V\"/" shims/ruby/lib/doppelkey.rb
sedi "s/^  version \".*\"/  version \"$V\"/" packaging/homebrew/doppelkey.rb
(cd shims/node && npm version --no-git-tag-version --allow-same-version "$V" >/dev/null)
cargo update -q --workspace 2>/dev/null || cargo metadata -q --format-version 1 >/dev/null
sh packaging/check-version.sh "$V"
