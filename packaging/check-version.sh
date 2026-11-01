#!/bin/sh
# Fail unless every package version equals $1. Run by the release workflow on the tag.
set -eu
V="${1:?usage: packaging/check-version.sh <version>}"
cd "$(dirname "$0")/.."
bad=0
check() { if [ "$2" != "$V" ]; then echo "$1 has version $2, expected $V" >&2; bad=1; fi; }
check Cargo.toml "$(sed -n 's/^version = "\(.*\)"/\1/p' Cargo.toml | head -1)"
check Cargo.lock "$(grep -A1 '^name = "doppelkeyd"' Cargo.lock | sed -n 's/^version = "\(.*\)"/\1/p')"
check shims/node/package.json "$(node -p 'require("./shims/node/package.json").version')"
check shims/node/package-lock.json "$(node -p 'require("./shims/node/package-lock.json").version')"
check shims/python/pyproject.toml "$(sed -n 's/^version = "\(.*\)"/\1/p' shims/python/pyproject.toml)"
check shims/python/src/doppelkey/__init__.py "$(sed -n 's/^__version__ = "\(.*\)"/\1/p' shims/python/src/doppelkey/__init__.py)"
check shims/ruby/doppelkey.gemspec "$(sed -n 's/^  s.version = "\(.*\)"/\1/p' shims/ruby/doppelkey.gemspec)"
check shims/ruby/lib/doppelkey.rb "$(sed -n 's/^  VERSION = "\(.*\)"/\1/p' shims/ruby/lib/doppelkey.rb)"
if [ "$bad" = 1 ]; then echo "Fix with: sh packaging/set-version.sh $V" >&2; exit 1; fi
echo "All versions are $V"
