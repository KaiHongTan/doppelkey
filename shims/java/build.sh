#!/bin/sh
# Build dist/doppelkey-agent.jar with only the JDK (no Maven/Gradle needed). Java 16+.
set -eu
cd "$(dirname "$0")"
rm -rf build dist && mkdir -p build dist
javac --release 17 -d build $(find src -name '*.java')
printf 'Premain-Class: dev.doppelkey.Agent\nAgent-Class: dev.doppelkey.Agent\nImplementation-Title: doppelkey\nImplementation-Version: 0.1.0\n' > build/MANIFEST.MF
jar --create --file dist/doppelkey-agent.jar --manifest build/MANIFEST.MF -C build dev
echo "built dist/doppelkey-agent.jar"
