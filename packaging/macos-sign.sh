#!/bin/sh
# Sign doppelkey binaries with a Developer ID, hardened runtime, no get-task-allow, then notarize.
# Hardened runtime without get-task-allow is what stops same-user debuggers from reading the
# keeper's memory on macOS (docs/research.md); a stable signature keeps Keychain ACLs working
# across upgrades. Usage: packaging/macos-sign.sh <dir-with-binaries>
set -eu
DIR="$1"
KEYCHAIN="$RUNNER_TEMP/signing.keychain-db"
security create-keychain -p "" "$KEYCHAIN"
security set-keychain-settings "$KEYCHAIN"
security unlock-keychain -p "" "$KEYCHAIN"
echo "$APPLE_CERT_P12" | base64 --decode > "$RUNNER_TEMP/cert.p12"
security import "$RUNNER_TEMP/cert.p12" -k "$KEYCHAIN" -P "$APPLE_CERT_PASSWORD" -T /usr/bin/codesign
security list-keychains -d user -s "$KEYCHAIN"
IDENTITY="Developer ID Application: ($APPLE_TEAM_ID)"
for b in doppelkey doppelkeyd; do
  codesign --force --options runtime --timestamp --keychain "$KEYCHAIN" --sign "$(security find-identity -v -p codesigning "$KEYCHAIN" | awk -F'"' '/Developer ID Application/ {print $2; exit}')" "$DIR/$b"
done
echo "$APPLE_NOTARY_KEY" > "$RUNNER_TEMP/notary.p8"
ditto -c -k "$DIR/doppelkeyd" "$RUNNER_TEMP/notarize.zip"
xcrun notarytool submit "$RUNNER_TEMP/notarize.zip" --key "$RUNNER_TEMP/notary.p8" --key-id "$APPLE_NOTARY_KEY_ID" --issuer "$APPLE_NOTARY_ISSUER" --wait
