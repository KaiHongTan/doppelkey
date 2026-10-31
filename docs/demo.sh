#!/bin/sh
# 60-second demo, safe to run anywhere: everything happens in a temporary directory with fake
# secrets, and the keeper is stopped at the end. Needs: doppelkey + doppelkeyd on PATH, node.
#   sh docs/demo.sh
set -eu
DEMO="$(mktemp -d)"
export HOME="$DEMO/home" DOPPELKEY_HOME="$DEMO/home/doppelkey" DOPPELKEY_SOCK="$DEMO/k.sock" DOPPELKEY_PASSPHRASE="demo passphrase" DOPPELKEY_SERVICE=detached
mkdir -p "$HOME" "$DEMO/app" && cd "$DEMO/app"
say() { printf '\n\033[1m%s\033[0m\n' "$*"; sleep "${DEMO_PAUSE:-1}"; }

say "1. An app with a JWT secret in .env (fake). Anything running as you can read it:"
echo 'JWT_SECRET=super-secret-signing-key-do-not-leak-123' > .env
echo '{"name":"demo","private":true,"scripts":{"start":"node app.js"}}' > package.json
cat > app.js <<'JS'
const fs = require('fs'), crypto = require('crypto');
const secret = fs.readFileSync('.env', 'utf8').match(/JWT_SECRET=(.*)/)[1];
console.log('app signs with:', secret.slice(0, 44));
console.log('signature:     ', crypto.createHmac('sha256', secret).update('user=alice').digest('hex').slice(0, 32));
JS
cat .env
npm start -s

say "2. doppelkey init: preview, then move the value into the keeper"
doppelkey init --yes | grep -E 'protect|Protected'
cat .env

say "3. Same command, same signature. The app only ever saw the handle:"
npm start -s

say "4. What a curious agent gets:"
echo "\$ cat .env"; cat .env
echo "\$ doppelkey eject   (writes real values back)"; doppelkey eject 2>&1 | sed 's/^/  /' || true

say "5. Every use is audited:"
doppelkey log -n 3

doppelkey service uninstall >/dev/null 2>&1 || true
rm -rf "$DEMO"
say "Done. Real project: cd your-app && npx doppelkey init"
