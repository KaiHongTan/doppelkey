#!/bin/sh
# doppelkey SessionStart hook.
# - Project already protected: load the shims into every Bash command Claude runs (via
#   CLAUDE_ENV_FILE), and remind Claude what handles are.
# - Plain secrets in .env: point Claude at the doppelkey skill, which proposes `doppelkey init`.
# Prints nothing and exits 0 when doppelkey isn't relevant. Never prints secret values.
DIR="${CLAUDE_PROJECT_DIR:-$PWD}"
cd "$DIR" 2>/dev/null || exit 0

has_handles=0
has_secrets=0
for f in .env .env.*; do
  [ -f "$f" ] || continue
  case "$f" in *example*|*sample*|*template*) continue ;; esac
  if grep -Eq 'dk1:|=["'"'"']?(whsec_|base64:)?(646b313a|ZGsxO)' "$f" 2>/dev/null; then has_handles=1; fi
  if grep -Eiq '^(export +)?[A-Z0-9_]*(SECRET|SIGNING_KEY|ENCRYPTION_KEY|SESSION_PASSWORD)[A-Z0-9_]*=' "$f" 2>/dev/null; then has_secrets=1; fi
done
[ -f .doppelkey/manifest.json ] && has_handles=1

if [ "$has_handles" = 1 ]; then
  if command -v doppelkey >/dev/null 2>&1; then
    if [ -n "${CLAUDE_ENV_FILE:-}" ]; then
      doppelkey env --dir "$DIR" >> "$CLAUDE_ENV_FILE" 2>/dev/null
    fi
    echo "This project uses doppelkey. Values in .env that start with dk1:, 646b313a or ZGsxO (sometimes after whsec_) are handles, not broken secrets: never replace them or ask for real values. The real keys live in the doppelkey keeper; crypto made with a handle is done there. If a crypto call fails with a doppelkey error, run \"doppelkey doctor\". New secrets: ask the user to run \"doppelkey set NAME\"."
  else
    echo "This project's .env contains doppelkey handles, but the doppelkey CLI is not installed here. Ask the user to install it (https://github.com/KaiHongTan/doppelkey) before running the app."
  fi
elif [ "$has_secrets" = 1 ]; then
  echo "This project keeps signing or encryption secrets in .env files, readable by any tool you run. The doppelkey skill can help the user protect them (they run \"npx doppelkey init\" and review a preview first)."
fi
exit 0
