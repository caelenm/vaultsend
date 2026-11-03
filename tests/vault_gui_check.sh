#!/usr/bin/env bash
# Run through the vault UI in the real window and capture screenshots (VAULTS_PLAN.md
# §5.3). Needs a display (WSLg, or Xvfb at 880x600), a session bus, ImageMagick's
# `import` and xdotool. A fresh temp dir holds HOME, the XDG dirs and every test
# vault, so the real key and config are out of reach.
#
#   tests/vault_gui_check.sh [SCREENSHOT_DIR]
set -euo pipefail

ROOT=$(cd "$(dirname "$0")/.." && pwd)
OUT=${1:-$(mktemp -d /tmp/vaultsend-shots-XXXXXX)}
BIN=${VAULTSEND_BACKEND:-$ROOT/backend/target/release/vaultsend-backend}
: "${DISPLAY:?needs a display: run under WSLg or Xvfb}"

T=$(mktemp -d /tmp/vaultsend-gui-XXXXXX)
trap 'rm -rf "$T"' EXIT
export HOME="$T/home" XDG_DATA_HOME="$T/data" XDG_CONFIG_HOME="$T/config"
export VAULTSEND_BACKEND=$BIN PYTHONDONTWRITEBYTECODE=1
export VS_ID_PASS='gui test identity passphrase'
mkdir -p "$HOME" "$XDG_DATA_HOME" "$XDG_CONFIG_HOME/vaultsend"

"$BIN" keygen --pass-fd 3 3<<<"$VS_ID_PASS" >/dev/null
a=$(XDG_DATA_HOME="$T/a" "$BIN" keygen --pass-fd 3 3<<<"$VS_ID_PASS")
b=$(XDG_DATA_HOME="$T/b" "$BIN" keygen --pass-fd 3 3<<<"$VS_ID_PASS")
printf '[{"name":"Test Contact A","pubkey":"%s"},{"name":"Test Contact B","pubkey":"%s"}]' "$a" "$b" \
    >"$XDG_CONFIG_HOME/vaultsend/contacts.json"

python3 "$ROOT/tests/vault_gui_driver.py" "$OUT" "$T/work"
echo "screenshots: $OUT"
