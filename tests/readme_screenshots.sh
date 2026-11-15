#!/usr/bin/env bash
# Regenerate the screenshots at the top of README.md from the real app, with throwaway
# keys, contacts and a demo vault. Your own key and config are never touched: a fresh
# temp dir holds HOME and the XDG dirs.
#
# Needs: the release backend (make build), GTK 4 + libadwaita Python bindings,
# ImageMagick's `import`, and Xvfb (or an existing $DISPLAY, e.g. WSLg).
#
#   tests/readme_screenshots.sh [OUT_DIR]      # default: docs/screenshots
set -euo pipefail

ROOT=$(cd "$(dirname "$0")/.." && pwd)
OUT=$(realpath -m "${1:-$ROOT/docs/screenshots}")
BIN=${VAULTSEND_BACKEND:-$ROOT/backend/target/release/vaultsend-backend}
[ -x "$BIN" ] || { echo "no backend at $BIN: run 'make build' first" >&2; exit 1; }

T=$(mktemp -d /tmp/vaultsend-shots-XXXXXX)
trap 'rm -rf "$T"' EXIT
export HOME="$T/home" XDG_DATA_HOME="$T/data" XDG_CONFIG_HOME="$T/config"
export VAULTSEND_BACKEND=$BIN PYTHONDONTWRITEBYTECODE=1 GTK_A11Y=none
unset GTK_THEME  # it would override libadwaita's own stylesheet
export VS_ID_PASS='readme screenshot passphrase'
mkdir -p "$HOME" "$XDG_DATA_HOME" "$XDG_CONFIG_HOME/vaultsend"

# Your key, and three contacts with real (throwaway) public keys.
"$BIN" keygen --pass-fd 3 3<<<"$VS_ID_PASS" >/dev/null
contact() { XDG_DATA_HOME="$T/$1" "$BIN" keygen --pass-fd 3 3<<<"$VS_ID_PASS"; }
printf '[{"name":"Alice Chen","pubkey":"%s"},{"name":"Bob Martinez","pubkey":"%s"},{"name":"Priya Shah","pubkey":"%s"}]' \
    "$(contact a)" "$(contact b)" "$(contact c)" >"$XDG_CONFIG_HOME/vaultsend/contacts.json"

# A demo vault, sealed with your key, holding a small folder tree.
SRC="$T/src/Documents"
mkdir -p "$SRC/Taxes/2025" "$SRC/Photos" "$SRC/Medical"
filler() { head -c "$2" /dev/urandom >"$1"; }  # realistic sizes in the file list
filler "$SRC/Taxes/2025/return.pdf" 196400
filler "$SRC/Taxes/2025/receipts.csv" 18230
filler "$SRC/Taxes/notes.txt" 2140
filler "$SRC/Photos/passport-scan.jpg" 1843200
filler "$SRC/Medical/vaccination-record.pdf" 88100
filler "$T/src/recovery-codes.txt" 412
VAULT="$XDG_DATA_HOME/vaultsend/vaults/Personal.vsvault"
mkdir -p "$(dirname "$VAULT")"
"$BIN" vault-create --dir "$VAULT" --mode self --pass-fd 3 3<<<"$VS_ID_PASS" >/dev/null
"$BIN" vault-add --dir "$VAULT" --pass-fd 3 --src "$SRC" --src "$T/src/recovery-codes.txt" 3<<<"$VS_ID_PASS" >/dev/null
printf '[{"name":"Personal","path":"%s","mode":"self","last_generation":0}]' "$VAULT" \
    >"$XDG_CONFIG_HOME/vaultsend/vaults.json"

# A file to "drop" on the window.
export VS_DROP_FILE="$T/Q3-financials.pdf"
printf 'demo\n' >"$VS_DROP_FILE"

run=(python3 "$ROOT/tests/readme_screenshots_driver.py" "$OUT")
command -v dbus-run-session >/dev/null && run=(dbus-run-session -- "${run[@]}")
if [ -n "${DISPLAY:-}" ]; then
    "${run[@]}"
else
    xvfb-run -a -s '-screen 0 1012x690x24' "${run[@]}"
fi
echo "screenshots: $OUT"
