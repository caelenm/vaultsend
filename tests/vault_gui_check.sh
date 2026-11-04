#!/usr/bin/env bash
# Run through the vault UI in the real window and capture screenshots (VAULTS_PLAN.md
# §5.3). Needs a display (WSLg, or Xvfb at 1012x690), a session bus, ImageMagick's
# `import`, xdotool and an in-memory $XDG_RUNTIME_DIR or /dev/shm. A fresh temp dir
# holds HOME, the XDG dirs and every test vault, so the real key and config are out of
# reach. Open is tested with a stand-in app, registered in those throwaway dirs as the
# default for text files, that records what it was given.
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

export VS_VIEWER_LOG="$T/viewer.log"
cat >"$T/viewer.sh" <<'EOF'
#!/bin/sh
cp "$1" "$VS_VIEWER_LOG.content"
printf '%s\n' "$1" >>"$VS_VIEWER_LOG"
EOF
chmod +x "$T/viewer.sh"
mkdir -p "$XDG_DATA_HOME/applications"
cat >"$XDG_DATA_HOME/applications/vs-test-viewer.desktop" <<EOF
[Desktop Entry]
Type=Application
Name=Test viewer
Exec=$T/viewer.sh %f
MimeType=text/plain;
EOF
printf '[Default Applications]\ntext/plain=vs-test-viewer.desktop\n' >"$XDG_CONFIG_HOME/mimeapps.list"

python3 "$ROOT/tests/vault_gui_driver.py" "$OUT" "$T/work"
echo "screenshots: $OUT"
