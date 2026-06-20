#!/bin/sh
# Builds VaultSend-x86_64.AppImage from VaultSend.AppDir.
#
# Run this on a real Linux machine with network access (it downloads
# appimagetool on first run if not already present). Re-run any time after
# rebuilding the backend or editing the frontend — it just re-copies the
# latest binary/source into the AppDir and re-packs.
set -e

HERE="$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)"
cd "$HERE"

APPDIR="VaultSend.AppDir"
BACKEND_SRC="../backend/target/release/vaultsend-backend"
FRONTEND_SRC="../frontend/app.py"

# 1. Make sure the backend is built.
if [ ! -f "$BACKEND_SRC" ]; then
    echo "Building backend..."
    (cd ../backend && cargo build --release)
fi

# 2. Refresh bundled copies so the AppImage always reflects the current source.
cp "$BACKEND_SRC" "$APPDIR/usr/bin/vaultsend-backend"
chmod +x "$APPDIR/usr/bin/vaultsend-backend"
cp "$FRONTEND_SRC" "$APPDIR/usr/share/vaultsend/frontend/app.py"

# 3. Get appimagetool if we don't have it.
if [ ! -x ./appimagetool ]; then
    echo "Downloading appimagetool..."
    curl -L -o appimagetool \
        "https://github.com/AppImage/appimagetool/releases/download/continuous/appimagetool-x86_64.AppImage"
    chmod +x appimagetool
fi

# 4. Pack it. (appimagetool needs FUSE or --appimage-extract-and-run as a fallback.)
ARCH=x86_64 ./appimagetool "$APPDIR" VaultSend-x86_64.AppImage \
    || ARCH=x86_64 ./appimagetool --appimage-extract-and-run "$APPDIR" VaultSend-x86_64.AppImage

chmod +x VaultSend-x86_64.AppImage
echo "Built: $(pwd)/VaultSend-x86_64.AppImage"
