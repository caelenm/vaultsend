#!/bin/sh
# Build VaultSend-x86_64.AppImage.
#
# This directory keeps NO copy of the application code. Everything that goes
# into the AppImage is assembled fresh, at build time, from the real sources:
#
#     backend binary   <-  ../backend/target/release/vaultsend-backend
#     frontend source  <-  ../frontend/app.py
#     static assets    <-  ./AppDir.template/   (AppRun, .desktop, icon)
#
# The packaged tree is staged under ./build/ (git-ignored) and rebuilt from
# scratch on every run, so it can never drift out of sync with the sources the
# way a committed copy inside the AppDir would. The only things tracked in this
# folder are this script, the static template, and the docs.
#
# Run on a real Linux machine with network access (it fetches appimagetool on
# first run and caches it locally as ./appimagetool).
set -eu

HERE="$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)"
cd "$HERE"

# --- Sources: the single source of truth. Nothing here is a copy. -----------
TEMPLATE="AppDir.template"
BACKEND_SRC="../backend/target/release/vaultsend-backend"
FRONTEND_SRC="../frontend/app.py"

# --- Staging: disposable build output, safe to delete at any time. ----------
APPDIR="build/VaultSend.AppDir"
OUTPUT="VaultSend-x86_64.AppImage"

# 1. Build the backend. cargo is incremental, so this is a near-instant no-op
#    when nothing changed; running it unconditionally guarantees the bundled
#    binary matches the current source rather than some older target/ artifact.
echo "Building backend..."
( cd ../backend && cargo build --release )

# 2. Verify every source exists before staging anything.
[ -f "$BACKEND_SRC" ]  || { echo "error: backend binary not found at $BACKEND_SRC" >&2; exit 1; }
[ -f "$FRONTEND_SRC" ] || { echo "error: frontend not found at $FRONTEND_SRC" >&2; exit 1; }
[ -d "$TEMPLATE" ]     || { echo "error: AppDir template not found at $TEMPLATE" >&2; exit 1; }

# 3. Assemble a fresh AppDir from scratch. Wiping it first guarantees no stale
#    file from a previous build survives into the package.
echo "Staging AppDir from sources..."
rm -rf "$APPDIR"
mkdir -p "$APPDIR/usr/bin" \
         "$APPDIR/usr/share/vaultsend/frontend" \
         "$APPDIR/usr/share/applications" \
         "$APPDIR/usr/share/icons/hicolor/256x256/apps"

# 3a. Static assets from the committed template (one canonical copy of each).
cp "$TEMPLATE/AppRun"            "$APPDIR/AppRun"
cp "$TEMPLATE/vaultsend.desktop" "$APPDIR/vaultsend.desktop"
cp "$TEMPLATE/vaultsend.png"     "$APPDIR/vaultsend.png"
chmod +x "$APPDIR/AppRun"
# appimagetool requires a top-level .desktop + icon; these usr/share copies are
# the conventional locations used for desktop integration after install, and
# .DirIcon is what appimagetool uses as the AppImage's own icon. All are placed
# from the same single template asset, so there is no duplication to maintain.
cp "$TEMPLATE/vaultsend.desktop" "$APPDIR/usr/share/applications/vaultsend.desktop"
cp "$TEMPLATE/vaultsend.png"     "$APPDIR/usr/share/icons/hicolor/256x256/apps/vaultsend.png"
cp "$TEMPLATE/vaultsend.png"     "$APPDIR/.DirIcon"

# 3b. Application code, pulled straight from the project. Never committed here.
cp "$BACKEND_SRC"  "$APPDIR/usr/bin/vaultsend-backend"
chmod +x "$APPDIR/usr/bin/vaultsend-backend"
cp "$FRONTEND_SRC" "$APPDIR/usr/share/vaultsend/frontend/app.py"

# 4. Fetch appimagetool if we don't have it (cached in ./ for reuse).
#    Pinned to a tagged release and checked against its SHA-256: this binary is
#    executed by install.sh's `curl | sh` path, so an unpinned "continuous"
#    download would run whatever that URL served on the day. To upgrade, change
#    both values together.
APPIMAGETOOL_VERSION="1.9.1"
APPIMAGETOOL_SHA256="ed4ce84f0d9caff66f50bcca6ff6f35aae54ce8135408b3fa33abfc3cb384eb0"

sha256_of() {
    if command -v sha256sum >/dev/null 2>&1; then sha256sum "$1" | cut -d' ' -f1
    else shasum -a 256 "$1" | cut -d' ' -f1; fi
}

if [ ! -x ./appimagetool ] || [ "$(sha256_of ./appimagetool)" != "$APPIMAGETOOL_SHA256" ]; then
    echo "Downloading appimagetool $APPIMAGETOOL_VERSION..."
    rm -f appimagetool appimagetool.download
    curl -fL -o appimagetool.download \
        "https://github.com/AppImage/appimagetool/releases/download/$APPIMAGETOOL_VERSION/appimagetool-x86_64.AppImage"
    got="$(sha256_of appimagetool.download)"
    if [ "$got" != "$APPIMAGETOOL_SHA256" ]; then
        rm -f appimagetool.download
        echo "error: appimagetool checksum mismatch (expected $APPIMAGETOOL_SHA256, got $got)" >&2
        exit 1
    fi
    mv appimagetool.download appimagetool
    chmod +x appimagetool
fi

# 5. Pack. appimagetool needs FUSE; fall back to extract-and-run without it.
echo "Packing..."
ARCH=x86_64 ./appimagetool "$APPDIR" "$OUTPUT" \
    || ARCH=x86_64 ./appimagetool --appimage-extract-and-run "$APPDIR" "$OUTPUT"

chmod +x "$OUTPUT"
echo "Built: $HERE/$OUTPUT"
