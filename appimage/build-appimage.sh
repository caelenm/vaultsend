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
# Run on a real Linux machine with network access (it fetches appimagetool and
# the AppImage runtime on first run, both pinned and hash-checked, and caches
# them locally as ./appimagetool and ./runtime-x86_64).
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

# 4. Fetch appimagetool and the AppImage runtime (cached in ./ for reuse).
#    Both are pinned to a tagged release and checked against their SHA-256:
#    appimagetool is executed by install.sh's `curl | sh` path, and the runtime
#    becomes the executable header of the AppImage we ship, so neither may be
#    whatever a "continuous" URL happens to serve on the day. Passing the runtime
#    with --runtime-file also stops appimagetool from downloading its own
#    unpinned copy at pack time. To upgrade either, change its version and hash
#    together.
APPIMAGETOOL_VERSION="1.9.1"
APPIMAGETOOL_SHA256="ed4ce84f0d9caff66f50bcca6ff6f35aae54ce8135408b3fa33abfc3cb384eb0"
RUNTIME_VERSION="20251108"
RUNTIME_SHA256="2fca8b443c92510f1483a883f60061ad09b46b978b2631c807cd873a47ec260d"

sha256_of() {
    if command -v sha256sum >/dev/null 2>&1; then sha256sum "$1" | cut -d' ' -f1
    else shasum -a 256 "$1" | cut -d' ' -f1; fi
}

# fetch_pinned FILE SHA256 URL: download URL to FILE unless a cached FILE
# already has the expected hash. A mismatch aborts the build.
fetch_pinned() {
    if [ -f "$1" ] && [ "$(sha256_of "$1")" = "$2" ]; then return 0; fi
    echo "Downloading $1 from $3..."
    rm -f "$1" "$1.download"
    curl -fL -o "$1.download" "$3"
    got="$(sha256_of "$1.download")"
    if [ "$got" != "$2" ]; then
        rm -f "$1.download"
        echo "error: $1 checksum mismatch (expected $2, got $got)" >&2
        exit 1
    fi
    mv "$1.download" "$1"
}

fetch_pinned appimagetool "$APPIMAGETOOL_SHA256" \
    "https://github.com/AppImage/appimagetool/releases/download/$APPIMAGETOOL_VERSION/appimagetool-x86_64.AppImage"
fetch_pinned runtime-x86_64 "$RUNTIME_SHA256" \
    "https://github.com/AppImage/type2-runtime/releases/download/$RUNTIME_VERSION/runtime-x86_64"
chmod +x appimagetool

# 5. Pack. appimagetool needs FUSE; fall back to extract-and-run without it.
echo "Packing..."
ARCH=x86_64 ./appimagetool --runtime-file runtime-x86_64 "$APPDIR" "$OUTPUT" \
    || ARCH=x86_64 ./appimagetool --appimage-extract-and-run --runtime-file runtime-x86_64 "$APPDIR" "$OUTPUT"

chmod +x "$OUTPUT"
echo "Built: $HERE/$OUTPUT"
