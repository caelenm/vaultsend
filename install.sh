#!/bin/sh
# install.sh — build & install VaultSend (https://github.com/caelenm/vaultsend)
# POSIX sh, distro-independent. Run: sh install.sh   (use SKIP_DEPS=1 to skip deps)
set -eu

REPO=https://github.com/caelenm/vaultsend
BIN="$HOME/.local/bin"; APP="$HOME/.local/share/applications"; ICO="$HOME/.local/share/icons/hicolor/256x256/apps"
say() { printf '\033[1;34m[vaultsend]\033[0m %s\n' "$1"; }
have() { command -v "$1" >/dev/null 2>&1; }
SUDO=""; [ "$(id -u)" -eq 0 ] || { have sudo && SUDO=sudo; }

# 1. deps — pick the first package manager we find
if [ "${SKIP_DEPS:-0}" != 1 ]; then
  if   have apt;    then $SUDO apt-get update && $SUDO apt-get install -y python3-gi gir1.2-gtk-4.0 gir1.2-adw-1 cargo git
  elif have dnf;    then $SUDO dnf install -y python3-gobject gtk4 libadwaita cargo git
  elif have pacman; then $SUDO pacman -Sy --needed --noconfirm python-gobject gtk4 libadwaita cargo git
  elif have zypper; then $SUDO zypper -n install python3-gobject gtk4 libadwaita-devel cargo git
  elif have apk;    then $SUDO apk add py3-gobject3 gtk4.0 libadwaita cargo git
  else say "No known package manager — install GTK4/libadwaita/PyGObject/cargo yourself, then re-run with SKIP_DEPS=1."; fi
fi

# 2. fetch source (git, else curl tarball)
DIR=$(mktemp -d); trap 'rm -rf "$DIR"' EXIT
if have git; then git clone --depth 1 "$REPO" "$DIR/src"
else mkdir "$DIR/src"; curl -fsSL "$REPO/archive/refs/heads/main.tar.gz" | tar xz --strip-components=1 -C "$DIR/src"; fi

# 3. build
say "Building AppImage..."; ( cd "$DIR/src/appimage" && sh build-appimage.sh )
IMG=$(find "$DIR/src/appimage" -maxdepth 1 -name 'VaultSend-*.AppImage' | head -n1)
[ -n "$IMG" ] || { say "No AppImage produced — see build output above."; exit 1; }

# 4. install as a normal app
mkdir -p "$BIN" "$APP" "$ICO"
cp "$IMG" "$BIN/VaultSend.AppImage"; chmod +x "$BIN/VaultSend.AppImage"; ln -sf "$BIN/VaultSend.AppImage" "$BIN/vaultsend"
( cd "$DIR" && "$BIN/VaultSend.AppImage" --appimage-extract >/dev/null 2>&1 ) || true
D=$(find "$DIR/squashfs-root" -maxdepth 1 -name '*.desktop' 2>/dev/null | head -n1)
I=$(find "$DIR/squashfs-root" -maxdepth 1 \( -name '*.png' -o -name '*.svg' \) 2>/dev/null | head -n1)
[ -n "${I:-}" ] && cp "$I" "$ICO/vaultsend.${I##*.}"
[ -n "${D:-}" ] && sed "s#^Exec=.*#Exec=$BIN/VaultSend.AppImage#; s#^Icon=.*#Icon=vaultsend#" "$D" > "$APP/vaultsend.desktop"
have update-desktop-database && update-desktop-database "$APP" >/dev/null 2>&1 || true

case ":$PATH:" in *":$BIN:"*) ;; *) say "Add to PATH: export PATH=\"\$HOME/.local/bin:\$PATH\"";; esac
say "Done. Run: vaultsend  (or launch 'VaultSend' from your app menu)"
