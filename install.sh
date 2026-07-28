#!/bin/sh
# install.sh — build, install & update VaultSend (https://github.com/caelenm/vaultsend)
# POSIX sh, distro-independent.
#
#   install / update :  curl -fsSL https://raw.githubusercontent.com/caelenm/vaultsend/refs/heads/main/install.sh | bash
#   uninstall        :  curl -fsSL .../install.sh | bash -s -- --uninstall
#   from a checkout  :  sh install.sh            (SKIP_DEPS=1 to skip the package step)
#
# Re-running this is the supported way to update. Any previously installed copy
# is removed first, so a stale AppImage, symlink, launcher or icon can never be
# left behind next to the new one.
#
# ---------------------------------------------------------------------------
# YOUR KEY AND CONTACTS ARE NEVER TOUCHED.
#
# This script only ever removes the four things it installs, all of which live
# under ~/.local/bin and ~/.local/share/{applications,icons}:
#
#     ~/.local/bin/VaultSend.AppImage          the app
#     ~/.local/bin/vaultsend                   symlink to it
#     ~/.local/share/applications/*.desktop    launcher (only ones pointing at it)
#     ~/.local/share/icons/.../vaultsend.*     icon
#
# Your data lives somewhere else entirely and is deliberately absent from every
# removal below — note in particular that ~/.local/share/vaultsend/ (the
# directory holding identity.age and pubkey) is NOT the same path as
# ~/.local/share/applications or ~/.local/share/icons, and is never a target:
#
#     ~/.local/share/vaultsend/identity.age    your passphrase-encrypted key
#     ~/.local/share/vaultsend/pubkey          your public key
#     ~/.config/vaultsend/contacts.json        your contacts
#
# (or the XDG_DATA_HOME / XDG_CONFIG_HOME equivalents). Uninstalling leaves all
# of it in place, so reinstalling later picks your identity back up with nothing
# to import. To remove those too, delete them yourself — but back up
# identity.age first, because it cannot be regenerated.
# ---------------------------------------------------------------------------
set -eu

REPO=https://github.com/caelenm/vaultsend

# Every path below derives from $HOME, so refuse to guess if it is not set:
# an empty $HOME would turn "$HOME/.local/bin" into an absolute system path.
[ -n "${HOME:-}" ] || { echo "install.sh: HOME is not set; refusing to guess where to install." >&2; exit 1; }

BIN="$HOME/.local/bin"
APP="$HOME/.local/share/applications"
ICONS="$HOME/.local/share/icons/hicolor"
ICO="$ICONS/256x256/apps"

say()  { printf '\033[1;34m[vaultsend]\033[0m %s\n' "$1"; }
warn() { printf '\033[1;33m[vaultsend]\033[0m %s\n' "$1" >&2; }
have() { command -v "$1" >/dev/null 2>&1; }

SUDO=""; if [ "$(id -u)" -ne 0 ] && have sudo; then SUDO=sudo; fi

MODE=install
for a in "$@"; do
  case "$a" in
    --uninstall|--remove) MODE=uninstall ;;
    -h|--help) sed -n '2,9p' "$0" 2>/dev/null || echo "usage: install.sh [--uninstall]"; exit 0 ;;
    *) warn "ignoring unknown option: $a" ;;
  esac
done

# ---------------------------------------------------------------------------
# Remove a previously installed copy.
#
# Everything here is matched narrowly and by name: no wildcard deletion of a
# directory, no rm -rf, and nothing outside the three install locations. If
# nothing is installed this is a silent no-op, so it is safe to run first on a
# clean machine.
# ---------------------------------------------------------------------------
remove_installed() {
  found=0

  # 1. The AppImage and its symlink. VaultSend-x86_64.AppImage is the name the
  #    build produces, in case a past install copied it across verbatim; remove
  #    it too so an update cannot leave two copies in PATH. -L catches a symlink
  #    whose target is already gone.
  for f in "$BIN/VaultSend.AppImage" "$BIN/VaultSend-x86_64.AppImage" "$BIN/vaultsend"; do
    if [ -e "$f" ] || [ -L "$f" ]; then
      rm -f "$f"
      say "removed $f"
      found=1
    fi
  done

  # 2. Launchers. Matched on what they point at rather than on their filename,
  #    which also catches entries created by hand or by a pinning tool. Only
  #    files directly inside the user's own applications directory are even
  #    looked at, and only ones whose Exec line names a VaultSend AppImage or
  #    the vaultsend symlink are removed.
  if [ -d "$APP" ]; then
    for f in "$APP"/*.desktop; do
      [ -f "$f" ] || continue
      if grep -qs -e '^Exec=.*[Vv]ault[Ss]end.*\.AppImage' \
                  -e "^Exec=.*$BIN/vaultsend\([ ]\|\$\)" "$f"; then
        rm -f "$f"
        say "removed launcher $f"
        found=1
      fi
    done
  fi

  # 3. Icons, by exact filename, at whatever size a past version installed.
  if [ -d "$ICONS" ]; then
    for f in "$ICONS"/*/apps/vaultsend.png "$ICONS"/*/apps/vaultsend.svg "$ICONS"/*/apps/vaultsend.xpm; do
      if [ -f "$f" ]; then
        rm -f "$f"
        say "removed icon $f"
        found=1
      fi
    done
  fi

  [ "$found" -eq 1 ]
}

refresh_caches() {
  if have update-desktop-database; then update-desktop-database "$APP" >/dev/null 2>&1 || true; fi
  if have gtk-update-icon-cache; then gtk-update-icon-cache -f -t "$ICONS" >/dev/null 2>&1 || true; fi
}

show_data_paths() {
  say "Your key and contacts were not touched:"
  printf '    %s\n' "${XDG_DATA_HOME:-$HOME/.local/share}/vaultsend/identity.age"
  printf '    %s\n' "${XDG_CONFIG_HOME:-$HOME/.config}/vaultsend/contacts.json"
}

# ---------------------------------------------------------------------------
# Uninstall-only mode.
# ---------------------------------------------------------------------------
if [ "$MODE" = uninstall ]; then
  if remove_installed; then
    refresh_caches
    say "VaultSend has been uninstalled."
  else
    say "VaultSend does not appear to be installed; nothing to remove."
  fi
  show_data_paths
  exit 0
fi

# ---------------------------------------------------------------------------
# 1. Dependencies — pick the first package manager we find.
# ---------------------------------------------------------------------------
if [ "${SKIP_DEPS:-0}" != 1 ]; then
  if   have apt;    then $SUDO apt-get update && $SUDO apt-get install -y python3-gi gir1.2-gtk-4.0 gir1.2-adw-1 cargo git
  elif have dnf;    then $SUDO dnf install -y python3-gobject gtk4 libadwaita cargo git
  elif have pacman; then $SUDO pacman -Sy --needed --noconfirm python-gobject gtk4 libadwaita cargo git
  elif have zypper; then $SUDO zypper -n install python3-gobject gtk4 libadwaita-devel cargo git
  elif have apk;    then $SUDO apk add py3-gobject3 gtk4.0 libadwaita cargo git
  else say "No known package manager — install GTK4/libadwaita/PyGObject/cargo yourself, then re-run with SKIP_DEPS=1."; fi
fi

# ---------------------------------------------------------------------------
# 2. Fetch source (git, else curl tarball).
# ---------------------------------------------------------------------------
DIR=$(mktemp -d); trap 'rm -rf "$DIR"' EXIT
if have git; then git clone --depth 1 "$REPO" "$DIR/src"
else mkdir "$DIR/src"; curl -fsSL "$REPO/archive/refs/heads/main.tar.gz" | tar xz --strip-components=1 -C "$DIR/src"; fi

# ---------------------------------------------------------------------------
# 3. Build. Done BEFORE removing the installed copy, so a build failure leaves
#    the working version you already had in place rather than nothing at all.
# ---------------------------------------------------------------------------
say "Building AppImage..."
( cd "$DIR/src/appimage" && sh build-appimage.sh )
IMG=$(find "$DIR/src/appimage" -maxdepth 1 -name 'VaultSend-*.AppImage' | head -n1)
[ -n "$IMG" ] || { warn "No AppImage produced — see build output above."; exit 1; }

# ---------------------------------------------------------------------------
# 4. Remove the old install, now that we have something to replace it with.
# ---------------------------------------------------------------------------
if pgrep -f 'VaultSend.*\.AppImage' >/dev/null 2>&1; then
  warn "VaultSend appears to be running. The update will still complete, but"
  warn "close and reopen the app afterwards to be running the new version."
fi

if remove_installed; then
  say "Removed the previous installation."
  UPDATING=1
else
  UPDATING=0
fi

# ---------------------------------------------------------------------------
# 5. Install.
# ---------------------------------------------------------------------------
mkdir -p "$BIN" "$APP" "$ICO"
cp "$IMG" "$BIN/VaultSend.AppImage"
chmod +x "$BIN/VaultSend.AppImage"
ln -sf "$BIN/VaultSend.AppImage" "$BIN/vaultsend"

( cd "$DIR" && "$BIN/VaultSend.AppImage" --appimage-extract >/dev/null 2>&1 ) || true
D=$(find "$DIR/squashfs-root" -maxdepth 1 -name '*.desktop' 2>/dev/null | head -n1)
I=$(find "$DIR/squashfs-root" -maxdepth 1 \( -name '*.png' -o -name '*.svg' \) 2>/dev/null | head -n1)
if [ -n "${I:-}" ]; then cp "$I" "$ICO/vaultsend.${I##*.}"; fi
if [ -n "${D:-}" ]; then
  sed "s#^Exec=.*#Exec=$BIN/VaultSend.AppImage#; s#^Icon=.*#Icon=vaultsend#" "$D" > "$APP/vaultsend.desktop"
fi
refresh_caches

case ":$PATH:" in *":$BIN:"*) ;; *) say "Add to PATH: export PATH=\"\$HOME/.local/bin:\$PATH\"";; esac
if [ "$UPDATING" -eq 1 ]; then say "Updated. Run: vaultsend  (or launch 'VaultSend' from your app menu)"
else say "Done. Run: vaultsend  (or launch 'VaultSend' from your app menu)"; fi
show_data_paths
