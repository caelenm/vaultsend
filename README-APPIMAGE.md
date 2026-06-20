# Building and using the VaultSend AppImage

## What's bundled, what isn't

This AppImage bundles the **Rust backend binary** and the **Python frontend
source**. It deliberately does **not** bundle GTK4, libadwaita, or PyGObject —
those come from your system. This is the standard, pragmatic approach for
GTK4/libadwaita AppImages: those libraries are heavy and version-sensitive to
bundle correctly (theming, icon themes, GSettings schemas), so the AppImage
ecosystem generally expects them on the host, the same way it expects a kernel
and an X11/Wayland session.

In practice this means: if you can run a normal GTK4/libadwaita app on your
system already (e.g. GNOME Text Editor, GNOME Calculator), VaultSend's
AppImage will work too. If not, install the same packages listed in the main
README:

```sh
# Debian / Ubuntu
sudo apt install python3-gi gir1.2-gtk-4.0 gir1.2-adw-1
# Fedora
sudo dnf install python3-gobject gtk4 libadwaita
# Arch
sudo pacman -S python-gobject gtk4 libadwaita
```

## Build it

On a real Linux machine (this can't be done in a sandboxed/offline build
environment — it needs to fetch `appimagetool`):

```sh
cd appimage
./build-appimage.sh
```

This will:
1. Build the backend if it isn't already built.
2. Copy the latest backend binary + frontend source into `VaultSend.AppDir`.
3. Download `appimagetool` if not already present (cached as `./appimagetool`).
4. Produce `VaultSend-x86_64.AppImage` in this directory.

Re-run it any time after changing the backend or frontend — it always
refreshes the bundled copies before packing.

## Run it

```sh
chmod +x VaultSend-x86_64.AppImage
./VaultSend-x86_64.AppImage
```

If your system doesn't have FUSE (some minimal distros, containers, or
Wayland-only setups without `fuse2`), run it with:

```sh
./VaultSend-x86_64.AppImage --appimage-extract-and-run
```

## Troubleshooting: I double-click it and nothing happens

A GUI launch (from a file manager) hides the app's stderr, so any startup
error fails silently with no window. Run it from a terminal to see what went
wrong:

```sh
./VaultSend-x86_64.AppImage          # or add --appimage-extract-and-run
```

The most common cause is a **too-old toolkit**. VaultSend needs GTK ≥ 4.10 and
libadwaita ≥ 1.5; if they're present but older, the app prints a one-line
requirement notice and exits. `AppRun` only checks that the bindings are
*installed*, not their version, so this check happens in `app.py` itself.
On distributions that ship older versions (e.g. Ubuntu 22.04 has GTK 4.6 /
libadwaita 1.1), upgrade the distro or run from a newer environment.

## What's inside (for auditing)

```
VaultSend.AppDir/
├── AppRun                          # entry point: sets VAULTSEND_BACKEND, checks
│                                    #   for GTK4/libadwaita, then runs app.py
├── vaultsend.desktop                # also copied to usr/share/applications/
├── vaultsend.png                    # also copied to usr/share/icons/...
└── usr/
    ├── bin/vaultsend-backend        # the Rust binary — only dynamic deps are
    │                                #   libc and libgcc, present everywhere
    └── share/vaultsend/frontend/app.py
```

`AppRun` is ~25 lines and is the entire trust boundary for what the AppImage
does beyond what's documented in the main README: it sets one environment
variable and execs `python3` against the bundled `app.py`.
