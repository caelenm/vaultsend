# Building and using the VaultSend AppImage

## How this directory is organized

This folder keeps **no copy of the application code**. The AppImage is assembled
fresh from the real project sources every time you build:

```
appimage/
├── build-appimage.sh      # the build script
├── AppDir.template/        # static assets only — AppRun, .desktop, icon
│   ├── AppRun
│   ├── vaultsend.desktop
│   └── vaultsend.png
├── README-APPIMAGE.md
└── .gitignore              # ignores build/, appimagetool, *.AppImage

build/VaultSend.AppDir/      # (generated, git-ignored) staged at build time
```

At build time the script wipes `build/VaultSend.AppDir`, recreates it from
scratch, and copies in:

- the backend binary from `../backend/target/release/vaultsend-backend`,
- the frontend source from `../frontend/app.py`,
- the static assets from `AppDir.template/`.

Because the packaged tree is rebuilt from the sources on every run, it can never
drift out of sync the way a committed copy inside the AppDir would. `app.py` and
the backend binary live in exactly one place each (`frontend/` and `backend/`);
this directory only references them.

## What's bundled, what isn't

The AppImage bundles the **Rust backend binary** and the **Python frontend
source**. It deliberately does **not** bundle GTK4, libadwaita, or PyGObject —
those come from your system. This is the standard, pragmatic approach for
GTK4/libadwaita AppImages: those libraries are heavy and version-sensitive to
bundle correctly (theming, icon themes, GSettings schemas), so the AppImage
ecosystem generally expects them on the host, the same way it expects a kernel
and an X11/Wayland session.

In practice this means: if you can run a normal GTK4/libadwaita app on your
system already (e.g. GNOME Text Editor, GNOME Calculator), VaultSend's AppImage
will work too. If not, install the same packages listed in the main README:

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
1. Build the backend (`cargo build --release`; incremental, so it's a no-op
   when nothing changed, and it guarantees the bundled binary is current).
2. Stage a fresh `build/VaultSend.AppDir` from the backend binary, the frontend
   source, and `AppDir.template/`.
3. Download `appimagetool` if not already present (cached as `./appimagetool`).
4. Produce `VaultSend-x86_64.AppImage` in this directory.

You never need to edit anything inside `build/` — it is regenerated each run.
Edit the real sources in `../backend` and `../frontend` instead.

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

If launching produces no window, run it from a terminal rather than
double-clicking — a GUI launch hides stderr, and the most common cause is a
GTK/libadwaita version below VaultSend's floor (≥ 4.10 / ≥ 1.5), which the app
detects and reports as a one-line message.

## What's inside the built AppImage (for auditing)

```
VaultSend.AppDir/
├── AppRun                          # entry point: sets VAULTSEND_BACKEND, checks
│                                    #   for GTK4/libadwaita, then runs app.py
├── vaultsend.desktop                # also copied to usr/share/applications/
├── vaultsend.png / .DirIcon         # also copied to usr/share/icons/...
└── usr/
    ├── bin/vaultsend-backend        # the Rust binary — only dynamic deps are
    │                                #   libc and libgcc, present everywhere
    └── share/vaultsend/frontend/app.py
```

`AppRun` is the entire trust boundary for what the AppImage does beyond what's
documented in the main README: it sets one environment variable and execs
`python3` against the bundled `app.py`.
