#!/usr/bin/env python3
"""Drive the real window to the four states shown in README.md and capture each one.
Started by tests/readme_screenshots.sh, which sets up the throwaway environment.

Usage: readme_screenshots_driver.py OUT_DIR
"""

import os
import subprocess
import sys
import traceback
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO / "frontend"))

import app  # noqa: E402
from gi.repository import Adw, Gio, GLib, Gtk  # noqa: E402

OUT = Path(sys.argv[1])
ID_PASS = os.environ["VS_ID_PASS"]
DROP_FILE = os.environ["VS_DROP_FILE"]
SETTLE = 800  # ms for dialogs and rows to finish animating

application = None
win = None
ok = True


def walk(widget):
    yield widget
    child = widget.get_first_child()
    while child:
        yield from walk(child)
        child = child.get_next_sibling()


def dialog():
    dlg = win.get_visible_dialog()
    assert dlg is not None, "expected a dialog"
    return dlg


def respond(label):
    """Click a button in the visible dialog, as a user would."""
    for w in walk(dialog()):
        if isinstance(w, Gtk.Button) and w.get_label() == label and w.is_sensitive():
            w.emit("clicked")
            return
    raise AssertionError(f"no enabled button labelled {label!r}")


def shot(name):
    OUT.mkdir(parents=True, exist_ok=True)
    subprocess.run(["import", "-window", "root", str(OUT / f"{name}.png")], check=True)
    print(f"shot  {name}", flush=True)


class Dropped:
    """Stands in for the Gdk.FileList a real drag delivers."""

    def __init__(self, path):
        self.path = path

    def get_files(self):
        return [Gio.File.new_for_path(self.path)]


def script():
    yield 1800

    # 1. Main view: contacts in the sidebar, a message being written.
    win.textview.get_buffer().set_text(
        "Hi Alice,\n\nThe signed contract is attached. The password for the shared "
        "vault is in the usual place.\n\n- C"
    )
    win.textview.grab_focus()
    yield SETTLE
    shot("main-view")

    # 2. Drag and drop: a file lands on the window and VaultSend asks what to do.
    win.textview.get_buffer().set_text("")
    win.on_file_dropped(None, Dropped(DROP_FILE), 0, 0)
    yield SETTLE
    shot("drag-and-drop")

    # 3. Select contacts: choosing Encrypt asks who may read it.
    respond("Encrypt")
    yield SETTLE
    checks = [w for w in walk(dialog()) if isinstance(w, Gtk.CheckButton) and w.is_sensitive()]
    for cb in checks[:2]:
        cb.set_active(True)
    yield SETTLE
    shot("select-contacts")
    respond("Cancel")
    yield SETTLE

    # 4. Vaults page: the demo vault, unlocked, folders open.
    win.vaults_toggle.emit("clicked")
    yield SETTLE
    rows = [w for w in walk(win.vault_list) if isinstance(w, Adw.ActionRow)]
    win.vault_list.select_row(rows[0])
    win.vault_list.emit("row-activated", rows[0])
    yield SETTLE
    win.vault_unlock()
    yield SETTLE
    next(w for w in walk(dialog()) if isinstance(w, Gtk.PasswordEntry)).set_text(ID_PASS)
    respond("Continue")
    for _ in range(300):
        if win.vault_entries:
            break
        yield 100
    assert win.vault_entries, "the vault never unlocked"
    win.expanded.update(["Documents", "Documents/Taxes", "Documents/Taxes/2025"])
    win._show_files(list(win.vault_entries.values()))
    yield SETTLE
    shot("vaults")


def run(gen):
    def step():
        global ok
        try:
            delay = next(gen)
        except StopIteration:
            application.quit()
            return False
        except Exception:
            traceback.print_exc()
            ok = False
            application.quit()
            return False
        GLib.timeout_add(delay, step)
        return False

    GLib.timeout_add(100, step)


def main():
    global application
    application = app.VaultSend()

    def started(_app):
        global win
        win = application.window
        run(script())

    application.connect_after("activate", started)
    Adw.init()
    application.run([])
    sys.exit(0 if ok else 1)


if __name__ == "__main__":
    main()
