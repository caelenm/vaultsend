#!/usr/bin/env python3
"""Run through the vault UI in the real window: real buttons, real dialogs, the real
backend, and throwaway data. Takes the screenshots in VAULTS_PLAN.md §5.3 on the way.
Started by tests/vault_gui_check.sh, which sets up the throwaway environment.

Usage: vault_gui_driver.py SCREENSHOT_DIR WORK_DIR
"""

import json
import os
import shutil
import subprocess
import sys
import traceback
import warnings
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO / "frontend"))

import app  # noqa: E402
import gi  # noqa: E402

gi.require_version("Graphene", "1.0")
from gi.repository import Adw, Gio, GLib, Graphene, Gtk  # noqa: E402

# The app uses Gtk.FileDialog; only this driver reaches into the chooser it opens.
warnings.filterwarnings("ignore", category=DeprecationWarning)

SHOTS = Path(sys.argv[1])
WORK = Path(sys.argv[2])
ID_PASS = os.environ["VS_ID_PASS"]
VAULT_PASS = "gui test vault password"
VIEWER_LOG = Path(os.environ["VS_VIEWER_LOG"])
assert app.memory_folder(), "needs an in-memory $XDG_RUNTIME_DIR or /dev/shm"
STALE_COPY = Path(app.memory_folder(), app.OPEN_PREFIX + "left-by-a-crash")

SETTLE = 700  # ms for dialogs and rows to finish animating
passed = 0
failed = 0
application = None
win = None
toasts = []  # the text of every toast shown so far


def watch_toasts():
    """Record toasts, and dismiss them shortly after. libadwaita pauses a toast's
    timeout while the window is unfocused, and without a window manager it always is,
    so they would otherwise pile up over every screenshot."""
    real_add = win.toasts.add_toast

    def add(toast):
        toasts.append(toast.get_title())
        real_add(toast)
        GLib.timeout_add(1000, lambda: toast.dismiss() or False)

    win.toasts.add_toast = add


def check(condition, what):
    global passed, failed
    if condition:
        passed += 1
        print(f"ok    {what}", flush=True)
    else:
        failed += 1
        print(f"FAIL  {what}", flush=True)


def walk(widget):
    yield widget
    child = widget.get_first_child()
    while child:
        yield from walk(child)
        child = child.get_next_sibling()


def find_button(root, label):
    for w in walk(root):
        if isinstance(w, Gtk.Button) and w.get_label() == label and w.is_sensitive():
            return w
    raise AssertionError(f"no enabled button labelled {label!r}")


def find_check(root, label):
    for w in walk(root):
        if isinstance(w, Gtk.CheckButton) and w.get_label() == label:
            return w
    raise AssertionError(f"no check button labelled {label!r}")


def shot(name):
    SHOTS.mkdir(parents=True, exist_ok=True)
    subprocess.run(["import", "-window", "root", str(SHOTS / f"{name}.png")], check=True)
    print(f"shot  {name}", flush=True)


def dialog():
    dlg = win.get_visible_dialog()
    assert dlg is not None, "expected a dialog"
    return dlg


def dialog_text():
    dlg = dialog()
    return f"{dlg.get_heading()}\n{dlg.get_body()}"


def respond(label):
    find_button(dialog(), label).emit("clicked")


def enter_passphrase(*texts):
    entries = [w for w in walk(dialog()) if isinstance(w, Gtk.PasswordEntry)]
    assert len(entries) == len(texts), f"expected {len(texts)} passphrase entries, found {len(entries)}"
    for entry, text in zip(entries, texts):
        entry.set_text(text)
    respond("Continue")


def wait_for(condition, what, ms=60000):
    waited = 0
    while not condition():
        yield 100
        waited += 100
        assert waited < ms, f"timed out waiting for {what}"


def idle():
    """Until no operation is running and any dialog it was showing has gone."""
    yield 150
    yield from wait_for(lambda: win.current_op is None, "the operation to finish")
    yield SETTLE


def click_vault(vault):
    """What clicking a vault in the sidebar does: select the row, then activate it."""
    rows = [w for w in walk(win.vault_list) if isinstance(w, Adw.ActionRow)]
    row = rows[win.vaults.index(vault)]
    win.vault_list.select_row(row)
    win.vault_list.emit("row-activated", row)


def radio_of(path):
    """A row's radio button. They run in display order after "Everything"."""
    radios = [w for w in walk(win.file_list) if isinstance(w, Gtk.CheckButton)]
    paths = [app.ROOT_ENTRY, *win.vault_entries]
    assert len(radios) == len(paths), f"{len(radios)} radios for {len(paths)} rows"
    return radios[paths.index(path)]


def select(path):
    """Click a row's radio button."""
    radio_of(path).set_active(True)
    assert win.selected_entry == path, f"selected {win.selected_entry!r}, wanted {path!r}"


def left_edge(path):
    """Where a row's radio button really is on screen."""
    ok, point = radio_of(path).compute_point(win, Graphene.Point())
    assert ok, f"{path!r} isn't on screen"
    return point.x


def arrow_color(path):
    """The colour of a folder's own arrow, the first one under its row."""
    row = radio_of(path).get_ancestor(Adw.ExpanderRow)
    arrow = next(w for w in walk(row) if "expander-row-arrow" in w.get_css_classes())
    return arrow.get_color().to_string()


def real_click(widget):
    """Click with the real pointer. The window is at 0,0, with no window manager to move it."""
    native = widget.get_native()
    centre = Graphene.Point().init(widget.get_width() / 2, widget.get_height() / 2)
    ok, point = widget.compute_point(native, centre)
    assert ok, f"{widget} isn't on screen"
    x, y = native.get_surface_transform()
    subprocess.run(["xdotool", "mousemove", str(round(point.x + x)), str(round(point.y + y)), "click", "1"], check=True)


def visible_vault_page():
    return win.content_stack.get_visible_child_name() == "vault"


def locked():
    return win.vault_entries is None and win.vault_body.get_visible_child_name() == "locked"


def registry(vault):
    return next(v for v in json.loads(app.VAULTS_FILE.read_text()) if v["path"] == vault["path"])


def choose_in_file_dialog(path, *, save_as=None):
    """Answer the real GTK file chooser that a Gtk.FileDialog opened."""
    chooser = None
    for w in Gtk.Window.list_toplevels():
        if isinstance(w, Gtk.FileChooserDialog) and w.get_visible():
            chooser = w
    assert chooser is not None, "no file chooser is open"
    if save_as:
        chooser.set_current_folder(Gio.File.new_for_path(path))
        chooser.set_current_name(save_as)
    else:
        chooser.set_file(Gio.File.new_for_path(path))
    return chooser


def tree_digest(root):
    result = {}
    for base, dirs, files in os.walk(root):
        rel = os.path.relpath(base, root)
        result[rel + "/"] = None
        for name in files:
            result[os.path.join(rel, name)] = Path(base, name).read_bytes()
    return result


def build_source_tree():
    src = WORK / "My Documents"
    (src / "taxes" / "2025").mkdir(parents=True)
    (src / "photos").mkdir()
    (src / "empty folder").mkdir()
    (src / "notes.txt").write_text("private notes\n")
    (src / "taxes" / "return.pdf").write_bytes(os.urandom(200_000))
    (src / "taxes" / "2025" / "receipts & <invoices>.csv").write_text("a,b,c\n")
    (src / "photos" / "ünï çödé ☃.jpg").write_bytes(os.urandom(70_000))
    return src


def forge_key_file(vault):
    """What an attacker with write access could do: a key wrapped to the user's public
    key, made by the backend so that it is perfectly valid."""
    forged = WORK / "forged.vsvault"
    shutil.rmtree(forged, ignore_errors=True)
    subprocess.run([app.BACKEND, "vault-create", "--dir", str(forged), "--mode", "self"], check=True)
    return (forged / "key.age").read_bytes()


def script():
    yield 1800
    check(not STALE_COPY.exists(), "a crash's leftover copy is cleared at launch")
    # -- Contacts mode: unchanged apart from the toggle ------------------------------
    shot("01b-contacts-branch")
    check(win.content_stack.get_visible_child_name() == "send", "starts on the send page")
    check(win.sidebar_stack.get_visible_child_name() == "contacts", "starts on contacts")
    check(win.add_content.get_label() == "Add contact", "add button says Add contact")

    # -- Vaults mode, empty ----------------------------------------------------------
    win.vaults_toggle.emit("clicked")
    yield SETTLE
    check(win.sidebar_stack.get_visible_child_name() == "vaults", "toggle shows the vault list")
    check(win.add_content.get_label() == "Add vault", "add button follows the toggle")
    shot("02-vaults-empty")

    # -- Create a vault with the user's own key --------------------------------------
    win.on_add_clicked()
    yield SETTLE
    dlg = dialog()
    entry = next(w for w in walk(dlg) if type(w) is Gtk.Entry)
    entry.set_text("Personal")
    yield 300
    check(find_check(dlg, "Encrypt with my key (simplest, secure)").get_active(), "my key is the default")
    check(find_check(dlg, "Default").get_active(), "default location is the default")
    shot("04-create-dialog")
    respond("Create")
    yield from wait_for(lambda: win.vaults, "the vault to appear")
    yield SETTLE
    own = win.vaults[0]
    check(own["path"] == str(app.VAULTS_DIR / "Personal.vsvault"), "created at the default location")
    check(app.read_vault_mode(own["path"]) == "self", "VAULT file says self")
    check(own["key_sha256"] == app.key_fingerprint(own["path"]) != "", "key.age pinned at creation")
    check(registry(own)["last_generation"] == 0, "registry written")
    check(visible_vault_page() and locked(), "new vault shows locked")

    # An invalid name is refused without creating anything.
    win.on_add_clicked()
    yield SETTLE
    next(w for w in walk(dialog()) if type(w) is Gtk.Entry).set_text("a/b")
    respond("Create")
    yield SETTLE
    check(len(win.vaults) == 1, "a name with / is refused")

    # -- Create a password vault somewhere chosen, through the real folder chooser ---
    (WORK / "elsewhere").mkdir()
    win.on_add_clicked()
    yield SETTLE
    dlg = dialog()
    next(w for w in walk(dlg) if type(w) is Gtk.Entry).set_text("Shared")
    find_check(dlg, "Use a password (shareable)").set_active(True)
    find_check(dlg, "Select a location…").set_active(True)
    respond("Create")
    yield 1500
    chooser = choose_in_file_dialog(str(WORK / "elsewhere"))
    yield 800
    chooser.response(Gtk.ResponseType.ACCEPT)
    yield 1000
    check("password" in dialog_text(), "asks to choose a password")
    enter_passphrase("short", "short")
    yield SETTLE
    check(len(win.vaults) == 1, "a short password is refused")
    enter_passphrase(VAULT_PASS, VAULT_PASS)
    yield from wait_for(lambda: len(win.vaults) == 2, "the password vault to appear")
    yield SETTLE
    shared = win.vaults[1]
    check(shared["path"] == str(WORK / "elsewhere" / "Shared.vsvault"), "created in the chosen folder")
    check(app.read_vault_mode(shared["path"]) == "password", "VAULT file says password")
    shot("03-vaults-two")

    # -- Unlock the password vault; a wrong password is a clean error ----------------
    win.vault_unlock()
    yield SETTLE
    enter_passphrase("not the right password")
    yield SETTLE
    check("wrong password" in dialog_text(), "wrong password is reported")
    check(locked(), "still locked after a wrong password")
    respond("Close")
    yield SETTLE
    win.vault_unlock()
    yield SETTLE
    enter_passphrase(VAULT_PASS)
    yield SETTLE
    check(not locked() and win.vault_entries == {}, "password vault unlocks, empty")

    # -- The self vault: add a tree through the real folder chooser ------------------
    click_vault(own)
    yield SETTLE
    check(win.vault is own and locked(), "clicking the other vault shows it, locked")
    win.vault_unlock()
    yield SETTLE
    enter_passphrase(ID_PASS)
    yield SETTLE
    check(not locked(), "self vault unlocks with the identity passphrase")

    src = build_source_tree()
    win.vault_add_folder()
    yield 1500
    chooser = choose_in_file_dialog(str(src))
    yield 800
    chooser.response(Gtk.ResponseType.ACCEPT)
    yield 1000
    enter_passphrase(ID_PASS)
    yield from idle()
    entries = win.vault_entries
    check("My Documents/taxes/2025/receipts & <invoices>.csv" in entries, "folder added, awkward name intact")
    check(entries["My Documents/empty folder"]["is_dir"], "empty folder kept")
    check(registry(own)["last_generation"] == 1, "generation stored after the change")

    # Files through the real multi-file chooser, into the selected folder.
    single = WORK / "letter.txt"
    single.write_text("a letter\n")
    select("My Documents/taxes")
    win.vault_add_files()
    yield 1500
    chooser = choose_in_file_dialog(str(single))
    yield 800
    chooser.response(Gtk.ResponseType.ACCEPT)
    yield 1000
    enter_passphrase(ID_PASS)
    yield from idle()
    check("My Documents/taxes/letter.txt" in win.vault_entries, "added into the selected folder")
    check(win.selected_entry == app.ROOT_ENTRY, "selection returns to the whole vault after a change")

    # Dropping a file is the same path.
    class Dropped:
        def get_files(self):
            return [Gio.File.new_for_path(str(single))]

    check(win.on_vault_drop(None, Dropped(), 0, 0) is True, "drop accepted while unlocked")
    yield SETTLE
    enter_passphrase(ID_PASS)
    yield from idle()
    check("letter.txt" in win.vault_entries, "dropped file added at the top")

    # Expand the folders and take the unlocked screenshot.
    for path in ("My Documents", "My Documents/taxes", "My Documents/taxes/2025"):
        win.expanded.add(path)
    win._show_files(list(win.vault_entries.values()))
    yield SETTLE
    shot("05-unlocked-nested")

    # -- The list shows how deep each row is, and each folder's own state ------------
    top = left_edge("My Documents")
    subfolder = left_edge("My Documents/taxes")
    deeper = left_edge("My Documents/taxes/2025")
    check(top == left_edge(app.ROOT_ENTRY) == left_edge("letter.txt"), "top-level rows line up")
    check(top < subfolder < deeper, "each folder level sits further in")
    check(left_edge("My Documents/taxes/return.pdf") == deeper, "a file lines up with the folders beside it")
    check(left_edge("My Documents/notes.txt") == subfolder, "and so does one higher up")

    photos = radio_of("My Documents/photos")
    photos_row = photos.get_ancestor(Adw.ExpanderRow)
    real_click(photos)
    yield SETTLE
    check(win.selected_entry == "My Documents/photos", "clicking a folder's radio selects it")
    check(not photos_row.get_expanded(), "without opening it")
    closed_color = arrow_color("My Documents/photos")
    real_click(photos.get_ancestor(Adw.ActionRow))
    yield SETTLE
    check(photos_row.get_expanded() and "My Documents/photos" in win.expanded, "clicking the rest of its row opens it")
    check(arrow_color("My Documents/photos") != closed_color, "and its arrow changes")
    check(win.selected_entry == "My Documents/photos", "the selection stays")
    real_click(photos.get_ancestor(Adw.ActionRow))
    yield SETTLE
    check(not photos_row.get_expanded() and "My Documents/photos" not in win.expanded, "clicking again closes it")

    def folder(path):
        return {"path": path, "is_dir": True, "size": 0}

    listing = list(win.vault_entries.values())
    was_expanded = win.expanded
    win.expanded = {"open", "open/open"}
    win._show_files([folder("closed"), folder("open"), folder("open/closed"), folder("open/open"), folder("open/open/closed")])
    yield SETTLE
    check(arrow_color("open/closed") == arrow_color("closed"), "a closed folder inside an open one has a closed arrow")
    check(arrow_color("open/open/closed") == arrow_color("closed"), "at any depth")
    check(arrow_color("open/open") == arrow_color("open") != arrow_color("closed"), "an open folder has an open arrow at any depth")

    # A very deep path keeps its indent within reason, and leaves the window alone.
    width = win.get_width()
    levels = ["/".join(f"level {n}" for n in range(depth + 1)) for depth in range(40)]
    long_name = levels[-1] + "/" + "a long file name " * 12
    win.expanded = set(levels)
    win._show_files([folder(path) for path in levels] + [{"path": long_name, "is_dir": False, "size": 1}])
    yield from wait_for(lambda: radio_of(long_name).get_width() > 0, "the deep listing to be laid out")
    yield SETTLE
    check(win.get_width() == width, "a very deep path doesn't widen the window")
    check(left_edge(levels[app.INDENT_LEVELS]) == left_edge(long_name) > left_edge(levels[app.INDENT_LEVELS - 1]), "and its indent stops at the cap")

    win.expanded = was_expanded
    win._show_files(listing)
    yield SETTLE

    # -- Name clash: Replace / Cancel ------------------------------------------------
    single.write_text("a second version of the letter\n")
    win._add_paths([str(single)])
    yield SETTLE
    check("letter.txt" in dialog().get_body(), "a clash names the file")
    respond("Cancel")
    yield SETTLE
    check(win.current_op is None, "cancelling the clash does nothing")
    win._add_paths([str(single)])
    yield SETTLE
    respond("Replace")
    yield SETTLE
    enter_passphrase(ID_PASS)
    yield from idle()

    # -- Extract: a file through the real save dialog, then the whole vault ----------
    select("letter.txt")
    win.vault_extract()
    yield SETTLE
    enter_passphrase(ID_PASS)
    yield 1500
    (WORK / "out").mkdir()
    chooser = choose_in_file_dialog(str(WORK / "out"), save_as="letter-out.txt")
    yield 800
    chooser.response(Gtk.ResponseType.ACCEPT)
    yield 1000
    yield from idle()
    check((WORK / "out" / "letter-out.txt").read_text() == single.read_text(), "extracted file has the new contents")
    check((WORK / "out" / "letter-out.txt").stat().st_mode & 0o777 == 0o600, "extracted file is private")

    select(app.ROOT_ENTRY)
    win.vault_extract()
    yield SETTLE
    enter_passphrase(ID_PASS)
    yield 1500
    chooser = choose_in_file_dialog(str(WORK / "out"), save_as="everything")
    yield 800
    chooser.response(Gtk.ResponseType.ACCEPT)
    yield 1000
    yield from idle()
    check(tree_digest(WORK / "out" / "everything" / "My Documents") != {}, "whole vault extracted")
    expected = tree_digest(src)
    expected.pop("./", None)
    got = tree_digest(WORK / "out" / "everything" / "My Documents")
    got.pop("./", None)
    expected_with_letter = dict(expected)
    expected_with_letter["taxes/letter.txt"] = b"a letter\n"
    check(got == expected_with_letter, "extracted tree is byte-identical, empty folder included")

    # -- Delete, with a destructive confirmation ------------------------------------
    select(app.ROOT_ENTRY)
    win.vault_delete()
    yield SETTLE
    check(win.get_visible_dialog() is None, "delete needs a selection")
    select("My Documents/photos")
    win.vault_delete()
    yield SETTLE
    check("and everything in it" in dialog().get_body(), "deleting a folder says so")
    respond("Cancel")
    yield SETTLE
    check("My Documents/photos" in win.vault_entries, "cancel keeps it")
    win.vault_delete()
    yield SETTLE
    respond("Delete")
    yield SETTLE
    enter_passphrase(ID_PASS)
    yield from idle()
    check(not any(p.startswith("My Documents/photos") for p in win.vault_entries), "folder and contents deleted")

    # -- Verify all ------------------------------------------------------------------
    win.vault_verify()
    yield SETTLE
    enter_passphrase(ID_PASS)
    yield from idle()
    check(win.get_visible_dialog() is None, "Verify all is clean on a good vault")
    check("Every file verified." in toasts, "and says so")

    # -- Cancel: an add changes nothing, an extract leaves nothing --------------------
    big = WORK / "big.bin"
    big.write_bytes(os.urandom(32 * 1024 * 1024))
    generation = registry(own)["last_generation"]
    win._add_paths([str(big)])
    yield SETTLE
    enter_passphrase(ID_PASS)
    win.current_op.cancel()
    yield from idle()
    check("Cancelled." in toasts, "an add can be cancelled")
    check("big.bin" not in win.vault_entries, "a cancelled add adds nothing")
    check(registry(own)["last_generation"] == generation, "and makes no new generation")

    select(app.ROOT_ENTRY)
    win.vault_extract()
    yield SETTLE
    enter_passphrase(ID_PASS)
    yield 1500
    chooser = choose_in_file_dialog(str(WORK / "out"), save_as="cancelled")
    yield 800
    # Made only now: its name starts with "cancelled", which the chooser's name entry
    # would otherwise autocomplete to.
    stale = WORK / "out" / "cancelled.vaultsend-part"
    stale.mkdir()
    (stale / "leftover").write_text("from a killed run")
    chooser.response(Gtk.ResponseType.ACCEPT)
    yield from wait_for(lambda: win.current_op is not None, "the extract to start")
    win.current_op.cancel()
    yield from idle()
    check(not (WORK / "out" / "cancelled").exists(), "a cancelled extract produces nothing")
    check(not stale.exists(), "and its staging folder is removed")

    # -- Open: a warning once, a copy in memory, the file's real default app ----------
    def opened_folders():
        return list(Path(app.memory_folder()).glob(app.OPEN_PREFIX + "*"))

    def viewer_calls():
        return VIEWER_LOG.read_text().splitlines() if VIEWER_LOG.exists() else []

    select("My Documents")
    win.vault_open()
    yield SETTLE
    check("Select a file to open." in toasts, "Open needs a file, not a folder")
    check(win.get_visible_dialog() is None, "and asks for nothing")

    select("letter.txt")
    win.vault_open()
    yield SETTLE
    check("unencrypted copies" in dialog().get_body(), "first Open warns about plaintext")
    check(not [w for w in walk(dialog()) if isinstance(w, Gtk.PasswordEntry)], "before asking for a secret")
    shot("10-open-warning")
    respond("Cancel")
    yield SETTLE
    check(not opened_folders() and not win.opened, "Cancel decrypts nothing")
    check(not json.loads(app.SETTINGS_FILE.read_text() if app.SETTINGS_FILE.exists() else "{}").get("open_explained"), "and isn't remembered")

    win.vault_open()
    yield SETTLE
    respond("I understand")
    yield SETTLE
    check(json.loads(app.SETTINGS_FILE.read_text())["open_explained"] is True, "I understand is remembered")
    enter_passphrase(ID_PASS)
    yield from wait_for(lambda: len(viewer_calls()) == 1, "the default app to be launched")
    yield from idle()
    copy = Path(viewer_calls()[0])
    check(Path(str(VIEWER_LOG) + ".content").read_text() == single.read_text(), "the default app got the decrypted file")
    check(copy.name == "letter.txt", "under its own name, so the right app opens it")
    check(app.is_in_memory(copy.parent), "in a folder that is really in memory")
    check(copy.stat().st_mode & 0o777 == 0o600 and copy.parent.stat().st_mode & 0o777 == 0o700, "private, and not executable")
    check(not list(Path(copy.parent).glob("*.vaultsend-part")), "with no staging file left")

    select("letter.txt")
    win.vault_open()
    yield SETTLE
    check(bool([w for w in walk(dialog()) if isinstance(w, Gtk.PasswordEntry)]), "second Open doesn't warn again")
    enter_passphrase(ID_PASS)
    yield from wait_for(lambda: len(viewer_calls()) == 2, "the second launch")
    yield from idle()
    check(len(opened_folders()) == 2, "each Open makes its own copy")

    # Unchanged copies just go; an edited one asks first.
    win.vault_lock()
    yield SETTLE
    check(win.get_visible_dialog() is None and locked(), "Lock with unedited copies needs no confirmation")
    check(not opened_folders() and not win.opened, "and deletes them")

    win.vault_unlock()
    yield SETTLE
    enter_passphrase(ID_PASS)
    yield SETTLE
    select("letter.txt")
    win.vault_open()
    yield SETTLE
    enter_passphrase(ID_PASS)
    yield from wait_for(lambda: len(viewer_calls()) == 3, "the third launch")
    yield from idle()
    copy = Path(viewer_calls()[2])
    copy.write_text("edited in the other app, longer than before\n")
    win.vault_lock()
    yield SETTLE
    check("letter.txt" in dialog().get_body() and dialog().get_heading() == "Changes will be lost", "Lock warns about an edited copy")
    shot("11-open-changes-lost")
    respond("Cancel")
    yield SETTLE
    check(not locked() and copy.exists(), "Cancel keeps the vault unlocked and the copy")
    win.vault_lock()
    yield SETTLE
    respond("Delete changes")
    yield SETTLE
    check(locked() and not copy.exists() and not opened_folders(), "Delete changes locks and deletes it")

    win.vault_unlock()
    yield SETTLE
    enter_passphrase(ID_PASS)
    yield SETTLE

    # A type with no default app: says so, and leaves nothing.
    select("My Documents/taxes/return.pdf")
    win.vault_open()
    yield SETTLE
    enter_passphrase(ID_PASS)
    yield from idle()  # past the progress dialog, which is a dialog too
    yield from wait_for(lambda: win.get_visible_dialog() is not None, "the no-app error")
    yield SETTLE
    check(dialog().get_heading() == "Couldn't open that file", "no default app is reported")
    check(not opened_folders() and not win.opened, "and its copy is deleted at once")
    respond("Close")
    yield SETTLE

    # No in-memory folder: refuses rather than falling back to disk.
    real_memory_folder = app.memory_folder
    app.memory_folder = lambda: None
    select("letter.txt")
    win.vault_open()
    yield SETTLE
    check(dialog().get_heading() == "Can't open this file", "no in-memory folder is refused")
    check(not [w for w in walk(dialog()) if isinstance(w, Gtk.PasswordEntry)], "without asking for a secret")
    respond("Close")
    yield SETTLE
    app.memory_folder = real_memory_folder

    # -- Tamper: extract fails, says why, writes nothing -----------------------------
    blobs = sorted(Path(own["path"], "blobs").rglob("*.age"))
    victim = blobs[0]
    good = victim.read_bytes()
    bad = bytearray(good)
    bad[len(bad) // 2] ^= 1
    victim.write_bytes(bad)
    select(app.ROOT_ENTRY)
    win.vault_extract()
    yield SETTLE
    enter_passphrase(ID_PASS)
    yield 1500
    chooser = choose_in_file_dialog(str(WORK / "out"), save_as="tampered")
    yield 800
    chooser.response(Gtk.ResponseType.ACCEPT)
    yield 1000
    yield from idle()
    check("failed verification" in dialog_text(), "tampered blob is reported")
    check(not (WORK / "out" / "tampered").exists(), "no output from a tampered vault")
    check(not (WORK / "out" / "tampered.vaultsend-part").exists(), "no staging output either")
    shot("07-tamper-error")
    respond("Close")
    yield SETTLE
    win.vault_verify()
    yield SETTLE
    enter_passphrase(ID_PASS)
    yield from idle()
    check("failed verification" in dialog_text(), "Verify all finds it too")
    respond("Close")
    yield SETTLE
    victim.write_bytes(good)

    # Open follows the same rule: nothing reaches the app, or memory, unverified.
    originals = {b: b.read_bytes() for b in blobs}
    for blob in blobs:
        damaged = bytearray(originals[blob])
        damaged[len(damaged) // 2] ^= 1
        blob.write_bytes(damaged)
    launches = len(viewer_calls())
    select("letter.txt")
    win.vault_open()
    yield SETTLE
    enter_passphrase(ID_PASS)
    yield from idle()
    check("failed verification" in dialog_text(), "Open refuses a tampered file")
    check(len(viewer_calls()) == launches, "and no app is launched")
    check(not opened_folders() and not win.opened, "and no copy is left")
    respond("Close")
    yield SETTLE
    for blob, data in originals.items():
        blob.write_bytes(data)

    # -- Rollback warning ------------------------------------------------------------
    backup = WORK / "backup.vsvault"
    shutil.rmtree(backup, ignore_errors=True)
    shutil.copytree(own["path"], backup)
    note = WORK / "newer.txt"
    note.write_text("newer\n")
    win._add_paths([str(note)])
    yield SETTLE
    enter_passphrase(ID_PASS)
    yield from idle()
    newest = registry(own)["last_generation"]
    current = WORK / "current.vsvault"
    shutil.rmtree(current, ignore_errors=True)
    shutil.move(own["path"], current)
    shutil.copytree(backup, own["path"])
    win.vault_lock()
    win.vault_unlock()
    yield SETTLE
    enter_passphrase(ID_PASS)
    yield SETTLE
    check("rolled back by someone else" in dialog().get_body(), "older vault warns")
    shot("06-rollback-warning")
    respond("Cancel")
    yield SETTLE
    check(locked(), "Cancel stays locked")
    check(registry(own)["last_generation"] == newest, "Cancel keeps the remembered generation")
    win.vault_unlock()
    yield SETTLE
    enter_passphrase(ID_PASS)
    yield SETTLE
    respond("Open anyway")
    yield SETTLE
    check(not locked(), "Open anyway opens it")
    check(registry(own)["last_generation"] == newest - 1, "Open anyway stores the generation it accepted")
    shutil.rmtree(own["path"])
    shutil.move(current, own["path"])
    own["last_generation"] = newest
    app.save_json(app.VAULTS_FILE, win.vaults)

    # -- A swapped key.age: warned before any secret is asked for --------------------
    key_path = Path(own["path"], "key.age")
    real_key = key_path.read_bytes()
    pin = own["key_sha256"]
    key_path.write_bytes(forge_key_file(own))
    win.vault_lock()
    win.vault_unlock()
    yield SETTLE
    check("key has changed" in dialog().get_heading(), "a swapped key warns before any prompt")
    check(not [w for w in walk(dialog()) if isinstance(w, Gtk.PasswordEntry)], "no passphrase is asked for yet")
    shot("09-key-changed-warning")
    respond("Cancel")
    yield SETTLE
    check(win.get_visible_dialog() is None and locked(), "Cancel stops there")
    check(registry(own)["key_sha256"] == pin, "Cancel keeps the pin")
    # The backend refuses too, for a swap made after the frontend's check has passed.
    try:
        app.run_backend(win._vault_args(own, "vault-list"), passphrase=ID_PASS)
        refusal = ""
    except app.BackendError as e:
        refusal = str(e)
    check("has changed" in refusal, "backend refuses the swapped key by itself")
    win.vault_unlock()
    yield SETTLE
    respond("Trust the new key")
    yield SETTLE
    check(registry(own)["key_sha256"] == app.key_fingerprint(own["path"]), "Trust updates the pin")
    enter_passphrase(ID_PASS)
    yield SETTLE
    # The forged key opens with the passphrase but can't read the real manifest.
    check("manifest is damaged or was replaced" in dialog().get_body(), "a forged key can't read the real vault")
    respond("Close")
    yield SETTLE
    key_path.write_bytes(real_key)
    own["key_sha256"] = pin
    app.save_json(app.VAULTS_FILE, win.vaults)

    # -- Remember passphrase ---------------------------------------------------------
    win.activate_action("win.remember", GLib.Variant("s", "5m"))
    yield SETTLE
    check("swap" in dialog().get_body(), "first use explains the caveat")
    respond("Got it")
    yield SETTLE
    check(json.loads(app.SETTINGS_FILE.read_text())["remember"] == "5m", "the choice is saved")
    check(ID_PASS not in app.SETTINGS_FILE.read_text(), "the passphrase is not")
    win.vault_unlock()
    yield SETTLE
    enter_passphrase(ID_PASS)
    yield SETTLE
    check(not locked(), "unlocked")
    win.vault_verify()
    yield 400
    check(win.get_visible_dialog() is None or not [w for w in walk(win.get_visible_dialog()) if isinstance(w, Gtk.PasswordEntry)], "second op doesn't ask again")
    yield from idle()
    win.buffer.set_text("")
    armored = subprocess.run(
        [app.BACKEND, "encrypt", "-r", win.my_pubkey, "--armor"], input=b"cached decrypt", capture_output=True, check=True,
    ).stdout.decode()
    win.vaults_toggle.emit("clicked")
    win.contacts_toggle.emit("clicked")
    yield SETTLE
    check(win.content_stack.get_visible_child_name() == "send", "Contacts toggle returns to the send page")
    win.set_text(armored)
    win.decrypt_text()
    yield SETTLE
    check(win.get_text() == "cached decrypt", "text decrypt uses the remembered passphrase too")
    win.vaults_toggle.emit("clicked")
    yield SETTLE
    check(visible_vault_page(), "Vaults toggle returns to the selected vault")

    win.activate_action("win.lock-now", None)
    yield SETTLE
    check(locked() and win.cache.entries == {}, "Lock now forgets everything and locks")
    win.vault_unlock()
    yield SETTLE
    check(bool([w for w in walk(dialog()) if isinstance(w, Gtk.PasswordEntry)]), "and it asks again")
    respond("Cancel")
    yield SETTLE

    # A wrong passphrase is forgotten rather than retried forever.
    win.vault_unlock()
    yield SETTLE
    enter_passphrase("a wrong passphrase!")
    yield SETTLE
    check("wrong passphrase" in dialog_text(), "wrong passphrase reported")
    check(win.cache.entries == {}, "a wrong passphrase isn't remembered")
    respond("Close")
    yield SETTLE

    # Changing the setting clears; Lock forgets that vault's secret.
    win.cache.put("identity", ID_PASS)
    win.activate_action("win.remember", GLib.Variant("s", "session"))
    yield SETTLE
    check(win.get_visible_dialog() is None, "the explanation shows only once")
    check(win.cache.entries == {}, "changing the setting clears the cache")
    win.cache.put("identity", ID_PASS)
    win._show_files([])
    win.vault_lock()
    check(win.cache.entries == {} and locked(), "Lock forgets the vault's secret")
    win.activate_action("win.remember", GLib.Variant("s", "off"))
    yield SETTLE

    # The menu itself, opened with real clicks.
    subprocess.run(["xdotool", "mousemove", "738", "28", "click", "1"], check=True)
    yield 900
    subprocess.run(["xdotool", "mousemove", "660", "99", "click", "1"], check=True)
    yield 900
    shot("08-passphrase-menu")
    subprocess.run(["xdotool", "key", "Escape"], check=True)
    yield 500
    subprocess.run(["xdotool", "mousemove", "500", "580", "click", "1"], check=True)
    yield SETTLE

    # -- Remove from list, Not found, Add existing -----------------------------------
    path = shared["path"]
    click_vault(shared)
    yield SETTLE
    win._confirm_forget_vault(shared)
    yield SETTLE
    check("does not delete" in dialog().get_body(), "Remove says it deletes nothing")
    respond("Remove from list")
    yield SETTLE
    check(shared not in win.vaults, "forgotten from the list")
    check(os.path.isfile(os.path.join(path, "VAULT")), "the vault's files are untouched")
    check(win.content_stack.get_visible_child_name() == "send", "removed vault's page closes")

    win.on_add_clicked()
    yield SETTLE
    respond("Add existing vault…")
    yield 1500
    chooser = choose_in_file_dialog(path)
    yield 800
    chooser.response(Gtk.ResponseType.ACCEPT)
    yield 1000
    readded = next((v for v in win.vaults if v["path"] == path), None)
    check(readded is not None and readded["mode"] == "password", "Add existing re-attaches it, mode read from VAULT")
    check(readded is not None and readded["name"] == "Shared", "named after its folder")

    win._add_existing_vault(str(WORK))
    yield SETTLE
    check("isn't a vault" in dialog().get_heading(), "a folder without VAULT is refused")
    respond("Close")
    yield SETTLE

    moved = path + ".moved"
    os.rename(path, moved)
    win._refresh_vaults()
    yield SETTLE
    subtitles = [w.get_subtitle() for w in walk(win.vault_list) if hasattr(w, "get_subtitle")]
    check("Not found" in subtitles, "a missing folder shows Not found")
    os.rename(moved, path)
    win._refresh_vaults()
    yield SETTLE

    # Contacts must still work as before.
    win.contacts_toggle.emit("clicked")
    yield SETTLE
    check(win.add_content.get_label() == "Add contact", "back to contacts")
    check(len(win.contacts) == 2, "contacts untouched")
    check(not list(WORK.rglob("*.vaultsend-part")), "no staging files left anywhere")
    config = app.VAULTS_FILE.read_text() + app.SETTINGS_FILE.read_text()
    check(ID_PASS not in config and VAULT_PASS not in config, "no secret in any config file")

    # -- Closing the window: an edited copy asks first, and nothing stays in memory ---
    win.vaults_toggle.emit("clicked")
    click_vault(own)
    yield SETTLE
    win.vault_unlock()
    yield SETTLE
    enter_passphrase(ID_PASS)
    yield SETTLE
    select("letter.txt")
    win.vault_open()
    yield SETTLE
    launches = len(viewer_calls())
    enter_passphrase(ID_PASS)
    yield from wait_for(lambda: len(viewer_calls()) == launches + 1, "the last launch")
    yield from idle()
    Path(viewer_calls()[-1]).write_text("edited again, and again longer than before\n")
    win.close()
    yield SETTLE
    check(dialog().get_heading() == "Changes will be lost", "closing warns about an edited copy")
    respond("Cancel")
    yield SETTLE
    check(win.get_visible() and len(opened_folders()) == 1, "Cancel keeps the window and the copy")
    win.close()
    yield SETTLE
    respond("Delete changes")
    # The window closes and the app quits here; main() checks that the copies went too.
    yield SETTLE


def run(gen):
    def step():
        global failed
        try:
            delay = next(gen)
        except StopIteration:
            application.quit()
            return False
        except Exception:
            traceback.print_exc()
            dlg = win.get_visible_dialog()
            print("dialog:", dlg and (dlg.get_heading(), dlg.get_body()))
            print("last toasts:", toasts[-4:])
            print("toplevels:", [(type(w).__name__, w.get_visible()) for w in Gtk.Window.list_toplevels()])
            subprocess.run(["import", "-window", "root", os.environ.get("VS_CRASH_SHOT", str(WORK / "crash.png"))])
            failed += 1
            application.quit()
            return False
        GLib.timeout_add(delay, step)
        return False

    GLib.timeout_add(100, step)


def main():
    global application, win
    WORK.mkdir(parents=True, exist_ok=True)
    STALE_COPY.mkdir()
    (STALE_COPY / "secret.txt").write_text("from a run that never got to clean up")
    application = app.VaultSend()

    def started(_app):
        global win
        win = application.window
        watch_toasts()
        run(script())

    application.connect_after("activate", started)
    app.Adw.init()
    application.run([])
    check(not list(Path(app.memory_folder()).glob(app.OPEN_PREFIX + "*")), "no opened copy survives the app closing")
    print(f"\n{passed} passed, {failed} failed")
    sys.exit(1 if failed or passed == 0 else 0)


if __name__ == "__main__":
    main()
