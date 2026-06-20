#!/usr/bin/env python3
"""VaultSend — a small Adwaita front-end for the age-based encryption backend.

This process never sees your private key. It only:
  * keeps a list of contacts (their public keys) as plain JSON, and
  * runs the `vaultsend-backend` binary, which does all cryptography.

The private key lives, passphrase-encrypted, where only the backend reads it.
"""

import json
import os
import subprocess
import sys
from pathlib import Path

import gi

gi.require_version("Gtk", "4.0")
gi.require_version("Adw", "1")
from gi.repository import Adw, Gdk, Gio, GLib, GObject, Gtk  # noqa: E402

# --- Require the toolkit versions whose APIs we use --------------------------
# Adw.AlertDialog needs libadwaita >= 1.5; Gtk.FileDialog needs GTK >= 4.10.
if (Adw.get_major_version(), Adw.get_minor_version()) < (1, 5):
    sys.exit("VaultSend needs libadwaita 1.5 or newer.")
if (Gtk.get_major_version(), Gtk.get_minor_version()) < (4, 10):
    sys.exit("VaultSend needs GTK 4.10 or newer.")

APP_ID = "org.vaultsend.VaultSend"

CONFIG_DIR = Path(os.environ.get("XDG_CONFIG_HOME") or Path.home() / ".config") / "vaultsend"
CONTACTS_FILE = CONFIG_DIR / "contacts.json"


# ---------------------------------------------------------------------------
# Backend plumbing
# ---------------------------------------------------------------------------
class BackendError(Exception):
    """Raised when the backend exits non-zero; carries its stderr message."""


def find_backend() -> str:
    """Locate the backend binary: env override, sibling build dir, then PATH."""
    override = os.environ.get("VAULTSEND_BACKEND")
    if override:
        return override
    sibling = Path(__file__).resolve().parent.parent / "backend" / "target" / "release" / "vaultsend-backend"
    if sibling.exists():
        return str(sibling)
    return "vaultsend-backend"


BACKEND = find_backend()


def run_backend(args, *, input_bytes=None, passphrase=None) -> bytes:
    """Run the backend once. Passphrase (if any) is handed over on a private pipe,
    never on the command line. Returns stdout; raises BackendError on failure."""
    extra = {}
    read_fd = None
    if passphrase is not None:
        read_fd, write_fd = os.pipe()
        os.write(write_fd, passphrase.encode("utf-8"))
        os.close(write_fd)
        args = list(args) + ["--pass-fd", str(read_fd)]
        extra["pass_fds"] = (read_fd,)
    try:
        proc = subprocess.run(
            [BACKEND, *args],
            input=input_bytes,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            **extra,
        )
    except FileNotFoundError:
        raise BackendError(
            f"Backend not found at '{BACKEND}'.\nBuild it with 'cargo build --release' "
            "or set VAULTSEND_BACKEND."
        )
    finally:
        if read_fd is not None:
            try:
                os.close(read_fd)
            except OSError:
                pass
    if proc.returncode != 0:
        msg = proc.stderr.decode("utf-8", "replace").strip()
        raise BackendError(msg.removeprefix("error: ") or "the operation failed")
    return proc.stdout


# ---------------------------------------------------------------------------
# Contacts (plain, exportable JSON)
# ---------------------------------------------------------------------------
def load_contacts() -> list:
    try:
        data = json.loads(CONTACTS_FILE.read_text("utf-8"))
        return [c for c in data if "name" in c and "pubkey" in c]
    except (OSError, ValueError):
        return []


def save_contacts(contacts: list) -> None:
    CONFIG_DIR.mkdir(parents=True, exist_ok=True)
    CONTACTS_FILE.write_text(json.dumps(contacts, indent=2), "utf-8")


def looks_like_pubkey(s: str) -> bool:
    s = s.strip()
    return s.startswith("age1") and 50 <= len(s) <= 80 and s[4:].isalnum()


def short(pubkey: str) -> str:
    return pubkey[:12] + "…" + pubkey[-6:] if len(pubkey) > 24 else pubkey


# ---------------------------------------------------------------------------
# Main window
# ---------------------------------------------------------------------------
class Window(Adw.ApplicationWindow):
    def __init__(self, app):
        super().__init__(application=app, title="VaultSend")
        self.set_default_size(880, 600)
        self.my_pubkey = None
        self.contacts = load_contacts()
        self._load_css()

        self.split = Adw.OverlaySplitView(sidebar_width_fraction=0.25)
        self.split.set_max_sidebar_width(320)
        self.set_content(self.split)
        self.split.set_sidebar(self._build_sidebar())
        self.split.set_content(self._build_content())

        self._install_actions()

    def _load_css(self):
        # App-wide styles. The delete menu entry shows its trash icon and label
        # in red on hover/focus (#e01b24 is the standard Adwaita red), so the
        # destructive nature is obvious before you commit to it.
        css = """
        .vaultsend-delete { padding: 6px 10px; border-radius: 6px; }
        .vaultsend-delete:hover,
        .vaultsend-delete:focus,
        .vaultsend-delete:active {
            color: #e01b24;
            background-color: alpha(#e01b24, 0.12);
        }
        """
        provider = Gtk.CssProvider()
        try:
            provider.load_from_string(css)      # GTK 4.12+
        except AttributeError:
            provider.load_from_data(css.encode())  # GTK 4.10 / 4.11
        Gtk.StyleContext.add_provider_for_display(
            Gdk.Display.get_default(), provider, Gtk.STYLE_PROVIDER_PRIORITY_APPLICATION
        )

    # -- Sidebar --------------------------------------------------------------
    def _build_sidebar(self):
        view = Adw.ToolbarView()
        header = Adw.HeaderBar()
        header.set_title_widget(Adw.WindowTitle(title="Contacts"))
        view.add_top_bar(header)

        box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL)
        add_btn = Gtk.Button(margin_top=8, margin_bottom=8, margin_start=8, margin_end=8)
        add_btn.set_child(Adw.ButtonContent(icon_name="list-add-symbolic", label="Add contact"))
        add_btn.connect("clicked", lambda *_: self.add_contact_dialog())
        box.append(add_btn)

        self.contact_list = Gtk.ListBox(selection_mode=Gtk.SelectionMode.NONE)
        self.contact_list.add_css_class("boxed-list")
        self.contact_list.set_margin_start(8)
        self.contact_list.set_margin_end(8)
        scroller = Gtk.ScrolledWindow(vexpand=True)
        scroller.set_child(self.contact_list)
        box.append(scroller)
        view.set_content(box)
        self._refresh_contacts()
        return view

    def _refresh_contacts(self):
        child = self.contact_list.get_first_child()
        while child:
            self.contact_list.remove(child)
            child = self.contact_list.get_first_child()
        if not self.contacts:
            row = Adw.ActionRow(title="No contacts yet", subtitle="Add someone's public key to send to them.")
            row.set_activatable(False)
            self.contact_list.append(row)
            return
        for c in self.contacts:
            row = Adw.ActionRow(title=c["name"], subtitle=short(c["pubkey"]))
            row.set_activatable(True)
            copy = Gtk.Button(icon_name="edit-copy-symbolic", valign=Gtk.Align.CENTER)
            copy.add_css_class("flat")
            copy.set_tooltip_text("Copy public key")
            copy.connect("clicked", lambda _b, pk=c["pubkey"]: self.copy(pk, "Public key copied."))
            row.add_suffix(copy)
            row.connect("activated", lambda _r, pk=c["pubkey"]: self.copy(pk, "Public key copied."))

            # Right-click (or long-press, for touchscreens) opens a context menu
            # offering to delete this contact.
            self._attach_context_menu(row, c["pubkey"], c["name"])

            self.contact_list.append(row)

    def _attach_context_menu(self, row, pubkey, name):
        """Open a delete menu when `row` is right-clicked or long-pressed."""
        click = Gtk.GestureClick(button=Gdk.BUTTON_SECONDARY)
        click.connect("pressed", lambda _g, _n, x, y: self._show_delete_menu(row, pubkey, name, x, y))
        row.add_controller(click)

        # Touchscreens have no secondary button: long-press opens the same menu.
        press = Gtk.GestureLongPress()
        press.connect("pressed", lambda _g, x, y: self._show_delete_menu(row, pubkey, name, x, y))
        row.add_controller(press)

    def _show_delete_menu(self, row, pubkey, name, x, y):
        """A small popover with a single destructive 'Delete contact' button.

        Built by hand rather than from a Gio.Menu model so it can carry a trash
        icon and turn red on hover, and so the delete is dispatched directly by
        the button instead of through an action that races the popover's close.
        """
        pop = Gtk.Popover(has_arrow=False, autohide=True)
        pop.set_parent(row)
        rect = Gdk.Rectangle()
        rect.x, rect.y, rect.width, rect.height = int(x), int(y), 1, 1
        pop.set_pointing_to(rect)

        btn = Gtk.Button()
        btn.add_css_class("flat")
        btn.add_css_class("vaultsend-delete")  # red-on-hover; see _load_css()
        content = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=8)
        content.append(Gtk.Image.new_from_icon_name("user-trash-symbolic"))
        content.append(Gtk.Label(label="Delete contact"))
        btn.set_child(content)

        def on_click(_b):
            pop.popdown()
            self._confirm_delete_contact(pubkey, name)

        btn.connect("clicked", on_click)
        pop.set_child(btn)
        # Defer unparent to idle so it never runs mid-dispatch of the click.
        pop.connect("closed", lambda p: GLib.idle_add(lambda: p.unparent() or False))
        pop.popup()
        return pop

    def _confirm_delete_contact(self, pubkey, name):
        dlg = Adw.AlertDialog(
            heading="Delete contact?",
            body=f"Remove “{name}” from your contacts? This only forgets their saved "
            "public key — it doesn't affect anything you've already encrypted.",
        )
        dlg.add_response("cancel", "Cancel")
        dlg.add_response("delete", "Delete")
        dlg.set_response_appearance("delete", Adw.ResponseAppearance.DESTRUCTIVE)
        dlg.set_default_response("cancel")
        dlg.set_close_response("cancel")

        def resp(_d, r):
            if r != "delete":
                return
            self.contacts = [c for c in self.contacts if c["pubkey"] != pubkey]
            save_contacts(self.contacts)
            self._refresh_contacts()
            self.toast(f"Deleted {name}.")

        dlg.connect("response", resp)
        dlg.present(self)

    # -- Content --------------------------------------------------------------
    def _build_content(self):
        view = Adw.ToolbarView()
        header = Adw.HeaderBar()

        toggle = Gtk.ToggleButton(icon_name="sidebar-show-symbolic", tooltip_text="Toggle contacts")
        self.split.bind_property(
            "show-sidebar", toggle, "active", GObject.BindingFlags.BIDIRECTIONAL | GObject.BindingFlags.SYNC_CREATE
        )
        header.pack_start(toggle)
        header.set_title_widget(Adw.WindowTitle(title="VaultSend"))

        menu = Gio.Menu()
        menu.append("My public key", "win.show-key")
        menu.append("About VaultSend", "win.about")
        menu_btn = Gtk.MenuButton(icon_name="open-menu-symbolic", menu_model=menu, tooltip_text="Menu")
        header.pack_end(menu_btn)
        view.add_top_bar(header)

        self.toasts = Adw.ToastOverlay()
        view.set_content(self.toasts)

        clamp = Adw.Clamp(maximum_size=680, margin_top=24, margin_bottom=24, margin_start=16, margin_end=16)
        scroller = Gtk.ScrolledWindow(vexpand=True)
        scroller.set_child(clamp)
        self.toasts.set_child(scroller)

        col = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=16)
        clamp.set_child(col)

        title = Gtk.Label(label="Encrypt a message or a file", xalign=0)
        title.add_css_class("title-2")
        col.append(title)
        subtitle = Gtk.Label(
            label="Type or paste text below, or drop a file here. Encrypting scrambles it for chosen "
            "recipients; decrypting needs your passphrase.",
            xalign=0,
            wrap=True,
        )
        subtitle.add_css_class("dim-label")
        col.append(subtitle)

        # Text / drop card
        card = Gtk.Frame()
        card.add_css_class("card")
        card.set_size_request(-1, 220)
        self.textview = Gtk.TextView(
            wrap_mode=Gtk.WrapMode.WORD_CHAR, left_margin=12, right_margin=12, top_margin=12, bottom_margin=12
        )
        self.textview.add_css_class("vaultsend-text")
        self.buffer = self.textview.get_buffer()
        text_scroll = Gtk.ScrolledWindow(vexpand=True)
        text_scroll.set_child(self.textview)
        card.set_child(text_scroll)
        col.append(card)

        drop = Gtk.DropTarget.new(Gdk.FileList, Gdk.DragAction.COPY)
        drop.connect("drop", self.on_file_dropped)
        card.add_controller(drop)

        # Action bar
        actions = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=8)
        enc = Gtk.Button(label="Encrypt")
        enc.add_css_class("suggested-action")
        enc.connect("clicked", lambda *_: self.encrypt_text())
        dec = Gtk.Button(label="Decrypt")
        dec.connect("clicked", lambda *_: self.decrypt_text())
        spacer = Gtk.Box(hexpand=True)
        open_btn = Gtk.Button()
        open_btn.set_child(Adw.ButtonContent(icon_name="document-open-symbolic", label="Open file…"))
        open_btn.connect("clicked", lambda *_: self.open_file_dialog())
        for w in (enc, dec, spacer, open_btn):
            actions.append(w)
        col.append(actions)
        return view

    def _install_actions(self):
        for name, fn in (("show-key", self.on_show_key), ("about", self.on_about)):
            act = Gio.SimpleAction.new(name, None)
            act.connect("activate", fn)
            self.add_action(act)

    # -- Small helpers --------------------------------------------------------
    def toast(self, text):
        self.toasts.add_toast(Adw.Toast.new(text))

    def error(self, text):
        self.toasts.add_toast(Adw.Toast.new(text))

    def copy(self, text, note="Copied."):
        self.get_clipboard().set(text)
        self.toast(note)

    def get_text(self):
        start, end = self.buffer.get_bounds()
        return self.buffer.get_text(start, end, False)

    def set_text(self, text):
        self.buffer.set_text(text)

    # -- Identity / first run -------------------------------------------------
    def ensure_identity(self):
        # Ask the backend what state we're in (no passphrase needed):
        #   ready  -> pubkey cache present, just read it
        #   locked -> identity.age exists but pubkey was lost; rebuild it (needs pass)
        #   empty  -> no identity at all; create one
        try:
            status = run_backend(["status"]).decode("utf-8").strip()
        except BackendError:
            # Older backend without `status`: fall back to the legacy path.
            try:
                self.my_pubkey = run_backend(["pubkey"]).decode("utf-8").strip()
            except BackendError:
                self.first_run()
            return

        if status == "ready":
            try:
                self.my_pubkey = run_backend(["pubkey"]).decode("utf-8").strip()
            except BackendError:
                # Cache vanished between the check and the read; recover it.
                self.recover_identity()
        elif status == "locked":
            self.recover_identity()
        elif status == "corrupt":
            self.corrupt_identity()
        else:
            self.first_run()

    def first_run(self):
        self.ask_passphrase(
            self._do_keygen,
            heading="Create your key",
            body="Pick a passphrase. It protects your private key and is required to decrypt.",
            confirm=True,
        )

    def _do_keygen(self, passphrase):
        try:
            self.my_pubkey = run_backend(["keygen"], passphrase=passphrase).decode("utf-8").strip()
            self.toast("Your key is ready.")
        except BackendError as e:
            self.error(str(e))

    def recover_identity(self):
        # identity.age exists but its public key cache was lost. Rebuild the
        # public key from the identity — this needs the passphrase (the identity
        # is encrypted) but creates nothing new.
        self.ask_passphrase(
            self._do_recover,
            heading="Restore your public key",
            body="Your saved key is here, but its public address needs to be rebuilt. "
            "Enter your passphrase to restore it.",
        )

    def _do_recover(self, passphrase):
        try:
            self.my_pubkey = run_backend(["recover-pubkey"], passphrase=passphrase).decode("utf-8").strip()
            self.toast("Your key is ready.")
        except BackendError as e:
            self.error(str(e))

    def corrupt_identity(self):
        # identity.age exists but is empty/unreadable: there is no key in it to
        # recover. Be honest about the data loss and offer to start fresh.
        dlg = Adw.AlertDialog(
            heading="Your key file is damaged",
            body="VaultSend found a saved identity, but it is empty or unreadable and "
            "cannot be recovered. You can create a new key to continue — but anything "
            "that was encrypted only to the old key will no longer be readable.",
        )
        dlg.add_response("cancel", "Cancel")
        dlg.add_response("new", "Create new key")
        dlg.set_response_appearance("new", Adw.ResponseAppearance.DESTRUCTIVE)
        dlg.set_default_response("cancel")
        dlg.set_close_response("cancel")
        # keygen now replaces an invalid identity, so the normal create flow works.
        dlg.connect("response", lambda _d, r: self.first_run() if r == "new" else None)
        dlg.present(self)

    # -- File handling --------------------------------------------------------
    def on_file_dropped(self, _target, value, _x, _y):
        files = value.get_files()
        if files:
            self.handle_file(files[0].get_path())
        return True

    def open_file_dialog(self):
        dialog = Gtk.FileDialog(title="Open a file")

        def done(dlg, res):
            try:
                f = dlg.open_finish(res)
            except GLib.Error:
                return
            if f:
                self.handle_file(f.get_path())

        dialog.open(self, None, done)

    def handle_file(self, path):
        if not path:
            self.error("That item has no file path on disk.")
            return
        dlg = Adw.AlertDialog(
            heading="Encrypt or decrypt?",
            body=f"What should VaultSend do with “{os.path.basename(path)}”?",
        )
        dlg.add_response("cancel", "Cancel")
        dlg.add_response("decrypt", "Decrypt")
        dlg.add_response("encrypt", "Encrypt")
        dlg.set_response_appearance("encrypt", Adw.ResponseAppearance.SUGGESTED)
        dlg.set_default_response("encrypt")
        dlg.set_close_response("cancel")

        def resp(_d, r):
            if r == "encrypt":
                self.encrypt_file(path)
            elif r == "decrypt":
                self.decrypt_file(path)

        dlg.connect("response", resp)
        dlg.present(self)

    def encrypt_file(self, path):
        self.pick_recipients(lambda recips: self._save_then(
            os.path.basename(path) + ".age",
            lambda out: self._run_encrypt(["--in", path, "--out", out], recips, f"Encrypted to {len(recips)}."),
        ))

    def decrypt_file(self, path):
        suggested = os.path.basename(path)
        suggested = suggested[:-4] if suggested.endswith(".age") else suggested + ".decrypted"
        self.ask_passphrase(lambda p: self._save_then(
            suggested,
            lambda out: self._run_decrypt(["--in", path, "--out", out], p, "Decrypted."),
        ))

    def _save_then(self, suggested_name, callback):
        dialog = Gtk.FileDialog(title="Save as", initial_name=suggested_name)

        def done(dlg, res):
            try:
                f = dlg.save_finish(res)
            except GLib.Error:
                return
            if f:
                callback(f.get_path())

        dialog.save(self, None, done)

    def _run_encrypt(self, io_args, recips, note):
        args = ["encrypt"]
        for r in recips:
            args += ["-r", r]
        args += io_args
        try:
            run_backend(args)
            self.toast(note)
        except BackendError as e:
            self.error(str(e))

    def _run_decrypt(self, io_args, passphrase, note):
        try:
            run_backend(["decrypt", *io_args], passphrase=passphrase)
            self.toast(note)
        except BackendError as e:
            self.error(str(e))

    # -- Text handling --------------------------------------------------------
    def encrypt_text(self):
        text = self.get_text().strip()
        if not text:
            self.error("Type or paste a message first.")
            return
        self.pick_recipients(lambda recips: self._encrypt_text(text, recips))

    def _encrypt_text(self, text, recips):
        args = ["encrypt", "--armor"]
        for r in recips:
            args += ["-r", r]
        try:
            out = run_backend(args, input_bytes=text.encode("utf-8"))
            self.set_text(out.decode("utf-8"))
            self.toast("Encrypted. Copy the text below and send it.")
        except BackendError as e:
            self.error(str(e))

    def decrypt_text(self):
        text = self.get_text().strip()
        if not text:
            self.error("Paste the encrypted text first.")
            return
        self.ask_passphrase(lambda p: self._decrypt_text(text, p))

    def _decrypt_text(self, text, passphrase):
        try:
            out = run_backend(["decrypt"], input_bytes=text.encode("utf-8"), passphrase=passphrase)
            self.set_text(out.decode("utf-8", "replace"))
            self.toast("Decrypted.")
        except BackendError as e:
            self.error(str(e))

    # -- Dialogs --------------------------------------------------------------
    def pick_recipients(self, on_ok):
        if self.my_pubkey is None:
            self.error("Your key isn't ready yet.")
            return
        dlg = Adw.AlertDialog(heading="Encrypt to…", body="Everyone you choose will be able to decrypt it.")
        box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=6)
        checks = []
        you = Gtk.CheckButton(label=f"You ({short(self.my_pubkey)})", active=True, sensitive=False)
        box.append(you)
        for c in self.contacts:
            cb = Gtk.CheckButton(label=f"{c['name']} ({short(c['pubkey'])})")
            box.append(cb)
            checks.append((cb, c["pubkey"]))
        scroller = Gtk.ScrolledWindow(propagate_natural_height=True)
        scroller.set_min_content_height(80)
        scroller.set_max_content_height(260)
        scroller.set_child(box)
        dlg.set_extra_child(scroller)
        dlg.add_response("cancel", "Cancel")
        dlg.add_response("encrypt", "Encrypt")
        dlg.set_response_appearance("encrypt", Adw.ResponseAppearance.SUGGESTED)
        dlg.set_default_response("encrypt")
        dlg.set_close_response("cancel")

        def resp(_d, r):
            if r != "encrypt":
                return
            recips = [self.my_pubkey] + [pk for cb, pk in checks if cb.get_active()]
            on_ok(recips)

        dlg.connect("response", resp)
        dlg.present(self)

    def ask_passphrase(self, on_ok, heading="Unlock your key", body="Enter your passphrase.", confirm=False):
        dlg = Adw.AlertDialog(heading=heading, body=body)
        box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=6)
        entry = Gtk.PasswordEntry(show_peek_icon=True, activates_default=True)
        box.append(entry)
        entry2 = None
        if confirm:
            entry2 = Gtk.PasswordEntry(show_peek_icon=True, activates_default=True)
            box.append(Gtk.Label(label="Repeat passphrase", xalign=0))
            box.append(entry2)
        dlg.set_extra_child(box)
        dlg.add_response("cancel", "Cancel")
        dlg.add_response("ok", "Continue")
        dlg.set_response_appearance("ok", Adw.ResponseAppearance.SUGGESTED)
        dlg.set_default_response("ok")
        dlg.set_close_response("cancel")

        def resp(_d, r):
            if r != "ok":
                return
            p = entry.get_text()
            if not p:
                self.error("Passphrase can't be empty.")
                return
            if confirm and entry2 is not None and p != entry2.get_text():
                self.error("Those passphrases don't match.")
                return
            on_ok(p)

        dlg.connect("response", resp)
        dlg.present(self)

    def add_contact_dialog(self):
        dlg = Adw.AlertDialog(heading="Add contact", body="Paste the public key they shared with you.")
        box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=6)
        name = Gtk.Entry(placeholder_text="Name")
        key = Gtk.Entry(placeholder_text="age1…")
        box.append(name)
        box.append(key)
        dlg.set_extra_child(box)
        dlg.add_response("cancel", "Cancel")
        dlg.add_response("add", "Add")
        dlg.set_response_appearance("add", Adw.ResponseAppearance.SUGGESTED)
        dlg.set_default_response("add")
        dlg.set_close_response("cancel")

        def resp(_d, r):
            if r != "add":
                return
            n = name.get_text().strip()
            k = key.get_text().strip()
            if not n:
                self.error("Give the contact a name.")
                return
            if not looks_like_pubkey(k):
                self.error("That doesn't look like an age public key (age1…).")
                return
            self.contacts.append({"name": n, "pubkey": k})
            save_contacts(self.contacts)
            self._refresh_contacts()
            self.toast(f"Added {n}.")

        dlg.connect("response", resp)
        dlg.present(self)

    def on_show_key(self, *_):
        if not self.my_pubkey:
            self.error("Your key isn't ready yet.")
            return
        dlg = Adw.AlertDialog(
            heading="My public key",
            body="Share this with people who want to send you encrypted files. It is safe to share.",
        )
        label = Gtk.Label(label=self.my_pubkey, selectable=True, wrap=True, wrap_mode=2)
        label.add_css_class("monospace")
        dlg.set_extra_child(label)
        dlg.add_response("close", "Close")
        dlg.add_response("copy", "Copy")
        dlg.set_response_appearance("copy", Adw.ResponseAppearance.SUGGESTED)
        dlg.set_default_response("copy")
        dlg.connect("response", lambda _d, r: self.copy(self.my_pubkey, "Public key copied.") if r == "copy" else None)
        dlg.present(self)

    def on_about(self, *_):
        about = Adw.AboutDialog(
            application_name="VaultSend",
            application_icon="security-high-symbolic",
            developer_name="VaultSend",
            version="0.1.0",
            comments="File and text encryption using the age format. "
            "All cryptography is performed by a small separate backend.",
        )
        about.present(self)


class VaultSend(Adw.Application):
    def __init__(self):
        super().__init__(application_id=APP_ID, flags=Gio.ApplicationFlags.FLAGS_NONE)
        self.window = None

    def do_activate(self):
        if not self.window:
            self.window = Window(self)
        self.window.present()
        self.window.ensure_identity()


def main():
    Adw.init()
    return VaultSend().run(sys.argv)


if __name__ == "__main__":
    sys.exit(main())
