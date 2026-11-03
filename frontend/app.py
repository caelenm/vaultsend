#!/usr/bin/env python3
"""VaultSend — a small Adwaita front-end for the age-based encryption backend.

This process never sees your private key. It only:
  * keeps a list of contacts (their public keys) as plain JSON, and
  * runs the `vaultsend-backend` binary, which does all cryptography.

The private key lives, passphrase-encrypted, where only the backend reads it.
File plaintext from a vault never passes through this process either: the backend
decrypts it, verifies it and writes it straight to the location you choose, or, for
Open, to a private in-memory folder that another app reads it from.
"""

import hashlib
import json
import os
import shutil
import subprocess
import sys
import tempfile
import time
from pathlib import Path
from urllib.parse import unquote

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
VAULTS_FILE = CONFIG_DIR / "vaults.json"
SETTINGS_FILE = CONFIG_DIR / "settings.json"

DATA_DIR = Path(os.environ.get("XDG_DATA_HOME") or Path.home() / ".local" / "share") / "vaultsend"
VAULTS_DIR = DATA_DIR / "vaults"  # where a new vault goes unless you choose elsewhere
VAULT_SUFFIX = ".vsvault"
ROOT_ENTRY = "/"  # backend's name for the whole vault (ROOT_ENTRY in vault.rs)
OPEN_PREFIX = "vaultsend-open-"  # folders holding opened copies, cleared after a crash

APP_VERSION = "0.2.0"

# Required when creating a key. The passphrase is all that protects identity.age
# once it is backed up, so trivially guessable ones are refused. Unlocking an
# existing key accepts whatever passphrase it was made with.
MIN_PASSPHRASE_LEN = 10

# Suffix the backend stages file output under before renaming it into place
# (see staging_path() in backend/src/main.rs).
STAGING_SUFFIX = ".vaultsend-part"


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


def spawn_backend(args, *, passphrase=None):
    """Start the backend without waiting for it. Same passphrase handling as
    run_backend (a private pipe, never argv); returns the Popen.

    Only used for the file paths, where --in/--out are always given, so the
    child neither reads stdin nor writes payload to stdout. stderr stays a pipe
    because that is where a failure message arrives; it is a single short line,
    far below the pipe buffer, so the child can never block writing it."""
    extra = {}
    read_fd = None
    if passphrase is not None:
        read_fd, write_fd = os.pipe()
        os.write(write_fd, passphrase.encode("utf-8"))
        os.close(write_fd)
        args = list(args) + ["--pass-fd", str(read_fd)]
        extra["pass_fds"] = (read_fd,)
    try:
        return subprocess.Popen(
            [BACKEND, *args],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.PIPE,
            **extra,
        )
    except FileNotFoundError:
        raise BackendError(
            f"Backend not found at '{BACKEND}'.\nBuild it with 'cargo build --release' "
            "or set VAULTSEND_BACKEND."
        )
    finally:
        # The write end is already closed, so the child sees EOF regardless;
        # this just keeps the parent from leaking the descriptor.
        if read_fd is not None:
            try:
                os.close(read_fd)
            except OSError:
                pass


# ---------------------------------------------------------------------------
# Progress measurement
#
# Progress is read from the output file's size as the backend streams into it.
# That is a measurement of work actually completed, not a timer: age writes the
# payload in fixed chunks and the file grows in step with them.
#
# Reading the backend's own input offset from /proc/<pid>/fdinfo would be more
# direct, but harden_process() sets PR_SET_DUMPABLE(0) precisely so that a
# same-user process cannot inspect it — that includes us. The output file is the
# one honest channel that costs the backend nothing.
#
# The numerator is therefore exact. The denominator is derived, because age
# stores no plaintext length: for encryption it follows from the input size and
# the format's fixed overhead; for decryption it is the ciphertext size less
# that same overhead. Both land within a fraction of a percent at any size where
# a progress bar is worth showing.
# ---------------------------------------------------------------------------
AGE_CHUNK = 65536  # STREAM payload chunk, plaintext bytes
AGE_TAG = 16  # Poly1305 tag appended to every chunk
AGE_NONCE = 16  # STREAM nonce, once, before the first chunk
# The header is not a fixed size: it holds one stanza per recipient and its
# encoded fields vary in length. Measured against the age crate it runs roughly
# 190-350 bytes for a single recipient and grows about 100 per extra one, so
# this is a typical value rather than an exact one. At any file large enough for
# a progress bar to appear the difference is under a hundredth of a percent, and
# the bar clamps at both ends, so a miss in either direction is invisible.
AGE_HEADER = 300


def file_size(path) -> int:
    try:
        return os.path.getsize(path)
    except OSError:
        return 0


def is_armored(path) -> bool:
    try:
        with open(path, "rb") as f:
            return f.read(14) == b"-----BEGIN AGE"
    except OSError:
        return False


def expected_ciphertext_size(plaintext: int) -> int:
    """Size of the binary age file produced from `plaintext` bytes."""
    chunks = max(1, -(-plaintext // AGE_CHUNK))
    return AGE_HEADER + AGE_NONCE + plaintext + chunks * AGE_TAG


def expected_plaintext_size(path) -> int:
    """Size of the plaintext recovered from the age file at `path`."""
    size = file_size(path)
    if is_armored(path):
        # Armor emits 64 base64 characters plus a newline per 48 raw bytes,
        # wrapped in BEGIN/END lines.
        size = max(0, (size - 70) * 48 // 65)
    body = max(0, size - AGE_HEADER - AGE_NONCE)
    chunks = max(1, -(-body // (AGE_CHUNK + AGE_TAG)))
    return max(1, body - chunks * AGE_TAG)


def human_bytes(n: float) -> str:
    for unit in ("B", "KB", "MB", "GB"):
        if n < 1024 or unit == "GB":
            return f"{n:.0f} B" if unit == "B" else f"{n:.1f} {unit}"
        n /= 1024
    return f"{n:.1f} GB"


# ---------------------------------------------------------------------------
# Contacts (plain, exportable JSON)
# ---------------------------------------------------------------------------
def load_contacts() -> list:
    try:
        data = json.loads(CONTACTS_FILE.read_text("utf-8"))
    except (OSError, ValueError):
        return []
    if not isinstance(data, list):
        return []
    # Keep only well-formed entries: a hand-edited or foreign file must not be
    # able to crash startup (e.g. a list of strings, where `"name" in c` is a
    # substring test and c["name"] then raises).
    return [
        {"name": c["name"], "pubkey": c["pubkey"]}
        for c in data
        if isinstance(c, dict) and isinstance(c.get("name"), str) and isinstance(c.get("pubkey"), str)
    ]


def save_contacts(contacts: list) -> None:
    # Write a temp file and rename it over the old one, so a crash or full disk
    # mid-write can never leave a truncated contacts.json (which would load as
    # an empty list and then be saved over).
    CONFIG_DIR.mkdir(parents=True, exist_ok=True)
    tmp = CONTACTS_FILE.with_name(CONTACTS_FILE.name + ".tmp")
    with open(tmp, "w", encoding="utf-8") as f:
        f.write(json.dumps(contacts, indent=2))
        f.flush()
        os.fsync(f.fileno())
    os.replace(tmp, CONTACTS_FILE)


def is_valid_pubkey(s: str) -> bool:
    """True if `s` is an age X25519 recipient the backend accepts.

    Checked by the backend's own parser (bech32 checksum, HRP and key length)
    by encrypting zero bytes to it, rather than by a shape test that let typos
    through and then broke every later encryption to that contact."""
    s = s.strip()
    if not s.startswith("age1"):
        return False
    try:
        run_backend(["encrypt", "-r", s], input_bytes=b"")
        return True
    except BackendError:
        return False


def short(pubkey: str) -> str:
    return pubkey[:12] + "…" + pubkey[-6:] if len(pubkey) > 24 else pubkey


# ---------------------------------------------------------------------------
# Vault registry and settings (plain JSON; no secrets in either)
# ---------------------------------------------------------------------------
def save_json(path, value) -> None:
    # Temp file and rename, for the same reason as save_contacts().
    CONFIG_DIR.mkdir(parents=True, exist_ok=True)
    tmp = path.with_name(path.name + ".tmp")
    with open(tmp, "w", encoding="utf-8") as f:
        f.write(json.dumps(value, indent=2))
        f.flush()
        os.fsync(f.fileno())
    os.replace(tmp, path)


def load_vaults() -> list:
    """The vaults this device knows about. Besides name and location, each entry
    remembers two values for spotting tampering: the highest generation seen
    (rollback) and the hash of its key.age (a swapped key)."""
    try:
        data = json.loads(VAULTS_FILE.read_text("utf-8"))
    except (OSError, ValueError):
        return []
    if not isinstance(data, list):
        return []
    vaults = []
    for v in data:
        if not (isinstance(v, dict) and isinstance(v.get("name"), str) and isinstance(v.get("path"), str)):
            continue
        generation = v.get("last_generation")
        key = v.get("key_sha256")
        vaults.append({
            "name": v["name"],
            "path": v["path"],
            "mode": "password" if v.get("mode") == "password" else "self",
            "last_generation": generation if type(generation) is int and generation >= 0 else 0,
            "key_sha256": key if isinstance(key, str) else "",
        })
    return vaults


# How long a typed passphrase may be remembered: (value, menu label, seconds).
# None means until the app closes; it is never written to disk.
REMEMBER_CHOICES = (
    ("off", "Off", 0),
    ("5m", "5 minutes", 5 * 60),
    ("20m", "20 minutes", 20 * 60),
    ("1d", "1 day", 24 * 60 * 60),
    ("1w", "1 week", 7 * 24 * 60 * 60),
    ("session", "Until VaultSend closes", None),
)
REMEMBER_SECONDS = {value: seconds for value, _, seconds in REMEMBER_CHOICES}


def load_settings() -> dict:
    settings = {"remember": "off", "cache_explained": False, "open_explained": False}
    try:
        data = json.loads(SETTINGS_FILE.read_text("utf-8"))
    except (OSError, ValueError):
        return settings
    if isinstance(data, dict):
        if isinstance(data.get("remember"), str) and data["remember"] in REMEMBER_SECONDS:
            settings["remember"] = data["remember"]
        settings["cache_explained"] = data.get("cache_explained") is True
        settings["open_explained"] = data.get("open_explained") is True
    return settings


def is_valid_vault_name(name: str) -> bool:
    return (
        bool(name)
        and "/" not in name
        and "\0" not in name
        and name not in (".", "..")
        and len((name + VAULT_SUFFIX).encode("utf-8")) <= 255
    )


def read_vault_mode(path):
    """'self' or 'password' from a vault's VAULT file, or None if it isn't a vault.
    Only decides which prompt to show; the backend doesn't trust it either."""
    file = Path(path, "VAULT")
    try:
        # is_file first: reading a FIFO put here would hang the window, at startup.
        text = file.read_text("utf-8") if file.is_file() else ""
    except (OSError, ValueError):
        return None
    return {
        "vaultsend-vault 1\nmode self\n": "self",
        "vaultsend-vault 1\nmode password\n": "password",
    }.get(text)


def key_fingerprint(path) -> str:
    """SHA-256 of a vault's key.age, or "" if it can't be read. key.age is
    encrypted, so hashing it here touches no secret."""
    file = Path(path, "key.age")
    try:
        return hashlib.sha256(file.read_bytes()).hexdigest() if file.is_file() else ""
    except OSError:
        return ""


def parse_listing(text: str):
    """Turn `vault-list` output into (generation, entries), with paths unescaped and
    entries sorted for display: folder by folder, folders first. Names and sizes
    only; the backend never sends file content."""
    lines = text.split("\n")
    generation = int(lines[0].removeprefix("generation "))
    entries = []
    for line in lines[1:]:
        fields = line.split(" ")
        if fields[0] == "D" and len(fields) == 2:
            entries.append({"path": unquote(fields[1]), "is_dir": True, "size": 0})
        elif fields[0] == "F" and len(fields) == 3:
            entries.append({"path": unquote(fields[2]), "is_dir": False, "size": int(fields[1])})

    def order(entry):
        *parents, name = entry["path"].split("/")
        return [(0, p.casefold(), p) for p in parents] + [(0 if entry["is_dir"] else 1, name.casefold(), name)]

    return generation, sorted(entries, key=order)


def short_path(path: str) -> str:
    home = str(Path.home())
    if path == home or path.startswith(home + "/"):
        path = "~" + path[len(home):]
    parts = path.split("/")
    return path if len(parts) <= 3 else f"{parts[0]}/…/{parts[-1]}"


def memory_candidates() -> list:
    # $XDG_RUNTIME_DIR is private to this user and cleared at logout, so it comes first.
    # /dev/shm is shared, but mkdtemp makes a 0700 folder with an unguessable name in it.
    return [p for p in (os.environ.get("XDG_RUNTIME_DIR"), "/dev/shm") if p]


def is_in_memory(path) -> bool:
    try:
        info = Gio.File.new_for_path(str(path)).query_filesystem_info("filesystem::type", None)
    except GLib.Error:
        return False
    return info.get_attribute_string("filesystem::type") in ("tmpfs", "ramfs")


def memory_folder():
    """Where Open may put a decrypted copy, or None. Checked rather than assumed, so a
    copy can never quietly land on disk because a folder turned out not to be in RAM."""
    return next((p for p in memory_candidates() if is_in_memory(p)), None)


def clear_stale_copies() -> None:
    """Remove opened copies left behind by a crash. Only real folders of ours with our
    prefix: never a symlink, and never another user's in the shared /dev/shm."""
    for base in memory_candidates():
        try:
            with os.scandir(base) as entries:
                for entry in entries:
                    if (
                        entry.name.startswith(OPEN_PREFIX)
                        and entry.is_dir(follow_symlinks=False)
                        and entry.stat(follow_symlinks=False).st_uid == os.getuid()
                    ):
                        shutil.rmtree(entry.path, ignore_errors=True)
        except OSError:
            pass


def file_stamp(path):
    """Enough to notice an edit without reading the file: this process must never hold
    a vault file's plaintext, even to hash it."""
    try:
        info = os.stat(path)
    except OSError:
        return None
    return (info.st_mtime_ns, info.st_size)


class PassphraseCache:
    """Passphrases the user chose to have remembered, in this process's memory only.
    Keyed "identity" or ("vault", path). `clock` is injectable for the tests. Wall
    clock rather than monotonic, which on Linux stops counting while suspended."""

    def __init__(self, clock=time.time):
        self.clock = clock
        self.seconds = 0  # 0 = remember nothing; None = until the app closes
        self.entries = {}  # key -> (passphrase, expiry or None)

    def set_lifetime(self, seconds):
        self.seconds = seconds
        self.clear()

    def put(self, key, passphrase):
        if self.seconds != 0:
            expiry = None if self.seconds is None else self.clock() + self.seconds
            self.entries[key] = (passphrase, expiry)

    def get(self, key):
        self.sweep()
        entry = self.entries.get(key)
        return entry[0] if entry else None

    def forget(self, key):
        self.entries.pop(key, None)

    def sweep(self):
        now = self.clock()
        self.entries = {k: e for k, e in self.entries.items() if e[1] is None or now < e[1]}

    def clear(self):
        self.entries.clear()


# ---------------------------------------------------------------------------
# One file encrypt/decrypt, run without blocking the UI
# ---------------------------------------------------------------------------
class FileOperation:
    """Runs the backend on a file and reports real progress while it works.

    The backend was previously invoked with subprocess.run() straight from the
    GTK main loop, which froze the window for the whole operation and left no
    way to draw a bar. Here it is spawned instead, and a single 100 ms timer
    both polls for completion and samples the growing output file. No threads,
    so nothing touches GTK off the main loop.

    Failure handling: the backend stages both encrypt and decrypt output to
    `<out>.vaultsend-part` and renames it into place only once complete (for a
    decrypt, once the ciphertext has authenticated), so the destination is never
    a partial file. It cannot clean up after a signal, though, so on cancel or
    failure we remove the staging file ourselves.
    """

    POLL_MS = 100
    DIALOG_DELAY_MS = 400  # don't flash a dialog for a file that finishes at once
    KILL_AFTER_MS = 2000  # SIGKILL fallback if SIGTERM is ignored

    def __init__(self, window, args, *, passphrase=None, heading, subject, watch_path, total, note):
        self.window = window
        self.args = args
        self.passphrase = passphrase
        self.heading = heading
        self.subject = subject
        self.watch_path = watch_path  # file whose size tracks progress
        self.total = max(1, total)
        self.note = note  # toast on success

        self.proc = None
        self.dialog = None
        self.dialog_handler = None
        self.bar = None
        self.timer = None
        self.cancelled = False
        self.done = False

    # -- lifecycle ------------------------------------------------------------
    def start(self):
        try:
            self.proc = spawn_backend(self.args, passphrase=self.passphrase)
        except BackendError as e:
            self.window.error(str(e))
            self.window.current_op = None
            return
        self.timer = GLib.timeout_add(self.POLL_MS, self._tick)
        GLib.timeout_add(self.DIALOG_DELAY_MS, self._present_dialog)

    def _present_dialog(self):
        if self.done:
            return False
        self.bar = Gtk.ProgressBar(show_text=True, text="Starting…")
        self.dialog = Adw.AlertDialog(heading=self.heading, body=self.subject)
        self.dialog.set_extra_child(self.bar)
        self.dialog.add_response("cancel", "Cancel")
        self.dialog.set_close_response("cancel")
        # Closing the dialog programmatically also emits "response" with the
        # close response, so _finish() disconnects this before closing rather
        # than letting a completed operation report itself as cancelled.
        self.dialog_handler = self.dialog.connect(
            "response", lambda _d, r: self.cancel() if r == "cancel" else None
        )
        self.dialog.present(self.window)
        return False

    def _tick(self):
        if self.proc.poll() is None:
            self._update()
            return True
        self.timer = None
        self._finish()
        return False

    def _update(self):
        if self.bar is None:
            return
        written = file_size(self.watch_path)
        if written >= self.total:
            # The stream is through; the backend is now flushing, fsyncing and
            # renaming. That tail is real work with no byte count behind it, so
            # pulse rather than sit at a stalled 100%.
            self.bar.pulse()
            self.bar.set_text("Finishing…")
        else:
            fraction = written / self.total
            self.bar.set_fraction(fraction)
            self.bar.set_text(
                f"{fraction * 100:.0f}% — {human_bytes(written)} of {human_bytes(self.total)}"
            )

    def _finish(self):
        self.done = True
        if self.dialog is not None:
            self.dialog.disconnect(self.dialog_handler)
            self.dialog.close()
            self.dialog = None
        # The process has exited, so this returns immediately and cannot deadlock.
        _, err = self.proc.communicate()
        code = self.proc.returncode
        self.window.current_op = None

        if self.cancelled:
            self._discard_partials()
            self.window.toast("Cancelled.")
        elif code == 0:
            self.window.toast(self.note)
        else:
            self._discard_partials()
            msg = err.decode("utf-8", "replace").strip().removeprefix("error: ")
            # A signalled process (OOM killer, a crash) has no message of its own.
            self.window.error(msg or f"the operation failed (exit {code})")

    def cancel(self):
        if self.done or self.proc is None:
            return
        self.cancelled = True
        if self.bar is not None:
            self.bar.set_text("Cancelling…")
        self.proc.terminate()
        GLib.timeout_add(self.KILL_AFTER_MS, self._force_kill)

    def _force_kill(self):
        if not self.done and self.proc is not None and self.proc.poll() is None:
            self.proc.kill()
        return False

    def _discard_partials(self):
        """Remove the incomplete output.

        watch_path is exactly the file the backend was writing: the staging
        file `<out>.vaultsend-part`. `<out>` itself is never touched until the
        atomic rename, so a failed or cancelled run cannot cost the user an
        existing file."""
        try:
            os.remove(self.watch_path)
        except OSError:
            pass


class VaultOperation(FileOperation):
    """A vault command, run the same way as a file operation. A subclass so that
    FileOperation stays exactly as audited. A vault command has no output growing at
    a known rate (extract writes nothing until everything has verified in RAM), so
    the bar pulses instead of measuring.

    `partial` is what to remove after a cancel or failure: the staging path of an
    extract, which is a folder for a folder extract. `on_done` gets the failure
    message, or None on success or cancel."""

    def __init__(self, window, args, *, passphrase, heading, subject, note, on_done, partial=None):
        super().__init__(
            window, args, passphrase=passphrase, heading=heading, subject=subject,
            watch_path=partial, total=1, note=note,
        )
        self.on_done = on_done

    def _update(self):
        if self.bar is not None:
            self.bar.pulse()
            self.bar.set_text("Working…")

    def _finish(self):
        self.done = True
        if self.dialog is not None:
            self.dialog.disconnect(self.dialog_handler)
            self.dialog.close()
            self.dialog = None
        _, err = self.proc.communicate()
        code = self.proc.returncode
        self.window.current_op = None

        lines = err.decode("utf-8", "replace").strip().splitlines()
        warnings = [line.removeprefix("warning: ") for line in lines if line.startswith("warning: ")]
        if self.cancelled:
            self._discard_partials()
            self.window.toast("Cancelled.")
            self.on_done(None)
        elif code == 0:
            # Toasts parse markup, and a warning can name a path.
            note = f"{self.note} Note: {GLib.markup_escape_text(warnings[0])}." if warnings else self.note
            self.window.toast(note)
            self.on_done(None)
        else:
            self._discard_partials()
            errors = [line.removeprefix("error: ") for line in lines if line.startswith("error: ")]
            # A signalled process (OOM killer, a crash) has no message of its own.
            self.on_done(errors[-1] if errors else f"the operation failed (exit {code})")

    def _discard_partials(self):
        if self.watch_path and os.path.isdir(self.watch_path) and not os.path.islink(self.watch_path):
            shutil.rmtree(self.watch_path, ignore_errors=True)
        elif self.watch_path:
            super()._discard_partials()


# ---------------------------------------------------------------------------
# Main window
# ---------------------------------------------------------------------------
class Window(Adw.ApplicationWindow):
    def __init__(self, app):
        super().__init__(application=app, title="VaultSend")
        self.set_default_size(880, 600)
        self.my_pubkey = None
        self.contacts = load_contacts()
        self.current_op = None  # in-flight FileOperation, if any
        self.vaults = load_vaults()
        self.vault = None  # the vault selected in the sidebar, if any
        self.vault_entries = None  # its listing by path, or None while locked
        self.selected_entry = ROOT_ENTRY  # what Extract and Delete act on
        self.expanded = set()  # folders left open, kept across re-listing
        self.opened = []  # decrypted copies given to other apps; see vault_open()
        clear_stale_copies()
        self.connect("close-request", self._on_close_request)
        self.settings = load_settings()
        self.cache = PassphraseCache()
        self.cache.set_lifetime(REMEMBER_SECONDS[self.settings["remember"]])
        GLib.timeout_add_seconds(30, lambda: self.cache.sweep() or True)
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
        header.set_title_widget(self._build_mode_toggle())
        view.add_top_bar(header)

        box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL)
        add_btn = Gtk.Button(margin_top=8, margin_bottom=8, margin_start=8, margin_end=8)
        self.add_content = Adw.ButtonContent(icon_name="list-add-symbolic", label="Add contact")
        add_btn.set_child(self.add_content)
        add_btn.connect("clicked", lambda *_: self.on_add_clicked())
        box.append(add_btn)

        self.contact_list = Gtk.ListBox(selection_mode=Gtk.SelectionMode.NONE)
        self.contact_list.add_css_class("boxed-list")
        self.contact_list.set_margin_start(8)
        self.contact_list.set_margin_end(8)
        scroller = Gtk.ScrolledWindow(vexpand=True)
        scroller.set_child(self.contact_list)

        self.vault_list = Gtk.ListBox(selection_mode=Gtk.SelectionMode.SINGLE)
        self.vault_list.add_css_class("boxed-list")
        self.vault_list.set_margin_start(8)
        self.vault_list.set_margin_end(8)
        vault_scroller = Gtk.ScrolledWindow(vexpand=True)
        vault_scroller.set_child(self.vault_list)

        self.sidebar_stack = Gtk.Stack()
        self.sidebar_stack.add_named(scroller, "contacts")
        self.sidebar_stack.add_named(vault_scroller, "vaults")
        box.append(self.sidebar_stack)
        view.set_content(box)
        self._refresh_contacts()
        self._refresh_vaults()
        return view

    def _build_mode_toggle(self):
        # Two grouped toggle buttons rather than Adw.ToggleGroup, which needs
        # libadwaita 1.7; this app's floor is 1.5.
        self.contacts_toggle = Gtk.ToggleButton(label="Contacts", active=True)
        self.vaults_toggle = Gtk.ToggleButton(label="Vaults")
        self.vaults_toggle.set_group(self.contacts_toggle)
        # This one, not Contacts: a group deactivates the old button before activating
        # the new one, so only this one's state is right when "toggled" fires either way.
        self.vaults_toggle.connect("toggled", lambda *_: self._on_mode_toggled())
        box = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL)
        box.add_css_class("linked")
        box.append(self.contacts_toggle)
        box.append(self.vaults_toggle)
        return box

    def _on_mode_toggled(self):
        vaults = self.vaults_toggle.get_active()
        self.sidebar_stack.set_visible_child_name("vaults" if vaults else "contacts")
        self.add_content.set_label("Add vault" if vaults else "Add contact")
        self.content_stack.set_visible_child_name("vault" if vaults and self.vault else "send")

    def on_add_clicked(self):
        if self.vaults_toggle.get_active():
            self.add_vault_dialog()
        else:
            self.add_contact_dialog()

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

        toggle = Gtk.ToggleButton(icon_name="sidebar-show-symbolic", tooltip_text="Toggle sidebar")
        self.split.bind_property(
            "show-sidebar", toggle, "active", GObject.BindingFlags.BIDIRECTIONAL | GObject.BindingFlags.SYNC_CREATE
        )
        header.pack_start(toggle)
        header.set_title_widget(Adw.WindowTitle(title="VaultSend"))

        menu = Gio.Menu()
        menu.append("My public key", "win.show-key")
        remember = Gio.Menu()
        for value, label, _seconds in REMEMBER_CHOICES:
            remember.append(label, f"win.remember::{value}")
        menu.append_submenu("Remember passphrase", remember)
        menu.append("Lock now", "win.lock-now")
        menu.append("About VaultSend", "win.about")
        menu_btn = Gtk.MenuButton(icon_name="open-menu-symbolic", menu_model=menu, tooltip_text="Menu")
        header.pack_end(menu_btn)
        view.add_top_bar(header)

        self.toasts = Adw.ToastOverlay()
        view.set_content(self.toasts)

        clamp = Adw.Clamp(maximum_size=680, margin_top=24, margin_bottom=24, margin_start=16, margin_end=16)
        scroller = Gtk.ScrolledWindow(vexpand=True)
        scroller.set_child(clamp)
        self.content_stack = Gtk.Stack()
        self.content_stack.add_named(scroller, "send")
        self.content_stack.add_named(self._build_vault_page(), "vault")
        self.toasts.set_child(self.content_stack)

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
        drop.set_propagation_phase(Gtk.PropagationPhase.CAPTURE) 
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
        for name, fn in (("show-key", self.on_show_key), ("about", self.on_about), ("lock-now", self.on_lock_now)):
            act = Gio.SimpleAction.new(name, None)
            act.connect("activate", fn)
            self.add_action(act)
        remember = Gio.SimpleAction.new_stateful(
            "remember", GLib.VariantType.new("s"), GLib.Variant("s", self.settings["remember"])
        )
        remember.connect("change-state", self.on_remember_changed)
        self.add_action(remember)

    # -- Small helpers --------------------------------------------------------
    def toast(self, text):
        self.toasts.add_toast(Adw.Toast.new(text))

    def error(self, text):
        # Every identity decrypt reports failure through here, including the file
        # path's FileOperation, so this is the one place to drop a rejected passphrase.
        if "wrong passphrase" in text:
            self.cache.forget("identity")
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
        if files and files[0].get_path():
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
            lambda out: self._run_encrypt(path, out, recips),
        ))

    def decrypt_file(self, path):
        suggested = os.path.basename(path)
        suggested = suggested[:-4] if suggested.endswith(".age") else suggested + ".decrypted"
        self.with_passphrase("identity", lambda p: self._save_then(
            suggested,
            lambda out: self._run_decrypt(path, out, p),
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

    def _start_op(self, op):
        """Run one file operation at a time. The progress dialog is modal but
        only appears after a short delay, so without this guard a quick second
        drop could still start a concurrent backend."""
        if self.current_op is not None:
            self.error("Another file is still being processed.")
            return
        self.current_op = op
        op.start()

    def _run_encrypt(self, in_path, out_path, recips):
        args = ["encrypt"]
        for r in recips:
            args += ["-r", r]
        args += ["--in", in_path, "--out", out_path]
        self._start_op(FileOperation(
            self,
            args,
            heading="Encrypting…",
            subject=os.path.basename(in_path),
            # The backend stages the ciphertext and renames it into place when
            # done; the staging file's size tracks progress, and its final size
            # follows from the input plus the format's overhead.
            watch_path=out_path + STAGING_SUFFIX,
            total=expected_ciphertext_size(file_size(in_path)),
            note=f"Encrypted to {len(recips)}.",
        ))

    def _run_decrypt(self, in_path, out_path, passphrase):
        self._start_op(FileOperation(
            self,
            ["decrypt", "--in", in_path, "--out", out_path],
            passphrase=passphrase,
            heading="Decrypting…",
            subject=os.path.basename(in_path),
            # Decryption stages to a sibling temp and renames only once the
            # ciphertext authenticates, so the temp is what grows.
            watch_path=out_path + STAGING_SUFFIX,
            total=expected_plaintext_size(in_path),
            note="Decrypted.",
        ))

    # -- Text handling --------------------------------------------------------
    def encrypt_text(self):
        # Encrypted verbatim: leading/trailing whitespace is part of the message.
        text = self.get_text()
        if not text.strip():
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
        self.with_passphrase("identity", lambda p: self._decrypt_text(text, p))

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
            problem = None
            if not p:
                problem = "Passphrase can't be empty."
            elif confirm and len(p) < MIN_PASSPHRASE_LEN:
                problem = f"Use at least {MIN_PASSPHRASE_LEN} characters — a few random words works well."
            elif confirm and entry2 is not None and p != entry2.get_text():
                problem = "Those passphrases don't match."
            if problem:
                self.error(problem)
                # Creating a key: ask again. On first run nothing else in the
                # UI leads back to this dialog, so returning left the app with
                # no key until it was restarted.
                if confirm:
                    self.ask_passphrase(on_ok, heading=heading, body=body, confirm=confirm)
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
            if not is_valid_pubkey(k):
                self.error("That isn't a valid age public key (age1…). Check it was copied in full.")
                return
            if any(c["pubkey"] == k for c in self.contacts):
                self.error("That public key is already saved.")
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
            version=APP_VERSION,
            comments="File and text encryption using the age format. "
            "All cryptography is performed by a small separate backend. \n"
            "Source code can be found here: \n https://github.com/caelenm/vaultsend/",
        )
        about.present(self)

    # -- Remembered passphrases -----------------------------------------------
    def with_passphrase(self, key, on_ok, **dialog):
        """Call on_ok with the remembered passphrase for `key`, or ask for it."""
        cached = self.cache.get(key)
        if cached is not None:
            on_ok(cached)
            return

        def typed(passphrase):
            self.cache.put(key, passphrase)
            on_ok(passphrase)

        self.ask_passphrase(typed, **dialog)

    def on_remember_changed(self, action, value):
        choice = value.get_string()
        action.set_state(value)
        self.cache.set_lifetime(REMEMBER_SECONDS[choice])
        self.settings["remember"] = choice
        if choice != "off" and not self.settings["cache_explained"]:
            self.settings["cache_explained"] = True
            dlg = Adw.AlertDialog(
                heading="Remembering your passphrase",
                body="While remembered, your passphrase is held in this window's memory. It is "
                "never written to disk, but unlike the backend, this part of the app isn't locked "
                "out of swap, and Python can't reliably wipe text from memory. Use Lock now to "
                "forget it at any time.",
            )
            dlg.add_response("ok", "Got it")
            dlg.present(self)
        save_json(SETTINGS_FILE, self.settings)

    def on_lock_now(self, *_):
        def lock():
            self.cache.clear()
            self._discard_copies()
            if self.vault:
                self._show_locked()
            self.toast("Locked. Passphrases forgotten and opened files deleted.")

        self._confirm_discard(None, lock)

    # -- Vault list -----------------------------------------------------------
    def _refresh_vaults(self):
        child = self.vault_list.get_first_child()
        while child:
            self.vault_list.remove(child)
            child = self.vault_list.get_first_child()
        if not self.vaults:
            row = Adw.ActionRow(title="No vaults yet", subtitle="Create an encrypted folder, or add one you already have.")
            row.set_activatable(False)
            row.set_selectable(False)
            self.vault_list.append(row)
            return
        for v in self.vaults:
            kind = "Password" if v["mode"] == "password" else "Your key"
            found = read_vault_mode(v["path"]) is not None
            subtitle = f"{kind} · {short_path(v['path'])}" if found else "Not found"
            # Names can come from folder names on disk, so they are never markup.
            row = Adw.ActionRow(title=v["name"], subtitle=subtitle, use_markup=False)
            row.set_activatable(found)
            row.set_selectable(found)
            row.connect("activated", lambda _r, vault=v: self.select_vault(vault))
            self._attach_vault_menu(row, v)
            self.vault_list.append(row)
            if v is self.vault:
                self.vault_list.select_row(row)

    def _attach_vault_menu(self, row, vault):
        click = Gtk.GestureClick(button=Gdk.BUTTON_SECONDARY)
        click.connect("pressed", lambda _g, _n, x, y: self._show_vault_menu(row, vault, x, y))
        row.add_controller(click)
        press = Gtk.GestureLongPress()
        press.connect("pressed", lambda _g, x, y: self._show_vault_menu(row, vault, x, y))
        row.add_controller(press)

    def _show_vault_menu(self, row, vault, x, y):
        pop = Gtk.Popover(has_arrow=False, autohide=True)
        pop.set_parent(row)
        rect = Gdk.Rectangle()
        rect.x, rect.y, rect.width, rect.height = int(x), int(y), 1, 1
        pop.set_pointing_to(rect)

        btn = Gtk.Button()
        btn.add_css_class("flat")
        btn.add_css_class("vaultsend-delete")
        content = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=8)
        content.append(Gtk.Image.new_from_icon_name("list-remove-symbolic"))
        content.append(Gtk.Label(label="Remove from list"))
        btn.set_child(content)

        def on_click(_b):
            pop.popdown()
            self._confirm_forget_vault(vault)

        btn.connect("clicked", on_click)
        pop.set_child(btn)
        pop.connect("closed", lambda p: GLib.idle_add(lambda: p.unparent() or False))
        pop.popup()
        return pop

    def _confirm_forget_vault(self, vault):
        dlg = Adw.AlertDialog(
            heading="Remove from list?",
            body=f"This only makes VaultSend forget “{vault['name']}”. It does not delete the "
            f"vault or any file in it, which stay in {vault['path']}.",
        )
        dlg.add_response("cancel", "Cancel")
        dlg.add_response("remove", "Remove from list")
        dlg.set_default_response("cancel")
        dlg.set_close_response("cancel")

        def resp(_d, r):
            if r != "remove":
                return
            self.vaults = [v for v in self.vaults if v is not vault]
            save_json(VAULTS_FILE, self.vaults)
            if self.vault is vault:
                self.vault = None
                self.content_stack.set_visible_child_name("send")
            self._refresh_vaults()

        dlg.connect("response", resp)
        dlg.present(self)

    def select_vault(self, vault):
        if vault is not self.vault:
            self.vault = vault
            self.vault_title.set_label(vault["name"])
            self._show_locked()
        self.content_stack.set_visible_child_name("vault")

    # -- Adding a vault -------------------------------------------------------
    def add_vault_dialog(self):
        dlg = Adw.AlertDialog(heading="Add vault", body="A vault is an encrypted folder of files.")
        box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=6)
        name = Gtk.Entry(placeholder_text="Vault name")
        box.append(name)

        how = Gtk.Label(label="Protection", xalign=0, margin_top=8)
        how.add_css_class("heading")
        box.append(how)
        with_key = Gtk.CheckButton(label="Encrypt with my key (simplest, secure)", active=True)
        with_password = Gtk.CheckButton(label="Use a password (shareable)")
        with_password.set_group(with_key)
        box.append(with_key)
        box.append(with_password)

        where = Gtk.Label(label="Location", xalign=0, margin_top=8)
        where.add_css_class("heading")
        box.append(where)
        default_place = Gtk.CheckButton(label="Default", active=True)
        chosen_place = Gtk.CheckButton(label="Select a location…")
        chosen_place.set_group(default_place)
        default_path = Gtk.Label(xalign=0, wrap=True, wrap_mode=2, margin_start=28)
        default_path.add_css_class("dim-label")
        default_path.add_css_class("caption")
        box.append(default_place)
        box.append(default_path)
        box.append(chosen_place)

        def show_default_path(*_):
            default_path.set_label(str(VAULTS_DIR / (name.get_text().strip() + VAULT_SUFFIX)))

        name.connect("changed", show_default_path)
        show_default_path()

        dlg.set_extra_child(box)
        dlg.add_response("cancel", "Cancel")
        dlg.add_response("existing", "Add existing vault…")
        dlg.add_response("create", "Create")
        dlg.set_response_appearance("create", Adw.ResponseAppearance.SUGGESTED)
        dlg.set_default_response("create")
        dlg.set_close_response("cancel")

        def resp(_d, r):
            if r == "existing":
                self._pick_folder("Add existing vault", self._add_existing_vault)
            if r != "create":
                return
            n = name.get_text().strip()
            if not is_valid_vault_name(n):
                self.error("Give the vault a name, without any “/” in it.")
                return
            mode = "password" if with_password.get_active() else "self"
            if chosen_place.get_active():
                self._pick_folder(
                    "Where should the vault go?",
                    lambda folder: self._begin_create(n, os.path.join(folder, n + VAULT_SUFFIX), mode),
                )
            else:
                self._begin_create(n, str(VAULTS_DIR / (n + VAULT_SUFFIX)), mode)

        dlg.connect("response", resp)
        dlg.present(self)
        return dlg

    def _pick_folder(self, title, on_ok):
        dialog = Gtk.FileDialog(title=title)

        def done(dlg, res):
            try:
                f = dlg.select_folder_finish(res)
            except GLib.Error:
                return
            if f and f.get_path():
                on_ok(f.get_path())

        dialog.select_folder(self, None, done)

    def _begin_create(self, name, path, mode):
        if mode == "password":
            self.ask_passphrase(
                lambda p: self._create_vault(name, path, mode, p),
                heading="Choose a vault password",
                body="Anyone with this password and a copy of the vault can open it. "
                "If you lose it, the files can't be recovered.",
                confirm=True,
            )
        else:
            self._create_vault(name, path, mode, None)

    def _create_vault(self, name, path, mode, password):
        if mode == "self" and self.my_pubkey is None:
            self.error("Your key isn't ready yet.")
            return
        try:
            run_backend(["vault-create", "--dir", path, "--mode", mode], passphrase=password)
        except BackendError as e:
            self._vault_error("Couldn't create the vault", str(e))
            return
        vault = self._remember_vault(name, path, mode)
        if password is not None:
            self.cache.put(self._secret_key(vault), password)
        self.toast("Vault created.")

    def _add_existing_vault(self, path):
        mode = read_vault_mode(path)
        if mode is None:
            self._vault_error("That isn't a vault", "The folder you chose has no valid VAULT file.")
            return
        if any(v["path"] == path for v in self.vaults):
            self.error("That vault is already in your list.")
            return
        name = os.path.basename(path.rstrip("/")).removesuffix(VAULT_SUFFIX)
        self._remember_vault(name, path, mode)

    def _remember_vault(self, name, path, mode):
        # The key pinned here is trusted as found, the same as any first use.
        vault = {
            "name": name, "path": path, "mode": mode,
            "last_generation": 0, "key_sha256": key_fingerprint(path),
        }
        self.vaults.append(vault)
        save_json(VAULTS_FILE, self.vaults)
        self.select_vault(vault)
        self._refresh_vaults()
        return vault

    # -- Vault page -----------------------------------------------------------
    def _build_vault_page(self):
        clamp = Adw.Clamp(maximum_size=680, margin_top=24, margin_bottom=24, margin_start=16, margin_end=16)
        col = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=16)
        clamp.set_child(col)

        self.vault_title = Gtk.Label(xalign=0, wrap=True, wrap_mode=2)
        self.vault_title.add_css_class("title-2")
        col.append(self.vault_title)

        files_row = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL)
        files_heading = Gtk.Label(label="Files", xalign=0, hexpand=True)
        files_heading.add_css_class("heading")
        self.verify_btn = Gtk.Button(label="Verify all", tooltip_text="Check every file in this vault for tampering")
        self.verify_btn.add_css_class("flat")
        self.verify_btn.connect("clicked", lambda *_: self.vault_verify())
        files_row.append(files_heading)
        files_row.append(self.verify_btn)
        col.append(files_row)

        unlock = Gtk.Button(label="Unlock", halign=Gtk.Align.CENTER)
        unlock.add_css_class("pill")
        unlock.add_css_class("suggested-action")
        unlock.connect("clicked", lambda *_: self.vault_unlock())
        locked = Adw.StatusPage(icon_name="changes-prevent-symbolic", title="Locked")
        locked.set_child(unlock)

        self.file_list = Gtk.ListBox(selection_mode=Gtk.SelectionMode.NONE, valign=Gtk.Align.START)
        self.file_list.add_css_class("boxed-list")
        file_scroller = Gtk.ScrolledWindow(vexpand=True, hscrollbar_policy=Gtk.PolicyType.NEVER)
        file_scroller.set_child(self.file_list)

        self.vault_body = Gtk.Stack(vexpand=True)
        self.vault_body.add_named(locked, "locked")
        self.vault_body.add_named(file_scroller, "files")
        col.append(self.vault_body)

        self.vault_actions = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=8)
        for label, handler in (
            ("Add files…", self.vault_add_files),
            ("Add folder…", self.vault_add_folder),
            (None, None),
            ("Open", self.vault_open),
            ("Extract…", self.vault_extract),
            ("Delete", self.vault_delete),
            ("Lock", self.vault_lock),
        ):
            if label is None:
                self.vault_actions.append(Gtk.Box(hexpand=True))
                continue
            btn = Gtk.Button(label=label)
            btn.connect("clicked", lambda _b, fn=handler: fn())
            self.vault_actions.append(btn)
        col.append(self.vault_actions)

        drop = Gtk.DropTarget.new(Gdk.FileList, Gdk.DragAction.COPY)
        drop.connect("drop", self.on_vault_drop)
        clamp.add_controller(drop)
        self._show_locked()
        return clamp

    def _show_locked(self):
        """Drop the listing. It is only metadata, but locked means locked."""
        self.vault_entries = None
        self.selected_entry = ROOT_ENTRY
        child = self.file_list.get_first_child()
        while child:
            self.file_list.remove(child)
            child = self.file_list.get_first_child()
        self.vault_body.set_visible_child_name("locked")
        self.vault_actions.set_sensitive(False)
        self.verify_btn.set_sensitive(False)

    def _show_files(self, entries):
        self._show_locked()
        self.vault_entries = {e["path"]: e for e in entries}
        files = [e for e in entries if not e["is_dir"]]

        # One radio group across every row, however deeply nested. "Everything" is
        # always there to come back to, so Extract never needs a hidden default.
        everything = Gtk.CheckButton(active=True, valign=Gtk.Align.CENTER)
        everything.connect("toggled", self._on_entry_toggled, ROOT_ENTRY)
        total = human_bytes(sum(e["size"] for e in files))
        count = "1 file" if len(files) == 1 else f"{len(files)} files"
        top = Adw.ActionRow(title="Everything in this vault", subtitle=f"{count}, {total}")
        top.add_prefix(everything)
        top.set_activatable_widget(everything)
        self.file_list.append(top)

        folders = {}
        for e in entries:
            parent, _, name = e["path"].rpartition("/")
            radio = Gtk.CheckButton(valign=Gtk.Align.CENTER)
            radio.set_group(everything)
            radio.connect("toggled", self._on_entry_toggled, e["path"])
            if e["is_dir"]:
                row = Adw.ExpanderRow(title=name + "/", use_markup=False)
                row.set_expanded(e["path"] in self.expanded)
                row.connect("notify::expanded", self._on_folder_expanded, e["path"])
                folders[e["path"]] = row
            else:
                row = Adw.ActionRow(title=name, subtitle=human_bytes(e["size"]), use_markup=False)
                row.set_activatable_widget(radio)
            row.add_prefix(radio)
            if parent in folders:
                folders[parent].add_row(row)
            else:
                self.file_list.append(row)

        self.vault_body.set_visible_child_name("files")
        self.vault_actions.set_sensitive(True)
        self.verify_btn.set_sensitive(True)

    def _on_entry_toggled(self, radio, path):
        if radio.get_active():
            self.selected_entry = path

    def _on_folder_expanded(self, row, _pspec, path):
        (self.expanded.add if row.get_expanded() else self.expanded.discard)(path)

    # -- Vault operations -----------------------------------------------------
    def _secret_key(self, vault):
        return "identity" if vault["mode"] == "self" else ("vault", vault["path"])

    def _vault_error(self, heading, message):
        # A dialog, not a toast: a failed integrity check must not fade away by itself.
        dlg = Adw.AlertDialog(heading=heading, body=message)
        dlg.add_response("close", "Close")
        dlg.present(self)

    def _vault_failed(self, vault, message):
        if "wrong pass" in message:
            self.cache.forget(self._secret_key(vault))
        self._vault_error(f"Problem with “{vault['name']}”", message)

    def with_vault_secret(self, vault, on_ok):
        """The way into every operation: check the vault's key file hasn't been
        swapped, and only then ask for (or recall) the secret."""
        def ask():
            if vault["mode"] == "self":
                self.with_passphrase("identity", on_ok)
            else:
                self.with_passphrase(
                    self._secret_key(vault), on_ok,
                    heading="Unlock vault", body=f"Enter the password for “{vault['name']}”.",
                )

        current = key_fingerprint(vault["path"])
        if not vault["key_sha256"] and current:
            vault["key_sha256"] = current  # added before keys were remembered
            save_json(VAULTS_FILE, self.vaults)
        if current in ("", vault["key_sha256"]):  # unreadable: the backend will say so
            ask()
            return
        dlg = Adw.AlertDialog(
            heading="This vault's key has changed",
            body=f"The key file in “{vault['name']}” isn't the one this device remembers, and it "
            "never changes in normal use. Someone with access to the folder may have replaced "
            "it, and anything you add could then be readable by them.\n\nContinue only if you "
            "know why it changed, for example if you put a different vault in this folder.",
        )
        dlg.add_response("cancel", "Cancel")
        dlg.add_response("trust", "Trust the new key")
        dlg.set_response_appearance("trust", Adw.ResponseAppearance.DESTRUCTIVE)
        dlg.set_default_response("cancel")
        dlg.set_close_response("cancel")

        def resp(_d, r):
            if r == "trust":
                vault["key_sha256"] = current
                save_json(VAULTS_FILE, self.vaults)
                ask()

        dlg.connect("response", resp)
        dlg.present(self)

    def _vault_args(self, vault, command, *rest):
        # The pin also goes to the backend, which checks it against the exact bytes
        # it decrypts: the check above can't see a swap made after it ran.
        pin = ["--key-sha256", vault["key_sha256"]] if vault["key_sha256"] else []
        return [command, "--dir", vault["path"], *pin, *rest]

    def vault_unlock(self):
        vault = self.vault
        self.with_vault_secret(vault, lambda p: self._list_vault(vault, p))

    def _list_vault(self, vault, passphrase):
        try:
            out = run_backend(self._vault_args(vault, "vault-list"), passphrase=passphrase)
            generation, entries = parse_listing(out.decode("utf-8"))
        except (BackendError, ValueError, IndexError) as e:
            self._vault_failed(vault, str(e))
            return
        if self.vault is not vault:
            return
        if generation >= vault["last_generation"]:
            self._accept_listing(vault, generation, entries)
            return
        dlg = Adw.AlertDialog(
            heading="This vault looks older",
            body="This vault is older than the last version this device saw. It may have been "
            "restored from a backup — or rolled back by someone else.",
        )
        dlg.add_response("cancel", "Cancel")
        dlg.add_response("open", "Open anyway")
        dlg.set_response_appearance("open", Adw.ResponseAppearance.DESTRUCTIVE)
        dlg.set_default_response("cancel")
        dlg.set_close_response("cancel")

        def resp(_d, r):
            if r == "open":
                self._accept_listing(vault, generation, entries)
            else:
                self._show_locked()

        dlg.connect("response", resp)
        dlg.present(self)

    def _accept_listing(self, vault, generation, entries):
        vault["last_generation"] = generation
        save_json(VAULTS_FILE, self.vaults)
        self._show_files(entries)

    def _run_vault_op(self, vault, passphrase, args, *, heading, subject, note, partial=None, relist=False, after=None):
        def done(failure):
            if failure is not None:
                self._vault_failed(vault, failure)
            elif relist and self.vault is vault:
                self._list_vault(vault, passphrase)  # same secret, so no second prompt
            if after:
                after()

        self._start_op(VaultOperation(
            self, self._vault_args(vault, *args), passphrase=passphrase,
            heading=heading, subject=subject, note=note, partial=partial, on_done=done,
        ))

    def vault_add_files(self):
        dialog = Gtk.FileDialog(title="Add files")

        def done(dlg, res):
            try:
                files = dlg.open_multiple_finish(res)
            except GLib.Error:
                return
            self._add_paths([f.get_path() for f in files if f.get_path()])

        dialog.open_multiple(self, None, done)

    def vault_add_folder(self):
        self._pick_folder("Add folder", lambda path: self._add_paths([path]))

    def on_vault_drop(self, _target, value, _x, _y):
        if self.vault_entries is None:
            self.error("Unlock the vault first.")
            return False
        self._add_paths([f.get_path() for f in value.get_files() if f.get_path()])
        return True

    def _add_paths(self, paths):
        if not paths or self.vault_entries is None:
            return
        # Into the selected folder, or the folder of the selected file.
        selected = self.vault_entries.get(self.selected_entry)
        dest = self.selected_entry if selected and selected["is_dir"] else self.selected_entry.rpartition("/")[0]
        targets =[f"{dest}/{os.path.basename(p.rstrip('/'))}".lstrip("/") for p in paths]
        clashes = [t for t in targets if t in self.vault_entries]
        vault = self.vault

        def run(replace):
            args = ["vault-add"]
            for p in paths:
                args += ["--src", p]
            if dest:
                args += ["--dest", dest]
            if replace:
                args.append("--replace")
            self.with_vault_secret(vault, lambda s: self._run_vault_op(
                vault, s, args, heading="Adding to vault…", subject=vault["name"],
                note="Added to the vault.", relist=True,
            ))

        if not clashes:
            run(False)
            return
        dlg = Adw.AlertDialog(
            heading="Replace existing items?",
            body="Already in this vault:\n" + "\n".join(clashes[:5]) + ("\n…" if len(clashes) > 5 else ""),
        )
        dlg.add_response("cancel", "Cancel")
        dlg.add_response("replace", "Replace")
        dlg.set_response_appearance("replace", Adw.ResponseAppearance.DESTRUCTIVE)
        dlg.set_default_response("cancel")
        dlg.set_close_response("cancel")
        dlg.connect("response", lambda _d, r: run(True) if r == "replace" else None)
        dlg.present(self)

    def vault_extract(self):
        vault, entry = self.vault, self.selected_entry
        suggested = vault["name"] if entry == ROOT_ENTRY else os.path.basename(entry)
        self.with_vault_secret(vault, lambda s: self._save_then(
            suggested,
            lambda out: self._run_vault_op(
                vault, s, ["vault-extract", "--entry", entry, "--out", out],
                heading="Extracting…", subject=suggested, note="Extracted.", partial=out + STAGING_SUFFIX,
            ),
        ))

    def vault_delete(self):
        vault, entry = self.vault, self.selected_entry
        if entry == ROOT_ENTRY:
            self.error("Select a file or folder to delete.")
            return
        is_dir = self.vault_entries[entry]["is_dir"]
        dlg = Adw.AlertDialog(
            heading="Delete from vault?",
            body=f"“{entry}”{' and everything in it' if is_dir else ''} will be permanently "
            "deleted from this vault. This can't be undone.",
        )
        dlg.add_response("cancel", "Cancel")
        dlg.add_response("delete", "Delete")
        dlg.set_response_appearance("delete", Adw.ResponseAppearance.DESTRUCTIVE)
        dlg.set_default_response("cancel")
        dlg.set_close_response("cancel")

        def resp(_d, r):
            if r == "delete":
                self.with_vault_secret(vault, lambda s: self._run_vault_op(
                    vault, s, ["vault-remove", "--entry", entry],
                    heading="Deleting…", subject=os.path.basename(entry), note="Deleted.", relist=True,
                ))

        dlg.connect("response", resp)
        dlg.present(self)

    def vault_verify(self):
        vault = self.vault
        self.with_vault_secret(vault, lambda s: self._run_vault_op(
            vault, s, ["vault-check"],
            heading="Verifying…", subject=vault["name"], note="Every file verified.",
        ))

    def vault_lock(self):
        vault = self.vault

        def lock():
            self.cache.forget(self._secret_key(vault))
            self._discard_copies(vault)
            self._show_locked()

        self._confirm_discard(vault, lock)

    # -- Opening a file in another app ----------------------------------------
    def vault_open(self):
        """The backend decrypts a copy into a private in-memory folder, and the file's
        default app opens it from there. This process only ever handles its path.

        Once another app has the file, this one can't vouch for it: the app can write
        its own copies to disk. So the first use says so and asks for an acknowledgement."""
        vault, entry = self.vault, self.selected_entry
        selected = self.vault_entries.get(entry)
        if selected is None or selected["is_dir"]:
            self.error("Select a file to open.")
            return
        if self.settings["open_explained"]:
            self._open_entry(vault, entry)
            return
        dlg = Adw.AlertDialog(
            heading="Opening outside the vault",
            body="VaultSend will decrypt a copy into memory and open it in another app. That app "
            "may save its own unencrypted copies to your disk, such as recovery files and "
            "thumbnails, and VaultSend can't remove those.\n\nThe copy is deleted when you lock "
            "the vault or close VaultSend. Changes aren't saved back to the vault.",
        )
        dlg.add_response("cancel", "Cancel")
        dlg.add_response("understand", "I understand")
        dlg.set_response_appearance("understand", Adw.ResponseAppearance.DESTRUCTIVE)
        dlg.set_default_response("cancel")
        dlg.set_close_response("cancel")

        def resp(_d, r):
            if r == "understand":
                self.settings["open_explained"] = True
                save_json(SETTINGS_FILE, self.settings)
                self._open_entry(vault, entry)

        dlg.connect("response", resp)
        dlg.present(self)

    def _open_entry(self, vault, entry):
        base = memory_folder()
        if base is None:
            self._vault_error(
                "Can't open this file",
                "This system has no in-memory folder to put it in, and VaultSend won't write it to "
                "disk by itself. Use Extract… to save it somewhere you choose.",
            )
            return
        if self.current_op is not None:
            self.error("Another file is still being processed.")
            return
        name = os.path.basename(entry)

        def extract(secret):
            try:
                folder = tempfile.mkdtemp(prefix=OPEN_PREFIX, dir=base)
            except OSError as e:
                self._vault_error("Can't open this file", str(e))
                return
            # Tracked from here on, so it is deleted however this goes.
            copy = {"vault": vault["path"], "name": name, "folder": folder,
                    "path": os.path.join(folder, name), "stamp": None}
            self.opened.append(copy)

            def extracted():
                copy["stamp"] = file_stamp(copy["path"])
                if copy["stamp"] is None:  # failed or cancelled: the reason is already shown
                    self._discard_copy(copy)
                else:
                    self._launch_copy(copy)

            self._run_vault_op(
                vault, secret, ["vault-extract", "--entry", entry, "--out", copy["path"]],
                heading="Opening…", subject=name, note="Opening in its default app.",
                partial=copy["path"] + STAGING_SUFFIX, after=extracted,
            )

        self.with_vault_secret(vault, extract)

    def _launch_copy(self, copy):
        def done(launcher, res):
            try:
                launcher.launch_finish(res)
            except GLib.Error:
                self._discard_copy(copy)
                self._vault_error(
                    "Couldn't open that file",
                    "No app on this system could open it. Use Extract… to save it somewhere you "
                    "choose instead.",
                )

        Gtk.FileLauncher(file=Gio.File.new_for_path(copy["path"])).launch(self, None, done)

    def _copies(self, vault=None):
        return [c for c in self.opened if vault is None or c["vault"] == vault["path"]]

    def _discard_copy(self, copy):
        shutil.rmtree(copy["folder"], ignore_errors=True)
        self.opened.remove(copy)

    def _discard_copies(self, vault=None):
        for copy in self._copies(vault):
            self._discard_copy(copy)

    def _edited_copies(self, vault=None):
        return [
            c["name"] for c in self._copies(vault)
            if c["stamp"] is not None and file_stamp(c["path"]) != c["stamp"]
        ]

    def _confirm_discard(self, vault, then):
        """Run `then`, which deletes opened copies, asking first if any have been edited,
        because that work has nowhere else to go. Edits still unsaved in another app can't
        be seen from here; the warning before the first Open covers those."""
        edited = self._edited_copies(vault)
        if not edited:
            then()
            return
        dlg = Adw.AlertDialog(
            heading="Changes will be lost",
            body="These opened files have changed, and changes aren't saved back to the vault:\n"
            + "\n".join(edited[:5]) + ("\n…" if len(edited) > 5 else "")
            + "\n\nTo keep them, use Save As in that app to save elsewhere, then add the file back.",
        )
        dlg.add_response("cancel", "Cancel")
        dlg.add_response("discard", "Delete changes")
        dlg.set_response_appearance("discard", Adw.ResponseAppearance.DESTRUCTIVE)
        dlg.set_default_response("cancel")
        dlg.set_close_response("cancel")
        dlg.connect("response", lambda _d, r: then() if r == "discard" else None)
        dlg.present(self)

    def _on_close_request(self, _window):
        if not self._edited_copies():
            return False  # nothing to lose; do_shutdown deletes the copies

        def close():
            self._discard_copies()
            self.close()

        self._confirm_discard(None, close)
        return True


class VaultSend(Adw.Application):
    def __init__(self):
        super().__init__(application_id=APP_ID, flags=Gio.ApplicationFlags.FLAGS_NONE)
        self.window = None

    def do_activate(self):
        if not self.window:
            self.window = Window(self)
        self.window.present()
        self.window.ensure_identity()

    def do_shutdown(self):
        if self.window:
            self.window.cache.clear()
            self.window._discard_copies()
        Adw.Application.do_shutdown(self)


def main():
    Adw.init()
    return VaultSend().run(sys.argv)


if __name__ == "__main__":
    sys.exit(main())
