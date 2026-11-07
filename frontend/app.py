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

import json
import os
import shutil
import subprocess
import sys
import tempfile
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
INDENT_STEP = 20  # pixels a row in a vault's file list sits in, per folder level
INDENT_LEVELS = 6  # no further: the list can't scroll sideways, so more would widen the window
OPEN_ASK_ABOVE = 10  # opening more files than this at once asks first: each one starts an app
KEY_MISMATCH = "does not open with your key"  # the backend's words for a `self` vault of someone else's

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
    save_json(CONTACTS_FILE, contacts)


def save_json(path, value) -> None:
    # Write a temp file and rename it over the old one, so a crash or full disk
    # mid-write can never leave a truncated file (contacts.json would then load as
    # an empty list and be saved over). Private: who you talk to, and your vaults'
    # names and locations, are nobody else's business on a shared machine.
    CONFIG_DIR.mkdir(parents=True, exist_ok=True)
    tmp = path.with_name(path.name + ".tmp")
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with open(fd, "w", encoding="utf-8") as f:
        os.fchmod(fd, 0o600)  # a temp file left by a crash keeps its old mode otherwise
        f.write(json.dumps(value, indent=2))
        f.flush()
        os.fsync(f.fileno())
    os.replace(tmp, path)


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
def load_vaults() -> list:
    """The vaults this device knows about. Besides name and location, each entry
    remembers the highest generation seen, for spotting a rollback."""
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
        vaults.append({
            "name": v["name"],
            "path": v["path"],
            "mode": "password" if v.get("mode") == "password" else "self",
            "last_generation": generation if type(generation) is int and generation >= 0 else 0,
        })
    return vaults


# Whether a typed passphrase is remembered: (value, menu label). "session" keeps it
# until the app closes; it is never written to disk.
REMEMBER_CHOICES = (
    ("off", "Off"),
    ("session", "Until VaultSend closes"),
)
REMEMBER_VALUES = {value for value, _ in REMEMBER_CHOICES}


def load_settings() -> dict:
    settings = {"remember": "off", "cache_explained": False, "open_explained": False}
    try:
        data = json.loads(SETTINGS_FILE.read_text("utf-8"))
    except (OSError, ValueError):
        return settings
    if isinstance(data, dict):
        if isinstance(data.get("remember"), str) and data["remember"] in REMEMBER_VALUES:
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


def entry_indent(path: str) -> int:
    return min(path.count("/"), INDENT_LEVELS) * INDENT_STEP


def parent_folders(path: str) -> list:
    """Every folder leading to `path`, outermost first: "a/b/c" gives "a", "a/b"."""
    parts = path.split("/")
    return ["/".join(parts[:i]) for i in range(1, len(parts))]


def top_level_selection(paths) -> list:
    """What a set of ticked rows comes to: a ticked folder already covers what's in it."""
    chosen = set(paths)
    if ROOT_ENTRY in chosen:
        return [ROOT_ENTRY]
    return sorted(p for p in chosen if not any(parent in chosen for parent in parent_folders(p)))


def files_in_selection(selection, entries) -> list:
    """The files a selection covers, in display order. `entries` is a listing by path."""
    def covered(path):
        return any(s == ROOT_ENTRY or path == s or path.startswith(s + "/") for s in selection)

    return [path for path, entry in entries.items() if not entry["is_dir"] and covered(path)]


def entry_args(selection) -> list:
    return [arg for path in selection for arg in ("--entry", path)]


def share_file_name(vault_name: str, selection, entries) -> str:
    """A name to suggest for a share. One file stays that file; anything else is an archive."""
    if len(selection) > 1:
        return f"{vault_name} selection.tar.age"
    only = selection[0]
    if only == ROOT_ENTRY:
        return f"{vault_name}.tar.age"
    return os.path.basename(only) + (".tar.age" if entries[only]["is_dir"] else ".age")


def share_is_archive(file_name: str) -> bool:
    """Whether a share's name says it's an archive: what Share names one (share_file_name)."""
    return file_name.endswith(".tar.age")


def unpacked_name(file_name: str) -> str:
    """A name for what a share holds: a folder for "Photos.tar.age", a file for "a.txt.age"."""
    for suffix in (".tar.age", ".age"):
        if file_name.endswith(suffix) and len(file_name) > len(suffix):
            return file_name[: -len(suffix)]
    return file_name + " decrypted"


def saved_name(file_name: str) -> str:
    """A name for a share saved as it is: the .age comes off, so an archive stays a .tar."""
    if file_name.endswith(".age") and len(file_name) > len(".age"):
        return file_name[: -len(".age")]
    return file_name + " decrypted"


def free_name(folder: str, name: str) -> str:
    """`name` in `folder`, or the first of "name (2)", "name (3)"… not already there. The
    number goes before the extension, so "a.txt" becomes "a (2).txt"."""
    stem, ext = os.path.splitext(name)
    if not stem:  # ".age" and the like: all extension
        stem, ext = name, ""
    candidate, n = name, 1
    while os.path.lexists(os.path.join(folder, candidate)):
        n += 1
        candidate = f"{stem} ({n}){ext}"
    return candidate


def share_actions(kind: str, file_name: str) -> list:
    """What Decrypt offers for a file, given what `share-kind` said it needs. An archive
    can be unpacked, saved as it is, or added to a vault; one file with a password can be
    saved or added. One file for your key gets no choice: the plain decrypt, as always."""
    if share_is_archive(file_name):
        return ["unpack", "save", "import"]
    if kind == "password":
        return ["save", "import"]
    return []


def check_share_password(path: str, password: str) -> None:
    """Raise BackendError unless `password` opens the share at `path`. The backend unwraps
    the file key only, so this takes one scrypt and decrypts nothing. Like run_backend,
    the password goes over a private pipe, never on the command line; run_backend itself
    only knows --pass-fd, and stays as audited."""
    read_fd, write_fd = os.pipe()
    os.write(write_fd, password.encode("utf-8"))
    os.close(write_fd)
    try:
        proc = subprocess.run(
            [BACKEND, "share-check", "--in", path, "--share-pass-fd", str(read_fd)],
            stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE, pass_fds=(read_fd,),
        )
    except FileNotFoundError:
        raise BackendError(f"Backend not found at '{BACKEND}'.")
    finally:
        os.close(read_fd)
    if proc.returncode != 0:
        msg = proc.stderr.decode("utf-8", "replace").strip()
        raise BackendError(msg.removeprefix("error: ") or "the operation failed")


def vault_name_from_path(path: str) -> str:
    return os.path.basename(path.rstrip("/")).removesuffix(VAULT_SUFFIX)


def last_percent(reports: bytes, previous):
    """The latest whole percent in what the backend has written to its progress pipe."""
    for line in reversed(reports.split(b"\n")):
        if line.isdigit():
            return min(int(line), 100)
    return previous


def plain_row(title: str, subtitle: str) -> Adw.ActionRow:
    """A row showing a name exactly as it is. As markup, an "&" in a contact's or a file's
    name would leave it blank. Setters, in this order: passed to the constructor, the text
    is parsed as markup first."""
    row = Adw.ActionRow()
    row.set_use_markup(False)
    row.set_title(title)
    row.set_subtitle(subtitle)
    return row


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
    """Passphrases the user chose to have remembered, in this process's memory only,
    until Lock now, a change of setting, or the app closes. Keyed "identity" or
    ("vault", path)."""

    def __init__(self):
        self.enabled = False
        self.entries = {}  # key -> passphrase

    def set_enabled(self, enabled):
        self.enabled = enabled
        self.clear()

    def put(self, key, passphrase):
        if self.enabled:
            self.entries[key] = passphrase

    def get(self, key):
        return self.entries.get(key)

    def forget(self, key):
        self.entries.pop(key, None)

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
    a known rate (extract writes nothing until everything has verified in RAM), so the
    backend reports its own percentage on a pipe. The bar pulses until the first report,
    while the key is being unlocked, and again once the work is done but not yet committed.

    `partial` is what to remove after a cancel or failure: the staging path of an
    extract, which is a folder for a folder extract. `on_done` gets the failure
    message, or None on success or cancel.

    `passphrase` goes on `--pass-fd`, and each of `secrets` ({"--share-pass-fd": text})
    on a pipe of its own: opening a share can take a passphrase and a share's password
    at once. `passphrase` may be None when a command needs only the others."""

    def __init__(self, window, args, *, passphrase, heading, subject, note, on_done, partial=None, secrets=None):
        super().__init__(
            window, args, passphrase=passphrase, heading=heading, subject=subject,
            watch_path=partial, total=1, note=note,
        )
        self.on_done = on_done
        self.progress_pipe = None
        self.percent = None
        self.secrets = {} if passphrase is None else {"--pass-fd": passphrase}
        self.secrets.update(secrets or {})

    def start(self):
        """FileOperation.start, with a pipe for the backend's reports. Its own, rather than
        an option on spawn_backend, so that stays as audited; the same reason as _finish."""
        self.progress_pipe, write_end = os.pipe()
        os.set_blocking(self.progress_pipe, False)  # a tick must never wait on it
        os.set_blocking(write_end, False)  # nor may a report ever hold up the backend
        secret_args, secret_fds = [], []
        for option, text in self.secrets.items():
            pass_read, pass_write = os.pipe()
            os.write(pass_write, text.encode("utf-8"))
            os.close(pass_write)
            secret_args += [option, str(pass_read)]
            secret_fds.append(pass_read)
        try:
            self.proc = subprocess.Popen(
                [BACKEND, *self.args, "--progress-fd", str(write_end), *secret_args],
                stdin=subprocess.DEVNULL,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.PIPE,
                pass_fds=(write_end, *secret_fds),
            )
        except FileNotFoundError:
            os.close(self.progress_pipe)
            self.window.error(
                f"Backend not found at '{BACKEND}'.\nBuild it with 'cargo build --release' "
                "or set VAULTSEND_BACKEND."
            )
            self.window.current_op = None
            return
        finally:
            os.close(write_end)
            for fd in secret_fds:
                os.close(fd)
        self.timer = GLib.timeout_add(self.POLL_MS, self._tick)
        GLib.timeout_add(self.DIALOG_DELAY_MS, self._present_dialog)

    def _read_progress(self):
        try:
            self.percent = last_percent(os.read(self.progress_pipe, 4096), self.percent)
        except BlockingIOError:
            pass  # nothing new

    def _update(self):
        self._read_progress()
        if self.bar is None:
            return
        if self.percent is None or self.percent >= 100:
            self.bar.pulse()
            self.bar.set_text("Working…" if self.percent is None else "Finishing…")
        else:
            self.bar.set_fraction(self.percent / 100)
            self.bar.set_text(f"{self.percent}%")

    def _finish(self):
        self.done = True
        if self.dialog is not None:
            self.dialog.disconnect(self.dialog_handler)
            self.dialog.close()
            self.dialog = None
        os.close(self.progress_pipe)
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
            self.window.toast(f"{self.note} Note: {warnings[0]}." if warnings else self.note)
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
        self.set_default_size(1012, 690)
        # GTK would otherwise log every file chosen in a dialog to the desktop's shared list of
        # recent files, by name, and keep that record after the file itself has gone.
        self.get_settings().set_property("gtk-recent-files-enabled", False)
        self.my_pubkey = None
        self.contacts = load_contacts()
        self.current_op = None  # in-flight FileOperation, if any
        self.vaults = load_vaults()
        self.vault = None  # the vault selected in the sidebar, if any
        self.vault_entries = None  # its listing by path, or None while locked
        self.selected_entry = None  # what the actions act on, selecting one at a time
        self.entry_checks = {}  # every row's radio button or tick box, by path
        self.syncing_checks = False  # ticking one box is ticking others too; see _on_entry_ticked
        self.syncing_select_all = False  # Select all's state set from _update_selection
        self.expanded = set()  # folders left open, kept across re-listing
        self.opened = []  # decrypted copies given to other apps; see vault_open()
        clear_stale_copies()
        self.connect("close-request", self._on_close_request)
        self.settings = load_settings()
        self.cache = PassphraseCache()
        self.cache.set_enabled(self.settings["remember"] != "off")
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
        /* libadwaita styles every arrow below an open row as open, so a closed folder
           inside an open one would look open. Give it the theme's closed arrow back. */
        list.nested row.expander:not(:checked) > box > list > row image.expander-row-arrow {
            -gtk-icon-transform: rotate(0.5turn);
            opacity: 0.55;
            color: inherit;
        }
        list.nested row.expander:not(:checked) > box > list > row image.expander-row-arrow:dir(rtl) {
            -gtk-icon-transform: rotate(-0.5turn);
        }
        /* Each nested list is shaded on top of its parent's, which a very deep vault would
           take too dark to read. Stop one level past INDENT_LEVELS, as the indent does. */
        list.nested list.nested list.nested list.nested list.nested list.nested list.nested {
            background: none;
        }
        /* Both groups of buttons on one line, at the window's default size. */
        .vaultsend-actions > flowboxchild { padding: 0; }
        /* The cells only lay the groups out. Without this the theme shades a whole cell on
           hover, a ghost box behind the buttons. */
        .vaultsend-actions > flowboxchild,
        .vaultsend-actions > flowboxchild:hover,
        .vaultsend-actions > flowboxchild:active,
        .vaultsend-actions > flowboxchild:selected,
        .vaultsend-actions > flowboxchild:focus,
        .vaultsend-actions > flowboxchild:focus-visible {
            background: none; box-shadow: none; outline: none;
        }
        /* One of Select all and Select multiple is lit at a time. With everything ticked,
           Select all is, so Select multiple, still on underneath, doesn't show it. */
        .vaultsend-select-mode.vaultsend-outranked:checked:not(:hover):not(:active) {
            background-color: transparent;
        }
        /* Above the row of buttons at the bottom, not over them, where it would catch their clicks. */
        toast { margin-bottom: 72px; }
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
            row = plain_row(c["name"], short(c["pubkey"]))
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
        for value, label in REMEMBER_CHOICES:
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
            label="Type or paste text below, or drop a file or a vault here. Encrypting scrambles it "
            "for chosen recipients; decrypting needs your passphrase.",
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
        # Plain text: messages can name files and contacts, and an "&" read as markup
        # would make the whole toast fail to appear.
        self.toasts.add_toast(Adw.Toast(use_markup=False, title=text))

    def error(self, text):
        # Every identity decrypt reports failure through here, including the file
        # path's FileOperation, so this is the one place to drop a rejected passphrase.
        if "wrong passphrase" in text:
            self.cache.forget("identity")
        self.toast(text)

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
            # The drag left the keyboard with the other app, and a prompt may come next.
            self.present()
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
        if os.path.isdir(path):
            self._handle_folder(path)
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

    def _handle_folder(self, path):
        """A vault dropped on the main page opens here; any other folder has no use there."""
        mode = read_vault_mode(path)
        if mode is None:
            self._vault_error(
                "That folder isn't a vault",
                "Only single files can be encrypted here. To protect a folder, add it to a vault.",
            )
            return
        kind = "a password" if mode == "password" else "a key"
        dlg = Adw.AlertDialog(
            heading="Decrypt this vault?",
            body=f"“{os.path.basename(path.rstrip('/'))}” is a vault protected by {kind}. "
            "Decrypting unlocks it and adds it to your vaults.",
        )
        dlg.add_response("cancel", "Cancel")
        dlg.add_response("decrypt", "Decrypt")
        dlg.set_response_appearance("decrypt", Adw.ResponseAppearance.SUGGESTED)
        dlg.set_default_response("decrypt")
        dlg.set_close_response("cancel")
        dlg.connect("response", lambda _d, r: self._decrypt_vault(path, mode) if r == "decrypt" else None)
        dlg.present(self)

    def _decrypt_vault(self, path, mode):
        real = os.path.realpath(path)
        known = next((v for v in self.vaults if os.path.realpath(v["path"]) == real), None)
        vault = known or {"name": vault_name_from_path(path), "path": path, "mode": mode, "last_generation": 0}

        def opened(secret):
            # Listed before it's added, so a vault that won't open leaves nothing behind.
            try:
                out = run_backend(self._vault_args(vault, "vault-list"), passphrase=secret)
                listing = parse_listing(out.decode("utf-8"))
            except (BackendError, ValueError, IndexError) as e:
                self._vault_failed(vault, str(e))
                return
            if known is None:
                self.vaults.append(vault)
                save_json(VAULTS_FILE, self.vaults)
            self.select_vault(vault)
            self._refresh_vaults()
            self.vaults_toggle.set_active(True)
            self._apply_listing(vault, *listing)

        self.with_vault_secret(vault, opened)

    def encrypt_file(self, path):
        name = os.path.basename(path) + ".age"
        self.pick_recipients(
            lambda recips: self._save_then(name, lambda out: self._run_encrypt(path, out, recips)),
            # Set password instead: for anyone with the password, as the Android app's Share.
            on_password=lambda: self.ask_passphrase(
                lambda pw: self._save_then(name, lambda out: self._run_encrypt(path, out, [], password=pw)),
                heading="Set password",
                body="",
                confirm=True,
            ),
        )

    def decrypt_file(self, path):
        """A file someone shared may need a password rather than your key, and an archive
        can be unpacked or added to a vault: ask the backend which, from the header alone."""
        try:
            kind = run_backend(["share-kind", "--in", path]).decode("utf-8").strip()
        except BackendError as e:
            self.error(str(e))
            return
        actions = share_actions(kind, os.path.basename(path))
        if actions:
            self._choose_share_action(path, kind, actions)
        else:
            self._decrypt_with_key(path)

    def _decrypt_with_key(self, path):
        suggested = os.path.basename(path)
        suggested = suggested[:-4] if suggested.endswith(".age") else suggested + ".decrypted"
        self.with_passphrase("identity", lambda p: self._save_then(
            suggested,
            lambda out: self._run_decrypt(path, out, p),
        ))

    # -- Opening a share -----------------------------------------------------
    def _choose_share_action(self, path, kind, actions):
        name = os.path.basename(path)
        archive = "unpack" in actions
        what = "a folder or several files" if archive else "one file"
        how = "a password" if kind == "password" else "your key"
        dlg = Adw.AlertDialog(
            heading=f"Open “{name}”",
            body=f"This was shared with {how}, and holds {what}.",
        )
        dlg.add_response("cancel", "Cancel")
        if "import" in actions:
            dlg.add_response("import", "Add to a vault…")
            dlg.set_response_enabled("import", bool(self.vaults))
        dlg.add_response("save", "Save as it is…" if archive else "Save…")
        if archive:
            dlg.add_response("unpack", "Unpack…")
        default = "unpack" if archive else "save"
        dlg.set_response_appearance(default, Adw.ResponseAppearance.SUGGESTED)
        dlg.set_default_response(default)
        dlg.set_close_response("cancel")

        def resp(_d, r):
            if r in ("unpack", "save", "import"):
                self._with_share_key(path, kind, lambda key: self._share_action(path, r, key))

        dlg.connect("response", resp)
        dlg.present(self)

    def _with_share_key(self, path, kind, on_ok, retry=False):
        """Call on_ok with what opens the share: ("--share-pass-fd", its password), checked
        at once so a wrong one is asked again, or ("--pass-fd", your passphrase)."""
        if kind != "password":
            self.with_passphrase("identity", lambda p: on_ok(("--pass-fd", p)))
            return

        def typed(password):
            try:
                check_share_password(path, password)
            except BackendError as e:
                if "wrong password" in str(e):
                    self._with_share_key(path, kind, on_ok, retry=True)  # its heading says so
                else:
                    self.error(str(e))
                return
            on_ok(("--share-pass-fd", password))

        name = os.path.basename(path)
        self.ask_passphrase(
            typed,
            heading="Wrong password. Try again" if retry else "Enter the share's password",
            body=f"“{name}” was shared with a password. Whoever sent it can tell you what it is.",
        )

    def _share_action(self, path, action, key):
        name = os.path.basename(path)
        option, secret = key

        def done(failure):
            if failure is None:
                return
            if "wrong passphrase" in failure:
                self.cache.forget("identity")
            self._vault_error("Couldn't open the share", failure)

        def run(args, *, heading, note, out):
            self._start_op(VaultOperation(
                self, args, passphrase=None, secrets={option: secret}, heading=heading,
                subject=name, note=note, on_done=done, partial=out + STAGING_SUFFIX,
            ))

        def into_folder(title, wanted, command, heading, note):
            # A folder, not a name: GTK's save chooser completes a typed name, and beside
            # the share "Photos" completes to "Photos.tar.age", the share itself.
            def chosen(folder):
                out = os.path.join(folder, free_name(folder, wanted))
                run([command, "--in", path, "--out", out], heading=heading, note=note(os.path.basename(out)), out=out)

            self._pick_folder(title, chosen)

        if action == "unpack":
            into_folder("Unpack into which folder?", unpacked_name(name), "share-extract",
                        "Unpacking…", lambda n: f"Unpacked into “{n}”.")
        elif action == "save":
            into_folder("Save into which folder?", saved_name(name), "share-decrypt",
                        "Decrypting…", lambda n: f"Saved as “{n}”.")
        elif action == "import":
            self._pick_vault_for(name, lambda vault: self._import_share(vault, path, key))

    def _pick_vault_for(self, name, on_ok):
        dlg = Adw.AlertDialog(
            heading="Add to which vault?",
            body=f"What “{name}” holds goes in at the top of the vault you choose.",
        )
        rows = Gtk.ListBox(selection_mode=Gtk.SelectionMode.NONE)
        rows.add_css_class("boxed-list")
        for v in self.vaults:
            row = plain_row(v["name"], short_path(v["path"]))
            row.set_activatable(True)
            row.add_suffix(Gtk.Image.new_from_icon_name("go-next-symbolic"))
            row.connect("activated", lambda _r, vault=v: (dlg.close(), on_ok(vault)))
            rows.append(row)
        scroller = Gtk.ScrolledWindow(propagate_natural_height=True, hscrollbar_policy=Gtk.PolicyType.NEVER)
        scroller.set_max_content_height(260)
        scroller.set_child(rows)
        dlg.set_extra_child(scroller)
        dlg.add_response("cancel", "Cancel")
        dlg.set_close_response("cancel")
        dlg.present(self)

    def _import_share(self, vault, path, key):
        option, secret = key
        name = os.path.basename(path)
        # vault-import's --pass-fd unlocks the vault, so your passphrase for the share
        # goes on --id-pass-fd. A `self` vault takes the same passphrase: asked once.
        share_secret = {"--id-pass-fd" if option == "--pass-fd" else option: secret}

        def run(vault_secret):
            def done(failure):
                if failure is not None:
                    self._vault_failed(vault, failure)
                    return
                self.select_vault(vault)
                self._refresh_vaults()
                self.vaults_toggle.set_active(True)
                self._list_vault(vault, vault_secret)  # same secret, so no second prompt

            self._start_op(VaultOperation(
                self, self._vault_args(vault, "vault-import", "--in", path, "--name", unpacked_name(name)),
                passphrase=vault_secret, secrets=share_secret,
                heading=f"Adding to “{vault['name']}”…", subject=name,
                note=f"Added to “{vault['name']}”.", on_done=done,
            ))

        if vault["mode"] == "self" and option == "--pass-fd":
            run(secret)
        else:
            self.with_vault_secret(vault, run)

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

    def _run_encrypt(self, in_path, out_path, recips, password=None):
        args = ["encrypt"]
        for r in recips:
            args += ["-r", r]
        if password is not None:
            args.append("--password")
        args += ["--in", in_path, "--out", out_path]
        self._start_op(FileOperation(
            self,
            args,
            passphrase=password,
            heading="Encrypting…",
            subject=os.path.basename(in_path),
            # The backend stages the ciphertext and renames it into place when
            # done; the staging file's size tracks progress, and its final size
            # follows from the input plus the format's overhead.
            watch_path=out_path + STAGING_SUFFIX,
            total=expected_ciphertext_size(file_size(in_path)),
            note="Encrypted with your password." if password is not None else f"Encrypted to {len(recips)}.",
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
    def pick_recipients(self, on_ok, on_password=None):
        if self.my_pubkey is None:
            self.error("Your key isn't ready yet.")
            return
        dlg = Adw.AlertDialog(heading="Encrypt to…", body="Everyone you choose will be able to decrypt it.")
        box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=6)
        checks = []
        you = Gtk.CheckButton(label=f"You ({short(self.my_pubkey)})", active=True, sensitive=False)
        box.append(you)
        for c in self.contacts:
            # Wrapped: clipped, a long name would hide the key that confirms who this is.
            cb = Gtk.CheckButton()
            cb.set_child(Gtk.Label(label=f"{c['name']} ({short(c['pubkey'])})", wrap=True, wrap_mode=2, xalign=0))
            box.append(cb)
            checks.append((cb, c["pubkey"]))
        scroller = Gtk.ScrolledWindow(propagate_natural_height=True, hscrollbar_policy=Gtk.PolicyType.NEVER)
        scroller.set_min_content_height(80)
        scroller.set_max_content_height(260)
        scroller.set_child(box)
        dlg.set_extra_child(scroller)
        dlg.add_response("cancel", "Cancel")
        if on_password is not None:
            dlg.add_response("password", "Set password instead")
        dlg.add_response("encrypt", "Encrypt")
        dlg.set_response_appearance("encrypt", Adw.ResponseAppearance.SUGGESTED)
        dlg.set_default_response("encrypt")
        dlg.set_close_response("cancel")

        def resp(_d, r):
            if r == "password":
                on_password()
                return
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
            box.append(Gtk.Label(label="Repeat it", xalign=0))  # a passphrase, or a vault's password
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
                problem = "Those don't match."
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
        dlg.set_focus(entry)  # ready to type into, without reaching for the mouse
        dlg.present(self)

    def add_contact_dialog(self, on_added=None):
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

        def update_add(*_):
            # Answering closes the dialog, so Add can't be offered until there's something to add.
            complete = name.get_text().strip() and key.get_text().strip().startswith("age1")
            dlg.set_response_enabled("add", bool(complete))

        name.connect("changed", update_add)
        key.connect("changed", update_add)
        update_add()

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
            if on_added:
                on_added()

        dlg.connect("response", resp)
        dlg.set_focus(name)
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
        self.cache.set_enabled(choice != "off")
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
            row = plain_row(v["name"], subtitle)  # names can come from folder names on disk
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
            "vault or any file in it, which stay here:",
        )
        # Its own label: the text of a dialog's body can't be selected.
        where = Gtk.Box(spacing=6)
        path = Gtk.Label(label=vault["path"], selectable=True, wrap=True, wrap_mode=2, xalign=0, hexpand=True)
        path.add_css_class("monospace")
        copy = Gtk.Button(icon_name="edit-copy-symbolic", valign=Gtk.Align.CENTER, tooltip_text="Copy path")
        copy.add_css_class("flat")
        copy.connect("clicked", lambda _b: self.copy(vault["path"], "Path copied."))
        where.append(path)
        where.append(copy)
        dlg.set_extra_child(where)
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
        name = Gtk.Entry(placeholder_text="Vault name", activates_default=True)
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

        def update_create(*_):
            # Answering closes the dialog, so Create can't be offered until the name will do.
            text = name.get_text().strip()
            usable = is_valid_vault_name(text)
            dlg.set_response_enabled("create", usable)
            (name.remove_css_class if usable or not text else name.add_css_class)("error")

        name.connect("changed", update_create)
        update_create()

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
        dlg.set_focus(name)
        dlg.present(self)
        return dlg

    def _pick_folder(self, title, on_ok):
        # Folders only, and checked again below, because the filter is a request: a desktop's
        # own file chooser can ignore it, and some return a file picked in folder mode.
        folders = Gtk.FileFilter(name="Folders")
        folders.add_mime_type("inode/directory")
        only_folders = Gio.ListStore.new(Gtk.FileFilter)
        only_folders.append(folders)
        dialog = Gtk.FileDialog(title=title, filters=only_folders, default_filter=folders)

        def done(dlg, res):
            try:
                f = dlg.select_folder_finish(res)
            except GLib.Error:
                return
            if f and f.get_path():
                self._folder_chosen(f.get_path(), on_ok)

        dialog.select_folder(self, None, done)

    def _folder_chosen(self, path, on_ok):
        if os.path.isdir(path):
            on_ok(path)
        else:
            self.error("That's a file. Choose a folder.")

    def _begin_create(self, name, path, mode):
        if mode == "password":
            self.ask_passphrase(
                lambda p: self._create_vault(name, path, mode, p),
                heading="Choose a vault password",
                body="Anyone with this password and a copy of the vault can open it. "
                "If you lose it, the files can't be recovered.",
                confirm=True,
            )
        elif self.my_pubkey is None:
            self.error("Your key isn't ready yet.")
        else:
            # Sealing the vault's key takes your private key, not just the public one.
            self.with_passphrase("identity", lambda p: self._create_vault(name, path, mode, p))

    def _create_vault(self, name, path, mode, secret):
        try:
            run_backend(["vault-create", "--dir", path, "--mode", mode], passphrase=secret)
        except BackendError as e:
            if "wrong passphrase" in str(e):
                self.cache.forget("identity")
            self._vault_error("Couldn't create the vault", str(e))
            return
        vault = self._remember_vault(name, path, mode)
        self.cache.put(self._secret_key(vault), secret)
        self.toast("Vault created.")

    def _add_existing_vault(self, path):
        mode = read_vault_mode(path)
        if mode is None:
            self._vault_error("That isn't a vault", "The folder you chose has no valid VAULT file.")
            return
        if any(v["path"] == path for v in self.vaults):
            self.error("That vault is already in your list.")
            return
        self._remember_vault(vault_name_from_path(path), path, mode)

    def _remember_vault(self, name, path, mode):
        vault = {"name": name, "path": path, "mode": mode, "last_generation": 0}
        self.vaults.append(vault)
        save_json(VAULTS_FILE, self.vaults)
        self.select_vault(vault)
        self._refresh_vaults()
        return vault

    # -- Vault page -----------------------------------------------------------
    def _build_vault_page(self):
        # No tightening: it would narrow the page until the buttons wrapped, with room to spare.
        clamp = Adw.Clamp(maximum_size=760, tightening_threshold=760, margin_top=24, margin_bottom=24, margin_start=16, margin_end=16)
        col = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=16)
        clamp.set_child(col)

        self.vault_title = Gtk.Label(xalign=0, wrap=True, wrap_mode=2)
        self.vault_title.add_css_class("title-2")
        col.append(self.vault_title)

        files_row = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL)
        self.files_heading = Gtk.Label(label="Files", xalign=0, hexpand=True, ellipsize=3)  # 3: at the end
        self.files_heading.add_css_class("heading")
        # A toggle, lit while everything is selected; see _update_selection.
        self.select_all_btn = Gtk.ToggleButton(label="Select all", tooltip_text="Select every file and folder in this vault")
        self.select_all_btn.add_css_class("flat")
        self.select_all_btn.connect("toggled", self._on_select_all)
        self.select_mode_btn = Gtk.ToggleButton(tooltip_text="Select several at once")
        self.select_mode_btn.set_child(Gtk.Label(label="Select multiple"))
        self.select_mode_btn.add_css_class("flat")
        self.select_mode_btn.add_css_class("vaultsend-select-mode")
        self.select_mode_btn.connect("toggled", self._on_select_mode_toggled)
        self.verify_btn = Gtk.Button(label="Verify all", tooltip_text="Check every file in this vault for tampering")
        self.verify_btn.add_css_class("flat")
        self.verify_btn.connect("clicked", lambda *_: self.vault_verify())
        files_row.append(self.files_heading)
        files_row.append(self.select_all_btn)
        files_row.append(self.select_mode_btn)
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

        # Two groups that share a line when they fit and wrap when they don't. In one fixed
        # row, these buttons would set the minimum width of the whole window, on every page.
        self.vault_actions = Gtk.FlowBox(
            selection_mode=Gtk.SelectionMode.NONE, max_children_per_line=2, row_spacing=8, column_spacing=6,
        )
        self.vault_actions.add_css_class("vaultsend-actions")
        self.selection_buttons = []  # the ones with nothing to do until something is selected
        for halign, buttons in (
            (Gtk.Align.START, (("Add files…", self.vault_add_files), ("Add folder…", self.vault_add_folder))),
            (Gtk.Align.END, (
                ("Open", self.vault_open),
                ("Extract…", self.vault_extract),
                ("Share…", self.vault_share),
                ("Delete", self.vault_delete),
                ("Lock", self.vault_lock),
            )),
        ):
            group = Gtk.Box(spacing=6, halign=halign)
            for label, handler in buttons:
                btn = Gtk.Button(label=label)
                btn.connect("clicked", lambda _b, fn=handler: fn())
                group.append(btn)
                if handler in (self.vault_open, self.vault_extract, self.vault_share, self.vault_delete):
                    self.selection_buttons.append(btn)
            self.vault_actions.append(group)
            group.get_parent().set_focusable(False)  # Tab goes to the buttons, not around them
        col.append(self.vault_actions)

        drop = Gtk.DropTarget.new(Gdk.FileList, Gdk.DragAction.COPY)
        drop.connect("drop", self.on_vault_drop)
        clamp.add_controller(drop)
        self._show_locked()
        return clamp

    def _clear_files(self):
        self.vault_entries = None
        self.selected_entry = None
        self.entry_checks = {}
        child = self.file_list.get_first_child()
        while child:
            self.file_list.remove(child)
            child = self.file_list.get_first_child()

    def _show_locked(self):
        """Drop the listing. It is only metadata, but locked means locked."""
        self._clear_files()
        self.select_mode_btn.set_active(False)
        self.vault_body.set_visible_child_name("locked")
        self.vault_actions.set_sensitive(False)
        self.verify_btn.set_sensitive(False)
        self.select_mode_btn.set_sensitive(False)
        self._update_selection()

    def _show_files(self, entries, ticked=()):
        self._clear_files()
        self.vault_entries = {e["path"]: e for e in entries}
        several = self.select_mode_btn.get_active()
        if not entries:
            row = Adw.ActionRow(title="Nothing in this vault yet", subtitle="Add files or a folder, or drop them here.")
            row.set_activatable(False)
            self.file_list.append(row)

        # Selecting one at a time, this is one radio group across every row, however deeply
        # nested, with nothing selected until you pick. There's no hidden default for the
        # actions: they wait. Selecting several, the same rows have independent boxes.
        first_radio = None
        folders = {}
        for e in entries:
            parent, _, name = e["path"].rpartition("/")
            radio = Gtk.CheckButton(valign=Gtk.Align.CENTER, margin_start=entry_indent(e["path"]))
            self.entry_checks[e["path"]] = radio
            if several:
                radio.connect("toggled", self._on_entry_ticked, e["path"])
            else:
                radio.set_group(first_radio)
                first_radio = first_radio or radio
                radio.connect("toggled", self._on_entry_toggled, e["path"])
            if e["is_dir"]:
                row = Adw.ExpanderRow(title=name + "/", use_markup=False)
                row.set_expanded(e["path"] in self.expanded)
                row.connect("notify::expanded", self._on_folder_expanded, e["path"])
                folders[e["path"]] = row
            else:
                row = plain_row(name, human_bytes(e["size"]))
                row.set_activatable_widget(radio)
            row.add_prefix(radio)
            if parent in folders:
                folders[parent].add_row(row)
            else:
                self.file_list.append(row)

        for path in ticked:
            self.entry_checks[path].set_active(True)

        self.vault_body.set_visible_child_name("files")
        self.vault_actions.set_sensitive(True)
        self.verify_btn.set_sensitive(True)
        self.select_mode_btn.set_sensitive(True)
        self._update_selection()

    def _on_select_mode_toggled(self, btn):
        if self.vault_entries is None:
            return
        # Whatever was selected stays selected on the way in. On the way out, a selection of
        # several can't become one, so it starts over.
        chosen = self.selected_entry
        self._show_files(list(self.vault_entries.values()), ticked=[chosen] if chosen and btn.get_active() else [])

    def _selection(self):
        """What the actions act on: paths, with none inside another, ROOT_ENTRY for every
        row in the vault, or nothing at all."""
        if not self.select_mode_btn.get_active():
            return [self.selected_entry] if self.selected_entry else []
        boxes = self.entry_checks
        if boxes and all(box.get_active() for box in boxes.values()):
            return [ROOT_ENTRY]
        return top_level_selection(p for p, box in boxes.items() if box.get_active())

    def _update_selection(self):
        chosen = self._selection() if self.vault_entries is not None else []
        if self.vault_entries is None:
            summary = "Files"
        elif chosen == [ROOT_ENTRY]:
            summary = "Files · all selected"
        elif self.select_mode_btn.get_active():
            summary = f"Files · {len(chosen)} selected"
        else:
            files = [e for e in self.vault_entries.values() if not e["is_dir"]]
            count = "1 file" if len(files) == 1 else f"{len(files)} files"
            summary = f"Files · {count}, {human_bytes(sum(e['size'] for e in files))}"
        self.files_heading.set_label(summary)
        for btn in self.selection_buttons:
            btn.set_sensitive(bool(chosen))
        everything = chosen == [ROOT_ENTRY]
        self.select_all_btn.set_label("Select none" if everything else "Select all")
        self.select_all_btn.set_sensitive(bool(self.vault_entries))
        # Only one of the two is lit: Select all while everything is selected, else Select
        # multiple while it's on.
        self.syncing_select_all = True
        self.select_all_btn.set_active(everything)
        self.syncing_select_all = False
        (self.select_mode_btn.add_css_class if everything else self.select_mode_btn.remove_css_class)(
            "vaultsend-outranked"
        )

    def _on_select_all(self, _btn):
        """Selecting everything takes the tick boxes, so this turns them on if they aren't."""
        if self.syncing_select_all:
            return
        everything = self._selection() != [ROOT_ENTRY]
        self.select_mode_btn.set_active(True)
        self.syncing_checks = True
        self._set_ticks(self.entry_checks, everything)
        self.syncing_checks = False
        self._update_selection()

    def _on_entry_toggled(self, radio, path):
        if radio.get_active():
            self.selected_entry = path
            self._update_selection()

    def _set_ticks(self, paths, active):
        for path in paths:
            self.entry_checks[path].set_active(active)

    def _on_entry_ticked(self, box, path):
        """A folder's box speaks for what's inside it, so it is ticked only while all of that
        is. The guard is for the boxes set from here."""
        if self.syncing_checks:
            return
        self.syncing_checks = True
        active = box.get_active()
        self._set_ticks([p for p in self.entry_checks if p.startswith(path + "/")], active)
        if not active:
            self._set_ticks(parent_folders(path), False)
        self.syncing_checks = False
        self._update_selection()

    def _on_folder_expanded(self, row, _pspec, path):
        (self.expanded.add if row.get_expanded() else self.expanded.discard)(path)
        if row.get_expanded():
            return
        # The actions follow the selection, so it can't stay on a row that's now hidden.
        # Ticked itself, a folder is still in sight, and says what it's acting on.
        if self.select_mode_btn.get_active():
            if path in self.entry_checks and not self.entry_checks[path].get_active():
                self.syncing_checks = True
                self._set_ticks([p for p in self.entry_checks if p.startswith(path + "/")], False)
                self.syncing_checks = False
                self._update_selection()
        elif self.selected_entry and self.selected_entry.startswith(path + "/"):
            self.entry_checks[self.selected_entry].set_active(False)
            self.selected_entry = None
            self._update_selection()

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
        if KEY_MISMATCH in message:
            self._vault_error(
                "Your key doesn't match this vault",
                f"“{vault['name']}” was made for a different recipient, or with a different key, "
                f"so yours can't unlock it.\n\nThe details: {message}.",
            )
            return
        self._vault_error(f"Problem with “{vault['name']}”", message)

    def with_vault_secret(self, vault, on_ok):
        """The way into every operation: ask for (or recall) the vault's secret."""
        if vault["mode"] == "self":
            self.with_passphrase("identity", on_ok)
        else:
            self.with_passphrase(
                self._secret_key(vault), on_ok,
                heading="Unlock vault", body=f"Enter the password for “{vault['name']}”.",
            )

    def _vault_args(self, vault, command, *rest):
        return [command, "--dir", vault["path"], *rest]

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
        self._apply_listing(vault, generation, entries)

    def _apply_listing(self, vault, generation, entries):
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
        # The drag left the keyboard with the other app: without this, a passphrase typed
        # into the prompt that comes next would go there instead.
        self.present()
        self._add_paths([f.get_path() for f in value.get_files() if f.get_path()])
        return True

    def _add_paths(self, paths):
        if not paths or self.vault_entries is None:
            return
        # Into the selected folder, or the folder of the selected file. With several
        # selected there's no one place that could mean, so into the top of the vault.
        chosen = self._selection()
        one = chosen[0] if len(chosen) == 1 else ROOT_ENTRY
        selected = self.vault_entries.get(one)
        dest = one if selected and selected["is_dir"] else one.rpartition("/")[0]
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
        vault, chosen = self.vault, self._selection()
        if len(chosen) > 1:
            suggested = f"{vault['name']} selection"
        else:
            suggested = vault["name"] if chosen == [ROOT_ENTRY] else os.path.basename(chosen[0])
        self.with_vault_secret(vault, lambda s: self._save_then(
            suggested,
            lambda out: self._run_vault_op(
                vault, s, ["vault-extract", *entry_args(chosen), "--out", out],
                heading="Extracting…", subject=suggested, note="Extracted.", partial=out + STAGING_SUFFIX,
            ),
        ))

    def vault_share(self):
        """Pick who it's for, then where to save it. Adding someone new happens on top of this
        dialog, so neither the selection nor the place in the flow is lost."""
        vault, chosen = self.vault, self._selection()
        if self.my_pubkey is None:
            self.error("Your key isn't ready yet.")
            return
        what = vault["name"] if chosen == [ROOT_ENTRY] else os.path.basename(chosen[0])
        if len(chosen) > 1:
            what = f"{len(chosen)} items"
        one_file = len(chosen) == 1 and chosen != [ROOT_ENTRY] and not self.vault_entries[chosen[0]]["is_dir"]
        dlg = Adw.AlertDialog(
            heading=f"Share “{what}”",
            body="Encrypted so only you and the person you choose can read it. They open it by "
            "dropping it on VaultSend's main page"
            + (", which gives them this file." if one_file else ", which unpacks it into a folder (or saves it as a .tar archive)."),
        )
        contacts = Gtk.ListBox(selection_mode=Gtk.SelectionMode.NONE)
        contacts.add_css_class("boxed-list")

        def show_contacts(focus_last=False):
            child = contacts.get_first_child()
            while child:
                contacts.remove(child)
                child = contacts.get_first_child()
            if not self.contacts:
                row = Adw.ActionRow(title="No contacts yet")
                row.set_activatable(False)
                contacts.append(row)
                return
            for c in self.contacts:
                row = plain_row(c["name"], short(c["pubkey"]))
                row.set_activatable(True)
                row.add_suffix(Gtk.Image.new_from_icon_name("go-next-symbolic"))
                row.connect("activated", lambda _r, contact=c: (dlg.close(), self._share_with(vault, chosen, contact)))
                contacts.append(row)
            if focus_last:
                row.grab_focus()  # brings someone just added into view, ready to pick

        show_contacts()
        scroller = Gtk.ScrolledWindow(propagate_natural_height=True, hscrollbar_policy=Gtk.PolicyType.NEVER)
        scroller.set_max_content_height(260)
        scroller.set_child(contacts)
        add_new = Gtk.Label(label='<a href="add-contact">Add new contact</a>', use_markup=True, xalign=0)

        def on_add_new(_label, _uri):
            self.add_contact_dialog(on_added=lambda: show_contacts(focus_last=True))
            return True  # handled: this isn't a link for a browser to follow

        add_new.connect("activate-link", on_add_new)
        with_password = Gtk.Label(
            label='<a href="password">Share with a password instead</a>', use_markup=True, xalign=0,
            tooltip_text="For someone who isn't a contact: anyone with the file and the password can open it",
        )

        def on_password(_label, _uri):
            dlg.close()
            self._share_with_password(vault, chosen)
            return True

        with_password.connect("activate-link", on_password)
        box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=10)
        box.append(scroller)
        box.append(add_new)
        box.append(with_password)
        dlg.set_extra_child(box)
        dlg.add_response("cancel", "Cancel")
        dlg.set_close_response("cancel")
        dlg.present(self)

    def _share_with(self, vault, chosen, contact):
        suggested = share_file_name(vault["name"], chosen, self.vault_entries)
        # You as well, as when encrypting anything else: you can still read what you sent.
        recipients = dict.fromkeys((contact["pubkey"], self.my_pubkey))
        to = [arg for pubkey in recipients for arg in ("--to", pubkey)]
        self.with_vault_secret(vault, lambda s: self._save_then(
            suggested,
            lambda out: self._run_vault_op(
                vault, s, ["vault-share", *entry_args(chosen), *to, "--out", out],
                heading=f"Encrypting for {contact['name']}…", subject=suggested,
                note=f"Encrypted for {contact['name']}. Send them the saved file.",
                partial=out + STAGING_SUFFIX,
            ),
        ))

    def _share_with_password(self, vault, chosen):
        suggested = share_file_name(vault["name"], chosen, self.vault_entries)

        def with_password(vault_secret, password):
            self._save_then(suggested, lambda out: self._start_op(VaultOperation(
                self, self._vault_args(vault, "vault-share", *entry_args(chosen), "--out", out),
                passphrase=vault_secret, secrets={"--share-pass-fd": password},
                heading="Encrypting with a password…", subject=suggested,
                note="Encrypted with a password. Send the file, and tell them the password another way.",
                partial=out + STAGING_SUFFIX,
                on_done=lambda failure: failure and self._vault_failed(vault, failure),
            )))

        self.with_vault_secret(vault, lambda s: self.ask_passphrase(
            lambda password: with_password(s, password),
            heading="Choose a password for this share",
            body="Anyone with the file and this password can open it, in VaultSend or with the age tool. "
            "Send the password another way than the file.",
            confirm=True,
        ))

    def vault_delete(self):
        vault, chosen = self.vault, self._selection()
        args = ["vault-remove", *entry_args(chosen)]
        if chosen == [ROOT_ENTRY]:
            count = len(files_in_selection(chosen, self.vault_entries))
            heading = "Delete everything in this vault?"
            body = (f"Everything in “{vault['name']}” ({'1 file' if count == 1 else f'{count} files'}, "
                    "plus any folders) will be permanently deleted. The vault itself stays, empty. "
                    "This can't be undone.")
            subject = vault["name"]
            args = ["vault-remove", "--all"]
        elif len(chosen) > 1:
            heading = f"Delete {len(chosen)} items from vault?"
            body = ("These, and everything in any folders among them, will be permanently deleted "
                    "from this vault. This can't be undone.\n\n"
                    + "\n".join(chosen[:5]) + ("\n…" if len(chosen) > 5 else ""))
            subject = f"{len(chosen)} items"
        else:
            entry = chosen[0]
            is_dir = self.vault_entries[entry]["is_dir"]
            heading = "Delete from vault?"
            body = (f"“{entry}”{' and everything in it' if is_dir else ''} will be permanently "
                    "deleted from this vault. This can't be undone.")
            subject = os.path.basename(entry)
        dlg = Adw.AlertDialog(heading=heading, body=body)
        dlg.add_response("cancel", "Cancel")
        dlg.add_response("delete", "Delete")
        dlg.set_response_appearance("delete", Adw.ResponseAppearance.DESTRUCTIVE)
        dlg.set_default_response("cancel")
        dlg.set_close_response("cancel")

        def resp(_d, r):
            if r == "delete":
                self.with_vault_secret(vault, lambda s: self._run_vault_op(
                    vault, s, args, heading="Deleting…", subject=subject, note="Deleted.", relist=True,
                ))

        dlg.connect("response", resp)
        dlg.present(self)

    def vault_verify(self):
        """Verify every file, and only then remove encrypted files the vault doesn't list
        (left by an interrupted change). Ordinary changes never delete those: in a
        synced folder they may be another device's change still on its way."""
        vault = self.vault
        self.with_vault_secret(vault, lambda s: self._run_vault_op(
            vault, s, ["vault-check", "--clean"],
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
        vault = self.vault
        files = files_in_selection(self._selection(), self.vault_entries)
        selected = self.vault_entries.get(self.selected_entry)
        if not self.select_mode_btn.get_active() and (selected is None or selected["is_dir"]):
            self.error("Select a file to open.")
            return
        if not files:
            self.error("Those are empty folders: there's no file in them to open.")
            return
        if self.settings["open_explained"]:
            self._ask_then_open(vault, files)
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
                self._ask_then_open(vault, files)

        dlg.connect("response", resp)
        dlg.present(self)

    def _ask_then_open(self, vault, files):
        if len(files) <= OPEN_ASK_ABOVE:
            self._open_entries(vault, files)
            return
        dlg = Adw.AlertDialog(heading=f"Open {len(files)} files?", body="Each one starts in its default app.")
        dlg.add_response("cancel", "Cancel")
        dlg.add_response("open", "Open them all")
        dlg.set_response_appearance("open", Adw.ResponseAppearance.SUGGESTED)
        dlg.set_default_response("cancel")
        dlg.set_close_response("cancel")
        dlg.connect("response", lambda _d, r: self._open_entries(vault, files) if r == "open" else None)
        dlg.present(self)

    def _open_entries(self, vault, entries):
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

        def extract(secret):
            # Several come out together, with one unlock and one percentage, into a folder
            # of their own, and then move to a folder each, as a single file gets.
            several = len(entries) > 1
            name = "several files" if several else os.path.basename(entries[0])
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
                if several:
                    copies = self._separate_copies(vault, entries, copy["path"], base)
                    self._discard_copy(copy)
                    for each in copies:
                        self._launch_copy(each)
                    return
                copy["stamp"] = file_stamp(copy["path"])
                if copy["stamp"] is None:  # failed or cancelled: the reason is already shown
                    self._discard_copy(copy)
                else:
                    self._launch_copy(copy)

            self._run_vault_op(
                vault, secret, ["vault-extract", *entry_args(entries), "--out", copy["path"]],
                heading="Opening…", subject=f"{len(entries)} files" if several else name,
                note=f"Opening {len(entries)} files in their default apps." if several else "Opening in its default app.",
                partial=copy["path"] + STAGING_SUFFIX, after=extracted,
            )

        self.with_vault_secret(vault, extract)

    def _separate_copies(self, vault, entries, extracted_to, base):
        """Move each file of a joint extract to its own folder, so that its name is its own
        and one can be deleted without the rest. Only ever a rename in memory: this process
        doesn't read them. No file there means it failed, and the reason is already shown."""
        copies = []
        for entry in entries:
            source = os.path.join(extracted_to, entry)
            if not os.path.isfile(source):
                continue
            name = os.path.basename(entry)
            folder = tempfile.mkdtemp(prefix=OPEN_PREFIX, dir=base)
            copy = {"vault": vault["path"], "name": name, "folder": folder,
                    "path": os.path.join(folder, name), "stamp": None}
            self.opened.append(copy)
            os.rename(source, copy["path"])
            copy["stamp"] = file_stamp(copy["path"])
            copies.append(copy)
        return copies

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
