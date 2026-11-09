#!/usr/bin/env python3
"""Tests for the frontend's window-free helpers. Run with the system Python, which
has the GTK bindings: python3 tests/test_frontend_helpers.py

XDG dirs and HOME point into a temp dir before the app is imported, because it reads
them at import time, so the real config can't be touched."""

import json
import os
import shutil
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

ROOT = tempfile.mkdtemp(prefix="vaultsend-frontend-test-", dir="/tmp")
os.environ["XDG_CONFIG_HOME"] = f"{ROOT}/config"
os.environ["XDG_DATA_HOME"] = f"{ROOT}/data"
os.environ["HOME"] = f"{ROOT}/home"
sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "frontend"))

import app  # noqa: E402


def tearDownModule():
    shutil.rmtree(ROOT, ignore_errors=True)


class ConfigFiles(unittest.TestCase):
    def setUp(self):
        shutil.rmtree(app.CONFIG_DIR, ignore_errors=True)

    def write(self, path, text):
        app.CONFIG_DIR.mkdir(parents=True, exist_ok=True)
        path.write_text(text, "utf-8")


class Registry(ConfigFiles):
    GOOD = {"name": "A", "path": "/a", "mode": "password", "last_generation": 3}

    def test_round_trip(self):
        app.save_json(app.VAULTS_FILE, [self.GOOD])
        self.assertEqual(app.load_vaults(), [self.GOOD])
        self.assertFalse(app.VAULTS_FILE.with_name("vaults.json.tmp").exists())

    def test_missing_file(self):
        self.assertEqual(app.load_vaults(), [])

    def test_garbled_files(self):
        for text in ("{not json", "", "null", '{"name": "x"}', "42", '"text"'):
            self.write(app.VAULTS_FILE, text)
            self.assertEqual(app.load_vaults(), [], text)

    def test_bad_entries_are_dropped_not_fatal(self):
        self.write(app.VAULTS_FILE, json.dumps(["str", 1, None, {"name": "x"}, {"path": "/p"}, {"name": 1, "path": "/p"}, self.GOOD]))
        self.assertEqual(app.load_vaults(), [self.GOOD])

    def test_bad_fields_get_safe_defaults(self):
        for generation in (-1, "7", 1.5, True, None):
            self.write(app.VAULTS_FILE, json.dumps([{"name": "x", "path": "/p", "mode": "odd", "last_generation": generation}]))
            self.assertEqual(app.load_vaults(), [{"name": "x", "path": "/p", "mode": "self", "last_generation": 0}], generation)

    def test_a_key_hash_from_an_older_build_is_dropped(self):
        self.write(app.VAULTS_FILE, json.dumps([{"name": "x", "path": "/p", "mode": "self", "last_generation": 2, "key_sha256": "ab"}]))
        self.assertEqual(app.load_vaults(), [{"name": "x", "path": "/p", "mode": "self", "last_generation": 2}])

    def test_saved_files_are_private(self):
        old = os.umask(0)
        self.addCleanup(os.umask, old)
        for path, save in (
            (app.VAULTS_FILE, lambda: app.save_json(app.VAULTS_FILE, [])),
            (app.SETTINGS_FILE, lambda: app.save_json(app.SETTINGS_FILE, {})),
            (app.CONTACTS_FILE, lambda: app.save_contacts([])),
        ):
            save()
            self.assertEqual(path.stat().st_mode & 0o777, 0o600, path)
            # Neither an older, wider file nor a temp file left by a crash passes its mode on.
            path.chmod(0o644)
            tmp = path.with_name(path.name + ".tmp")
            tmp.write_text("left by a crash")
            tmp.chmod(0o644)
            save()
            self.assertEqual(path.stat().st_mode & 0o777, 0o600, path)
            self.assertFalse(tmp.exists())


class Settings(ConfigFiles):
    DEFAULT = {"remember": "off", "cache_explained": False, "open_explained": False}

    def test_defaults(self):
        self.assertEqual(app.load_settings(), self.DEFAULT)

    def test_round_trip(self):
        value = {"remember": "session", "cache_explained": True, "open_explained": True}
        app.save_json(app.SETTINGS_FILE, value)
        self.assertEqual(app.load_settings(), value)

    def test_settings_from_before_open_existed_still_warn(self):
        self.write(app.SETTINGS_FILE, '{"remember": "session", "cache_explained": true}')
        self.assertFalse(app.load_settings()["open_explained"])

    def test_garbled(self):
        for text in ("{not json", "[]", "null", '{"remember": "forever"}', '{"remember": ["session"]}', '{"remember": 5}'):
            self.write(app.SETTINGS_FILE, text)
            self.assertEqual(app.load_settings(), self.DEFAULT, text)

    def test_only_true_counts_as_explained(self):
        self.write(app.SETTINGS_FILE, '{"cache_explained": "yes"}')
        self.assertFalse(app.load_settings()["cache_explained"])

    def test_choices(self):
        self.assertEqual(
            [label for _, label in app.REMEMBER_CHOICES],
            ["Off", "Until VaultSend closes"],
        )

    def test_old_timed_choices_fall_back_to_off(self):
        for value in ("5m", "20m", "1d", "1w"):
            self.write(app.SETTINGS_FILE, '{"remember": "%s"}' % value)
            self.assertEqual(app.load_settings()["remember"], "off", value)


class Cache(unittest.TestCase):
    def setUp(self):
        self.cache = app.PassphraseCache()

    def test_off_remembers_nothing(self):
        self.cache.put("identity", "secret")
        self.assertIsNone(self.cache.get("identity"))
        self.assertEqual(self.cache.entries, {})

    def test_until_closed_keeps_it(self):
        self.cache.set_enabled(True)
        self.cache.put("identity", "secret")
        self.assertEqual(self.cache.get("identity"), "secret")

    def test_keys_are_separate(self):
        self.cache.set_enabled(True)
        self.cache.put("identity", "one")
        self.cache.put(("vault", "/a"), "two")
        self.cache.put(("vault", "/b"), "three")
        self.cache.forget(("vault", "/a"))
        self.assertEqual(self.cache.get("identity"), "one")
        self.assertIsNone(self.cache.get(("vault", "/a")))
        self.assertEqual(self.cache.get(("vault", "/b")), "three")
        self.cache.forget("not there")

    def test_clear(self):
        self.cache.set_enabled(True)
        self.cache.put("identity", "secret")
        self.cache.clear()
        self.assertIsNone(self.cache.get("identity"))

    def test_changing_the_setting_clears(self):
        self.cache.set_enabled(True)
        self.cache.put("identity", "secret")
        self.cache.set_enabled(False)
        self.assertIsNone(self.cache.get("identity"))
        self.cache.set_enabled(True)
        self.assertIsNone(self.cache.get("identity"))


class Names(unittest.TestCase):
    def test_valid(self):
        for name in ("a", "My Vault", "ünï ☃", "a.b", "..x", "-x", "x" * 247):
            self.assertTrue(app.is_valid_vault_name(name), name)

    def test_invalid(self):
        for name in ("", ".", "..", "a/b", "/", "a\0b", "x" * 248):
            self.assertFalse(app.is_valid_vault_name(name), name)

    def test_short_path(self):
        home = str(Path.home())
        self.assertEqual(app.short_path(f"{home}/x.vsvault"), "~/x.vsvault")
        self.assertEqual(app.short_path(f"{home}/a/b/c/x.vsvault"), "~/…/x.vsvault")
        self.assertEqual(app.short_path("/mnt/data/deep/x.vsvault"), "/…/x.vsvault")
        self.assertEqual(app.short_path("/x.vsvault"), "/x.vsvault")
        self.assertEqual(app.short_path(home + "er/x.vsvault"), "/…/x.vsvault")

    def test_entry_indent_follows_depth(self):
        self.assertEqual(app.entry_indent("top"), 0)
        self.assertEqual(app.entry_indent("a/b"), app.INDENT_STEP)
        self.assertEqual(app.entry_indent("a/b/c.txt"), 2 * app.INDENT_STEP)

    def test_entry_indent_is_capped(self):
        most = app.INDENT_LEVELS * app.INDENT_STEP
        self.assertEqual(app.entry_indent("a/" * app.INDENT_LEVELS + "x"), most)
        self.assertEqual(app.entry_indent("a/" * (app.INDENT_LEVELS + 1) + "x"), most)
        self.assertEqual(app.entry_indent("a/" * 1000 + "x"), most)


class Selection(unittest.TestCase):
    ENTRIES = {
        "a": {"is_dir": True}, "a/1.txt": {"is_dir": False}, "a/b": {"is_dir": True},
        "a/b/2.txt": {"is_dir": False}, "ab.txt": {"is_dir": False}, "empty": {"is_dir": True},
    }

    def test_parent_folders(self):
        self.assertEqual(app.parent_folders("top"), [])
        self.assertEqual(app.parent_folders("a/b/c"), ["a", "a/b"])

    def test_a_folder_covers_what_is_in_it(self):
        self.assertEqual(app.top_level_selection(["a", "a/1.txt", "a/b", "a/b/2.txt", "ab.txt"]), ["a", "ab.txt"])

    def test_a_similar_name_is_not_inside(self):
        self.assertEqual(app.top_level_selection(["a", "ab.txt"]), ["a", "ab.txt"])

    def test_the_whole_vault_covers_everything(self):
        self.assertEqual(app.top_level_selection(["a", app.ROOT_ENTRY]), [app.ROOT_ENTRY])

    def test_nothing_selected(self):
        self.assertEqual(app.top_level_selection([]), [])

    def test_files_in_a_selection(self):
        files = lambda *selection: app.files_in_selection(selection, self.ENTRIES)
        self.assertEqual(files("a"), ["a/1.txt", "a/b/2.txt"])
        self.assertEqual(files("a/b", "ab.txt"), ["a/b/2.txt", "ab.txt"])
        self.assertEqual(files(app.ROOT_ENTRY), ["a/1.txt", "a/b/2.txt", "ab.txt"])
        self.assertEqual(files("empty"), [])

    def test_entry_args(self):
        self.assertEqual(app.entry_args(["a", "--replace"]), ["--entry", "a", "--entry", "--replace"])

    def test_share_names(self):
        name = lambda *selection: app.share_file_name("V", selection, self.ENTRIES)
        self.assertEqual(name("a/1.txt"), "1.txt.age")
        self.assertEqual(name("a/b"), "b.tar.age")
        self.assertEqual(name(app.ROOT_ENTRY), "V.tar.age")
        self.assertEqual(name("a/1.txt", "ab.txt"), "V selection.tar.age")

    def test_receiving_a_share_suggests_names_that_round_trip(self):
        # What Share names a share comes back as what was shared.
        for selection, unpacked in ((("a/b",), "b"), ((app.ROOT_ENTRY,), "V"), (("a/1.txt",), "1.txt")):
            shared = app.share_file_name("V", selection, self.ENTRIES)
            self.assertEqual(app.unpacked_name(shared), unpacked)
        self.assertEqual(app.saved_name("b.tar.age"), "b.tar")
        self.assertEqual(app.saved_name("1.txt.age"), "1.txt")
        self.assertEqual(app.unpacked_name("renamed"), "renamed decrypted")
        self.assertEqual(app.saved_name("renamed"), "renamed decrypted")
        for name in (".age", ".tar.age"):  # nothing left once the suffix comes off
            self.assertNotEqual(app.unpacked_name(name), "")
            self.assertNotEqual(app.saved_name(name), "")

    def test_a_free_name_never_replaces_anything(self):
        folder = tempfile.mkdtemp(dir=ROOT)
        self.assertEqual(app.free_name(folder, "Photos"), "Photos")
        os.mkdir(os.path.join(folder, "Photos"))
        self.assertEqual(app.free_name(folder, "Photos"), "Photos (2)")
        Path(folder, "a.txt").write_text("x")
        Path(folder, "a (2).txt").write_text("x")
        self.assertEqual(app.free_name(folder, "a.txt"), "a (3).txt")
        os.symlink("/nonexistent", os.path.join(folder, "dangling"))  # a broken link is still taken
        self.assertEqual(app.free_name(folder, "dangling"), "dangling (2)")
        Path(folder, ".age").write_text("x")
        self.assertEqual(app.free_name(folder, ".age"), ".age (2)")

    def test_what_decrypt_offers_for_a_share(self):
        self.assertEqual(app.share_actions("password", "b.tar.age"), ["unpack", "save", "import"])
        self.assertEqual(app.share_actions("key", "b.tar.age"), ["unpack", "save", "import"])
        self.assertEqual(app.share_actions("password", "1.txt.age"), ["save", "import"])
        # One file for your key: the plain decrypt, as before.
        self.assertEqual(app.share_actions("key", "1.txt.age"), [])

    def test_vault_name_from_path(self):
        self.assertEqual(app.vault_name_from_path("/x/My Vault.vsvault"), "My Vault")
        self.assertEqual(app.vault_name_from_path("/x/My Vault.vsvault/"), "My Vault")
        self.assertEqual(app.vault_name_from_path("/x/plain"), "plain")


class ProgressReports(unittest.TestCase):
    def test_latest_wins(self):
        self.assertEqual(app.last_percent(b"3\n4\n5\n", None), 5)

    def test_nothing_new_keeps_the_last(self):
        self.assertEqual(app.last_percent(b"", 40), 40)
        self.assertIsNone(app.last_percent(b"", None))

    def test_never_above_100(self):
        self.assertEqual(app.last_percent(b"999\n", 1), 100)

    def test_junk_is_ignored(self):
        self.assertEqual(app.last_percent(b"7\nnot a number\n", None), 7)
        self.assertEqual(app.last_percent(b"\xff\xfe", 7), 7)


class Listing(unittest.TestCase):
    def test_unescapes_for_display(self):
        generation, entries = app.parse_listing(
            "generation 7\n"
            "D a%20b\n"
            "F 12 a%20b/%C3%BCn%C3%AF%25.txt\n"
            "F 0 new%0Aline\n"
        )
        self.assertEqual(generation, 7)
        self.assertEqual(entries, [
            {"path": "a b", "is_dir": True, "size": 0},
            {"path": "a b/ünï%.txt", "is_dir": False, "size": 12},
            {"path": "new\nline", "is_dir": False, "size": 0},
        ])

    def test_empty_vault(self):
        self.assertEqual(app.parse_listing("generation 0\n"), (0, []))

    def test_folder_by_folder_folders_first(self):
        text = "generation 1\nF 1 Zebra\nD apple\nF 1 apple/z\nD apple/sub\nF 1 apple/sub/x\nD Banana\nF 1 cherry\n"
        paths = [e["path"] for e in app.parse_listing(text)[1]]
        self.assertEqual(paths, ["apple", "apple/sub", "apple/sub/x", "apple/z", "Banana", "cherry", "Zebra"])

    def test_every_parent_comes_before_its_contents(self):
        # The manifest's byte order would put "a b" between "a" and "a/c".
        text = "generation 1\nD a\nD a b\nF 1 a b/x\nF 1 a/c\n"
        seen = set()
        for e in app.parse_listing(text)[1]:
            parent = e["path"].rpartition("/")[0]
            self.assertTrue(parent == "" or parent in seen, e)
            seen.add(e["path"])

    def test_garbled_generation_raises(self):
        for text in ("", "nonsense\n", "generation x\n"):
            with self.assertRaises(ValueError):
                app.parse_listing(text)


class OpenedCopies(unittest.TestCase):
    def setUp(self):
        self.dir = Path(tempfile.mkdtemp(dir=ROOT))

    def test_only_a_folder_really_in_memory_is_used(self):
        with mock.patch.object(app, "memory_candidates", lambda: ["/disk", "/ram", "/also-ram"]), \
                mock.patch.object(app, "is_in_memory", lambda p: p != "/disk"):
            self.assertEqual(app.memory_folder(), "/ram")
        # The point of the check: no in-memory folder means no folder, never a disk one.
        with mock.patch.object(app, "memory_candidates", lambda: ["/disk"]), \
                mock.patch.object(app, "is_in_memory", lambda p: False):
            self.assertIsNone(app.memory_folder())

    def test_candidates_prefer_the_private_runtime_dir(self):
        with mock.patch.dict(os.environ, {"XDG_RUNTIME_DIR": "/run/user/1"}):
            self.assertEqual(app.memory_candidates(), ["/run/user/1", "/dev/shm"])
        with mock.patch.dict(os.environ):
            os.environ.pop("XDG_RUNTIME_DIR", None)
            self.assertEqual(app.memory_candidates(), ["/dev/shm"])

    def test_in_memory_detection(self):
        self.assertFalse(app.is_in_memory("/proc"))
        self.assertFalse(app.is_in_memory("/no/such/folder"))
        with open("/proc/mounts") as mounts:
            tmpfs = [line.split()[1] for line in mounts if line.split()[2] == "tmpfs"]
        tmpfs = [m for m in tmpfs if os.path.isdir(m)]
        if not tmpfs:
            self.skipTest("no tmpfs is mounted here")
        self.assertTrue(app.is_in_memory(tmpfs[0]), tmpfs[0])

    def test_clearing_leftovers_touches_only_our_folders(self):
        ours = self.dir / f"{app.OPEN_PREFIX}abc"
        ours.mkdir()
        (ours / "secret.txt").write_text("left by a crash")
        other_folder = self.dir / "someone-elses"
        other_folder.mkdir()
        (other_folder / "keep.txt").write_text("keep")
        a_file = self.dir / f"{app.OPEN_PREFIX}a-file"
        a_file.write_text("keep")
        link = self.dir / f"{app.OPEN_PREFIX}a-link"
        link.symlink_to(other_folder)
        with mock.patch.object(app, "memory_candidates", lambda: [str(self.dir), "/no/such/folder"]):
            app.clear_stale_copies()
        self.assertFalse(ours.exists())
        self.assertEqual((other_folder / "keep.txt").read_text(), "keep")
        self.assertTrue(a_file.exists())
        self.assertTrue(link.is_symlink())

    def test_stamp_notices_an_edit_without_reading_the_file(self):
        f = self.dir / "copy"
        f.write_text("original")
        before = app.file_stamp(f)
        self.assertEqual(app.file_stamp(f), before)
        f.write_text("edited, and longer")
        self.assertNotEqual(app.file_stamp(f), before)
        f.unlink()
        self.assertIsNone(app.file_stamp(f))


class VaultFiles(unittest.TestCase):
    def setUp(self):
        self.dir = Path(tempfile.mkdtemp(dir=ROOT))

    def test_mode(self):
        self.assertIsNone(app.read_vault_mode(self.dir))
        (self.dir / "VAULT").write_text("vaultsend-vault 1\nmode self\n")
        self.assertEqual(app.read_vault_mode(self.dir), "self")
        (self.dir / "VAULT").write_text("vaultsend-vault 1\nmode password\n")
        self.assertEqual(app.read_vault_mode(self.dir), "password")
        for bad in ("", "vaultsend-vault 2\nmode self\n", "vaultsend-vault 1\nmode other\n", "vaultsend-vault 1\nmode self"):
            (self.dir / "VAULT").write_text(bad)
            self.assertIsNone(app.read_vault_mode(self.dir), bad)
        (self.dir / "VAULT").write_bytes(b"\xff\xfe")
        self.assertIsNone(app.read_vault_mode(self.dir))

    def test_a_fifo_does_not_hang(self):
        # A hang would fail this by never finishing: the window would freeze the same way.
        os.mkfifo(self.dir / "VAULT")
        self.assertIsNone(app.read_vault_mode(self.dir))


class CutAndPaste(unittest.TestCase):
    """The rules behind Cut and Paste, the same as on Android."""

    ENTRIES = {
        p: {"path": p, "is_dir": d}
        for p, d in [("a", True), ("a/1.txt", False), ("a/b", True), ("dest", True),
                     ("dest/1.txt", False), ("x.txt", False), ("y.txt", False)]
    }

    def test_destination(self):
        e = self.ENTRIES
        self.assertEqual(app.destination_folder(["dest"], e), "dest")
        self.assertEqual(app.destination_folder(["a/1.txt"], e), "a")  # beside a chosen file
        self.assertEqual(app.destination_folder([], e), "")
        self.assertEqual(app.destination_folder(["x.txt", "y.txt"], e), "")
        self.assertEqual(app.destination_folder([app.ROOT_ENTRY], e), "")

    def test_moves_skip_what_is_already_there(self):
        self.assertEqual(app.paste_moves(["x.txt", "y.txt"], "dest"), [("x.txt", "dest/x.txt"), ("y.txt", "dest/y.txt")])
        self.assertEqual(app.paste_moves(["a/1.txt"], ""), [("a/1.txt", "1.txt")])
        self.assertEqual(app.paste_moves(["x.txt"], ""), [])
        self.assertEqual(app.paste_moves(["dest/1.txt"], "dest"), [])

    def test_problems(self):
        e = self.ENTRIES
        self.assertIsNone(app.paste_problem(["x.txt"], "dest", e))
        self.assertEqual(app.paste_problem(["a"], "a", e), "Can't paste “a” inside itself.")
        self.assertEqual(app.paste_problem(["a"], "a/b", e), "Can't paste “a” inside itself.")
        self.assertEqual(app.paste_problem(["a/1.txt"], "dest", e), "“1.txt” already exists there.")


if __name__ == "__main__":
    unittest.main()
