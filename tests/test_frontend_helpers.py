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


class FakeClock:
    def __init__(self):
        self.now = 1000.0

    def __call__(self):
        return self.now


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


class Settings(ConfigFiles):
    DEFAULT = {"remember": "off", "cache_explained": False, "open_explained": False}

    def test_defaults(self):
        self.assertEqual(app.load_settings(), self.DEFAULT)

    def test_round_trip(self):
        value = {"remember": "20m", "cache_explained": True, "open_explained": True}
        app.save_json(app.SETTINGS_FILE, value)
        self.assertEqual(app.load_settings(), value)

    def test_settings_from_before_open_existed_still_warn(self):
        self.write(app.SETTINGS_FILE, '{"remember": "5m", "cache_explained": true}')
        self.assertFalse(app.load_settings()["open_explained"])

    def test_garbled(self):
        for text in ("{not json", "[]", "null", '{"remember": "forever"}', '{"remember": ["5m"]}', '{"remember": 5}'):
            self.write(app.SETTINGS_FILE, text)
            self.assertEqual(app.load_settings(), self.DEFAULT, text)

    def test_only_true_counts_as_explained(self):
        self.write(app.SETTINGS_FILE, '{"cache_explained": "yes"}')
        self.assertFalse(app.load_settings()["cache_explained"])

    def test_every_choice_has_a_lifetime(self):
        self.assertEqual(app.REMEMBER_SECONDS["off"], 0)
        self.assertIsNone(app.REMEMBER_SECONDS["session"])
        self.assertEqual(
            [label for _, label, _ in app.REMEMBER_CHOICES],
            ["Off", "5 minutes", "20 minutes", "1 day", "1 week", "Until VaultSend closes"],
        )


class Cache(unittest.TestCase):
    def setUp(self):
        self.clock = FakeClock()
        self.cache = app.PassphraseCache(clock=self.clock)

    def test_off_remembers_nothing(self):
        self.cache.put("identity", "secret")
        self.assertIsNone(self.cache.get("identity"))
        self.assertEqual(self.cache.entries, {})

    def test_expiry(self):
        self.cache.set_lifetime(300)
        self.cache.put("identity", "secret")
        self.clock.now += 299
        self.assertEqual(self.cache.get("identity"), "secret")
        self.clock.now += 1
        self.assertIsNone(self.cache.get("identity"))
        self.assertEqual(self.cache.entries, {})

    def test_reading_does_not_extend_it(self):
        self.cache.set_lifetime(300)
        self.cache.put("identity", "secret")
        self.clock.now += 200
        self.cache.get("identity")
        self.clock.now += 200
        self.assertIsNone(self.cache.get("identity"))

    def test_sweep_clears_without_a_read(self):
        self.cache.set_lifetime(60)
        self.cache.put("identity", "secret")
        self.clock.now += 61
        self.cache.sweep()
        self.assertEqual(self.cache.entries, {})

    def test_until_closed_never_expires(self):
        self.cache.set_lifetime(None)
        self.cache.put("identity", "secret")
        self.clock.now += 10 * 365 * 24 * 3600
        self.assertEqual(self.cache.get("identity"), "secret")

    def test_keys_are_separate(self):
        self.cache.set_lifetime(300)
        self.cache.put("identity", "one")
        self.cache.put(("vault", "/a"), "two")
        self.cache.put(("vault", "/b"), "three")
        self.cache.forget(("vault", "/a"))
        self.assertEqual(self.cache.get("identity"), "one")
        self.assertIsNone(self.cache.get(("vault", "/a")))
        self.assertEqual(self.cache.get(("vault", "/b")), "three")
        self.cache.forget("not there")

    def test_clear(self):
        self.cache.set_lifetime(None)
        self.cache.put("identity", "secret")
        self.cache.clear()
        self.assertIsNone(self.cache.get("identity"))

    def test_changing_the_setting_clears(self):
        self.cache.set_lifetime(300)
        self.cache.put("identity", "secret")
        self.cache.set_lifetime(1200)
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


if __name__ == "__main__":
    unittest.main()
