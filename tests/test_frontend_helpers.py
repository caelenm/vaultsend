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
    GOOD = {"name": "A", "path": "/a", "mode": "password", "last_generation": 3, "key_sha256": "ab"}

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
            self.write(app.VAULTS_FILE, json.dumps([{"name": "x", "path": "/p", "mode": "odd", "last_generation": generation, "key_sha256": 5}]))
            self.assertEqual(app.load_vaults(), [{"name": "x", "path": "/p", "mode": "self", "last_generation": 0, "key_sha256": ""}], generation)

    def test_registry_written_before_key_pinning_still_loads(self):
        self.write(app.VAULTS_FILE, json.dumps([{"name": "x", "path": "/p", "mode": "self", "last_generation": 2}]))
        self.assertEqual(app.load_vaults()[0]["key_sha256"], "")


class Settings(ConfigFiles):
    DEFAULT = {"remember": "off", "cache_explained": False}

    def test_defaults(self):
        self.assertEqual(app.load_settings(), self.DEFAULT)

    def test_round_trip(self):
        value = {"remember": "20m", "cache_explained": True}
        app.save_json(app.SETTINGS_FILE, value)
        self.assertEqual(app.load_settings(), value)

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
        os.mkfifo(self.dir / "key.age")
        self.assertIsNone(app.read_vault_mode(self.dir))
        self.assertEqual(app.key_fingerprint(self.dir), "")

    def test_key_fingerprint(self):
        self.assertEqual(app.key_fingerprint(self.dir), "")
        (self.dir / "key.age").write_bytes(b"abc")
        self.assertEqual(
            app.key_fingerprint(self.dir),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
        )


if __name__ == "__main__":
    unittest.main()
