# VaultSend — Vaults: change record

Record for `feature/vaults`, version 0.2.0 (spec: `VAULTS_PLAN.md`). Local branch
only; nothing has been pushed.

- [Summary](#summary)
- [Decisions made by the owner](#decisions-made-by-the-owner)
- [Files touched](#files-touched)
- [Every existing line changed, and why](#every-existing-line-changed-and-why)
- [New CLI commands](#new-cli-commands)
- [On-disk format](#on-disk-format-v1)
- [Threat model additions](#threat-model-additions)
- [Known limitations](#known-limitations)
- [Deviations from the plan](#deviations-from-the-plan)
- [Test results](#test-results)
- [Hashes](#hashes)
- [Screenshots](#screenshots)
- [How this was tested](#how-this-was-tested)

---

## Summary

Vaults are encrypted folders that change one file at a time: per-file age blobs bound
by an age-encrypted manifest that pins each blob by SHA-256 and carries a generation
counter. Everything in the plan is built, in the backend (`vault.rs`), the frontend
(`app.py`) and tests, plus an **Open** button the owner asked for afterwards. No new
crate. The audited backend functions and `FileOperation`, `run_backend` and
`spawn_backend` are byte-identical to `main`, checked by comparing each definition.

---

## Decisions made by the owner

**Option B kept at the fallback gate (2026-11-03).** The plan (§1) says that if
`vault.rs` exceeds ~550 lines excluding `#[cfg(test)]`, stop and ask whether to fall
back to option A. It measured 791 at that point (632 code, 104 comments, 55 blank),
after a first draft of 943 and one simplification pass. The owner kept option B and
the budget became ~800.

The estimate was simply low. Every fallible call needs a readable error, every write
is stage/fsync/rename, and every path is validated. Going lower would have meant
dropping required behaviour or packing code onto fewer lines. The file lock, the one
sizable addition (21 lines), prevents silent data loss. Option A would have added
`tar` and its dependencies, a third-party parser of hostile input, and lost partial
updates.

**Key-swap gap fixed rather than documented (2026-11-03).** See the threat model below.

**Open button added (2026-11-03), reversing §0.6's "no 'open in app'".** The owner asked
how files are meant to be used from inside a vault, then asked for an Open button with a
plaintext warning acknowledged on first use. The rest of §0.6 holds: the frontend still
never holds file plaintext, and a file is still fully verified in RAM before any of it is
written. See the threat model below.

---

## Files touched

```
 CHANGES-VAULTS.md                                  |  486 +++++++++++++
 README.md                                          |  103 ++-
 VAULTS_PLAN.md                                     |  403 +++++++++++
 backend/Cargo.lock                                 |    4 +-
 backend/Cargo.toml                                 |   13 +-
 backend/src/main.rs                                |    8 +-
 backend/src/vault.rs                               | 1542 ++++++++++++++++++++++++++++++++++++++++
 docs/screenshots/vaults/01a-contacts-main.png      |  Bin 0 -> 40841 bytes
 docs/screenshots/vaults/01b-contacts-branch.png    |  Bin 0 -> 42208 bytes
 docs/screenshots/vaults/02-vaults-empty.png        |  Bin 0 -> 39245 bytes
 docs/screenshots/vaults/03-vaults-two.png          |  Bin 0 -> 36869 bytes
 docs/screenshots/vaults/04-create-dialog.png       |  Bin 0 -> 61092 bytes
 docs/screenshots/vaults/05-unlocked-nested.png     |  Bin 0 -> 47764 bytes
 docs/screenshots/vaults/06-rollback-warning.png    |  Bin 0 -> 54236 bytes
 docs/screenshots/vaults/07-tamper-error.png        |  Bin 0 -> 62387 bytes
 docs/screenshots/vaults/08-passphrase-menu.png     |  Bin 0 -> 45891 bytes
 docs/screenshots/vaults/09-key-changed-warning.png |  Bin 0 -> 69172 bytes
 docs/screenshots/vaults/10-open-warning.png        |  Bin 0 -> 76764 bytes
 docs/screenshots/vaults/11-open-changes-lost.png   |  Bin 0 -> 63308 bytes
 frontend/app.py                                    | 1132 ++++++++++++++++++++++++++++-
 tests/test_frontend_helpers.py                     |  322 +++++++++
 tests/vault_gui_check.sh                           |   48 ++
 tests/vault_gui_driver.py                          |  897 +++++++++++++++++++++++
 tests/vault_roundtrip.sh                           |  257 +++++++
 tests/verify_deps.sh                               |   75 ++
 25 files changed, 5274 insertions(+), 16 deletions(-)
```

| File | What |
|---|---|
| `backend/src/vault.rs` | New. All vault logic and its unit tests. |
| `backend/src/main.rs` | `mod vault;`, one dispatch arm, usage text. |
| `backend/Cargo.toml`, `Cargo.lock` | `sha2` and `rand` as direct dependencies, version, test profile. |
| `frontend/app.py` | Sidebar toggle, vault page, dialogs, registry, passphrase cache. |
| `tests/verify_deps.sh` | §5.1: crate hashes against the lock and crates.io. |
| `tests/vault_roundtrip.sh` | §5.2: end-to-end CLI test, tamper suite, optional strace proof. |
| `tests/test_frontend_helpers.py` | §4.6: frontend helpers. |
| `tests/vault_gui_check.sh`, `vault_gui_driver.py` | Not in the plan: a repeatable §5.3 run-through in the real window, which also takes the screenshots. |
| `docs/screenshots/vaults/` | §5.3. |
| `README.md` | §6. |
| `CHANGES-VAULTS.md` | This file. |

---

## Every existing line changed, and why

Lines added around existing code aren't listed; these are the lines that were altered.

### `backend/src/main.rs` (one line)

| Line | Why |
|---|---|
| The usage string in `run()`'s unknown-command error | Lists the new commands. §3 allows it. |

**No `pub(crate)` was needed, so none was added.** A child module can already see its
ancestors' private items, so the helpers §3 reuses needed no change at all. The other
additions are `mod vault;`, one new dispatch arm, and one line in the header's command list.

### `backend/Cargo.toml` (one line)

`version` from 0.1.2 to 0.2.0 (§6). New lines only otherwise: `sha2`, `rand`, and
`[profile.dev.package."*"] opt-level = 2`. That profile isn't in the plan. The unit
tests run real scrypt at 2^18, which is slow unoptimized. It affects test and debug
builds only.

### `backend/Cargo.lock`

`vaultsend-backend`'s version, plus `rand` and `sha2` in its dependency list. No `[[package]]` added.

### `frontend/app.py` (ten lines)

| Line on `main` | Becomes | Why |
|---|---|---|
| `APP_VERSION = "0.1.2"` | `"0.2.0"` | §6 |
| `header.set_title_widget(Adw.WindowTitle(title="Contacts"))` | the toggle | §4.1 |
| `add_btn.set_child(Adw.ButtonContent(…, label="Add contact"))` | held in `self.add_content` | §4.1: the label follows the toggle |
| `add_btn.connect("clicked", … self.add_contact_dialog())` | `self.on_add_clicked()` | §4.1 |
| `box.append(scroller)` | appended to a `Gtk.Stack` | §4.1 |
| `tooltip_text="Toggle contacts"` | `"Toggle sidebar"` | §4.1 |
| `self.toasts.set_child(scroller)` | `content_stack` | §4.2 |
| `for name, fn in (("show-key", …), ("about", …)):` | adds `lock-now` | §4.5 |
| `self.ask_passphrase(lambda p: self._save_then(` in `decrypt_file` | `with_passphrase("identity", …)` | §4.5 |
| `self.ask_passphrase(lambda p: self._decrypt_text(text, p))` | `with_passphrase("identity", …)` | §4.5 |

New lines also went into `Window.__init__`, `Window.error` (forgets a rejected
passphrase; every identity decrypt reports through it), the menu in `_build_content`,
and `VaultSend` (clears the cache on shutdown). All are §4.5. `ask_passphrase` itself
is unchanged. Key creation and recovery still call it directly, so those are never cached.

### `README.md` (three lines)

The backend's line count, "forgets it" (now qualified by Remember passphrase), and
"two source files" (now three). Everything else is additions.

---

## New CLI commands

```
vault-create  --dir P --mode self
vault-create  --dir P --mode password --pass-fd N
vault-list    --dir P --pass-fd N
vault-add     --dir P --pass-fd N --src PATH [--src PATH]... [--dest VAULTDIR] [--replace]
vault-remove  --dir P --pass-fd N --entry VAULTPATH
vault-extract --dir P --pass-fd N --entry VAULTPATH --out PATH
vault-check   --dir P --pass-fd N
```

Every command that opens a vault also accepts `--key-sha256 HEX`. `--pass-fd` carries
the identity passphrase for a `self` vault and the vault password for a `password`
vault. `--entry /` means the whole vault.

---

## On-disk format (v1)

A vault is a directory (default suffix `.vsvault`):

```
MyVault.vsvault/
  VAULT          plaintext, not secret:  "vaultsend-vault 1\nmode self|password\n"
  key.age        the vault's own X25519 identity, age-encrypted:
                   mode self     -> to the user's own pubkey (unlock = identity passphrase)
                   mode password -> age scrypt recipient, work factor 2^18 (SCRYPT_LOG_N)
  manifest.age   age-encrypted to the vault's public key (see below)
  blobs/<aa>/<32-hex-random-id>.age   one per file, age-encrypted to the vault's public key
```

`VAULT`'s `mode` line is only a hint for which prompt to show. The backend doesn't trust
it: a wrong mode just fails to decrypt `key.age`, as a clear error. age requires a
passphrase (scrypt) stanza to be the only stanza, so a vault is key-unlocked or
password-unlocked, never both.

### Manifest (plaintext inside `manifest.age`, UTF-8, `\n` line endings)

```
vaultsend-manifest 1
generation <u64>
F <blob-id:32 hex> <sha256-of-blob-file:64 hex> <plaintext-size> <escaped-path>
D <escaped-path>
```

- `F` = file, `D` = folder. Every parent folder has its own `D` record.
- `escaped-path`: vault-relative, `/`-separated; every byte outside
  `[A-Za-z0-9._~/-]` written as `%XX`, canonically (one spelling per path).
- **Path validation** (`valid_vault_path`, used by add, remove, extract and manifest
  parsing): non-empty; not absolute; no empty, `.` or `..` components; no NUL;
  components ≤ 255 bytes; total ≤ 4096 bytes. Must be valid UTF-8.
- The parser rejects: unknown version, unknown record type, duplicate paths, malformed
  hex/size, a file path that is also a folder path, a missing parent, a non-canonical
  escape or number, trailing junk.
- The hash is over the **ciphertext blob file**, so it is checked before decrypting and
  pins the exact bytes.
- `size` is for display only; the hash and age authenticate a file.

### Write protocol

1. Write each new blob to `<blob>.vaultsend-part` via `open_private_new`, hashing while
   writing, fsync, rename, fsync its folder.
2. Write the new manifest with `generation + 1` to `manifest.age.vaultsend-part`, fsync,
   rename → **this rename is the commit point.** fsync the vault folder.
3. Delete blobs the new manifest doesn't reference, including orphans from an earlier
   crash. Only files under `blobs/` named exactly
   `^[0-9a-f]{2}/[0-9a-f]{32}\.age(\.vaultsend-part)?$` qualify. Nothing else is ever deleted.

A crash at any point leaves the old vault or the new one, never a mix.

---

## Threat model additions

**What a vault protects against,** for someone who can read or write the vault's folder
but has neither the vault key nor the secret that unlocks it:

- **Reading content or names:** both are encrypted.
- **Forging a manifest:** age recipients are anonymous and the vault's public key is
  stored nowhere in the clear, so it can't be made without the vault key.
- **Altering, truncating, swapping or deleting a blob, or putting back an old one:** the
  pinned hash catches it, before decryption, with nothing written.
- **Rolling back the whole vault:** caught by the generation check, on a device that saw
  the newer version.
- **Swapping `key.age` (below):** caught on a device that has seen the vault.

**Plaintext rule.** The frontend never holds file plaintext. A file is fully decrypted
and verified in the backend's RAM before any of it is written, a folder extract does this
for every file first, and VaultSend writes plaintext to disk only at a path the user chose.
The strace check in `vault_roundtrip.sh` confirms the ordering. RAM is held in zeroizing
buffers, allocated once so they never leave a copy behind, and swap protection is the
same best-effort `mlockall` as the rest of the backend.

### Open (added at the owner's request)

Open hands a decrypted file to another program, which is outside anything VaultSend can
protect. What it does:

- The backend extracts the file as usual, verified in RAM first, into a new `0700` folder
  from `mkdtemp`, with the file itself `0600` and so never executable. The frontend only
  handles the path, and detects edits from metadata without reading the file.
- The folder must really be in memory. `$XDG_RUNTIME_DIR` is preferred, then `/dev/shm`, and
  each is checked to be tmpfs or ramfs. If neither is, Open refuses and suggests Extract.
- The copy is deleted on Lock, Lock now and close. Leftovers from a crash are removed at the
  next launch: only real folders with our prefix owned by this user, never a symlink.
- The first use warns about the plaintext risk and needs **I understand**, remembered in
  `settings.json`. Cancel decrypts nothing and isn't remembered.

What it can't do, and the warning and README say so:

- **The other app can write its own plaintext to disk:** recovery files, thumbnails,
  recent-file lists. This is the main risk, and VaultSend can't see or remove them.
- **Other programs running as the user can read the copy,** which is the same-user threat
  the backend's hardening defends the key against.
- **tmpfs can reach disk** through swap or hibernation.
- **Unsaved work in the other app is invisible to VaultSend.** It can only tell a copy has
  changed once it's saved, so Lock can delete a file still being worked on.
- **Opening runs the file's default app on its contents.** A shared vault's files are as
  untrusted as any other download.

### The `key.age` swap (found during this work, fixed at the owner's request)

age has no sender authentication, and a user's public key is public by design. So anyone
who could write to a **`self`** vault's folder could replace `key.age` with one wrapping a
vault key they know, plus a matching manifest. The user's passphrase would still unlock
it, and the generation check could be satisfied by picking a high number. The listing
would look wrong, since the attacker can't read the old contents. But any file the user
then added would be encrypted to a key the attacker holds. A `password` vault isn't
exposed the same way, because forging its `key.age` needs the password.

The fix pins `key.age` by SHA-256 in two layers, for both modes, because `key.age` never
legitimately changes in 0.2.0:

- **Frontend:** `vaults.json` gains `key_sha256`, recorded when a vault is created or
  added. Before asking for any secret, `with_vault_secret` compares the current file and
  shows a warning if it changed.
- **Backend:** `--key-sha256` makes `unlock` refuse if the bytes of `key.age` it just read
  don't match, before reading the secret. A frontend-only check could be beaten by swapping
  the file after it ran.

### Not defended against

The same as the rest of VaultSend, plus: someone with write access can always *destroy* a
vault, by deleting or corrupting it, or stall an operation by putting a FIFO in it. Damage
gets detected but can't be prevented, so keep backups.

---

## Known limitations

- Whole-vault rollback and a swapped `key.age` are detected only on a device that saw the
  vault before. The memory lives in `vaults.json`: a vault swapped before this device first
  added it isn't detected, and neither is one reached with `vaults.json` deleted.
- On-disk metadata: file count, approximate per-file sizes, blob modified times. Names and
  folder structure stay hidden.
- Extraction needs RAM of about 2× the file's size. A folder needs about its total size.
  Open needs about 3×, since the copy stays in memory too.
- Open handles one file at a time, and changes aren't saved back: Save As in the other app,
  then add the file back. Sandboxed apps (Flatpak, Snap) may not be able to read the copy. If
  VaultSend is killed, the copy stays in memory until its next launch, logout or reboot.
- The frontend's passphrase cache is not swap-protected, and Python can't reliably wipe
  strings. Off by default, and the app says so the first time it's turned on.
- Sharing a password vault means copying its folder (no single-file export yet), and a
  password can't be changed yet.
- Names must be valid UTF-8: adding a non-UTF-8 name fails and names it. On the command
  line, any non-UTF-8 argument aborts the backend, as it already did for the existing commands.
- `vault-list` runs synchronously, as the existing text decrypt does, so unlocking freezes
  the window for the length of one scrypt.
- A cancelled or failed `add` leaves encrypted orphan blobs if the backend is killed; the
  next change collects them, and `vault-check` reports them until then.

---

## Deviations from the plan

Places this differs from, or adds to, what the plan says:

| What | Why |
|---|---|
| `key_sha256` in `vaults.json`, and `--key-sha256` | Owner's decision, above. |
| An **Open** button, reversing §0.6's "no 'open in app'" | Owner's decision, above. |
| A "Changes will be lost" prompt on Lock, Lock now and close | Not asked for. An edited copy is about to be deleted and has nowhere else to go, and this catches it for saved edits. |
| A `flock` on the `VAULT` file | The plan's garbage collection deletes unreferenced blobs, which would include another process's uncommitted ones. Exclusive for changes, shared for reads, released by the kernel however the process dies. |
| `vault-add` accepts repeated `--src` | Several files are then one unlock and one generation. Otherwise each dropped file would pay a full scrypt. |
| Folder extract builds under `<out>.vaultsend-part`, then renames | `--out` is only ever absent or complete, and a cancel has one unambiguous thing to clean up. |
| Options parsed strictly in `vault.rs`, not with `main.rs`'s helpers | Values can be names out of a vault: a folder called `--replace` must not read as the flag. |
| Parents must have `D` records; only canonical escapes | Stricter parser than §2 lists. One rule covers several cases. |
| The manifest is parsed back before every commit | So a bug can't write one that locks the user out. |
| `VaultOperation` subclass, not `total=None` in `FileOperation` | §4.2 allowed the smallest change to `FileOperation`. A subclass needs none, so it stays byte-identical, at the cost of repeating a few lines of `_finish`. |
| Only changes re-list, not "every op" (§4.2) | Extract and verify change nothing, and a re-list costs a scrypt with the window frozen. |
| A **Verify all** button beside the "Files" heading | §4.2 lists check as a frontend operation, but its action bar has no button for it. The bar itself matches the plan. |
| An "Everything in this vault" row | What Extract acts on when nothing else is selected, so there's no hidden default. |
| Vault errors are dialogs, not toasts | A failed integrity check shouldn't fade away by itself. |
| A file with a name colliding on extract is an error | `open_private_new` would replace it, and "A" and "a" are one file on a case-insensitive disk. |
| Clippy gate runs on Rust 1.85.0 | On untouched `main`, `clippy -D warnings` under 1.75.0 already fails on `File::open(&p)` in `identity_is_valid`, a lint later narrowed. That line is audited, so it stays. Build and tests run on both. |
| `tests/vault_gui_check.sh` and `vault_gui_driver.py` | Not asked for. They make the Phase 4 run-through and §5.3 repeatable. |
| `vault.rs` is 804 lines without its tests | Budget ~800, after the owner raised it from ~550. |

---

## Test results

Run from the final tree:

| Check | Result |
|---|---|
| `cargo test --locked`, Rust 1.75.0 and 1.85.0 | 28 passed, 0 failed, on both |
| `cargo clippy --locked --all-targets -- -D warnings`, 1.85.0 | Clean |
| `cargo build --release --locked`, 1.75.0 | OK |
| `tests/verify_deps.sh` | All 8 crates match `Cargo.lock` and crates.io; no `[[package]]` added |
| `tests/vault_roundtrip.sh` | 89 passed, 0 failed; 90 of 90 where `strace` is available |
| strace proof | The last blob is opened before the output path is first touched |
| `tests/test_frontend_helpers.py` | 36 passed, on both GTK versions below |
| `tests/vault_gui_check.sh`, Debian trixie: Python 3.13, GTK 4.18.6, libadwaita 1.7.6 | 119 passed, 0 failed |
| `tests/vault_gui_check.sh`, Ubuntu 24.04: Python 3.12, GTK 4.14.5, libadwaita 1.5.0 | 119 passed, 0 failed |

The backend hasn't changed since those Rust, dependency and round-trip results, because Open
needed no backend change; the binary hash is the same. The Python and GUI runs are on the
final frontend.

**The version floor.** libadwaita 1.5.0 is exactly the app's floor, and the whole run-through
passes on it. GTK 4.10 itself wasn't tested, but it isn't reachable with that floor anyway:
Ubuntu's libadwaita 1.5 package requires GTK ≥ 4.13.4, so 4.14 is close to the real minimum.
On Ubuntu the run logs GTK warnings that the file-chooser and open-file portals are too old.
No portal runs in the test environment, and GTK fell back and worked.

**Not run:** the AppImage wasn't rebuilt. `build-appimage.sh` copies the same two files as
before, the release binary and `app.py`, and its build command is unchanged.

**Bugs these tests and the Phase 7 review found, all fixed:**

- The Contacts/Vaults toggle didn't switch views. A toggle group deactivates the old button
  before activating the new one, and the handler was on the wrong button.
- On extract, names colliding on a case-insensitive disk would silently drop a file.
- A FIFO in place of `VAULT` or `key.age` could hang the window at startup.
- A warning toast containing a path with `&` would have failed to display.
- A vault with one file said "1 files".
- The first Open warning's heading was too long and triggered a GTK layout warning.

---

## Hashes

| | SHA-256 |
|---|---|
| Baseline binary, `main` @ `ecab899`, rustc 1.75.0 | `9bd8360a7eac449c92192591dc757df918b110b8f4973ced33ec5d8c029aafb1` |
| This branch's binary, rustc 1.75.0 | `ceec2ef9c4505c640ca70f8735347ed4e48d012e438f71a1c74790a4b36cadc2` |

Registry `.crate` files, each matching both `Cargo.lock` and the checksum crates.io
publishes (`tests/verify_deps.sh`):

| Crate | Version | SHA-256 |
|---|---|---|
| age | 0.11.3 | `a07d86e4272c093c88caf7864a2d09af52a5159180848ca4832a3cdbd7d014d5` |
| age-core | 0.11.0 | `e2bf6a89c984ca9d850913ece2da39e1d200563b0a94b002b253beee4c5acf99` |
| chacha20poly1305 | 0.10.1 | `10cd79432192d1c0f4e1a0fef9527696cc039165d729fb41b3f4f4f354c2dc35` |
| scrypt | 0.11.0 | `0516a385866c09368f0b5bcd1caff3366aace790fcd46e2bb032697bb172fd1f` |
| x25519-dalek | 2.0.1 | `c7e468321c81fb07fa7f4c636c3972b9100f0346e5b6a9f2bd0603a52f7ed277` |
| sha2 | 0.10.9 | `a7507d819769d01a365ab707794a4084392c824f54a7a6a7862f8c3d0892b283` |
| rand | 0.8.6 | `5ca0ecfa931c29007047d1bc58e623ab12e5590e8c7cc53200d5202b69266d8a` |
| zeroize | 1.8.2 | `b97154e67e32c85465826e8bcc1c59429aaaf107c1e4a9e53c8d8ccd5eff88d0` |

---

## Screenshots

In `docs/screenshots/vaults/`, all with a throwaway identity and test vaults. Each was
looked at before committing.

| File | Shows |
|---|---|
| `01a-contacts-main.png` | Contacts mode on `main`, the baseline. |
| `01b-contacts-branch.png` | Contacts mode on this branch: the same, apart from the toggle replacing the "Contacts" title. |
| `02-vaults-empty.png` | Vaults mode with an empty list and the "Add vault" button. |
| `03-vaults-two.png` | Two vaults, one per mode, with the password vault selected and locked. |
| `04-create-dialog.png` | The create dialog: exact protection labels, default location shown in full. |
| `05-unlocked-nested.png` | An unlocked vault with nested folders, a name containing `&` and `<`, and sizes. |
| `06-rollback-warning.png` | The rollback warning, with Open anyway and Cancel. |
| `07-tamper-error.png` | The error after extracting from a tampered vault; nothing was written. |
| `08-passphrase-menu.png` | The Remember passphrase submenu. |
| `09-key-changed-warning.png` | Added: the warning for a swapped `key.age`, shown before any secret is asked for. |
| `10-open-warning.png` | Added: the plaintext warning on first Open, with I understand and Cancel. The Open button is in the action bar behind it. |
| `11-open-changes-lost.png` | Added: Lock with an edited copy, naming the file. |

---

## How this was tested

The WSL distro (Debian trixie, kernel 5.10, no WSLg) had no Rust, GTK or Xvfb, `sudo`
requires a password, and the Docker daemon isn't running. No root was used and no system
package installed. Everything is user-level:

- Rust through `rustup --no-modify-path`: toolchains 1.75.0 (the declared MSRV, used for the
  hashes) and 1.85.0, in `~/.rustup` and `~/.cargo`. Shell profiles untouched.
- Debian and Ubuntu packages unpacked into throwaway rootfs folders,
  `~/.cache/vaultsend-gui` and `~/.cache/vaultsend-gui-noble`, and entered with `unshare` +
  `chroot`. Apt signatures were checked. Delete those folders to undo it.

Every test uses throwaway `HOME` and XDG dirs under `mktemp -d` in `/tmp` (ext4). The real
key and config were never touched.

**The GUI run-through drives the real window** with real dialogs and the real backend,
including real GTK file choosers, but through its widgets rather than a mouse. For Open it
launches through the real GTK and desktop-file path, but the "default app" is a stand-in
script registered in the throwaway dirs. What it can't show: a real drag from a file manager
(it calls the drop handler directly), Open with real apps, and how the app behaves on a real
desktop under a window manager, since Xvfb has none. Those are worth a manual check.

To re-run, from a shell with Rust on the `PATH` and GTK available:

```bash
cd backend && cargo test --locked && cargo clippy --locked --all-targets -- -D warnings && cd ..
```

```bash
bash tests/verify_deps.sh
```

```bash
bash tests/vault_roundtrip.sh
```

```bash
python3 tests/test_frontend_helpers.py
```

```bash
bash tests/vault_gui_check.sh docs/screenshots/vaults
```
