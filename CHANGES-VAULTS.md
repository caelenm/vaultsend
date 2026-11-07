# VaultSend for Android — Vaults: change record

Record for `feature/android_vaults`, version 0.2.0: the desktop `feature/vaults` branch
ported to Android, starting from a copy of `android`. The desktop branch's
`CHANGES-VAULTS.md` and `VAULTS_PLAN.md` describe the feature itself (format, threat model,
write protocol). This file covers how each desktop change was mapped here, and where the port
differs and why.

- [Summary](#summary)
- [Decisions made by the owner](#decisions-made-by-the-owner)
- [Every desktop change, and where it went](#every-desktop-change-and-where-it-went)
- [Deviations from the desktop](#deviations-from-the-desktop)
- [Test results](#test-results)
- [Not tested](#not-tested)

---

## Summary

Vaults are the desktop's, byte for byte. A vault made on the desktop opens here and the
other way round, because `vault.rs` and `tar.rs` are the desktop files. The format, the
manifest parser, path validation, the seal, what garbage collection may delete, and every
error message are unchanged. What changed is how the code reaches files:

- **`Store`.** Every file access goes through a `Store`. `PathStore` is the desktop code,
  used by the unit tests and the host-side CLI. `SafStore` (in `ffi.rs`) reaches a folder
  the user picked through the Storage Access Framework, by calling back into a Kotlin
  `VaultTree`.
- **Where vaults live.** In a folder the user picks: visible in the file manager, and the
  app holds access to that folder only, with no storage permission.

The UI is the desktop's vault page in Compose, with the desktop's wording:

- the Contacts / Vaults toggle in the drawer, and the vault list;
- the page itself: Select all, Select multiple, Verify all, Add files…, Add folder…, Open,
  Extract…, Share…, Delete and Lock;
- the dialogs, Remember passphrase and Lock now.

---

## Decisions made by the owner

| Question | Decision |
|---|---|
| Where vaults are stored | A folder the user selects, seen in the file manager, with access limited to that folder (SAF tree grant), not all-files access. |
| Open, which the desktop allows only from a folder in RAM | A copy in the app's private cache, handed to the viewer read-only through a `FileProvider`. It is deleted on Lock, Lock now and close, and leftovers at the next launch. |
| `lock_in_ram`, which the desktop never undoes (one short-lived process per operation) | Ported, with `munlock` when each buffer is dropped, since this library lives in the app's long-lived process. |
| Remember passphrase | A `self` vault uses the existing native session key. A password vault's key, not its password, is remembered in native memory. The Remember menu sets the lifetime of both, and Lock now forgets both. |

---

## Every desktop change, and where it went

### Rust (`backend/` on desktop, `rust/` here)

| Desktop | Android |
|---|---|
| `Cargo.toml`: version 0.2.0, `sha2`, `rand` | The same, plus `libc` (already locked) for `mlock`, `munlock` and `flock`. As on desktop, the lock gains no `[[package]]`. |
| `[profile.dev.package."*"] opt-level = 2` | Already there (`opt-level = 3`). |
| `main.rs`: `lock_in_ram`, `secret_buffer`, `SECRET_CAPACITY` | `backend.rs`. `lock_in_ram` returns a guard that unlocks when dropped; pages are reference-counted, because `mlock` isn't and two buffers can share a page. It's used in `passphrase_from_bytes` (the desktop's `read_passphrase`), `load_identity` and `keygen`, and also for the session key, which the desktop doesn't have. |
| `main.rs`: `mod tar; mod vault;`, the `vault-*` dispatch, usage text | `lib.rs`: `mod tar; pub mod vault;`. Instead of argv dispatch, there is one JNI entry point per command in `ffi.rs`. |
| `tar.rs` | Copied unchanged, tests included. |
| `vault.rs` | Copied. The plumbing changes are listed under [Deviations](#deviations-from-the-desktop). |
| `vault.rs`'s CLI (`parse_opts`, `run`, `cmd_create`) | `vault_cli.rs`, built only for tests (feature `cli`) and for `examples/vault_cli.rs`, which isn't shipped. |
| `encrypt_to` (already on `main`) | Added to `backend.rs`; `encrypt` uses it. |

### Frontend (`frontend/app.py` on desktop, `app/` here)

| Desktop | Android |
|---|---|
| `APP_VERSION = "0.2.0"` | `versionName` 0.2.0, `versionCode` 4, About. |
| Sidebar toggle Contacts / Vaults; Add follows it | `SidebarDrawer` (`VaultScreen.kt`): a segmented toggle; the + button adds a contact or a vault. |
| Vault list: kind and short path, or "Not found"; long-press/right-click menu with Remove from list | The same subtitles; a ⋮ menu with Remove from list. |
| "Remove from list?" with a selectable path and a copy button | The same, showing the folder's location. It also releases the folder grant if no other vault uses it. |
| Add vault: name (Create off until valid, red on `/`), protection, location, Add existing vault… | `AddVaultDialog`: the same rules. Location is always "choose a folder", since there's no default folder the app could write to without a grant. |
| Password vault: "Choose a vault password"; self vault: the passphrase | The same. A self vault uses the unlocked session, or unlocks it. |
| "That isn't a vault" / "That vault is already in your list." | The same. |
| Vault page: Locked + Unlock; "Files · N files, size" / "N selected" / "all selected"; Select all ⇄ Select none; Select multiple; Verify all; nested rows with an indent per level, capped | `VaultPage`. The selection rules are `VaultSelection` in `VaultHelpers.kt`: ticking a folder ticks its contents, unticking inside unticks the folders above, closing a folder clears ticks hidden inside it, and only one of the two select buttons is lit at a time. |
| Rollback warning ("This vault looks older", Open anyway) | The same, from `last_generation` in `vaults.json`. |
| Vault errors as dialogs; key mismatch explained | `MessageDialog`, with the same texts. |
| Add files… / Add folder… (folders only), into the selected folder; "Replace existing items?" | `OpenMultipleDocuments` and `OpenDocumentTree` (which can't return a file), with the same destination rule and Replace dialog. |
| Drop files onto a vault | Share files from another app while a vault is open: one file offers "Add it to … instead", several (`SEND_MULTIPLE`) ask "Add to …?". |
| Drop a vault on the main page: Decrypt, then its password; joins the list once it opens | Pick or "open with" a vault's `VAULT` file. "Decrypt this vault?" then asks for its folder, and it joins the list only once it opens. |
| Extract…: one file to a file; several to one new folder keeping paths | One file to "Save as". A folder or several go into a new folder in a folder you choose. |
| Share…: contacts, *Add new contact* over the dialog, then Save | The same. Add contact stacks on Share and returns to it. |
| Delete: three wordings; everything → `--all` | The same texts; everything calls `vaultRemove(all = true)`. |
| Open: first-use warning (I understand), asks above 10 files | The same, worded for Android. |
| Lock, Lock now, Remember passphrase (Off or Until VaultSend closes; the timed choices are dropped), first-use explanation | ⋮ menu: **Remember passphrase…** and **Lock now**; each vault page has Lock. The explanation is reworded, since nothing is held in Python. |
| Percentages on vault operations | A progress bar under the list, fed by the core through `ProgressSink`. It pulses before the first report and after 100%, as on desktop. |
| `vaults.json`, `settings.json`, `contacts.json` written `0600` | `savePrivately`. The app's files are private already; this matches the mode and replaces a stale temp file. |
| Toast markup bug with `&`; contact names with `&` | Not applicable: Compose doesn't parse markup. |
| Add contact's Add waits for a name and a key | The same. |
| Passphrase prompt focused on open; "Repeat it" / "Those don't match." | The same. |
| GTK recent files off; window size; CSS | Not applicable. |

### Tests

| Desktop | Android |
|---|---|
| `vault.rs`/`tar.rs` unit tests (48) | All 48 ported: the same tests, adapted only where they built a `Vault` or wrote a tree directly. Plus 7 for the Android parts: SAF commit and crash recovery, in-process locking, output inside the vault, the session, remembered keys, page counting. |
| `tests/vault_roundtrip.sh` | `rust/tests/vault_roundtrip.sh`, unchanged apart from the binary. Runs in CI. |
| `tests/vault_attack.py` | `rust/tests/vault_attack.py`, unchanged; run by hand (it needs the `age` tool). |
| `tests/verify_deps.sh` | `rust/tests/verify_deps.sh`: compares against `origin/android` and hashes the host build of the library. |
| `tests/test_frontend_helpers.py` | `app/src/test/.../VaultHelpersTest.kt` (JUnit): every case that applies, plus the selection rules. Runs in CI (`testDebugUnitTest`). |
| `tests/vault_gui_driver.py` / screenshots | Not ported: see [Not tested](#not-tested). |

---

## Deviations from the desktop

| What | Why |
|---|---|
| **Replacing the manifest, on a SAF folder:** delete `manifest.age`, then rename `manifest.age.vaultsend-part` in. If the app is killed in between, the next open finds the staged manifest, checks that it decrypts with the vault's key and parses, and puts it in place (`recover_manifest`). | SAF's rename can't replace an existing name (some providers rename around it instead). Only the manifest is ever replaced. Blobs, `key.age` and `VAULT` are always new names. The desktop never leaves the manifest missing, so this is safe to add there too: a possible follow-up. |
| **Garbage collection (0.3.6):** a change deletes only the blobs it dropped (in the old manifest and not the new one) and, if it fails, only the blobs it wrote. Blobs no manifest names stay until the user removes them: Verify all reports them and offers to, and `vault-check --clean` does it after every file has verified. `vault_roundtrip.sh` section 6 and `vault_attack.py`'s kill test now clean explicitly. | The desktop deletes every unlisted blob after each change. With a vault folder synced between devices, that deletes another device's new blobs whose manifest hasn't arrived yet, and the deletion syncs back. A failed SAF commit could also delete the blobs its staged manifest names, which `recover_manifest` then put in place (fixed in the same release). |
| A SAF vault is locked within the process, not with `flock` | `flock` isn't dependable on a SAF descriptor, and only this app writes there. A vault on a real path (tests, CLI) still uses `flock`. |
| `--pass-fd` becomes a byte array, or null for the session or a remembered key | There's no pipe in-process. `PASSWORD_NEEDED` tells the app to ask. |
| Warnings (skipped items, orphans) are returned, not printed | They end the result as `warning: …` lines, and the app shows them. `vault_cli` still prints them to stderr. |
| A blob's size is counted while it's encrypted, not taken from `stat` | A SAF source can be a pipe from a cloud provider, whose size isn't known in advance. For a regular file the two are the same. |
| A SAF source isn't checked to be a regular file | A FIFO can't be made in shared storage, and a cloud provider may hand a file over as a pipe. Virtual documents (such as a Google Doc) are skipped and counted, as the desktop skips what isn't a regular file. |
| Extract, Open, Share and Verify stream each file instead of decrypting it whole in RAM (0.3.2): the blob is read once, hashed in the same pass that decrypts it into private staging in the app's storage, and copied out only after all of it, and for a folder or a share all of them, has verified | A phone can't hold a large file twice over (ciphertext and plaintext): a 2 GB file needed about 4 GB, and couldn't be extracted at all on a 32-bit ABI. Memory is now one chunk. The order is the desktop's: nothing reaches the output until everything verified. The staging is deleted however the operation ends, and swept when the app starts. `vault_attack.py`'s low-memory check now expects success where it expected the process to die |
| Open's copy is on disk (the app's private cache), not in tmpfs | Android gives apps no RAM folder. The copy is readable only by this app, and by the viewer through a one-time, read-only grant. |
| No "Changes will be lost" prompt | The viewer can't write the copy, so there are no edits to detect. |
| The background auto-lock (2 minutes, already on `android`) locks keys and vault pages but keeps opened copies | Leaving the app is how you look at an opened copy. Copies go on Lock now, a vault's Lock, and close, as on desktop. |
| Remember defaults to "Until VaultSend closes", not Off | That's what this app already did (unlock once). Off now really does lock after each use. |
| Extracting a folder asks for a folder to put it in, named after the selection | SAF can't "Save as" a folder. If that name already exists, the core refuses, as it does on desktop. |
| Location in Add vault is always chosen | There's no default folder the app may write to without a grant. |

### Process hardening (unchanged from `android`)

`vault_attack.py`'s *process hardening* section fails 4 checks here:

- `/proc/pid/mem` can be read;
- `/proc/pid/environ` can be read;
- `/proc/pid/maps` can be read;
- a crash leaves a core file.

These test the desktop backend's `PR_SET_DUMPABLE` and `RLIMIT_CORE`, which this port deliberately doesn't use: the core runs inside the app's process, and the Android sandbox is the boundary (README, *Security model*). The CLI they run against inherits that.

---

## Test results

Run in this branch's environment (Linux, no Android SDK or emulator: Google's Maven and SDK
downloads aren't reachable from it):

| Check | Result |
|---|---|
| `cargo test`, Rust 1.97 and 1.75.0 (`--locked`) | 62 passed, 0 failed, on both (48 ported, 7 new, 7 existing) |
| `cargo clippy --lib --features cli -- -D warnings` | Clean. With `--all-targets`, newer clippy lints flag test code that was already on `android` or copied as is |
| `cargo build --locked`, 1.75.0 | OK; `Cargo.lock` gains no `[[package]]` |
| `rust/tests/vault_roundtrip.sh` | **131 passed, 0 failed**, as on desktop, with `strace` |
| `rust/tests/vault_attack.py`, with `age` 1.1.1 | **211 passed, 4 failed**: the four process-hardening checks above; everything about vaults passes |
| `VaultHelpersTest` (JVM) | 45 passed |
| Kotlin type-check: everything but the Compose UI, against Robolectric's `android-all` (API 34) | Compiles |
| Kotlin type-check: the Compose UI and view model, against Compose Multiplatform 1.7 (the same `androidx.compose` APIs as this app's Compose BOM) and `android-all`, with stubs for the AndroidX activity, lifecycle and `FileProvider` calls | Compiles. It found one error (a function clashing with a property's setter), now fixed. `MainActivity.kt` and `Theme.kt` were left out; their changes are small |

---

## Not tested

- **The app itself.** `./gradlew assembleDebug` needs the Android SDK and AGP from Google's
  Maven, which weren't reachable here; CI builds it. The UI was type-checked as above, not run.
- **SAF on real providers.** `SafStore` follows the rules the unit tests' `NoReplaceStore`
  models, and `VaultTree` is written against `DocumentsContract`. Neither has run against
  `ExternalStorageProvider`, an SD card, or a cloud provider.
- **A vault moved between desktop and phone.** `a_store_that_cannot_rename_over_a_file_still_commits_every_change`
  shows a vault written with SAF's rules opens with the desktop's code. A real copy through
  a file manager hasn't been done.
- **Open with real viewers**, and the background auto-lock while one is showing a copy.
- The desktop's GUI run-through (`vault_gui_driver.py`) and screenshots have no counterpart
  yet. A Compose UI test on an emulator would be the equivalent.

---

## Follow-up: password shares, receiving shares, vault page

Changes asked for after manual testing of 0.2.0.

| Asked for | Where |
|---|---|
| Share a vault's contents with a password; the receiver decrypts it on the main page | `Vault::share_password` (vault.rs); Share… → **Set password instead**; `shared.rs` for opening it |
| Open file… / shared in: save an archive as it is, or unpacked as a folder | `ArchiveChoiceDialog`; `shared::decrypt_file_to`, `shared::extract_archive` |
| Add existing vault… with a shared `.tar.age`: unlock, choose protection and place, import into a proper vault | `ExistingVaultDialog`, the Add vault form as **Import as a vault**; `shared::import_archive` |
| Drop "(shareable)" | Add vault's second choice is **Use a password** |
| Invert selection while Select multiple is on | `VaultSelection.invert()` |
| Contacts \| Vaults divider slides to widen the chosen side | `SlidingToggle` |
| The drawing's vault page | Four equal buttons above the list; a collapsible panel of stacked actions below it |
| Validate the blob file manager | See below |

**The archive reader.** `tar.rs` used to only write. Reading a share someone sends
back is new, and the reader treats the archive as hostile. The rules are in the
README's *Security model*. Each is tested with hand-built bad archives, a seeded
mutation fuzz of the reader, and an end-to-end run through decrypt, the private
tree and the output folder.

**Cancel.** `Progress` carries a cancel hook. It is polled once per MiB and once per
entry, and through JNI it calls `ProgressSink.isCancelled()`. `ProgressSink` is now a
class, so that method exists however the sink was made. A cancelled run behaves like
a failed one and cleans up the same way:
- An unpack leaves no folder and no staging behind.
- An import or an add leaves the vault's generation unchanged.

**The blob file manager.** I reviewed `vault.rs` and its Kotlin mirror (`parseListing`, `VaultSelection`, Add's destination), and the existing tests already covered generations, GC, tampering and crash recovery. One gap was fixed:
- **The gap.** A `Sources` that left out a folder its entries go in (`a/b` with no `a`) wrote every blob before the manifest's round-trip check refused it, as an "internal error".
- **The fix.** `add_to` now refuses this before writing anything, with a test (`sources_must_bring_the_folders_they_go_in`).
- **Who could hit it.** The app's own walks always list folders, but the archive import is a new `Sources`, so this now matters.

**Not tested here.** The app on a device, and SAF on real providers for unpacking and import. `vault_attack.py` was not rerun, since it needs the `age` tool.
