# VaultSend — Vaults feature: implementation plan for Claude Code

Status: plan only, nothing implemented yet. Branch: `feature/vaults` (local only).
Baseline: `main` @ `ecab899` (v0.1.2). Target version: **0.2.0**. Linux only.

Read this whole file before writing any code. Where this plan and the code
disagree, the code wins: stop and report the mismatch instead of improvising.

---

## 0. Ground rules (non-negotiable)

1. **Work only on branch `feature/vaults`** in `C:\Users\caele\claude\vaultsend`
   (`/mnt/c/Users/caele/claude/vaultsend` from WSL). **Never push** to GitHub —
   the repo is public and the owner pulls/merges the branch himself.
2. **Simple and auditable beats clever.** The README promises "one person can
   read the whole thing in an afternoon". Every addition is weighed against that.
3. **Be skeptical of refactoring.** Existing audited code paths (`cmd_*`,
   `harden_process`, `read_passphrase`, `load_identity`, `run_backend`,
   `spawn_backend`, `FileOperation`) stay byte-identical except where a step
   below explicitly says otherwise. Allowed exceptions: widening a helper's
   visibility (`fn` → `pub(crate) fn`), adding dispatch arms to `run()`, and the
   specific frontend edits in §4. Any other change to an existing line must be
   justified in `CHANGES-VAULTS.md` *before* it is made.
4. **No new crates.** Everything needed (`age`, `sha2`, `rand`, `zeroize`) is
   already in `backend/Cargo.lock`. Adding `sha2`/`rand` to `Cargo.toml` as
   direct deps must not add a single `[[package]]` entry to the lock — verify
   with `git diff main -- backend/Cargo.lock`. If a new crate seems necessary,
   stop and ask.
5. **Never touch the user's real key or config.** Every test, script and
   screenshot run uses throwaway `XDG_DATA_HOME` / `XDG_CONFIG_HOME` /
   `HOME` under `mktemp -d` **in `/tmp`** (ext4 — DrvFs under `/mnt/c` ignores
   `0600`, which would make permission tests lie).
6. **Plaintext rules** (owner's requirement):
   - The frontend never holds file plaintext. All vault crypto and parsing
     happens in the hardened backend.
   - Every plaintext read out of a vault is **fully decrypted and verified in
     RAM** (age authentication + manifest hash) **before a single byte is
     written to disk**.
   - Plaintext reaches disk only when the user explicitly extracts a file/folder
     to a location they choose. No temp mounts, no cache dirs, no "open in app".
7. Commit in small, reviewable steps. Every commit message ends with:
   ```
   Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>
   ```

---

## 1. Why this design (research summary)

The owner asked for secure *partial* modification if the auditability cost is
acceptable, otherwise a single encrypted archive ("option A": `vault.tar.age`).

age is one authenticated stream per file (STREAM construction: 64 KiB chunks,
each chunk's nonce encodes its counter and a last-chunk flag, so reordering and
truncation are detected). A single age file therefore cannot be modified in
part. Every well-known tool that supports partial updates gets there the same
way: **encrypt small units independently, then bind the units together.**

| Tool | Unit | How units are bound together | Detects file swap / rollback |
|---|---|---|---|
| gocryptfs | 4 KiB blocks per file, AES-GCM | file ID + block number in AAD | Swap: no (documented). Rollback: no |
| Cryptomator | 32 KiB chunks per file, AES-GCM | chunk number + header nonce in AAD; names AES-SIV with parent dir ID | Moves between dirs: yes. Swap/rollback: not addressed |
| CryFS | 32 KiB blocks, XChaCha20-Poly1305, random IDs | encrypted block tree + local version table | Yes, but only via **local state** on the same device |
| rclone crypt | 64 KiB chunks per file, secretbox | per-file random nonce, incremented per chunk | Not addressed |
| restic / borg / kopia | content-defined chunks in packs | content-addressed (SHA-256) tree → snapshot | Swap: yes (hash = name). Rollback of whole repo: no |
| VeraCrypt | 512 B sectors, XTS | none — XTS is unauthenticated | No integrity at all → rejected |

**Chosen design ("option B"): per-file age blobs + an age-encrypted manifest
that pins every blob by SHA-256, plus a generation counter.** It is the
restic idea at minimum size, using age for every encryption:

- age already gives each blob what gocryptfs/Cryptomator build by hand (chunk
  numbering in the nonce, truncation detection).
- The manifest stores `SHA-256(blob ciphertext)` for every file, so swapping,
  replacing with an old version, or deleting a blob is detected — stronger than
  gocryptfs/Cryptomator/rclone.
- A generation number in the manifest, remembered per-vault by the frontend,
  detects whole-vault rollback **on this device** (the CryFS idea, at ~15 lines).
- Changing one file re-encrypts one blob and the (small) manifest.

**Auditability cost vs option A:**

| | A: `vault.tar.age` | B: blobs + manifest (chosen) |
|---|---|---|
| New crates | `tar` (+ its deps) — a third-party archive parser | **none** |
| New own code (est.) | ~200 lines | ~400–500 lines incl. a ~40-line manifest parser and a path validator |
| Partial updates | no | yes |
| Metadata visible on disk | total size only | file count, each blob's approximate size, blob mtimes. **Names and folder structure stay hidden** |

**Fallback gate:** if `backend/src/vault.rs` exceeds **~550 lines excluding
`#[cfg(test)]`**, or any step needs a new crate, stop, write up why in
`CHANGES-VAULTS.md`, and ask the owner whether to fall back to option A.

---

## 2. On-disk format (v1)

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

Why a per-vault key (like Cryptomator's masterkey / restic's key files): scrypt
costs ~1 s per use, so passphrase-encrypting every blob would make a 50-file
vault take a minute to open. With a vault key, each operation pays **one**
unlock, and a password change only re-wraps `key.age` (password change itself
is out of scope for 0.2.0 — list it as future work).

`VAULT`'s `mode` line is only a hint for which prompt to show. The backend
must not trust it for security: a wrong mode simply fails to decrypt
`key.age`, and that must produce a clear error, never a crash.

age requires a passphrase (scrypt) stanza to be the *only* stanza, so a vault
is either key-unlocked or password-unlocked, never both. This is why the user
chooses one at creation.

### Manifest (plaintext inside `manifest.age`, UTF-8, `\n` line endings)

```
vaultsend-manifest 1
generation <u64>
F <blob-id:32 hex> <sha256-of-blob-file:64 hex> <plaintext-size> <escaped-path>
D <escaped-path>
```

- `F` = file, `D` = folder (needed so empty folders survive).
- `escaped-path`: vault-relative, `/`-separated; every byte outside
  `[A-Za-z0-9._~/-]` written as `%XX` (so spaces/newlines can't break lines).
- **Path validation** (`valid_vault_path`, one function, used by add, remove,
  extract and manifest parsing): non-empty; not absolute; no empty, `.` or
  `..` components; no NUL; components ≤ 255 bytes; total ≤ 4096 bytes.
- Parser rejects: unknown version, unknown record type, duplicate paths,
  malformed hex/size, a file path that is also a folder path, trailing junk.
- Hash is over the **ciphertext blob file**, so it can be checked before
  decrypting and pins the exact bytes.

### Write protocol (crash-safe, mirrors restic's packs → index → snapshot order)

1. Write each new blob to `<blob>.vaultsend-part` via `open_private_new`,
   hashing while writing (small hashing `Write` wrapper), fsync, rename.
2. Write the new manifest with `generation + 1` to
   `manifest.age.vaultsend-part`, fsync, rename → **this rename is the commit
   point.** fsync the vault directory after it.
3. Only then delete blobs the new manifest no longer references.
4. On every mutating operation, also garbage-collect orphan blobs left by an
   earlier crash: delete only files under `blobs/` matching exactly
   `^[0-9a-f]{2}/[0-9a-f]{32}\.age(\.vaultsend-part)?$` that the manifest does
   not reference. Never delete anything else.

A crash at any point leaves either the old vault or the new vault, never a mix.

---

## 3. Backend (`backend/src/vault.rs`, new file)

Keep `main.rs` changes to: `mod vault;`, dispatch arms in `run()`, the usage
string, and `pub(crate)` on the helpers reused below. Reuse, don't copy:
`read_passphrase`, `load_identity`, `open_private_new`, `commit_staged`,
`staging_path`, `encrypt_to`, `SCRYPT_LOG_N`, `SCRYPT_MAX_LOG_N`.

### Commands

```
vault-create  --dir P --mode self                     # no secret needed (uses pubkey)
vault-create  --dir P --mode password --pass-fd N     # new vault password, >= 10 chars
vault-list    --dir P --pass-fd N
vault-add     --dir P --pass-fd N --src PATH [--dest VAULTDIR] [--replace]
vault-remove  --dir P --pass-fd N --entry VAULTPATH            # file or folder (recursive)
vault-extract --dir P --pass-fd N --entry VAULTPATH --out PATH # file or folder
vault-check   --dir P --pass-fd N                              # verify every blob in RAM
```

- `--pass-fd` carries the identity passphrase for `self` vaults and the vault
  password for `password` vaults. Same fd rules as today (fd ≥ 3, never argv).
- `vault-create` refuses if `P` exists and is non-empty.
- `vault-list` prints `generation <n>` then one line per entry
  (`F <size> <escaped-path>` / `D <escaped-path>`). Names and sizes only —
  never content. Output goes to the frontend via the stdout pipe.
- `vault-add` with a folder: walk recursively; **skip symlinks, sockets,
  devices, FIFOs** (report skipped count on stderr as a warning line, exit 0).
  Without `--replace`, an existing entry is an error naming the path. Source
  files are read, never moved or deleted.
- `vault-extract` (the RAM-only rule, per file):
  1. Read the entire blob into memory once (no re-open → no TOCTOU).
  2. SHA-256 it; compare to the manifest. Mismatch → error, nothing written.
  3. Decrypt from the in-memory buffer into `Zeroizing<Vec<u8>>` to the end
     (age authenticates every chunk and the final-chunk flag).
  4. Only now write to `staging_path(out)` via `open_private_new`, fsync, rename.
  For a folder: verify-and-decrypt **every** file in RAM first; if any fails,
  write nothing; then create the tree under `--out` (refuse if `--out` exists).
  Memory need ≈ 2× the largest file (folder: the sum). Document this limit.
  `--out` must not be inside the vault directory.
- `vault-check`: steps 1–3 for every file, discard plaintext, report OK/first
  failure. Also report blobs present on disk but not in the manifest.

### Unit tests (`#[cfg(test)] mod tests` in `vault.rs` — the repo's first `cargo test`)

Use temp dirs; never the real data dir. At minimum:

- create → add → list → extract round-trip, **both modes**; bytes identical.
- wrong passphrase / wrong mode → clean error.
- manifest: parse(serialize(x)) == x; rejects each malformed case in §2.
- `valid_vault_path`: rejects `""`, `/a`, `a//b`, `./a`, `a/..`, `../x`,
  NUL, over-long; accepts unicode and spaces (escaped).
- tamper: flip one byte in a blob → extract fails **and `--out` does not
  exist** (proves verify-before-write); truncate a blob → same; swap two blobs'
  filenames → same; delete a blob → clear error; replace a blob with the same
  path's *previous* blob → same.
- add with `--replace` keeps every other blob byte-identical (hash the files).
- remove keeps every other blob byte-identical; removed blob is gone after commit.
- crash simulation: leave a stray `blobs/xx/<id>.age` and a
  `manifest.age.vaultsend-part`; next mutating op GCs the blob, ignores/clears
  the part file, vault still lists the old contents.
- GC never deletes a non-matching file placed in `blobs/`.
- generation increments by exactly 1 per mutating op.
- folder extract with one corrupted file writes nothing at all.

Gate: `cargo test --locked`, `cargo clippy --locked -- -D warnings`,
`cargo build --release --locked` all clean before any frontend work.

---

## 4. Frontend (`frontend/app.py`)

Match the existing style (section comments, small helpers, `Adw.AlertDialog`).
Keep the GTK ≥ 4.10 / libadwaita ≥ 1.5 floor: **do not use `Adw.ToggleGroup`**
(needs 1.7) — use two `Gtk.ToggleButton`s with `set_group()` inside a box with
the `linked` CSS class.

### 4.1 Sidebar (`_build_sidebar`, line ~453) — matches the owner's sketches

```
[ Contacts | Vaults ]      <- linked toggle, replaces the "Contacts" title
[       +          ]       <- "Add contact" / "Add vault" (label follows toggle)
  list                      <- Gtk.Stack: contact list | vault list
```

- Contacts page: the existing list, untouched (`_refresh_contacts` unchanged).
- Vault rows: name; subtitle = "Your key" or "Password" + shortened path.
  Right-click/long-press → "Remove from list" (reuse the `_show_delete_menu`
  pattern; this **only** forgets the entry, never deletes vault files — say so
  in the confirm dialog). A vault whose folder is missing shows "Not found".
- The main pane's sidebar toggle tooltip changes from "Toggle contacts" to
  "Toggle sidebar".

### 4.2 Main pane (`_build_content`, line ~569)

Wrap the existing column in a `Gtk.Stack` page `"send"` (unchanged content) and
add page `"vault"`. Contacts toggle → `"send"`; selecting a vault → `"vault"`.

Vault page (sketch 2):
- Title = vault name, heading "Files".
- Locked state: lock icon + "Unlock" button.
- Unlocked: list from `vault-list`; folders as `Adw.ExpanderRow` (nested),
  files as `Adw.ActionRow` with size. Trailing folder slash as in the sketch.
- Action bar: **Add files…**, **Add folder…**, **Extract…**, **Delete**, **Lock**.
  Drag-and-drop onto the page = add (same `Gdk.FileList` drop target pattern).
- Delete confirms with `DESTRUCTIVE` appearance.
- Name clash on add → dialog: Replace / Cancel.
- After every op, re-list. "Lock" just drops the listing (and the cached
  passphrase for that vault, if any) — the listing is metadata, not plaintext.
- Long ops (add/extract/check) run through `spawn_backend` so the window stays
  responsive. Read `FileOperation` first; if it can't show an indeterminate
  (pulsing) bar for ops whose output size isn't known, add the **smallest**
  possible change (e.g. `total=None` → pulse) and record it.

### 4.3 Create-vault dialog

- Name entry (validated: non-empty, no `/`, not `.`/`..`).
- Two radio options (`Gtk.CheckButton` group), exact labels:
  - **Encrypt with my key (simplest, secure)** — default
  - **Use a password (shareable)** → reuse `ask_passphrase(confirm=True)`,
    10-character minimum, same as the identity passphrase.
- Location: **Default** (`$XDG_DATA_HOME/vaultsend/vaults/<name>.vsvault`,
  shown in full) or **Select a location…** (`Gtk.FileDialog.select_folder`;
  vault created as `<chosen>/<name>.vsvault`).
- Also on the "+" button: **Add existing vault…** (select a `.vsvault`
  folder; checks for a `VAULT` file) — needed to re-attach after restoring a
  backup or receiving a shared password vault.

### 4.4 Vault registry

`$XDG_CONFIG_HOME/vaultsend/vaults.json` — list of
`{"name", "path", "mode", "last_generation"}`. No secrets. Load/save mirror
`load_contacts`/`save_contacts` (tolerant of a missing/garbled file).

Rollback check: if `vault-list` returns `generation` < `last_generation`, show a
warning dialog ("This vault is older than the last version this device saw. It
may have been restored from a backup — or rolled back by someone else.") with
**Open anyway** / **Cancel**. Otherwise store the new generation.

### 4.5 Passphrase cache (hamburger menu)

- Menu: submenu **Remember passphrase** with radio items **Off** (default) and
  **Until VaultSend closes** (the passphrase is **never** written to disk),
  plus a **Lock now** item.
- Implementation: a stateful `Gio.SimpleAction` with a string state; the
  choice (not the passphrase) is saved to `$XDG_CONFIG_HOME/vaultsend/settings.json`.
- Cache: dict keyed `"identity"` or `("vault", path)`. Cleared on: Lock now,
  setting change, a "wrong passphrase" error for that key, app quit.
- Applies to the identity passphrase everywhere (text/file decrypt too) and to
  vault passwords.
- When the user picks anything other than Off, show a one-time explanation:
  the cached passphrase lives in the frontend's memory, which (unlike the
  backend) is not locked out of swap, and Python cannot reliably wipe strings.
  Record the same caveat in the README security model.

### 4.6 Python tests

`tests/test_frontend_helpers.py` (unittest, run with system Python + gi):
registry load/save/garbled-file, settings load/save, cache expiry and clearing
(inject a fake clock), vault-name validation, manifest-path unescaping used for
display. Keep these helpers at module level so they're testable without a window.

---

## 5. Verification (all must pass; record outputs in `CHANGES-VAULTS.md`)

### 5.1 Crypto library hashes — `tests/verify_deps.sh`
1. `cargo fetch --locked`.
2. For `age`, `age-core`, `chacha20poly1305`, `scrypt`, `x25519-dalek`,
   `sha2`, `rand`, `zeroize`: `sha256sum` of
   `~/.cargo/registry/cache/*/<name>-<version>.crate` must equal the
   `checksum` in `backend/Cargo.lock` **and** the checksum crates.io reports
   (`https://crates.io/api/v1/crates/<name>/<version>` → `version.checksum`).
   Baseline: `age 0.11.3` = `a07d86e4272c093c88caf7864a2d09af52a5159180848ca4832a3cdbd7d014d5`.
3. `git diff main -- backend/Cargo.lock` adds **no** `[[package]]`.
4. Record the `sha256sum` of `backend/target/release/vaultsend-backend`
   (built with `--locked`) at baseline and at the end.

### 5.2 Round trips — `tests/vault_roundtrip.sh`
Fresh temp `HOME`/XDG dirs; passphrases via `--pass-fd` from a here-string fd,
never argv. Build a test tree: nested folders, an empty folder, an empty file,
a 1-byte file, a 3 MiB random binary, a file exactly 65536 bytes (age chunk
boundary), names with spaces / unicode / `%`.
1. `keygen`; regression: existing `encrypt`/`decrypt` file round trip still matches.
2. For each mode: `vault-create` → `vault-add` the tree → `vault-list` →
   `vault-extract` the root → `sha256sum` manifest of extracted tree ==
   original (`find -type f -print0 | sort -z | xargs -0 sha256sum`, and the
   folder list incl. the empty folder).
3. `vault-remove` one file; re-extract; others identical.
4. `vault-add --replace` one file; extract it; matches new content.
5. Tamper suite (flip byte, truncate, swap, delete blob, old manifest) →
   non-zero exit **and no output path created**.
6. `vault-check` clean on a good vault, failing on a tampered one.
7. Optional proof of verify-before-write: `strace -f -e trace=openat,rename`
   on an extract shows the output path opened only after the blob read completes.

### 5.3 Screenshots — `docs/screenshots/vaults/`
Run the app under WSLg or `Xvfb :99` with temp XDG dirs and a seeded test
identity + test vaults (never real ones); capture with ImageMagick `import
-window root` or `gnome-screenshot`. Required:
1. Contacts mode **on `main`** (baseline) and **on the branch** — must look the same apart from the toggle.
2. Vaults mode, empty list.  3. Vaults mode with 2 vaults (one per mode).
4. Create-vault dialog.  5. Unlocked vault with nested folders.
6. Rollback warning.  7. Tamper error on extract.  8. Passphrase-cache menu.
Look at every screenshot before committing it; describe each in one line.

---

## 6. Documentation

- **`CHANGES-VAULTS.md`** (new): every file touched with `git diff --stat`;
  every existing line changed and why; new CLI commands; format spec (copy §2);
  threat model additions; test/hash/screenshot results; known limitations:
  - whole-vault rollback is detected only on a device that saw the newer version;
  - on-disk metadata: file count, approximate per-file sizes, blob mtimes;
  - extraction needs RAM ≈ 2× file size (folder: total);
  - frontend passphrase cache is not swap-protected;
  - sharing a password vault means copying its folder (no single-file export yet).
- **README**: Features (Vaults), Backend CLI (new commands), Where things are
  stored (`vaults.json`, `settings.json`, default vault dir), Security model
  (vault key + manifest pinning), Where to look when auditing (add `vault.rs`
  and its key functions), line counts updated.
- Bump `version` in `backend/Cargo.toml` and `APP_VERSION` to `0.2.0`.

---

## 7. Execution order and gates

| Phase | Work | Gate before moving on |
|---|---|---|
| 0 | Baseline: build `--locked`, record hashes, run existing CLI round trip, baseline screenshot | all recorded |
| 1 | `vault.rs`: path validation, manifest, create/list/add/remove/extract/check + unit tests | §3 gate green; line budget check |
| 2 | `tests/verify_deps.sh`, `tests/vault_roundtrip.sh` | §5.1–5.2 green |
| 3 | Sidebar toggle, vault registry, create/add-existing dialogs | app launches; contacts mode unchanged |
| 4 | Vault page: list/add/extract/delete/lock, rollback warning | manual run-through with test vault |
| 5 | Passphrase cache setting | Python tests green |
| 6 | Screenshots, README, `CHANGES-VAULTS.md`, version bump | everything in §5 re-run green |
| 7 | Self-review of `git diff main` as an auditor would; final report to owner | — |

The final report lists: what was built, test results, hashes, screenshot list,
any deviations from this plan and why, and the exact command to pull the branch.
