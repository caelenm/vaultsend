# VaultSend — Vaults: change record

Living record for `feature/vaults` (spec: `VAULTS_PLAN.md`). Local branch only;
nothing has been pushed.

---

## Fallback gate: `vault.rs` went over budget — owner kept option B

**Decision (owner, 2026-11-03): keep option B, budget raised to ~800 lines, and fix
the `self`-vault key-swap gap below rather than documenting it.** The analysis that
led to it is kept here as the record.

The plan (§1) says: if `backend/src/vault.rs` exceeds ~550 lines excluding
`#[cfg(test)]`, stop, write up why here, and ask whether to fall back to option A.

**Measured: 791 lines** (632 code, 104 comment-only, 55 blank), plus 702 lines of
tests. That is about 44% over the budget, and the plan's own estimate was 400–500.
No new crate was needed, so the other half of the gate is not in play.

Everything else about Phase 1 is green (results further down).

### Why it came out larger than estimated

A first draft was 943 lines. One simplification pass removed 152 lines of real
logic and duplication, not formatting: a plaintext byte-counting reader, a
special-case error branch, a refusal to add a vault to itself, a second "already
exists" check, and a verbose option struct. The `size` field also became
display-only, which removed a real hazard (a source file changing during `add`
could otherwise make its blob fail a size check forever).

Where the remaining 791 lines go:

| Lines | What | In the plan? |
|---|---|---|
| 46 | Header comment, imports, constants | Implied |
| 61 | Path validator, ancestor/subtree helpers, escape and unescape | Yes |
| 91 | Manifest types, serializer, strict parser, number and hex helpers | Yes (plan guessed ~40 for the parser alone) |
| 53 | Staged write, directory fsync, parent path, private mkdir, hashing `Write` wrapper | Yes |
| 21 | `flock` on the vault | **No — added**, see below |
| 34 | Unlock (`key.age`, both modes, clear errors) | Yes |
| 69 | `Vault` struct, open, and vault creation in both modes | Yes |
| 70 | age encrypt/decrypt wrappers, manifest load and commit, RAM-only blob read | Yes |
| 46 | Garbage collection and the exact-name orphan matcher | Yes |
| 111 | `add`: walk, name-clash rules, blob write, `--dest` | Yes |
| 89 | `remove`, `extract` for a file and a folder, tree writing, `--out` refusal | Yes |
| 40 | `list` and `check` | Yes |
| 60 | Strict option parser, stdout helper, command dispatch | **Partly** — the plan put dispatch in `main.rs` |

The estimate was simply low. The plan's security rules are all things that need a
line of their own: every fallible call gets a user-readable error, every write is
stage/fsync/rename, and every path is validated. None of that is padding, and
`age` does the part that would otherwise be the most code.

### What going further would take

Reaching ~550 honestly is not possible without dropping required behaviour or
packing code onto fewer lines, which would defeat the purpose of the budget.
Available reductions, none of which I'd recommend:

- **Remove the `flock` (−21).** Reintroduces silent data loss: two concurrent
  writers could have one's garbage collection delete the other's uncommitted blobs.
- **Parse options with `main.rs`'s scanning helpers (about −20 net).** Mostly moves
  lines between files, and a vault folder named `--replace` would then read as the flag.
- **Strip comments (up to −104).** The comments are what an auditor reads first.

### The choice

| | Keep option B at ~790 lines | Fall back to option A (`vault.tar.age`) |
|---|---|---|
| Backend size | `main.rs` 515 + `vault.rs` 791 = about 1,300 lines | Plan estimates ~200 new lines |
| New crates | **None** | `tar` and its dependencies: a third-party archive parser |
| Partial updates | Yes, one file at a time | No, every change rewrites the archive |
| On-disk metadata | File count, approximate sizes, mtimes | Total size only |
| Status | Written, 26 tests passing | Not started |

**Recommendation: keep option B and raise the budget to ~800.** The README's promise
is that one person can read the whole thing in an afternoon, and about 1,300 lines
of short functions with no new crates still meets it. Option A swaps our own lines
for a third-party parser of hostile input, and I'd expect its ~200-line estimate to
grow for the same reasons this one did, since tar paths need the same validation and
output the same staging. That second part is my judgment, not a measurement.

---

## Security finding: key swap in `self` vaults (fixed at the owner's request)

Age has no sender authentication, and a user's public key is public by design. So
anyone who can write to a **`self`-mode** vault's folder could replace `key.age` with
one wrapping a vault key they know, plus a matching manifest.

- The user's passphrase would still unlock it, and the generation check could be
  satisfied by choosing a high number.
- The listing would look wrong, since the attacker can't read the old contents.
- But any file the user then added would be encrypted to a key the attacker holds.

`password` vaults weren't exposed in the same way: forging `key.age` needs the password.

**The fix pins `key.age` by SHA-256, in two layers.** The plan didn't cover this; the
owner asked for it.

- **Frontend:** `vaults.json` gains a `key_sha256` per vault, recorded when the vault
  is created or added. Before asking for a secret, it compares the current `key.age`
  and shows a warning if it changed. Applies to both modes, since `key.age` never
  legitimately changes in 0.2.0.
- **Backend:** every command that opens a vault accepts `--key-sha256 HEX` and refuses
  if the bytes of `key.age` it just read don't match, before reading the secret. A
  frontend-only check could be beaten by swapping the file after the check.

Limits: like the generation check this is per-device, and it trusts what it first saw.
A vault swapped before this device first added it isn't detected, and neither is one
reached with `vaults.json` deleted.

---

## Phase 0: baseline

Baseline `main` @ `ecab899`, backend source identical on this branch at the time.

**Environment.** The WSL distro (Debian trixie, kernel 5.10, no WSLg) had no Rust,
GTK or Xvfb, `sudo` requires a password, and the Docker daemon isn't running. No
root was used and no system package installed. User-level only:

- Rust through `rustup --no-modify-path`: toolchains 1.75.0 (the declared MSRV) and
  1.85.0, in `~/.rustup` and `~/.cargo`. Shell profiles untouched.
- GUI tools: Debian packages unpacked into a throwaway rootfs at
  `~/.cache/vaultsend-gui` and run through `unshare` + `chroot` (GTK 4.18.6,
  libadwaita 1.7.6, Xvfb, ImageMagick). Remove that folder to undo it.

**Build.** `cargo build --release --locked` with rustc 1.75.0:

```
9bd8360a7eac449c92192591dc757df918b110b8f4973ced33ec5d8c029aafb1  backend/target/release/vaultsend-backend
```

**Crate hashes.** `sha256sum` of each registry `.crate` equals its `Cargo.lock`
checksum. The crates.io API comparison belongs to `tests/verify_deps.sh` (Phase 2).

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

**Existing CLI round trip** (throwaway `HOME`/XDG dirs in `/tmp`, ext4): `keygen`
gave a `0600` identity; a 3 MiB random file encrypted and decrypted byte-identical;
armored text round-tripped; a wrong passphrase exited 1 and left no output file.

**Screenshot.** `docs/screenshots/vaults/01a-contacts-main.png`: contacts mode on
`main`, with a throwaway identity and two test contacts.

---

## Phase 1: `backend/src/vault.rs`

### Gate results

| Check | Result |
|---|---|
| `cargo test --locked` (1.75.0 and 1.85.0) | 26 passed, 0 failed, on both |
| `cargo clippy --locked --all-targets -- -D warnings` (1.85.0) | Clean |
| `cargo build --release --locked` (1.75.0) | OK; `8d6ca2ed2c116ed91a3f50b08fcac8a49fc9fbf6f7ca6795323f0dc5dcc3efa1` |
| `git diff main -- backend/Cargo.lock` | Adds no `[[package]]`, only `rand` and `sha2` in our dependency list |
| Line budget | **791 vs ~550: over, see the top of this file** |

**Clippy and the MSRV.** On untouched `main`, `clippy -D warnings` under 1.75.0
already fails on `File::open(&p)` in `identity_is_valid` (a lint later narrowed;
1.85.0 passes). That line is audited code and has not been changed. So the clippy
gate runs on 1.85.0, while build and tests run on both.

### Every existing line changed, and why

`backend/src/main.rs`, inside what §3 allows:

- New `mod vault;`.
- New line in the header's command list naming the vault commands (treated as part
  of "the usage string").
- New dispatch arm in `run()`.
- **One existing line changed:** the usage string in `run()`'s unknown-command error.

No `pub(crate)` was needed, so none was added: a child module can already see its
ancestors' private items, which keeps the audited functions byte-identical.

`backend/Cargo.toml`, new lines only:

- `sha2` and `rand` as direct dependencies, as §0.4 allows.
- `[profile.dev.package."*"] opt-level = 2`. Not in the plan. The unit tests run real
  scrypt at 2^18, which is very slow unoptimized. Test and debug builds only.

### Decisions the plan left open

- **`--entry /` means the vault root.** §5.2 extracts "the root" without saying how.
  `/` can never be a valid vault path, so it can't collide. `vault-remove` refuses it.
- **`vault-add` accepts repeated `--src`.** Adding several files is one unlock and one
  generation. Without this, each dropped file would pay a full scrypt.
- **`--replace` merges folders** but never turns a file into a folder or the reverse.
- **Every parent folder must have a `D` record.** Stricter than §2's list, and the same
  check rejects a file used as a folder.
- **Only canonical escapes are accepted,** so `%2F` can't smuggle a separator and one
  path has one spelling.
- **Names must be valid UTF-8.** A non-UTF-8 name fails the whole add, naming the file,
  rather than being silently left out.
- **`check` reports orphans** on stdout and as a `warning:` line on stderr, because
  `spawn_backend` discards stdout.

### Additions beyond the plan

- **`flock` on the `VAULT` file:** exclusive for changes, shared for reads, non-blocking,
  released by the kernel however the process dies. The plan's garbage collection deletes
  unreferenced blobs, which would include another process's uncommitted ones.
- **Folder extraction builds under `<out>.vaultsend-part`, then renames,** so `--out` is
  only ever absent or complete, and a cancel has one unambiguous thing to clean up.
- **The manifest is parsed back before every commit,** so a bug can't write one that
  locks the user out of the vault.

### Unit tests beyond §3's minimum

Manifest encrypted to the wrong key; rollback through an old `manifest.age`; symlinks and
FIFOs skipped; symlinked `blobs/<aa>` not walked; `--out` through a symlink into the vault;
clash rules; stale staging; lock behaviour; file and folder permissions.
