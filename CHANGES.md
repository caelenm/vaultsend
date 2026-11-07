# What changed in this build

## Unreleased: a smaller surface

A review pass for security, then auditability, then simplicity. Nothing a person
does in the app changes, except where noted.

- **Four fewer JNI entry points (37 → 33).** `decryptBytes` and `decryptFd`, which
  took the identity passphrase on every call, were never used: every decrypt
  already went through the unlocked session. They're gone, with Rust's
  passphrase-taking `decrypt_file_to`. `decryptFdSession` did exactly what
  `sharedDecrypt` does with no password, so the main page's Decrypt now uses that
  one path for every file (and `backend::decrypt_file_to_session` is gone).
  `vaultSweep` only served timed Remember choices, removed in 0.2.0.
- **Remember passphrase is a yes/no in the core.** `vault::set_remember` takes a
  bool instead of seconds, so the wall-clock expiry, `sweep()` and the app's
  15-second polling loop are gone. Off and Until VaultSend closes behave as before.
- **settings.json, vaults.json and contacts.json** are written through a temp file
  created 0600 and atomically moved into place. The old fallback that, if the
  rename failed, wrote the file in place (and briefly readable by default
  permissions) is gone: a save now either replaces the file whole or fails.
- **Files shared into a running app in a batch** (several at once, to add to the
  open vault) were ignored unless the app was starting: the screen watched only
  for single files and text. The three kinds are now one pending value it watches.
- **Add contact** checks a key with the core's parser only. The separate
  look-alike check (`looksLikePubkey`) that greyed out Add is gone; a bad key says
  why under the field, as before, and keeps what was typed.
- Smaller: one unlock prompt instead of three copies; one Save File or Share flow
  for a file and one for a vault (each was written twice, for contacts and for a
  password); every "write to a destination" in `Backend` removes the destination
  itself on failure; `VaultTree.key()` takes no unused argument; `ProgressSink` is
  final, so its R8 rule for subclasses is gone; About no longer calls the
  in-process core "a separate backend".

## Unreleased: notes and Rename… in vaults

- **Add note…** on a vault's action panel opens a note editor in place of the page:
  a title at the top (saved as *title*.md, the extension shown after it), a text
  box below like the main page's, and Save in the top-right corner. The note goes
  where Add files… would put a file. Its text goes from memory straight into the
  vault; no plaintext copy is written anywhere. Close or Back asks before
  discarding anything unsaved.
- **Edit note** opens the one chosen .md or .txt file (up to 1 MB, and only if it is
  valid UTF-8) in the same editor. Saving writes the new text, under a changed title
  if it was changed, and drops the old file in the same commit. Locking the vault, by
  Lock, Lock now or the background lock, closes the editor and discards the draft.
- **Rename…** renames the one chosen file or folder, within its folder. Only the
  vault's encrypted file list changes: nothing is decrypted or re-encrypted, so a
  folder of any size is renamed in one step, along with everything in it.
- Core: `Vault::rename`, `Vault::write_text` and `Vault::read_text` in `vault.rs`
  (Android only: the desktop has no counterpart yet), with JNI calls `vaultRename`,
  `vaultWriteText` and `vaultReadText`. `read_text` holds the plaintext in a buffer
  of exactly the manifest's size, wiped when dropped, which it never grows.

## 0.3.4

- **Saved files showing 0 bytes:** a file unlocked from a password share could be
  listed as 0 bytes by Photos and file managers, though it opened fine. Save as
  creates the file empty, and the slow password step meant Android's media index
  recorded that size before the picture was written. After every save VaultSend
  now asks the index to re-read the file.

## 0.3.3

- **Open file… → Encrypt → Set password instead**, as on a vault's Share…: a
  "Set password" dialog, then the same Save File or Share. The file is age
  encrypted with scrypt at 2^18 (the same as a vault's password share), with the
  same 10-character floor, so VaultSend's Decrypt or `age -d` opens it.

## 0.3.2: audit fixes (file handling and encryption)

- **Background lock:** the 2 minutes are now measured with the clock that keeps
  running while the phone sleeps, and checked again when the app comes back. Before,
  the timer counted only time awake, didn't run while Android froze the app, and was
  cancelled on return, so the key could stay unlocked for hours. The timer lives in
  the view model, so a rotation while away can't leave one behind.
- **Decrypted text:** every lock (Lock now, the background lock, closing) clears
  decrypted text from the message box; it stayed on screen before. Below Android 13
  the window is made secure while decrypted text or an unlocked vault is showing, so
  the Recents thumbnail can't show it. Text fields ask the keyboard not to learn
  from what's in them (`IME_FLAG_NO_PERSONALIZED_LEARNING`).
- **Opened copies:** swept at every process start, and Lock now and closing delete
  every copy in the folder. Before, if Android killed the app and it was reopened
  from Recents, copies from the earlier process were never deleted.
- **Plaintext staging:** what a killed decrypt, extract, Share or unpack left in the
  app's storage is removed when the app starts (`sweepStaging`), not only at the
  next decrypt. Cleanup is counted per folder, so staging in one never holds off
  cleanup in another.
- **Vault files stream:** Extract, Open, Share and Verify no longer load whole
  files into RAM. Each blob is read once, hashed in the same pass that decrypts it
  into private staging, and copied out only after all of it (all of them, for a
  folder or a share) has verified. Memory is one chunk whatever the file's size,
  where a 2 GB file needed about 4 GB before. A tampered blob is still refused
  before anything is written, and an enormous one is refused without reading it.
- **Weak identities:** an `identity.age` wrapped below scrypt 2^18 (earlier
  calibrating builds, or an import) is re-wrapped at 2^18 when unlocked or
  imported, after checking the new file opens to the same key. Identity writes are
  serialized. Import reads at most 64 KiB.
- **Incoming files:** a URI another app hands over is refused if it's to
  VaultSend's own FileProvider or inside a folder VaultSend holds access to, since
  VaultSend opens it with its own permissions, not the sender's.
- **Folder access, stated correctly:** making a vault keeps access to the folder
  picked for it and everything in it, not only the vault's folder; the README and
  the Add vault hint now say so.
- **JNI boundary:** every entry point catches panics, and every passphrase,
  password and plaintext buffer in the native layer is wiped on drop, early
  returns included.
- **New-key passphrase floor** (10 characters) is enforced in the core too, and the
  app counts characters the way the core does (code points).
- **Build:** the shipped library is built with `--locked`, as is CI's `cargo test`;
  CI's actions are pinned to commits. Rust crate version 0.3.2, matching
  `versionName`.

## 0.3.1

- **Set password:** Share… → Set password instead now opens a dialog titled just
  "Set password", with the password fields and no explanatory paragraph.
- **Vault actions panel:** on the app's own background instead of a tinted one;
  the actions are plain rows with a line between each instead of outlined
  buttons, and the handle is a chevron (^ closed, V open) instead of a solid
  triangle.
- **Contacts | Vaults toggle:** no ripple when tapped; the sliding change of
  width still animates.

## Build

- **Gradle wrapper committed:** `gradle/wrapper/` (jar and properties) is now in
  the repo, pinning Gradle 8.13 by version and SHA-256, so `./gradlew` works on a
  fresh clone. It was previously excluded by `.gitignore`. The committed `gradlew`
  script, which had a broken `printf` line, is regenerated.
- **Supported toolchain:** AGP 8.2.2 was only tested up to API 34 and warned with
  `compileSdk = 35`. Now AGP 8.9.0 with Kotlin (and the Compose compiler plugin)
  2.1.10.
- **CI** builds with `./gradlew` instead of a separately pinned Gradle.

## Audit fixes (v0.1.2)

- **Portable identity:** new keys use a fixed scrypt work factor of 2^18 instead
  of one calibrated to the phone. Imports and unlocks accept up to 2^20, and a
  higher work factor is reported as such instead of as "wrong passphrase".
- **File decrypt staging:** each decrypt stages to its own temp file, so two
  decrypts running at once can no longer swap plaintext. Leftovers from a killed
  run are cleaned up on the next decrypt.
- **Failed file operations** delete the destination the user picked, instead of
  leaving a truncated `.age` file or an empty file behind.
- **Session:** auto-locks after 2 minutes in the background. Decrypted text is
  kept out of the recent-apps thumbnail (Android 13+).
- **Passphrase:** at least 10 characters for a new key.
- **Contacts:** keys are validated by the core's parser on add and on import
  (invalid ones are skipped and counted), and duplicates are refused.
- **Text:** encrypted verbatim (leading/trailing whitespace is no longer trimmed).
- **Intents:** only `content://` URIs are accepted from other apps, and the VIEW
  filters are no longer `BROWSABLE`.
- Rust crate version 0.1.2, matching `versionName`. Dependencies are optimized in
  test builds, so `cargo test` stays fast at the real work factor.

Five updates were made on top of the `android` branch. The Rust core was
compiled and unit-tested here; the Kotlin/Gradle half builds in Android Studio
(no SDK/NDK was available in the authoring environment — same caveat as the
original README).

## 1. Verify the password before decrypting; never store the password

Decryption now uses an **unlock-once-per-session** model. You enter your
passphrase once; it is **verified** against your stored key before any decryption
happens, and a wrong passphrase is shown inline instead of failing later. The
passphrase itself is never stored — what is cached for the session is the
*decrypted key*, and it is held **in the Rust library** (a `SecretString` that
zeroes on drop), not in the JVM, because Kotlin strings can't be reliably wiped.
It is cleared on **Lock** (new ⋮ menu item) and when the app closes.

See the expanded "Security model → Unlock-once-per-session" section in `README.md`
for the honest tradeoff (this is weaker than per-operation decryption) and how to
switch to locking on background.

- Rust: `unlock` / `lock` / `is_unlocked` / `decrypt_session` /
  `decrypt_file_to_session` in `rust/src/backend.rs`, with matching JNI entry
  points in `rust/src/ffi.rs`.
- Kotlin: `Backend.unlock/lock/isUnlocked/decryptTextSession/decryptFileSession`;
  `PassphraseDialog` gained inline async verification.

## 2. Welcome + explainer onboarding, with Generate / Import

First launch now shows a **Welcome** screen, then a short **How VaultSend works**
explainer with two buttons: **Generate new keypair** or **Import previous
identity.age**. Import verifies the file against its passphrase before writing it
into place (and refuses to overwrite an existing identity).

- `app/.../ui/Screens.kt` (new), `ui/AppViewModel.kt` (phase state),
  `ui/App.kt` (flow); Rust `import_identity` + `importIdentity` JNI.

## 3a. Backup screen after generating a key

After a new key is generated, a one-time screen offers to save a copy of
`identity.age`, notes that it's cloud-safe because it's passphrase-protected, and
shows the reminder: *"You need both your identity.age file and password to decrypt
any files secured by your keypair!"* Importing skips this (assumed already backed
up). A **Back up private key** item was also added to the ⋮ menu for everyone.

## 3b. Open files from outside the app (share sheet / "open with")

VaultSend now accepts files shared from any app's share sheet (`ACTION_SEND`) and
via "open with" (`ACTION_VIEW`, including `.age` files), routing them to the same
encrypt/decrypt chooser as the in-app *Open file…* button. Shared plain text drops
into the message box. In-app, files are still opened only via the button.

- `AndroidManifest.xml` (intent filters + `singleTask`), `MainActivity.kt`
  (intent handling + lock-on-close), `ui/AppViewModel.kt` (pending-share state).

## 4. About section matches the Linux app

The About dialog now reads exactly:

> File and text encryption using the age format.
> All cryptography is performed by a small separate backend.
> Source code can be found here:
> https://github.com/caelenm/vaultsend/tree/android

(the URL is tappable). See `ui/Dialogs.kt`.

## Files touched

- `rust/src/backend.rs`, `rust/src/ffi.rs`
- `app/src/main/java/org/vaultsend/VaultSendNative.kt`
- `app/src/main/java/org/vaultsend/Backend.kt`
- `app/src/main/java/org/vaultsend/MainActivity.kt`
- `app/src/main/java/org/vaultsend/ui/App.kt`
- `app/src/main/java/org/vaultsend/ui/Dialogs.kt`
- `app/src/main/java/org/vaultsend/ui/AppViewModel.kt`
- `app/src/main/java/org/vaultsend/ui/Screens.kt` (new)
- `app/src/main/AndroidManifest.xml`
- `README.md`
