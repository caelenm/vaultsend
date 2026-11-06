<h1>
  <img src="https://github.com/user-attachments/assets/d590919f-bb4f-46fd-a9d8-12f54f0b6700" alt="VaultSend icon" width="48" height="48" style="vertical-align:middle; margin-right:8px;">
  VaultSend for Android
</h1>


| Main View | Add Contact | Select Contacts | Decrypting View |
|---|---|---|---|
| <img src="https://github.com/user-attachments/assets/412faa21-2d96-46c7-a844-33d232d1885b" width="500"> | <img src="https://github.com/user-attachments/assets/47f8f56e-48c4-409c-b223-893fa2fbe869" width="500"> | <img src="https://github.com/user-attachments/assets/73e27861-424e-4df2-bfb7-5145d59b8036" width="500"> | <img src="https://github.com/user-attachments/assets/be1712bc-bc1a-4d9c-81df-f110372eed64" width="500"> |


[![Get it on Obtainium](https://github.com/user-attachments/assets/9e480740-e1db-4520-b52b-8d45bd1de410)](https://apps.obtainium.imranr.dev/redirect.html?r=obtainium://app/%7B%22id%22%3A%22org.vaultsend%22%2C%22url%22%3A%22https%3A%2F%2Fgithub.com%2Fcaelenm%2Fvaultsend%22%2C%22author%22%3A%22caelenm%22%2C%22name%22%3A%22VaultSend%22%2C%22versionExtractionRegEx%22%3A%22v%3F%28%5B%5C%5Cd.%5D%2B%29%22%2C%22apkFilterRegExp%22%3A%22.%2A%5C%5C.apk%22%7D)


[Or Download from the releases page](https://github.com/caelenm/vaultsend/releases)

An Android port of [VaultSend](https://github.com/caelenm/vaultsend) — a small,
auditable tool for encrypting messages and files to people you choose, using the
[age](https://github.com/str4d/rage) encryption format. This port keeps the same
cryptography and the same on-disk format as the desktop app; only the front end
and the way the two halves talk to each other are new.

- **Backend:** the original Rust core, refactored into a library (`rust/`).
- **Frontend:** Kotlin + Jetpack Compose (Material 3), replacing the desktop's
  Python/GTK UI (`app/`).
- **Output:** one universal `.apk` that installs on any current Android device.

The goal was a faithful port. Where a desktop idiom
doesn't fit a phone (drag-and-drop, a docked sidebar) the closest touch
equivalent is used (an "Open file…" button, a contacts drawer).

## App verifier Details

org.vaultsend
01:DA:07:1F:28:FD:27:38:02:D8:2D:23:BC:1C:AD:64:55:00:11:33:3D:1C:A0:91:85:58:33:E2:59:93:BF:0D

## Project layout

```
vaultsend-android/
├── rust/                     # Rust core (the only code that touches the key)
│   ├── src/backend.rs        #   crypto + identity logic (refactored desktop main.rs)
│   ├── src/vault.rs          #   vaults: the desktop's vault.rs, behind a Store
│   ├── src/tar.rs            #   the archive Share writes, and a strict reader for one sent back
│   ├── src/shared.rs         #   opening a share: password check, save, unpack, import as a vault
│   ├── src/ffi.rs            #   JNI entry points (the whole FFI surface)
│   ├── src/vault_cli.rs      #   desktop vault-* commands, for host tests only
│   ├── examples/vault_cli.rs #   ...as a binary the desktop test scripts drive
│   ├── tests/                #   the desktop's vault_roundtrip.sh, vault_attack.py, verify_deps.sh
│   └── src/lib.rs
├── app/                      # Android app
│   └── src/main/
│       ├── java/org/vaultsend/        # Kotlin (UI + native bindings)
│       ├── res/                       # icon, theme, strings, backup rules
│       └── AndroidManifest.xml        # no permissions; no network
│   └── src/test/                      # JVM unit tests (VaultHelpersTest)
├── build-rust.sh             # cross-compiles the core for all ABIs -> jniLibs
└── settings.gradle.kts, build.gradle.kts, app/build.gradle.kts
```

## Building

The simplest path is **Android Studio** (it provides the SDK and a one-click NDK
install). The Gradle wrapper is checked in and pins Gradle 8.13 by version and
SHA-256, so `./gradlew` works on a fresh clone with no system Gradle. You also need a Rust toolchain to compile the core.

### One-time setup

1. **Android Studio** with the Android SDK (compileSdk 35).
2. **Android NDK** — in Android Studio: *SDK Manager → SDK Tools → NDK (Side by
   side)*. Set `ANDROID_NDK_HOME` (or `ANDROID_NDK_ROOT`) to its path.
3. **Rust** — install from <https://rustup.rs>, then add the Android targets:
   ```sh
   rustup target add aarch64-linux-android armv7-linux-androideabi \
                     i686-linux-android x86_64-linux-android
   ```
4. **cargo-ndk** (drives the cross-compile):
   ```sh
   cargo install cargo-ndk
   ```

### Build the APK

Opening the project in Android Studio and pressing Run is enough — the Gradle
build invokes `build-rust.sh` automatically (see the `buildRust` task in
`app/build.gradle.kts`), which compiles `libvaultsend.so` for all four ABIs into
`app/src/main/jniLibs/` before packaging.

From the command line:

```sh
# Debug build:
./gradlew assembleDebug
# Release (minified, shrunk) universal APK:
./gradlew assembleRelease
```

The APK lands in `app/build/outputs/apk/`. A release build is unsigned; sign it
with your own key (`apksigner`, or Android Studio's *Build → Generate Signed
Bundle / APK*) before distributing.

### Releasing

Releases are signed with the key whose certificate is listed under *App verifier
Details*; an APK signed with any other key won't install over an existing copy.
Each release needs a higher `versionCode` than the last one published (including
betas), and a tag `vX.Y.Z` matching `versionName`, which Obtainium reads. The
steps are listed below; `apksigner` is in the SDK's `build-tools/<version>/`.

```sh
git checkout android && git pull origin android
(cd rust && cargo test)
./gradlew clean testDebugUnitTest assembleRelease
apksigner sign --ks /path/to/vaultsend-release.jks \
  --out vaultsend-X.Y.Z.apk app/build/outputs/apk/release/app-release-unsigned.apk
apksigner verify --print-certs vaultsend-X.Y.Z.apk   # SHA-256 must match above
git tag -a vX.Y.Z -m "VaultSend Android X.Y.Z" && git push origin vX.Y.Z
```

Then publish a GitHub release for the tag with the `.apk` attached.

You can also build the native libraries by themselves at any time:

```sh
./build-rust.sh
```

### Device independence

`app/build.gradle.kts` packages the core for `arm64-v8a`, `armeabi-v7a`, `x86`,
and `x86_64` into a single APK, and `minSdk` is 26, so one `.apk` installs and
runs on essentially any phone, tablet, or emulator in use today. (If you'd rather
ship smaller per-ABI APKs later, enable ABI splits — but the single universal APK
is the device-independent default requested here.)

## What it does

- **First run** shows a short welcome and explainer, then lets you either generate
  a new keypair or **import an existing `identity.age`** (e.g. a backup, or one
  made on the desktop app). The private key is stored **passphrase-encrypted** in
  app-private storage (`identity.age`); the public key is cached in the clear
  (`pubkey`) so encrypting needs no passphrase.
- After generating a new key, a one-time **backup screen** offers to save a copy of
  `identity.age` to a location you choose. It's safe to keep in the cloud because
  it is passphrase-encrypted — but remember you need *both* the file and the
  passphrase to decrypt anything. A **Back up private key** item in the ⋮ menu lets
  you do this again at any time.
- **Encrypt** text or a file to yourself plus any contacts you pick; text comes
  out ASCII-armored so it pastes into any chat or email.
- **Decrypt** text or a file. The first decrypt of a session asks for your
  passphrase to **unlock**; after that you stay unlocked until you close the app,
  tap **Lock now** in the ⋮ menu, or leave the app in the background for 2 minutes
  (see the security note below). Locking also clears decrypted text from the message
  box. With **Remember passphrase** set to Off, it asks every time. File decryption stages
  the output to a private temp file and only writes it to your chosen destination
  after the whole stream authenticates, so a tampered or truncated file never
  leaves partial plaintext behind.
- **Files from other apps**: share a file to VaultSend from any app's share sheet,
  or use "open with" on a file (e.g. a `.age` file in a file manager). It opens the
  same encrypt/decrypt chooser as the in-app *Open file…* button. Shared plain text
  drops straight into the message box. (Inside the app, files are opened only via
  the *Open file…* button.) VaultSend opens what it's handed with its own access, so
  it refuses a file inside a folder it has access to (a vault's, or the one you made
  a vault in) when another app hands it over: use *Open file…* for those.
- **Contacts** are stored as `contacts.json` in the same `[{name, pubkey}]` shape
  as desktop, so the file is interchangeable between the two. Contacts never reach
  the crypto core.
- **Vaults.** Keep a whole folder encrypted and change it one file at a time, as in
  the desktop app, in the same format, so a vault moves between the two. Open the
  drawer, switch it to **Vaults** (the chosen side of the toggle widens), tap **+**,
  name it, choose how to protect it (your key, or a password), then choose the folder it goes in. It stays
  there, where your file manager shows it. VaultSend keeps access to the folder you
  choose, and everything in it, so a folder just for vaults is best. Tap a vault, then **Unlock**, to see its files. Above the list,
  **Select all** ticks every row, **Select multiple** turns the rows into tick boxes,
  **Invert selection** (with Select multiple on) flips every tick, and **Verify all**
  checks every file for tampering. Below it, a panel you can fold away holds **Add
  files…** and **Add folder…** (into the selected folder, if one is), **Open**,
  **Extract…**, **Share…** and **Delete** (which act on what's selected, and wait
  until something is), and **Lock**. **Share…** encrypts what's selected as an
  ordinary `.age` file, for the contacts you tick or, with **Set password instead**,
  for anyone with a password you choose, then saves it or hands it to the share
  sheet; a folder or several items arrive as a `.tar` inside it.
  **Remove from list** only forgets a vault; its files stay where they are. To add a
  vault you already have (a backup, or a copy from your computer), use **Add existing
  vault… → A vault folder…**, or pick its `VAULT` file with **Open file…** and choose
  its folder.
- **Receiving a share.** Open a shared `.age` file with **Open file…**, or share it to
  VaultSend from another app, and choose **Decrypt**: VaultSend asks for its password,
  or uses your key if it was made for you. An archive (`Name.tar.age`) can be saved as
  one `.tar` or unpacked into a new folder. Or make it a vault of your own: **Add
  existing vault… → A shared vault file…** unlocks it, asks how the new vault is
  protected and where it goes, and fills it with what the file holds. Unpacking and
  importing can be cancelled.
- **Remember passphrase** (⋮ menu): whether your key stays unlocked, and whether a
  password vault's key is remembered. There are two choices: **Off** (ask every
  time) or **Until VaultSend closes** (the default, which is how this app has always
  worked). Either way the 2-minute background lock still applies.
  **Lock now** forgets all of it, locks open vaults, clears decrypted text and
  deletes opened copies.

## Security model — what changed in the port

This is the one place the port is not a like-for-like translation, so it's worth
stating plainly.

On the desktop, the UI and the crypto backend are **separate OS processes**: the
frontend spawns the backend per operation and pipes the passphrase to it over a
file descriptor. The private key only ever lives in the short-lived backend
process, which additionally hardens itself (disables core dumps and ptrace,
`mlockall`s its memory).

On Android, the Rust core is compiled to a native library and loaded **into the
app's own process** over JNI. That is the conventional, supported way to ship Rust
on Android, and it's what makes a single self-contained APK possible — but it does
mean the frontend/backend boundary is now an in-process one rather than an
OS-enforced one. The boundary that protects your key is instead the one Android
provides: every app runs under its **own UID in its own sandbox**, with SELinux on
top, so other installed apps cannot read this process's memory or its
app-private files. `identity.age` and `pubkey` live in internal storage, which is
private to this app; auto-backup is turned off so the encrypted key is never swept
into a cloud backup.

The desktop's process-hardening calls are deliberately **not** reproduced here:
`mlockall` in a long-lived JVM would try to pin the entire managed heap, and
ptrace/core-dump restrictions are already governed by the Android sandbox and
SELinux. What is preserved: the key is never written unencrypted; the passphrase
is passed as a byte array that both Kotlin and Rust zero after use (the residual
copy held by the text field is an inherent limitation of the on-screen keyboard,
the same class of caveat as a desktop keylogger); secret buffers in Rust are
zeroized on drop; and the atomic-write and staged-decrypt guarantees are intact.

### Unlock-once-per-session

Decryption uses an **unlock-once** model: you enter your passphrase once, and the
app then decrypts without re-asking until you lock it, close the app, or leave it
in the background for 2 minutes. The
passphrase itself is still **never stored** — what is cached is the *decrypted
secret key* it unlocked.

That cache lives in the **Rust library, not the JVM**, on purpose. A Kotlin
`String`/`ByteArray` cannot be reliably wiped: the garbage collector may copy it
around the managed heap and leave the original in freed memory until it is
reclaimed. The native cache is a `SecretString` that zeroes its buffer on drop;
`lock()` drops it, the ⋮ **Lock now** action calls it, and the Activity calls it when
the app is finishing or has been in the background for 2 minutes (Android does not
reliably call `onDestroy()` when an app is swiped away or left running). The 2 minutes
are measured on the clock that keeps running while the phone sleeps, and checked
again when the app comes back, so a sleeping phone or a frozen process can't stretch
them. The key is never written to disk and never crosses back into
the JVM; for each decrypt it is briefly copied into zeroizing storage, used, and
dropped.

This is, honestly, a **weaker posture than decrypting per-operation** (where the
secret exists only for the duration of one call). Keeping an unlocked key resident
widens the window in which it is in memory. That is the cost of the unlock-once
convenience; it is made as safe as an in-process design allows — zeroizing,
mutex-guarded, native-only — and the OS sandbox above is the same boundary that
protects `identity.age` itself. If you prefer the stronger per-operation posture,
set **Remember passphrase** to Off, or shorten `BACKGROUND_LOCK_MS` in `Session.kt`.
Every lock, the background one included, also clears decrypted text from the message
box. The recent-apps thumbnail is disabled (Android 13+) so decrypted text isn't shown
there; on older versions the window is made secure (no thumbnail, no screenshots)
while decrypted text or an unlocked vault's list is on screen. Text fields ask the
keyboard not to learn from what's typed or shown in them.

### Vaults

A vault is the desktop app's: each file is its own age file, a manifest pins each
one by SHA-256, and the vault's key is sealed with a secret only your private key
can produce, or with a password. `rust/src/vault.rs` is the desktop's file, with
its file access behind a `Store`. See the desktop branch's `CHANGES-VAULTS.md` for
the format and threat model, and this branch's `CHANGES-VAULTS.md` for what differs
here. In short:

- **Where it lives.** In a folder you choose, through the Storage Access Framework.
  The app keeps access to the folder you chose for it (the one the vault is made in,
  and everything in it) and nothing else. Anything that can read the
  folder sees what the desktop says it would: how many files, roughly how big, when
  they changed. It doesn't see names or contents.
- **Nothing is written until it has verified.** As on desktop, a file is decrypted
  and verified in full before any of it is written, and only to a place you chose.
  Unlike the desktop, which does that in RAM, a phone can't hold a large file twice
  over, so here each file is read once, its hash checked in the same pass that
  decrypts it into private staging in the app's own storage, and copied out only
  once all of it (for a folder or a share, all of them) has verified. Memory use is
  one chunk whatever the size. The staging is deleted however the operation ends,
  and when the app next starts if it was killed.
- **Replacing the manifest.** SAF can't rename over a file, so a change deletes the
  old manifest and then renames the new one in. If the app is killed in between,
  the next open puts the new one in place, after checking that it's this vault's.
- **Remembered keys.** A password vault's own key, not its password, is held in the
  native library, wiped on drop and locked in RAM (see below), and never in the JVM.
  A vault using your key needs nothing remembered: it opens with your unlocked key.
- **Locked buffers.** The desktop's per-buffer `mlock` of secrets is kept: the
  passphrase as read, your key's text, the seal, a vault's key, and here also the
  unlocked session key. Since this process outlives one operation, each buffer is
  unlocked again when it's dropped.
- **Open takes a file outside what VaultSend can protect.** The copy goes in the
  app's private storage. That's on disk, which Android encrypts, because Android has
  no RAM folder an app can use. The app that shows it gets read-only access to that
  one file. It can still keep its own copies (recent files, previews), and VaultSend
  can't see or remove those; the first Open says so and asks you to acknowledge it.
  Copies are deleted when you lock the vault, use Lock now, or close the app, and at
  the next launch if the app was killed (including when Android restarts it from
  Recents). They are not deleted by the 2-minute
  background lock, since you're probably looking at one in another app.

- **A shared archive is read as hostile.** Age has authenticated it, but only as
  coming from whoever knew the password. `tar.rs`'s reader canonicalizes every name
  and refuses one that could leave the folder (`..`, absolute paths, drive prefixes,
  backslashes, NUL). It takes only files and folders, skipping links, devices and the
  rest without creating them. It caps the entry count (100,000), each entry (8 GB) and
  the total (32 GB), and checks every declared size against the archive's real
  length. Everything streams. Unpacking decrypts the whole file to private staging
  first, so age has authenticated all of it. It then builds the whole tree in the
  app's private storage, copies it into the folder you chose under a temporary name,
  and renames it last. Nothing reaches your folder from an archive that fails
  anywhere. A password share uses scrypt at 2^18, and one asking for more work is
  refused.

New keys need a passphrase of at least 10 characters, and the identity is
encrypted at the standard scrypt work factor of 2^18 (the same as the desktop app,
the web build and the `age` CLI), so an `identity.age` from any of them imports
here. Files at a work factor above 2^20 are refused with an explicit message:
scrypt would need more than 1 GiB of memory. An identity wrapped with less than
2^18 (from an earlier build that calibrated to the phone, or imported from
elsewhere) is wrapped again at 2^18 the first time it's unlocked or imported, which
makes its passphrase as costly to guess as a new one's. The new file is checked to
open with the same passphrase and hold the same key before it replaces the old one.

## Build verification status

**Audit fixes (0.3.2).** `cargo test --locked` passes 86 tests on current stable,
eight of them new: reading an identity's work factor from its header; a weak
identity re-wrapped on import; one already on the device re-wrapped on unlock (and
a stronger one left alone); the import size cap; the new-key passphrase floor,
counted in characters; the start-up staging sweep, which leaves live staging alone;
files streamed through staging that is always removed, with an appended-to or
enormous blob refused (the enormous one without being read); and every blob read
exactly once. `cargo clippy --lib
--features cli -D warnings` is clean, and `tests/verify_deps.sh` passes.
`vault_roundtrip.sh` passes 131 of 131 (its strace check included).
`vault_attack.py`, with `age`, passes 212 and fails the same 4 process-hardening
checks as before (see `CHANGES-VAULTS.md`). Its 1.5 GiB file now extracts
identically under a 1 GiB memory limit, where the process used to be killed. The
app was built here with the Android SDK and NDK 27: `assembleDebug` (all four ABIs,
through `build-rust.sh --locked`), `assembleRelease` (R8), and `testDebugUnitTest`
(VaultHelpersTest 52, SessionTest 4). Each `.so` exports exactly the 33 functions
`VaultSendNative` declares. The app wasn't run on a device or emulator.

**Password shares, receiving shares, vault page (0.2.x).** `cargo test` passes 78
tests on Rust 1.75 and current stable. Among them are known-bad archives (traversal
names, links and devices, huge declared sizes, truncation, clashes), a seeded
mutation fuzz of the tar reader (5,000 cases), and an end-to-end run of hostile
archives through decrypt, private tree and output folder. `vault_roundtrip.sh` still
passes 131 of 131. `VaultHelpersTest` passes 52, including the new invert, Add
destination and shared-name cases. The Compose UI was type-checked against Compose
Multiplatform 1.7 and `android-all` with stubs for the AndroidX activity, lifecycle
and `FileProvider` calls, and the vault page was rendered off-screen to compare
with the design. The app wasn't built or run on a device here; CI builds it.

**Vaults (0.2.0).** Remember passphrase offers only Off and Until VaultSend
closes; the timed choices from 0.2.0 beta 1 were removed, and a saved timed choice
falls back to the default. The Rust core passes `cargo test` on Rust 1.75 and current
stable: 62 tests, including all 48 of the desktop branch's vault and tar tests. The
desktop's end-to-end `vault_roundtrip.sh` passes 131 of 131 against this code
(`rust/tests/`, run in CI), and `vault_attack.py` passes everything about vaults
(211 checks). Its 4 process-hardening checks don't apply here, for the reason given in
*Security model*. The Kotlin vault helpers have JVM unit tests (`testDebugUnitTest`,
in CI). The app itself is built by CI; it wasn't built or run on a device or emulator
for this change. See `CHANGES-VAULTS.md`.

The Rust core in this tree was compiled and unit-tested with `cargo test` —
encrypt/decrypt round-trips, multi-recipient, key recovery, status transitions,
the new **unlock/lock/session-decrypt** flow, and **importing** an identity in the
desktop format (wrong-passphrase and garbage-input rejection included) — and all
**fourteen** JNI symbols are confirmed exported from the built `.so` (the eight
original ones plus `unlock`, `lock`, `isUnlocked`, `importIdentity`,
`decryptBytesSession`, and `decryptFdSession`). The Kotlin/Gradle half is compiled
by CI (`.github/workflows/android.yml`): every push to and pull request against the
`android` branch runs `cargo test`, cross-compiles the core for all four ABIs, and
runs `./gradlew assembleDebug`. Version numbers in the Gradle files are pinned to a
known-consistent set (AGP 8.9, Kotlin 2.1.10, Gradle 8.13) — Android Studio may
offer newer ones, which you can accept (bump AGP, Kotlin, and the Compose plugin
together, and regenerate the wrapper with `./gradlew wrapper --gradle-version <v>
--gradle-distribution-sha256-sum <sha>`).

## Acknowledgements 

Note: VaultSend's design, functionality and code review was performed by [myself](https://caelen.ca), technical implementation completed with the help of [claude](https://claude.ai)

My pubkey: age192d2u5rkgv9nvl9858fhyqsk78shhgknfjydukfgepu5c608439qnk8z62

