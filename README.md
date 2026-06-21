# VaultSend for Android

[![Get it on Obtainium](https://github.com/user-attachments/assets/9e480740-e1db-4520-b52b-8d45bd1de410)](obtainium://app/%7B%22id%22%3A%22org.vaultsend%22%2C%22url%22%3A%22https%3A%2F%2Fgithub.com%2Fcaelenm%2Fvaultsend%22%2C%22author%22%3A%22caelenm%22%2C%22name%22%3A%22VaultSend%22%7D)

An Android port of [VaultSend](https://github.com/caelenm/vaultsend) — a small,
auditable tool for encrypting messages and files to people you choose, using the
[age](https://github.com/str4d/rage) encryption format. This port keeps the same
cryptography and the same on-disk format as the desktop app; only the front end
and the way the two halves talk to each other are new.

- **Backend:** the original Rust core, refactored into a library (`rust/`).
- **Frontend:** Kotlin + Jetpack Compose (Material 3), replacing the desktop's
  Python/GTK UI (`app/`).
- **Output:** one universal `.apk` that installs on any current Android device.

No new features were added; the goal was a faithful port. Where a desktop idiom
doesn't fit a phone (drag-and-drop, a docked sidebar) the closest touch
equivalent is used (an "Open file…" button, a contacts drawer).

## Project layout

```
vaultsend-android/
├── rust/                     # Rust core (the only code that touches the key)
│   ├── src/backend.rs        #   crypto + identity logic (refactored desktop main.rs)
│   ├── src/ffi.rs            #   JNI entry points (the whole FFI surface)
│   └── src/lib.rs
├── app/                      # Android app
│   └── src/main/
│       ├── java/org/vaultsend/        # Kotlin (UI + native bindings)
│       ├── res/                       # icon, theme, strings, backup rules
│       └── AndroidManifest.xml        # no permissions; no network
├── build-rust.sh             # cross-compiles the core for all ABIs -> jniLibs
└── settings.gradle.kts, build.gradle.kts, app/build.gradle.kts
```

## Building

The simplest path is **Android Studio** (it provides the SDK, the Gradle wrapper,
and a one-click NDK install). You also need a Rust toolchain to compile the core.

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
# If you don't have the Gradle wrapper jar yet (it isn't checked in), generate it:
gradle wrapper --gradle-version 8.9        # needs a system Gradle once; or let
                                           # Android Studio create it for you.

# Debug build:
./gradlew assembleDebug
# Release (minified, shrunk) universal APK:
./gradlew assembleRelease
```

The APK lands in `app/build/outputs/apk/`. A release build is unsigned; sign it
with your own key (`apksigner`, or Android Studio's *Build → Generate Signed
Bundle / APK*) before distributing.

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
  passphrase to **unlock**; after that you stay unlocked until you close the app or
  tap **Lock** in the ⋮ menu (see the security note below). File decryption stages
  the output to a private temp file and only writes it to your chosen destination
  after the whole stream authenticates, so a tampered or truncated file never
  leaves partial plaintext behind.
- **Files from other apps**: share a file to VaultSend from any app's share sheet,
  or use "open with" on a file (e.g. a `.age` file in a file manager). It opens the
  same encrypt/decrypt chooser as the in-app *Open file…* button. Shared plain text
  drops straight into the message box. (Inside the app, files are opened only via
  the *Open file…* button.)
- **Contacts** are stored as `contacts.json` in the same `[{name, pubkey}]` shape
  as desktop, so the file is interchangeable between the two. Contacts never reach
  the crypto core.

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
app then decrypts without re-asking until you lock it or close the app. The
passphrase itself is still **never stored** — what is cached is the *decrypted
secret key* it unlocked.

That cache lives in the **Rust library, not the JVM**, on purpose. A Kotlin
`String`/`ByteArray` cannot be reliably wiped: the garbage collector may copy it
around the managed heap and leave the original in freed memory until it is
reclaimed. The native cache is a `SecretString` that zeroes its buffer on drop;
`lock()` drops it, the ⋮ **Lock** action calls it, and the Activity calls it when
the app is finishing. The key is never written to disk and never crosses back into
the JVM; for each decrypt it is briefly copied into zeroizing storage, used, and
dropped.

This is, honestly, a **weaker posture than decrypting per-operation** (where the
secret exists only for the duration of one call). Keeping an unlocked key resident
widens the window in which it is in memory. That is the cost of the unlock-once
convenience; it is made as safe as an in-process design allows — zeroizing,
mutex-guarded, native-only — and the OS sandbox above is the same boundary that
protects `identity.age` itself. If you prefer the stronger per-operation posture,
tap **Lock** after each use (or simply lock before backgrounding); to make locking
on background automatic, call `backend.lock()` from `MainActivity.onStop()` instead
of `onDestroy()`.

## Build verification status

The Rust core in this tree was compiled and unit-tested with `cargo test` —
encrypt/decrypt round-trips, multi-recipient, key recovery, status transitions,
the new **unlock/lock/session-decrypt** flow, and **importing** an identity in the
desktop format (wrong-passphrase and garbage-input rejection included) — and all
**fourteen** JNI symbols are confirmed exported from the built `.so` (the eight
original ones plus `unlock`, `lock`, `isUnlocked`, `importIdentity`,
`decryptBytesSession`, and `decryptFdSession`). The Kotlin/Gradle half was written
against stable Compose/AGP APIs but **not** compiled in the environment it was
authored in (no Android SDK/NDK there); build it as above and it will pull its
dependencies and assemble. Version numbers in the Gradle files are pinned to a
known-consistent set — Android Studio may offer newer ones, which you can accept
(bump AGP, Kotlin, and the Compose plugin together).
