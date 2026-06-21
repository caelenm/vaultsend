# What changed in this build

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
