// VaultSend core — the only code that ever touches the private key.
//
// This is a direct refactor of the desktop backend's command functions into a
// small library. The cryptography is unchanged: every operation is delegated to
// the `age` crate (str4d/rage); there is no hand-written crypto here, only
// plumbing. What changed for Android is *how the plumbing is driven*:
//
//   * Desktop: a separate short-lived process per operation, reading the
//     passphrase from a pipe (fd) and moving data over stdin/stdout.
//   * Android: these functions are called directly over JNI (see ffi.rs) from
//     the Kotlin UI, in the same process. The passphrase arrives as a byte slice
//     the caller zeroes after the call; file data moves over file descriptors
//     handed in from the Storage Access Framework, or over byte buffers for the
//     copy/paste text path.
//
// On-disk layout is identical to desktop, just rooted at the app's private
// internal storage instead of XDG: `<data_dir>/identity.age` is the secret key,
// passphrase-encrypted; `<data_dir>/pubkey` caches the public key in the clear
// (a public key is not a secret) so encryption never needs the passphrase.

use std::fs::{self, File};
use std::io::{self, BufReader, Read, Write};
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::sync::Mutex;

use age::armor::{ArmoredReader, ArmoredWriter, Format};
use age::secrecy::{ExposeSecret, SecretString};
use age::x25519;
use zeroize::Zeroizing;

pub type R<T> = Result<T, String>;

// ---------------------------------------------------------------------------
// Paths.
// ---------------------------------------------------------------------------
fn identity_path(data_dir: &str) -> PathBuf {
    Path::new(data_dir).join("identity.age")
}
fn pubkey_path(data_dir: &str) -> PathBuf {
    Path::new(data_dir).join("pubkey")
}

// ---------------------------------------------------------------------------
// Passphrase handling.
//
// The bytes are owned by the JNI layer, which zeroes them after we return. We
// additionally hold every intermediate in zeroizing storage, strip a trailing
// CR/LF without allocating an un-zeroed copy, and move the validated text into a
// SecretString (wiped on drop). Mirrors the desktop `read_passphrase`, minus the
// pipe — there is no fd to read on Android.
// ---------------------------------------------------------------------------
fn passphrase_from_bytes(raw: &[u8]) -> R<SecretString> {
    let buf: Zeroizing<Vec<u8>> = Zeroizing::new(raw.to_vec());
    let end = buf
        .iter()
        .rposition(|&b| b != b'\n' && b != b'\r')
        .map_or(0, |i| i + 1);
    if end == 0 {
        return Err("passphrase is empty".into());
    }
    let pass =
        std::str::from_utf8(&buf[..end]).map_err(|_| "passphrase is not valid UTF-8".to_string())?;
    Ok(SecretString::from(pass.to_owned()))
}

// ---------------------------------------------------------------------------
// Session ("unlock once") store.
//
// The UI's chosen model is unlock-once-per-session: the passphrase is entered and
// verified once, after which decryption proceeds without re-asking until the
// session is locked or the app is closed.
//
// To honour "never store the passphrase", what we cache is NOT the passphrase but
// the *decrypted secret key* it unlocked — and we keep that here, in the native
// library, rather than in the JVM. The JVM is the wrong place for a secret: a
// Kotlin `String`/`ByteArray` cannot be reliably wiped (the GC may copy it around
// the managed heap and the original is left in freed memory until reclaimed). Here
// the secret lives in a `SecretString`, which zeroes its buffer on drop; `lock()`
// drops it, and the Kotlin side calls `lock()` on app close.
//
// This is deliberately a weaker posture than the per-operation path (where the
// secret exists only transiently inside one decrypt call and is gone immediately
// after). It is the cost of the unlock-once convenience that was requested, made
// as safe as an in-process design allows: the secret is zeroizing, mutex-guarded,
// never written to disk, and never crosses back into the JVM. The OS boundary that
// ultimately protects it is the same one the README describes — the app's private
// UID sandbox plus SELinux.
// ---------------------------------------------------------------------------
static SESSION: Mutex<Option<SecretString>> = Mutex::new(None);

/// Verify `passphrase` against the stored identity and, on success, cache the
/// unlocked secret key for this session. Returns the public key. A wrong
/// passphrase (or damaged identity) returns an error and changes no state — this
/// is the "check that the password is correct before decrypting" gate.
pub fn unlock(data_dir: &str, passphrase: &[u8]) -> R<String> {
    let identity = load_identity(data_dir, passphrase)?;
    let public = identity.to_public().to_string();
    let mut guard = SESSION
        .lock()
        .map_err(|_| "internal error: session lock poisoned".to_string())?;
    *guard = Some(identity.to_string());
    Ok(public)
}

/// Drop the cached secret key (zeroized on drop). Safe to call when already locked.
pub fn lock() {
    if let Ok(mut guard) = SESSION.lock() {
        *guard = None;
    }
}

/// True if a secret key is currently held for this session.
pub fn is_unlocked() -> bool {
    SESSION.lock().map(|g| g.is_some()).unwrap_or(false)
}

/// Parse the cached secret into an identity for one operation. The lock is held
/// only long enough to copy the secret text out (into zeroizing storage), so a
/// long file decrypt never blocks `lock()`/`is_unlocked()`.
fn session_identity() -> R<x25519::Identity> {
    let secret_copy: Zeroizing<String> = {
        let guard = SESSION
            .lock()
            .map_err(|_| "internal error: session lock poisoned".to_string())?;
        let secret = guard
            .as_ref()
            .ok_or_else(|| "locked — enter your passphrase to unlock".to_string())?;
        Zeroizing::new(secret.expose_secret().to_owned())
    };
    secret_copy
        .trim()
        .parse::<x25519::Identity>()
        .map_err(|e| format!("session identity is corrupt: {e}"))
}

// ---------------------------------------------------------------------------
// Small fs helpers (unchanged from desktop).
// ---------------------------------------------------------------------------

/// Create a brand-new 0600 file, refusing to follow or reuse anything already at
/// the path (O_CREAT|O_EXCL). A stale file from an interrupted run is removed and
/// recreated, so we never write through a pre-placed symlink. On Android the
/// containing directory is already the app's private storage, but the 0600 mode
/// and no-clobber semantics are kept exactly.
fn open_private_new(path: &Path) -> R<File> {
    fn create(path: &Path) -> io::Result<File> {
        fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(path)
    }
    match create(path) {
        Ok(f) => Ok(f),
        Err(e) if e.kind() == io::ErrorKind::AlreadyExists => {
            fs::remove_file(path).map_err(|e| format!("clearing stale {}: {e}", path.display()))?;
            create(path).map_err(|e| format!("creating {}: {e}", path.display()))
        }
        Err(e) => Err(format!("creating {}: {e}", path.display())),
    }
}

/// True if identity.age exists and is a structurally valid age file (its header
/// parses). Needs no passphrase. A valid identity is never overwritten; an
/// invalid one is safe to replace because nothing can be recovered from it.
fn identity_is_valid(data_dir: &str) -> bool {
    File::open(identity_path(data_dir))
        .map(|f| age::Decryptor::new(BufReader::new(f)).is_ok())
        .unwrap_or(false)
}

// ---------------------------------------------------------------------------
// Identity lifecycle.
// ---------------------------------------------------------------------------

/// Create the identity on first run and return the public key ("age1…").
pub fn keygen(data_dir: &str, passphrase: &[u8]) -> R<String> {
    let dir = Path::new(data_dir);
    fs::create_dir_all(dir).map_err(|e| format!("creating {}: {e}", dir.display()))?;
    let _ = fs::set_permissions(dir, fs::Permissions::from_mode(0o700));

    // Refuse only if a *valid* identity already exists. An empty/corrupt
    // identity.age (e.g. from an interrupted run) holds no key, so replacing it
    // is safe and avoids leaving the user permanently stuck.
    if identity_is_valid(data_dir) {
        return Err("an identity already exists; refusing to overwrite it".into());
    }
    let passphrase = passphrase_from_bytes(passphrase)?;

    let identity = x25519::Identity::generate();
    let public = identity.to_public().to_string(); // "age1..."
    let secret = identity.to_string(); // SecretString "AGE-SECRET-KEY-1..."

    // Write to a temp file then atomically rename into place, so identity.age is
    // only ever absent or fully written — never a partial/empty file a later run
    // would mistake for a real identity.
    let id_path = identity_path(data_dir);
    let tmp = id_path.with_extension("age.new");
    let file = open_private_new(&tmp)?;
    let write_result = (move || -> R<()> {
        let encryptor = age::Encryptor::with_user_passphrase(passphrase);
        let mut w = encryptor
            .wrap_output(file)
            .map_err(|e| format!("encrypting identity: {e}"))?;
        w.write_all(secret.expose_secret().as_bytes())
            .map_err(|e| format!("encrypting identity: {e}"))?;
        let mut inner = w.finish().map_err(|e| format!("encrypting identity: {e}"))?;
        inner
            .flush()
            .map_err(|e| format!("encrypting identity: {e}"))?;
        inner
            .sync_all()
            .map_err(|e| format!("encrypting identity: {e}"))?;
        Ok(())
    })();
    if let Err(e) = write_result {
        let _ = fs::remove_file(&tmp);
        return Err(e);
    }
    fs::rename(&tmp, &id_path).map_err(|e| {
        let _ = fs::remove_file(&tmp);
        format!("finalizing identity: {e}")
    })?;

    fs::write(pubkey_path(data_dir), &public).map_err(|e| format!("writing public key: {e}"))?;

    // The user just proved knowledge of the passphrase by choosing it; unlock the
    // session so the first decrypt doesn't immediately re-ask for it.
    if let Ok(mut guard) = SESSION.lock() {
        *guard = Some(identity.to_string());
    }
    Ok(public)
}

/// Import an existing `identity.age` (already passphrase-encrypted, e.g. a backup
/// or one exported from the desktop app). The candidate bytes are read from
/// `input` and **verified** to decrypt under `passphrase` before anything is
/// written: that both confirms the passphrase and proves the file is a real age
/// identity. Only on success are the original bytes written into place as
/// `identity.age`, the public-key cache rebuilt, and the session unlocked. A valid
/// existing identity is never overwritten. Returns the public key.
pub fn import_identity<R2: Read>(data_dir: &str, passphrase: &[u8], mut input: R2) -> R<String> {
    let dir = Path::new(data_dir);
    fs::create_dir_all(dir).map_err(|e| format!("creating {}: {e}", dir.display()))?;
    let _ = fs::set_permissions(dir, fs::Permissions::from_mode(0o700));

    if identity_is_valid(data_dir) {
        return Err("an identity already exists on this device; refusing to overwrite it".into());
    }

    // Identity files are tiny; read the whole candidate into memory.
    let mut bytes: Vec<u8> = Vec::new();
    input
        .read_to_end(&mut bytes)
        .map_err(|e| format!("reading the selected file: {e}"))?;

    // Verify structure + passphrase by fully decrypting to the secret key. If any
    // of this fails, nothing has been written and the device is unchanged.
    let pass = passphrase_from_bytes(passphrase)?;
    let dec = age::Decryptor::new(BufReader::new(io::Cursor::new(&bytes)))
        .map_err(|_| "that file is not a valid age identity".to_string())?;
    let scrypt_id = age::scrypt::Identity::new(pass);
    let mut id_reader = dec
        .decrypt(std::iter::once(&scrypt_id as &dyn age::Identity))
        .map_err(|_| "wrong passphrase, or that is not a VaultSend identity file".to_string())?;
    let mut secret_bytes: Zeroizing<Vec<u8>> = Zeroizing::new(Vec::new());
    id_reader
        .read_to_end(&mut secret_bytes)
        .map_err(|e| format!("reading identity: {e}"))?;
    let secret_str =
        std::str::from_utf8(&secret_bytes).map_err(|_| "identity file is corrupt".to_string())?;
    let identity = secret_str
        .trim()
        .parse::<x25519::Identity>()
        .map_err(|e| format!("identity file is corrupt: {e}"))?;
    let public = identity.to_public().to_string();

    // Verified. Write the original encrypted bytes into place, atomically, 0600.
    let id_path = identity_path(data_dir);
    let tmp = id_path.with_extension("age.new");
    let write_result = (|| -> R<()> {
        let mut file = open_private_new(&tmp)?;
        file.write_all(&bytes)
            .map_err(|e| format!("writing identity: {e}"))?;
        file.sync_all()
            .map_err(|e| format!("writing identity: {e}"))?;
        Ok(())
    })();
    if let Err(e) = write_result {
        let _ = fs::remove_file(&tmp);
        return Err(e);
    }
    fs::rename(&tmp, &id_path).map_err(|e| {
        let _ = fs::remove_file(&tmp);
        format!("finalizing identity: {e}")
    })?;
    fs::write(pubkey_path(data_dir), &public).map_err(|e| format!("writing public key: {e}"))?;

    // Unlock the freshly imported identity for this session.
    if let Ok(mut guard) = SESSION.lock() {
        *guard = Some(identity.to_string());
    }
    Ok(public)
}
pub fn pubkey(data_dir: &str) -> R<String> {
    fs::read_to_string(pubkey_path(data_dir))
        .map(|s| s.trim().to_string())
        .map_err(|_| "no identity yet — run keygen first".to_string())
}

/// Report identity state without unlocking:
///   "ready"   — pubkey cache present (encrypt/lookup work with no passphrase)
///   "locked"  — identity.age exists but pubkey cache is missing; rebuild it
///   "empty"   — no identity at all (first run)
///   "corrupt" — identity.age present but empty/unreadable; nothing to recover
pub fn status(data_dir: &str) -> R<String> {
    let has_pubkey = match fs::read_to_string(pubkey_path(data_dir)) {
        Ok(s) => !s.trim().is_empty(),
        Err(_) => false,
    };
    let state = if has_pubkey {
        "ready"
    } else if !identity_path(data_dir).exists() {
        "empty"
    } else if identity_is_valid(data_dir) {
        "locked"
    } else {
        "corrupt"
    };
    Ok(state.to_string())
}

/// Decrypt identity.age with the passphrase and return the parsed identity.
fn load_identity(data_dir: &str, passphrase: &[u8]) -> R<x25519::Identity> {
    let passphrase = passphrase_from_bytes(passphrase)?;
    let id_file = File::open(identity_path(data_dir))
        .map_err(|_| "no identity yet — run keygen first".to_string())?;
    let dec = age::Decryptor::new(BufReader::new(id_file))
        .map_err(|_| "your saved identity is empty or damaged and can't be read".to_string())?;
    let scrypt_id = age::scrypt::Identity::new(passphrase);
    let mut id_reader = dec
        .decrypt(std::iter::once(&scrypt_id as &dyn age::Identity))
        .map_err(|_| "wrong passphrase, or the identity file is damaged".to_string())?;
    // Hold the decrypted secret-key text in zeroizing storage so it is wiped on
    // drop rather than left behind in freed heap.
    let mut secret_bytes: Zeroizing<Vec<u8>> = Zeroizing::new(Vec::new());
    id_reader
        .read_to_end(&mut secret_bytes)
        .map_err(|e| format!("reading identity: {e}"))?;
    let secret =
        std::str::from_utf8(&secret_bytes).map_err(|_| "identity file is corrupt".to_string())?;
    secret
        .trim()
        .parse::<x25519::Identity>()
        .map_err(|e| format!("identity file is corrupt: {e}"))
}

/// Rebuild the clear pubkey cache from the encrypted identity (needs passphrase).
/// Used when the pubkey file was lost but identity.age still exists.
pub fn recover_pubkey(data_dir: &str, passphrase: &[u8]) -> R<String> {
    let identity = load_identity(data_dir, passphrase)?;
    let public = identity.to_public().to_string();
    fs::write(pubkey_path(data_dir), &public).map_err(|e| format!("writing public key: {e}"))?;
    Ok(public)
}

// ---------------------------------------------------------------------------
// Encrypt / decrypt, generic over the byte (text) and fd (file) paths.
// ---------------------------------------------------------------------------

/// Encrypt `input` to `recipients`, writing (optionally ASCII-armored) ciphertext
/// to `output`. Streams, so large files never load fully into memory.
pub fn encrypt<R2: Read, W: Write>(
    recipients: &[String],
    armor: bool,
    mut input: R2,
    output: W,
) -> R<()> {
    if recipients.is_empty() {
        return Err("no recipients given".into());
    }
    let recipients: Vec<x25519::Recipient> = recipients
        .iter()
        .map(|s| {
            s.parse::<x25519::Recipient>()
                .map_err(|e| format!("invalid recipient '{s}': {e}"))
        })
        .collect::<R<_>>()?;

    let encryptor =
        age::Encryptor::with_recipients(recipients.iter().map(|r| r as &dyn age::Recipient))
            .map_err(|e| format!("preparing encryption: {e}"))?;

    let format = if armor {
        Format::AsciiArmor
    } else {
        Format::Binary
    };
    let armored =
        ArmoredWriter::wrap_output(output, format).map_err(|e| format!("preparing output: {e}"))?;
    let mut stream = encryptor
        .wrap_output(armored)
        .map_err(|e| format!("encrypting: {e}"))?;
    io::copy(&mut input, &mut stream).map_err(|e| format!("encrypting: {e}"))?;
    let armored = stream.finish().map_err(|e| format!("finishing: {e}"))?;
    armored.finish().map_err(|e| format!("finishing: {e}"))?;
    Ok(())
}

/// Decrypt `input` (binary or ASCII-armored, detected automatically) to `output`,
/// using the identity unlocked by `passphrase`. The whole stream is read and
/// authenticated before this returns success.
pub fn decrypt<R2: Read, W: Write>(
    data_dir: &str,
    passphrase: &[u8],
    input: R2,
    output: W,
) -> R<()> {
    let identity = load_identity(data_dir, passphrase)?;
    decrypt_with_identity(&identity, input, output)
}

/// Decrypt using the secret key cached by [`unlock`] for this session. Errors if
/// the session is locked.
pub fn decrypt_session<R2: Read, W: Write>(input: R2, output: W) -> R<()> {
    let identity = session_identity()?;
    decrypt_with_identity(&identity, input, output)
}

/// The shared decrypt core, generic over how the identity was obtained.
fn decrypt_with_identity<R2: Read, W: Write>(
    identity: &x25519::Identity,
    input: R2,
    mut output: W,
) -> R<()> {
    let armored = ArmoredReader::new(BufReader::new(input));
    let dec = age::Decryptor::new(armored).map_err(|e| format!("reading input: {e}"))?;
    let mut stream = dec
        .decrypt(std::iter::once(identity as &dyn age::Identity))
        .map_err(|_| {
            "this was not encrypted to you (or the input is not an age file)".to_string()
        })?;
    io::copy(&mut stream, &mut output).map_err(|e| format!("decrypting: {e}"))?;
    output.flush().map_err(|e| format!("writing output: {e}"))?;
    Ok(())
}

/// Decrypt a file to another file, preserving the desktop guarantee that a
/// truncated or tampered ciphertext never leaves partial plaintext at the
/// destination. age authenticates as it streams, so we stage the plaintext to a
/// private 0600 temp inside `data_dir`, fsync it, and only copy it out to the
/// caller's (SAF-provided) writer once the whole stream has decrypted cleanly.
/// The temp is always removed.
pub fn decrypt_file_to<R2: Read, W: Write>(
    data_dir: &str,
    passphrase: &[u8],
    input: R2,
    output: W,
) -> R<()> {
    decrypt_file_staged(data_dir, input, output, |inp, tmp| {
        decrypt(data_dir, passphrase, inp, tmp)
    })
}

/// As [`decrypt_file_to`], but using the unlocked session key instead of a
/// passphrase.
pub fn decrypt_file_to_session<R2: Read, W: Write>(
    data_dir: &str,
    input: R2,
    output: W,
) -> R<()> {
    decrypt_file_staged(data_dir, input, output, |inp, tmp| decrypt_session(inp, tmp))
}

/// Shared staging logic for the two file-decrypt paths above.
fn decrypt_file_staged<R2: Read, W: Write>(
    data_dir: &str,
    input: R2,
    mut output: W,
    decrypt_into: impl FnOnce(R2, &mut File) -> R<()>,
) -> R<()> {
    let tmp = Path::new(data_dir).join(".decrypt.part");
    // Clean any stale staging file from a previous interrupted run.
    let _ = fs::remove_file(&tmp);

    let staged: R<()> = (|| {
        let mut tmp_file = open_private_new(&tmp)?;
        decrypt_into(input, &mut tmp_file)?;
        tmp_file
            .sync_all()
            .map_err(|e| format!("flushing output: {e}"))
    })();

    let result = staged.and_then(|()| {
        let mut tmp_file = File::open(&tmp).map_err(|e| format!("reading staged output: {e}"))?;
        io::copy(&mut tmp_file, &mut output).map_err(|e| format!("writing output: {e}"))?;
        output.flush().map_err(|e| format!("writing output: {e}"))
    });

    let _ = fs::remove_file(&tmp);
    result
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    // The session store and tmpdir() naming are process-global; serialize tests so
    // one test's keygen/unlock can't perturb another's view of that shared state.
    static TEST_GUARD: Mutex<()> = Mutex::new(());

    fn tmpdir() -> String {
        let p = std::env::temp_dir().join(format!("vaultsend-test-{}", std::process::id()));
        let _ = fs::remove_dir_all(&p);
        fs::create_dir_all(&p).unwrap();
        p.to_string_lossy().into_owned()
    }

    #[test]
    fn full_round_trip() {
        let _guard = TEST_GUARD.lock().unwrap_or_else(|e| e.into_inner());
        let dir = tmpdir();
        let pass = b"correct horse battery staple";

        assert_eq!(status(&dir).unwrap(), "empty");
        let pk = keygen(&dir, pass).unwrap();
        assert!(pk.starts_with("age1"));
        assert_eq!(status(&dir).unwrap(), "ready");
        assert_eq!(pubkey(&dir).unwrap(), pk);

        // Refuses to overwrite a valid identity.
        assert!(keygen(&dir, pass).is_err());

        // Armored text round-trip.
        let msg = b"meet me at the bridge";
        let mut ct = Vec::new();
        encrypt(&[pk.clone()], true, Cursor::new(msg), &mut ct).unwrap();
        assert!(ct.starts_with(b"-----BEGIN AGE ENCRYPTED FILE-----"));
        let mut pt = Vec::new();
        decrypt(&dir, pass, Cursor::new(&ct), &mut pt).unwrap();
        assert_eq!(pt, msg);

        // Wrong passphrase fails.
        assert!(decrypt(&dir, b"nope", Cursor::new(&ct), &mut Vec::new()).is_err());

        // recover-pubkey rebuilds the cache after the pubkey file is lost.
        fs::remove_file(pubkey_path(&dir)).unwrap();
        assert_eq!(status(&dir).unwrap(), "locked");
        assert_eq!(recover_pubkey(&dir, pass).unwrap(), pk);
        assert_eq!(status(&dir).unwrap(), "ready");

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn multi_recipient_and_binary_file() {
        let _guard = TEST_GUARD.lock().unwrap_or_else(|e| e.into_inner());
        let dir_a = tmpdir() + "-a";
        let dir_b = tmpdir() + "-b";
        fs::create_dir_all(&dir_a).unwrap();
        fs::create_dir_all(&dir_b).unwrap();
        let pk_a = keygen(&dir_a, b"aaaa").unwrap();
        let pk_b = keygen(&dir_b, b"bbbb").unwrap();

        let data = vec![0xABu8; 100_000];
        let mut ct = Vec::new();
        encrypt(&[pk_a, pk_b], false, Cursor::new(&data), &mut ct).unwrap();

        // Both recipients can decrypt the single ciphertext.
        let mut out_a = Vec::new();
        decrypt(&dir_a, b"aaaa", Cursor::new(&ct), &mut out_a).unwrap();
        let mut out_b = Vec::new();
        decrypt(&dir_b, b"bbbb", Cursor::new(&ct), &mut out_b).unwrap();
        assert_eq!(out_a, data);
        assert_eq!(out_b, data);

        let _ = fs::remove_dir_all(&dir_a);
        let _ = fs::remove_dir_all(&dir_b);
    }

    #[test]
    fn unlock_lock_and_session_decrypt() {
        let _guard = TEST_GUARD.lock().unwrap_or_else(|e| e.into_inner());
        let dir = tmpdir() + "-session";
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        let pass = b"open sesame";

        lock(); // clean slate regardless of prior tests
        assert!(!is_unlocked());

        // keygen auto-unlocks (the user just chose the passphrase).
        let pk = keygen(&dir, pass).unwrap();
        assert!(is_unlocked());

        let msg = b"the password is swordfish";
        let mut ct = Vec::new();
        encrypt(&[pk.clone()], true, Cursor::new(msg), &mut ct).unwrap();

        // Session decrypt works with no passphrase while unlocked.
        let mut pt = Vec::new();
        decrypt_session(Cursor::new(&ct), &mut pt).unwrap();
        assert_eq!(pt, msg);

        // After locking, session decrypt refuses; unlock with the wrong passphrase
        // fails and does NOT unlock; the right passphrase unlocks again.
        lock();
        assert!(!is_unlocked());
        assert!(decrypt_session(Cursor::new(&ct), &mut Vec::new()).is_err());
        assert!(unlock(&dir, b"wrong").is_err());
        assert!(!is_unlocked());
        assert_eq!(unlock(&dir, pass).unwrap(), pk);
        assert!(is_unlocked());

        let mut pt2 = Vec::new();
        decrypt_session(Cursor::new(&ct), &mut pt2).unwrap();
        assert_eq!(pt2, msg);

        lock();
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn import_round_trips_with_desktop_format() {
        let _guard = TEST_GUARD.lock().unwrap_or_else(|e| e.into_inner());
        // Create an identity in one dir, grab its raw identity.age bytes, then
        // import those bytes into a fresh dir — the public key must match.
        let src = tmpdir() + "-imp-src";
        let dst = tmpdir() + "-imp-dst";
        let _ = fs::remove_dir_all(&src);
        let _ = fs::remove_dir_all(&dst);
        fs::create_dir_all(&src).unwrap();
        fs::create_dir_all(&dst).unwrap();
        let pass = b"portable passphrase";

        lock();
        let pk = keygen(&src, pass).unwrap();
        let id_bytes = fs::read(identity_path(&src)).unwrap();

        // Wrong passphrase must not write anything or unlock.
        lock();
        assert!(import_identity(&dst, b"nope", Cursor::new(&id_bytes)).is_err());
        assert_eq!(status(&dst).unwrap(), "empty");
        assert!(!is_unlocked());

        // Garbage bytes are rejected as not-an-age-file.
        assert!(import_identity(&dst, pass, Cursor::new(b"not an age file")).is_err());
        assert_eq!(status(&dst).unwrap(), "empty");

        // Correct import reproduces the same public key, becomes ready, unlocks.
        let imported_pk = import_identity(&dst, pass, Cursor::new(&id_bytes)).unwrap();
        assert_eq!(imported_pk, pk);
        assert_eq!(status(&dst).unwrap(), "ready");
        assert_eq!(pubkey(&dst).unwrap(), pk);
        assert!(is_unlocked());

        // The imported identity can actually decrypt something sent to that key.
        let msg = b"hello from the other device";
        let mut ct = Vec::new();
        encrypt(&[pk.clone()], true, Cursor::new(msg), &mut ct).unwrap();
        let mut pt = Vec::new();
        decrypt_session(Cursor::new(&ct), &mut pt).unwrap();
        assert_eq!(pt, msg);

        // Re-importing over a valid identity is refused.
        assert!(import_identity(&dst, pass, Cursor::new(&id_bytes)).is_err());

        lock();
        let _ = fs::remove_dir_all(&src);
        let _ = fs::remove_dir_all(&dst);
    }
}
