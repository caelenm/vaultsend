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
use std::sync::atomic::{AtomicU64, Ordering};
use std::collections::BTreeMap;
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
pub(crate) fn pubkey_path(data_dir: &str) -> PathBuf {
    Path::new(data_dir).join("pubkey")
}

// scrypt work factor (N = 2^LOG_N) for the passphrase-encrypted identity.
//
// Fixed rather than left to age's default, which calibrates to ~1 s on the
// device running keygen with no floor or ceiling: on a phone that gave keys
// weaker than age's standard, and a key made on a fast desktop could exceed
// what this device accepts (its own target + 4), so importing it failed with
// "wrong passphrase". 18 is what age, rage, the desktop app and the web build
// use, so an identity.age made anywhere opens everywhere.
pub(crate) const SCRYPT_LOG_N: u8 = 18;
// Highest work factor accepted when unlocking or importing. Above the fixed
// value so keys from earlier, calibrating builds still open; capped at 2^20
// (scrypt then needs 1 GiB) because a phone cannot afford more, and the web
// build uses the same limit.
const SCRYPT_MAX_LOG_N: u8 = 20;

/// The shortest passphrase a new identity may have, in characters (Unicode scalar
/// values). The app checks the same floor before it calls keygen; this is the
/// check that holds whoever calls.
pub(crate) const MIN_PASSPHRASE_CHARS: usize = 10;

/// The largest file `import_identity` reads. A real identity.age is a few hundred
/// bytes; this only stops a wrong pick (a video, say) from being read into memory.
const MAX_IDENTITY_FILE: u64 = 64 << 10;

/// Held while identity.age is being replaced, so two writers can never interleave
/// on its staging file (`identity.age.new`): one could otherwise rename the other's
/// half-written file into place.
static IDENTITY_FILE: Mutex<()> = Mutex::new(());

/// Encryptor for the identity file at the fixed work factor.
pub(crate) fn identity_encryptor(passphrase: SecretString) -> R<age::Encryptor> {
    let mut recipient = age::scrypt::Recipient::new(passphrase);
    recipient.set_work_factor(SCRYPT_LOG_N);
    age::Encryptor::with_recipients(std::iter::once(&recipient as &dyn age::Recipient))
        .map_err(|e| format!("encrypting identity: {e}"))
}

/// Unwrap a passphrase-encrypted identity, with an error that says what failed.
fn decrypt_identity<'a, RR: Read + 'a>(
    dec: age::Decryptor<RR>,
    passphrase: SecretString,
    wrong_pass: &str,
) -> R<impl Read + 'a> {
    let mut scrypt_id = age::scrypt::Identity::new(passphrase);
    scrypt_id.set_max_work_factor(SCRYPT_MAX_LOG_N);
    dec.decrypt(std::iter::once(&scrypt_id as &dyn age::Identity))
        .map_err(|e| match e {
            // Not a passphrase problem: say so, or the user retypes a correct
            // passphrase forever.
            age::DecryptError::ExcessiveWork { required, .. } => format!(
                "this identity file was created with a scrypt work factor of 2^{required}, \
                 above this device's limit of 2^{SCRYPT_MAX_LOG_N}"
            ),
            _ => wrong_pass.to_string(),
        })
}

/// The scrypt work factor (log2 N) an identity file is wrapped with, read from its
/// header, or None if the header isn't a single scrypt stanza.
pub(crate) fn identity_work_factor(file: &[u8]) -> Option<u8> {
    let mut lines = file.split(|&b| b == b'\n');
    if lines.next()? != b"age-encryption.org/v1" {
        return None;
    }
    let stanza = std::str::from_utf8(lines.next()?).ok()?;
    match stanza.strip_prefix("-> scrypt ")?.split(' ').collect::<Vec<_>>()[..] {
        [_salt, log_n] => log_n.parse().ok().filter(|n: &u8| n.to_string() == log_n),
        _ => None,
    }
}

/// Unwrap the identity in `file` (the bytes of an identity.age) with `passphrase`.
/// `not_age` is said if it isn't an age file at all, `wrong_pass` if it doesn't open.
fn identity_from_bytes(file: &[u8], passphrase: &[u8], not_age: &str, wrong_pass: &str) -> R<x25519::Identity> {
    let (passphrase, _pass_ram) = passphrase_from_bytes(passphrase)?;
    let dec = age::Decryptor::new(file).map_err(|_| not_age.to_string())?;
    let mut id_reader = decrypt_identity(dec, passphrase, wrong_pass)?;
    // Hold the decrypted secret-key text in zeroizing storage so it is wiped on
    // drop rather than left behind in freed heap.
    let mut secret_bytes = secret_buffer();
    id_reader
        .read_to_end(&mut secret_bytes)
        .map_err(|e| format!("reading identity: {e}"))?;
    std::str::from_utf8(&secret_bytes)
        .map_err(|_| "identity file is corrupt".to_string())?
        .trim()
        .parse::<x25519::Identity>()
        .map_err(|e| format!("identity file is corrupt: {e}"))
}

/// Replace identity.age, so it is only ever the old file or the new one: `fill`
/// writes the new one to `identity.age.new`, which is fsynced, then `verify`d, and
/// only then renamed into place. Any failure removes the staging file and leaves
/// identity.age as it was.
fn replace_identity(
    data_dir: &str,
    fill: impl FnOnce(&mut File) -> R<()>,
    verify: impl FnOnce(&Path) -> R<()>,
) -> R<()> {
    let _held = IDENTITY_FILE.lock().unwrap_or_else(|e| e.into_inner());
    let id_path = identity_path(data_dir);
    let tmp = id_path.with_extension("age.new");
    let staged = (|| -> R<()> {
        let mut file = open_private_new(&tmp)?;
        fill(&mut file)?;
        file.flush().map_err(|e| format!("writing identity: {e}"))?;
        file.sync_all().map_err(|e| format!("writing identity: {e}"))?;
        drop(file);
        verify(&tmp)
    })();
    if let Err(e) = staged {
        let _ = fs::remove_file(&tmp);
        return Err(e);
    }
    fs::rename(&tmp, &id_path).map_err(|e| {
        let _ = fs::remove_file(&tmp);
        format!("finalizing identity: {e}")
    })?;
    // Make the rename durable. Best-effort: by now it has happened.
    if let Ok(dir) = File::open(data_dir) {
        let _ = dir.sync_all();
    }
    Ok(())
}

/// Re-wrap identity.age at SCRYPT_LOG_N if `file` (what was just read from it, and
/// opened with `passphrase` as `identity`) is wrapped with less. An identity made by
/// an earlier, calibrating build, or imported from elsewhere, can carry a work
/// factor as low as 2^1, which makes the passphrase cheap to guess from a copy of
/// the file. The passphrase is at hand only here, so this is where it's fixed.
///
/// Best-effort: on any failure identity.age is left exactly as it was, and the
/// next unlock tries again. The new file is decrypted and checked to hold the same
/// key before it replaces the old one, and the old one is replaced only if it is
/// still the file that was read.
fn strengthen_identity(data_dir: &str, file: &[u8], passphrase: &[u8], identity: &x25519::Identity) {
    if !identity_work_factor(file).is_some_and(|log_n| log_n < SCRYPT_LOG_N) {
        return;
    }
    let public = identity.to_public().to_string();
    let _ = replace_identity(
        data_dir,
        |out| {
            if fs::read(identity_path(data_dir)).ok().as_deref() != Some(file) {
                return Err("identity.age changed since it was read".into());
            }
            let (pass, _pass_ram) = passphrase_from_bytes(passphrase)?;
            let secret = identity.to_string();
            let _secret_ram = lock_in_ram(secret.expose_secret().as_bytes());
            let encryptor = identity_encryptor(pass)?;
            let mut w = encryptor
                .wrap_output(&mut *out)
                .map_err(|e| format!("encrypting identity: {e}"))?;
            w.write_all(secret.expose_secret().as_bytes())
                .map_err(|e| format!("encrypting identity: {e}"))?;
            w.finish().map_err(|e| format!("encrypting identity: {e}"))?;
            Ok(())
        },
        |staged| {
            let bytes = fs::read(staged).map_err(|e| format!("reading identity: {e}"))?;
            if identity_work_factor(&bytes) != Some(SCRYPT_LOG_N) {
                return Err("re-wrapped identity has the wrong work factor".into());
            }
            let reread = identity_from_bytes(&bytes, passphrase, "re-wrapped identity is damaged", "re-wrapped identity does not open")?;
            if reread.to_public().to_string() == public {
                Ok(())
            } else {
                Err("re-wrapped identity holds a different key".into())
            }
        },
    );
}

// ---------------------------------------------------------------------------
// Passphrase handling.
//
// The bytes are owned by the JNI layer, which zeroes them after we return. We
// additionally hold every intermediate in zeroizing storage, strip a trailing
// CR/LF without allocating an un-zeroed copy, and move the validated text into a
// SecretString (wiped on drop). Mirrors the desktop `read_passphrase`, minus the
// pipe — there is no fd to read on Android.
//
// The returned RamLock keeps the passphrase's bytes out of swap; hold it for as
// long as the SecretString is in use.
// ---------------------------------------------------------------------------
pub(crate) fn passphrase_from_bytes(raw: &[u8]) -> R<(SecretString, RamLock)> {
    let mut buf = secret_buffer();
    buf.extend_from_slice(raw);
    let end = buf
        .iter()
        .rposition(|&b| b != b'\n' && b != b'\r')
        .map_or(0, |i| i + 1);
    if end == 0 {
        return Err("passphrase is empty".into());
    }
    let pass =
        std::str::from_utf8(&buf[..end]).map_err(|_| "passphrase is not valid UTF-8".to_string())?;
    // The owned String moved into SecretString is zeroized on drop; `buf` is too.
    let passphrase = SecretString::from(pass.to_owned());
    let ram = lock_in_ram(passphrase.expose_secret().as_bytes());
    Ok((passphrase, ram))
}

// ---------------------------------------------------------------------------
// Keeping secret buffers out of swap (ported from the desktop vaults branch).
//
// The desktop backend calls mlockall once, and since that's all or nothing, also
// locks each secret buffer with mlock (`lock_in_ram`), never unlocking because the
// process exits when the operation ends. This library lives in the long-lived app
// process instead (see lib.rs), so each lock is undone when its buffer is dropped:
// otherwise locked pages would pile up for the life of the app, and Android's
// limit on locked memory is small. mlock isn't counted per call, and two small
// buffers can share a page, so pages are reference-counted here and a page is only
// unlocked once nothing locked on it is left. Best-effort, as on desktop: a refused
// mlock is ignored.
// ---------------------------------------------------------------------------
static LOCKED_PAGES: Mutex<BTreeMap<usize, usize>> = Mutex::new(BTreeMap::new());

fn page_size() -> usize {
    // SAFETY: sysconf only reads a configuration value.
    let size = unsafe { libc::sysconf(libc::_SC_PAGESIZE) };
    if size > 0 { size as usize } else { 4096 }
}

/// Pages locked on behalf of one buffer; unlocks them (when no other buffer still
/// needs them) when dropped. Bind it alongside the secret it covers.
#[must_use = "the buffer is unlocked again as soon as this is dropped"]
pub(crate) struct RamLock {
    pages: Option<(usize, usize)>,
}

/// Keep one secret buffer out of swap until the returned guard is dropped.
pub(crate) fn lock_in_ram<T>(buffer: &[T]) -> RamLock {
    let len = std::mem::size_of_val(buffer);
    if len == 0 {
        return RamLock { pages: None };
    }
    let size = page_size();
    let first = buffer.as_ptr() as usize & !(size - 1);
    let last = (buffer.as_ptr() as usize + len - 1) & !(size - 1);
    let mut pages = LOCKED_PAGES.lock().unwrap_or_else(|e| e.into_inner());
    for page in (first..=last).step_by(size) {
        let count = pages.entry(page).or_insert(0);
        if *count == 0 {
            // SAFETY: mlock only reads the address range, which `buffer` borrows.
            let _ = unsafe { libc::mlock(page as *const libc::c_void, size) };
        }
        *count += 1;
    }
    RamLock { pages: Some((first, last)) }
}

impl Drop for RamLock {
    fn drop(&mut self) {
        let Some((first, last)) = self.pages else { return };
        let size = page_size();
        let mut pages = LOCKED_PAGES.lock().unwrap_or_else(|e| e.into_inner());
        for page in (first..=last).step_by(size) {
            if let Some(count) = pages.get_mut(&page) {
                *count -= 1;
                if *count == 0 {
                    pages.remove(&page);
                    // SAFETY: munlock only changes the page's residency. If the memory
                    // has been returned to the system since, it fails, harmlessly.
                    let _ = unsafe { libc::munlock(page as *const libc::c_void, size) };
                }
            }
        }
    }
}

#[cfg(test)]
pub(crate) fn page_of(address: usize) -> usize {
    address & !(page_size() - 1)
}

/// How many live RamLocks cover this page.
#[cfg(test)]
pub(crate) fn lock_count(page: usize) -> usize {
    LOCKED_PAGES.lock().unwrap_or_else(|e| e.into_inner()).get(&page).copied().unwrap_or(0)
}

/// Room for a passphrase or a key's text without reallocating, which would leave an
/// unlocked, unwiped copy behind. A longer passphrase still works; its growth just isn't locked.
const SECRET_CAPACITY: usize = 1024;

/// A buffer for secret bytes: wiped on drop, locked before anything is put in it.
/// Fields drop in order, so it is wiped before it is unlocked.
pub(crate) struct SecretBuf {
    buf: Zeroizing<Vec<u8>>,
    _ram: RamLock,
}

impl std::ops::Deref for SecretBuf {
    type Target = Vec<u8>;
    fn deref(&self) -> &Vec<u8> {
        &self.buf
    }
}

impl std::ops::DerefMut for SecretBuf {
    fn deref_mut(&mut self) -> &mut Vec<u8> {
        &mut self.buf
    }
}

pub(crate) fn secret_buffer() -> SecretBuf {
    let mut buf = Zeroizing::new(Vec::with_capacity(SECRET_CAPACITY));
    let ram = lock_in_ram(buf.spare_capacity_mut());
    SecretBuf { buf, _ram: ram }
}

/// A secret held for longer than one call (the session key, a remembered vault
/// key), locked in RAM for as long as it is held. Wiped, then unlocked, on drop.
pub(crate) struct Held {
    secret: SecretString,
    _ram: RamLock,
}

impl Held {
    pub(crate) fn new(secret: SecretString) -> Held {
        let ram = lock_in_ram(secret.expose_secret().as_bytes());
        Held { secret, _ram: ram }
    }

    pub(crate) fn expose(&self) -> &str {
        self.secret.expose_secret()
    }
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
static SESSION: Mutex<Option<Held>> = Mutex::new(None);

fn hold_session(identity: &x25519::Identity) {
    if let Ok(mut guard) = SESSION.lock() {
        *guard = Some(Held::new(identity.to_string()));
    }
}

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
    *guard = Some(Held::new(identity.to_string()));
    Ok(public)
}

/// Drop the cached secret key (zeroized on drop), and every remembered vault key
/// with it. Safe to call when already locked.
pub fn lock() {
    if let Ok(mut guard) = SESSION.lock() {
        *guard = None;
    }
    crate::vault::forget_all();
}

/// True if a secret key is currently held for this session.
pub fn is_unlocked() -> bool {
    SESSION.lock().map(|g| g.is_some()).unwrap_or(false)
}

/// Parse the cached secret into an identity for one operation. The lock is held
/// only long enough to copy the secret text out (into zeroizing storage), so a
/// long file decrypt never blocks `lock()`/`is_unlocked()`.
pub(crate) fn session_identity() -> R<x25519::Identity> {
    let mut secret_copy = secret_buffer();
    {
        let guard = SESSION
            .lock()
            .map_err(|_| "internal error: session lock poisoned".to_string())?;
        let secret = guard
            .as_ref()
            .ok_or_else(|| "locked — enter your passphrase to unlock".to_string())?;
        secret_copy.extend_from_slice(secret.expose().as_bytes());
    }
    std::str::from_utf8(&secret_copy)
        .map_err(|_| "session identity is corrupt".to_string())?
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
pub(crate) fn open_private_new(path: &Path) -> R<File> {
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
    let (passphrase, _pass_ram) = passphrase_from_bytes(passphrase)?;
    if passphrase.expose_secret().chars().count() < MIN_PASSPHRASE_CHARS {
        return Err(format!("use a passphrase of at least {MIN_PASSPHRASE_CHARS} characters"));
    }

    let identity = x25519::Identity::generate();
    let public = identity.to_public().to_string(); // "age1..."
    let secret = identity.to_string(); // SecretString "AGE-SECRET-KEY-1..."
    let _secret_ram = lock_in_ram(secret.expose_secret().as_bytes());

    // Written to a temp file then atomically renamed into place, so identity.age is
    // only ever absent or fully written — never a partial/empty file a later run
    // would mistake for a real identity.
    replace_identity(
        data_dir,
        |file| {
            let encryptor = identity_encryptor(passphrase)?;
            let mut w = encryptor
                .wrap_output(&mut *file)
                .map_err(|e| format!("encrypting identity: {e}"))?;
            w.write_all(secret.expose_secret().as_bytes())
                .map_err(|e| format!("encrypting identity: {e}"))?;
            w.finish().map_err(|e| format!("encrypting identity: {e}"))?;
            Ok(())
        },
        |_| Ok(()),
    )?;

    fs::write(pubkey_path(data_dir), &public).map_err(|e| format!("writing public key: {e}"))?;

    // The user just proved knowledge of the passphrase by choosing it; unlock the
    // session so the first decrypt doesn't immediately re-ask for it.
    hold_session(&identity);
    Ok(public)
}

/// Import an existing `identity.age` (already passphrase-encrypted, e.g. a backup
/// or one exported from the desktop app). The candidate bytes are read from
/// `input` and **verified** to decrypt under `passphrase` before anything is
/// written: that both confirms the passphrase and proves the file is a real age
/// identity. Only on success are the original bytes written into place as
/// `identity.age`, the public-key cache rebuilt, and the session unlocked. A valid
/// existing identity is never overwritten. Returns the public key.
pub fn import_identity<R2: Read>(data_dir: &str, passphrase: &[u8], input: R2) -> R<String> {
    let dir = Path::new(data_dir);
    fs::create_dir_all(dir).map_err(|e| format!("creating {}: {e}", dir.display()))?;
    let _ = fs::set_permissions(dir, fs::Permissions::from_mode(0o700));

    if identity_is_valid(data_dir) {
        return Err("an identity already exists on this device; refusing to overwrite it".into());
    }

    // Identity files are tiny; read the whole candidate into memory, but no more
    // than a real one could be.
    let mut bytes: Vec<u8> = Vec::new();
    input
        .take(MAX_IDENTITY_FILE + 1)
        .read_to_end(&mut bytes)
        .map_err(|e| format!("reading the selected file: {e}"))?;
    if bytes.len() as u64 > MAX_IDENTITY_FILE {
        return Err("that file is too large to be an identity file".into());
    }

    // Verify structure + passphrase by fully decrypting to the secret key. If any
    // of this fails, nothing has been written and the device is unchanged.
    let identity = identity_from_bytes(
        &bytes,
        passphrase,
        "that file is not a valid age identity",
        "wrong passphrase, or that is not a VaultSend identity file",
    )?;
    let public = identity.to_public().to_string();

    // Verified. Write the original encrypted bytes into place, atomically, 0600.
    replace_identity(
        data_dir,
        |file| file.write_all(&bytes).map_err(|e| format!("writing identity: {e}")),
        |_| Ok(()),
    )?;
    fs::write(pubkey_path(data_dir), &public).map_err(|e| format!("writing public key: {e}"))?;
    // And if it was wrapped weakly, wrap it again at the standard work factor.
    strengthen_identity(data_dir, &bytes, passphrase, &identity);

    // Unlock the freshly imported identity for this session.
    hold_session(&identity);
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
/// A weakly wrapped one is wrapped again at the standard work factor on the way
/// (`strengthen_identity`).
pub(crate) fn load_identity(data_dir: &str, passphrase: &[u8]) -> R<x25519::Identity> {
    let file = fs::read(identity_path(data_dir))
        .map_err(|_| "no identity yet — run keygen first".to_string())?;
    let identity = identity_from_bytes(
        &file,
        passphrase,
        "your saved identity is empty or damaged and can't be read",
        "wrong passphrase, or the identity file is damaged",
    )?;
    strengthen_identity(data_dir, &file, passphrase, &identity);
    Ok(identity)
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
    encrypt_to(encryptor, armor, &mut input, output)?;
    Ok(())
}

/// Encrypt for anyone who knows `password`, as a vault's Share → Set password
/// instead does: scrypt at SCRYPT_LOG_N, and the same floor on the password.
pub fn encrypt_password<R2: Read, W: Write>(password: &[u8], mut input: R2, output: W) -> R<()> {
    let (password, _password_ram) = passphrase_from_bytes(password)?;
    if password.expose_secret().chars().count() < MIN_PASSPHRASE_CHARS {
        return Err(format!("use a password of at least {MIN_PASSPHRASE_CHARS} characters"));
    }
    let mut recipient = age::scrypt::Recipient::new(password);
    recipient.set_work_factor(SCRYPT_LOG_N);
    let encryptor = age::Encryptor::with_recipients(std::iter::once(&recipient as &dyn age::Recipient))
        .map_err(|e| format!("preparing encryption: {e}"))?;
    encrypt_to(encryptor, false, &mut input, output)?;
    Ok(())
}

/// Stream `reader` through `encryptor` into `out`, returning `out` once finished.
/// The same helper the desktop backend's encrypt and vault code share.
pub(crate) fn encrypt_to<W: Write>(
    encryptor: age::Encryptor,
    armor: bool,
    mut reader: impl Read,
    out: W,
) -> R<W> {
    let format = if armor { Format::AsciiArmor } else { Format::Binary };
    let armored =
        ArmoredWriter::wrap_output(out, format).map_err(|e| format!("preparing output: {e}"))?;
    let mut stream = encryptor.wrap_output(armored).map_err(|e| format!("encrypting: {e}"))?;
    io::copy(&mut reader, &mut stream).map_err(|e| format!("encrypting: {e}"))?;
    let armored = stream.finish().map_err(|e| format!("finishing: {e}"))?;
    armored.finish().map_err(|e| format!("finishing: {e}"))
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

/// A staging file name unique to this operation. It used to be a fixed
/// `.decrypt.part`, so two file decrypts running at once (the UI does not
/// serialize them) deleted and reused each other's staging file, and one
/// destination could receive the other file's plaintext.
fn staging_path(data_dir: &str) -> PathBuf {
    staging_named(data_dir, "decrypt")
}

/// `.decrypt-<what>-<pid>-<n>.part` in `data_dir`: a name `clear_stale_staging`
/// sweeps, file or folder, if a run is killed before removing it.
pub(crate) fn staging_named(data_dir: &str, what: &str) -> PathBuf {
    static NEXT: AtomicU64 = AtomicU64::new(0);
    let n = NEXT.fetch_add(1, Ordering::Relaxed);
    let what = if what == "decrypt" { String::new() } else { format!("-{what}") };
    Path::new(data_dir).join(format!(".decrypt{what}-{}-{n}.part", std::process::id()))
}

/// Remove staging files left by an earlier run that was killed mid-decrypt
/// (they hold plaintext). Only called when no decrypt is in progress.
fn clear_stale_staging(data_dir: &str) {
    let Ok(entries) = fs::read_dir(data_dir) else { return };
    for entry in entries.flatten() {
        let name = entry.file_name();
        let name = name.to_string_lossy();
        if name.starts_with(".decrypt") && name.ends_with(".part") {
            // file_type doesn't follow a symlink, so a link is removed, never entered.
            if entry.file_type().is_ok_and(|t| t.is_dir()) {
                let _ = fs::remove_dir_all(entry.path());
            } else {
                let _ = fs::remove_file(entry.path());
            }
        }
    }
}

/// How many staged operations are running, by the folder they stage in; a folder's
/// stale-file cleanup waits for its count to be 0. Kept per folder, so staging in one
/// never holds off the cleanup of another.
static ACTIVE_DECRYPTS: Mutex<BTreeMap<String, usize>> = Mutex::new(BTreeMap::new());

/// Held while plaintext is staged in `data_dir`: the first one in sweeps what a
/// killed run left behind, and none sweeps while another is staging there.
pub(crate) struct StagingGuard {
    dir: String,
}

impl StagingGuard {
    pub(crate) fn new(data_dir: &str) -> StagingGuard {
        let mut active = ACTIVE_DECRYPTS.lock().unwrap_or_else(|e| e.into_inner());
        let count = active.entry(data_dir.to_string()).or_insert(0);
        if *count == 0 {
            clear_stale_staging(data_dir);
        }
        *count += 1;
        StagingGuard { dir: data_dir.to_string() }
    }
}

impl Drop for StagingGuard {
    fn drop(&mut self) {
        let mut active = ACTIVE_DECRYPTS.lock().unwrap_or_else(|e| e.into_inner());
        if let Some(count) = active.get_mut(&self.dir) {
            *count -= 1;
            if *count == 0 {
                active.remove(&self.dir);
            }
        }
    }
}

/// Remove the plaintext staging a killed run left in `data_dir`, unless something is
/// staging there now. For the app's start: otherwise leftovers wait for the next
/// staged operation, which may never come. The count's lock is held throughout, so
/// no operation can start staging while this sweeps.
pub fn sweep_staging(data_dir: &str) {
    let active = ACTIVE_DECRYPTS.lock().unwrap_or_else(|e| e.into_inner());
    if active.get(data_dir).copied().unwrap_or(0) == 0 {
        clear_stale_staging(data_dir);
    }
}

/// One file of plaintext staged in `data_dir` (0600, a name `clear_stale_staging`
/// sweeps), removed when dropped. It holds no descriptor, so thousands can be staged
/// at once without running out.
pub(crate) struct StagedFile {
    path: PathBuf,
    _guard: StagingGuard,
}

impl StagedFile {
    /// A new staging file, and a write-only descriptor on it.
    pub(crate) fn create(data_dir: &str, what: &str) -> R<(StagedFile, File)> {
        let guard = StagingGuard::new(data_dir);
        let path = staging_named(data_dir, what);
        let file = open_private_new(&path)?;
        Ok((StagedFile { path, _guard: guard }, file))
    }

    /// Its contents, from the start.
    pub(crate) fn open(&self) -> R<File> {
        File::open(&self.path).map_err(|e| format!("reading the staged file: {e}"))
    }
}

impl Drop for StagedFile {
    fn drop(&mut self) {
        let _ = fs::remove_file(&self.path);
    }
}

/// A private (0700) folder in `data_dir`, removed with everything in it when dropped.
pub(crate) struct PrivateDir {
    pub(crate) path: PathBuf,
    _guard: StagingGuard,
}

impl PrivateDir {
    pub(crate) fn create(data_dir: &str, what: &str) -> R<PrivateDir> {
        use std::os::unix::fs::DirBuilderExt;
        let guard = StagingGuard::new(data_dir);
        let path = staging_named(data_dir, what);
        fs::DirBuilder::new()
            .mode(0o700)
            .create(&path)
            .map_err(|e| format!("creating {}: {e}", path.display()))?;
        Ok(PrivateDir { path, _guard: guard })
    }
}

impl Drop for PrivateDir {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.path);
    }
}

/// Shared staging logic for the file-decrypt paths (here and in shared.rs).
pub(crate) fn decrypt_file_staged<R2: Read, W: Write>(
    data_dir: &str,
    input: R2,
    mut output: W,
    decrypt_into: impl FnOnce(R2, &mut File) -> R<()>,
) -> R<()> {
    let _guard = StagingGuard::new(data_dir);
    let tmp = staging_path(data_dir);

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

/// The session store, the remembered vault keys and tmpdir() naming are
/// process-global; tests that touch them hold this, so one test's keygen, unlock or
/// lock can't perturb another's view of that shared state.
#[cfg(test)]
pub(crate) static TEST_GUARD: Mutex<()> = Mutex::new(());

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;


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
        let pk_a = keygen(&dir_a, b"aaaa aaaa aaaa").unwrap();
        let pk_b = keygen(&dir_b, b"bbbb bbbb bbbb").unwrap();

        let data = vec![0xABu8; 100_000];
        let mut ct = Vec::new();
        encrypt(&[pk_a, pk_b], false, Cursor::new(&data), &mut ct).unwrap();

        // Both recipients can decrypt the single ciphertext.
        let mut out_a = Vec::new();
        decrypt(&dir_a, b"aaaa aaaa aaaa", Cursor::new(&ct), &mut out_a).unwrap();
        let mut out_b = Vec::new();
        decrypt(&dir_b, b"bbbb bbbb bbbb", Cursor::new(&ct), &mut out_b).unwrap();
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
    fn identity_uses_fixed_work_factor() {
        let _guard = TEST_GUARD.lock().unwrap_or_else(|e| e.into_inner());
        let dir = tmpdir() + "-logn";
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        keygen(&dir, b"work factor test").unwrap();
        let text = fs::read(identity_path(&dir)).unwrap();
        let stanza = String::from_utf8_lossy(&text).lines().nth(1).unwrap().to_string();
        assert!(stanza.starts_with("-> scrypt "), "{stanza}");
        assert!(stanza.ends_with(" 18"), "{stanza}");
        lock();
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn excessive_work_factor_is_reported_as_such() {
        let _guard = TEST_GUARD.lock().unwrap_or_else(|e| e.into_inner());
        let dir = tmpdir() + "-excess";
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        // Hand-build an identity at 2^21; unwrapping it is refused before any
        // scrypt work, so this costs nothing.
        let mut r = age::scrypt::Recipient::new(SecretString::from("pw".to_owned()));
        r.set_work_factor(SCRYPT_MAX_LOG_N + 1);
        let enc = age::Encryptor::with_recipients(std::iter::once(&r as &dyn age::Recipient)).unwrap();
        let mut bytes = Vec::new();
        let mut w = enc.wrap_output(&mut bytes).unwrap();
        w.write_all(x25519::Identity::generate().to_string().expose_secret().as_bytes()).unwrap();
        w.finish().unwrap();
        let err = import_identity(&dir, b"pw", Cursor::new(&bytes)).unwrap_err();
        assert!(err.contains("work factor"), "{err}");
        assert_eq!(status(&dir).unwrap(), "empty");
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn staged_decrypts_do_not_share_a_file() {
        let _guard = TEST_GUARD.lock().unwrap_or_else(|e| e.into_inner());
        let dir = tmpdir() + "-staging";
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        assert_ne!(staging_path(&dir), staging_path(&dir));

        // A stale staging file from a killed run is removed by the next decrypt.
        let stale = Path::new(&dir).join(".decrypt.part");
        fs::write(&stale, b"old plaintext").unwrap();
        let pass = b"staging test";
        lock();
        let pk = keygen(&dir, pass).unwrap();
        let msg = vec![7u8; 200_000];
        let mut ct = Vec::new();
        encrypt(&[pk], false, Cursor::new(&msg), &mut ct).unwrap();
        let mut out = Vec::new();
        decrypt_file_to_session(&dir, Cursor::new(&ct), &mut out).unwrap();
        assert_eq!(out, msg);
        assert!(!stale.exists());
        let leftovers: Vec<_> = fs::read_dir(&dir)
            .unwrap()
            .flatten()
            .filter(|e| e.file_name().to_string_lossy().ends_with(".part"))
            .collect();
        assert!(leftovers.is_empty());
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

    /// An identity.age for `identity`, wrapped with `pass` at scrypt 2^`log_n`.
    fn identity_file(identity: &x25519::Identity, pass: &str, log_n: u8) -> Vec<u8> {
        let mut r = age::scrypt::Recipient::new(SecretString::from(pass.to_owned()));
        r.set_work_factor(log_n);
        let enc = age::Encryptor::with_recipients(std::iter::once(&r as &dyn age::Recipient)).unwrap();
        let mut bytes = Vec::new();
        let mut w = enc.wrap_output(&mut bytes).unwrap();
        w.write_all(identity.to_string().expose_secret().as_bytes()).unwrap();
        w.finish().unwrap();
        bytes
    }

    #[test]
    fn the_work_factor_is_read_from_the_header() {
        let id = x25519::Identity::generate();
        assert_eq!(identity_work_factor(&identity_file(&id, "pw", 3)), Some(3));
        assert_eq!(identity_work_factor(b"age-encryption.org/v1\n-> scrypt c2FsdA 018\n"), None);
        assert_eq!(identity_work_factor(b"age-encryption.org/v1\n-> X25519 abc\n"), None);
        assert_eq!(identity_work_factor(b"not an age file"), None);
    }

    #[test]
    fn a_weakly_wrapped_import_is_wrapped_again_at_the_standard_work_factor() {
        let _guard = TEST_GUARD.lock().unwrap_or_else(|e| e.into_inner());
        let dir = tmpdir() + "-weak-import";
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        lock();
        let id = x25519::Identity::generate();
        let pk = import_identity(&dir, b"weak but mine", Cursor::new(identity_file(&id, "weak but mine", 1))).unwrap();
        assert_eq!(pk, id.to_public().to_string());
        let stored = fs::read(identity_path(&dir)).unwrap();
        assert_eq!(identity_work_factor(&stored), Some(SCRYPT_LOG_N));
        assert!(!identity_path(&dir).with_extension("age.new").exists());
        // The same key and passphrase still open it.
        lock();
        assert_eq!(unlock(&dir, b"weak but mine").unwrap(), pk);
        lock();
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_weak_identity_already_on_the_device_is_strengthened_when_unlocked() {
        let _guard = TEST_GUARD.lock().unwrap_or_else(|e| e.into_inner());
        let dir = tmpdir() + "-weak-existing";
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        lock();
        let id = x25519::Identity::generate();
        fs::write(identity_path(&dir), identity_file(&id, "an older build", 2)).unwrap();
        fs::write(pubkey_path(&dir), id.to_public().to_string()).unwrap();
        // A wrong passphrase changes nothing.
        assert!(unlock(&dir, b"not the passphrase").is_err());
        assert_eq!(identity_work_factor(&fs::read(identity_path(&dir)).unwrap()), Some(2));
        assert_eq!(unlock(&dir, b"an older build").unwrap(), id.to_public().to_string());
        assert_eq!(identity_work_factor(&fs::read(identity_path(&dir)).unwrap()), Some(SCRYPT_LOG_N));
        // Stronger than standard is left as it is.
        let strong = identity_file(&id, "an older build", 19);
        fs::write(identity_path(&dir), &strong).unwrap();
        load_identity(&dir, b"an older build").unwrap();
        assert_eq!(fs::read(identity_path(&dir)).unwrap(), strong);
        lock();
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn import_reads_no_more_than_an_identity_could_be() {
        let _guard = TEST_GUARD.lock().unwrap_or_else(|e| e.into_inner());
        let dir = tmpdir() + "-big-import";
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        let huge = io::repeat(b'x').take(MAX_IDENTITY_FILE * 4);
        assert!(import_identity(&dir, b"whatever passphrase", huge).unwrap_err().contains("too large"));
        assert_eq!(status(&dir).unwrap(), "empty");
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_new_identity_needs_a_passphrase_of_ten_characters() {
        let _guard = TEST_GUARD.lock().unwrap_or_else(|e| e.into_inner());
        let dir = tmpdir() + "-short";
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        // Characters, not bytes: nine accented letters are 18 bytes and still too short.
        assert!(keygen(&dir, "ééééééééé".as_bytes()).unwrap_err().contains("at least 10"));
        assert_eq!(status(&dir).unwrap(), "empty");
        lock();
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn the_start_sweep_removes_leftover_staging_but_never_live_staging() {
        let dir = std::env::temp_dir().join(format!("vaultsend-sweep-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(dir.join(".decrypt-tree-1-2.part")).unwrap();
        fs::write(dir.join(".decrypt-1-1.part"), b"old plaintext").unwrap();
        fs::write(dir.join("identity.age"), b"kept").unwrap();
        let d = dir.to_str().unwrap();
        // While something is staging there, nothing is touched...
        let (live, _file) = StagedFile::create(d, "live").unwrap();
        fs::write(dir.join(".decrypt-1-3.part"), b"a killed run's").unwrap();
        sweep_staging(d);
        assert!(dir.join(".decrypt-1-3.part").exists() && live.open().is_ok());
        drop(live);
        // ...and once it's done, every leftover goes, and nothing else.
        sweep_staging(d);
        let left: Vec<_> = fs::read_dir(&dir).unwrap().flatten().map(|e| e.file_name()).collect();
        assert_eq!(left, vec![std::ffi::OsString::from("identity.age")]);
        let _ = fs::remove_dir_all(&dir);
    }
}
