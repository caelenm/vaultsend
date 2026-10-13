// VaultSend backend — the only component that ever touches the private key.
//
// It is a small, stateless command-line tool. The Python UI runs it once per
// operation. All encryption is delegated to the `age` crate (str4d/rage). The
// only other cryptographic call is one HKDF (RustCrypto `hkdf`) that mixes
// optional user entropy into a new key at keygen; this file implements no
// primitives, only plumbing.
//
// Commands:
//   keygen  --pass-fd N [--entropy-fd M]
//                                 Create the identity (first run). Print public key.
//                                 M, if given, carries exactly 64 bytes of user
//                                 entropy (the scribble digest) mixed into the key.
//   pubkey                        Print this device's public key. (no secret needed)
//   status                        Print ready|locked|empty|corrupt. (no secret needed)
//   recover-pubkey --pass-fd N    Rebuild the public key cache from identity.age.
//   encrypt -r AGE1.. [..] [--armor] [--in P] [--out P]   (no secret needed)
//   decrypt --pass-fd N [--in P] [--out P]
//
// Secrets never travel on argv (which is world-readable via /proc). The identity
// passphrase, and keygen's optional user entropy, are read from file descriptors
// handed over by the parent process.
// File data flows over stdin/stdout (in-memory pipes) so plaintext need not touch
// disk; an explicit --in / --out path may be used instead.
//
// Hardening (see harden_process): the process is made non-dumpable, core dumps
// are disabled, and memory is locked out of swap, so secrets held transiently in
// RAM cannot be read by other same-user processes, recovered from a core file,
// or paged to a swap device. Secret buffers are additionally held in zeroizing
// storage so they are wiped from memory on drop.

use std::env;
use std::fs::{self, File};
use std::io::{self, BufReader, Read, Write};
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::os::unix::io::FromRawFd;
use std::path::PathBuf;
use std::process::ExitCode;

use age::armor::{ArmoredReader, ArmoredWriter, Format};
use age::secrecy::{ExposeSecret, SecretString};
use age::x25519;
use bech32::{ToBase32, Variant};
use hkdf::Hkdf;
use rand_core::{OsRng, RngCore};
use sha2::Sha256;
use zeroize::Zeroizing;

type R<T> = Result<T, String>;

// ---------------------------------------------------------------------------
// Process hardening. Runs once, before any secret can enter memory.
// ---------------------------------------------------------------------------
//  * PR_SET_DUMPABLE(0): re-owns /proc/<pid>/{mem,maps,environ} to root and
//    blocks ptrace from same-user processes, so another program running as the
//    same user cannot read this process's memory while it holds the key —
//    regardless of the system's Yama ptrace_scope setting.
//  * RLIMIT_CORE = 0: a crash cannot write a core file carrying secret memory
//    to disk. (Relevant with `panic = "abort"`, where unwinding/zeroize-on-drop
//    does not run on a panic.)
//  * mlockall: keep secret pages out of swap. Best-effort — it may be refused
//    when RLIMIT_MEMLOCK is low, in which case we proceed (no swap / encrypted
//    swap is the remaining mitigation).
#[cfg(target_os = "linux")]
fn harden_process() {
    unsafe {
        let _ = libc::prctl(libc::PR_SET_DUMPABLE, 0, 0, 0, 0);
        let no_core = libc::rlimit { rlim_cur: 0, rlim_max: 0 };
        let _ = libc::setrlimit(libc::RLIMIT_CORE, &no_core);

        // Keep secret pages out of swap — but carefully. MCL_FUTURE locks every
        // *future* allocation, and if one would exceed RLIMIT_MEMLOCK the kernel
        // fails the allocation outright, aborting the process. scrypt (used by
        // keygen/decrypt) allocates a large buffer, so on a machine with the
        // common low memlock limit that abort is exactly what happens. So: try
        // to lift the limit, and only lock future allocations when it is truly
        // unlimited. Otherwise lock just what's mapped now (best-effort) and let
        // allocations proceed normally. Hardening must never break the app.
        let inf = libc::rlimit { rlim_cur: libc::RLIM_INFINITY, rlim_max: libc::RLIM_INFINITY };
        let _ = libc::setrlimit(libc::RLIMIT_MEMLOCK, &inf);

        let mut cur = libc::rlimit { rlim_cur: 0, rlim_max: 0 };
        let unlimited = libc::getrlimit(libc::RLIMIT_MEMLOCK, &mut cur) == 0
            && cur.rlim_cur == libc::RLIM_INFINITY;

        let flags = if unlimited {
            libc::MCL_CURRENT | libc::MCL_FUTURE
        } else {
            libc::MCL_CURRENT
        };
        let _ = libc::mlockall(flags);
    }
}

#[cfg(not(target_os = "linux"))]
fn harden_process() {
    // The primitives above are Linux-specific (notably PR_SET_DUMPABLE). The
    // equivalents on macOS (PT_DENY_ATTACH) and elsewhere differ; left as a
    // no-op so the binary still builds on other platforms.
}

// ---------------------------------------------------------------------------
// Paths.  Identity lives under XDG_DATA_HOME (default ~/.local/share/vaultsend).
// `identity.age` is the secret key, passphrase-encrypted. `pubkey` is the public
// key in clear (a public key is not a secret) so encryption never needs the
// passphrase.
// ---------------------------------------------------------------------------
fn data_dir() -> R<PathBuf> {
    if let Ok(x) = env::var("XDG_DATA_HOME") {
        if !x.is_empty() {
            return Ok(PathBuf::from(x).join("vaultsend"));
        }
    }
    let home = env::var("HOME").map_err(|_| "HOME is not set".to_string())?;
    Ok(PathBuf::from(home).join(".local/share/vaultsend"))
}
fn identity_path() -> R<PathBuf> { Ok(data_dir()?.join("identity.age")) }
fn pubkey_path() -> R<PathBuf> { Ok(data_dir()?.join("pubkey")) }

// scrypt work factor (N = 2^LOG_N) for the passphrase-encrypted identity.
//
// Fixed rather than left to age's default, which calibrates to ~1 s on the
// machine running keygen and has no floor or ceiling. That produced identities
// that were weaker than age's standard on slow machines, and on fast machines
// identities that a slower device (default limit: its own target + 4) or the
// web build (limit: 20) refuses to open. 18 is what age, rage's CLI and the web
// build use, so an identity.age made anywhere opens everywhere.
const SCRYPT_LOG_N: u8 = 18;
// Highest work factor accepted when unlocking. Above the fixed value so that
// identities created by earlier, calibrating builds still open on any device.
const SCRYPT_MAX_LOG_N: u8 = 22;

/// Plaintext and ciphertext written to a file are staged here first and renamed
/// into place only once complete. A distinctive suffix, because a stale staging
/// file is deleted on the next run and must never be one of the user's own
/// files (`<name>.part` is what browsers use for in-progress downloads).
fn staging_path(path: &str) -> String { format!("{path}.vaultsend-part") }

// ---------------------------------------------------------------------------
// Small IO helpers.
// ---------------------------------------------------------------------------
fn read_passphrase(fd: i32) -> R<SecretString> {
    // Reject the standard streams: from_raw_fd takes ownership and would close
    // the fd on drop, and a passphrase pipe should never be 0/1/2 anyway.
    if fd < 3 {
        return Err("--pass-fd must refer to a dedicated pipe (fd >= 3)".into());
    }
    // SAFETY: the parent passes a readable pipe end as this fd. We take ownership
    // here and close it on drop.
    let mut f = unsafe { File::from_raw_fd(fd) };
    // Read into zeroizing storage so the raw passphrase bytes are wiped from
    // memory on drop instead of lingering in freed heap.
    let mut buf: Zeroizing<Vec<u8>> = Zeroizing::new(Vec::new());
    f.read_to_end(&mut buf).map_err(|e| format!("reading passphrase: {e}"))?;
    // Strip trailing CR/LF without allocating an un-zeroized copy.
    let end = buf
        .iter()
        .rposition(|&b| b != b'\n' && b != b'\r')
        .map_or(0, |i| i + 1);
    if end == 0 {
        return Err("passphrase is empty".into());
    }
    let pass = std::str::from_utf8(&buf[..end])
        .map_err(|_| "passphrase is not valid UTF-8".to_string())?;
    // The owned String moved into SecretString is zeroized on drop; `buf` is too.
    Ok(SecretString::from(pass.to_owned()))
}

/// Length of keygen's optional user entropy: the frontend's scribble digest.
const USER_ENTROPY_LEN: usize = 64;

/// Read exactly USER_ENTROPY_LEN bytes of user entropy from `fd`, with the same
/// ownership rules as read_passphrase. Too few or too many bytes is an error, so
/// a truncated or partial scribble can never become a key.
fn read_entropy(fd: i32) -> R<Zeroizing<[u8; USER_ENTROPY_LEN]>> {
    if fd < 3 {
        return Err("--entropy-fd must refer to a dedicated pipe (fd >= 3)".into());
    }
    // SAFETY: as in read_passphrase — a readable pipe end we now own and close.
    let mut f = unsafe { File::from_raw_fd(fd) };
    let mut buf = Zeroizing::new([0u8; USER_ENTROPY_LEN]);
    f.read_exact(&mut buf[..]).map_err(|e| match e.kind() {
        io::ErrorKind::UnexpectedEof => {
            format!("entropy must be exactly {USER_ENTROPY_LEN} bytes (got fewer)")
        }
        _ => format!("reading entropy: {e}"),
    })?;
    match f.read(&mut [0u8; 1]) {
        Ok(0) => Ok(buf),
        Ok(_) => Err(format!("entropy must be exactly {USER_ENTROPY_LEN} bytes (got more)")),
        Err(e) => Err(format!("reading entropy: {e}")),
    }
}

/// Create a brand-new file private to the user (0600), refusing to follow or
/// reuse anything already at the path (O_CREAT|O_EXCL). A stale file from an
/// interrupted run is removed and recreated, so we never write through a
/// pre-placed symlink.
fn open_private_new(path: &str) -> R<File> {
    fn create(path: &str) -> io::Result<File> {
        fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(path)
    }
    match create(path) {
        Ok(f) => Ok(f),
        Err(e) if e.kind() == io::ErrorKind::AlreadyExists => {
            fs::remove_file(path).map_err(|e| format!("clearing stale {path}: {e}"))?;
            create(path).map_err(|e| format!("creating {path}: {e}"))
        }
        Err(e) => Err(format!("creating {path}: {e}")),
    }
}

/// Finish a staged write: on success fsync was already done by the caller, so
/// atomically rename the staging file over `path`; on failure remove it so no
/// partial output is ever left behind.
fn commit_staged(staged: R<()>, tmp: &str, path: &str) -> R<()> {
    match staged {
        Ok(()) => fs::rename(tmp, path).map_err(|e| {
            let _ = fs::remove_file(tmp);
            format!("finalizing {path}: {e}")
        }),
        Err(e) => {
            let _ = fs::remove_file(tmp);
            Err(e)
        }
    }
}

fn input_reader(path: Option<&str>) -> R<Box<dyn Read>> {
    match path {
        Some(p) => Ok(Box::new(File::open(p).map_err(|e| format!("opening {p}: {e}"))?)),
        None => Ok(Box::new(io::stdin())),
    }
}

// ---------------------------------------------------------------------------
// Key generation, with optional user entropy (the "scribble").
// ---------------------------------------------------------------------------
// By default a new secret key is age's own x25519::Identity::generate(): 32
// bytes straight from the OS RNG. If the user opted in at first run, the
// frontend also hands over a 64-byte digest of their pointer scribble, and the
// key becomes
//
//     HKDF-SHA256(salt = "vaultsend/keygen/v1",
//                 ikm  = 32 bytes of OS randomness || 64-byte scribble digest,
//                 info = "age X25519 secret key")
//
// Why hash the two together rather than XOR them: XOR needs equal-length inputs
// and only gives a uniformly random key when one input already is one. If the
// OS RNG were weak, XOR with a scribble (human input of unknown quality) would
// still leave a skewed key. HKDF extracts from the whole concatenation, so the
// key is uniformly distributed and at least as hard to predict as the stronger
// of the two inputs. A healthy OS RNG keeps the key strong however poor
// the scribble, and a good scribble keeps it strong if the OS RNG is weak or
// compromised. Any 32 bytes are a valid X25519 secret (clamping happens inside
// x25519-dalek at use), so the HKDF output is used as-is.
//
// The scribble is not a second factor. It is used once, here, and discarded,
// and never has to be reproduced: the resulting key is stored in identity.age
// and unlocked with the passphrase exactly like any other.
const KEYGEN_HKDF_SALT: &[u8] = b"vaultsend/keygen/v1";
const KEYGEN_HKDF_INFO: &[u8] = b"age X25519 secret key";
/// Bech32 HRP of an age secret key, as used by x25519::Identity::to_string.
const AGE_SECRET_KEY_HRP: &str = "age-secret-key-";

fn derive_secret(os: &[u8; 32], user: &[u8; USER_ENTROPY_LEN]) -> Zeroizing<[u8; 32]> {
    let mut ikm = Zeroizing::new([0u8; 32 + USER_ENTROPY_LEN]);
    ikm[..32].copy_from_slice(os);
    ikm[32..].copy_from_slice(user);
    // (hkdf keeps its intermediate PRK on the stack without zeroizing it; like
    // age's own internal HKDF use, that is covered by harden_process.)
    let hk = Hkdf::<Sha256>::new(Some(KEYGEN_HKDF_SALT), &ikm[..]);
    let mut okm = Zeroizing::new([0u8; 32]);
    hk.expand(KEYGEN_HKDF_INFO, &mut okm[..])
        .expect("32 bytes is a valid HKDF-SHA256 output length");
    okm
}

/// Turn 32 raw secret-key bytes into an age identity. age 0.11 has no
/// constructor from bytes, so this produces the identity's own text form exactly
/// as x25519::Identity::to_string does (Bech32, uppercased) and parses it.
fn identity_from_secret(secret: &[u8; 32]) -> R<x25519::Identity> {
    // Encode into one pre-sized zeroizing buffer, so no reallocation leaves a
    // copy of the key text behind. (The intermediate base32 digits are not
    // wiped: bech32's u5 has no Zeroize, the same limitation age's to_string has.)
    let mut encoded = Zeroizing::new(String::with_capacity(128));
    bech32::encode_to_fmt(&mut *encoded, AGE_SECRET_KEY_HRP, secret.to_base32(), Variant::Bech32)
        .map_err(|e| format!("encoding new key: {e}"))?
        .map_err(|e| format!("encoding new key: {e}"))?;
    encoded.make_ascii_uppercase();
    encoded
        .parse::<x25519::Identity>()
        .map_err(|e| format!("encoding new key: {e}"))
}

/// Generate a new identity: from the OS RNG alone when `user` is None (age's own
/// generator, unchanged), otherwise from derive_secret(OS randomness, user).
fn generate_identity(user: Option<&[u8; USER_ENTROPY_LEN]>) -> R<x25519::Identity> {
    let Some(user) = user else {
        return Ok(x25519::Identity::generate());
    };
    let mut os = Zeroizing::new([0u8; 32]);
    OsRng
        .try_fill_bytes(&mut os[..])
        .map_err(|e| format!("reading OS randomness: {e}"))?;
    let secret = derive_secret(&os, user);
    identity_from_secret(&secret)
}

// ---------------------------------------------------------------------------
// Commands.
// ---------------------------------------------------------------------------
/// True if identity.age exists and is a structurally valid age file (its header
/// parses). Needs no passphrase, and is what separates a recoverable identity
/// from an empty/corrupt leftover. A valid identity is never overwritten; an
/// invalid one is safe to replace because nothing can be recovered from it.
fn identity_is_valid() -> bool {
    match identity_path() {
        Ok(p) => File::open(&p)
            .map(|f| age::Decryptor::new(BufReader::new(f)).is_ok())
            .unwrap_or(false),
        Err(_) => false,
    }
}

fn cmd_keygen(pass_fd: i32, entropy_fd: Option<i32>) -> R<()> {
    let dir = data_dir()?;
    fs::create_dir_all(&dir).map_err(|e| format!("creating {}: {e}", dir.display()))?;
    let _ = fs::set_permissions(&dir, fs::Permissions::from_mode(0o700));

    // Refuse only if a *valid* identity already exists. An empty or corrupt
    // identity.age (e.g. left by an interrupted earlier run) holds no key, so it
    // is safe to replace rather than leaving the user permanently stuck.
    if identity_is_valid() {
        return Err("an identity already exists; refusing to overwrite it".into());
    }
    if entropy_fd == Some(pass_fd) {
        return Err("--entropy-fd and --pass-fd must be different pipes".into());
    }
    // Read every input before any key material exists. A bad entropy pipe
    // (wrong length, unreadable) fails here, with nothing written.
    let passphrase = read_passphrase(pass_fd)?;
    let entropy = entropy_fd.map(read_entropy).transpose()?;

    let identity = generate_identity(entropy.as_deref())?;
    drop(entropy); // consumed once; wipe it now
    let public = identity.to_public().to_string(); // "age1..."
    let secret = identity.to_string();             // SecretString "AGE-SECRET-KEY-1..."

    // Write the encrypted identity to a temp file, then atomically rename it into
    // place. identity.age is therefore only ever absent or fully written — never
    // a partial/empty file that a later run would mistake for a real identity
    // (the very state that produced "failed to fill whole buffer" on recovery).
    let id_path = identity_path()?;
    let tmp = format!("{}.new", id_path.display());
    let file = open_private_new(&tmp)?;
    let write_result = (move || -> R<()> {
        let mut recipient = age::scrypt::Recipient::new(passphrase);
        recipient.set_work_factor(SCRYPT_LOG_N);
        let encryptor =
            age::Encryptor::with_recipients(std::iter::once(&recipient as &dyn age::Recipient))
                .map_err(|e| format!("encrypting identity: {e}"))?;
        let mut w = encryptor.wrap_output(file).map_err(|e| format!("encrypting identity: {e}"))?;
        w.write_all(secret.expose_secret().as_bytes())
            .map_err(|e| format!("encrypting identity: {e}"))?;
        let mut inner = w.finish().map_err(|e| format!("encrypting identity: {e}"))?;
        inner.flush().map_err(|e| format!("encrypting identity: {e}"))?;
        inner.sync_all().map_err(|e| format!("encrypting identity: {e}"))?;
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

    fs::write(pubkey_path()?, &public).map_err(|e| format!("writing public key: {e}"))?;
    print!("{public}");
    Ok(())
}

fn cmd_pubkey() -> R<()> {
    let pk = fs::read_to_string(pubkey_path()?)
        .map_err(|_| "no identity yet — run keygen first".to_string())?;
    print!("{}", pk.trim());
    Ok(())
}

/// Report whether an identity is present and usable without unlocking:
///   "ready"  — the clear pubkey cache exists (encrypt/lookup work with no pass)
///   "locked" — identity.age exists but the pubkey cache is missing/empty, so it
///              must be regenerated with the passphrase (run `recover-pubkey`)
///   "empty"  — no identity at all (first run; run `keygen`)
/// Takes no secret, so the frontend can call it on every launch to decide what
/// to do without ever prompting unnecessarily.
fn cmd_status() -> R<()> {
    let has_pubkey = match fs::read_to_string(pubkey_path()?) {
        Ok(s) => !s.trim().is_empty(),
        Err(_) => false,
    };
    let state = if has_pubkey {
        "ready"
    } else if !identity_path()?.exists() {
        "empty"
    } else if identity_is_valid() {
        "locked" // a real encrypted identity, just missing its pubkey cache
    } else {
        "corrupt" // identity.age present but empty/unreadable — nothing to recover
    };
    print!("{state}");
    Ok(())
}

/// Decrypt identity.age with the passphrase and return the parsed identity.
/// Shared by `decrypt` and `recover-pubkey` so both use identical logic.
fn load_identity(pass_fd: i32) -> R<x25519::Identity> {
    let passphrase = read_passphrase(pass_fd)?;
    let id_file = File::open(identity_path()?)
        .map_err(|_| "no identity yet — run keygen first".to_string())?;
    let dec = age::Decryptor::new(BufReader::new(id_file))
        .map_err(|_| "your saved identity is empty or damaged and can't be read".to_string())?;
    let mut scrypt_id = age::scrypt::Identity::new(passphrase);
    scrypt_id.set_max_work_factor(SCRYPT_MAX_LOG_N);
    let mut id_reader = dec
        .decrypt(std::iter::once(&scrypt_id as &dyn age::Identity))
        .map_err(|e| match e {
            // Not a passphrase problem: say so, or the user retypes a correct
            // passphrase forever.
            age::DecryptError::ExcessiveWork { required, .. } => format!(
                "your identity file was created with a scrypt work factor of 2^{required}, \
                 above this app's limit of 2^{SCRYPT_MAX_LOG_N}"
            ),
            _ => "wrong passphrase, or the identity file is damaged".to_string(),
        })?;
    // Hold the decrypted secret-key text in zeroizing storage so it is wiped on
    // drop rather than left behind in freed heap. (age keeps the parsed scalar
    // in its own zeroizing storage; this protects the intermediate text form.)
    let mut secret_bytes: Zeroizing<Vec<u8>> = Zeroizing::new(Vec::new());
    id_reader
        .read_to_end(&mut secret_bytes)
        .map_err(|e| format!("reading identity: {e}"))?;
    let secret = std::str::from_utf8(&secret_bytes)
        .map_err(|_| "identity file is corrupt".to_string())?;
    secret
        .trim()
        .parse::<x25519::Identity>()
        .map_err(|e| format!("identity file is corrupt: {e}"))
}

/// Rebuild the clear pubkey cache from the encrypted identity. Used when the
/// pubkey file was lost (e.g. deleted) but identity.age still exists — the public
/// key is derived from the secret key, so unlocking the identity is enough to
/// restore it; no new identity is created.
fn cmd_recover_pubkey(pass_fd: i32) -> R<()> {
    let identity = load_identity(pass_fd)?;
    let public = identity.to_public().to_string();
    fs::write(pubkey_path()?, &public).map_err(|e| format!("writing public key: {e}"))?;
    print!("{public}");
    Ok(())
}

fn cmd_encrypt(recipient_strs: &[String], armor: bool, in_p: Option<&str>, out_p: Option<&str>) -> R<()> {
    if recipient_strs.is_empty() {
        return Err("no recipients given".into());
    }
    let recipients: Vec<x25519::Recipient> = recipient_strs
        .iter()
        .map(|s| s.parse::<x25519::Recipient>().map_err(|e| format!("invalid recipient '{s}': {e}")))
        .collect::<R<_>>()?;

    let encryptor =
        age::Encryptor::with_recipients(recipients.iter().map(|r| r as &dyn age::Recipient))
            .map_err(|e| format!("preparing encryption: {e}"))?;

    let reader = input_reader(in_p)?;
    match out_p {
        // Stage to a sibling temp and rename into place once complete, as
        // decrypt does. Writing straight to the destination truncated it first,
        // so `--out` naming the input destroyed the input (and reported success),
        // and a cancelled or failed run left a truncated .age file that looked
        // valid until someone tried to decrypt it.
        Some(path) => {
            let tmp = staging_path(path);
            let file = open_private_new(&tmp)?;
            let staged = encrypt_to(encryptor, armor, reader, file).and_then(|mut f| {
                f.flush().map_err(|e| format!("writing output: {e}"))?;
                f.sync_all().map_err(|e| format!("flushing output: {e}"))
            });
            commit_staged(staged, &tmp, path)
        }
        None => {
            let mut stdout = encrypt_to(encryptor, armor, reader, io::stdout())?;
            stdout.flush().map_err(|e| format!("writing output: {e}"))
        }
    }
}

/// Encrypt everything from `reader` into `out`, returning `out` once the age
/// stream and any armor are finished.
fn encrypt_to<W: Write>(
    encryptor: age::Encryptor,
    armor: bool,
    mut reader: Box<dyn Read>,
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

fn cmd_decrypt(pass_fd: i32, in_p: Option<&str>, out_p: Option<&str>) -> R<()> {
    // Recover the secret key by decrypting identity.age with the passphrase.
    let identity = load_identity(pass_fd)?;

    // Decrypt the payload. ArmoredReader transparently handles both binary and
    // ASCII-armored input, so one path covers files and pasted text.
    let armored = ArmoredReader::new(BufReader::new(input_reader(in_p)?));
    let dec = age::Decryptor::new(armored).map_err(|e| format!("reading input: {e}"))?;
    let mut stream = dec
        .decrypt(std::iter::once(&identity as &dyn age::Identity))
        .map_err(|_| "this was not encrypted to you (or the input is not an age file)".to_string())?;

    match out_p {
        // Writing plaintext to a file: stage it to a sibling temp created 0600,
        // fsync, then atomically rename into place only after the whole stream
        // has decrypted and authenticated. A truncated or tampered ciphertext
        // therefore never leaves a partial plaintext file at the destination,
        // and the destination is never a half-written file.
        Some(path) => {
            let tmp = staging_path(path);
            let mut file = open_private_new(&tmp)?;
            let staged = io::copy(&mut stream, &mut file)
                .map_err(|e| format!("decrypting: {e}"))
                .and_then(|_| file.flush().map_err(|e| format!("writing output: {e}")))
                .and_then(|_| file.sync_all().map_err(|e| format!("flushing output: {e}")));
            // Never leave partial plaintext behind on a failed decrypt.
            commit_staged(staged, &tmp, path)
        }
        // No --out: stream straight to stdout, an in-memory pipe to the caller.
        // Nothing is written to disk.
        None => {
            let mut stdout = io::stdout();
            io::copy(&mut stream, &mut stdout).map_err(|e| format!("decrypting: {e}"))?;
            stdout.flush().map_err(|e| format!("writing output: {e}"))
        }
    }
}

// ---------------------------------------------------------------------------
// Tiny argument parsing (no dependency).
// ---------------------------------------------------------------------------
fn opt_value(args: &[String], name: &str) -> Option<String> {
    args.iter().position(|a| a == name).and_then(|i| args.get(i + 1).cloned())
}
fn has_flag(args: &[String], name: &str) -> bool {
    args.iter().any(|a| a == name)
}
fn all_values(args: &[String], name: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut i = 0;
    while i < args.len() {
        if args[i] == name {
            if let Some(v) = args.get(i + 1) {
                out.push(v.clone());
                i += 2;
                continue;
            }
        }
        i += 1;
    }
    out
}
fn require_fd(args: &[String]) -> R<i32> {
    opt_value(args, "--pass-fd")
        .ok_or_else(|| "--pass-fd is required".to_string())?
        .parse::<i32>()
        .map_err(|_| "--pass-fd must be a number".into())
}
/// An optional fd flag. Present without a usable value is an error rather than
/// "absent", so a malformed --entropy-fd can never silently mean "no entropy".
fn optional_fd(args: &[String], name: &str) -> R<Option<i32>> {
    if !has_flag(args, name) {
        return Ok(None);
    }
    opt_value(args, name)
        .ok_or_else(|| format!("{name} needs a value"))?
        .parse::<i32>()
        .map(Some)
        .map_err(|_| format!("{name} must be a number"))
}

fn run() -> R<()> {
    let args: Vec<String> = env::args().skip(1).collect();
    let cmd = args.first().map(String::as_str).unwrap_or("");
    let rest = if args.is_empty() { &[][..] } else { &args[1..] };
    match cmd {
        "keygen" => cmd_keygen(require_fd(rest)?, optional_fd(rest, "--entropy-fd")?),
        "pubkey" => cmd_pubkey(),
        "status" => cmd_status(),
        "recover-pubkey" => cmd_recover_pubkey(require_fd(rest)?),
        "encrypt" => cmd_encrypt(
            &all_values(rest, "-r"),
            has_flag(rest, "--armor"),
            opt_value(rest, "--in").as_deref(),
            opt_value(rest, "--out").as_deref(),
        ),
        "decrypt" => cmd_decrypt(
            require_fd(rest)?,
            opt_value(rest, "--in").as_deref(),
            opt_value(rest, "--out").as_deref(),
        ),
        other => Err(format!(
            "unknown command '{other}' (expected keygen|pubkey|status|recover-pubkey|encrypt|decrypt)"
        )),
    }
}

fn main() -> ExitCode {
    harden_process();
    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("error: {e}");
            ExitCode::FAILURE
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bech32::FromBase32;

    fn hex(bytes: &[u8]) -> String {
        bytes.iter().map(|b| format!("{b:02x}")).collect()
    }

    #[test]
    fn derive_secret_known_answer() {
        // Computed independently with Python's hmac/hashlib (RFC 5869 HKDF).
        let os: [u8; 32] = std::array::from_fn(|i| i as u8);
        let user = [0xAB; USER_ENTROPY_LEN];
        assert_eq!(
            hex(&derive_secret(&os, &user)[..]),
            "5288c681a97744dc9bf50730353ac4adf08fdd82e74aa5181e8771c108eca924"
        );
    }

    #[test]
    fn identity_text_round_trips_to_secret_bytes() {
        let os: [u8; 32] = std::array::from_fn(|i| i as u8);
        let secret = derive_secret(&os, &[0xAB; USER_ENTROPY_LEN]);
        let identity = identity_from_secret(&secret).unwrap();
        let text = identity.to_string();
        let (hrp, data, variant) = bech32::decode(text.expose_secret()).unwrap();
        assert_eq!(hrp, AGE_SECRET_KEY_HRP);
        assert_eq!(variant, Variant::Bech32);
        assert_eq!(Vec::<u8>::from_base32(&data).unwrap(), secret.to_vec());
    }

    #[test]
    fn same_user_entropy_gives_different_keys() {
        let user = [0x42; USER_ENTROPY_LEN];
        let a = generate_identity(Some(&user)).unwrap();
        let b = generate_identity(Some(&user)).unwrap();
        assert_ne!(a.to_public().to_string(), b.to_public().to_string());
    }

    #[test]
    fn derived_identity_works_with_age() {
        let identity = generate_identity(Some(&[0x42; USER_ENTROPY_LEN])).unwrap();
        let recipient = identity.to_public();
        let encryptor =
            age::Encryptor::with_recipients(std::iter::once(&recipient as &dyn age::Recipient))
                .unwrap();
        let mut ciphertext = Vec::new();
        let mut w = encryptor.wrap_output(&mut ciphertext).unwrap();
        w.write_all(b"hello").unwrap();
        w.finish().unwrap();

        let dec = age::Decryptor::new(&ciphertext[..]).unwrap();
        let mut r = dec.decrypt(std::iter::once(&identity as &dyn age::Identity)).unwrap();
        let mut plaintext = Vec::new();
        r.read_to_end(&mut plaintext).unwrap();
        assert_eq!(plaintext, b"hello");
    }
}
