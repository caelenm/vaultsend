// VaultSend backend — the only component that ever touches the private key.
//
// It is a small, stateless command-line tool. The Python UI runs it once per
// operation. All cryptography is delegated to the `age` crate (str4d/rage); this
// file contains no custom crypto, only plumbing.
//
// Commands:
//   keygen  --pass-fd N           Create the identity (first run). Print public key.
//   pubkey                        Print this device's public key. (no secret needed)
//   encrypt -r AGE1.. [..] [--armor] [--in P] [--out P]   (no secret needed)
//   decrypt --pass-fd N [--in P] [--out P]
//
// Secrets never travel on argv (which is world-readable via /proc). The identity
// passphrase is read from a file descriptor handed over by the parent process.
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
        let _ = libc::mlockall(libc::MCL_CURRENT | libc::MCL_FUTURE);
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

fn input_reader(path: Option<&str>) -> R<Box<dyn Read>> {
    match path {
        Some(p) => Ok(Box::new(File::open(p).map_err(|e| format!("opening {p}: {e}"))?)),
        None => Ok(Box::new(io::stdin())),
    }
}
fn output_writer(path: Option<&str>) -> R<Box<dyn Write>> {
    match path {
        Some(p) => Ok(Box::new(File::create(p).map_err(|e| format!("creating {p}: {e}"))?)),
        None => Ok(Box::new(io::stdout())),
    }
}

// ---------------------------------------------------------------------------
// Commands.
// ---------------------------------------------------------------------------
fn cmd_keygen(pass_fd: i32) -> R<()> {
    let dir = data_dir()?;
    fs::create_dir_all(&dir).map_err(|e| format!("creating {}: {e}", dir.display()))?;
    let _ = fs::set_permissions(&dir, fs::Permissions::from_mode(0o700));

    // Fast, friendly check before we consume the passphrase pipe. The atomic
    // O_EXCL open below is the authoritative guard against the create race.
    if identity_path()?.exists() {
        return Err("an identity already exists; refusing to overwrite it".into());
    }
    let passphrase = read_passphrase(pass_fd)?;

    let identity = x25519::Identity::generate();
    let public = identity.to_public().to_string(); // "age1..."
    let secret = identity.to_string();             // SecretString "AGE-SECRET-KEY-1..."

    // Create the identity file atomically as 0600, refusing to clobber an
    // existing one (O_CREAT|O_EXCL). This removes the exists()/create race and
    // the window in which the file was briefly readable at default (0644) perms.
    let file = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(identity_path()?)
        .map_err(|e| match e.kind() {
            io::ErrorKind::AlreadyExists => {
                "an identity already exists; refusing to overwrite it".to_string()
            }
            _ => format!("writing identity: {e}"),
        })?;

    // Encrypt the secret key to the passphrase (age scrypt). If anything fails
    // mid-write, remove the partial file so a later keygen isn't blocked by it.
    let write_result = (move || -> R<()> {
        let encryptor = age::Encryptor::with_user_passphrase(passphrase);
        let mut w = encryptor.wrap_output(file).map_err(|e| format!("encrypting identity: {e}"))?;
        w.write_all(secret.expose_secret().as_bytes())
            .map_err(|e| format!("encrypting identity: {e}"))?;
        w.finish().map_err(|e| format!("encrypting identity: {e}"))?;
        Ok(())
    })();
    if let Err(e) = write_result {
        let _ = fs::remove_file(identity_path()?);
        return Err(e);
    }

    fs::write(pubkey_path()?, &public).map_err(|e| format!("writing public key: {e}"))?;
    println!("{public}");
    Ok(())
}

fn cmd_pubkey() -> R<()> {
    let pk = fs::read_to_string(pubkey_path()?)
        .map_err(|_| "no identity yet — run keygen first".to_string())?;
    print!("{}", pk.trim());
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

    let format = if armor { Format::AsciiArmor } else { Format::Binary };
    let armored = ArmoredWriter::wrap_output(output_writer(out_p)?, format)
        .map_err(|e| format!("preparing output: {e}"))?;
    let mut stream = encryptor.wrap_output(armored).map_err(|e| format!("encrypting: {e}"))?;

    let mut reader = input_reader(in_p)?;
    io::copy(&mut reader, &mut stream).map_err(|e| format!("encrypting: {e}"))?;
    let armored = stream.finish().map_err(|e| format!("finishing: {e}"))?;
    armored.finish().map_err(|e| format!("finishing: {e}"))?;
    Ok(())
}

fn cmd_decrypt(pass_fd: i32, in_p: Option<&str>, out_p: Option<&str>) -> R<()> {
    let passphrase = read_passphrase(pass_fd)?;

    // Recover the secret key by decrypting identity.age with the passphrase.
    let id_file = File::open(identity_path()?)
        .map_err(|_| "no identity yet — run keygen first".to_string())?;
    let dec = age::Decryptor::new(BufReader::new(id_file))
        .map_err(|e| format!("reading identity: {e}"))?;
    let scrypt_id = age::scrypt::Identity::new(passphrase);
    let mut id_reader = dec
        .decrypt(std::iter::once(&scrypt_id as &dyn age::Identity))
        .map_err(|_| "wrong passphrase, or the identity file is damaged".to_string())?;
    // Hold the decrypted secret-key text in zeroizing storage so it is wiped on
    // drop rather than left behind in freed heap. (age keeps the parsed scalar
    // in its own zeroizing storage; this protects the intermediate text form.)
    let mut secret_bytes: Zeroizing<Vec<u8>> = Zeroizing::new(Vec::new());
    id_reader
        .read_to_end(&mut secret_bytes)
        .map_err(|e| format!("reading identity: {e}"))?;
    let secret = std::str::from_utf8(&secret_bytes)
        .map_err(|_| "identity file is corrupt".to_string())?;
    let identity: x25519::Identity =
        secret.trim().parse().map_err(|e| format!("identity file is corrupt: {e}"))?;

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
            let tmp = format!("{path}.part");
            let mut file = open_private_new(&tmp)?;
            let staged = io::copy(&mut stream, &mut file)
                .map_err(|e| format!("decrypting: {e}"))
                .and_then(|_| file.flush().map_err(|e| format!("writing output: {e}")))
                .and_then(|_| file.sync_all().map_err(|e| format!("flushing output: {e}")));
            match staged {
                Ok(()) => fs::rename(&tmp, path).map_err(|e| format!("finalizing {path}: {e}")),
                Err(e) => {
                    // Never leave partial plaintext behind on a failed decrypt.
                    let _ = fs::remove_file(&tmp);
                    Err(e)
                }
            }
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

fn run() -> R<()> {
    let args: Vec<String> = env::args().skip(1).collect();
    let cmd = args.first().map(String::as_str).unwrap_or("");
    let rest = if args.is_empty() { &[][..] } else { &args[1..] };
    match cmd {
        "keygen" => cmd_keygen(require_fd(rest)?),
        "pubkey" => cmd_pubkey(),
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
        other => Err(format!("unknown command '{other}' (expected keygen|pubkey|encrypt|decrypt)")),
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
