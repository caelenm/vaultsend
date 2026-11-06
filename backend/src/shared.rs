// Receiving what someone shared from a vault: a plain age file (vault.rs `share_to`
// and `share_password`, or the Android app's), encrypted to this user's key or to a
// password. One file stays that file; anything else is a tar archive inside it. The
// same steps as the Android build's shared.rs, as commands:
//
//   share-kind     [--in P]                          "password" or "key", from the header
//   share-check    --share-pass-fd N [--in P]         unwraps the file key only, so a wrong
//                                                     password is said at once
//   share-decrypt  KEY [--in P] --out P               saves it as it is (the archive, or
//                                                     the one file)
//   share-extract  KEY [--in P] --out DIR             unpacks the archive into a new folder
//   vault-import   --dir V --pass-fd N KEY' [--in P] [--name N] [--dest D]
//                                                     adds what it holds to a vault
//
// KEY is --pass-fd N (your identity passphrase, for a share made for you) or
// --share-pass-fd N (the share's password). For vault-import --pass-fd unlocks the
// vault, so KEY' is --id-pass-fd N or --share-pass-fd N. Each also takes --progress-fd.
//
// The archive is hostile input even though age authenticated it: it came from
// whoever knew the password. tar.rs's `scan` canonicalizes every name, takes only
// files and folders, and caps sizes and counts; nothing here writes anything `scan`
// didn't accept. Plaintext is decrypted in full to a private staging folder first (so
// age has authenticated every byte before any of it is used), and unpacking builds
// the whole tree in private storage before any of it reaches the folder the user
// chose, under a staging name renamed into place last. Everything streams, a chunk at
// a time.
//
// Staging lives in $XDG_DATA_HOME/vaultsend/staging (0700), a folder per run, each
// held under an flock for as long as its process lives. A run that is killed can't
// clean up after itself, so every new run first removes any folder there whose lock
// it can take: the kernel releases a dead process's locks, and never a live one's.

use std::fs::{self, File, OpenOptions};
use std::io::{self, BufReader, Read, Seek, SeekFrom, Write};
use std::iter::once;
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};

use age::armor::ArmoredReader;
use age::secrecy::SecretString;
use age::x25519;
use age::DecryptError;
use rand::RngCore;
use zeroize::Zeroizing;

use crate::tar::{self, Item, Limits, Scan, LIMITS};
use crate::vault::{
    parent_of, print_out, private_dir, sync_dir, valid_vault_path, write_atomic, Opts, Plan, Progress, Sources,
    Vault, CANCELLED,
};
use crate::{data_dir, load_identity, open_private_new, read_passphrase, staging_path, R, SCRYPT_LOG_N};

/// What opens a shared file.
pub(crate) enum Key {
    /// This user's own key: a share made for them.
    Identity(x25519::Identity),
    /// A password share. Opening one allows scrypt at SCRYPT_LOG_N (2^18), what
    /// VaultSend makes them with, and no more: a file asking for more could otherwise
    /// cost gigabytes and minutes. (identity.age keeps its own, higher limit.)
    Password(age::scrypt::Identity),
}

impl Key {
    pub(crate) fn password(password: SecretString) -> Key {
        let mut identity = age::scrypt::Identity::new(password);
        identity.set_max_work_factor(SCRYPT_LOG_N);
        Key::Password(identity)
    }
}

/// A copy buffer: everything streams through one of these.
const CHUNK: usize = 64 << 10;

fn decryptor<Rd: Read>(input: Rd) -> R<age::Decryptor<impl Read>> {
    age::Decryptor::new(ArmoredReader::new(BufReader::new(input)))
        .map_err(|_| "this isn't a file VaultSend can decrypt (not an age file)".to_string())
}

/// "password" for a file encrypted to a password, "key" for one encrypted to people.
pub(crate) fn age_kind<Rd: Read>(input: Rd) -> R<&'static str> {
    Ok(if decryptor(input)?.is_scrypt() { "password" } else { "key" })
}

/// The decrypted stream. For a password, scrypt runs here.
fn open_stream<'a, Rd: Read + 'a>(input: Rd, key: &Key) -> R<Box<dyn Read + 'a>> {
    let dec = decryptor(input)?;
    let stream = match key {
        Key::Password(identity) => {
            if !dec.is_scrypt() {
                return Err("this file was encrypted for people, not with a password".into());
            }
            dec.decrypt(once(identity as &dyn age::Identity)).map_err(|e| match e {
                DecryptError::ExcessiveWork { required, .. } => format!(
                    "this file asks for more work to decrypt (scrypt 2^{required}) than VaultSend allows (2^{SCRYPT_LOG_N})"
                ),
                _ => "wrong password, or the file is damaged".to_string(),
            })?
        }
        Key::Identity(identity) => {
            if dec.is_scrypt() {
                return Err("this file needs its password".into());
            }
            dec.decrypt(once(identity as &dyn age::Identity))
                .map_err(|_| "this was not encrypted to you (or the input is not an age file)".to_string())?
        }
    };
    Ok(Box::new(stream))
}

/// Whether `key` (a password) opens this file. Only the file key is unwrapped;
/// nothing is decrypted or written.
pub(crate) fn check_password<Rd: Read>(input: Rd, key: &Key) -> R<()> {
    if !matches!(key, Key::Password(_)) {
        return Err("no password was given".into());
    }
    open_stream(input, key).map(|_| ())
}

// ---------------------------------------------------------------------------
// Private staging.
// ---------------------------------------------------------------------------

/// Where the commands stage: the data dir, private to the user.
fn staging_root() -> R<String> {
    let root = data_dir()?.join("staging");
    root.to_str().map(str::to_string).ok_or_else(|| format!("{}: not valid UTF-8", root.display()))
}

#[cfg(target_os = "linux")]
fn flock(file: &File, op: libc::c_int) -> bool {
    use std::os::unix::io::AsRawFd;
    // SAFETY: flock only reads the descriptor, which `file` keeps open.
    unsafe { libc::flock(file.as_raw_fd(), op) == 0 }
}

/// This run's own private folder under a staging root, removed with everything in it
/// when dropped. Held under an exclusive flock while this process lives, so another
/// run can tell a killed run's leftovers from a live run's work.
pub(crate) struct Staging {
    path: PathBuf,
    _lock: Option<File>,
}

impl Staging {
    pub(crate) fn new(root: &str) -> R<Staging> {
        private_dir(root, true).or_else(|e| match fs::symlink_metadata(root) {
            Ok(meta) if meta.is_dir() => Ok(()),
            _ => Err(e),
        })?;
        // Created by us, but check: never stage through a link to somewhere else.
        if !fs::symlink_metadata(root).is_ok_and(|m| m.is_dir()) {
            return Err(format!("{root} is not a folder"));
        }
        let mut raw = [0u8; 8];
        rand::rngs::OsRng.fill_bytes(&mut raw);
        let name = format!("{}-{}", std::process::id(), raw.iter().map(|b| format!("{b:02x}")).collect::<String>());
        let path = Path::new(root).join(name);
        let path_str = path.to_str().ok_or("the staging path is not valid UTF-8")?.to_string();

        #[cfg(target_os = "linux")]
        {
            // The root's lock keeps a sweep and a new run's folder apart: a folder is
            // never seen between being made and being locked.
            let root_lock = OpenOptions::new()
                .create(true)
                .truncate(false)
                .write(true)
                .mode(0o600)
                .custom_flags(libc::O_NOFOLLOW)
                .open(Path::new(root).join(".lock"))
                .map_err(|e| format!("locking {root}: {e}"))?;
            if !flock(&root_lock, libc::LOCK_EX) {
                return Err(format!("locking {root}: {}", io::Error::last_os_error()));
            }
            sweep(root);
            private_dir(&path_str, false)?;
            let own = File::open(&path).map_err(|e| format!("{}: {e}", path.display()))?;
            if !flock(&own, libc::LOCK_EX | libc::LOCK_NB) {
                let _ = fs::remove_dir(&path);
                return Err(format!("locking {}: {}", path.display(), io::Error::last_os_error()));
            }
            Ok(Staging { path, _lock: Some(own) })
        }
        #[cfg(not(target_os = "linux"))]
        {
            private_dir(&path_str, false)?;
            Ok(Staging { path, _lock: None })
        }
    }

    fn path(&self, name: &str) -> String {
        self.path.join(name).to_string_lossy().into_owned()
    }
}

impl Drop for Staging {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.path);
    }
}

/// Remove what killed runs left under `root`: every folder whose lock is free. The
/// caller holds the root's lock. Only VaultSend writes here, so anything that isn't a
/// run's folder is removed too; file_type doesn't follow a link, so one is removed,
/// never entered.
#[cfg(target_os = "linux")]
fn sweep(root: &str) {
    let Ok(entries) = fs::read_dir(root) else { return };
    for entry in entries.flatten() {
        if entry.file_name() == ".lock" {
            continue;
        }
        if entry.file_type().is_ok_and(|t| t.is_dir()) {
            let Ok(dir) = File::open(entry.path()) else { continue };
            if flock(&dir, libc::LOCK_EX | libc::LOCK_NB) {
                let _ = fs::remove_dir_all(entry.path());
            }
        } else {
            let _ = fs::remove_file(entry.path());
        }
    }
}

/// Plaintext staged in a run's folder (0600), removed when dropped.
struct Staged {
    path: String,
    file: File,
    len: u64,
}

impl Drop for Staged {
    fn drop(&mut self) {
        let _ = fs::remove_file(&self.path);
    }
}

/// Copy exactly `size` bytes, a chunk at a time, counting and asking about Cancel.
fn copy_exact(from: &mut dyn Read, to: &mut dyn Write, size: u64, progress: &Progress, what: &str) -> R<()> {
    let mut buf = Zeroizing::new(vec![0u8; CHUNK]);
    let mut left = size;
    while left > 0 {
        if progress.cancelled() {
            return Err(CANCELLED.into());
        }
        let want = left.min(CHUNK as u64) as usize;
        let n = match from.read(&mut buf[..want]) {
            Ok(0) => return Err(format!("{what} ended early")),
            Ok(n) => n,
            Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
            Err(e) => return Err(format!("reading {what}: {e}")),
        };
        to.write_all(&buf[..n]).map_err(|e| format!("writing {what}: {e}"))?;
        progress.advance(n as u64);
        left -= n as u64;
    }
    Ok(())
}

/// Decrypt all of `input` to a private staging file, refusing more than `cap` bytes.
/// Only once this returns has age authenticated every byte, the last chunk included.
fn decrypt_to_staging<Rd: Read>(staging: &Staging, key: &Key, input: Rd, cap: u64, progress: &Progress) -> R<Staged> {
    let path = staging.path("plain");
    let file = open_private_new(&path)?;
    // Removed on drop from here on, whatever happens below.
    let mut staged = Staged { path, file, len: 0 };
    let mut stream = open_stream(input, key)?;
    let mut buf = Zeroizing::new(vec![0u8; CHUNK]);
    loop {
        if progress.cancelled() {
            return Err(CANCELLED.into());
        }
        let n = match stream.read(&mut buf[..]) {
            Ok(n) => n,
            Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
            Err(e) => return Err(format!("decrypting: {e}")),
        };
        if n == 0 {
            break;
        }
        staged.len += n as u64;
        if staged.len > cap {
            return Err("this file is larger than VaultSend will unpack".into());
        }
        staged.file.write_all(&buf[..n]).map_err(|e| format!("staging: {e}"))?;
        progress.advance(n as u64);
    }
    staged.file.sync_all().map_err(|e| format!("staging: {e}"))?;
    // Written through a write-only descriptor; read back through a new one.
    staged.file = File::open(&staged.path).map_err(|e| format!("reading the staged file: {e}"))?;
    Ok(staged)
}

/// Save a shared file as it is, to `out`: staged privately and authenticated in full,
/// then written to `<out>.vaultsend-part` and renamed into place.
pub(crate) fn decrypt_file_to<Rd: Read>(
    staging_root: &str,
    key: &Key,
    input: Rd,
    input_len: u64,
    out: &str,
    progress: &Progress,
) -> R<()> {
    // Decrypting, then writing: about the size of the file each time.
    progress.start(input_len.saturating_mul(2));
    let staging = Staging::new(staging_root)?;
    let mut staged = decrypt_to_staging(&staging, key, input, u64::MAX, progress)?;
    let len = staged.len;
    write_atomic(out, |mut file| {
        copy_exact(&mut staged.file, &mut file, len, progress, out)?;
        Ok(file)
    })?;
    sync_dir(parent_of(out));
    Ok(())
}

/// The most an archive can be: its files plus a header block per entry, generously.
fn archive_cap(limits: &Limits) -> u64 {
    limits.max_total.saturating_add((limits.max_entries as u64).saturating_mul(4 * 512)).saturating_add(1 << 20)
}

/// Whether the staged plaintext is a tar archive.
fn is_archive(staged: &mut Staged) -> R<bool> {
    if staged.len < 1024 {
        return Ok(false);
    }
    let mut first = [0u8; 512];
    staged.file.seek(SeekFrom::Start(0)).map_err(|e| e.to_string())?;
    staged.file.read_exact(&mut first).map_err(|e| e.to_string())?;
    Ok(tar::looks_like_tar(&first))
}

fn scan_staged(staged: &mut Staged, limits: &Limits, progress: &Progress) -> R<Scan> {
    if !is_archive(staged)? {
        return Err("this file isn't an archive of files and folders".into());
    }
    tar::scan(&mut staged.file, staged.len, limits, &|| progress.check().is_err())
}

/// A new file, private to the user, that must not exist yet: on a case-insensitive
/// disk "A" and "a" are one file, and one would otherwise silently go missing.
fn create_new(path: &str) -> R<File> {
    OpenOptions::new().write(true).create_new(true).mode(0o600).open(path).map_err(|e| match e.kind() {
        io::ErrorKind::AlreadyExists => format!("{path}: two names in the archive collide on this disk"),
        _ => format!("creating {path}: {e}"),
    })
}

/// Write what `scan` holds into `root`, a new folder. `open` gives each file's bytes,
/// at its start. Every path is checked once more before anything is made.
fn write_items(root: &str, scan: &Scan, open: &mut dyn FnMut(&str, u64) -> R<File>, progress: &Progress) -> R<()> {
    private_dir(root, false)?;
    // In order, so every folder is made before what's in it.
    for (rel, item) in &scan.items {
        progress.check()?;
        if !valid_vault_path(rel) || tar::canonical_entry_path(rel)?.as_deref() != Some(rel.as_str()) {
            return Err(format!("refusing to write outside the folder: {rel}"));
        }
        let path = format!("{root}/{rel}");
        match *item {
            Item::Dir => private_dir(&path, false)?,
            Item::File { offset, size } => {
                let mut source = open(rel, offset)?;
                let mut out = create_new(&path)?;
                copy_exact(&mut source, &mut out, size, progress, &path)?;
                out.sync_all().map_err(|e| format!("flushing {path}: {e}"))?;
            }
        }
    }
    sync_dir(root);
    Ok(())
}

/// Unpack a shared archive into `out`, a new folder. Returns how many entries were
/// skipped (links and the like).
///
/// In three steps, each streamed: decrypt all of it to a private staging file; build
/// the whole tree in a private folder; only then copy that into `<out>.vaultsend-part`
/// and rename it to `out`. So `out` is only ever absent or complete, and the user's
/// folder sees nothing from an archive that fails anywhere.
#[allow(clippy::too_many_arguments)]
pub(crate) fn extract_archive<Rd: Read>(
    staging_root: &str,
    key: &Key,
    input: Rd,
    input_len: u64,
    out: &str,
    limits: &Limits,
    progress: &Progress,
) -> R<usize> {
    let name = Path::new(out).file_name().and_then(|n| n.to_str()).filter(|n| valid_vault_path(n));
    if name.is_none() {
        return Err(format!("--out must name a new folder: {out}"));
    }
    if fs::symlink_metadata(out).is_ok() {
        return Err(format!("{out} already exists; choose a new folder name"));
    }
    if !fs::metadata(parent_of(out)).is_ok_and(|m| m.is_dir()) {
        return Err(format!("{} is not a folder", parent_of(out)));
    }
    // Decrypting, then writing twice: about the size of the file each time.
    progress.start(input_len.saturating_mul(3));
    let staging = Staging::new(staging_root)?;
    let mut staged = decrypt_to_staging(&staging, key, input, archive_cap(limits), progress)?;
    let scan = scan_staged(&mut staged, limits, progress)?;

    let private = staging.path("tree");
    let archive = &staged.file;
    write_items(&private, &scan, &mut |_, offset| {
        let mut f = archive.try_clone().map_err(|e| e.to_string())?;
        f.seek(SeekFrom::Start(offset)).map_err(|e| format!("reading the archive: {e}"))?;
        Ok(f)
    }, progress)?;
    drop(staged); // the archive's plaintext isn't needed any more

    let tmp = staging_path(out);
    let _ = fs::remove_dir_all(&tmp); // a killed run's leftovers; the suffix is ours
    let copied = write_items(&tmp, &scan, &mut |rel, _| {
        let path = Path::new(&private).join(rel);
        let meta = fs::symlink_metadata(&path).map_err(|e| format!("{}: {e}", path.display()))?;
        if !meta.is_file() {
            return Err(format!("{}: not a regular file", path.display()));
        }
        File::open(&path).map_err(|e| format!("{}: {e}", path.display()))
    }, progress)
    .and_then(|()| {
        progress.check()?;
        fs::rename(&tmp, out).map_err(|e| format!("finalizing {out}: {e}"))
    });
    if copied.is_err() {
        let _ = fs::remove_dir_all(&tmp);
    }
    copied?;
    sync_dir(parent_of(out));
    Ok(scan.skipped)
}

/// A shared archive, staged and scanned, as what a vault add adds. Each file is read
/// straight from the staged archive into its blob, a chunk at a time.
struct ArchiveSources {
    file: File,
    plan: Vec<(String, Option<usize>)>,
    files: Vec<(u64, u64)>,
    skipped: usize,
}

impl ArchiveSources {
    fn from_scan(file: File, scan: &Scan) -> ArchiveSources {
        let mut plan = Vec::new();
        let mut files = Vec::new();
        for (path, item) in &scan.items {
            match *item {
                Item::Dir => plan.push((path.clone(), None)),
                Item::File { offset, size } => {
                    files.push((offset, size));
                    plan.push((path.clone(), Some(files.len() - 1)));
                }
            }
        }
        ArchiveSources { file, plan, files, skipped: scan.skipped }
    }
}

impl Sources for ArchiveSources {
    fn plan(&self) -> R<Plan> {
        Ok((self.plan.clone(), self.skipped))
    }
    fn open(&self, index: usize) -> R<Box<dyn Read>> {
        let (offset, size) = self.files[index];
        let mut f = self.file.try_clone().map_err(|e| e.to_string())?;
        f.seek(SeekFrom::Start(offset)).map_err(|e| format!("reading the archive: {e}"))?;
        Ok(Box::new(f.take(size)))
    }
    fn size(&self, index: usize) -> u64 {
        self.files[index].1
    }
}

/// Add what a shared file holds to `vault`, under `dest` (its top if None): an
/// archive's files and folders, or a single file as `single_name`. All of it or none:
/// the vault's own write protocol commits once, at the end, and a failure or Cancel
/// before then leaves the vault as it was.
#[allow(clippy::too_many_arguments)]
pub(crate) fn import_archive<Rd: Read>(
    vault: &Vault,
    staging_root: &str,
    key: &Key,
    input: Rd,
    input_len: u64,
    single_name: Option<&str>,
    dest: Option<&str>,
    limits: &Limits,
) -> R<usize> {
    let progress = &vault.progress;
    progress.start(input_len.saturating_mul(2));
    let staging = Staging::new(staging_root)?;
    let mut staged = decrypt_to_staging(&staging, key, input, archive_cap(limits), progress)?;
    let file = staged.file.try_clone().map_err(|e| e.to_string())?;
    let sources = if is_archive(&mut staged)? {
        let scan = tar::scan(&mut staged.file, staged.len, limits, &|| progress.check().is_err())?;
        ArchiveSources::from_scan(file, &scan)
    } else {
        let name = single_name.ok_or("this share holds one file: give it a name with --name")?;
        if !valid_vault_path(name) || name.contains('/') {
            return Err(format!("not a usable file name: {name}"));
        }
        ArchiveSources { file, plan: vec![(name.to_string(), Some(0))], files: vec![(0, staged.len)], skipped: 0 }
    };
    if sources.plan.is_empty() {
        return Err("there is nothing in this archive to import".into());
    }
    vault.add_from(&sources, dest, false)?;
    Ok(sources.skipped)
}

// ---------------------------------------------------------------------------
// Commands.
// ---------------------------------------------------------------------------

/// The input: --in, or stdin. And its length, for the percentage only (0 for a pipe).
fn input(o: &Opts) -> R<(Box<dyn Read>, u64)> {
    match o.get("--in") {
        Some(p) => {
            let f = File::open(p).map_err(|e| format!("opening {p}: {e}"))?;
            let meta = f.metadata().map_err(|e| format!("{p}: {e}"))?;
            if !meta.is_file() {
                return Err(format!("{p} is not a regular file"));
            }
            Ok((Box::new(f), meta.len()))
        }
        None => Ok((Box::new(io::stdin()), 0)),
    }
}

/// The key a share opens with: exactly one of `identity_opt` (the identity
/// passphrase) and --share-pass-fd (the share's password).
fn key_from(o: &Opts, identity_opt: &str) -> R<Key> {
    match (o.fd(identity_opt)?, o.fd("--share-pass-fd")?) {
        (Some(_), Some(_)) => Err(format!("give {identity_opt} or --share-pass-fd, not both")),
        (Some(fd), None) => Ok(Key::Identity(load_identity(fd)?)),
        (None, Some(fd)) => Ok(Key::password(read_passphrase(fd)?)),
        (None, None) => Err(format!("{identity_opt} or --share-pass-fd is required")),
    }
}

/// `vault-import`, for vault.rs's `run`, which has opened the vault.
pub(crate) fn import_cli(vault: &Vault, o: &Opts) -> R<usize> {
    let key = key_from(o, "--id-pass-fd")?;
    let (reader, len) = input(o)?;
    // A share of one file goes in under its own name, less the .age.
    let derived = o.get("--in").and_then(|p| Path::new(p).file_name()?.to_str()?.strip_suffix(".age"));
    let name = o.get("--name").or(derived);
    import_archive(vault, &staging_root()?, &key, reader, len, name, o.get("--dest"), &LIMITS)
}

pub(crate) fn run(cmd: &str, args: &[String]) -> R<()> {
    let o = crate::vault::parse_opts(args)?;
    match cmd {
        "share-kind" => print_out(age_kind(input(&o)?.0)?),
        "share-check" => {
            let fd = o.fd("--share-pass-fd")?.ok_or("--share-pass-fd is required")?;
            check_password(input(&o)?.0, &Key::password(read_passphrase(fd)?))
        }
        "share-decrypt" => {
            let key = key_from(&o, "--pass-fd")?;
            let (reader, len) = input(&o)?;
            decrypt_file_to(&staging_root()?, &key, reader, len, o.need("--out")?, &o.progress()?)
        }
        "share-extract" => {
            let key = key_from(&o, "--pass-fd")?;
            let (reader, len) = input(&o)?;
            let skipped = extract_archive(&staging_root()?, &key, reader, len, o.need("--out")?, &LIMITS, &o.progress()?)?;
            if skipped > 0 {
                eprintln!("warning: skipped {skipped} item(s) that are not regular files or folders");
            }
            Ok(())
        }
        other => Err(format!("unknown command '{other}'")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::encrypt_to;
    use std::cell::Cell;
    use std::rc::Rc;
    use std::sync::atomic::{AtomicU32, Ordering};

    const PW: &str = "a shared password";

    struct Temp(PathBuf);

    impl Temp {
        fn new() -> Temp {
            static NEXT: AtomicU32 = AtomicU32::new(0);
            let n = NEXT.fetch_add(1, Ordering::SeqCst);
            let p = std::env::temp_dir().join(format!("vs-shared-{}-{n}", std::process::id()));
            let _ = fs::remove_dir_all(&p);
            fs::create_dir_all(&p).unwrap();
            Temp(p)
        }
        fn path(&self, rel: &str) -> String {
            self.0.join(rel).to_str().unwrap().to_string()
        }
        fn write(&self, rel: &str, data: &[u8]) {
            let p = self.0.join(rel);
            fs::create_dir_all(p.parent().unwrap()).unwrap();
            fs::write(p, data).unwrap();
        }
        fn dir(&self, rel: &str) -> String {
            let p = self.path(rel);
            fs::create_dir_all(&p).unwrap();
            p
        }
    }

    impl Drop for Temp {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    fn pw(text: &str) -> Key {
        Key::password(SecretString::from(text.to_string()))
    }

    /// A vault held open in memory, as vault.rs's tests make one.
    fn quick_vault(dir: &str) -> Vault {
        let throwaway = x25519::Identity::generate().to_public();
        let wrap = age::Encryptor::with_recipients(once(&throwaway as &dyn age::Recipient)).unwrap();
        Vault::create(dir, "self", wrap).unwrap()
    }

    /// A vault holding a small tree, and that tree shared with PW into `share.tar.age`.
    fn shared_tree(t: &Temp) -> (Vault, String) {
        t.write("src/tree/a.txt", b"alpha");
        t.write("src/tree/sub/b.bin", &[7u8; 200_000]);
        t.write("src/tree/sub/empty.txt", b"");
        t.write("src/tree/spaced name ü.txt", b"names survive");
        fs::create_dir_all(t.path("src/tree/empty-folder")).unwrap();
        let v = quick_vault(&t.path("v.vsvault"));
        v.add(&[t.path("src/tree")], None, false).unwrap();
        v.share_password(&["/"], SecretString::from(PW.to_string()), &t.path("share.tar.age")).unwrap();
        (v, t.path("share.tar.age"))
    }

    fn open(path: &str) -> File {
        File::open(path).unwrap()
    }

    fn len(path: &str) -> u64 {
        fs::metadata(path).unwrap().len()
    }

    /// No staged plaintext or private tree is left under the staging root.
    fn assert_no_staging(root: &str) {
        let left: Vec<_> = match fs::read_dir(root) {
            Ok(entries) => entries.flatten().map(|e| e.file_name()).filter(|n| n != ".lock").collect(),
            Err(_) => Vec::new(),
        };
        assert!(left.is_empty(), "left behind: {left:?}");
    }

    fn encrypt_with(pw: &str, plain: &[u8], out: &str, log_n: u8) {
        let mut r = age::scrypt::Recipient::new(SecretString::from(pw.to_string()));
        r.set_work_factor(log_n);
        let enc = age::Encryptor::with_recipients(once(&r as &dyn age::Recipient)).unwrap();
        encrypt_to(enc, false, Box::new(io::Cursor::new(plain.to_vec())), File::create(out).unwrap()).unwrap();
    }

    fn none() -> Progress {
        Progress::default()
    }

    fn generation(v: &Vault) -> String {
        v.listing().unwrap().lines().next().unwrap().to_string()
    }

    #[test]
    fn a_password_share_is_told_apart_checked_and_saved_as_is() {
        let t = Temp::new();
        let data = t.path("staging");
        let (v, share) = shared_tree(&t);
        assert_eq!(age_kind(open(&share)).unwrap(), "password");
        assert!(check_password(open(&share), &pw("not the password")).unwrap_err().contains("wrong password"));
        check_password(open(&share), &pw(PW)).unwrap();
        let me = x25519::Identity::generate();
        let mine = Key::Identity(me.clone());
        assert!(check_password(open(&share), &mine).is_err());
        let out = t.path("saved.tar");
        assert!(decrypt_file_to(&data, &mine, open(&share), len(&share), &out, &none()).unwrap_err().contains("needs its password"));
        assert!(!Path::new(&out).exists());

        decrypt_file_to(&data, &pw(PW), open(&share), len(&share), &out, &none()).unwrap();
        let tar_bytes = fs::read(&out).unwrap();
        assert!(tar::looks_like_tar(&tar_bytes[..512]));
        let scan = tar::scan(&mut io::Cursor::new(&tar_bytes), tar_bytes.len() as u64, &LIMITS, &|| false).unwrap();
        assert!(scan.items.contains_key("tree/sub/b.bin") && scan.items.contains_key("tree/empty-folder"));
        assert_no_staging(&data);

        // A key share says so, and opens with the key it was made for.
        let key_share = t.path("key.age");
        v.share_to(&["tree/a.txt"], &[&me.to_public().to_string()], &key_share).unwrap();
        assert_eq!(age_kind(open(&key_share)).unwrap(), "key");
        assert!(check_password(open(&key_share), &pw(PW)).unwrap_err().contains("for people"));
        let other = Key::Identity(x25519::Identity::generate());
        let one = t.path("one.txt");
        assert!(decrypt_file_to(&data, &other, open(&key_share), len(&key_share), &one, &none()).unwrap_err().contains("not encrypted to you"));
        decrypt_file_to(&data, &mine, open(&key_share), len(&key_share), &one, &none()).unwrap();
        assert_eq!(fs::read(&one).unwrap(), b"alpha");
        assert!(age_kind(&b"not an age file at all"[..]).is_err());
        assert_no_staging(&data);
    }

    /// The share limit is 2^18, what VaultSend makes; a file asking for more is refused
    /// before scrypt runs. (identity.age keeps its own limit of 2^22.)
    #[test]
    fn opening_a_share_allows_no_more_scrypt_work_than_2_18() {
        let t = Temp::new();
        let data = t.path("staging");
        let costly = t.path("costly.age");
        encrypt_with(PW, b"x", &costly, SCRYPT_LOG_N + 1);
        let err = check_password(open(&costly), &pw(PW)).unwrap_err();
        assert!(err.contains("more work") && err.contains("2^19"), "{err}");
        let out = t.dir("out");
        let err = extract_archive(&data, &pw(PW), open(&costly), len(&costly), &format!("{out}/x"), &LIMITS, &none());
        assert!(err.unwrap_err().contains("more work"));
        let fresh = quick_vault(&t.path("fresh.vsvault"));
        let err = import_archive(&fresh, &data, &pw(PW), open(&costly), 0, Some("x"), None, &LIMITS).unwrap_err();
        assert!(err.contains("more work"), "{err}");
        const _: () = assert!(crate::SCRYPT_MAX_LOG_N > SCRYPT_LOG_N, "identity files keep the higher limit");
    }

    #[test]
    fn an_archive_extracts_into_a_new_folder_with_everything_in_it() {
        let t = Temp::new();
        let data = t.path("staging");
        let (_v, share) = shared_tree(&t);
        let out = t.dir("out");
        let shared = format!("{out}/Shared");
        let skipped = extract_archive(&data, &pw(PW), open(&share), len(&share), &shared, &LIMITS, &none()).unwrap();
        assert_eq!(skipped, 0);
        let root = format!("{shared}/tree");
        assert_eq!(fs::read(format!("{root}/a.txt")).unwrap(), b"alpha");
        assert_eq!(fs::read(format!("{root}/sub/b.bin")).unwrap(), vec![7u8; 200_000]);
        assert_eq!(fs::read(format!("{root}/sub/empty.txt")).unwrap(), b"");
        assert_eq!(fs::read(format!("{root}/spaced name ü.txt")).unwrap(), b"names survive");
        assert!(Path::new(&format!("{root}/empty-folder")).is_dir());
        assert!(!Path::new(&staging_path(&shared)).exists());
        assert_no_staging(&data);

        // Never over an existing name.
        let again = extract_archive(&data, &pw(PW), open(&share), len(&share), &shared, &LIMITS, &none());
        assert!(again.unwrap_err().contains("already exists"));
        // A wrong password writes nothing.
        let other = format!("{out}/Other");
        let wrong = extract_archive(&data, &pw("wrong password!"), open(&share), len(&share), &other, &LIMITS, &none());
        assert!(wrong.unwrap_err().contains("wrong password"));
        assert!(!Path::new(&other).exists());
        // One file that isn't an archive is no folder.
        let single = t.path("photo.jpg.age");
        encrypt_with(PW, &[1u8; 5000], &single, 2);
        let err = extract_archive(&data, &pw(PW), open(&single), len(&single), &other, &LIMITS, &none());
        assert!(err.unwrap_err().contains("isn't an archive"));
        assert!(!Path::new(&other).exists());
        assert_no_staging(&data);
    }

    #[test]
    fn an_archive_imports_into_a_vault_as_it_was() {
        let t = Temp::new();
        let data = t.path("staging");
        let (v, share) = shared_tree(&t);
        let fresh = quick_vault(&t.path("fresh.vsvault"));
        import_archive(&fresh, &data, &pw(PW), open(&share), len(&share), None, None, &LIMITS).unwrap();
        let body = |l: String| l.split_once('\n').unwrap().1.to_string();
        assert_eq!(body(fresh.listing().unwrap()), body(v.listing().unwrap()));
        fresh.check().unwrap();
        let out = t.path("check");
        fresh.extract("tree/sub/b.bin", &out).unwrap();
        assert_eq!(fs::read(&out).unwrap(), vec![7u8; 200_000]);
        assert_no_staging(&data);

        // Again, into a folder: --dest.
        import_archive(&fresh, &data, &pw(PW), open(&share), len(&share), None, Some("again/here"), &LIMITS).unwrap();
        assert!(fresh.listing().unwrap().contains("F 5 again/here/tree/a.txt\n"));
        // Again at the top: it's all there already, so nothing changes.
        let before = fresh.listing().unwrap();
        let err = import_archive(&fresh, &data, &pw(PW), open(&share), len(&share), None, None, &LIMITS).unwrap_err();
        assert!(err.contains("already exists"), "{err}");
        assert_eq!(fresh.listing().unwrap(), before);

        // One file that isn't an archive goes in under the name given.
        let single = t.path("photo.jpg.age");
        encrypt_with(PW, b"just one file", &single, 2);
        let one = quick_vault(&t.path("one.vsvault"));
        let err = import_archive(&one, &data, &pw(PW), open(&single), 0, None, None, &LIMITS).unwrap_err();
        assert!(err.contains("--name"), "{err}");
        import_archive(&one, &data, &pw(PW), open(&single), len(&single), Some("photo.jpg"), None, &LIMITS).unwrap();
        assert_eq!(body(one.listing().unwrap()), "F 13 photo.jpg\n");
        for bad in ["../x", "a/b", "", ".."] {
            assert!(import_archive(&one, &data, &pw(PW), open(&single), 0, Some(bad), None, &LIMITS).is_err(), "{bad}");
        }
        assert_no_staging(&data);
    }

    #[test]
    fn cancel_leaves_no_folder_no_staging_and_an_unchanged_vault() {
        let t = Temp::new();
        let data = t.path("staging");
        let (_v, share) = shared_tree(&t);
        let out = t.dir("out");
        let stop = Progress::default().with_cancel(|| true);
        let err = extract_archive(&data, &pw(PW), open(&share), len(&share), &format!("{out}/Shared"), &LIMITS, &stop).unwrap_err();
        assert_eq!(err, CANCELLED);
        assert!(fs::read_dir(&out).unwrap().next().is_none(), "nothing in the folder");
        assert_no_staging(&data);

        // Cancelled during the second copy, into the user's folder, after the private
        // tree: count how often a whole run asks, then say yes near its end.
        let asked = Rc::new(Cell::new(0));
        let count = asked.clone();
        let counting = Progress::default().with_cancel(move || {
            count.set(count.get() + 1);
            false
        });
        extract_archive(&data, &pw(PW), open(&share), len(&share), &format!("{out}/Count"), &LIMITS, &counting).unwrap();
        fs::remove_dir_all(format!("{out}/Count")).unwrap();
        let total = asked.get();
        let count = Rc::new(Cell::new(0));
        let seen = count.clone();
        let late = Progress::default().with_cancel(move || {
            seen.set(seen.get() + 1);
            seen.get() >= total - 2
        });
        let err = extract_archive(&data, &pw(PW), open(&share), len(&share), &format!("{out}/Late"), &LIMITS, &late);
        assert_eq!(err.unwrap_err(), CANCELLED);
        assert!(count.get() > total / 2, "stopped late: {} of {total}", count.get());
        assert!(fs::read_dir(&out).unwrap().next().is_none(), "nothing in the folder");
        assert_no_staging(&data);

        // Import: cancelled at once, and on the last ask of a whole run, once every blob
        // but the last is written. Count the asks first, as above.
        let asks_in = |cancel_at: usize, name: &str| {
            let mut v = quick_vault(&t.path(name));
            let before = v.listing().unwrap();
            let asks = Rc::new(Cell::new(0usize));
            let n = asks.clone();
            v.progress = Rc::new(Progress::default().with_cancel(move || {
                n.set(n.get() + 1);
                n.get() >= cancel_at
            }));
            let r = import_archive(&v, &data, &pw(PW), open(&share), len(&share), None, None, &LIMITS);
            v.progress = Rc::new(Progress::default());
            (v, before, r, asks.get())
        };
        let (_, _, r, total) = asks_in(usize::MAX, "count.vsvault");
        r.unwrap();
        for (cancel_at, name) in [(1, "first.vsvault"), (total, "last.vsvault")] {
            let (v, before, r, _) = asks_in(cancel_at, name);
            let err = r.unwrap_err();
            assert!(err.contains(CANCELLED), "{err}");
            assert_eq!(v.listing().unwrap(), before);
            assert_eq!(generation(&v), "generation 0");
            v.check().unwrap();
            let mut blobs = Vec::new();
            walk(Path::new(&t.path(&format!("{name}/blobs"))), &mut blobs);
            assert!(blobs.iter().all(|p| p.is_dir()), "the cancelled run's blobs are collected: {blobs:?}");
            // Late, blobs were written first (their folders stay); at once, none were.
            assert_eq!(!blobs.is_empty(), cancel_at == total, "{name}: {blobs:?}");
            assert_no_staging(&data);
        }
        // The late one really was cancelled while writing blobs.
        assert!(total > 8, "asked {total} times");
    }

    /// A killed run can't clean up: the next run removes its folder, but never one a
    /// live run still holds.
    #[test]
    fn a_killed_runs_staging_is_swept_and_a_live_ones_is_not() {
        let t = Temp::new();
        let root = t.path("staging");
        let live = Staging::new(&root).unwrap();
        fs::write(live.path("plain"), b"live plaintext").unwrap();
        // A dead run's folder: nothing holds its lock.
        let dead = format!("{root}/12345-dead");
        private_dir(&dead, false).unwrap();
        fs::write(format!("{dead}/plain"), b"left by a killed run").unwrap();
        fs::write(format!("{root}/stray"), b"x").unwrap();
        let next = Staging::new(&root).unwrap();
        assert!(!Path::new(&dead).exists(), "the dead run's staging is swept");
        assert!(!Path::new(&format!("{root}/stray")).exists());
        assert_eq!(fs::read(live.path("plain")).unwrap(), b"live plaintext", "a live run's is kept");
        drop(next);
        drop(live);
        assert_no_staging(&root);
        // Never through a link in place of the root.
        let link = t.path("link-root");
        std::os::unix::fs::symlink(t.dir("elsewhere"), &link).unwrap();
        assert!(Staging::new(&link).is_err());
    }

    /// Every path under `root`, which must hold no symlinks and nothing else odd.
    fn walk(root: &Path, found: &mut Vec<PathBuf>) {
        for e in fs::read_dir(root).unwrap().flatten() {
            let meta = fs::symlink_metadata(e.path()).unwrap();
            assert!(meta.is_file() || meta.is_dir(), "{} is neither file nor folder", e.path().display());
            found.push(e.path());
            if meta.is_dir() {
                walk(&e.path(), found);
            }
        }
    }

    /// A raw header with its checksum made right.
    fn header(name: &[u8], size_field: &[u8; 12], kind: u8, link: &[u8]) -> [u8; 512] {
        let mut h = [0u8; 512];
        h[..name.len()].copy_from_slice(name);
        h[100..108].copy_from_slice(b"0000777\0");
        h[124..136].copy_from_slice(size_field);
        h[156] = kind;
        h[157..157 + link.len()].copy_from_slice(link);
        h[257..263].copy_from_slice(b"ustar\0");
        h[148..156].fill(b' ');
        let sum: u64 = h.iter().map(|&b| u64::from(b)).sum();
        h[148..156].copy_from_slice(format!("{sum:06o}\0 ").as_bytes());
        h
    }

    fn file_entry(name: &[u8], data: &[u8]) -> Vec<u8> {
        let mut out = header(name, format!("{:011o}\0", data.len()).as_bytes().try_into().unwrap(), b'0', b"").to_vec();
        out.extend_from_slice(data);
        out.extend(tar::padding(data.len() as u64));
        out
    }

    /// Known-bad and mutated archives, through the whole path: decrypt, scan, private
    /// tree, the user's folder, and a vault. Nothing may land outside the folder, a
    /// failure leaves nothing, and a vault is changed by all of an archive or none.
    #[test]
    fn hostile_archives_end_to_end() {
        use rand::{Rng, SeedableRng};
        let t = Temp::new();
        let data = t.path("staging");
        let (_v, share) = shared_tree(&t);
        let good_path = t.path("good.tar");
        decrypt_file_to(&data, &pw(PW), open(&share), len(&share), &good_path, &none()).unwrap();
        let good = fs::read(&good_path).unwrap();

        let mut known_bad: Vec<Vec<u8>> = Vec::new();
        // 0: a symlink entry, then a file "through" it: the link is never made.
        let mut link = good.clone();
        link.splice(0..0, header(b"esc", b"00000000000\0", b'2', b"/tmp"));
        link.splice(512..512, file_entry(b"esc/through-the-link", b"lands in a plain folder"));
        known_bad.push(link);
        // 1-3: truncated, twice, and a size bigger than the archive.
        known_bad.push(good[..good.len() / 2].to_vec());
        known_bad.push(good[..700].to_vec());
        let mut huge = good.clone();
        huge[124..136].copy_from_slice(b"77777777777\0");
        known_bad.push(huge);
        // 4-: traversal, absolute, drive and backslash names, devices and hard links,
        // and two names for one file.
        let end = &tar::END[..];
        for name in [&b"../escape"[..], b"a/../../escape", b"/tmp/abs-escape", b"C:escape", b"a\\..\\escape"] {
            known_bad.push([file_entry(name, b"x"), end.to_vec()].concat());
        }
        known_bad.push([file_entry(b"same", b"1"), file_entry(b"same", b"2"), end.to_vec()].concat());
        known_bad.push([file_entry(b"f", b"1"), file_entry(b"f/inside", b"2"), end.to_vec()].concat());
        let first_bad_name = 4;
        let names_end = known_bad.len();
        let mut devices = Vec::new();
        for (name, kind) in [(&b"hard"[..], b'1'), (b"chr", b'3'), (b"blk", b'4'), (b"fifo", b'6')] {
            devices.extend_from_slice(&header(name, b"00000000000\0", kind, b"/etc/passwd"));
        }
        devices.extend(file_entry(b"kept.txt", b"kept"));
        devices.extend_from_slice(end);
        let devices_case = known_bad.len();
        known_bad.push(devices);

        let mut rng = rand::rngs::StdRng::seed_from_u64(0xfeed);
        for _ in 0..300 {
            let mut d = good.clone();
            for _ in 0..rng.gen_range(1..4) {
                let i = rng.gen_range(0..d.len().min(4096));
                d[i] = [b'/', b'.', 0, b'2', b'5', b'\\', 0xff, b'0'][rng.gen_range(0..8)];
            }
            known_bad.push(d);
        }

        let out_dir = t.dir("out");
        let root = fs::canonicalize(&out_dir).unwrap();
        let vault = quick_vault(&t.path("import.vsvault"));
        for (i, plain) in known_bad.iter().enumerate() {
            let file = t.path("case.age");
            encrypt_with(PW, plain, &file, 2);
            let out = format!("{out_dir}/case{i}");
            let r = extract_archive(&data, &pw(PW), open(&file), len(&file), &out, &LIMITS, &none());
            assert!(!Path::new(&staging_path(&out)).exists());
            match r {
                Ok(_) => {
                    let mut found = Vec::new();
                    walk(Path::new(&out), &mut found);
                    for p in found {
                        assert!(fs::canonicalize(&p).unwrap().starts_with(&root), "{} escaped", p.display());
                    }
                }
                Err(_) => assert!(!Path::new(&out).exists(), "case {i} left a folder"),
            }
            assert_no_staging(&data);

            // The same archive into a vault, under its own folder: all or nothing.
            let before = vault.listing().unwrap();
            let dest = format!("case{i}");
            match import_archive(&vault, &data, &pw(PW), open(&file), len(&file), Some("one"), Some(&dest), &LIMITS) {
                Ok(_) => {
                    let after = vault.listing().unwrap();
                    for line in after.lines().skip(1).filter(|l| !before.contains(&format!("{l}\n"))) {
                        let path = line.rsplit(' ').next().unwrap();
                        assert!(path == dest || path.starts_with(&format!("{dest}/")), "{line} outside {dest}");
                    }
                }
                Err(_) => assert_eq!(vault.listing().unwrap(), before, "case {i} changed the vault"),
            }
            assert_no_staging(&data);
        }
        vault.check().unwrap();
        // Nothing escaped the output folder at all.
        for name in ["escape", "abs-escape"] {
            assert!(!t.0.join(name).exists() && !Path::new(&format!("/tmp/{name}")).exists());
        }
        // The symlink case still unpacked everything else, and made no link.
        assert!(Path::new(&format!("{out_dir}/case0/tree/a.txt")).is_file());
        assert!(fs::symlink_metadata(format!("{out_dir}/case0/esc")).unwrap().is_dir());
        assert!(Path::new(&format!("{out_dir}/case0/esc/through-the-link")).is_file());
        for i in (1..=3).chain(first_bad_name..names_end) {
            assert!(!Path::new(&format!("{out_dir}/case{i}")).exists(), "case {i} must be refused");
        }
        // Devices and hard links are skipped; the file beside them is kept.
        let mut found = Vec::new();
        walk(Path::new(&format!("{out_dir}/case{devices_case}")), &mut found);
        assert_eq!(found.len(), 1, "{found:?}");
        assert_eq!(fs::read(&found[0]).unwrap(), b"kept");
    }
}
