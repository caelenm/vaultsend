// VaultSend vaults: a folder of individually age-encrypted files ("blobs"), bound
// together by an age-encrypted manifest that pins every blob by SHA-256 and carries
// a generation counter, so one file can change without re-encrypting the rest.
//
//   MyVault.vsvault/
//     VAULT          "vaultsend-vault 1\nmode self|password\n"  (not secret; a prompt hint)
//     key.age        the vault's own X25519 identity, sealed with a secret only the user's
//                    private key can produce (self) or a password at scrypt 2^18 (password)
//     manifest.age   the file list, encrypted to the vault's public key
//     blobs/<aa>/<32-hex-id>.age   one per file, encrypted to the vault's public key
//
// No custom crypto here either: all encryption is age. The security rests on the
// bookkeeping: every blob's hash checked in the same pass that decrypts it,
// plaintext fully verified before a byte reaches the output, and age recipients
// being anonymous (the vault's public key is stored nowhere in the clear, so a
// manifest can't be forged without the key).
//
// Android port. This is the desktop vaults branch's vault.rs, and everything that
// decides what a vault is (the format, the manifest parser, path rules, the seal,
// what garbage collection may delete, the error messages) is unchanged. What
// differs is how it reaches files: through a `Store`, which is either a real folder
// (`PathStore`: the desktop code, used by the unit tests and the host-side CLI) or
// a folder the user picked through the Storage Access Framework (`SafStore` in
// ffi.rs). Three consequences, each marked where it happens:
//   * SAF can't rename over an existing file, so replacing the manifest deletes the
//     old one and then renames the new one in; a crash between the two is repaired
//     the next time the vault is opened (`recover_manifest`).
//   * flock isn't dependable on a SAF descriptor, and only this app writes there,
//     so a SAF vault is locked within the process (`process_lock`) instead.
//   * Secrets come from the session or a byte array, not a pipe (`Secret`), and a
//     password vault's key can be remembered in native memory (`remember`).
//   * The desktop decrypts each file whole in RAM. A phone can't hold a large file
//     twice over, so here a file is verified as a stream into private staging in the
//     app's own storage (`stage`), and copied out only once all of it has verified.
//     Memory use is one chunk; the staging is deleted however the operation ends,
//     and at the app's next start if it was killed.

use std::any::Any;
use std::cell::{Cell, RefCell};
use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::fs::{self, DirBuilder, File};
use std::io::{self, Cursor, Read, Write};
use std::iter::once;
use std::os::unix::fs::{DirBuilderExt, PermissionsExt};
use std::path::Path;
use std::rc::Rc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Mutex;
use std::time::{SystemTime, UNIX_EPOCH};

use age::secrecy::{ExposeSecret, SecretString};
use age::x25519;
use rand::RngCore;
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

use crate::backend::{
    encrypt_to, load_identity, lock_in_ram, sync_file, open_private_new, passphrase_from_bytes,
    secret_buffer, session_identity, Held, RamLock, StagedFile, MIN_PASSPHRASE_CHARS, SCRYPT_LOG_N,
};
use crate::{tar, R};

const VAULT_FILE: &str = "VAULT";
const VAULT_MAGIC: &str = "vaultsend-vault 1";
const KEY_FILE: &str = "key.age";
const SEAL_PREFIX: &str = "vaultsend-vault-key-1:";
/// scrypt cost of a `self` vault's seal. Its input is a private key rather than something
/// a person chose, so there is nothing for a higher cost to protect.
const SEAL_LOG_N: u8 = 10;
const MANIFEST_FILE: &str = "manifest.age";
const MANIFEST_MAGIC: &str = "vaultsend-manifest 1";
const BLOBS_DIR: &str = "blobs";
/// `--entry` / `--dest` value meaning the top of the vault. Never a valid vault path.
pub const ROOT_ENTRY: &str = "/";
/// Same floor as the identity passphrase (MIN_PASSPHRASE_LEN in the frontend).
const MIN_PASSWORD_CHARS: usize = MIN_PASSPHRASE_CHARS;
/// How much plaintext goes by between progress reports, at most.
const PROGRESS_CHUNK: usize = 1 << 20;
/// How much plaintext a streamed copy holds in memory at once.
const COPY_CHUNK: usize = 64 << 10;
/// What unlocking a password vault says when it was given no password and has none
/// remembered. The app asks for the password when it sees this.
pub const PASSWORD_NEEDED: &str = "this vault's password is needed";
/// What an operation stopped by the user says. The app knows it asked, and says so itself.
pub const CANCELLED: &str = "cancelled";

/// Plaintext and ciphertext written to a file are staged here first and renamed
/// into place only once complete (desktop main.rs's `staging_path`).
fn staging_path(path: &str) -> String {
    format!("{path}.vaultsend-part")
}

// ---------------------------------------------------------------------------
// Vault paths.  The one validator used by add, remove, extract and the manifest
// parser; everything joined onto a real directory has passed through it, so a
// hostile path can never climb out of the output folder.
// ---------------------------------------------------------------------------
pub(crate) fn valid_vault_path(p: &str) -> bool {
    !p.is_empty()
        && p.len() <= 4096
        && !p.contains('\0')
        && p.split('/').all(|c| !c.is_empty() && c != "." && c != ".." && c.len() <= 255)
}

/// Every parent folder of `path`, outermost first: "a/b/c" gives "a", "a/b".
pub(crate) fn ancestors(path: &str) -> impl Iterator<Item = &str> {
    path.match_indices('/').map(move |(i, _)| &path[..i])
}

/// `path` relative to `root` if it lies inside it ("" for the root itself).
pub(crate) fn within<'a>(path: &'a str, root: &str) -> Option<&'a str> {
    if root == ROOT_ENTRY {
        return Some(path);
    }
    let rest = path.strip_prefix(root)?;
    if rest.is_empty() { Some(rest) } else { rest.strip_prefix('/') }
}

/// Every byte outside [A-Za-z0-9._~/-] becomes %XX, so spaces and newlines in a
/// name cannot break the line-based manifest.
fn escape_path(p: &str) -> String {
    let mut out = String::with_capacity(p.len());
    for &b in p.as_bytes() {
        if b.is_ascii_alphanumeric() || b"._~/-".contains(&b) {
            out.push(b as char);
        } else {
            out.push_str(&format!("%{b:02X}"));
        }
    }
    out
}

fn unescape_path(s: &str) -> R<String> {
    let mut out = Vec::with_capacity(s.len());
    let mut i = 0;
    while i < s.len() {
        if s.as_bytes()[i] == b'%' {
            let hi_lo = s.get(i + 1..i + 3).and_then(|h| u8::from_str_radix(h, 16).ok());
            out.push(hi_lo.ok_or_else(|| format!("bad escape in path: {s}"))?);
            i += 3;
        } else {
            out.push(s.as_bytes()[i]);
            i += 1;
        }
    }
    let path = String::from_utf8(out).map_err(|_| format!("path is not UTF-8: {s}"))?;
    // Exactly one spelling per path, so `%2F` can't smuggle a separator past the
    // validator and two spellings of one name can't both appear.
    if escape_path(&path) != s {
        return Err(format!("non-canonical escape in path: {s}"));
    }
    Ok(path)
}

fn is_hex(s: &str, len: usize) -> bool {
    s.len() == len && s.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().fold(String::new(), |s, b| s + &format!("{b:02x}"))
}

/// Canonical decimal only: rejects "+5", "007" and anything else u64 would forgive.
fn parse_u64(s: &str) -> Option<u64> {
    s.parse::<u64>().ok().filter(|n| n.to_string() == s)
}

// ---------------------------------------------------------------------------
// Manifest.  Plaintext inside manifest.age; UTF-8, one record per line:
//   vaultsend-manifest 1
//   generation <u64>
//   F <blob-id:32 hex> <sha256-of-blob-file:64 hex> <plaintext-size> <escaped-path>
//   D <escaped-path>
// `size` is for display only; the hash and age are what authenticate a file.
// ---------------------------------------------------------------------------
#[derive(Debug, Clone, PartialEq)]
enum Entry {
    Dir,
    File { blob: String, sha256: String, size: u64 },
}

/// A BTreeMap so paths are unique, the file is deterministic, and a folder always
/// sorts before its contents (a prefix sorts first).
#[derive(Debug, Clone, PartialEq, Default)]
struct Manifest {
    generation: u64,
    entries: BTreeMap<String, Entry>,
}

impl Manifest {
    fn serialize(&self) -> String {
        let mut out = format!("{MANIFEST_MAGIC}\ngeneration {}\n", self.generation);
        for (path, entry) in &self.entries {
            let path = escape_path(path);
            out.push_str(&match entry {
                Entry::Dir => format!("D {path}\n"),
                Entry::File { blob, sha256, size } => format!("F {blob} {sha256} {size} {path}\n"),
            });
        }
        out
    }

    fn parse(text: &str) -> R<Manifest> {
        let body = text.strip_suffix('\n').ok_or("missing final newline")?;
        let mut lines = body.split('\n');
        if lines.next() != Some(MANIFEST_MAGIC) {
            return Err("unknown manifest version".into());
        }
        let generation = lines
            .next()
            .and_then(|l| l.strip_prefix("generation "))
            .and_then(parse_u64)
            .ok_or("bad generation line")?;

        let mut entries = BTreeMap::new();
        for line in lines {
            let fields: Vec<&str> = line.split(' ').collect();
            let (escaped, entry) = match fields[..] {
                ["D", p] => (p, Entry::Dir),
                ["F", blob, sha256, size, p] if is_hex(blob, 32) && is_hex(sha256, 64) => {
                    let size = parse_u64(size).ok_or_else(|| format!("bad size in: {line}"))?;
                    (p, Entry::File { blob: blob.into(), sha256: sha256.into(), size })
                }
                _ => return Err(format!("unrecognised record: {line}")),
            };
            let path = unescape_path(escaped)?;
            if !valid_vault_path(&path) {
                return Err(format!("invalid path: {escaped}"));
            }
            if entries.insert(path, entry).is_some() {
                return Err(format!("duplicate path: {escaped}"));
            }
        }
        // Every parent must be a recorded folder. This one check also rejects a
        // file that is also used as a folder.
        for path in entries.keys() {
            if ancestors(path).any(|a| entries.get(a) != Some(&Entry::Dir)) {
                return Err(format!("parent is not a folder: {}", escape_path(path)));
            }
        }
        Ok(Manifest { generation, entries })
    }

    /// The blob IDs this manifest names.
    fn blobs(&self) -> BTreeSet<&str> {
        self.entries.values().filter_map(|e| match e {
            Entry::File { blob, .. } => Some(blob.as_str()),
            Entry::Dir => None,
        }).collect()
    }

    /// Plaintext bytes in these paths; folders count for nothing.
    fn size_of<'a>(&self, paths: impl Iterator<Item = &'a str>) -> u64 {
        paths.fold(0, |sum, path| match self.entries.get(path) {
            Some(Entry::File { size, .. }) => sum.saturating_add(*size),
            _ => sum,
        })
    }

    /// Everything `entries` covers and the folders leading to it, parents first. Overlaps
    /// (a folder and a file inside it) just count once. Every entry must exist.
    fn selection<'a>(&'a self, entries: &[&str]) -> R<BTreeSet<&'a str>> {
        if let Some(missing) = entries.iter().find(|e| **e != ROOT_ENTRY && !self.entries.contains_key(**e)) {
            return Err(format!("'{missing}' is not in the vault"));
        }
        let mut chosen = BTreeSet::new();
        for path in self.entries.keys() {
            if entries.iter().any(|e| within(path, e).is_some()) {
                chosen.extend(ancestors(path));
                chosen.insert(path.as_str());
            }
        }
        Ok(chosen)
    }
}


// ---------------------------------------------------------------------------
// Where a vault's files live.  Paths given to a Store are relative to its root,
// '/'-separated, with "" meaning the root itself.
// ---------------------------------------------------------------------------
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Kind {
    Missing,
    File,
    Dir,
    /// A symlink, FIFO, socket or device: never followed, read or deleted.
    Other,
}

pub trait Store {
    /// A stable name for the root, for telling whether one folder lies inside
    /// another and for remembering a vault's key: the canonical path, or for SAF
    /// the folder's document ID.
    fn key(&self) -> R<String>;
    /// `rel` as the user would recognise it, for messages.
    fn show(&self, rel: &str) -> String;
    /// What is at `rel`, without following a symlink.
    fn kind(&self, rel: &str) -> Kind;
    /// The whole of a regular file. Anything else is an error: a FIFO planted in
    /// a vault would otherwise block forever.
    fn read(&self, rel: &str) -> io::Result<Vec<u8>>;
    /// A regular file, to read as a stream; anything else is an error, as for `read`.
    fn open(&self, rel: &str) -> io::Result<File>;
    /// A new private file at `rel`, replacing a stale one of that name. Its
    /// folder must exist.
    fn create_new(&self, rel: &str) -> R<File>;
    /// Rename within one folder. Whether an existing `to` is replaced depends on
    /// `replaces_on_rename`.
    fn rename(&self, from: &str, to: &str) -> io::Result<()>;
    /// False for SAF, whose rename refuses (or renames around) an existing name.
    fn replaces_on_rename(&self) -> bool;
    fn remove_file(&self, rel: &str) -> io::Result<()>;
    /// Best-effort removal of a folder and everything in it.
    fn remove_tree(&self, rel: &str);
    /// A private folder (0700 where that means anything); `recursive` also makes
    /// its parents, and accepts one that exists.
    fn mkdir(&self, rel: &str, recursive: bool) -> R<()>;
    /// Names and kinds of what's in a folder. Names that aren't UTF-8 are left out.
    fn list(&self, rel: &str) -> R<Vec<(String, Kind)>>;
    /// Make renames in this folder durable. Best-effort.
    fn sync_dir(&self, rel: &str);
    /// Shared (reads) or exclusive (changes) use of the vault rooted here, held
    /// until the returned value is dropped. Fails at once if it would have to wait.
    fn lock(&self, exclusive: bool) -> R<Box<dyn Any>>;
}

fn not_a_vault(store: &dyn Store) -> String {
    format!("{} is not a VaultSend vault (no {VAULT_FILE} file)", store.show(""))
}

const BUSY: &str = "another VaultSend operation is using this vault";

/// A real folder: the desktop backend's file handling, unchanged.
pub struct PathStore {
    root: String,
}

impl PathStore {
    pub fn new(root: &str) -> PathStore {
        PathStore { root: root.to_string() }
    }

    fn full(&self, rel: &str) -> String {
        if rel.is_empty() { self.root.clone() } else { format!("{}/{rel}", self.root) }
    }
}

impl Store for PathStore {
    fn key(&self) -> R<String> {
        let path = fs::canonicalize(&self.root).map_err(|e| format!("{}: {e}", self.root))?;
        path.to_str().map(str::to_string).ok_or_else(|| format!("{}: not valid UTF-8", self.root))
    }
    fn show(&self, rel: &str) -> String {
        self.full(rel)
    }
    fn kind(&self, rel: &str) -> Kind {
        match fs::symlink_metadata(self.full(rel)) {
            Err(_) => Kind::Missing,
            Ok(m) if m.is_file() => Kind::File,
            Ok(m) if m.is_dir() => Kind::Dir,
            Ok(_) => Kind::Other,
        }
    }
    fn read(&self, rel: &str) -> io::Result<Vec<u8>> {
        read_regular(&self.full(rel))
    }
    fn open(&self, rel: &str) -> io::Result<File> {
        open_regular(&self.full(rel))
    }
    fn create_new(&self, rel: &str) -> R<File> {
        open_private_new(Path::new(&self.full(rel)))
    }
    fn rename(&self, from: &str, to: &str) -> io::Result<()> {
        fs::rename(self.full(from), self.full(to))
    }
    fn replaces_on_rename(&self) -> bool {
        true
    }
    fn remove_file(&self, rel: &str) -> io::Result<()> {
        fs::remove_file(self.full(rel))
    }
    fn remove_tree(&self, rel: &str) {
        let _ = fs::remove_dir_all(self.full(rel));
    }
    fn mkdir(&self, rel: &str, recursive: bool) -> R<()> {
        let path = self.full(rel);
        private_dir(&path, recursive)?;
        if recursive {
            // An existing folder is accepted, so make sure it's private too.
            fs::set_permissions(&path, fs::Permissions::from_mode(0o700)).map_err(|e| format!("{path}: {e}"))?;
        }
        Ok(())
    }
    fn list(&self, rel: &str) -> R<Vec<(String, Kind)>> {
        let path = self.full(rel);
        let mut found = Vec::new();
        for item in fs::read_dir(&path).map_err(|e| format!("{path}: {e}"))?.flatten() {
            let Ok(name) = item.file_name().into_string() else { continue };
            // file_type doesn't follow symlinks, so a link is neither entered nor deleted.
            let kind = match item.file_type() {
                Ok(t) if t.is_file() => Kind::File,
                Ok(t) if t.is_dir() => Kind::Dir,
                _ => Kind::Other,
            };
            found.push((name, kind));
        }
        Ok(found)
    }
    fn sync_dir(&self, rel: &str) {
        sync_dir(&self.full(rel));
    }
    fn lock(&self, exclusive: bool) -> R<Box<dyn Any>> {
        Ok(Box::new(lock_vault(&self.root, exclusive)?))
    }
}

/// Hold a lock on the vault for the life of the operation, so one operation's garbage
/// collection can never delete blobs another has written but not yet committed.
/// The kernel releases flock however the process dies, so there is no stale lock.
fn lock_vault(dir: &str, exclusive: bool) -> R<File> {
    let path = format!("{dir}/{VAULT_FILE}");
    let not_a_vault = format!("{dir} is not a VaultSend vault (no {VAULT_FILE} file)");
    if !fs::metadata(&path).is_ok_and(|m| m.is_file()) {
        return Err(not_a_vault);
    }
    let file = File::open(&path).map_err(|_| not_a_vault)?;
    #[cfg(any(target_os = "linux", target_os = "android"))]
    {
        use std::os::unix::io::AsRawFd;
        let kind = if exclusive { libc::LOCK_EX } else { libc::LOCK_SH };
        // SAFETY: flock only reads the descriptor, which `file` keeps open.
        let failed = unsafe { libc::flock(file.as_raw_fd(), kind | libc::LOCK_NB) } != 0;
        if failed && io::Error::last_os_error().kind() == io::ErrorKind::WouldBlock {
            return Err(BUSY.into());
        }
    }
    #[cfg(not(any(target_os = "linux", target_os = "android")))]
    let _ = exclusive;
    Ok(file)
}

/// For a store with no flock (SAF): the same rule, kept within this process, which
/// is the only one that writes there. Keyed by the store's `key`. Positive counts
/// readers; -1 is a writer.
static PROCESS_LOCKS: Mutex<BTreeMap<String, isize>> = Mutex::new(BTreeMap::new());

pub struct ProcessLock {
    key: String,
}

pub fn process_lock(key: &str, exclusive: bool) -> R<ProcessLock> {
    let mut locks = PROCESS_LOCKS.lock().unwrap_or_else(|e| e.into_inner());
    let count = locks.entry(key.to_string()).or_insert(0);
    match (exclusive, *count) {
        (true, 0) => *count = -1,
        (false, n) if n >= 0 => *count += 1,
        _ => return Err(BUSY.into()),
    }
    Ok(ProcessLock { key: key.to_string() })
}

impl Drop for ProcessLock {
    fn drop(&mut self) {
        let mut locks = PROCESS_LOCKS.lock().unwrap_or_else(|e| e.into_inner());
        if let Some(count) = locks.get_mut(&self.key) {
            *count = if *count < 0 { 0 } else { *count - 1 };
            if *count == 0 {
                locks.remove(&self.key);
            }
        }
    }
}

/// What every non-path store does before locking: the VAULT check lock_vault makes.
pub fn lock_by_key(store: &dyn Store, exclusive: bool) -> R<Box<dyn Any>> {
    if store.kind(VAULT_FILE) != Kind::File {
        return Err(not_a_vault(store));
    }
    Ok(Box::new(process_lock(&store.key()?, exclusive)?))
}

// ---------------------------------------------------------------------------
// Small IO helpers.
// ---------------------------------------------------------------------------
/// Stage `rel` with create_new, let `fill` write it, fsync, rename into place.
fn write_atomic(store: &dyn Store, rel: &str, fill: impl FnOnce(File) -> R<File>) -> R<()> {
    let tmp = staging_path(rel);
    let shown = store.show(rel);
    let file = store.create_new(&tmp)?;
    let staged = fill(file).and_then(|mut f| {
        f.flush().map_err(|e| format!("writing {shown}: {e}"))?;
        sync_file(&f).map_err(|e| format!("flushing {shown}: {e}"))
    });
    commit_staged(store, staged, &tmp, rel)
}

/// Finish a staged write: on success rename the staging file over `rel`; on failure
/// remove it so no partial output is ever left behind.
///
/// Android: a store that can't rename over a file (SAF) deletes the old one first.
/// If the rename then fails, the staged file is left where it is: for the manifest,
/// the only file ever replaced, it's the newer committed state, and
/// `recover_manifest` puts it in place on the next open.
fn commit_staged(store: &dyn Store, staged: R<()>, tmp: &str, rel: &str) -> R<()> {
    let finalizing = |e: io::Error| format!("finalizing {}: {e}", store.show(rel));
    if let Err(e) = staged {
        let _ = store.remove_file(tmp);
        return Err(e);
    }
    let mut replaced = false;
    if !store.replaces_on_rename() && store.kind(rel) != Kind::Missing {
        store.remove_file(rel).map_err(|e| {
            let _ = store.remove_file(tmp);
            finalizing(e)
        })?;
        replaced = true;
    }
    store.rename(tmp, rel).map_err(|e| {
        if !replaced {
            let _ = store.remove_file(tmp);
        }
        finalizing(e)
    })
}

/// Make a rename durable. Best-effort: some filesystems refuse fsync on a folder,
/// and by now the rename has happened, so failing here would misreport the outcome.
fn sync_dir(path: &str) {
    if let Ok(dir) = File::open(path) {
        let _ = dir.sync_all();
    }
}

/// fs::read for anything inside a vault. A FIFO planted there would otherwise block forever,
/// with the window frozen behind it, since unlocking runs in the foreground.
fn read_regular(path: &str) -> io::Result<Vec<u8>> {
    let mut data = Vec::new();
    open_regular(path)?.read_to_end(&mut data)?;
    Ok(data)
}

/// File::open for anything inside a vault, for the same reason. What was opened is
/// checked again, so a file swapped for something else in between is refused too.
fn open_regular(path: &str) -> io::Result<File> {
    if !fs::metadata(path)?.is_file() {
        return Err(io::Error::other("not a regular file"));
    }
    let file = File::open(path)?;
    if !file.metadata()?.is_file() {
        return Err(io::Error::other("not a regular file"));
    }
    Ok(file)
}

/// Within a store, where "" is the root rather than ".".
fn parent_rel(rel: &str) -> &str {
    rel.rfind('/').map_or("", |i| &rel[..i])
}

fn private_dir(path: &str, recursive: bool) -> R<()> {
    DirBuilder::new()
        .recursive(recursive)
        .mode(0o700)
        .create(path)
        .map_err(|e| format!("creating {path}: {e}"))
}

/// Hashes the ciphertext on its way to the blob file.
struct HashingWriter<W> {
    inner: W,
    hasher: Sha256,
}

impl<W: Write> Write for HashingWriter<W> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        let n = self.inner.write(buf)?;
        self.hasher.update(&buf[..n]);
        Ok(n)
    }
    fn flush(&mut self) -> io::Result<()> {
        self.inner.flush()
    }
}

/// A buffer that refuses to grow past `cap`, so plaintext written into it is never
/// reallocated (which would leave an unwiped copy in freed heap). `read_text`.
struct Capped<'a> {
    buf: &'a mut Vec<u8>,
    cap: usize,
}

impl Write for Capped<'_> {
    fn write(&mut self, data: &[u8]) -> io::Result<usize> {
        if data.len() > self.cap - self.buf.len() {
            return Err(io::Error::other("longer than the vault's manifest says"));
        }
        self.buf.extend_from_slice(data);
        Ok(data.len())
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

/// Hashes a blob's ciphertext on its way to age, so one read both verifies and
/// decrypts it. Remembers a read error, so one can be told from tampering.
struct HashingReader<R> {
    inner: R,
    hasher: Sha256,
    failed: Option<String>,
}

impl<R: Read> Read for HashingReader<R> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        match self.inner.read(buf) {
            Ok(n) => {
                self.hasher.update(&buf[..n]);
                Ok(n)
            }
            Err(e) => {
                self.failed.get_or_insert_with(|| e.to_string());
                Err(e)
            }
        }
    }
}

/// Whole percent, as much as anyone can tell with age storing no plaintext length.
/// Only numbers, so nothing about the vault's contents, and at most 101 reports.
///
/// Android: the desktop wrote these to a pipe the frontend read (`--progress-fd`);
/// here they go to a callback (`ffi.rs` hands them to the UI; `vault_cli` still
/// writes them to a pipe). A report that can't be delivered is just dropped.
///
/// It also carries the user's Cancel: `cancelled` asks the app at most once per
/// PROGRESS_CHUNK of work (and `check` whenever called), and once it has said yes,
/// stays yes. Work that stops this way fails with CANCELLED and cleans up as any
/// other failure does.
#[derive(Default)]
pub struct Progress {
    sink: Option<Box<dyn Fn(u64)>>,
    cancel: Option<Box<dyn Fn() -> bool>>,
    total: Cell<u64>,
    done: Cell<u64>,
    shown: Cell<Option<u64>>,
    /// Bytes gone by, whatever the total, and when Cancel was last asked about.
    seen: Cell<u64>,
    polled_at: Cell<u64>,
    stopped: Cell<bool>,
}

impl Progress {
    pub fn new(sink: impl Fn(u64) + 'static) -> Progress {
        Progress { sink: Some(Box::new(sink)), ..Default::default() }
    }

    /// Ask `cancel` whether the user has stopped this operation.
    pub fn with_cancel(mut self, cancel: impl Fn() -> bool + 'static) -> Progress {
        self.cancel = Some(Box::new(cancel));
        self
    }

    /// Whether the user has cancelled, asking the app only every PROGRESS_CHUNK bytes.
    pub(crate) fn cancelled(&self) -> bool {
        if !self.stopped.get() && self.seen.get().saturating_sub(self.polled_at.get()) >= PROGRESS_CHUNK as u64 {
            self.poll();
        }
        self.stopped.get()
    }

    fn poll(&self) {
        self.polled_at.set(self.seen.get());
        if let Some(cancel) = &self.cancel {
            if cancel() {
                self.stopped.set(true);
            }
        }
    }

    /// Ask now, between steps: Err(CANCELLED) if the user has stopped this.
    pub(crate) fn check(&self) -> R<()> {
        if !self.stopped.get() {
            self.poll();
        }
        if self.stopped.get() { Err(CANCELLED.into()) } else { Ok(()) }
    }

    pub(crate) fn start(&self, total: u64) {
        self.total.set(total);
        self.done.set(0);
    }

    pub(crate) fn advance(&self, n: u64) {
        self.seen.set(self.seen.get().saturating_add(n));
        let (Some(sink), total) = (&self.sink, self.total.get()) else { return };
        if total == 0 {
            return;
        }
        let done = self.done.get().saturating_add(n);
        self.done.set(done);
        let percent = (u128::from(done) * 100 / u128::from(total)).min(100) as u64;
        if self.shown.get() != Some(percent) {
            self.shown.set(Some(percent));
            sink(percent);
        }
    }
}

/// Counts what's read through it, for encrypting a source file into a blob. Also
/// keeps the total, which becomes the size in the manifest: a SAF source can be a
/// pipe from a cloud provider, whose size isn't known until it has been read.
struct CountingReader<R> {
    inner: R,
    progress: Rc<Progress>,
    count: Rc<Cell<u64>>,
}

impl<R: Read> Read for CountingReader<R> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        if self.progress.cancelled() {
            return Err(io::Error::other(CANCELLED));
        }
        let n = self.inner.read(buf)?;
        self.progress.advance(n as u64);
        self.count.set(self.count.get() + n as u64);
        Ok(n)
    }
}

/// One piece of what Share encrypts: a tar header or padding, or a verified file.
enum Part {
    Bytes(Zeroizing<Vec<u8>>),
    Staged(StagedFile),
}

/// A staged file being read, deleted when dropped (fields drop in order: the
/// descriptor is closed first).
struct StagedReader {
    file: File,
    _staged: StagedFile,
}

impl Read for StagedReader {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        self.file.read(buf)
    }
}

/// Reads a list of parts in order, wiping or deleting each one as soon as it has
/// been read. A staged file is opened only when its turn comes, so sharing thousands
/// of files holds one descriptor at a time.
struct Parts {
    parts: VecDeque<Part>,
    reading: Option<Box<dyn Read>>,
    progress: Rc<Progress>,
}

impl Read for Parts {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        if buf.is_empty() {
            return Ok(0);
        }
        loop {
            let reading = match &mut self.reading {
                Some(reading) => reading,
                None => self.reading.insert(match self.parts.pop_front() {
                    None => return Ok(0),
                    Some(Part::Bytes(bytes)) => Box::new(Cursor::new(bytes)),
                    Some(Part::Staged(staged)) => Box::new(StagedReader { file: staged.open().map_err(io::Error::other)?, _staged: staged }),
                }),
            };
            let n = reading.read(buf)?;
            if n > 0 {
                self.progress.advance(n as u64);
                return Ok(n);
            }
            self.reading = None; // this part is done: dropping it wipes or deletes it
        }
    }
}

/// io::copy, through one wiped buffer, counting for the percentage as it goes.
/// Returns how many bytes went by.
fn copy_counted(from: &mut dyn Read, to: &mut dyn Write, progress: &Progress, path: &str) -> R<u64> {
    let mut buf = Zeroizing::new(vec![0u8; COPY_CHUNK]);
    let mut total = 0u64;
    loop {
        let n = match from.read(&mut buf) {
            Ok(0) => return Ok(total),
            Ok(n) => n,
            Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
            Err(e) => return Err(format!("reading for {path}: {e}")),
        };
        to.write_all(&buf[..n]).map_err(|e| format!("writing {path}: {e}"))?;
        progress.advance(n as u64);
        total += n as u64;
    }
}

// ---------------------------------------------------------------------------
// Unlocking.
// ---------------------------------------------------------------------------
/// What sealing a `self` vault's key.age needs: an age seal of the user's private key.
/// age has no sender authentication and a public key is public, so a key wrapped to it
/// could have come from anyone, and a vault built around it would open normally. Only
/// the holder of the private key can compute this, so only they can make a key.age
/// that opens here. Locked in RAM for as long as the returned guard is held.
fn seal_secret(identity: &x25519::Identity) -> (SecretString, RamLock) {
    let private = identity.to_string();
    let private = private.expose_secret();
    let _private_ram = lock_in_ram(private.as_bytes());
    // Exact capacity: SecretString won't reallocate it, so no copy is left behind.
    let mut text = String::with_capacity(SEAL_PREFIX.len() + private.len());
    text.push_str(SEAL_PREFIX);
    text.push_str(private);
    // Moving the String into SecretString leaves its bytes where they are.
    let ram = lock_in_ram(text.as_bytes());
    (SecretString::from(text), ram)
}

/// An encryptor for whoever knows `secret`, through scrypt at `log_n`. age wraps the file
/// key as the encryptor is made, so the secret, and its lock in RAM, go on return.
fn scrypt_encryptor((secret, _ram): (SecretString, RamLock), log_n: u8) -> R<age::Encryptor> {
    let mut recipient = age::scrypt::Recipient::new(secret);
    recipient.set_work_factor(log_n);
    age::Encryptor::with_recipients(once(&recipient as &dyn age::Recipient))
        .map_err(|e| format!("preparing encryption: {e}"))
}

/// The same for a password a person chose, which must be at least MIN_PASSWORD_CHARS long.
fn password_encryptor(password: &[u8], log_n: u8) -> R<age::Encryptor> {
    let password = passphrase_from_bytes(password)?;
    if password.0.expose_secret().chars().count() < MIN_PASSWORD_CHARS {
        return Err(format!("use a password of at least {MIN_PASSWORD_CHARS} characters"));
    }
    scrypt_encryptor(password, log_n)
}

/// The secret that opens a vault, replacing the desktop's `--pass-fd`. Like that
/// pipe, `bytes` carries the identity passphrase for a `self` vault and the password
/// for a `password` vault. Without bytes, a `self` vault uses the unlocked session
/// key and a `password` vault its remembered key, if any.
pub struct Secret<'a> {
    /// Where identity.age is, for a passphrase.
    pub data_dir: &'a str,
    pub bytes: Option<&'a [u8]>,
}

impl Secret<'_> {
    fn identity(&self) -> R<x25519::Identity> {
        match self.bytes {
            Some(passphrase) => load_identity(self.data_dir, passphrase),
            None => session_identity(),
        }
    }
}

/// Decrypt key.age and return the vault's identity. scrypt runs here, once per
/// operation rather than once per file. The VAULT file's mode is only a hint for
/// which secret to try: a wrong mode just fails to decrypt, as an ordinary error.
fn unlock(store: &dyn Store, secret: &Secret) -> R<x25519::Identity> {
    let hint = store.read(VAULT_FILE).map_err(|e| format!("reading {VAULT_FILE}: {e}"))?;
    let hint = String::from_utf8_lossy(&hint);
    let mode = hint.strip_prefix(VAULT_MAGIC).and_then(|r| r.strip_prefix("\nmode "));
    if mode == Some("password\n") && secret.bytes.is_none() {
        return remembered(&store.key()?).ok_or_else(|| PASSWORD_NEEDED.to_string());
    }
    let wrapped = store.read(KEY_FILE).map_err(|e| format!("reading this vault's {KEY_FILE}: {e}"))?;
    let dec = age::Decryptor::new(&wrapped[..])
        .map_err(|_| format!("this vault's {KEY_FILE} is damaged"))?;
    let mut stream = match mode {
        Some("self\n") => {
            let identity = secret.identity()?;
            let (seal, _seal_ram) = seal_secret(&identity);
            let mut sealed = age::scrypt::Identity::new(seal);
            sealed.set_max_work_factor(SEAL_LOG_N);
            dec.decrypt(once(&sealed as &dyn age::Identity))
                .map_err(|_| format!("this vault does not open with your key ({KEY_FILE} wasn't made with your private key, or is damaged)"))?
        }
        Some("password\n") => {
            let (password, _password_ram) = passphrase_from_bytes(secret.bytes.unwrap_or_default())?;
            let mut scrypt_id = age::scrypt::Identity::new(password);
            // What vault-create uses, and no more: a shared vault could otherwise cost gigabytes.
            scrypt_id.set_max_work_factor(SCRYPT_LOG_N);
            dec.decrypt(once(&scrypt_id as &dyn age::Identity))
                .map_err(|_| format!("wrong password, or this vault's {KEY_FILE} is damaged"))?
        }
        _ => return Err(format!("{}/{VAULT_FILE} is not a format this version understands", store.show(""))),
    };
    let mut secret_text = secret_buffer();
    stream.read_to_end(&mut secret_text).map_err(|e| format!("reading this vault's {KEY_FILE}: {e}"))?;
    let key = std::str::from_utf8(&secret_text)
        .map_err(|_| format!("this vault's {KEY_FILE} is corrupt"))?
        .trim()
        .parse::<x25519::Identity>()
        .map_err(|e| format!("this vault's {KEY_FILE} is corrupt: {e}"))?;
    if mode == Some("password\n") {
        remember(&store.key()?, &key);
    }
    Ok(key)
}

// ---------------------------------------------------------------------------
// Remembered vault keys (Android; the desktop frontend's PassphraseCache).
//
// The desktop app remembers the password itself, in Python, for as long as the user
// chose under Remember passphrase. Here what's remembered is a password vault's own
// key, which is what the password unlocks, and it's held in native memory: zeroizing,
// locked in RAM, never in the JVM, where a String can't be wiped. A `self` vault
// needs nothing remembered, because it opens with the unlocked session key. There
// are two choices, as in the app's Remember passphrase: nothing, or until the app
// closes (or Lock now, or the background lock). Setting it forgets everything, as
// `set_lifetime` does on desktop.
// ---------------------------------------------------------------------------
static REMEMBER: AtomicBool = AtomicBool::new(false);
/// Vault key text by the vault's store key.
static REMEMBERED: Mutex<BTreeMap<String, Held>> = Mutex::new(BTreeMap::new());

/// Whether a password vault's key is kept once its password has opened it.
pub fn set_remember(on: bool) {
    REMEMBER.store(on, Ordering::SeqCst);
    forget_all();
}

fn remember(vault: &str, key: &x25519::Identity) {
    if REMEMBER.load(Ordering::SeqCst) {
        let held = Held::new(key.to_string());
        REMEMBERED.lock().unwrap_or_else(|e| e.into_inner()).insert(vault.to_string(), held);
    }
}

fn remembered(vault: &str) -> Option<x25519::Identity> {
    let keys = REMEMBERED.lock().unwrap_or_else(|e| e.into_inner());
    keys.get(vault)?.expose().parse().ok()
}

/// True if a key for this vault is remembered now.
pub fn is_remembered(vault: &str) -> bool {
    REMEMBERED.lock().unwrap_or_else(|e| e.into_inner()).contains_key(vault)
}

pub fn forget(vault: &str) {
    REMEMBERED.lock().unwrap_or_else(|e| e.into_inner()).remove(vault);
}

pub fn forget_all() {
    REMEMBERED.lock().unwrap_or_else(|e| e.into_inner()).clear();
}

// ---------------------------------------------------------------------------
// Sources and destinations.
// ---------------------------------------------------------------------------
/// Refuse an output that resolves to anywhere inside the vault: `name` within the
/// folder of an `Out::In`. The name need not exist yet, so its folder is what gets
/// resolved. An `Out::File` was checked by the caller that made it.
fn refuse_out_inside_vault(vault: &dyn Store, out: &Out) -> R<()> {
    let Out::In(folder, name) = out else { return Ok(()) };
    if Path::new(&folder.key()?).join(name).starts_with(vault.key()?) {
        return Err("the output path must not be inside the vault".into());
    }
    Ok(())
}

/// Everything to add, as (path below the destination, None for a folder or
/// Some(index) for a file), and how many items were skipped as neither.
pub type Plan = (Vec<(String, Option<usize>)>, usize);

/// What `vault-add` adds. The desktop walked real paths; the app hands over
/// documents it picked, so the walk is behind this.
pub trait Sources {
    fn plan(&self) -> R<Plan>;
    /// The contents of file `index`.
    fn open(&self, index: usize) -> R<Box<dyn Read>>;
    /// Its expected size, for the percentage only.
    fn size(&self, index: usize) -> u64;
}

/// Where extract and share write. The desktop always took a path (`--out`).
pub enum Out<'a> {
    /// A file the caller already made, such as a SAF document from "Save as"; it
    /// checked it isn't inside the vault and removes it if this fails. Written in place.
    File(&'a mut File),
    /// A new name in a folder: staged and renamed into place, as on desktop.
    In(&'a dyn Store, &'a str),
}

/// Write one file to `out` with `fill`, given the descriptor and a name for messages:
/// in place, into a file the caller made, or staged in its folder and renamed into
/// place, so the name is only ever absent or complete.
fn write_out(out: Out, fill: impl FnOnce(&mut File, &str) -> R<()>) -> R<()> {
    match out {
        Out::File(file) => {
            fill(file, "the output")?;
            file.flush().and_then(|_| sync_file(file)).map_err(|e| format!("writing the output: {e}"))
        }
        Out::In(folder, name) => {
            write_atomic(folder, name, |mut file| fill(&mut file, &folder.show(name)).map(|()| file))?;
            folder.sync_dir("");
            Ok(())
        }
    }
}

/// Write `tree` (paths under `root`, None for a folder, or a file's verified
/// plaintext) into `root`, a new folder in `store`. Each staged file is deleted as
/// soon as it has been copied.
fn write_tree(store: &dyn Store, root: &str, tree: Vec<(&str, Option<StagedFile>)>, progress: &Progress) -> R<()> {
    store.mkdir(root, false)?;
    // In manifest order, so every folder is created before its contents.
    for (rel, staged) in tree {
        let path = format!("{root}/{rel}");
        match staged {
            None => store.mkdir(&path, false)?,
            Some(staged) => {
                // create_new would replace it, and on a case-insensitive disk
                // "A" and "a" are the same file: one would silently go missing.
                if store.kind(&path) != Kind::Missing {
                    return Err(format!("{}: two names in the vault collide on this disk", store.show(&path)));
                }
                let mut file = store.create_new(&path)?;
                copy_counted(&mut staged.open()?, &mut file, progress, &store.show(&path))?;
                sync_file(&file).map_err(|e| format!("flushing {}: {e}", store.show(&path)))?;
            }
        }
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// An unlocked vault.
// ---------------------------------------------------------------------------
pub struct Vault {
    /// The vault's folder as the user would recognise it (the tests build paths on it).
    #[cfg_attr(not(test), allow(dead_code))]
    pub(crate) dir: String,
    store: Box<dyn Store>,
    key: x25519::Identity,
    /// Where plaintext is staged while it verifies: the app's private storage (the
    /// folder identity.age is in), never anywhere in the vault or the output.
    staging: String,
    /// Held only for its lock, released when this is dropped.
    _lock: Option<Box<dyn Any>>,
    pub progress: Rc<Progress>,
    /// The desktop printed these to stderr as "warning: ...". Kept here so the app
    /// can show them; vault_cli still prints them.
    warnings: RefCell<Vec<String>>,
    /// The blobs the change in progress has written (`change`).
    written: RefCell<Vec<String>>,
}

impl Vault {
    /// Plaintext is staged in `secret.data_dir`.
    pub fn open_in(store: Box<dyn Store>, secret: &Secret, exclusive: bool) -> R<Vault> {
        let lock = store.lock(exclusive)?;
        let key = unlock(&*store, secret)?;
        Ok(Vault::with(store, key, Some(lock), secret.data_dir))
    }

    fn with(store: Box<dyn Store>, key: x25519::Identity, lock: Option<Box<dyn Any>>, staging: &str) -> Vault {
        Vault {
            dir: store.show(""),
            store,
            key,
            staging: staging.to_string(),
            _lock: lock,
            progress: Rc::default(),
            warnings: RefCell::default(),
            written: RefCell::default(),
        }
    }

    /// `wrap` already holds key.age's wrapped file key, so scrypt (for a password
    /// vault) has run by now. VAULT goes last: its presence marks a complete vault.
    pub(crate) fn create_in(store: Box<dyn Store>, mode: &str, wrap: age::Encryptor, staging: &str) -> R<Vault> {
        let v = Vault::with(store, x25519::Identity::generate(), None, staging);
        let store = &*v.store;
        let populate = || -> R<()> {
            store.mkdir("", true)?;
            store.mkdir(BLOBS_DIR, false)?;
            let secret = Zeroizing::new(v.key.to_string().expose_secret().to_owned());
            let _secret_ram = lock_in_ram(secret.as_bytes());
            write_atomic(store, KEY_FILE, |file| {
                encrypt_to(wrap, false, Cursor::new(secret.as_bytes()), file)
            })?;
            v.write_manifest(&Manifest::default())?;
            write_atomic(store, VAULT_FILE, |mut file| {
                let text = format!("{VAULT_MAGIC}\nmode {mode}\n");
                file.write_all(text.as_bytes()).map_err(|e| format!("writing {VAULT_FILE}: {e}"))?;
                Ok(file)
            })?;
            store.sync_dir("");
            Ok(())
        };
        if let Err(e) = populate() {
            store.remove_tree(""); // only ever a folder we just found empty
            return Err(e);
        }
        Ok(v)
    }

    pub fn warnings(&self) -> Vec<String> {
        self.warnings.take()
    }

    fn warn(&self, message: String) {
        self.warnings.borrow_mut().push(message);
    }

    fn blob_rel(&self, blob: &str) -> String {
        format!("{BLOBS_DIR}/{}/{blob}.age", &blob[..2])
    }

    #[cfg(test)]
    fn blob_path(&self, blob: &str) -> String {
        self.store.show(&self.blob_rel(blob))
    }

    fn encrypt_stream<W: Write>(&self, reader: Box<dyn Read>, out: W) -> R<W> {
        let recipient = self.key.to_public();
        let encryptor = age::Encryptor::with_recipients(once(&recipient as &dyn age::Recipient))
            .map_err(|e| format!("preparing encryption: {e}"))?;
        encrypt_to(encryptor, false, reader, out)
    }

    /// Decrypt a complete in-memory ciphertext to the end, so age has authenticated
    /// every chunk and the final-chunk flag. Plaintext is never longer than its
    /// ciphertext, so this buffer never reallocates (which would leave an unwiped
    /// copy behind in freed heap). Only for the manifest, which is parsed whole;
    /// files go through `verify_into`.
    fn decrypt_in_ram(&self, ciphertext: &[u8]) -> R<Zeroizing<Vec<u8>>> {
        let dec = age::Decryptor::new(ciphertext).map_err(|e| e.to_string())?;
        let mut stream = dec.decrypt(once(&self.key as &dyn age::Identity)).map_err(|e| e.to_string())?;
        let mut plain = Zeroizing::new(Vec::with_capacity(ciphertext.len()));
        stream.read_to_end(&mut plain).map_err(|e| e.to_string())?;
        Ok(plain)
    }

    fn decrypt_manifest(&self, data: &[u8]) -> R<Manifest> {
        let text = self.decrypt_in_ram(data).map_err(|_| "the vault's manifest is damaged or was replaced".to_string())?;
        let text = std::str::from_utf8(&text).map_err(|_| "the vault's manifest is not valid text".to_string())?;
        Manifest::parse(text).map_err(|e| format!("the vault's manifest is invalid: {e}"))
    }

    fn load_manifest(&self) -> R<Manifest> {
        if self.store.kind(MANIFEST_FILE) == Kind::Missing {
            self.recover_manifest();
        }
        let data = self.store.read(MANIFEST_FILE)
            .map_err(|e| format!("reading the vault's manifest: {e}"))?;
        self.decrypt_manifest(&data)
    }

    /// Android: a store that can't rename over a file commits a new manifest by
    /// deleting the old one, then renaming the staged one in (`commit_staged`). If
    /// the app was killed in between, the staged file is the committed state: put it
    /// in place, if it decrypts with this vault's key and parses. One that doesn't is
    /// left alone, and the vault reports its manifest missing.
    fn recover_manifest(&self) {
        let staged = staging_path(MANIFEST_FILE);
        if self.store.kind(&staged) != Kind::File {
            return;
        }
        let Ok(data) = self.store.read(&staged) else { return };
        if self.decrypt_manifest(&data).is_ok() {
            let _ = self.store.rename(&staged, MANIFEST_FILE);
            self.store.sync_dir("");
        }
    }

    /// The desktop's RAM-only rule, as a stream: read the blob once (no re-open, so
    /// no TOCTOU), hashing every byte on its way into age, decrypt it to the end into
    /// `out`, then check the hash against the manifest. Returns the plaintext length.
    ///
    /// Plaintext reaches `out` before the last check, so `out` must be private
    /// staging the caller deletes unless this returns Ok (`stage`), or a sink.
    ///
    /// age reads to the end of the blob and refuses anything after its last chunk,
    /// so on success the hash has covered the whole file. A blob age can't decrypt
    /// is one that was changed (the manifest pins what this vault wrote), and is
    /// refused at once, without reading the rest of what may be an enormous file.
    fn verify_into(&self, path: &str, blob: &str, sha256: &str, out: &mut dyn Write) -> R<u64> {
        let file = self.store.open(&self.blob_rel(blob)).map_err(|e| match e.kind() {
            io::ErrorKind::NotFound => format!("'{path}': its encrypted data is missing from the vault"),
            _ => format!("'{path}': reading its encrypted data: {e}"),
        })?;
        let changed = || format!("'{path}' failed verification: its encrypted data was changed or replaced");
        let mut hashing = HashingReader { inner: file, hasher: Sha256::new(), failed: None };
        let mut wrote: Option<String> = None;
        let decrypted = (|| -> Option<u64> {
            let dec = age::Decryptor::new(io::BufReader::new(&mut hashing)).ok()?;
            let mut stream = dec.decrypt(once(&self.key as &dyn age::Identity)).ok()?;
            let mut buf = Zeroizing::new(vec![0u8; COPY_CHUNK]);
            let mut total = 0u64;
            loop {
                let n = match stream.read(&mut buf) {
                    Ok(0) => return Some(total),
                    Ok(n) => n,
                    Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
                    Err(_) => return None,
                };
                if let Err(e) = out.write_all(&buf[..n]) {
                    wrote = Some(format!("'{path}': staging its plaintext: {e}"));
                    return None;
                }
                self.progress.advance(n as u64);
                total += n as u64;
            }
        })();
        if let Some(e) = hashing.failed {
            return Err(format!("'{path}': reading its encrypted data: {e}"));
        }
        if let Some(e) = wrote {
            return Err(e);
        }
        let total = decrypted.ok_or_else(changed)?;
        if hex(&hashing.hasher.finalize()) != sha256 {
            return Err(changed());
        }
        Ok(total)
    }

    /// One file's plaintext, verified (`verify_into`) into private staging in the
    /// app's storage, and its length. Nothing of it is anywhere else; the staging is
    /// deleted when the result is dropped, or at once if verification fails.
    fn stage(&self, path: &str, blob: &str, sha256: &str) -> R<(StagedFile, u64)> {
        let (staged, mut file) = StagedFile::create(&self.staging, "vault")?;
        let size = self.verify_into(path, blob, sha256, &mut file)?;
        // No fsync: staging is meant to vanish if the app dies (it's swept at the next
        // start), and reading it back is served from the page cache, so a flush per
        // file would only slow a large extract. The output is fsynced, as before.
        file.flush().map_err(|e| format!("'{path}': staging its plaintext: {e}"))?;
        Ok((staged, size))
    }

    fn write_manifest(&self, m: &Manifest) -> R<()> {
        let text = Zeroizing::new(m.serialize());
        // Never commit a manifest that could not be read back: that would lock the
        // user out of every file in the vault.
        if Manifest::parse(&text).as_ref() != Ok(m) {
            return Err("internal error: manifest does not round-trip; nothing changed".into());
        }
        write_atomic(&*self.store, MANIFEST_FILE, |file| {
            self.encrypt_stream(Box::new(Cursor::new(text)), file)
        })?;
        self.store.sync_dir("");
        Ok(())
    }

    /// Every change goes through here: load the manifest, let `edit` change it (writing
    /// any new blobs), and commit it as the next generation. If that fails, the blobs
    /// `edit` wrote are deleted again, unless the manifest naming them may still take
    /// effect: a store that can't rename over a file (SAF) deletes the old manifest
    /// before renaming the new one in, and if that rename fails, the staged manifest is
    /// the committed state, which `recover_manifest` puts in place at the next open.
    fn change<T>(&self, edit: impl FnOnce(&mut Manifest) -> R<T>) -> R<T> {
        let old = self.load_manifest()?;
        let mut m = old.clone();
        self.written.borrow_mut().clear();
        let changed = edit(&mut m).and_then(|done| self.commit_next(&old, m).map(|()| done));
        let written = self.written.take();
        if changed.is_err() && self.store.kind(&staging_path(MANIFEST_FILE)) != Kind::File {
            for blob in written {
                let _ = self.store.remove_file(&self.blob_rel(&blob));
            }
        }
        changed
    }

    /// The write protocol, once any new blobs are durable: bump the generation and
    /// rename the manifest into place (the commit point), then delete the blobs this
    /// change dropped from `old`. A crash at any moment leaves the old vault or the new
    /// one, never a mix. Nothing else is deleted, since a blob no manifest here names may
    /// be another device's change that hasn't finished syncing: `clean` removes those,
    /// when the user asks.
    fn commit_next(&self, old: &Manifest, mut m: Manifest) -> R<()> {
        m.generation = m.generation.checked_add(1).ok_or("generation counter overflow")?;
        self.write_manifest(&m)?;
        let dropped = old.blobs().difference(&m.blobs()).map(|blob| self.blob_rel(blob)).collect();
        self.delete_blobs(dropped);
        Ok(())
    }

    /// Blob files in the vault that `m` does not reference, relative to the vault.
    /// Only files named exactly blobs/<2 hex>/<32 hex>.age[.vaultsend-part] qualify;
    /// nothing else under blobs/ is ever reported or deleted. A symlink is neither
    /// entered nor deleted.
    fn orphans(&self, m: &Manifest) -> R<Vec<String>> {
        let live = m.blobs();
        let part_suffix = staging_path("");
        let mut found = Vec::new();
        for (aa, kind) in self.store.list(BLOBS_DIR)? {
            if !is_hex(&aa, 2) || kind != Kind::Dir {
                continue;
            }
            for (name, kind) in self.store.list(&format!("{BLOBS_DIR}/{aa}"))? {
                let part = name.strip_suffix(part_suffix.as_str());
                let Some(id) = part.unwrap_or(&name).strip_suffix(".age") else { continue };
                if !is_hex(id, 32) || kind != Kind::File {
                    continue;
                }
                if part.is_some() || aa != id[..2] || !live.contains(id) {
                    found.push(format!("{BLOBS_DIR}/{aa}/{name}"));
                }
            }
        }
        Ok(found)
    }

    /// Delete these blob files (paths in the vault), and say how many went. Only a
    /// warning if one can't be: this runs after the commit point, so the vault is
    /// already correct, and Verify all will offer the rest again.
    fn delete_blobs(&self, doomed: Vec<String>) -> usize {
        // Deleting has no bytes to measure, so it counts blobs instead.
        if self.progress.total.get() == 0 {
            self.progress.start(doomed.len() as u64);
        }
        for (removed, rel) in doomed.iter().enumerate() {
            if let Err(e) = self.store.remove_file(rel) {
                if self.store.kind(rel) != Kind::Missing {
                    self.warn(format!("could not remove an unused blob: {}: {e}", self.store.show(rel)));
                    return removed;
                }
            }
            self.progress.advance(1);
        }
        doomed.len()
    }

    /// Encrypt one source file to a new blob: stage, hash while writing, fsync, rename.
    fn write_blob(&self, source: Box<dyn Read>) -> R<Entry> {
        let mut raw = [0u8; 16];
        rand::rngs::OsRng.fill_bytes(&mut raw);
        let blob = hex(&raw);
        let rel = self.blob_rel(&blob);
        self.store.mkdir(parent_rel(&rel), true)?;
        let mut sha256 = String::new();
        let size = Rc::new(Cell::new(0));
        write_atomic(&*self.store, &rel, |out| {
            let hashing = HashingWriter { inner: out, hasher: Sha256::new() };
            let reader = CountingReader { inner: source, progress: self.progress.clone(), count: size.clone() };
            let hashing = self.encrypt_stream(Box::new(reader), hashing)?;
            sha256 = hex(&hashing.hasher.finalize());
            Ok(hashing.inner)
        })?;
        // The manifest will name this blob, so its directory entry must be durable
        // before the manifest's is.
        self.store.sync_dir(parent_rel(&rel));
        self.store.sync_dir(BLOBS_DIR);
        self.written.borrow_mut().push(blob.clone());
        Ok(Entry::File { blob, sha256, size: size.get() })
    }

    pub fn add_from(&self, sources: &dyn Sources, dest: Option<&str>, replace: bool) -> R<()> {
        let skipped = self.change(|m| self.add_to(m, sources, dest, replace))?;
        if skipped > 0 {
            self.warn(format!("skipped {skipped} item(s) that are not regular files or folders"));
        }
        Ok(())
    }

    /// Returns how many sources were skipped as neither a file nor a folder.
    fn add_to(&self, m: &mut Manifest, sources: &dyn Sources, dest: Option<&str>, replace: bool) -> R<usize> {
        let dest = dest.filter(|d| *d != ROOT_ENTRY);
        if let Some(d) = dest {
            if !valid_vault_path(d) {
                return Err(format!("invalid vault path: {d}"));
            }
            for folder in ancestors(d).chain(once(d)) {
                if matches!(m.entries.get(folder), Some(Entry::File { .. })) {
                    return Err(format!("'{folder}' is a file, not a folder"));
                }
                m.entries.entry(folder.to_string()).or_insert(Entry::Dir);
            }
        }
        let (items, skipped) = sources.plan()?;
        let mut plan = BTreeMap::new();
        for (rel, source) in items {
            let target = dest.map_or(rel.clone(), |d| format!("{d}/{rel}"));
            if !valid_vault_path(&target) {
                return Err(format!("can't store this path in a vault: {target}"));
            }
            if plan.insert(target.clone(), source).is_some() {
                return Err(format!("two sources would both be stored as '{target}'"));
            }
        }
        if plan.is_empty() {
            return Err("nothing to add: not a regular file or folder".into());
        }
        // Every folder a new entry goes in must be a folder, in the vault or among the
        // sources. The manifest would refuse anything else at commit time, but only
        // after the blobs were written, and as an internal error.
        for path in plan.keys() {
            for folder in ancestors(path) {
                let is_dir = match plan.get(folder) {
                    Some(source) => source.is_none(),
                    None => m.entries.get(folder) == Some(&Entry::Dir),
                };
                if !is_dir {
                    return Err(format!("'{folder}' is not a folder in the vault, so '{path}' can't go in it"));
                }
            }
        }
        // Decide everything before writing anything, so a name clash costs nothing.
        for (path, source) in &plan {
            let Some(existing) = m.entries.get(path) else { continue };
            if !replace {
                return Err(format!("'{path}' already exists in the vault"));
            }
            if (*existing == Entry::Dir) != source.is_none() {
                return Err(format!("'{path}': a file can't replace a folder, or a folder a file"));
            }
        }
        let sizes = plan.values().flatten().map(|index| sources.size(*index));
        self.progress.start(sizes.fold(0, u64::saturating_add));
        for (path, source) in plan {
            let entry = match source {
                None => Entry::Dir,
                Some(index) => self.write_blob(sources.open(index)?)?,
            };
            m.entries.insert(path, entry);
        }
        Ok(skipped)
    }

    /// All of these or none of them: one new manifest, so one new generation.
    pub fn remove(&self, entries: &[&str]) -> R<()> {
        if let Some(bad) = entries.iter().find(|e| !valid_vault_path(e)) {
            return Err(format!("invalid vault path: {bad}"));
        }
        self.change(|m| {
            if let Some(missing) = entries.iter().find(|e| !m.entries.contains_key(**e)) {
                return Err(format!("'{missing}' is not in the vault"));
            }
            m.entries.retain(|path, _| entries.iter().all(|entry| within(path, entry).is_none()));
            Ok(())
        })
    }

    /// Empties the vault and leaves it in place. Its own flag rather than
    /// `--entry /`, so that no path, however it got built, can mean this by accident.
    pub fn remove_everything(&self) -> R<()> {
        self.change(|m| {
            m.entries.clear();
            Ok(())
        })
    }

    /// Rename or move `from`, a file or a folder with everything in it, to `to`,
    /// which must not exist yet and must be in a folder that does. Android only (the
    /// app's Rename…). Only the manifest changes: every blob stays as it is, so a
    /// folder of any size is one commit, and nothing is decrypted.
    pub fn rename(&self, from: &str, to: &str) -> R<()> {
        for p in [from, to] {
            if !valid_vault_path(p) {
                return Err(format!("invalid vault path: {p}"));
            }
        }
        if from == to {
            // Nothing to commit, so no new generation.
            return match self.load_manifest()?.entries.contains_key(from) {
                true => Ok(()),
                false => Err(format!("'{from}' is not in the vault")),
            };
        }
        self.change(|m| self.rename_in(m, from, to))
    }

    fn rename_in(&self, m: &mut Manifest, from: &str, to: &str) -> R<()> {
        if !m.entries.contains_key(from) {
            return Err(format!("'{from}' is not in the vault"));
        }
        if m.entries.contains_key(to) {
            return Err(format!("'{to}' already exists in the vault"));
        }
        if within(to, from).is_some() {
            return Err(format!("'{from}' can't be moved inside itself"));
        }
        if let Some(folder) = ancestors(to).find(|f| m.entries.get(*f) != Some(&Entry::Dir)) {
            return Err(format!("'{folder}' is not a folder in the vault, so '{to}' can't go in it"));
        }
        let moving: Vec<(String, String)> = m.entries.keys().filter_map(|old| {
            let rest = within(old, from)?;
            Some((old.clone(), if rest.is_empty() { to.to_string() } else { format!("{to}/{rest}") }))
        }).collect();
        if let Some((_, bad)) = moving.iter().find(|(_, new)| !valid_vault_path(new)) {
            return Err(format!("can't store this path in a vault: {bad}"));
        }
        for (old, new) in moving {
            let entry = m.entries.remove(&old).expect("listed above");
            m.entries.insert(new, entry);
        }
        Ok(())
    }

    /// Save `text` as the file `path`: a note written in the app (Android only). With
    /// `previous`, it takes the place of that file, an edited note that may also have
    /// been renamed, in the same commit. A different file already at `path` is
    /// replaced only if `replace`; a folder never is. The folder it goes in must exist.
    pub fn write_text(&self, path: &str, text: &[u8], previous: Option<&str>, replace: bool) -> R<()> {
        self.change(|m| self.write_text_to(m, path, text, previous, replace))
    }

    fn write_text_to(&self, m: &mut Manifest, path: &str, text: &[u8], previous: Option<&str>, replace: bool) -> R<()> {
        for p in once(path).chain(previous) {
            if !valid_vault_path(p) {
                return Err(format!("invalid vault path: {p}"));
            }
        }
        if let Some(p) = previous {
            if !matches!(m.entries.get(p), Some(Entry::File { .. })) {
                return Err(format!("'{p}' is not a file in the vault"));
            }
        }
        if let Some(folder) = ancestors(path).find(|f| m.entries.get(*f) != Some(&Entry::Dir)) {
            return Err(format!("'{folder}' is not a folder in the vault, so '{path}' can't go in it"));
        }
        match m.entries.get(path) {
            Some(Entry::Dir) => return Err(format!("'{path}': a file can't replace a folder, or a folder a file")),
            Some(Entry::File { .. }) if previous != Some(path) && !replace => {
                return Err(format!("'{path}' already exists in the vault"));
            }
            _ => {}
        }
        self.progress.start(text.len() as u64);
        let entry = self.write_blob(Box::new(Cursor::new(Zeroizing::new(text.to_vec()))))?;
        if let Some(p) = previous {
            m.entries.remove(p);
        }
        m.entries.insert(path.to_string(), entry);
        Ok(())
    }

    /// One file's whole plaintext, verified, for the app's note editor (Android only).
    /// Refused, before anything is decrypted, if the manifest says it is over `max`
    /// bytes. It is held only in a buffer of exactly the manifest's size, wiped when
    /// dropped, which a file longer than that (so not this vault's) can't overrun.
    pub fn read_text(&self, entry: &str, max: u64) -> R<Zeroizing<Vec<u8>>> {
        let m = self.load_manifest()?;
        let Some(Entry::File { blob, sha256, size }) = m.entries.get(entry) else {
            return Err(format!("'{entry}' is not a file in the vault"));
        };
        if *size > max {
            return Err(format!("'{entry}' is too large to edit as a note"));
        }
        self.progress.start(*size);
        let mut plain = Zeroizing::new(Vec::with_capacity(*size as usize));
        let mut out = Capped { buf: &mut plain, cap: *size as usize };
        self.verify_into(entry, blob, sha256, &mut out)?;
        Ok(plain)
    }

    pub fn extract_to(&self, entry: &str, out: Out) -> R<()> {
        refuse_out_inside_vault(&*self.store, &out)?;
        let m = self.load_manifest()?;
        match m.entries.get(entry) {
            Some(Entry::File { blob, sha256, size }) => {
                self.progress.start(size.saturating_mul(2)); // once decrypting, once writing
                let (staged, _) = self.stage(entry, blob, sha256)?;
                let mut plain = staged.open()?;
                // Only now does anything reach the output.
                write_out(out, |file, shown| copy_counted(&mut plain, file, &self.progress, shown).map(drop))
            }
            Some(Entry::Dir) => self.extract_folder(&m, entry, out),
            None if entry == ROOT_ENTRY => self.extract_folder(&m, entry, out),
            None => Err(format!("'{entry}' is not in the vault")),
        }
    }

    fn extract_folder(&self, m: &Manifest, entry: &str, out: Out) -> R<()> {
        let wanted = m.entries.keys().filter_map(|path| {
            within(path, entry).filter(|rel| !rel.is_empty()).map(|rel| (path.as_str(), rel))
        });
        self.extract_tree(m, wanted.collect(), out)
    }

    /// Several entries into a new folder `out`, each keeping its path from the top of the
    /// vault, so two files with one name can't collide.
    pub fn extract_many_to(&self, entries: &[&str], out: Out) -> R<()> {
        refuse_out_inside_vault(&*self.store, &out)?;
        let m = self.load_manifest()?;
        let wanted = m.selection(entries)?.into_iter().map(|path| (path, path));
        self.extract_tree(&m, wanted.collect(), out)
    }

    /// `wanted` is (path in the vault, path under `out`), parents first.
    /// Verify and decrypt every file first, each into private staging; if any fails,
    /// nothing at all is written. The tree is then built under a staging name and
    /// renamed into place, so `out` is only ever absent or complete.
    fn extract_tree(&self, m: &Manifest, wanted: Vec<(&str, &str)>, out: Out) -> R<()> {
        let Out::In(folder, out) = out else {
            return Err("a folder can only be extracted into a folder".into());
        };
        if folder.kind(out) != Kind::Missing {
            return Err(format!("{} already exists; choose a new folder name", folder.show(out)));
        }
        self.progress.start(m.size_of(wanted.iter().map(|(path, _)| *path)).saturating_mul(2));
        let mut tree = Vec::new();
        for (path, rel) in wanted {
            tree.push((rel, match &m.entries[path] {
                Entry::Dir => None,
                Entry::File { blob, sha256, .. } => Some(self.stage(path, blob, sha256)?.0),
            }));
        }
        let tmp = staging_path(out);
        folder.remove_tree(&tmp); // a killed run's leftovers; the suffix is ours
        let staged = write_tree(folder, &tmp, tree, &self.progress).and_then(|_| {
            folder.rename(&tmp, out).map_err(|e| format!("finalizing {}: {e}", folder.show(out)))
        });
        if staged.is_err() {
            folder.remove_tree(&tmp);
        }
        staged?;
        folder.sync_dir("");
        Ok(())
    }

    /// Re-encrypt entries for other people, as a plain age file anyone with VaultSend or the
    /// `age` tool can open: not a vault, because `self` vaults only open for whoever sealed
    /// them. One file stays that file; anything else becomes a tar archive inside the age
    /// file. Same rule as extract: everything verifies, into private staging, before
    /// `out` is touched.
    pub fn share_to(&self, entries: &[&str], to: &[&str], out: Out) -> R<()> {
        let recipients: Vec<x25519::Recipient> = to.iter()
            .map(|r| r.parse().map_err(|e| format!("invalid recipient '{r}': {e}")))
            .collect::<R<_>>()?;
        if recipients.is_empty() {
            return Err("--to is required".into());
        }
        let encryptor = age::Encryptor::with_recipients(recipients.iter().map(|r| r as &dyn age::Recipient))
            .map_err(|e| format!("preparing encryption: {e}"))?;
        self.share_with(entries, encryptor, out)
    }

    /// Share for anyone who knows `password`, rather than for chosen people: the same
    /// plain age file, encrypted with scrypt at the cost a password vault uses, so
    /// VaultSend (Open file…, or Add existing vault) or `age -d` opens it. The same
    /// floor on the password as a password vault's.
    pub fn share_password(&self, entries: &[&str], password: &[u8], out: Out) -> R<()> {
        self.share_with(entries, password_encryptor(password, share_work_factor())?, out)
    }

    fn share_with(&self, entries: &[&str], encryptor: age::Encryptor, out: Out) -> R<()> {
        refuse_out_inside_vault(&*self.store, &out)?;
        let m = self.load_manifest()?;
        let chosen = m.selection(entries)?;
        if chosen.is_empty() {
            return Err("there is nothing in the vault to share".into());
        }
        let one_file = matches!(entries, [one] if matches!(m.entries.get(*one), Some(Entry::File { .. })));
        let plain_bytes = m.size_of(chosen.iter().copied());
        // Decrypting counts once and encrypting again, with the archive's headers on top.
        let overhead = if one_file { 0 } else { (chosen.len() as u64 + 2) * 512 };
        self.progress.start(plain_bytes.saturating_mul(2).saturating_add(overhead));

        let now = SystemTime::now().duration_since(UNIX_EPOCH).map_or(0, |t| t.as_secs());
        let mut parts = VecDeque::new();
        for path in chosen {
            match &m.entries[path] {
                Entry::Dir if one_file => {} // only the folders leading to it
                Entry::Dir => parts.push_back(Part::Bytes(Zeroizing::new(tar::dir_header(path, now)))),
                Entry::File { blob, sha256, .. } => {
                    let (plain, size) = self.stage(path, blob, sha256)?;
                    if one_file {
                        parts.push_back(Part::Staged(plain));
                    } else {
                        parts.push_back(Part::Bytes(Zeroizing::new(tar::file_header(path, size, now)?)));
                        parts.push_back(Part::Staged(plain));
                        parts.push_back(Part::Bytes(Zeroizing::new(tar::padding(size))));
                    }
                }
            }
        }
        if !one_file {
            parts.push_back(Part::Bytes(Zeroizing::new(tar::END.to_vec())));
        }
        let reader = Parts { parts, reading: None, progress: self.progress.clone() };
        write_out(out, |file, _| encrypt_to(encryptor, false, reader, file).map(drop))
    }

    /// Names and sizes only, never content.
    pub fn listing(&self) -> R<String> {
        let m = self.load_manifest()?;
        let mut out = format!("generation {}\n", m.generation);
        for (path, entry) in &m.entries {
            let path = escape_path(path);
            out.push_str(&match entry {
                Entry::Dir => format!("D {path}\n"),
                Entry::File { size, .. } => format!("F {size} {path}\n"),
            });
        }
        Ok(out)
    }

    /// Every file verified as extract verifies it, discarding the plaintext as it
    /// goes; stops at the first failure. Orphans, blob files the manifest doesn't name,
    /// are reported but are no failure: an interrupted change leaves them, and so does
    /// another device's change that hasn't finished syncing. `clean` removes them.
    pub fn check(&self) -> R<String> {
        self.verify_all(false)
    }

    /// `check`, then, only if every file verified, delete the orphans it found. Needs
    /// the vault open for changes.
    pub fn clean(&self) -> R<String> {
        self.verify_all(true)
    }

    fn verify_all(&self, clean: bool) -> R<String> {
        let m = self.load_manifest()?;
        let orphans = self.orphans(&m)?;
        if !orphans.is_empty() && !clean {
            self.warn(format!("{} blob file(s) on disk are not in the manifest", orphans.len()));
        }
        self.progress.start(m.size_of(m.entries.keys().map(String::as_str)));
        let mut report = String::new();
        if !clean {
            for orphan in &orphans {
                report.push_str(&format!("orphan {orphan}\n"));
            }
        }
        let mut verified = 0;
        for (path, entry) in &m.entries {
            if let Entry::File { blob, sha256, .. } = entry {
                self.verify_into(path, blob, sha256, &mut io::sink())?;
                verified += 1;
            }
        }
        if clean && !orphans.is_empty() {
            report.push_str(&format!("removed {} unused blob file(s)\n", self.delete_blobs(orphans)));
        }
        report.push_str(&format!("ok {verified} file(s) verified\n"));
        Ok(report)
    }
}

/// scrypt cost of a password share: a password vault's. Tests use less, so they stay
/// fast; the work factor is in the file, so either opens the same way.
fn share_work_factor() -> u8 {
    if cfg!(test) { 10 } else { SCRYPT_LOG_N }
}

// ---------------------------------------------------------------------------
// Making a vault (the desktop's `cmd_create`).
// ---------------------------------------------------------------------------
pub fn create(store: Box<dyn Store>, mode: &str, secret: &Secret) -> R<()> {
    if store.list("").is_ok_and(|names| !names.is_empty()) {
        return Err(format!("{} already exists and is not empty", store.show("")));
    }
    let wrap = match mode {
        "self" => scrypt_encryptor(seal_secret(&secret.identity()?), SEAL_LOG_N)?,
        "password" => password_encryptor(secret.bytes.ok_or_else(|| PASSWORD_NEEDED.to_string())?, SCRYPT_LOG_N)?,
        other => return Err(format!("--mode must be self or password, not '{other}'")),
    };
    let vault = Vault::create_in(store, mode, wrap, secret.data_dir)?;
    if mode == "password" {
        // The password was just typed, so remember the key as if it had opened it.
        remember(&vault.store.key()?, &vault.key);
    }
    Ok(())
}

#[cfg(test)]
#[path = "vault_tests.rs"]
mod tests;
