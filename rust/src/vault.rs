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
// bookkeeping: hashes checked before decrypting, plaintext fully verified in RAM
// before a byte reaches disk, and age recipients being anonymous (the vault's public
// key is stored nowhere in the clear, so a manifest can't be forged without the key).
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

use std::any::Any;
use std::cell::{Cell, RefCell};
use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::fs::{self, DirBuilder, File};
use std::io::{self, Cursor, Read, Write};
use std::iter::once;
use std::os::unix::fs::{DirBuilderExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::rc::Rc;
use std::sync::Mutex;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use age::secrecy::{ExposeSecret, SecretString};
use age::x25519;
use rand::RngCore;
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

use crate::backend::{
    encrypt_to, load_identity, lock_in_ram, open_private_new, passphrase_from_bytes,
    secret_buffer, session_identity, Held, RamLock, SCRYPT_LOG_N,
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
const MIN_PASSWORD_CHARS: usize = 10;
/// How much plaintext goes by between progress reports, at most.
const PROGRESS_CHUNK: usize = 1 << 20;
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
        f.sync_all().map_err(|e| format!("flushing {shown}: {e}"))
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
    if !fs::metadata(path)?.is_file() {
        return Err(io::Error::other("not a regular file"));
    }
    fs::read(path)
}

fn parent_of(path: &str) -> &str {
    match Path::new(path).parent().and_then(Path::to_str) {
        Some("") | None => ".",
        Some(parent) => parent,
    }
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

/// Reads a list of buffers in order, wiping each one as soon as it has been read.
struct Parts {
    parts: VecDeque<Zeroizing<Vec<u8>>>,
    position: usize,
    progress: Rc<Progress>,
}

impl Read for Parts {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        while let Some(part) = self.parts.front() {
            let rest = &part[self.position..];
            if rest.is_empty() {
                self.parts.pop_front();
                self.position = 0;
                continue;
            }
            let n = rest.len().min(buf.len());
            buf[..n].copy_from_slice(&rest[..n]);
            self.position += n;
            self.progress.advance(n as u64);
            return Ok(n);
        }
        Ok(0)
    }
}

/// write_all, in pieces small enough for the percentage to keep moving.
fn write_counted(file: &mut File, data: &[u8], progress: &Progress, path: &str) -> R<()> {
    for piece in data.chunks(PROGRESS_CHUNK) {
        file.write_all(piece).map_err(|e| format!("writing {path}: {e}"))?;
        progress.advance(piece.len() as u64);
    }
    Ok(())
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
// needs nothing remembered, because it opens with the unlocked session key. The
// lifetime counts from when the key was remembered, as on desktop, and setting it
// forgets everything, as `set_lifetime` does there.
// ---------------------------------------------------------------------------
#[derive(Clone, Copy, PartialEq)]
enum Lifetime {
    Off,
    For(Duration),
    UntilClosed,
}

static LIFETIME: Mutex<Lifetime> = Mutex::new(Lifetime::Off);
/// Vault key text by the vault's store key, with when it expires.
static REMEMBERED: Mutex<BTreeMap<String, (Held, Option<SystemTime>)>> = Mutex::new(BTreeMap::new());

/// 0 remembers nothing, a negative number until the app closes, otherwise seconds.
pub fn set_remember(seconds: i64) {
    let lifetime = match seconds {
        0 => Lifetime::Off,
        s if s < 0 => Lifetime::UntilClosed,
        s => Lifetime::For(Duration::from_secs(s as u64)),
    };
    *LIFETIME.lock().unwrap_or_else(|e| e.into_inner()) = lifetime;
    forget_all();
}

fn remember(vault: &str, key: &x25519::Identity) {
    let expiry = match *LIFETIME.lock().unwrap_or_else(|e| e.into_inner()) {
        Lifetime::Off => return,
        Lifetime::For(d) => Some(SystemTime::now() + d),
        Lifetime::UntilClosed => None,
    };
    let held = Held::new(key.to_string());
    REMEMBERED.lock().unwrap_or_else(|e| e.into_inner()).insert(vault.to_string(), (held, expiry));
}

fn remembered(vault: &str) -> Option<x25519::Identity> {
    sweep();
    let keys = REMEMBERED.lock().unwrap_or_else(|e| e.into_inner());
    keys.get(vault)?.0.expose().parse().ok()
}

/// True if a key for this vault is remembered now.
pub fn is_remembered(vault: &str) -> bool {
    sweep();
    REMEMBERED.lock().unwrap_or_else(|e| e.into_inner()).contains_key(vault)
}

pub fn forget(vault: &str) {
    REMEMBERED.lock().unwrap_or_else(|e| e.into_inner()).remove(vault);
}

pub fn forget_all() {
    REMEMBERED.lock().unwrap_or_else(|e| e.into_inner()).clear();
}

/// Forget whatever has expired. Wall clock rather than monotonic, as on desktop,
/// so time asleep counts.
pub fn sweep() {
    let now = SystemTime::now();
    REMEMBERED.lock().unwrap_or_else(|e| e.into_inner()).retain(|_, (_, expiry)| !matches!(expiry, Some(t) if now >= *t));
}

// ---------------------------------------------------------------------------
// Sources and destinations.
// ---------------------------------------------------------------------------
/// Refuse an output that resolves to anywhere inside the vault: `name` within the
/// folder `out`. The name need not exist yet, so its folder is what gets resolved.
fn refuse_out_inside_vault(vault: &dyn Store, out: &dyn Store, name: &str) -> R<()> {
    let parent = out.key()?;
    let vault = vault.key()?;
    if Path::new(&parent).join(name).starts_with(vault) {
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

/// Real paths, walked as the desktop does.
pub struct PathSources {
    paths: Vec<String>,
    files: RefCell<Vec<PathBuf>>,
}

impl PathSources {
    pub fn new<S: AsRef<str>>(paths: &[S]) -> PathSources {
        PathSources { paths: paths.iter().map(|p| p.as_ref().to_string()).collect(), files: RefCell::default() }
    }
}

impl Sources for PathSources {
    fn plan(&self) -> R<Plan> {
        let mut plan = BTreeMap::new();
        let mut skipped = 0;
        for src in &self.paths {
            let src = Path::new(src);
            let name = src.file_name().and_then(|n| n.to_str());
            let name = name.ok_or_else(|| format!("{}: no usable file name", src.display()))?;
            plan_source(src, name, &mut plan, &mut skipped)?;
        }
        let mut files = self.files.borrow_mut();
        let items = plan.into_iter().map(|(target, src)| {
            (target, src.map(|path| {
                files.push(path);
                files.len() - 1
            }))
        });
        Ok((items.collect(), skipped))
    }

    fn open(&self, index: usize) -> R<Box<dyn Read>> {
        let src = &self.files.borrow()[index];
        let file = File::open(src).map_err(|e| format!("opening {}: {e}", src.display()))?;
        let meta = file.metadata().map_err(|e| format!("{}: {e}", src.display()))?;
        if !meta.is_file() {
            return Err(format!("{} is no longer a regular file", src.display()));
        }
        Ok(Box::new(file))
    }

    fn size(&self, index: usize) -> u64 {
        fs::symlink_metadata(&self.files.borrow()[index]).map_or(0, |meta| meta.len())
    }
}

/// Walk one source into `plan` (path -> None for a folder, Some(path) for a
/// file). Lstat throughout: symlinks, sockets, devices and FIFOs are never followed
/// or read, only counted.
fn plan_source(src: &Path, target: &str, plan: &mut BTreeMap<String, Option<PathBuf>>, skipped: &mut usize) -> R<()> {
    let fail = |e: io::Error| format!("{}: {e}", src.display());
    let meta = fs::symlink_metadata(src).map_err(fail)?;
    if !meta.is_file() && !meta.is_dir() {
        *skipped += 1;
        return Ok(());
    }
    if plan.insert(target.to_string(), meta.is_file().then(|| src.to_path_buf())).is_some() {
        return Err(format!("two sources would both be stored as '{target}'"));
    }
    if meta.is_dir() {
        for child in fs::read_dir(src).map_err(fail)? {
            let child = child.map_err(fail)?;
            let name = child.file_name();
            let name = name.to_str().ok_or_else(|| format!("{}: name is not valid UTF-8", child.path().display()))?;
            plan_source(&child.path(), &format!("{target}/{name}"), plan, skipped)?;
        }
    }
    Ok(())
}

/// Where extract and share write. The desktop always took a path (`--out`).
pub enum Out<'a> {
    /// A file the caller already made, such as a SAF document from "Save as"; it
    /// checked it isn't inside the vault and removes it if this fails. Written in place.
    File(&'a mut File),
    /// A new name in a folder: staged and renamed into place, as on desktop.
    In(&'a dyn Store, &'a str),
}

fn write_tree(store: &dyn Store, root: &str, tree: &[(&str, Option<Zeroizing<Vec<u8>>>)], progress: &Progress) -> R<()> {
    store.mkdir(root, false)?;
    // In manifest order, so every folder is created before its contents.
    for (rel, data) in tree {
        let path = format!("{root}/{rel}");
        match data {
            None => store.mkdir(&path, false)?,
            Some(data) => {
                // create_new would replace it, and on a case-insensitive disk
                // "A" and "a" are the same file: one would silently go missing.
                if store.kind(&path) != Kind::Missing {
                    return Err(format!("{}: two names in the vault collide on this disk", store.show(&path)));
                }
                let mut file = store.create_new(&path)?;
                write_counted(&mut file, data, progress, &store.show(&path))?;
                file.sync_all().map_err(|e| format!("flushing {}: {e}", store.show(&path)))?;
            }
        }
    }
    Ok(())
}

/// A path as an output: its folder as a store, and its name.
fn path_out(out: &str) -> R<(PathStore, String)> {
    let name = Path::new(out).file_name().and_then(|n| n.to_str());
    let name = name.ok_or_else(|| format!("--out must name a file or folder: {out}"))?;
    Ok((PathStore::new(parent_of(out)), name.to_string()))
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
    /// Held only for its lock, released when this is dropped.
    _lock: Option<Box<dyn Any>>,
    pub progress: Rc<Progress>,
    /// The desktop printed these to stderr as "warning: ...". Kept here so the app
    /// can show them; vault_cli still prints them.
    warnings: RefCell<Vec<String>>,
}

impl Vault {
    pub fn open_in(store: Box<dyn Store>, secret: &Secret, exclusive: bool) -> R<Vault> {
        let lock = store.lock(exclusive)?;
        let key = unlock(&*store, secret)?;
        Ok(Vault::with(store, key, Some(lock)))
    }

    fn with(store: Box<dyn Store>, key: x25519::Identity, lock: Option<Box<dyn Any>>) -> Vault {
        Vault { dir: store.show(""), store, key, _lock: lock, progress: Rc::default(), warnings: RefCell::default() }
    }

    /// `wrap` already holds key.age's wrapped file key, so scrypt (for a password
    /// vault) has run by now. VAULT goes last: its presence marks a complete vault.
    fn create_in(store: Box<dyn Store>, mode: &str, wrap: age::Encryptor) -> R<Vault> {
        let v = Vault::with(store, x25519::Identity::generate(), None);
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

    /// A vault on a real path (the desktop's `Vault::create`, kept for the tests).
    pub fn create(dir: &str, mode: &str, wrap: age::Encryptor) -> R<Vault> {
        Vault::create_in(Box::new(PathStore::new(dir)), mode, wrap)
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
    /// copy behind in freed heap).
    fn decrypt_in_ram(&self, ciphertext: &[u8], on_read: impl Fn(u64)) -> R<Zeroizing<Vec<u8>>> {
        let dec = age::Decryptor::new(ciphertext).map_err(|e| e.to_string())?;
        let mut stream = dec.decrypt(once(&self.key as &dyn age::Identity)).map_err(|e| e.to_string())?;
        let mut plain = Zeroizing::new(Vec::with_capacity(ciphertext.len()));
        loop {
            let n = (&mut stream).take(PROGRESS_CHUNK as u64).read_to_end(&mut plain).map_err(|e| e.to_string())?;
            if n == 0 {
                return Ok(plain);
            }
            on_read(n as u64);
        }
    }

    fn decrypt_manifest(&self, data: &[u8]) -> R<Manifest> {
        let text = self.decrypt_in_ram(data, |_| ()).map_err(|_| "the vault's manifest is damaged or was replaced".to_string())?;
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

    /// The RAM-only rule: read the whole blob once (no re-open, so no TOCTOU), check
    /// its hash against the manifest, decrypt to the end in memory. The caller gets
    /// plaintext only if all of that succeeded.
    fn read_verified(&self, path: &str, blob: &str, sha256: &str) -> R<Zeroizing<Vec<u8>>> {
        let data = self.store.read(&self.blob_rel(blob)).map_err(|e| match e.kind() {
            io::ErrorKind::NotFound => format!("'{path}': its encrypted data is missing from the vault"),
            _ => format!("'{path}': reading its encrypted data: {e}"),
        })?;
        if hex(&Sha256::digest(&data)) != sha256 {
            return Err(format!("'{path}' failed verification: its encrypted data was changed or replaced"));
        }
        self.decrypt_in_ram(&data, |n| self.progress.advance(n)).map_err(|e| format!("'{path}' failed to decrypt: {e}"))
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

    /// The write protocol, once any new blobs are durable: bump the generation and
    /// rename the manifest into place (the commit point), then delete everything the
    /// new manifest does not reference. A crash at any moment leaves the old vault or
    /// the new one, never a mix.
    fn commit_next(&self, mut m: Manifest) -> R<()> {
        m.generation = m.generation.checked_add(1).ok_or("generation counter overflow")?;
        self.write_manifest(&m)?;
        self.collect_garbage(&m);
        Ok(())
    }

    /// Blob files in the vault that `m` does not reference, relative to the vault.
    /// Only files named exactly blobs/<2 hex>/<32 hex>.age[.vaultsend-part] qualify;
    /// nothing else under blobs/ is ever reported or deleted. A symlink is neither
    /// entered nor deleted.
    fn orphans(&self, m: &Manifest) -> R<Vec<String>> {
        let live: BTreeSet<&str> = m.entries.values().filter_map(|e| match e {
            Entry::File { blob, .. } => Some(blob.as_str()),
            Entry::Dir => None,
        }).collect();
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

    /// Only a warning if this fails: it runs after the commit point, so the vault is
    /// already correct and the next change will try again.
    fn collect_garbage(&self, m: &Manifest) {
        let removed = self.orphans(m).and_then(|list| {
            // Deleting has no bytes to measure, so it counts blobs instead.
            if self.progress.total.get() == 0 {
                self.progress.start(list.len() as u64);
            }
            list.iter().try_for_each(|p| {
                self.store.remove_file(p).map_err(|e| format!("{}: {e}", self.store.show(p)))?;
                self.progress.advance(1);
                Ok(())
            })
        });
        if let Err(e) = removed {
            self.warn(format!("could not remove an unused blob: {e}"));
        }
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
        Ok(Entry::File { blob, sha256, size: size.get() })
    }

    /// Add files and folders from real paths (the desktop's `add`).
    pub fn add<S: AsRef<str>>(&self, sources: &[S], dest: Option<&str>, replace: bool) -> R<()> {
        self.add_from(&PathSources::new(sources), dest, replace)
    }

    pub fn add_from(&self, sources: &dyn Sources, dest: Option<&str>, replace: bool) -> R<()> {
        let old = self.load_manifest()?;
        let added = self.add_to(old.clone(), sources, dest, replace);
        if added.is_err() {
            self.collect_garbage(&old); // the failed attempt's blobs; old is still current
        }
        added
    }

    fn add_to(&self, mut m: Manifest, sources: &dyn Sources, dest: Option<&str>, replace: bool) -> R<()> {
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
        self.commit_next(m)?;
        if skipped > 0 {
            self.warn(format!("skipped {skipped} item(s) that are not regular files or folders"));
        }
        Ok(())
    }

    /// All of these or none of them: one new manifest, so one new generation.
    pub fn remove(&self, entries: &[&str]) -> R<()> {
        if let Some(bad) = entries.iter().find(|e| !valid_vault_path(e)) {
            return Err(format!("invalid vault path: {bad}"));
        }
        let mut m = self.load_manifest()?;
        if let Some(missing) = entries.iter().find(|e| !m.entries.contains_key(**e)) {
            return Err(format!("'{missing}' is not in the vault"));
        }
        m.entries.retain(|path, _| entries.iter().all(|entry| within(path, entry).is_none()));
        self.commit_next(m)
    }

    /// Empties the vault and leaves it in place. Its own flag rather than
    /// `--entry /`, so that no path, however it got built, can mean this by accident.
    pub fn remove_everything(&self) -> R<()> {
        let mut m = self.load_manifest()?;
        m.entries.clear();
        self.commit_next(m)
    }

    /// Extract to a real path (the desktop's `extract`).
    pub fn extract(&self, entry: &str, out: &str) -> R<()> {
        let (folder, name) = path_out(out)?;
        self.extract_to(entry, Out::In(&folder, &name))
    }

    pub fn extract_to(&self, entry: &str, out: Out) -> R<()> {
        if let Out::In(folder, name) = &out {
            refuse_out_inside_vault(&*self.store, *folder, name)?;
        }
        let m = self.load_manifest()?;
        match m.entries.get(entry) {
            Some(Entry::File { blob, sha256, size }) => {
                self.progress.start(size.saturating_mul(2)); // once decrypting, once writing
                let plain = self.read_verified(entry, blob, sha256)?;
                // Only now does anything reach the disk.
                match out {
                    Out::File(file) => {
                        write_counted(file, &plain, &self.progress, "the output")?;
                        file.flush().and_then(|_| file.sync_all()).map_err(|e| format!("writing the output: {e}"))
                    }
                    Out::In(folder, name) => {
                        write_atomic(folder, name, |mut file| {
                            write_counted(&mut file, &plain, &self.progress, &folder.show(name))?;
                            Ok(file)
                        })?;
                        folder.sync_dir("");
                        Ok(())
                    }
                }
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
    pub fn extract_many(&self, entries: &[&str], out: &str) -> R<()> {
        let (folder, name) = path_out(out)?;
        self.extract_many_to(entries, Out::In(&folder, &name))
    }

    pub fn extract_many_to(&self, entries: &[&str], out: Out) -> R<()> {
        if let Out::In(folder, name) = &out {
            refuse_out_inside_vault(&*self.store, *folder, name)?;
        }
        let m = self.load_manifest()?;
        let wanted = m.selection(entries)?.into_iter().map(|path| (path, path));
        self.extract_tree(&m, wanted.collect(), out)
    }

    /// `wanted` is (path in the vault, path under `out`), parents first.
    /// Verify and decrypt every file first; if any fails, nothing at all is written.
    /// The tree is then built under a staging name and renamed into place, so `out`
    /// is only ever absent or complete.
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
                Entry::File { blob, sha256, .. } => Some(self.read_verified(path, blob, sha256)?),
            }));
        }
        let tmp = staging_path(out);
        folder.remove_tree(&tmp); // a killed run's leftovers; the suffix is ours
        let staged = write_tree(folder, &tmp, &tree, &self.progress).and_then(|_| {
            folder.rename(&tmp, out).map_err(|e| format!("finalizing {}: {e}", folder.show(out)))
        });
        if staged.is_err() {
            folder.remove_tree(&tmp);
        }
        staged?;
        folder.sync_dir("");
        Ok(())
    }

    /// Share to a real path (the desktop's `share`).
    pub fn share(&self, entries: &[&str], to: &[&str], out: &str) -> R<()> {
        let (folder, name) = path_out(out)?;
        self.share_to(entries, to, Out::In(&folder, &name))
    }

    /// Re-encrypt entries for other people, as a plain age file anyone with VaultSend or the
    /// `age` tool can open: not a vault, because `self` vaults only open for whoever sealed
    /// them. One file stays that file; anything else becomes a tar archive inside the age
    /// file. Same RAM-only rule as extract: everything verifies before `out` is touched.
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
        let (password, _password_ram) = passphrase_from_bytes(password)?;
        if password.expose_secret().chars().count() < MIN_PASSWORD_CHARS {
            return Err(format!("use a password of at least {MIN_PASSWORD_CHARS} characters"));
        }
        let mut recipient = age::scrypt::Recipient::new(password);
        recipient.set_work_factor(share_work_factor());
        let encryptor = age::Encryptor::with_recipients(once(&recipient as &dyn age::Recipient))
            .map_err(|e| format!("preparing encryption: {e}"))?;
        self.share_with(entries, encryptor, out)
    }

    fn share_with(&self, entries: &[&str], encryptor: age::Encryptor, out: Out) -> R<()> {
        if let Out::In(folder, name) = &out {
            refuse_out_inside_vault(&*self.store, *folder, name)?;
        }
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
                Entry::Dir => parts.push_back(Zeroizing::new(tar::dir_header(path, now))),
                Entry::File { blob, sha256, .. } => {
                    let plain = self.read_verified(path, blob, sha256)?;
                    let size = plain.len() as u64;
                    if one_file {
                        parts.push_back(plain);
                    } else {
                        parts.push_back(Zeroizing::new(tar::file_header(path, size, now)?));
                        parts.push_back(plain);
                        parts.push_back(Zeroizing::new(tar::padding(size)));
                    }
                }
            }
        }
        if !one_file {
            parts.push_back(Zeroizing::new(tar::END.to_vec()));
        }
        let reader = Parts { parts, position: 0, progress: self.progress.clone() };
        match out {
            Out::File(file) => {
                let file = encrypt_to(encryptor, false, reader, file)?;
                file.flush().and_then(|_| file.sync_all()).map_err(|e| format!("writing the output: {e}"))
            }
            Out::In(folder, name) => {
                write_atomic(folder, name, |file| encrypt_to(encryptor, false, reader, file))?;
                folder.sync_dir("");
                Ok(())
            }
        }
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

    /// The RAM-only rule for every file, discarding the plaintext; stops at the first
    /// failure. Orphans are reported but are no failure: a crash leaves them behind
    /// and the next change removes them.
    pub fn check(&self) -> R<String> {
        let m = self.load_manifest()?;
        let orphans = self.orphans(&m)?;
        if !orphans.is_empty() {
            self.warn(format!("{} blob file(s) on disk are not in the manifest", orphans.len()));
        }
        self.progress.start(m.size_of(m.entries.keys().map(String::as_str)));
        let mut report = String::new();
        for orphan in &orphans {
            report.push_str(&format!("orphan {orphan}\n"));
        }
        let mut verified = 0;
        for (path, entry) in &m.entries {
            if let Entry::File { blob, sha256, .. } = entry {
                self.read_verified(path, blob, sha256)?;
                verified += 1;
            }
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
        "self" => {
            let identity = secret.identity()?;
            let (seal, _seal_ram) = seal_secret(&identity);
            let mut recipient = age::scrypt::Recipient::new(seal);
            recipient.set_work_factor(SEAL_LOG_N);
            age::Encryptor::with_recipients(once(&recipient as &dyn age::Recipient))
        }
        "password" => {
            let bytes = secret.bytes.ok_or_else(|| PASSWORD_NEEDED.to_string())?;
            let (password, _password_ram) = passphrase_from_bytes(bytes)?;
            if password.expose_secret().chars().count() < MIN_PASSWORD_CHARS {
                return Err(format!("use a password of at least {MIN_PASSWORD_CHARS} characters"));
            }
            let mut recipient = age::scrypt::Recipient::new(password);
            recipient.set_work_factor(SCRYPT_LOG_N);
            age::Encryptor::with_recipients(once(&recipient as &dyn age::Recipient))
        }
        other => return Err(format!("--mode must be self or password, not '{other}'")),
    }
    .map_err(|e| format!("preparing the vault key: {e}"))?;
    let vault = Vault::create_in(store, mode, wrap)?;
    if mode == "password" {
        // The password was just typed, so remember the key as if it had opened it.
        remember(&vault.store.key()?, &vault.key);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::vault_cli::{parse_opts, run};
    use std::os::unix::io::FromRawFd;
    use std::sync::atomic::{AtomicU32, Ordering};
    use std::sync::Once;

    const ID_PASS: &str = "test identity passphrase";
    const VAULT_PASS: &str = "test vault password";

    /// A pipe holding `pass`, as the frontend hands it over.
    fn pass_fd(pass: &str) -> i32 {
        let mut fds = [0i32; 2];
        assert_eq!(unsafe { libc::pipe(fds.as_mut_ptr()) }, 0);
        let mut w = unsafe { File::from_raw_fd(fds[1]) };
        w.write_all(pass.as_bytes()).unwrap();
        fds[0]
    }

    /// One throwaway identity per test process. XDG_DATA_HOME and HOME are pointed
    /// into a temp dir before anything can read them, so the real key is unreachable.
    fn test_env() {
        static INIT: Once = Once::new();
        INIT.call_once(|| {
            let root = std::env::temp_dir().join(format!("vs-test-env-{}", std::process::id()));
            fs::create_dir_all(&root).unwrap();
            std::env::set_var("XDG_DATA_HOME", &root);
            std::env::set_var("HOME", &root);
            // backend::keygen would also unlock the session, which other tests watch.
            let data_dir = crate::vault_cli::data_dir();
            fs::create_dir_all(&data_dir).unwrap();
            let identity = x25519::Identity::generate();
            let encryptor = crate::backend::identity_encryptor(SecretString::from(ID_PASS.to_string())).unwrap();
            let file = File::create(format!("{data_dir}/identity.age")).unwrap();
            let secret = identity.to_string();
            encrypt_to(encryptor, false, secret.expose_secret().as_bytes(), file).unwrap();
            fs::write(crate::backend::pubkey_path(&data_dir), identity.to_public().to_string()).unwrap();
        });
    }

    struct TempDir(String);

    impl TempDir {
        fn new() -> TempDir {
            test_env();
            static NEXT: AtomicU32 = AtomicU32::new(0);
            let n = NEXT.fetch_add(1, Ordering::SeqCst);
            let p = std::env::temp_dir().join(format!("vs-test-{}-{n}", std::process::id()));
            fs::create_dir_all(&p).unwrap();
            TempDir(p.to_str().unwrap().to_string())
        }
        fn path(&self, rel: &str) -> String {
            format!("{}/{rel}", self.0)
        }
        fn write(&self, rel: &str, data: &[u8]) -> String {
            let p = self.path(rel);
            fs::create_dir_all(parent_of(&p)).unwrap();
            fs::write(&p, data).unwrap();
            p
        }
    }

    impl Drop for TempDir {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    fn args(a: &[&str]) -> Vec<String> {
        a.iter().map(|s| s.to_string()).collect()
    }

    /// A vault held open in memory: no scrypt, so the tamper tests stay fast. The
    /// real unlock path is exercised by the two round-trip tests.
    fn quick_vault(t: &TempDir) -> Vault {
        let dir = t.path("v.vsvault");
        let throwaway = x25519::Identity::generate().to_public();
        let wrap = age::Encryptor::with_recipients(once(&throwaway as &dyn age::Recipient)).unwrap();
        Vault::create(&dir, "self", wrap).unwrap()
    }

    fn add(v: &Vault, src: &str) {
        v.add(&[src.to_string()], None, false).unwrap();
    }

    fn generation(v: &Vault) -> u64 {
        v.load_manifest().unwrap().generation
    }

    fn blob_of(v: &Vault, path: &str) -> String {
        match v.load_manifest().unwrap().entries.get(path) {
            Some(Entry::File { blob, .. }) => v.blob_path(blob),
            other => panic!("{path}: {other:?}"),
        }
    }

    fn assert_nothing_written(out: &str) {
        assert!(!Path::new(out).exists(), "{out} must not exist");
        let part = staging_path(out);
        assert!(!Path::new(&part).exists(), "{part} must not exist");
    }

    fn fake_entry() -> Entry {
        Entry::File { blob: "a".repeat(32), sha256: "b".repeat(64), size: 5 }
    }

    fn roundtrip_cli(t: &TempDir, mode: &str, pass: &str) {
        let dir = t.path("vault.vsvault");
        run("vault-create", &args(&["--dir", &dir, "--mode", mode, "--pass-fd", &pass_fd(pass).to_string()])).unwrap();
        let random: Vec<u8> = (0..200_000u32).map(|i| (i.wrapping_mul(2654435761) >> 24) as u8).collect();
        let boundary = vec![7u8; 65536];
        t.write("src/tree/nested/deep/random.bin", &random);
        t.write("src/tree/nested/boundary.bin", &boundary);
        t.write("src/tree/empty.txt", b"");
        t.write("src/tree/one.txt", b"x");
        t.write("src/tree/spaced name %and ünïcode.txt", b"names survive");
        fs::create_dir_all(t.path("src/tree/empty-folder")).unwrap();

        let fd = || pass_fd(pass).to_string();
        run("vault-add", &args(&["--dir", &dir, "--pass-fd", &fd(), "--src", &t.path("src/tree")])).unwrap();

        // vault-list goes to stdout, so check its source directly.
        let v = Vault::open(&dir, pass_fd(pass), false).unwrap();
        let listing = v.listing().unwrap();
        assert!(listing.starts_with("generation 1\n"), "{listing}");
        assert!(listing.contains("D tree/empty-folder\n"), "{listing}");
        assert!(listing.contains("F 0 tree/empty.txt\n"), "{listing}");
        assert!(listing.contains("F 65536 tree/nested/boundary.bin\n"), "{listing}");
        assert!(listing.contains("F 13 tree/spaced%20name%20%25and%20%C3%BCn%C3%AFcode.txt\n"), "{listing}");
        drop(v);

        let out = t.path("out");
        run("vault-extract", &args(&["--dir", &dir, "--pass-fd", &fd(), "--entry", "/", "--out", &out])).unwrap();
        assert_eq!(fs::read(format!("{out}/tree/nested/deep/random.bin")).unwrap(), random);
        assert_eq!(fs::read(format!("{out}/tree/nested/boundary.bin")).unwrap(), boundary);
        assert_eq!(fs::read(format!("{out}/tree/empty.txt")).unwrap(), b"");
        assert_eq!(fs::read(format!("{out}/tree/one.txt")).unwrap(), b"x");
        assert_eq!(fs::read(format!("{out}/tree/spaced name %and ünïcode.txt")).unwrap(), b"names survive");
        assert!(Path::new(&format!("{out}/tree/empty-folder")).is_dir());

        let one = t.path("one-out.txt");
        run("vault-extract", &args(&["--dir", &dir, "--pass-fd", &fd(), "--entry", "tree/one.txt", "--out", &one])).unwrap();
        assert_eq!(fs::read(&one).unwrap(), b"x");
        assert_eq!(fs::metadata(&one).unwrap().permissions().mode() & 0o777, 0o600);

        run("vault-check", &args(&["--dir", &dir, "--pass-fd", &fd()])).unwrap();
        run("vault-remove", &args(&["--dir", &dir, "--pass-fd", &fd(), "--entry", "tree/one.txt"])).unwrap();
        let gone = t.path("gone");
        assert!(run("vault-extract", &args(&["--dir", &dir, "--pass-fd", &fd(), "--entry", "tree/one.txt", "--out", &gone])).is_err());
        assert_nothing_written(&gone);
    }

    #[test]
    fn roundtrip_self_mode() {
        let t = TempDir::new();
        roundtrip_cli(&t, "self", ID_PASS);
    }

    #[test]
    fn roundtrip_password_mode() {
        let t = TempDir::new();
        roundtrip_cli(&t, "password", VAULT_PASS);
    }

    #[test]
    fn wrong_secret_and_wrong_mode_are_clean_errors() {
        let t = TempDir::new();
        let pw = t.path("pw.vsvault");
        let own = t.path("own.vsvault");
        run("vault-create", &args(&["--dir", &pw, "--mode", "password", "--pass-fd", &pass_fd(VAULT_PASS).to_string()])).unwrap();
        run("vault-create", &args(&["--dir", &own, "--mode", "self", "--pass-fd", &pass_fd(ID_PASS).to_string()])).unwrap();
        let open_err = |d: &str, p: &str| Vault::open(d, pass_fd(p), false).err().unwrap();

        assert!(open_err(&pw, "not the vault password").contains("wrong password"));
        assert!(open_err(&own, "not the identity pass").contains("wrong passphrase"));

        // VAULT is a hint: flip it and unlocking fails cleanly, it doesn't crash.
        let flip = |d: &str, mode: &str| fs::write(format!("{d}/VAULT"), format!("vaultsend-vault 1\nmode {mode}\n")).unwrap();
        flip(&pw, "self");
        assert!(open_err(&pw, ID_PASS).contains("does not open with your key"));
        flip(&own, "password");
        assert!(open_err(&own, ID_PASS).contains("wrong password"));

        flip(&pw, "nonsense");
        assert!(open_err(&pw, ID_PASS).contains("understands"));
        fs::remove_file(format!("{pw}/VAULT")).unwrap();
        assert!(open_err(&pw, ID_PASS).contains("not a VaultSend vault"));

        // A damaged key.age is an error too.
        fs::write(format!("{own}/key.age"), b"garbage").unwrap();
        flip(&own, "self");
        assert!(open_err(&own, ID_PASS).contains("damaged"));
    }

    /// The attack sealing exists for: someone who can write to the folder builds a
    /// complete, valid vault around a key they know, wrapped to the user's public key,
    /// which is all age would ask of them. Without the seal it opens and passes every
    /// check, and whatever the user adds next is readable by whoever built it.
    #[test]
    fn a_vault_forged_from_the_public_key_is_refused() {
        let t = TempDir::new();
        let dir = t.path("forged.vsvault");
        let public = fs::read_to_string(crate::backend::pubkey_path(&crate::vault_cli::data_dir())).unwrap();
        let own = public.trim().parse::<x25519::Recipient>().unwrap();
        let wrap = age::Encryptor::with_recipients(once(&own as &dyn age::Recipient)).unwrap();
        let forged = Vault::create(&dir, "self", wrap).unwrap();
        add(&forged, &t.write("planted.txt", b"planted by the forger"));
        assert_eq!(generation(&forged), 1);
        let blobs = fs::read_dir(format!("{dir}/blobs")).unwrap().count();

        let err = Vault::open(&dir, pass_fd(ID_PASS), false).err().unwrap();
        assert!(err.contains("does not open with your key"), "{err}");

        // Through the CLI too, for a mutating command, and nothing is changed.
        let fd = pass_fd(ID_PASS).to_string();
        let src = t.write("secret.txt", b"would be readable by the forger");
        let err = run("vault-add", &args(&["--dir", &dir, "--pass-fd", &fd, "--src", &src])).unwrap_err();
        assert!(err.contains("does not open with your key"), "{err}");
        assert_eq!(fs::read_dir(format!("{dir}/blobs")).unwrap().count(), blobs);
    }

    /// key.age from another of the user's own vaults is genuine, so it unseals, but it
    /// can't read this vault's manifest.
    #[test]
    fn a_key_file_from_another_vault_cannot_read_this_one() {
        let t = TempDir::new();
        let (dir, other) = (t.path("mine.vsvault"), t.path("other.vsvault"));
        for d in [&dir, &other] {
            run("vault-create", &args(&["--dir", d, "--mode", "self", "--pass-fd", &pass_fd(ID_PASS).to_string()])).unwrap();
        }
        fs::copy(format!("{other}/key.age"), format!("{dir}/key.age")).unwrap();
        let v = Vault::open(&dir, pass_fd(ID_PASS), false).unwrap();
        assert!(v.load_manifest().err().unwrap().contains("manifest"));
    }

    /// A hang would fail this by never finishing, and would freeze the window the same way.
    #[test]
    fn a_fifo_in_a_vault_is_refused_rather_than_waited_on() {
        let t = TempDir::new();
        let fifo = t.path("fifo");
        let c_path = std::ffi::CString::new(fifo.as_str()).unwrap();
        // SAFETY: mkfifo only reads the path, which outlives the call.
        assert_eq!(unsafe { libc::mkfifo(c_path.as_ptr(), 0o600) }, 0);
        assert!(read_regular(&fifo).is_err());
        fs::create_dir(t.path("v")).unwrap();
        fs::rename(&fifo, t.path("v/VAULT")).unwrap();
        assert!(lock_vault(&t.path("v"), false).is_err());
    }

    #[test]
    fn create_rules() {
        let t = TempDir::new();
        let fd = || pass_fd(ID_PASS).to_string();
        let d = t.path("short.vsvault");
        let short = pass_fd("too short").to_string();
        let err = run("vault-create", &args(&["--dir", &d, "--mode", "password", "--pass-fd", &short])).unwrap_err();
        assert!(err.contains("at least 10"), "{err}");
        assert!(!Path::new(&d).exists());

        // A self vault takes the private key, so it can't be made from the public key alone.
        let err = run("vault-create", &args(&["--dir", &d, "--mode", "self"])).unwrap_err();
        assert!(err.contains("--pass-fd"), "{err}");
        let wrong = pass_fd("not the identity passphrase").to_string();
        let err = run("vault-create", &args(&["--dir", &d, "--mode", "self", "--pass-fd", &wrong])).unwrap_err();
        assert!(err.contains("wrong passphrase"), "{err}");
        assert!(!Path::new(&d).exists());

        t.write("full/file", b"x");
        assert!(run("vault-create", &args(&["--dir", &t.path("full"), "--mode", "self", "--pass-fd", &fd()])).unwrap_err().contains("not empty"));
        assert_eq!(fs::read(t.path("full/file")).unwrap(), b"x");

        fs::create_dir(t.path("empty")).unwrap();
        run("vault-create", &args(&["--dir", &t.path("empty"), "--mode", "self", "--pass-fd", &fd()])).unwrap();
        assert_eq!(fs::read_to_string(t.path("empty/VAULT")).unwrap(), "vaultsend-vault 1\nmode self\n");
        // Sealed, and not wrapped to the public key.
        let key = fs::read(t.path("empty/key.age")).unwrap();
        assert!(key.windows(9).any(|w| w == b"-> scrypt") && !key.windows(9).any(|w| w == b"-> X25519"));
        assert!(run("vault-create", &args(&["--dir", &d, "--mode", "other"])).is_err());
        for name in ["key.age", "manifest.age", "VAULT"] {
            assert_eq!(fs::metadata(t.path(&format!("empty/{name}"))).unwrap().permissions().mode() & 0o777, 0o600);
        }
        assert_eq!(fs::metadata(t.path("empty")).unwrap().permissions().mode() & 0o777, 0o700);
    }

    #[test]
    fn manifest_round_trip() {
        let mut m = Manifest { generation: 42, entries: BTreeMap::new() };
        m.entries.insert("a".into(), Entry::Dir);
        m.entries.insert("a/b c".into(), Entry::Dir);
        m.entries.insert("a/b c/ünï%.txt".into(), fake_entry());
        m.entries.insert("a/new\nline".into(), fake_entry());
        m.entries.insert("z".into(), Entry::Dir);
        assert_eq!(Manifest::parse(&m.serialize()).unwrap(), m);
        assert_eq!(Manifest::parse(&Manifest::default().serialize()).unwrap(), Manifest::default());
    }

    #[test]
    fn manifest_rejects_malformed() {
        let (id, sha) = ("a".repeat(32), "b".repeat(64));
        let head = "vaultsend-manifest 1\ngeneration 1\n";
        let cases = [
            ("unknown version", "vaultsend-manifest 2\ngeneration 1\n".to_string()),
            ("no generation", "vaultsend-manifest 1\n".to_string()),
            ("bad generation", "vaultsend-manifest 1\ngeneration x\n".to_string()),
            ("signed generation", "vaultsend-manifest 1\ngeneration +1\n".to_string()),
            ("padded generation", "vaultsend-manifest 1\ngeneration 01\n".to_string()),
            ("unknown record", format!("{head}X foo\n")),
            ("short F", format!("{head}F {id} {sha} 1\n")),
            ("short hex id", format!("{head}F {} {sha} 1 a\n", "a".repeat(31))),
            ("upper hex id", format!("{head}F {} {sha} 1 a\n", "A".repeat(32))),
            ("non-hex id", format!("{head}F {} {sha} 1 a\n", "g".repeat(32))),
            ("short hash", format!("{head}F {id} {} 1 a\n", "b".repeat(63))),
            ("bad size", format!("{head}F {id} {sha} one a\n")),
            ("negative size", format!("{head}F {id} {sha} -1 a\n")),
            ("padded size", format!("{head}F {id} {sha} 01 a\n")),
            ("duplicate", format!("{head}D a\nD a\n")),
            ("file is also folder", format!("{head}F {id} {sha} 1 a\nD a\n")),
            ("file used as parent", format!("{head}F {id} {sha} 1 a\nF {id} {sha} 1 a/b\n")),
            ("missing parent", format!("{head}F {id} {sha} 1 a/b\n")),
            ("extra field", format!("{head}D a b\n")),
            ("traversal", format!("{head}D a\nD a/..\n")),
            ("escaped traversal", format!("{head}D %2E%2E\n")),
            ("absolute", format!("{head}D /a\n")),
            ("escaped slash", format!("{head}D a%2Fb\n")),
            ("unescaped byte", format!("{head}D a+b\n")),
            ("lowercase escape", format!("{head}D a%c3%bc\n")),
            ("bad escape", format!("{head}D a%2\n")),
            ("not utf-8", format!("{head}D %FF\n")),
            ("escaped NUL", format!("{head}D a%00b\n")),
            ("blank line", format!("{head}D a\n\n")),
            ("trailing junk", format!("{head}D a\ntrailing")),
            ("no final newline", format!("{head}D a")),
            ("CRLF", "vaultsend-manifest 1\r\ngeneration 1\r\n".to_string()),
            ("empty", String::new()),
        ];
        for (why, text) in &cases {
            assert!(Manifest::parse(text).is_err(), "accepted {why}: {text:?}");
        }
        assert!(Manifest::parse(&format!("{head}D a\nF {id} {sha} 1 a/b\n")).is_ok());
    }

    #[test]
    fn vault_path_rules() {
        for bad in ["", "/a", "a//b", "./a", "a/..", "../x", "a/./b", "a/", "/", ".", "..", "a\0b"] {
            assert!(!valid_vault_path(bad), "accepted {bad:?}");
        }
        assert!(!valid_vault_path(&"x".repeat(256)));
        assert!(!valid_vault_path(&vec!["y".repeat(200); 21].join("/"))); // > 4096 total
        for good in ["a", "a/b/c", "with space", "ünï/cödé.txt", "..hidden", "a.", "%25", "new\nline", "-x"] {
            assert!(valid_vault_path(good), "rejected {good:?}");
        }
        assert!(valid_vault_path(&"x".repeat(255)));
        assert_eq!(unescape_path(&escape_path("sp ace/ünï%")).unwrap(), "sp ace/ünï%");
        assert_eq!(escape_path("a b/c"), "a%20b/c");
        assert_eq!(escape_path("AZaz09._~/-"), "AZaz09._~/-");
    }

    #[test]
    fn tampered_blobs_fail_and_write_nothing() {
        let t = TempDir::new();
        let v = quick_vault(&t);
        add(&v, &t.write("a.txt", b"contents of a"));
        add(&v, &t.write("b.txt", b"contents of b"));
        let (a, b) = (blob_of(&v, "a.txt"), blob_of(&v, "b.txt"));
        let (a_bytes, b_bytes) = (fs::read(&a).unwrap(), fs::read(&b).unwrap());
        let out = t.path("out.txt");

        // Flip one byte.
        let mut flipped = a_bytes.clone();
        *flipped.last_mut().unwrap() ^= 1;
        fs::write(&a, &flipped).unwrap();
        assert!(v.extract("a.txt", &out).unwrap_err().contains("failed verification"));
        assert_nothing_written(&out);
        assert!(v.check().is_err());

        // Truncate.
        fs::write(&a, &a_bytes[..a_bytes.len() - 10]).unwrap();
        assert!(v.extract("a.txt", &out).unwrap_err().contains("failed verification"));
        assert_nothing_written(&out);

        // Swap two blobs' files.
        fs::write(&a, &b_bytes).unwrap();
        fs::write(&b, &a_bytes).unwrap();
        assert!(v.extract("a.txt", &out).unwrap_err().contains("failed verification"));
        assert_nothing_written(&out);

        // Delete: a clear error that says so.
        fs::write(&b, &b_bytes).unwrap();
        fs::remove_file(&a).unwrap();
        assert!(v.extract("a.txt", &out).unwrap_err().contains("missing"));
        assert_nothing_written(&out);
        assert!(v.check().unwrap_err().contains("missing"));

        // The other file was never affected.
        v.extract("b.txt", &out).unwrap();
        assert_eq!(fs::read(&out).unwrap(), b"contents of b");
    }

    #[test]
    fn previous_blob_for_the_same_path_is_rejected() {
        let t = TempDir::new();
        let v = quick_vault(&t);
        add(&v, &t.write("doc.txt", b"version one"));
        let old = fs::read(blob_of(&v, "doc.txt")).unwrap();
        v.add(&[t.write("doc.txt", b"version two")], None, true).unwrap();
        fs::write(blob_of(&v, "doc.txt"), &old).unwrap();
        let out = t.path("out.txt");
        assert!(v.extract("doc.txt", &out).unwrap_err().contains("failed verification"));
        assert_nothing_written(&out);
    }

    #[test]
    fn manifest_tampering_is_a_clean_error() {
        let t = TempDir::new();
        let v = quick_vault(&t);
        add(&v, &t.write("a.txt", b"aaa"));
        let path = format!("{}/manifest.age", v.dir);
        let mut flipped = fs::read(&path).unwrap();
        *flipped.last_mut().unwrap() ^= 1;
        fs::write(&path, &flipped).unwrap();
        assert!(v.load_manifest().unwrap_err().contains("damaged"));

        // A manifest encrypted to some other key: what a forger without the vault's
        // public key would have to produce.
        let other = Vault::with(Box::new(PathStore::new(&v.dir)), x25519::Identity::generate(), None);
        other.write_manifest(&Manifest::default()).unwrap();
        assert!(v.load_manifest().unwrap_err().contains("damaged"));
    }

    #[test]
    fn old_manifest_lists_the_old_generation_and_fails_on_replaced_files() {
        let t = TempDir::new();
        let v = quick_vault(&t);
        add(&v, &t.write("a.txt", b"one"));
        let path = format!("{}/manifest.age", v.dir);
        let old = fs::read(&path).unwrap();
        v.add(&[t.write("a.txt", b"two")], None, true).unwrap();
        assert_eq!(generation(&v), 2);
        fs::write(&path, &old).unwrap();
        // The backend reports the lower generation; the frontend compares it.
        assert_eq!(generation(&v), 1);
        let out = t.path("out.txt");
        assert!(v.extract("a.txt", &out).is_err());
        assert_nothing_written(&out);
    }

    #[test]
    fn replace_keeps_every_other_blob_byte_identical() {
        let t = TempDir::new();
        let v = quick_vault(&t);
        for name in ["a.txt", "b.txt", "c.txt"] {
            add(&v, &t.write(name, name.as_bytes()));
        }
        let (a, c) = (blob_of(&v, "a.txt"), blob_of(&v, "c.txt"));
        let (a_bytes, c_bytes) = (fs::read(&a).unwrap(), fs::read(&c).unwrap());
        let old_b = blob_of(&v, "b.txt");

        let src = t.write("b.txt", b"new b");
        let err = v.add(&[src.clone()], None, false).unwrap_err();
        assert!(err.contains("'b.txt' already exists"), "{err}");

        v.add(&[src], None, true).unwrap();
        assert_eq!(fs::read(&a).unwrap(), a_bytes);
        assert_eq!(fs::read(&c).unwrap(), c_bytes);
        assert!(!Path::new(&old_b).exists(), "replaced blob must be collected");
        let out = t.path("out.txt");
        v.extract("b.txt", &out).unwrap();
        assert_eq!(fs::read(&out).unwrap(), b"new b");
    }

    #[test]
    fn add_clash_rules() {
        let t = TempDir::new();
        let v = quick_vault(&t);
        t.write("one/thing/inner.txt", b"x");
        add(&v, &t.path("one/thing"));
        let before = generation(&v);

        // A folder clash without --replace names the path and changes nothing.
        assert!(v.add(&[t.path("one/thing")], None, false).unwrap_err().contains("'thing' already exists"));
        // --replace never turns a folder into a file or a file into a folder.
        let file_named_thing = t.write("two/thing", b"file");
        assert!(v.add(&[file_named_thing], None, true).unwrap_err().contains("can't replace"));
        t.write("three/inner.txt/deep", b"y");
        assert!(v.add(&[t.path("three/inner.txt")], Some("thing"), true).unwrap_err().contains("can't replace"));
        // Nor can a file become a destination folder.
        assert!(v.add(&[t.path("one/thing")], Some("thing/inner.txt"), false).unwrap_err().contains("not a folder"));
        // Two sources can't land on one name.
        let dup = [t.write("p/same", b"1"), t.write("q/same", b"2")];
        assert!(v.add(&dup, None, false).unwrap_err().contains("both"));
        assert_eq!(generation(&v), before);

        // Merge with --replace: new files join, unrelated files stay.
        t.write("one/thing/second.txt", b"z");
        v.add(&[t.path("one/thing")], None, true).unwrap();
        let m = v.load_manifest().unwrap();
        assert!(m.entries.contains_key("thing/inner.txt") && m.entries.contains_key("thing/second.txt"));
    }

    #[test]
    fn add_into_dest_creates_parents() {
        let t = TempDir::new();
        let v = quick_vault(&t);
        v.add(&[t.write("f.txt", b"x")], Some("a/b/c"), false).unwrap();
        let m = v.load_manifest().unwrap();
        for folder in ["a", "a/b", "a/b/c"] {
            assert_eq!(m.entries.get(folder), Some(&Entry::Dir));
        }
        assert!(m.entries.contains_key("a/b/c/f.txt"));
        assert!(v.add(&[t.path("f.txt")], Some("../x"), false).unwrap_err().contains("invalid"));
        assert!(v.add(&[t.path("f.txt")], Some("/"), false).is_ok());
        assert!(v.load_manifest().unwrap().entries.contains_key("f.txt"));
    }

    /// Sources listed in any order, missing a folder, or putting a file inside a file.
    struct Listed(Vec<(String, Option<usize>)>);

    impl Sources for Listed {
        fn plan(&self) -> R<Plan> {
            Ok((self.0.clone(), 0))
        }
        fn open(&self, _: usize) -> R<Box<dyn Read>> {
            Ok(Box::new(Cursor::new(b"data".to_vec())))
        }
        fn size(&self, _: usize) -> u64 {
            4
        }
    }

    #[test]
    fn sources_must_bring_the_folders_they_go_in() {
        let t = TempDir::new();
        let v = quick_vault(&t);
        let blobs = || fs::read_dir(t.path("v.vsvault/blobs")).unwrap().count();
        let before = blobs();
        let missing = Listed(vec![("a/b.txt".into(), Some(0))]);
        let err = v.add_from(&missing, None, false).unwrap_err();
        assert!(err.contains("'a' is not a folder"), "{err}");
        let in_a_file = Listed(vec![("f".into(), Some(0)), ("f/x".into(), Some(1))]);
        assert!(v.add_from(&in_a_file, None, false).unwrap_err().contains("'f' is not a folder"));
        assert_eq!((generation(&v), blobs()), (0, before), "nothing written");
        // A folder already in the vault will do, and so will one among the sources.
        v.add_from(&Listed(vec![("a".into(), None), ("a/b.txt".into(), Some(0))]), None, false).unwrap();
        v.add_from(&Listed(vec![("a/c.txt".into(), Some(0))]), None, false).unwrap();
        assert!(v.listing().unwrap().ends_with("D a\nF 4 a/b.txt\nF 4 a/c.txt\n"));
    }

    #[test]
    fn add_skips_specials_and_never_touches_sources() {
        let t = TempDir::new();
        let v = quick_vault(&t);
        let real = t.write("tree/real.txt", b"real");
        let secret = t.write("secret.txt", b"must not be followed");
        std::os::unix::fs::symlink(&secret, t.path("tree/link.txt")).unwrap();
        std::os::unix::fs::symlink(t.path(""), t.path("tree/link-dir")).unwrap();
        let fifo = std::ffi::CString::new(t.path("tree/fifo")).unwrap();
        assert_eq!(unsafe { libc::mkfifo(fifo.as_ptr(), 0o600) }, 0);
        add(&v, &t.path("tree"));

        let m = v.load_manifest().unwrap();
        let names: Vec<&str> = m.entries.keys().map(String::as_str).collect();
        assert_eq!(names, ["tree", "tree/real.txt"]);
        assert_eq!(fs::read(&real).unwrap(), b"real");

        // A top-level symlink alone is nothing to add.
        let err = v.add(&[t.path("tree/link.txt")], None, false).unwrap_err();
        assert!(err.contains("nothing to add"), "{err}");
    }

    #[test]
    fn remove_keeps_other_blobs_and_deletes_the_removed_one() {
        let t = TempDir::new();
        let v = quick_vault(&t);
        add(&v, &t.write("keep.txt", b"keep"));
        add(&v, &t.write("drop.txt", b"drop"));
        t.write("dir/sub/x.txt", b"x");
        t.write("dir/y.txt", b"y");
        add(&v, &t.path("dir"));
        let keep = blob_of(&v, "keep.txt");
        let keep_bytes = fs::read(&keep).unwrap();
        let dropped = [blob_of(&v, "drop.txt"), blob_of(&v, "dir/sub/x.txt"), blob_of(&v, "dir/y.txt")];

        v.remove(&["drop.txt"]).unwrap();
        assert!(!Path::new(&dropped[0]).exists());
        assert_eq!(fs::read(&keep).unwrap(), keep_bytes);

        // Recursive for a folder; a sibling sharing the prefix survives.
        add(&v, &t.write("dir2", b"sibling"));
        v.remove(&["dir"]).unwrap();
        assert!(!Path::new(&dropped[1]).exists() && !Path::new(&dropped[2]).exists());
        let m = v.load_manifest().unwrap();
        let names: Vec<&str> = m.entries.keys().map(String::as_str).collect();
        assert_eq!(names, ["dir2", "keep.txt"]);

        assert!(v.remove(&["missing"]).unwrap_err().contains("not in the vault"));
        assert!(v.remove(&["/"]).unwrap_err().contains("invalid"));
        assert!(v.remove(&["../keep.txt"]).unwrap_err().contains("invalid"));
    }

    #[test]
    fn crash_leftovers_are_collected_and_old_contents_survive() {
        let t = TempDir::new();
        let v = quick_vault(&t);
        add(&v, &t.write("a.txt", b"aaa"));
        let a = blob_of(&v, "a.txt");

        // A crash after a blob was written but before the manifest was committed,
        // and one mid-write of each of the blob and the manifest.
        let stray = t.write("v.vsvault/blobs/ab/abababababababababababababababab.age", b"stray");
        let stray_part = t.write("v.vsvault/blobs/ab/cdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcd.age.vaultsend-part", b"partial");
        let manifest_part = t.write("v.vsvault/manifest.age.vaultsend-part", b"half a manifest");
        // A referenced blob's own half-written replacement is garbage as well.
        let live_part = format!("{a}.vaultsend-part");
        fs::write(&live_part, b"partial").unwrap();

        // Reading ignores all of it, and check reports the orphans without failing.
        assert_eq!(generation(&v), 1);
        let report = v.check().unwrap();
        assert!(report.contains("orphan blobs/ab/abababababababababababababababab.age\n"), "{report}");
        assert!(report.contains("ok 1 file(s) verified"), "{report}");

        add(&v, &t.write("b.txt", b"bbb"));
        for gone in [&stray, &stray_part, &manifest_part, &live_part] {
            assert!(!Path::new(gone).exists(), "{gone} should have been collected");
        }
        assert!(Path::new(&a).exists());
        let m = v.load_manifest().unwrap();
        assert!(m.entries.contains_key("a.txt") && m.entries.contains_key("b.txt"));
        assert!(!v.check().unwrap().contains("orphan"));
    }

    #[test]
    fn gc_never_deletes_anything_else() {
        let t = TempDir::new();
        let v = quick_vault(&t);
        let id = "ab".repeat(16);
        let safe = [
            t.write("v.vsvault/blobs/notes.txt", b"mine"),
            t.write("v.vsvault/blobs/ab/readme.txt", b"mine"),
            t.write(&format!("v.vsvault/blobs/ab/{}.age", id.to_uppercase()), b"mine"),
            t.write(&format!("v.vsvault/blobs/ab/{}.age", &id[..31]), b"mine"),
            t.write(&format!("v.vsvault/blobs/ab/{id}a.age"), b"mine"),
            t.write(&format!("v.vsvault/blobs/ab/{id}.age.bak"), b"mine"),
            t.write(&format!("v.vsvault/blobs/ab/{id}.txt"), b"mine"),
            t.write(&format!("v.vsvault/blobs/zz/{id}.age"), b"mine"),
            t.write(&format!("v.vsvault/blobs/abc/{id}.age"), b"mine"),
            t.write(&format!("v.vsvault/{id}.age"), b"mine"),
        ];
        // A symlink named like a blob folder must not be walked into.
        let outside = t.write(&format!("outside/{id}.age"), b"mine");
        std::os::unix::fs::symlink(parent_of(&outside), t.path("v.vsvault/blobs/cd")).unwrap();

        add(&v, &t.write("a.txt", b"aaa"));
        v.remove(&["a.txt"]).unwrap();
        for f in safe.iter().chain([&outside]) {
            assert_eq!(fs::read(f).unwrap(), b"mine", "{f} was touched");
        }
    }

    #[test]
    fn generation_goes_up_by_exactly_one_per_change() {
        let t = TempDir::new();
        let v = quick_vault(&t);
        assert_eq!(generation(&v), 0);
        add(&v, &t.write("a.txt", b"a"));
        assert_eq!(generation(&v), 1);
        v.add(&[t.path("a.txt")], None, true).unwrap();
        assert_eq!(generation(&v), 2);
        // Several sources in one call are one change.
        v.add(&[t.write("b.txt", b"b"), t.write("c.txt", b"c")], None, false).unwrap();
        assert_eq!(generation(&v), 3);
        v.remove(&["a.txt"]).unwrap();
        assert_eq!(generation(&v), 4);
        // Reads don't count, and a refused change doesn't either.
        v.extract("b.txt", &t.path("out.txt")).unwrap();
        v.check().unwrap();
        v.listing().unwrap();
        assert!(v.remove(&["nope"]).is_err());
        assert!(v.add(&[t.path("b.txt")], None, false).is_err());
        assert_eq!(generation(&v), 4);
    }

    #[test]
    fn failed_add_changes_nothing_and_leaves_no_blobs() {
        let t = TempDir::new();
        let v = quick_vault(&t);
        add(&v, &t.write("a.txt", b"a"));
        let before = v.load_manifest().unwrap();
        t.write("tree/fine.txt", b"fine");
        let unreadable = t.write("tree/z-unreadable.txt", b"no");
        fs::set_permissions(&unreadable, fs::Permissions::from_mode(0o000)).unwrap();
        // Root reads anything, so this only proves something as a normal user.
        if File::open(&unreadable).is_err() {
            assert!(v.add(&[t.path("tree")], None, false).is_err());
            assert_eq!(v.load_manifest().unwrap(), before);
            assert_eq!(v.orphans(&before).unwrap(), Vec::<String>::new());
        }
        fs::set_permissions(&unreadable, fs::Permissions::from_mode(0o600)).unwrap();
    }

    #[test]
    fn folder_extract_with_one_corrupt_file_writes_nothing() {
        let t = TempDir::new();
        let v = quick_vault(&t);
        for f in ["tree/a.txt", "tree/sub/b.txt", "tree/z.txt"] {
            t.write(f, f.as_bytes());
        }
        fs::create_dir_all(t.path("tree/empty")).unwrap();
        add(&v, &t.path("tree"));
        let z = blob_of(&v, "tree/z.txt");
        let good = fs::read(&z).unwrap();
        let mut bad = good.clone();
        bad[good.len() / 2] ^= 0x40;
        fs::write(&z, &bad).unwrap();

        let out = t.path("out");
        assert!(v.extract("tree", &out).unwrap_err().contains("tree/z.txt"));
        assert_nothing_written(&out);
        assert!(v.extract("/", &out).is_err());
        assert_nothing_written(&out);

        // Once repaired the same call works, and only the requested subtree comes out.
        fs::write(&z, &good).unwrap();
        v.extract("tree/sub", &out).unwrap();
        assert_eq!(fs::read(format!("{out}/b.txt")).unwrap(), b"tree/sub/b.txt");
        assert!(!Path::new(&format!("{out}/a.txt")).exists());
        // Staging is gone, and a second folder extract refuses the existing path.
        assert!(!Path::new(&staging_path(&out)).exists());
        assert!(v.extract("tree", &out).unwrap_err().contains("already exists"));
        assert_eq!(fs::metadata(&out).unwrap().permissions().mode() & 0o777, 0o700);
    }

    #[test]
    fn colliding_names_are_an_error_not_a_silent_loss() {
        let t = TempDir::new();
        // Two entries landing on one file, as "A" and "a" do on a case-insensitive disk.
        let data = Some(Zeroizing::new(b"y".to_vec()));
        let items = [("Name", data.clone()), ("Name", data)];
        assert!(write_tree(&PathStore::new(&t.0), "root", &items, &Progress::default()).unwrap_err().contains("collide"));
    }

    #[test]
    fn stale_folder_staging_is_replaced() {
        let t = TempDir::new();
        let v = quick_vault(&t);
        t.write("tree/a.txt", b"a");
        add(&v, &t.path("tree"));
        let out = t.path("out");
        t.write("out.vaultsend-part/leftover.txt", b"from a killed run");
        v.extract("tree", &out).unwrap();
        assert!(!Path::new(&format!("{out}/leftover.txt")).exists());
        assert_eq!(fs::read(format!("{out}/a.txt")).unwrap(), b"a");
    }

    #[test]
    fn out_must_not_be_inside_the_vault() {
        let t = TempDir::new();
        let v = quick_vault(&t);
        add(&v, &t.write("a.txt", b"a"));
        for bad in [v.dir.clone(), format!("{}/x", v.dir), format!("{}/blobs/x", v.dir)] {
            assert!(v.extract("a.txt", &bad).unwrap_err().contains("inside the vault"), "{bad}");
        }
        std::os::unix::fs::symlink(&v.dir, t.path("alias")).unwrap();
        assert!(v.extract("a.txt", &t.path("alias/x")).unwrap_err().contains("inside the vault"));
        assert!(v.extract("a.txt", "/").is_err());
    }

    #[test]
    fn unknown_entries_and_options_are_errors() {
        let t = TempDir::new();
        let v = quick_vault(&t);
        assert!(v.extract("../../etc/passwd", &t.path("o")).unwrap_err().contains("not in the vault"));
        assert_nothing_written(&t.path("o"));
        let strict = |a: &[&str]| parse_opts(&args(a)).err().unwrap();
        assert!(strict(&["--nope", "x"]).contains("unknown option"));
        assert!(strict(&["--dir"]).contains("needs a value"));
        assert!(parse_opts(&args(&["--pass-fd", "x"])).unwrap().pass_fd().unwrap_err().contains("number"));
        // A value that looks like a flag stays a value.
        let flaglike = args(&["--dest", "--replace", "--entry", "--out"]);
        let o = parse_opts(&flaglike).unwrap();
        assert!(!o.replace && o.get("--dest") == Some("--replace") && o.get("--entry") == Some("--out") && o.get("--out").is_none());
        assert!(run("vault-frob", &args(&["--dir", "x"])).unwrap_err().contains("unknown command"));
    }

    #[test]
    fn a_second_writer_is_refused() {
        let t = TempDir::new();
        let v = quick_vault(&t);
        let writer = lock_vault(&v.dir, true).unwrap();
        assert!(lock_vault(&v.dir, true).unwrap_err().contains("another"));
        assert!(lock_vault(&v.dir, false).unwrap_err().contains("another"));
        drop(writer);
        let reader_one = lock_vault(&v.dir, false).unwrap();
        let reader_two = lock_vault(&v.dir, false).unwrap();
        assert!(lock_vault(&v.dir, true).unwrap_err().contains("another"));
        drop((reader_one, reader_two));
        lock_vault(&v.dir, true).unwrap();
    }

    /// A vault holding a/1.txt, a/2.txt, a/sub/3.txt and top.txt.
    fn tree_vault(t: &TempDir) -> Vault {
        let v = quick_vault(t);
        let a = t.path("src/a");
        t.write("src/a/1.txt", b"one");
        t.write("src/a/2.txt", b"two");
        t.write("src/a/sub/3.txt", b"three");
        add(&v, &a);
        add(&v, &t.write("src/top.txt", b"top"));
        v
    }

    fn paths(v: &Vault) -> Vec<String> {
        v.load_manifest().unwrap().entries.into_keys().collect()
    }

    #[test]
    fn removing_several_is_one_change_and_overlaps_are_fine() {
        let t = TempDir::new();
        let v = tree_vault(&t);
        let before = generation(&v);
        v.remove(&["a/1.txt", "a/sub", "a/sub/3.txt", "top.txt"]).unwrap();
        assert_eq!(paths(&v), ["a", "a/2.txt"]);
        assert_eq!(generation(&v), before + 1);
    }

    #[test]
    fn removing_several_with_one_missing_changes_nothing() {
        let t = TempDir::new();
        let v = tree_vault(&t);
        let before = paths(&v);
        assert!(v.remove(&["top.txt", "nope"]).unwrap_err().contains("not in the vault"));
        assert_eq!(paths(&v), before);
    }

    #[test]
    fn removing_everything_empties_the_vault_and_its_blobs() {
        let t = TempDir::new();
        let v = tree_vault(&t);
        let before = generation(&v);
        v.remove_everything().unwrap();
        assert!(paths(&v).is_empty());
        assert_eq!(generation(&v), before + 1);
        assert!(v.orphans(&v.load_manifest().unwrap()).unwrap().is_empty());
        let blobs: Vec<_> = fs::read_dir(format!("{}/{BLOBS_DIR}", v.dir)).unwrap()
            .flatten().flat_map(|d| fs::read_dir(d.path()).unwrap().flatten()).collect();
        assert!(blobs.is_empty(), "{blobs:?}");
    }

    #[test]
    fn root_is_only_removable_by_its_own_flag() {
        let t = TempDir::new();
        let dir = t.path("vault.vsvault");
        let pass = |p: &str| pass_fd(p).to_string();
        run("vault-create", &args(&["--dir", &dir, "--mode", "password", "--pass-fd", &pass(VAULT_PASS)])).unwrap();
        run("vault-add", &args(&["--dir", &dir, "--src", &t.write("f.txt", b"x"), "--pass-fd", &pass(VAULT_PASS)])).unwrap();
        let by_entry = run("vault-remove", &args(&["--dir", &dir, "--entry", "/", "--pass-fd", &pass(VAULT_PASS)]));
        assert!(by_entry.unwrap_err().contains("invalid"));
        let neither = run("vault-remove", &args(&["--dir", &dir, "--pass-fd", &pass(VAULT_PASS)]));
        assert!(neither.unwrap_err().contains("--entry is required"));
        run("vault-remove", &args(&["--dir", &dir, "--all", "--pass-fd", &pass(VAULT_PASS)])).unwrap();
    }

    #[test]
    fn extracting_several_keeps_paths_and_skips_what_was_not_chosen() {
        let t = TempDir::new();
        let v = tree_vault(&t);
        let out = t.path("out");
        v.extract_many(&["a/sub", "a/sub/3.txt", "top.txt"], &out).unwrap();
        assert_eq!(fs::read(format!("{out}/a/sub/3.txt")).unwrap(), b"three");
        assert_eq!(fs::read(format!("{out}/top.txt")).unwrap(), b"top");
        assert!(!Path::new(&format!("{out}/a/1.txt")).exists());
        assert!(!Path::new(&staging_path(&out)).exists());
    }

    #[test]
    fn extracting_several_is_all_or_nothing() {
        let t = TempDir::new();
        let v = tree_vault(&t);
        let out = t.path("out");
        assert!(v.extract_many(&["top.txt", "nope"], &out).unwrap_err().contains("not in the vault"));
        assert_nothing_written(&out);
        fs::write(blob_of(&v, "a/2.txt"), b"tampered").unwrap();
        assert!(v.extract_many(&["top.txt", "a/2.txt"], &out).unwrap_err().contains("failed verification"));
        assert_nothing_written(&out);
    }

    /// What a contact does: decrypt with their private key.
    fn decrypt_as(identity: &x25519::Identity, path: &str) -> Vec<u8> {
        let data = fs::read(path).unwrap();
        let dec = age::Decryptor::new(&data[..]).unwrap();
        let mut stream = dec.decrypt(once(identity as &dyn age::Identity)).unwrap();
        let mut plain = Vec::new();
        stream.read_to_end(&mut plain).unwrap();
        plain
    }

    #[test]
    fn sharing_one_file_is_that_file_for_that_recipient_only() {
        let t = TempDir::new();
        let v = tree_vault(&t);
        let (friend, stranger) = (x25519::Identity::generate(), x25519::Identity::generate());
        let out = t.path("top.txt.age");
        v.share(&["top.txt"], &[&friend.to_public().to_string()], &out).unwrap();
        assert_eq!(decrypt_as(&friend, &out), b"top");
        let data = fs::read(&out).unwrap();
        let dec = age::Decryptor::new(&data[..]).unwrap();
        assert!(dec.decrypt(once(&stranger as &dyn age::Identity)).is_err());
        assert!(dec_fails_with_vault_key(&v, &data), "the vault's own key must not open a share");
    }

    fn dec_fails_with_vault_key(v: &Vault, data: &[u8]) -> bool {
        let dec = age::Decryptor::new(data).unwrap();
        dec.decrypt(once(&v.key as &dyn age::Identity)).is_err()
    }

    #[test]
    fn sharing_several_is_an_archive_of_only_what_was_chosen() {
        let t = TempDir::new();
        let v = tree_vault(&t);
        let friend = x25519::Identity::generate();
        let out = t.path("many.tar.age");
        v.share(&["a/sub", "top.txt"], &[&friend.to_public().to_string()], &out).unwrap();
        let tar = decrypt_as(&friend, &out);
        assert_eq!(tar.len() % 512, 0);
        assert!(tar.ends_with(&[0; 1024]));
        let names: Vec<String> = tar.chunks(512)
            .filter(|b| &b[257..262] == b"ustar")
            .map(|b| String::from_utf8_lossy(&b[..100]).trim_end_matches('\0').to_string())
            .collect();
        assert_eq!(names, ["a/", "a/sub/", "a/sub/3.txt", "top.txt"]);
    }

    #[test]
    fn sharing_refuses_bad_input_and_tampered_files_write_nothing() {
        let t = TempDir::new();
        let v = tree_vault(&t);
        let friend = x25519::Identity::generate().to_public().to_string();
        let out = t.path("out.age");
        assert!(v.share(&["top.txt"], &[], &out).unwrap_err().contains("--to"));
        assert!(v.share(&["top.txt"], &["age1nonsense"], &out).unwrap_err().contains("invalid recipient"));
        assert!(v.share(&["nope"], &[&friend], &out).unwrap_err().contains("not in the vault"));
        assert!(v.share(&["top.txt"], &[&friend], &format!("{}/x.age", v.dir)).unwrap_err().contains("inside the vault"));
        fs::write(blob_of(&v, "a/2.txt"), b"tampered").unwrap();
        assert!(v.share(&[ROOT_ENTRY], &[&friend], &out).unwrap_err().contains("failed verification"));
        assert_nothing_written(&out);
        v.remove_everything().unwrap();
        assert!(v.share(&[ROOT_ENTRY], &[&friend], &out).unwrap_err().contains("nothing"));
    }

    #[test]
    fn selection_covers_folders_their_contents_and_the_way_to_them() {
        let t = TempDir::new();
        let v = tree_vault(&t);
        let m = v.load_manifest().unwrap();
        let chosen: Vec<_> = m.selection(&["a/sub/3.txt"]).unwrap().into_iter().collect();
        assert_eq!(chosen, ["a", "a/sub", "a/sub/3.txt"]);
        assert_eq!(m.selection(&[ROOT_ENTRY]).unwrap().len(), m.entries.len());
        assert_eq!(m.size_of(m.selection(&["a"]).unwrap().into_iter()), 11);
    }

    /// A pipe as the frontend sets one up, and what arrived on it once `work` is done.
    fn reports(work: impl FnOnce(i32)) -> Vec<u64> {
        let mut fds = [0i32; 2];
        assert_eq!(unsafe { libc::pipe(fds.as_mut_ptr()) }, 0);
        work(fds[1]);
        unsafe { libc::close(fds[1]) };
        let mut text = String::new();
        unsafe { File::from_raw_fd(fds[0]) }.read_to_string(&mut text).unwrap();
        text.lines().map(|l| l.parse().unwrap()).collect()
    }

    #[test]
    fn progress_climbs_to_100_without_repeating_itself() {
        let t = TempDir::new();
        let mut v = quick_vault(&t);
        let big = t.write("big.bin", &vec![7u8; 5 << 20]);
        for step in 0..2 {
            let got = reports(|fd| {
                v.progress = Rc::new(Progress::to_fd(fd).unwrap());
                if step == 0 {
                    v.add(&[big.clone()], None, false).unwrap();
                } else {
                    v.extract("big.bin", &t.path("out.bin")).unwrap();
                }
            });
            assert!(got.len() > 3, "step {step}: {got:?}");
            assert!(got.windows(2).all(|w| w[0] < w[1]), "step {step}: {got:?}");
            assert_eq!(*got.last().unwrap(), 100, "step {step}: {got:?}");
        }
    }

    #[test]
    fn a_bad_progress_fd_is_harmless_or_refused() {
        assert!(Progress::to_fd(1).is_err());
        let progress = Progress::to_fd(987_654).unwrap(); // not open: writes just fail
        progress.start(10);
        progress.advance(5);
    }

    #[test]
    fn hashing_writer_hashes_what_reaches_the_disk() {
        let t = TempDir::new();
        let v = quick_vault(&t);
        add(&v, &t.write("a.txt", b"aaa"));
        let m = v.load_manifest().unwrap();
        let Some(Entry::File { blob, sha256, size }) = m.entries.get("a.txt") else { panic!() };
        assert_eq!(*size, 3);
        assert_eq!(&hex(&Sha256::digest(fs::read(v.blob_path(blob)).unwrap())), sha256);
        assert!(is_hex(blob, 32));
        assert_eq!(fs::metadata(v.blob_path(blob)).unwrap().permissions().mode() & 0o777, 0o600);
    }

    // -----------------------------------------------------------------------
    // Android: what the SAF store changes.
    // -----------------------------------------------------------------------

    /// A real folder with SAF's rules: rename never replaces, and locking is
    /// in-process. ffi.rs's SafStore follows these, through DocumentsContract.
    struct NoReplaceStore(PathStore);

    impl Store for NoReplaceStore {
        fn key(&self) -> R<String> { self.0.key() }
        fn show(&self, rel: &str) -> String { self.0.show(rel) }
        fn kind(&self, rel: &str) -> Kind { self.0.kind(rel) }
        fn read(&self, rel: &str) -> io::Result<Vec<u8>> { self.0.read(rel) }
        fn create_new(&self, rel: &str) -> R<File> { self.0.create_new(rel) }
        fn rename(&self, from: &str, to: &str) -> io::Result<()> {
            if self.0.kind(to) != Kind::Missing {
                return Err(io::Error::new(io::ErrorKind::AlreadyExists, "SAF can't rename over a file"));
            }
            self.0.rename(from, to)
        }
        fn replaces_on_rename(&self) -> bool { false }
        fn remove_file(&self, rel: &str) -> io::Result<()> { self.0.remove_file(rel) }
        fn remove_tree(&self, rel: &str) { self.0.remove_tree(rel) }
        fn mkdir(&self, rel: &str, recursive: bool) -> R<()> { self.0.mkdir(rel, recursive) }
        fn list(&self, rel: &str) -> R<Vec<(String, Kind)>> { self.0.list(rel) }
        fn sync_dir(&self, rel: &str) { self.0.sync_dir(rel) }
        fn lock(&self, exclusive: bool) -> R<Box<dyn Any>> { lock_by_key(self, exclusive) }
    }

    fn saf_vault(t: &TempDir, mode: &str, pass: &str) -> (String, Box<dyn Fn(bool) -> R<Vault>>) {
        let dir = t.path("saf.vsvault");
        let data_dir = crate::vault_cli::data_dir();
        let secret = Secret { data_dir: &data_dir, bytes: Some(pass.as_bytes()) };
        create(Box::new(NoReplaceStore(PathStore::new(&dir))), mode, &secret).unwrap();
        let (open_dir, pass) = (dir.clone(), pass.to_string());
        let open = move |exclusive| {
            let data_dir = crate::vault_cli::data_dir();
            let secret = Secret { data_dir: &data_dir, bytes: Some(pass.as_bytes()) };
            Vault::open_in(Box::new(NoReplaceStore(PathStore::new(&open_dir))), &secret, exclusive)
        };
        (dir, Box::new(open))
    }

    #[test]
    fn a_store_that_cannot_rename_over_a_file_still_commits_every_change() {
        let t = TempDir::new();
        let (dir, open) = saf_vault(&t, "self", ID_PASS);
        let v = open(true).unwrap();
        add(&v, &t.write("a.txt", b"one"));
        v.add(&[t.write("a.txt", b"two")], None, true).unwrap();
        add(&v, &t.write("b.txt", b"bee"));
        v.remove(&["b.txt"]).unwrap();
        assert_eq!(generation(&v), 4);
        assert!(!Path::new(&staging_path(&format!("{dir}/{MANIFEST_FILE}"))).exists());
        let out = t.path("out.txt");
        v.extract("a.txt", &out).unwrap();
        assert_eq!(fs::read(&out).unwrap(), b"two");
        assert!(v.check().unwrap().contains("ok 1 file(s) verified"));
        drop(v);
        // The same vault is an ordinary desktop vault.
        let desktop = Vault::open(&dir, pass_fd(ID_PASS), false).unwrap();
        assert_eq!(generation(&desktop), 4);
    }

    /// Killed between deleting the old manifest and renaming the new one in: the
    /// staged manifest is the committed state, and opening puts it in place.
    #[test]
    fn a_manifest_left_staged_by_a_crash_is_recovered() {
        let t = TempDir::new();
        let (dir, open) = saf_vault(&t, "password", VAULT_PASS);
        let v = open(true).unwrap();
        add(&v, &t.write("a.txt", b"aaa"));
        add(&v, &t.write("b.txt", b"bbb"));
        drop(v);
        let manifest = format!("{dir}/{MANIFEST_FILE}");
        let staged = staging_path(&manifest);
        fs::rename(&manifest, &staged).unwrap();

        let v = open(false).unwrap();
        assert_eq!(generation(&v), 2);
        assert!(Path::new(&manifest).exists() && !Path::new(&staged).exists());
        let out = t.path("b-out.txt");
        v.extract("b.txt", &out).unwrap();
        assert_eq!(fs::read(&out).unwrap(), b"bbb");

        // A staged file that isn't this vault's manifest is never promoted.
        fs::rename(&manifest, &staged).unwrap();
        fs::write(&staged, b"not a manifest").unwrap();
        assert!(v.load_manifest().unwrap_err().contains("reading the vault's manifest"));
        assert_eq!(fs::read(&staged).unwrap(), b"not a manifest");
        let other = Vault::with(Box::new(PathStore::new(&t.path("elsewhere"))), x25519::Identity::generate(), None);
        fs::create_dir_all(t.path("elsewhere")).unwrap();
        other.write_manifest(&Manifest::default()).unwrap();
        fs::rename(t.path(&format!("elsewhere/{MANIFEST_FILE}")), &staged).unwrap();
        assert!(v.load_manifest().is_err());
        assert!(Path::new(&staged).exists() && !Path::new(&manifest).exists());
    }

    #[test]
    fn a_store_without_flock_is_locked_within_the_process() {
        let t = TempDir::new();
        let (dir, _open) = saf_vault(&t, "self", ID_PASS);
        let store = NoReplaceStore(PathStore::new(&dir));
        let writer = store.lock(true).unwrap();
        assert!(store.lock(true).err().unwrap().contains("another"));
        assert!(store.lock(false).err().unwrap().contains("another"));
        drop(writer);
        let reader_one = store.lock(false).unwrap();
        let reader_two = store.lock(false).unwrap();
        assert!(store.lock(true).err().unwrap().contains("another"));
        drop((reader_one, reader_two));
        store.lock(true).unwrap();
        let not_a_vault = NoReplaceStore(PathStore::new(&t.path("")));
        assert!(not_a_vault.lock(false).err().unwrap().contains("not a VaultSend vault"));
    }

    #[test]
    fn a_saf_folder_extract_and_share_never_write_into_the_vault() {
        let t = TempDir::new();
        let (dir, open) = saf_vault(&t, "self", ID_PASS);
        let v = open(false).unwrap();
        drop(v);
        let v = open(true).unwrap();
        add(&v, &t.write("a.txt", b"a"));
        let inside = NoReplaceStore(PathStore::new(&format!("{dir}/blobs")));
        assert!(v.extract_to("a.txt", Out::In(&inside, "x")).unwrap_err().contains("inside the vault"));
        let friend = x25519::Identity::generate().to_public().to_string();
        assert!(v.share_to(&["a.txt"], &[&friend], Out::In(&inside, "x.age")).unwrap_err().contains("inside the vault"));

        // Into a file the caller made, as the app does with "Save as".
        let mut file = File::create(t.path("saved.txt")).unwrap();
        v.extract_to("a.txt", Out::File(&mut file)).unwrap();
        assert_eq!(fs::read(t.path("saved.txt")).unwrap(), b"a");
        let mut file = File::create(t.path("folder.out")).unwrap();
        assert!(v.extract_to("/", Out::File(&mut file)).unwrap_err().contains("into a folder"));
    }

    // -----------------------------------------------------------------------
    // Android: secrets from the session and remembered vault keys.
    // -----------------------------------------------------------------------

    #[test]
    fn a_self_vault_opens_with_the_unlocked_session() {
        let _guard = crate::backend::TEST_GUARD.lock().unwrap_or_else(|e| e.into_inner());
        let t = TempDir::new();
        let dir = t.path("v.vsvault");
        let data_dir = crate::vault_cli::data_dir();
        let session = Secret { data_dir: &data_dir, bytes: None };
        crate::backend::lock();
        assert!(create(Box::new(PathStore::new(&dir)), "self", &session).unwrap_err().contains("locked"));
        crate::backend::unlock(&data_dir, ID_PASS.as_bytes()).unwrap();
        create(Box::new(PathStore::new(&dir)), "self", &session).unwrap();
        Vault::open_in(Box::new(PathStore::new(&dir)), &session, false).unwrap();
        crate::backend::lock();
        assert!(Vault::open_in(Box::new(PathStore::new(&dir)), &session, false).err().unwrap().contains("locked"));
        // And a passphrase still works, as on desktop.
        Vault::open(&dir, pass_fd(ID_PASS), false).unwrap();
    }

    #[test]
    fn a_password_vault_key_is_remembered_only_as_long_as_asked() {
        let _guard = crate::backend::TEST_GUARD.lock().unwrap_or_else(|e| e.into_inner());
        let t = TempDir::new();
        let dir = t.path("pw.vsvault");
        let data_dir = crate::vault_cli::data_dir();
        let typed = Secret { data_dir: &data_dir, bytes: Some(VAULT_PASS.as_bytes()) };
        let nothing = Secret { data_dir: &data_dir, bytes: None };
        let open = |s: &Secret| Vault::open_in(Box::new(PathStore::new(&dir)), s, false);
        let key = || PathStore::new(&dir).key().unwrap();

        set_remember(0);
        create(Box::new(PathStore::new(&dir)), "password", &typed).unwrap();
        assert_eq!(open(&nothing).err().unwrap(), PASSWORD_NEEDED);
        open(&typed).unwrap();
        assert!(!is_remembered(&key()), "Off remembers nothing");

        set_remember(-1);
        open(&typed).unwrap();
        assert!(is_remembered(&key()));
        let v = open(&nothing).unwrap();
        assert_eq!(generation(&v), 0);
        drop(v);
        // A wrong password is never remembered, and doesn't replace the right key.
        assert!(open(&Secret { data_dir: &data_dir, bytes: Some(b"not the password") }).is_err());
        open(&nothing).unwrap();

        forget(&key());
        assert_eq!(open(&nothing).err().unwrap(), PASSWORD_NEEDED);
        open(&typed).unwrap();
        crate::backend::lock(); // Lock now forgets vault keys too
        assert_eq!(open(&nothing).err().unwrap(), PASSWORD_NEEDED);

        // Changing the lifetime forgets everything, as on desktop.
        open(&typed).unwrap();
        set_remember(300);
        assert!(!is_remembered(&key()));
        open(&typed).unwrap();
        assert!(is_remembered(&key()));
        set_remember(0);
    }

    #[test]
    fn locked_pages_are_counted_so_a_shared_page_stays_locked() {
        let both = [0u8; 64];
        let page = crate::backend::page_of(both.as_ptr() as usize);
        let before = crate::backend::lock_count(page);
        let first = crate::backend::lock_in_ram(&both[..32]);
        let second = crate::backend::lock_in_ram(&both[32..]);
        assert_eq!(crate::backend::lock_count(page), before + 2);
        drop(first);
        // Still locked for `second`: munlock isn't counted, so this is the case that matters.
        assert_eq!(crate::backend::lock_count(page), before + 1);
        drop(second);
        assert_eq!(crate::backend::lock_count(page), before);
    }
}
