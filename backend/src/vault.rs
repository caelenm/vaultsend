// VaultSend vaults: a folder of individually age-encrypted files ("blobs"), bound
// together by an age-encrypted manifest that pins every blob by SHA-256 and carries
// a generation counter, so one file can change without re-encrypting the rest.
//
//   MyVault.vsvault/
//     VAULT          "vaultsend-vault 1\nmode self|password\n"  (not secret; a prompt hint)
//     key.age        the vault's own X25519 identity, encrypted to the user's public key
//                    (self) or to a password at scrypt 2^18 (password)
//     manifest.age   the file list, encrypted to the vault's public key
//     blobs/<aa>/<32-hex-id>.age   one per file, encrypted to the vault's public key
//
// No custom crypto here either: all encryption is age. The security rests on the
// bookkeeping: hashes checked before decrypting, plaintext fully verified in RAM
// before a byte reaches disk, and age recipients being anonymous (the vault's public
// key is stored nowhere in the clear, so a manifest can't be forged without the key).

use std::collections::{BTreeMap, BTreeSet};
use std::fs::{self, DirBuilder, File};
use std::io::{self, Cursor, Read, Write};
use std::iter::once;
use std::os::unix::fs::{DirBuilderExt, PermissionsExt};
use std::path::{Path, PathBuf};

use age::secrecy::ExposeSecret;
use age::x25519;
use rand::RngCore;
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

use crate::{
    commit_staged, encrypt_to, load_identity, open_private_new, pubkey_path, read_passphrase,
    staging_path, R, SCRYPT_LOG_N, SCRYPT_MAX_LOG_N,
};

const VAULT_FILE: &str = "VAULT";
const VAULT_MAGIC: &str = "vaultsend-vault 1";
const KEY_FILE: &str = "key.age";
const MANIFEST_FILE: &str = "manifest.age";
const MANIFEST_MAGIC: &str = "vaultsend-manifest 1";
const BLOBS_DIR: &str = "blobs";
/// `--entry` / `--dest` value meaning the top of the vault. Never a valid vault path.
const ROOT_ENTRY: &str = "/";
/// Same floor as the identity passphrase (MIN_PASSPHRASE_LEN in the frontend).
const MIN_PASSWORD_CHARS: usize = 10;

// ---------------------------------------------------------------------------
// Vault paths.  The one validator used by add, remove, extract and the manifest
// parser; everything joined onto a real directory has passed through it, so a
// hostile path can never climb out of the output folder.
// ---------------------------------------------------------------------------
fn valid_vault_path(p: &str) -> bool {
    !p.is_empty()
        && p.len() <= 4096
        && !p.contains('\0')
        && p.split('/').all(|c| !c.is_empty() && c != "." && c != ".." && c.len() <= 255)
}

/// Every parent folder of `path`, outermost first: "a/b/c" gives "a", "a/b".
fn ancestors(path: &str) -> impl Iterator<Item = &str> {
    path.match_indices('/').map(move |(i, _)| &path[..i])
}

/// `path` relative to `root` if it lies inside it ("" for the root itself).
fn within<'a>(path: &'a str, root: &str) -> Option<&'a str> {
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
}

// ---------------------------------------------------------------------------
// Small IO helpers.
// ---------------------------------------------------------------------------
/// Stage `path` with open_private_new, let `fill` write it, fsync, rename into place.
fn write_atomic(path: &str, fill: impl FnOnce(File) -> R<File>) -> R<()> {
    let tmp = staging_path(path);
    let file = open_private_new(&tmp)?;
    let staged = fill(file).and_then(|mut f| {
        f.flush().map_err(|e| format!("writing {path}: {e}"))?;
        f.sync_all().map_err(|e| format!("flushing {path}: {e}"))
    });
    commit_staged(staged, &tmp, path)
}

/// Make a rename durable. Best-effort: some filesystems refuse fsync on a folder,
/// and by now the rename has happened, so failing here would misreport the outcome.
fn sync_dir(path: &str) {
    if let Ok(dir) = File::open(path) {
        let _ = dir.sync_all();
    }
}

fn parent_of(path: &str) -> &str {
    match Path::new(path).parent().and_then(Path::to_str) {
        Some("") | None => ".",
        Some(parent) => parent,
    }
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

/// Hold a lock on the vault for the life of the process, so one process's garbage
/// collection can never delete blobs another has written but not yet committed.
/// The kernel releases flock however the process dies, so there is no stale lock.
fn lock_vault(dir: &str, exclusive: bool) -> R<File> {
    let file = File::open(format!("{dir}/{VAULT_FILE}"))
        .map_err(|_| format!("{dir} is not a VaultSend vault (no {VAULT_FILE} file)"))?;
    #[cfg(target_os = "linux")]
    {
        use std::os::unix::io::AsRawFd;
        let kind = if exclusive { libc::LOCK_EX } else { libc::LOCK_SH };
        // SAFETY: flock only reads the descriptor, which `file` keeps open.
        let failed = unsafe { libc::flock(file.as_raw_fd(), kind | libc::LOCK_NB) } != 0;
        if failed && io::Error::last_os_error().kind() == io::ErrorKind::WouldBlock {
            return Err("another VaultSend operation is using this vault".into());
        }
    }
    #[cfg(not(target_os = "linux"))]
    let _ = exclusive;
    Ok(file)
}

/// Decrypt key.age and return the vault's identity. scrypt runs here, once per
/// operation rather than once per file. The VAULT file's mode is only a hint for
/// which secret to try: a wrong mode just fails to decrypt, as an ordinary error.
///
/// `pinned` is the SHA-256 of key.age the frontend remembers for this vault. age has
/// no sender authentication and a user's public key is public, so anyone who can
/// write here could wrap a key of their own to the user. It is checked on the exact
/// bytes about to be used, before the secret is even read.
fn unlock(dir: &str, pass_fd: i32, pinned: Option<&str>) -> R<x25519::Identity> {
    let hint = fs::read_to_string(format!("{dir}/{VAULT_FILE}"))
        .map_err(|e| format!("reading {VAULT_FILE}: {e}"))?;
    let mode = hint.strip_prefix(VAULT_MAGIC).and_then(|r| r.strip_prefix("\nmode "));
    let wrapped = fs::read(format!("{dir}/{KEY_FILE}"))
        .map_err(|e| format!("reading this vault's {KEY_FILE}: {e}"))?;
    if pinned.is_some_and(|p| hex(&Sha256::digest(&wrapped)) != p) {
        return Err(format!("this vault's {KEY_FILE} has changed since this device last opened it"));
    }
    let dec = age::Decryptor::new(&wrapped[..])
        .map_err(|_| format!("this vault's {KEY_FILE} is damaged"))?;
    let mut stream = match mode {
        Some("self\n") => {
            let identity = load_identity(pass_fd)?;
            dec.decrypt(once(&identity as &dyn age::Identity))
                .map_err(|_| format!("this vault does not open with your key ({KEY_FILE} is for another key, or damaged)"))?
        }
        Some("password\n") => {
            let mut scrypt_id = age::scrypt::Identity::new(read_passphrase(pass_fd)?);
            scrypt_id.set_max_work_factor(SCRYPT_MAX_LOG_N);
            dec.decrypt(once(&scrypt_id as &dyn age::Identity))
                .map_err(|_| format!("wrong password, or this vault's {KEY_FILE} is damaged"))?
        }
        _ => return Err(format!("{dir}/{VAULT_FILE} is not a format this version understands")),
    };
    let mut secret: Zeroizing<Vec<u8>> = Zeroizing::new(Vec::new());
    stream.read_to_end(&mut secret).map_err(|e| format!("reading this vault's {KEY_FILE}: {e}"))?;
    std::str::from_utf8(&secret)
        .map_err(|_| format!("this vault's {KEY_FILE} is corrupt"))?
        .trim()
        .parse::<x25519::Identity>()
        .map_err(|e| format!("this vault's {KEY_FILE} is corrupt: {e}"))
}

/// Refuse a `--out` that resolves to anywhere inside the vault. The final
/// component need not exist yet, so its parent is what gets resolved.
fn refuse_out_inside_vault(dir: &str, out: &str) -> R<()> {
    let name = Path::new(out).file_name().ok_or_else(|| format!("--out must name a file or folder: {out}"))?;
    let parent = fs::canonicalize(parent_of(out)).map_err(|e| format!("{}: {e}", parent_of(out)))?;
    let vault = fs::canonicalize(dir).map_err(|e| format!("{dir}: {e}"))?;
    if parent.join(name).starts_with(vault) {
        return Err("the output path must not be inside the vault".into());
    }
    Ok(())
}

/// Walk one source into `plan` (vault path -> None for a folder, Some(path) for a
/// file). Lstat throughout: symlinks, sockets, devices and FIFOs are never followed
/// or read, only counted.
fn plan_source(src: &Path, target: &str, plan: &mut BTreeMap<String, Option<PathBuf>>, skipped: &mut usize) -> R<()> {
    let fail = |e: io::Error| format!("{}: {e}", src.display());
    if !valid_vault_path(target) {
        return Err(format!("can't store this path in a vault: {target}"));
    }
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

fn write_tree(root: &str, tree: &[(&str, Option<Zeroizing<Vec<u8>>>)]) -> R<()> {
    private_dir(root, false)?;
    // In manifest order, so every folder is created before its contents.
    for (rel, data) in tree {
        let path = format!("{root}/{rel}");
        match data {
            None => private_dir(&path, false)?,
            Some(data) => {
                let mut file = open_private_new(&path)?;
                file.write_all(data).map_err(|e| format!("writing {path}: {e}"))?;
                file.sync_all().map_err(|e| format!("flushing {path}: {e}"))?;
            }
        }
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// An unlocked vault.
// ---------------------------------------------------------------------------
struct Vault {
    dir: String,
    key: x25519::Identity,
    /// Held only for its flock, released when this is dropped.
    _lock: Option<File>,
}

impl Vault {
    fn open(dir: &str, pass_fd: i32, pinned: Option<&str>, exclusive: bool) -> R<Vault> {
        let lock = lock_vault(dir, exclusive)?;
        Ok(Vault { dir: dir.to_string(), key: unlock(dir, pass_fd, pinned)?, _lock: Some(lock) })
    }

    /// `wrap` already holds key.age's wrapped file key, so scrypt (for a password
    /// vault) has run by now. VAULT goes last: its presence marks a complete vault.
    fn create(dir: &str, mode: &str, wrap: age::Encryptor) -> R<Vault> {
        let v = Vault { dir: dir.to_string(), key: x25519::Identity::generate(), _lock: None };
        let populate = || -> R<()> {
            private_dir(dir, true)?;
            fs::set_permissions(dir, fs::Permissions::from_mode(0o700)).map_err(|e| format!("{dir}: {e}"))?;
            private_dir(&format!("{dir}/{BLOBS_DIR}"), false)?;
            let secret = Zeroizing::new(v.key.to_string().expose_secret().to_owned());
            write_atomic(&format!("{dir}/{KEY_FILE}"), |file| {
                encrypt_to(wrap, false, Box::new(Cursor::new(secret)), file)
            })?;
            v.write_manifest(&Manifest::default())?;
            write_atomic(&format!("{dir}/{VAULT_FILE}"), |mut file| {
                let text = format!("{VAULT_MAGIC}\nmode {mode}\n");
                file.write_all(text.as_bytes()).map_err(|e| format!("writing {VAULT_FILE}: {e}"))?;
                Ok(file)
            })?;
            sync_dir(dir);
            Ok(())
        };
        if let Err(e) = populate() {
            let _ = fs::remove_dir_all(dir); // only ever a folder we just found empty
            return Err(e);
        }
        Ok(v)
    }

    fn blob_path(&self, blob: &str) -> String {
        format!("{}/{BLOBS_DIR}/{}/{blob}.age", self.dir, &blob[..2])
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
    fn decrypt_in_ram(&self, ciphertext: &[u8]) -> R<Zeroizing<Vec<u8>>> {
        let dec = age::Decryptor::new(ciphertext).map_err(|e| e.to_string())?;
        let mut stream = dec.decrypt(once(&self.key as &dyn age::Identity)).map_err(|e| e.to_string())?;
        let mut plain = Zeroizing::new(Vec::with_capacity(ciphertext.len()));
        stream.read_to_end(&mut plain).map_err(|e| e.to_string())?;
        Ok(plain)
    }

    fn load_manifest(&self) -> R<Manifest> {
        let data = fs::read(format!("{}/{MANIFEST_FILE}", self.dir))
            .map_err(|e| format!("reading the vault's manifest: {e}"))?;
        let text = self.decrypt_in_ram(&data).map_err(|_| "the vault's manifest is damaged or was replaced".to_string())?;
        let text = std::str::from_utf8(&text).map_err(|_| "the vault's manifest is not valid text".to_string())?;
        Manifest::parse(text).map_err(|e| format!("the vault's manifest is invalid: {e}"))
    }

    /// The RAM-only rule: read the whole blob once (no re-open, so no TOCTOU), check
    /// its hash against the manifest, decrypt to the end in memory. The caller gets
    /// plaintext only if all of that succeeded.
    fn read_verified(&self, path: &str, blob: &str, sha256: &str) -> R<Zeroizing<Vec<u8>>> {
        let data = fs::read(self.blob_path(blob)).map_err(|e| match e.kind() {
            io::ErrorKind::NotFound => format!("'{path}': its encrypted data is missing from the vault"),
            _ => format!("'{path}': reading its encrypted data: {e}"),
        })?;
        if hex(&Sha256::digest(&data)) != sha256 {
            return Err(format!("'{path}' failed verification: its encrypted data was changed or replaced"));
        }
        self.decrypt_in_ram(&data).map_err(|e| format!("'{path}' failed to decrypt: {e}"))
    }

    fn write_manifest(&self, m: &Manifest) -> R<()> {
        let text = Zeroizing::new(m.serialize());
        // Never commit a manifest that could not be read back: that would lock the
        // user out of every file in the vault.
        if Manifest::parse(&text).as_ref() != Ok(m) {
            return Err("internal error: manifest does not round-trip; nothing changed".into());
        }
        write_atomic(&format!("{}/{MANIFEST_FILE}", self.dir), |file| {
            self.encrypt_stream(Box::new(Cursor::new(text)), file)
        })?;
        sync_dir(&self.dir);
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

    /// Blob files on disk that `m` does not reference. Only files named exactly
    /// blobs/<2 hex>/<32 hex>.age[.vaultsend-part] qualify; nothing else under blobs/
    /// is ever reported or deleted. file_type doesn't follow symlinks, so a link is
    /// neither entered nor deleted.
    fn orphans(&self, m: &Manifest) -> R<Vec<String>> {
        let live: BTreeSet<&str> = m.entries.values().filter_map(|e| match e {
            Entry::File { blob, .. } => Some(blob.as_str()),
            Entry::Dir => None,
        }).collect();
        let part_suffix = staging_path("");
        let root = format!("{}/{BLOBS_DIR}", self.dir);
        let list = |p: PathBuf| fs::read_dir(&p).map_err(|e| format!("{}: {e}", p.display()));
        let mut found = Vec::new();
        for sub in list(PathBuf::from(&root))?.flatten() {
            let sub_name = sub.file_name();
            let Some(aa) = sub_name.to_str().filter(|n| is_hex(n, 2)) else { continue };
            if !sub.file_type().is_ok_and(|t| t.is_dir()) {
                continue;
            }
            for file in list(sub.path())?.flatten() {
                let file_name = file.file_name();
                let Some(name) = file_name.to_str() else { continue };
                let part = name.strip_suffix(part_suffix.as_str());
                let Some(id) = part.unwrap_or(name).strip_suffix(".age") else { continue };
                if !is_hex(id, 32) || !file.file_type().is_ok_and(|t| t.is_file()) {
                    continue;
                }
                if part.is_some() || aa != &id[..2] || !live.contains(id) {
                    found.push(format!("{root}/{aa}/{name}"));
                }
            }
        }
        Ok(found)
    }

    /// Only a warning if this fails: it runs after the commit point, so the vault is
    /// already correct and the next change will try again.
    fn collect_garbage(&self, m: &Manifest) {
        let removed = self.orphans(m).and_then(|list| {
            list.iter().try_for_each(|p| fs::remove_file(p).map_err(|e| format!("{p}: {e}")))
        });
        if let Err(e) = removed {
            eprintln!("warning: could not remove an unused blob: {e}");
        }
    }

    /// Encrypt one source file to a new blob: stage, hash while writing, fsync, rename.
    fn write_blob(&self, src: &Path) -> R<Entry> {
        let file = File::open(src).map_err(|e| format!("opening {}: {e}", src.display()))?;
        let meta = file.metadata().map_err(|e| format!("{}: {e}", src.display()))?;
        if !meta.is_file() {
            return Err(format!("{} is no longer a regular file", src.display()));
        }
        let mut raw = [0u8; 16];
        rand::rngs::OsRng.fill_bytes(&mut raw);
        let blob = hex(&raw);
        let path = self.blob_path(&blob);
        private_dir(parent_of(&path), true)?;
        let mut sha256 = String::new();
        write_atomic(&path, |out| {
            let hashing = HashingWriter { inner: out, hasher: Sha256::new() };
            let hashing = self.encrypt_stream(Box::new(file), hashing)?;
            sha256 = hex(&hashing.hasher.finalize());
            Ok(hashing.inner)
        })?;
        // The manifest will name this blob, so its directory entry must be durable
        // before the manifest's is.
        sync_dir(parent_of(&path));
        sync_dir(&format!("{}/{BLOBS_DIR}", self.dir));
        Ok(Entry::File { blob, sha256, size: meta.len() })
    }

    fn add<S: AsRef<str>>(&self, sources: &[S], dest: Option<&str>, replace: bool) -> R<()> {
        let old = self.load_manifest()?;
        let added = self.add_to(old.clone(), sources, dest, replace);
        if added.is_err() {
            self.collect_garbage(&old); // the failed attempt's blobs; old is still current
        }
        added
    }

    fn add_to<S: AsRef<str>>(&self, mut m: Manifest, sources: &[S], dest: Option<&str>, replace: bool) -> R<()> {
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
        let mut plan = BTreeMap::new();
        let mut skipped = 0;
        for src in sources {
            let src = Path::new(src.as_ref());
            let name = src.file_name().and_then(|n| n.to_str());
            let name = name.ok_or_else(|| format!("{}: no usable file name", src.display()))?;
            let target = dest.map_or(name.to_string(), |d| format!("{d}/{name}"));
            plan_source(src, &target, &mut plan, &mut skipped)?;
        }
        if plan.is_empty() {
            return Err("nothing to add: not a regular file or folder".into());
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
        for (path, source) in plan {
            let entry = match source {
                None => Entry::Dir,
                Some(src) => self.write_blob(&src)?,
            };
            m.entries.insert(path, entry);
        }
        self.commit_next(m)?;
        if skipped > 0 {
            eprintln!("warning: skipped {skipped} item(s) that are not regular files or folders");
        }
        Ok(())
    }

    fn remove(&self, entry: &str) -> R<()> {
        if !valid_vault_path(entry) {
            return Err(format!("invalid vault path: {entry}"));
        }
        let mut m = self.load_manifest()?;
        if !m.entries.contains_key(entry) {
            return Err(format!("'{entry}' is not in the vault"));
        }
        m.entries.retain(|path, _| within(path, entry).is_none());
        self.commit_next(m)
    }

    fn extract(&self, entry: &str, out: &str) -> R<()> {
        refuse_out_inside_vault(&self.dir, out)?;
        let m = self.load_manifest()?;
        match m.entries.get(entry) {
            Some(Entry::File { blob, sha256, .. }) => {
                let plain = self.read_verified(entry, blob, sha256)?;
                // Only now does anything reach the disk.
                write_atomic(out, |mut file| {
                    file.write_all(&plain).map_err(|e| format!("writing {out}: {e}"))?;
                    Ok(file)
                })?;
                sync_dir(parent_of(out));
                Ok(())
            }
            Some(Entry::Dir) => self.extract_folder(&m, entry, out),
            None if entry == ROOT_ENTRY => self.extract_folder(&m, entry, out),
            None => Err(format!("'{entry}' is not in the vault")),
        }
    }

    /// Verify and decrypt every file first; if any fails, nothing at all is written.
    /// The tree is then built under a staging name and renamed into place, so `out`
    /// is only ever absent or complete.
    fn extract_folder(&self, m: &Manifest, entry: &str, out: &str) -> R<()> {
        if fs::symlink_metadata(out).is_ok() {
            return Err(format!("{out} already exists; choose a new folder name"));
        }
        let mut tree = Vec::new();
        for (path, e) in &m.entries {
            let Some(rel) = within(path, entry).filter(|r| !r.is_empty()) else { continue };
            tree.push((rel, match e {
                Entry::Dir => None,
                Entry::File { blob, sha256, .. } => Some(self.read_verified(path, blob, sha256)?),
            }));
        }
        let tmp = staging_path(out);
        let _ = fs::remove_dir_all(&tmp); // a killed run's leftovers; the suffix is ours
        let staged = write_tree(&tmp, &tree)
            .and_then(|_| fs::rename(&tmp, out).map_err(|e| format!("finalizing {out}: {e}")));
        if staged.is_err() {
            let _ = fs::remove_dir_all(&tmp);
        }
        staged?;
        sync_dir(parent_of(out));
        Ok(())
    }

    /// Names and sizes only, never content.
    fn listing(&self) -> R<String> {
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
    fn check(&self) -> R<String> {
        let m = self.load_manifest()?;
        let orphans = self.orphans(&m)?;
        if !orphans.is_empty() {
            eprintln!("warning: {} blob file(s) on disk are not in the manifest", orphans.len());
        }
        let mut report = String::new();
        for orphan in &orphans {
            report.push_str(&format!("orphan {}\n", &orphan[self.dir.len() + 1..]));
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

// ---------------------------------------------------------------------------
// Commands.
// ---------------------------------------------------------------------------
struct Opts<'a> {
    pairs: Vec<(&'a str, &'a str)>,
    replace: bool,
}

/// Strict "--name value" pairs, unlike the scanning helpers in main.rs, because
/// values here can be names out of a vault: a folder called "--replace" must not
/// read as the flag.
fn parse_opts(args: &[String]) -> R<Opts<'_>> {
    let mut o = Opts { pairs: Vec::new(), replace: false };
    let mut it = args.iter().map(String::as_str);
    while let Some(name) = it.next() {
        match name {
            "--replace" => o.replace = true,
            "--dir" | "--mode" | "--pass-fd" | "--key-sha256" | "--src" | "--dest" | "--entry" | "--out" => {
                o.pairs.push((name, it.next().ok_or_else(|| format!("{name} needs a value"))?))
            }
            other => return Err(format!("unknown option '{other}'")),
        }
    }
    Ok(o)
}

impl<'a> Opts<'a> {
    fn all(&self, name: &str) -> Vec<&'a str> {
        self.pairs.iter().filter(|(n, _)| *n == name).map(|(_, v)| *v).collect()
    }
    fn get(&self, name: &str) -> Option<&'a str> {
        self.all(name).first().copied()
    }
    fn need(&self, name: &str) -> R<&'a str> {
        self.get(name).ok_or_else(|| format!("{name} is required"))
    }
    fn pass_fd(&self) -> R<i32> {
        self.need("--pass-fd")?.parse().map_err(|_| "--pass-fd must be a number".to_string())
    }
}

fn cmd_create(dir: &str, o: &Opts) -> R<()> {
    if fs::read_dir(dir).is_ok_and(|mut d| d.next().is_some()) {
        return Err(format!("{dir} already exists and is not empty"));
    }
    let mode = o.need("--mode")?;
    let wrap = match mode {
        "self" => {
            let public = fs::read_to_string(pubkey_path()?).map_err(|_| "no identity yet — run keygen first".to_string())?;
            let own = public.trim().parse::<x25519::Recipient>().map_err(|e| format!("reading your public key: {e}"))?;
            age::Encryptor::with_recipients(once(&own as &dyn age::Recipient))
        }
        "password" => {
            let password = read_passphrase(o.pass_fd()?)?;
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
    Vault::create(dir, mode, wrap).map(|_| ())
}

fn print_out(text: &str) -> R<()> {
    let mut stdout = io::stdout();
    stdout.write_all(text.as_bytes()).and_then(|_| stdout.flush()).map_err(|e| format!("writing output: {e}"))
}

pub(crate) fn run(cmd: &str, args: &[String]) -> R<()> {
    let o = parse_opts(args)?;
    let dir = o.need("--dir")?;
    let open = |exclusive| Vault::open(dir, o.pass_fd()?, o.get("--key-sha256"), exclusive);
    match cmd {
        "vault-create" => cmd_create(dir, &o),
        "vault-list" => print_out(&open(false)?.listing()?),
        "vault-add" => open(true)?.add(&o.all("--src"), o.get("--dest"), o.replace),
        "vault-remove" => open(true)?.remove(o.need("--entry")?),
        "vault-extract" => open(false)?.extract(o.need("--entry")?, o.need("--out")?),
        "vault-check" => print_out(&open(false)?.check()?),
        other => Err(format!("unknown command '{other}'")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
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
            crate::cmd_keygen(pass_fd(ID_PASS)).unwrap();
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
        match mode {
            "self" => run("vault-create", &args(&["--dir", &dir, "--mode", "self"])).unwrap(),
            _ => run(
                "vault-create",
                &args(&["--dir", &dir, "--mode", "password", "--pass-fd", &pass_fd(pass).to_string()]),
            )
            .unwrap(),
        }
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
        let v = Vault::open(&dir, pass_fd(pass), None, false).unwrap();
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
        run("vault-create", &args(&["--dir", &own, "--mode", "self"])).unwrap();
        let open_err = |d: &str, p: &str| Vault::open(d, pass_fd(p), None, false).err().unwrap();

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

    /// The attack the pin exists for: someone who can write to a `self` vault's folder
    /// wraps a key of their own to the user's public key. The user's passphrase still
    /// opens it, so without the pin nothing would stand in the way.
    #[test]
    fn a_swapped_key_file_is_refused_when_pinned() {
        let t = TempDir::new();
        let (dir, forged) = (t.path("mine.vsvault"), t.path("forged.vsvault"));
        run("vault-create", &args(&["--dir", &dir, "--mode", "self"])).unwrap();
        run("vault-create", &args(&["--dir", &forged, "--mode", "self"])).unwrap();
        let key = format!("{dir}/key.age");
        let pin = hex(&Sha256::digest(fs::read(&key).unwrap()));

        assert!(Vault::open(&dir, pass_fd(ID_PASS), Some(&pin), false).is_ok());
        fs::copy(format!("{forged}/key.age"), &key).unwrap();
        // Without a pin the swap goes unnoticed: the passphrase unlocks the new key.
        assert!(Vault::open(&dir, pass_fd(ID_PASS), None, false).is_ok());
        let err = Vault::open(&dir, pass_fd(ID_PASS), Some(&pin), false).err().unwrap();
        assert!(err.contains("has changed"), "{err}");

        // Through the CLI too, for a mutating command, and nothing is changed.
        let fd = pass_fd(ID_PASS).to_string();
        let src = t.write("secret.txt", b"would be readable by whoever swapped the key");
        let err = run("vault-add", &args(&["--dir", &dir, "--pass-fd", &fd, "--key-sha256", &pin, "--src", &src])).unwrap_err();
        assert!(err.contains("has changed"), "{err}");
        assert_eq!(fs::read_dir(format!("{dir}/blobs")).unwrap().count(), 0);
    }

    #[test]
    fn create_rules() {
        let t = TempDir::new();
        let d = t.path("short.vsvault");
        let short = pass_fd("too short").to_string();
        let err = run("vault-create", &args(&["--dir", &d, "--mode", "password", "--pass-fd", &short])).unwrap_err();
        assert!(err.contains("at least 10"), "{err}");
        assert!(!Path::new(&d).exists());

        t.write("full/file", b"x");
        assert!(run("vault-create", &args(&["--dir", &t.path("full"), "--mode", "self"])).unwrap_err().contains("not empty"));
        assert_eq!(fs::read(t.path("full/file")).unwrap(), b"x");

        fs::create_dir(t.path("empty")).unwrap();
        run("vault-create", &args(&["--dir", &t.path("empty"), "--mode", "self"])).unwrap();
        assert_eq!(fs::read_to_string(t.path("empty/VAULT")).unwrap(), "vaultsend-vault 1\nmode self\n");
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
        let other = Vault { dir: v.dir.clone(), key: x25519::Identity::generate(), _lock: None };
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

        v.remove("drop.txt").unwrap();
        assert!(!Path::new(&dropped[0]).exists());
        assert_eq!(fs::read(&keep).unwrap(), keep_bytes);

        // Recursive for a folder; a sibling sharing the prefix survives.
        add(&v, &t.write("dir2", b"sibling"));
        v.remove("dir").unwrap();
        assert!(!Path::new(&dropped[1]).exists() && !Path::new(&dropped[2]).exists());
        let m = v.load_manifest().unwrap();
        let names: Vec<&str> = m.entries.keys().map(String::as_str).collect();
        assert_eq!(names, ["dir2", "keep.txt"]);

        assert!(v.remove("missing").unwrap_err().contains("not in the vault"));
        assert!(v.remove("/").unwrap_err().contains("invalid"));
        assert!(v.remove("../keep.txt").unwrap_err().contains("invalid"));
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
        v.remove("a.txt").unwrap();
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
        v.remove("a.txt").unwrap();
        assert_eq!(generation(&v), 4);
        // Reads don't count, and a refused change doesn't either.
        v.extract("b.txt", &t.path("out.txt")).unwrap();
        v.check().unwrap();
        v.listing().unwrap();
        assert!(v.remove("nope").is_err());
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
}
