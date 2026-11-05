// Receiving what someone shared from a vault: a plain age file (vault.rs `share_to`
// and `share_password`), encrypted to this device's key or to a password. One file
// stays that file; anything else is a tar archive inside it. This module opens one:
//
//   * `age_kind` tells the app which prompt to show, from the age header alone.
//   * `check_password` unwraps the file key only, so a wrong password is said at once.
//   * `decrypt_file_to` saves it as it is (the archive, or the one file).
//   * `extract_archive` unpacks the archive into a new folder.
//   * `import_archive` adds what it holds to a vault (Add existing vault).
//
// The archive is hostile input even though age authenticated it: it came from
// whoever knew the password. tar.rs's `scan` canonicalizes every name, takes only
// files and folders, and caps sizes and counts; nothing here writes anything `scan`
// didn't accept. Plaintext is decrypted in full to a private staging file first (so
// age has authenticated every byte), and unpacking builds the whole tree in the app's
// private storage before any of it reaches the folder the user chose, under a staging
// name renamed into place last. Everything streams, a block at a time.

use std::fs::{self, File};
use std::io::{self, BufReader, Read, Seek, SeekFrom, Write};
use std::iter::once;
use std::path::{Path, PathBuf};

use age::armor::ArmoredReader;
use age::DecryptError;

use crate::backend::{
    decrypt_file_staged, open_private_new, passphrase_from_bytes, session_identity, staging_named, StagingGuard,
    SCRYPT_LOG_N,
};
use crate::tar::{self, Item, Limits, Scan};
use crate::vault::{valid_vault_path, within, Kind, PathStore, Plan, Progress, Sources, Store, Vault, CANCELLED};
use crate::R;

/// How a shared file is opened.
pub enum Key<'a> {
    /// The unlocked session key: a share made for this person.
    Session,
    /// A password share.
    Password(&'a [u8]),
}

/// A copy buffer: everything streams through one of these.
const CHUNK: usize = 64 << 10;

fn decryptor<Rd: Read>(input: Rd) -> R<age::Decryptor<impl Read>> {
    age::Decryptor::new(ArmoredReader::new(BufReader::new(input)))
        .map_err(|_| "this isn't a file VaultSend can decrypt (not an age file)".to_string())
}

/// "password" for a file encrypted to a password, "key" for one encrypted to people.
pub fn age_kind<Rd: Read>(input: Rd) -> R<&'static str> {
    Ok(if decryptor(input)?.is_scrypt() { "password" } else { "key" })
}

/// The decrypted stream. For a password, scrypt runs here, at no more than the
/// cost VaultSend uses: a file asking for more could otherwise cost gigabytes.
fn open_stream<'a, Rd: Read + 'a>(input: Rd, key: &Key) -> R<Box<dyn Read + 'a>> {
    let dec = decryptor(input)?;
    let stream = match key {
        Key::Password(bytes) => {
            if !dec.is_scrypt() {
                return Err("this file was encrypted for people, not with a password".into());
            }
            let (password, _password_ram) = passphrase_from_bytes(bytes)?;
            let mut identity = age::scrypt::Identity::new(password);
            identity.set_max_work_factor(SCRYPT_LOG_N);
            dec.decrypt(once(&identity as &dyn age::Identity)).map_err(|e| match e {
                DecryptError::ExcessiveWork { .. } => {
                    "this file asks for more work to decrypt than VaultSend allows".to_string()
                }
                _ => "wrong password, or the file is damaged".to_string(),
            })?
        }
        Key::Session => {
            if dec.is_scrypt() {
                return Err("this file needs its password".into());
            }
            let identity = session_identity()?;
            dec.decrypt(once(&identity as &dyn age::Identity))
                .map_err(|_| "this was not encrypted to you (or the input is not an age file)".to_string())?
        }
    };
    Ok(Box::new(stream))
}

/// Whether `password` opens this file. Only the file key is unwrapped; nothing is
/// decrypted or written.
pub fn check_password<Rd: Read>(input: Rd, password: &[u8]) -> R<()> {
    open_stream(input, &Key::Password(password)).map(|_| ())
}

/// Decrypt to `output` as it is, with the desktop's guarantee: staged privately and
/// copied out only once age has authenticated all of it.
pub fn decrypt_file_to<Rd: Read, W: Write>(data_dir: &str, key: &Key, input: Rd, output: W) -> R<()> {
    decrypt_file_staged(data_dir, input, output, |input, tmp| {
        let mut stream = open_stream(input, key)?;
        io::copy(&mut stream, tmp).map_err(|e| format!("decrypting: {e}"))?;
        Ok(())
    })
}

/// Plaintext staged in the app's private storage (0600), removed when dropped.
struct Staged {
    path: PathBuf,
    file: File,
    len: u64,
    _guard: StagingGuard,
}

impl Drop for Staged {
    fn drop(&mut self) {
        let _ = fs::remove_file(&self.path);
    }
}

/// Copy exactly `size` bytes, a chunk at a time, counting and asking about Cancel.
fn copy_exact(from: &mut dyn Read, to: &mut dyn Write, size: u64, progress: &Progress, what: &str) -> R<()> {
    let mut buf = vec![0u8; CHUNK];
    let mut left = size;
    while left > 0 {
        if progress.cancelled() {
            return Err(CANCELLED.into());
        }
        let want = left.min(CHUNK as u64) as usize;
        let n = from.read(&mut buf[..want]).map_err(|e| format!("reading {what}: {e}"))?;
        if n == 0 {
            return Err(format!("{what} ended early"));
        }
        to.write_all(&buf[..n]).map_err(|e| format!("writing {what}: {e}"))?;
        progress.advance(n as u64);
        left -= n as u64;
    }
    Ok(())
}

/// Decrypt all of `input` to a private staging file, refusing more than `cap` bytes.
fn decrypt_to_staging<Rd: Read>(data_dir: &str, key: &Key, input: Rd, cap: u64, progress: &Progress) -> R<Staged> {
    let guard = StagingGuard::new(data_dir);
    let path = staging_named(data_dir, "import");
    let file = open_private_new(&path)?;
    // Removed on drop from here on, whatever happens below.
    let mut staged = Staged { path, file, len: 0, _guard: guard };
    let mut stream = open_stream(input, key)?;
    let mut buf = vec![0u8; CHUNK];
    loop {
        if progress.cancelled() {
            return Err(CANCELLED.into());
        }
        let n = stream.read(&mut buf).map_err(|e| format!("decrypting: {e}"))?;
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

/// Write what `scan` holds into `root` in `store` (a new folder; "" for the store's
/// own top, which must be empty). `open` gives each file's bytes, at its start.
/// Every path is checked once more to lie inside `root` before anything is made.
fn write_items(
    store: &dyn Store,
    root: &str,
    scan: &Scan,
    open: &mut dyn FnMut(&str, u64) -> R<File>,
    progress: &Progress,
) -> R<()> {
    if !root.is_empty() {
        store.mkdir(root, false)?;
    }
    for (rel, item) in &scan.items {
        progress.check()?;
        let path = if root.is_empty() { rel.clone() } else { format!("{root}/{rel}") };
        if !valid_vault_path(rel) || (!root.is_empty() && within(&path, root) != Some(rel.as_str())) {
            return Err(format!("refusing to write outside the folder: {}", store.show(&path)));
        }
        match *item {
            Item::Dir => store.mkdir(&path, false)?,
            Item::File { offset, size } => {
                // create_new would replace it, and on a case-insensitive disk "A" and
                // "a" are one file: one would silently go missing.
                if store.kind(&path) != Kind::Missing {
                    return Err(format!("{}: two names in the archive collide on this disk", store.show(&path)));
                }
                let mut source = open(rel, offset)?;
                let mut out = store.create_new(&path)?;
                copy_exact(&mut source, &mut out, size, progress, &store.show(&path))?;
                out.sync_all().map_err(|e| format!("flushing {}: {e}", store.show(&path)))?;
            }
        }
    }
    store.sync_dir(root);
    Ok(())
}

/// A folder in the app's private storage, removed with everything in it when dropped.
struct PrivateTree {
    path: PathBuf,
    _guard: StagingGuard,
}

impl Drop for PrivateTree {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.path);
    }
}

/// Unpack a shared archive into a new folder `name` inside `folder`. Returns how
/// many entries were skipped (links and the like).
///
/// In three steps, each streamed: decrypt all of it to a private staging file; build
/// the whole tree in a private folder; only then copy that into `name.vaultsend-part`
/// in `folder` and rename it to `name`. So `name` is only ever absent or complete,
/// and the user's folder sees nothing from an archive that fails anywhere.
#[allow(clippy::too_many_arguments)]
pub fn extract_archive<Rd: Read>(
    data_dir: &str,
    key: &Key,
    input: Rd,
    input_len: u64,
    folder: &dyn Store,
    name: &str,
    limits: &Limits,
    progress: &Progress,
) -> R<usize> {
    if !valid_vault_path(name) || name.contains('/') {
        return Err(format!("not a usable folder name: {name}"));
    }
    if folder.kind(name) != Kind::Missing {
        return Err(format!("{} already exists; choose a new folder name", folder.show(name)));
    }
    // Decrypting, then writing twice: about the size of the file each time.
    progress.start(input_len.saturating_mul(3));
    let mut staged = decrypt_to_staging(data_dir, key, input, archive_cap(limits), progress)?;
    let scan = scan_staged(&mut staged, limits, progress)?;

    let private = PrivateTree { path: staging_named(data_dir, "tree"), _guard: StagingGuard::new(data_dir) };
    let private_dir = private.path.to_str().ok_or("the app's storage path is not valid UTF-8")?.to_string();
    fs::DirBuilder::new()
        .mode_private()
        .create(&private.path)
        .map_err(|e| format!("creating {private_dir}: {e}"))?;
    let private_store = PathStore::new(&private_dir);
    let archive = staged.file.try_clone().map_err(|e| e.to_string())?;
    write_items(&private_store, "", &scan, &mut |_, offset| {
        let mut f = archive.try_clone().map_err(|e| e.to_string())?;
        f.seek(SeekFrom::Start(offset)).map_err(|e| format!("reading the archive: {e}"))?;
        Ok(f)
    }, progress)?;
    drop(archive);
    drop(staged); // the archive's plaintext isn't needed any more

    let tmp = format!("{name}.vaultsend-part");
    folder.remove_tree(&tmp); // a killed run's leftovers; the suffix is ours
    let copied = write_items(folder, &tmp, &scan, &mut |rel, _| {
        let path = Path::new(&private_dir).join(rel);
        let meta = fs::symlink_metadata(&path).map_err(|e| format!("{}: {e}", path.display()))?;
        if !meta.is_file() {
            return Err(format!("{}: not a regular file", path.display()));
        }
        File::open(&path).map_err(|e| format!("{}: {e}", path.display()))
    }, progress)
    .and_then(|()| folder.rename(&tmp, name).map_err(|e| format!("finalizing {}: {e}", folder.show(name))));
    if copied.is_err() {
        folder.remove_tree(&tmp);
    }
    copied?;
    folder.sync_dir("");
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

/// Add what a shared file holds to `vault`, at its top: an archive's files and
/// folders, or a single file as `single_name`. All of it or none: the vault's own
/// write protocol commits once, at the end, and a failure or Cancel before then
/// leaves the vault as it was.
pub fn import_archive<Rd: Read>(
    vault: &Vault,
    data_dir: &str,
    key: &Key,
    input: Rd,
    input_len: u64,
    single_name: &str,
    limits: &Limits,
) -> R<usize> {
    let progress = &vault.progress;
    progress.start(input_len.saturating_mul(2));
    let mut staged = decrypt_to_staging(data_dir, key, input, archive_cap(limits), progress)?;
    let file = staged.file.try_clone().map_err(|e| e.to_string())?;
    let sources = if is_archive(&mut staged)? {
        let scan = tar::scan(&mut staged.file, staged.len, limits, &|| progress.check().is_err())?;
        ArchiveSources::from_scan(file, &scan)
    } else {
        if !valid_vault_path(single_name) || single_name.contains('/') {
            return Err(format!("not a usable file name: {single_name}"));
        }
        ArchiveSources { file, plan: vec![(single_name.to_string(), Some(0))], files: vec![(0, staged.len)], skipped: 0 }
    };
    if sources.plan.is_empty() {
        return Err("there is nothing in this archive to import".into());
    }
    vault.add_from(&sources, None, false)?;
    Ok(sources.skipped)
}

/// DirBuilder with mode 0700.
trait PrivateMode {
    fn mode_private(&mut self) -> &mut Self;
}

impl PrivateMode for fs::DirBuilder {
    fn mode_private(&mut self) -> &mut Self {
        use std::os::unix::fs::DirBuilderExt;
        self.mode(0o700)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::backend::encrypt_to;
    use crate::tar::LIMITS;
    use crate::vault::Out;
    use age::secrecy::SecretString;
    use std::sync::atomic::{AtomicU32, Ordering};

    const PW: &[u8] = b"a shared password";

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

    /// A vault held open in memory, as vault.rs's tests make one.
    fn quick_vault(dir: &str) -> Vault {
        let throwaway = age::x25519::Identity::generate().to_public();
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
        let out = PathStore::new(&t.0.to_string_lossy());
        v.share_password(&["/"], PW, Out::In(&out, "share.tar.age")).unwrap();
        (v, t.path("share.tar.age"))
    }

    fn open(path: &str) -> File {
        File::open(path).unwrap()
    }

    fn len(path: &str) -> u64 {
        fs::metadata(path).unwrap().len()
    }

    /// No staged plaintext or private tree is left in `data_dir`.
    fn assert_no_staging(data_dir: &str) {
        let left: Vec<_> = fs::read_dir(data_dir).unwrap().flatten().map(|e| e.file_name()).collect();
        assert!(left.iter().all(|n| !n.to_string_lossy().starts_with(".decrypt")), "left behind: {left:?}");
    }

    fn encrypt_with(pw: &[u8], plain: &[u8], out: &str) {
        let mut r = age::scrypt::Recipient::new(SecretString::from(String::from_utf8(pw.to_vec()).unwrap()));
        r.set_work_factor(2);
        let enc = age::Encryptor::with_recipients(once(&r as &dyn age::Recipient)).unwrap();
        encrypt_to(enc, false, plain, File::create(out).unwrap()).unwrap();
    }

    #[test]
    fn a_password_share_is_told_apart_checked_and_saved_as_is() {
        let t = Temp::new();
        let data = t.dir("data");
        let (_v, share) = shared_tree(&t);
        assert_eq!(age_kind(open(&share)).unwrap(), "password");
        assert!(check_password(open(&share), b"not the password").unwrap_err().contains("wrong password"));
        check_password(open(&share), PW).unwrap();
        assert!(decrypt_file_to(&data, &Key::Session, open(&share), Vec::new()).unwrap_err().contains("needs its password"));

        let mut tar_bytes = Vec::new();
        decrypt_file_to(&data, &Key::Password(PW), open(&share), &mut tar_bytes).unwrap();
        assert!(tar::looks_like_tar(&tar_bytes[..512]));
        let scan = tar::scan(&mut io::Cursor::new(&tar_bytes), tar_bytes.len() as u64, &LIMITS, &|| false).unwrap();
        assert!(scan.items.contains_key("tree/sub/b.bin") && scan.items.contains_key("tree/empty-folder"));
        assert_no_staging(&data);

        // A key share says so, and a share's password has the vault password's floor.
        let key_share = t.path("key.age");
        let me = age::x25519::Identity::generate().to_public();
        let enc = age::Encryptor::with_recipients(once(&me as &dyn age::Recipient)).unwrap();
        encrypt_to(enc, false, &b"x"[..], File::create(&key_share).unwrap()).unwrap();
        assert_eq!(age_kind(open(&key_share)).unwrap(), "key");
        assert!(check_password(open(&key_share), PW).unwrap_err().contains("for people"));
        let short = PathStore::new(&t.0.to_string_lossy());
        assert!(_v.share_password(&["/"], b"short", Out::In(&short, "x.age")).unwrap_err().contains("at least"));
        assert!(age_kind(&b"not an age file at all"[..]).is_err());
    }

    #[test]
    fn an_archive_extracts_into_a_new_folder_with_everything_in_it() {
        let t = Temp::new();
        let data = t.dir("data");
        let (_v, share) = shared_tree(&t);
        let parent = PathStore::new(&t.dir("out"));
        let skipped = extract_archive(&data, &Key::Password(PW), open(&share), len(&share), &parent, "Shared", &LIMITS, &Progress::default()).unwrap();
        assert_eq!(skipped, 0);
        let root = t.path("out/Shared/tree");
        assert_eq!(fs::read(format!("{root}/a.txt")).unwrap(), b"alpha");
        assert_eq!(fs::read(format!("{root}/sub/b.bin")).unwrap(), vec![7u8; 200_000]);
        assert_eq!(fs::read(format!("{root}/sub/empty.txt")).unwrap(), b"");
        assert_eq!(fs::read(format!("{root}/spaced name ü.txt")).unwrap(), b"names survive");
        assert!(Path::new(&format!("{root}/empty-folder")).is_dir());
        assert!(!Path::new(&t.path("out/Shared.vaultsend-part")).exists());
        assert_no_staging(&data);

        // Never over an existing name.
        let again = extract_archive(&data, &Key::Password(PW), open(&share), len(&share), &parent, "Shared", &LIMITS, &Progress::default());
        assert!(again.unwrap_err().contains("already exists"));
        // A wrong password writes nothing.
        let wrong = extract_archive(&data, &Key::Password(b"wrong password!"), open(&share), len(&share), &parent, "Other", &LIMITS, &Progress::default());
        assert!(wrong.unwrap_err().contains("wrong password"));
        assert!(!Path::new(&t.path("out/Other")).exists());
        assert_no_staging(&data);
    }

    #[test]
    fn an_archive_imports_into_a_vault_as_it_was() {
        let t = Temp::new();
        let data = t.dir("data");
        let (v, share) = shared_tree(&t);
        let fresh = quick_vault(&t.path("fresh.vsvault"));
        import_archive(&fresh, &data, &Key::Password(PW), open(&share), len(&share), "unused", &LIMITS).unwrap();
        let body = |l: String| l.split_once('\n').unwrap().1.to_string();
        assert_eq!(body(fresh.listing().unwrap()), body(v.listing().unwrap()));
        fresh.check().unwrap();
        let out = t.path("check");
        fresh.extract("tree/sub/b.bin", &out).unwrap();
        assert_eq!(fs::read(&out).unwrap(), vec![7u8; 200_000]);
        assert_no_staging(&data);

        // One file that isn't an archive goes in under the name the app gives it.
        let single = t.path("photo.jpg.age");
        encrypt_with(PW, b"just one file", &single);
        let one = quick_vault(&t.path("one.vsvault"));
        import_archive(&one, &data, &Key::Password(PW), open(&single), len(&single), "photo.jpg", &LIMITS).unwrap();
        assert_eq!(body(one.listing().unwrap()), "F 13 photo.jpg\n");
        assert!(import_archive(&one, &data, &Key::Password(PW), open(&single), 0, "../x", &LIMITS).is_err());
    }

    #[test]
    fn cancel_leaves_no_folder_no_staging_and_an_unchanged_vault() {
        let t = Temp::new();
        let data = t.dir("data");
        let (_v, share) = shared_tree(&t);
        let parent = PathStore::new(&t.dir("out"));
        let stop = Progress::default().with_cancel(|| true);
        let err = extract_archive(&data, &Key::Password(PW), open(&share), len(&share), &parent, "Shared", &LIMITS, &stop).unwrap_err();
        assert_eq!(err, CANCELLED);
        assert!(fs::read_dir(t.path("out")).unwrap().next().is_none(), "nothing in the folder");
        assert_no_staging(&data);

        // Cancelled during the second copy, into the user's folder, after the private
        // tree: count how often a whole run asks, then say yes near its end.
        let asked = std::rc::Rc::new(std::cell::Cell::new(0));
        let count = asked.clone();
        let counting = Progress::default().with_cancel(move || {
            count.set(count.get() + 1);
            false
        });
        extract_archive(&data, &Key::Password(PW), open(&share), len(&share), &parent, "Count", &LIMITS, &counting).unwrap();
        fs::remove_dir_all(t.path("out/Count")).unwrap();
        let total = asked.get();
        let count = std::rc::Rc::new(std::cell::Cell::new(0));
        let seen = count.clone();
        let late = Progress::default().with_cancel(move || {
            seen.set(seen.get() + 1);
            seen.get() >= total - 2
        });
        let err = extract_archive(&data, &Key::Password(PW), open(&share), len(&share), &parent, "Late", &LIMITS, &late);
        assert_eq!(err.unwrap_err(), CANCELLED);
        assert!(count.get() > total / 2, "stopped late: {} of {total}", count.get());
        assert!(fs::read_dir(t.path("out")).unwrap().next().is_none(), "nothing in the folder");
        assert_no_staging(&data);

        let mut fresh = quick_vault(&t.path("fresh.vsvault"));
        let before = fresh.listing().unwrap();
        fresh.progress = std::rc::Rc::new(Progress::default().with_cancel(|| true));
        let err = import_archive(&fresh, &data, &Key::Password(PW), open(&share), len(&share), "x", &LIMITS).unwrap_err();
        assert!(err.contains(CANCELLED), "{err}");
        assert_eq!(fresh.listing().unwrap(), before);
        fresh.check().unwrap();
        assert_no_staging(&data);
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

    /// Known-bad and mutated archives, through the whole path: decrypt, scan, private
    /// tree, the user's folder. Nothing may land outside it, and a failure leaves nothing.
    #[test]
    fn hostile_archives_end_to_end() {
        use rand::{Rng, SeedableRng};
        let t = Temp::new();
        let data = t.dir("data");
        let (_v, share) = shared_tree(&t);
        let mut good = Vec::new();
        decrypt_file_to(&data, &Key::Password(PW), open(&share), &mut good).unwrap();

        let mut known_bad: Vec<Vec<u8>> = Vec::new();
        // A symlink entry, then a file "through" it: the link is never made.
        let mut link = good.clone();
        let mut h = [0u8; 512];
        h[..4].copy_from_slice(b"esc\0");
        h[100..108].copy_from_slice(b"0000777\0");
        h[124..136].copy_from_slice(b"00000000000\0");
        h[156] = b'2';
        h[157..161].copy_from_slice(b"/tmp");
        h[257..263].copy_from_slice(b"ustar\0");
        h[148..156].fill(b' ');
        let sum: u64 = h.iter().map(|&b| u64::from(b)).sum();
        h[148..156].copy_from_slice(format!("{sum:06o}\0 ").as_bytes());
        link.splice(0..0, h);
        known_bad.push(link);
        known_bad.push(good[..good.len() / 2].to_vec()); // truncated
        known_bad.push(good[..700].to_vec());
        let mut huge = good.clone();
        huge[124..136].copy_from_slice(b"77777777777\0");
        known_bad.push(huge);

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
        let parent = PathStore::new(&out_dir);
        for (i, plain) in known_bad.iter().enumerate() {
            let file = t.path("case.age");
            encrypt_with(PW, plain, &file);
            let name = format!("case{i}");
            let r = extract_archive(&data, &Key::Password(PW), open(&file), len(&file), &parent, &name, &LIMITS, &Progress::default());
            assert!(!Path::new(&format!("{out_dir}/{name}.vaultsend-part")).exists());
            match r {
                Ok(_) => {
                    let mut found = Vec::new();
                    walk(Path::new(&format!("{out_dir}/{name}")), &mut found);
                    let root = fs::canonicalize(&out_dir).unwrap();
                    for p in found {
                        assert!(fs::canonicalize(&p).unwrap().starts_with(&root), "{} escaped", p.display());
                    }
                }
                Err(_) => assert!(!Path::new(&format!("{out_dir}/{name}")).exists(), "case {i} left a folder"),
            }
            assert_no_staging(&data);
        }
        // The symlink case still unpacked everything else, and made no link.
        assert!(Path::new(&format!("{out_dir}/case0/tree/a.txt")).is_file());
        assert!(!Path::new(&format!("{out_dir}/case0/esc")).exists());
        for i in 1..=3 {
            assert!(!Path::new(&format!("{out_dir}/case{i}")).exists(), "case {i} must be refused");
        }
    }
}
