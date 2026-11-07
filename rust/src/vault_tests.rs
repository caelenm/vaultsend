// Tests for vault.rs, a child module of it (`#[path]`), so they reach its private items.

use super::*;
use crate::vault_cli::{host_staging_dir, parent_of, parse_opts, run};
use std::os::unix::io::FromRawFd;
use std::sync::atomic::AtomicU32;
use std::sync::Once;
use std::time::Duration;

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
    let other = Vault::with(Box::new(PathStore::new(&v.dir)), x25519::Identity::generate(), None, &v.staging);
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
fn rename_moves_entries_and_keeps_blobs() {
    let t = TempDir::new();
    let v = quick_vault(&t);
    add(&v, &t.write("a.txt", b"aaa"));
    t.write("dir/sub/x.txt", b"x");
    add(&v, &t.path("dir"));
    add(&v, &t.write("dir2", b"sibling"));
    let a_blob = blob_of(&v, "a.txt");
    let x_blob = blob_of(&v, "dir/sub/x.txt");

    // A file: same blob, new name, one commit.
    let before = generation(&v);
    v.rename("a.txt", "b.txt").unwrap();
    assert_eq!(generation(&v), before + 1);
    assert_eq!(blob_of(&v, "b.txt"), a_blob);
    assert!(Path::new(&a_blob).exists());
    let out = t.path("b-out.txt");
    v.extract("b.txt", &out).unwrap();
    assert_eq!(fs::read(&out).unwrap(), b"aaa");

    // A folder takes everything in it; a sibling sharing the prefix stays.
    v.rename("dir", "renamed").unwrap();
    let m = v.load_manifest().unwrap();
    let names: Vec<&str> = m.entries.keys().map(String::as_str).collect();
    assert_eq!(names, ["b.txt", "dir2", "renamed", "renamed/sub", "renamed/sub/x.txt"]);
    assert_eq!(blob_of(&v, "renamed/sub/x.txt"), x_blob);

    // Refusals change nothing.
    let before = generation(&v);
    assert!(v.rename("missing", "m").unwrap_err().contains("not in the vault"));
    assert!(v.rename("b.txt", "dir2").unwrap_err().contains("already exists"));
    assert!(v.rename("renamed", "renamed/sub/inner").unwrap_err().contains("inside itself"));
    assert!(v.rename("b.txt", "nowhere/b.txt").unwrap_err().contains("not a folder"));
    assert!(v.rename("b.txt", "dir2/b.txt").unwrap_err().contains("not a folder"));
    assert!(v.rename("b.txt", "../b.txt").unwrap_err().contains("invalid"));
    assert!(v.rename("/", "x").unwrap_err().contains("invalid"));
    assert_eq!(generation(&v), before);
    // Into an existing folder is a move.
    v.rename("b.txt", "renamed/b.txt").unwrap();
    assert!(v.load_manifest().unwrap().entries.contains_key("renamed/b.txt"));
    v.check().unwrap();
}

#[test]
fn write_text_adds_edits_and_renames_notes() {
    let t = TempDir::new();
    let v = quick_vault(&t);
    t.write("folder/keep.txt", b"keep");
    add(&v, &t.path("folder"));

    v.write_text("folder/Note.md", b"# hello\n", None, false).unwrap();
    assert_eq!(&*v.read_text("folder/Note.md", 1 << 20).unwrap(), b"# hello\n");
    let first = blob_of(&v, "folder/Note.md");

    // Saving over itself: new blob, old one collected.
    v.write_text("folder/Note.md", "edited \u{e9}".as_bytes(), Some("folder/Note.md"), false).unwrap();
    assert_eq!(&*v.read_text("folder/Note.md", 1 << 20).unwrap(), "edited \u{e9}".as_bytes());
    assert!(!Path::new(&first).exists());

    // An edit under a new title replaces the old file in one commit.
    let before = generation(&v);
    v.write_text("folder/Renamed.md", b"moved", Some("folder/Note.md"), false).unwrap();
    assert_eq!(generation(&v), before + 1);
    let m = v.load_manifest().unwrap();
    assert!(!m.entries.contains_key("folder/Note.md"));
    assert_eq!(&*v.read_text("folder/Renamed.md", 100).unwrap(), b"moved");

    // Clashes and bad places change nothing and leave no blob behind.
    let blobs = || v.orphans(&v.load_manifest().unwrap()).unwrap().len();
    let before = generation(&v);
    let err = v.write_text("folder/keep.txt", b"x", None, false).unwrap_err();
    assert!(err.contains("already exists"), "{err}");
    assert!(v.write_text("folder", b"x", None, true).unwrap_err().contains("can't replace a folder"));
    assert!(v.write_text("nowhere/n.md", b"x", None, false).unwrap_err().contains("not a folder"));
    assert!(v.write_text("n.md", b"x", Some("missing.md"), false).unwrap_err().contains("not a file"));
    assert!(v.write_text("../n.md", b"x", None, false).unwrap_err().contains("invalid"));
    assert_eq!((generation(&v), blobs()), (before, 0));
    // With replace, a clash is overwritten.
    v.write_text("folder/keep.txt", b"replaced", None, true).unwrap();
    assert_eq!(&*v.read_text("folder/keep.txt", 100).unwrap(), b"replaced");
    // An empty note is a file too.
    v.write_text("empty.md", b"", None, false).unwrap();
    assert!(v.read_text("empty.md", 0).unwrap().is_empty());

    // Reading: too large, a folder, or missing.
    assert!(v.read_text("folder/keep.txt", 3).unwrap_err().contains("too large"));
    assert!(v.read_text("folder", 100).unwrap_err().contains("not a file"));
    assert!(v.read_text("missing", 100).unwrap_err().contains("not a file"));
    v.check().unwrap();
}

#[test]
fn read_text_never_grows_past_the_manifest_size() {
    let t = TempDir::new();
    let v = quick_vault(&t);
    add(&v, &t.write("n.md", b"exactly this"));
    // A manifest whose size is understated (only someone with the key could write
    // one) still can't make the buffer grow: the read stops at the size.
    let mut m = v.load_manifest().unwrap();
    if let Some(Entry::File { size, .. }) = m.entries.get_mut("n.md") {
        *size = 4;
    }
    v.write_manifest(&m).unwrap();
    let err = v.read_text("n.md", 100).unwrap_err();
    assert!(err.contains("longer than"), "{err}");
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
fn crash_leftovers_survive_changes_and_go_on_clean() {
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

    // A change deletes only the blobs it dropped: these could be another device's
    // change that hasn't finished syncing. Its own staged manifest replaces the old one.
    add(&v, &t.write("b.txt", b"bbb"));
    v.remove(&["b.txt"]).unwrap();
    for kept in [&stray, &stray_part, &live_part] {
        assert!(Path::new(kept).exists(), "{kept} was deleted by a change");
    }
    assert!(!Path::new(&manifest_part).exists());

    // Clean refuses while anything fails to verify, and deletes nothing.
    let saved = fs::read(&a).unwrap();
    fs::write(&a, b"tampered").unwrap();
    assert!(v.clean().unwrap_err().contains("failed verification"));
    assert!(Path::new(&stray).exists());
    fs::write(&a, saved).unwrap();

    let report = v.clean().unwrap();
    assert_eq!(report, "removed 3 unused blob file(s)\nok 1 file(s) verified\n");
    for gone in [&stray, &stray_part, &live_part] {
        assert!(!Path::new(gone).exists(), "{gone} should have been cleaned");
    }
    assert!(Path::new(&a).exists());
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
    v.clean().unwrap();
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
    let staging = host_staging_dir().unwrap();
    let staged = || {
        let (staged, mut file) = StagedFile::create(&staging, "test").unwrap();
        file.write_all(b"y").unwrap();
        Some(staged)
    };
    let items = vec![("Name", staged()), ("Name", staged())];
    assert!(write_tree(&PathStore::new(&t.0), "root", items, &Progress::default()).unwrap_err().contains("collide"));
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
    fn open(&self, rel: &str) -> io::Result<File> { self.0.open(rel) }
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

// -----------------------------------------------------------------------
// Android: files stream through private staging instead of RAM.
// -----------------------------------------------------------------------

/// A PathStore that counts how often each file is opened or read.
struct CountingStore(PathStore, Rc<RefCell<BTreeMap<String, usize>>>);

impl CountingStore {
    fn count(&self, rel: &str) {
        *self.1.borrow_mut().entry(rel.to_string()).or_insert(0) += 1;
    }
}

impl Store for CountingStore {
    fn key(&self) -> R<String> { self.0.key() }
    fn show(&self, rel: &str) -> String { self.0.show(rel) }
    fn kind(&self, rel: &str) -> Kind { self.0.kind(rel) }
    fn read(&self, rel: &str) -> io::Result<Vec<u8>> { self.count(rel); self.0.read(rel) }
    fn open(&self, rel: &str) -> io::Result<File> { self.count(rel); self.0.open(rel) }
    fn create_new(&self, rel: &str) -> R<File> { self.0.create_new(rel) }
    fn rename(&self, from: &str, to: &str) -> io::Result<()> { self.0.rename(from, to) }
    fn replaces_on_rename(&self) -> bool { true }
    fn remove_file(&self, rel: &str) -> io::Result<()> { self.0.remove_file(rel) }
    fn remove_tree(&self, rel: &str) { self.0.remove_tree(rel) }
    fn mkdir(&self, rel: &str, recursive: bool) -> R<()> { self.0.mkdir(rel, recursive) }
    fn list(&self, rel: &str) -> R<Vec<(String, Kind)>> { self.0.list(rel) }
    fn sync_dir(&self, rel: &str) { self.0.sync_dir(rel) }
    fn lock(&self, _exclusive: bool) -> R<Box<dyn Any>> { Ok(Box::new(())) }
}

/// `v` again, staging in a folder of its own (`t`'s "staging"), so what it stages
/// can be counted while other tests stage in the shared one.
fn with_own_staging(t: &TempDir, v: &Vault, store: Box<dyn Store>) -> (Vault, String) {
    let staging = t.path("staging");
    fs::create_dir_all(&staging).unwrap();
    (Vault::with(store, v.key.clone(), None, &staging), staging)
}

fn staged_now(staging: &str) -> Vec<String> {
    fs::read_dir(staging).unwrap().flatten().map(|e| e.file_name().to_string_lossy().into_owned()).collect()
}

#[test]
fn files_stream_through_private_staging_that_is_always_removed() {
    let t = TempDir::new();
    let built = quick_vault(&t);
    // Larger than one age chunk and one copy buffer, and not a multiple of either.
    let big: Vec<u8> = (0..3_000_017u32).map(|i| (i.wrapping_mul(2654435761) >> 24) as u8).collect();
    add(&built, &t.write("src/big.bin", &big));
    add(&built, &t.write("src/small.txt", b"small"));
    let (v, staging) = with_own_staging(&t, &built, Box::new(PathStore::new(&built.dir)));

    let out = t.path("big.out");
    v.extract("big.bin", &out).unwrap();
    assert_eq!(fs::read(&out).unwrap(), big);
    assert!(staged_now(&staging).is_empty(), "left behind: {:?}", staged_now(&staging));

    let many = t.path("many.out");
    v.extract_many(&["big.bin", "small.txt"], &many).unwrap();
    assert_eq!(fs::read(format!("{many}/big.bin")).unwrap(), big);
    assert_eq!(fs::read(format!("{many}/small.txt")).unwrap(), b"small");
    let friend = x25519::Identity::generate();
    let shared = t.path("shared.tar.age");
    v.share(&[ROOT_ENTRY], &[&friend.to_public().to_string()], &shared).unwrap();
    let mut plain = Vec::new();
    age::Decryptor::new(File::open(&shared).unwrap()).unwrap()
        .decrypt(once(&friend as &dyn age::Identity)).unwrap()
        .read_to_end(&mut plain).unwrap();
    let scan = tar::scan(&mut Cursor::new(&plain), plain.len() as u64, &tar::LIMITS, &|| false).unwrap();
    let Some(tar::Item::File { offset, size }) = scan.items.get("big.bin").copied() else { panic!("{scan:?}") };
    assert_eq!(&plain[offset as usize..(offset + size) as usize], &big[..]);
    assert_eq!(v.check().unwrap(), "ok 2 file(s) verified\n");
    assert!(staged_now(&staging).is_empty(), "left behind: {:?}", staged_now(&staging));

    // Tampered: data after age's last chunk, and an enormous file in a blob's place.
    // Each is refused, writes nothing, and leaves no staging.
    let small = blob_of(&v, "small.txt");
    let mut f = fs::OpenOptions::new().append(true).open(&small).unwrap();
    f.write_all(b"trailing").unwrap();
    drop(f);
    let out = t.path("small.out");
    assert!(v.extract("small.txt", &out).unwrap_err().contains("failed verification"));
    assert_nothing_written(&out);
    File::create(blob_of(&v, "big.bin")).unwrap().set_len(64 << 30).unwrap(); // sparse
    let started = std::time::Instant::now();
    assert!(v.extract("big.bin", &out).unwrap_err().contains("failed verification"));
    assert!(started.elapsed() < Duration::from_secs(10), "read the whole enormous blob");
    assert_nothing_written(&out);
    assert!(v.check().unwrap_err().contains("failed verification"));
    assert!(staged_now(&staging).is_empty(), "left behind: {:?}", staged_now(&staging));
}

#[test]
fn every_blob_is_read_exactly_once() {
    let t = TempDir::new();
    let built = quick_vault(&t);
    add(&built, &t.write("src/tree/a.txt", b"alpha"));
    add(&built, &t.write("src/tree/sub/b.txt", b"beta"));
    let counts = Rc::new(RefCell::new(BTreeMap::new()));
    let counting = Box::new(CountingStore(PathStore::new(&built.dir), counts.clone()));
    let (v, _) = with_own_staging(&t, &built, counting);
    let blobs: Vec<String> = v.load_manifest().unwrap().entries.values().filter_map(|e| match e {
        Entry::File { blob, .. } => Some(v.blob_rel(blob)),
        Entry::Dir => None,
    }).collect();
    assert_eq!(blobs.len(), 2);
    v.extract(ROOT_ENTRY, &t.path("all.out")).unwrap();
    // No second read of a blob, so nothing can swap it between check and use.
    let counts = counts.borrow();
    for blob in &blobs {
        assert_eq!(counts.get(blob), Some(&1), "{blob}: {counts:?}");
    }
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
    let other = Vault::with(Box::new(PathStore::new(&t.path("elsewhere"))), x25519::Identity::generate(), None, &host_staging_dir().unwrap());
    fs::create_dir_all(t.path("elsewhere")).unwrap();
    other.write_manifest(&Manifest::default()).unwrap();
    fs::rename(t.path(&format!("elsewhere/{MANIFEST_FILE}")), &staged).unwrap();
    assert!(v.load_manifest().is_err());
    assert!(Path::new(&staged).exists() && !Path::new(&manifest).exists());
}

/// SAF, with the manifest's rename refused once: after the old manifest is gone.
struct FailingRenameStore(NoReplaceStore, Cell<bool>);

impl Store for FailingRenameStore {
    fn key(&self) -> R<String> { self.0.key() }
    fn show(&self, rel: &str) -> String { self.0.show(rel) }
    fn kind(&self, rel: &str) -> Kind { self.0.kind(rel) }
    fn read(&self, rel: &str) -> io::Result<Vec<u8>> { self.0.read(rel) }
    fn open(&self, rel: &str) -> io::Result<File> { self.0.open(rel) }
    fn create_new(&self, rel: &str) -> R<File> { self.0.create_new(rel) }
    fn rename(&self, from: &str, to: &str) -> io::Result<()> {
        if to == MANIFEST_FILE && self.1.replace(false) {
            return Err(io::Error::other("the provider refused the rename"));
        }
        self.0.rename(from, to)
    }
    fn replaces_on_rename(&self) -> bool { false }
    fn remove_file(&self, rel: &str) -> io::Result<()> { self.0.remove_file(rel) }
    fn remove_tree(&self, rel: &str) { self.0.remove_tree(rel) }
    fn mkdir(&self, rel: &str, recursive: bool) -> R<()> { self.0.mkdir(rel, recursive) }
    fn list(&self, rel: &str) -> R<Vec<(String, Kind)>> { self.0.list(rel) }
    fn sync_dir(&self, rel: &str) { self.0.sync_dir(rel) }
    fn lock(&self, _exclusive: bool) -> R<Box<dyn Any>> { Ok(Box::new(())) }
}

/// The change is reported as failed, but its staged manifest is the committed
/// state and the next open puts it in place, so the blobs it names must survive.
#[test]
fn a_manifest_rename_refused_after_the_delete_keeps_the_new_blobs() {
    let t = TempDir::new();
    let built = quick_vault(&t);
    add(&built, &t.write("a.txt", b"aaa"));
    let failing = FailingRenameStore(NoReplaceStore(PathStore::new(&built.dir)), Cell::new(true));
    let v = Vault::with(Box::new(failing), built.key.clone(), None, &host_staging_dir().unwrap());
    let err = v.add(&[t.write("b.txt", b"bbb")], None, false).unwrap_err();
    assert!(err.contains("finalizing"), "{err}");
    assert!(!Path::new(&t.path(&format!("v.vsvault/{MANIFEST_FILE}"))).exists());

    let v = Vault::with(Box::new(NoReplaceStore(PathStore::new(&built.dir))), built.key.clone(), None, &host_staging_dir().unwrap());
    assert_eq!(generation(&v), 2);
    for (name, data) in [("a.txt", b"aaa"), ("b.txt", b"bbb")] {
        let out = t.path(&format!("{name}.out"));
        v.extract(name, &out).unwrap();
        assert_eq!(fs::read(&out).unwrap(), data);
    }
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

    set_remember(false);
    create(Box::new(PathStore::new(&dir)), "password", &typed).unwrap();
    assert_eq!(open(&nothing).err().unwrap(), PASSWORD_NEEDED);
    open(&typed).unwrap();
    assert!(!is_remembered(&key()), "Off remembers nothing");

    set_remember(true);
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

    // Setting it again forgets everything, as on desktop.
    open(&typed).unwrap();
    assert!(is_remembered(&key()));
    set_remember(true);
    assert!(!is_remembered(&key()));
    open(&typed).unwrap();
    assert!(is_remembered(&key()));
    set_remember(false);
    assert!(!is_remembered(&key()));
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
