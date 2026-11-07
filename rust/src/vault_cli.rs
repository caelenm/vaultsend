// The desktop backend's vault commands, on the host: the same options and output,
// over a real folder. Not part of the app: it's built only for the unit tests and
// for examples/vault_cli.rs, which tests/vault_roundtrip.sh and tests/vault_attack.py
// drive exactly as they drive the desktop binary.
//
//   vault-create  --dir P --mode self|password --pass-fd N
//   vault-list|vault-check  --dir P --pass-fd N   (vault-check --clean also removes orphans)
//   vault-add     --dir P --pass-fd N --src PATH [--src PATH]... [--dest VAULTDIR] [--replace]
//   vault-remove  --dir P --pass-fd N (--entry VAULTPATH... | --all)
//   vault-extract --dir P --pass-fd N --entry VAULTPATH... --out PATH
//   vault-share   --dir P --pass-fd N --entry VAULTPATH... --to AGE1.. [--to AGE1..]... --out PATH
//
// Anything that opens a vault also takes --progress-fd N. The identity is read
// from $XDG_DATA_HOME/vaultsend (default ~/.local/share/vaultsend), as on desktop.

use std::cell::RefCell;
use std::collections::BTreeMap;
use std::env;
use std::fs::{self, DirBuilder, File};
use std::io::{self, Read, Write};
use std::mem::ManuallyDrop;
use std::os::unix::fs::DirBuilderExt;
use std::os::unix::io::FromRawFd;
use std::path::{Path, PathBuf};
use std::rc::Rc;

use crate::backend::{secret_buffer, SecretBuf};
use crate::vault::{self, Out, PathStore, Plan, Progress, Secret, Sources, Vault};
use crate::R;

/// Where the desktop keeps identity.age.
pub fn data_dir() -> String {
    let base = env::var_os("XDG_DATA_HOME")
        .filter(|v| !v.is_empty())
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from(env::var_os("HOME").unwrap_or_default()).join(".local/share"));
    base.join("vaultsend").to_string_lossy().into_owned()
}

/// The secret from a pipe, as the desktop's `read_passphrase` reads it. Trailing
/// CR/LF is stripped later, by `passphrase_from_bytes`.
fn read_secret_fd(fd: i32) -> R<SecretBuf> {
    // Reject the standard streams: from_raw_fd takes ownership and would close
    // the fd on drop, and a passphrase pipe should never be 0/1/2 anyway.
    if fd < 3 {
        return Err("--pass-fd must refer to a dedicated pipe (fd >= 3)".into());
    }
    // SAFETY: the parent passes a readable pipe end as this fd. We take ownership
    // here and close it on drop.
    let mut f = unsafe { File::from_raw_fd(fd) };
    let mut buf = secret_buffer();
    f.read_to_end(&mut buf).map_err(|e| format!("reading passphrase: {e}"))?;
    Ok(buf)
}

impl Progress {
    /// Whole percents, one per line, on a pipe (the desktop's `--progress-fd`).
    pub fn to_fd(fd: i32) -> R<Progress> {
        if fd < 3 {
            return Err("--progress-fd must refer to a dedicated pipe (fd >= 3)".into());
        }
        // SAFETY: only ever written to, and never closed, so it needs nothing of the fd.
        // A number that isn't open just fails each write, which is ignored.
        let pipe = ManuallyDrop::new(unsafe { File::from_raw_fd(fd) });
        Ok(Progress::new(move |percent| {
            let mut pipe: &File = &pipe;
            let _ = pipe.write_all(format!("{percent}\n").as_bytes());
        }))
    }
}

impl Vault {
    /// The desktop's `Vault::open`: a vault on a real path, its secret on a pipe.
    pub fn open(dir: &str, pass_fd: i32, exclusive: bool) -> R<Vault> {
        let secret = read_secret_fd(pass_fd)?;
        let data_dir = data_dir();
        Vault::open_in(Box::new(PathStore::new(dir)), &Secret { data_dir: &data_dir, bytes: Some(&secret) }, exclusive)
    }

    /// A vault on a real path (the desktop's `Vault::create`, kept for the tests).
    /// It stages plaintext in a private folder of this process's under the temp dir.
    pub fn create(dir: &str, mode: &str, wrap: age::Encryptor) -> R<Vault> {
        Vault::create_in(Box::new(PathStore::new(dir)), mode, wrap, &host_staging_dir()?)
    }

    /// Add files and folders from real paths (the desktop's `add`).
    pub fn add<S: AsRef<str>>(&self, sources: &[S], dest: Option<&str>, replace: bool) -> R<()> {
        self.add_from(&PathSources::new(sources), dest, replace)
    }

    /// Extract to a real path (the desktop's `extract`).
    pub fn extract(&self, entry: &str, out: &str) -> R<()> {
        let (folder, name) = path_out(out)?;
        self.extract_to(entry, Out::In(&folder, &name))
    }

    /// Several entries into a new folder `out` (the desktop's `extract` of several).
    pub fn extract_many(&self, entries: &[&str], out: &str) -> R<()> {
        let (folder, name) = path_out(out)?;
        self.extract_many_to(entries, Out::In(&folder, &name))
    }

    /// Share to a real path (the desktop's `share`).
    pub fn share(&self, entries: &[&str], to: &[&str], out: &str) -> R<()> {
        let (folder, name) = path_out(out)?;
        self.share_to(entries, to, Out::In(&folder, &name))
    }
}

/// The folder `path` is in, "." for a bare name.
pub(crate) fn parent_of(path: &str) -> &str {
    match Path::new(path).parent().and_then(Path::to_str) {
        Some("") | None => ".",
        Some(parent) => parent,
    }
}

/// A path as an output: its folder as a store, and its name.
fn path_out(out: &str) -> R<(PathStore, String)> {
    let name = Path::new(out).file_name().and_then(|n| n.to_str());
    let name = name.ok_or_else(|| format!("--out must name a file or folder: {out}"))?;
    Ok((PathStore::new(parent_of(out)), name.to_string()))
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

/// Where a vault made by `Vault::create` (the tests) stages plaintext: a private
/// folder of this process's under the temp dir, so its sweep of leftovers can't
/// touch another process's staging.
pub(crate) fn host_staging_dir() -> R<String> {
    let dir = std::env::temp_dir().join(format!("vaultsend-staging-{}", std::process::id()));
    DirBuilder::new()
        .recursive(true)
        .mode(0o700)
        .create(&dir)
        .map_err(|e| format!("creating {}: {e}", dir.display()))?;
    dir.to_str().map(str::to_string).ok_or_else(|| format!("{}: not valid UTF-8", dir.display()))
}


pub(crate) struct Opts<'a> {
    pairs: Vec<(&'a str, &'a str)>,
    pub(crate) replace: bool,
    everything: bool,
    clean: bool,
}

/// Strict "--name value" pairs, unlike the scanning helpers in main.rs, because
/// values here can be names out of a vault: a folder called "--replace" must not
/// read as the flag.
pub(crate) fn parse_opts(args: &[String]) -> R<Opts<'_>> {
    let mut o = Opts { pairs: Vec::new(), replace: false, everything: false, clean: false };
    let mut it = args.iter().map(String::as_str);
    while let Some(name) = it.next() {
        match name {
            "--replace" => o.replace = true,
            "--all" => o.everything = true,
            "--clean" => o.clean = true,
            "--dir" | "--mode" | "--pass-fd" | "--progress-fd" | "--src" | "--dest" | "--entry" | "--out" | "--to" => {
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
    pub(crate) fn get(&self, name: &str) -> Option<&'a str> {
        self.all(name).first().copied()
    }
    fn need(&self, name: &str) -> R<&'a str> {
        self.get(name).ok_or_else(|| format!("{name} is required"))
    }
    pub(crate) fn pass_fd(&self) -> R<i32> {
        self.need("--pass-fd")?.parse().map_err(|_| "--pass-fd must be a number".to_string())
    }
    fn entries(&self) -> R<Vec<&'a str>> {
        self.need("--entry")?;
        Ok(self.all("--entry"))
    }
}

fn cmd_create(dir: &str, o: &Opts) -> R<()> {
    let mode = o.need("--mode")?;
    if mode != "self" && mode != "password" {
        return Err(format!("--mode must be self or password, not '{mode}'"));
    }
    let secret = read_secret_fd(o.pass_fd()?)?;
    let data_dir = data_dir();
    vault::create(Box::new(PathStore::new(dir)), mode, &Secret { data_dir: &data_dir, bytes: Some(&secret) })
}

fn print_out(text: &str) -> R<()> {
    let mut stdout = io::stdout();
    stdout.write_all(text.as_bytes()).and_then(|_| stdout.flush()).map_err(|e| format!("writing output: {e}"))
}

pub fn run(cmd: &str, args: &[String]) -> R<()> {
    let o = parse_opts(args)?;
    let dir = o.need("--dir")?;
    let open = |exclusive| -> R<Vault> {
        let mut vault = Vault::open(dir, o.pass_fd()?, exclusive)?;
        if let Some(fd) = o.get("--progress-fd") {
            let fd = fd.parse().map_err(|_| "--progress-fd must be a number".to_string())?;
            vault.progress = Rc::new(Progress::to_fd(fd)?);
        }
        Ok(vault)
    };
    let with = |vault: Vault, act: &dyn Fn(&Vault) -> R<()>| -> R<()> {
        let result = act(&vault);
        for warning in vault.warnings() {
            eprintln!("warning: {warning}");
        }
        result
    };
    match cmd {
        "vault-create" => cmd_create(dir, &o),
        "vault-list" => with(open(false)?, &|v| print_out(&v.listing()?)),
        "vault-add" => with(open(true)?, &|v| v.add(&o.all("--src"), o.get("--dest"), o.replace)),
        "vault-remove" if o.everything => with(open(true)?, &|v| v.remove_everything()),
        "vault-remove" => with(open(true)?, &|v| v.remove(&o.entries()?)),
        "vault-extract" => with(open(false)?, &|v| match o.entries()?[..] {
            [one] => v.extract(one, o.need("--out")?),
            ref many => v.extract_many(many, o.need("--out")?),
        }),
        "vault-share" => with(open(false)?, &|v| v.share(&o.entries()?, &o.all("--to"), o.need("--out")?)),
        "vault-check" if o.clean => with(open(true)?, &|v| print_out(&v.clean()?)),
        "vault-check" => with(open(false)?, &|v| print_out(&v.check()?)),
        other => Err(format!("unknown command '{other}'")),
    }
}
