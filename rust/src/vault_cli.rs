// The desktop backend's vault commands, on the host: the same options and output,
// over a real folder. Not part of the app: it's built only for the unit tests and
// for examples/vault_cli.rs, which tests/vault_roundtrip.sh and tests/vault_attack.py
// drive exactly as they drive the desktop binary.
//
//   vault-create  --dir P --mode self|password --pass-fd N
//   vault-list|vault-check  --dir P --pass-fd N
//   vault-add     --dir P --pass-fd N --src PATH [--src PATH]... [--dest VAULTDIR] [--replace]
//   vault-remove  --dir P --pass-fd N (--entry VAULTPATH... | --all)
//   vault-extract --dir P --pass-fd N --entry VAULTPATH... --out PATH
//   vault-share   --dir P --pass-fd N --entry VAULTPATH... --to AGE1.. [--to AGE1..]... --out PATH
//
// Anything that opens a vault also takes --progress-fd N. The identity is read
// from $XDG_DATA_HOME/vaultsend (default ~/.local/share/vaultsend), as on desktop.

use std::env;
use std::fs::File;
use std::io::{self, Read, Write};
use std::mem::ManuallyDrop;
use std::os::unix::io::FromRawFd;
use std::path::PathBuf;
use std::rc::Rc;

use crate::backend::{secret_buffer, SecretBuf};
use crate::vault::{self, PathStore, Progress, Secret, Vault};
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
}

pub(crate) struct Opts<'a> {
    pairs: Vec<(&'a str, &'a str)>,
    pub(crate) replace: bool,
    everything: bool,
}

/// Strict "--name value" pairs, unlike the scanning helpers in main.rs, because
/// values here can be names out of a vault: a folder called "--replace" must not
/// read as the flag.
pub(crate) fn parse_opts(args: &[String]) -> R<Opts<'_>> {
    let mut o = Opts { pairs: Vec::new(), replace: false, everything: false };
    let mut it = args.iter().map(String::as_str);
    while let Some(name) = it.next() {
        match name {
            "--replace" => o.replace = true,
            "--all" => o.everything = true,
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
        "vault-check" => with(open(false)?, &|v| print_out(&v.check()?)),
        other => Err(format!("unknown command '{other}'")),
    }
}
