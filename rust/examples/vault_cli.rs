// Host-side command line for tests/vault_roundtrip.sh and tests/vault_attack.py,
// which drive it exactly as they drive the desktop backend binary: the vault-*
// commands (src/vault_cli.rs), plus keygen, encrypt and decrypt over this
// library's backend, so those scripts can make an identity and check shares.
// Not shipped in the app. Build with: cargo build --example vault_cli --features cli

use std::fs::File;
use std::io::{self, Read, Write};
use std::os::unix::io::FromRawFd;
use std::process::ExitCode;

use vaultsend::backend;
use vaultsend::vault_cli::{data_dir, run};

type R<T> = Result<T, String>;

/// The value after `name`, as the desktop's opt_value scans for it.
fn opt_value(args: &[String], name: &str) -> Option<String> {
    args.iter().position(|a| a == name).and_then(|i| args.get(i + 1)).cloned()
}

fn read_fd(args: &[String]) -> R<Vec<u8>> {
    let fd: i32 = opt_value(args, "--pass-fd")
        .ok_or("--pass-fd is required")?
        .parse()
        .map_err(|_| "--pass-fd must be a number".to_string())?;
    if fd < 3 {
        return Err("--pass-fd must refer to a dedicated pipe (fd >= 3)".into());
    }
    let mut bytes = Vec::new();
    // SAFETY: the caller hands over a readable pipe end; we own and close it.
    unsafe { File::from_raw_fd(fd) }.read_to_end(&mut bytes).map_err(|e| format!("reading passphrase: {e}"))?;
    Ok(bytes)
}

fn input(args: &[String]) -> R<Box<dyn Read>> {
    match opt_value(args, "--in") {
        Some(p) => Ok(Box::new(File::open(&p).map_err(|e| format!("opening {p}: {e}"))?)),
        None => Ok(Box::new(io::stdin())),
    }
}

fn output(args: &[String]) -> R<Box<dyn Write>> {
    match opt_value(args, "--out") {
        Some(p) => Ok(Box::new(File::create(&p).map_err(|e| format!("creating {p}: {e}"))?)),
        None => Ok(Box::new(io::stdout())),
    }
}

fn identity_command(cmd: &str, args: &[String]) -> R<()> {
    let dir = data_dir();
    match cmd {
        "keygen" => {
            let public = backend::keygen(&dir, &read_fd(args)?)?;
            println!("{public}");
            Ok(())
        }
        "encrypt" => {
            let recipients: Vec<String> = args.windows(2).filter(|w| w[0] == "-r").map(|w| w[1].clone()).collect();
            let armor = args.iter().any(|a| a == "--armor");
            backend::encrypt(&recipients, armor, input(args)?, output(args)?)
        }
        "decrypt" => {
            let pass = read_fd(args)?;
            // Authenticated in full before any of it reaches --out, as on desktop.
            let mut plain = Vec::new();
            backend::decrypt(&dir, &pass, input(args)?, &mut plain)?;
            let mut out = output(args)?;
            out.write_all(&plain).and_then(|_| out.flush()).map_err(|e| format!("writing output: {e}"))
        }
        other => run(other, args),
    }
}

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let Some((cmd, rest)) = args.split_first() else {
        eprintln!("usage: vault_cli keygen|encrypt|decrypt|vault-create|vault-list|vault-add|vault-remove|vault-extract|vault-share|vault-check [options]");
        return ExitCode::from(2);
    };
    match identity_command(cmd, rest) {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("error: {e}");
            ExitCode::FAILURE
        }
    }
}
