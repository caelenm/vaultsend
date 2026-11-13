# VaultSend

A single-file, fully offline encryption tool for the [`age`](https://age-encryption.org)
format. Open `index.html` in any modern browser and encrypt text or
files to anyone whose public key you have — no install, no accounts, no servers,
no network requests at all.

VaultSend is interoperable with the `age` and [`rage`](https://github.com/str4d/rage)
command-line tools and the desktop app: anything you encrypt here can be
decrypted there, and vice versa.

> **Status:** v1.4.0 · self-contained web build · MIT-licensed dependencies

---

## Why a single HTML file?

Encryption tools are only as trustworthy as the code that actually runs. VaultSend
ships as **one HTML file with everything inlined** so that:

- there is nothing to install and nothing fetched at runtime;
- the exact bytes that execute are fixed, hashed, and auditable;
- you can read, archive, and re-verify the whole thing offline, forever.

You can literally save the file, unplug from the network, and it still works.

---

## Features

- **age keypairs** — generate an identity (`AGE-SECRET-KEY-1…`) and share your
  public key (`age1…`). Your private key is encrypted with a passphrase
  (scrypt) before it is ever stored.
- **Encrypt text or files** to one or more recipients. You are always added as a
  recipient so you can read your own messages back.
- **Decrypt** age files and ASCII-armored age messages, made for your key or
  with a password.
- **Open what someone shared from a vault** in the desktop or Android app: a
  `Name.tar.age` shows the files and folders it holds, to save one at a time,
  all into a new folder, or as the `.tar` it is. See
  [Files shared from a vault](#files-shared-from-a-vault).
- **Drag & drop** files; drop a folder and it is zipped first.
- **Contacts** — save people's public keys with names; import/export as JSON.
- **Portable identity** — export/import a passphrase-protected `identity.age`.
- **Interoperable** with `age`, `rage`, and the desktop app.
- **Light / dark theme**, keyboard-navigable menus, screen-reader labels.
- **Works completely offline** — open from disk (`file://`) with no connection.

---

## Security model

### No network, by construction

The page ships a strict Content-Security-Policy:

```
default-src 'none'; script-src 'sha256-…' 'sha256-…';
style-src 'self' 'unsafe-inline'; img-src 'self' data:;
manifest-src 'self'; worker-src 'self';
base-uri 'none'; form-action 'none'
```

`default-src 'none'` means `connect-src` is also `none`: **the page cannot make a
network request** — no `fetch`, `XMLHttpRequest`, `WebSocket`, or beacon will
load. Scripts are allowed only by hash: there is no `'self'`, no `unsafe-inline`
and no `unsafe-eval`.

Browsers ignore `frame-ancestors` in a `<meta>` policy, so the file cannot stop
another site from framing it. If you host a copy, send
`Content-Security-Policy: frame-ancestors 'none'` as an HTTP response header.

After editing either inline script, re-pin its hash with `python3 update-csp.py`
(`--check` only reports whether the pins are current).

### Installing it as an app

`index.html` on its own is the whole tool, and opened from disk (`file://`) it
stays exactly that: browsers only offer to install a page served over `https`.

A hosted copy can be installed (Chrome, Edge and Android: the install button in
the address bar or menu; iOS and macOS Safari: Share → Add to Home Screen / Add
to Dock). For that, host these beside `index.html`:

| File | Purpose |
|------|---------|
| `manifest.webmanifest` | Name, colours and icons of the installed app. |
| `icons/` | The app icon, 192 and 512 px. |
| `sw.js` | Service worker: keeps a copy of these files so the app opens offline. |

What this changes in the security model, and what it doesn't:

- The CSP gains `manifest-src 'self'` and `worker-src 'self'`. `script-src` is
  unchanged: page scripts still run only by pinned hash.
- `sw.js` is the one script not pinned by hash (a service worker can't be
  inline). It runs in its own context, sees no keys, text or files, and only
  re-fetches VaultSend's own files from its own origin (network first, kept
  copy when offline). It can decide which copy of `index.html` the browser
  gets, as the host already can, but not what that copy is allowed to run.
- The page itself still makes no network requests.

If you'd rather not have a service worker, don't host `sw.js`: everything else
works, and the app just won't open offline when installed.

### Pinned, auditable code

The only third-party code is a single inline `<script>` containing a tree-shaken
bundle of the `age` stack. Its SHA-256 is **pinned in the CSP**, so the browser
refuses to run it if even one byte changes. The application script is pinned the
same way. Nothing can be swapped in by a CDN, a cache, or an injection.

### Key handling

- Your private key is stored **only** as a passphrase-encrypted `age` blob
  (scrypt) in `localStorage`. The passphrase is never stored.
- After you unlock, the decrypted key is held in a **session key vault** that:
  - keeps it as a zeroable byte buffer (wiped on lock);
  - **auto-locks after 5 minutes idle**;
  - **locks shortly after the browser tab is hidden** and wipes on unload;
  - offers a **"don't remember"** option to re-ask every time;
  - can be locked instantly from **Menu → Lock session now**.

### Files shared from a vault

The desktop and Android apps keep **vaults**: encrypted folders that change one
file at a time. Their **Share…** hands part of a vault to someone else as an
ordinary age file, encrypted to that person's key or to a password. One file
stays that file (`photo.jpg.age`); a folder or several items travel as a tar
archive inside it (`Holiday.tar.age`).

The web build opens those files, and has no vaults of its own:

- **Decrypt** reads the file's header to see which it needs. A file made with a
  password asks for that password, checks it at once and asks again if it is
  wrong; any other uses your key. The password is used for that one file and
  never kept.
- **An archive** is decrypted and authenticated in full before any of it is
  read, then listed. Nothing is saved until you choose: **Save** on one file,
  **Save all to a folder…** (a new folder inside one you pick, never over an
  existing name; in browsers without that, **Download as .zip**), or **Save as
  .tar**. Closing the list drops the decrypted copy.
- **No key is needed for a password.** On the welcome page, **Open it without
  a key** (or just dropping the file there) goes straight to Decrypt. Nothing
  is created or stored. Encrypting, and files made for a key, still need yours.
- **A shared archive is read as hostile**, by the same rules as the apps'
  reader: age has authenticated it, but only as coming from whoever knew the
  password. Names that could leave the folder (`..`, absolute paths, drive
  prefixes, backslashes, NUL) are refused; links, devices and FIFOs are skipped
  and never created; at most 100,000 entries and 32 GB, and every declared size
  is checked against the file. An archive that fails any of this shows nothing
  and saves nothing. `node tests/shared_archive_test.mjs` runs these rules
  against the reader inside `index.html`.
- **A password file may ask for scrypt up to 2^18**, what VaultSend and the
  `age` tool make, and one asking for more is refused before any work is done.
- **A vault itself can't be imported.** Dropping a `.vsvault` folder (or its
  `VAULT` file) says so: importing vaults is not supported on the web, and the
  desktop or mobile versions are the place for it.

What a page can't do that the apps can: build the unpacked folder somewhere
private and rename it into place. Here the archive is verified and checked in
full first, and if writing then fails or is cancelled, the new folder is removed
again.

### Threat model — what VaultSend does and doesn't protect

**Protects against:** a malicious or compromised host/CDN (there is none — it's
offline and hash-pinned); silent code substitution; accidental network leakage of
plaintext or keys; shoulder-surfing of an idle unlocked session.

**Does not protect against:** malware or a malicious browser extension already
running in your browser (it can read anything the page can); a weak passphrase on
your identity; a compromised device or OS; or you sending to the wrong public key.
Browser JavaScript also cannot guarantee that transient plaintext strings are
wiped from memory — VaultSend minimizes their lifetime but cannot eliminate it.

Encryption is only as good as recipient verification: confirm a contact's full
`age1…` key out-of-band before trusting it.

---

## Verifying the build matches upstream

You don't have to take the bundle on faith. It is a **byte-for-byte reproducible
build** of pinned upstream releases, and you can confirm that three ways.

### 1. In the app (no tools)

- **Menu → Verify integrity** recomputes the SHA-256 of the two scripts running
  in your browser and shows that they match the CSP pins and the documented
  build hash.
- **Menu → Run crypto self-test** decrypts ciphertexts — and reproduces an
  identity→recipient mapping — that were generated by the genuine upstream
  `age-encryption`, then runs a live encrypt/decrypt round-trip and a tamper
  rejection check. This proves the embedded X25519, HKDF, ChaCha20-Poly1305, and
  scrypt behave exactly like upstream.

### 2. One command

With Node.js, npm, and Python 3 installed:

```sh
bash verify.sh index.html
```

It extracts the embedded bundle, rebuilds it from the pinned sources, and compares
hashes. Expected result:

```
✅  PASS — Embedded bundle is byte-identical to the pinned upstream rebuild.
```

The script checks its prerequisites first and reports clearly if anything is
missing (including an offline hash-only fallback), so it never fails silently.

### 3. By hand

```sh
npm i age-encryption@0.2.4 fflate@0.8.2 esbuild@0.28.1 \
      @noble/ciphers@1.3.0 @noble/curves@1.9.7 \
      @noble/hashes@1.8.0 @scure/base@1.2.6

cat > entry.js <<'JS'
import {generateIdentity,identityToRecipient,Encrypter,Decrypter,armor} from "age-encryption";
import {zipSync} from "fflate";
globalThis.__VS_AGE__={generateIdentity,identityToRecipient,Encrypter,Decrypter,armor};
globalThis.__VS_FFLATE__={zipSync};
JS

npx esbuild entry.js --bundle --format=iife --platform=browser \
  --target=es2020 --minify --legal-comments=none --outfile=vendor.min.js

sha256sum vendor.min.js
# 2029930d2807bd3b37d5d4718194b77dd086ba7d420a18176cbdc616960c9eb2
```

That hex digest equals the base64 CSP pin
`sha256-ICmTDSgHvTs31dRxgZS3fdCGun1CChgXbL3GFpYMnrI=`.

See **[PROVENANCE.md](PROVENANCE.md)** for the full pinned dependency table and
what is and isn't proven by a reproducible build.

### Pinned dependencies

| Package          | Version | License |
|------------------|---------|---------|
| age-encryption   | 0.2.4   | MIT |
| @noble/ciphers   | 1.3.0   | MIT |
| @noble/curves    | 1.9.7   | MIT |
| @noble/hashes    | 1.8.0   | MIT |
| @scure/base      | 1.2.6   | MIT |
| fflate           | 0.8.2   | MIT |
| esbuild (build)  | 0.28.1  | MIT |

---

## Usage

1. **Open** `index.html` in a browser.
2. **Create your key** and set a strong passphrase. Copy your public key
   (`age1…`) to share it.
3. **Add contacts** — paste the public keys others share with you.
4. **Encrypt** — type a message or drop a file, choose recipients, and copy or
   download the result. *Tick every recipient you intend to send to* — only
   checked recipients (plus yourself) can decrypt.
5. **Decrypt** — paste an armored message or drop an `.age` file and unlock with
   your passphrase.
6. **Open a share** — drop the `.age` file someone shared from their vault and
   click **Decrypt**. Enter the password they gave you, or your passphrase if it
   was made for your key. With only a password you don't need a key of your
   own: choose **Open it without a key** on the welcome page. An archive (`Name.tar.age`) lists what it holds;
   choose what to save.

> **"This was not encrypted to you"?** That means your key wasn't among the
> file's recipients. Re-encrypt with the recipient's contact ticked, and confirm
> their saved `age1…` key matches their current public key. It is not a crypto
> error — see SECURITY.md for the full explanation.

---

## Files in this repo

| File | Purpose |
|------|---------|
| `index.html` | The application — open this. |
| `verify.sh`              | Reproducible-build verifier. |
| `manifest.webmanifest`, `icons/`, `sw.js` | Make a hosted copy installable as an app (optional). |
| `update-csp.py`          | Re-pins the CSP script hashes after an edit. |
| `tests/shared_archive_test.mjs` | Tests the shared-archive reader inside `index.html` (Node only). |
| `LICENSE`                | GPL-3.0 license text. |
| `PROVENANCE.md`          | Pinned versions and what reproducibility proves. |
| `SECURITY.md`            | Session-lock model and operational notes. |
| `README.md`              | This file. |

---

## Credits & license

VaultSend builds on the work of others:

- **age / typage** — Filippo Valsorda
- **noble cryptography** (ciphers, curves, hashes) and **scure/base** — Paul Miller
- **fflate** — Arjun Barrett
- **esbuild** — Evan Wallace

All bundled dependencies are MIT-licensed. VaultSend is released under the GPL-3.0
license; see `LICENSE`.

VaultSend is provided as-is, without warranty. It has not undergone a formal
third-party security audit. Review the code and verify the build before relying
on it for anything important.


## Acknowledgements 

Note: VaultSend's design, functionality and code review was performed by [myself](https://caelen.ca), technical implementation completed with the help of [claude](https://claude.ai)

My pubkey: age192d2u5rkgv9nvl9858fhyqsk78shhgknfjydukfgepu5c608439qnk8z62


