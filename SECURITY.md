# VaultSend — security notes (v1.4.0)

## Session key lifetime (hardened in 1.2.0)

The decrypted identity (`AGE-SECRET-KEY-1…`) is the most sensitive value the app
handles. Previously it was cached as a plaintext string for the entire tab
session with no lock. It is now managed by a `keyVault` that:

- stores the identity as a `Uint8Array` (zeroed on lock) and only materialises a
  transient string for the duration of a single age call;
- **auto-locks after 5 minutes idle** (any keypress / pointer activity resets the
  timer);
- **locks 60 s after the tab is hidden**, and **wipes immediately on
  pagehide / unload**;
- offers a per-unlock **“Keep unlocked for this session”** checkbox — uncheck it
  and the key is used once and never retained;
- exposes **Menu → Lock session now**, and a status pill in the top bar
  (No key / Locked / Unlocked).

Importing or generating an identity always wipes the previously held key first,
and replacing an existing identity asks for confirmation (with an option to
export the current one). Each unlock re-derives your public key from the private
key and repairs the stored `vs_pubkey` if another page on the same origin has
changed it. New keys need a passphrase of at least 10 characters, because the
passphrase is all that protects an exported `identity.age`.

Honest limits: JavaScript strings are immutable and cannot be reliably zeroed, so
a transient plaintext copy still exists during each crypto call and lingers until
garbage collection. None of this defends against script already executing in the
page (e.g. a malicious extension). It bounds *when* the key sits in memory; it
cannot make a browser tab a secure enclave. Tune the timeouts via `IDLE_LOCK_MS`
and `HIDDEN_LOCK_MS` near the top of the app script.

## Files shared from a vault (added in 1.4.0)

The desktop and Android apps share part of a vault as a plain age file, to a
key or to a password: one file, or a tar archive of several. The web build
opens these; it keeps no vaults, and a dropped `.vsvault` is refused with a
pointer to the desktop and mobile versions.

- **Which key.** The header says in the clear whether a file is for a password
  (an `scrypt` stanza) or for people. The page reads that and nothing else
  before asking. A password file asking for more than scrypt 2^18 is refused
  from the header, before scrypt runs.
- **The password is checked once.** The library's `decryptHeader` unwraps the
  file key; a wrong password fails there and is asked for again, with nothing
  decrypted. The same file key then opens each pass over the file (verify, then
  write), through the library's `Identity` interface, so scrypt runs once. The
  library still checks the header MAC with that key every time, so it opens no
  other file. The key is zeroed when the operation ends; the password is a
  JavaScript string and is subject to the limits below. Neither is stored.
- **Authenticated before it is read.** An archive is decrypted in full into a
  Blob the browser manages (in memory, or a temporary file for a large one)
  before a byte of it is parsed, so age has authenticated all of it, the last
  chunk included. A tampered or truncated file shows nothing.
- **Read as hostile input.** The reader is a port of the apps' `tar.rs` and is
  kept to its rules and its tests (`tests/shared_archive_test.mjs`): every name
  is canonicalized lexically and refused if it could leave the folder; only
  regular files and folders are taken; counts and sizes are capped and checked
  against the real length; nothing is buffered whole. It is stricter in one
  place: folders implied by deep paths count against the entry limit too.
- **Writing.** Nothing is written until you choose. Saving all into a folder
  makes a new folder (never an existing name), re-checks every path, creates
  entries one name at a time through the File System Access API (which takes no
  paths, so there is no `..` to follow), and refuses two names that collide on
  a case-insensitive disk rather than let one replace the other. If writing
  fails or is cancelled, the new folder is removed. Unlike the apps, a page
  cannot stage the tree privately and rename it into place.
- **Shown safely.** Names are inserted as text, and control or text-direction
  characters in them are spelled out (`\u{202e}`), so a name cannot pose as
  another on screen. The saved file keeps its real name.
- **The decrypted copy** lives as long as the list is open and is dropped when
  it closes. It is not tied to the session lock: a password share never
  unlocks your key.

## Provenance / integrity

See `PROVENANCE.md`. The crypto bundle is a byte-for-byte reproducible build of
pinned upstream `age` releases; verify in-browser (Menu → Verify integrity / Run
crypto self-test) or with `bash verify.sh index.html`.

## “This was not encrypted to you” — diagnosis

This message (the phone app’s wording for age’s `no identity matched any of the
file's recipients`) is **not** a crypto bug. A cross-keypair round-trip confirms
that encrypting from one keypair to another and decrypting with the recipient’s
identity works every time. The error appears only when the decrypting key was not
actually one of the file’s recipients. Two real-world causes:

1. **The recipient wasn’t selected.** In the web app’s “Encrypt to” picker, *You*
   is always a recipient, but each contact starts **unchecked**. If you click
   Encrypt without ticking your phone contact, the file is encrypted only to your
   web identity — a different keypair than your phone’s — so the phone can’t open
   it. Fix: tick the phone contact before confirming.
2. **The saved contact key is wrong/old.** If the `age1…` stored for that contact
   isn’t your phone’s *current* public key, the phone can’t decrypt. Fix:
   re-copy the public key from the phone app and compare the full string (not the
   truncated display) against the saved contact.

Quick test: encrypt with **both** *You* and the phone contact ticked. Your phone
should open it (it matches the phone stanza) **and** the web app should open it
(it matches the self stanza). If the web app can open it but the phone can’t, the
phone key in your contacts doesn’t match the phone’s actual identity.
