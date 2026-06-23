# VaultSend — security notes (v1.2.0)

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

Honest limits: JavaScript strings are immutable and cannot be reliably zeroed, so
a transient plaintext copy still exists during each crypto call and lingers until
garbage collection. None of this defends against script already executing in the
page (e.g. a malicious extension). It bounds *when* the key sits in memory; it
cannot make a browser tab a secure enclave. Tune the timeouts via `IDLE_LOCK_MS`
and `HIDDEN_LOCK_MS` near the top of the app script.

## Provenance / integrity

See `PROVENANCE.md`. The crypto bundle is a byte-for-byte reproducible build of
pinned upstream `age` releases; verify in-browser (Menu → Verify integrity / Run
crypto self-test) or with `bash verify.sh VaultSend_offline.html`.

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
