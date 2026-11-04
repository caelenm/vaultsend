// VaultSend — Android library crate.
//
// `backend` is the pure, testable core (all cryptography, identical to desktop).
// `ffi` is the thin JNI shim the Kotlin UI calls. Keeping them apart preserves
// the desktop project's "one person can read the whole thing in an afternoon"
// auditing story: the crypto path is in backend.rs and nowhere else.
//
// Vaults (`vault`, `tar`) are the desktop vaults branch's code, with its file
// access behind a `Store`, so the same logic runs on a real folder (the unit
// tests and the host-side `vault_cli`) and on a folder the user picked through the
// Storage Access Framework (the app; see ffi.rs). The format on disk is the
// desktop's, byte for byte, so a vault moves between the two.
//
// Note on process hardening: the desktop build called PR_SET_DUMPABLE, mlockall
// and RLIMIT_CORE in a tiny, short-lived per-operation process. None of that is
// appropriate here — this code is loaded into the long-lived JVM, where e.g.
// mlockall would try to pin the entire managed heap. On Android the OS boundary
// is instead the per-app UID sandbox (plus SELinux), which already stops other
// installed apps from reading this process's memory. See README "Security model".
// What is kept is the desktop's per-buffer locking of secrets (`lock_in_ram` in
// backend.rs), changed to unlock each buffer again when it is dropped, since this
// process doesn't exit after one operation.

pub mod backend;
mod ffi;
mod tar;
pub mod vault;
#[cfg(any(test, feature = "cli"))]
pub mod vault_cli;

pub(crate) use backend::R;
