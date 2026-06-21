// VaultSend — Android library crate.
//
// `backend` is the pure, testable core (all cryptography, identical to desktop).
// `ffi` is the thin JNI shim the Kotlin UI calls. Keeping them apart preserves
// the desktop project's "one person can read the whole thing in an afternoon"
// auditing story: the crypto path is in backend.rs and nowhere else.
//
// Note on process hardening: the desktop build called PR_SET_DUMPABLE, mlockall
// and RLIMIT_CORE in a tiny, short-lived per-operation process. None of that is
// appropriate here — this code is loaded into the long-lived JVM, where e.g.
// mlockall would try to pin the entire managed heap. On Android the OS boundary
// is instead the per-app UID sandbox (plus SELinux), which already stops other
// installed apps from reading this process's memory. See README "Security model".

pub mod backend;
mod ffi;
