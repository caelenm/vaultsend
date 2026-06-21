package org.vaultsend

/**
 * Raised by the native layer (and by the file plumbing) when an operation fails;
 * carries a human-readable message that the UI shows verbatim. This is the
 * Android analogue of the desktop frontend's `BackendError`.
 *
 * The Rust side raises this by its fully-qualified name via JNI ThrowNew, so its
 * package/name and (String) constructor are pinned in proguard-rules.pro.
 */
class BackendException(message: String) : Exception(message)
