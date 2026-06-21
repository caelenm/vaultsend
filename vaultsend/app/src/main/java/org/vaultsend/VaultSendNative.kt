package org.vaultsend

/**
 * The full FFI surface. Each `external` function binds to a
 * `Java_org_vaultsend_VaultSendNative_*` symbol exported by libvaultsend.so
 * (the Rust core). This is the only place the native library is touched.
 *
 * Passphrases are passed as a ByteArray (UTF-8) rather than a String so the
 * caller can wipe it after use; the Rust side also holds its copy in zeroizing
 * storage. All functions throw [BackendException] on failure.
 */
object VaultSendNative {
    init {
        System.loadLibrary("vaultsend")
    }

    @Throws(BackendException::class)
    external fun keygen(dataDir: String, passphrase: ByteArray): String

    @Throws(BackendException::class)
    external fun pubkey(dataDir: String): String

    @Throws(BackendException::class)
    external fun status(dataDir: String): String

    @Throws(BackendException::class)
    external fun recoverPubkey(dataDir: String, passphrase: ByteArray): String

    /**
     * Verify [passphrase] against the stored identity and, on success, cache the
     * unlocked key in the native library for this session (the passphrase itself
     * is never retained). Returns the public key; throws on a wrong passphrase.
     */
    @Throws(BackendException::class)
    external fun unlock(dataDir: String, passphrase: ByteArray): String

    /** Drop the cached session key (zeroized in native memory). */
    external fun lock()

    /** True while a session key is held. */
    external fun isUnlocked(): Boolean

    /**
     * Import an existing identity.age read from [inFd], verifying it against
     * [passphrase] before writing it into place. Returns the public key and
     * unlocks the session on success.
     */
    @Throws(BackendException::class)
    external fun importIdentity(dataDir: String, passphrase: ByteArray, inFd: Int): String

    @Throws(BackendException::class)
    external fun encryptBytes(recipients: Array<String>, armor: Boolean, input: ByteArray): ByteArray

    @Throws(BackendException::class)
    external fun decryptBytes(dataDir: String, passphrase: ByteArray, input: ByteArray): ByteArray

    /** Decrypt copy/paste text with the unlocked session key (no passphrase). */
    @Throws(BackendException::class)
    external fun decryptBytesSession(input: ByteArray): ByteArray

    @Throws(BackendException::class)
    external fun encryptFd(recipients: Array<String>, armor: Boolean, inFd: Int, outFd: Int)

    @Throws(BackendException::class)
    external fun decryptFd(dataDir: String, passphrase: ByteArray, inFd: Int, outFd: Int)

    /** Decrypt a file with the unlocked session key (no passphrase). */
    @Throws(BackendException::class)
    external fun decryptFdSession(dataDir: String, inFd: Int, outFd: Int)
}
