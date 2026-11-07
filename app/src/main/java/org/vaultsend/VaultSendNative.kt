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
     * Remove plaintext staging a killed run left in [dataDir], unless something is
     * staging there now. Called when the app starts.
     */
    @Throws(BackendException::class)
    external fun sweepStaging(dataDir: String)

    /**
     * Import an existing identity.age read from [inFd], verifying it against
     * [passphrase] before writing it into place. Returns the public key and
     * unlocks the session on success.
     */
    @Throws(BackendException::class)
    external fun importIdentity(dataDir: String, passphrase: ByteArray, inFd: Int): String

    @Throws(BackendException::class)
    external fun encryptBytes(recipients: Array<String>, armor: Boolean, input: ByteArray): ByteArray

    /**
     * Decrypt copy/paste text with the unlocked session key. Every decrypt goes
     * through the session; a file is decrypted with [sharedDecrypt].
     */
    @Throws(BackendException::class)
    external fun decryptBytesSession(input: ByteArray): ByteArray

    /** A file for [recipients], binary. */
    @Throws(BackendException::class)
    external fun encryptFd(recipients: Array<String>, inFd: Int, outFd: Int)

    /** A file for anyone with [password], as a vault's password share. */
    @Throws(BackendException::class)
    external fun encryptFdPassword(password: ByteArray, inFd: Int, outFd: Int)

    // --- Vaults (vault.rs, through ffi.rs) ------------------------------------
    //
    // One call per desktop vault-* command. `tree` is the vault's folder;
    // `secret` carries what the desktop's --pass-fd carried (the identity
    // passphrase for a "self" vault, the password for a "password" vault) or
    // null to use the unlocked session or a remembered key. Calls that return a
    // String end with any warnings, one "warning: ..." line each.

    @Throws(BackendException::class)
    external fun vaultCreate(dataDir: String, tree: VaultTree, mode: String, secret: ByteArray?)

    /** "generation N", then "D path" and "F size path" lines (paths %-escaped). */
    @Throws(BackendException::class)
    external fun vaultList(dataDir: String, tree: VaultTree, secret: ByteArray?): String

    /** "orphan ..." lines, then "ok N file(s) verified". */
    @Throws(BackendException::class)
    external fun vaultCheck(dataDir: String, tree: VaultTree, secret: ByteArray?, progress: ProgressSink?): String

    @Throws(BackendException::class)
    external fun vaultAdd(
        dataDir: String,
        tree: VaultTree,
        secret: ByteArray?,
        targets: Array<String>,
        isDir: BooleanArray,
        sizes: LongArray,
        skipped: Int,
        sources: VaultSources,
        dest: String?,
        replace: Boolean,
        progress: ProgressSink?,
    ): String

    @Throws(BackendException::class)
    external fun vaultRemove(
        dataDir: String,
        tree: VaultTree,
        secret: ByteArray?,
        entries: Array<String>,
        all: Boolean,
        progress: ProgressSink?,
    ): String

    /** Rename…: [from], a file or a folder with all it holds, becomes [to]. */
    @Throws(BackendException::class)
    external fun vaultRename(dataDir: String, tree: VaultTree, secret: ByteArray?, from: String, to: String): String

    /** A note from the editor saved as [path], in place of [previous] (null for a new one). */
    @Throws(BackendException::class)
    external fun vaultWriteText(
        dataDir: String,
        tree: VaultTree,
        secret: ByteArray?,
        path: String,
        text: ByteArray,
        previous: String?,
        replace: Boolean,
        progress: ProgressSink?,
    ): String

    /** A note's whole text, verified, if it's no more than [max] bytes. The caller wipes it. */
    @Throws(BackendException::class)
    external fun vaultReadText(dataDir: String, tree: VaultTree, secret: ByteArray?, entry: String, max: Long): ByteArray

    /** One file into [outFd], a document the caller made and removes if this fails. */
    @Throws(BackendException::class)
    external fun vaultExtractFile(
        dataDir: String,
        tree: VaultTree,
        secret: ByteArray?,
        entry: String,
        outFd: Int,
        progress: ProgressSink?,
    ): String

    /** A folder, or several entries keeping their paths, into a new folder [name] in [outTree]. */
    @Throws(BackendException::class)
    external fun vaultExtractTree(
        dataDir: String,
        tree: VaultTree,
        secret: ByteArray?,
        entries: Array<String>,
        outTree: VaultTree,
        name: String,
        progress: ProgressSink?,
    ): String

    /** A plain age file for [recipients] into [outFd]: one file as itself, anything else as a tar. */
    @Throws(BackendException::class)
    external fun vaultShare(
        dataDir: String,
        tree: VaultTree,
        secret: ByteArray?,
        entries: Array<String>,
        recipients: Array<String>,
        outFd: Int,
        progress: ProgressSink?,
    ): String

    /** A share for anyone with [password], into [outFd], as [vaultShare]. */
    @Throws(BackendException::class)
    external fun vaultSharePassword(
        dataDir: String,
        tree: VaultTree,
        secret: ByteArray?,
        entries: Array<String>,
        password: ByteArray,
        outFd: Int,
        progress: ProgressSink?,
    ): String

    /**
     * Add what a shared file holds to the vault in [tree], at its top: an archive's
     * files and folders, or one file named [singleName]. All or nothing. A null
     * [password] means the unlocked session key.
     */
    @Throws(BackendException::class)
    external fun vaultImportShared(
        dataDir: String,
        tree: VaultTree,
        secret: ByteArray?,
        password: ByteArray?,
        inFd: Int,
        singleName: String,
        progress: ProgressSink?,
    ): String

    // --- Receiving a share (shared.rs) ---------------------------------------

    /** "password" or "key": which prompt a shared file needs. */
    @Throws(BackendException::class)
    external fun sharedKind(inFd: Int): String

    /** Throws unless [password] opens the file. Only the file key is unwrapped. */
    @Throws(BackendException::class)
    external fun sharedCheckPassword(inFd: Int, password: ByteArray)

    /**
     * Decrypt a file as it is, staged and authenticated in full before a byte
     * reaches [outFd]: a share, or any age file. Null [password] for the session key.
     */
    @Throws(BackendException::class)
    external fun sharedDecrypt(dataDir: String, password: ByteArray?, inFd: Int, outFd: Int)

    /** Unpack a shared archive into a new folder [name] in [outTree]. Returns warnings. */
    @Throws(BackendException::class)
    external fun sharedExtract(
        dataDir: String,
        password: ByteArray?,
        inFd: Int,
        outTree: VaultTree,
        name: String,
        progress: ProgressSink?,
    ): String

    /** Whether a password vault's key is remembered until the app closes. Forgets all. */
    external fun vaultSetRemember(on: Boolean)

    /** Forget one vault's remembered key, by [VaultTree.key]. */
    external fun vaultForget(key: String)

    external fun vaultIsRemembered(key: String): Boolean
}

