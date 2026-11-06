package org.vaultsend

import android.content.Context
import android.net.Uri
import android.os.ParcelFileDescriptor
import android.provider.DocumentsContract
import android.provider.OpenableColumns
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import java.io.File
import java.nio.file.Files
import java.nio.file.attribute.PosixFilePermissions

/**
 * Thin wrapper over [VaultSendNative]. It owns the data directory (the app's
 * private internal storage, the Android equivalent of the desktop XDG data dir)
 * and runs every native call on the IO dispatcher, so a large file never blocks
 * the UI thread. The cryptography and the on-disk layout are identical to desktop.
 *
 * Contacts are deliberately NOT handled here: like the desktop frontend, they
 * live entirely on the UI side (see [ContactStore]) and never cross into the
 * crypto core. The core only ever receives recipient public keys.
 */
class Backend(private val context: Context) {

    /** identity.age and pubkey live directly under this directory. */
    val dataDir: String = context.filesDir.absolutePath

    suspend fun status(): String = withContext(Dispatchers.IO) {
        VaultSendNative.status(dataDir)
    }

    suspend fun pubkey(): String = withContext(Dispatchers.IO) {
        VaultSendNative.pubkey(dataDir)
    }

    suspend fun keygen(passphrase: ByteArray): String = withContext(Dispatchers.IO) {
        VaultSendNative.keygen(dataDir, passphrase)
    }

    suspend fun recoverPubkey(passphrase: ByteArray): String = withContext(Dispatchers.IO) {
        VaultSendNative.recoverPubkey(dataDir, passphrase)
    }

    // --- session ("unlock once") ---------------------------------------------

    /** Verify the passphrase and cache the unlocked key; returns the public key. */
    suspend fun unlock(passphrase: ByteArray): String = withContext(Dispatchers.IO) {
        VaultSendNative.unlock(dataDir, passphrase)
    }

    /** Forget the cached session key. Cheap; safe to call from any thread. */
    fun lock() = VaultSendNative.lock()

    /** Whether a session key is currently held. */
    fun isUnlocked(): Boolean = VaultSendNative.isUnlocked()

    /**
     * Import an existing identity.age chosen via the Storage Access Framework.
     * Verified against [passphrase] before anything is written; returns the
     * public key and unlocks the session on success.
     */
    suspend fun importIdentity(passphrase: ByteArray, input: Uri): String =
        withContext(Dispatchers.IO) {
            context.contentResolver.openFileDescriptor(input, "r").use { pfd ->
                requireNotNull(pfd) { "Couldn't open the selected file." }
                VaultSendNative.importIdentity(dataDir, passphrase, pfd.fd)
            }
        }

    /**
     * Copy the encrypted private key (identity.age) to a user-chosen destination,
     * for backup. The file is already passphrase-encrypted; this is a plain byte
     * copy with no key material exposed in the clear.
     */
    suspend fun exportIdentity(output: Uri) = withContext(Dispatchers.IO) {
        val src = java.io.File(dataDir, "identity.age")
        if (!src.exists()) throw BackendException("There's no identity to back up yet.")
        context.contentResolver.openOutputStream(output, "wt").use { os ->
            requireNotNull(os) { "Couldn't open the destination." }
            src.inputStream().use { it.copyTo(os) }
        }
    }

    /**
     * True if [key] is an age X25519 public key the core accepts (bech32
     * checksum, "age" prefix, 32-byte key). Checked by the core's own parser by
     * encrypting zero bytes to it, so no recipient parsing is duplicated here.
     */
    fun isValidRecipient(key: String): Boolean {
        val k = key.trim()
        if (!k.startsWith("age1")) return false
        return runCatching { VaultSendNative.encryptBytes(arrayOf(k), false, ByteArray(0)) }.isSuccess
    }

    /** Encrypt copy/paste text; result is ASCII-armored so it pastes anywhere. */
    suspend fun encryptText(recipients: List<String>, text: String): String =
        withContext(Dispatchers.IO) {
            val out = VaultSendNative.encryptBytes(
                recipients.toTypedArray(),
                /* armor = */ true,
                text.toByteArray(Charsets.UTF_8),
            )
            String(out, Charsets.UTF_8)
        }

    suspend fun decryptText(passphrase: ByteArray, text: String): String =
        withContext(Dispatchers.IO) {
            val out = VaultSendNative.decryptBytes(
                dataDir,
                passphrase,
                text.toByteArray(Charsets.UTF_8),
            )
            String(out, Charsets.UTF_8)
        }

    /** Decrypt copy/paste text with the unlocked session key (no passphrase). */
    suspend fun decryptTextSession(text: String): String =
        withContext(Dispatchers.IO) {
            val out = VaultSendNative.decryptBytesSession(text.toByteArray(Charsets.UTF_8))
            String(out, Charsets.UTF_8)
        }

    /** Encrypt a picked file to a chosen destination; binary (no armor) for files. */
    suspend fun encryptFile(recipients: List<String>, input: Uri, output: Uri) =
        withContext(Dispatchers.IO) {
            withFds(input, output) { inFd, outFd ->
                VaultSendNative.encryptFd(recipients.toTypedArray(), /* armor = */ false, inFd, outFd)
            }
        }

    /** Encrypt a picked file for anyone with [password]. */
    suspend fun encryptFilePassword(password: ByteArray, input: Uri, output: Uri) =
        withContext(Dispatchers.IO) {
            withFds(input, output) { inFd, outFd ->
                VaultSendNative.encryptFdPassword(password, inFd, outFd)
            }
        }

    suspend fun decryptFile(passphrase: ByteArray, input: Uri, output: Uri) =
        withContext(Dispatchers.IO) {
            withFds(input, output) { inFd, outFd ->
                VaultSendNative.decryptFd(dataDir, passphrase, inFd, outFd)
            }
        }

    /** Decrypt a picked file with the unlocked session key (no passphrase). */
    suspend fun decryptFileSession(input: Uri, output: Uri) =
        withContext(Dispatchers.IO) {
            withFds(input, output) { inFd, outFd ->
                VaultSendNative.decryptFdSession(dataDir, inFd, outFd)
            }
        }

    /**
     * Remove a destination created by "Save as" for an operation that failed,
     * so a failed encrypt doesn't leave a truncated .age file (and a failed
     * decrypt an empty one) that looks like a real result. Best-effort.
     */
    fun discardOutput(output: Uri) {
        runCatching { DocumentsContract.deleteDocument(context.contentResolver, output) }
    }

    /**
     * Open read/write file descriptors for the two content URIs and hand their
     * raw fds to [block]. The descriptors stay owned by these
     * ParcelFileDescriptors (closed by `use`); the Rust side only borrows them.
     */
    private inline fun <T> withFds(input: Uri, output: Uri, block: (Int, Int) -> T): T {
        val resolver = context.contentResolver
        resolver.openFileDescriptor(input, "r").use { inPfd ->
            requireNotNull(inPfd) { "Couldn't open the selected file." }
            // "wt" = write + truncate, so re-using an existing file fully replaces it.
            resolver.openFileDescriptor(output, "wt").use { outPfd ->
                requireNotNull(outPfd) { "Couldn't open the destination." }
                return block(inPfd.fd, outPfd.fd)
            }
        }
    }

    /** The human-facing file name behind a content URI (for save suggestions). */
    fun displayName(uri: Uri): String {
        context.contentResolver.query(uri, arrayOf(OpenableColumns.DISPLAY_NAME), null, null, null)
            ?.use { cursor ->
                if (cursor.moveToFirst()) {
                    val idx = cursor.getColumnIndex(OpenableColumns.DISPLAY_NAME)
                    if (idx >= 0) {
                        val name = cursor.getString(idx)
                        if (!name.isNullOrBlank()) return name
                    }
                }
            }
        return uri.lastPathSegment?.substringAfterLast('/') ?: "file"
    }

    // --- Vaults ---------------------------------------------------------------
    //
    // Thin wrappers over the vault calls in VaultSendNative, on the IO dispatcher.
    // Each returns the core's output with the warnings split off. `secret` is the
    // identity passphrase (a "self" vault), the vault password (a "password"
    // vault), or null for the unlocked session or a remembered key; the caller
    // wipes it afterwards.

    /** Output of a vault call, and what the desktop would have printed as warnings. */
    data class VaultResult(val output: String, val warnings: List<String>)

    private fun result(text: String): VaultResult {
        val (warnings, rest) = text.lines().partition { it.startsWith("warning: ") }
        return VaultResult(rest.joinToString("\n"), warnings.map { it.removePrefix("warning: ") })
    }

    fun vaultTree(record: VaultRecord): VaultTree = VaultTree.fromDocumentUri(context, Uri.parse(record.uri))

    /**
     * The vault's folder for an operation, refused with a clear message if the
     * app no longer holds access to it (the grant can be revoked in system
     * settings), rather than reporting the folder as "not a vault".
     */
    private fun openVault(record: VaultRecord): VaultTree {
        val vault = vaultTree(record)
        val granted = context.contentResolver.persistedUriPermissions.any {
            it.uri == vault.treeUri && it.isReadPermission && it.isWritePermission
        }
        if (!granted) {
            throw BackendException(
                "VaultSend no longer has access to this vault's folder. Remove it from the list, " +
                    "then add it again with Add existing vault….",
            )
        }
        return vault
    }

    /** The vault folder a user picked as itself (Add existing vault), and its mode, or null. */
    suspend fun inspectVault(tree: Uri): Pair<VaultTree, String?> = withContext(Dispatchers.IO) {
        val vault = VaultTree.fromTree(context, tree)
        vault to readVaultMode(vault.vaultFileText())
    }

    /** The mode a known vault's VAULT file names now, or null if it isn't there or isn't a vault. */
    suspend fun vaultMode(record: VaultRecord): String? = withContext(Dispatchers.IO) {
        runCatching { readVaultMode(vaultTree(record).vaultFileText()) }.getOrNull()
    }

    /**
     * Make a vault called `name` inside the folder `parent` (a tree the user
     * picked), as `name.vsvault`. An empty folder of that name is used; anything
     * else is refused by the core, as on desktop. Returns the new vault's folder.
     */
    suspend fun vaultCreate(parent: Uri, name: String, mode: String, secret: ByteArray?): VaultTree =
        withContext(Dispatchers.IO) {
            val parentTree = VaultTree.fromTree(context, parent)
            val folder = name + VAULT_SUFFIX
            if (parentTree.kind(folder) == 0) parentTree.mkdir(folder, false)
            if (parentTree.kind(folder) != 2) throw BackendException("${parentTree.show(folder)} is not a folder.")
            val vault = VaultTree(context, parent, childId(parentTree, folder))
            VaultSendNative.vaultCreate(dataDir, vault, mode, secret)
            vault
        }

    /** The document ID of `name` directly inside `tree`. */
    private fun childId(tree: VaultTree, name: String): String {
        val children = DocumentsContract.buildChildDocumentsUriUsingTree(tree.treeUri, tree.rootId)
        val columns = arrayOf(DocumentsContract.Document.COLUMN_DOCUMENT_ID, DocumentsContract.Document.COLUMN_DISPLAY_NAME)
        context.contentResolver.query(children, columns, null, null, null)?.use { c ->
            while (c.moveToNext()) if (c.getString(1) == name) return c.getString(0)
        }
        throw BackendException("${tree.show(name)} could not be found after creating it.")
    }

    suspend fun vaultList(record: VaultRecord, secret: ByteArray?): VaultResult = withContext(Dispatchers.IO) {
        result(VaultSendNative.vaultList(dataDir, openVault(record), secret))
    }

    suspend fun vaultCheck(record: VaultRecord, secret: ByteArray?, progress: ProgressSink?): VaultResult =
        withContext(Dispatchers.IO) {
            result(VaultSendNative.vaultCheck(dataDir, openVault(record), secret, progress))
        }

    /** Add picked files and folders, under `dest` (null for the top of the vault). */
    suspend fun vaultAdd(
        record: VaultRecord,
        secret: ByteArray?,
        files: List<Uri>,
        folders: List<Uri>,
        dest: String?,
        replace: Boolean,
        progress: ProgressSink?,
    ): VaultResult = withContext(Dispatchers.IO) {
        val sources = VaultSources.walk(context, files, folders)
        result(
            VaultSendNative.vaultAdd(
                dataDir, openVault(record), secret, sources.targets, sources.isDir, sources.sizes,
                sources.skipped, sources, dest, replace, progress,
            ),
        )
    }

    /** Remove `entries`, or empty the vault if `all`. */
    suspend fun vaultRemove(
        record: VaultRecord,
        secret: ByteArray?,
        entries: List<String>,
        all: Boolean,
        progress: ProgressSink?,
    ): VaultResult = withContext(Dispatchers.IO) {
        result(VaultSendNative.vaultRemove(dataDir, openVault(record), secret, entries.toTypedArray(), all, progress))
    }

    private fun refuseInside(vault: VaultTree, out: Uri) {
        if (vault.contains(out)) throw BackendException("the output path must not be inside the vault")
    }

    /** One file into `output`, a document from "Save as", which is removed if this fails. */
    suspend fun vaultExtractFile(
        record: VaultRecord,
        secret: ByteArray?,
        entry: String,
        output: Uri,
        progress: ProgressSink?,
    ): VaultResult = withContext(Dispatchers.IO) {
        val vault = openVault(record)
        try {
            refuseInside(vault, output)
            context.contentResolver.openFileDescriptor(output, "wt").use { pfd ->
                requireNotNull(pfd) { "Couldn't open the destination." }
                result(VaultSendNative.vaultExtractFile(dataDir, vault, secret, entry, pfd.fd, progress))
            }
        } catch (e: Exception) {
            discardOutput(output)
            throw e
        }
    }

    /** A folder, or several entries, into a new folder `name` inside the picked folder `outTree`. */
    suspend fun vaultExtractTree(
        record: VaultRecord,
        secret: ByteArray?,
        entries: List<String>,
        outTree: Uri,
        name: String,
        progress: ProgressSink?,
    ): VaultResult = withContext(Dispatchers.IO) {
        val vault = openVault(record)
        refuseInside(vault, outTree)
        val folder = VaultTree.fromTree(context, outTree)
        result(VaultSendNative.vaultExtractTree(dataDir, vault, secret, entries.toTypedArray(), folder, name, progress))
    }

    /** Share as a plain age file for `recipients` into `output`, removed if this fails. */
    suspend fun vaultShare(
        record: VaultRecord,
        secret: ByteArray?,
        entries: List<String>,
        recipients: List<String>,
        output: Uri,
        progress: ProgressSink?,
    ): VaultResult = withContext(Dispatchers.IO) {
        val vault = openVault(record)
        try {
            refuseInside(vault, output)
            context.contentResolver.openFileDescriptor(output, "wt").use { pfd ->
                requireNotNull(pfd) { "Couldn't open the destination." }
                result(
                    VaultSendNative.vaultShare(
                        dataDir, vault, secret, entries.toTypedArray(), recipients.toTypedArray(), pfd.fd, progress,
                    ),
                )
            }
        } catch (e: Exception) {
            discardOutput(output)
            throw e
        }
    }

    /** Share for anyone with `password`, as [vaultShare]: removed if this fails. */
    suspend fun vaultSharePassword(
        record: VaultRecord,
        secret: ByteArray?,
        entries: List<String>,
        password: ByteArray,
        output: Uri,
        progress: ProgressSink?,
    ): VaultResult = withContext(Dispatchers.IO) {
        val vault = openVault(record)
        try {
            refuseInside(vault, output)
            context.contentResolver.openFileDescriptor(output, "wt").use { pfd ->
                requireNotNull(pfd) { "Couldn't open the destination." }
                result(
                    VaultSendNative.vaultSharePassword(
                        dataDir, vault, secret, entries.toTypedArray(), password, pfd.fd, progress,
                    ),
                )
            }
        } catch (e: Exception) {
            discardOutput(output)
            throw e
        }
    }

    /**
     * Add what the shared file `input` holds to a vault, at its top. `password` is
     * the share's, or null for one made for this person (the unlocked session).
     */
    suspend fun vaultImportShared(
        record: VaultRecord,
        secret: ByteArray?,
        password: ByteArray?,
        input: Uri,
        singleName: String,
        progress: ProgressSink?,
    ): VaultResult = withContext(Dispatchers.IO) {
        val vault = openVault(record)
        context.contentResolver.openFileDescriptor(input, "r").use { pfd ->
            requireNotNull(pfd) { "Couldn't open the shared file." }
            result(VaultSendNative.vaultImportShared(dataDir, vault, secret, password, pfd.fd, singleName, progress))
        }
    }

    // --- Receiving a share ---------------------------------------------------

    private inline fun <T> readFd(input: Uri, block: (Int) -> T): T =
        context.contentResolver.openFileDescriptor(input, "r").use { pfd ->
            requireNotNull(pfd) { "Couldn't open the selected file." }
            block(pfd.fd)
        }

    /** "password" or "key": which prompt a shared file needs. */
    suspend fun sharedKind(input: Uri): String = withContext(Dispatchers.IO) {
        readFd(input) { VaultSendNative.sharedKind(it) }
    }

    /** Null if `password` opens the file, else what to say. Only the file key is unwrapped. */
    suspend fun sharedCheckPassword(input: Uri, password: ByteArray): String? = withContext(Dispatchers.IO) {
        try {
            readFd(input) { VaultSendNative.sharedCheckPassword(it, password) }
            null
        } catch (e: Exception) {
            e.message ?: "Wrong password."
        }
    }

    /** Save a shared file as it is (an archive stays one); `output` is removed if this fails. */
    suspend fun sharedDecrypt(password: ByteArray?, input: Uri, output: Uri) = withContext(Dispatchers.IO) {
        try {
            withFds(input, output) { inFd, outFd -> VaultSendNative.sharedDecrypt(dataDir, password, inFd, outFd) }
        } catch (e: Exception) {
            discardOutput(output)
            throw e
        }
    }

    /** Unpack a shared archive into a new folder `name` inside the picked folder `outTree`. */
    suspend fun sharedExtract(
        password: ByteArray?,
        input: Uri,
        outTree: Uri,
        name: String,
        progress: ProgressSink?,
    ): VaultResult = withContext(Dispatchers.IO) {
        val folder = VaultTree.fromTree(context, outTree)
        readFd(input) { result(VaultSendNative.sharedExtract(dataDir, password, it, folder, name, progress)) }
    }

    /** Where Open's copies go: see OpenCopies.kt. */
    val openRoot: File get() = File(context.cacheDir, OPEN_DIR)

    /**
     * A new, empty file named `name` for encrypted output that goes to the share
     * sheet. Only ciphertext is ever written here. Earlier staged files are
     * deleted first, so at most one share's worth is kept in the cache.
     */
    fun newShareFile(name: String): File {
        val root = File(context.cacheDir, SHARE_DIR)
        deleteTree(root)
        val folder = newCopyFolder(root)
        return File(folder, name).also { it.createNewFile() }
    }

    /**
     * Decrypt one file for Open into a new private folder in the cache, as
     * `name`, 0600. Verified in full in the core before a byte is written. Returns
     * the copy; on failure nothing is left behind.
     */
    suspend fun vaultOpenCopy(
        record: VaultRecord,
        secret: ByteArray?,
        entry: String,
        progress: ProgressSink?,
    ): File = withContext(Dispatchers.IO) {
        val folder = newCopyFolder(openRoot)
        val copy = File(folder, entry.substringAfterLast('/'))
        try {
            Files.createFile(copy.toPath(), PosixFilePermissions.asFileAttribute(PosixFilePermissions.fromString("rw-------")))
            ParcelFileDescriptor.open(copy, ParcelFileDescriptor.MODE_WRITE_ONLY).use { pfd ->
                VaultSendNative.vaultExtractFile(dataDir, openVault(record), secret, entry, pfd.fd, progress)
            }
            copy
        } catch (e: Exception) {
            deleteTree(folder)
            throw e
        }
    }

    /**
     * Remove plaintext staging a killed run left in [dataDir] (an interrupted file
     * decrypt, extract, Share or unpack). The core skips it while anything is staging.
     */
    fun sweepStaging() = VaultSendNative.sweepStaging(dataDir)

    /** Delete opened copies: these, or with none given, every one in the folder. */
    fun discardCopies(copies: Collection<File>? = null) {
        if (copies == null) {
            clearStaleCopies(openRoot)
        } else {
            copies.forEach { deleteTree(it.parentFile ?: it) }
        }
    }

    /** How long a password vault's key is remembered: 0 never, null until the app closes. */
    fun setVaultRemember(seconds: Long?) = VaultSendNative.vaultSetRemember(seconds ?: -1)

    fun forgetVault(record: VaultRecord) {
        runCatching { VaultSendNative.vaultForget(vaultTree(record).key("")) }
    }

    fun isVaultRemembered(record: VaultRecord): Boolean =
        runCatching { VaultSendNative.vaultIsRemembered(vaultTree(record).key("")) }.getOrDefault(false)

    fun sweepVaultKeys() = VaultSendNative.vaultSweep()
}

