package org.vaultsend

import android.content.Context
import android.net.Uri
import android.provider.OpenableColumns
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext

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
}
