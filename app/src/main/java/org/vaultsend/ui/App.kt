package org.vaultsend.ui

import android.content.ActivityNotFoundException
import android.content.Intent
import android.net.Uri
import android.os.Handler
import android.os.Looper
import android.provider.DocumentsContract
import androidx.activity.compose.BackHandler
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.ArrowBack
import androidx.compose.material.icons.filled.Close
import androidx.compose.material.icons.filled.FolderOpen
import androidx.compose.material.icons.filled.MoreVert
import androidx.compose.material.icons.filled.Menu
import androidx.compose.material3.Button
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.DropdownMenu
import androidx.compose.material3.DropdownMenuItem
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.FilledTonalButton
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.ModalNavigationDrawer
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.RadioButton
import androidx.compose.material3.TextButton
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.Scaffold
import androidx.compose.material3.SnackbarHost
import androidx.compose.material3.SnackbarHostState
import androidx.compose.material3.Text
import androidx.compose.material3.TopAppBar
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateMapOf
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.foundation.clickable
import androidx.compose.ui.platform.LocalClipboardManager
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.AnnotatedString
import androidx.compose.ui.unit.dp
import androidx.core.content.FileProvider
import androidx.lifecycle.viewmodel.compose.viewModel
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.delay
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import org.vaultsend.Backend
import org.vaultsend.Contact
import org.vaultsend.KEY_MISMATCH
import org.vaultsend.NOTE_SUFFIX
import org.vaultsend.OPEN_ASK_ABOVE
import org.vaultsend.PASSWORD_NEEDED
import org.vaultsend.ProgressSink
import org.vaultsend.REMEMBER_CHOICES
import org.vaultsend.ROOT_ENTRY
import org.vaultsend.VaultEntry
import org.vaultsend.VaultRecord
import org.vaultsend.VaultTree
import org.vaultsend.archiveFolderName
import org.vaultsend.filesInSelection
import org.vaultsend.isArchiveName
import org.vaultsend.noteSuffix
import org.vaultsend.noteTitle
import org.vaultsend.renamedPath
import org.vaultsend.singleNameFromShared
import org.vaultsend.vaultNameFromShared
import org.vaultsend.parseListing
import org.vaultsend.shareFileName
import org.vaultsend.shortPath
import org.vaultsend.vaultNameFromPath
import java.io.File

// Which modal dialog is currently open (at most one at a time).
private sealed interface DialogState
private data class AskPassphrase(
    val heading: String,
    val body: String,
    val confirm: Boolean,
    // If set, run when the user taps Continue: returns null to proceed (then
    // onSubmit fires) or an error string to show inline. Used to verify the
    // passphrase (unlock / import) before the dialog closes.
    val validate: (suspend (ByteArray) -> String?)? = null,
    val fieldLabel: String = "Passphrase",
    val onCancel: (() -> Unit)? = null,
    val onSubmit: (ByteArray) -> Unit,
) : DialogState
private data class PickRecipients(
    val onPassword: (() -> Unit)? = null,
    val onConfirm: (List<String>) -> Unit,
) : DialogState
// After choosing who it's for: save the encrypted result to a file, or hand it to the share sheet.
private data class SaveOrShare(
    val title: String,
    val body: String,
    val dismissLabel: String = "Cancel",
    val onCancel: (() -> Unit)? = null,
    val onSave: () -> Unit,
    val onShare: () -> Unit,
) : DialogState
private data object AddContactDialogState : DialogState
private data class DeleteContactDialogState(val contact: Contact) : DialogState
private data class FileActionDialogState(val uri: Uri) : DialogState
private data object ShowPublicKey : DialogState
private data object AboutDialogState : DialogState
private data object CorruptKey : DialogState

// Vaults (VaultScreen.kt).
private data object AddVaultDialogState : DialogState
private data class VaultMessage(val heading: String, val body: String) : DialogState
private data class Confirm(
    val heading: String,
    val body: String,
    val action: String,
    val destructive: Boolean,
    val onCancel: (() -> Unit)? = null,
    val onConfirm: () -> Unit,
) : DialogState
private data class RemoveFromList(val vault: VaultRecord) : DialogState
private data class Share(
    val vault: VaultRecord,
    val chosen: List<String>,
    // Contacts ticked so far (pubkeys), kept across Add new contact.
    val picked: Set<String> = emptySet(),
) : DialogState
// Add contact on top of Share: back to the same Share afterwards.
private data class ShareAddContact(val share: Share) : DialogState
private data object RememberChoices : DialogState
// Rename… for one file or folder.
private data class RenameEntry(val vault: VaultRecord, val path: String, val isDir: Boolean) : DialogState

// Receiving a share (shared.rs). `password` is the share's, copied out of the prompt
// and wiped once used or abandoned; null for one made for this person's key.
private data object ExistingVaultChoice : DialogState
private class ArchiveChoice(val uri: Uri, val fileName: String, val password: ByteArray?) : DialogState
private class ImportVault(val uri: Uri, val fileName: String, val password: ByteArray?) : DialogState

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun App(vm: AppViewModel = viewModel()) {
    val scope = rememberCoroutineScope()
    val snackbar = remember { SnackbarHostState() }
    val clipboard = LocalClipboardManager.current
    val context = LocalContext.current

    var dialog by remember { mutableStateOf<DialogState?>(null) }
    val drawerState = androidx.compose.material3.rememberDrawerState(
        androidx.compose.material3.DrawerValue.Closed,
    )

    fun toast(text: String) {
        scope.launch { snackbar.showSnackbar(text) }
    }

    fun copy(text: String, note: String) {
        clipboard.setText(AnnotatedString(text))
        toast(note)
    }

    // --- "Save as" plumbing (mirrors the desktop _save_then) ------------------
    // CreateDocument returns a destination URI; we stash what to do with it.
    var saveCallback by remember { mutableStateOf<((Uri) -> Unit)?>(null) }
    var saveCancelled by remember { mutableStateOf<(() -> Unit)?>(null) }
    val createDocument = rememberLauncherForActivityResult(
        ActivityResultContracts.CreateDocument("application/octet-stream"),
    ) { uri ->
        val callback = saveCallback
        val cancelled = saveCancelled
        saveCallback = null
        saveCancelled = null
        if (uri != null && callback != null) callback(uri) else cancelled?.invoke()
    }
    /** "Save as", then `onPicked`; `onCancel` if no place was chosen. */
    fun saveThen(suggestedName: String, onCancel: () -> Unit = {}, onPicked: (Uri) -> Unit) {
        saveCallback = onPicked
        saveCancelled = onCancel
        createDocument.launch(suggestedName)
    }

    // --- Android share sheet ---------------------------------------------------
    /** A content:// URI for a file staged by Backend.newShareFile. */
    fun shareUri(file: File): Uri = FileProvider.getUriForFile(context, "${context.packageName}.open", file)

    fun launchChooser(send: Intent) {
        try {
            context.startActivity(Intent.createChooser(send, "Share"))
        } catch (e: ActivityNotFoundException) {
            toast("No app on this device can share it. Use Save File instead.")
        }
    }

    /** Hand an encrypted file staged by Backend.newShareFile to the share sheet. */
    fun shareFile(file: File) {
        val uri = shareUri(file)
        val send = Intent(Intent.ACTION_SEND)
            .setType("application/octet-stream")
            .putExtra(Intent.EXTRA_STREAM, uri)
            .addFlags(Intent.FLAG_GRANT_READ_URI_PERMISSION)
        send.clipData = android.content.ClipData.newRawUri(file.name, uri)
        launchChooser(send)
    }

    fun shareText(text: String) {
        launchChooser(Intent(Intent.ACTION_SEND).setType("text/plain").putExtra(Intent.EXTRA_TEXT, text))
    }

    // In-app "Open file…" button: routes the picked file to the encrypt/decrypt
    // chooser. (Files arriving from OUTSIDE the app are handled separately, via
    // the share sheet / "open with" intents in MainActivity.)
    val openDocument = rememberLauncherForActivityResult(
        ActivityResultContracts.OpenDocument(),
    ) { uri ->
        if (uri != null) dialog = FileActionDialogState(uri)
    }

    /** A file that is a vault's VAULT file: the desktop's vault dropped on the main page. */
    fun isVaultFile(uri: Uri): Boolean = vm.backend.displayName(uri) == "VAULT"

    // --- Decrypt helpers (run once the session is unlocked) -------------------

    fun doDecryptText(text: String) {
        scope.launch {
            try {
                vm.showDecrypted(vm.backend.decryptTextSession(text))
                toast("Decrypted.")
            } catch (e: Exception) {
                toast(e.message ?: "The operation failed.")
            } finally {
                vm.afterSecretUse()
            }
        }
    }

    fun doDecryptFile(input: Uri) {
        val name = vm.backend.displayName(input)
        val suggested = if (name.endsWith(".age")) name.dropLast(4) else "$name.decrypted"
        saveThen(suggested) { output ->
            scope.launch {
                try {
                    vm.backend.decryptFileSession(input, output)
                    toast("Decrypted and saved.")
                } catch (e: Exception) {
                    vm.backend.discardOutput(output)
                    toast(e.message ?: "The operation failed.")
                } finally {
                    vm.afterSecretUse()
                }
            }
        }
    }

    // Verify the passphrase (unlock the session) without keeping it: returns an
    // error string to show inline, or null on success.
    suspend fun tryUnlock(bytes: ByteArray): String? = try {
        vm.backend.unlock(bytes)
        null
    } catch (e: Exception) {
        e.message ?: "Incorrect passphrase."
    }

    // --- Actions (each mirrors a desktop handler) -----------------------------

    fun encryptText() {
        // Encrypted verbatim: leading/trailing whitespace is part of the message.
        val text = vm.message
        if (text.isBlank()) { toast("Type or paste a message first."); return }
        val pk = vm.myPubkey
        if (pk == null) { toast("Your key isn't ready yet."); return }
        dialog = PickRecipients { recipients ->
            dialog = null
            scope.launch {
                val encrypted = try {
                    vm.backend.encryptText(recipients, text)
                } catch (e: Exception) {
                    toast(e.message ?: "The operation failed.")
                    return@launch
                }
                vm.replaceMessage(encrypted)
                dialog = SaveOrShare(
                    "Encrypted",
                    "Encrypted to ${recipients.size} recipient(s). Save it to a file, or share it. " +
                        "It's also in the text box to copy.",
                    dismissLabel = "Close",
                    onSave = {
                        dialog = null
                        saveThen("message.age") { output ->
                            scope.launch {
                                try {
                                    withContext(Dispatchers.IO) {
                                        context.contentResolver.openOutputStream(output, "wt").use { out ->
                                            requireNotNull(out) { "Couldn't open the destination." }
                                            out.write(encrypted.toByteArray(Charsets.UTF_8))
                                        }
                                    }
                                    toast("Saved.")
                                } catch (e: Exception) {
                                    vm.backend.discardOutput(output)
                                    toast(e.message ?: "The operation failed.")
                                }
                            }
                        }
                    },
                    onShare = { dialog = null; shareText(encrypted) },
                )
            }
        }
    }

    fun decryptText() {
        val text = vm.message.trim()
        if (text.isEmpty()) { toast("Paste the encrypted text first."); return }
        if (vm.unlocked) { doDecryptText(text); return }
        dialog = AskPassphrase(
            "Unlock your key",
            "Enter your passphrase to decrypt. You'll stay unlocked until you " +
                "lock it, close the app, or leave it in the background for 2 minutes.",
            confirm = false,
            validate = { bytes -> tryUnlock(bytes) },
        ) {
            dialog = null
            vm.refreshUnlocked()
            doDecryptText(text)
        }
    }

    /** Open file… → Encrypt → Set password instead: the same Save File or Share as a vault's password share. */
    fun encryptFileWithPassword(input: Uri, base: String, password: ByteArray) {
        dialog = SaveOrShare(
            "Share with a password",
            "Save the encrypted file, or share it. Tell them the password some other way than the file.",
            onCancel = { password.fill(0) },
            onSave = {
                dialog = null
                saveThen("$base.age", onCancel = { password.fill(0) }) { output ->
                    scope.launch {
                        try {
                            vm.backend.encryptFilePassword(password, input, output)
                            toast("Encrypted. Send the saved file, and tell them the password some other way.")
                        } catch (e: Exception) {
                            vm.backend.discardOutput(output)
                            toast(e.message ?: "The operation failed.")
                        } finally {
                            password.fill(0)
                        }
                    }
                }
            },
            onShare = {
                dialog = null
                scope.launch {
                    try {
                        val staged = try {
                            withContext(Dispatchers.IO) { vm.backend.newShareFile("$base.age") }
                        } catch (e: Exception) {
                            toast(e.message ?: "The operation failed.")
                            return@launch
                        }
                        try {
                            vm.backend.encryptFilePassword(password, input, shareUri(staged))
                        } catch (e: Exception) {
                            staged.delete()
                            toast(e.message ?: "The operation failed.")
                            return@launch
                        }
                        shareFile(staged)
                    } finally {
                        password.fill(0)
                    }
                }
            },
        )
    }

    fun encryptFile(input: Uri) {
        val pk = vm.myPubkey
        if (pk == null) { toast("Your key isn't ready yet."); return }
        val base = vm.backend.displayName(input)
        lateinit var pick: PickRecipients
        pick = PickRecipients(onPassword = {
            // Share… → Set password instead, as on a vault's page.
            dialog = AskPassphrase(
                "Set password",
                "",
                confirm = true,
                fieldLabel = "Password",
                onCancel = { dialog = pick },
            ) { bytes ->
                dialog = null
                encryptFileWithPassword(input, base, bytes)
            }
        }) { recipients ->
            dialog = SaveOrShare(
                "Encrypt “$base”",
                "Encrypting to ${recipients.size} recipient(s). Save the encrypted file, or share it.",
                onSave = {
                    dialog = null
                    saveThen("$base.age") { output ->
                        scope.launch {
                            try {
                                vm.backend.encryptFile(recipients, input, output)
                                toast("Encrypted to ${recipients.size} recipient(s).")
                            } catch (e: Exception) {
                                vm.backend.discardOutput(output)
                                toast(e.message ?: "The operation failed.")
                            }
                        }
                    }
                },
                onShare = {
                    dialog = null
                    scope.launch {
                        val staged = try {
                            withContext(Dispatchers.IO) { vm.backend.newShareFile("$base.age") }
                        } catch (e: Exception) {
                            toast(e.message ?: "The operation failed.")
                            return@launch
                        }
                        try {
                            vm.backend.encryptFile(recipients, input, shareUri(staged))
                        } catch (e: Exception) {
                            staged.delete()
                            toast(e.message ?: "The operation failed.")
                            return@launch
                        }
                        shareFile(staged)
                    }
                },
            )
        }
        dialog = pick
    }

    fun createKey() {
        dialog = AskPassphrase(
            "Create your key",
            "Choose a passphrase. It encrypts your private key on this device and " +
                "can't be recovered if you forget it.",
            confirm = true,
        ) { pass ->
            dialog = null
            scope.launch {
                try {
                    vm.myPubkey = vm.backend.keygen(pass)
                    vm.refreshUnlocked()
                    vm.phase = AppPhase.BackupOffer
                    toast("Your key is ready.")
                } catch (e: Exception) {
                    toast(e.message ?: "Couldn't create the key.")
                } finally {
                    pass.fill(0)
                }
            }
        }
    }

    // Import an existing identity.age picked from the file manager.
    val importPicker = rememberLauncherForActivityResult(
        ActivityResultContracts.OpenDocument(),
    ) { uri ->
        if (uri == null) return@rememberLauncherForActivityResult
        dialog = AskPassphrase(
            "Import identity",
            "Enter the passphrase that protects this identity.age file.",
            confirm = false,
            validate = { bytes ->
                try {
                    vm.myPubkey = vm.backend.importIdentity(bytes, uri)
                    null
                } catch (e: Exception) {
                    e.message ?: "Couldn't import that file."
                }
            },
        ) {
            dialog = null
            vm.refreshUnlocked()
            vm.phase = AppPhase.Main
            toast("Identity imported.")
        }
    }

    // Import contacts from a picked contacts.json (top-right menu → Import
    // contacts). Mirrors the identity importPicker, but routes to the contact
    // store instead of the crypto core: merges into the current list and reports
    // how many new entries were added.
    val importContactsPicker = rememberLauncherForActivityResult(
        ActivityResultContracts.OpenDocument(),
    ) { uri ->
        if (uri == null) return@rememberLauncherForActivityResult
        scope.launch {
            try {
                val (added, skipped) = vm.importContacts(uri)
                val summary = when (added) {
                    0 -> "No new contacts to import."
                    1 -> "Imported 1 contact."
                    else -> "Imported $added contacts."
                }
                toast(if (skipped > 0) "$summary Skipped $skipped with an invalid public key." else summary)
            } catch (e: Exception) {
                toast(e.message ?: "Couldn't import that file.")
            }
        }
    }

    // Export contacts to a chosen destination (top-right menu → Export contacts).
    // Mirrors backupPrivateKey: pick a save location, then write contacts.json.
    fun exportContacts() {
        if (vm.contacts.isEmpty()) { toast("You have no contacts to export."); return }
        saveThen("contacts.json") { output ->
            scope.launch {
                try {
                    vm.exportContacts(output)
                    toast("Contacts exported.")
                } catch (e: Exception) {
                    toast(e.message ?: "Couldn't export contacts.")
                }
            }
        }
    }

    fun restoreKey() {
        dialog = AskPassphrase(
            "Restore your public key",
            "Your encrypted key is here but its public key cache is missing. " +
                "Enter your passphrase to rebuild it.",
            confirm = false,
        ) { pass ->
            dialog = null
            scope.launch {
                try {
                    vm.myPubkey = vm.backend.recoverPubkey(pass)
                    toast("Restored.")
                } catch (e: Exception) {
                    toast(e.message ?: "Couldn't restore the key.")
                } finally {
                    pass.fill(0)
                }
            }
        }
    }

    fun backupPrivateKey(thenGoMain: Boolean) {
        saveThen("identity.age") { output ->
            scope.launch {
                try {
                    vm.backend.exportIdentity(output)
                    toast("Private key backed up.")
                    if (thenGoMain) vm.phase = AppPhase.Main
                } catch (e: Exception) {
                    toast(e.message ?: "Couldn't back up the key.")
                }
            }
        }
    }

    // =========================================================================
    // Vaults: the desktop vaults branch's flows (frontend/app.py), one for one.
    // =========================================================================

    // One folder picker for everything that needs a folder: where a vault goes,
    // an existing vault, a folder to add, where a folder is extracted to. The
    // system picker only ever returns folders, so the desktop's check afterwards
    // ("That's a file. Choose a folder.") has nothing to catch here.
    var treeCallback by remember { mutableStateOf<((Uri) -> Unit)?>(null) }
    var treeCancelled by remember { mutableStateOf<(() -> Unit)?>(null) }
    val openTree = rememberLauncherForActivityResult(ActivityResultContracts.OpenDocumentTree()) { uri ->
        val callback = treeCallback
        val cancelled = treeCancelled
        treeCallback = null
        treeCancelled = null
        if (uri != null && callback != null) callback(uri) else cancelled?.invoke()
    }
    fun pickFolder(onCancel: () -> Unit = {}, onPicked: (Uri) -> Unit) {
        treeCallback = onPicked
        treeCancelled = onCancel
        openTree.launch(null)
    }

    // A shared file to import as a vault (Add existing vault… → A shared vault file…).
    var sharedFileCallback by remember { mutableStateOf<((Uri) -> Unit)?>(null) }
    val openSharedFile = rememberLauncherForActivityResult(ActivityResultContracts.OpenDocument()) { uri ->
        val callback = sharedFileCallback
        sharedFileCallback = null
        if (uri != null && callback != null) callback(uri)
    }

    var filesCallback by remember { mutableStateOf<((List<Uri>) -> Unit)?>(null) }
    val openFiles = rememberLauncherForActivityResult(ActivityResultContracts.OpenMultipleDocuments()) { uris ->
        val callback = filesCallback
        filesCallback = null
        if (uris.isNotEmpty() && callback != null) callback(uris)
    }

    /**
     * Keep access to a picked folder across restarts. For a new vault that's the
     * folder it's made in, not just the vault's own folder: SAF only grants what
     * the user picked, so the app can reach everything in that folder.
     */
    fun keepAccess(tree: Uri) {
        runCatching {
            context.contentResolver.takePersistableUriPermission(
                tree, Intent.FLAG_GRANT_READ_URI_PERMISSION or Intent.FLAG_GRANT_WRITE_URI_PERMISSION,
            )
        }
    }

    fun vaultError(heading: String, message: String) {
        dialog = VaultMessage(heading, message)
    }

    fun vaultFailed(vault: VaultRecord, message: String) {
        if (KEY_MISMATCH in message) {
            vaultError(
                "Your key doesn't match this vault",
                "“${vault.name}” was made for a different recipient, or with a different key, " +
                    "so yours can't unlock it.\n\nThe details: $message.",
            )
            return
        }
        vaultError("Problem with “${vault.name}”", message)
    }

    /**
     * The way into every operation: the secret for this vault, asked for or
     * recalled. A "self" vault uses the unlocked session (unlocking it first if
     * need be) and passes null; a "password" vault passes the typed password,
     * or null when its key is remembered. Wiped once `onOk` returns.
     */
    fun withVaultSecret(vault: VaultRecord, onCancel: () -> Unit = {}, onOk: suspend (ByteArray?) -> Unit) {
        if (vault.mode == "self") {
            if (vm.unlocked) {
                scope.launch { onOk(null) }
                return
            }
            dialog = AskPassphrase(
                "Unlock your key",
                "Enter your passphrase to open “${vault.name}”.",
                confirm = false,
                validate = { bytes -> tryUnlock(bytes) },
                onCancel = onCancel,
            ) {
                dialog = null
                vm.refreshUnlocked()
                scope.launch { onOk(null) }
            }
            return
        }
        if (vm.backend.isVaultRemembered(vault)) {
            scope.launch { onOk(null) }
            return
        }
        dialog = AskPassphrase(
            "Unlock vault",
            "Enter the password for “${vault.name}”.",
            confirm = false,
            fieldLabel = "Password",
            onCancel = onCancel,
        ) { bytes ->
            dialog = null
            scope.launch {
                try {
                    onOk(bytes)
                } finally {
                    bytes.fill(0)
                }
            }
        }
    }

    // Progress reports come from the core on an IO thread; show them on the main one.
    // A cancellable operation's sink is also what its Cancel button sets.
    val mainThread = remember { Handler(Looper.getMainLooper()) }
    fun progressSink(cancellable: Boolean = false): ProgressSink =
        ProgressSink { percent -> mainThread.post { vm.vaultProgress = percent } }
            .also { if (cancellable) vm.cancellable = it }

    fun cancelRunning() {
        vm.cancellable?.let {
            it.cancelled = true
            vm.vaultProgressHeading = "Cancelling…"
        }
    }

    /** Whether a known vault's folder can be reached now, by URI, for the list's subtitles. */
    val vaultFound = remember { mutableStateMapOf<String, Boolean>() }

    fun describeVault(vault: VaultRecord): String {
        if (vaultFound[vault.uri] == false) return NOT_FOUND
        val kind = if (vault.mode == "password") "Password" else "Your key"
        val where = runCatching { vm.backend.vaultTree(vault).show("") }.getOrDefault("")
        return "$kind · ${shortPath(where, "Internal storage")}"
    }

    fun acceptListing(vault: VaultRecord, generation: Long, entries: List<VaultEntry>) {
        if (generation >= vault.lastGeneration) {
            vm.acceptListing(vault, generation, entries)
            return
        }
        dialog = Confirm(
            "This vault looks older",
            "This vault is older than the last version this device saw. It may have been " +
                "restored from a backup — or rolled back by someone else.",
            action = "Open anyway",
            destructive = true,
            onCancel = { vm.lockVaultPage() },
        ) {
            dialog = null
            vm.acceptListing(vault, generation, entries)
        }
    }

    /** List a vault with this secret and show it. False if it failed (already reported). */
    suspend fun listVault(vault: VaultRecord, secret: ByteArray?): Boolean {
        val listing = try {
            parseListing(vm.backend.vaultList(vault, secret).output + "\n")
        } catch (e: Exception) {
            vaultFailed(vault, e.message ?: "The vault couldn't be read.")
            return false
        }
        if (vm.selectedVault?.uri == vault.uri) acceptListing(vault, listing.first, listing.second)
        return true
    }

    fun vaultUnlock() {
        val vault = vm.selectedVault ?: return
        withVaultSecret(vault) { secret ->
            listVault(vault, secret)
            vm.afterSecretUse()
        }
    }

    /**
     * The progress bar, toast and error for any long operation. A cancelled one
     * just says so: whatever it was writing has been removed by then.
     */
    suspend fun runOp(
        heading: String,
        note: String,
        cancellable: Boolean,
        onFail: (String) -> Unit,
        op: suspend (ProgressSink) -> Backend.VaultResult,
    ): Boolean {
        vm.vaultProgressHeading = heading
        vm.vaultProgress = -1
        val sink = progressSink(cancellable)
        return try {
            val result = op(sink)
            toast(result.warnings.firstOrNull()?.let { "$note Note: $it." } ?: note)
            true
        } catch (e: Exception) {
            if (sink.cancelled) toast("Cancelled.") else onFail(e.message ?: "The operation failed.")
            false
        } finally {
            mainThread.post {
                vm.vaultProgress = null
                if (vm.cancellable === sink) vm.cancellable = null
            }
        }
    }

    /**
     * Run one vault operation with a progress bar, then say how it went: a
     * dialog if it failed, else a toast. With `relist`, the page is listed
     * again with the same secret, so no second prompt.
     */
    suspend fun runVaultOp(
        vault: VaultRecord,
        secret: ByteArray?,
        heading: String,
        note: String,
        relist: Boolean = false,
        cancellable: Boolean = false,
        onFail: ((String) -> Unit)? = null,
        op: suspend (ProgressSink) -> Backend.VaultResult,
    ): Boolean {
        val ok = runOp(heading, note, cancellable, onFail ?: { vaultFailed(vault, it) }, op)
        if (ok && relist && vm.selectedVault?.uri == vault.uri) listVault(vault, secret)
        vm.afterSecretUse()
        return ok
    }

    /**
     * Make a vault. `then`, if given, runs once it exists, with the secret that made
     * it, before Remember-off locks anything; `onGiveUp` if it's never made.
     */
    fun beginCreate(
        name: String,
        parent: Uri,
        mode: String,
        onGiveUp: () -> Unit = {},
        then: (suspend (VaultRecord, ByteArray?) -> Unit)? = null,
    ) {
        suspend fun create(secret: ByteArray?) {
            val record = try {
                val tree = vm.backend.vaultCreate(parent, name, mode, secret)
                vm.rememberVault(VaultRecord(name, tree.documentUri.toString(), mode, 0)).also {
                    vm.sidebarMode = SidebarMode.Vaults
                    if (then == null) toast("Vault created.")
                }
            } catch (e: Exception) {
                vaultError("Couldn't create the vault", e.message ?: "The vault couldn't be created.")
                null
            }
            if (record == null) onGiveUp() else then?.invoke(record, secret)
            vm.afterSecretUse()
        }
        if (mode == "password") {
            dialog = AskPassphrase(
                "Choose a vault password",
                "Anyone with this password and a copy of the vault can open it. " +
                    "If you lose it, the files can't be recovered.",
                confirm = true,
                fieldLabel = "Password",
                onCancel = onGiveUp,
            ) { bytes ->
                dialog = null
                scope.launch {
                    try {
                        create(bytes)
                    } finally {
                        bytes.fill(0)
                    }
                }
            }
        } else if (vm.myPubkey == null) {
            toast("Your key isn't ready yet.")
            onGiveUp()
        } else {
            // Sealing the vault's key takes your private key, not just the public one.
            withVaultSecret(VaultRecord(name, "", "self", 0), onCancel = onGiveUp) { create(null) }
        }
    }

    // --- Receiving a share ---------------------------------------------------

    /** Unlock the session if need be, then `then`; `onCancel` if the prompt is cancelled. */
    fun withSession(onCancel: () -> Unit = {}, then: () -> Unit) {
        if (vm.unlocked) { then(); return }
        dialog = AskPassphrase(
            "Unlock your key",
            "Enter your passphrase to decrypt. You'll stay unlocked until you " +
                "lock it, close the app, or leave it in the background for 2 minutes.",
            confirm = false,
            validate = { bytes -> tryUnlock(bytes) },
            onCancel = onCancel,
        ) {
            dialog = null
            vm.refreshUnlocked()
            then()
        }
    }

    /**
     * The key a shared file needs: its password, checked before the prompt closes
     * (only the file key is unwrapped), or the unlocked session for one made for
     * this person. `then` gets a copy of the password, or null; the caller wipes it.
     */
    fun unlockShared(input: Uri, then: (fileName: String, password: ByteArray?) -> Unit) {
        scope.launch {
            val kind = try {
                vm.backend.sharedKind(input)
            } catch (e: Exception) {
                vaultError("Couldn't open that file", e.message ?: "It isn't a file VaultSend can decrypt.")
                return@launch
            }
            val name = vm.backend.displayName(input)
            if (kind != "password") {
                withSession { then(name, null) }
                return@launch
            }
            dialog = AskPassphrase(
                "Enter the password",
                "“$name” is protected with a password. Enter the one the person who shared it gave you.",
                confirm = false,
                fieldLabel = "Password",
                validate = { bytes -> vm.backend.sharedCheckPassword(input, bytes) },
            ) { bytes ->
                dialog = null
                // The prompt wipes its own bytes as soon as this returns.
                then(name, bytes.copyOf())
            }
        }
    }

    /** Save a shared file as it is: one file, or an archive kept as its .tar. */
    fun saveSharedAsIs(input: Uri, fileName: String, password: ByteArray?) {
        saveThen(singleNameFromShared(fileName), onCancel = { password?.fill(0) }) { output ->
            scope.launch {
                try {
                    vm.backend.sharedDecrypt(password, input, output)
                    toast("Decrypted and saved.")
                } catch (e: Exception) {
                    toast(e.message ?: "The operation failed.")
                } finally {
                    password?.fill(0)
                    vm.afterSecretUse()
                }
            }
        }
    }

    /** Unpack a shared archive into a new folder, in a folder the user picks. */
    fun extractShared(input: Uri, fileName: String, password: ByteArray?) {
        val folder = archiveFolderName(fileName)
        pickFolder(onCancel = { password?.fill(0) }) { parent ->
            scope.launch {
                try {
                    runOp("Unpacking…", "Unpacked into “$folder”.", cancellable = true, onFail = {
                        vaultError("Couldn't unpack “$fileName”", it)
                    }) { sink -> vm.backend.sharedExtract(password, input, parent, folder, sink) }
                } finally {
                    password?.fill(0)
                    vm.afterSecretUse()
                }
            }
        }
    }

    /**
     * Decrypt on the main page. A share made with a password asks for it; an
     * archive (Share's .tar.age) can be kept as one or unpacked into a folder.
     */
    fun decryptFile(input: Uri) {
        unlockShared(input) { name, password ->
            when {
                isArchiveName(name) -> dialog = ArchiveChoice(input, name, password)
                password == null -> doDecryptFile(input)
                else -> saveSharedAsIs(input, name, password)
            }
        }
    }

    /** Add existing vault → A shared vault file…: unlock it, then the Add vault form. */
    fun importSharedFile(input: Uri) {
        unlockShared(input) { name, password -> dialog = ImportVault(input, name, password) }
    }

    /** Make the vault the Import form describes, then fill it from the shared file. */
    fun createFromShared(d: ImportVault, name: String, mode: String) {
        val wipe = { d.password?.fill(0); Unit }
        pickFolder(onCancel = wipe) { parent ->
            keepAccess(parent)
            beginCreate(name, parent, mode, onGiveUp = wipe) { record, secret ->
                try {
                    runVaultOp(
                        record, secret, "Importing…", "Imported into “${record.name}”.",
                        relist = true, cancellable = true,
                        onFail = {
                            vaultError(
                                "Couldn't import into “${record.name}”",
                                "The vault was made, but nothing was added to it: $it\n\n" +
                                    "It's in your list, empty. Remove it from the list, or add files to it.",
                            )
                        },
                    ) { sink ->
                        vm.backend.vaultImportShared(record, secret, d.password, d.uri, singleNameFromShared(d.fileName), sink)
                    }
                } finally {
                    wipe()
                }
            }
        }
    }

    fun addExistingVault(tree: Uri) {
        scope.launch {
            val (vault, mode) = try {
                vm.backend.inspectVault(tree)
            } catch (e: Exception) {
                vaultError("That isn't a vault", e.message ?: "The folder you chose couldn't be read.")
                return@launch
            }
            if (mode == null) {
                vaultError("That isn't a vault", "The folder you chose has no valid VAULT file.")
                return@launch
            }
            val uri = vault.documentUri.toString()
            if (vm.vaults.any { it.uri == uri }) {
                toast("That vault is already in your list.")
                return@launch
            }
            keepAccess(tree)
            vm.rememberVault(VaultRecord(vaultNameFromPath(vault.show("")), uri, mode, 0))
        }
    }

    /**
     * A vault folder handed to the main page (the desktop's drop of a vault):
     * decrypt it, and only once it has opened, add it to the list.
     */
    fun decryptVault(tree: Uri) {
        scope.launch {
            val (folder, mode) = try {
                vm.backend.inspectVault(tree)
            } catch (e: Exception) {
                null to null
            }
            if (folder == null || mode == null) {
                vaultError(
                    "That folder isn't a vault",
                    "Only single files can be encrypted here. To protect a folder, add it to a vault.",
                )
                return@launch
            }
            val uri = folder.documentUri.toString()
            val known = vm.vaults.firstOrNull { it.uri == uri }
            val vault = known ?: VaultRecord(vaultNameFromPath(folder.show("")), uri, mode, 0)
            // Access first, since opening needs it; given back if the vault doesn't open.
            keepAccess(tree)
            fun giveBack() {
                if (known == null) {
                    runCatching {
                        context.contentResolver.releasePersistableUriPermission(
                            tree, Intent.FLAG_GRANT_READ_URI_PERMISSION or Intent.FLAG_GRANT_WRITE_URI_PERMISSION,
                        )
                    }
                }
            }
            withVaultSecret(vault, onCancel = { giveBack() }) { secret ->
                // Listed before it's added, so a vault that won't open leaves nothing behind.
                val listing = try {
                    parseListing(vm.backend.vaultList(vault, secret).output + "\n")
                } catch (e: Exception) {
                    giveBack()
                    vaultFailed(vault, e.message ?: "The vault couldn't be read.")
                    vm.afterSecretUse()
                    return@withVaultSecret
                }
                vm.rememberVault(known ?: vault)
                vm.sidebarMode = SidebarMode.Vaults
                acceptListing(known ?: vault, listing.first, listing.second)
                vm.afterSecretUse()
            }
        }
    }

    fun offerVaultDecrypt() {
        dialog = Confirm(
            "Decrypt this vault?",
            "That's a vault's VAULT file. To decrypt the vault, choose its folder next; VaultSend " +
                "asks for access to that folder only. Decrypting unlocks it and adds it to your vaults.",
            action = "Choose folder…",
            destructive = false,
        ) {
            dialog = null
            pickFolder { decryptVault(it) }
        }
    }

    /** Add picked files or folders to the open vault, where the selection says. */
    fun addToVault(files: List<Uri>, folders: List<Uri>) {
        val vault = vm.selectedVault
        val page = vm.vaultPage
        if (vault == null || page == null) {
            toast("Unlock the vault first.")
            return
        }
        val dest = page.addDestination()
        val names = files.map { vm.backend.displayName(it) } + folders.map { tree ->
            vm.backend.displayName(DocumentsContract.buildDocumentUriUsingTree(tree, DocumentsContract.getTreeDocumentId(tree)))
        }
        val targets = names.map { if (dest.isEmpty()) it else "$dest/$it" }
        val clashes = targets.filter { it in page.entries }

        fun run(replace: Boolean) {
            withVaultSecret(vault) { secret ->
                runVaultOp(vault, secret, "Adding to vault…", "Added to the vault.", relist = true, cancellable = true) { sink ->
                    vm.backend.vaultAdd(vault, secret, files, folders, dest.ifEmpty { null }, replace, sink)
                }
            }
        }

        if (clashes.isEmpty()) {
            run(false)
            return
        }
        dialog = Confirm(
            "Replace existing items?",
            "Already in this vault:\n" + clashes.take(5).joinToString("\n") + if (clashes.size > 5) "\n…" else "",
            action = "Replace",
            destructive = true,
        ) {
            dialog = null
            run(true)
        }
    }

    fun vaultExtract() {
        val vault = vm.selectedVault ?: return
        val page = vm.vaultPage ?: return
        val chosen = page.chosen()
        if (chosen.isEmpty()) return
        val suggested = when {
            chosen.size > 1 -> "${vault.name} selection"
            chosen == listOf(ROOT_ENTRY) -> vault.name
            else -> chosen[0].substringAfterLast('/')
        }
        val oneFile = chosen.size == 1 && page.entries[chosen[0]]?.isDir == false
        if (oneFile) {
            saveThen(suggested) { output ->
                withVaultSecret(vault, onCancel = { vm.backend.discardOutput(output) }) { secret ->
                    runVaultOp(vault, secret, "Extracting…", "Extracted.") { sink ->
                        vm.backend.vaultExtractFile(vault, secret, chosen[0], output, sink)
                    }
                }
            }
        } else {
            // A folder, or several: a new folder of this name, in a folder you choose.
            pickFolder { parent ->
                withVaultSecret(vault) { secret ->
                    runVaultOp(vault, secret, "Extracting…", "Extracted to “$suggested”.") { sink ->
                        vm.backend.vaultExtractTree(vault, secret, chosen, parent, suggested, sink)
                    }
                }
            }
        }
    }

    fun shareWith(share: Share, contacts: List<Contact>) {
        val vault = share.vault
        val chosen = share.chosen
        val page = vm.vaultPage ?: return
        val me = vm.myPubkey ?: return
        if (contacts.isEmpty()) return
        val suggested = shareFileName(vault.name, chosen, page.entries)
        val recipients = (contacts.map { it.pubkey } + me).distinct()
        val who = if (contacts.size <= 2) contacts.joinToString(" and ") { it.name } else "${contacts.size} people"
        dialog = SaveOrShare(
            "Share with $who",
            "Save the encrypted file, or share it.",
            onSave = {
                dialog = null
                saveThen(suggested) { output ->
                    withVaultSecret(vault, onCancel = { vm.backend.discardOutput(output) }) { secret ->
                        runVaultOp(
                            vault, secret, "Encrypting for $who…",
                            "Encrypted for $who. Send them the saved file.",
                        ) { sink -> vm.backend.vaultShare(vault, secret, chosen, recipients, output, sink) }
                    }
                }
            },
            onShare = {
                dialog = null
                val staged = runCatching { vm.backend.newShareFile(suggested) }.getOrElse { e ->
                    toast(e.message ?: "The operation failed.")
                    null
                }
                if (staged != null) withVaultSecret(vault, onCancel = { staged.delete() }) { secret ->
                    val ok = runVaultOp(vault, secret, "Encrypting for $who…", "Encrypted for $who.") { sink ->
                        vm.backend.vaultShare(vault, secret, chosen, recipients, shareUri(staged), sink)
                    }
                    if (ok) shareFile(staged) else staged.delete()
                }
            },
        )
    }

    /** Share… → Set password instead: the same file, for anyone with the password. */
    /**
     * Share… → Set password instead: the same file, for anyone with the password,
     * then the same Save File or Share as a share for contacts.
     */
    fun shareWithPassword(share: Share, password: ByteArray) {
        val vault = share.vault
        val chosen = share.chosen
        val page = vm.vaultPage
        if (page == null) { password.fill(0); return }
        val suggested = shareFileName(vault.name, chosen, page.entries)
        val heading = "Encrypting with your password…"
        dialog = SaveOrShare(
            "Share with a password",
            "Save the encrypted file, or share it. Tell them the password some other way than the file.",
            onCancel = { password.fill(0) },
            onSave = {
                dialog = null
                saveThen(suggested, onCancel = { password.fill(0) }) { output ->
                    withVaultSecret(vault, onCancel = { vm.backend.discardOutput(output); password.fill(0) }) { secret ->
                        try {
                            runVaultOp(
                                vault, secret, heading,
                                "Encrypted. Send the saved file, and tell them the password some other way.",
                            ) { sink -> vm.backend.vaultSharePassword(vault, secret, chosen, password, output, sink) }
                        } finally {
                            password.fill(0)
                        }
                    }
                }
            },
            onShare = {
                dialog = null
                val staged = runCatching { vm.backend.newShareFile(suggested) }.getOrElse { e ->
                    toast(e.message ?: "The operation failed.")
                    null
                }
                if (staged == null) {
                    password.fill(0)
                } else {
                    withVaultSecret(vault, onCancel = { staged.delete(); password.fill(0) }) { secret ->
                        val ok = try {
                            runVaultOp(vault, secret, heading, "Encrypted with your password.") { sink ->
                                vm.backend.vaultSharePassword(vault, secret, chosen, password, shareUri(staged), sink)
                            }
                        } finally {
                            password.fill(0)
                        }
                        if (ok) shareFile(staged) else staged.delete()
                    }
                }
            },
        )
    }

    fun vaultShare() {
        val vault = vm.selectedVault ?: return
        val chosen = vm.vaultPage?.chosen().orEmpty()
        if (chosen.isEmpty()) return
        if (vm.myPubkey == null) {
            toast("Your key isn't ready yet.")
            return
        }
        dialog = Share(vault, chosen)
    }

    fun vaultDelete() {
        val vault = vm.selectedVault ?: return
        val page = vm.vaultPage ?: return
        val chosen = page.chosen()
        if (chosen.isEmpty()) return
        val all = chosen == listOf(ROOT_ENTRY)
        val (heading, body) = when {
            all -> {
                val count = filesInSelection(chosen, page.entries).size
                "Delete everything in this vault?" to
                    "Everything in “${vault.name}” (${if (count == 1) "1 file" else "$count files"}, " +
                    "plus any folders) will be permanently deleted. The vault itself stays, empty. " +
                    "This can't be undone."
            }
            chosen.size > 1 ->
                "Delete ${chosen.size} items from vault?" to
                    "These, and everything in any folders among them, will be permanently deleted " +
                    "from this vault. This can't be undone.\n\n" +
                    chosen.take(5).joinToString("\n") + if (chosen.size > 5) "\n…" else ""
            else -> {
                val isDir = page.entries[chosen[0]]?.isDir == true
                "Delete from vault?" to
                    "“${chosen[0]}”${if (isDir) " and everything in it" else ""} will be permanently " +
                    "deleted from this vault. This can't be undone."
            }
        }
        dialog = Confirm(heading, body, action = "Delete", destructive = true) {
            dialog = null
            withVaultSecret(vault) { secret ->
                runVaultOp(vault, secret, "Deleting…", "Deleted.", relist = true) { sink ->
                    vm.backend.vaultRemove(vault, secret, if (all) emptyList() else chosen, all, sink)
                }
            }
        }
    }

    fun vaultVerify() {
        val vault = vm.selectedVault ?: return
        withVaultSecret(vault) { secret ->
            runVaultOp(vault, secret, "Verifying…", "Every file verified.") { sink ->
                vm.backend.vaultCheck(vault, secret, sink)
            }
        }
    }

    /** Hand a copy to the app that shows its type, read-only. */
    fun launchCopy(copy: File) {
        val uri = FileProvider.getUriForFile(context, "${context.packageName}.open", copy)
        val view = Intent(Intent.ACTION_VIEW)
            .setDataAndType(uri, context.contentResolver.getType(uri) ?: "application/octet-stream")
            .addFlags(Intent.FLAG_GRANT_READ_URI_PERMISSION)
        try {
            context.startActivity(view)
        } catch (e: ActivityNotFoundException) {
            vm.openedCopies.removeAll { it.file == copy }
            vm.backend.discardCopies(listOf(copy))
            vaultError(
                "Couldn't open that file",
                "No app on this device could open it. Use Extract… to save it somewhere you choose instead.",
            )
        }
    }

    fun openEntries(vault: VaultRecord, files: List<String>) {
        withVaultSecret(vault) { secret ->
            val several = files.size > 1
            val name = if (several) "${files.size} files" else files[0].substringAfterLast('/')
            val opened = mutableListOf<File>()
            runVaultOp(
                vault, secret, "Opening…",
                if (several) "Opening ${files.size} files in their apps." else "Opening in its app.",
            ) { sink ->
                for (entry in files) {
                    val copy = vm.backend.vaultOpenCopy(vault, secret, entry, sink)
                    vm.openedCopies.add(OpenedCopy(vault.uri, copy))
                    opened.add(copy)
                }
                Backend.VaultResult(name, emptyList())
            }
            opened.forEach(::launchCopy)
        }
    }

    fun askThenOpen(vault: VaultRecord, files: List<String>) {
        if (files.size <= OPEN_ASK_ABOVE) {
            openEntries(vault, files)
            return
        }
        dialog = Confirm("Open ${files.size} files?", "Each one starts in its own app.", "Open them all", destructive = false) {
            dialog = null
            openEntries(vault, files)
        }
    }

    /**
     * Open: the core decrypts a copy into this app's private storage, and the
     * app for its type shows it, read-only. The first use says what that means
     * and needs an acknowledgement.
     */
    fun vaultOpen() {
        val vault = vm.selectedVault ?: return
        val page = vm.vaultPage ?: return
        val files = filesInSelection(page.chosen(), page.entries)
        val selected = page.single?.let { page.entries[it] }
        if (!page.multiple && (selected == null || selected.isDir)) {
            toast("Select a file to open.")
            return
        }
        if (files.isEmpty()) {
            toast("Those are empty folders: there's no file in them to open.")
            return
        }
        if (vm.settings.openExplained) {
            askThenOpen(vault, files)
            return
        }
        dialog = Confirm(
            "Opening outside the vault",
            "VaultSend will decrypt a copy into its own private storage and open it in another " +
                "app. That app can read the copy but not change it. It may keep its own " +
                "unencrypted copies, such as recent files, previews and thumbnails, and VaultSend " +
                "can't remove those.\n\nThe copy is deleted when you lock the vault, use Lock now " +
                "or close VaultSend. Changes aren't saved back to the vault.",
            action = "I understand",
            destructive = true,
        ) {
            dialog = null
            vm.updateSettings(vm.settings.copy(openExplained = true))
            askThenOpen(vault, files)
        }
    }

    fun vaultLock() {
        val vault = vm.selectedVault ?: return
        vm.lockVault(vault)
    }

    // --- Notes and Rename… (Android only) -------------------------------------

    /** Add note…: an empty note, going where Add files… would put a file. */
    fun vaultAddNote() {
        val vault = vm.selectedVault ?: return
        val page = vm.vaultPage ?: return
        vm.noteDraft = NoteDraft(vault.uri, page.addDestination(), previous = null, suffix = NOTE_SUFFIX, title = "", body = "")
    }

    /** Edit note: the chosen .md or .txt file, decrypted into the editor. */
    fun vaultEditNote() {
        val vault = vm.selectedVault ?: return
        val path = vm.vaultPage?.chosenNote() ?: return
        withVaultSecret(vault) { secret ->
            vm.vaultProgressHeading = "Opening note…"
            vm.vaultProgress = -1
            val text = try {
                vm.backend.vaultReadText(vault, secret, path)
            } catch (e: Exception) {
                vaultFailed(vault, e.message ?: "The note couldn't be read.")
                null
            } finally {
                vm.vaultProgress = null
            }
            vm.afterSecretUse()
            // Only if the vault is still open: it may have locked meanwhile.
            if (text != null && vm.selectedVault?.uri == vault.uri && vm.vaultPage != null) {
                vm.noteDraft = NoteDraft(
                    vault.uri, path.substringBeforeLast('/', ""), previous = path,
                    suffix = noteSuffix(path) ?: NOTE_SUFFIX, title = noteTitle(path), body = text,
                )
            }
        }
    }

    /**
     * Save: the note goes into the vault as `title` + its extension, in place of the
     * file it was opened from. A different file of that name is replaced only once
     * that's confirmed.
     */
    fun saveNote() {
        val draft = vm.noteDraft ?: return
        val vault = vm.selectedVault ?: return
        val page = vm.vaultPage ?: return
        if (!draft.canSave || vm.vaultProgress != null || vault.uri != draft.vaultUri) return
        val path = if (draft.folder.isEmpty()) draft.fileName else "${draft.folder}/${draft.fileName}"
        val existing = page.entries[path]
        if (existing?.isDir == true) {
            vaultError("Can't save the note", "There's already a folder called “${draft.fileName}” here. Choose another title.")
            return
        }

        fun run(replace: Boolean) {
            val text = draft.body.toByteArray(Charsets.UTF_8)
            withVaultSecret(vault, onCancel = { text.fill(0) }) { secret ->
                val ok = try {
                    runVaultOp(vault, secret, "Saving note…", "Note saved.", relist = true) { sink ->
                        vm.backend.vaultWriteText(vault, secret, path, text, draft.previous, replace, sink)
                    }
                } finally {
                    text.fill(0)
                }
                if (ok) {
                    vm.noteDraft = null
                    vm.vaultPage = vm.vaultPage?.let { p -> if (p.multiple || path !in p.entries) p else p.select(path) }
                }
            }
        }

        if (existing == null || path == draft.previous) {
            run(false)
            return
        }
        dialog = Confirm(
            "Replace “${draft.fileName}”?",
            "There's already a file with that name here. Saving the note replaces it. This can't be undone.",
            action = "Replace",
            destructive = true,
        ) {
            dialog = null
            run(true)
        }
    }

    /** Close the editor, asking first if that would lose what was written. */
    fun closeNote() {
        val draft = vm.noteDraft ?: return
        if (vm.vaultProgress != null) return // saving: it closes when done
        if (!draft.changed) {
            vm.noteDraft = null
            return
        }
        dialog = Confirm(
            if (draft.previous == null) "Discard this note?" else "Discard your changes?",
            if (draft.previous == null) "It hasn't been saved to the vault." else "They haven't been saved to the vault.",
            action = "Discard",
            destructive = true,
        ) {
            dialog = null
            vm.noteDraft = null
        }
    }

    fun vaultRename() {
        val vault = vm.selectedVault ?: return
        val page = vm.vaultPage ?: return
        val path = page.oneChosen() ?: return
        dialog = RenameEntry(vault, path, page.entries[path]?.isDir == true)
    }

    /** Rename `from` to `to`, keeping it chosen and, for a folder, open folders open. */
    fun renameEntry(vault: VaultRecord, from: String, to: String) {
        withVaultSecret(vault) { secret ->
            val ok = runVaultOp(vault, secret, "Renaming…", "Renamed.", relist = true) { _ ->
                vm.backend.vaultRename(vault, secret, from, to)
            }
            if (ok) {
                vm.vaultPage = vm.vaultPage?.let { p ->
                    fun moved(e: String) = if (e == from || e.startsWith("$from/")) to + e.removePrefix(from) else e
                    val kept = p.copy(expanded = p.expanded.map(::moved).toSet())
                    if (kept.multiple || to !in kept.entries) kept else kept.select(to)
                }
            }
        }
    }

    val vaultActions = VaultActions(
        onUnlock = { vaultUnlock() },
        onAddFiles = {
            filesCallback = { uris -> addToVault(uris, emptyList()) }
            openFiles.launch(arrayOf("*/*"))
        },
        onAddFolder = { pickFolder { addToVault(emptyList(), listOf(it)) } },
        onAddNote = { vaultAddNote() },
        onEditNote = { vaultEditNote() },
        onRename = { vaultRename() },
        onOpen = { vaultOpen() },
        onExtract = { vaultExtract() },
        onShare = { vaultShare() },
        onDelete = { vaultDelete() },
        onLock = { vaultLock() },
        onVerify = { vaultVerify() },
        onCancel = { cancelRunning() },
    )

    fun chooseRemember(choice: String) {
        dialog = null
        if (choice == vm.settings.remember) return
        vm.setRemember(choice)
        if (choice != "off" && !vm.settings.cacheExplained) {
            vm.updateSettings(vm.settings.copy(cacheExplained = true))
            dialog = VaultMessage(
                "Remembering your passphrase",
                "While remembered, your key stays unlocked in VaultSend's memory, and so does the " +
                    "key of a password vault you've opened. Neither is ever written to disk, and " +
                    "they're held where the rest of the app can't copy them, but anyone using this " +
                    "phone while they're held can use them. Use Lock now to forget them at any time.",
            )
        }
    }

    // Lock the session once its Remember lifetime is up, and forget expired vault keys.
    LaunchedEffect(Unit) {
        while (true) {
            delay(15_000)
            vm.enforceRemember()
        }
    }

    // Whether each vault's folder can be reached, for "Not found" in the list.
    LaunchedEffect(vm.vaults.toList(), vm.sidebarMode) {
        for (v in vm.vaults.toList()) vaultFound[v.uri] = vm.backend.vaultMode(v) != null
    }

    // Back from a vault's page goes to the main page.
    BackHandler(enabled = vm.phase == AppPhase.Main && vm.selectedVault != null) { vm.selectVault(null) }
    // Back from the note editor closes it (asking first if it would lose anything). Later, so it wins.
    BackHandler(enabled = vm.phase == AppPhase.Main && vm.noteDraft != null) { closeNote() }

    // --- First-run / recovery flow on launch ----------------------------------
    LaunchedEffect(Unit) {
        try {
            when (vm.backend.status()) {
                "ready" -> {
                    vm.phase = AppPhase.Main
                    try {
                        vm.myPubkey = vm.backend.pubkey()
                    } catch (e: Exception) {
                        restoreKey()
                    }
                    vm.refreshUnlocked()
                }
                "locked" -> { vm.phase = AppPhase.Main; restoreKey() }
                "corrupt" -> { vm.phase = AppPhase.Main; dialog = CorruptKey }
                else -> vm.phase = AppPhase.Welcome // "empty" → onboarding
            }
        } catch (e: Exception) {
            vm.phase = AppPhase.Main
            toast(e.message ?: "Couldn't read your key state.")
        }
    }

    // --- Shared-in content (share sheet / "open with") ------------------------
    // Handled only once we're past onboarding, so a share that arrives on first
    // run waits until the user has a key.
    LaunchedEffect(vm.phase, vm.pendingShareUri, vm.pendingShareText) {
        if (vm.phase != AppPhase.Main) return@LaunchedEffect
        val uri = vm.pendingShareUri
        val text = vm.pendingShareText
        val many = vm.pendingShareMany
        when {
            many != null -> {
                vm.clearPendingShare()
                val vault = vm.selectedVault
                if (vault == null || vm.vaultPage == null) {
                    toast("Open and unlock a vault first to add these files to it.")
                } else {
                    dialog = Confirm(
                        "Add to “${vault.name}”?",
                        "${many.size} files will be encrypted into this vault.",
                        action = "Add",
                        destructive = false,
                    ) { dialog = null; addToVault(many, emptyList()) }
                }
            }
            uri != null && isVaultFile(uri) -> { vm.clearPendingShare(); offerVaultDecrypt() }
            uri != null -> { dialog = FileActionDialogState(uri); vm.clearPendingShare() }
            text != null -> {
                vm.replaceMessage(text)
                vm.clearPendingShare()
                toast("Loaded shared text.")
            }
        }
    }

    // --- UI: pick the screen for the current phase ----------------------------
    when (vm.phase) {
        AppPhase.Loading -> Box(
            modifier = Modifier.fillMaxSize(),
            contentAlignment = Alignment.Center,
        ) { CircularProgressIndicator() }

        AppPhase.Welcome -> WelcomeScreen(onContinue = { vm.phase = AppPhase.Intro })

        AppPhase.Intro -> IntroScreen(
            onGenerate = { createKey() },
            onImport = { importPicker.launch(arrayOf("*/*")) },
        )

        AppPhase.BackupOffer -> BackupOfferScreen(
            onBackUp = { backupPrivateKey(thenGoMain = true) },
            onSkip = { vm.phase = AppPhase.Main },
        )

        AppPhase.Main -> MainScreen(
            vm = vm,
            drawerState = drawerState,
            snackbar = snackbar,
            scope = scope,
            onEncryptText = { encryptText() },
            onDecryptText = { decryptText() },
            onOpenFile = { openDocument.launch(arrayOf("*/*")) },
            onAddContact = { dialog = AddContactDialogState },
            onCopyContact = { copy(it.pubkey, "Public key copied.") },
            onDeleteContact = { dialog = DeleteContactDialogState(it) },
            onAddVault = { dialog = AddVaultDialogState },
            onOpenVault = { vault ->
                vm.selectVault(vault)
                scope.launch { drawerState.close() }
            },
            onForgetVault = { dialog = RemoveFromList(it) },
            describeVault = { describeVault(it) },
            vaultActions = vaultActions,
            onSaveNote = { saveNote() },
            onCloseNote = { closeNote() },
            onRemember = { dialog = RememberChoices },
            onLock = { vm.lockSession(); toast("Locked.") },
            onBackupKey = { backupPrivateKey(thenGoMain = false) },
            onPublicKey = { dialog = ShowPublicKey },
            onImportContacts = { importContactsPicker.launch(arrayOf("application/json", "text/plain", "application/octet-stream")) },
            onExportContacts = { exportContacts() },
            onAbout = { dialog = AboutDialogState },
        )
    }

    // --- Dialog host (overlays every phase) -----------------------------------
    when (val d = dialog) {
        is AskPassphrase -> PassphraseDialog(
            heading = d.heading,
            body = d.body,
            confirm = d.confirm,
            onCancel = { dialog = null; d.onCancel?.invoke() },
            onSubmit = d.onSubmit,
            validate = d.validate,
            fieldLabel = d.fieldLabel,
        )
        is PickRecipients -> {
            val pk = vm.myPubkey
            if (pk == null) { dialog = null } else {
                RecipientsDialog(
                    myPubkey = pk,
                    contacts = vm.contacts,
                    onCancel = { dialog = null },
                    onConfirm = d.onConfirm,
                    onPassword = d.onPassword,
                )
            }
        }
        is SaveOrShare -> SaveOrShareDialog(
            title = d.title,
            body = d.body,
            dismissLabel = d.dismissLabel,
            onSave = d.onSave,
            onShare = d.onShare,
            onCancel = { dialog = null; d.onCancel?.invoke() },
        )
        AddContactDialogState -> AddContactDialog(
            onCancel = { dialog = null },
            onAdd = { name, key ->
                vm.addContact(name, key)
                dialog = null
                toast("Contact added.")
            },
            checkKey = { key ->
                when {
                    !vm.backend.isValidRecipient(key) ->
                        "That isn't a valid age public key. Check it was copied in full."
                    vm.contacts.any { it.pubkey == key } -> "That public key is already saved."
                    else -> null
                }
            },
        )
        is DeleteContactDialogState -> DeleteContactDialog(
            name = d.contact.name,
            onCancel = { dialog = null },
            onConfirm = {
                vm.deleteContact(d.contact)
                dialog = null
                toast("Contact deleted.")
            },
        )
        is FileActionDialogState -> FileActionDialog(
            filename = vm.backend.displayName(d.uri),
            onEncrypt = { val u = d.uri; dialog = null; encryptFile(u) },
            onDecrypt = {
                val u = d.uri
                dialog = null
                if (isVaultFile(u)) offerVaultDecrypt() else decryptFile(u)
            },
            onCancel = { dialog = null },
            // The desktop's drop onto an open vault.
            addTo = vm.selectedVault?.takeIf { vm.vaultPage != null }?.name,
            onAdd = { val u = d.uri; dialog = null; addToVault(listOf(u), emptyList()) },
        )
        ShowPublicKey -> {
            val pk = vm.myPubkey
            if (pk == null) { dialog = null; toast("Your key isn't ready yet.") } else {
                PublicKeyDialog(
                    pubkey = pk,
                    onCopy = { copy(pk, "Public key copied.") },
                    onClose = { dialog = null },
                )
            }
        }
        AboutDialogState -> AboutDialog(onClose = { dialog = null })
        CorruptKey -> CorruptKeyDialog(
            onCancel = { dialog = null },
            onCreateNew = { dialog = null; createKey() },
        )
        AddVaultDialogState -> AddVaultDialog(
            onCancel = { dialog = null },
            onExisting = { dialog = ExistingVaultChoice },
            onCreate = { name, mode ->
                dialog = null
                // Where should the vault go? Access is kept to the folder picked, and
                // everything in it (see keepAccess).
                pickFolder { parent ->
                    keepAccess(parent)
                    beginCreate(name, parent, mode)
                }
            },
        )
        ExistingVaultChoice -> ExistingVaultDialog(
            onFolder = { dialog = null; pickFolder { addExistingVault(it) } },
            onSharedFile = {
                dialog = null
                sharedFileCallback = { importSharedFile(it) }
                openSharedFile.launch(arrayOf("*/*"))
            },
            onCancel = { dialog = AddVaultDialogState },
        )
        is ArchiveChoice -> ArchiveChoiceDialog(
            fileName = d.fileName,
            onArchive = {
                dialog = null
                if (d.password == null) doDecryptFile(d.uri) else saveSharedAsIs(d.uri, d.fileName, d.password)
            },
            onFolder = { dialog = null; extractShared(d.uri, d.fileName, d.password) },
            onCancel = { dialog = null; d.password?.fill(0) },
        )
        is ImportVault -> AddVaultDialog(
            title = "Import as a vault",
            intro = "“${d.fileName}” is unlocked. Choose a name for the new vault, how it's protected " +
                "and where it goes; what the file holds is then added to it.",
            initialName = vaultNameFromShared(d.fileName),
            onExisting = null,
            onCancel = { dialog = null; d.password?.fill(0) },
            onCreate = { name, mode -> dialog = null; createFromShared(d, name, mode) },
        )
        is VaultMessage -> MessageDialog(d.heading, d.body, onClose = { dialog = null })
        is Confirm -> ConfirmDialog(
            heading = d.heading,
            body = d.body,
            action = d.action,
            destructive = d.destructive,
            onCancel = { dialog = null; d.onCancel?.invoke() },
            onConfirm = d.onConfirm,
        )
        is RemoveFromList -> {
            val location = runCatching { vm.backend.vaultTree(d.vault).show("") }.getOrDefault(d.vault.uri)
            RemoveFromListDialog(
                vault = d.vault,
                location = location,
                onCopy = { copy(location, "Location copied.") },
                onCancel = { dialog = null },
                onRemove = { dialog = null; vm.forgetVault(d.vault) },
            )
        }
        is Share -> {
            val page = vm.vaultPage
            if (page == null) { dialog = null } else {
                val chosen = d.chosen
                val what = when {
                    chosen.size > 1 -> "${chosen.size} items"
                    chosen == listOf(ROOT_ENTRY) -> d.vault.name
                    else -> chosen[0].substringAfterLast('/')
                }
                ShareDialog(
                    what = what,
                    oneFile = chosen.size == 1 && page.entries[chosen[0]]?.isDir == false,
                    contacts = vm.contacts,
                    initiallyPicked = d.picked,
                    onAddNew = { picked -> dialog = ShareAddContact(d.copy(picked = picked)) },
                    onPassword = {
                        dialog = AskPassphrase(
                            "Set password",
                            "",
                            confirm = true,
                            fieldLabel = "Password",
                            onCancel = { dialog = d },
                        ) { bytes ->
                            dialog = null
                            shareWithPassword(d, bytes)
                        }
                    },
                    onConfirm = { contacts -> dialog = null; shareWith(d, contacts) },
                    onCancel = { dialog = null },
                )
            }
        }
        is RenameEntry -> {
            val page = vm.vaultPage
            if (page == null || vm.selectedVault?.uri != d.vault.uri) { dialog = null } else {
                RenameDialog(
                    current = d.path.substringAfterLast('/'),
                    isDir = d.isDir,
                    taken = { name -> renamedPath(d.path, name) in page.entries },
                    onCancel = { dialog = null },
                    onRename = { name -> dialog = null; renameEntry(d.vault, d.path, renamedPath(d.path, name)) },
                )
            }
        }
        is ShareAddContact -> AddContactDialog(
            onCancel = { dialog = d.share },
            onAdd = { name, key ->
                vm.addContact(name, key)
                dialog = d.share.copy(picked = d.share.picked + key.trim())
                toast("Contact added.")
            },
            checkKey = { key ->
                when {
                    !vm.backend.isValidRecipient(key) ->
                        "That isn't a valid age public key. Check it was copied in full."
                    vm.contacts.any { it.pubkey == key } -> "That public key is already saved."
                    else -> null
                }
            },
        )
        RememberChoices -> AlertDialog(
            onDismissRequest = { dialog = null },
            title = { Text("Remember passphrase") },
            text = {
                Column {
                    for (choice in REMEMBER_CHOICES) {
                        Row(
                            verticalAlignment = Alignment.CenterVertically,
                            modifier = Modifier.fillMaxWidth().clickable { chooseRemember(choice.value) },
                        ) {
                            RadioButton(selected = vm.settings.remember == choice.value, onClick = { chooseRemember(choice.value) })
                            Text(choice.label)
                        }
                    }
                }
            },
            confirmButton = { TextButton(onClick = { dialog = null }) { Text("Close") } },
        )
        null -> Unit
    }
}

@OptIn(ExperimentalMaterial3Api::class)
@Composable
private fun MainScreen(
    vm: AppViewModel,
    drawerState: androidx.compose.material3.DrawerState,
    snackbar: SnackbarHostState,
    scope: kotlinx.coroutines.CoroutineScope,
    onEncryptText: () -> Unit,
    onDecryptText: () -> Unit,
    onOpenFile: () -> Unit,
    onAddContact: () -> Unit,
    onCopyContact: (Contact) -> Unit,
    onDeleteContact: (Contact) -> Unit,
    onAddVault: () -> Unit,
    onOpenVault: (VaultRecord) -> Unit,
    onForgetVault: (VaultRecord) -> Unit,
    describeVault: (VaultRecord) -> String,
    vaultActions: VaultActions,
    onSaveNote: () -> Unit,
    onCloseNote: () -> Unit,
    onRemember: () -> Unit,
    onLock: () -> Unit,
    onBackupKey: () -> Unit,
    onPublicKey: () -> Unit,
    onImportContacts: () -> Unit,
    onExportContacts: () -> Unit,
    onAbout: () -> Unit,
) {
    // The note editor takes the vault page's place, and the top bar becomes its own.
    val note = vm.noteDraft?.takeIf { it.vaultUri == vm.selectedVault?.uri && vm.vaultPage != null }
    ModalNavigationDrawer(
        drawerState = drawerState,
        drawerContent = {
            SidebarDrawer(
                mode = vm.sidebarMode,
                onMode = { vm.sidebarMode = it },
                contacts = vm.contacts,
                onAddContact = onAddContact,
                onCopyContact = onCopyContact,
                onDeleteContact = onDeleteContact,
                vaults = vm.vaults,
                selected = vm.selectedVault,
                describeVault = describeVault,
                onAddVault = onAddVault,
                onOpenVault = onOpenVault,
                onForgetVault = onForgetVault,
            )
        },
    ) {
        Scaffold(
            topBar = {
                TopAppBar(
                    title = { Text(if (note == null) "VaultSend" else if (note.previous == null) "New note" else "Edit note") },
                    navigationIcon = {
                        if (note != null) {
                            IconButton(onClick = onCloseNote) {
                                Icon(Icons.Filled.Close, contentDescription = "Close note")
                            }
                        } else if (vm.selectedVault != null) {
                            IconButton(onClick = { vm.selectVault(null) }) {
                                Icon(Icons.AutoMirrored.Filled.ArrowBack, contentDescription = "Back")
                            }
                        } else {
                            IconButton(onClick = { scope.launch { drawerState.open() } }) {
                                Icon(Icons.Filled.Menu, contentDescription = "Contacts and vaults")
                            }
                        }
                    },
                    actions = {
                        if (note != null) {
                            TextButton(onClick = onSaveNote, enabled = note.canSave && vm.vaultProgress == null) {
                                Text("Save")
                            }
                        } else {
                            OverflowMenu(
                                canLock = vm.unlocked || vm.messageIsDecrypted || vm.vaultPage != null || vm.openedCopies.isNotEmpty(),
                                hasKey = vm.myPubkey != null,
                                onRemember = onRemember,
                                onLock = onLock,
                                onBackupKey = onBackupKey,
                                onPublicKey = onPublicKey,
                                onImportContacts = onImportContacts,
                                onExportContacts = onExportContacts,
                                onAbout = onAbout,
                            )
                        }
                    },
                )
            },

        ) { padding ->
            val vault = vm.selectedVault
            if (vault != null) {
                Column(modifier = Modifier.fillMaxSize().padding(padding).padding(horizontal = 16.dp)) {
                    if (note != null) NoteEditor(
                        draft = note,
                        onChange = { vm.noteDraft = it },
                        progress = vm.vaultProgress,
                        progressHeading = vm.vaultProgressHeading,
                        modifier = Modifier.weight(1f).padding(bottom = 12.dp),
                    ) else VaultPage(
                        vault = vault,
                        page = vm.vaultPage,
                        progress = vm.vaultProgress,
                        progressHeading = vm.vaultProgressHeading,
                        onChange = { vm.vaultPage = it },
                        actions = vaultActions,
                        menuOpen = vm.vaultMenuOpen,
                        onMenuOpen = { vm.vaultMenuOpen = it },
                        canCancel = vm.cancellable != null,
                        modifier = Modifier.weight(1f),
                    )
                    SnackbarHost(hostState = snackbar)
                }
            } else Column(
                modifier = Modifier
                    .fillMaxSize()
                    .padding(padding)
                    .padding(horizontal = 16.dp),
                verticalArrangement = Arrangement.spacedBy(12.dp),
            ) {
                Text(
                    "Encrypt a message or a file",
                    style = MaterialTheme.typography.titleMedium,
                )
                Text(
                    "Type or paste text below, or open a file. Encrypting scrambles it " +
                        "for the people you choose; decrypting needs your passphrase.",
                    style = MaterialTheme.typography.bodyMedium,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                )
                OutlinedTextField(
                    value = vm.message,
                    onValueChange = { vm.editMessage(it) },
                    modifier = Modifier
                        .fillMaxWidth()
                        .weight(1f),
                    placeholder = { Text("Message or encrypted text…") },
                )
                SnackbarHost(hostState = snackbar)
                vm.vaultProgress?.let { progress ->
                    ProgressRow(progress, vm.vaultProgressHeading, if (vm.cancellable != null) vaultActions.onCancel else null)
                }
                Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                    Button(onClick = onEncryptText) { Text("Encrypt") }
                    FilledTonalButton(onClick = onDecryptText) { Text("Decrypt") }
                    Spacer(Modifier.weight(1f))
                    OutlinedButton(onClick = onOpenFile) {
                        Icon(
                            Icons.Filled.FolderOpen,
                            contentDescription = null,
                            modifier = Modifier.padding(end = 6.dp),
                        )
                        Text("Open file…")
                    }
                }
                Spacer(Modifier.padding(bottom = 4.dp))
            }
        }
    }
}

@Composable
private fun OverflowMenu(
    canLock: Boolean,
    hasKey: Boolean,
    onRemember: () -> Unit,
    onLock: () -> Unit,
    onBackupKey: () -> Unit,
    onPublicKey: () -> Unit,
    onImportContacts: () -> Unit,
    onExportContacts: () -> Unit,
    onAbout: () -> Unit,
) {
    var open by remember { mutableStateOf(false) }
    IconButton(onClick = { open = true }) {
        Icon(Icons.Filled.MoreVert, contentDescription = "More")
    }
    DropdownMenu(expanded = open, onDismissRequest = { open = false }) {
        DropdownMenuItem(
            text = { Text("My public key") },
            onClick = { open = false; onPublicKey() },
        )
        if (hasKey) {
            DropdownMenuItem(
                text = { Text("Back up private key") },
                onClick = { open = false; onBackupKey() },
            )
        }
        DropdownMenuItem(
            text = { Text("Import contacts") },
            onClick = { open = false; onImportContacts() },
        )
        DropdownMenuItem(
            text = { Text("Export contacts") },
            onClick = { open = false; onExportContacts() },
        )
        DropdownMenuItem(
            text = { Text("Remember passphrase…") },
            onClick = { open = false; onRemember() },
        )
        // Forgets the key, every remembered vault key, open vaults' listings and
        // opened copies.
        if (canLock) {
            DropdownMenuItem(
                text = { Text("Lock now") },
                onClick = { open = false; onLock() },
            )
        }
        DropdownMenuItem(
            text = { Text("About") },
            onClick = { open = false; onAbout() },
        )
    }
}
