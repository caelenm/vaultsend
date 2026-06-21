package org.vaultsend.ui

import android.net.Uri
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
import androidx.compose.material3.Scaffold
import androidx.compose.material3.SnackbarHost
import androidx.compose.material3.SnackbarHostState
import androidx.compose.material3.Text
import androidx.compose.material3.TopAppBar
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalClipboardManager
import androidx.compose.ui.text.AnnotatedString
import androidx.compose.ui.unit.dp
import androidx.lifecycle.viewmodel.compose.viewModel
import kotlinx.coroutines.launch
import org.vaultsend.Contact

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
    val onSubmit: (ByteArray) -> Unit,
) : DialogState
private data class PickRecipients(val onConfirm: (List<String>) -> Unit) : DialogState
private data object AddContactDialogState : DialogState
private data class DeleteContactDialogState(val contact: Contact) : DialogState
private data class FileActionDialogState(val uri: Uri) : DialogState
private data object ShowPublicKey : DialogState
private data object AboutDialogState : DialogState
private data object CorruptKey : DialogState

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun App(vm: AppViewModel = viewModel()) {
    val scope = rememberCoroutineScope()
    val snackbar = remember { SnackbarHostState() }
    val clipboard = LocalClipboardManager.current

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
    val createDocument = rememberLauncherForActivityResult(
        ActivityResultContracts.CreateDocument("application/octet-stream"),
    ) { uri ->
        val callback = saveCallback
        saveCallback = null
        if (uri != null && callback != null) callback(uri)
    }
    fun saveThen(suggestedName: String, onPicked: (Uri) -> Unit) {
        saveCallback = onPicked
        createDocument.launch(suggestedName)
    }

    // In-app "Open file…" button: routes the picked file to the encrypt/decrypt
    // chooser. (Files arriving from OUTSIDE the app are handled separately, via
    // the share sheet / "open with" intents in MainActivity.)
    val openDocument = rememberLauncherForActivityResult(
        ActivityResultContracts.OpenDocument(),
    ) { uri ->
        if (uri != null) dialog = FileActionDialogState(uri)
    }

    // --- Decrypt helpers (run once the session is unlocked) -------------------

    fun doDecryptText(text: String) {
        scope.launch {
            try {
                vm.message = vm.backend.decryptTextSession(text)
                toast("Decrypted.")
            } catch (e: Exception) {
                toast(e.message ?: "The operation failed.")
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
                    toast(e.message ?: "The operation failed.")
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
        val text = vm.message.trim()
        if (text.isEmpty()) { toast("Type or paste a message first."); return }
        val pk = vm.myPubkey
        if (pk == null) { toast("Your key isn't ready yet."); return }
        dialog = PickRecipients { recipients ->
            dialog = null
            scope.launch {
                try {
                    vm.message = vm.backend.encryptText(recipients, text)
                    toast("Encrypted. Copy the text and share it.")
                } catch (e: Exception) {
                    toast(e.message ?: "The operation failed.")
                }
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
                "close the app or lock it.",
            confirm = false,
            validate = { bytes -> tryUnlock(bytes) },
        ) {
            dialog = null
            vm.refreshUnlocked()
            doDecryptText(text)
        }
    }

    fun encryptFile(input: Uri) {
        val pk = vm.myPubkey
        if (pk == null) { toast("Your key isn't ready yet."); return }
        val base = vm.backend.displayName(input)
        dialog = PickRecipients { recipients ->
            dialog = null
            saveThen("$base.age") { output ->
                scope.launch {
                    try {
                        vm.backend.encryptFile(recipients, input, output)
                        toast("Encrypted to ${recipients.size} recipient(s).")
                    } catch (e: Exception) {
                        toast(e.message ?: "The operation failed.")
                    }
                }
            }
        }
    }

    fun decryptFile(input: Uri) {
        if (vm.unlocked) { doDecryptFile(input); return }
        dialog = AskPassphrase(
            "Unlock your key",
            "Enter your passphrase to decrypt. You'll stay unlocked until you " +
                "close the app or lock it.",
            confirm = false,
            validate = { bytes -> tryUnlock(bytes) },
        ) {
            dialog = null
            vm.refreshUnlocked()
            doDecryptFile(input)
        }
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
        when {
            uri != null -> { dialog = FileActionDialogState(uri); vm.clearPendingShare() }
            text != null -> {
                vm.message = text
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
            onLock = { vm.lockSession(); toast("Locked.") },
            onBackupKey = { backupPrivateKey(thenGoMain = false) },
            onPublicKey = { dialog = ShowPublicKey },
            onAbout = { dialog = AboutDialogState },
        )
    }

    // --- Dialog host (overlays every phase) -----------------------------------
    when (val d = dialog) {
        is AskPassphrase -> PassphraseDialog(
            heading = d.heading,
            body = d.body,
            confirm = d.confirm,
            onCancel = { dialog = null },
            onSubmit = d.onSubmit,
            validate = d.validate,
        )
        is PickRecipients -> {
            val pk = vm.myPubkey
            if (pk == null) { dialog = null } else {
                RecipientsDialog(
                    myPubkey = pk,
                    contacts = vm.contacts,
                    onCancel = { dialog = null },
                    onConfirm = d.onConfirm,
                )
            }
        }
        AddContactDialogState -> AddContactDialog(
            onCancel = { dialog = null },
            onAdd = { name, key ->
                vm.addContact(name, key)
                dialog = null
                toast("Contact added.")
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
            onDecrypt = { val u = d.uri; dialog = null; decryptFile(u) },
            onCancel = { dialog = null },
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
    onLock: () -> Unit,
    onBackupKey: () -> Unit,
    onPublicKey: () -> Unit,
    onAbout: () -> Unit,
) {
    ModalNavigationDrawer(
        drawerState = drawerState,
        drawerContent = {
            ContactsDrawer(
                contacts = vm.contacts,
                onAdd = onAddContact,
                onCopy = onCopyContact,
                onDelete = onDeleteContact,
            )
        },
    ) {
        Scaffold(
            topBar = {
                TopAppBar(
                    title = { Text("VaultSend") },
                    navigationIcon = {
                        IconButton(onClick = { scope.launch { drawerState.open() } }) {
                            Icon(Icons.Filled.Menu, contentDescription = "Contacts")
                        }
                    },
                    actions = {
                        OverflowMenu(
                            unlocked = vm.unlocked,
                            hasKey = vm.myPubkey != null,
                            onLock = onLock,
                            onBackupKey = onBackupKey,
                            onPublicKey = onPublicKey,
                            onAbout = onAbout,
                        )
                    },
                )
            },

        ) { padding ->
            Column(
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
                    onValueChange = { vm.message = it },
                    modifier = Modifier
                        .fillMaxWidth()
                        .weight(1f),
                    placeholder = { Text("Message or encrypted text…") },
                )
                SnackbarHost(hostState = snackbar)
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
    unlocked: Boolean,
    hasKey: Boolean,
    onLock: () -> Unit,
    onBackupKey: () -> Unit,
    onPublicKey: () -> Unit,
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
        if (unlocked) {
            DropdownMenuItem(
                text = { Text("Lock") },
                onClick = { open = false; onLock() },
            )
        }
        DropdownMenuItem(
            text = { Text("About") },
            onClick = { open = false; onAbout() },
        )
    }
}
