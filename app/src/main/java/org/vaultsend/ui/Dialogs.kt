package org.vaultsend.ui

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.heightIn
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.text.selection.SelectionContainer
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Add
import androidx.compose.material.icons.filled.ContentCopy
import androidx.compose.material.icons.filled.Delete
import androidx.compose.material.icons.filled.MoreVert
import androidx.compose.material.icons.filled.Visibility
import androidx.compose.material.icons.filled.VisibilityOff
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.Checkbox
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.DropdownMenu
import androidx.compose.material3.DropdownMenuItem
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.ModalDrawerSheet
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateMapOf
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalUriHandler
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.input.KeyboardType
import androidx.compose.ui.text.input.PasswordVisualTransformation
import androidx.compose.ui.text.input.VisualTransformation
import androidx.compose.ui.unit.dp
import androidx.compose.foundation.text.KeyboardOptions
import kotlinx.coroutines.launch
import org.vaultsend.Contact
import org.vaultsend.looksLikePubkey
import org.vaultsend.shortKey

// --- Contacts drawer --------------------------------------------------------

@Composable
fun ContactsDrawer(
    contacts: List<Contact>,
    onAdd: () -> Unit,
    onCopy: (Contact) -> Unit,
    onDelete: (Contact) -> Unit,
) {
    ModalDrawerSheet {
        Column(modifier = Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(8.dp)) {
            Row(
                modifier = Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.SpaceBetween,
                verticalAlignment = Alignment.CenterVertically,
            ) {
                Text("Contacts", style = MaterialTheme.typography.titleLarge)
                IconButton(onClick = onAdd) {
                    Icon(Icons.Filled.Add, contentDescription = "Add contact")
                }
            }
            HorizontalDivider()
            if (contacts.isEmpty()) {
                Text(
                    "No contacts yet. Add someone's public key so you can encrypt to them.",
                    style = MaterialTheme.typography.bodyMedium,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                )
            } else {
                Column(
                    modifier = Modifier.verticalScroll(rememberScrollState()),
                    verticalArrangement = Arrangement.spacedBy(4.dp),
                ) {
                    for (contact in contacts) {
                        ContactRow(contact = contact, onCopy = { onCopy(contact) }, onDelete = { onDelete(contact) })
                    }
                }
            }
        }
    }
}

@Composable
private fun ContactRow(contact: Contact, onCopy: () -> Unit, onDelete: () -> Unit) {
    var menu by remember { mutableStateOf(false) }
    Row(
        modifier = Modifier.fillMaxWidth(),
        verticalAlignment = Alignment.CenterVertically,
    ) {
        Column(modifier = Modifier.weight(1f)) {
            Text(contact.name, style = MaterialTheme.typography.bodyLarge)
            Text(
                shortKey(contact.pubkey),
                style = MaterialTheme.typography.bodySmall,
                fontFamily = FontFamily.Monospace,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
            )
        }
        IconButton(onClick = { menu = true }) {
            Icon(Icons.Filled.MoreVert, contentDescription = "More")
        }
        DropdownMenu(expanded = menu, onDismissRequest = { menu = false }) {
            DropdownMenuItem(
                leadingIcon = { Icon(Icons.Filled.ContentCopy, contentDescription = null) },
                text = { Text("Copy public key") },
                onClick = { menu = false; onCopy() },
            )
            DropdownMenuItem(
                leadingIcon = { Icon(Icons.Filled.Delete, contentDescription = null) },
                text = { Text("Delete") },
                onClick = { menu = false; onDelete() },
            )
        }
    }
}

// --- Passphrase -------------------------------------------------------------

/**
 * Asks for a passphrase.
 *
 * [confirm] adds a "repeat" field (for choosing a new passphrase at keygen).
 *
 * [validate], if given, is run when the user taps Continue: it returns null to
 * proceed (then [onSubmit] is called) or an error string to show inline while
 * keeping the dialog open. This is how "check the password is correct before
 * decrypting" is surfaced — the unlock attempt happens here, and a wrong password
 * just shows an error instead of dismissing. While it runs, the button shows a
 * spinner. When [validate] is null the dialog behaves as a plain prompt and
 * [onSubmit] is called directly (the caller is then responsible for using and
 * zeroing the bytes).
 *
 * In the [validate] path the bytes are wiped by this dialog after use; the
 * proceed action ([onSubmit]) does not receive live key material there.
 */
@Composable
fun PassphraseDialog(
    heading: String,
    body: String,
    confirm: Boolean,
    onCancel: () -> Unit,
    onSubmit: (ByteArray) -> Unit,
    validate: (suspend (ByteArray) -> String?)? = null,
) {
    val scope = rememberCoroutineScope()
    var pass by remember { mutableStateOf("") }
    var repeat by remember { mutableStateOf("") }
    var visible by remember { mutableStateOf(false) }
    var error by remember { mutableStateOf<String?>(null) }
    var busy by remember { mutableStateOf(false) }

    val transformation: VisualTransformation =
        if (visible) VisualTransformation.None else PasswordVisualTransformation()

    fun submit() {
        when {
            pass.isEmpty() -> error = "Passphrase can't be empty."
            confirm && pass != repeat -> error = "Those passphrases don't match."
            validate != null -> {
                val bytes = pass.toByteArray(Charsets.UTF_8)
                busy = true
                error = null
                scope.launch {
                    val err = try {
                        validate(bytes)
                    } catch (e: Exception) {
                        e.message ?: "That didn't work."
                    }
                    if (err == null) {
                        onSubmit(bytes)
                    } else {
                        error = err
                        busy = false
                    }
                    bytes.fill(0)
                }
            }
            else -> onSubmit(pass.toByteArray(Charsets.UTF_8))
        }
    }

    AlertDialog(
        onDismissRequest = { if (!busy) onCancel() },
        title = { Text(heading) },
        text = {
            Column(verticalArrangement = Arrangement.spacedBy(8.dp)) {
                Text(body, style = MaterialTheme.typography.bodyMedium)
                OutlinedTextField(
                    value = pass,
                    onValueChange = { pass = it; error = null },
                    label = { Text("Passphrase") },
                    singleLine = true,
                    enabled = !busy,
                    visualTransformation = transformation,
                    keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Password),
                    trailingIcon = {
                        IconButton(onClick = { visible = !visible }) {
                            Icon(
                                if (visible) Icons.Filled.Visibility else Icons.Filled.VisibilityOff,
                                contentDescription = if (visible) "Hide" else "Show",
                            )
                        }
                    },
                )
                if (confirm) {
                    OutlinedTextField(
                        value = repeat,
                        onValueChange = { repeat = it; error = null },
                        label = { Text("Repeat passphrase") },
                        singleLine = true,
                        enabled = !busy,
                        visualTransformation = transformation,
                        keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Password),
                    )
                }
                error?.let { Text(it, color = MaterialTheme.colorScheme.error, style = MaterialTheme.typography.bodySmall) }
            }
        },
        confirmButton = {
            TextButton(onClick = { submit() }, enabled = !busy) {
                if (busy) {
                    CircularProgressIndicator(
                        modifier = Modifier.padding(end = 8.dp).size(16.dp),
                        strokeWidth = 2.dp,
                    )
                }
                Text("Continue")
            }
        },
        dismissButton = { TextButton(onClick = onCancel, enabled = !busy) { Text("Cancel") } },
    )
}

// --- Recipients -------------------------------------------------------------

@Composable
fun RecipientsDialog(
    myPubkey: String,
    contacts: List<Contact>,
    onCancel: () -> Unit,
    onConfirm: (List<String>) -> Unit,
) {
    val checked = remember { mutableStateMapOf<String, Boolean>() }

    AlertDialog(
        onDismissRequest = onCancel,
        title = { Text("Encrypt to…") },
        text = {
            Column(verticalArrangement = Arrangement.spacedBy(4.dp)) {
                Text(
                    "Everyone you choose will be able to decrypt it. You're always included.",
                    style = MaterialTheme.typography.bodyMedium,
                )
                Row(verticalAlignment = Alignment.CenterVertically) {
                    Checkbox(checked = true, onCheckedChange = null, enabled = false)
                    Text("You  (${shortKey(myPubkey)})")
                }
                Column(
                    modifier = Modifier
                        .heightIn(max = 260.dp)
                        .verticalScroll(rememberScrollState()),
                ) {
                    for (contact in contacts) {
                        Row(verticalAlignment = Alignment.CenterVertically) {
                            Checkbox(
                                checked = checked[contact.pubkey] ?: false,
                                onCheckedChange = { checked[contact.pubkey] = it },
                            )
                            Text("${contact.name}  (${shortKey(contact.pubkey)})")
                        }
                    }
                }
            }
        },
        confirmButton = {
            TextButton(onClick = {
                val recipients = buildList {
                    add(myPubkey)
                    for (contact in contacts) if (checked[contact.pubkey] == true) add(contact.pubkey)
                }
                onConfirm(recipients)
            }) { Text("Encrypt") }
        },
        dismissButton = { TextButton(onClick = onCancel) { Text("Cancel") } },
    )
}

// --- Add / delete contact ---------------------------------------------------

@Composable
fun AddContactDialog(onCancel: () -> Unit, onAdd: (String, String) -> Unit) {
    var name by remember { mutableStateOf("") }
    var key by remember { mutableStateOf("") }
    var error by remember { mutableStateOf<String?>(null) }

    AlertDialog(
        onDismissRequest = onCancel,
        title = { Text("Add contact") },
        text = {
            Column(verticalArrangement = Arrangement.spacedBy(8.dp)) {
                OutlinedTextField(
                    value = name,
                    onValueChange = { name = it; error = null },
                    label = { Text("Name") },
                    singleLine = true,
                )
                OutlinedTextField(
                    value = key,
                    onValueChange = { key = it; error = null },
                    label = { Text("Public key (age1…)") },
                    singleLine = true,
                )
                error?.let { Text(it, color = MaterialTheme.colorScheme.error, style = MaterialTheme.typography.bodySmall) }
            }
        },
        confirmButton = {
            TextButton(onClick = {
                when {
                    name.isBlank() -> error = "Give this contact a name."
                    !looksLikePubkey(key) -> error = "That doesn't look like an age public key."
                    else -> onAdd(name, key)
                }
            }) { Text("Add") }
        },
        dismissButton = { TextButton(onClick = onCancel) { Text("Cancel") } },
    )
}

@Composable
fun DeleteContactDialog(name: String, onCancel: () -> Unit, onConfirm: () -> Unit) {
    AlertDialog(
        onDismissRequest = onCancel,
        title = { Text("Delete contact") },
        text = { Text("Remove \"$name\" from your contacts? This only affects this device.") },
        confirmButton = {
            TextButton(onClick = onConfirm) {
                Text("Delete", color = MaterialTheme.colorScheme.error)
            }
        },
        dismissButton = { TextButton(onClick = onCancel) { Text("Cancel") } },
    )
}

// --- File action (encrypt or decrypt the opened file) -----------------------

@Composable
fun FileActionDialog(
    filename: String,
    onEncrypt: () -> Unit,
    onDecrypt: () -> Unit,
    onCancel: () -> Unit,
) {
    AlertDialog(
        onDismissRequest = onCancel,
        title = { Text("Opened: $filename") },
        text = { Text("Encrypt this file for others, or decrypt it with your passphrase?") },
        confirmButton = {
            Row(horizontalArrangement = Arrangement.spacedBy(4.dp)) {
                TextButton(onClick = onDecrypt) { Text("Decrypt") }
                TextButton(onClick = onEncrypt) { Text("Encrypt") }
            }
        },
        dismissButton = { TextButton(onClick = onCancel) { Text("Cancel") } },
    )
}

// --- My public key ----------------------------------------------------------

@Composable
fun PublicKeyDialog(pubkey: String, onCopy: () -> Unit, onClose: () -> Unit) {
    AlertDialog(
        onDismissRequest = onClose,
        title = { Text("Your public key") },
        text = {
            Column(verticalArrangement = Arrangement.spacedBy(8.dp)) {
                Text(
                    "Share this with anyone who wants to send you encrypted messages. " +
                        "It's safe to post publicly.",
                    style = MaterialTheme.typography.bodyMedium,
                )
                SelectionContainer {
                    Text(
                        pubkey,
                        fontFamily = FontFamily.Monospace,
                        style = MaterialTheme.typography.bodyMedium,
                    )
                }
            }
        },
        confirmButton = { TextButton(onClick = onCopy) { Text("Copy") } },
        dismissButton = { TextButton(onClick = onClose) { Text("Close") } },
    )
}

// --- About ------------------------------------------------------------------

@Composable
fun AboutDialog(onClose: () -> Unit) {
    val uriHandler = LocalUriHandler.current
    val source = "https://github.com/caelenm/vaultsend/tree/android"
    AlertDialog(
        onDismissRequest = onClose,
        title = { Text("VaultSend") },
        text = {
            Column(verticalArrangement = Arrangement.spacedBy(8.dp)) {
                Text("Version 0.1.0", style = MaterialTheme.typography.bodyMedium)
                Text(
                    "File and text encryption using the age format.\n" +
                        "All cryptography is performed by a small separate backend.\n" +
                        "Source code can be found here:",
                    style = MaterialTheme.typography.bodyMedium,
                )
                TextButton(
                    onClick = { uriHandler.openUri(source) },
                    contentPadding = androidx.compose.foundation.layout.PaddingValues(0.dp),
                ) { Text(source) }
            }
        },
        confirmButton = { TextButton(onClick = onClose) { Text("Close") } },
    )
}

// --- Corrupt key ------------------------------------------------------------

@Composable
fun CorruptKeyDialog(onCancel: () -> Unit, onCreateNew: () -> Unit) {
    AlertDialog(
        onDismissRequest = onCancel,
        title = { Text("Key unreadable") },
        text = {
            Text(
                "Your saved identity is empty or damaged and can't be opened. Nothing can " +
                    "be recovered from it. Create a new key? Anything encrypted to your old " +
                    "key will no longer be readable.",
            )
        },
        confirmButton = {
            TextButton(onClick = onCreateNew) {
                Text("Create new key", color = MaterialTheme.colorScheme.error)
            }
        },
        dismissButton = { TextButton(onClick = onCancel) { Text("Cancel") } },
    )
}
