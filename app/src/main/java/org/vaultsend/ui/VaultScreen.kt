package org.vaultsend.ui

import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.ExperimentalLayoutApi
import androidx.compose.foundation.layout.FlowRow
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.heightIn
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.text.selection.SelectionContainer
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.KeyboardArrowRight
import androidx.compose.material.icons.filled.Add
import androidx.compose.material.icons.filled.ContentCopy
import androidx.compose.material.icons.filled.KeyboardArrowDown
import androidx.compose.material.icons.filled.Lock
import androidx.compose.material.icons.filled.MoreVert
import androidx.compose.material.icons.filled.RemoveCircleOutline
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.Button
import androidx.compose.material3.Checkbox
import androidx.compose.material3.DropdownMenu
import androidx.compose.material3.DropdownMenuItem
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.FilterChip
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.LinearProgressIndicator
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.ModalDrawerSheet
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.RadioButton
import androidx.compose.material3.SegmentedButton
import androidx.compose.material3.SegmentedButtonDefaults
import androidx.compose.material3.SingleChoiceSegmentedButtonRow
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import org.vaultsend.Contact
import org.vaultsend.ROOT_ENTRY
import org.vaultsend.VaultEntry
import org.vaultsend.VaultRecord
import org.vaultsend.VaultSelection
import org.vaultsend.entryIndent
import org.vaultsend.humanSize
import org.vaultsend.isValidVaultName
import org.vaultsend.shortKey

/*
 * The vaults half of the app: the desktop vaults branch's sidebar toggle, vault
 * list, vault page and dialogs, in Compose. Wording follows the desktop's.
 */

// --- Sidebar: Contacts / Vaults ---------------------------------------------

/**
 * The side drawer, with the desktop's toggle between contacts and vaults at the
 * top. The + button adds whichever the drawer shows.
 */
@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun SidebarDrawer(
    mode: SidebarMode,
    onMode: (SidebarMode) -> Unit,
    contacts: List<Contact>,
    onAddContact: () -> Unit,
    onCopyContact: (Contact) -> Unit,
    onDeleteContact: (Contact) -> Unit,
    vaults: List<VaultRecord>,
    selected: VaultRecord?,
    describeVault: (VaultRecord) -> String,
    onAddVault: () -> Unit,
    onOpenVault: (VaultRecord) -> Unit,
    onForgetVault: (VaultRecord) -> Unit,
) {
    ModalDrawerSheet {
        Column(modifier = Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(8.dp)) {
            Row(
                modifier = Modifier.fillMaxWidth(),
                verticalAlignment = Alignment.CenterVertically,
            ) {
                SingleChoiceSegmentedButtonRow(modifier = Modifier.weight(1f)) {
                    SidebarMode.entries.forEachIndexed { i, m ->
                        SegmentedButton(
                            selected = mode == m,
                            onClick = { onMode(m) },
                            shape = SegmentedButtonDefaults.itemShape(i, SidebarMode.entries.size),
                        ) { Text(m.name) }
                    }
                }
                val adding = if (mode == SidebarMode.Contacts) "Add contact" else "Add vault"
                IconButton(onClick = if (mode == SidebarMode.Contacts) onAddContact else onAddVault) {
                    Icon(Icons.Filled.Add, contentDescription = adding)
                }
            }
            HorizontalDivider()
            when (mode) {
                SidebarMode.Contacts -> ContactsList(contacts, onCopyContact, onDeleteContact)
                SidebarMode.Vaults -> if (vaults.isEmpty()) {
                    Text("No vaults yet", style = MaterialTheme.typography.bodyLarge)
                    Text(
                        "Create an encrypted folder, or add one you already have.",
                        style = MaterialTheme.typography.bodyMedium,
                        color = MaterialTheme.colorScheme.onSurfaceVariant,
                    )
                } else {
                    Column(
                        modifier = Modifier.verticalScroll(rememberScrollState()),
                        verticalArrangement = Arrangement.spacedBy(4.dp),
                    ) {
                        for (vault in vaults) {
                            VaultRow(
                                vault = vault,
                                subtitle = describeVault(vault),
                                isSelected = vault.uri == selected?.uri,
                                onOpen = { onOpenVault(vault) },
                                onForget = { onForgetVault(vault) },
                            )
                        }
                    }
                }
            }
        }
    }
}

@Composable
private fun VaultRow(
    vault: VaultRecord,
    subtitle: String,
    isSelected: Boolean,
    onOpen: () -> Unit,
    onForget: () -> Unit,
) {
    var menu by remember { mutableStateOf(false) }
    val found = subtitle != NOT_FOUND
    Row(
        modifier = Modifier
            .fillMaxWidth()
            .clickable(enabled = found, onClick = onOpen),
        verticalAlignment = Alignment.CenterVertically,
    ) {
        Column(modifier = Modifier.weight(1f).padding(vertical = 6.dp)) {
            Text(
                vault.name,
                style = MaterialTheme.typography.bodyLarge,
                color = if (isSelected) MaterialTheme.colorScheme.primary else MaterialTheme.colorScheme.onSurface,
            )
            Text(
                subtitle,
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
                maxLines = 1,
                overflow = TextOverflow.Ellipsis,
            )
        }
        IconButton(onClick = { menu = true }) {
            Icon(Icons.Filled.MoreVert, contentDescription = "More")
        }
        DropdownMenu(expanded = menu, onDismissRequest = { menu = false }) {
            DropdownMenuItem(
                leadingIcon = { Icon(Icons.Filled.RemoveCircleOutline, contentDescription = null) },
                text = { Text("Remove from list") },
                onClick = { menu = false; onForget() },
            )
        }
    }
}

/** A vault row's subtitle when its folder can't be reached. */
const val NOT_FOUND = "Not found"

// --- The vault page ---------------------------------------------------------

/** What the page's buttons do; the flows live in App.kt with the other actions. */
class VaultActions(
    val onUnlock: () -> Unit,
    val onAddFiles: () -> Unit,
    val onAddFolder: () -> Unit,
    val onOpen: () -> Unit,
    val onExtract: () -> Unit,
    val onShare: () -> Unit,
    val onDelete: () -> Unit,
    val onLock: () -> Unit,
    val onVerify: () -> Unit,
)

@OptIn(ExperimentalLayoutApi::class)
@Composable
fun VaultPage(
    vault: VaultRecord,
    page: VaultSelection?,
    progress: Int?,
    progressHeading: String,
    onChange: (VaultSelection) -> Unit,
    actions: VaultActions,
    modifier: Modifier = Modifier,
) {
    Column(modifier = modifier, verticalArrangement = Arrangement.spacedBy(12.dp)) {
        Text(vault.name, style = MaterialTheme.typography.headlineSmall)

        Row(verticalAlignment = Alignment.CenterVertically) {
            Text(
                page?.summary() ?: "Files",
                style = MaterialTheme.typography.titleSmall,
                modifier = Modifier.weight(1f),
                maxLines = 1,
                overflow = TextOverflow.Ellipsis,
            )
        }
        val everything = page?.chosen() == listOf(ROOT_ENTRY)
        // Only one of Select all and Select multiple is lit at a time: with every row
        // ticked, Select all is.
        FlowRow(horizontalArrangement = Arrangement.spacedBy(6.dp)) {
            FilterChip(
                selected = everything,
                onClick = { page?.let { onChange(it.selectAll()) } },
                enabled = !page?.entries.isNullOrEmpty(),
                label = { Text(if (everything) "Select none" else "Select all") },
            )
            FilterChip(
                selected = page?.multiple == true && !everything,
                onClick = { page?.let { onChange(it.withMultiple(!it.multiple)) } },
                enabled = page != null,
                label = { Text("Select multiple") },
            )
            TextButton(onClick = actions.onVerify, enabled = page != null) { Text("Verify all") }
        }

        Box(modifier = Modifier.weight(1f).fillMaxWidth()) {
            if (page == null) {
                Column(
                    modifier = Modifier.align(Alignment.Center),
                    horizontalAlignment = Alignment.CenterHorizontally,
                    verticalArrangement = Arrangement.spacedBy(12.dp),
                ) {
                    Icon(Icons.Filled.Lock, contentDescription = null, modifier = Modifier.size(48.dp))
                    Text("Locked", style = MaterialTheme.typography.titleMedium)
                    Button(onClick = actions.onUnlock) { Text("Unlock") }
                }
            } else if (page.entries.isEmpty()) {
                Column(modifier = Modifier.align(Alignment.TopStart)) {
                    Text("Nothing in this vault yet", style = MaterialTheme.typography.bodyLarge)
                    Text(
                        "Add files or a folder, or share them here from another app.",
                        style = MaterialTheme.typography.bodyMedium,
                        color = MaterialTheme.colorScheme.onSurfaceVariant,
                    )
                }
            } else {
                LazyColumn(modifier = Modifier.fillMaxSize()) {
                    items(page.visible(), key = { it.path }) { entry ->
                        EntryRow(entry, page, onChange)
                    }
                }
            }
        }

        if (progress != null) {
            Column(verticalArrangement = Arrangement.spacedBy(4.dp)) {
                Text(
                    if (progress >= 0) "$progressHeading $progress%" else progressHeading,
                    style = MaterialTheme.typography.bodySmall,
                )
                // Pulses until the first report and once the work is done but not yet committed.
                if (progress in 0..99) {
                    LinearProgressIndicator(progress = { progress / 100f }, modifier = Modifier.fillMaxWidth())
                } else {
                    LinearProgressIndicator(modifier = Modifier.fillMaxWidth())
                }
            }
        }

        // Nothing selected means nothing to act on: Open, Extract…, Share… and Delete wait.
        val chosen = page?.chosen().orEmpty().isNotEmpty()
        val idle = page != null && progress == null
        FlowRow(
            horizontalArrangement = Arrangement.spacedBy(6.dp),
            verticalArrangement = Arrangement.spacedBy(4.dp),
        ) {
            OutlinedButton(onClick = actions.onAddFiles, enabled = idle) { Text("Add files…") }
            OutlinedButton(onClick = actions.onAddFolder, enabled = idle) { Text("Add folder…") }
            OutlinedButton(onClick = actions.onOpen, enabled = idle && chosen) { Text("Open") }
            OutlinedButton(onClick = actions.onExtract, enabled = idle && chosen) { Text("Extract…") }
            OutlinedButton(onClick = actions.onShare, enabled = idle && chosen) { Text("Share…") }
            OutlinedButton(onClick = actions.onDelete, enabled = idle && chosen) { Text("Delete") }
            OutlinedButton(onClick = actions.onLock, enabled = page != null) { Text("Lock") }
        }
        Spacer(Modifier.padding(bottom = 4.dp))
    }
}

@Composable
private fun EntryRow(entry: VaultEntry, page: VaultSelection, onChange: (VaultSelection) -> Unit) {
    val name = entry.path.substringAfterLast('/')
    val ticked = page.isTicked(entry.path)
    fun choose() {
        onChange(if (page.multiple) page.tick(entry.path, !ticked) else page.select(entry.path))
    }
    Row(
        modifier = Modifier
            .fillMaxWidth()
            .clickable { choose() }
            // Indented by depth, and no further than INDENT_LEVELS: the list can't scroll sideways.
            .padding(start = entryIndent(entry.path).dp),
        verticalAlignment = Alignment.CenterVertically,
    ) {
        if (page.multiple) {
            Checkbox(checked = ticked, onCheckedChange = { choose() })
        } else {
            RadioButton(selected = ticked, onClick = { choose() })
        }
        Column(modifier = Modifier.weight(1f)) {
            // Shown exactly as named: a name from someone else's vault is just text.
            Text(if (entry.isDir) "$name/" else name, maxLines = 2, overflow = TextOverflow.Ellipsis)
            if (!entry.isDir) {
                Text(
                    humanSize(entry.size),
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                )
            }
        }
        if (entry.isDir) {
            val open = entry.path in page.expanded
            IconButton(onClick = { onChange(page.toggleExpanded(entry.path)) }) {
                Icon(
                    if (open) Icons.Filled.KeyboardArrowDown else Icons.AutoMirrored.Filled.KeyboardArrowRight,
                    contentDescription = if (open) "Close folder" else "Open folder",
                )
            }
        }
    }
}

// --- Dialogs ----------------------------------------------------------------

/** The desktop's Adw.AlertDialog with Cancel and one action. */
@Composable
fun ConfirmDialog(
    heading: String,
    body: String,
    action: String,
    destructive: Boolean,
    onCancel: () -> Unit,
    onConfirm: () -> Unit,
    extra: (@Composable () -> Unit)? = null,
) {
    AlertDialog(
        onDismissRequest = onCancel,
        title = { Text(heading) },
        text = {
            Column(
                modifier = Modifier.verticalScroll(rememberScrollState()),
                verticalArrangement = Arrangement.spacedBy(8.dp),
            ) {
                Text(body, style = MaterialTheme.typography.bodyMedium)
                extra?.invoke()
            }
        },
        confirmButton = {
            TextButton(onClick = onConfirm) {
                Text(action, color = if (destructive) MaterialTheme.colorScheme.error else MaterialTheme.colorScheme.primary)
            }
        },
        dismissButton = { TextButton(onClick = onCancel) { Text("Cancel") } },
    )
}

/** A vault error: a dialog, not a toast, because a failed integrity check mustn't fade away. */
@Composable
fun MessageDialog(heading: String, body: String, onClose: () -> Unit) {
    AlertDialog(
        onDismissRequest = onClose,
        title = { Text(heading) },
        text = {
            Text(
                body,
                style = MaterialTheme.typography.bodyMedium,
                modifier = Modifier.verticalScroll(rememberScrollState()),
            )
        },
        confirmButton = { TextButton(onClick = onClose) { Text("Close") } },
    )
}

/**
 * Add vault: a name, how it's protected and where it goes. Create stays off until
 * the name will do, and a name with "/" turns the field red, as on desktop.
 */
@Composable
fun AddVaultDialog(
    onCancel: () -> Unit,
    onExisting: () -> Unit,
    onCreate: (name: String, mode: String) -> Unit,
) {
    var name by remember { mutableStateOf("") }
    var password by remember { mutableStateOf(false) }
    val trimmed = name.trim()
    val ok = isValidVaultName(trimmed)

    AlertDialog(
        onDismissRequest = onCancel,
        title = { Text("Add vault") },
        text = {
            Column(verticalArrangement = Arrangement.spacedBy(6.dp)) {
                Text("A vault is an encrypted folder of files.", style = MaterialTheme.typography.bodyMedium)
                OutlinedTextField(
                    value = name,
                    onValueChange = { name = it },
                    label = { Text("Vault name") },
                    singleLine = true,
                    isError = '/' in name,
                    supportingText = { if ('/' in name) Text("A name can't contain “/”.") },
                )
                Text("Protection", style = MaterialTheme.typography.titleSmall)
                Row(
                    verticalAlignment = Alignment.CenterVertically,
                    modifier = Modifier.clickable { password = false },
                ) {
                    RadioButton(selected = !password, onClick = { password = false })
                    Text("Encrypt with my key (simplest, secure)")
                }
                Row(
                    verticalAlignment = Alignment.CenterVertically,
                    modifier = Modifier.clickable { password = true },
                ) {
                    RadioButton(selected = password, onClick = { password = true })
                    Text("Use a password (shareable)")
                }
                Text(
                    "Next, choose the folder it goes in. It stays there, where your file manager " +
                        "shows it, and VaultSend asks for access to that folder only.",
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                )
                TextButton(
                    onClick = onExisting,
                    contentPadding = androidx.compose.foundation.layout.PaddingValues(0.dp),
                ) { Text("Add existing vault…") }
            }
        },
        confirmButton = {
            TextButton(onClick = { onCreate(trimmed, if (password) "password" else "self") }, enabled = ok) {
                Text("Create")
            }
        },
        dismissButton = { TextButton(onClick = onCancel) { Text("Cancel") } },
    )
}

/** "Remove from list?", with the location selectable and a copy button. */
@Composable
fun RemoveFromListDialog(vault: VaultRecord, location: String, onCopy: () -> Unit, onCancel: () -> Unit, onRemove: () -> Unit) {
    ConfirmDialog(
        heading = "Remove from list?",
        body = "This only makes VaultSend forget “${vault.name}”. It does not delete the " +
            "vault or any file in it, which stay here:",
        action = "Remove from list",
        destructive = true,
        onCancel = onCancel,
        onConfirm = onRemove,
        extra = {
            Row(verticalAlignment = Alignment.CenterVertically) {
                SelectionContainer(modifier = Modifier.weight(1f)) {
                    Text(location, fontFamily = FontFamily.Monospace, style = MaterialTheme.typography.bodySmall)
                }
                IconButton(onClick = onCopy) { Icon(Icons.Filled.ContentCopy, contentDescription = "Copy location") }
            }
        },
    )
}

/**
 * Share…: who it's for. Picking a contact goes straight on to Save. "Add new
 * contact" opens Add contact over this, so the selection and place are kept.
 */
@Composable
fun ShareDialog(
    what: String,
    oneFile: Boolean,
    contacts: List<Contact>,
    onAddNew: () -> Unit,
    onPick: (Contact) -> Unit,
    onCancel: () -> Unit,
) {
    AlertDialog(
        onDismissRequest = onCancel,
        title = { Text("Share “$what”") },
        text = {
            Column(verticalArrangement = Arrangement.spacedBy(8.dp)) {
                Text(
                    "Encrypted so only you and the person you choose can read it. They open it by " +
                        "decrypting it in VaultSend" +
                        if (oneFile) ", which gives them this file." else ", which gives them a .tar archive of it all.",
                    style = MaterialTheme.typography.bodyMedium,
                )
                Column(modifier = Modifier.heightIn(max = 260.dp).verticalScroll(rememberScrollState())) {
                    if (contacts.isEmpty()) Text("No contacts yet", style = MaterialTheme.typography.bodyLarge)
                    for (c in contacts) {
                        Row(
                            modifier = Modifier.fillMaxWidth().clickable { onPick(c) }.padding(vertical = 6.dp),
                            verticalAlignment = Alignment.CenterVertically,
                        ) {
                            Column(modifier = Modifier.weight(1f)) {
                                Text(c.name)
                                Text(
                                    shortKey(c.pubkey),
                                    fontFamily = FontFamily.Monospace,
                                    style = MaterialTheme.typography.bodySmall,
                                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                                )
                            }
                            Icon(Icons.AutoMirrored.Filled.KeyboardArrowRight, contentDescription = null)
                        }
                    }
                }
                TextButton(
                    onClick = onAddNew,
                    contentPadding = androidx.compose.foundation.layout.PaddingValues(0.dp),
                ) { Text("Add new contact") }
            }
        },
        confirmButton = {},
        dismissButton = { TextButton(onClick = onCancel) { Text("Cancel") } },
    )
}
