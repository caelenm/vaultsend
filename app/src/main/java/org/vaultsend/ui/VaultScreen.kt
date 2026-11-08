package org.vaultsend.ui

import androidx.compose.animation.AnimatedVisibility
import androidx.compose.animation.core.animateFloatAsState
import androidx.compose.animation.core.tween
import androidx.compose.foundation.BorderStroke
import androidx.compose.foundation.background
import androidx.compose.foundation.border
import androidx.compose.foundation.clickable
import androidx.compose.foundation.interaction.MutableInteractionSource
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.PaddingValues
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.RowScope
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxHeight
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.heightIn
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.selection.selectable
import androidx.compose.foundation.selection.selectableGroup
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.text.selection.SelectionContainer
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.KeyboardArrowRight
import androidx.compose.material.icons.automirrored.filled.NoteAdd
import androidx.compose.material.icons.filled.Add
import androidx.compose.material.icons.filled.Check
import androidx.compose.material.icons.filled.ContentCopy
import androidx.compose.material.icons.filled.ContentCut
import androidx.compose.material.icons.filled.ContentPaste
import androidx.compose.material.icons.filled.CreateNewFolder
import androidx.compose.material.icons.filled.Delete
import androidx.compose.material.icons.filled.DriveFileRenameOutline
import androidx.compose.material.icons.filled.Edit
import androidx.compose.material.icons.filled.FileOpen
import androidx.compose.material.icons.filled.KeyboardArrowDown
import androidx.compose.material.icons.filled.KeyboardArrowUp
import androidx.compose.material.icons.filled.Lock
import androidx.compose.material.icons.filled.MoreVert
import androidx.compose.material.icons.filled.RemoveCircleOutline
import androidx.compose.material.icons.filled.Share
import androidx.compose.material.icons.filled.Unarchive
import androidx.compose.material.icons.filled.UploadFile
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.Button
import androidx.compose.material3.Checkbox
import androidx.compose.material3.DropdownMenu
import androidx.compose.material3.DropdownMenuItem
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.FilledTonalButton
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.LinearProgressIndicator
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.ModalDrawerSheet
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.RadioButton
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.material3.VerticalDivider
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateMapOf
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.alpha
import androidx.compose.ui.draw.clip
import androidx.compose.ui.focus.FocusRequester
import androidx.compose.ui.focus.focusRequester
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.vector.ImageVector
import androidx.compose.ui.semantics.Role
import androidx.compose.ui.text.TextRange
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.input.ImeAction
import androidx.compose.ui.text.input.KeyboardCapitalization
import androidx.compose.ui.text.input.TextFieldValue
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import org.vaultsend.Contact
import org.vaultsend.ROOT_ENTRY
import org.vaultsend.VaultEntry
import org.vaultsend.VaultRecord
import org.vaultsend.VaultSelection
import org.vaultsend.entryIndent
import org.vaultsend.countOf
import org.vaultsend.entryNameProblem
import org.vaultsend.humanSize
import org.vaultsend.isValidVaultName
import org.vaultsend.noteFileName
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
                SlidingToggle(
                    options = SidebarMode.entries.map { it.name },
                    selected = SidebarMode.entries.indexOf(mode),
                    onSelect = { onMode(SidebarMode.entries[it]) },
                    modifier = Modifier.weight(1f),
                )
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

/** How much of the toggle the chosen side takes; the line between them slides to match. */
private const val TOGGLE_CHOSEN_SHARE = 0.62f

/**
 * Two options in one outlined pill. The chosen one is filled and wider, and the
 * line between them slides across as the choice changes.
 */
@Composable
fun SlidingToggle(
    options: List<String>,
    selected: Int,
    onSelect: (Int) -> Unit,
    modifier: Modifier = Modifier,
) {
    val outline = MaterialTheme.colorScheme.outline
    val shape = RoundedCornerShape(50)
    Row(
        modifier = modifier
            .height(40.dp)
            .clip(shape)
            .border(1.dp, outline, shape)
            .selectableGroup(),
    ) {
        options.forEachIndexed { i, label ->
            val chosen = i == selected
            val share by animateFloatAsState(
                targetValue = if (chosen) TOGGLE_CHOSEN_SHARE else (1f - TOGGLE_CHOSEN_SHARE) / (options.size - 1),
                animationSpec = tween(durationMillis = 250),
                label = "toggle share",
            )
            if (i > 0) VerticalDivider(color = outline)
            Box(
                modifier = Modifier
                    .weight(share)
                    .fillMaxHeight()
                    .background(if (chosen) MaterialTheme.colorScheme.secondaryContainer else Color.Transparent)
                    .selectable(
                        selected = chosen,
                        interactionSource = remember { MutableInteractionSource() },
                        indication = null,
                        role = Role.Tab,
                        onClick = { onSelect(i) },
                    ),
                contentAlignment = Alignment.Center,
            ) {
                Row(verticalAlignment = Alignment.CenterVertically) {
                    AnimatedVisibility(visible = chosen) {
                        Icon(
                            Icons.Filled.Check,
                            contentDescription = null,
                            modifier = Modifier.padding(end = 4.dp).size(18.dp),
                        )
                    }
                    Text(
                        label,
                        style = MaterialTheme.typography.labelLarge,
                        maxLines = 1,
                        overflow = TextOverflow.Ellipsis,
                        color = if (chosen) MaterialTheme.colorScheme.onSecondaryContainer else MaterialTheme.colorScheme.onSurface,
                    )
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
    val onAddNote: () -> Unit,
    val onEditNote: () -> Unit,
    val onRename: () -> Unit,
    val onCut: () -> Unit = {},
    val onPaste: () -> Unit = {},
    val onOpen: () -> Unit,
    val onExtract: () -> Unit,
    val onShare: () -> Unit,
    val onDelete: () -> Unit,
    val onLock: () -> Unit,
    val onVerify: () -> Unit,
    /** Stop the operation in progress, where it can be stopped. */
    val onCancel: () -> Unit = {},
)

@Composable
fun VaultPage(
    vault: VaultRecord,
    page: VaultSelection?,
    progress: Int?,
    progressHeading: String,
    onChange: (VaultSelection) -> Unit,
    actions: VaultActions,
    menuOpen: Boolean,
    onMenuOpen: (Boolean) -> Unit,
    canCancel: Boolean,
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
        // Four equal buttons. Only one of Select all and Select multiple is lit at a
        // time: with every row ticked, Select all is. Invert works on tick boxes, so
        // it waits for Select multiple.
        Row(horizontalArrangement = Arrangement.spacedBy(6.dp), modifier = Modifier.fillMaxWidth()) {
            val row = Modifier.weight(1f)
            TopButton(
                label = if (everything) "Select none" else "Select all",
                lit = everything,
                enabled = !page?.entries.isNullOrEmpty(),
                onClick = { page?.let { onChange(it.selectAll()) } },
                modifier = row,
            )
            TopButton(
                label = "Select multiple",
                lit = page?.multiple == true && !everything,
                enabled = page != null,
                onClick = { page?.let { onChange(it.withMultiple(!it.multiple)) } },
                modifier = row,
            )
            TopButton(
                label = "Invert selection",
                lit = false,
                enabled = page != null && page.multiple && page.entries.isNotEmpty(),
                onClick = { page?.let { onChange(it.invert()) } },
                modifier = row,
            )
            TopButton(
                label = "Verify all",
                lit = false,
                enabled = page != null && progress == null,
                onClick = actions.onVerify,
                modifier = row,
            )
        }

        if (page != null && page.cut.isNotEmpty()) {
            val problem = page.pasteProblem()
            Row(verticalAlignment = Alignment.CenterVertically) {
                Column(modifier = Modifier.weight(1f)) {
                    Text(
                        "${countOf(page.cut.size, "item")} cut. Choose a folder, then Paste.",
                        style = MaterialTheme.typography.bodyMedium,
                    )
                    if (problem != null) {
                        Text(problem, style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.error)
                    }
                }
                TextButton(onClick = { onChange(page.cancelCut()) }) { Text("Cancel") }
            }
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
            ProgressRow(progress, progressHeading, if (canCancel) actions.onCancel else null)
        }

        // Nothing selected means nothing to act on: Open, Extract…, Share… and Delete wait.
        VaultActionSheet(
            open = menuOpen,
            onOpen = onMenuOpen,
            idle = page != null && progress == null,
            chosen = page?.chosen().orEmpty().isNotEmpty(),
            one = page?.oneChosen() != null,
            note = page?.chosenNote() != null,
            canCut = page?.canCut() == true,
            pasteLabel = page?.takeIf { it.cut.isNotEmpty() }?.let { p ->
                val dest = p.addDestination()
                if (dest.isEmpty()) "Paste here (top of vault)" else "Paste into ${dest.substringAfterLast('/')}/"
            },
            canPaste = page?.canPaste() == true,
            unlocked = page != null,
            actions = actions,
        )
    }
}

/** A progress bar with its heading, and Cancel where the operation can stop. */
@Composable
fun ProgressRow(progress: Int, heading: String, onCancel: (() -> Unit)?) {
    Column(verticalArrangement = Arrangement.spacedBy(4.dp)) {
        Row(verticalAlignment = Alignment.CenterVertically) {
            Text(
                if (progress >= 0) "$heading $progress%" else heading,
                style = MaterialTheme.typography.bodySmall,
                modifier = Modifier.weight(1f),
            )
            if (onCancel != null) TextButton(onClick = onCancel) { Text("Cancel") }
        }
        // Pulses until the first report and once the work is done but not yet committed.
        if (progress in 0..99) {
            LinearProgressIndicator(progress = { progress / 100f }, modifier = Modifier.fillMaxWidth())
        } else {
            LinearProgressIndicator(modifier = Modifier.fillMaxWidth())
        }
    }
}

/** One of the four buttons above the list: filled while its mode is on. */
@Composable
private fun TopButton(label: String, lit: Boolean, enabled: Boolean, onClick: () -> Unit, modifier: Modifier) {
    val padding = PaddingValues(horizontal = 4.dp, vertical = 6.dp)
    val content: @Composable RowScope.() -> Unit = {
        Text(
            label,
            style = MaterialTheme.typography.labelMedium,
            textAlign = TextAlign.Center,
            maxLines = 2,
            overflow = TextOverflow.Ellipsis,
        )
    }
    val shape = RoundedCornerShape(12.dp)
    val sized = modifier.heightIn(min = 52.dp)
    if (lit) {
        FilledTonalButton(onClick = onClick, enabled = enabled, shape = shape, contentPadding = padding, modifier = sized, content = content)
    } else {
        OutlinedButton(onClick = onClick, enabled = enabled, shape = shape, contentPadding = padding, modifier = sized, content = content)
    }
}

/**
 * The page's actions, stacked in a panel with rounded top corners that folds away
 * to its handle, so the list can have the screen.
 */
@Composable
private fun VaultActionSheet(
    open: Boolean,
    onOpen: (Boolean) -> Unit,
    idle: Boolean,
    chosen: Boolean,
    /** Exactly one file or folder is chosen: Rename… */
    one: Boolean,
    /** That one is a .md or .txt file: Edit note. */
    note: Boolean,
    /** Something other than the whole vault is chosen: Cut. */
    canCut: Boolean,
    /** Set while something is cut: what Paste says, naming where it goes. */
    pasteLabel: String?,
    canPaste: Boolean,
    unlocked: Boolean,
    actions: VaultActions,
) {
    Surface(
        shape = RoundedCornerShape(topStart = 24.dp, topEnd = 24.dp),
        color = MaterialTheme.colorScheme.background,
        border = BorderStroke(1.dp, MaterialTheme.colorScheme.outlineVariant),
        modifier = Modifier.fillMaxWidth(),
    ) {
        Column {
            val toggle = if (open) "Hide actions" else "Show actions"
            Box(
                modifier = Modifier
                    .fillMaxWidth()
                    .clickable(onClickLabel = toggle) { onOpen(!open) }
                    .padding(vertical = 2.dp),
                contentAlignment = Alignment.Center,
            ) {
                Icon(
                    if (open) Icons.Filled.KeyboardArrowDown else Icons.Filled.KeyboardArrowUp,
                    contentDescription = toggle,
                    modifier = Modifier.size(32.dp),
                )
            }
            AnimatedVisibility(visible = open) {
                // Plain rows with a line between each, on the app's own background.
                Column(modifier = Modifier.padding(bottom = 8.dp)) {
                    HorizontalDivider()
                    // With something cut, Paste leads: it's the next step.
                    if (pasteLabel != null) {
                        SheetItem(Icons.Filled.ContentPaste, pasteLabel, idle && canPaste, actions.onPaste)
                        HorizontalDivider()
                    }
                    SheetItem(Icons.Filled.UploadFile, "Add files…", idle, actions.onAddFiles)
                    HorizontalDivider()
                    SheetItem(Icons.Filled.CreateNewFolder, "Add folder…", idle, actions.onAddFolder)
                    HorizontalDivider()
                    SheetItem(Icons.AutoMirrored.Filled.NoteAdd, "Add note…", idle, actions.onAddNote)
                    HorizontalDivider()
                    SheetItem(Icons.Filled.FileOpen, "Open", idle && chosen, actions.onOpen)
                    HorizontalDivider()
                    SheetItem(Icons.Filled.Edit, "Edit note", idle && note, actions.onEditNote)
                    HorizontalDivider()
                    SheetItem(Icons.Filled.DriveFileRenameOutline, "Rename…", idle && one, actions.onRename)
                    HorizontalDivider()
                    SheetItem(Icons.Filled.ContentCut, "Cut", idle && canCut, actions.onCut)
                    HorizontalDivider()
                    SheetItem(Icons.Filled.Unarchive, "Extract…", idle && chosen, actions.onExtract)
                    HorizontalDivider()
                    SheetItem(Icons.Filled.Share, "Share…", idle && chosen, actions.onShare)
                    HorizontalDivider()
                    SheetItem(Icons.Filled.Delete, "Delete", idle && chosen, actions.onDelete, destructive = true)
                    HorizontalDivider()
                    SheetItem(Icons.Filled.Lock, "Lock", unlocked, actions.onLock)
                }
            }
        }
    }
}

@Composable
private fun SheetItem(icon: ImageVector, label: String, enabled: Boolean, onClick: () -> Unit, destructive: Boolean = false) {
    val base = if (destructive) MaterialTheme.colorScheme.error else MaterialTheme.colorScheme.primary
    val color = if (enabled) base else MaterialTheme.colorScheme.onSurface.copy(alpha = 0.38f)
    Row(
        modifier = Modifier
            .fillMaxWidth()
            .heightIn(min = 48.dp)
            .clickable(enabled = enabled, role = Role.Button, onClick = onClick)
            .padding(horizontal = 20.dp, vertical = 12.dp),
        verticalAlignment = Alignment.CenterVertically,
    ) {
        Icon(icon, contentDescription = null, tint = color, modifier = Modifier.size(20.dp))
        Spacer(Modifier.width(16.dp))
        Text(label, color = color, modifier = Modifier.weight(1f))
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
            .alpha(if (page.isCut(entry.path)) 0.5f else 1f)
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

// --- The note editor (Android only) -----------------------------------------

/**
 * A note being written: a new one in `folder` ("" for the top of the vault), or the
 * file `previous` opened for editing. Saving writes `title` + `suffix` there.
 */
data class NoteDraft(
    val vaultUri: String,
    val folder: String,
    val previous: String?,
    val suffix: String,
    val title: String,
    val body: String,
    /** What it held when opened, to tell whether closing loses anything. */
    val openedTitle: String = title,
    val openedBody: String = body,
) {
    val changed: Boolean get() = title != openedTitle || body != openedBody

    /** The file name it saves as. */
    val fileName: String get() = noteFileName(title, suffix)

    /** Why it can't be saved under this title, or null; nothing to say while the title is blank. */
    val titleProblem: String? get() = if (title.isBlank()) null else entryNameProblem(fileName)

    val canSave: Boolean get() = title.isNotBlank() && titleProblem == null
}

/**
 * The note editor, in place of the vault's page: a title at the top, with the
 * extension it's saved with after it, and a text box below like the main page's.
 * Save is in the top bar (App.kt).
 */
@Composable
fun NoteEditor(
    draft: NoteDraft,
    onChange: (NoteDraft) -> Unit,
    progress: Int?,
    progressHeading: String,
    modifier: Modifier = Modifier,
) {
    val busy = progress != null
    Column(modifier = modifier, verticalArrangement = Arrangement.spacedBy(12.dp)) {
        OutlinedTextField(
            value = draft.title,
            onValueChange = { onChange(draft.copy(title = it)) },
            label = { Text("Title") },
            suffix = { Text(draft.suffix) },
            singleLine = true,
            enabled = !busy,
            isError = draft.titleProblem != null,
            supportingText = {
                Text(
                    draft.titleProblem
                        ?: if (draft.folder.isEmpty()) "Saved at the top of the vault." else "Saved in “${draft.folder}”.",
                )
            },
            keyboardOptions = KeyboardOptions(capitalization = KeyboardCapitalization.Sentences, imeAction = ImeAction.Next),
            textStyle = MaterialTheme.typography.titleMedium,
            modifier = Modifier.fillMaxWidth(),
        )
        OutlinedTextField(
            value = draft.body,
            onValueChange = { onChange(draft.copy(body = it)) },
            enabled = !busy,
            placeholder = { Text("Write your note…") },
            keyboardOptions = KeyboardOptions(capitalization = KeyboardCapitalization.Sentences),
            modifier = Modifier.fillMaxWidth().weight(1f),
        )
        if (progress != null) ProgressRow(progress, progressHeading, null)
    }
}

// --- Dialogs ----------------------------------------------------------------

/**
 * Rename…: a new name for one file or folder, in the same folder. Rename stays off
 * until the name is usable and different, and says why when it can't be used.
 */
@Composable
fun RenameDialog(
    current: String,
    isDir: Boolean,
    taken: (String) -> Boolean,
    onCancel: () -> Unit,
    onRename: (String) -> Unit,
) {
    // A file's name starts selected up to its extension, so typing keeps the type.
    val stem = if (isDir) current.length else current.lastIndexOf('.').takeIf { it > 0 } ?: current.length
    var field by remember { mutableStateOf(TextFieldValue(current, TextRange(0, stem))) }
    val name = field.text.trim()
    val problem = entryNameProblem(name)?.takeIf { name.isNotEmpty() }
        ?: "Something here already has that name.".takeIf { name != current && taken(name) }
    val focus = remember { FocusRequester() }
    LaunchedEffect(Unit) { focus.requestFocus() }
    AlertDialog(
        onDismissRequest = onCancel,
        title = { Text(if (isDir) "Rename folder" else "Rename file") },
        text = {
            OutlinedTextField(
                value = field,
                onValueChange = { field = it },
                label = { Text("Name") },
                singleLine = true,
                isError = problem != null,
                supportingText = { if (problem != null) Text(problem) },
                modifier = Modifier.fillMaxWidth().focusRequester(focus),
            )
        },
        confirmButton = {
            TextButton(onClick = { onRename(name) }, enabled = name.isNotEmpty() && problem == null && name != current) {
                Text("Rename")
            }
        },
        dismissButton = { TextButton(onClick = onCancel) { Text("Cancel") } },
    )
}

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
 *
 * The same form makes a vault from a shared file ("Import as a vault"): then it
 * starts with the shared vault's name, and has no Add existing vault… link.
 */
@Composable
fun AddVaultDialog(
    onCancel: () -> Unit,
    onExisting: (() -> Unit)?,
    onCreate: (name: String, mode: String) -> Unit,
    title: String = "Add vault",
    intro: String = "A vault is an encrypted folder of files.",
    initialName: String = "",
) {
    var name by remember { mutableStateOf(initialName) }
    var password by remember { mutableStateOf(false) }
    val trimmed = name.trim()
    val ok = isValidVaultName(trimmed)

    AlertDialog(
        onDismissRequest = onCancel,
        title = { Text(title) },
        text = {
            Column(
                modifier = Modifier.verticalScroll(rememberScrollState()),
                verticalArrangement = Arrangement.spacedBy(6.dp),
            ) {
                Text(intro, style = MaterialTheme.typography.bodyMedium)
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
                    Text("Use a password")
                }
                Text(
                    "Next, choose the folder it goes in. It stays there, where your file manager " +
                        "shows it. VaultSend keeps access to the folder you choose and what's in it, " +
                        "so a folder just for vaults is best.",
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                )
                if (onExisting != null) {
                    TextButton(onClick = onExisting, contentPadding = PaddingValues(0.dp)) { Text("Add existing vault…") }
                }
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
 * Add existing vault…: a vault's folder, as before, or a file someone shared from
 * their vault (Share…), which becomes a new vault here.
 */
@Composable
fun ExistingVaultDialog(onFolder: () -> Unit, onSharedFile: () -> Unit, onCancel: () -> Unit) {
    AlertDialog(
        onDismissRequest = onCancel,
        title = { Text("Add existing vault") },
        text = {
            Column(verticalArrangement = Arrangement.spacedBy(4.dp)) {
                ChoiceRow(
                    "A vault folder…",
                    "A .vsvault folder on this device: it's added to your list where it is.",
                    onFolder,
                )
                ChoiceRow(
                    "A shared vault file…",
                    "A file someone made with Share… (like “Holiday.tar.age”). You unlock it, then " +
                        "choose how the new vault is protected and where it goes.",
                    onSharedFile,
                )
            }
        },
        confirmButton = {},
        dismissButton = { TextButton(onClick = onCancel) { Text("Cancel") } },
    )
}

/**
 * A decrypted archive: keep it as the one .tar file, or unpack it into a folder.
 */
@Composable
fun ArchiveChoiceDialog(fileName: String, onArchive: () -> Unit, onFolder: () -> Unit, onCancel: () -> Unit) {
    AlertDialog(
        onDismissRequest = onCancel,
        title = { Text("Save “$fileName”") },
        text = {
            Column(verticalArrangement = Arrangement.spacedBy(4.dp)) {
                Text(
                    "This is several files and folders in one archive.",
                    style = MaterialTheme.typography.bodyMedium,
                )
                ChoiceRow("As an archive (.tar)", "One file, which a file manager or tar can unpack later.", onArchive)
                ChoiceRow("As a folder", "Unpacked into a new folder, in a folder you choose.", onFolder)
            }
        },
        confirmButton = {},
        dismissButton = { TextButton(onClick = onCancel) { Text("Cancel") } },
    )
}

@Composable
private fun ChoiceRow(title: String, detail: String, onClick: () -> Unit) {
    Row(
        modifier = Modifier.fillMaxWidth().clickable(onClick = onClick).padding(vertical = 8.dp),
        verticalAlignment = Alignment.CenterVertically,
    ) {
        Column(modifier = Modifier.weight(1f)) {
            Text(title, style = MaterialTheme.typography.bodyLarge)
            Text(detail, style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
        }
        Icon(Icons.AutoMirrored.Filled.KeyboardArrowRight, contentDescription = null)
    }
}

/**
 * Share…: who it's for. Tick one or more contacts, then Continue goes on to
 * Save File or Share. "Add new contact" opens Add contact over this, so the
 * selection and place are kept.
 * "Set password instead" makes a file anyone with the password can open, and goes
 * on to the same Save File or Share.
 */
@Composable
fun ShareDialog(
    what: String,
    oneFile: Boolean,
    contacts: List<Contact>,
    initiallyPicked: Set<String>,
    onAddNew: (Set<String>) -> Unit,
    onPassword: () -> Unit,
    onConfirm: (List<Contact>) -> Unit,
    onCancel: () -> Unit,
) {
    val checked = remember { mutableStateMapOf<String, Boolean>().apply { initiallyPicked.forEach { put(it, true) } } }
    fun picked(): Set<String> = checked.filterValues { it }.keys.toSet()
    AlertDialog(
        onDismissRequest = onCancel,
        title = { Text("Share “$what”") },
        text = {
            Column(verticalArrangement = Arrangement.spacedBy(8.dp)) {
                Text(
                    "Encrypted so only you and the people you choose can read it. They open it by " +
                        "decrypting it in VaultSend" +
                        if (oneFile) ", which gives them this file." else ", which gives them a .tar archive of it all.",
                    style = MaterialTheme.typography.bodyMedium,
                )
                Column(modifier = Modifier.heightIn(max = 260.dp).verticalScroll(rememberScrollState())) {
                    if (contacts.isEmpty()) Text("No contacts yet", style = MaterialTheme.typography.bodyLarge)
                    for (c in contacts) {
                        val on = checked[c.pubkey] ?: false
                        Row(
                            modifier = Modifier.fillMaxWidth().clickable { checked[c.pubkey] = !on }.padding(vertical = 2.dp),
                            verticalAlignment = Alignment.CenterVertically,
                        ) {
                            Checkbox(checked = on, onCheckedChange = { checked[c.pubkey] = it })
                            Column(modifier = Modifier.weight(1f)) {
                                Text(c.name)
                                Text(
                                    shortKey(c.pubkey),
                                    fontFamily = FontFamily.Monospace,
                                    style = MaterialTheme.typography.bodySmall,
                                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                                )
                            }
                        }
                    }
                }
                TextButton(onClick = { onAddNew(picked()) }, contentPadding = PaddingValues(0.dp)) { Text("Add new contact") }
                TextButton(onClick = onPassword, contentPadding = PaddingValues(0.dp)) { Text("Set password instead") }
            }
        },
        confirmButton = {
            TextButton(
                onClick = { val p = picked(); onConfirm(contacts.filter { it.pubkey in p }) },
                enabled = contacts.any { checked[it.pubkey] == true },
            ) { Text("Continue") }
        },
        dismissButton = { TextButton(onClick = onCancel) { Text("Cancel") } },
    )
}
