package org.vaultsend

import java.net.URLDecoder

/*
 * The desktop frontend's window-free vault helpers (frontend/app.py on the vaults
 * branch), ported one for one. Plain Kotlin with no Android types, so
 * VaultHelpersTest runs them on the JVM exactly as test_frontend_helpers.py runs
 * the originals.
 */

/** The suffix a new vault's folder gets. */
const val VAULT_SUFFIX = ".vsvault"

/** The backend's name for the whole vault (ROOT_ENTRY in vault.rs). */
const val ROOT_ENTRY = "/"

/** dp a row in a vault's file list sits in, per folder level. */
const val INDENT_STEP = 20

/** No further: the list can't scroll sideways, so more would push names off a phone screen. */
const val INDENT_LEVELS = 6

/** Opening more files than this at once asks first: each one starts an app. */
const val OPEN_ASK_ABOVE = 10

/** The backend's words for a `self` vault of someone else's. */
const val KEY_MISMATCH = "does not open with your key"

/** What the backend says when a password vault needs its password (vault.rs PASSWORD_NEEDED). */
const val PASSWORD_NEEDED = "this vault's password is needed"

/** Folders holding opened copies start with this, so leftovers can be found after a crash. */
const val OPEN_PREFIX = "vaultsend-open-"

/** One row of a vault's file list. Names and sizes only; the core never sends content. */
data class VaultEntry(val path: String, val isDir: Boolean, val size: Long)

fun isValidVaultName(name: String): Boolean =
    name.isNotEmpty() &&
        '/' !in name &&
        '\u0000' !in name &&
        name != "." && name != ".." &&
        (name + VAULT_SUFFIX).toByteArray(Charsets.UTF_8).size <= 255

/**
 * "self" or "password" from the text of a vault's VAULT file, or null if it isn't
 * a vault. Only decides which prompt to show; the core doesn't trust it either.
 */
fun readVaultMode(text: String?): String? = when (text) {
    "vaultsend-vault 1\nmode self\n" -> "self"
    "vaultsend-vault 1\nmode password\n" -> "password"
    else -> null
}

/** A manifest path as vault.rs escapes it: every byte outside [A-Za-z0-9._~/-] as %XX. */
private fun unescapePath(s: String): String =
    // `+` never appears unescaped (the core escapes it), so URLDecoder's reading of
    // it as a space can't happen; anything else is plain %XX over UTF-8.
    URLDecoder.decode(s.replace("+", "%2B"), "UTF-8")

/**
 * Turn `vault-list` output into (generation, entries), with paths unescaped and
 * entries sorted for display: folder by folder, folders first. Throws
 * IllegalArgumentException on a garbled generation line, as the desktop raises
 * ValueError.
 */
fun parseListing(text: String): Pair<Long, List<VaultEntry>> {
    val lines = text.split("\n")
    val generation = lines[0].removePrefix("generation ").let {
        require(lines[0].startsWith("generation ") && it.isNotEmpty() && it.all(Char::isDigit)) {
            "not a vault listing"
        }
        it.toLong()
    }
    val entries = buildList {
        for (line in lines.drop(1)) {
            val fields = line.split(" ")
            if (fields[0] == "D" && fields.size == 2) {
                add(VaultEntry(unescapePath(fields[1]), isDir = true, size = 0))
            } else if (fields[0] == "F" && fields.size == 3) {
                add(VaultEntry(unescapePath(fields[2]), isDir = false, size = fields[1].toLong()))
            }
        }
    }
    return generation to entries.sortedWith(::compareForDisplay)
}

/**
 * The desktop's sort key, compared part by part: each parent folder by its
 * case-folded name then its exact name, then the entry itself with folders first.
 */
private fun compareForDisplay(a: VaultEntry, b: VaultEntry): Int {
    fun key(e: VaultEntry): List<Triple<Int, String, String>> {
        val parts = e.path.split("/")
        val name = parts.last()
        return parts.dropLast(1).map { Triple(0, it.lowercase(), it) } +
            Triple(if (e.isDir) 0 else 1, name.lowercase(), name)
    }
    val (ka, kb) = key(a) to key(b)
    for (i in 0 until minOf(ka.size, kb.size)) {
        val c = compareValuesBy(ka[i], kb[i], { it.first }, { it.second }, { it.third })
        if (c != 0) return c
    }
    return ka.size.compareTo(kb.size)
}

/**
 * A location shortened for display: `home` becomes "~", and anything deeper
 * than three parts keeps only the first and the last. On Android `home` is the
 * name of the storage the folder is on.
 */
fun shortPath(path: String, home: String): String {
    var p = path
    if (home.isNotEmpty() && (p == home || p.startsWith("$home/"))) {
        p = "~" + p.substring(home.length)
    }
    val parts = p.split("/")
    return if (parts.size <= 3) p else "${parts.first()}/…/${parts.last()}"
}

fun entryIndent(path: String): Int = minOf(path.count { it == '/' }, INDENT_LEVELS) * INDENT_STEP

/** Every folder leading to `path`, outermost first: "a/b/c" gives "a", "a/b". */
fun parentFolders(path: String): List<String> {
    val parts = path.split("/")
    return (1 until parts.size).map { parts.subList(0, it).joinToString("/") }
}

/** What a set of ticked rows comes to: a ticked folder already covers what's in it. */
fun topLevelSelection(paths: Collection<String>): List<String> {
    val chosen = paths.toSet()
    if (ROOT_ENTRY in chosen) return listOf(ROOT_ENTRY)
    return chosen.filter { p -> parentFolders(p).none { it in chosen } }.sorted()
}

/** The files a selection covers, in display order. `entries` is a listing by path. */
fun filesInSelection(selection: Collection<String>, entries: Map<String, VaultEntry>): List<String> {
    fun covered(path: String) =
        selection.any { s -> s == ROOT_ENTRY || path == s || path.startsWith("$s/") }
    return entries.filter { (path, entry) -> !entry.isDir && covered(path) }.keys.toList()
}

/** A name to suggest for a share. One file stays that file; anything else is an archive. */
fun shareFileName(vaultName: String, selection: List<String>, entries: Map<String, VaultEntry>): String {
    if (selection.size > 1) return "$vaultName selection.tar.age"
    val only = selection[0]
    if (only == ROOT_ENTRY) return "$vaultName.tar.age"
    return only.substringAfterLast('/') + if (entries.getValue(only).isDir) ".tar.age" else ".age"
}

/** What Share names an archive ends with. */
const val ARCHIVE_SUFFIX = ".tar.age"

/** Whether a shared file's name says it's an archive of several files (Share's naming). */
fun isArchiveName(name: String): Boolean =
    name.lowercase().let { it.endsWith(ARCHIVE_SUFFIX) || it.endsWith(".tar") }

private fun withoutAge(name: String): String =
    if (name.lowercase().endsWith(".age")) name.dropLast(4) else name

private fun withoutTar(name: String): String =
    if (name.lowercase().endsWith(".tar")) name.dropLast(4) else name

/** The folder an archive unpacks into: "Holiday.tar.age" gives "Holiday". */
fun archiveFolderName(fileName: String): String =
    withoutTar(withoutAge(fileName)).trim().takeIf { isValidVaultName(it) } ?: "Shared files"

/** A single shared file's own name, as it goes into a vault: "photo.jpg.age" gives "photo.jpg". */
fun singleNameFromShared(fileName: String): String =
    withoutAge(fileName).trim().takeIf { it.isNotEmpty() && '/' !in it && it != "." && it != ".." } ?: "shared file"

/**
 * The name to suggest for a vault made from a shared file: the vault it came from,
 * as Share named it ("Holiday.tar.age", "Holiday selection.tar.age"), or a single
 * file's name without its extension.
 */
fun vaultNameFromShared(fileName: String): String {
    val base = withoutAge(fileName)
    val name = if (base.lowercase().endsWith(".tar")) {
        withoutTar(base).removeSuffix(" selection")
    } else {
        base.substringBeforeLast('.', base).ifEmpty { base }
    }
    return name.trim().takeIf { isValidVaultName(it) } ?: "Shared vault"
}

fun vaultNameFromPath(path: String): String =
    path.trimEnd('/').substringAfterLast('/').removeSuffix(VAULT_SUFFIX)

/** What a new note is saved as: its title, then this. */
const val NOTE_SUFFIX = ".md"

/** Files the note editor opens for editing (case-insensitive). */
val NOTE_SUFFIXES = listOf(".md", ".txt")

/** The largest note the editor opens: text this long is already unwieldy on a phone. */
const val NOTE_MAX_BYTES = 1 shl 20

/** The extension that makes `path` a note, as it's written there, or null if it isn't one. */
fun noteSuffix(path: String): String? {
    val name = path.substringAfterLast('/')
    return NOTE_SUFFIXES.firstOrNull { name.length > it.length && name.lowercase().endsWith(it) }
        ?.let { name.takeLast(it.length) }
}

/** The title a note's editor shows: its name without the note extension. */
fun noteTitle(path: String): String {
    val name = path.substringAfterLast('/')
    return noteSuffix(name)?.let { name.dropLast(it.length) } ?: name
}

/**
 * The file name a title saves as: "Shopping" gives "Shopping.md". The suffix is
 * always added (the editor shows it after the title), so a note's title and name
 * go back and forth unchanged.
 */
fun noteFileName(title: String, suffix: String = NOTE_SUFFIX): String = title.trim() + suffix

/** Why `name` can't name a file or folder in a vault (the core's rule for one path part), or null. */
fun entryNameProblem(name: String): String? = when {
    name.isEmpty() -> "Enter a name."
    '/' in name -> "A name can't contain “/”."
    '\u0000' in name || name == "." || name == ".." -> "That name can't be used."
    name.toByteArray(Charsets.UTF_8).size > 255 -> "That name is too long."
    else -> null
}

/** `path` with its last part replaced by `name`: Rename… stays in the same folder. */
fun renamedPath(path: String, name: String): String {
    val folder = path.substringBeforeLast('/', "")
    return if (folder.isEmpty()) name else "$folder/$name"
}

/** A file size as people read it. */
fun humanSize(bytes: Long): String {
    if (bytes < 1024) return if (bytes == 1L) "1 byte" else "$bytes bytes"
    val units = listOf("KB", "MB", "GB", "TB")
    var value = bytes / 1024.0
    var unit = 0
    while (value >= 1024 && unit < units.lastIndex) {
        value /= 1024
        unit++
    }
    return String.format(java.util.Locale.ROOT, if (value < 10) "%.1f %s" else "%.0f %s", value, units[unit])
}

/** "1 file" / "3 files": the desktop's fix for "1 files". */
fun countOf(n: Int, one: String, many: String = one + "s"): String = "$n ${if (n == 1) one else many}"

/**
 * What's selected on a vault's page, and which folders are open: the desktop's
 * _selection, _on_entry_ticked, _on_select_all and _on_folder_expanded, as one
 * immutable value so the page just shows it. Nothing is selected to begin with.
 *
 * With Select multiple off, one row at a time is chosen. With it on, rows have
 * tick boxes: ticking a folder ticks what's in it and stands for all of it, and
 * unticking something inside unticks the folders above it, so a ticked folder
 * always means the whole folder. Every row ticked means the whole vault.
 */
data class VaultSelection(
    /** The listing by path, in display order. */
    val entries: Map<String, VaultEntry> = emptyMap(),
    val multiple: Boolean = false,
    val single: String? = null,
    val ticked: Set<String> = emptySet(),
    val expanded: Set<String> = emptySet(),
) {
    /** A fresh listing: nothing selected, the same folders open (desktop keeps `expanded`). */
    fun withEntries(list: List<VaultEntry>): VaultSelection =
        VaultSelection(entries = list.associateBy { it.path }, multiple = multiple, expanded = expanded)

    /** What the actions act on: paths, none inside another; ROOT_ENTRY for everything; or nothing. */
    fun chosen(): List<String> = when {
        !multiple -> listOfNotNull(single)
        entries.isNotEmpty() && ticked.containsAll(entries.keys) -> listOf(ROOT_ENTRY)
        else -> topLevelSelection(ticked)
    }

    fun select(path: String): VaultSelection = copy(single = path)

    /** Turning it on carries the one chosen row over as ticked; turning it off clears. */
    fun withMultiple(on: Boolean): VaultSelection =
        if (on) {
            val carried = single?.let { tick(it, true).ticked } ?: emptySet()
            copy(multiple = true, single = null, ticked = carried)
        } else {
            copy(multiple = false, single = null, ticked = emptySet())
        }

    fun tick(path: String, active: Boolean): VaultSelection {
        val inside = entries.keys.filter { it == path || it.startsWith("$path/") }
        return if (active) {
            copy(ticked = ticked + inside)
        } else {
            copy(ticked = ticked - inside.toSet() - parentFolders(path).toSet())
        }
    }

    /**
     * Invert selection, with Select multiple on: every file and empty folder flips,
     * hidden ones too, and a folder is ticked exactly when everything in it is, so a
     * ticked folder still means the whole folder. Off, it does nothing.
     */
    fun invert(): VaultSelection {
        if (!multiple) return this
        val holding = entries.keys.flatMapTo(HashSet()) { parentFolders(it) }
        val leaves = entries.values.filter { !it.isDir || it.path !in holding }.map { it.path }
        val flipped = leaves.filterTo(HashSet()) { it !in ticked }
        // A folder is whole when no leaf below it is left unticked.
        val partial = leaves.filter { it !in flipped }.flatMapTo(HashSet()) { parentFolders(it) }
        val folders = holding.filter { it in entries && it !in partial }
        return copy(ticked = flipped + folders)
    }

    /**
     * Where Add files… and Add folder… put things: into the one chosen folder, beside
     * the one chosen file, otherwise at the top of the vault ("").
     */
    fun addDestination(): String {
        val chosen = chosen()
        val one = if (chosen.size == 1) chosen[0] else ROOT_ENTRY
        return if (entries[one]?.isDir == true) one else one.substringBeforeLast('/', "").removePrefix("/")
    }

    /** The one file or folder chosen, for Rename…; null for none, several or the whole vault. */
    fun oneChosen(): String? = chosen().singleOrNull()?.takeIf { it != ROOT_ENTRY && it in entries }

    /** The one note chosen, for Edit note: a .md or .txt file. */
    fun chosenNote(): String? = oneChosen()?.takeIf { entries[it]?.isDir == false && noteSuffix(it) != null }

    /** Select all takes the tick boxes; pressed again with everything ticked, Select none. */
    fun selectAll(): VaultSelection =
        if (chosen() == listOf(ROOT_ENTRY)) {
            copy(multiple = true, single = null, ticked = emptySet())
        } else {
            copy(multiple = true, single = null, ticked = entries.keys)
        }

    /**
     * Open or close a folder. Closing one clears ticks hidden inside it, unless the
     * folder itself is ticked, and with one row chosen, a choice hidden inside it.
     */
    fun toggleExpanded(path: String): VaultSelection {
        if (path !in expanded) return copy(expanded = expanded + path)
        val closed = copy(expanded = expanded - path)
        return when {
            multiple && path !in ticked ->
                closed.copy(ticked = ticked.filterNot { it.startsWith("$path/") }.toSet())
            !multiple && single?.startsWith("$path/") == true -> closed.copy(single = null)
            else -> closed
        }
    }

    /** Rows to draw: those whose every folder above is open. */
    fun visible(): List<VaultEntry> =
        entries.values.filter { e -> parentFolders(e.path).all { it in expanded } }

    fun isTicked(path: String): Boolean = if (multiple) path in ticked else path == single

    /** The heading over the list, as on desktop. */
    fun summary(): String {
        val chosen = chosen()
        return when {
            chosen == listOf(ROOT_ENTRY) -> "Files · all selected"
            multiple -> "Files · ${chosen.size} selected"
            else -> {
                val files = entries.values.filter { !it.isDir }
                "Files · ${countOf(files.size, "file")}, ${humanSize(files.sumOf { it.size })}"
            }
        }
    }
}
