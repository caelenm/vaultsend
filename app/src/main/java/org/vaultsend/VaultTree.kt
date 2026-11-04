package org.vaultsend

import android.content.ContentResolver
import android.content.Context
import android.database.Cursor
import android.net.Uri
import android.provider.DocumentsContract
import android.provider.DocumentsContract.Document
import java.io.FileNotFoundException
import java.io.IOException

/*
 * The Kotlin half of the vault storage. The Rust core's SafStore (ffi.rs) calls
 * these methods back, by name and JVM signature, for every file it reads or
 * writes in a folder the user picked through the Storage Access Framework, so
 * vaults live where the user can see them in a file manager, with no storage
 * permission. They are kept under R8 by proguard-rules.pro.
 *
 * Paths are relative to the vault's folder, '/'-separated, "" for the folder
 * itself. SAF has no paths, only document IDs, so each one is resolved a name at a
 * time and remembered for the life of the operation.
 */

/** Kinds, as SafStore reads them: 0 missing, 1 file, 2 folder, 3 anything else. */
private const val MISSING = 0
private const val FILE = 1
private const val DIR = 2

/** Readable names for the storage volumes ExternalStorageProvider calls by ID. */
private fun volumeLabel(volume: String): String =
    if (volume == "primary") "Internal storage" else volume

/**
 * A folder reached through `treeUri`, the tree the user granted, rooted at the
 * document `rootId` inside it (the tree's own document unless the vault is a
 * folder made inside the granted one).
 */
class VaultTree(context: Context, val treeUri: Uri, val rootId: String) {

    private val resolver: ContentResolver = context.contentResolver

    /** Document ID and MIME type by path, filled in as paths are resolved. */
    private val known = HashMap<String, Pair<String, String>>()

    init {
        known[""] = rootId to Document.MIME_TYPE_DIR
    }

    /** This folder's document URI, which is what the vault list stores. */
    val documentUri: Uri get() = DocumentsContract.buildDocumentUriUsingTree(treeUri, rootId)

    private fun uriOf(id: String): Uri = DocumentsContract.buildDocumentUriUsingTree(treeUri, id)

    private fun join(parent: String, name: String) = if (parent.isEmpty()) name else "$parent/$name"

    private fun parentOf(rel: String) = rel.substringBeforeLast('/', "")

    private fun nameOf(rel: String) = rel.substringAfterLast('/')

    /** The children of a folder, as (id, name, MIME type). */
    private fun children(parentId: String): List<Triple<String, String, String>> {
        val uri = DocumentsContract.buildChildDocumentsUriUsingTree(treeUri, parentId)
        val columns = arrayOf(Document.COLUMN_DOCUMENT_ID, Document.COLUMN_DISPLAY_NAME, Document.COLUMN_MIME_TYPE)
        val cursor: Cursor = resolver.query(uri, columns, null, null, null)
            ?: throw IOException("Couldn't list a folder: access to it may have been lost.")
        return cursor.use {
            buildList {
                while (it.moveToNext()) {
                    add(Triple(it.getString(0), it.getString(1) ?: "", it.getString(2) ?: ""))
                }
            }
        }
    }

    /** (document ID, MIME type) for `rel`, or null if nothing has that name. */
    private fun resolve(rel: String): Pair<String, String>? {
        known[rel]?.let { return it }
        val parent = resolve(parentOf(rel)) ?: return null
        if (parent.second != Document.MIME_TYPE_DIR) return null
        val name = nameOf(rel)
        // Exact match only: a case-insensitive disk would otherwise make "A" and "a" one file.
        val child = children(parent.first).firstOrNull { it.second == name } ?: return null
        return (child.first to child.third).also { known[rel] = it }
    }

    /** Forget what was resolved at and below `rel`, after it changed. */
    private fun forget(rel: String) {
        known.keys.removeAll { it == rel || it.startsWith("$rel/") }
        if (rel.isEmpty()) known[""] = rootId to Document.MIME_TYPE_DIR
    }

    private fun need(rel: String): Pair<String, String> =
        resolve(rel) ?: throw FileNotFoundException("${show(rel)}: not found")

    // --- Called from Rust (SafStore). ---------------------------------------

    /** Stable, path-like name for this folder: whether one folder is inside another. */
    @Suppress("UNUSED_PARAMETER")
    fun key(unused: String): String = "${treeUri.authority}/$rootId"

    /** `rel` as a person would recognise it. */
    fun show(rel: String): String {
        val base = rootId.substringAfter(':', rootId).let { path ->
            val volume = rootId.substringBefore(':', "")
            if (volume.isEmpty()) path else "${volumeLabel(volume)}/$path".trimEnd('/')
        }
        return if (rel.isEmpty()) base else "$base/$rel"
    }

    fun kind(rel: String): Int {
        val found = try {
            resolve(rel)
        } catch (e: Exception) {
            null
        } ?: return MISSING
        return if (found.second == Document.MIME_TYPE_DIR) DIR else FILE
    }

    /** A detached descriptor the caller closes, or -1 if `rel` isn't there. */
    fun openRead(rel: String): Int {
        val (id, mime) = resolve(rel) ?: return -1
        if (mime == Document.MIME_TYPE_DIR) return -1
        return resolver.openFileDescriptor(uriOf(id), "r")?.detachFd() ?: -1
    }

    /**
     * A new empty file at `rel`, replacing a stale one of that exact name; its
     * folder must exist. Refused if the provider would store it under another
     * name, which is what a case-insensitive disk does with a clash.
     */
    fun createNew(rel: String): Int {
        val parent = parentOf(rel)
        val name = nameOf(rel)
        val (parentId, parentMime) = need(parent)
        if (parentMime != Document.MIME_TYPE_DIR) throw IOException("${show(parent)} is not a folder")
        resolve(rel)?.let { (id, _) ->
            DocumentsContract.deleteDocument(resolver, uriOf(id))
            forget(rel)
        }
        val created = DocumentsContract.createDocument(resolver, uriOf(parentId), "application/octet-stream", name)
            ?: throw IOException("creating ${show(rel)}: the folder refused it")
        val id = DocumentsContract.getDocumentId(created)
        if (displayName(created) != name) {
            DocumentsContract.deleteDocument(resolver, created)
            throw IOException("${show(rel)}: two names in the vault collide on this disk")
        }
        known[rel] = id to "application/octet-stream"
        return resolver.openFileDescriptor(created, "w")?.detachFd()
            ?: throw IOException("creating ${show(rel)}: couldn't open it")
    }

    /** Rename within one folder. `to` must not exist: SAF can't replace a file this way. */
    fun rename(from: String, to: String) {
        require(parentOf(from) == parentOf(to)) { "rename across folders" }
        val (id, _) = need(from)
        if (resolve(to) != null) throw IOException("${show(to)} already exists")
        val newName = nameOf(to)
        val renamed = DocumentsContract.renameDocument(resolver, uriOf(id), newName) ?: uriOf(id)
        forget(from)
        forget(to)
        if (displayName(renamed) != newName) {
            // The provider changed the name (a clash it resolved its own way): undo.
            DocumentsContract.renameDocument(resolver, renamed, nameOf(from))
            throw IOException("${show(to)}: the folder wouldn't take that name")
        }
    }

    /** Delete a file, or a folder and everything in it. 1 if something was deleted. */
    fun delete(rel: String): Int {
        val (id, _) = resolve(rel) ?: return 0
        DocumentsContract.deleteDocument(resolver, uriOf(id))
        forget(rel)
        return 1
    }

    /** A folder at `rel`; with `recursive`, its parents too, and an existing one is fine. */
    fun mkdir(rel: String, recursive: Boolean) {
        if (rel.isEmpty()) return
        resolve(rel)?.let { (_, mime) ->
            if (recursive && mime == Document.MIME_TYPE_DIR) return
            throw IOException("${show(rel)} already exists")
        }
        val parent = parentOf(rel)
        if (recursive) mkdir(parent, true)
        val (parentId, _) = need(parent)
        val created = DocumentsContract.createDocument(resolver, uriOf(parentId), Document.MIME_TYPE_DIR, nameOf(rel))
            ?: throw IOException("the folder refused it")
        if (displayName(created) != nameOf(rel)) {
            DocumentsContract.deleteDocument(resolver, created)
            throw IOException("two names in the vault collide on this disk")
        }
        known[rel] = DocumentsContract.getDocumentId(created) to Document.MIME_TYPE_DIR
    }

    /** "f:name", "d:name" for what's in a folder. */
    fun list(rel: String): Array<String> {
        val (id, mime) = need(rel)
        if (mime != Document.MIME_TYPE_DIR) throw IOException("not a folder")
        return children(id).map { (childId, name, childMime) ->
            val isDir = childMime == Document.MIME_TYPE_DIR
            known[join(rel, name)] = childId to childMime
            (if (isDir) "d:" else "f:") + name
        }.toTypedArray()
    }

    private fun displayName(uri: Uri): String? =
        resolver.query(uri, arrayOf(Document.COLUMN_DISPLAY_NAME), null, null, null)?.use {
            if (it.moveToFirst()) it.getString(0) else null
        }

    // --- Used by the app. ---------------------------------------------------

    /** The text of this folder's VAULT file, or null if it has none. */
    fun vaultFileText(): String? {
        if (kind("VAULT") != FILE) return null
        val (id, _) = need("VAULT")
        return runCatching {
            resolver.openInputStream(uriOf(id))?.use { input ->
                // A real VAULT file is a few dozen bytes.
                String(input.readNBytesCompat(256), Charsets.UTF_8)
            }
        }.getOrNull()
    }

    /** True if this folder has nothing in it. */
    fun isEmpty(): Boolean = children(rootId).isEmpty()

    /** True if `other` is this folder or anywhere inside it. */
    fun contains(other: Uri): Boolean {
        if (other.authority != treeUri.authority) return false
        val otherId = runCatching { DocumentsContract.getDocumentId(other) }.getOrNull()
            ?: runCatching { DocumentsContract.getTreeDocumentId(other) }.getOrNull()
            ?: return false
        if (otherId == rootId || otherId.startsWith("$rootId/")) return true
        return runCatching { DocumentsContract.isChildDocument(resolver, documentUri, other) }.getOrDefault(false)
    }

    companion object {
        /** The vault at a document URI the vault list stored. */
        fun fromDocumentUri(context: Context, uri: Uri): VaultTree {
            val treeId = DocumentsContract.getTreeDocumentId(uri)
            val tree = DocumentsContract.buildTreeDocumentUri(uri.authority, treeId)
            val id = runCatching { DocumentsContract.getDocumentId(uri) }.getOrDefault(treeId)
            return VaultTree(context, tree, id)
        }

        /** A folder the user just picked (OpenDocumentTree), as itself. */
        fun fromTree(context: Context, tree: Uri): VaultTree =
            VaultTree(context, tree, DocumentsContract.getTreeDocumentId(tree))
    }
}

/** InputStream.readNBytes is API 33; this is the same for the small reads here. */
private fun java.io.InputStream.readNBytesCompat(limit: Int): ByteArray {
    val out = java.io.ByteArrayOutputStream()
    val buf = ByteArray(256)
    while (out.size() < limit) {
        val n = read(buf, 0, minOf(buf.size, limit - out.size()))
        if (n < 0) break
        out.write(buf, 0, n)
    }
    return out.toByteArray()
}

/**
 * What a vault-add adds, called back by the core: picked documents, walked into
 * a flat list of paths below the destination. A folder's contents come from
 * DocumentsContract; a virtual document (a Google Doc, say) has no bytes to read
 * and is skipped and counted, as the desktop skips what isn't a regular file.
 */
class VaultSources private constructor(
    private val resolver: ContentResolver,
    val targets: Array<String>,
    val isDir: BooleanArray,
    val sizes: LongArray,
    private val uris: List<Uri?>,
    val skipped: Int,
) {
    /** Called from Rust: a detached descriptor for file `index`. */
    fun openSource(index: Int): Int {
        val uri = uris[index] ?: return -1
        return resolver.openFileDescriptor(uri, "r")?.detachFd() ?: -1
    }

    companion object {
        private data class Item(val target: String, val uri: Uri?, val size: Long)

        private data class Child(val id: String, val name: String, val mime: String, val size: Long, val flags: Int)

        /**
         * Picked `files` (OpenMultipleDocuments) and `folders` (OpenDocumentTree),
         * each added under its own name.
         */
        fun walk(context: Context, files: List<Uri>, folders: List<Uri>): VaultSources {
            val resolver = context.contentResolver
            val items = mutableListOf<Item>()
            var skipped = 0
            for (uri in files) {
                val info = info(resolver, uri) ?: continue
                if (info.virtual) skipped++ else items += Item(info.name, uri, info.size)
            }
            for (tree in folders) {
                val rootId = DocumentsContract.getTreeDocumentId(tree)
                val rootUri = DocumentsContract.buildDocumentUriUsingTree(tree, rootId)
                val name = info(resolver, rootUri)?.name ?: continue
                skipped += walkFolder(resolver, tree, rootId, name, items)
            }
            return VaultSources(
                resolver,
                items.map { it.target }.toTypedArray(),
                BooleanArray(items.size) { items[it].uri == null },
                LongArray(items.size) { items[it].size },
                items.map { it.uri },
                skipped,
            )
        }

        private fun walkFolder(resolver: ContentResolver, tree: Uri, id: String, target: String, items: MutableList<Item>): Int {
            items += Item(target, null, 0)
            var skipped = 0
            val uri = DocumentsContract.buildChildDocumentsUriUsingTree(tree, id)
            val columns = arrayOf(
                Document.COLUMN_DOCUMENT_ID, Document.COLUMN_DISPLAY_NAME,
                Document.COLUMN_MIME_TYPE, Document.COLUMN_SIZE, Document.COLUMN_FLAGS,
            )
            val children = resolver.query(uri, columns, null, null, null)?.use { c ->
                buildList<Child> {
                    while (c.moveToNext()) {
                        add(Child(c.getString(0), c.getString(1) ?: "", c.getString(2) ?: "", c.getLong(3), c.getInt(4)))
                    }
                }
            } ?: return 0
            for (child in children) {
                val path = "$target/${child.name}"
                when {
                    child.mime == Document.MIME_TYPE_DIR -> skipped += walkFolder(resolver, tree, child.id, path, items)
                    (child.flags and Document.FLAG_VIRTUAL_DOCUMENT) != 0 -> skipped++
                    else -> items += Item(path, DocumentsContract.buildDocumentUriUsingTree(tree, child.id), child.size)
                }
            }
            return skipped
        }

        private data class Info(val name: String, val size: Long, val virtual: Boolean)

        private fun info(resolver: ContentResolver, uri: Uri): Info? {
            val columns = arrayOf(Document.COLUMN_DISPLAY_NAME, Document.COLUMN_SIZE, Document.COLUMN_FLAGS)
            return runCatching {
                resolver.query(uri, columns, null, null, null)?.use { c ->
                    if (!c.moveToFirst()) return@use null
                    val flagsIndex = c.getColumnIndex(Document.COLUMN_FLAGS)
                    val flags = if (flagsIndex >= 0 && !c.isNull(flagsIndex)) c.getInt(flagsIndex) else 0
                    Info(
                        name = c.getString(0) ?: uri.lastPathSegment?.substringAfterLast('/') ?: "file",
                        size = if (c.isNull(1)) 0 else c.getLong(1),
                        virtual = (flags and Document.FLAG_VIRTUAL_DOCUMENT) != 0,
                    )
                }
            }.getOrNull()
        }
    }
}

/** Called from Rust with whole percents as a vault operation goes. */
fun interface ProgressSink {
    fun report(percent: Int)
}
