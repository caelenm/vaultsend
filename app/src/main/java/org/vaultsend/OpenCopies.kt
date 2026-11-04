package org.vaultsend

import java.io.File
import java.nio.file.Files
import java.nio.file.LinkOption
import java.nio.file.attribute.PosixFilePermissions
import java.security.SecureRandom

/*
 * Where Open puts a decrypted copy for another app to show: the desktop's
 * memory_folder / clear_stale_copies, changed for Android.
 *
 * The desktop insists on a folder in RAM (tmpfs) and refuses otherwise. Android
 * gives apps no such folder, so the copy goes in this app's cache directory: on
 * disk, but in storage only this app can read, which Android encrypts. Another
 * app sees it only through a read-only content:// grant (FileProvider), so it can
 * read the copy but never change it, which is also why there are no edits to
 * detect and no "changes will be lost" prompt on Lock. Each copy is deleted on
 * Lock, Lock now and when the app closes, and anything left by a crash is deleted
 * at the next launch.
 */

/** The folder under the cache directory that holds every opened copy. */
const val OPEN_DIR = "open"

/**
 * A new private (0700) folder for one opened file, under `openRoot`, with a name
 * nobody can guess. The copy inside is written 0600 by the core.
 */
fun newCopyFolder(openRoot: File): File {
    openRoot.mkdirs()
    val bytes = ByteArray(12).also { SecureRandom().nextBytes(it) }
    val name = OPEN_PREFIX + bytes.joinToString("") { "%02x".format(it) }
    val folder = File(openRoot, name)
    Files.createDirectory(
        folder.toPath(),
        PosixFilePermissions.asFileAttribute(PosixFilePermissions.fromString("rwx------")),
    )
    return folder
}

/**
 * Delete what a crash left behind: only real folders with our prefix, never a
 * symlink (which would be followed into someone else's files) or a plain file.
 */
fun clearStaleCopies(openRoot: File) {
    val items = openRoot.listFiles() ?: return
    for (item in items) {
        val path = item.toPath()
        if (item.name.startsWith(OPEN_PREFIX) &&
            Files.isDirectory(path, LinkOption.NOFOLLOW_LINKS)
        ) {
            deleteTree(item)
        }
    }
}

/** Delete a folder and what's in it without following symlinks out of it. */
fun deleteTree(folder: File) {
    val path = folder.toPath()
    if (Files.isDirectory(path, LinkOption.NOFOLLOW_LINKS)) {
        folder.listFiles()?.forEach(::deleteTree)
    }
    Files.deleteIfExists(path)
}
