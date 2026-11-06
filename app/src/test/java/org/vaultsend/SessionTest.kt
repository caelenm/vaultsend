package org.vaultsend

import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class SessionTest {

    @Test
    fun backgroundLockIsDueOnceTheTimeAwayHasRunOut() {
        val left = 1_000_000L
        assertFalse("never left", backgroundLockDue(0L, left + BACKGROUND_LOCK_MS * 10))
        assertFalse(backgroundLockDue(left, left))
        assertFalse(backgroundLockDue(left, left + BACKGROUND_LOCK_MS - 1))
        assertTrue(backgroundLockDue(left, left + BACKGROUND_LOCK_MS))
        // Hours asleep, when the timer may never have fired.
        assertTrue(backgroundLockDue(left, left + 3 * 60 * 60 * 1000L))
    }

    private val ours = "org.vaultsend.open"
    private val docs = "com.android.externalstorage.documents"

    /** A persisted tree grant on `primary:Documents`, as getPathSegments() decodes it. */
    private val grant = UriParts("content", docs, listOf("tree", "primary:Documents"))

    @Test
    fun aDocumentInsideAGrantedFolderIsRefused() {
        val inside = UriParts("content", docs, listOf("tree", "primary:Documents", "document", "primary:Documents/taxes.pdf"))
        assertTrue(refuseIncoming(inside, ours, listOf(grant)))
        assertTrue("the tree itself", refuseIncoming(grant, ours, listOf(grant)))
        // Case can only refuse more.
        val shouted = UriParts("CONTENT", docs.uppercase(), inside.path)
        assertTrue(refuseIncoming(shouted, ours, listOf(grant)))
    }

    @Test
    fun ownFileProviderAndNonContentUrisAreRefused() {
        val copy = UriParts("content", ours, listOf("open", "vaultsend-open-0123", "photo.jpg"))
        assertTrue(refuseIncoming(copy, ours, emptyList()))
        assertTrue(refuseIncoming(UriParts("file", null, listOf("data", "x")), ours, emptyList()))
        assertTrue(refuseIncoming(UriParts(null, null, emptyList()), ours, emptyList()))
    }

    @Test
    fun whatOtherAppsCanReachThemselvesIsAccepted() {
        // A different tree on the same provider: a prefix of the name isn't a parent.
        val sibling = UriParts("content", docs, listOf("tree", "primary:Documents2", "document", "primary:Documents2/a.age"))
        assertFalse(refuseIncoming(sibling, ours, listOf(grant)))
        // A plain document URI the sender granted: VaultSend's tree grant doesn't reach it.
        val plain = UriParts("content", docs, listOf("document", "primary:Download/a.age"))
        assertFalse(refuseIncoming(plain, ours, listOf(grant)))
        // Another app's own provider.
        val other = UriParts("content", "com.example.files.provider", listOf("files", "a.age"))
        assertFalse(refuseIncoming(other, ours, listOf(grant)))
        assertFalse(refuseIncoming(other, ours, emptyList()))
    }
}
