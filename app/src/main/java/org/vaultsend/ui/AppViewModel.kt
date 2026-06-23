package org.vaultsend.ui

import android.app.Application
import android.net.Uri
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateListOf
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.setValue
import androidx.lifecycle.AndroidViewModel
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import org.vaultsend.Backend
import org.vaultsend.Contact
import org.vaultsend.ContactStore
import org.vaultsend.readContacts
import org.vaultsend.writeContacts

/** The top-level screen the app is showing. Dialogs overlay these. */
enum class AppPhase {
    /** Initial state while we read the identity status on launch. */
    Loading,

    /** First-run welcome splash. */
    Welcome,

    /** First-run explainer with "Generate new" / "Import" buttons. */
    Intro,

    /** Shown once, right after a brand-new key is generated. */
    BackupOffer,

    /** The normal encrypt/decrypt screen. */
    Main,
}

/**
 * Holds the small amount of app state that should outlive recomposition and
 * screen rotation: the onboarding [phase], this device's public key, whether the
 * session is unlocked, the contact list, the contents of the message box, and any
 * content that was shared into the app from outside. Crypto calls are delegated
 * straight to [Backend]; this class adds no logic of its own beyond persisting
 * contacts and tracking which screen is visible.
 */
class AppViewModel(app: Application) : AndroidViewModel(app) {

    val backend = Backend(app)
    private val contactStore = ContactStore(app)

    /** Which top-level screen is showing. */
    var phase by mutableStateOf(AppPhase.Loading)

    /** This device's "age1…" public key, or null until the key is ready. */
    var myPubkey by mutableStateOf<String?>(null)

    /** Whether the session is currently unlocked (mirrors the native session). */
    var unlocked by mutableStateOf(false)
        private set

    /** The encrypt/decrypt text box. Kept here so rotation doesn't lose it. */
    var message by mutableStateOf("")

    /**
     * A file or text shared into the app from outside (share sheet / "open with").
     * Picked up by the UI once the app is past onboarding, then cleared.
     */
    var pendingShareUri by mutableStateOf<Uri?>(null)
        private set
    var pendingShareText by mutableStateOf<String?>(null)
        private set

    val contacts = mutableStateListOf<Contact>().apply { addAll(contactStore.load()) }

    /** Refresh [unlocked] from the native session (call after unlock/lock/keygen). */
    fun refreshUnlocked() {
        unlocked = backend.isUnlocked()
    }

    /** Clear the session key and update [unlocked]. */
    fun lockSession() {
        backend.lock()
        unlocked = false
    }

    /** Record content shared into the app; consumed by the UI when ready. */
    fun setPendingShare(uri: Uri?, text: String?) {
        pendingShareUri = uri
        pendingShareText = text
    }

    fun clearPendingShare() {
        pendingShareUri = null
        pendingShareText = null
    }

    fun addContact(name: String, pubkey: String) {
        contacts.add(Contact(name.trim(), pubkey.trim()))
        contactStore.save(contacts)
    }

    fun deleteContact(contact: Contact) {
        contacts.remove(contact)
        contactStore.save(contacts)
    }

    /**
     * Import contacts from a user-picked JSON file (Storage Access Framework URI),
     * merging them into the current list. Reads/parse off the main thread; the
     * file read is the only blocking step. Existing contacts are kept and any
     * incoming entry whose pubkey is already present is skipped, so re-importing
     * the same file is a no-op rather than a source of duplicates.
     *
     * Returns the number of new contacts actually added. Throws if the file can't
     * be opened or isn't a valid contacts.json (the caller reports the message).
     */
    suspend fun importContacts(uri: Uri): Int {
        val incoming = withContext(Dispatchers.IO) {
            getApplication<Application>().contentResolver.openInputStream(uri).use { input ->
                requireNotNull(input) { "Couldn't open the selected file." }
                readContacts(input)
            }
        }
        // Resumes on the caller's dispatcher (Main) — safe to mutate snapshot state.
        val seen = contacts.mapTo(HashSet()) { it.pubkey }
        var added = 0
        for (c in incoming) {
            if (seen.add(c.pubkey)) {
                contacts.add(c)
                added++
            }
        }
        if (added > 0) contactStore.save(contacts)
        return added
    }

    /**
     * Export the current contacts to a user-chosen destination (SAF URI), in the
     * desktop-compatible contacts.json shape. The write happens off the main
     * thread. Throws if the destination can't be opened.
     */
    suspend fun exportContacts(uri: Uri) {
        val snapshot = contacts.toList()
        withContext(Dispatchers.IO) {
            // "wt" = write + truncate, so an existing file is fully replaced.
            getApplication<Application>().contentResolver.openOutputStream(uri, "wt").use { os ->
                requireNotNull(os) { "Couldn't open the destination." }
                writeContacts(os, snapshot)
            }
        }
    }
}
