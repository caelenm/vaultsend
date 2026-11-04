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
import org.vaultsend.AppSettings
import org.vaultsend.Backend
import org.vaultsend.Contact
import org.vaultsend.ContactStore
import org.vaultsend.REMEMBER_SECONDS
import org.vaultsend.VaultRecord
import org.vaultsend.VaultSelection
import org.vaultsend.VaultStore
import org.vaultsend.readContacts
import org.vaultsend.writeContacts
import java.io.File

/** What the side drawer lists: the desktop's Contacts / Vaults toggle. */
enum class SidebarMode { Contacts, Vaults }

/** A decrypted copy handed to another app by Open, and the vault it came from. */
data class OpenedCopy(val vaultUri: String, val file: File)

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

    /** Several files shared in at once (SEND_MULTIPLE): offered to the open vault. */
    var pendingShareMany by mutableStateOf<List<Uri>?>(null)
        private set

    val contacts = mutableStateListOf<Contact>().apply { addAll(contactStore.load()) }

    /** Refresh [unlocked] from the native session (call after unlock/lock/keygen). */
    fun refreshUnlocked() {
        val now = backend.isUnlocked()
        if (now && !unlocked) unlockedAt = System.currentTimeMillis()
        unlocked = now
    }

    /**
     * Clear the session key and every remembered vault key (the native lock()
     * does both), and update [unlocked]. Open vaults show as locked again and
     * their opened copies are deleted: the desktop's Lock now.
     */
    fun lockSession() {
        backend.lock()
        unlocked = false
        lockVaultPage()
        discardCopies()
    }

    // --- Vaults ---------------------------------------------------------------

    private val vaultStore = VaultStore(app.filesDir)

    /** The vaults this device knows about (vaults.json). */
    val vaults = mutableStateListOf<VaultRecord>().apply { addAll(vaultStore.loadVaults()) }

    /** settings.json: Remember passphrase, and which warnings were acknowledged. */
    var settings by mutableStateOf(vaultStore.loadSettings())
        private set

    var sidebarMode by mutableStateOf(SidebarMode.Contacts)

    /** The vault whose page is showing, or null for the main page. */
    var selectedVault by mutableStateOf<VaultRecord?>(null)
        private set

    /** Its listing and what's selected, or null while it's locked. */
    var vaultPage by mutableStateOf<VaultSelection?>(null)

    /** A vault operation's percent: null for none running, -1 before the first report. */
    var vaultProgress by mutableStateOf<Int?>(null)

    /** What the progress bar is for ("Adding to vault…"). */
    var vaultProgressHeading by mutableStateOf("")

    /** Copies Open has handed to other apps, deleted on Lock, Lock now and close. */
    val openedCopies = mutableStateListOf<OpenedCopy>()

    /** When the session was unlocked, for a Remember lifetime. */
    private var unlockedAt = 0L

    init {
        backend.setVaultRemember(rememberSeconds())
    }

    fun saveVaults() = vaultStore.saveVaults(vaults)

    fun updateSettings(new: AppSettings) {
        settings = new
        vaultStore.saveSettings(new)
    }

    /** Show a vault's page, locked until it's unlocked. */
    fun selectVault(record: VaultRecord?) {
        if (record?.uri != selectedVault?.uri) vaultPage = null
        selectedVault = record
    }

    /** Add or update a vault in the list, and show it. */
    fun rememberVault(record: VaultRecord): VaultRecord {
        val i = vaults.indexOfFirst { it.uri == record.uri }
        if (i >= 0) vaults[i] = record else vaults.add(record)
        saveVaults()
        selectVault(record)
        return record
    }

    /** The desktop's "Remove from list": forgets the vault, deletes nothing in it. */
    fun forgetVault(record: VaultRecord) {
        vaults.removeAll { it.uri == record.uri }
        saveVaults()
        backend.forgetVault(record)
        discardCopies(record)
        if (selectedVault?.uri == record.uri) selectVault(null)
        runCatching {
            val uri = android.net.Uri.parse(record.uri)
            val tree = android.provider.DocumentsContract.buildTreeDocumentUri(
                uri.authority, android.provider.DocumentsContract.getTreeDocumentId(uri),
            )
            // Keep the grant if another vault in the list lives under the same tree.
            if (vaults.none { it.uri.startsWith("$tree/") }) {
                getApplication<Application>().contentResolver.releasePersistableUriPermission(
                    tree,
                    android.content.Intent.FLAG_GRANT_READ_URI_PERMISSION or android.content.Intent.FLAG_GRANT_WRITE_URI_PERMISSION,
                )
            }
        }
    }

    /** Accept a listing: remember its generation, and show it with nothing selected. */
    fun acceptListing(record: VaultRecord, generation: Long, entries: List<org.vaultsend.VaultEntry>) {
        val updated = record.copy(lastGeneration = generation)
        val i = vaults.indexOfFirst { it.uri == record.uri }
        if (i >= 0) {
            vaults[i] = updated
            saveVaults()
        }
        if (selectedVault?.uri == record.uri) {
            selectedVault = updated
            vaultPage = (vaultPage ?: VaultSelection()).withEntries(entries)
        }
    }

    /** Drop the listing. It is only metadata, but locked means locked. */
    fun lockVaultPage() {
        vaultPage = null
    }

    /** The desktop vault page's Lock: forget this vault's key and its opened copies. */
    fun lockVault(record: VaultRecord) {
        backend.forgetVault(record)
        discardCopies(record)
        if (selectedVault?.uri == record.uri) lockVaultPage()
    }

    fun discardCopies(record: VaultRecord? = null) {
        val gone = openedCopies.filter { record == null || it.vaultUri == record.uri }
        backend.discardCopies(gone.map { it.file })
        openedCopies.removeAll(gone)
    }

    // --- Remember passphrase --------------------------------------------------

    /** The chosen lifetime in seconds: 0 none, null until the app closes. */
    fun rememberSeconds(): Long? = REMEMBER_SECONDS[settings.remember]

    /**
     * Change how long secrets are remembered. As on desktop, this forgets what
     * was remembered: the session locks and remembered vault keys go.
     */
    fun setRemember(choice: String) {
        if (choice == settings.remember || choice !in REMEMBER_SECONDS) return
        updateSettings(settings.copy(remember = choice))
        backend.setVaultRemember(rememberSeconds())
        lockSession()
    }

    /** Lock the session once its Remember lifetime is up, and sweep vault keys. Polled. */
    fun enforceRemember() {
        backend.sweepVaultKeys()
        val seconds = rememberSeconds() ?: return
        if (seconds > 0 && unlocked && System.currentTimeMillis() - unlockedAt >= seconds * 1000) {
            lockSession()
        }
    }

    /** The background auto-lock: keys and open vault pages, but not opened copies. */
    fun lockForBackground() {
        backend.lock()
        unlocked = false
        lockVaultPage()
    }

    /** After an operation that used the session: with Remember off, lock straight away. */
    fun afterSecretUse() {
        if (rememberSeconds() == 0L && unlocked) {
            backend.lock()
            unlocked = false
        }
    }

    /** Record content shared into the app; consumed by the UI when ready. */
    fun setPendingShare(uri: Uri?, text: String?) {
        pendingShareUri = uri
        pendingShareText = text
    }

    fun clearPendingShare() {
        pendingShareUri = null
        pendingShareText = null
        pendingShareMany = null
    }

    fun setPendingShareMany(uris: List<Uri>) {
        pendingShareMany = uris
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
     * Entries whose public key the core rejects are skipped rather than saved,
     * since a bad key would break every later encryption to that contact.
     *
     * Returns (added, skipped). Throws if the file can't be opened or isn't a
     * valid contacts.json (the caller reports the message).
     */
    suspend fun importContacts(uri: Uri): Pair<Int, Int> {
        val incoming = withContext(Dispatchers.IO) {
            getApplication<Application>().contentResolver.openInputStream(uri).use { input ->
                requireNotNull(input) { "Couldn't open the selected file." }
                readContacts(input)
            }
        }
        // Resumes on the caller's dispatcher (Main) — safe to mutate snapshot state.
        val seen = contacts.mapTo(HashSet()) { it.pubkey }
        var added = 0
        var skipped = 0
        for (c in incoming) {
            if (!backend.isValidRecipient(c.pubkey)) {
                skipped++
            } else if (seen.add(c.pubkey)) {
                contacts.add(c)
                added++
            }
        }
        if (added > 0) contactStore.save(contacts)
        return added to skipped
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
