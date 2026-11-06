package org.vaultsend.ui

import android.app.Application
import android.net.Uri
import android.os.Handler
import android.os.Looper
import android.os.SystemClock
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateListOf
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.setValue
import androidx.lifecycle.AndroidViewModel
import androidx.lifecycle.viewModelScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import org.vaultsend.AppSettings
import org.vaultsend.BACKGROUND_LOCK_MS
import org.vaultsend.Backend
import org.vaultsend.Contact
import org.vaultsend.ContactStore
import org.vaultsend.REMEMBER_SECONDS
import org.vaultsend.VaultRecord
import org.vaultsend.VaultSelection
import org.vaultsend.VaultStore
import org.vaultsend.backgroundLockDue
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
        private set

    /**
     * Whether [message] holds text this app decrypted (or what the user has made of
     * it since), which every lock clears. Encrypting it, loading shared text over
     * it, or emptying the box ends that.
     */
    var messageIsDecrypted by mutableStateOf(false)
        private set

    /** The user typed in the box. */
    fun editMessage(text: String) {
        message = text
        if (text.isEmpty()) messageIsDecrypted = false
    }

    /** Something that isn't decrypted text replaces what's in the box. */
    fun replaceMessage(text: String) {
        message = text
        messageIsDecrypted = false
    }

    /** Decrypted text goes in the box, until the next lock. */
    fun showDecrypted(text: String) {
        message = text
        messageIsDecrypted = true
    }

    /** Locking: decrypted text leaves the screen with the key that decrypted it. */
    fun clearDecryptedMessage() {
        if (messageIsDecrypted) {
            message = ""
            messageIsDecrypted = false
        }
    }

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
        unlocked = backend.isUnlocked()
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
        clearDecryptedMessage()
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

    /** The running operation's progress and Cancel, while it can be cancelled. */
    var cancellable by mutableStateOf<org.vaultsend.ProgressSink?>(null)

    /** Whether the vault page's action panel is open. Starts open; kept for the session. */
    var vaultMenuOpen by mutableStateOf(true)

    /** Copies Open has handed to other apps, deleted on Lock, Lock now and close. */
    val openedCopies = mutableStateListOf<OpenedCopy>()

    init {
        backend.setVaultRemember(rememberSeconds())
        // A new view model means a new process, or an activity that finished (and
        // locked) before this one: no opened copy can be in use, and none would be in
        // [openedCopies] if Android had restarted the app, so they're swept here. So
        // is plaintext staging a killed run left in the data dir; the core skips that
        // if something is staging, so it can run off the main thread.
        backend.discardCopies()
        viewModelScope.launch(Dispatchers.IO) { runCatching { backend.sweepStaging() } }
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

    /**
     * Delete opened copies: one vault's (its Lock, Remove from list), or with no
     * vault, every copy in the folder, including any an earlier process handed out
     * that this one never knew about (Lock now, and closing the app).
     */
    fun discardCopies(record: VaultRecord? = null) {
        if (record == null) {
            backend.discardCopies()
            openedCopies.clear()
            return
        }
        val gone = openedCopies.filter { it.vaultUri == record.uri }
        backend.discardCopies(gone.map { it.file })
        openedCopies.removeAll(gone)
    }

    // --- Remember passphrase --------------------------------------------------

    /** The chosen lifetime: 0 none, null until the app closes. */
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

    /** Sweep remembered vault keys. Polled; no choice is timed, so nothing else expires. */
    fun enforceRemember() {
        backend.sweepVaultKeys()
    }

    /** The background auto-lock: keys, open vault pages and decrypted text, but not opened copies. */
    fun lockForBackground() {
        backend.lock()
        unlocked = false
        lockVaultPage()
        clearDecryptedMessage()
    }

    // --- The background lock's timing ---------------------------------------
    // Here rather than in the activity, so that one instance can cancel the timer
    // another posted (a rotation while away makes a new activity).

    private val lockHandler = Handler(Looper.getMainLooper())
    private val backgroundLock = Runnable { lockForBackground() }

    /** When the app went to the background (SystemClock.elapsedRealtime), or 0 while it's in front. */
    private var backgroundSince = 0L

    /** The app went to the background: lock once it has been away [BACKGROUND_LOCK_MS]. */
    fun wentToBackground() {
        backgroundSince = SystemClock.elapsedRealtime()
        lockHandler.removeCallbacks(backgroundLock)
        lockHandler.postDelayed(backgroundLock, BACKGROUND_LOCK_MS)
    }

    /**
     * Back in front: cancel the timer, and lock now if the time away has run out
     * whether or not it fired (see [backgroundLockDue]).
     */
    fun cameToForeground() {
        lockHandler.removeCallbacks(backgroundLock)
        val since = backgroundSince
        backgroundSince = 0L
        if (backgroundLockDue(since, SystemClock.elapsedRealtime())) lockForBackground()
    }

    override fun onCleared() {
        lockHandler.removeCallbacks(backgroundLock)
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

    fun offerShareMany(uris: List<Uri>) {
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
