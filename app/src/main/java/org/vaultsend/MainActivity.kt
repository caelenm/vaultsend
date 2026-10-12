package org.vaultsend

import android.content.ContentResolver
import android.content.Intent
import android.net.Uri
import android.os.Build
import android.os.Bundle
import android.os.Handler
import android.os.Looper
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.activity.enableEdgeToEdge
import androidx.activity.viewModels
import androidx.core.content.IntentCompat
import org.vaultsend.ui.App
import org.vaultsend.ui.AppViewModel
import org.vaultsend.ui.VaultSendTheme

class MainActivity : ComponentActivity() {

    // Same Activity-scoped instance that App() resolves via viewModel(), so a
    // share intent handled here is visible to the composables.
    private val vm: AppViewModel by viewModels()

    // Locks the session once the app has been in the background for a while, so
    // an unlocked key doesn't stay resident for as long as Android keeps the
    // process alive (onDestroy is not called when the app is swiped away or
    // simply left in the background). Long enough to survive a trip through the
    // system file picker, which also puts this activity in the background.
    private val lockHandler = Handler(Looper.getMainLooper())
    private val backgroundLock = Runnable { vm.lockSession() }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        enableEdgeToEdge()

        // Keep decrypted text out of the recent-apps thumbnail (API 33+). Unlike
        // FLAG_SECURE this still allows deliberate screenshots, e.g. of a public key.
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
            setRecentsScreenshotEnabled(false)
        }

        // Handle a share/"open with" intent only on a fresh start; on rotation
        // (savedInstanceState != null) the pending content is already in the VM
        // and must not be re-applied.
        if (savedInstanceState == null) handleShareIntent(intent)

        setContent {
            VaultSendTheme {
                App(vm)
            }
        }
    }

    // Delivered when the app is already running (launchMode="singleTask") and the
    // user shares something else into it.
    override fun onNewIntent(intent: Intent) {
        super.onNewIntent(intent)
        setIntent(intent)
        handleShareIntent(intent)
    }

    /**
     * Turn an incoming ACTION_SEND (share sheet) or ACTION_VIEW ("open with")
     * intent into pending content on the view model. A shared file becomes a
     * file URI routed to the encrypt/decrypt chooser; shared plain text drops
     * into the message box. The normal MAIN/LAUNCHER intent has no matching
     * action and is ignored.
     */
    private fun handleShareIntent(intent: Intent?) {
        if (intent == null) return
        when (intent.action) {
            Intent.ACTION_SEND -> {
                val uri = IntentCompat.getParcelableExtra(intent, Intent.EXTRA_STREAM, Uri::class.java)
                if (uri != null) {
                    if (isContentUri(uri)) vm.setPendingShare(uri, null)
                } else {
                    val text = intent.getStringExtra(Intent.EXTRA_TEXT)
                    if (!text.isNullOrEmpty()) vm.setPendingShare(null, text)
                }
            }
            Intent.ACTION_VIEW -> {
                intent.data?.let { if (isContentUri(it)) vm.setPendingShare(it, null) }
            }
        }
    }

    /**
     * Only content:// URIs are accepted from other apps. A file:// URI is opened
     * with this app's own permissions, so another app could name a file in our
     * private storage (identity.age, contacts.json) and have the user encrypt it
     * out to a location of their choosing.
     */
    private fun isContentUri(uri: Uri): Boolean = uri.scheme == ContentResolver.SCHEME_CONTENT

    override fun onStart() {
        super.onStart()
        lockHandler.removeCallbacks(backgroundLock)
    }

    override fun onStop() {
        super.onStop()
        if (!isChangingConfigurations) {
            lockHandler.removeCallbacks(backgroundLock)
            lockHandler.postDelayed(backgroundLock, BACKGROUND_LOCK_MS)
        }
    }

    override fun onDestroy() {
        super.onDestroy()
        // Drop the in-memory session key when the app is actually closing. Guard
        // on isFinishing so a configuration change (e.g. rotation) doesn't lock
        // the session — the native key is process-global and survives rotation.
        if (isFinishing) {
            lockHandler.removeCallbacks(backgroundLock)
            vm.backend.lock()
        }
    }

    private companion object {
        const val BACKGROUND_LOCK_MS = 2 * 60 * 1000L
    }
}
