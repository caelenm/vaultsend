package org.vaultsend

import android.content.Intent
import android.net.Uri
import android.os.Bundle
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

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        enableEdgeToEdge()

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
                    vm.setPendingShare(uri, null)
                } else {
                    val text = intent.getStringExtra(Intent.EXTRA_TEXT)
                    if (!text.isNullOrEmpty()) vm.setPendingShare(null, text)
                }
            }
            Intent.ACTION_VIEW -> {
                intent.data?.let { vm.setPendingShare(it, null) }
            }
        }
    }

    override fun onDestroy() {
        super.onDestroy()
        // Drop the in-memory session key when the app is actually closing. Guard
        // on isFinishing so a configuration change (e.g. rotation) doesn't lock
        // the session — the native key is process-global and survives rotation.
        if (isFinishing) vm.backend.lock()
    }
}
