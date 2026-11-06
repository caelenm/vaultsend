package org.vaultsend

import android.content.Intent
import android.net.Uri
import android.os.Build
import android.os.Bundle
import android.view.WindowManager
import android.view.inputmethod.EditorInfo
import android.view.inputmethod.InputConnection
import android.widget.Toast
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.activity.enableEdgeToEdge
import androidx.activity.viewModels
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.ui.ExperimentalComposeUiApi
import androidx.compose.ui.platform.InterceptPlatformTextInput
import androidx.compose.ui.platform.PlatformTextInputMethodRequest
import androidx.core.content.IntentCompat
import org.vaultsend.ui.App
import org.vaultsend.ui.AppViewModel
import org.vaultsend.ui.VaultSendTheme

class MainActivity : ComponentActivity() {

    // Same Activity-scoped instance that App() resolves via viewModel(), so a
    // share intent handled here is visible to the composables. It also owns the
    // background lock's timer, so a recreated activity can cancel one an earlier
    // instance posted.
    private val vm: AppViewModel by viewModels()

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
        // and must not be re-applied. (Copies and staging a killed run left behind
        // are swept when the view model is made, which is once per process.)
        if (savedInstanceState == null) {
            handleShareIntent(intent)
        }

        setContent {
            // Below API 33 the thumbnail can't be turned off on its own, so the window
            // is made secure while it shows decrypted text or an unlocked vault's list.
            if (Build.VERSION.SDK_INT < Build.VERSION_CODES.TIRAMISU) {
                val secret = vm.messageIsDecrypted || vm.vaultPage != null
                LaunchedEffect(secret) {
                    if (secret) {
                        window.addFlags(WindowManager.LayoutParams.FLAG_SECURE)
                    } else {
                        window.clearFlags(WindowManager.LayoutParams.FLAG_SECURE)
                    }
                }
            }
            VaultSendTheme {
                NoPersonalizedLearning {
                    App(vm)
                }
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
            Intent.ACTION_SEND_MULTIPLE -> {
                // Several files at once only make sense for a vault: added to the open one.
                val uris = IntentCompat.getParcelableArrayListExtra(intent, Intent.EXTRA_STREAM, Uri::class.java)
                    ?: return
                val accepted = uris.filter { accept(it) }
                if (accepted.size < uris.size) refused()
                if (accepted.isNotEmpty()) vm.offerShareMany(accepted)
            }
            Intent.ACTION_SEND -> {
                val uri = IntentCompat.getParcelableExtra(intent, Intent.EXTRA_STREAM, Uri::class.java)
                if (uri != null) {
                    if (accept(uri)) vm.setPendingShare(uri, null) else refused()
                } else {
                    val text = intent.getStringExtra(Intent.EXTRA_TEXT)
                    if (!text.isNullOrEmpty()) vm.setPendingShare(null, text)
                }
            }
            Intent.ACTION_VIEW -> {
                intent.data?.let { if (accept(it)) vm.setPendingShare(it, null) else refused() }
            }
        }
    }

    /**
     * Only content:// URIs are accepted from other apps, and none that only
     * VaultSend's own access reaches (see [refuseIncoming]). A URI is opened with
     * this app's permissions, not the sender's: a file:// URI could name
     * identity.age, a URI to this app's FileProvider an opened copy, and one inside
     * a folder VaultSend was granted (a vault's, and the folder it was made in) any
     * file there, none of which the sender could read itself.
     */
    private fun accept(uri: Uri): Boolean {
        val grants = runCatching { contentResolver.persistedUriPermissions.map { it.uri.parts() } }
            // If the grants can't be read, nothing can be told apart: refuse.
            .getOrElse { return false }
        return !refuseIncoming(uri.parts(), "$packageName.open", grants)
    }

    private fun Uri.parts() = UriParts(scheme, authority, pathSegments)

    private fun refused() {
        Toast.makeText(
            this,
            "VaultSend didn't open that: another app can't hand it a file in a folder it has access to. " +
                "Use Open file… in VaultSend instead.",
            Toast.LENGTH_LONG,
        ).show()
    }

    override fun onStart() {
        super.onStart()
        vm.cameToForeground()
    }

    override fun onStop() {
        super.onStop()
        if (!isChangingConfigurations) vm.wentToBackground()
    }

    override fun onDestroy() {
        super.onDestroy()
        // Drop the in-memory session key when the app is actually closing. Guard
        // on isFinishing so a configuration change (e.g. rotation) doesn't lock
        // the session — the native key is process-global and survives rotation.
        // Lock now: the key, remembered vault keys, decrypted text and every opened
        // copy. (The view model is cleared next, which cancels the background timer.)
        if (isFinishing) {
            vm.lockSession()
        }
    }
}

/**
 * Asks the keyboard not to learn from anything typed or shown in `content`'s text
 * fields (IME_FLAG_NO_PERSONALIZED_LEARNING, which Gboard and others honour as
 * incognito): decrypted messages, and the plaintext typed to encrypt, would
 * otherwise feed its suggestions and personal dictionary. Compose has no
 * KeyboardOptions for it, so the request each field makes is amended on its way.
 */
@OptIn(ExperimentalComposeUiApi::class)
@Composable
private fun NoPersonalizedLearning(content: @Composable () -> Unit) {
    InterceptPlatformTextInput(
        interceptor = { request, nextHandler ->
            val noLearning = object : PlatformTextInputMethodRequest {
                override fun createInputConnection(outAttributes: EditorInfo): InputConnection {
                    val connection = request.createInputConnection(outAttributes)
                    outAttributes.imeOptions = outAttributes.imeOptions or EditorInfo.IME_FLAG_NO_PERSONALIZED_LEARNING
                    return connection
                }
            }
            nextHandler.startInputMethod(noLearning)
        },
        content = content,
    )
}
