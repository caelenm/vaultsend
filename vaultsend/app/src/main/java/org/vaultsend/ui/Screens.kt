package org.vaultsend.ui

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.CloudUpload
import androidx.compose.material.icons.filled.Lock
import androidx.compose.material3.Button
import androidx.compose.material3.Icon
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.unit.dp

/**
 * The three first-run screens. They are deliberately plain full-screen Columns —
 * no scaffold, no navigation library — so the app stays a single self-contained
 * Activity and the onboarding flow is just a [AppPhase] transition driven from
 * [App].
 */

/** Branded splash shown the very first time the app launches. */
@Composable
fun WelcomeScreen(onContinue: () -> Unit) {
    Surface(modifier = Modifier.fillMaxSize()) {
        Column(
            modifier = Modifier
                .fillMaxSize()
                .padding(horizontal = 32.dp, vertical = 48.dp),
            horizontalAlignment = Alignment.CenterHorizontally,
            verticalArrangement = Arrangement.Center,
        ) {
            Icon(
                Icons.Filled.Lock,
                contentDescription = null,
                modifier = Modifier.size(72.dp),
                tint = MaterialTheme.colorScheme.primary,
            )
            Spacer(Modifier.size(24.dp))
            Text(
                "Welcome to VaultSend",
                style = MaterialTheme.typography.headlineMedium,
                textAlign = TextAlign.Center,
            )
            Spacer(Modifier.size(12.dp))
            Text(
                "Private, end-to-end encryption for your messages and files, " +
                    "built on the open age format.",
                style = MaterialTheme.typography.bodyLarge,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
                textAlign = TextAlign.Center,
            )
            Spacer(Modifier.size(40.dp))
            Button(onClick = onContinue, modifier = Modifier.fillMaxWidth()) {
                Text("Get started")
            }
        }
    }
}

/**
 * Short explainer plus the two entry points: create a fresh keypair, or import an
 * existing identity.age (e.g. a backup, or one made on the desktop app).
 */
@Composable
fun IntroScreen(onGenerate: () -> Unit, onImport: () -> Unit) {
    Surface(modifier = Modifier.fillMaxSize()) {
        Column(
            modifier = Modifier
                .fillMaxSize()
                .verticalScroll(rememberScrollState())
                .padding(horizontal = 32.dp, vertical = 48.dp),
            verticalArrangement = Arrangement.Center,
        ) {
            Text("How VaultSend works", style = MaterialTheme.typography.headlineSmall)
            Spacer(Modifier.size(16.dp))
            Text(
                "VaultSend encrypts messages and files so that only the people you " +
                    "choose can read them.",
                style = MaterialTheme.typography.bodyLarge,
            )
            Spacer(Modifier.size(16.dp))
            Bullet("You get a keypair: a public key you can share freely, and a private key that never leaves this device, protected by a passphrase.")
            Bullet("Encrypt to anyone using their public key — only they can decrypt it.")
            Bullet("Decrypt anything sent to you with your passphrase. Nothing is ever sent over a network.")
            Spacer(Modifier.size(40.dp))
            Button(onClick = onGenerate, modifier = Modifier.fillMaxWidth()) {
                Text("Generate new keypair")
            }
            Spacer(Modifier.size(12.dp))
            OutlinedButton(onClick = onImport, modifier = Modifier.fillMaxWidth()) {
                Text("Import previous identity.age")
            }
        }
    }
}

@Composable
private fun Bullet(text: String) {
    Column(modifier = Modifier.padding(vertical = 4.dp)) {
        Text(
            "•  $text",
            style = MaterialTheme.typography.bodyMedium,
            color = MaterialTheme.colorScheme.onSurfaceVariant,
        )
    }
}

/**
 * Shown once, immediately after a brand-new key is generated, offering to save a
 * copy of identity.age. Carries the "safe to store in the cloud" reassurance and
 * the critical reminder that both the file and the passphrase are required.
 */
@Composable
fun BackupOfferScreen(onBackUp: () -> Unit, onSkip: () -> Unit) {
    Surface(modifier = Modifier.fillMaxSize()) {
        Column(
            modifier = Modifier
                .fillMaxSize()
                .verticalScroll(rememberScrollState())
                .padding(horizontal = 32.dp, vertical = 48.dp),
            verticalArrangement = Arrangement.Center,
        ) {
            Icon(
                Icons.Filled.CloudUpload,
                contentDescription = null,
                modifier = Modifier.size(56.dp),
                tint = MaterialTheme.colorScheme.primary,
            )
            Spacer(Modifier.size(20.dp))
            Text("Back up your identity", style = MaterialTheme.typography.headlineSmall)
            Spacer(Modifier.size(16.dp))
            Text(
                "Your private key lives in a file called identity.age. Save a copy " +
                    "somewhere safe. It's fine to store it in the cloud, because it is " +
                    "protected by your passphrase.",
                style = MaterialTheme.typography.bodyLarge,
            )
            Spacer(Modifier.size(16.dp))
            Text(
                "You need both your identity.age file and password to decrypt any " +
                    "files secured by your keypair!",
                style = MaterialTheme.typography.bodyMedium,
                fontWeight = FontWeight.SemiBold,
                color = MaterialTheme.colorScheme.primary,
            )
            Spacer(Modifier.size(40.dp))
            Button(onClick = onBackUp, modifier = Modifier.fillMaxWidth()) {
                Text("Back up now")
            }
            Spacer(Modifier.size(8.dp))
            TextButton(onClick = onSkip, modifier = Modifier.fillMaxWidth()) {
                Text("Not now")
            }
        }
    }
}
