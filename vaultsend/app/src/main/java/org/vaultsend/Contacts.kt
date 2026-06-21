package org.vaultsend

import android.content.Context
import org.json.JSONArray
import org.json.JSONObject
import java.io.File

/** A saved recipient: a display name and their "age1…" public key. */
data class Contact(val name: String, val pubkey: String)

/**
 * Loads and saves contacts as JSON in the app's private storage, in the same
 * `[{ "name", "pubkey" }]` shape the desktop app uses, so a contacts.json can be
 * moved between the two. Contacts never reach the crypto core.
 */
class ContactStore(context: Context) {
    private val file = File(context.filesDir, "contacts.json")

    fun load(): List<Contact> {
        if (!file.exists()) return emptyList()
        return runCatching {
            val arr = JSONArray(file.readText())
            buildList {
                for (i in 0 until arr.length()) {
                    val o = arr.getJSONObject(i)
                    val name = o.optString("name").trim()
                    val pubkey = o.optString("pubkey").trim()
                    if (name.isNotEmpty() && pubkey.isNotEmpty()) add(Contact(name, pubkey))
                }
            }
        }.getOrDefault(emptyList())
    }

    fun save(contacts: List<Contact>) {
        val arr = JSONArray()
        for (c in contacts) {
            arr.put(JSONObject().put("name", c.name).put("pubkey", c.pubkey))
        }
        // Write to a temp file then rename, so contacts.json is never half-written.
        val tmp = File(file.parentFile, "contacts.json.tmp")
        tmp.writeText(arr.toString(2))
        if (!tmp.renameTo(file)) {
            file.writeText(arr.toString(2))
            tmp.delete()
        }
    }
}

/**
 * A cheap sanity check on a public key before saving it, mirroring the desktop
 * `looks_like_pubkey`: starts with "age1", a plausible length, and otherwise
 * alphanumeric (bech32). Not a cryptographic check — the core rejects truly
 * invalid keys at encrypt time — just enough to catch a bad paste.
 */
fun looksLikePubkey(value: String): Boolean {
    val s = value.trim()
    return s.startsWith("age1") &&
        s.length in 50..80 &&
        s.drop(4).all { it.isLetterOrDigit() }
}

/** Shorten a key for display: first 12 + "…" + last 6, like the desktop `short`. */
fun shortKey(pubkey: String): String =
    if (pubkey.length > 24) pubkey.take(12) + "…" + pubkey.takeLast(6) else pubkey
