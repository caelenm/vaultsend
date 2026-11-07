package org.vaultsend

import android.content.Context
import org.json.JSONArray
import org.json.JSONObject
import java.io.InputStream
import java.io.OutputStream
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
        return runCatching { parseContacts(file.readText()) }.getOrDefault(emptyList())
    }

    /** Never half-written, and readable by this app alone (see [savePrivately]). */
    fun save(contacts: List<Contact>) = savePrivately(file, serializeContacts(contacts))
}

/**
 * Parse a contacts.json payload into validated [Contact]s, mirroring the lenient
 * `ContactStore.load` behaviour: entries with a blank name or pubkey are dropped.
 * Throws if the text isn't a JSON array at all (so the caller can report a bad file).
 */
fun parseContacts(text: String): List<Contact> {
    val arr = JSONArray(text)
    return buildList {
        for (i in 0 until arr.length()) {
            val o = arr.optJSONObject(i) ?: continue
            val name = o.optString("name").trim()
            val pubkey = o.optString("pubkey").trim()
            if (name.isNotEmpty() && pubkey.isNotEmpty()) add(Contact(name, pubkey))
        }
    }
}

/** Serialize contacts to the desktop-compatible `[{ "name", "pubkey" }]` JSON. */
fun serializeContacts(contacts: List<Contact>): String {
    val arr = JSONArray()
    for (c in contacts) {
        arr.put(JSONObject().put("name", c.name).put("pubkey", c.pubkey))
    }
    return arr.toString(2)
}

/** Read and validate contacts from an arbitrary stream (e.g. a picked file). */
fun readContacts(input: InputStream): List<Contact> =
    parseContacts(input.readBytes().toString(Charsets.UTF_8))

/** Write contacts to an arbitrary stream (e.g. a "save as" destination). */
fun writeContacts(out: OutputStream, contacts: List<Contact>) {
    out.write(serializeContacts(contacts).toByteArray(Charsets.UTF_8))
}

/** Shorten a key for display: first 12 + "…" + last 6, like the desktop `short`. */
fun shortKey(pubkey: String): String =
    if (pubkey.length > 24) pubkey.take(12) + "…" + pubkey.takeLast(6) else pubkey
