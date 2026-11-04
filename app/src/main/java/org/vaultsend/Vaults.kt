package org.vaultsend

import org.json.JSONArray
import org.json.JSONObject
import org.json.JSONTokener
import java.io.File

/*
 * The vault registry and the app's settings: plain JSON in the app's private
 * storage, with no secrets in either, as on desktop (vaults.json, settings.json).
 * The parsing is plain Kotlin so VaultHelpersTest covers it on the JVM.
 */

/**
 * A vault this device knows about. `uri` is the folder's Storage Access Framework
 * tree URI, which stands in for the desktop's path. Besides name and location,
 * each entry remembers the highest generation seen, for spotting a rollback.
 */
data class VaultRecord(
    val name: String,
    val uri: String,
    val mode: String,
    val lastGeneration: Long,
)

fun parseVaults(text: String): List<VaultRecord> {
    val data = runCatching { JSONTokener(text).nextValue() }.getOrNull() as? JSONArray ?: return emptyList()
    return buildList {
        for (i in 0 until data.length()) {
            val v = data.opt(i) as? JSONObject ?: continue
            val name = v.opt("name") as? String ?: continue
            val uri = v.opt("uri") as? String ?: continue
            val generation = when (val g = v.opt("last_generation")) {
                is Int -> g.toLong()
                is Long -> g
                else -> 0L
            }
            add(
                VaultRecord(
                    name = name,
                    uri = uri,
                    mode = if (v.opt("mode") == "password") "password" else "self",
                    lastGeneration = generation.coerceAtLeast(0),
                ),
            )
        }
    }
}

fun serializeVaults(vaults: List<VaultRecord>): String {
    val array = JSONArray()
    for (v in vaults) {
        array.put(
            JSONObject()
                .put("name", v.name)
                .put("uri", v.uri)
                .put("mode", v.mode)
                .put("last_generation", v.lastGeneration),
        )
    }
    return array.toString(2)
}

/** How long a typed secret may be remembered: (value, menu label, seconds). */
data class RememberChoice(val value: String, val label: String, val seconds: Long?)

/** null seconds means until the app closes; the choice itself is never a secret. */
val REMEMBER_CHOICES = listOf(
    RememberChoice("off", "Off", 0),
    RememberChoice("5m", "5 minutes", 5 * 60),
    RememberChoice("20m", "20 minutes", 20 * 60),
    RememberChoice("1d", "1 day", 24 * 60 * 60),
    RememberChoice("1w", "1 week", 7 * 24 * 60 * 60),
    RememberChoice("session", "Until VaultSend closes", null),
)

val REMEMBER_SECONDS: Map<String, Long?> = REMEMBER_CHOICES.associate { it.value to it.seconds }

/**
 * The app's settings. `remember` defaults to "session", not the desktop's "off":
 * this app already kept the key unlocked until it closed (or two minutes in the
 * background), and the default keeps that behaviour.
 */
data class AppSettings(
    val remember: String = DEFAULT_REMEMBER,
    val cacheExplained: Boolean = false,
    val openExplained: Boolean = false,
)

const val DEFAULT_REMEMBER = "session"

fun parseSettings(text: String): AppSettings {
    val data = runCatching { JSONTokener(text).nextValue() }.getOrNull() as? JSONObject ?: return AppSettings()
    val remember = data.opt("remember")
    return AppSettings(
        remember = if (remember is String && remember in REMEMBER_SECONDS) remember else DEFAULT_REMEMBER,
        cacheExplained = data.opt("cache_explained") == true,
        openExplained = data.opt("open_explained") == true,
    )
}

fun serializeSettings(s: AppSettings): String =
    JSONObject()
        .put("remember", s.remember)
        .put("cache_explained", s.cacheExplained)
        .put("open_explained", s.openExplained)
        .toString(2)

/**
 * Write `text` to `file` so it's only ever the old or the new contents, readable
 * by this app alone: the desktop's save_json. A temp file left by a crash is
 * replaced rather than reused.
 */
fun savePrivately(file: File, text: String) {
    val tmp = File(file.parentFile, file.name + ".tmp")
    tmp.delete()
    tmp.writeText(text)
    tmp.setReadable(false, false)
    tmp.setWritable(false, false)
    tmp.setReadable(true, true)
    tmp.setWritable(true, true)
    if (!tmp.renameTo(file)) {
        // As ContactStore always did: a rename in the app's own folder doesn't fail
        // in practice, but if it does, a direct write is better than losing the change.
        tmp.delete()
        file.writeText(text)
        file.setReadable(false, false)
        file.setReadable(true, true)
    }
}

/** The registry and settings files under the app's private storage. */
class VaultStore(dir: File) {
    private val vaultsFile = File(dir, "vaults.json")
    private val settingsFile = File(dir, "settings.json")

    fun loadVaults(): List<VaultRecord> =
        runCatching { parseVaults(vaultsFile.readText()) }.getOrDefault(emptyList())

    fun saveVaults(vaults: List<VaultRecord>) = savePrivately(vaultsFile, serializeVaults(vaults))

    fun loadSettings(): AppSettings =
        runCatching { parseSettings(settingsFile.readText()) }.getOrDefault(AppSettings())

    fun saveSettings(settings: AppSettings) = savePrivately(settingsFile, serializeSettings(settings))
}
