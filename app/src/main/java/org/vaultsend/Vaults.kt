package org.vaultsend

import org.json.JSONArray
import org.json.JSONObject
import org.json.JSONTokener
import java.io.File
import java.nio.file.Files
import java.nio.file.StandardCopyOption
import java.nio.file.attribute.PosixFilePermissions

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

/**
 * Remember passphrase, by saved value, with its menu label: Off (ask every time),
 * or until the app closes. The choice itself is never a secret. A saved timed
 * choice from an older version falls back to the default.
 */
val REMEMBER_CHOICES: Map<String, String> = linkedMapOf(
    "off" to "Off",
    "session" to "Until VaultSend closes",
)

/**
 * The app's settings. `remember` defaults to "session", not the desktop's "off":
 * this app already kept the key unlocked until it closed (or two minutes in the
 * background), and the default keeps that behaviour.
 */
data class AppSettings(
    val remember: String = DEFAULT_REMEMBER,
    val cacheExplained: Boolean = false,
    val openExplained: Boolean = false,
) {
    /** Whether the unlocked key, and a password vault's key, are kept between operations. */
    val remembers: Boolean get() = remember != "off"
}

const val DEFAULT_REMEMBER = "session"

fun parseSettings(text: String): AppSettings {
    val data = runCatching { JSONTokener(text).nextValue() }.getOrNull() as? JSONObject ?: return AppSettings()
    val remember = data.opt("remember")
    return AppSettings(
        remember = if (remember is String && remember in REMEMBER_CHOICES) remember else DEFAULT_REMEMBER,
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
 * by this app alone: the desktop's save_json. The temp file is created 0600, so
 * it is never readable by anyone else, and one left by a crash is replaced
 * rather than reused. Throws rather than ever writing `file` in place.
 */
fun savePrivately(file: File, text: String) {
    val tmp = File(file.parentFile, file.name + ".tmp").toPath()
    Files.deleteIfExists(tmp)
    Files.createFile(tmp, PosixFilePermissions.asFileAttribute(PosixFilePermissions.fromString("rw-------")))
    Files.write(tmp, text.toByteArray(Charsets.UTF_8))
    Files.move(tmp, file.toPath(), StandardCopyOption.ATOMIC_MOVE, StandardCopyOption.REPLACE_EXISTING)
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
