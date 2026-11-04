package org.vaultsend

import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test
import org.json.JSONArray
import java.io.File
import java.nio.file.Files
import java.nio.file.attribute.PosixFilePermission

/*
 * The desktop vaults branch's tests/test_frontend_helpers.py, case for case, for
 * the Kotlin ports in VaultHelpers.kt, Vaults.kt and OpenCopies.kt. Classes there
 * with no counterpart here:
 *   Cache            the remembered secrets live in the native library; vault.rs's
 *                    a_password_vault_key_is_remembered_only_as_long_as_asked
 *   ProgressReports  progress arrives as an int, so there's no pipe text to parse
 *   OpenedCopies' RAM checks and file_stamp: Android has no RAM folder to look for,
 *                    and an opened copy can't be edited (see OpenCopies.kt)
 */
class VaultHelpersTest {
    private lateinit var dir: File

    @Before
    fun setUp() {
        dir = Files.createTempDirectory("vaultsend-helpers-test-").toFile()
    }

    @After
    fun tearDown() {
        deleteTree(dir)
    }

    // --- Registry ----------------------------------------------------------

    private val good = VaultRecord("A", "content://tree/a", "password", 3)

    @Test
    fun registryRoundTrip() {
        val store = VaultStore(dir)
        store.saveVaults(listOf(good))
        assertEquals(listOf(good), store.loadVaults())
        assertFalse(File(dir, "vaults.json.tmp").exists())
    }

    @Test
    fun registryMissingFile() {
        assertEquals(emptyList<VaultRecord>(), VaultStore(dir).loadVaults())
    }

    @Test
    fun registryGarbledFiles() {
        for (text in listOf("{not json", "", "null", """{"name": "x"}""", "42", "\"text\"")) {
            assertEquals(text, emptyList<VaultRecord>(), parseVaults(text))
        }
    }

    @Test
    fun registryBadEntriesAreDroppedNotFatal() {
        val text = """["str", 1, null, {"name": "x"}, {"uri": "/p"}, {"name": 1, "uri": "/p"},
            {"name": "A", "uri": "content://tree/a", "mode": "password", "last_generation": 3}]"""
        assertEquals(listOf(good), parseVaults(text))
    }

    @Test
    fun registryBadFieldsGetSafeDefaults() {
        for (generation in listOf("-1", "\"7\"", "1.5", "true", "null")) {
            val text = """[{"name": "x", "uri": "/p", "mode": "odd", "last_generation": $generation}]"""
            assertEquals(generation, listOf(VaultRecord("x", "/p", "self", 0)), parseVaults(text))
        }
    }

    @Test
    fun registryUnknownFieldsAreDropped() {
        val text = """[{"name": "x", "uri": "/p", "mode": "self", "last_generation": 2, "key_sha256": "ab"}]"""
        assertEquals(listOf(VaultRecord("x", "/p", "self", 2)), parseVaults(text))
        assertFalse(serializeVaults(parseVaults(text)).contains("key_sha256"))
    }

    @Test
    fun savedFilesArePrivate() {
        val store = VaultStore(dir)
        val saves = listOf(
            File(dir, "vaults.json") to { store.saveVaults(emptyList()) },
            File(dir, "settings.json") to { store.saveSettings(AppSettings()) },
            File(dir, "contacts.json") to { savePrivately(File(dir, "contacts.json"), "[]") },
        )
        for ((file, save) in saves) {
            save()
            assertEquals(file.name, ownerOnly, perms(file))
            // Neither an older, wider file nor a temp file left by a crash passes its mode on.
            Files.setPosixFilePermissions(file.toPath(), wide)
            val tmp = File(dir, file.name + ".tmp")
            tmp.writeText("left by a crash")
            Files.setPosixFilePermissions(tmp.toPath(), wide)
            save()
            assertEquals(file.name, ownerOnly, perms(file))
            assertFalse(tmp.exists())
        }
    }

    private val ownerOnly = setOf(PosixFilePermission.OWNER_READ, PosixFilePermission.OWNER_WRITE)
    private val wide = ownerOnly + PosixFilePermission.GROUP_READ + PosixFilePermission.OTHERS_READ
    private fun perms(f: File) = Files.getPosixFilePermissions(f.toPath())

    // --- Settings ----------------------------------------------------------

    @Test
    fun settingsDefaults() {
        assertEquals(AppSettings("session", cacheExplained = false, openExplained = false), VaultStore(dir).loadSettings())
    }

    @Test
    fun settingsRoundTrip() {
        val value = AppSettings("off", cacheExplained = true, openExplained = true)
        VaultStore(dir).saveSettings(value)
        assertEquals(value, VaultStore(dir).loadSettings())
    }

    @Test
    fun settingsFromBeforeOpenExistedStillWarn() {
        assertFalse(parseSettings("""{"remember": "off", "cache_explained": true}""").openExplained)
    }

    @Test
    fun settingsGarbled() {
        for (text in listOf("{not json", "[]", "null", """{"remember": "forever"}""", """{"remember": "5m"}""", """{"remember": "1w"}""", """{"remember": ["5m"]}""", """{"remember": 5}""")) {
            assertEquals(text, AppSettings(), parseSettings(text))
        }
    }

    @Test
    fun onlyTrueCountsAsExplained() {
        assertFalse(parseSettings("""{"cache_explained": "yes"}""").cacheExplained)
    }

    @Test
    fun everyChoiceHasALifetime() {
        assertEquals(0L, REMEMBER_SECONDS["off"])
        assertNull(REMEMBER_SECONDS["session"])
        assertTrue("session" in REMEMBER_SECONDS)
        assertEquals(
            listOf("Off", "Until VaultSend closes"),
            REMEMBER_CHOICES.map { it.label },
        )
    }

    // --- Names -------------------------------------------------------------

    @Test
    fun validNames() {
        for (name in listOf("a", "My Vault", "ünï ☃", "a.b", "..x", "-x", "x".repeat(247))) {
            assertTrue(name, isValidVaultName(name))
        }
    }

    @Test
    fun invalidNames() {
        for (name in listOf("", ".", "..", "a/b", "/", "a\u0000b", "x".repeat(248))) {
            assertFalse(name, isValidVaultName(name))
        }
    }

    @Test
    fun shortPaths() {
        val home = "/home/me"
        assertEquals("~/x.vsvault", shortPath("$home/x.vsvault", home))
        assertEquals("~/…/x.vsvault", shortPath("$home/a/b/c/x.vsvault", home))
        assertEquals("/…/x.vsvault", shortPath("/mnt/data/deep/x.vsvault", home))
        assertEquals("/x.vsvault", shortPath("/x.vsvault", home))
        assertEquals("/…/x.vsvault", shortPath("${home}er/x.vsvault", home))
    }

    @Test
    fun entryIndentFollowsDepth() {
        assertEquals(0, entryIndent("top"))
        assertEquals(INDENT_STEP, entryIndent("a/b"))
        assertEquals(2 * INDENT_STEP, entryIndent("a/b/c.txt"))
    }

    @Test
    fun entryIndentIsCapped() {
        val most = INDENT_LEVELS * INDENT_STEP
        assertEquals(most, entryIndent("a/".repeat(INDENT_LEVELS) + "x"))
        assertEquals(most, entryIndent("a/".repeat(INDENT_LEVELS + 1) + "x"))
        assertEquals(most, entryIndent("a/".repeat(1000) + "x"))
    }

    // --- Selection ---------------------------------------------------------

    private val entries = linkedMapOf(
        "a" to VaultEntry("a", true, 0), "a/1.txt" to VaultEntry("a/1.txt", false, 1),
        "a/b" to VaultEntry("a/b", true, 0), "a/b/2.txt" to VaultEntry("a/b/2.txt", false, 1),
        "ab.txt" to VaultEntry("ab.txt", false, 1), "empty" to VaultEntry("empty", true, 0),
    )

    @Test
    fun parentFolderList() {
        assertEquals(emptyList<String>(), parentFolders("top"))
        assertEquals(listOf("a", "a/b"), parentFolders("a/b/c"))
    }

    @Test
    fun aFolderCoversWhatIsInIt() {
        assertEquals(listOf("a", "ab.txt"), topLevelSelection(listOf("a", "a/1.txt", "a/b", "a/b/2.txt", "ab.txt")))
    }

    @Test
    fun aSimilarNameIsNotInside() {
        assertEquals(listOf("a", "ab.txt"), topLevelSelection(listOf("a", "ab.txt")))
    }

    @Test
    fun theWholeVaultCoversEverything() {
        assertEquals(listOf(ROOT_ENTRY), topLevelSelection(listOf("a", ROOT_ENTRY)))
    }

    @Test
    fun nothingSelected() {
        assertEquals(emptyList<String>(), topLevelSelection(emptyList()))
    }

    @Test
    fun filesInASelection() {
        fun files(vararg selection: String) = filesInSelection(selection.toList(), entries)
        assertEquals(listOf("a/1.txt", "a/b/2.txt"), files("a"))
        assertEquals(listOf("a/b/2.txt", "ab.txt"), files("a/b", "ab.txt"))
        assertEquals(listOf("a/1.txt", "a/b/2.txt", "ab.txt"), files(ROOT_ENTRY))
        assertEquals(emptyList<String>(), files("empty"))
    }

    @Test
    fun shareNames() {
        fun name(vararg selection: String) = shareFileName("V", selection.toList(), entries)
        assertEquals("1.txt.age", name("a/1.txt"))
        assertEquals("b.tar.age", name("a/b"))
        assertEquals("V.tar.age", name(ROOT_ENTRY))
        assertEquals("V selection.tar.age", name("a/1.txt", "ab.txt"))
    }

    @Test
    fun vaultNameFromAPath() {
        assertEquals("My Vault", vaultNameFromPath("/x/My Vault.vsvault"))
        assertEquals("My Vault", vaultNameFromPath("/x/My Vault.vsvault/"))
        assertEquals("plain", vaultNameFromPath("/x/plain"))
    }

    // --- Listing -----------------------------------------------------------

    @Test
    fun listingUnescapesForDisplay() {
        val (generation, list) = parseListing(
            "generation 7\n" +
                "D a%20b\n" +
                "F 12 a%20b/%C3%BCn%C3%AF%25.txt\n" +
                "F 0 new%0Aline\n",
        )
        assertEquals(7L, generation)
        assertEquals(
            listOf(
                VaultEntry("a b", true, 0),
                VaultEntry("a b/ünï%.txt", false, 12),
                VaultEntry("new\nline", false, 0),
            ),
            list,
        )
    }

    @Test
    fun listingOfAnEmptyVault() {
        assertEquals(0L to emptyList<VaultEntry>(), parseListing("generation 0\n"))
    }

    @Test
    fun listingIsFolderByFolderFoldersFirst() {
        val text = "generation 1\nF 1 Zebra\nD apple\nF 1 apple/z\nD apple/sub\nF 1 apple/sub/x\nD Banana\nF 1 cherry\n"
        assertEquals(
            listOf("apple", "apple/sub", "apple/sub/x", "apple/z", "Banana", "cherry", "Zebra"),
            parseListing(text).second.map { it.path },
        )
    }

    @Test
    fun everyParentComesBeforeItsContents() {
        // The manifest's byte order would put "a b" between "a" and "a/c".
        val text = "generation 1\nD a\nD a b\nF 1 a b/x\nF 1 a/c\n"
        val seen = mutableSetOf<String>()
        for (e in parseListing(text).second) {
            val parent = e.path.substringBeforeLast('/', "")
            assertTrue(e.toString(), parent == "" || parent in seen)
            seen += e.path
        }
    }

    @Test
    fun aGarbledGenerationThrows() {
        for (text in listOf("", "nonsense\n", "generation x\n")) {
            assertThrows(text, IllegalArgumentException::class.java) { parseListing(text) }
        }
    }

    // --- Opened copies -----------------------------------------------------

    @Test
    fun clearingLeftoversTouchesOnlyOurFolders() {
        val ours = File(dir, "${OPEN_PREFIX}abc").apply { mkdir() }
        File(ours, "secret.txt").writeText("left by a crash")
        val other = File(dir, "someone-elses").apply { mkdir() }
        File(other, "keep.txt").writeText("keep")
        val aFile = File(dir, "${OPEN_PREFIX}a-file").apply { writeText("keep") }
        val link = File(dir, "${OPEN_PREFIX}a-link")
        Files.createSymbolicLink(link.toPath(), other.toPath())
        clearStaleCopies(dir)
        assertFalse(ours.exists())
        assertEquals("keep", File(other, "keep.txt").readText())
        assertTrue(aFile.exists())
        assertTrue(Files.isSymbolicLink(link.toPath()))
        clearStaleCopies(File(dir, "no-such-folder"))
    }

    @Test
    fun aCopyFolderIsPrivateAndUnguessable() {
        val one = newCopyFolder(File(dir, OPEN_DIR))
        val two = newCopyFolder(File(dir, OPEN_DIR))
        assertTrue(one.name.startsWith(OPEN_PREFIX) && one.name.length >= OPEN_PREFIX.length + 24)
        assertTrue(one != two)
        assertEquals(
            setOf(PosixFilePermission.OWNER_READ, PosixFilePermission.OWNER_WRITE, PosixFilePermission.OWNER_EXECUTE),
            perms(one),
        )
    }

    // --- Vault files -------------------------------------------------------

    @Test
    fun vaultMode() {
        assertNull(readVaultMode(null))
        assertEquals("self", readVaultMode("vaultsend-vault 1\nmode self\n"))
        assertEquals("password", readVaultMode("vaultsend-vault 1\nmode password\n"))
        for (bad in listOf("", "vaultsend-vault 2\nmode self\n", "vaultsend-vault 1\nmode other\n", "vaultsend-vault 1\nmode self")) {
            assertNull(bad, readVaultMode(bad))
        }
        assertNull(readVaultMode(String(byteArrayOf(0xff.toByte(), 0xfe.toByte()), Charsets.UTF_8)))
    }

    // --- Small display helpers (not on desktop, which used GLib) -----------

    @Test
    fun countsReadNaturally() {
        assertEquals("1 file", countOf(1, "file"))
        assertEquals("3 files", countOf(3, "file"))
        assertEquals("0 files", countOf(0, "file"))
    }

    @Test
    fun sizesReadNaturally() {
        assertEquals("1 byte", humanSize(1))
        assertEquals("1023 bytes", humanSize(1023))
        assertEquals("1.0 KB", humanSize(1024))
        assertEquals("15 MB", humanSize(15L * 1024 * 1024))
    }

    @Test
    fun serializedRegistryIsJson() {
        assertEquals(1, JSONArray(serializeVaults(listOf(good))).length())
    }

    // --- The vault page's selection (the GUI run-through's selection checks) ---

    private val page = VaultSelection().withEntries(entries.values.toList())

    @Test
    fun nothingIsSelectedToBeginWith() {
        assertEquals(emptyList<String>(), page.chosen())
        assertEquals("Files · 3 files, 3 bytes", page.summary())
    }

    @Test
    fun oneRowAtATime() {
        assertEquals(listOf("a/1.txt"), page.select("a/1.txt").chosen())
        assertEquals(listOf("ab.txt"), page.select("a/1.txt").select("ab.txt").chosen())
    }

    @Test
    fun tickingAFolderTicksWhatIsInItAndUntickingInsideUnticksTheFoldersAbove() {
        val ticked = page.withMultiple(true).tick("a", true)
        assertEquals(setOf("a", "a/1.txt", "a/b", "a/b/2.txt"), ticked.ticked)
        assertEquals(listOf("a"), ticked.chosen())
        val partly = ticked.tick("a/b/2.txt", false)
        assertEquals(setOf("a/1.txt"), partly.ticked)
        assertEquals("Files · 1 selected", partly.summary())
    }

    @Test
    fun everyRowTickedIsTheWholeVault() {
        var s = page.withMultiple(true)
        for (path in entries.keys) s = s.tick(path, true)
        assertEquals(listOf(ROOT_ENTRY), s.chosen())
        assertEquals("Files · all selected", s.summary())
    }

    @Test
    fun selectAllTakesTheTickBoxesAndThenSelectsNone() {
        val all = page.select("ab.txt").selectAll()
        assertTrue(all.multiple)
        assertEquals(listOf(ROOT_ENTRY), all.chosen())
        val none = all.selectAll()
        assertTrue(none.multiple)
        assertEquals(emptyList<String>(), none.chosen())
        assertEquals(emptyList<String>(), VaultSelection().selectAll().chosen())
    }

    @Test
    fun turningMultipleOnCarriesTheChoiceAndOffClearsIt() {
        val on = page.select("a/b").withMultiple(true)
        assertEquals(setOf("a/b", "a/b/2.txt"), on.ticked)
        assertEquals(listOf("a/b"), on.chosen())
        assertEquals(emptyList<String>(), on.withMultiple(false).chosen())
    }

    @Test
    fun closingAFolderClearsWhatItHides() {
        val open = page.toggleExpanded("a").toggleExpanded("a/b")
        assertEquals(listOf("a", "a/1.txt", "a/b", "a/b/2.txt", "ab.txt", "empty"), open.visible().map { it.path })
        // One row chosen inside a folder that closes: nothing is chosen.
        assertEquals(emptyList<String>(), open.select("a/b/2.txt").toggleExpanded("a").chosen())
        assertEquals(listOf("a/1.txt"), open.select("a/1.txt").toggleExpanded("a/b").chosen())
        // Ticks inside a folder that closes go, unless the folder itself is ticked.
        val ticked = open.withMultiple(true).tick("a/1.txt", true).tick("ab.txt", true)
        assertEquals(listOf("ab.txt"), ticked.toggleExpanded("a").chosen())
        assertEquals(listOf("a"), open.withMultiple(true).tick("a", true).toggleExpanded("a").chosen())
        assertEquals(listOf("a", "ab.txt", "empty"), page.visible().map { it.path })
    }

    @Test
    fun aNewListingClearsTheSelectionButKeepsFoldersOpen() {
        val before = page.toggleExpanded("a").select("a/1.txt")
        val after = before.withEntries(entries.values.toList())
        assertEquals(emptyList<String>(), after.chosen())
        assertEquals(setOf("a"), after.expanded)
    }
}

