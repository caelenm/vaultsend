// Versions are pinned to a known-consistent set. Android Studio will offer
// updates; bump them together (AGP/Kotlin/Compose move in lockstep).
plugins {
    id("com.android.application") version "8.2.2" apply false
    id("org.jetbrains.kotlin.android") version "2.0.20" apply false
    id("org.jetbrains.kotlin.plugin.compose") version "2.0.20" apply false
}
