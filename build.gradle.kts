// Versions are pinned to a known-consistent set: AGP 8.9 supports compileSdk 35
// and needs Gradle 8.11.1+ (the wrapper pins 8.13). Android Studio will offer
// updates; bump them together (AGP/Kotlin/Compose move in lockstep), along with
// the wrapper's distributionUrl and distributionSha256Sum.
plugins {
    id("com.android.application") version "8.9.0" apply false
    id("org.jetbrains.kotlin.android") version "2.1.10" apply false
    id("org.jetbrains.kotlin.plugin.compose") version "2.1.10" apply false
}
