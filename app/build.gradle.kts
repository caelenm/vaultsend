import org.gradle.api.tasks.Exec

plugins {
    id("com.android.application")
    id("org.jetbrains.kotlin.android")
    id("org.jetbrains.kotlin.plugin.compose")
}

android {
    namespace = "org.vaultsend"
    compileSdk = 35

    defaultConfig {
        applicationId = "org.vaultsend"
        minSdk = 26
        targetSdk = 35
        versionCode = 3
        versionName = "0.1.2"

        // Device independence: package the native library for every Android ABI
        // into one universal APK, so a single .apk installs on any device.
        ndk {
            abiFilters += listOf("arm64-v8a", "armeabi-v7a", "x86", "x86_64")
        }
    }

    buildTypes {
        release {
            isMinifyEnabled = true
            isShrinkResources = true
            proguardFiles(
                getDefaultProguardFile("proguard-android-optimize.txt"),
                "proguard-rules.pro",
            )
        }
    }

    buildFeatures {
        compose = true
    }

    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }
    kotlinOptions {
        jvmTarget = "17"
    }

    // The .so files are produced by the Rust build (see build-rust.sh) into this
    // directory; this is the default jniLibs location, listed for clarity.
    sourceSets["main"].jniLibs.srcDirs("src/main/jniLibs")

    packaging {
        // The release .so is already stripped by Cargo's release profile.
        jniLibs.useLegacyPackaging = false
    }
}

dependencies {
    val composeBom = platform("androidx.compose:compose-bom:2024.09.03")
    implementation(composeBom)

    implementation("androidx.core:core-ktx:1.13.1")
    implementation("androidx.activity:activity-compose:1.9.2")
    implementation("androidx.lifecycle:lifecycle-viewmodel-compose:2.8.6")

    implementation("androidx.compose.ui:ui")
    implementation("androidx.compose.ui:ui-graphics")
    implementation("androidx.compose.material3:material3")
    implementation("androidx.compose.material:material-icons-extended")

    debugImplementation("androidx.compose.ui:ui-tooling")
    implementation("androidx.compose.ui:ui-tooling-preview")
}

// --- Build the Rust core for all ABIs before the native libs are merged ------
// Requires the Android NDK and cargo-ndk (see README "Build"). Runs the same
// build-rust.sh you can run by hand; wired in so a normal Gradle build is enough.
val buildRust by tasks.registering(Exec::class) {
    workingDir = rootProject.projectDir
    commandLine("bash", "build-rust.sh")
}

tasks.named("preBuild").configure {
    dependsOn(buildRust)
}
