#!/usr/bin/env bash
# Build the Rust core (libvaultsend.so) for every Android ABI and drop the
# results into app/src/main/jniLibs/<abi>/, where Gradle packages them.
#
# Prerequisites (one-time):
#   * Android NDK installed; ANDROID_NDK_HOME (or ANDROID_NDK_ROOT) pointing at it.
#     Android Studio: SDK Manager -> SDK Tools -> "NDK (Side by side)".
#   * cargo-ndk:     cargo install cargo-ndk
#   * Rust targets:  rustup target add \
#                       aarch64-linux-android armv7-linux-androideabi \
#                       i686-linux-android x86_64-linux-android
#
# Gradle runs this automatically (see app/build.gradle.kts), or run it by hand.
set -euo pipefail

cd "$(dirname "$0")/rust"

ABIS=(arm64-v8a armeabi-v7a x86 x86_64)
TARGET_ARGS=()
for abi in "${ABIS[@]}"; do
    TARGET_ARGS+=(-t "$abi")
done

exec cargo ndk "${TARGET_ARGS[@]}" -o ../app/src/main/jniLibs build --release
