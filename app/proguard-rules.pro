# The native methods are bound by their fully-qualified JVM names from Rust
# (Java_org_vaultsend_VaultSendNative_*), so this class and its methods must keep
# their names under R8.
-keep class org.vaultsend.VaultSendNative { *; }
-keepclasseswithmembernames class * {
    native <methods>;
}

# Rust raises this by name via JNI ThrowNew("org/vaultsend/BackendException");
# its name and (String) constructor must survive shrinking.
-keep class org.vaultsend.BackendException {
    <init>(java.lang.String);
}

# Vaults: Rust calls these back by method name and JVM signature (ffi.rs,
# SafStore, SafSources and the progress callback), so R8 must keep them.
-keep class org.vaultsend.VaultTree { public *; }
-keep class org.vaultsend.VaultSources { public int openSource(int); }
-keep interface org.vaultsend.ProgressSink { *; }
-keep class * implements org.vaultsend.ProgressSink { public void report(int); }
