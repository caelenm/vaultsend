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
