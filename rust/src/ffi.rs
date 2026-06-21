// FFI surface: the JNI entry points the Kotlin UI calls. This is the whole trust
// boundary on Android — the analogue of the desktop frontend's `run_backend()`.
//
// Each function: pulls its arguments out of the JVM, calls one `backend`
// function, and either returns the result or throws `org.vaultsend.BackendException`
// carrying the error message (mirroring the desktop `BackendError`, whose text the
// UI shows verbatim). Errors are caught here at the boundary; we never unwind into
// the JVM.
//
// Passphrases arrive as a byte[] the caller zeroes after the call; we additionally
// zero our own copy here. File data for the file paths arrives as raw file
// descriptors borrowed from the caller's Storage Access Framework
// ParcelFileDescriptors — we wrap them in ManuallyDrop so dropping our File never
// closes a descriptor the Kotlin side still owns and will close itself.

use std::fs::File;
use std::mem::ManuallyDrop;
use std::os::fd::FromRawFd;

use jni::objects::{JByteArray, JClass, JObjectArray, JString};
use jni::sys::{jboolean, jbyteArray, jint, jstring, JNI_FALSE, JNI_TRUE};
use jni::JNIEnv;
use zeroize::Zeroize;

use crate::backend;

const EXCEPTION: &str = "org/vaultsend/BackendException";

// --- argument/return helpers ------------------------------------------------

fn get_string(env: &mut JNIEnv, s: &JString) -> Result<String, String> {
    env.get_string(s)
        .map(|js| js.into())
        .map_err(|e| e.to_string())
}

fn get_bytes(env: &mut JNIEnv, a: &JByteArray) -> Result<Vec<u8>, String> {
    env.convert_byte_array(a).map_err(|e| e.to_string())
}

fn get_string_array(env: &mut JNIEnv, arr: &JObjectArray) -> Result<Vec<String>, String> {
    let len = env.get_array_length(arr).map_err(|e| e.to_string())?;
    let mut out = Vec::with_capacity(len.max(0) as usize);
    for i in 0..len {
        let el = env
            .get_object_array_element(arr, i)
            .map_err(|e| e.to_string())?;
        let s: String = env
            .get_string(&JString::from(el))
            .map(|js| js.into())
            .map_err(|e| e.to_string())?;
        out.push(s);
    }
    Ok(out)
}

fn throw(env: &mut JNIEnv, msg: &str) {
    // If a JNI call already left a pending exception, keep it; otherwise raise ours.
    if !env.exception_check().unwrap_or(false) {
        let _ = env.throw_new(EXCEPTION, msg);
    }
}

fn ret_string(env: &mut JNIEnv, r: Result<String, String>) -> jstring {
    match r {
        Ok(s) => match env.new_string(s) {
            Ok(js) => js.into_raw(),
            Err(_) => std::ptr::null_mut(),
        },
        Err(e) => {
            throw(env, &e);
            std::ptr::null_mut()
        }
    }
}

fn ret_bytes(env: &mut JNIEnv, r: Result<Vec<u8>, String>) -> jbyteArray {
    match r {
        Ok(v) => match env.byte_array_from_slice(&v) {
            Ok(arr) => arr.into_raw(),
            Err(_) => std::ptr::null_mut(),
        },
        Err(e) => {
            throw(env, &e);
            std::ptr::null_mut()
        }
    }
}

/// Borrow a raw fd as a File without taking ownership: ManuallyDrop means dropping
/// it will NOT close the descriptor (the Kotlin ParcelFileDescriptor owns it).
fn borrow_fd(fd: jint) -> ManuallyDrop<File> {
    ManuallyDrop::new(unsafe { File::from_raw_fd(fd) })
}

// --- identity lifecycle -----------------------------------------------------

#[no_mangle]
pub extern "system" fn Java_org_vaultsend_VaultSendNative_keygen<'l>(
    mut env: JNIEnv<'l>,
    _class: JClass<'l>,
    data_dir: JString<'l>,
    passphrase: JByteArray<'l>,
) -> jstring {
    let r = (|| {
        let dir = get_string(&mut env, &data_dir)?;
        let mut pass = get_bytes(&mut env, &passphrase)?;
        let out = backend::keygen(&dir, &pass);
        pass.zeroize();
        out
    })();
    ret_string(&mut env, r)
}

#[no_mangle]
pub extern "system" fn Java_org_vaultsend_VaultSendNative_pubkey<'l>(
    mut env: JNIEnv<'l>,
    _class: JClass<'l>,
    data_dir: JString<'l>,
) -> jstring {
    let r = get_string(&mut env, &data_dir).and_then(|dir| backend::pubkey(&dir));
    ret_string(&mut env, r)
}

#[no_mangle]
pub extern "system" fn Java_org_vaultsend_VaultSendNative_status<'l>(
    mut env: JNIEnv<'l>,
    _class: JClass<'l>,
    data_dir: JString<'l>,
) -> jstring {
    let r = get_string(&mut env, &data_dir).and_then(|dir| backend::status(&dir));
    ret_string(&mut env, r)
}

#[no_mangle]
pub extern "system" fn Java_org_vaultsend_VaultSendNative_recoverPubkey<'l>(
    mut env: JNIEnv<'l>,
    _class: JClass<'l>,
    data_dir: JString<'l>,
    passphrase: JByteArray<'l>,
) -> jstring {
    let r = (|| {
        let dir = get_string(&mut env, &data_dir)?;
        let mut pass = get_bytes(&mut env, &passphrase)?;
        let out = backend::recover_pubkey(&dir, &pass);
        pass.zeroize();
        out
    })();
    ret_string(&mut env, r)
}

// --- session ("unlock once") ------------------------------------------------

/// Verify the passphrase and cache the unlocked key for this session. Returns the
/// public key, or throws on a wrong passphrase. The passphrase byte[] is zeroed
/// here as well as by the caller.
#[no_mangle]
pub extern "system" fn Java_org_vaultsend_VaultSendNative_unlock<'l>(
    mut env: JNIEnv<'l>,
    _class: JClass<'l>,
    data_dir: JString<'l>,
    passphrase: JByteArray<'l>,
) -> jstring {
    let r = (|| {
        let dir = get_string(&mut env, &data_dir)?;
        let mut pass = get_bytes(&mut env, &passphrase)?;
        let out = backend::unlock(&dir, &pass);
        pass.zeroize();
        out
    })();
    ret_string(&mut env, r)
}

/// Drop the cached session key (zeroized). Called on app close and on explicit Lock.
#[no_mangle]
pub extern "system" fn Java_org_vaultsend_VaultSendNative_lock<'l>(
    _env: JNIEnv<'l>,
    _class: JClass<'l>,
) {
    backend::lock();
}

/// True if the session currently holds an unlocked key.
#[no_mangle]
pub extern "system" fn Java_org_vaultsend_VaultSendNative_isUnlocked<'l>(
    _env: JNIEnv<'l>,
    _class: JClass<'l>,
) -> jboolean {
    if backend::is_unlocked() {
        JNI_TRUE
    } else {
        JNI_FALSE
    }
}

/// Import an existing identity.age (read from `in_fd`), verifying it against the
/// passphrase before writing it into place. Returns the public key; unlocks the
/// session on success.
#[no_mangle]
pub extern "system" fn Java_org_vaultsend_VaultSendNative_importIdentity<'l>(
    mut env: JNIEnv<'l>,
    _class: JClass<'l>,
    data_dir: JString<'l>,
    passphrase: JByteArray<'l>,
    in_fd: jint,
) -> jstring {
    let r = (|| {
        let dir = get_string(&mut env, &data_dir)?;
        let mut pass = get_bytes(&mut env, &passphrase)?;
        let mut input = borrow_fd(in_fd);
        let out = backend::import_identity(&dir, &pass, &mut *input);
        pass.zeroize();
        out
    })();
    ret_string(&mut env, r)
}

// --- text (in-memory byte) paths --------------------------------------------

#[no_mangle]
pub extern "system" fn Java_org_vaultsend_VaultSendNative_encryptBytes<'l>(
    mut env: JNIEnv<'l>,
    _class: JClass<'l>,
    recipients: JObjectArray<'l>,
    armor: jboolean,
    input: JByteArray<'l>,
) -> jbyteArray {
    let r = (|| {
        let recips = get_string_array(&mut env, &recipients)?;
        let data = get_bytes(&mut env, &input)?;
        let mut out = Vec::new();
        backend::encrypt(&recips, armor == JNI_TRUE, std::io::Cursor::new(data), &mut out)?;
        Ok(out)
    })();
    ret_bytes(&mut env, r)
}

#[no_mangle]
pub extern "system" fn Java_org_vaultsend_VaultSendNative_decryptBytes<'l>(
    mut env: JNIEnv<'l>,
    _class: JClass<'l>,
    data_dir: JString<'l>,
    passphrase: JByteArray<'l>,
    input: JByteArray<'l>,
) -> jbyteArray {
    let r = (|| {
        let dir = get_string(&mut env, &data_dir)?;
        let mut pass = get_bytes(&mut env, &passphrase)?;
        let data = get_bytes(&mut env, &input)?;
        let mut out = Vec::new();
        let res = backend::decrypt(&dir, &pass, std::io::Cursor::new(data), &mut out);
        pass.zeroize();
        res.map(|()| out)
    })();
    ret_bytes(&mut env, r)
}

/// Decrypt copy/paste text using the unlocked session key (no passphrase).
#[no_mangle]
pub extern "system" fn Java_org_vaultsend_VaultSendNative_decryptBytesSession<'l>(
    mut env: JNIEnv<'l>,
    _class: JClass<'l>,
    input: JByteArray<'l>,
) -> jbyteArray {
    let r = (|| {
        let data = get_bytes(&mut env, &input)?;
        let mut out = Vec::new();
        backend::decrypt_session(std::io::Cursor::new(data), &mut out)?;
        Ok(out)
    })();
    ret_bytes(&mut env, r)
}

// --- file (descriptor) paths ------------------------------------------------

#[no_mangle]
pub extern "system" fn Java_org_vaultsend_VaultSendNative_encryptFd<'l>(
    mut env: JNIEnv<'l>,
    _class: JClass<'l>,
    recipients: JObjectArray<'l>,
    armor: jboolean,
    in_fd: jint,
    out_fd: jint,
) {
    let r = (|| {
        let recips = get_string_array(&mut env, &recipients)?;
        let mut input = borrow_fd(in_fd);
        let mut output = borrow_fd(out_fd);
        backend::encrypt(&recips, armor == JNI_TRUE, &mut *input, &mut *output)
    })();
    if let Err(e) = r {
        throw(&mut env, &e);
    }
}

#[no_mangle]
pub extern "system" fn Java_org_vaultsend_VaultSendNative_decryptFd<'l>(
    mut env: JNIEnv<'l>,
    _class: JClass<'l>,
    data_dir: JString<'l>,
    passphrase: JByteArray<'l>,
    in_fd: jint,
    out_fd: jint,
) {
    let r = (|| {
        let dir = get_string(&mut env, &data_dir)?;
        let mut pass = get_bytes(&mut env, &passphrase)?;
        let mut input = borrow_fd(in_fd);
        let mut output = borrow_fd(out_fd);
        let res = backend::decrypt_file_to(&dir, &pass, &mut *input, &mut *output);
        pass.zeroize();
        res
    })();
    if let Err(e) = r {
        throw(&mut env, &e);
    }
}

/// Decrypt a file using the unlocked session key (no passphrase). Same staged,
/// authenticate-before-write guarantee as the passphrase path.
#[no_mangle]
pub extern "system" fn Java_org_vaultsend_VaultSendNative_decryptFdSession<'l>(
    mut env: JNIEnv<'l>,
    _class: JClass<'l>,
    data_dir: JString<'l>,
    in_fd: jint,
    out_fd: jint,
) {
    let r = (|| {
        let dir = get_string(&mut env, &data_dir)?;
        let mut input = borrow_fd(in_fd);
        let mut output = borrow_fd(out_fd);
        backend::decrypt_file_to_session(&dir, &mut *input, &mut *output)
    })();
    if let Err(e) = r {
        throw(&mut env, &e);
    }
}
