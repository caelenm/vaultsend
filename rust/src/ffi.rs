// FFI surface: the JNI entry points the Kotlin UI calls. This is the whole trust
// boundary on Android — the analogue of the desktop frontend's `run_backend()`.
//
// Each function: pulls its arguments out of the JVM, calls one `backend`
// function, and either returns the result or throws `org.vaultsend.BackendException`
// carrying the error message (mirroring the desktop `BackendError`, whose text the
// UI shows verbatim). Errors are caught here at the boundary, and so are panics:
// every entry point runs its work inside `guard`, so nothing ever unwinds into the
// JVM (undefined behaviour on older Rust, an abort of the whole app on newer).
//
// Passphrases arrive as a byte[] the caller zeroes after the call. Our copy of it,
// and of any plaintext crossing in either direction, is held in `Zeroizing`
// storage, so it is wiped on drop however the call ends, early returns included.
// File data for the file paths arrives as raw file descriptors borrowed from the
// caller's Storage Access Framework ParcelFileDescriptors — we wrap them in
// ManuallyDrop so dropping our File never closes a descriptor the Kotlin side
// still owns and will close itself.

use std::fs::File;
use std::io::Read;
use std::mem::ManuallyDrop;
use std::os::fd::FromRawFd;
use std::panic::{catch_unwind, AssertUnwindSafe};

use jni::objects::{JByteArray, JClass, JObjectArray, JString};
use jni::sys::{jboolean, jbyteArray, jint, jstring, JNI_FALSE, JNI_TRUE};
use jni::JNIEnv;
use zeroize::Zeroizing;

use crate::backend;

const EXCEPTION: &str = "org/vaultsend/BackendException";

/// What a panic in the core comes back to the app as.
const PANICKED: &str = "internal error in VaultSend's core";

// --- argument/return helpers ------------------------------------------------

/// Run one entry point's work, turning a panic into an error, so it can never
/// unwind across the JNI boundary.
fn guard<T>(work: impl FnOnce() -> Result<T, String>) -> Result<T, String> {
    catch_unwind(AssertUnwindSafe(work)).unwrap_or_else(|_| Err(PANICKED.into()))
}

fn get_string(env: &mut JNIEnv, s: &JString) -> Result<String, String> {
    env.get_string(s)
        .map(|js| js.into())
        .map_err(|e| e.to_string())
}

/// A byte[]'s contents, wiped when dropped: it may be a passphrase or plaintext.
fn get_bytes(env: &mut JNIEnv, a: &JByteArray) -> Result<Zeroizing<Vec<u8>>, String> {
    env.convert_byte_array(a).map(Zeroizing::new).map_err(|e| e.to_string())
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

/// A result's bytes as a new byte[]; ours are wiped once copied.
fn ret_bytes(env: &mut JNIEnv, r: Result<Zeroizing<Vec<u8>>, String>) -> jbyteArray {
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

fn ret_unit(env: &mut JNIEnv, r: Result<(), String>) {
    if let Err(e) = r {
        throw(env, &e);
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
    let r = guard(|| {
        let dir = get_string(&mut env, &data_dir)?;
        let pass = get_bytes(&mut env, &passphrase)?;
        backend::keygen(&dir, &pass)
    });
    ret_string(&mut env, r)
}

#[no_mangle]
pub extern "system" fn Java_org_vaultsend_VaultSendNative_pubkey<'l>(
    mut env: JNIEnv<'l>,
    _class: JClass<'l>,
    data_dir: JString<'l>,
) -> jstring {
    let r = guard(|| get_string(&mut env, &data_dir).and_then(|dir| backend::pubkey(&dir)));
    ret_string(&mut env, r)
}

#[no_mangle]
pub extern "system" fn Java_org_vaultsend_VaultSendNative_status<'l>(
    mut env: JNIEnv<'l>,
    _class: JClass<'l>,
    data_dir: JString<'l>,
) -> jstring {
    let r = guard(|| get_string(&mut env, &data_dir).and_then(|dir| backend::status(&dir)));
    ret_string(&mut env, r)
}

#[no_mangle]
pub extern "system" fn Java_org_vaultsend_VaultSendNative_recoverPubkey<'l>(
    mut env: JNIEnv<'l>,
    _class: JClass<'l>,
    data_dir: JString<'l>,
    passphrase: JByteArray<'l>,
) -> jstring {
    let r = guard(|| {
        let dir = get_string(&mut env, &data_dir)?;
        let pass = get_bytes(&mut env, &passphrase)?;
        backend::recover_pubkey(&dir, &pass)
    });
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
    let r = guard(|| {
        let dir = get_string(&mut env, &data_dir)?;
        let pass = get_bytes(&mut env, &passphrase)?;
        backend::unlock(&dir, &pass)
    });
    ret_string(&mut env, r)
}

/// Drop the cached session key (zeroized). Called on app close and on explicit Lock.
#[no_mangle]
pub extern "system" fn Java_org_vaultsend_VaultSendNative_lock<'l>(
    mut env: JNIEnv<'l>,
    _class: JClass<'l>,
) {
    let r = guard(|| {
        backend::lock();
        Ok(())
    });
    ret_unit(&mut env, r);
}

/// True if the session currently holds an unlocked key.
#[no_mangle]
pub extern "system" fn Java_org_vaultsend_VaultSendNative_isUnlocked<'l>(
    _env: JNIEnv<'l>,
    _class: JClass<'l>,
) -> jboolean {
    match guard(|| Ok(backend::is_unlocked())) {
        Ok(true) => JNI_TRUE,
        _ => JNI_FALSE,
    }
}

/// Remove plaintext staging a killed run left in the data directory, unless a
/// staged operation is running. The app calls this when it starts.
#[no_mangle]
pub extern "system" fn Java_org_vaultsend_VaultSendNative_sweepStaging<'l>(
    mut env: JNIEnv<'l>,
    _class: JClass<'l>,
    data_dir: JString<'l>,
) {
    let r = guard(|| {
        let dir = get_string(&mut env, &data_dir)?;
        backend::sweep_staging(&dir);
        Ok(())
    });
    ret_unit(&mut env, r);
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
    let r = guard(|| {
        let dir = get_string(&mut env, &data_dir)?;
        let pass = get_bytes(&mut env, &passphrase)?;
        let mut input = borrow_fd(in_fd);
        backend::import_identity(&dir, &pass, &mut *input)
    });
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
    let r = guard(|| {
        let recips = get_string_array(&mut env, &recipients)?;
        let plain = get_bytes(&mut env, &input)?;
        let mut out = Zeroizing::new(Vec::new());
        backend::encrypt(&recips, armor == JNI_TRUE, &plain[..], &mut *out)?;
        Ok(out)
    });
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
    let r = guard(|| {
        let dir = get_string(&mut env, &data_dir)?;
        let pass = get_bytes(&mut env, &passphrase)?;
        let data = get_bytes(&mut env, &input)?;
        let mut out = Zeroizing::new(Vec::new());
        backend::decrypt(&dir, &pass, &data[..], &mut *out)?;
        Ok(out)
    });
    ret_bytes(&mut env, r)
}

/// Decrypt copy/paste text using the unlocked session key (no passphrase).
#[no_mangle]
pub extern "system" fn Java_org_vaultsend_VaultSendNative_decryptBytesSession<'l>(
    mut env: JNIEnv<'l>,
    _class: JClass<'l>,
    input: JByteArray<'l>,
) -> jbyteArray {
    let r = guard(|| {
        let data = get_bytes(&mut env, &input)?;
        let mut out = Zeroizing::new(Vec::new());
        backend::decrypt_session(&data[..], &mut *out)?;
        Ok(out)
    });
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
    let r = guard(|| {
        let recips = get_string_array(&mut env, &recipients)?;
        let mut input = borrow_fd(in_fd);
        let mut output = borrow_fd(out_fd);
        backend::encrypt(&recips, armor == JNI_TRUE, &mut *input, &mut *output)
    });
    ret_unit(&mut env, r);
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
    let r = guard(|| {
        let dir = get_string(&mut env, &data_dir)?;
        let pass = get_bytes(&mut env, &passphrase)?;
        let mut input = borrow_fd(in_fd);
        let mut output = borrow_fd(out_fd);
        backend::decrypt_file_to(&dir, &pass, &mut *input, &mut *output)
    });
    ret_unit(&mut env, r);
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
    let r = guard(|| {
        let dir = get_string(&mut env, &data_dir)?;
        let mut input = borrow_fd(in_fd);
        let mut output = borrow_fd(out_fd);
        backend::decrypt_file_to_session(&dir, &mut *input, &mut *output)
    });
    ret_unit(&mut env, r);
}

// ===========================================================================
// Vaults.
//
// One entry point per desktop `vault-*` command. The vault's folder, a folder
// the user picked through the Storage Access Framework, arrives as a Kotlin
// `VaultTree` object, which this side calls back for every file operation
// (`SafStore`); the code that decides what to read and write is vault.rs, shared
// with the host tests. The secret is a byte[] carrying what the desktop's
// --pass-fd carried, or null for the unlocked session (a `self` vault) or a
// remembered key (a `password` vault). Each of these returns the warnings the
// desktop printed to stderr, one per line, after any output.
// ===========================================================================

use std::cell::OnceCell;
use std::io;
use std::rc::Rc;

use jni::objects::{GlobalRef, JBooleanArray, JLongArray, JObject, JValue};
use jni::JavaVM;

use crate::shared::{self, Key};
use crate::tar::LIMITS;
use crate::vault::{self, Kind, Out, Plan, Progress, Secret, Sources, Store, Vault};

/// An error from a callback into Kotlin, with the exception's message.
struct JniFail(String);

impl From<jni::errors::Error> for JniFail {
    fn from(e: jni::errors::Error) -> JniFail {
        JniFail(e.to_string())
    }
}

/// A Kotlin object this side calls back, from whichever thread is running the
/// operation (always one already attached: the caller's).
struct Callback {
    vm: JavaVM,
    obj: GlobalRef,
}

impl Callback {
    fn new(env: &mut JNIEnv, obj: &JObject) -> Result<Callback, String> {
        Ok(Callback {
            vm: env.get_java_vm().map_err(|e| e.to_string())?,
            obj: env.new_global_ref(obj).map_err(|e| e.to_string())?,
        })
    }

    /// Run `f` in its own local frame, so thousands of calls don't pile up local
    /// references, turning a Kotlin exception into its message.
    fn call<T>(&self, f: impl FnOnce(&mut JNIEnv, &JObject) -> jni::errors::Result<T>) -> Result<T, String> {
        let mut env = self.vm.get_env().map_err(|e| e.to_string())?;
        env.with_local_frame(16, |env| -> Result<T, JniFail> {
            match f(env, self.obj.as_obj()) {
                Ok(value) => Ok(value),
                Err(jni::errors::Error::JavaException) => Err(JniFail(take_exception(env))),
                Err(e) => Err(e.into()),
            }
        })
        .map_err(|JniFail(e)| e)
    }
}

/// Clear the pending Java exception and return its message.
fn take_exception(env: &mut JNIEnv) -> String {
    let Ok(throwable) = env.exception_occurred() else { return "unknown error".into() };
    let _ = env.exception_clear();
    let message = env
        .call_method(&throwable, "getMessage", "()Ljava/lang/String;", &[])
        .and_then(|m| m.l())
        .ok()
        .filter(|m| !m.is_null())
        .and_then(|m| env.get_string(&JString::from(m)).ok().map(String::from));
    let _ = env.exception_clear();
    message.unwrap_or_else(|| "unknown error".into())
}

fn jstr<'a>(env: &mut JNIEnv<'a>, s: &str) -> jni::errors::Result<JObject<'a>> {
    env.new_string(s).map(JObject::from)
}

/// A folder picked through the Storage Access Framework, reached through
/// org.vaultsend.VaultTree. SAF's rules: no rename over an existing name, no
/// flock (locked within the process instead), no fsync of a folder.
struct SafStore {
    tree: Callback,
    key: OnceCell<String>,
}

impl SafStore {
    fn new(env: &mut JNIEnv, tree: &JObject) -> Result<SafStore, String> {
        if tree.is_null() {
            return Err("no folder was given".into());
        }
        Ok(SafStore { tree: Callback::new(env, tree)?, key: OnceCell::new() })
    }

    fn string(&self, method: &str, arg: &str) -> Result<String, String> {
        self.tree.call(|env, tree| {
            let arg = jstr(env, arg)?;
            let value = env.call_method(tree, method, "(Ljava/lang/String;)Ljava/lang/String;", &[JValue::Object(&arg)])?.l()?;
            Ok(env.get_string(&JString::from(value))?.into())
        })
    }

    fn int(&self, method: &str, arg: &str) -> Result<i32, String> {
        self.tree.call(|env, tree| {
            let arg = jstr(env, arg)?;
            env.call_method(tree, method, "(Ljava/lang/String;)I", &[JValue::Object(&arg)])?.i()
        })
    }

    /// A descriptor Kotlin detached from a ParcelFileDescriptor, so ours to close.
    fn owned_fd(&self, method: &str, rel: &str) -> Result<Option<File>, String> {
        let fd = self.int(method, rel)?;
        // SAFETY: VaultTree hands over a detached descriptor, which nothing else closes.
        Ok((fd >= 0).then(|| unsafe { File::from_raw_fd(fd) }))
    }
}

impl Store for SafStore {
    fn key(&self) -> backend::R<String> {
        if let Some(key) = self.key.get() {
            return Ok(key.clone());
        }
        let key = self.string("key", "")?;
        Ok(self.key.get_or_init(|| key).clone())
    }
    fn show(&self, rel: &str) -> String {
        self.string("show", rel).unwrap_or_else(|_| rel.to_string())
    }
    fn kind(&self, rel: &str) -> Kind {
        match self.int("kind", rel) {
            Ok(1) => Kind::File,
            Ok(2) => Kind::Dir,
            Ok(3) => Kind::Other,
            _ => Kind::Missing,
        }
    }
    fn read(&self, rel: &str) -> io::Result<Vec<u8>> {
        let mut data = Vec::new();
        self.open(rel)?.read_to_end(&mut data)?;
        Ok(data)
    }
    fn open(&self, rel: &str) -> io::Result<File> {
        // A FIFO can't be made in shared storage, and a cloud provider may hand a
        // file over as a pipe, so unlike PathStore a descriptor's type isn't checked.
        if self.kind(rel) != Kind::File {
            return Err(io::Error::new(io::ErrorKind::NotFound, "not a file in the folder"));
        }
        self.owned_fd("openRead", rel).map_err(io::Error::other)?
            .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "not a file in the folder"))
    }
    fn create_new(&self, rel: &str) -> backend::R<File> {
        self.owned_fd("createNew", rel)?.ok_or_else(|| format!("creating {}: no descriptor", self.show(rel)))
    }
    fn rename(&self, from: &str, to: &str) -> io::Result<()> {
        self.tree
            .call(|env, tree| {
                let (from, to) = (jstr(env, from)?, jstr(env, to)?);
                env.call_method(tree, "rename", "(Ljava/lang/String;Ljava/lang/String;)V", &[JValue::Object(&from), JValue::Object(&to)])?;
                Ok(())
            })
            .map_err(io::Error::other)
    }
    fn replaces_on_rename(&self) -> bool {
        false
    }
    fn remove_file(&self, rel: &str) -> io::Result<()> {
        self.int("delete", rel).map(|_| ()).map_err(io::Error::other)
    }
    fn remove_tree(&self, rel: &str) {
        let _ = self.int("delete", rel);
    }
    fn mkdir(&self, rel: &str, recursive: bool) -> backend::R<()> {
        self.tree
            .call(|env, tree| {
                let rel = jstr(env, rel)?;
                env.call_method(tree, "mkdir", "(Ljava/lang/String;Z)V", &[JValue::Object(&rel), JValue::Bool(recursive.into())])?;
                Ok(())
            })
            .map_err(|e| format!("creating {}: {e}", self.show(rel)))
    }
    fn list(&self, rel: &str) -> backend::R<Vec<(String, Kind)>> {
        let names = self.tree.call(|env, tree| {
            let arg = jstr(env, rel)?;
            let array = env.call_method(tree, "list", "(Ljava/lang/String;)[Ljava/lang/String;", &[JValue::Object(&arg)])?.l()?;
            let array = JObjectArray::from(array);
            let mut names = Vec::new();
            for i in 0..env.get_array_length(&array)? {
                let item = env.get_object_array_element(&array, i)?;
                names.push(String::from(env.get_string(&JString::from(item))?));
            }
            Ok(names)
        }).map_err(|e| format!("{}: {e}", self.show(rel)))?;
        // Each is "<f|d|o>:<name>".
        Ok(names.into_iter().filter_map(|item| {
            let (kind, name) = item.split_once(':')?;
            let kind = match kind { "f" => Kind::File, "d" => Kind::Dir, _ => Kind::Other };
            Some((name.to_string(), kind))
        }).collect())
    }
    fn sync_dir(&self, _rel: &str) {
        // Nothing to do: SAF has no handle on a folder. Each file is fsynced.
    }
    fn lock(&self, exclusive: bool) -> backend::R<Box<dyn std::any::Any>> {
        vault::lock_by_key(self, exclusive)
    }
}

/// What a vault-add adds: documents the app walked (org.vaultsend.VaultSources),
/// each a path below the destination, a folder or a file with its expected size.
struct SafSources {
    callback: Callback,
    plan: Vec<(String, Option<usize>)>,
    sizes: Vec<i64>,
    skipped: usize,
}

impl Sources for SafSources {
    fn plan(&self) -> backend::R<Plan> {
        Ok((self.plan.clone(), self.skipped))
    }
    fn open(&self, index: usize) -> backend::R<Box<dyn Read>> {
        let fd = self.callback.call(|env, sources| {
            env.call_method(sources, "openSource", "(I)I", &[JValue::Int(index as i32)])?.i()
        })?;
        if fd < 0 {
            return Err(format!("opening {}: no descriptor", self.plan[index].0));
        }
        // SAFETY: VaultSources hands over a detached descriptor, which nothing else closes.
        Ok(Box::new(unsafe { File::from_raw_fd(fd) }))
    }
    fn size(&self, index: usize) -> u64 {
        self.sizes.get(index).map_or(0, |s| (*s).max(0) as u64)
    }
}

/// Progress reports go to `sink.report(int)`, and the user's Cancel comes from
/// `sink.isCancelled()` (org.vaultsend.ProgressSink).
fn progress_to(env: &mut JNIEnv, sink: &JObject) -> Result<Rc<Progress>, String> {
    if sink.is_null() {
        return Ok(Rc::default());
    }
    let sink = Rc::new(Callback::new(env, sink)?);
    let asks = sink.clone();
    Ok(Rc::new(
        Progress::new(move |percent| {
            // Undeliverable reports are dropped, as on desktop.
            let _ = sink.call(|env, sink| {
                env.call_method(sink, "report", "(I)V", &[JValue::Int(percent as i32)]).map(|_| ())
            });
        })
        .with_cancel(move || {
            asks.call(|env, sink| env.call_method(sink, "isCancelled", "()Z", &[])?.z()).unwrap_or(false)
        }),
    ))
}

/// A byte[] that may be null (the session or a remembered key), wiped when dropped.
fn opt_bytes(env: &mut JNIEnv, a: &JByteArray) -> Result<Option<Zeroizing<Vec<u8>>>, String> {
    if a.is_null() { Ok(None) } else { get_bytes(env, a).map(Some) }
}

/// The parts every vault call shares: open the vault in `tree` with `secret`, run
/// `act`, and return its output followed by any warnings. Secret bytes are wiped,
/// and a panic comes back as an error rather than unwinding into the JVM.
#[allow(clippy::too_many_arguments)]
fn with_vault(
    env: &mut JNIEnv,
    data_dir: &JString,
    tree: &JObject,
    secret: &JByteArray,
    exclusive: bool,
    progress: &JObject,
    act: &mut dyn FnMut(&mut JNIEnv, &Vault) -> Result<String, String>,
) -> Result<String, String> {
    let dir = get_string(env, data_dir)?;
    let bytes = opt_bytes(env, secret)?;
    let store = SafStore::new(env, tree);
    let progress = progress_to(env, progress);
    guard(|| {
        let secret = Secret { data_dir: &dir, bytes: bytes.as_deref().map(Vec::as_slice) };
        let mut vault = Vault::open_in(Box::new(store?), &secret, exclusive)?;
        vault.progress = progress?;
        let mut out = act(env, &vault)?;
        for warning in vault.warnings() {
            out.push_str(&format!("warning: {warning}\n"));
        }
        Ok(out)
    })
}

/// Make a vault in `tree`, an empty folder.
#[no_mangle]
pub extern "system" fn Java_org_vaultsend_VaultSendNative_vaultCreate<'l>(
    mut env: JNIEnv<'l>,
    _class: JClass<'l>,
    data_dir: JString<'l>,
    tree: JObject<'l>,
    mode: JString<'l>,
    secret: JByteArray<'l>,
) {
    let r = guard(|| {
        let dir = get_string(&mut env, &data_dir)?;
        let mode = get_string(&mut env, &mode)?;
        let bytes = opt_bytes(&mut env, &secret)?;
        let store = SafStore::new(&mut env, &tree)?;
        vault::create(Box::new(store), &mode, &Secret { data_dir: &dir, bytes: bytes.as_deref().map(Vec::as_slice) })
    });
    ret_unit(&mut env, r);
}

/// `vault-list`: "generation N" then "F size path" / "D path" lines.
#[no_mangle]
pub extern "system" fn Java_org_vaultsend_VaultSendNative_vaultList<'l>(
    mut env: JNIEnv<'l>,
    _class: JClass<'l>,
    data_dir: JString<'l>,
    tree: JObject<'l>,
    secret: JByteArray<'l>,
) -> jstring {
    let r = guard(|| with_vault(&mut env, &data_dir, &tree, &secret, false, &JObject::null(), &mut |_, v| v.listing()));
    ret_string(&mut env, r)
}

/// `vault-check`: "orphan ..." lines, then "ok N file(s) verified".
#[no_mangle]
pub extern "system" fn Java_org_vaultsend_VaultSendNative_vaultCheck<'l>(
    mut env: JNIEnv<'l>,
    _class: JClass<'l>,
    data_dir: JString<'l>,
    tree: JObject<'l>,
    secret: JByteArray<'l>,
    progress: JObject<'l>,
) -> jstring {
    let r = guard(|| with_vault(&mut env, &data_dir, &tree, &secret, false, &progress, &mut |_, v| v.check()));
    ret_string(&mut env, r)
}

/// `vault-add`: `targets[i]` is a path below `dest` (null for the top), a folder
/// if `isDir[i]`, otherwise a file `sources.openSource(i)` opens, of about
/// `sizes[i]` bytes. `skipped` counts what the walk left out.
#[no_mangle]
pub extern "system" fn Java_org_vaultsend_VaultSendNative_vaultAdd<'l>(
    mut env: JNIEnv<'l>,
    _class: JClass<'l>,
    data_dir: JString<'l>,
    tree: JObject<'l>,
    secret: JByteArray<'l>,
    targets: JObjectArray<'l>,
    is_dir: JBooleanArray<'l>,
    sizes: JLongArray<'l>,
    skipped: jint,
    sources: JObject<'l>,
    dest: JString<'l>,
    replace: jboolean,
    progress: JObject<'l>,
) -> jstring {
    let r = guard(|| {
        let targets = get_string_array(&mut env, &targets)?;
        let n = targets.len();
        let mut dirs = vec![JNI_FALSE; n];
        env.get_boolean_array_region(&is_dir, 0, &mut dirs).map_err(|e| e.to_string())?;
        let mut size_list = vec![0i64; n];
        env.get_long_array_region(&sizes, 0, &mut size_list).map_err(|e| e.to_string())?;
        let dest = if dest.is_null() { None } else { Some(get_string(&mut env, &dest)?) };
        let sources = SafSources {
            callback: Callback::new(&mut env, &sources)?,
            plan: targets.into_iter().zip(&dirs).enumerate()
                .map(|(i, (target, dir))| (target, (*dir == JNI_FALSE).then_some(i)))
                .collect(),
            sizes: size_list,
            skipped: skipped.max(0) as usize,
        };
        with_vault(&mut env, &data_dir, &tree, &secret, true, &progress, &mut |_, v| {
            v.add_from(&sources, dest.as_deref(), replace == JNI_TRUE).map(|()| String::new())
        })
    });
    ret_string(&mut env, r)
}

/// `vault-remove`: the entries, or everything if `all`.
#[no_mangle]
pub extern "system" fn Java_org_vaultsend_VaultSendNative_vaultRemove<'l>(
    mut env: JNIEnv<'l>,
    _class: JClass<'l>,
    data_dir: JString<'l>,
    tree: JObject<'l>,
    secret: JByteArray<'l>,
    entries: JObjectArray<'l>,
    all: jboolean,
    progress: JObject<'l>,
) -> jstring {
    let r = guard(|| {
        let entries = if all == JNI_TRUE { Vec::new() } else { get_string_array(&mut env, &entries)? };
        with_vault(&mut env, &data_dir, &tree, &secret, true, &progress, &mut |_, v| {
            let entries: Vec<&str> = entries.iter().map(String::as_str).collect();
            let done = if all == JNI_TRUE { v.remove_everything() } else { v.remove(&entries) };
            done.map(|()| String::new())
        })
    });
    ret_string(&mut env, r)
}

/// `vault-extract` of one file into `out_fd`, a document the app created and
/// checked is outside the vault; it deletes the document if this fails.
#[no_mangle]
pub extern "system" fn Java_org_vaultsend_VaultSendNative_vaultExtractFile<'l>(
    mut env: JNIEnv<'l>,
    _class: JClass<'l>,
    data_dir: JString<'l>,
    tree: JObject<'l>,
    secret: JByteArray<'l>,
    entry: JString<'l>,
    out_fd: jint,
    progress: JObject<'l>,
) -> jstring {
    let r = guard(|| {
        let entry = get_string(&mut env, &entry)?;
        with_vault(&mut env, &data_dir, &tree, &secret, false, &progress, &mut |_, v| {
            let mut out = borrow_fd(out_fd);
            v.extract_to(&entry, Out::File(&mut out)).map(|()| String::new())
        })
    });
    ret_string(&mut env, r)
}

/// `vault-extract` into a new folder `name` inside `out_tree`: a folder's contents,
/// or several entries each keeping its path from the top of the vault.
#[no_mangle]
pub extern "system" fn Java_org_vaultsend_VaultSendNative_vaultExtractTree<'l>(
    mut env: JNIEnv<'l>,
    _class: JClass<'l>,
    data_dir: JString<'l>,
    tree: JObject<'l>,
    secret: JByteArray<'l>,
    entries: JObjectArray<'l>,
    out_tree: JObject<'l>,
    name: JString<'l>,
    progress: JObject<'l>,
) -> jstring {
    let r = guard(|| {
        let entries = get_string_array(&mut env, &entries)?;
        let name = get_string(&mut env, &name)?;
        let folder = SafStore::new(&mut env, &out_tree)?;
        with_vault(&mut env, &data_dir, &tree, &secret, false, &progress, &mut |_, v| {
            let entries: Vec<&str> = entries.iter().map(String::as_str).collect();
            let out = Out::In(&folder, &name);
            match entries[..] {
                [one] => v.extract_to(one, out),
                ref many => v.extract_many_to(many, out),
            }
            .map(|()| String::new())
        })
    });
    ret_string(&mut env, r)
}

/// `vault-share` into `out_fd`, as vaultExtractFile.
#[no_mangle]
pub extern "system" fn Java_org_vaultsend_VaultSendNative_vaultShare<'l>(
    mut env: JNIEnv<'l>,
    _class: JClass<'l>,
    data_dir: JString<'l>,
    tree: JObject<'l>,
    secret: JByteArray<'l>,
    entries: JObjectArray<'l>,
    recipients: JObjectArray<'l>,
    out_fd: jint,
    progress: JObject<'l>,
) -> jstring {
    let r = guard(|| {
        let entries = get_string_array(&mut env, &entries)?;
        let recipients = get_string_array(&mut env, &recipients)?;
        with_vault(&mut env, &data_dir, &tree, &secret, false, &progress, &mut |_, v| {
            let entries: Vec<&str> = entries.iter().map(String::as_str).collect();
            let to: Vec<&str> = recipients.iter().map(String::as_str).collect();
            let mut out = borrow_fd(out_fd);
            v.share_to(&entries, &to, Out::File(&mut out)).map(|()| String::new())
        })
    });
    ret_string(&mut env, r)
}

/// How long a password vault's key is remembered: 0 not at all, negative until
/// the app closes, otherwise seconds. Changing it forgets every key.
#[no_mangle]
pub extern "system" fn Java_org_vaultsend_VaultSendNative_vaultSetRemember<'l>(
    _env: JNIEnv<'l>,
    _class: JClass<'l>,
    seconds: jni::sys::jlong,
) {
    let _ = guard(|| {
        vault::set_remember(seconds);
        Ok(())
    });
}

/// Forget one vault's remembered key, by its VaultTree key.
#[no_mangle]
pub extern "system" fn Java_org_vaultsend_VaultSendNative_vaultForget<'l>(
    mut env: JNIEnv<'l>,
    _class: JClass<'l>,
    key: JString<'l>,
) {
    let _ = guard(|| {
        vault::forget(&get_string(&mut env, &key)?);
        Ok(())
    });
}

/// Whether a vault's key is remembered now, by its VaultTree key.
#[no_mangle]
pub extern "system" fn Java_org_vaultsend_VaultSendNative_vaultIsRemembered<'l>(
    mut env: JNIEnv<'l>,
    _class: JClass<'l>,
    key: JString<'l>,
) -> jboolean {
    match guard(|| get_string(&mut env, &key).map(|key| vault::is_remembered(&key))) {
        Ok(true) => JNI_TRUE,
        _ => JNI_FALSE,
    }
}

/// Forget remembered keys whose time is up.
#[no_mangle]
pub extern "system" fn Java_org_vaultsend_VaultSendNative_vaultSweep<'l>(_env: JNIEnv<'l>, _class: JClass<'l>) {
    let _ = guard(|| {
        vault::sweep();
        Ok(())
    });
}

// ===========================================================================
// Receiving a share (shared.rs): a plain age file someone made with Share…,
// encrypted to this device's key or to a password. `password` is null for the
// unlocked session key. As above, secrets are wiped and panics come back as errors.
// ===========================================================================

/// The input's length, for the percentage only (0 for a pipe: the bar pulses).
fn input_len(file: &File) -> u64 {
    file.metadata().map_or(0, |m| m.len())
}

/// Run `act` with the key a shared file opens with, wiping a password afterwards.
fn with_key<T>(
    env: &mut JNIEnv,
    password: &JByteArray,
    act: impl FnOnce(&Key) -> Result<T, String>,
) -> Result<T, String> {
    let bytes = opt_bytes(env, password)?;
    guard(|| {
        let key = match bytes.as_deref() {
            Some(b) => Key::Password(b),
            None => Key::Session,
        };
        act(&key)
    })
}

/// "password" or "key": which prompt a shared file needs.
#[no_mangle]
pub extern "system" fn Java_org_vaultsend_VaultSendNative_sharedKind<'l>(
    mut env: JNIEnv<'l>,
    _class: JClass<'l>,
    in_fd: jint,
) -> jstring {
    let r = guard(|| shared::age_kind(&mut *borrow_fd(in_fd)).map(str::to_string));
    ret_string(&mut env, r)
}

/// Throws unless `password` opens the file. Only the file key is unwrapped.
#[no_mangle]
pub extern "system" fn Java_org_vaultsend_VaultSendNative_sharedCheckPassword<'l>(
    mut env: JNIEnv<'l>,
    _class: JClass<'l>,
    in_fd: jint,
    password: JByteArray<'l>,
) {
    let r = guard(|| {
        with_key(&mut env, &password, |key| match key {
            Key::Password(pw) => shared::check_password(&mut *borrow_fd(in_fd), pw),
            Key::Session => Err("no password was given".into()),
        })
    });
    ret_unit(&mut env, r);
}

/// Save a shared file as it is (an archive stays an archive), staged and
/// authenticated in full before a byte reaches `out_fd`.
#[no_mangle]
pub extern "system" fn Java_org_vaultsend_VaultSendNative_sharedDecrypt<'l>(
    mut env: JNIEnv<'l>,
    _class: JClass<'l>,
    data_dir: JString<'l>,
    password: JByteArray<'l>,
    in_fd: jint,
    out_fd: jint,
) {
    let r = guard(|| {
        let dir = get_string(&mut env, &data_dir)?;
        with_key(&mut env, &password, |key| {
            shared::decrypt_file_to(&dir, key, &mut *borrow_fd(in_fd), &mut *borrow_fd(out_fd))
        })
    });
    ret_unit(&mut env, r);
}

/// Unpack a shared archive into a new folder `name` inside `out_tree`. Returns
/// warnings, one per line, as the vault calls do.
#[no_mangle]
pub extern "system" fn Java_org_vaultsend_VaultSendNative_sharedExtract<'l>(
    mut env: JNIEnv<'l>,
    _class: JClass<'l>,
    data_dir: JString<'l>,
    password: JByteArray<'l>,
    in_fd: jint,
    out_tree: JObject<'l>,
    name: JString<'l>,
    progress: JObject<'l>,
) -> jstring {
    let r = guard(|| {
        let dir = get_string(&mut env, &data_dir)?;
        let name = get_string(&mut env, &name)?;
        let folder = SafStore::new(&mut env, &out_tree)?;
        let progress = progress_to(&mut env, &progress)?;
        with_key(&mut env, &password, |key| {
            let mut input = borrow_fd(in_fd);
            let len = input_len(&input);
            let skipped = shared::extract_archive(&dir, key, &mut *input, len, &folder, &name, &LIMITS, &progress)?;
            Ok(skipped_warning(skipped))
        })
    });
    ret_string(&mut env, r)
}

fn skipped_warning(skipped: usize) -> String {
    if skipped > 0 {
        format!("warning: skipped {skipped} item(s) that are not regular files or folders\n")
    } else {
        String::new()
    }
}

/// `vault-share` for anyone with `password`, into `out_fd`, as vaultShare.
#[no_mangle]
pub extern "system" fn Java_org_vaultsend_VaultSendNative_vaultSharePassword<'l>(
    mut env: JNIEnv<'l>,
    _class: JClass<'l>,
    data_dir: JString<'l>,
    tree: JObject<'l>,
    secret: JByteArray<'l>,
    entries: JObjectArray<'l>,
    password: JByteArray<'l>,
    out_fd: jint,
    progress: JObject<'l>,
) -> jstring {
    let r = guard(|| {
        let entries = get_string_array(&mut env, &entries)?;
        let pw = get_bytes(&mut env, &password)?;
        with_vault(&mut env, &data_dir, &tree, &secret, false, &progress, &mut |_, v| {
            let entries: Vec<&str> = entries.iter().map(String::as_str).collect();
            let mut out = borrow_fd(out_fd);
            v.share_password(&entries, &pw, Out::File(&mut out)).map(|()| String::new())
        })
    });
    ret_string(&mut env, r)
}

/// Add what a shared file holds to the vault in `tree`, at its top: an archive's
/// files and folders, or one file named `single_name`. All of it, or nothing.
#[no_mangle]
pub extern "system" fn Java_org_vaultsend_VaultSendNative_vaultImportShared<'l>(
    mut env: JNIEnv<'l>,
    _class: JClass<'l>,
    data_dir: JString<'l>,
    tree: JObject<'l>,
    secret: JByteArray<'l>,
    password: JByteArray<'l>,
    in_fd: jint,
    single_name: JString<'l>,
    progress: JObject<'l>,
) -> jstring {
    let r = guard(|| {
        let dir = get_string(&mut env, &data_dir)?;
        let single_name = get_string(&mut env, &single_name)?;
        let pw = opt_bytes(&mut env, &password)?;
        with_vault(&mut env, &data_dir, &tree, &secret, true, &progress, &mut |_, v| {
            let key = match pw.as_deref() {
                Some(b) => Key::Password(b),
                None => Key::Session,
            };
            let mut input = borrow_fd(in_fd);
            let len = input_len(&input);
            shared::import_archive(v, &dir, &key, &mut *input, len, &single_name, &LIMITS).map(|_| String::new())
        })
    });
    ret_string(&mut env, r)
}
