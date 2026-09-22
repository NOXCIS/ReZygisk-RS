//! Port of hook.c's JNI hooking machinery:
//! - `hook_jni_methods` (hook.c 381-445) — also the module API entry:
//!   the C installs it as `api->hook_jni_native_methods = hook_jni_methods`
//!   (module.h:134) from `rezygisk_module_register` (the module_api.rs
//!   slice), so modules register JNI hooks through this same function.
//! - `initialize_jni_hook` (hook.c 450-518) — called from the strdup PLT
//!   hook (fork_hooks.rs) when the zygote strdup's
//!   "com.android.internal.os.ZygoteInit".
//! - `do_hook_zygote` (jni_hooks.h 422-458) — hooks every entry of
//!   `crate::jni_tables::JNI_HOOKS` and records the unhook list.
//!
//! Sibling contracts:
//! - `abi::JNINativeMethod { name, signature, fn_ptr }` — jni.h layout.
//! - `context::{JniHookEntry, jni_hook_list()}` — hook.c `jni_hook_list`
//!   (replayed by the cleanup path, hook.c 1235-1255).
//! - `crate::jni_tables::JNI_HOOKS: &[(&str, &str, &str, usize)]` =
//!   (class_name, method_name, signature, wrapper_fn_ptr) — the flat port
//!   of jni_hooks.h's three per-API-level method tables.
//! - `crate::art_method::{amethod_init, amethod_get_data,
//!   amethod_from_reflected_method}` — art_method.h inline helpers.
//!
//! C-parity notes:
//! - `hook_jni_methods` keeps the C's exact extern shape: the C function is
//!   non-static (`void hook_jni_methods(JNIEnv *, const char *,
//!   JNINativeMethod *, int)`) because modules receive it as a function
//!   pointer, so the port exports `pub unsafe extern "C" fn` with the same
//!   signature (matching `abi::ReZygiskApi::hook_jni_native_methods`).
//! - This C tree has no "unregister via registerNatives" prelude: the C
//!   reads the original entry point with `amethod_get_data` and then
//!   re-registers the wrappers with `RegisterNatives`, exactly as ported.
//! - Where the C would dereference NULL (a NULL class/method name/signature
//!   from a misbehaving module), the port takes the closest well-defined
//!   path (lookup failure: fnPtr = NULL) instead of crashing.

use std::ffi::{c_char, c_void, CStr, CString};
use std::mem::{size_of, transmute};
use std::os::raw::c_int;
use std::ptr::NonNull;

use std::sync::atomic::{AtomicBool, AtomicI32, AtomicPtr, Ordering};

use jni::objects::{JMethodID, JObject};
use jni::signature::{JavaType, Primitive, ReturnType};
use jni::sys::{jboolean, jint, jsize, _jmethodID};
use jni::JNIEnv;

use crate::abi::JNINativeMethod;
use crate::context;

/// Module-local logcat tag (the whole library logs as "zygisk" in the C).
const TAG: &str = rz_common::LOG_TAG;

// hook.c file-scope statics (lines 377-379). Use atomics for sound access.
static CAN_HOOK_JNI: AtomicBool = AtomicBool::new(false);
static MODIFIER_NATIVE: AtomicI32 = AtomicI32::new(0);
static MEMBER_GET_MODIFIERS: AtomicPtr<_jmethodID> = AtomicPtr::new(std::ptr::null_mut());

// ---------------------------------------------------------------------------
// hook.c `hook_jni_methods` (381-445): rewrite a native methods array in
// place — fnPtr becomes the original entry point, and the wrappers get
// registered with RegisterNatives.
// ---------------------------------------------------------------------------

pub unsafe extern "C" fn hook_jni_methods(
    env_ptr: *mut jni::sys::JNIEnv,
    clz: *const c_char,
    methods: *mut JNINativeMethod,
    num_methods: c_int,
) {
    if !CAN_HOOK_JNI.load(Ordering::Relaxed) {
        return;
    }

    let Ok(mut env) = (unsafe { JNIEnv::from_raw(env_ptr) }) else {
        return;
    };

    if env.exception_check().unwrap_or(false) {
        let _ = env.exception_clear();
    }

    let class_name = if clz.is_null() {
        None
    } else {
        Some(unsafe { CStr::from_ptr(clz) }.to_string_lossy())
    };

    let class = class_name.as_deref().and_then(|name| env.find_class(name).ok());

    let Some(class) = class else {
        let _ = env.exception_clear();
        let count = num_methods.max(0) as usize;
        if !methods.is_null() && count > 0 {
            unsafe {
                libc::memset(methods as *mut c_void, 0, count * size_of::<JNINativeMethod>());
            }
        }
        return;
    };

    let count = num_methods.max(0) as usize;
    let methods = unsafe {
        if methods.is_null() {
            std::slice::from_raw_parts_mut(NonNull::<JNINativeMethod>::dangling().as_ptr(), 0)
        } else {
            std::slice::from_raw_parts_mut(methods, count)
        }
    };

    let mut hooks: Vec<JNINativeMethod> = Vec::with_capacity(count.min(32));

    for nm in methods.iter_mut() {
        let mut is_static = false;

        // C: GetMethodID(env, clazz, nm->name, nm->signature). NULL name or
        // signature would crash the C; take the lookup-failure path instead.
        let name = if nm.name.is_null() {
            None
        } else {
            Some(unsafe { CStr::from_ptr(nm.name) }.to_string_lossy())
        };
        let sig = if nm.signature.is_null() {
            None
        } else {
            Some(unsafe { CStr::from_ptr(nm.signature) }.to_string_lossy())
        };
        let Some((name, sig)) = name.zip(sig) else {
            nm.fn_ptr = std::ptr::null_mut();
            continue;
        };

        let mid = match env.get_method_id(&class, name.as_ref(), sig.as_ref()) {
            Ok(mid) => mid.into_raw(),
            Err(_) => {
                let _ = env.exception_clear();
                is_static = true;
                match env.get_static_method_id(&class, name.as_ref(), sig.as_ref()) {
                    Ok(mid) => mid.into_raw(),
                    Err(_) => {
                        let _ = env.exception_clear();
                        nm.fn_ptr = std::ptr::null_mut();
                        continue;
                    }
                }
            }
        };

        // C: jobject method = ToReflectedMethod(env, clazz, mid, is_static);
        // A missing table entry skips the method (fail-soft) instead of
        // aborting the zygote.
        let Some(to_reflected_method) = (unsafe { (**env_ptr).ToReflectedMethod }) else {
            rz_common::loge!(TAG, "JNIEnv::ToReflectedMethod is unavailable");
            nm.fn_ptr = std::ptr::null_mut();
            continue;
        };
        let method = unsafe { to_reflected_method(env_ptr, class.as_raw(), mid, is_static as jboolean) };
        let method = if method.is_null() {
            JObject::null()
        } else {
            unsafe { JObject::from_raw(method) }
        };

        // C: jint modifier = CallIntMethod(env, method, member_getModifiers);
        let modifier = unsafe {
            env.call_method_unchecked(
                &method,
                JMethodID::from_raw(MEMBER_GET_MODIFIERS.load(Ordering::Relaxed)),
                ReturnType::Primitive(Primitive::Int),
                &[],
            )
        }
        .ok()
        .and_then(|v| v.i().ok());
        let exception = env.exception_check().unwrap_or(false);
        let modifier_native = MODIFIER_NATIVE.load(Ordering::Relaxed);
        if exception || modifier.map_or(true, |m| (m & modifier_native) == 0) {
            let _ = env.exception_clear();
            nm.fn_ptr = std::ptr::null_mut();
            let _ = env.delete_local_ref(method);
            continue;
        }

        let art_method = crate::art_method::amethod_from_reflected_method(env_ptr, method.as_raw());

        if hooks.len() < 32 {
            hooks.push(*nm);
        }

        let orig = crate::art_method::amethod_get_data(art_method as usize);
        nm.fn_ptr = orig;

        rz_common::logv!(
            TAG,
            "replaced {} {} orig {:p}: {}",
            class_name.as_deref().unwrap_or(""),
            name,
            orig,
            sig
        );

        let _ = env.delete_local_ref(method);
    }

    if hooks.is_empty() {
        let _ = env.delete_local_ref(class);
        return;
    }

    let native_methods: Vec<jni::NativeMethod> = hooks
        .iter()
        .map(|h| jni::NativeMethod {
            name: unsafe { CStr::from_ptr(h.name) }.to_string_lossy().into_owned().into(),
            sig: unsafe { CStr::from_ptr(h.signature) }
                .to_string_lossy()
                .into_owned()
                .into(),
            fn_ptr: h.fn_ptr,
        })
        .collect();
    // A failed RegisterNatives leaves the originals registered and none of
    // our wrappers installed. Clear the caller's table so do_hook_zygote does
    // not record the rewritten fn_ptrs into the `*_orig` statics / unhook
    // list as if the wrappers were live — that would make every wrapper's
    // transmute-based dispatch lie about what is actually registered.
    if let Err(err) = env.register_native_methods(&class, &native_methods) {
        let _ = env.exception_clear();
        rz_common::loge!(
            TAG,
            "RegisterNatives failed for {} ({} methods): {err:?} — zygote JNI hooks inert for this table",
            class_name.as_deref().unwrap_or("?"),
            native_methods.len()
        );
        for nm in methods.iter_mut() {
            nm.fn_ptr = std::ptr::null_mut();
        }
    }
    let _ = env.delete_local_ref(class);
}

// ---------------------------------------------------------------------------
// hook.c `initialize_jni_hook` (450-518) + jni_hooks.h `do_hook_zygote`
// (422-458).
// ---------------------------------------------------------------------------

pub unsafe fn initialize_jni_hook() {
    type JniGetCreatedJavaVms = unsafe extern "C" fn(
        *mut *mut jni::sys::JavaVM,
        jsize,
        *mut jsize,
    ) -> jint;

    let mut get_created_java_vms: Option<JniGetCreatedJavaVms> = unsafe {
        transmute::<*mut c_void, Option<JniGetCreatedJavaVms>>(libc::dlsym(
            std::ptr::null_mut(),
            c"JNI_GetCreatedJavaVMs".as_ptr(),
        ))
    };

    if get_created_java_vms.is_none() {
        let Some(maps) = rz_common::parse_maps_safe("self") else {
            rz_common::loge!(TAG, "Failed to scan maps for plt_hook_register_v4");
            return;
        };

        for map in &maps {
            if !map.path.contains("/libnativehelper.so") {
                continue;
            }

            // C: /* TODO: Add RTLD_NOLOAD? */
            let path = CString::new(map.path.as_str()).expect("map path contains NUL");
            let handle = unsafe { libc::dlopen(path.as_ptr(), libc::RTLD_LAZY) };
            if handle.is_null() {
                rz_common::loge!(TAG, "Failed to dlopen {}: {}", map.path, dlerror_str());
                break;
            }

            get_created_java_vms = unsafe {
                transmute::<*mut c_void, Option<JniGetCreatedJavaVms>>(libc::dlsym(
                    handle,
                    c"JNI_GetCreatedJavaVMs".as_ptr(),
                ))
            };
            unsafe {
                libc::dlclose(handle);
            }

            break;
        }
        // maps drops here (C: free_maps(maps));

        if get_created_java_vms.is_none() {
            rz_common::loge!(TAG, "Failed to find JNI_GetCreatedJavaVMs");
            return;
        }
    }

    let mut vm: *mut jni::sys::JavaVM = std::ptr::null_mut();
    let mut num: jsize = 0;
    let Some(get_created_java_vms) = get_created_java_vms else {
        rz_common::loge!(TAG, "JNI_GetCreatedJavaVMs unavailable");
        return;
    };
    let res = unsafe { get_created_java_vms(&mut vm, 1, &mut num) };
    if res != jni::sys::JNI_OK || vm.is_null() {
        return;
    }

    let mut env_ptr: *mut jni::sys::JNIEnv = std::ptr::null_mut();
    let Some(get_env) = (unsafe { (**vm).GetEnv }) else {
        rz_common::loge!(TAG, "JavaVM::GetEnv is unavailable");
        return;
    };
    let res = unsafe {
        get_env(
            vm,
            &mut env_ptr as *mut *mut jni::sys::JNIEnv as *mut *mut c_void,
            jni::sys::JNI_VERSION_1_6,
        )
    };
    if res != jni::sys::JNI_OK || env_ptr.is_null() {
        return;
    }

    let Ok(mut env) = (unsafe { JNIEnv::from_raw(env_ptr) }) else {
        return;
    };

    let class_member = env.find_class("java/lang/reflect/Member").ok();
    if let Some(cm) = class_member.as_ref() {
        let method_id = env
            .get_method_id(cm, "getModifiers", "()I")
            .map(|mid| mid.into_raw())
            .unwrap_or(std::ptr::null_mut());
        MEMBER_GET_MODIFIERS.store(method_id, Ordering::Relaxed);
    }

    let class_modifier = env.find_class("java/lang/reflect/Modifier").ok();
    if let Some(cm) = class_modifier.as_ref() {
        if let Ok(field_id) = env.get_static_field_id(cm, "NATIVE", "I") {
            if let Ok(value) =
                env.get_static_field_unchecked(cm, field_id, JavaType::Primitive(Primitive::Int))
            {
                MODIFIER_NATIVE.store(value.i().unwrap_or(0), Ordering::Relaxed);
            }
        }
    }

    if let Some(cm) = class_member {
        let _ = env.delete_local_ref(cm);
    }
    if let Some(cm) = class_modifier {
        let _ = env.delete_local_ref(cm);
    }

    if MEMBER_GET_MODIFIERS.load(Ordering::Relaxed).is_null() || MODIFIER_NATIVE.load(Ordering::Relaxed) == 0 {
        return;
    }

    // Hand the env back to raw calls: amethod_init / do_hook_zygote (and
    // hook_jni_methods below) each wrap the raw pointer themselves, exactly
    // like the C passing the JNIEnv * through art_method.h helpers.
    drop(env);

    if !crate::art_method::amethod_init(env_ptr) {
        rz_common::loge!(TAG, "failed to init amethod");
        return;
    }

    CAN_HOOK_JNI.store(true, Ordering::Relaxed);
    unsafe {
        do_hook_zygote(env_ptr);
    }
}

/// jni_hooks.h `do_hook_zygote` (422-458): hook every method table and
/// record the unhook entries in `context::JNI_HOOK_LIST` (hook.c
/// `jni_hook_list_add`).
///
/// A NUL-terminated, never-freed copy of a table literal.
///
/// `JNINativeMethod.name`/`.signature` are jni.h C strings: ART runs `strlen`
/// over them in `RegisterNatives`, and the restore path re-reads them with
/// `CStr::from_ptr`. Rust `&str` literals are **not** NUL-terminated, so
/// handing out `str::as_ptr()` made `strlen` run on into the next literal in
/// .rodata. ART then logged `Failed to register native method ...Zygote
/// .nativeForkAndSpecialize(...)I(II[II...)I(II[II[[IJJ)Iselfutf8info...` (a
/// smear of neighbouring strings), failed the lookup, and left a pending
/// NoSuchMethodError that killed the zygote on its next fork — the 5x-boot
/// crash loop. The C reference uses `static const char*` literals, which are
/// NUL-terminated and immortal; a leaked `CString` reproduces exactly that
/// lifetime. It is never freed because the entry list also carries
/// module-owned pointers that must not be freed, and because these entries
/// die with the process anyway.
fn static_cstr(s: &'static str) -> *mut c_char {
    CString::new(s)
        .expect("JNI name/signature literal cannot contain an interior NUL")
        .into_raw()
}

/// The bootstrap hooks are installed from the flat table's own `&'static str`
/// name/signature slices instead of going through a `JNINativeMethod`
/// pointer buffer: instrumentation during the original bring-up showed
/// GetMethodID failing for every table entry while the identical literals
/// resolve, so the pointer round-trip is what breaks. The pointer-based
/// `hook_jni_methods` stays for the module API.
unsafe fn do_hook_zygote(env_ptr: *mut jni::sys::JNIEnv) {
    // Group the flat table by class name preserving table order.
    let mut per_class: Vec<(&'static str, Vec<(&'static str, &'static str, usize)>)> = Vec::new();
    for &(class_name, method_name, signature, wrapper_fn_ptr) in &crate::jni_tables::jni_hooks() {
        match per_class
            .iter_mut()
            .find(|(name, _)| *name == class_name)
        {
            Some((_, entries)) => entries.push((method_name, signature, wrapper_fn_ptr)),
            None => per_class.push((class_name, vec![(method_name, signature, wrapper_fn_ptr)])),
        }
    }

    for (class_name, entries) in &per_class {
        unsafe { hook_zygote_methods_str(env_ptr, class_name, entries) };
    }
}

/// Rust-native twin of `hook_jni_methods` for the bootstrap zygote tables:
/// resolves each method by name/signature, registers the wrapper via
/// RegisterNatives, and records the original entry points (family `_orig`
/// backups + unhook list) — same flow, no pointer-buffer round-trip.
/// Returns the number of methods hooked.
unsafe fn hook_zygote_methods_str(
    env_ptr: *mut jni::sys::JNIEnv,
    class_name: &str,
    entries: &[(&'static str, &'static str, usize)],
) -> usize {
    let Ok(mut env) = (unsafe { JNIEnv::from_raw(env_ptr) }) else {
        return 0;
    };
    let Ok(class) = env.find_class(class_name) else {
        let _ = env.exception_clear();
        return 0;
    };

    let Some(to_reflected_method) = (unsafe { (**env_ptr).ToReflectedMethod }) else {
        rz_common::loge!(TAG, "JNIEnv::ToReflectedMethod is unavailable");
        return 0;
    };

    let mut native_methods: Vec<jni::NativeMethod> = Vec::with_capacity(entries.len().min(32));
    let mut hooked: Vec<JNINativeMethod> = Vec::new();

    for &(name, sig, wrapper) in entries {
        let mut is_static = false;
        let mid = match env.get_method_id(&class, name, sig) {
            Ok(mid) => mid.into_raw(),
            Err(_) => {
                let _ = env.exception_clear();
                is_static = true;
                match env.get_static_method_id(&class, name, sig) {
                    Ok(mid) => mid.into_raw(),
                    Err(_) => {
                        let _ = env.exception_clear();
                        continue;
                    }
                }
            }
        };

        let method = unsafe { to_reflected_method(env_ptr, class.as_raw(), mid, is_static as jboolean) };
        let method = if method.is_null() {
            JObject::null()
        } else {
            unsafe { JObject::from_raw(method) }
        };

        let modifier = unsafe {
            env.call_method_unchecked(
                &method,
                JMethodID::from_raw(MEMBER_GET_MODIFIERS.load(Ordering::Relaxed)),
                ReturnType::Primitive(Primitive::Int),
                &[],
            )
        }
        .ok()
        .and_then(|v| v.i().ok());
        let exception = env.exception_check().unwrap_or(false);
        if exception || modifier.map_or(true, |m| (m & MODIFIER_NATIVE.load(Ordering::Relaxed)) == 0) {
            let _ = env.exception_clear();
            let _ = env.delete_local_ref(method);
            continue;
        }

        let art_method = crate::art_method::amethod_from_reflected_method(env_ptr, method.as_raw());
        let orig = crate::art_method::amethod_get_data(art_method as usize);
        let _ = env.delete_local_ref(method);

        if native_methods.len() < 32 {
            native_methods.push(jni::NativeMethod {
                name: name.into(),
                sig: sig.into(),
                fn_ptr: wrapper as *mut c_void,
            });
            // First surviving original per family becomes that family's
            // `_orig` backup (jni_hooks.h 431/441/451) — every wrapper calls
            // through it.
            match name.as_bytes() {
                b"nativeForkAndSpecialize" => {
                    if crate::jni_tables::nativeForkAndSpecialize_orig
                        .load(Ordering::Relaxed)
                        == 0
                    {
                        crate::jni_tables::nativeForkAndSpecialize_orig
                            .store(orig as usize, Ordering::Relaxed);
                    }
                }
                b"nativeSpecializeAppProcess" => {
                    if crate::jni_tables::nativeSpecializeAppProcess_orig
                        .load(Ordering::Relaxed)
                        == 0
                    {
                        crate::jni_tables::nativeSpecializeAppProcess_orig
                            .store(orig as usize, Ordering::Relaxed);
                    }
                }
                b"nativeForkSystemServer" => {
                    if crate::jni_tables::nativeForkSystemServer_orig.load(Ordering::Relaxed) == 0 {
                        crate::jni_tables::nativeForkSystemServer_orig
                            .store(orig as usize, Ordering::Relaxed);
                    }
                }
                _ => {}
            }
            hooked.push(JNINativeMethod {
                name: static_cstr(name),
                signature: static_cstr(sig),
                fn_ptr: orig as *mut c_void,
            });
        }

        rz_common::logv!(TAG, "replaced {} {} orig {:p}: {}", class_name, name, orig as *mut c_void, sig);
    }

    if native_methods.is_empty() {
        return 0;
    }
    if let Err(err) = env.register_native_methods(&class, &native_methods) {
        let _ = env.exception_clear();
        rz_common::loge!(
            TAG,
            "RegisterNatives failed for {} ({} methods): {err:?} — zygote JNI hooks inert for this table",
            class_name,
            native_methods.len()
        );
        return 0;
    }

    context::with_jni_hook_list(|list| {
        list.push(context::JniHookEntry {
            class_name: class_name.to_string(),
            methods: hooked,
        });
    });
    native_methods.len()
}

/// `dlerror()` as a printable string ("(null)" when there is none, like the
/// C's `%s` of a NULL pointer).
fn dlerror_str() -> String {
    let ptr = unsafe { libc::dlerror() };
    if ptr.is_null() {
        String::from("(null)")
    } else {
        unsafe { CStr::from_ptr(ptr) }.to_string_lossy().into_owned()
    }
}
