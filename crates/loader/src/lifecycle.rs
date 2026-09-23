//! Port of hook.c lines 1217-1290: `init` (1217-1227) and `cleanup`
//! (1228-1290).
//!
//! `init` is deliberately small — exactly like the C it only memsets the
//! context, fills env/args.ptr/pid, initializes the hook_info_lock mutex and
//! publishes the context into `g_ctx`. The big init sequence (daemon flags,
//! update_mnt_ns, module pre-calls, fd sanitization) lives in the
//! specialize/pre functions that CALL rz_init, not here.
//!
//! `cleanup` runs after the original JNI call returns (every wrapper in
//! jni_tables.rs calls it): it unhooks the JNI methods recorded in
//! `context::JNI_HOOK_LIST`, releases the register/ignore/plt lists, strips
//! the API function pointers out of every loaded module, arms the unloader
//! and destroys the hook_info_lock. In the zygote itself (not a child —
//! `is_zygote_child` false) it returns right after clearing `g_ctx`, leaving
//! the hooks installed for the next fork pass — the C does exactly this.
//!
//! Sibling contract: crate::jni_tables calls these with the signatures below.
//!
//! C-parity notes:
//! - `memset(ctx, 0, sizeof(struct zygisk_context))` is an explicit
//!   all-fields-zero assignment: Rust cannot hold uninitialized
//!   `Vec`/`String`/`pthread_mutex_t`, so every field gets its
//!   memset-equivalent zero value (empty strings/vecs, zeroed arrays, an
//!   all-zero mutex — `PTHREAD_MUTEX_INITIALIZER` is all-zero on
//!   bionic/glibc) and `pthread_mutex_init` runs afterwards, as in the C.
//! - The JNI unhook loop wraps `ctx.env` with `JNIEnv::from_raw` like the
//!   rest of the crate. A NULL env would crash the C; here the JNI calls
//!   are skipped but the lists are still released (closest well-defined
//!   path).
//! - `RegisterNatives` goes through the jni crate's
//!   `register_native_methods` (the same call jni_hooks.rs uses); its error
//!   path covers both a non-zero return and a pending exception, and the
//!   C's `methods_count > 0` guard is kept.
//! - The C's `regfree`+`free` loops, the plt list free loop and
//!   `free(jni_hook_list)` all become Rust drops (`Vec::clear()` /
//!   `Option = None`).

use std::ffi::{c_void, CStr};

use jni::JNIEnv;

use crate::context::{self, ZygiskArgs, ZygiskContext, MAX_EXEMPTED_FDS, MAX_FD_SIZE};

/// Module-local logcat tag (the whole library logs as "zygisk" in the C).
const TAG: &str = rz_common::LOG_TAG;

// ---------------------------------------------------------------------------
// hook.c `rz_init` (1217-1227)
// ---------------------------------------------------------------------------

pub unsafe fn init(ctx: &mut ZygiskContext, env: *mut jni::sys::JNIEnv, args: *mut c_void) {
    // C: memset(ctx, 0, sizeof(struct zygisk_context)) — every field gets
    // its memset-equivalent zero value (the process string is empty, like
    // the C's zeroed char *).
    *ctx = ZygiskContext {
        env: std::ptr::null_mut(),
        args: ZygiskArgs { ptr: std::ptr::null_mut() },
        process: String::new(),
        pid: 0,
        flags: 0,
        info_flags: 0,
        allowed_fds: [0; MAX_FD_SIZE],
        exempted_fds: [0; MAX_EXEMPTED_FDS],
        exempted_fds_count: 0,
        // PTHREAD_MUTEX_INITIALIZER is all-zero on bionic/glibc — the C's
        // memset produces the same bit pattern.
        hook_info_lock: unsafe { std::mem::zeroed() },
        register_info: Vec::new(),
        ignore_info: Vec::new(),
    };

    ctx.env = env;
    ctx.args.ptr = args;
    ctx.pid = -1;
    libc::pthread_mutex_init(&mut ctx.hook_info_lock, std::ptr::null());

    // C: g_ctx = ctx;
    context::set_ctx(ctx as *mut ZygiskContext);
}

// ---------------------------------------------------------------------------
// hook.c `rz_cleanup` (1228-1290)
// ---------------------------------------------------------------------------

pub unsafe fn cleanup(ctx: &mut ZygiskContext) {
    // C: g_ctx = NULL;
    context::set_ctx(std::ptr::null_mut());

    // C: if (!is_zygote_child(ctx)) return; — the zygote itself keeps the
    // hooks, the lists and the mutex for the next fork pass (the C's early
    // return also skips pthread_mutex_destroy); only the child tears down.
    if !context::is_zygote_child(ctx) {
        return;
    }

    context::SHOULD_UNMAP_ZYGISK.store(true, std::sync::atomic::Ordering::Relaxed);

    // C: /* INFO: Unhook JNI methods */
    let mut env = unsafe { JNIEnv::from_raw(ctx.env) }.ok();
    if let Some(env) = env.as_mut() {
        context::with_jni_hook_list(|list| {
            for entry in list.iter() {
                // C: jclass jc = FindClass(env, entry->class_name); if (jc) {...}
                let Ok(jc) = env.find_class(entry.class_name.as_str()) else {
                    continue;
                };
                // C: entry->methods_count > 0 && RegisterNatives(...) != 0
                if !entry.methods.is_empty() {
                    let native_methods: Vec<jni::NativeMethod> = entry
                        .methods
                        .iter()
                        .map(|m| jni::NativeMethod {
                            name: unsafe { CStr::from_ptr(m.name) }
                                .to_string_lossy()
                                .into_owned()
                                .into(),
                            sig: unsafe { CStr::from_ptr(m.signature) }
                                .to_string_lossy()
                                .into_owned()
                                .into(),
                            fn_ptr: m.fn_ptr,
                        })
                        .collect();
                    if env.register_native_methods(&jc, &native_methods).is_err() {
                        rz_common::loge!(
                            TAG,
                            "Failed to restore JNI hook of class [{}]",
                            entry.class_name
                        );
                        // RegisterNatives throws (NoSuchMethodError for the
                        // method it could not resolve) and leaves the exception
                        // *pending*. A pending exception on a JVM thread is
                        // fatal: it resurfaces at the next JNI call and tears
                        // the process down — that is how one failed restore
                        // became "System zygote died with fatal exception" in
                        // the zygote child. The install side already clears it
                        // (jni_hooks.rs); the C needed no clear only because
                        // its literals can never fail this lookup.
                        let _ = env.exception_clear();
                        context::SHOULD_UNMAP_ZYGISK.store(false, std::sync::atomic::Ordering::Relaxed);
                    }
                }
                let _ = env.delete_local_ref(jc);
            }
        });
    }
    // C: free(jni_hook_list); jni_hook_list = NULL; jni_hook_list_count = 0.
    // The Vec drop releases every entry's class_name String + methods Vec
    // (the C's per-entry free(entry->class_name) / free(entry->methods)).
    context::with_jni_hook_list(|list| list.clear());

    // C: regfree + free(symbol) for each register_info entry, count = 0;
    // same for ignore_info. Rust's Regex/String drops perform the releases.
    ctx.register_info.clear();
    ctx.ignore_info.clear();

    // C: if (plt_hook_list) { free lib_path/symbol per entry; free(list);
    // plt_hook_list = NULL; plt_hook_list_count = 0; }. The Vec clear
    // frees the entry Strings.
    context::with_plt_hook_list(|list| list.clear());

    // C: /* INFO: Strip out all API function pointers */
    // Snapshot + raw writes (F1 discipline): keep the table lock free while
    // touching elements; no module code runs here, so the short snapshots
    // are purely to avoid reintroducing the &mut Vec aliasing shape.
    let modules = context::module_snapshot();
    for i in 0..modules.len {
        // C: memset(&zygisk_modules[i], 0, sizeof(zygisk_modules[i])). Use
        // Default instead of mem::zeroed for sound Rust access.
        unsafe { *modules.base.add(i) = crate::abi::ReZygiskModule::default() };
    }

    context::ENABLE_UNLOADER.store(true, std::sync::atomic::Ordering::Relaxed);

    libc::pthread_mutex_destroy(&mut ctx.hook_info_lock);
}
