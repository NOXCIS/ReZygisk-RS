//! art_method.h port: ART `ArtMethod` offset probing + reflected-method
//! pointer access (`amethod_init` / `amethod_get_data` /
//! `amethod_from_reflected_method`).
//!
//! PORT TASK: loader/src/injector/art_method.h (all 115 lines). The
//! file-scope statics `art_method_field` / `art_method_size` /
//! `entry_point_offset` / `data_offset` become module statics; the three
//! `static inline` fns become plain fns. Callers: the hook.c `hook_zygote`
//! (`amethod_init`) and `hook_jni_native_methods`
//! (`amethod_from_reflected_method` + `amethod_get_data`) ports in the
//! sibling modules.
//!
//! # Deviations (C → Rust)
//!
//! - Log tag: C `LOG_TAG` is `"zygisk-core" LP_SELECT("32","64")`; the
//!   loader port uses `"zygisk"` (port-wide convention, see misc_port.rs).
//! - The jni crate wrappers used for the C `(*env)->...` calls check for a
//!   pending exception after each call and surface failures as `Err`,
//!   leaving the exception pending exactly like the C. Results the C never
//!   checks are mapped to the C-observable behavior: a failed `GetMethodID`
//!   (C proceeds to `CallObjectMethod` with a NULL id, which ART answers
//!   with NULL + a pending exception) and a failed `CallObjectMethod` /
//!   `GetObjectArrayElement` / `GetLongField` (C: NULL / 0 results) all
//!   become NULL, feeding the same branches with the same log lines.
//! - `GetLongField` has no named jni-crate wrapper; it goes through
//!   `get_field_unchecked(ReturnType::Primitive(Long))`. `FromReflectedMethod`
//!   has no wrapper at all, so it uses the raw `jni::sys` function table.
//! - A null env pointer (or one `JNIEnv::from_raw` rejects): the C
//!   dereferences it and crashes; the port returns `false` / NULL
//!   (defensive — both C call sites pass a valid `GetEnv` result).
//! - C `size_t` subtraction wraps on underflow; the port uses
//!   `wrapping_sub` (identical bit semantics).
//! - C `LOGD` compiles out under `NDEBUG`; the Rust `logd!` always emits
//!   (port-wide convention).

use std::ffi::c_void;
use std::mem::size_of;
use std::ptr;
use std::sync::atomic::{AtomicPtr, AtomicUsize, Ordering};

use jni::objects::{JClass, JFieldID, JObject, JObjectArray};
use jni::signature::{Primitive, ReturnType};
use jni::sys::{jobject, _jfieldID};
use jni::JNIEnv;

use rz_common::{logd, loge, logw};

pub const TAG: &str = rz_common::LOG_TAG;

// art_method.h file-scope statics. Uses atomics for sound Rust access.
static ART_METHOD_FIELD: AtomicPtr<_jfieldID> = AtomicPtr::new(ptr::null_mut());
static ART_METHOD_SIZE: AtomicUsize = AtomicUsize::new(0);
static ENTRY_POINT_OFFSET: AtomicUsize = AtomicUsize::new(0);
static DATA_OFFSET: AtomicUsize = AtomicUsize::new(0);

/// art_method.h line 89: `4 * 9 + 3 * sizeof(void *)` sanity bound.
const MAX_ASSUMED_ART_METHOD_SIZE: usize = 4 * 9 + 3 * size_of::<*mut c_void>();

/// art_method.h `amethod_init`: probe the ART `ArtMethod` layout from the
/// first two `Throwable` constructors and derive `entry_point_offset` /
/// `data_offset`.
pub fn amethod_init(env_ptr: *mut jni::sys::JNIEnv) -> bool {
    let mut env = match unsafe { JNIEnv::from_raw(env_ptr) } {
        Ok(env) => env,
        Err(_) => return false,
    };

    // C: FindClass java/lang/reflect/Executable → GetFieldID "artMethod" "J".
    let clazz: Option<JClass> = match env.find_class("java/lang/reflect/Executable") {
        Ok(clazz) => match env.get_field_id(&clazz, "artMethod", "J") {
            Ok(field) => {
                ART_METHOD_FIELD.store(field.into_raw(), Ordering::Relaxed);
                Some(clazz)
            }
            Err(_) => {
                // C assigns art_method_field = GetFieldID(...) (NULL) first.
                ART_METHOD_FIELD.store(ptr::null_mut(), Ordering::Relaxed);
                logw!(TAG, "Failed to find artMethod field, falling back to FromReflectedMethod");
                if env.exception_check().unwrap_or(false) {
                    let _ = env.exception_clear();
                }
                Some(clazz)
            }
        },
        Err(_) => {
            logw!(TAG, "Executable not found, falling back to FromReflectedMethod");
            if env.exception_check().unwrap_or(false) {
                let _ = env.exception_clear();
            }
            ART_METHOD_FIELD.store(ptr::null_mut(), Ordering::Relaxed);
            None
        }
    };

    let throwable = match env.find_class("java/lang/Throwable") {
        Ok(throwable) => throwable,
        Err(_) => {
            loge!(TAG, "Failed to found Throwable");
            if let Some(clazz) = clazz {
                let _ = env.delete_local_ref(clazz);
            }
            return false;
        }
    };

    let clz = match env.find_class("java/lang/Class") {
        Ok(clz) => clz,
        Err(_) => {
            loge!(TAG, "Failed to found Class");
            if let Some(clazz) = clazz {
                let _ = env.delete_local_ref(clazz);
            }
            let _ = env.delete_local_ref(throwable);
            return false;
        }
    };

    // C: GetMethodID getDeclaredConstructors; DeleteLocalRef(clz).
    let get_declared_constructors = env.get_method_id(
        &clz,
        "getDeclaredConstructors",
        "()[Ljava/lang/reflect/Constructor;",
    );
    let _ = env.delete_local_ref(clz);

    // C: CallObjectMethod(throwable, get_declared_constructors);
    // DeleteLocalRef(throwable). A failed GetMethodID still reaches
    // CallObjectMethod in C with a NULL id (ART answers NULL with a pending
    // exception), which is the same observable state as None here.
    let constructors = match get_declared_constructors {
        Ok(mid) => {
            // SAFETY: mid was looked up on java/lang/Class and the call takes
            // no arguments; C does the same unchecked call.
            unsafe { env.call_method_unchecked(&throwable, mid, ReturnType::Object, &[]) }
                .ok()
                .and_then(|value| value.l().ok())
        }
        Err(_) => None,
    };
    let _ = env.delete_local_ref(throwable);

    let constructors: JObjectArray = match constructors {
        Some(ctors) => JObjectArray::from(ctors),
        None => JObjectArray::from(JObject::null()),
    };
    if constructors.as_raw().is_null() || env.get_array_length(&constructors).unwrap_or(0) < 2 {
        loge!(TAG, "Throwable has less than 2 constructors");
        if let Some(clazz) = clazz {
            let _ = env.delete_local_ref(clazz);
        }
        return false;
    }

    let first_ctor = env.get_object_array_element(&constructors, 0);
    let second_ctor = env.get_object_array_element(&constructors, 1);

    let first = amethod_from_reflected_method(
        env_ptr,
        first_ctor.as_ref().map_or(ptr::null_mut(), |ctor| ctor.as_raw()),
    ) as usize;
    let second = amethod_from_reflected_method(
        env_ptr,
        second_ctor.as_ref().map_or(ptr::null_mut(), |ctor| ctor.as_raw()),
    ) as usize;

    if let Ok(first_ctor) = first_ctor {
        let _ = env.delete_local_ref(first_ctor);
    }
    if let Ok(second_ctor) = second_ctor {
        let _ = env.delete_local_ref(second_ctor);
    }
    let _ = env.delete_local_ref(constructors);
    if let Some(clazz) = clazz {
        let _ = env.delete_local_ref(clazz);
    }

    // C: unsigned `second - first` (wraps).
    let art_method_size = second.wrapping_sub(first);
    ART_METHOD_SIZE.store(art_method_size, Ordering::Relaxed);
    logd!(TAG, "ArtMethod size: {}", art_method_size);

    if MAX_ASSUMED_ART_METHOD_SIZE < art_method_size {
        loge!(TAG, "ArtMethod size exceeds maximum assume. There may be something wrong.");
        return false;
    }

    let (entry_point_offset, data_offset) = derive_offsets(art_method_size);
    ENTRY_POINT_OFFSET.store(entry_point_offset, Ordering::Relaxed);
    DATA_OFFSET.store(data_offset, Ordering::Relaxed);
    logd!(TAG, "ArtMethod entrypoint offset: {}", entry_point_offset);
    logd!(TAG, "ArtMethod data offset: {}", data_offset);

    true
}

/// art_method.h `amethod_get_data`: read the pointer stored at `data_offset`
/// inside the `ArtMethod` object.
pub fn amethod_get_data(self_: usize) -> *mut c_void {
    let data_offset = DATA_OFFSET.load(Ordering::Relaxed);
    unsafe { *((self_.wrapping_add(data_offset)) as *const *mut c_void) }
}

/// art_method.h `amethod_from_reflected_method`: prefer the cached
/// `artMethod` field id (`GetLongField`) and fall back to the raw
/// `FromReflectedMethod` JNI entry when it was unavailable.
pub fn amethod_from_reflected_method(env_ptr: *mut jni::sys::JNIEnv, method: jobject) -> *mut c_void {
    let mut env = match unsafe { JNIEnv::from_raw(env_ptr) } {
        Ok(env) => env,
        Err(_) => return ptr::null_mut(),
    };

    let field = ART_METHOD_FIELD.load(Ordering::Relaxed);
    if !field.is_null() {
        let obj = unsafe { JObject::from_raw(method) };
        match env.get_field_unchecked(
            &obj,
            unsafe { JFieldID::from_raw(field) },
            ReturnType::Primitive(Primitive::Long),
        ) {
            Ok(value) => value.j().unwrap_or(0) as *mut c_void,
            // C: GetLongField returns 0 with a pending exception.
            Err(_) => ptr::null_mut(),
        }
    } else {
        unsafe {
            match (**env_ptr).FromReflectedMethod {
                Some(from_reflected_method) => from_reflected_method(env_ptr, method) as *mut c_void,
                None => ptr::null_mut(),
            }
        }
    }
}

/// art_method.h lines 95-96: entrypoint/data offsets sit at the tail of the
/// ArtMethod object (unsigned wrapping arithmetic, like the C). Split out so
/// the offset arithmetic is host-testable.
#[inline]
fn derive_offsets(size: usize) -> (usize, usize) {
    let ptr_size = size_of::<*mut c_void>();
    let entry_point = size.wrapping_sub(ptr_size);
    let data = entry_point.wrapping_sub(ptr_size);
    (entry_point, data)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn assumed_size_bound_matches_c_expression() {
        assert_eq!(
            MAX_ASSUMED_ART_METHOD_SIZE,
            4 * 9 + 3 * size_of::<*mut c_void>()
        );
    }

    #[test]
    fn derive_offsets_places_entrypoint_and_data_at_object_tail() {
        let size = MAX_ASSUMED_ART_METHOD_SIZE + 4 * size_of::<*mut c_void>();
        let (entry, data) = derive_offsets(size);
        assert_eq!(entry, size - size_of::<*mut c_void>());
        assert_eq!(data, size - 2 * size_of::<*mut c_void>());
    }

    #[test]
    fn amethod_get_data_reads_pointer_at_data_offset() {
        let base_slot = 3;
        DATA_OFFSET.store(base_slot * size_of::<*mut c_void>(), Ordering::Relaxed);

        let mut buf = [0usize; 8];
        let sentinel = 0x1234_5678 as *mut c_void;
        buf[base_slot] = sentinel as usize;

        let base = buf.as_ptr() as usize;
        assert_eq!(amethod_get_data(base), sentinel);
    }
}
