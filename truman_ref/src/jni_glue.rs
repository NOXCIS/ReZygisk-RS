//! JNI reflection writer: applies `spoof::SPOOF_ENTRIES` via
//! `SetStaticObjectField` in the specialized app process. Fail-soft — a
//! missing class/field or a pending exception is logged and skipped, never
//! fatal (the zygote child must survive).

use jni::objects::{JObject, JValue};
use jni::signature::JavaType;
use jni::{JNIEnv, objects::JString};

use crate::spoof::SpoofEntry;
use crate::truman_log;

const STRING_SIG: &str = "Ljava/lang/String;";

/// Apply one rewrite entry. Returns Ok(()) when the field was written,
/// Err(reason) for the fail-soft log line.
pub fn apply_entry(env: &mut JNIEnv, entry: &SpoofEntry) -> Result<(), String> {
    let class = env
        .find_class(entry.class)
        .map_err(|e| format!("find_class({}) failed: {e}", entry.class))?;

    let field_id = env
        .get_static_field_id(&class, entry.field, STRING_SIG)
        .map_err(|e| format!("get_static_field_id({}.{}) failed: {e}", entry.class, entry.field))?;

    // Log the donor-honest value we are replacing (verification evidence).
    let old = env
        .get_static_field_unchecked(&class, &field_id, JavaType::Object(STRING_SIG.into()))
        .ok()
        .and_then(|v| v.l().ok());
    if let Some(old) = old {
        let old = unsafe { JString::from_raw(old.as_raw()) };
        if let Ok(s) = env.get_string(&old) {
            truman_log(&format!(
                "{}.{}: '{}' -> '{}'",
                entry.class, entry.field, s.to_str().unwrap_or("?"), entry.value
            ));
        }
        // The local ref was created by OUR GetStaticObjectField — dropping
        // the wrapper here is correct. `forget` would leak it.
        drop(old);
    }

    let value = env
        .new_string(entry.value)
        .map_err(|e| format!("new_string({}) failed: {e}", entry.value))?;

    env.set_static_field(&class, (&class, entry.field, STRING_SIG), JValue::Object(&value))
        .map_err(|e| format!("set_static_field({}.{}) failed: {e}", entry.class, entry.field))?;

    Ok(())
}

/// Drop any pending exception so the process keeps running normally.
pub fn clear_pending(env: &mut JNIEnv) -> bool {
    if env.exception_check().unwrap_or(false) {
        let _ = env.exception_clear();
        true
    } else {
        false
    }
}

/// Read a borrowed jstring (NOT owned — belongs to the zygote's args) into a
/// Rust String without deleting the local ref.
pub unsafe fn borrow_jstring(env: &mut JNIEnv, raw: *mut jni::sys::_jobject) -> Option<String> {
    if raw.is_null() {
        return None;
    }
    let s = JString::from_raw(raw);
    let out = env
        .get_string(&s)
        .ok()
        .map(|j| j.to_str().unwrap_or("").to_string());
    std::mem::forget(s); // borrowed ref — never DeleteLocalRef it
    out
}

/// Keep `JObject::from_raw` importable without an unused-import warning.
#[allow(dead_code)]
fn _unused(_: JObject) {}
