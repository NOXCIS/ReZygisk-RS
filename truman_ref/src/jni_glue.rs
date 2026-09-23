//! JNI reflection writer: applies `spoof::SPOOF_ENTRIES` via
//! `SetStaticObjectField` in the specialized app process. Fail-soft — a
//! missing class/field or a pending exception is logged and skipped, never
//! fatal (the zygote child must survive).

use jni::objects::JValue;
use jni::signature::JavaType;
use jni::{JNIEnv, objects::JString};

use crate::spoof::SpoofEntry;
#[allow(unused_imports)]
use crate::tlog;

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

    // Log the donor-honest value we are replacing (dev evidence only — a
    // pure read, compiled out of release to save a JNI round-trip).
    #[cfg(feature = "truman-log")]
    {
        let old = env
            .get_static_field_unchecked(&class, &field_id, JavaType::Object(STRING_SIG.into()))
            .ok()
            .and_then(|v| v.l().ok());
        if let Some(old) = old {
            // Wrapper only — the local ref from our GetStaticObjectField is
            // released with this JNI frame; the wrapper owns nothing.
            let old = unsafe { JString::from_raw(old.as_raw()) };
            if let Ok(s) = env.get_string(&old) {
                tlog!(
                    "{}.{}: '{}' -> '{}'",
                    entry.class, entry.field, s.to_str().unwrap_or("?"), entry.value
                );
            }
            // The local ref was created by OUR GetStaticObjectField — it is
            // released with this JNI frame; the wrapper owns nothing.
        }
    }

    let value = env
        .new_string(entry.value)
        .map_err(|e| format!("new_string({}) failed: {e}", entry.value))?;

    env.set_static_field(&class, (&class, entry.field, STRING_SIG), JValue::Object(&value))
        .map_err(|e| format!("set_static_field({}.{}) failed: {e}", entry.class, entry.field))?;

    // Verify the spoof actually took: re-read the field and compare. A
    // mismatch is fail-soft (Err → caller logs in dev builds) but never
    // leaves us assuming a rewrite that ART silently dropped.
    let written = match env
        .get_static_field_unchecked(&class, field_id, JavaType::Object(STRING_SIG.into()))
        .ok()
        .and_then(|v| v.l().ok())
    {
        Some(v) => {
            // Wrapper only: no Drop, so no DeleteLocalRef happens here. The
            // local ref belongs to this JNI frame and dies with it.
            let jstr = unsafe { JString::from_raw(v.as_raw()) };
            env.get_string(&jstr)
                .ok()
                .map(|s| s.to_str().unwrap_or("").to_string())
        }
        None => None,
    };
    match written {
        Some(current) if current == entry.value => Ok(()),
        Some(current) => Err(format!(
            "verify({}.{}) failed: field reads '{}' but expected '{}'",
            entry.class, entry.field, current, entry.value
        )),
        None => Err(format!(
            "verify({}.{}) failed: field could not be re-read",
            entry.class, entry.field
        )),
    }
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
    // Borrowed ref — never DeleteLocalRef it. The wrapper has no Drop, so
    // there is nothing to forget; the ref outlives this call by design.
    env.get_string(&s)
        .ok()
        .map(|j| j.to_str().unwrap_or("").to_string())
}
