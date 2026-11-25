//! A credential [`Sealer`] backed by the Android Keystore: the key is
//! generated in and never leaves the Keystore (hardware-backed where the
//! phone has secure hardware). The cryptography runs in Kotlin
//! (`gen/android/.../KeystoreSealer.kt`), reached over JNI through the app's
//! class loader, so it works from any thread.

use jni::JNIEnv;
use jni::objects::{JByteArray, JClass, JObject, JValue};
use rebsync_core::credentials::StoreError;
use rebsync_core::credentials::files::Sealer;

pub const SEALER_ID: &str = "android-keystore.aes-256-gcm.v1";
const CLASS: &str = "com.tabenius.rebeqah.KeystoreSealer";

pub struct KeystoreSealer;

/// Run `work` with a JNI environment attached to this thread and the
/// app's `KeystoreSealer` class.
fn with_sealer_class<T>(
    work: impl FnOnce(&mut JNIEnv, &JClass) -> jni::errors::Result<T>,
) -> Result<T, StoreError> {
    let context = ndk_context::android_context();
    // SAFETY: the pointers come from the Android runtime via ndk-context,
    // which Tauri initialises before any command runs.
    let vm = unsafe { jni::JavaVM::from_raw(context.vm().cast()) }
        .map_err(|_| StoreError::Unavailable)?;
    let activity = unsafe { JObject::from_raw(context.context().cast()) };
    let mut env = vm
        .attach_current_thread()
        .map_err(|_| StoreError::Unavailable)?;
    let result = (|| {
        // FindClass on a non-main thread sees only system classes: ask the
        // app's class loader instead.
        let loader = env
            .call_method(
                &activity,
                "getClassLoader",
                "()Ljava/lang/ClassLoader;",
                &[],
            )?
            .l()?;
        let name = env.new_string(CLASS)?;
        let class = env
            .call_method(
                &loader,
                "loadClass",
                "(Ljava/lang/String;)Ljava/lang/Class;",
                &[JValue::Object(&name)],
            )?
            .l()?;
        work(&mut env, &JClass::from(class))
    })();
    match result {
        Ok(value) => Ok(value),
        Err(_) => {
            // A Java exception: tell a failed authentication (wrong key,
            // altered or moved data) apart from the Keystore being unusable.
            let invalid = env.exception_check().unwrap_or(false)
                && env
                    .exception_occurred()
                    .ok()
                    .and_then(|throwable| {
                        let _ = env.exception_clear();
                        env.is_instance_of(&throwable, "javax/crypto/AEADBadTagException")
                            .ok()
                    })
                    .unwrap_or(false);
            let _ = env.exception_clear();
            Err(if invalid {
                StoreError::Invalid
            } else {
                StoreError::Locked
            })
        }
    }
}

fn call(method: &str, input: &[u8], aad: &[u8]) -> Result<Vec<u8>, StoreError> {
    with_sealer_class(|env, class| {
        let input = env.byte_array_from_slice(input)?;
        let aad = env.byte_array_from_slice(aad)?;
        let output = env
            .call_static_method(
                class,
                method,
                "([B[B)[B",
                &[JValue::Object(&input), JValue::Object(&aad)],
            )?
            .l()?;
        env.convert_byte_array(JByteArray::from(output))
    })
}

impl KeystoreSealer {
    /// Whether the Keystore key is in secure hardware; reported, not assumed.
    pub fn hardware_backed() -> Option<bool> {
        with_sealer_class(|env, class| {
            env.call_static_method(class, "hardwareBacked", "()Z", &[])?
                .z()
        })
        .ok()
    }
}

impl Sealer for KeystoreSealer {
    fn id(&self) -> &str {
        SEALER_ID
    }

    fn seal(&self, plaintext: &[u8], aad: &[u8]) -> Result<Vec<u8>, StoreError> {
        call("seal", plaintext, aad)
    }

    fn open(&self, sealed: &[u8], aad: &[u8]) -> Result<Vec<u8>, StoreError> {
        call("open", sealed, aad)
    }
}
