#[cfg(target_os = "android")]
use jni::objects::JClass;
#[cfg(target_os = "android")]
use jni::JNIEnv;

#[cfg(target_os = "android")]
#[no_mangle]
pub extern "system" fn Java_com_simplesecrets_Library_init(mut _env: JNIEnv, _class: JClass) {
    // Initialization code for Android
}
