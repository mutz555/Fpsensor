#include <android/log.h>
#include <jni.h>
#include <cstring>
#include <cstdio>
#include <sys/system_properties.h>
#include "zygisk.hpp"

#define LOGI(...) __android_log_print(ANDROID_LOG_INFO, "FingerprintBypasser", __VA_ARGS__)
#define LOGE(...) __android_log_print(ANDROID_LOG_ERROR, "FingerprintBypasser", __VA_ARGS__)

/**
 * Zygisk module to bypass fingerprint hardware detection.
 * Hooks the method isFpHardwareDetected() in FingerprintServiceStubImpl to always return true.
 */
class FingerprintBypasserModule : public zygisk::ModuleBase {
private:
    bool shouldHook = false;
    JNIEnv* env = nullptr;

    // Target class and method signatures
    const char* TARGET_CLASS = "com/android/server/biometrics/sensors/fingerprint/FingerprintServiceStubImpl";
    const char* TARGET_METHOD1 = "isFpHardwareDetected";
    const char* TARGET_METHOD2 = "isFingerprintHardwareDetected";
    const char* TARGET_METHOD3 = "isFingerprintHardwarePresent";
    const char* TARGET_METHOD4 = "isHardwareDetected";
    const char* TARGET_SIG     = "()Z";

    /**
     * Hooked method implementation for fingerprint hardware detection.
     * Always returns JNI_TRUE. Also sets fingerprint-related system properties
     * on first call to bypass checks and logs the bypass event.
     */
    static jboolean isFpHardwareDetected_hook(JNIEnv* env, jobject thiz) {
        static int call_count = 0;
        call_count++;
        LOGI("Fingerprint hardware check invoked (count=%d), forcing return TRUE", call_count);

        static bool propsSet = false;
        if (!propsSet) {
            LOGI("Overriding fingerprint-related system properties");
            __system_property_set("persist.vendor.sys.fp.vendor", "goodix");
            __system_property_set("persist.vendor.sys.fp.module", "true");
            __system_property_set("ro.vendor.fingerprint", "infinix/X6833B*/Infinix-X6833B*");
            __system_property_set("ro.boot.fingerprint", "goodix");
            __system_property_set("ro.boot.fpsensor", "goodix");
            __system_property_set("ro.hardware.fingerprint", "goodix");
            __system_property_set("ro.hardware.fp", "goodix");
            __system_property_set("sys.fp.goodix", "enabled");
            __system_property_set("sys.fp.vendor", "goodix");
            __system_property_set("ro.infinix.fingerprint", "goodix");
            __system_property_set("ro.hardware.fingerprint.supported", "1");
            __system_property_set("ro.vendor.fingerprint.supported", "1");
            __system_property_set("ro.vendor.infinix.fingerprint.supported", "1");
            __system_property_set("persist.sys.fp.supported", "1");
            __system_property_set("vendor.sys.fp.module", "true");
            __system_property_set("vendor.sys.fp.present", "true");
            __system_property_set("vendor.sys.fp.enable", "true");
            __system_property_set("vendor.sys.fp.hardware", "true");
            propsSet = true;
        }

        LOGE("===============================================");
        LOGE(">> FINGERPRINT HARDWARE DETECTION BYPASSED! <<");
        LOGE("===============================================");
        return JNI_TRUE;
    }

    /**
     * Attempt to load the target class using the context ClassLoader if FindClass fails.
     */
    jclass findClassWithClassLoader(const char* name) {
        jclass threadClass = env->FindClass("java/lang/Thread");
        if (!threadClass) {
            LOGE("Failed to find Thread class");
            return nullptr;
        }
        jmethodID currentThread = env->GetStaticMethodID(threadClass, "currentThread", "()Ljava/lang/Thread;");
        if (!currentThread) {
            LOGE("Failed to find Thread.currentThread");
            env->DeleteLocalRef(threadClass);
            return nullptr;
        }
        jobject threadObj = env->CallStaticObjectMethod(threadClass, currentThread);
        if (!threadObj) {
            LOGE("Failed to get current Thread object");
            env->DeleteLocalRef(threadClass);
            return nullptr;
        }
        jmethodID getCL = env->GetMethodID(threadClass, "getContextClassLoader", "()Ljava/lang/ClassLoader;");
        if (!getCL) {
            LOGE("Failed to find getContextClassLoader");
            env->DeleteLocalRef(threadObj);
            env->DeleteLocalRef(threadClass);
            return nullptr;
        }
        jobject classLoader = env->CallObjectMethod(threadObj, getCL);
        env->DeleteLocalRef(threadObj);
        env->DeleteLocalRef(threadClass);
        if (!classLoader) {
            LOGE("Failed to get ContextClassLoader");
            return nullptr;
        }
        jclass loaderClass = env->FindClass("java/lang/ClassLoader");
        if (!loaderClass) {
            LOGE("Failed to find ClassLoader class");
            env->DeleteLocalRef(classLoader);
            return nullptr;
        }
        jmethodID loadClass = env->GetMethodID(loaderClass, "loadClass", "(Ljava/lang/String;)Ljava/lang/Class;");
        if (!loadClass) {
            LOGE("Failed to find loadClass method");
            env->DeleteLocalRef(loaderClass);
            env->DeleteLocalRef(classLoader);
            return nullptr;
        }
        // Convert class name to dot notation
        char clsName[256];
        strncpy(clsName, name, sizeof(clsName) - 1);
        clsName[sizeof(clsName) - 1] = '\0';
        for (char* p = clsName; *p; ++p) {
            if (*p == '/') *p = '.';
        }
        jstring jName = env->NewStringUTF(clsName);
        jclass result = (jclass)env->CallObjectMethod(classLoader, loadClass, jName);
        env->DeleteLocalRef(jName);
        env->DeleteLocalRef(loaderClass);
        env->DeleteLocalRef(classLoader);
        return result;
    }

    /**
     * Set a range of fingerprint-related system properties to expected values.
     */
    void setupSystemPropertyHooks() {
        LOGI("Setting fingerprint-related system properties");
        const char* props[][2] = {
            {"persist.vendor.sys.fp.vendor", "goodix"},
            {"persist.vendor.sys.fp.module", "true"},
            {"ro.vendor.fingerprint", "infinix/X6833B*/Infinix-X6833B*"},
            {"ro.boot.fingerprint", "goodix"},
            {"ro.boot.fpsensor", "goodix"},
            {"ro.hardware.fingerprint", "goodix"},
            {"ro.hardware.fp", "goodix"},
            {"sys.fp.goodix", "enabled"},
            {"sys.fp.vendor", "goodix"},
            {"ro.infinix.fingerprint", "goodix"},
            {"ro.hardware.fingerprint.supported", "1"},
            {"ro.vendor.fingerprint.supported", "1"},
            {"ro.vendor.infinix.fingerprint.supported", "1"},
            {"persist.sys.fp.supported", "1"},
            {"vendor.sys.fp.module", "true"},
            {"vendor.sys.fp.present", "true"},
            {"vendor.sys.fp.enable", "true"},
            {"vendor.sys.fp.hardware", "true"}
        };
        int count = sizeof(props) / sizeof(props[0]);
        for (int i = 0; i < count; i++) {
            __system_property_set(props[i][0], props[i][1]);
            LOGI("  Set: %s = %s", props[i][0], props[i][1]);
        }
    }

    /**
     * Find and hook the fingerprint hardware detection method in the target class.
     */
    bool hookFingerprintServiceMethod() {
        LOGI("Attempting to hook %s", TARGET_CLASS);
        jclass cls = env->FindClass(TARGET_CLASS);
        if (!cls) {
            if (env->ExceptionCheck()) env->ExceptionClear();
            LOGI("FindClass failed, trying ClassLoader");
            cls = findClassWithClassLoader(TARGET_CLASS);
        }
        if (!cls) {
            LOGE("Failed to find class %s", TARGET_CLASS);
            return false;
        }

        const char* methods[] = { TARGET_METHOD1, TARGET_METHOD2, TARGET_METHOD3, TARGET_METHOD4 };
        jmethodID mid = nullptr;
        const char* foundMethod = nullptr;
        for (const char* m : methods) {
            mid = env->GetMethodID(cls, m, TARGET_SIG);
            if (mid) {
                foundMethod = m;
                break;
            }
            if (env->ExceptionCheck()) env->ExceptionClear();
        }
        if (!foundMethod) {
            LOGE("Fingerprint hardware detection method not found in %s", TARGET_CLASS);
            env->DeleteLocalRef(cls);
            return false;
        }
        LOGI("Hooking method %s", foundMethod);
        JNINativeMethod nativeMethod = {
            const_cast<char*>(foundMethod),
            const_cast<char*>(TARGET_SIG),
            (void*)isFpHardwareDetected_hook
        };
        if (env->RegisterNatives(cls, &nativeMethod, 1) != 0) {
            LOGE("Failed to register native for %s", foundMethod);
            env->DeleteLocalRef(cls);
            return false;
        }
        LOGI("Successfully hooked %s", foundMethod);
        env->DeleteLocalRef(cls);
        return true;
    }

public:
    // Called when Zygisk loads the module; save JNIEnv for later use
    void onLoad(zygisk::Api* api, JNIEnv* env) override {
        this->env = env;
        LOGI("FingerprintBypasser module loaded");
    }

    // Before system_server specialization: mark we should hook
    void preServerSpecialize(zygisk::ServerSpecializeArgs* args) override {
        shouldHook = true;
        LOGI("preServerSpecialize: targeting system_server process");
    }

    // After system_server specialization: perform hooking
    void postServerSpecialize(const zygisk::ServerSpecializeArgs* args) override {
        if (shouldHook) {
            LOGI("postServerSpecialize: installing fingerprint hooks");
            setupSystemPropertyHooks();
            if (!hookFingerprintServiceMethod()) {
                LOGE("Error: Failed to hook fingerprint hardware detection method");
            }
        }
    }
};

static FingerprintBypasserModule module;

// Required entry point for Zygisk modules
__attribute__((section(".zygisk"))) 
void zygisk_module_entry(zygisk::Api* api, JNIEnv* env) {
    module.onLoad(api, env);
}

// Companion process entry (not used here)
__attribute__((section(".zygisk"))) 
void zygisk_companion_entry(zygisk::Api* api, JNIEnv* env) {
    // Not used
}

// JNI_OnLoad to handle cases where the library is loaded directly (not really needed for Zygisk)
extern "C" jint JNI_OnLoad(JavaVM* vm, void* reserved) {
    return JNI_VERSION_1_6;
}