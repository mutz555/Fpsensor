#include <cstdlib>
#include <unistd.h>
#include <sys/system_properties.h>
#include <dlfcn.h>
#include <cstring>
#include <algorithm>
#include <android/log.h>
#include <jni.h>

#include "zygisk.hpp"

// Helper function for min value since we're using -fno-exceptions
template <typename T>
inline T min(T a, T b) {
    return (a < b) ? a : b;
}

// Detailed logging for debugging
#define LOGT(...) __android_log_print(ANDROID_LOG_VERBOSE, "FingerprintBypasser", "[TRACE] " __VA_ARGS__)
#define LOGD(...) __android_log_print(ANDROID_LOG_DEBUG, "FingerprintBypasser", "[DEBUG] " __VA_ARGS__)
#define LOGI(...) __android_log_print(ANDROID_LOG_INFO, "FingerprintBypasser", "[INFO] " __VA_ARGS__)
#define LOGW(...) __android_log_print(ANDROID_LOG_WARN, "FingerprintBypasser", "[WARN] " __VA_ARGS__)
#define LOGE(...) __android_log_print(ANDROID_LOG_ERROR, "FingerprintBypasser", "[ERROR] " __VA_ARGS__)

// Debug function to dump system properties
void dump_system_info() {
    char sdk_ver[PROP_VALUE_MAX];
    char device[PROP_VALUE_MAX];
    char model[PROP_VALUE_MAX];
    char manufacturer[PROP_VALUE_MAX];
    char fingerprint[PROP_VALUE_MAX];

    __system_property_get("ro.build.version.sdk", sdk_ver);
    __system_property_get("ro.product.device", device);
    __system_property_get("ro.product.model", model);
    __system_property_get("ro.product.manufacturer", manufacturer);
    __system_property_get("ro.build.fingerprint", fingerprint);

    LOGI("===== System Information =====");
    LOGI("Android SDK: %s", sdk_ver);
    LOGI("Device: %s", device);
    LOGI("Model: %s", model);
    LOGI("Manufacturer: %s", manufacturer);
    LOGI("Fingerprint: %s", fingerprint);
    LOGI("=============================\n");
}

// Target class and methods
const char* TARGET_CLASS = "com/android/server/biometrics/sensors/fingerprint/FingerprintServiceStubImpl";
const char* TARGET_METHOD_HYPEROS = "isFpHardwareDetected";
const char* TARGET_METHOD_ANDROID14 = "isFingerprintHardwareDetected";
const char* TARGET_METHOD_ANDROID13 = "isFingerprintHardwarePresent";
const char* TARGET_METHOD_SIG = "()Z"; // signature - returns boolean, no params

/**
 * Hook implementation for isFpHardwareDetected()
 * Always returns true regardless of actual hardware status
 */
jboolean isFpHardwareDetected_hook(JNIEnv* env, jobject thiz) {
    static int hook_call_count = 0;
    hook_call_count++;

    LOGI("!!!!! HOOKED: Fingerprint hardware detection method called %d times - FORCING TRUE !!!!!", hook_call_count);

    // Optional: dump stack for debugging
    jclass threadClass = env->FindClass("java/lang/Thread");
    if (threadClass) {
        jmethodID currentThreadMethod = env->GetStaticMethodID(threadClass, "currentThread", "()Ljava/lang/Thread;");
        if (currentThreadMethod) {
            jobject threadObj = env->CallStaticObjectMethod(threadClass, currentThreadMethod);
            if (threadObj) {
                jmethodID getStackTraceMethod = env->GetMethodID(threadClass, "getStackTrace", "()[Ljava/lang/StackTraceElement;");
                if (getStackTraceMethod) {
                    jobjectArray stackArray = (jobjectArray)env->CallObjectMethod(threadObj, getStackTraceMethod);
                    if (stackArray) {
                        jsize stackSize = env->GetArrayLength(stackArray);
                        LOGI("Stack depth: %d", stackSize);
                        LOGI("CALL STACK:");
                        jclass elementClass = env->FindClass("java/lang/StackTraceElement");
                        jmethodID getClassNameMethod = env->GetMethodID(elementClass, "getClassName", "()Ljava/lang/String;");
                        jmethodID getMethodNameMethod = env->GetMethodID(elementClass, "getMethodName", "()Ljava/lang/String;");

                        for (jsize i = 0; i < min((int)stackSize, 5); i++) {
                            jobject element = env->GetObjectArrayElement(stackArray, i);
                            if (element) {
                                jstring classNameStr = (jstring)env->CallObjectMethod(element, getClassNameMethod);
                                jstring methodNameStr = (jstring)env->CallObjectMethod(element, getMethodNameMethod);
                                if (classNameStr && methodNameStr) {
                                    const char* className = env->GetStringUTFChars(classNameStr, nullptr);
                                    const char* methodName = env->GetStringUTFChars(methodNameStr, nullptr);
                                    LOGI("  [%d] %s.%s()", i, className, methodName);
                                    env->ReleaseStringUTFChars(classNameStr, className);
                                    env->ReleaseStringUTFChars(methodNameStr, methodName);
                                }
                                env->DeleteLocalRef(element);
                            }
                        }

                        env->DeleteLocalRef(elementClass);
                        env->DeleteLocalRef(stackArray);
                    }
                }
                env->DeleteLocalRef(threadObj);
            }
        }
        env->DeleteLocalRef(threadClass);
    }

    // Re-apply property overrides to ensure the values remain
    static bool refreshed_properties = false;
    if (!refreshed_properties) {
        LOGI("Refreshing system properties in hook execution");
        const char* all_fp_props[][2] = {
            {"persist.vendor.sys.fp.vendor", "goodix"},
            {"persist.vendor.sys.fp.module", "true"},
            {"ro.vendor.fingerprint", "infinix/X6833B*/Infinix-X6833B*"},
            {"ro.boot.fingerprint", "goodix"},
            {"ro.hardware.fingerprint", "goodix"},
            {"ro.hardware.fingerprint.supported", "1"}
        };
        for (auto& prop : all_fp_props) {
            __system_property_set(prop[0], prop[1]);
        }
        refreshed_properties = true;
    }

    LOGE("===============================================");
    LOGE(">> FINGERPRINT HARDWARE DETECTION BYPASSED! <<");
    LOGE(">> HOOK EXECUTED SUCCESSFULLY <<");
    LOGE("===============================================");

    return JNI_TRUE; // Always return true
}

/**
 * Hook for SystemProperties.get (with default)
 * Bypasses permission to read vendor fingerprint props
 */
jstring systemPropertiesGetHook(JNIEnv* env, jclass clazz, jstring key, jstring def) {
    const char* keyC = env->GetStringUTFChars(key, nullptr);
    if (keyC) {
        if (strcmp(keyC, "persist.vendor.sys.fp.vendor") == 0) {
            env->ReleaseStringUTFChars(key, keyC);
            return env->NewStringUTF("goodix");
        }
        if (strcmp(keyC, "persist.vendor.sys.fp.module") == 0) {
            env->ReleaseStringUTFChars(key, keyC);
            return env->NewStringUTF("true");
        }
    }
    char val[PROP_VALUE_MAX] = {0};
    int len = __system_property_get(keyC ? keyC : "", val);
    env->ReleaseStringUTFChars(key, keyC);
    if (len > 0) {
        jstring result = env->NewStringUTF(val);
        return result;
    } else {
        if (def) {
            const char* defC = env->GetStringUTFChars(def, nullptr);
            jstring res = env->NewStringUTF(defC);
            env->ReleaseStringUTFChars(def, defC);
            return res;
        }
        return env->NewStringUTF("");
    }
}

/**
 * Hook for SystemProperties.get (no default)
 */
jstring systemPropertiesGetHookNoDef(JNIEnv* env, jclass clazz, jstring key) {
    jstring emptyStr = env->NewStringUTF("");
    jstring res = systemPropertiesGetHook(env, clazz, key, emptyStr);
    env->DeleteLocalRef(emptyStr);
    return res;
}

class FingerprintBypasserModule : public zygisk::ModuleBase {
    // Constructor dengan atribut yang diperlukan
    __attribute__((constructor))
    static void init() {
        __android_log_print(ANDROID_LOG_ERROR, "FINGERPRINT_BYPASS", "Zygisk module loaded!");
    }
public:
    void onLoad(zygisk::Api* api, JNIEnv* env) override {
        this->api = api;
        this->env = env;
        LOGI("**************************************************");
        LOGI("*   Fingerprint Bypasser Module v1.0 LOADED!    *");
        LOGI("*          Build date: May 4, 2025             *");
        LOGI("**************************************************");
        LOGI("Module loaded into process memory");
        dump_system_info();
        JavaVM* vm;
        env->GetJavaVM(&vm);
        if (vm) {
            LOGI("Successfully retrieved JavaVM pointer");
        }
    }

    void preAppSpecialize(zygisk::AppSpecializeArgs* args) override {
        if (args && args->nice_name) {
            const char* process_name = env->GetStringUTFChars(args->nice_name, nullptr);
            if (process_name) {
                if (strcmp(process_name, "system_server") == 0) {
                    shouldHook = true;
                    LOGI("Targeting system_server process for hooking");
                }
                env->ReleaseStringUTFChars(args->nice_name, process_name);
            }
        }
    }
    void postAppSpecialize(const zygisk::AppSpecializeArgs* args) override {
        if (shouldHook) {
            installHooks();
        }
    }
    void preServerSpecialize(zygisk::ServerSpecializeArgs* args) override {
        shouldHook = true;
        LOGE("CRITICAL: Targeting system_server process for hooking (preServerSpecialize)");
        LOGI("OVERRIDE: Early setting of fingerprint properties in preServerSpecialize");
        __system_property_set("persist.vendor.sys.fp.vendor", "goodix");
        __system_property_set("persist.vendor.sys.fp.module", "true");
        __system_property_set("ro.vendor.fingerprint", "infinix/X6833B*/Infinix-X6833B*");
        __system_property_set("ro.hardware.fingerprint", "goodix");
        __system_property_set("ro.hardware.fingerprint.supported", "1");
    }
    void postServerSpecialize(const zygisk::ServerSpecializeArgs* args) override {
        if (shouldHook) {
            LOGE("CRITICAL: Running installHooks in postServerSpecialize");
            installHooks();
        } else {
            LOGE("ERROR: shouldHook is false in postServerSpecialize");
        }
    }

private:
    zygisk::Api* api = nullptr;
    JNIEnv* env = nullptr;
    bool shouldHook = false;

    void installHooks() {
        LOGI("Installing fingerprint hardware detection hook");
        // Step 1: Set fingerprint-related system properties
        setupSystemPropertyHooks();
        // Step 2: Hook SystemProperties.get to bypass property permissions
        hookSystemPropertiesGet();
        // Step 3: Hook the fingerprint service method
        bool methodHookSuccess = hookFingerprintServiceMethod();
        if (!methodHookSuccess) {
            LOGE("Could not hook fingerprint method, trying alternatives");
            tryFindAndHookClassLoader();
        }
    }

    void hookSystemPropertiesGet() {
        jclass sysProps = env->FindClass("android/os/SystemProperties");
        if (sysProps == nullptr) {
            LOGE("Failed to find SystemProperties class");
            return;
        }
        static JNINativeMethod sp_methods[] = {
            {"get", "(Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;", (void*)systemPropertiesGetHook},
            {"get", "(Ljava/lang/String;)Ljava/lang/String;", (void*)systemPropertiesGetHookNoDef}
        };
        int res = env->RegisterNatives(sysProps, sp_methods, 2);
        if (res < 0) {
            LOGE("Failed to register SystemProperties.get hook, code=%d", res);
        } else {
            LOGI("Hooked SystemProperties.get methods successfully");
        }
        env->DeleteLocalRef(sysProps);
    }

    // Override ALL fingerprint-related system properties
    void setupSystemPropertyHooks() {
        LOGE("OVERRIDE: Setting ALL system properties for fingerprint hardware");
        const char* all_fp_props[][2] = {
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
        int prop_count = sizeof(all_fp_props) / sizeof(all_fp_props[0]);
        LOGI("OVERRIDE: Setting %d fingerprint system properties", prop_count);
        for (int i = 0; i < prop_count; i++) {
            __system_property_set(all_fp_props[i][0], all_fp_props[i][1]);
            LOGI("  [%d/%d] Set: %s = %s", i+1, prop_count, all_fp_props[i][0], all_fp_props[i][1]);
        }
        LOGI("OVERRIDE: All fingerprint properties have been set");
        LOGI("=== If detection still fails, check logcat ===\n");
    }

    // Hook the fingerprint hardware detection method
    bool hookFingerprintServiceMethod() {
        LOGI("Attempting to hook fingerprint hardware detection");
        LOGI("Direct class lookup for %s", TARGET_CLASS);
        jclass fingerprint_service_class = env->FindClass(TARGET_CLASS);
        if (fingerprint_service_class == nullptr) {
            if (env->ExceptionCheck()) env->ExceptionClear();
            LOGI("Direct lookup failed, using class loader");
            fingerprint_service_class = findClassWithClassLoader(TARGET_CLASS);
        }
        if (fingerprint_service_class == nullptr) {
            LOGE("CRITICAL: FingerprintServiceStubImpl class not found");
            const char* parent_packages[] = {
                "com/android/server/biometrics/sensors/fingerprint",
                "com/android/server/biometrics/sensors",
                "com/android/server/biometrics",
                "com/android/server"
            };
            for (const char* pkg : parent_packages) {
                LOGI("Checking package: %s", pkg);
                jclass test_class = findClassWithClassLoader(pkg);
                if (test_class != nullptr) {
                    LOGI("Found parent package: %s", pkg);
                    env->DeleteLocalRef(test_class);
                } else {
                    LOGI("Package not found: %s", pkg);
                }
            }
            return false;
        }
        LOGI("Found class, searching for detection method");
        const char* method_names[] = {
            TARGET_METHOD_HYPEROS,
            TARGET_METHOD_ANDROID14,
            TARGET_METHOD_ANDROID13,
            "isHardwareDetected"
        };
        jmethodID target_method = nullptr;
        const char* successful_method = nullptr;
        for (const char* method_name : method_names) {
            LOGI("Looking for method: %s", method_name);
            jmethodID method = env->GetMethodID(fingerprint_service_class, method_name, TARGET_METHOD_SIG);
            if (method != nullptr) {
                LOGI("Found method %s", method_name);
                target_method = method;
                successful_method = method_name;
                break;
            }
            if (env->ExceptionCheck()) env->ExceptionClear();
        }
        if (target_method == nullptr) {
            LOGE("CRITICAL: No fingerprint detection method found");
            jclass class_class = env->GetObjectClass(fingerprint_service_class);
            jmethodID get_methods = env->GetMethodID(class_class, "getMethods", "()[Ljava/lang/reflect/Method;");
            if (get_methods) {
                jobjectArray methods = (jobjectArray)env->CallObjectMethod(fingerprint_service_class, get_methods);
                if (methods) {
                    jsize method_count = env->GetArrayLength(methods);
                    LOGI("Class has %d methods:", method_count);
                    jclass method_class = env->FindClass("java/lang/reflect/Method");
                    jmethodID get_name = env->GetMethodID(method_class, "getName", "()Ljava/lang/String;");
                    for (jsize i = 0; i < min((int)method_count, 10); i++) {
                        jobject method = env->GetObjectArrayElement(methods, i);
                        jstring name_str = (jstring)env->CallObjectMethod(method, get_name);
                        if (name_str) {
                            const char* name = env->GetStringUTFChars(name_str, nullptr);
                            LOGI("  %s", name);
                            env->ReleaseStringUTFChars(name_str, name);
                            env->DeleteLocalRef(name_str);
                        }
                        env->DeleteLocalRef(method);
                    }
                    env->DeleteLocalRef(methods);
                    env->DeleteLocalRef(method_class);
                }
            }
            env->DeleteLocalRef(class_class);
            env->DeleteLocalRef(fingerprint_service_class);
            return false;
        }
        LOGI("Hooking method: %s", successful_method);
        JNINativeMethod hook_methods[] = {
            {const_cast<char*>(successful_method), const_cast<char*>(TARGET_METHOD_SIG),
             reinterpret_cast<void*>(isFpHardwareDetected_hook)}
        };
        int res = env->RegisterNatives(fingerprint_service_class, hook_methods, 1);
        if (res < 0) {
            LOGE("Failed to register native hook, code: %d", res);
            if (env->ExceptionCheck()) {
                env->ExceptionDescribe();
                env->ExceptionClear();
            }
            env->DeleteLocalRef(fingerprint_service_class);
            return false;
        }
        LOGI("Hook registered for method %s", successful_method);
        env->DeleteLocalRef(fingerprint_service_class);
        return true;
    }

    // Helper to find a class using class loader
    jclass findClassWithClassLoader(const char* class_name) {
        jclass clazz = env->FindClass(class_name);
        if (clazz) return clazz;
        LOGI("Trying class loader for %s", class_name);
        jclass thread_class = env->FindClass("java/lang/Thread");
        if (!thread_class) return nullptr;
        jmethodID current_thread = env->GetStaticMethodID(thread_class, "currentThread", "()Ljava/lang/Thread;");
        if (!current_thread) { env->DeleteLocalRef(thread_class); return nullptr; }
        jobject thread_obj = env->CallStaticObjectMethod(thread_class, current_thread);
        if (!thread_obj) { env->DeleteLocalRef(thread_class); return nullptr; }
        jmethodID get_class_loader = env->GetMethodID(thread_class, "getContextClassLoader", "()Ljava/lang/ClassLoader;");
        if (!get_class_loader) { env->DeleteLocalRef(thread_obj); env->DeleteLocalRef(thread_class); return nullptr; }
        jobject class_loader = env->CallObjectMethod(thread_obj, get_class_loader);
        if (!class_loader) { env->DeleteLocalRef(thread_obj); env->DeleteLocalRef(thread_class); return nullptr; }
        jclass class_loader_class = env->FindClass("java/lang/ClassLoader");
        if (!class_loader_class) { env->DeleteLocalRef(class_loader); env->DeleteLocalRef(thread_obj); env->DeleteLocalRef(thread_class); return nullptr; }
        jmethodID load_class = env->GetMethodID(class_loader_class, "loadClass", "(Ljava/lang/String;)Ljava/lang/Class;");
        if (!load_class) { env->DeleteLocalRef(class_loader_class); env->DeleteLocalRef(class_loader); env->DeleteLocalRef(thread_obj); env->DeleteLocalRef(thread_class); return nullptr; }
        char name_buf[256];
        strncpy(name_buf, class_name, 255);
        name_buf[255] = '\0';
        for (char* p = name_buf; *p; ++p) if (*p == '/') *p = '.';
        jstring name_str = env->NewStringUTF(name_buf);
        if (!name_str) { env->DeleteLocalRef(class_loader_class); env->DeleteLocalRef(class_loader); env->DeleteLocalRef(thread_obj); env->DeleteLocalRef(thread_class); return nullptr; }
        jclass result = (jclass)env->CallObjectMethod(class_loader, load_class, name_str);
        env->DeleteLocalRef(name_str);
        env->DeleteLocalRef(class_loader_class);
        env->DeleteLocalRef(class_loader);
        env->DeleteLocalRef(thread_obj);
        env->DeleteLocalRef(thread_class);
        return result;
    }

    // Alternative approach if direct hook fails
    void tryFindAndHookClassLoader() {
        LOGI("Alternative hook approach initiated");
        char process_name[256];
        FILE* cmd = popen("ps -p $$ -o comm=", "r");
        if (cmd) {
            fgets(process_name, sizeof(process_name), cmd);
            process_name[strcspn(process_name, "\n")] = 0;
            pclose(cmd);
            LOGI("Current process: %s", process_name);
        }
        LOGI("Looking for fingerprint classes in different packages...");
        const char* packages_to_check[] = {
            "com.android.server.biometrics.sensors.fingerprint.FingerprintServiceStubImpl",
            "com.android.server.biometrics.fingerprint.FingerprintServiceImpl",
            "com.android.server.biometrics.BiometricsService",
            "android.hardware.biometrics.fingerprint.FingerprintManager",
            "android.hardware.fingerprint.FingerprintManager"
        };
        for (const char* pkg : packages_to_check) {
            LOGI("Checking class: %s", pkg);
            jclass cls = findClassWithClassLoader(pkg);
            if (cls) {
                LOGI("Found class: %s", pkg);
                dumpClassMethods(cls, 5);
                env->DeleteLocalRef(cls);
            }
        }
        LOGI("Setting ALL fingerprint-related properties (fallback)");
        const char* fp_props[][2] = {
            {"ro.vendor.fingerprint", "infinix/X6833B*/Infinix-X6833B*"},
            {"persist.vendor.sys.fp.vendor", "goodix"},
            {"persist.vendor.sys.fp.module", "true"},
            {"ro.boot.fingerprint", "goodix"},
            {"ro.boot.fpsensor", "goodix"},
            {"ro.hardware.fingerprint", "goodix"},
            {"ro.hardware.fp", "goodix"},
            {"ro.infinix.fingerprint", "goodix"},
            {"sys.fp.goodix", "enabled"},
            {"sys.fp.vendor", "goodix"}
        };
        for (auto& prop : fp_props) {
            __system_property_set(prop[0], prop[1]);
            LOGI("Set property: %s = %s", prop[0], prop[1]);
        }
        LOGI("Alternative hooking completed. Properties overridden.");
    }

    // Dump class methods for debugging
    void dumpClassMethods(jclass cls, int maxMethods) {
        if (!cls) return;
        jclass clsClass = env->GetObjectClass(cls);
        jmethodID getMethods = env->GetMethodID(clsClass, "getMethods", "()[Ljava/lang/reflect/Method;");
        if (getMethods) {
            jobjectArray methods = (jobjectArray)env->CallObjectMethod(cls, getMethods);
            if (methods) {
                jsize count = env->GetArrayLength(methods);
                LOGI("Class has %d methods (showing up to %d)", count, min(count, (jsize)maxMethods));
                jclass methodClass = env->FindClass("java/lang/reflect/Method");
                jmethodID getName = env->GetMethodID(methodClass, "getName", "()Ljava/lang/String;");
                for (jsize i = 0; i < min(count, (jsize)maxMethods); ++i) {
                    jobject m = env->GetObjectArrayElement(methods, i);
                    jstring nameStr = (jstring)env->CallObjectMethod(m, getName);
                    if (nameStr) {
                        const char* name = env->GetStringUTFChars(nameStr, nullptr);
                        LOGI("Method[%d]: %s", i, name);
                        env->ReleaseStringUTFChars(nameStr, name);
                        env->DeleteLocalRef(nameStr);
                    }
                    env->DeleteLocalRef(m);
                }
                env->DeleteLocalRef(methodClass);
                env->DeleteLocalRef(methods);
            }
        }
        env->DeleteLocalRef(clsClass);
    }

    // Scan for fingerprint-related classes (placeholder)
    void scanForFingerprintClasses() {
        LOGI("Scanning for fingerprint-related classes...");
        const char* patterns[] = {
            "fingerprint", "FingerprintService", "FingerprintManager",
            "BiometricService", "Biometrics"
        };
        for (const char* pat : patterns) {
            LOGI("Looking for classes with pattern: %s", pat);
        }
    }
};

extern "C" {
    static FingerprintBypasserModule module;
    __attribute__((section(".zygisk")))
    void zygisk_module_entry(zygisk::Api* api, JNIEnv* env) {
        LOGI("ENTRY POINT: zygisk_module_entry called");
        module.onLoad(api, env);
    }
    __attribute__((section(".zygisk")))
    void zygisk_companion_entry(zygisk::Api* api, JNIEnv* env) {
        LOGI("ENTRY POINT: zygisk_companion_entry called (not used)");
    }
    JNIEXPORT jint JNICALL JNI_OnLoad(JavaVM* vm, void* reserved) {
        LOGE("JNI_OnLoad called - library loaded");
        return JNI_VERSION_1_6;
    }
}