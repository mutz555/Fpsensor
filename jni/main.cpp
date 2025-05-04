#include <cstdlib>
#include <unistd.h>
#include <sys/system_properties.h>
#include <dlfcn.h>
#include <cstring>
#include <algorithm>
#include <android/log.h>
#include <jni.h>

// Helper function for min value since we're using -fno-exceptions
template <typename T>
inline T min(T a, T b) {
    return (a < b) ? a : b;
}

#include "zygisk.hpp"

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

// Target packages and classes for different Android versions
// Target classes and methods - now with more specific targeting based on screenshotss
const char* TARGET_CLASS = "com/android/server/biometrics/sensors/fingerprint/FingerprintServiceStubImpl";

// We need to bypass the vendor property check that causes the failure - based on new log
const char* TARGET_PROP = "persist.vendor.sys.fp.vendor";
const char* HARDWARE_PROP = "persist.vendor.sys.fp.hardware";
const char* VENDOR_FINGERPRINT_PROP = "ro.vendor.fingerprint";
const char* DEVICE_FINGERPRINT_VALUE = "infinix/X6833B*/Infinix-X6833B*";

// Target methods for different Android versions
const char* TARGET_METHOD_HYPEROS = "isFpHardwareDetected";
const char* TARGET_METHOD_ANDROID13 = "isFingerprintHardwarePresent";
const char* TARGET_METHOD_ANDROID14 = "isFingerprintHardwareDetected";
const char* TARGET_METHOD_SIG = "()Z"; // method signature - returns boolean, no parameters

/**
 * Hook implementation for isFpHardwareDetected()
 * Always returns true regardless of actual hardware status
 */
jboolean isFpHardwareDetected_hook(JNIEnv* env, jobject thiz) {
    static int hook_call_count = 0;
    hook_call_count++;
    
    LOGI("!!!!! HOOKED: Fingerprint hardware detection method called %d times - FORCING TRUE !!!!!", hook_call_count);
    LOGI("!!!!! ANY APP CHECKING FOR FINGERPRINT HARDWARE WILL NOW GET TRUE !!!!!");
    
    // Dump the calling stack for debugging
    jclass threadClass = env->FindClass("java/lang/Thread");
    if (threadClass) {
        jmethodID currentThreadMethod = env->GetStaticMethodID(threadClass, "currentThread", "()Ljava/lang/Thread;");
        if (currentThreadMethod) {
            jobject threadObj = env->CallStaticObjectMethod(threadClass, currentThreadMethod);
            if (threadObj) {
                // Get current thread name for context
                jmethodID getNameMethod = env->GetMethodID(threadClass, "getName", "()Ljava/lang/String;");
                if (getNameMethod) {
                    jstring nameStr = (jstring)env->CallObjectMethod(threadObj, getNameMethod);
                    if (nameStr) {
                        const char* threadName = env->GetStringUTFChars(nameStr, nullptr);
                        LOGI("Called from thread: %s", threadName);
                        env->ReleaseStringUTFChars(nameStr, threadName);
                        env->DeleteLocalRef(nameStr);
                    }
                }
                
                // Get stack trace for caller info
                jmethodID getStackTraceMethod = env->GetMethodID(threadClass, "getStackTrace", "()[Ljava/lang/StackTraceElement;");
                if (getStackTraceMethod) {
                    jobjectArray stackArray = (jobjectArray)env->CallObjectMethod(threadObj, getStackTraceMethod);
                    if (stackArray) {
                        jsize stackSize = env->GetArrayLength(stackArray);
                        LOGI("Stack depth: %d", stackSize);
                        
                        // Create a formatted stack trace output
                        LOGI("CALL STACK:");
                        
                        jclass elementClass = env->FindClass("java/lang/StackTraceElement");
                        jmethodID getClassNameMethod = env->GetMethodID(elementClass, "getClassName", "()Ljava/lang/String;");
                        jmethodID getMethodNameMethod = env->GetMethodID(elementClass, "getMethodName", "()Ljava/lang/String;");
                        
                        // Examine up to 10 stack frames
                        for (jsize i = 0; i < min(10, stackSize); i++) {
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
                                    env->DeleteLocalRef(classNameStr);
                                    env->DeleteLocalRef(methodNameStr);
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
    
    // Make sure we set all system properties again to guarantee proper values
    static bool refreshed_properties = false;
    if (!refreshed_properties) {
        LOGI("Refreshing all system properties during hook execution");
        // Re-apply property overrides when hook is actually called
        const char* all_fp_props[][2] = {
            {"persist.vendor.sys.fp.vendor", "goodix"},
            {"persist.vendor.sys.fp.module", "true"},
            {"ro.vendor.fingerprint", "infinix/X6833B*/Infinix-X6833B*"},
            {"ro.boot.fingerprint", "goodix"},
            {"ro.hardware.fingerprint", "goodix"},
            {"ro.hardware.fingerprint.supported", "1"}
        };
        
        int prop_count = sizeof(all_fp_props) / sizeof(all_fp_props[0]);
        for (int i = 0; i < prop_count; i++) {
            __system_property_set(all_fp_props[i][0], all_fp_props[i][1]);
        }
        
        refreshed_properties = true;
    }
    
    // Log a highly visible message to indicate the hook was successful
    LOGI("===============================================");
    LOGI(">> FINGERPRINT HARDWARE DETECTION BYPASSED! <<");
    LOGI("===============================================");
    
    return JNI_TRUE; // Always return true for hardware detection
}

class FingerprintBypasserModule : public zygisk::ModuleBase {
    // Constructor dengan atribut yang diperlukan
    __attribute__((constructor))
    static void init() {
        android_log_print(ANDROID_LOG_ERROR, "FINGERPRINT_BYPASS", "Zygisk module loaded!");
    }
public:
    void onLoad(zygisk::Api* api, JNIEnv* env) override {
        this->api = api;
        this->env = env;
        
        // Print module version and system information for debugging
        LOGI("**************************************************");
        LOGI("*   Fingerprint Bypasser Module v1.0 LOADED!    *");
        LOGI("*          Build date: May 4, 2025             *");
        LOGI("**************************************************");
        
        // Log detailed environment information
        LOGI("Module loaded into process memory");
        dump_system_info();
        
        // Pre-fetch Java environment early to ensure availability
        JavaVM* vm;
        env->GetJavaVM(&vm);
        if (vm) {
            LOGI("Successfully retrieved JavaVM pointer");
        }
    }

    void preAppSpecialize(zygisk::AppSpecializeArgs* args) override {
        // We only care about system_server process
        if (args && args->nice_name) {
            const char* process_name = env->GetStringUTFChars(args->nice_name, nullptr);
            if (process_name) {
                // Compare process name with system_server
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
        // Always hook system_server
        shouldHook = true;
        LOGI("Targeting system_server for hooking");
    }

    void postServerSpecialize(const zygisk::ServerSpecializeArgs* args) override {
        if (shouldHook) {
            installHooks();
        }
    }

private:
    zygisk::Api* api = nullptr;
    JNIEnv* env = nullptr;
    bool shouldHook = false;

    void installHooks() {
        LOGI("Installing fingerprint hardware detection hook");
        
        // Based on screenshot analysis, we know the exact class and method to hook
        // We also need to override the system property that causes the check to fail
        
        // 1. Setup System Property Hooks
        setupSystemPropertyHooks();
        
        // 2. Hook the FingerprintServiceStubImpl.isFpHardwareDetected method
        bool methodHookSuccess = hookFingerprintServiceMethod();
        
        if (!methodHookSuccess) {
            LOGE("Could not hook fingerprint hardware detection method, trying backup approaches");
            tryFindAndHookClassLoader();
        }
    }
    
    // Override ALL fingerprint-related system properties to ensure detection works
    void setupSystemPropertyHooks() {
        LOGI("OVERRIDE: Setting ALL system properties for fingerprint hardware");
        
        // Common fingerprint properties across manufacturers
        const char* all_fp_props[][2] = {
            // Primary properties we need to set based on logs
            {"persist.vendor.sys.fp.vendor", "goodix"},
            {"persist.vendor.sys.fp.module", "true"},
            {"ro.vendor.fingerprint", "infinix/X6833B*/Infinix-X6833B*"},
            
            // Additional properties that might be checked
            {"ro.boot.fingerprint", "goodix"},
            {"ro.boot.fpsensor", "goodix"},
            {"ro.hardware.fingerprint", "goodix"},
            {"ro.hardware.fp", "goodix"},
            {"sys.fp.goodix", "enabled"},
            {"sys.fp.vendor", "goodix"},
            
            // Infinix-specific properties
            {"ro.infinix.fingerprint", "goodix"},
            
            // Force enable at framework level
            {"ro.hardware.fingerprint.supported", "1"},
            {"ro.vendor.fingerprint.supported", "1"},
            {"ro.vendor.infinix.fingerprint.supported", "1"},
            {"persist.sys.fp.supported", "1"},
            
            // Try all possible variations of vendor properties
            {"vendor.sys.fp.module", "true"},
            {"vendor.sys.fp.present", "true"},
            {"vendor.sys.fp.enable", "true"},
            {"vendor.sys.fp.hardware", "true"}
        };
        
        // Set all properties
        int prop_count = sizeof(all_fp_props) / sizeof(all_fp_props[0]);
        
        LOGI("OVERRIDE: Setting %d fingerprint system properties", prop_count);
        
        for (int i = 0; i < prop_count; i++) {
            __system_property_set(all_fp_props[i][0], all_fp_props[i][1]);
            LOGI("  [%d/%d] Set: %s = %s", i+1, prop_count, all_fp_props[i][0], all_fp_props[i][1]);
        }
        
        LOGI("OVERRIDE: All fingerprint properties have been set");
        LOGI("=== If fingerprint detection still fails, please check logcat for errors ===\n");
    }
    
    // Hook the FingerprintServiceStubImpl.isFpHardwareDetected method
    bool hookFingerprintServiceMethod() {
        LOGI("Attempting to hook FingerprintServiceStubImpl.isFpHardwareDetected");
        
        // Try multiple approaches for finding the class
        LOGI("Attempt 1: Direct class lookup");
        jclass fingerprint_service_class = env->FindClass(TARGET_CLASS);
        
        if (fingerprint_service_class == nullptr) {
            if (env->ExceptionCheck()) {
                env->ExceptionClear();
            }
            LOGI("Direct lookup failed, trying with class loader");
            fingerprint_service_class = findClassWithClassLoader(TARGET_CLASS);
        }
        
        if (fingerprint_service_class == nullptr) {
            LOGE("CRITICAL ERROR: Failed to find FingerprintServiceStubImpl class");
            LOGI("Looking for parent packages to debug class loading issues");
            
            // Try to find parent packages
            const char* parent_packages[] = {
                "com/android/server/biometrics/sensors/fingerprint",
                "com/android/server/biometrics/sensors",
                "com/android/server/biometrics",
                "com/android/server"
            };
            
            for (const char* pkg : parent_packages) {
                LOGI("Checking if package exists: %s", pkg);
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
        
        LOGI("SUCCESS: Found FingerprintServiceStubImpl class, looking for method");
        
        // Try all possible method names for different Android versions
        const char* method_names[] = {
            TARGET_METHOD_HYPEROS,          // HyperOS
            TARGET_METHOD_ANDROID14,        // Android 14
            TARGET_METHOD_ANDROID13,        // Android 13
            "isHardwareDetected"           // Generic fallback
        };
        
        jmethodID target_method = nullptr;
        const char* successful_method = nullptr;
        
        for (const char* method_name : method_names) {
            LOGI("Trying to find method: %s", method_name);
            jmethodID method = env->GetMethodID(fingerprint_service_class, method_name, TARGET_METHOD_SIG);
            
            if (method != nullptr) {
                LOGI("SUCCESS: Found method %s", method_name);
                target_method = method;
                successful_method = method_name;
                break;
            } else {
                if (env->ExceptionCheck()) {
                    env->ExceptionClear();
                }
                LOGI("Method %s not found, trying next", method_name);
            }
        }
        
        if (target_method == nullptr) {
            LOGE("CRITICAL ERROR: Failed to find any fingerprint hardware detection method");
            
            // Get all methods of the class for debugging
            jclass class_class = env->GetObjectClass(fingerprint_service_class);
            jmethodID get_methods_method = env->GetMethodID(class_class, "getMethods", "()[Ljava/lang/reflect/Method;");
            
            if (get_methods_method != nullptr) {
                LOGI("Dumping available methods in class:");
                jobjectArray methods = (jobjectArray)env->CallObjectMethod(fingerprint_service_class, get_methods_method);
                
                if (methods != nullptr) {
                    jsize method_count = env->GetArrayLength(methods);
                    LOGI("Found %d methods in class", method_count);
                    
                    jclass method_class = env->FindClass("java/lang/reflect/Method");
                    jmethodID get_name_method = env->GetMethodID(method_class, "getName", "()Ljava/lang/String;");
                    
                    for (jsize i = 0; i < min(15, method_count); i++) {
                        jobject method = env->GetObjectArrayElement(methods, i);
                        jstring method_name = (jstring)env->CallObjectMethod(method, get_name_method);
                        
                        if (method_name != nullptr) {
                            const char* name = env->GetStringUTFChars(method_name, nullptr);
                            LOGI("  Method[%d]: %s", i, name);
                            env->ReleaseStringUTFChars(method_name, name);
                            env->DeleteLocalRef(method_name);
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
        
        LOGI("Setting up hook for method: %s", successful_method);
        
        // Setup the hook with the found method name
        static JNINativeMethod hook_methods[] = {
            {const_cast<char*>(successful_method), const_cast<char*>(TARGET_METHOD_SIG), 
             reinterpret_cast<void*>(isFpHardwareDetected_hook)}
        };
        
        // Register our native method
        LOGI("CRITICAL STEP: Registering native method replacement");
        int register_result = env->RegisterNatives(fingerprint_service_class, hook_methods, 1);
        
        if (register_result < 0) {
            LOGE("CRITICAL ERROR: Failed to register native method - error code: %d", register_result);
            
            if (env->ExceptionCheck()) {
                LOGI("Exception occurred during RegisterNatives");
                env->ExceptionDescribe();
                env->ExceptionClear();
            }
            
            // Try to get more debug info
            jthrowable exc = env->ExceptionOccurred();
            if (exc) {
                LOGI("Exception details:");
                jclass exception_class = env->GetObjectClass(exc);
                jmethodID getMessage = env->GetMethodID(exception_class, "getMessage", "()Ljava/lang/String;");
                
                jstring message = (jstring) env->CallObjectMethod(exc, getMessage);
                if (message != nullptr) {
                    const char* msg = env->GetStringUTFChars(message, nullptr);
                    LOGI("Exception message: %s", msg);
                    env->ReleaseStringUTFChars(message, msg);
                    env->DeleteLocalRef(message);
                }
                
                env->DeleteLocalRef(exception_class);
                env->DeleteLocalRef(exc);
            }
            
            env->DeleteLocalRef(fingerprint_service_class);
            return false;
        }
        
        LOGI("SUCCESS: Successfully registered hook for %s", successful_method);
        LOGI("THE HOOK SHOULD NOW BE ACTIVE FOR FINGERPRINT HARDWARE DETECTION");
        env->DeleteLocalRef(fingerprint_service_class);
        
        return true;
    }
    
    // Helper to find a class using the application class loader
    jclass findClassWithClassLoader(const char* class_name) {
        // First try the normal way
        jclass clazz = env->FindClass(class_name);
        if (clazz != nullptr) {
            return clazz;
        }
        
        LOGI("Trying to find class %s using class loader", class_name);
        
        // Get the thread context class loader
        jclass thread_class = env->FindClass("java/lang/Thread");
        if (thread_class == nullptr) {
            LOGE("Failed to find Thread class");
            return nullptr;
        }
        
        jmethodID current_thread_method = env->GetStaticMethodID(thread_class, "currentThread", "()Ljava/lang/Thread;");
        if (current_thread_method == nullptr) {
            LOGE("Failed to find currentThread method");
            env->DeleteLocalRef(thread_class);
            return nullptr;
        }
        
        jobject thread_obj = env->CallStaticObjectMethod(thread_class, current_thread_method);
        if (thread_obj == nullptr) {
            LOGE("Failed to get current thread");
            env->DeleteLocalRef(thread_class);
            return nullptr;
        }
        
        jmethodID get_class_loader_method = env->GetMethodID(thread_class, "getContextClassLoader", "()Ljava/lang/ClassLoader;");
        if (get_class_loader_method == nullptr) {
            LOGE("Failed to find getContextClassLoader method");
            env->DeleteLocalRef(thread_obj);
            env->DeleteLocalRef(thread_class);
            return nullptr;
        }
        
        jobject class_loader = env->CallObjectMethod(thread_obj, get_class_loader_method);
        if (class_loader == nullptr) {
            LOGE("Failed to get class loader");
            env->DeleteLocalRef(thread_obj);
            env->DeleteLocalRef(thread_class);
            return nullptr;
        }
        
        // Use the class loader to load our target class
        jclass class_loader_class = env->FindClass("java/lang/ClassLoader");
        if (class_loader_class == nullptr) {
            LOGE("Failed to find ClassLoader class");
            env->DeleteLocalRef(class_loader);
            env->DeleteLocalRef(thread_obj);
            env->DeleteLocalRef(thread_class);
            return nullptr;
        }
        
        jmethodID load_class_method = env->GetMethodID(class_loader_class, "loadClass", "(Ljava/lang/String;)Ljava/lang/Class;");
        if (load_class_method == nullptr) {
            LOGE("Failed to find loadClass method");
            env->DeleteLocalRef(class_loader_class);
            env->DeleteLocalRef(class_loader);
            env->DeleteLocalRef(thread_obj);
            env->DeleteLocalRef(thread_class);
            return nullptr;
        }
        
        // Convert C string to Java string - use the correct format for Java class name
        // Replace slashes with dots for Java class loading
        char java_class_name[256];
        strncpy(java_class_name, class_name, 255);
        java_class_name[255] = '\0';
        
        // Replace all '/' with '.' for Java class format
        for (char* p = java_class_name; *p; p++) {
            if (*p == '/') *p = '.';
        }
        
        LOGI("Attempting to load class: %s", java_class_name);
        jstring class_name_str = env->NewStringUTF(java_class_name);
        if (class_name_str == nullptr) {
            LOGE("Failed to create Java string");
            env->DeleteLocalRef(class_loader_class);
            env->DeleteLocalRef(class_loader);
            env->DeleteLocalRef(thread_obj);
            env->DeleteLocalRef(thread_class);
            return nullptr;
        }
        
        // Load the class
        jclass result = (jclass)env->CallObjectMethod(class_loader, load_class_method, class_name_str);
        
        // Clean up references
        env->DeleteLocalRef(class_name_str);
        env->DeleteLocalRef(class_loader_class);
        env->DeleteLocalRef(class_loader);
        env->DeleteLocalRef(thread_obj);
        env->DeleteLocalRef(thread_class);
        
        return result;
    }
    
    // Alternative approach to find and hook the class
    void tryFindAndHookClassLoader() {
        // This is a backup approach if we can't find the class directly
        LOGI("CRITICAL: Direct hooking failed - trying alternative approach");
        
        // Log more information about the process we're running in
        char process_name[256];
        FILE* cmd = popen("ps -p $$ -o comm=", "r");
        if (cmd) {
            fgets(process_name, sizeof(process_name), cmd);
            process_name[strcspn(process_name, "\n")] = 0; // Remove trailing newline
            pclose(cmd);
            LOGI("Current process: %s", process_name);
        }
        
        LOGI("Looking for fingerprint classes in different packages...");
        
        // Try different package patterns based on Android 13-15 variations
        const char* packages_to_check[] = {
            "com.android.server.biometrics.sensors.fingerprint.FingerprintServiceStubImpl", // HyperOS
            "com.android.server.biometrics.fingerprint.FingerprintServiceImpl",           // Android 13
            "com.android.server.biometrics.BiometricsService",                           // General
            "android.hardware.biometrics.fingerprint.FingerprintManager",                // Client API
            "android.hardware.fingerprint.FingerprintManager"                           // Older
        };
        
        // Try to find ANY of these classes
        for (const char* pkg : packages_to_check) {
            LOGI("== Checking for class: %s", pkg);
            jclass cls = findClassWithClassLoader(pkg);
            if (cls != nullptr) {
                LOGI("SUCCESS: Found alternative class: %s", pkg);
                dumpClassMethods(cls, 10);
                env->DeleteLocalRef(cls);
            }
        }
        
        // Try a more direct approach to hooking
        LOGI("Trying direct property override as last resort");
        setupSystemPropertyHooks(); // Set properties again to be sure
        
        // If we can't hook the method directly, try hooking Android property service
        LOGI("Setting ALL fingerprint-related properties");
        
        // Common fingerprint properties across manufacturers
        const char* fp_props[][2] = {
            {"ro.vendor.fingerprint", "infinix/X6833B*/Infinix-X6833B*"},
            {"persist.vendor.sys.fp.vendor", "goodix"},
            {"persist.vendor.sys.fp.module", "true"},
            {"ro.boot.fingerprint", "goodix"},
            {"ro.boot.fpsensor", "goodix"},
            {"ro.hardware.fingerprint", "goodix"},
            {"ro.hardware.fp", "goodix"},
            // Infinix-specific properties
            {"ro.infinix.fingerprint", "goodix"},
            {"sys.fp.goodix", "enabled"},
            {"sys.fp.vendor", "goodix"}
        };
        
        // Set all possible properties
        for (const auto& prop : fp_props) {
            __system_property_set(prop[0], prop[1]);
            LOGI("  Set system property: %s = %s", prop[0], prop[1]);
        }
        
        LOGI("COMPLETED ALTERNATIVE HOOKING - will rely on property overrides");
    }
    
    // Helper to dump class methods
    void dumpClassMethods(jclass cls, int maxMethods) {
        if (cls == nullptr) return;
        
        jclass class_class = env->GetObjectClass(cls);
        jmethodID get_methods_method = env->GetMethodID(class_class, "getMethods", "()[Ljava/lang/reflect/Method;");
        
        if (get_methods_method != nullptr) {
            jobjectArray methods = (jobjectArray)env->CallObjectMethod(cls, get_methods_method);
            
            if (methods != nullptr) {
                jsize method_count = env->GetArrayLength(methods);
                LOGI("Class has %d methods, showing first %d", method_count, min(maxMethods, (int)method_count));
                
                jclass method_class = env->FindClass("java/lang/reflect/Method");
                jmethodID get_name_method = env->GetMethodID(method_class, "getName", "()Ljava/lang/String;");
                jmethodID get_return_method = env->GetMethodID(method_class, "getReturnType", "()Ljava/lang/Class;");
                
                if (method_class != nullptr && get_name_method != nullptr) {
                    for (jsize i = 0; i < min(maxMethods, method_count); i++) {
                        jobject method = env->GetObjectArrayElement(methods, i);
                        jstring method_name = (jstring)env->CallObjectMethod(method, get_name_method);
                        
                        if (method_name != nullptr) {
                            const char* name = env->GetStringUTFChars(method_name, nullptr);
                            
                            // Look for fingerprint methods specifically
                            if (strstr(name, "ingerprint") || strstr(name, "Biometric") || 
                                strstr(name, "isHardware") || strstr(name, "detect")) {
                                LOGI("*** IMPORTANT - Found method: %s", name);
                            } else {
                                LOGI("Method[%d]: %s", i, name);
                            }
                            
                            env->ReleaseStringUTFChars(method_name, name);
                            env->DeleteLocalRef(method_name);
                        }
                        
                        env->DeleteLocalRef(method);
                    }
                }
                
                env->DeleteLocalRef(methods);
                if (method_class != nullptr) env->DeleteLocalRef(method_class);
            }
        }
        
        env->DeleteLocalRef(class_class);
    }
    
    // Helper to dump package information for debugging
    void dumpPackageInfo(const char* packageName) {
        LOGI("Searching for package: %s", packageName);
        
        jclass class_loader_class = env->FindClass("java/lang/ClassLoader");
        if (class_loader_class == nullptr) {
            LOGE("Failed to find ClassLoader class");
            return;
        }
        
        jmethodID get_system_class_loader_method = env->GetStaticMethodID(
            class_loader_class, "getSystemClassLoader", "()Ljava/lang/ClassLoader;");
        if (get_system_class_loader_method == nullptr) {
            LOGE("Failed to find getSystemClassLoader method");
            env->DeleteLocalRef(class_loader_class);
            return;
        }
        
        jobject system_class_loader = env->CallStaticObjectMethod(
            class_loader_class, get_system_class_loader_method);
        if (system_class_loader == nullptr) {
            LOGE("Failed to get system class loader");
            env->DeleteLocalRef(class_loader_class);
            return;
        }
        
        jmethodID load_class_method = env->GetMethodID(
            class_loader_class, "loadClass", "(Ljava/lang/String;)Ljava/lang/Class;");
        if (load_class_method == nullptr) {
            LOGE("Failed to find loadClass method");
            env->DeleteLocalRef(system_class_loader);
            env->DeleteLocalRef(class_loader_class);
            return;
        }
        
        jstring package_name_str = env->NewStringUTF(packageName);
        if (package_name_str == nullptr) {
            LOGE("Failed to create package name string");
            env->DeleteLocalRef(system_class_loader);
            env->DeleteLocalRef(class_loader_class);
            return;
        }
        
        jclass target_class = nullptr;
        
        // Try to load the class and catch any exceptions
        target_class = (jclass)env->CallObjectMethod(
            system_class_loader, load_class_method, package_name_str);
        
        if (env->ExceptionCheck()) {
            env->ExceptionClear();
            LOGI("Class %s not found in system class loader", packageName);
        } else if (target_class != nullptr) {
            LOGI("Successfully found class: %s", packageName);
            
            // Get class methods for debugging
            jclass class_class = env->GetObjectClass(target_class);
            jmethodID get_methods_method = env->GetMethodID(
                class_class, "getMethods", "()[Ljava/lang/reflect/Method;");
            
            if (get_methods_method != nullptr) {
                jobjectArray methods = (jobjectArray)env->CallObjectMethod(
                    target_class, get_methods_method);
                
                if (methods != nullptr) {
                    jsize method_count = env->GetArrayLength(methods);
                    LOGI("Class %s has %d methods", packageName, method_count);
                    
                    // Examine first few methods
                    jclass method_class = env->FindClass("java/lang/reflect/Method");
                    jmethodID get_name_method = env->GetMethodID(
                        method_class, "getName", "()Ljava/lang/String;");
                    
                    if (method_class != nullptr && get_name_method != nullptr) {
                        for (jsize i = 0; i < min(5, method_count); i++) {
                            jobject method = env->GetObjectArrayElement(methods, i);
                            jstring method_name = (jstring)env->CallObjectMethod(
                                method, get_name_method);
                            
                            if (method_name != nullptr) {
                                const char* name = env->GetStringUTFChars(method_name, nullptr);
                                LOGI("Method %d: %s", i, name);
                                env->ReleaseStringUTFChars(method_name, name);
                                env->DeleteLocalRef(method_name);
                            }
                            
                            env->DeleteLocalRef(method);
                        }
                    }
                    
                    env->DeleteLocalRef(methods);
                    if (method_class != nullptr) env->DeleteLocalRef(method_class);
                }
            }
            
            env->DeleteLocalRef(class_class);
            env->DeleteLocalRef(target_class);
        }
        
        env->DeleteLocalRef(package_name_str);
        env->DeleteLocalRef(system_class_loader);
        env->DeleteLocalRef(class_loader_class);
    }
    
    // Scan for fingerprint-related classes
    void scanForFingerprintClasses() {
        LOGI("Scanning for fingerprint-related classes...");
        
        const char* searchPatterns[] = {
            "fingerprint",
            "FingerprintService",
            "FingerprintManager",
            "BiometricService",
            "Biometrics"
        };
        const int numPatterns = 5;
        
        // Since we can't directly enumerate all loaded classes,
        // we'll look for common fingerprint classes in system packages
        for (int i = 0; i < numPatterns; i++) {
            LOGI("Looking for classes containing: %s", searchPatterns[i]);
        }
    }
};

// Proper Zygisk module registration - CRITICAL PART
// Manual implementation of REGISTER_ZYGISK_MODULE macro for better compatibility
// This ensures it works on all Android versions and loads correctly
extern "C" {
    // Create a static instance of our module - this is key for proper loading
    static FingerprintBypasserModule module;
    
    // Required ZygiskModule entry point - MUST have .zygisk section attribute
    __attribute__((section(".zygisk"))) 
    void zygisk_module_entry(zygisk::Api *api, JNIEnv *env) {
        LOGI("ENTRY POINT: zygisk_module_entry called! Module is loading");
        module.onLoad(api, env);
    }
    
    // Required companion entry point - also with .zygisk section
    __attribute__((section(".zygisk"))) 
    void zygisk_companion_entry(zygisk::Api *api, JNIEnv *env) {
        // We don't use companion process for this module
        LOGI("ENTRY POINT: companion_entry called (not used)");
    }
    
    // This is required for Zygisk module detection
    JNIEXPORT jint JNICALL JNI_OnLoad(JavaVM* vm, void* reserved) {
        // Use error level to ensure it shows up clearly in logs
        __android_log_print(ANDROID_LOG_ERROR, "FINGERPRINT_BYPASS", 
                           "JNI_OnLoad called - library loaded directly");
        return JNI_VERSION_1_6;
    }
}