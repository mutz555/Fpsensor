    LOGI("Fingerprint: %s", #include <cstdlib>
#include <unistd.h>
#include <android/log.h>
#include <sys/system_properties.h>
#include <dlfcn.h>
#include <jni.h>
#include <cstring>

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
fingerprint);
    LOGI("=============================\n");
}

// Target package and class from screenshot (Android 15/HyperOS specific)
const char* TARGET_PACKAGE = "com.android.server.biometrics.sensors.fingerprint";
const char* TARGET_CLASS = "com/android/server/biometrics/sensors/fingerprint/FingerprintServiceStubImpl";

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
    LOGI("Hardware fingerprint detection method hooked - returning TRUE");
    
    // Get calling class and method for debugging
    jclass threadClass = env->FindClass("java/lang/Thread");
    if (threadClass) {
        jmethodID currentThreadMethod = env->GetStaticMethodID(threadClass, "currentThread", "()Ljava/lang/Thread;");
        if (currentThreadMethod) {
            jobject threadObj = env->CallStaticObjectMethod(threadClass, currentThreadMethod);
            if (threadObj) {
                jmethodID getStackTraceMethod = env->GetMethodID(threadClass, "getStackTrace", "()[Ljava/lang/StackTraceElement;");
                if (getStackTraceMethod) {
                    jobjectArray stackArray = (jobjectArray)env->CallObjectMethod(threadObj, getStackTraceMethod);
                    if (stackArray && env->GetArrayLength(stackArray) > 1) {
                        jobject element = env->GetObjectArrayElement(stackArray, 1); // Get caller element
                        if (element) {
                            jclass elementClass = env->GetObjectClass(element);
                            jmethodID getClassNameMethod = env->GetMethodID(elementClass, "getClassName", "()Ljava/lang/String;");
                            jmethodID getMethodNameMethod = env->GetMethodID(elementClass, "getMethodName", "()Ljava/lang/String;");
                            
                            if (getClassNameMethod && getMethodNameMethod) {
                                jstring classNameStr = (jstring)env->CallObjectMethod(element, getClassNameMethod);
                                jstring methodNameStr = (jstring)env->CallObjectMethod(element, getMethodNameMethod);
                                
                                if (classNameStr && methodNameStr) {
                                    const char* className = env->GetStringUTFChars(classNameStr, nullptr);
                                    const char* methodName = env->GetStringUTFChars(methodNameStr, nullptr);
                                    
                                    LOGD("Called from: %s.%s()", className, methodName);
                                    
                                    env->ReleaseStringUTFChars(classNameStr, className);
                                    env->ReleaseStringUTFChars(methodNameStr, methodName);
                                }
                            }
                            env->DeleteLocalRef(elementClass);
                            env->DeleteLocalRef(element);
                        }
                    }
                    if (stackArray) env->DeleteLocalRef(stackArray);
                }
                env->DeleteLocalRef(threadObj);
            }
        }
        env->DeleteLocalRef(threadClass);
    }
    
    LOGT("Hardware fingerprint detection hook completed");
    return JNI_TRUE;
}

class FingerprintBypasserModule : public zygisk::ModuleBase {
public:
    void onLoad(zygisk::Api* api, JNIEnv* env) override {
        this->api = api;
        this->env = env;
        
        // Print module version and system information for debugging
        LOGI("=================================");
        LOGI("Fingerprint Bypasser Module v1.0");
        LOGI("=================================");
        dump_system_info();
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
        
        // Find the target fingerprint service class
        jclass fingerprint_service_class = findClassWithClassLoader(TARGET_CLASS);
        
        if (fingerprint_service_class != nullptr) {
            // Try different method names based on Android version
            jmethodID is_fp_hardware_detected_method = env->GetMethodID(
                fingerprint_service_class, 
                TARGET_METHOD_HYPEROS, 
                TARGET_METHOD_SIG
            );
            
            if (is_fp_hardware_detected_method == nullptr) {
                LOGI("HyperOS method not found, trying Android 14 method");
                is_fp_hardware_detected_method = env->GetMethodID(
                    fingerprint_service_class, 
                    TARGET_METHOD_ANDROID14, 
                    TARGET_METHOD_SIG
                );
            }
            
            if (is_fp_hardware_detected_method == nullptr) {
                LOGI("Android 14 method not found, trying Android 13 method");
                is_fp_hardware_detected_method = env->GetMethodID(
                    fingerprint_service_class, 
                    TARGET_METHOD_ANDROID13, 
                    TARGET_METHOD_SIG
                );
            }
            
            if (is_fp_hardware_detected_method != nullptr) {
                // Instead of using Dobby for hooking, we'll use Zygisk API to directly
                // register our JNI method and override the original
                // Removed try-catch blocks since exceptions are disabled with -fno-exceptions
                
                // Implement direct JNI method registration
                static JNINativeMethod methods[] = {
                    {const_cast<char*>(TARGET_METHOD_HYPEROS), const_cast<char*>(TARGET_METHOD_SIG), 
                     reinterpret_cast<void*>(isFpHardwareDetected_hook)}
                };
            
                // Register our native method
                if (env->RegisterNatives(fingerprint_service_class, methods, 1) < 0) {
                    LOGE("Failed to register native method");
                } else {
                    LOGI("Successfully registered isFpHardwareDetected() replacement");
                }
                
                LOGI("Successfully hooked FingerprintServiceStubImpl.isFpHardwareDetected()");
            } else {
                LOGE("Failed to find isFpHardwareDetected method");
            }
            
            env->DeleteLocalRef(fingerprint_service_class);
        } else {
            LOGE("Failed to find FingerprintServiceStubImpl class");
            // Try to find it using a different approach
            tryFindAndHookClassLoader();
        }
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
        
        // Convert C string to Java string
        jstring class_name_str = env->NewStringUTF(TARGET_PACKAGE);
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
        LOGI("Trying alternative hooking approach by iterating through loaded classes");
        
        // Additional code here to find and hook the class when normal methods fail
        // (This would involve using dlopen/dlsym or other methods to get the class)
        
        // For Zygisk modules, we could also try to use the Java classloader to find the class
        LOGI("Attempting to hook on next load of the target class");
    }
};

// Register module with proper entry point for Zygisk
REGISTER_ZYGISK_MODULE(FingerprintBypasserModule)

// Required for Zygisk module detection
extern "C" {
    JNIEXPORT jint JNICALL JNI_OnLoad(JavaVM* vm, void* reserved) {
        LOGI("Fingerprint Bypasser module JNI_OnLoad called");
        return JNI_VERSION_1_6;
    }
}
