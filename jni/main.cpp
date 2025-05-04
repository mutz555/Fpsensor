#include <cstdlib>
#include <unistd.h>
#include <android/log.h>
#include <sys/system_properties.h>
#include <dlfcn.h>
#include <jni.h>

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
