#include <jni.h>
#include <cstring>
#include <android/log.h>
#include "xhook.h"
#include <sys/system_properties.h>

#define LOGI(...) __android_log_print(ANDROID_LOG_INFO, "[LSPosedSpoof]", __VA_ARGS__)
#define LOGE(...) __android_log_print(ANDROID_LOG_ERROR, "[LSPosedSpoof]", __VA_ARGS__)

static int (*original_system_property_get)(const char*, char*, size_t) = nullptr;

int my_system_property_get(const char* name, char* value, size_t value_len) {
    int result = original_system_property_get(name, value, value_len);

    // Spoof semua properti tanpa batasan package
    if (strcmp(name, "ro.product.model") == 0) {
        strlcpy(value, "SM-S928B", value_len);
    } else if (strcmp(name, "ro.product.brand") == 0) {
        strlcpy(value, "samsung", value_len);
    } else if (strcmp(name, "ro.product.device") == 0) {
        strlcpy(value, "dm3q", value_len);
    } else if (strcmp(name, "ro.product.manufacturer") == 0) {
        strlcpy(value, "samsung", value_len);
    } else if (strcmp(name, "ro.build.fingerprint") == 0) {
        strlcpy(value, "samsung/dm3qxx/dm3q:14/UP1A.231005.007/S928BXXU1AXB5:user/release-keys", value_len);
    } else if (strcmp(name, "ro.build.version.release") == 0) {
        strlcpy(value, "14", value_len);
    } else if (strcmp(name, "ro.hardware") == 0) {
        strlcpy(value, "qcom", value_len);
    } else if (strcmp(name, "ro.board.platform") == 0) {
        strlcpy(value, "kalama", value_len);
    } else if (strcmp(name, "ro.soc.manufacturer") == 0) {
        strlcpy(value, "Qualcomm Technologies, Inc.", value_len);
    } else if (strcmp(name, "ro.soc.model") == 0) {
        strlcpy(value, "SM8650", value_len);
    }

    return strlen(value);
}
    // Tambahin spoof lain kalau mau

    return original_system_property_get(name, value, value_len);
}

void setupHooks() {
    LOGI("Setting up xhook...");

    xhook_register("libc.so", "__system_property_get",
                   (void*)my_system_property_get,
                   (void**)&original_system_property_get);

    if (xhook_refresh(0) == 0) {
        LOGI("xhook sukses diterapkan");
    } else {
        LOGE("xhook gagal diterapkan");
    }
}

extern "C"
jint JNI_OnLoad(JavaVM* vm, void* reserved) {
    LOGI("JNI_OnLoad aktif dari LSPosed");
    setupHooks();
    return JNI_VERSION_1_6;
}