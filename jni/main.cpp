#include <jni.h>
#include <cstring>
#include <string>
#include <map>
#include <android/log.h>
#include "xhook.h"
#include <sys/system_properties.h>

#define LOGI(...) __android_log_print(ANDROID_LOG_INFO, "[LSPosedSpoof]", __VA_ARGS__)
#define LOGE(...) __android_log_print(ANDROID_LOG_ERROR, "[LSPosedSpoof]", __VA_ARGS__)

static int (*original_system_property_get)(const char*, char*, size_t) = nullptr;

// Map properti spoof
static std::map<std::string, std::string> spoof_props = {
    {"ro.product.model",        "SM-S928B"},
    {"ro.product.brand",        "samsung"},
    {"ro.product.manufacturer", "samsung"},
    {"ro.product.device",       "gts8q"},
    {"ro.product.name",         "gts8qxx"},
    {"ro.product.board",        "kalama"},
    {"ro.build.product",        "kalama"},
    {"ro.board.platform",       "kalama"},
    {"ro.hardware",             "qcom"},
    {"ro.hardware.chipname",    "SM8550-AC"},
    {"ro.soc.manufacturer",     "Qualcomm"},
    {"ro.soc.model",            "SM8550-AC"},
    {"ro.build.fingerprint",    "samsung/gts8qxx/gts8q:14/UKQ1.240314.002/S928BXXU1AXCA:user/release-keys"}
};

int my_system_property_get(const char* name, char* value, size_t value_len) {
    auto it = spoof_props.find(name);
    if (it != spoof_props.end()) {
        strlcpy(value, it->second.c_str(), value_len);
        LOGI("Spoofed: %s => %s", name, value);
        return strlen(value);
    }

    return original_system_property_get(name, value, value_len);
}

void setupHooks() {
    LOGI("Setting up xhook dari LSPosed");

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
    LOGI("JNI_OnLoad: native module LSPosed aktif");
    setupHooks();
    return JNI_VERSION_1_6;
}