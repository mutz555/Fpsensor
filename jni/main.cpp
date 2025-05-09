#include <jni.h>
#include <cstring>
#include <string>
#include <android/log.h>
#include "xhook.h"
#include <sys/system_properties.h>

#define LOGI(...) __android_log_print(ANDROID_LOG_INFO, "[LSPosedSpoof]", __VA_ARGS__)
#define LOGE(...) __android_log_print(ANDROID_LOG_ERROR, "[LSPosedSpoof]", __VA_ARGS__)

// Daftar aplikasi target
static const char *target_apps[] = {
    "com.mobile.legends",
    "com.miHoYo.GenshinImpact",
    "com.miHoYo.hkrpg",
    "com.tencent.ig",
    "com.garena.game.codm",
    nullptr
};

static std::string current_package;
static int (*original_system_property_get)(const char*, char*, size_t) = nullptr;

// Fungsi hook
int my_system_property_get(const char* name, char* value, size_t value_len) {
    int result = original_system_property_get(name, value, value_len);

    bool is_target_app = false;
    for (const char **app = target_apps; *app; ++app) {
        if (current_package == *app) {
            is_target_app = true;
            break;
        }
    }

    if (is_target_app) {
        if (strcmp(name, "ro.product.model") == 0) {
            snprintf(value, value_len, "SM-S928B");
        } else if (strcmp(name, "ro.product.brand") == 0) {
            snprintf(value, value_len, "samsung");
        } else if (strcmp(name, "ro.product.manufacturer") == 0) {
            snprintf(value, value_len, "samsung");
        } else if (strcmp(name, "ro.product.device") == 0) {
            snprintf(value, value_len, "dm3q");
        } else if (strcmp(name, "ro.product.name") == 0) {
            snprintf(value, value_len, "dm3qxx");
        } else if (strcmp(name, "ro.hardware") == 0) {
            snprintf(value, value_len, "qcom");
        } else if (strcmp(name, "ro.board.platform") == 0) {
            snprintf(value, value_len, "kalama");
        } else if (strcmp(name, "ro.build.id") == 0) {
            snprintf(value, value_len, "UP1A.231005.007");
        } else if (strcmp(name, "ro.build.display.id") == 0) {
            snprintf(value, value_len, "UP1A.231005.007.S928BXXU1AXB5");
        } else if (strcmp(name, "ro.build.version.release") == 0) {
            snprintf(value, value_len, "14");
        } else if (strcmp(name, "ro.build.version.sdk") == 0) {
            snprintf(value, value_len, "34");
        } else if (strcmp(name, "ro.build.fingerprint") == 0) {
            snprintf(value, value_len, "samsung/dm3qxx/dm3q:14/UP1A.231005.007/S928BXXU1AXB5:user/release-keys");
        } else if (strcmp(name, "ro.soc.manufacturer") == 0) {
            snprintf(value, value_len, "Qualcomm Technologies, Inc.");
        } else if (strcmp(name, "ro.soc.model") == 0) {
            snprintf(value, value_len, "SM8650");
        }
        LOGI("Spoofed %s -> %s", name, value);
    }

    return result;
}

// Setup hook xhook
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

    xhook_clear();
}

// Fungsi JNI saat library dimuat
extern "C"
jint JNI_OnLoad(JavaVM* vm, void* reserved) {
    LOGI("JNI_OnLoad: native module LSPosed aktif");
    setupHooks();
    return JNI_VERSION_1_6;
}

// Setter untuk package dari Java
extern "C"
JNIEXPORT void JNICALL
Java_com_mutz_spoof_SpoofBridge_setCurrentPackage(JNIEnv *env, jobject, jstring packageName) {
    const char *pkg = env->GetStringUTFChars(packageName, nullptr);
    if (pkg != nullptr) {
        current_package = pkg;
        LOGI("Package name diset: %s", current_package.c_str());
        env->ReleaseStringUTFChars(packageName, pkg);
    }
}