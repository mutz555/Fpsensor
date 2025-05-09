#include <jni.h>
#include <cstring>
#include <string>
#include <android/log.h>
#include "xhook.h"
#include <sys/system_properties.h>

#define LOGI(...) __android_log_print(ANDROID_LOG_INFO, "[LSPosedSpoof]", __VA_ARGS__)
#define LOGE(...) __android_log_print(ANDROID_LOG_ERROR, "[LSPosedSpoof]", __VA_ARGS__)

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
            strlcpy(value, "SM-S928B", value_len);
        } else if (strcmp(name, "ro.product.brand") == 0) {
            strlcpy(value, "samsung", value_len);
        }
        // Tambahkan property spoof lain di sini jika perlu
    }

    return result;
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

// Fungsi JNI dipanggil saat native library dimuat
extern "C"
jint JNI_OnLoad(JavaVM* vm, void* reserved) {
    LOGI("JNI_OnLoad: native module LSPosed aktif");
    setupHooks();
    return JNI_VERSION_1_6;
}

// Optional: fungsi setter untuk package name dari Java
extern "C"
JNIEXPORT void JNICALL
Java_com_yourpackage_YourClass_setCurrentPackage(JNIEnv *env, jobject, jstring packageName) {
    const char *pkg = env->GetStringUTFChars(packageName, nullptr);
    current_package = pkg;
    env->ReleaseStringUTFChars(packageName, pkg);
    LOGI("Package name diset: %s", current_package.c_str());
}