#include <cstring>
#include <string>
#include <android/log.h>
#include "zygisk.hpp"
#include "xhook.h"

#define LOGI(...) __android_log_print(ANDROID_LOG_INFO, "[ZygiskSpoof]", __VA_ARGS__)
#define LOGE(...) __android_log_print(ANDROID_LOG_ERROR, "[ZygiskSpoof]", __VA_ARGS__)

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

    for (const char **app = target_apps; *app; ++app) {
        if (current_package == *app) {
            if (strcmp(name, "ro.product.model") == 0) {
    strlcpy(value, "SM-S928B", value_len);
} else if (strcmp(name, "ro.product.brand") == 0) {
    strlcpy(value, "samsung", value_len);
} else if (strcmp(name, "ro.product.manufacturer") == 0) {
    strlcpy(value, "samsung", value_len);
} else if (strcmp(name, "ro.product.device") == 0) {
    strlcpy(value, "dm3q", value_len);
} else if (strcmp(name, "ro.product.name") == 0) {
    strlcpy(value, "dm3qxx", value_len);
} else if (strcmp(name, "ro.product.board") == 0) {
    strlcpy(value, "kalama", value_len);
} else if (strcmp(name, "ro.board.platform") == 0) {
    strlcpy(value, "kalama", value_len);
} else if (strcmp(name, "ro.soc.manufacturer") == 0) {
    strlcpy(value, "Qualcomm Technologies, Inc.", value_len);
} else if (strcmp(name, "ro.soc.model") == 0) {
    strlcpy(value, "SM8650", value_len);
} else if (strcmp(name, "ro.hardware") == 0) {
    strlcpy(value, "qcom", value_len);
} else if (strcmp(name, "ro.boot.hardware") == 0) {
    strlcpy(value, "qcom", value_len);
} else if (strcmp(name, "ro.boot.bootloader") == 0) {
    strlcpy(value, "S928BXXU1AWF2", value_len);
} else if (strcmp(name, "ro.build.id") == 0) {
    strlcpy(value, "UP1A.231005.007", value_len);
} else if (strcmp(name, "ro.build.display.id") == 0) {
    strlcpy(value, "UP1A.231005.007", value_len);
} else if (strcmp(name, "ro.build.tags") == 0) {
    strlcpy(value, "release-keys", value_len);
} else if (strcmp(name, "ro.build.type") == 0) {
    strlcpy(value, "user", value_len);
} else if (strcmp(name, "ro.build.user") == 0) {
    strlcpy(value, "dpi", value_len);
} else if (strcmp(name, "ro.build.host") == 0) {
    strlcpy(value, "21DJB", value_len);
} else if (strcmp(name, "ro.build.product") == 0) {
    strlcpy(value, "dm3q", value_len);
} else if (strcmp(name, "ro.build.flavor") == 0) {
    strlcpy(value, "dm3qxx-user", value_len);
} else if (strcmp(name, "ro.build.fingerprint") == 0) {
    strlcpy(value, "samsung/dm3qxx/dm3q:14/UP1A.231005.007/S928BXXU1AWF2:user/release-keys", value_len);
} else if (strcmp(name, "ro.bootimage.build.fingerprint") == 0) {
    strlcpy(value, "samsung/dm3qxx/dm3q:14/UP1A.231005.007/S928BXXU1AWF2:user/release-keys", value_len);
}
            break;
        }
    }

    return result;
}

void setupHooks() {
    LOGI("Setting up hook...");
    xhook_register("libc.so", "__system_property_get", (void *)my_system_property_get, (void **)&original_system_property_get);
    if (xhook_refresh(0) == 0) {
        LOGI("Hook sukses dipasang.");
    } else {
        LOGE("Gagal pasang hook.");
    }
}

class SpoofModule : public zygisk::ModuleBase {
    void onLoad(zygisk::Api *api, JNIEnv *env) override {
        LOGI("ZygiskSpoof loaded.");
    }

    void preAppSpecialize(zygisk::AppSpecializeArgs *args) override {
    JNIEnv *env = args->env;
    jstring jname = args->nice_name;
    const char* cname = env->GetStringUTFChars(jname, nullptr);
    std::string current_package = std::string(cname);
    env->ReleaseStringUTFChars(jname, cname);

    for (const char **app = target_apps; *app; ++app) {
        if (current_package == *app) {
            LOGI("Target app: %s", current_package.c_str());
            setupHooks();
            return;
        }
    }

    LOGI("Bukan target app: %s", current_package.c_str());
};

REGISTER_ZYGISK_MODULE(SpoofModule)