#include <cstring>
#include <android/log.h>
#include "zygisk.h"
#include <sys/system_properties.h>

#define LOGI(...) __android_log_print(ANDROID_LOG_INFO, "[ZygiskSpoof]", __VA_ARGS__)

static const char *target_apps[] = {
    "com.mobile.legends",
    "com.miHoYo.GenshinImpact",
    "com.miHoYo.hkrpg",
    "com.tencent.ig",
    "com.garena.game.codm",
    nullptr
};

bool shouldSpoof(const char *packageName) {
    for (const char **target = target_apps; *target; ++target) {
        if (strcmp(packageName, *target) == 0) return true;
    }
    return false;
}

class SpoofModule : public zygisk::ModuleBase {
private:
    zygisk::Api *zygisk_api = nullptr;
    JNIEnv *zygisk_env = nullptr;

public:
    void onLoad(zygisk::Api *api, JNIEnv *env) override {
        zygisk_api = api;
        zygisk_env = env;
        LOGI("ZygiskSpoof module loaded");
    }

    void postAppSpecialize(const zygisk::AppSpecializeArgs *args) override {
        const char *pkg = zygisk_env->GetStringUTFChars(args->nice_name, nullptr);
        if (shouldSpoof(pkg)) {
            LOGI("Target app detected: %s", pkg);
            __system_property_set("ro.product.model", "SM-S928B");
            __system_property_set("ro.product.brand", "samsung");
            __system_property_set("ro.product.manufacturer", "samsung");
            __system_property_set("ro.product.device", "dm3q");
            __system_property_set("ro.product.name", "dm3qxx");
            __system_property_set("ro.build.display.id", "UP1A.231005.007");
            __system_property_set("ro.build.id", "UP1A.231005.007");
            __system_property_set("ro.build.tags", "release-keys");
            __system_property_set("ro.build.type", "user");
            __system_property_set("ro.build.user", "dpi");
            __system_property_set("ro.build.host", "21DJB");
            __system_property_set("ro.board.platform", "kalama");
            __system_property_set("ro.soc.manufacturer", "Qualcomm Technologies, Inc.");
            __system_property_set("ro.soc.model", "SM8650");
        } else {
            LOGI("Non-target app: %s", pkg);
        }
        zygisk_env->ReleaseStringUTFChars(args->nice_name, pkg);
    }
};

REGISTER_ZYGISK_MODULE(SpoofModule);