#include <jni.h>
#include <cstring>
#include <unistd.h>
#include <sys/system_properties.h>
#include <android/log.h>
#include "zygisk.hpp"

#define LOG_TAG "ZygiskSpoof"
#define LOGI(...) __android_log_print(ANDROID_LOG_INFO, LOG_TAG, __VA_ARGS__)

// List package target
const char *target_apps[] = {
    "com.mobile.legends",
    "com.miHoYo.GenshinImpact",
    "com.miHoYo.honkaiimpact3",
    "com.tencent.ig",
    "com.activision.callofduty.shooter",
    nullptr
};

bool shouldSpoof(const char *packageName) {
    for (const char **target = target_apps; *target; ++target) {
        if (strcmp(packageName, *target) == 0) return true;
    }
    return false;
}

void set_prop(const char *key, const char *val) {
    if (__system_property_set(key, val) == 0) {
        LOGI("Spoofed %s = %s", key, val);
    }
}

class SpoofModule : public zygisk::ModuleBase {
public:
    void onLoad(zygisk::Api *api, JNIEnv *env) override {
        LOGI("ZygiskSpoof Module loaded");
    }

    void preAppSpecialize(zygisk::AppSpecializeArgs *args) override {
        const char *pkg = args->packageName;
        if (!pkg) return;

        if (shouldSpoof(pkg)) {
            LOGI("Target app detected: %s", pkg);

            set_prop("ro.product.brand", "samsung");
            set_prop("ro.product.manufacturer", "samsung");
            set_prop("ro.product.model", "SM-S928B");
            set_prop("ro.product.device", "dm3q");
            set_prop("ro.build.fingerprint", "samsung/dm3qxx/dm3q:14/UP1A.231005.007/S928BXXU1AXB5:user/release-keys");
            set_prop("ro.board.platform", "kalama");
            set_prop("ro.hardware", "qcom");
            set_prop("ro.soc.manufacturer", "Qualcomm Technologies, Inc.");
            set_prop("ro.soc.model", "SM8650");
        } else {
            LOGI("Non-target app: %s", pkg);
        }
    }
};

REGISTER_ZYGISK_MODULE(SpoofModule)