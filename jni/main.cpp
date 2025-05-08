#include <jni.h> #include <unistd.h> #include <android/log.h> #include <dlfcn.h> #include <cstring> #include <cstdlib> #include <sys/system_properties.h> #include "xhook.h" #include "zygisk.hpp"

#define LOG_TAG "ZygiskSpoof" #define LOGI(...) __android_log_print(ANDROID_LOG_INFO, LOG_TAG, VA_ARGS)

const char *target_apps[] = { "com.mobile.legends", "com.miHoYo.GenshinImpact", "com.miHoYo.hkrpg", "com.tencent.ig", "com.activision.callofduty.shooter" };

bool shouldSpoof(const char *packageName) { for (const char *target : target_apps) { if (strcmp(packageName, target) == 0) return true; } return false; }

void spoof_props() { struct prop_pair { const char *key; const char *val; } props[] = { {"ro.product.brand", "samsung"}, {"ro.product.manufacturer", "samsung"}, {"ro.product.device", "dm3q"}, {"ro.product.model", "SM-S928B"}, {"ro.product.name", "dm3qxx"}, {"ro.build.product", "dm3q"}, {"ro.build.fingerprint", "samsung/dm3qxx/dm3q:14/UP1A.231005.007/S928BXXU1AXB5:user/release-keys"}, {"ro.build.version.release", "14"}, {"ro.build.version.sdk", "34"}, {"ro.board.platform", "kalama"}, {"ro.hardware.soc.manufacturer", "Qualcomm Technologies, Inc."}, {"ro.hardware.soc.model", "SM8650"} };

for (auto &p : props) {
    __system_property_set(p.key, p.val);
    LOGI("Spoofed %s = %s", p.key, p.val);
}

}

class SpoofModule : public zygisk::ModuleBase { public: void onLoad(zygisk::Api *api, JNIEnv *env) override { LOGI("[ZygiskSpoof] Module loaded"); }

void preAppSpecialize(zygisk::AppSpecializeArgs *args) override {
    const char *pkg = args->nice_name ? args->env->GetStringUTFChars(args->nice_name, nullptr) : "";
    if (shouldSpoof(pkg)) {
        LOGI("[ZygiskSpoof] Target app detected: %s", pkg);
        spoof_props();
    } else {
        LOGI("[ZygiskSpoof] Non-target app: %s", pkg);
    }
    if (pkg && args->nice_name) args->env->ReleaseStringUTFChars(args->nice_name, pkg);
}

};

REGISTER_ZYGISK_MODULE(SpoofModule)

