#include <cstring>
#include <unistd.h>
#include <cstdlib>
#include <android/log.h>
#include <xhook.h>
#include "zygisk.hpp"

#define LOG_TAG "SnapdragonSpoof"
#define LOGI(...) __android_log_print(ANDROID_LOG_INFO, LOG_TAG, __VA_ARGS__)

static const char *target_packages[] = {
    "com.tencent.ig",
    "flar2.devcheck",
    "com.mobile.legends",
    "com.miHoYo.GenshinImpact",
    "com.miHoYo.honkaiimpact3",
    "com.activision.callofduty.shooter"
};

static const char *spoofed_props[][2] = {
    {"ro.board.platform", "kalama"},
    {"ro.hardware", "qcom"},
    {"ro.soc.manufacturer", "Qualcomm"},
    {"ro.soc.model", "SM8650"},
    {"ro.product.board", "kalama"},
    {"ro.chipname", "SM8650"}
};

static int (*orig___system_property_get)(const char *name, char *value);

static const char *get_process_name() {
    static char name[256] = {};
    if (name[0] == '\0') {
        FILE *f = fopen("/proc/self/cmdline", "r");
        if (f) {
            fread(name, 1, sizeof(name), f);
            fclose(f);
        }
    }
    return name;
}

static bool should_spoof() {
    const char *proc = get_process_name();
    for (const char *pkg : target_packages) {
        if (strstr(proc, pkg)) {
            LOGI("Matched target package: %s", proc);
            return true;
        }
    }
    return false;
}

extern "C"
int my___system_property_get(const char *name, char *value) {
    for (auto &pair : spoofed_props) {
        if (strcmp(name, pair[0]) == 0) {
            strcpy(value, pair[1]);
            LOGI("Spoofed %s -> %s", name, value);
            return strlen(value);
        }
    }
    return orig___system_property_get(name, value);
}

class MyModule : public zygisk::ModuleBase {
public:
    void onLoad(zygisk::Api *api) override {
        if (!should_spoof()) return;

        xhook_register(".*", "__system_property_get",
                       (void *) my___system_property_get,
                       (void **) &orig___system_property_get);

        xhook_refresh(0);
        xhook_clear();
        LOGI("Spoof hook injected!");
    }
};

REGISTER_ZYGISK_MODULE(MyModule)