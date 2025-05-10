#include <cstring>
#include <unistd.h>
#include <cstdlib>
#include <android/log.h>
#include <xhook.h>
#include <sys/system_properties.h>
#include "zygisk.hpp"

#define LOG_TAG "SnapdragonSpoof"
#define LOGI(...) __android_log_print(ANDROID_LOG_INFO, LOG_TAG, __VA_ARGS__)
#define LOGE(...) __android_log_print(ANDROID_LOG_ERROR, LOG_TAG, __VA_ARGS__)

// Target packages to apply spoofing
static const char *target_packages[] = {
    "com.tencent.ig", "com.pubg.imobile", "com.pubg.krmobile", "com.vng.pubgmobile", "com.rekoo.pubgm",
    "com.tencent.tmgp.pubgmhd", "com.pubg.newstate", "flar2.devcheck", "com.antutu.ABenchMark",
    "com.primatelabs.geekbench", "com.android.vending", "com.mobile.legends", "com.miHoYo.GenshinImpact",
    "com.miHoYo.Yuanshen", "com.miHoYo.honkaiimpact3", "com.miHoYo.bh3.global", "com.miHoYo.bh3.eur",
    "com.hoyoverse.hkrpg.global", "com.miHoYo.hkrpg", "com.hoyoverse.hkrpgoversea",
    "com.activision.callofduty.shooter", "com.garena.game.codm", "com.tencent.tmgp.cod",
    "com.ea.gp.apexlegendsmobilefps", "com.epicgames.fortnite", "com.netease.party.m",
    "com.netease.marvel.marvelsuperwarglobal", "com.supercell.brawlstars", "com.dts.freefireth",
    "com.dts.freefiremax", "com.riotgames.league.wildrift", "com.riotgames.legendsofruneterra",
    "com.riotgames.tacticiansandroid"
};
static const size_t target_packages_count = sizeof(target_packages) / sizeof(target_packages[0]);

// Snapdragon 8 Gen 3 (SM8650/Kalama) properties
static const char *spoofed_props[][2] = {
    {"ro.board.platform", "kalama"}, {"ro.hardware", "qcom"}, {"ro.soc.manufacturer", "Qualcomm"},
    {"ro.soc.model", "SM8650"}, {"ro.product.board", "kalama"}, {"ro.chipname", "SM8650"},
    {"ro.qualcomm.soc", "sm8650"}, {"ro.arch", "arm64"}, {"ro.cpu.core", "1+3+2+2"},
    {"ro.cpu.cluster0", "3.3GHz"}, {"ro.cpu.cluster1", "3.2GHz"}, {"ro.cpu.cluster2", "3.0GHz"},
    {"ro.cpu.cluster3", "2.3GHz"}, {"ro.gpu.model", "Adreno 750"}, {"ro.gpu.vendor", "Qualcomm"},
    {"ro.gpu.frequency", "1000MHz"}, {"ro.hardware.memory", "LPDDR5X"}, {"ro.memory.speed", "4800MHz"},
    {"ro.hardware.chipset", "Snapdragon 8 Gen 3"}, {"ro.qualcomm.version", "SM8650-AC"},
    {"ro.hardware.vulkan", "adreno"}, {"ro.hardware.egl", "adreno"}, {"ro.opengles.version", "196610"},
    {"ro.hardware.audio", "lito"}, {"ro.hardware.sensors", "kalama"},
    {"ro.build.description", "SM8650-kalama-user 14 UKQ1.230930.001 eng.user.20240213.144736 release-keys"},
    {"ro.build.fingerprint", "qcom/kalama/kalama:14/UKQ1.230930.001/20240213.144736:user/release-keys"}
};
static const size_t spoofed_props_count = sizeof(spoofed_props) / sizeof(spoofed_props[0]);

// Original function pointers
static int (*orig___system_property_get)(const char *name, char *value) = nullptr;
static int (*orig___system_property_read)(const prop_info *pi, char *name, char *value) = nullptr;
static int (*orig___system_property_read_callback)(const prop_info *pi,
    void (*callback)(void *cookie, const char *name, const char *value, uint32_t serial), void *cookie) = nullptr;

// Per-process flag
static bool enable_spoof = false;
static bool hook_applied = false;

// Get current process name (from /proc/self/cmdline)
static const char *get_process_name() {
    static char process_name[256] = {0};
    if (process_name[0] == '\0') {
        FILE *f = fopen("/proc/self/cmdline", "r");
        if (f) {
            fread(process_name, 1, sizeof(process_name) - 1, f);
            fclose(f);
        }
    }
    return process_name;
}

// Check if we should spoof for this process
static bool should_spoof() {
    return enable_spoof;
}

// Find spoofed property value
static bool find_spoofed_prop(const char *name, char *value) {
    for (size_t i = 0; i < spoofed_props_count; i++) {
        if (strcmp(name, spoofed_props[i][0]) == 0) {
            strcpy(value, spoofed_props[i][1]);
            return true;
        }
    }
    return false;
}

// Hook for __system_property_get
extern "C" int my___system_property_get(const char *name, char *value) {
    if (should_spoof()) {
        if (find_spoofed_prop(name, value)) {
            LOGI("Spoofed property get: %s -> %s", name, value);
            return strlen(value);
        }
    }
    return orig___system_property_get(name, value);
}

// Hook for __system_property_read
extern "C" int my___system_property_read(const prop_info *pi, char *name, char *value) {
    int ret = orig___system_property_read(pi, name, value);
    if (should_spoof() && ret > 0) {
        char spoofed_value[PROP_VALUE_MAX];
        if (find_spoofed_prop(name, spoofed_value)) {
            strcpy(value, spoofed_value);
            LOGI("Spoofed property read: %s -> %s", name, value);
        }
    }
    return ret;
}

// Callback wrapper for __system_property_read_callback
struct CallbackInfo {
    void (*orig_callback)(void *cookie, const char *name, const char *value, uint32_t serial);
    void *orig_cookie;
};

static void callback_wrapper(void *cookie, const char *name, const char *value, uint32_t serial) {
    CallbackInfo *info = static_cast<CallbackInfo*>(cookie);

    char spoofed_value[PROP_VALUE_MAX];
    const char *final_value = value;
    if (should_spoof() && find_spoofed_prop(name, spoofed_value)) {
        final_value = spoofed_value;
        LOGI("Spoofed property callback: %s -> %s", name, final_value);
    }
    info->orig_callback(info->orig_cookie, name, final_value, serial);
    delete info;
}

// Hook for __system_property_read_callback
extern "C" int my___system_property_read_callback(const prop_info *pi,
    void (*callback)(void *cookie, const char *name, const char *value, uint32_t serial),
    void *cookie) {
    if (!should_spoof()) {
        return orig___system_property_read_callback(pi, callback, cookie);
    }
    CallbackInfo *info = new CallbackInfo{callback, cookie};
    return orig___system_property_read_callback(pi, callback_wrapper, info);
}

// Inisialisasi spoofer
extern "C" void init_snapdragon_spoof() {
    LOGI("Initializing Snapdragon Spoofer");
}

// Fungsi untuk mengecek dan memasang hook hanya di target
extern "C" void apply_hooks_if_target_app(const char* process_name) {
    LOGI("apply_hooks_if_target_app masuk: %s", process_name ? process_name : "NULL");

    if (hook_applied) {
        LOGI("Hooks already applied for this process, skipping.");
        return;
    }

    // Print HEX dari nama proses untuk debug
    if (process_name) {
        char hexbuf[512] = {0};
        size_t i;
        for (i = 0; process_name[i] && i < sizeof(hexbuf)/3-1 && i < 100; ++i)
            sprintf(hexbuf + strlen(hexbuf), "%02X ", (unsigned char)process_name[i]);
        LOGI("Process name HEX: %s", hexbuf);
    }

    // Cek proses target
    enable_spoof = false;
    for (size_t i = 0; i < target_packages_count; i++) {
        LOGI("Comparing: [%s] <-> [%s]", process_name, target_packages[i]);
        if (process_name && strstr(process_name, target_packages[i])) {
            LOGI("Target app detected: %s", process_name);
            enable_spoof = true;
            break;
        }
    }

    if (!enable_spoof) {
        LOGI("Not a target app, skipping");
        return;
    }

    LOGI("Installing hooks for %s", process_name);

    int ret1 = xhook_register(".*libc\\.so$", "__system_property_get",
        (void*)my___system_property_get, (void**)&orig___system_property_get);
    LOGI("xhook_register __system_property_get: %d", ret1);

    int ret2 = xhook_register(".*libc\\.so$", "__system_property_read",
        (void*)my___system_property_read, (void**)&orig___system_property_read);
    LOGI("xhook_register __system_property_read: %d", ret2);

    int ret3 = xhook_register(".*libc\\.so$", "__system_property_read_callback",
        (void*)my___system_property_read_callback, (void**)&orig___system_property_read_callback);
    LOGI("xhook_register __system_property_read_callback: %d", ret3);

    int ret = xhook_refresh(0);
    LOGI("xhook_refresh returned: %d", ret);

    // Jangan panggil xhook_clear() di sini. Biarkan hook tetap aktif!
    hook_applied = true;
    LOGI("Spoof hook injection completed!");
}