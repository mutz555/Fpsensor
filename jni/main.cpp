#include <cstring>
#include <unistd.h>
#include <cstdlib>
#include <android/log.h>
#include <xhook.h>
#include <sys/system_properties.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <stdio.h>
#include "zygisk.hpp"

#define LOG_TAG "SnapdragonSpoof"
#define LOGI(...) __android_log_print(ANDROID_LOG_INFO, LOG_TAG, __VA_ARGS__)
#define LOGE(...) __android_log_print(ANDROID_LOG_ERROR, LOG_TAG, __VA_ARGS__)

// Target packages: hanya game & benchmarking, JANGAN proses sistem!
static const char *target_packages[] = {
    "com.tencent.ig", "com.pubg.imobile", "com.pubg.krmobile", "com.vng.pubgmobile", "com.rekoo.pubgm",
    "com.tencent.tmgp.pubgmhd", "com.pubg.newstate", "flar2.devcheck", "com.antutu.ABenchMark",
    "com.primatelabs.geekbench", "com.mobile.legends", "com.miHoYo.GenshinImpact",
    "com.miHoYo.Yuanshen", "com.miHoYo.honkaiimpact3", "com.miHoYo.bh3.global", "com.miHoYo.bh3.eur",
    "com.hoyoverse.hkrpg.global", "com.miHoYo.hkrpg", "com.hoyoverse.hkrpgoversea",
    "com.activision.callofduty.shooter", "com.garena.game.codm", "com.tencent.tmgp.cod",
    "com.ea.gp.apexlegendsmobilefps", "com.epicgames.fortnite", "com.netease.party.m",
    "com.netease.marvel.marvelsuperwarglobal", "com.supercell.brawlstars", "com.dts.freefireth",
    "com.dts.freefiremax", "com.riotgames.league.wildrift", "com.riotgames.legendsofruneterra",
    "com.riotgames.tacticiansandroid"
};
static const size_t target_packages_count = sizeof(target_packages) / sizeof(target_packages[0]);

// Spoof semua properti SoC yang umum diakses aplikasi hardware info
static const char *spoofed_props[][2] = {
    {"ro.hardware.chipset", "Snapdragon 8 Gen 3"},
    {"ro.hardware.chipname", "SM8650-AC"},
    {"ro.chipname", "SM8650-AC"},
    {"ro.soc.model", "SM8650"},
    {"ro.soc.manufacturer", "Qualcomm"},
    {"ro.vendor.soc.model.external_name", "SM8650-AC"},
    {"ro.vendor.soc.model.part_name", "SM8650-AC"}
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
static char current_process_name[256] = {0};

// Utility untuk mendapatkan nama proses
static const char* get_process_name() {
    if (current_process_name[0] != '\0') {
        return current_process_name;
    }
    int fd = open("/proc/self/cmdline", O_RDONLY);
    if (fd >= 0) {
        ssize_t len = read(fd, current_process_name, sizeof(current_process_name) - 1);
        close(fd);
        if (len > 0) {
            current_process_name[len] = '\0';
            LOGI("Got process name from cmdline: %s", current_process_name);
            return current_process_name;
        }
    }
    const char* progname = getprogname();
    if (progname) {
        strncpy(current_process_name, progname, sizeof(current_process_name) - 1);
        LOGI("Got process name from getprogname: %s", current_process_name);
        return current_process_name;
    }
    LOGE("Failed to get process name");
    return "unknown";
}

// Deteksi target hanya sekali di awal proses
static void detect_if_target_process(const char* process_name) {
    enable_spoof = false;
    if (!process_name || strlen(process_name) == 0) return;
    for (size_t i = 0; i < target_packages_count; i++) {
        if (strcmp(process_name, target_packages[i]) == 0 ||
            strstr(process_name, target_packages[i]) != NULL) {
            enable_spoof = true;
            LOGI("Detected target app: %s (spoof enabled)", process_name);
            return;
        }
    }
    LOGI("Not target app: %s (spoof disabled)", process_name);
}

// should_spoof cukup cek flag
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
    int ret = orig___system_property_get(name, value);
    if (should_spoof()) {
        if (find_spoofed_prop(name, value)) {
            LOGI("Spoofed property get: %s -> %s", name, value);
            return strlen(value);
        }
    }
    return ret;
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

// Inisialisasi xhook dan menerapkan hook (pattern HANYA libc.so)
static bool apply_hooks() {
    if (hook_applied) {
        LOGI("Hooks already applied, skipping");
        return true;
    }
    LOGI("Installing hooks for process: %s", get_process_name());
    xhook_clear();

    const char* pattern_libc = "libc\\.so$";

    int ret1 = xhook_register(pattern_libc, "__system_property_get",
        (void*)my___system_property_get, (void**)&orig___system_property_get);
    int ret2 = xhook_register(pattern_libc, "__system_property_read",
        (void*)my___system_property_read, (void**)&orig___system_property_read);
    int ret3 = xhook_register(pattern_libc, "__system_property_read_callback",
        (void*)my___system_property_read_callback, (void**)&orig___system_property_read_callback);

    int ret = xhook_refresh(0);

    bool success = (ret1 == 0) && (ret2 == 0) && (ret3 == 0) && (ret == 0);

    if (success) {
        LOGI("Spoof hook injection completed successfully!");
        hook_applied = true;
    } else {
        LOGE("Failed to apply one or more hooks!");
        if (ret1 != 0) LOGE("__system_property_get hook failed: %d", ret1);
        if (ret2 != 0) LOGE("__system_property_read hook failed: %d", ret2);
        if (ret3 != 0) LOGE("__system_property_read_callback hook failed: %d", ret3);
        if (ret != 0) LOGE("xhook_refresh failed: %d", ret);
    }
    return success;
}

// Inisialisasi spoofer
extern "C" void init_snapdragon_spoof() {
    LOGI("Initializing Snapdragon Spoofer");
    char sdk_ver[PROP_VALUE_MAX] = {0};
    __system_property_get("ro.build.version.sdk", sdk_ver);
    LOGI("Android SDK version: %s", sdk_ver);

    const char* proc_name = get_process_name();
    detect_if_target_process(proc_name);
    if (should_spoof()) {
        LOGI("Target process detected during init: %s", proc_name);
        apply_hooks();
    }
}

// Fungsi untuk mengecek dan memasang hook hanya di target
extern "C" void apply_hooks_if_target_app(const char* process_name) {
    LOGI("apply_hooks_if_target_app called: [%s]", process_name ? process_name : "NULL");
    if (process_name && strlen(process_name) > 0) {
        strncpy(current_process_name, process_name, sizeof(current_process_name) - 1);
    }
    detect_if_target_process(current_process_name);
    if (!should_spoof()) {
        LOGI("Not a target app, skipping: %s", process_name ? process_name : "NULL");
        return;
    }
    apply_hooks();
    if (hook_applied) {
        LOGI("Verifying hook effectiveness");
        // Cek semua properti yang di-spoof
        for (size_t i = 0; i < spoofed_props_count; ++i) {
            char value[PROP_VALUE_MAX] = {0};
            __system_property_get(spoofed_props[i][0], value);
            LOGI("Test read %s: %s", spoofed_props[i][0], value);
        }
    }
}