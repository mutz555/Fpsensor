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
#define LOGD(...) __android_log_print(ANDROID_LOG_DEBUG, LOG_TAG, __VA_ARGS__)
#define LOGW(...) __android_log_print(ANDROID_LOG_WARN, LOG_TAG, __VA_ARGS__)

// Target packages to apply spoofing (use exact package names)
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
    "com.riotgames.tacticiansandroid", "android.process.media", "com.android.systemui", "com.android.settings"
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

// Debug aide - hook untuk open() sebagai test
static int (*orig_open)(const char* path, int flags, ...) = nullptr;

// Per-process flag
static bool enable_spoof = false;
static bool hook_applied = false;
static char current_process_name[256] = {0};

// Utility untuk mendapatkan nama proses
static const char* get_process_name() {
    if (current_process_name[0] != '\0') {
        return current_process_name;
    }
    
    // Coba dapatkan dari /proc/self/cmdline
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
    
    // Fallback ke getprogname() jika tersedia
    const char* progname = getprogname();
    if (progname) {
        strncpy(current_process_name, progname, sizeof(current_process_name) - 1);
        LOGI("Got process name from getprogname: %s", current_process_name);
        return current_process_name;
    }
    
    LOGW("Failed to get process name");
    return "unknown";
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

// Hook untuk open sebagai test
extern "C" int my_open(const char* path, int flags, ...) {
    if (should_spoof() && path && strstr(path, "property")) {
        LOGI("[%s] open() called: %s", get_process_name(), path);
    }
    
    // Panggil fungsi asli
    va_list args;
    va_start(args, flags);
    mode_t mode = va_arg(args, int);
    va_end(args);
    return orig_open(path, flags, mode);
}

// Hook for __system_property_get
extern "C" int my___system_property_get(const char *name, char *value) {
    int ret = orig___system_property_get(name, value);
    
    if (should_spoof()) {
        if (find_spoofed_prop(name, value)) {
            LOGI("[%s] Spoofed property get: %s -> %s", get_process_name(), name, value);
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
            LOGI("[%s] Spoofed property read: %s -> %s", get_process_name(), name, value);
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
        LOGI("[%s] Spoofed property callback: %s -> %s", get_process_name(), name, final_value);
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

// Fungsi untuk memeriksa apakah proses saat ini cocok dengan salah satu target
static bool check_if_target_process(const char* process_name) {
    if (!process_name || strlen(process_name) == 0) {
        process_name = get_process_name();
    }
    
    LOGI("Checking if target: [%s]", process_name);
    
    for (size_t i = 0; i < target_packages_count; i++) {
        if (strcmp(process_name, target_packages[i]) == 0) {
            LOGI("Target app matched exactly: %s", process_name);
            return true;
        }
        
        // Coba juga dengan pencocokan sebagian
        if (strstr(process_name, target_packages[i]) != NULL) {
            LOGI("Target app matched partially: %s contains %s", process_name, target_packages[i]);
            return true;
        }
    }
    
    return false;
}

// Inisialisasi xhook dan menerapkan hook
static bool apply_hooks() {
    if (hook_applied) {
        LOGI("Hooks already applied, skipping");
        return true;
    }
    
    LOGI("Installing hooks for process: %s", get_process_name());
    
    // Hapus semua hook yang mungkin ada sebelumnya
    xhook_clear();
    
    // Pasang hook untuk properti system
    int ret1 = xhook_register(".*libc\\.so$", "__system_property_get",
        (void*)my___system_property_get, (void**)&orig___system_property_get);
    LOGI("xhook __system_property_get: %d", ret1);
    
    int ret2 = xhook_register(".*libc\\.so$", "__system_property_read",
        (void*)my___system_property_read, (void**)&orig___system_property_read);
    LOGI("xhook __system_property_read: %d", ret2);
    
    int ret3 = xhook_register(".*libc\\.so$", "__system_property_read_callback",
        (void*)my___system_property_read_callback, (void**)&orig___system_property_read_callback);
    LOGI("xhook __system_property_read_callback: %d", ret3);
    
    // Hook open() untuk debug
    int ret4 = xhook_register(".*libc\\.so$", "open", 
        (void*)my_open, (void**)&orig_open);
    LOGI("xhook open: %d", ret4);
    
    // Refresh hook
    int ret = xhook_refresh(0);
    LOGI("xhook_refresh returned: %d", ret);
    
    // Cek status
    bool success = (ret1 == 0 && ret2 == 0 && ret3 == 0 && ret == 0);
    
    if (success) {
        LOGI("Spoof hook injection completed successfully!");
        hook_applied = true;
    } else {
        LOGE("Failed to apply one or more hooks!");
        if (ret1 != 0) LOGE("__system_property_get hook failed: %d", ret1);
        if (ret2 != 0) LOGE("__system_property_read hook failed: %d", ret2);
        if (ret3 != 0) LOGE("__system_property_read_callback hook failed: %d", ret3);
        if (ret4 != 0) LOGE("open hook failed: %d", ret4);
        if (ret != 0) LOGE("xhook_refresh failed: %d", ret);
    }
    
    return success;
}

// Inisialisasi spoofer
extern "C" void init_snapdragon_spoof() {
    LOGI("Initializing Snapdragon Spoofer");
    
    // Log info versi Android
    char sdk_ver[PROP_VALUE_MAX] = {0};
    __system_property_get("ro.build.version.sdk", sdk_ver);
    LOGI("Android SDK version: %s", sdk_ver);
    
    // Cek library yang di-load
    LOGI("Checking loaded libraries");
    FILE* maps = fopen("/proc/self/maps", "r");
    if (maps) {
        char line[512];
        while (fgets(line, sizeof(line), maps)) {
            if (strstr(line, "xhook") || strstr(line, "zygisk")) {
                LOGI("Library loaded: %s", line);
            }
        }
        fclose(maps);
    }
    
    // Coba deteksi proses langsung
    const char* proc_name = get_process_name();
    if (check_if_target_process(proc_name)) {
        LOGI("Target process detected during init: %s", proc_name);
        enable_spoof = true;
        apply_hooks();
    }
}

// Fungsi untuk mengecek dan memasang hook hanya di target
extern "C" void apply_hooks_if_target_app(const char* process_name) {
    LOGI("apply_hooks_if_target_app called: [%s]", process_name ? process_name : "NULL");
    
    // Simpan nama proses jika valid
    if (process_name && strlen(process_name) > 0) {
        strncpy(current_process_name, process_name, sizeof(current_process_name) - 1);
    }
    
    // Cek apakah aplikasi target
    bool is_target = check_if_target_process(process_name);
    
    if (!is_target) {
        LOGI("Not a target app, skipping: %s", process_name ? process_name : "NULL");
        return;
    }
    
    // Aktifkan spoof dan pasang hook
    enable_spoof = true;
    apply_hooks();
    
    // Verifikasi dengan membaca beberapa properti
    if (enable_spoof && hook_applied) {
        LOGI("Verifying hook effectiveness");
        
        char value[PROP_VALUE_MAX];
        __system_property_get("ro.hardware.chipset", value);
        LOGI("Test read ro.hardware.chipset: %s", value);
        
        __system_property_get("ro.board.platform", value);
        LOGI("Test read ro.board.platform: %s", value);
    }
}