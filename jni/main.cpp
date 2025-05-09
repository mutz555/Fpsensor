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
    "com.tencent.ig",               // PUBG Mobile
    "com.pubg.imobile",             // PUBG Mobile (India)
    "com.pubg.krmobile",            // PUBG Mobile (Korea)
    "com.vng.pubgmobile",           // PUBG Mobile (Vietnam)
    "com.rekoo.pubgm",              // PUBG Mobile (Taiwan)
    "com.tencent.tmgp.pubgmhd",     // PUBG Mobile (CN HD)
    "com.pubg.newstate",            // PUBG New State
    "flar2.devcheck",               // DevCheck
    "com.antutu.ABenchMark",        // AnTuTu Benchmark
    "com.primatelabs.geekbench",    // Geekbench
    "com.android.vending",          // Google Play Store
    "com.mobile.legends",           // Mobile Legends
    "com.miHoYo.GenshinImpact",     // Genshin Impact
    "com.miHoYo.Yuanshen",          // Genshin Impact (CN)
    "com.miHoYo.honkaiimpact3",     // Honkai Impact 3rd
    "com.miHoYo.bh3.global",        // Honkai Impact 3rd (Global)
    "com.miHoYo.bh3.eur",           // Honkai Impact 3rd (Europe)
    "com.hoyoverse.hkrpg.global",   // Honkai: Star Rail
    "com.miHoYo.hkrpg",             // Honkai: Star Rail (CN)
    "com.hoyoverse.hkrpgoversea",   // Honkai: Star Rail (Global)
    "com.activision.callofduty.shooter", // Call of Duty Mobile
    "com.garena.game.codm",         // Call of Duty Mobile (Garena)
    "com.tencent.tmgp.cod",         // Call of Duty Mobile (CN)
    "com.ea.gp.apexlegendsmobilefps", // Apex Legends Mobile
    "com.epicgames.fortnite",       // Fortnite
    "com.netease.party.m",          // Marvel Snap
    "com.netease.marvel.marvelsuperwarglobal", // Marvel Super War
    "com.supercell.brawlstars",     // Brawl Stars
    "com.dts.freefireth",           // Free Fire
    "com.dts.freefiremax",          // Free Fire MAX
    "com.riotgames.league.wildrift", // League of Legends: Wild Rift
    "com.riotgames.legendsofruneterra", // Legends of Runeterra
    "com.riotgames.tacticiansandroid" // Teamfight Tactics
};

// Snapdragon 8 Gen 3 (SM8650/Kalama) properties
static const char *spoofed_props[][2] = {
    // Basic SoC information
    {"ro.board.platform", "kalama"},
    {"ro.hardware", "qcom"},
    {"ro.soc.manufacturer", "Qualcomm"},
    {"ro.soc.model", "SM8650"},
    {"ro.product.board", "kalama"},
    {"ro.chipname", "SM8650"},
    
    // CPU information
    {"ro.qualcomm.soc", "sm8650"},
    {"ro.arch", "arm64"},
    {"ro.cpu.core", "1+3+2+2"}, // CPU core config
    {"ro.cpu.cluster0", "3.3GHz"}, // Prime core
    {"ro.cpu.cluster1", "3.2GHz"}, // Performance cores
    {"ro.cpu.cluster2", "3.0GHz"}, // Mid cores
    {"ro.cpu.cluster3", "2.3GHz"}, // Efficiency cores
    
    // GPU information
    {"ro.gpu.model", "Adreno 750"},
    {"ro.gpu.vendor", "Qualcomm"},
    {"ro.gpu.frequency", "1000MHz"},
    
    // Memory information
    {"ro.hardware.memory", "LPDDR5X"},
    {"ro.memory.speed", "4800MHz"},
    
    // Hardware features
    {"ro.hardware.chipset", "Snapdragon 8 Gen 3"},
    {"ro.qualcomm.version", "SM8650-AC"},
    
    // Qualcomm features
    {"ro.hardware.vulkan", "adreno"},
    {"ro.hardware.egl", "adreno"},
    {"ro.opengles.version", "196610"}, // OpenGL ES 3.2
    {"ro.hardware.audio", "lito"},
    {"ro.hardware.sensors", "kalama"},
    
    // Build properties
    {"ro.build.description", "SM8650-kalama-user 14 UKQ1.230930.001 eng.user.20240213.144736 release-keys"},
    {"ro.build.fingerprint", "qcom/kalama/kalama:14/UKQ1.230930.001/20240213.144736:user/release-keys"}
};

// Original function pointers
static int (*orig___system_property_get)(const char *name, char *value) = nullptr;
static int (*orig___system_property_read)(const prop_info *pi, char *name, char *value) = nullptr;
static int (*orig___system_property_read_callback)(const prop_info *pi, 
                                              void (*callback)(void *cookie, const char *name, const char *value, uint32_t serial),
                                              void *cookie) = nullptr;

// Flag to determine if spoofing should be applied
static bool enable_spoof = false;

// Process name cache
static char process_name[256] = {0};

// Get current process name
static const char *get_process_name() {
    if (process_name[0] == '\0') {
        FILE *f = fopen("/proc/self/cmdline", "r");
        if (f) {
            fread(process_name, 1, sizeof(process_name) - 1, f);
            fclose(f);
        }
    }
    return process_name;
}

// Convert jstring to C string
static const char *jstring_to_cstr(JNIEnv *env, jstring jstr) {
    if (!jstr) return nullptr;
    const char *str = env->GetStringUTFChars(jstr, nullptr);
    if (str) {
        strncpy(process_name, str, sizeof(process_name) - 1);
        env->ReleaseStringUTFChars(jstr, str);
        return process_name;
    }
    return nullptr;
}

// Check if we should spoof for this process
static bool should_spoof() {
    if (enable_spoof) return true;
    
    const char *proc = get_process_name();
    for (const char *pkg : target_packages) {
        if (strstr(proc, pkg)) {
            LOGI("Matched target package: %s", proc);
            enable_spoof = true;
            return true;
        }
    }
    return false;
}

// Find spoofed property value
static bool find_spoofed_prop(const char *name, char *value) {
    for (auto &pair : spoofed_props) {
        if (strcmp(name, pair[0]) == 0) {
            strcpy(value, pair[1]);
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
    
    // Check if we need to spoof
    char spoofed_value[PROP_VALUE_MAX];
    const char *final_value = value;
    
    if (should_spoof() && find_spoofed_prop(name, spoofed_value)) {
        final_value = spoofed_value;
        LOGI("Spoofed property callback: %s -> %s", name, final_value);
    }
    
    // Call original callback with potentially spoofed value
    info->orig_callback(info->orig_cookie, name, final_value, serial);
    delete info;
}

// Hook for __system_property_read_callback
extern "C" int my___system_property_read_callback(const prop_info *pi, 
                                            void (*callback)(void *cookie, const char *name, const char *value, uint32_t serial),
                                            void *cookie) {
    // Don't wrap if we're not spoofing
    if (!should_spoof()) {
        return orig___system_property_read_callback(pi, callback, cookie);
    }
    
    // Create wrapper information
    CallbackInfo *info = new CallbackInfo{callback, cookie};
    return orig___system_property_read_callback(pi, callback_wrapper, info);
}

class SnapdragonSpoofer : public zygisk::ModuleBase {
public:
    void onLoad(zygisk::Api *api, JNIEnv *env) override {
        // Save API reference
        this->api = api;
        LOGI("SnapdragonSpoof module loaded");
    }
    
    void preAppSpecialize(zygisk::AppSpecializeArgs *args) override {
        // Check if we should enable for this app
        const char *process = nullptr;
        
        // Get process name from JNI args
        if (args->nice_name) {
            process = jstring_to_cstr(args->env, args->nice_name);
        }
        
        // If nice_name is not available, try to get from cmdline
        if (!process || process[0] == '\0') {
            get_process_name();
            process = process_name;
        }
        
        for (const char *pkg : target_packages) {
            if (strstr(process_name, pkg)) {
                LOGI("Target app detected: %s", process_name);
                enable_spoof = true;
                break;
            }
        }
        
        if (!enable_spoof) {
            // Not a target app, exempt the process
            api->setOption(zygisk::DLCLOSE_MODULE_LIBRARY);
            return;
        }
    }
    
    void postAppSpecialize(const zygisk::AppSpecializeArgs *args) override {
        if (!enable_spoof) return;
        
        // Set up hooks only if we're in a target process
        LOGI("Installing hooks for %s", process_name);
        
        // Register hooks
        xhook_register(".*libc\\.so$", "__system_property_get", 
                     (void*)my___system_property_get, (void**)&orig___system_property_get);
        
        xhook_register(".*libc\\.so$", "__system_property_read", 
                     (void*)my___system_property_read, (void**)&orig___system_property_read);
        
        xhook_register(".*libc\\.so$", "__system_property_read_callback", 
                     (void*)my___system_property_read_callback, (void**)&orig___system_property_read_callback);
        
        // Apply hooks
        int ret = xhook_refresh(0);
        LOGI("xhook_refresh returned: %d", ret);
        
        xhook_clear();
        LOGI("Spoof hook injection completed!");
    }
    
    void preServerSpecialize(zygisk::ServerSpecializeArgs *args) override {
        // We don't need to run in system_server
        api->setOption(zygisk::DLCLOSE_MODULE_LIBRARY);
    }
    
private:
    zygisk::Api *api;
};

REGISTER_ZYGISK_MODULE(SnapdragonSpoofer)

// Static instance of our module
static SnapdragonSpoofer moduleInstance;

// Explicit entry point untuk memastikan modul dikenali oleh Zygisk
extern "C" __attribute__((visibility("default")))
zygisk::ModuleBase *zygisk_module_entry() {
    LOGI("zygisk_module_entry called - providing module instance");
    return &moduleInstance;
}