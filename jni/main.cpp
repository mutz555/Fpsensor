#include <cstring>
#include <unistd.h>
#include <cstdlib>
#include <android/log.h>
#include <xhook.h>
#include <sys/system_properties.h>
#include <dlfcn.h>
#include "zygisk.hpp"

#define LOG_TAG "SnapdragonSpoof"
#define LOGI(...) __android_log_print(ANDROID_LOG_INFO, LOG_TAG, __VA_ARGS__)
#define LOGE(...) __android_log_print(ANDROID_LOG_ERROR, LOG_TAG, __VA_ARGS__)

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

// Debug log function for target packages
static void log_target_packages() {
    LOGI("Number of target packages: %zu", target_packages_count);
    for (size_t i = 0; i < target_packages_count; i++) {
        LOGI("Target[%zu]: %s", i, target_packages[i]);
    }
}

// Debug log function for spoof properties
static void log_spoof_properties() {
    LOGI("Number of spoofed properties: %zu", spoofed_props_count);
    for (size_t i = 0; i < 5 && i < spoofed_props_count; i++) { // Log first 5 only to avoid spam
        LOGI("Prop[%zu]: %s -> %s", i, spoofed_props[i][0], spoofed_props[i][1]);
    }
    LOGI("... (more properties available)");
}

// Check if we should spoof for this process
static bool should_spoof() {
    return enable_spoof;
}

// Find spoofed property value
static bool find_spoofed_prop(const char *name, char *value) {
    if (!name || !value) return false;
    
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

// Test spoof hook functionality
static void test_spoof_hooks() {
    if (!orig___system_property_get) {
        LOGE("Original __system_property_get is NULL, cannot test");
        return;
    }
    
    char original_value[PROP_VALUE_MAX] = {0};
    char spoofed_value[PROP_VALUE_MAX] = {0};
    
    // Get original value
    bool spoof_enabled = enable_spoof;
    enable_spoof = false;
    orig___system_property_get("ro.board.platform", original_value);
    
    // Get spoofed value
    enable_spoof = true;
    my___system_property_get("ro.board.platform", spoofed_value);
    
    // Reset flag
    enable_spoof = spoof_enabled;
    
    LOGI("Hook test: ro.board.platform: original=[%s], spoofed=[%s]", 
         original_value, spoofed_value);
         
    // Verify if spoofing works
    if (strcmp(original_value, spoofed_value) != 0) {
        LOGI("Hook test PASSED - values are different as expected");
    } else {
        LOGE("Hook test FAILED - spoofed value is same as original");
    }
}

// Inisialisasi spoofer
extern "C" void init_snapdragon_spoof() {
    LOGI("Initializing Snapdragon Spoofer");
    
    // Initialize xhook
    xhook_enable_debug(1);
    xhook_clear();
    
    // Log configuration for debugging
    log_target_packages();
    log_spoof_properties();
    
    LOGI("xhook initialized successfully");
}

// Verify symbols in libc.so are available
static bool verify_libc_symbols() {
    void* libc_handle = dlopen("libc.so", RTLD_NOW);
    if (!libc_handle) {
        LOGE("Failed to open libc.so: %s", dlerror());
        return false;
    }

    void* sym_get = dlsym(libc_handle, "__system_property_get");
    void* sym_read = dlsym(libc_handle, "__system_property_read");
    void* sym_callback = dlsym(libc_handle, "__system_property_read_callback");

    dlclose(libc_handle);

    if (!sym_get || !sym_read || !sym_callback) {
        LOGE("Failed to find required symbols: get=%p, read=%p, callback=%p", 
             sym_get, sym_read, sym_callback);
        return false;
    }

    LOGI("Verified symbols in libc.so: get=%p, read=%p, callback=%p", 
         sym_get, sym_read, sym_callback);
    return true;
}

// Fungsi untuk mengecek dan memasang hook hanya di target
extern "C" void apply_hooks_if_target_app(const char* process_name) {
    LOGI("apply_hooks_if_target_app called with: [%s]", process_name ? process_name : "NULL");

    if (hook_applied) {  
        LOGI("Hooks already applied for this process, skipping.");  
        return;  
    }  

    if (!process_name) {
        LOGE("Process name is NULL, cannot apply hooks");
        return;
    }

    // Log architecture information
    #if defined(__arm__)
        LOGI("Running on ARM 32-bit");
    #elif defined(__aarch64__)
        LOGI("Running on ARM 64-bit");
    #else
        LOGE("Unsupported architecture");
        return;
    #endif
    
    // Check if process is a target app - using both exact match and substring approaches
    enable_spoof = false;
    
    // Approach 1: Exact match
    for (size_t i = 0; i < target_packages_count; i++) {  
        if (strcmp(process_name, target_packages[i]) == 0) {  
            LOGI("TARGET FOUND (exact match): [%s] matches [%s]", process_name, target_packages[i]);  
            enable_spoof = true;  
            break;  
        }  
    }
    
    // Approach 2: Process name contains target package
    if (!enable_spoof) {
        for (size_t i = 0; i < target_packages_count; i++) {
            if (strstr(process_name, target_packages[i]) != NULL) {
                LOGI("TARGET FOUND (substring): [%s] contains [%s]", process_name, target_packages[i]);
                enable_spoof = true;
                break;
            }
        }
    }

    if (!enable_spoof) {  
        LOGI("Not a target app, skipping hook installation");  
        return;  
    }
    
    // Verify libc symbols are available
    if (!verify_libc_symbols()) {
        LOGE("Symbol verification failed, cannot continue with hook installation");
        return;
    }

    LOGI("Installing hooks for %s", process_name);
    
    // Configure xhook
    xhook_enable_sigsegv_protection(0);
    xhook_block_monitor_self(0);

    // Register hooks with multiple attempts if needed
    int ret1 = xhook_register(".*libc\\.so$", "__system_property_get",  
        (void*)my___system_property_get, (void**)&orig___system_property_get);  
    
    // Alternative pattern if the first one fails
    if (ret1 != 0) {
        LOGI("First attempt failed (ret=%d), trying alternative pattern", ret1);
        ret1 = xhook_register("libc\\.so$", "__system_property_get",  
            (void*)my___system_property_get, (void**)&orig___system_property_get);
    }
    LOGI("xhook_register __system_property_get: %d", ret1);  

    int ret2 = xhook_register(".*libc\\.so$", "__system_property_read",  
        (void*)my___system_property_read, (void**)&orig___system_property_read);  
    LOGI("xhook_register __system_property_read: %d", ret2);  

    int ret3 = xhook_register(".*libc\\.so$", "__system_property_read_callback",  
        (void*)my___system_property_read_callback, (void**)&orig___system_property_read_callback);  
    LOGI("xhook_register __system_property_read_callback: %d", ret3);  

    // Refresh hook to apply all registered hooks
    int ret = xhook_refresh(1);  // Use 1 to wait for completion
    LOGI("xhook_refresh returned: %d", ret);  

    // Verify hook installation
    if (ret1 != 0 || ret2 != 0 || ret3 != 0 || ret != 0) {  
        LOGE("xhook failed to install one or more hooks!");
        hook_applied = false;
    } else if (!orig___system_property_get || 
               !orig___system_property_read || 
               !orig___system_property_read_callback) {
        LOGE("Original function pointers are NULL after hook installation!");
        hook_applied = false;
    } else {  
        LOGI("Spoof hook installation completed successfully!");
        hook_applied = true;
        
        // Test the hook functionality
        test_spoof_hooks();
    }
}