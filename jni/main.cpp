#include <jni.h>
#include <cstring>
#include <string>
#include <map>
#include <android/log.h>
#include "xhook.h"
#include <sys/system_properties.h>
#include <pthread.h>
#include <unistd.h>

#define LOGI(...) __android_log_print(ANDROID_LOG_INFO, "[SpoofModule]", __VA_ARGS__)
#define LOGE(...) __android_log_print(ANDROID_LOG_ERROR, "[SpoofModule]", __VA_ARGS__)
#define LOGD(...) __android_log_print(ANDROID_LOG_DEBUG, "[SpoofModule]", __VA_ARGS__)


static FILE* (*original_fopen)(const char* path, const char* mode) = nullptr;

const char* fake_cpuinfo =
    "Processor\t: ARMv8 Processor rev 0 (v8l)\n"
    "Hardware\t: Qualcomm SM8550\n"
    "Model name\t: Snapdragon 8 Gen 2\n"
    "Features\t: fp asimd aes pmull sha1 sha2 crc32\n"
    "CPU implementer\t: 0x51\n"
    "CPU architecture: 8\n"
    "CPU variant\t: 0x0\n"
    "CPU part\t: 0x803\n"
    "CPU revision\t: 4\n";

FILE* my_fopen(const char* path, const char* mode) {
    if (strcmp(path, "/proc/cpuinfo") == 0) {
        LOGI("Spoofed /proc/cpuinfo via fmemopen.");
        return fmemopen((void*)fake_cpuinfo, strlen(fake_cpuinfo), "r");
    }
    return original_fopen(path, mode);
}

static int (*original_system_property_get)(const char*, char*, size_t) = nullptr;

// Map properti spoof
static std::map<std::string, std::string> spoof_props = {
    {"ro.product.model",        "SM-S928B"},
    {"ro.product.brand",        "samsung"},
    {"ro.product.manufacturer", "samsung"},
    {"ro.product.device",       "dm3q"},
    {"ro.product.name",         "dm3qxx"},
    {"ro.product.board",        "kalama"},
    {"ro.build.product",        "dm3qxx"},
    {"ro.board.platform",       "kalama"},
    {"ro.hardware",             "qcom"},
    {"ro.hardware.chipname",    "SM8550-AC"},
    {"ro.soc.manufacturer",     "Qualcomm"},
    {"ro.soc.model",            "SM8550-AC"},
    {"ro.build.fingerprint",    "samsung/dm3qxx/dm3q:14/UP1A.231005.007/S928BXXU1AXB5:user/release-keys"},
    {"ro.build.display.id",     "UP1A.231005.007"},
    {"ro.build.id",             "UP1A.231005.007"},
    {"ro.build.tags",           "release-keys"},
    {"ro.build.type",           "user"},
    {"ro.build.user",           "dpi"},
    {"ro.build.host",           "21DJB"},
    {"ro.build.version.sdk",    "34"},
    {"ro.build.version.release","14"}
};

// Boolean untuk menandai apakah hook sudah diaktifkan
static bool hook_initialized = false;

int my_system_property_get(const char* name, char* value, size_t value_len) {
    if (name == nullptr || value == nullptr) {
        return -1;
    }

    auto it = spoof_props.find(name);
    if (it != spoof_props.end()) {
        strlcpy(value, it->second.c_str(), value_len);
        LOGD("Spoofed: %s => %s", name, value);
        return strlen(value);
    }
    
    // Log permintaan properti yang tidak di-spoof untuk tujuan debugging
    // (komentar kode ini jika terlalu banyak log)
    int result = original_system_property_get(name, value, value_len);
    if (result > 0 && strstr(name, "ro.product") != nullptr || 
                      strstr(name, "ro.build") != nullptr ||
                      strstr(name, "ro.hardware") != nullptr ||
                      strstr(name, "ro.board") != nullptr ||
                      strstr(name, "ro.soc") != nullptr) {
        LOGD("Not spoofed: %s => %s", name, value);
    }
    
    return result;
}

// Fungsi untuk thread yang menjalankan xhook
void* hook_thread_func(void* arg) {
    LOGI("Hook thread started");
    
    // Delay kecil untuk memastikan proses sudah siap
    usleep(100 * 1000); // 100ms
    
    // Mendaftar hook
    int ret = xhook_register("libc.so", "__system_property_get",
                    (void*)my_system_property_get,
                    (void**)&original_system_property_get);
                    
    if (ret != 0) {
        LOGE("Gagal mendaftar hook: %d", ret);
        return nullptr;
    }
    
    // Mengaktifkan hook secara sinkron (mode 1)
    ret = xhook_refresh(1);
    if (ret == 0) {
        LOGI("xhook berhasil diterapkan");
        hook_initialized = true;
    } else {
        LOGE("xhook gagal diterapkan: %d", ret);
        
        // Coba refresh sekali lagi dengan mode asinkron
        ret = xhook_register("libc.so", "fopen", (void*)my_fopen, (void**)&original_fopen);
    xhook_refresh(0);
        if (ret == 0) {
            LOGI("xhook berhasil diterapkan (mode asinkron)");
            hook_initialized = true;
        } else {
            LOGE("xhook gagal diterapkan lagi: %d", ret);
        }
    }
    
    // Clear cache xhook setelah di-refresh untuk menghindari kebocoran memori
    xhook_clear();
    
    LOGI("Hook thread selesai");
    return nullptr;
}

void setupHooks() {
    if (hook_initialized) {
        LOGI("Hook sudah diinisialisasi sebelumnya, melewati");
        return;
    }

    LOGI("Setting up xhook untuk LSPosed");
    
    // Konfigurasi xhook
    xhook_enable_debug(1);  // Aktifkan debugging
    xhook_enable_sigsegv_protection(1);  // Lindungi dari SIGSEGV
    
    // Jalankan hook dalam thread terpisah
    pthread_t tid;
    int result = pthread_create(&tid, nullptr, hook_thread_func, nullptr);
    if (result != 0) {
        LOGE("Gagal membuat thread untuk hook: %d", result);
        // Jika thread gagal dibuat, jalankan fungsi hook langsung
        hook_thread_func(nullptr);
    } else {
        pthread_detach(tid);
        LOGI("Thread hook dibuat berhasil");
    }
}

// Hook untuk proses Android zygote
__attribute__((constructor)) void onModuleLoad() {
    LOGI("Constructor: Module dimuat, mengaktifkan hook");
    setupHooks();
}

extern "C"
JNIEXPORT jboolean JNICALL
Java_com_mutz_spoof_HookEntry_checkHookStatus(JNIEnv *env, jclass clazz) {
    return hook_initialized ? JNI_TRUE : JNI_FALSE;
}

extern "C"
JNIEXPORT jboolean JNICALL
Java_com_mutz_spoof_HookEntry_forceRefreshHook(JNIEnv *env, jclass clazz) {
    setupHooks();
    return hook_initialized ? JNI_TRUE : JNI_FALSE;
}

extern "C"
JNIEXPORT void JNICALL
Java_com_mutz_spoof_HookEntry_dumpSystemProperties(JNIEnv *env, jclass clazz) {
    // Logging beberapa properti penting untuk debugging
    char value[PROP_VALUE_MAX];
    
    LOGI("=== System Properties Dump ===");
    for (const auto& prop_pair : spoof_props) {
        if (original_system_property_get(prop_pair.first.c_str(), value, PROP_VALUE_MAX) > 0) {
            LOGI("Current %s = %s (akan di-spoof menjadi: %s)", 
                 prop_pair.first.c_str(), value, prop_pair.second.c_str());
        } else {
            LOGI("Property %s tidak ditemukan (akan di-set ke: %s)", 
                 prop_pair.first.c_str(), prop_pair.second.c_str());
        }
    }
    LOGI("============================");
}

extern "C"
jint JNI_OnLoad(JavaVM* vm, void* reserved) {
    LOGI("JNI_OnLoad: native module LSPosed aktif");
    setupHooks();
    return JNI_VERSION_1_6;
}