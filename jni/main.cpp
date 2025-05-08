#include <cstring>
#include <string>
#include <android/log.h>
#include "zygisk.hpp"
#include "xhook.h"
#include <sys/system_properties.h>

#define LOGI(...) __android_log_print(ANDROID_LOG_INFO, "[ZygiskSpoof]", __VA_ARGS__)
#define LOGE(...) __android_log_print(ANDROID_LOG_ERROR, "[ZygiskSpoof]", __VA_ARGS__)

static const char *target_apps[] = {
    "com.mobile.legends",
    "com.miHoYo.GenshinImpact",
    "com.miHoYo.hkrpg",
    "com.tencent.ig",
    "com.garena.game.codm",
    nullptr
};

// Variabel untuk menyimpan nama paket aplikasi
static std::string current_package;

// Fungsi asli yang akan di-hook
static int (*original_system_property_get)(const char*, char*, size_t) = nullptr;

// Fungsi kustom untuk pengganti system_property_get
int my_system_property_get(const char* name, char* value, size_t value_len) {
    // Panggil fungsi asli dulu
    int result = original_system_property_get(name, value, value_len);

    // Periksa apakah ini aplikasi target
    bool is_target_app = false;
    for (const char **app = target_apps; *app; ++app) {
        if (current_package == *app) {
            is_target_app = true;
            break;
        }
    }

    // Jika aplikasi target, modifikasi nilai yang dikembalikan
    if (is_target_app) {
        if (strcmp(name, "ro.product.model") == 0) {
            strlcpy(value, "SM-S928B", value_len);
        } else if (strcmp(name, "ro.product.brand") == 0) {
            strlcpy(value, "samsung", value_len);
        } else if (strcmp(name, "ro.product.manufacturer") == 0) {
            strlcpy(value, "samsung", value_len);
        } else if (strcmp(name, "ro.product.device") == 0) {
            strlcpy(value, "dm3q", value_len);
        } else if (strcmp(name, "ro.product.name") == 0) {
            strlcpy(value, "dm3qxx", value_len);
        } else if (strcmp(name, "ro.build.display.id") == 0) {
            strlcpy(value, "UP1A.231005.007", value_len);
        } else if (strcmp(name, "ro.build.id") == 0) {
            strlcpy(value, "UP1A.231005.007", value_len);
        } else if (strcmp(name, "ro.build.tags") == 0) {
            strlcpy(value, "release-keys", value_len);
        } else if (strcmp(name, "ro.build.type") == 0) {
            strlcpy(value, "user", value_len);
        } else if (strcmp(name, "ro.build.user") == 0) {
            strlcpy(value, "dpi", value_len);
        } else if (strcmp(name, "ro.build.host") == 0) {
            strlcpy(value, "21DJB", value_len);
        } else if (strcmp(name, "ro.board.platform") == 0) {
            strlcpy(value, "kalama", value_len);
        } else if (strcmp(name, "ro.soc.manufacturer") == 0) {
            strlcpy(value, "Qualcomm Technologies, Inc.", value_len);
        } else if (strcmp(name, "ro.soc.model") == 0) {
            strlcpy(value, "SM8650", value_len);
        }
    }

    return result;
}

// Fungsi untuk pasang hook
void setupHooks() {
    LOGI("Setting up xhook untuk system_property_get");

    // Register hook untuk system_property_get
    xhook_register("libc.so", "__system_property_get", 
                  (void*)my_system_property_get, (void**)&original_system_property_get);

    // Terapkan hook
    if (xhook_refresh(0) == 0) {
        LOGI("xhook sukses diterapkan");
    } else {
        LOGE("xhook gagal diterapkan");
    }
}

// Kelas utama modul Zygisk
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

    void preAppSpecialize(zygisk::AppSpecializeArgs *args) override {
        // Periksa apakah ini aplikasi target
        if (args->nice_name) {
            const char *pkg = zygisk_env->GetStringUTFChars(args->nice_name, nullptr);
            current_package = pkg;
            zygisk_env->ReleaseStringUTFChars(args->nice_name, pkg);

            bool is_target = false;
            for (const char **app = target_apps; *app; ++app) {
                if (current_package == *app) {
                    is_target = true;
                    break;
                }
            }

            if (!is_target) {
                // Jika bukan aplikasi target, batalkan proses hook
                LOGI("Bukan aplikasi target: %s", current_package.c_str());

                return;
            }

            LOGI("Aplikasi target terdeteksi: %s", current_package.c_str());

            // Aktifkan hooking untuk aplikasi target
            setupHooks();
        }
    }

    void postAppSpecialize(const zygisk::AppSpecializeArgs *args) override {
        // Kosong - hook sudah dipasang di preAppSpecialize
    }
};

// Daftarkan modul Zygisk
REGISTER_ZYGISK_MODULE(SpoofModule)