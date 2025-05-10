#include <unistd.h>
#include <cstdlib>
#include <cstring>
#include <android/log.h>
#include "zygisk.hpp"

// Deklarasi fungsi dari main.cpp yang akan dipanggil
extern "C" {
    void init_snapdragon_spoof();
    void apply_hooks_if_target_app(const char* process_name);
}

#define LOG_TAG "SnapdragonSpoof"
#define LOGI(...) __android_log_print(ANDROID_LOG_INFO, LOG_TAG, __VA_ARGS__)
#define LOGE(...) __android_log_print(ANDROID_LOG_ERROR, LOG_TAG, __VA_ARGS__)

// Helper function to extract package name from app_data_dir
static const char* extract_package_name(const char* app_data_dir) {
    if (!app_data_dir) return nullptr;

    const char *prefix1 = "/data/user/0/";
    const char *prefix2 = "/data/data/";

    if (strstr(app_data_dir, prefix1) == app_data_dir) {
        return app_data_dir + strlen(prefix1);
    } else if (strstr(app_data_dir, prefix2) == app_data_dir) {
        return app_data_dir + strlen(prefix2);
    }

    return nullptr;
}

// Kelas utama modul Zygisk
class SnapdragonSpoofModule : public zygisk::ModuleBase {
public:
    void onLoad(zygisk::Api* api, JNIEnv* env) override {
        LOGI("SnapdragonSpoof module loaded (onLoad)");
        init_snapdragon_spoof();
        g_api = api;
        g_env = env;
    }

    void preAppSpecialize(zygisk::AppSpecializeArgs* args) override {
        if (!g_env) {
            LOGE("JNIEnv is NULL di preAppSpecialize!");
            return;
        }

        // Get nice_name for logging
        const char *nice_name = nullptr;
        if (args->nice_name) {
            nice_name = g_env->GetStringUTFChars(args->nice_name, nullptr);
            LOGI("preAppSpecialize: nice_name = [%s]", nice_name ? nice_name : "NULL");
        }

        // Get app_data_dir to extract package name
        const char *app_data_dir = nullptr;
        const char *package_name = nullptr;
        if (args->app_data_dir) {
            app_data_dir = g_env->GetStringUTFChars(args->app_data_dir, nullptr);
            LOGI("preAppSpecialize: app_data_dir = [%s]", app_data_dir ? app_data_dir : "NULL");

            // Extract package name from app_data_dir
            package_name = extract_package_name(app_data_dir);
            if (package_name) {
                LOGI("Extracted package name: [%s]", package_name);
                apply_hooks_if_target_app(package_name);
            }
        }

        // If we couldn't extract package name from app_data_dir, try to use nice_name
        if (!package_name && nice_name) {
            LOGI("Falling back to nice_name as package identifier");
            apply_hooks_if_target_app(nice_name);
        }

        // Clean up
        if (nice_name) {
            g_env->ReleaseStringUTFChars(args->nice_name, nice_name);
        }
        if (app_data_dir) {
            g_env->ReleaseStringUTFChars(args->app_data_dir, app_data_dir);
        }
    }

    void postAppSpecialize(const zygisk::AppSpecializeArgs* /*args*/) override {
        LOGI("postAppSpecialize dipanggil");
    }

    void preServerSpecialize(zygisk::ServerSpecializeArgs* /*args*/) override {
        if (g_api) g_api->setOption(0);
    }
private:
    // Opsional: kamu bisa simpan pointer di sini jika tidak ingin pakai variabel global
};

// Variabel global untuk akses API/JNI jika tetap dibutuhkan
zygisk::Api* g_api = nullptr;
JNIEnv* g_env = nullptr;

// ENTRY POINT ZYGISK
REGISTER_ZYGISK_MODULE(SnapdragonSpoofModule)