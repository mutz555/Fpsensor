#include <unistd.h>
#include <cstdlib>
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

// Implementasi modul Zygisk
class SnapdragonSpoofModule : public zygisk::ModuleBase {
public:
    void onLoad(zygisk::Api *api, JNIEnv *env) override {
        this->api = api;
        this->env = env;
        LOGI("SnapdragonSpoof module loaded (onLoad)");
        init_snapdragon_spoof();
    }

    // Dipanggil sebelum proses app dispecialize
    void preAppSpecialize(zygisk::AppSpecializeArgs *args) override {
        if (!env) {
            LOGE("JNIEnv is NULL di preAppSpecialize!");
            return;
        }
        // Ambil nama proses dari nice_name (biasanya berisi package name)
        const char *process = nullptr;
        if (args->nice_name) {
            process = env->GetStringUTFChars(args->nice_name, nullptr);
            LOGI("preAppSpecialize: nice_name = [%s]", process ? process : "NULL");
            // Panggil fungsi hook dari main.cpp hanya jika proses terdaftar sebagai target
            apply_hooks_if_target_app(process);
            env->ReleaseStringUTFChars(args->nice_name, process);
        } else {
            LOGI("preAppSpecialize: nice_name NULL");
        }
    }

    void postAppSpecialize(const zygisk::AppSpecializeArgs *args) override {
        LOGI("postAppSpecialize dipanggil");
    }

    void preServerSpecialize(zygisk::ServerSpecializeArgs *args) override {
        // Contoh: gunakan enum yang benar, misal FORCE_DENYLIST_UNMOUNT
        if (api) api->setOption(zygisk::FORCE_DENYLIST_UNMOUNT);
    }

private:
    zygisk::Api *api = nullptr;
    JNIEnv *env = nullptr;
};

// ---- ENTRY POINT ZYGISK MODERN ----
REGISTER_ZYGISK_MODULE(SnapdragonSpoofModule)