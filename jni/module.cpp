#include <unistd.h>
#include <cstdlib>
#include <android/log.h>
#include "zygisk.hpp"

// Pastikan ini adalah modul utama Zygisk dengan entry point yang benar
#define ZYGISK_MODULE_NAME "SnapdragonSpoof"
#define ZYGISK_LOG_TAG "SnapdragonSpoof"
#define LOGD(...) __android_log_print(ANDROID_LOG_DEBUG, ZYGISK_LOG_TAG, __VA_ARGS__)
#define LOGI(...) __android_log_print(ANDROID_LOG_INFO, ZYGISK_LOG_TAG, __VA_ARGS__)
#define LOGE(...) __android_log_print(ANDROID_LOG_ERROR, ZYGISK_LOG_TAG, __VA_ARGS__)

// Deklarasi fungsi dari main.cpp yang akan dipanggil
extern "C" {
    void init_snapdragon_spoof();
    void apply_hooks_if_target_app(const char* process_name);
}

// Implementasi modul Zygisk dengan entry point yang benar
class SnapdragonSpoofModule : public zygisk::ModuleBase {
public:
    void onLoad(zygisk::Api *api, JNIEnv *env) override {
        this->api = api;
        this->env = env;
        LOGI("SnapdragonSpoof module loaded");
        
        // Inisialisasi modul
        init_snapdragon_spoof();
    }

    void preAppSpecialize(zygisk::AppSpecializeArgs *args) override {
        const char *process = nullptr;
        
        if (args->nice_name) {
            process = env->GetStringUTFChars(args->nice_name, nullptr);
            LOGI("Checking process: %s", process);
            
            // Panggil fungsi untuk mengecek dan menerapkan hook jika diperlukan
            apply_hooks_if_target_app(process);
            
            env->ReleaseStringUTFChars(args->nice_name, process);
        } else {
            LOGI("No process name provided, skipping");
        }
    }

    void postAppSpecialize(const zygisk::AppSpecializeArgs *args) override {
        // Kode yang akan dijalankan setelah app dispecialize
        LOGI("Post app specialization");
    }

    void preServerSpecialize(zygisk::ServerSpecializeArgs *args) override {
        // Tidak perlu dijalankan di system_server
        api->setOption(0);
    }

private:
    zygisk::Api *api;
    JNIEnv *env;
};

// Register modul Zygisk - ini adalah entry point utama
REGISTER_ZYGISK_MODULE(SnapdragonSpoofModule)