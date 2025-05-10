#include <unistd.h>
#include <cstdlib>
#include <android/log.h>
#include "zygisk.hpp"

// Deklarasi fungsi dari main.cpp yang akan dipanggil
extern "C" {
    void init_snapdragon_spoof();
    void apply_hooks_if_target_app(const char* process_name);
}

// Implementasi modul Zygisk
class SnapdragonSpoofModule : public zygisk::ModuleBase {
public:
    void onLoad(zygisk::Api *api, JNIEnv *env) override {
        this->api = api;
        this->env = env;
        __android_log_print(ANDROID_LOG_INFO, "SnapdragonSpoof", "SnapdragonSpoof module loaded");
        init_snapdragon_spoof();
    }

    void preAppSpecialize(zygisk::AppSpecializeArgs *args) override {
        const char *process = nullptr;
        if (args->nice_name) {
            process = env->GetStringUTFChars(args->nice_name, nullptr);
            __android_log_print(ANDROID_LOG_INFO, "SnapdragonSpoof", "Checking process: %s", process);
            apply_hooks_if_target_app(process);
            env->ReleaseStringUTFChars(args->nice_name, process);
        } else {
            __android_log_print(ANDROID_LOG_INFO, "SnapdragonSpoof", "No process name provided, skipping");
        }
    }

    void postAppSpecialize(const zygisk::AppSpecializeArgs *args) override {
        __android_log_print(ANDROID_LOG_INFO, "SnapdragonSpoof", "Post app specialization");
    }

    void preServerSpecialize(zygisk::ServerSpecializeArgs *args) override {
        api->setOption(0);
    }

private:
    zygisk::Api *api;
    JNIEnv *env;
};

// ---- ENTRY POINT ZYGISK WAJIB ----
static SnapdragonSpoofModule g_module;

// Untuk Zygisk modern (2023-2025): pointer to pointer
extern "C" void registerModule(zygisk::ModuleBase **module) {
    *module = &g_module;
}