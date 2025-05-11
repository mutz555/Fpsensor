#include <unistd.h>
#include <cstdlib>
#include <android/log.h>
#include <cstring>
#include "zygisk.hpp"

// Deklarasi fungsi dari main.cpp yang akan dipanggil
extern "C" {
    void init_snapdragon_spoof();
    void apply_hooks_if_target_app(const char* process_name);
}

#define LOG_TAG "SnapdragonSpoof"
#define LOGI(...) __android_log_print(ANDROID_LOG_INFO, LOG_TAG, __VA_ARGS__)
#define LOGE(...) __android_log_print(ANDROID_LOG_ERROR, LOG_TAG, __VA_ARGS__)

// Utility untuk mengambil process name dari /proc/self/cmdline
static void get_process_name(char* buf, size_t len) {
    buf[0] = 0;
    FILE *f = fopen("/proc/self/cmdline", "r");
    if (f) {
        size_t r = fread(buf, 1, len - 1, f);
        buf[r] = 0;
        fclose(f);
    }
}

class SnapdragonSpoofModule : public zygisk::ModuleBase {
public:
    void onLoad(zygisk::Api *api, JNIEnv *env) override {
        this->api = api;
        this->env = env;
        LOGI("SnapdragonSpoof module loaded (onLoad)");

        char process_name[256] = {0};
        get_process_name(process_name, sizeof(process_name));
        LOGI("onLoad: Detected process name: [%s]", process_name);

        // Pasang hook lebih awal, namun tetap per-app
        apply_hooks_if_target_app(process_name);

        init_snapdragon_spoof();
    }

    void preAppSpecialize(zygisk::AppSpecializeArgs *args) override {
        if (!env) {
            LOGE("JNIEnv is NULL di preAppSpecialize!");
            return;
        }
        const char *process = nullptr;
        if (args->nice_name) {
            process = env->GetStringUTFChars(args->nice_name, nullptr);
            LOGI("preAppSpecialize: nice_name = [%s]", process ? process : "NULL");
            // Tidak perlu panggil apply_hooks_if_target_app di sini lagi, sudah di onLoad
            env->ReleaseStringUTFChars(args->nice_name, process);
        } else {
            LOGI("preAppSpecialize: nice_name NULL");
        }
    }

    void postAppSpecialize(const zygisk::AppSpecializeArgs *args) override {
        LOGI("postAppSpecialize dipanggil");
    }

    void preServerSpecialize(zygisk::ServerSpecializeArgs *args) override {
        if (api) api->setOption(zygisk::FORCE_DENYLIST_UNMOUNT);
    }

private:
    zygisk::Api *api = nullptr;
    JNIEnv *env = nullptr;
};

REGISTER_ZYGISK_MODULE(SnapdragonSpoofModule)