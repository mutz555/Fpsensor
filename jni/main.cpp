#include <cstdlib>
#include <unistd.h>
#include <sys/system_properties.h>
#include <dlfcn.h>
#include <cstring>
#include <algorithm>
#include <android/log.h>
#include <jni.h>
#include <fcntl.h>

// Tambahkan xhook
#include "xhook.h"

#include "zygisk.hpp"

#define LOG_TAG "ZygiskXHook"
#define LOGI(...) __android_log_print(ANDROID_LOG_INFO, LOG_TAG, __VA_ARGS__)
#define LOGE(...) __android_log_print(ANDROID_LOG_ERROR, LOG_TAG, __VA_ARGS__)

// ===========================
// Native Hook Functions
// ===========================
static void (*orig_ANativeWindow_disconnect)(ANativeWindow *window) = nullptr;
static void my_ANativeWindow_disconnect(ANativeWindow *window) {
    LOGI("Hooked: ANativeWindow_disconnect");
    if (orig_ANativeWindow_disconnect) orig_ANativeWindow_disconnect(window);
}

static int (*orig_ANativeWindow_setBuffersGeometry)(ANativeWindow* window, int w, int h, int format) = nullptr;
static int my_ANativeWindow_setBuffersGeometry(ANativeWindow* window, int w, int h, int format) {
    LOGI("Hooked: ANativeWindow_setBuffersGeometry w=%d h=%d format=%d", w, h, format);
    return orig_ANativeWindow_setBuffersGeometry 
        ? orig_ANativeWindow_setBuffersGeometry(window, w, h, format)
        : -1;
}

// ===========================
// JNI (optional, bisa dipanggil dari Java)
// ===========================
extern "C"
jint JNI_OnLoad(JavaVM *vm, void *reserved) {
    LOGI("JNI_OnLoad dipanggil");
    return JNI_VERSION_1_6;
}

// ===========================
// Zygisk Module
// ===========================
class MyZygiskModule : public zygisk::Module {
public:
    void onLoad(zygisk::Api *api, JNIEnv *env) override {
        LOGI("Zygisk onLoad start");

        xhook_register(".*", "ANativeWindow_disconnect", (void *)my_ANativeWindow_disconnect, (void **)&orig_ANativeWindow_disconnect);
        xhook_register(".*", "ANativeWindow_setBuffersGeometry", (void *)my_ANativeWindow_setBuffersGeometry, (void **)&orig_ANativeWindow_setBuffersGeometry);
        xhook_refresh(0);

        LOGI("xhook registered successfully");
    }

    void preAppSpecialize(const zygisk::AppSpecializeArgs *args) override {
        LOGI("preAppSpecialize: %s", args->nice_name);
    }

    void postAppSpecialize(const zygisk::AppSpecializeArgs *args) override {
        LOGI("postAppSpecialize: %s", args->nice_name);
    }
};

REGISTER_ZYGISK_MODULE(MyZygiskModule)