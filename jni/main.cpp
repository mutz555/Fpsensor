#include <jni.h>
#include <android/log.h>
#include <android/native_window.h>
#include <zygisksub/zygisk.hpp>
#include "xhook.h"

#define LOG_TAG "ZygiskHook"
#define LOGI(...) __android_log_print(ANDROID_LOG_INFO, LOG_TAG, __VA_ARGS__)
#define LOGE(...) __android_log_print(ANDROID_LOG_ERROR, LOG_TAG, __VA_ARGS__)

// Hook target
static void (*orig_ANativeWindow_disconnect)(ANativeWindow *window) = nullptr;
static void my_ANativeWindow_disconnect(ANativeWindow *window) {
    LOGI("ANativeWindow_disconnect called!");
    if (orig_ANativeWindow_disconnect) {
        orig_ANativeWindow_disconnect(window);
    }
}

static int (*orig_ANativeWindow_setBuffersGeometry)(ANativeWindow* window, int w, int h, int format) = nullptr;
static int my_ANativeWindow_setBuffersGeometry(ANativeWindow* window, int w, int h, int format) {
    LOGI("ANativeWindow_setBuffersGeometry called!");
    return orig_ANativeWindow_setBuffersGeometry
        ? orig_ANativeWindow_setBuffersGeometry(window, w, h, format)
        : -1;
}

// Zygisk hook entry
class MyZygiskModule : public zygisk::Module {
public:
    void onLoad(zygisk::Api *api, JNIEnv *env) override {
        LOGI("Zygisk onLoad triggered");

        xhook_register(".*", "ANativeWindow_disconnect", (void *)my_ANativeWindow_disconnect, (void **)&orig_ANativeWindow_disconnect);
        xhook_register(".*", "ANativeWindow_setBuffersGeometry", (void *)my_ANativeWindow_setBuffersGeometry, (void **)&orig_ANativeWindow_setBuffersGeometry);
        xhook_refresh(0);
    }
};

REGISTER_ZYGISK_MODULE(MyZygiskModule)