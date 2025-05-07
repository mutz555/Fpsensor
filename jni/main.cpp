#include <jni.h>
#include <android/log.h>
#include <android/native_window_jni.h>
#include "zygisk.hpp"
#include "xhook.h"

#define LOG_TAG "ZygiskXHook"
#define LOGI(...) __android_log_print(ANDROID_LOG_INFO, LOG_TAG, __VA_ARGS__)

// Hook target functions
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

// JNI_OnLoad
extern "C"
jint JNI_OnLoad(JavaVM *vm, void *reserved) {
    LOGI("JNI_OnLoad called");
    return JNI_VERSION_1_6;
}

// Zygisk Module
class MyZygiskModule : public zygisk::ModuleBase {
public:
    void onLoad(zygisk::Api *api, JNIEnv *env) override {
        LOGI("Zygisk onLoad start");

        xhook_register(".*", "ANativeWindow_disconnect", (void *)my_ANativeWindow_disconnect, (void **)&orig_ANativeWindow_disconnect);
        xhook_register(".*", "ANativeWindow_setBuffersGeometry", (void *)my_ANativeWindow_setBuffersGeometry, (void **)&orig_ANativeWindow_setBuffersGeometry);
        xhook_refresh(0);

        LOGI("xhook registered successfully");
    }

    void preAppSpecialize(const zygisk::AppSpecializeArgs *args) override {
        LOGI("preAppSpecialize");
    }

    void postAppSpecialize(const zygisk::AppSpecializeArgs *args) override {
        LOGI("postAppSpecialize");
    }
};

REGISTER_ZYGISK_MODULE(MyZygiskModule)