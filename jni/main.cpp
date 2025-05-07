// main.cpp
#include <jni.h>
#include <cstdio>
#include <android/log.h>
#include <xhook.h>
#include "zygisk.hpp"

#define TAG "ZygiskHook"
#define LOGI(...) __android_log_print(ANDROID_LOG_INFO, TAG, __VA_ARGS__)

// ====== HOOK TARGETS ======

// 1. ANativeWindow_disconnect
static void (*orig_ANativeWindow_disconnect)(ANativeWindow *window) = nullptr;
static void my_ANativeWindow_disconnect(ANativeWindow *window) {
    LOGI("[+] Hooked ANativeWindow_disconnect");
    orig_ANativeWindow_disconnect(window);
}

// 2. ANativeWindow_setBuffersGeometry
static int (*orig_ANativeWindow_setBuffersGeometry)(ANativeWindow* window, int w, int h, int format) = nullptr;
static int my_ANativeWindow_setBuffersGeometry(ANativeWindow* window, int w, int h, int format) {
    LOGI("[+] Hooked ANativeWindow_setBuffersGeometry: %dx%d format=%d", w, h, format);
    return orig_ANativeWindow_setBuffersGeometry(window, w, h, format);
}

// 3. Surface::disconnect (note: needs mangled name and correct symbol resolution)
// Placeholder for C++ symbol, real one depends on build

// 4. JNI method (optional hook point)
extern "C" JNIEXPORT void JNICALL
Java_com_example_hookdemo_MainActivity_nativeHookTest(JNIEnv *, jobject) {
    LOGI("[+] JNI nativeHookTest called");
}

// ====== ZYGOTE ENTRY CLASS ======
class MyZygiskModule : public zygisk::Module {
public:
    void onLoad(zygisk::Api *api, JNIEnv *env) override {
        LOGI("[+] Zygisk module loaded");

        // Register xhook
        xhook_register(".*libnativewindow\\.so$", "ANativeWindow_disconnect",
                       (void *) my_ANativeWindow_disconnect,
                       (void **) &orig_ANativeWindow_disconnect);

        xhook_register(".*libnativewindow\\.so$", "ANativeWindow_setBuffersGeometry",
                       (void *) my_ANativeWindow_setBuffersGeometry,
                       (void **) &orig_ANativeWindow_setBuffersGeometry);

        // Apply hooks
        xhook_refresh(0);
        xhook_clear();
    }
};

// Required entry
REGISTER_ZYGISK_MODULE(MyZygiskModule)
