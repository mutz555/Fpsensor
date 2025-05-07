// xhook_jni_hook.cpp

#include <jni.h>
#include <android/log.h>
#include <dlfcn.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include "xhook.h"

// For Zygisk
#include "zygisk.h"

#define LOG_TAG "XHookJNI"
#define LOGI(...) __android_log_print(ANDROID_LOG_INFO, LOG_TAG, __VA_ARGS__)
#define LOGE(...) __android_log_print(ANDROID_LOG_ERROR, LOG_TAG, __VA_ARGS__)

// Original function pointers
static int (*original_ANativeWindow_disconnect)(void* window) = NULL;
static int (*original_Surface_disconnect)(void* surface) = NULL;
static void (*original_ViewRootImpl_doDie)(void* view) = NULL;
static int (*original_ANativeWindow_setBuffersGeometry)(void* window, int32_t width, int32_t height, int32_t format) = NULL;

// Hook implementations
int hook_ANativeWindow_disconnect(void* window) {
    LOGI("Hook: ANativeWindow_disconnect called");
    // Your custom code here before calling original
    
    // Call original function
    int result = 0;
    if (original_ANativeWindow_disconnect) {
        result = original_ANativeWindow_disconnect(window);
    }
    
    // Your custom code here after calling original
    
    return result;
}

int hook_Surface_disconnect(void* surface) {
    LOGI("Hook: Surface::disconnect called");
    // Your custom code here
    
    int result = 0;
    if (original_Surface_disconnect) {
        result = original_Surface_disconnect(surface);
    }
    
    return result;
}

void hook_ViewRootImpl_doDie(void* view) {
    LOGI("Hook: ViewRootImpl::doDie called");
    // Your custom code here
    
    if (original_ViewRootImpl_doDie) {
        original_ViewRootImpl_doDie(view);
    }
}

int hook_ANativeWindow_setBuffersGeometry(void* window, int32_t width, int32_t height, int32_t format) {
    LOGI("Hook: ANativeWindow_setBuffersGeometry called with width=%d, height=%d, format=%d", width, height, format);
    
    // Modify parameters if needed
    // Example: Force specific format
    // format = your_custom_format;
    
    int result = 0;
    if (original_ANativeWindow_setBuffersGeometry) {
        result = original_ANativeWindow_setBuffersGeometry(window, width, height, format);
    }
    
    return result;
}

// Setup hooks using xhook
void setup_hooks() {
    LOGI("Setting up xhook hooks");
    
    // Initialize xhook
    xhook_register("libandroid.so", "ANativeWindow_disconnect", 
                   (void*)hook_ANativeWindow_disconnect, (void**)&original_ANativeWindow_disconnect);
    
    xhook_register("libsurfaceflinger.so", "Surface::disconnect", 
                   (void*)hook_Surface_disconnect, (void**)&original_Surface_disconnect);
    
    xhook_register("libandroid_runtime.so", "ViewRootImpl::doDie", 
                   (void*)hook_ViewRootImpl_doDie, (void**)&original_ViewRootImpl_doDie);
    
    xhook_register("libandroid.so", "ANativeWindow_setBuffersGeometry", 
                   (void*)hook_ANativeWindow_setBuffersGeometry, (void**)&original_ANativeWindow_setBuffersGeometry);
    
    // Apply hooks
    int ret = xhook_refresh(0);
    LOGI("xhook_refresh returned: %d", ret);
}

// JNI functions
extern "C" {
    JNIEXPORT jint JNICALL JNI_OnLoad(JavaVM* vm, void* reserved) {
        LOGI("JNI_OnLoad called");
        
        JNIEnv* env;
        if (vm->GetEnv(reinterpret_cast<void**>(&env), JNI_VERSION_1_6) != JNI_OK) {
            return JNI_ERR;
        }
        
        // Setup hooks when library is loaded
        setup_hooks();
        
        return JNI_VERSION_1_6;
    }
    
    JNIEXPORT void JNICALL Java_com_example_xhookjni_HookManager_initHooks(JNIEnv* env, jobject thiz) {
        LOGI("initHooks called from Java");
        // This function can be called from Java to re-initialize hooks if needed
        setup_hooks();
    }
}

// Zygisk Module implementation
class XHookModule : public zygisk::ModuleBase {
public:
    void onLoad(zygisk::Api *api, JNIEnv *env) override {
        this->api = api;
        this->env = env;
    }
    
    void preAppSpecialize(zygisk::AppSpecializeArgs *args) override {
        // Check if we want to load into this process
        const char *process = env->GetStringUTFChars(args->nice_name, nullptr);
        bool should_hook = false;
        
        // Target specific apps (example: com.android.systemui)
        if (strstr(process, "com.android.systemui") != nullptr) {
            LOGI("Target app detected: %s", process);
            should_hook = true;
        }
        
        // Add more target apps as needed
        // if (strstr(process, "com.example.otherapp") != nullptr) {
        //     should_hook = true;
        // }
        
        env->ReleaseStringUTFChars(args->nice_name, process);
        
        if (!should_hook) {
            // Don't load into this process
            api->setOption(zygisk::Option::DLCLOSE_MODULE_LIBRARY);
            return;
        }
        
        // Allow the module to be loaded into the app process
        LOGI("Preparing to hook target app");
    }
    
    void postAppSpecialize(const zygisk::AppSpecializeArgs *args) override {
        // Hook after the app has been specialized
        LOGI("Setting up hooks in target app");
        setup_hooks();
    }
    
    void preServerSpecialize(zygisk::ServerSpecializeArgs *args) override {
        // Don't load into system_server process
        api->setOption(zygisk::Option::DLCLOSE_MODULE_LIBRARY);
    }
    
private:
    zygisk::Api *api;
    JNIEnv *env;
};

// Zygisk module entry point
REGISTER_ZYGISK_MODULE(XHookModule)

// Example of how to add Java component for managing hooks
/*
// In Java side (HookManager.java):

package com.example.xhookjni;

public class HookManager {
    static {
        System.loadLibrary("xhook_jni");
    }
    
    public native void initHooks();
    
    // Other methods to control hook behavior
}
*/