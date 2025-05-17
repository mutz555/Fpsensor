#include <android/log.h>
#include "xhook.h" // Pastikan path ini benar
#include <string> // Untuk std::string jika perlu

#define LOG_TAG "MyFingerprintHookLib"
#define ALOGI(...) __android_log_print(ANDROID_LOG_INFO, LOG_TAG, __VA_ARGS__)
#define ALOGE(...) __android_log_print(ANDROID_LOG_ERROR, LOG_TAG, __VA_ARGS__)

// Pointer untuk menyimpan fungsi asli
typedef void* (*t_dlopen_orig)(const char* filename, int flags);
static t_dlopen_orig original_dlopen_ptr = nullptr;

typedef void* (*t_android_dlopen_ext_orig)(const char* filename, int flags, const void* extinfo);
static t_android_dlopen_ext_orig original_android_dlopen_ext_ptr = nullptr;

// Fungsi pengganti
void* my_dlopen_replacement(const char* filename, int flags) {
    ALOGI("LD_PRELOAD_HOOK: dlopen: filename='%s', flags=%d", filename, flags);
    if (original_dlopen_ptr) {
        return original_dlopen_ptr(filename, flags);
    }
    ALOGE("LD_PRELOAD_HOOK: dlopen: original_dlopen_ptr null!");
    return nullptr; // Atau panggil dlopen sistem jika perlu fallback
}

void* my_android_dlopen_ext_replacement(const char* filename, int flags, const void* extinfo) {
    ALOGI("LD_PRELOAD_HOOK: android_dlopen_ext: filename='%s', flags=%d", filename, flags);
    if (original_android_dlopen_ext_ptr) {
        return original_android_dlopen_ext_ptr(filename, flags, extinfo);
    }
    ALOGE("LD_PRELOAD_HOOK: android_dlopen_ext: original_android_dlopen_ext_ptr null!");
    return nullptr;
}

// Fungsi constructor yang akan dipanggil saat pustaka dimuat
__attribute__((constructor)) static void initialize_hooks() {
    ALOGI("LD_PRELOAD_HOOK: Pustaka dimuat, menginisialisasi hook...");

    xhook_enable_debug(1); // Aktifkan debug xhook

    // Registrasi hook untuk dlopen
    if (xhook_register(".*\\libdl.so$", "dlopen", (void*)my_dlopen_replacement, (void**)&original_dlopen_ptr) != 0 &&
        xhook_register(".*\\linker.*$", "dlopen", (void*)my_dlopen_replacement, (void**)&original_dlopen_ptr) != 0 &&
        xhook_register(".*\\libc.so$", "dlopen", (void*)my_dlopen_replacement, (void**)&original_dlopen_ptr) != 0) {
        ALOGE("LD_PRELOAD_HOOK: Gagal mendaftarkan semua target hook untuk dlopen.");
    } else {
        ALOGI("LD_PRELOAD_HOOK: Hook untuk dlopen berhasil didaftarkan (atau sebagian).");
    }

    // Registrasi hook untuk android_dlopen_ext
    if (xhook_register(".*\\libdl.so$", "android_dlopen_ext", (void*)my_android_dlopen_ext_replacement, (void**)&original_android_dlopen_ext_ptr) != 0 &&
        xhook_register(".*\\linker.*$", "android_dlopen_ext", (void*)my_android_dlopen_ext_replacement, (void**)&original_android_dlopen_ext_ptr) != 0) {
        ALOGE("LD_PRELOAD_HOOK: Gagal mendaftarkan semua target hook untuk android_dlopen_ext.");
    } else {
        ALOGI("LD_PRELOAD_HOOK: Hook untuk android_dlopen_ext berhasil didaftarkan (atau sebagian).");
    }

    if (xhook_refresh(0) == 0) { // Argumen 0 untuk async, atau 1 untuk sync (coba 0 dulu)
        ALOGI("LD_PRELOAD_HOOK: xhook_refresh berhasil.");
    } else {
        ALOGE("LD_PRELOAD_HOOK: xhook_refresh GAGAL.");
    }
    ALOGI("LD_PRELOAD_HOOK: Inisialisasi hook selesai.");
}