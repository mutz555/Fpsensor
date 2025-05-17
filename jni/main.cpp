#include <cstdlib>
#include <unistd.h>
#include <fcntl.h>
#include <android/log.h>
#include <string>
#include <dlfcn.h> 
#include <thread>  

// Sertakan header API Zygisk
#include "zygisk.hpp"

// Sertakan header xhook
#include "xhook.h" // Pastikan path ini benar sesuai struktur proyek Anda

#define LOG_TAG "MyFingerprintXHookLog" 
#define ALOGD(...) __android_log_print(ANDROID_LOG_DEBUG, LOG_TAG, __VA_ARGS__)
#define ALOGI(...) __android_log_print(ANDROID_LOG_INFO, LOG_TAG, __VA_ARGS__)
#define ALOGE(...) __android_log_print(ANDROID_LOG_ERROR, LOG_TAG, __VA_ARGS__)

// Nama proses target
const char *TARGET_PROCESS_NAME = "android.hardware.biometrics.fingerprint@2.1-service";

// --- Definisi Pointer untuk Menyimpan Fungsi Asli ---
// Tanda tangan dan pointer untuk dlopen asli
typedef void* (*t_dlopen_orig)(const char* filename, int flags);
static t_dlopen_orig original_dlopen_ptr = nullptr; 

// Tanda tangan dan pointer untuk android_dlopen_ext asli
typedef void* (*t_android_dlopen_ext_orig)(const char* filename, int flags, const void* extinfo /*android_dlextinfo*/);
static t_android_dlopen_ext_orig original_android_dlopen_ext_ptr = nullptr;


// --- Fungsi Pengganti (Hook) ---
// Fungsi pengganti untuk dlopen
void* my_dlopen_replacement(const char* filename, int flags) {
    ALOGI("XHOOKED_DLOPEN: Mencoba memuat filename='%s', flags=%d", filename, flags);

    // Panggil fungsi asli menggunakan pointer yang disimpan oleh xhook
    if (original_dlopen_ptr) {
        // Jika Anda ingin memodifikasi filename sebelum memanggil yang asli:
        // const char* new_filename = filename;
        // if (strcmp(filename, "path/yang/ingin/diubah.so") == 0) {
        //     new_filename = "path/baru.so";
        //     ALOGI("XHOOKED_DLOPEN: Mengganti filename dari '%s' ke '%s'", filename, new_filename);
        // }
        // void* result = original_dlopen_ptr(new_filename, flags);
        
        void* result = original_dlopen_ptr(filename, flags);
        ALOGI("XHOOKED_DLOPEN: Panggilan asli dlopen mengembalikan %p untuk filename='%s'", result, filename);
        return result;
    } else {
        ALOGE("XHOOKED_DLOPEN: original_dlopen_ptr tidak diset! Tidak bisa memanggil fungsi asli.");
        // Fallback atau penanganan error, misalnya dengan mengembalikan nullptr
        // atau mencoba memanggil dlopen sistem secara langsung (meskipun ini mungkin berisiko jika hook diharapkan aktif)
        // return dlopen(filename, flags); // Hati-hati dengan pemanggilan rekursif jika hook gagal total
        return nullptr;
    }
}

// Fungsi pengganti untuk android_dlopen_ext
void* my_android_dlopen_ext_replacement(const char* filename, int flags, const void* extinfo) {
    ALOGI("XHOOKED_ADLOPEN: Mencoba memuat filename='%s', flags=%d, extinfo=%p", filename, flags, extinfo);

    // Panggil fungsi asli menggunakan pointer yang disimpan oleh xhook
    if (original_android_dlopen_ext_ptr) {
        void* result = original_android_dlopen_ext_ptr(filename, flags, extinfo);
        ALOGI("XHOOKED_ADLOPEN: Panggilan asli android_dlopen_ext mengembalikan %p untuk filename='%s'", result, filename);
        return result;
    } else {
        ALOGE("XHOOKED_ADLOPEN: original_android_dlopen_ext_ptr tidak diset! Tidak bisa memanggil fungsi asli.");
        return nullptr;
    }
}


static void do_hooking_with_xhook() {
    ALOGI("Memulai proses hooking dengan xhook untuk %s", TARGET_PROCESS_NAME);

    // Hook dlopen
    // Regex bisa disesuaikan jika perlu lebih spesifik atau lebih umum
    // Menyimpan pointer fungsi asli ke original_dlopen_ptr
    if (xhook_register(".*\\libdl.so$", "dlopen", (void*)my_dlopen_replacement, (void**)&original_dlopen_ptr) != 0 &&
        xhook_register(".*\\linker.*$", "dlopen", (void*)my_dlopen_replacement, (void**)&original_dlopen_ptr) != 0 && // Mencakup linker dan linker64
        xhook_register(".*\\libc.so$", "dlopen", (void*)my_dlopen_replacement, (void**)&original_dlopen_ptr) != 0 ) { // Beberapa implementasi libc mungkin juga mengeksposnya
        ALOGW("Gagal mendaftarkan semua target hook untuk dlopen. Beberapa mungkin berhasil.");
        // Tidak langsung error karena salah satu mungkin sudah cukup, tergantung implementasi sistem.
    } else {
        ALOGI("Hook untuk dlopen berhasil didaftarkan (atau setidaknya satu upaya berhasil).");
    }

    // Hook android_dlopen_ext
    // Menyimpan pointer fungsi asli ke original_android_dlopen_ext_ptr
    if (xhook_register(".*\\libdl.so$", "android_dlopen_ext", (void*)my_android_dlopen_ext_replacement, (void**)&original_android_dlopen_ext_ptr) != 0 &&
        xhook_register(".*\\linker.*$", "android_dlopen_ext", (void*)my_android_dlopen_ext_replacement, (void**)&original_android_dlopen_ext_ptr) != 0) {
        ALOGW("Gagal mendaftarkan semua target hook untuk android_dlopen_ext.");
    } else {
        ALOGI("Hook untuk android_dlopen_ext berhasil didaftarkan (atau setidaknya satu upaya berhasil).");
    }

    // Setelah semua hook didaftarkan, refresh cache hook
    if (xhook_refresh(1) == 0) { // Argumen 1 berarti untuk proses saat ini
        ALOGI("xhook_refresh berhasil diterapkan.");
    } else {
        ALOGE("xhook_refresh gagal.");
    }

    // (Opsional) Aktifkan mode debug xhook jika perlu untuk melihat log internal xhook
    // xhook_enable_debug(1);
    // xhook_enable_sigsegv_protection(0); // Coba nonaktifkan jika ada crash SEGV yang mencurigakan terkait xhook

    ALOGI("Proses hooking dengan xhook selesai.");
}


class MyXHookLoggerModule : public zygisk::ModuleBase {
public:
    void onLoad(zygisk::Api *api, JNIEnv *env) override {
        this->api = api;
        this->env = env;
        ALOGI("MyXHookLoggerModule onLoad: Modul Zygisk dimuat.");
    }

    void preAppSpecialize(zygisk::AppSpecializeArgs *args) override {
        const char *process_name_chars = env->GetStringUTFChars(args->nice_name, nullptr);
        if (process_name_chars) {
            std::string process_name(process_name_chars);
            env->ReleaseStringUTFChars(args->nice_name, process_name_chars);

            if (process_name == TARGET_PROCESS_NAME) {
                ALOGI("preAppSpecialize: Proses target '%s' ditemukan untuk xhook logging.", TARGET_PROCESS_NAME);
                is_target_process_for_xhook = true;
            }
        }
    }

    void postAppSpecialize(const zygisk::AppSpecializeArgs *args) override {
        if (is_target_process_for_xhook) {
            ALOGI("postAppSpecialize: Dalam proses target '%s'. Melakukan hook dengan xhook.", TARGET_PROCESS_NAME);
            
            std::thread hook_thread(do_hooking_with_xhook);
            hook_thread.detach(); 

            is_target_process_for_xhook = false; 
        }
    }

private:
    zygisk::Api *api = nullptr;
    JNIEnv *env = nullptr;
    bool is_target_process_for_xhook = false;
};

// Daftarkan modul Zygisk Anda
REGISTER_ZYGISK_MODULE(MyXHookLoggerModule)
