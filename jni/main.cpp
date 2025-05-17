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
#define ALOGW(...) __android_log_print(ANDROID_LOG_WARN, LOG_TAG, __VA_ARGS__) // Pastikan ini ALOGW
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

    if (original_dlopen_ptr) {
        void* result = original_dlopen_ptr(filename, flags);
        ALOGI("XHOOKED_DLOPEN: Panggilan asli dlopen mengembalikan %p untuk filename='%s'", result, filename);
        return result;
    } else {
        ALOGE("XHOOKED_DLOPEN: original_dlopen_ptr tidak diset! Tidak bisa memanggil fungsi asli.");
        return nullptr;
    }
}

// Fungsi pengganti untuk android_dlopen_ext
void* my_android_dlopen_ext_replacement(const char* filename, int flags, const void* extinfo) {
    ALOGI("XHOOKED_ADLOPEN: Mencoba memuat filename='%s', flags=%d, extinfo=%p", filename, flags, extinfo);

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

    // Aktifkan mode debug xhook untuk log internal tambahan dari xhook
    // Letakkan ini di awal sebelum xhook_register atau xhook_refresh
    xhook_enable_debug(1); // Panggil saja, tidak ada nilai kembalian
    ALOGI("xhook_enable_debug(1) telah dipanggil.");

    // Nonaktifkan proteksi SIGSEGV xhook jika Anda mencurigai ada konflik dengan handler lain
    // atau jika xhook sendiri menyebabkan crash SEGV saat debug. Biasanya biarkan default.
    // xhook_enable_sigsegv_protection(0); // Panggil saja
    // ALOGI("xhook_enable_sigsegv_protection(0) telah dipanggil.");


    // Hook dlopen
    ALOGI("Mencoba mendaftarkan hook untuk dlopen...");
    int dlopen_reg_status_libdl = xhook_register(".*\\libdl.so$", "dlopen", (void*)my_dlopen_replacement, (void**)&original_dlopen_ptr);
    ALOGI("xhook_register untuk dlopen di libdl.so: status %d (0 jika sukses)", dlopen_reg_status_libdl);
    
    int dlopen_reg_status_linker = xhook_register(".*\\linker.*$", "dlopen", (void*)my_dlopen_replacement, (void**)&original_dlopen_ptr);
    ALOGI("xhook_register untuk dlopen di linker: status %d (0 jika sukses)", dlopen_reg_status_linker);
    
    int dlopen_reg_status_libc = xhook_register(".*\\libc.so$", "dlopen", (void*)my_dlopen_replacement, (void**)&original_dlopen_ptr);
    ALOGI("xhook_register untuk dlopen di libc.so: status %d (0 jika sukses)", dlopen_reg_status_libc);

    if (dlopen_reg_status_libdl != 0 && dlopen_reg_status_linker != 0 && dlopen_reg_status_libc != 0) {
        ALOGE("Semua upaya pendaftaran hook untuk dlopen GAGAL.");
    } else {
        ALOGI("Setidaknya satu upaya pendaftaran hook untuk dlopen berhasil atau sedang diproses.");
    }

    // Hook android_dlopen_ext
    ALOGI("Mencoba mendaftarkan hook untuk android_dlopen_ext...");
    int adlopen_reg_status_libdl = xhook_register(".*\\libdl.so$", "android_dlopen_ext", (void*)my_android_dlopen_ext_replacement, (void**)&original_android_dlopen_ext_ptr);
    ALOGI("xhook_register untuk android_dlopen_ext di libdl.so: status %d (0 jika sukses)", adlopen_reg_status_libdl);
    
    int adlopen_reg_status_linker = xhook_register(".*\\linker.*$", "android_dlopen_ext", (void*)my_android_dlopen_ext_replacement, (void**)&original_android_dlopen_ext_ptr);
    ALOGI("xhook_register untuk android_dlopen_ext di linker: status %d (0 jika sukses)", adlopen_reg_status_linker);

    if (adlopen_reg_status_libdl != 0 && adlopen_reg_status_linker != 0) {
        ALOGE("Semua upaya pendaftaran hook untuk android_dlopen_ext GAGAL.");
    } else {
        ALOGI("Setidaknya satu upaya pendaftaran hook untuk android_dlopen_ext berhasil atau sedang diproses.");
    }
    
    // Setelah semua hook didaftarkan, refresh cache hook
    ALOGI("Mencoba menerapkan hook dengan xhook_refresh(1)...");
    if (xhook_refresh(1) == 0) { // Argumen 1 berarti untuk proses saat ini
        ALOGI("xhook_refresh berhasil diterapkan.");
    } else {
        ALOGE("xhook_refresh GAGAL.");
    }

    ALOGI("Proses hooking dengan xhook selesai (atau upaya telah dilakukan).");
}



class MyXHookLoggerModule : public zygisk::ModuleBase {
public:
    void onLoad(zygisk::Api *api, JNIEnv *env) override {
        this->api = api;
        this->env = env;
        ALOGI("MyXHookLoggerModule onLoad: Modul Zygisk dimuat. PID: %d", getpid());
    }

    void preAppSpecialize(zygisk::AppSpecializeArgs *args) override {
        // Dapatkan nama proses
        const char *process_name_chars = env->GetStringUTFChars(args->nice_name, nullptr);
        if (process_name_chars) {
            std::string process_name(process_name_chars);
            // Log semua proses yang di-spawn oleh Zygote untuk debugging
            ALOGD("preAppSpecialize: Melihat proses: '%s' (UID: %d, GID: %d)", process_name.c_str(), args->uid, args->gid);
            env->ReleaseStringUTFChars(args->nice_name, process_name_chars);

            // Periksa apakah ini proses target kita
            if (process_name == TARGET_PROCESS_NAME) {
                ALOGI("preAppSpecialize: Proses target '%s' DITEMUKAN. Flag diaktifkan.", TARGET_PROCESS_NAME);
                is_target_process_for_xhook = true;
            }
        } else {
            ALOGE("preAppSpecialize: Gagal mendapatkan nama proses (nice_name adalah null).");
        }
    }

    void postAppSpecialize(const zygisk::AppSpecializeArgs *args) override {
        if (is_target_process_for_xhook) {
            ALOGI("postAppSpecialize: Dalam proses target '%s' (PID: %d). Melakukan hook dengan xhook.", TARGET_PROCESS_NAME, getpid());
            
            // Untuk pengujian awal, Anda bisa mencoba menjalankan do_hooking_with_xhook() secara langsung:
            // do_hooking_with_xhook();
            // Jika ini berhasil, baru kembalikan ke penggunaan thread.

            // Menjalankan hooking di thread baru adalah praktik yang baik
            std::thread hook_thread(do_hooking_with_xhook);
            hook_thread.detach(); // Biarkan thread berjalan secara independen

            is_target_process_for_xhook = false; // Reset flag agar tidak dieksekusi lagi untuk proses ini
        }
    }

private:
    zygisk::Api *api = nullptr;
    JNIEnv *env = nullptr;
    bool is_target_process_for_xhook = false;
};

// Daftarkan modul Zygisk Anda
REGISTER_ZYGISK_MODULE(MyXHookLoggerModule)
